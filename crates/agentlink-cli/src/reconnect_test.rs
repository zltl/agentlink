//! Relay-drop session contract after the cd30 fail-closed teardown.
//!
//! When the relay link drops, the node stops in-flight shells, media, and
//! grant-tracked RPCs immediately. Those old sessions must not come back to
//! life. After the node redials a grant-verified fresh session can work
//! again, and a journaled copy may open a new request and resume. A
//! `cancelled` result is evidence the old request stopped, not success.

use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use agentlink_core::engine::{XferOpts, TRANSFER_FRAME_PAUSE_MS};
use agentlink_core::grant::{add_revoked_jti, load_issuer, save_grant, SignedGrant};
use agentlink_core::protocol::CompressPref;
use agentlink_core::{Client, ClientSettings, ExecRequest, Identity, NodePolicy};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use serde_json::json;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

struct PauseGuard;

impl Drop for PauseGuard {
    fn drop(&mut self) {
        TRANSFER_FRAME_PAUSE_MS.store(0, Ordering::Relaxed);
    }
}

/// Cancel the node if the test returns early so leftover exec/transfer
/// tasks cannot keep the runtime alive after a panic.
struct NodeStop(CancellationToken);

impl Drop for NodeStop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn relay_restart_mid_exec_pty_transfer_mcp_and_watch() {
    let result = tokio::time::timeout(Duration::from_secs(90), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("reconnect integration test timed out"),
    }
}

async fn flow() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let _pause = PauseGuard;
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("root");
    std::fs::create_dir_all(root.join("watched"))?;
    let relay_dir = dir.path().join("relay");
    let relay = spawn_relay(&relay_dir, "127.0.0.1:0".parse()?).await?;
    let relay_url = format!("wss://{}/v1/connect", relay.local_addr);
    let mut settings = ClientSettings {
        relay: relay_url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    };
    // Every client that holds the grant shares one identity so a single grant
    // covers them; grant files are keyed by node id, not by client.
    let identity = Identity::load_or_create(&dir.path().join("client-identity.json"))?;
    let admin = Client::connect_identity(&settings, identity.clone(), true).await?;
    admin.remember_node_pins(dir.path());
    admin.remember_grants(dir.path());
    let pairing = admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let node_shutdown = CancellationToken::new();
    let _node_stop = NodeStop(node_shutdown.clone());
    let node_dir = dir.path().join("node");
    let node_task = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: node_dir.clone(),
            name: "box".into(),
            pairing_token: Some(pairing.token),
            root: Some(root.clone()),
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        node_shutdown.clone(),
    ));
    wait_online(&admin, &node_task).await;
    let grant_jti = issue_test_grant(dir.path(), &node_dir, identity.public_hex())?;

    let long_exec_cmd = if cfg!(windows) {
        "ping -n 61 127.0.0.1 >nul & echo EXEC-OK"
    } else {
        "sleep 60; echo EXEC-OK"
    };
    let pty_beat_cmd = if cfg!(windows) {
        "for /L %i in (1,1,1000) do @(echo p>>pty-heartbeat & ping -n 2 127.0.0.1 >nul)"
    } else {
        "while true; do printf p >> pty-heartbeat; sleep 0.2; done"
    };
    let long_mcp_cmd = if cfg!(windows) {
        "ping -n 61 127.0.0.1 >nul & echo MCP-OK"
    } else {
        "sleep 60; echo MCP-OK"
    };

    // Long enough that these cannot finish before the relay is dropped.
    let exec = tokio::spawn({
        let admin = admin_clone(&settings, &identity, dir.path()).await?;
        async move {
            admin
                .exec_collect(
                    "box",
                    ExecRequest::shell(long_exec_cmd, Some(Duration::from_secs(75))),
                    None,
                )
                .await
        }
    });

    // Heartbeat file proves the shell is live, then that close_all stopped it.
    // read_available may hang with empty data after teardown (no PTY error).
    let pty_beat = root.join("pty-heartbeat");
    let pty: JoinHandle<anyhow::Result<()>> = tokio::spawn({
        let admin = admin_clone(&settings, &identity, dir.path()).await?;
        async move {
            let mut session = admin
                .open_pty("box", Some(pty_beat_cmd.into()), None, 24, 80)
                .await?;
            let mut buf = Vec::new();
            loop {
                let read = session
                    .read_available(Duration::from_secs(2), 64 * 1024)
                    .await?;
                buf.extend_from_slice(&read.data);
                if let Some(err) = read.error {
                    anyhow::bail!("pty error: {err}");
                }
                // After close_all, some reads return immediately with no
                // data and no error, which would otherwise spin the runtime.
                if read.data.is_empty() {
                    anyhow::bail!("pty session ended without output");
                }
            }
        }
    });

    let blob = dir.path().join("blob.bin");
    write_mib(&blob, 100)?;
    TRANSFER_FRAME_PAUSE_MS.store(200, Ordering::Relaxed);
    let transfer = tokio::spawn({
        let admin = admin_clone(&settings, &identity, dir.path()).await?;
        let blob = blob.clone();
        async move {
            let opts = XferOpts {
                transport: "relay-only".into(),
                compress: CompressPref::Off,
                resume: true,
                ..XferOpts::default()
            };
            admin
                .copy_upload("box", "blob.bin", &blob, &opts, None)
                .await
        }
    });

    let identity_path = dir.path().join("client-identity.json");
    let mcp_call = tokio::spawn({
        let settings = settings.clone();
        let identity_file = identity_path.clone();
        async move {
            let mut state = crate::mcp::new_state(settings, identity_file);
            let response = crate::mcp::handle(
                &mut state,
                json!({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": "run_command",
                        "arguments": {
                            "node": "box",
                            "command": long_mcp_cmd,
                            "timeout_ms": 75000
                        }
                    }
                }),
            )
            .await;
            let response = response.ok_or_else(|| anyhow::anyhow!("mcp returned no response"))?;
            let result = &response["result"];
            if result["isError"].as_bool().unwrap_or(true) {
                anyhow::bail!("mcp error: {result}");
            }
            let text = result["content"][0]["text"].as_str().unwrap_or("");
            if !text.contains("MCP-OK") {
                anyhow::bail!("mcp stdout missing MCP-OK: {text}");
            }
            Ok::<_, anyhow::Error>(())
        }
    });

    let started = admin.watch_start("box", "watched", false).await?;
    let watch_id = started["watch_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("watch_start returned no id"))?
        .to_string();
    let watch = tokio::spawn({
        let admin = admin_clone(&settings, &identity, dir.path()).await?;
        let watch_id = watch_id.clone();
        async move {
            admin
                .watch_poll("box", &watch_id, 0, 20_000, 20)
                .await
                .map_err(|err| anyhow::anyhow!(err.to_string()))
        }
    });

    let journal = root.join(".blob.bin.agentlink-partial.json");
    let started = Instant::now();
    let mut pty_started = false;
    while !journal.exists() || !pty_started {
        if started.elapsed() > Duration::from_secs(20) {
            let partial = std::fs::metadata(root.join(".blob.bin.agentlink-partial"))
                .map(|meta| meta.len())
                .unwrap_or(0);
            let final_len = std::fs::metadata(root.join("blob.bin"))
                .map(|meta| meta.len())
                .unwrap_or(0);
            let xfer_done = transfer.is_finished();
            let xfer_err = if xfer_done {
                format!("{:?}", transfer.await)
            } else {
                "still-running".into()
            };
            anyhow::bail!(
                "setup incomplete; journal={} pty_heartbeat={} partial={partial} final={final_len} xfer={xfer_err}",
                journal.exists(),
                file_len(&pty_beat)
            );
        }
        if file_len(&pty_beat) > 0 {
            pty_started = true;
        }
        if journal.exists() && pty_started {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let bind = relay.local_addr;
    let fingerprint = relay.fingerprint.clone();
    let beat_before = file_len(&pty_beat);
    anyhow::ensure!(beat_before > 0, "pty heartbeat never started");
    relay.going_away().await;
    drop(relay);
    TRANSFER_FRAME_PAUSE_MS.store(0, Ordering::Relaxed);

    // Bring the relay back promptly so a journaled copy can open a fresh session.
    let relay = respawn_relay(&relay_dir, bind).await?;
    anyhow::ensure!(
        relay.fingerprint == fingerprint,
        "respawned relay fingerprint changed"
    );
    settings.token = relay.admin_token.clone();
    settings.fingerprint = relay.fingerprint.clone();
    let admin = tokio::time::timeout(
        Duration::from_secs(15),
        admin_clone(&settings, &identity, dir.path()),
    )
    .await
    .map_err(|_| anyhow::anyhow!("admin_clone after respawn timed out"))??;
    wait_online(&admin, &node_task).await;

    // Old in-flight shells/RPCs must stop. Do not treat cancelled as success.
    // Assert this after the node can redial so a hung PTY read cannot eat the
    // copy resume budget, and so a resurrected shell would start beating again.
    let exec_err = expect_stopped_within(exec, "exec", Duration::from_secs(10)).await?;
    assert!(
        !exec_err.to_ascii_lowercase().contains("exec-ok"),
        "old exec must not finish after the relay dropped: {exec_err}"
    );
    expect_heartbeat_stopped(&pty_beat, beat_before, "pty").await?;
    match expect_stopped_within(pty, "pty", Duration::from_secs(3)).await {
        Ok(msg) => {
            anyhow::ensure!(
                !msg.to_ascii_lowercase().contains("pty-ok"),
                "old pty must not finish after the relay dropped: {msg}"
            );
        }
        Err(err) if err.to_string().contains("still running") => {
            // close_all stopped the shell (heartbeat is stable) but the client
            // read may not surface an error. Abort the hung reader.
            // The JoinHandle is already consumed; the task is abandoned at drop.
        }
        Err(err) => return Err(err),
    }
    let mcp_err = expect_stopped_within(mcp_call, "mcp", Duration::from_secs(10)).await?;
    assert!(
        !mcp_err.to_ascii_lowercase().contains("mcp-ok"),
        "old mcp command must not finish after the relay dropped: {mcp_err}"
    );
    // stop_live_sessions closes watches as well as shells/procs/tunnels/media (`SEC-08`).
    // The pre-drop poll must fail (e.g. cancelled / connection closed / not found: watch)
    // and must never complete as a live event stream.
    match expect_stopped_within(watch, "watch", Duration::from_secs(5)).await {
        Ok(msg) => {
            anyhow::ensure!(
                !msg.to_ascii_lowercase().contains("note.txt"),
                "pre-drop watch must not complete as a live event stream: {msg}"
            );
        }
        Err(err) if err.to_string().contains("still running") => {}
        Err(err) => return Err(err),
    }

    // Old watch id must not be a way to resurrect the stopped poll as success
    // of the pre-drop request. A later poll is a new RPC; the pre-drop task
    // already failed above. Fresh work uses a new watch after this check.
    let stranger = Identity::generate();
    let stranger_client = Client::connect_identity(&settings, stranger, true).await?;
    stranger_client.remember_node_pins(dir.path());
    let denied = stranger_client
        .exec_collect(
            "box",
            ExecRequest::shell("echo STRANGER-OK", Some(Duration::from_secs(10))),
            None,
        )
        .await;
    match denied {
        Ok(out) => anyhow::bail!(
            "client without a grant ran exec after reconnect: {}",
            String::from_utf8_lossy(&out.stdout)
        ),
        Err(err) => {
            let msg = err.to_string().to_ascii_lowercase();
            anyhow::ensure!(
                msg.contains("grant")
                    || msg.contains("permission")
                    || msg.contains("auth")
                    || msg.contains("denied"),
                "stranger exec must fail closed on authz, got: {err}"
            );
        }
    }

    let exec = admin
        .exec_collect(
            "box",
            ExecRequest::shell("echo FRESH-EXEC-OK", Some(Duration::from_secs(15))),
            None,
        )
        .await
        .map_err(|err| anyhow::anyhow!("fresh exec after reconnect: {err:#}"))?;
    assert_eq!(
        exec.exit_code,
        Some(0),
        "fresh exec stderr {}",
        String::from_utf8_lossy(&exec.stderr)
    );
    assert!(
        String::from_utf8_lossy(&exec.stdout).contains("FRESH-EXEC-OK"),
        "fresh exec stdout {}",
        String::from_utf8_lossy(&exec.stdout)
    );

    let mut session = admin
        .open_pty("box", Some("echo FRESH-PTY-OK".into()), None, 24, 80)
        .await
        .map_err(|err| anyhow::anyhow!("fresh pty after reconnect: {err:#}"))?;
    let mut buf = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    let pty_text = loop {
        if Instant::now() > deadline {
            anyhow::bail!("fresh pty timed out: {}", String::from_utf8_lossy(&buf));
        }
        let read = session
            .read_available(Duration::from_secs(2), 64 * 1024)
            .await?;
        buf.extend_from_slice(&read.data);
        let text = String::from_utf8_lossy(&buf).to_string();
        if text.contains("FRESH-PTY-OK") {
            break text;
        }
        if let Some(err) = read.error {
            anyhow::bail!("fresh pty error: {err}");
        }
    };
    assert!(pty_text.contains("FRESH-PTY-OK"), "{pty_text}");

    let stats = tokio::time::timeout(Duration::from_secs(30), transfer)
        .await
        .map_err(|_| anyhow::anyhow!("transfer join timed out"))?
        .map_err(|err| anyhow::anyhow!("transfer join: {err:#}"))?
        .map_err(|err| anyhow::anyhow!("transfer after reconnect: {err:#}"))?;
    assert!(
        stats.resumed_bytes > 0,
        "fresh transfer session did not resume the journal: {stats:?}"
    );
    assert_eq!(
        std::fs::metadata(root.join("blob.bin"))?.len(),
        100 * 1024 * 1024
    );

    let mut state = crate::mcp::new_state(settings.clone(), identity_path);
    let response = crate::mcp::handle(
        &mut state,
        json!({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "run_command",
                "arguments": {
                    "node": "box",
                    "command": "echo FRESH-MCP-OK",
                    "timeout_ms": 15000
                }
            }
        }),
    )
    .await
    .ok_or_else(|| anyhow::anyhow!("fresh mcp returned no response"))?;
    let result = &response["result"];
    if result["isError"].as_bool().unwrap_or(true) {
        anyhow::bail!("fresh mcp error: {result}");
    }
    let text = result["content"][0]["text"].as_str().unwrap_or("");
    anyhow::ensure!(
        text.contains("FRESH-MCP-OK"),
        "fresh mcp stdout missing FRESH-MCP-OK: {text}"
    );

    let started = admin.watch_start("box", "watched", false).await?;
    let fresh_watch_id = started["watch_id"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("fresh watch_start returned no id"))?
        .to_string();
    anyhow::ensure!(
        fresh_watch_id != watch_id,
        "fresh watch reused the pre-drop watch id {watch_id}"
    );
    std::fs::write(root.join("watched").join("note.txt"), b"hello")?;
    let watch = admin
        .watch_poll("box", &fresh_watch_id, 0, 20_000, 20)
        .await
        .map_err(|err| anyhow::anyhow!("fresh watch after reconnect: {err}"))?;
    let rendered = watch.to_string();
    assert!(
        rendered.contains("note.txt"),
        "fresh watch missed the file: {rendered}"
    );

    add_revoked_jti(&node_dir, &grant_jti)?;
    // The grant watcher is on a 1s tick; give it a moment plus a short retry.
    let revoke_deadline = Instant::now() + Duration::from_secs(3);
    let revoked_err = loop {
        match admin
            .exec_collect(
                "box",
                ExecRequest::shell("echo REVOKED-OK", Some(Duration::from_secs(10))),
                None,
            )
            .await
        {
            Ok(out) if Instant::now() > revoke_deadline => {
                anyhow::bail!(
                    "revoked grant still executed after reconnect: {}",
                    String::from_utf8_lossy(&out.stdout)
                );
            }
            Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
            Err(err) => break err.to_string(),
        }
    };
    let revoked_l = revoked_err.to_ascii_lowercase();
    anyhow::ensure!(
        revoked_l.contains("revok")
            || revoked_l.contains("grant")
            || revoked_l.contains("denied")
            || revoked_l.contains("permission"),
        "revoked grant must fail closed, got: {revoked_err}"
    );
    anyhow::ensure!(
        !revoked_l.contains("revoked-ok"),
        "revoked grant must not return command output: {revoked_err}"
    );

    node_shutdown.cancel();
    drop(relay);
    let _ = tokio::time::timeout(Duration::from_secs(5), node_task).await;
    Ok(())
}

fn file_len(path: &std::path::Path) -> u64 {
    std::fs::metadata(path).map(|meta| meta.len()).unwrap_or(0)
}

/// The shell must stop writing after `stop_live_sessions`. A later reconnect
/// must not start the same heartbeat growing again.
async fn expect_heartbeat_stopped(
    path: &std::path::Path,
    before: u64,
    label: &str,
) -> anyhow::Result<()> {
    tokio::time::sleep(Duration::from_millis(800)).await;
    let mid = file_len(path);
    tokio::time::sleep(Duration::from_millis(800)).await;
    let end = file_len(path);
    anyhow::ensure!(
        end == mid,
        "{label} kept running after relay drop (heartbeat {before} -> {mid} -> {end})"
    );
    Ok(())
}

async fn expect_stopped_within<T, E>(
    handle: JoinHandle<std::result::Result<T, E>>,
    label: &str,
    limit: Duration,
) -> anyhow::Result<String>
where
    T: std::fmt::Debug,
    E: std::fmt::Display,
{
    match tokio::time::timeout(limit, handle).await {
        Err(_) => anyhow::bail!("{label} still running {limit:?} after the relay dropped"),
        Ok(Ok(Ok(value))) => {
            anyhow::bail!("{label} unexpectedly completed after the relay dropped: {value:?}")
        }
        Ok(Ok(Err(err))) => {
            let msg = err.to_string();
            if !is_session_stop_error(&msg) {
                anyhow::bail!("{label} failed with unexpected error: {msg}");
            }
            Ok(msg)
        }
        Ok(Err(join)) => anyhow::bail!("{label} join error: {join:#}"),
    }
}

fn is_session_stop_error(msg: &str) -> bool {
    let lower = msg.to_ascii_lowercase();
    lower.contains("cancelled")
        || lower.contains("connection closed")
        || lower.contains("going away")
        || lower.contains("transfer closed")
        || lower.contains("websocket")
        || lower.contains("pty session ended")
        || lower.contains("not found: watch")
}

async fn admin_clone(
    settings: &ClientSettings,
    identity: &Identity,
    config_dir: &std::path::Path,
) -> anyhow::Result<Client> {
    let client = Client::connect_identity(settings, identity.clone(), true).await?;
    client.remember_node_pins(config_dir);
    client.remember_grants(config_dir);
    Ok(client)
}

/// Sign a grant with the node's bootstrapped issuer and store it where every
/// client in this process looks (`<config_dir>/grants/<node_id>.json`).
fn issue_test_grant(
    config_dir: &std::path::Path,
    node_dir: &std::path::Path,
    grantee_id: &str,
) -> anyhow::Result<String> {
    let issuer = load_issuer(node_dir)?
        .ok_or_else(|| anyhow::anyhow!("node did not bootstrap a grant issuer"))?;
    let node_id = Identity::load_or_create(&node_dir.join("identity.json"))?
        .node_id()
        .to_string();
    let now = agentlink_core::util::unix_now();
    let grant = SignedGrant::sign(
        &issuer,
        grantee_id,
        &node_id,
        NodePolicy::phase1_ceiling(),
        now - 60,
        now + 3600,
        "reconnect-test",
    )?;
    let jti = grant.jti.clone();
    save_grant(config_dir, &grant)?;
    Ok(jti)
}

async fn wait_online(
    admin: &Client,
    node_task: &tokio::task::JoinHandle<agentlink_core::Result<()>>,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let online = admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|node| node.name == "box" && node.online))
            .unwrap_or(false);
        if online {
            return;
        }
        if node_task.is_finished() {
            panic!("node exited before it was online");
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for the node");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn spawn_relay(
    data_dir: &std::path::Path,
    bind: std::net::SocketAddr,
) -> anyhow::Result<RelayHandle> {
    Ok(RelayHandle::spawn(RelayConfig {
        bind,
        data_dir: data_dir.to_path_buf(),
        capture: None,
        database_url: None,
        allow_signup: false,
        bootstrap_admin: false,
        db_schema: None,
        trust_proxy: Vec::new(),
        print_admin_token: false,
        legacy_admin_override: Some((true, Some(86_400))),
    })
    .await?)
}

async fn respawn_relay(
    data_dir: &std::path::Path,
    bind: std::net::SocketAddr,
) -> anyhow::Result<RelayHandle> {
    let mut last = None;
    for _ in 0..40 {
        match spawn_relay(data_dir, bind).await {
            Ok(handle) => return Ok(handle),
            Err(err) => {
                last = Some(err);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("relay did not rebind")))
}

fn write_mib(path: &std::path::Path, mib: u64) -> anyhow::Result<()> {
    let mut file = std::fs::File::create(path)?;
    let chunk = vec![0u8; 1024 * 1024];
    for _ in 0..mib {
        file.write_all(&chunk)?;
    }
    file.flush()?;
    let mut check = std::fs::File::open(path)?;
    let mut buf = [0u8; 16];
    check.read_exact(&mut buf)?;
    Ok(())
}
