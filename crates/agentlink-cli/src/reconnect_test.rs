//! A relay restart in the middle of live work must not surface as an error.

use std::io::{Read, Write};
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use agentlink_core::engine::{XferOpts, TRANSFER_FRAME_PAUSE_MS};
use agentlink_core::grant::{load_issuer, save_grant, SignedGrant};
use agentlink_core::protocol::CompressPref;
use agentlink_core::{Client, ClientSettings, ExecRequest, Identity, NodePolicy};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use serde_json::json;
use tokio_util::sync::CancellationToken;

struct PauseGuard;

impl Drop for PauseGuard {
    fn drop(&mut self) {
        TRANSFER_FRAME_PAUSE_MS.store(0, Ordering::Relaxed);
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
    let settings = ClientSettings {
        relay: relay_url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    };
    // Every client in this test shares one identity so a single grant covers
    // them; grant files are keyed by node id, not by client.
    let identity = Identity::load_or_create(&dir.path().join("client-identity.json"))?;
    let admin = Client::connect_identity(&settings, identity.clone(), true).await?;
    admin.remember_node_pins(dir.path());
    admin.remember_grants(dir.path());
    let pairing = admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let node_shutdown = CancellationToken::new();
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
    issue_test_grant(dir.path(), &node_dir, identity.public_hex())?;

    let exec = tokio::spawn({
        let admin = admin_clone(&settings, &identity, dir.path()).await?;
        async move {
            admin
                .exec_collect(
                    "box",
                    ExecRequest::shell("sleep 3; echo EXEC-OK", Some(Duration::from_secs(30))),
                    None,
                )
                .await
        }
    });

    let pty = tokio::spawn({
        let admin = admin_clone(&settings, &identity, dir.path()).await?;
        async move {
            let mut session = admin
                .open_pty("box", Some("sleep 3; echo PTY-OK".into()), None, 24, 80)
                .await?;
            let mut buf = Vec::new();
            let deadline = Instant::now() + Duration::from_secs(40);
            loop {
                if Instant::now() > deadline {
                    anyhow::bail!("pty timed out: {}", String::from_utf8_lossy(&buf));
                }
                let read = session
                    .read_available(Duration::from_secs(2), 64 * 1024)
                    .await?;
                buf.extend_from_slice(&read.data);
                let text = String::from_utf8_lossy(&buf);
                if text.contains("PTY-OK") {
                    return Ok::<_, anyhow::Error>(text.to_string());
                }
                if let Some(err) = read.error {
                    anyhow::bail!("pty error: {err}");
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
                            "command": "sleep 3; echo MCP-OK",
                            "timeout_ms": 30000
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
        async move {
            admin
                .watch_poll("box", &watch_id, 0, 20_000, 20)
                .await
                .map_err(|err| anyhow::anyhow!(err.to_string()))
        }
    });

    let journal = root.join(".blob.bin.agentlink-partial.json");
    let started = Instant::now();
    while !journal.exists() {
        if started.elapsed() > Duration::from_secs(20) {
            let partial = std::fs::metadata(root.join(".blob.bin.agentlink-partial"))
                .map(|meta| meta.len())
                .unwrap_or(0);
            anyhow::bail!("transfer journal was not written; partial={partial} bytes");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let bind = relay.local_addr;
    relay.going_away().await;
    drop(relay);
    TRANSFER_FRAME_PAUSE_MS.store(0, Ordering::Relaxed);
    let relay = respawn_relay(&relay_dir, bind).await?;

    tokio::time::sleep(Duration::from_millis(300)).await;
    std::fs::write(root.join("watched").join("note.txt"), b"hello")?;

    let exec = exec.await??;
    assert_eq!(
        exec.exit_code,
        Some(0),
        "exec stderr {}",
        String::from_utf8_lossy(&exec.stderr)
    );
    assert!(
        String::from_utf8_lossy(&exec.stdout).contains("EXEC-OK"),
        "stdout {}",
        String::from_utf8_lossy(&exec.stdout)
    );

    let pty = pty.await??;
    assert!(pty.contains("PTY-OK"), "{pty}");

    let stats = transfer.await??;
    assert!(
        stats.resumed_bytes > 0,
        "transfer did not resume: {stats:?}"
    );
    assert_eq!(
        std::fs::metadata(root.join("blob.bin"))?.len(),
        100 * 1024 * 1024
    );

    mcp_call.await??;

    let watch = watch.await??;
    let rendered = watch.to_string();
    assert!(
        rendered.contains("note.txt"),
        "watch missed the file: {rendered}"
    );

    node_shutdown.cancel();
    drop(relay);
    let _ = tokio::time::timeout(Duration::from_secs(5), node_task).await;
    Ok(())
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
) -> anyhow::Result<()> {
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
    save_grant(config_dir, &grant)?;
    Ok(())
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
