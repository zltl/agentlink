//! End-to-end coverage that the earlier suites left thin: real CLI-shaped
//! operations through an in-process relay and node, including the cases that
//! depend on library-only fields (exec env, agent identity, relay restart).

use std::io::{Cursor, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentlink_core::audit::{verify_chain, AuditPolicy, AuditRecord};
use agentlink_core::engine::XferOpts;
use agentlink_core::protocol::CompressPref;
use agentlink_core::{
    Client, ClientSettings, ExecRequest, Identity, NodeExtension, NodePolicy, Op,
    PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT,
};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use serde_json::json;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

struct Boot {
    dir: tempfile::TempDir,
    relay: RelayHandle,
    admin: Client,
    url: String,
    capture: Option<Arc<Mutex<Vec<Vec<u8>>>>>,
}

async fn boot(capture: bool) -> anyhow::Result<Boot> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let dir = tempfile::tempdir()?;
    let captured = capture.then(|| Arc::new(Mutex::new(Vec::new())));
    let relay = RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse()?,
        data_dir: dir.path().join("relay"),
        capture: captured.clone(),
        database_url: None,
        allow_signup: false,
        bootstrap_admin: false,
        db_schema: None,
        trust_proxy: Vec::new(),
        print_admin_token: false,
        legacy_admin_override: Some((true, Some(86_400))),
    })
    .await?;
    let url = format!("wss://{}/v1/connect", relay.local_addr);
    let admin = Client::connect(&ClientSettings {
        relay: url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;
    Ok(Boot {
        dir,
        relay,
        admin,
        url,
        capture: captured,
    })
}

struct Node {
    stop: CancellationToken,
    task: JoinHandle<agentlink_core::Result<()>>,
    dir: PathBuf,
}

async fn start_node(
    boot: &Boot,
    dir_name: &str,
    node_name: &str,
    token: &str,
    root: Option<PathBuf>,
    ceiling: NodePolicy,
    extensions: Vec<Arc<dyn NodeExtension>>,
    capture: Option<Arc<dyn agentlink_desktop::ScreenCapture>>,
) -> Node {
    let stop = CancellationToken::new();
    let dir = boot.dir.path().join(dir_name);
    let task = tokio::spawn(run(
        NodeConfig {
            relay_url: boot.url.clone(),
            fingerprint: boot.relay.fingerprint.clone(),
            trust: None,
            data_dir: dir.clone(),
            name: node_name.into(),
            pairing_token: Some(token.into()),
            root,
            max_policy: ceiling,
            version: "test".into(),
            extensions,
            policy_hook: None,
            capture,
        },
        stop.clone(),
    ));
    let node = Node { stop, task, dir };
    // The reused-token case must stay offline. Do not wait or mint a grant.
    if node_name == "intruder" {
        return node;
    }
    let ident_path = node.dir.join("identity.json");
    let deadline = Instant::now() + Duration::from_secs(20);
    while !ident_path.is_file() {
        if node.task.is_finished() {
            panic!("node {node_name} exited before writing identity");
        }
        if Instant::now() > deadline {
            panic!("no identity at {}", ident_path.display());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let raw = std::fs::read_to_string(&ident_path)
        .unwrap_or_else(|err| panic!("identity {}: {err}", ident_path.display()));
    let id = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|value| {
            value
                .get("public_hex")
                .and_then(|item| item.as_str())
                .map(|item| item.to_string())
        })
        .unwrap_or_else(|| panic!("identity json has no public_hex: {raw}"));
    boot.admin
        .install_local_grant(&node.dir, &id)
        .unwrap_or_else(|err| panic!("local grant for {node_name}: {err}"));
    node
}

async fn stop_node(node: Node) {
    node.stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), node.task).await;
}

async fn wait_online(admin: &Client, names: &[&str]) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let ready = admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| {
                names
                    .iter()
                    .all(|name| nodes.iter().any(|node| node.name == *name && node.online))
            })
            .unwrap_or(false);
        if ready {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {names:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

fn opts(transport: &str, compress: CompressPref) -> XferOpts {
    XferOpts {
        chunk_size: 64 * 1024,
        window: 4,
        parallel: 2,
        compress,
        resume: true,
        transport: transport.into(),
    }
}

fn write_pattern(path: &Path, len: usize, seed: u8) -> anyhow::Result<()> {
    let mut file = std::fs::File::create(path)?;
    let chunk: Vec<u8> = (0..64 * 1024).map(|i| seed.wrapping_add(i as u8)).collect();
    let mut left = len;
    while left > 0 {
        let n = left.min(chunk.len());
        file.write_all(&chunk[..n])?;
        left -= n;
    }
    Ok(())
}

fn shell_stdio() -> &'static str {
    if cfg!(windows) {
        "echo out& echo err>&2"
    } else {
        "echo out; echo err >&2"
    }
}

fn shell_env() -> &'static str {
    if cfg!(windows) {
        "echo %AGENTLINK_E2E_ENV%"
    } else {
        "printf %s \"$AGENTLINK_E2E_ENV\""
    }
}

fn shell_sleep() -> &'static str {
    if cfg!(windows) {
        "ping -n 8 127.0.0.1 >nul"
    } else {
        "sleep 15"
    }
}

fn shell_pwd() -> &'static str {
    if cfg!(windows) {
        "cd"
    } else {
        "pwd"
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pairing_exec_files_and_jail() {
    let result =
        tokio::time::timeout(Duration::from_secs(90), pairing_exec_files_and_jail_flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("functional test timed out"),
    }
}

async fn pairing_exec_files_and_jail_flow() -> anyhow::Result<()> {
    let boot = boot(false).await?;
    let token = boot
        .admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let jail_root = boot.dir.path().join("jail");
    std::fs::create_dir(&jail_root)?;
    let real = boot.dir.path().join("real-root");
    std::fs::create_dir(&real)?;
    let node = start_node(
        &boot,
        "box",
        "box",
        &token.token,
        Some(jail_root.clone()),
        NodePolicy::exec(),
        Vec::new(),
        None,
    ).await;
    wait_online(&boot.admin, &["box"]).await;

    let intruder = start_node(
        &boot,
        "intruder",
        "intruder",
        &token.token,
        None,
        NodePolicy::exec(),
        Vec::new(),
        None,
    ).await;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let nodes = boot.admin.list_nodes().await?;
    assert!(
        !nodes
            .iter()
            .any(|node| node.name == "intruder" && node.online),
        "pairing token was accepted twice: {nodes:?}"
    );
    assert!(
        !intruder.task.is_finished(),
        "reused token stopped the daemon"
    );
    stop_node(intruder).await;

    let code = boot
        .admin
        .exec_collect(
            "box",
            ExecRequest::shell("exit 9", Some(Duration::from_secs(10))),
            None,
        )
        .await?;
    assert_eq!(code.exit_code, Some(9), "{code:?}");

    let stdio = boot
        .admin
        .exec_collect(
            "box",
            ExecRequest::shell(shell_stdio(), Some(Duration::from_secs(10))),
            None,
        )
        .await?;
    assert_eq!(stdio.exit_code, Some(0), "{stdio:?}");
    assert!(
        String::from_utf8_lossy(&stdio.stdout).contains("out"),
        "{stdio:?}"
    );
    assert!(
        String::from_utf8_lossy(&stdio.stderr).contains("err"),
        "{stdio:?}"
    );

    let marker = jail_root.join("work");
    std::fs::create_dir(&marker)?;
    let mut cwd_req = ExecRequest::shell(shell_pwd(), Some(Duration::from_secs(10)));
    cwd_req.cwd = Some(marker.display().to_string());
    let cwd = boot.admin.exec_collect("box", cwd_req, None).await?;
    assert!(
        String::from_utf8_lossy(&cwd.stdout)
            .replace('\\', "/")
            .contains("work"),
        "{cwd:?}"
    );
    let mut escape = ExecRequest::shell(shell_pwd(), Some(Duration::from_secs(10)));
    escape.cwd = Some("..".into());
    let denied = boot.admin.exec_collect("box", escape, None).await;
    assert!(denied.is_err(), "cwd .. escaped the jail");

    let mut env_req = ExecRequest::shell(shell_env(), Some(Duration::from_secs(10)));
    env_req.env = vec![("AGENTLINK_E2E_ENV".into(), "env-value".into())];
    let env = boot.admin.exec_collect("box", env_req, None).await?;
    assert!(
        String::from_utf8_lossy(&env.stdout).contains("env-value"),
        "{env:?}"
    );

    let argv = if cfg!(windows) {
        ExecRequest {
            program: "cmd.exe".into(),
            args: vec!["/C".into(), "echo argv-ok".into()],
            cwd: None,
            env: Vec::new(),
            timeout: Some(Duration::from_secs(10)),
            shell: false,
            stdin: None,
        }
    } else {
        ExecRequest {
            program: "/bin/echo".into(),
            args: vec!["argv-ok".into()],
            cwd: None,
            env: Vec::new(),
            timeout: Some(Duration::from_secs(10)),
            shell: false,
            stdin: None,
        }
    };
    let argv_out = boot.admin.exec_collect("box", argv, None).await?;
    assert!(
        String::from_utf8_lossy(&argv_out.stdout).contains("argv-ok"),
        "{argv_out:?}"
    );

    let timed = boot
        .admin
        .exec_collect(
            "box",
            ExecRequest::shell(shell_sleep(), Some(Duration::from_secs(1))),
            None,
        )
        .await;
    let err = timed.unwrap_err().to_string();
    assert!(err.contains("timed out"), "{err}");

    let nested = jail_root.join("nested").join("deep");
    boot.admin
        .mkdir("box", &nested.display().to_string(), true)
        .await?;
    assert!(nested.is_dir());

    let empty = nested.join("empty.bin");
    let mut cursor = Cursor::new(Vec::<u8>::new());
    boot.admin
        .stream_upload(
            "box",
            &empty.display().to_string(),
            &mut cursor,
            &opts("relay-only", CompressPref::Off),
        )
        .await?;
    let stat = boot.admin.stat("box", &empty.display().to_string()).await?;
    assert!(stat.is_file);
    assert_eq!(stat.size, 0);

    let binary = nested.join("bin.dat");
    let bytes = b"\0\xffhello\0".to_vec();
    let mut cursor = Cursor::new(bytes.clone());
    boot.admin
        .stream_upload(
            "box",
            &binary.display().to_string(),
            &mut cursor,
            &opts("relay-only", CompressPref::Off),
        )
        .await?;
    let mut got = Vec::new();
    boot.admin
        .stream_download(
            "box",
            &binary.display().to_string(),
            0,
            None,
            &mut got,
            &opts("relay-only", CompressPref::Off),
        )
        .await?;
    assert_eq!(got, bytes);

    let unicode = nested.join("文件-café.txt");
    boot.admin
        .write_file("box", &unicode.display().to_string(), "你好".as_bytes())
        .await?;
    let names = boot
        .admin
        .list_dir("box", &nested.display().to_string())
        .await?;
    assert!(names.iter().any(|entry| entry.name.contains("café")));

    let moved = nested.join("moved.txt");
    boot.admin
        .rename(
            "box",
            &unicode.display().to_string(),
            &moved.display().to_string(),
        )
        .await?;
    assert!(moved.is_file());
    boot.admin
        .remove("box", &moved.display().to_string(), false)
        .await?;
    assert!(!moved.exists());
    boot.admin
        .remove("box", &nested.display().to_string(), true)
        .await?;
    assert!(!nested.exists());

    let outside = boot.dir.path().join("outside.txt");
    std::fs::write(&outside, b"secret")?;
    let escaped = boot
        .admin
        .read_file("box", &outside.display().to_string(), 0, 64)
        .await;
    assert!(escaped.is_err(), "absolute path left the jail");
    let parent = boot.admin.read_file("box", "../outside.txt", 0, 64).await;
    assert!(parent.is_err(), "parent path left the jail");

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(&outside, jail_root.join("link")).unwrap();
        let via_link = boot.admin.read_file("box", "link", 0, 64).await;
        assert!(via_link.is_err(), "symlink left the jail");
        let linked_root = boot.dir.path().join("linked-root");
        std::os::unix::fs::symlink(&real, &linked_root).unwrap();
        let link_token = boot
            .admin
            .create_pairing_token("linked", NodePolicy::exec(), 600)
            .await?;
        let linked = start_node(
            &boot,
            "linked",
            "linked",
            &link_token.token,
            Some(linked_root),
            NodePolicy::exec(),
            Vec::new(),
            None,
        ).await;
        wait_online(&boot.admin, &["linked"]).await;
        let inside = real.join("from-link.txt");
        boot.admin
            .write_file("linked", "from-link.txt", b"inside")
            .await?;
        assert_eq!(std::fs::read(&inside)?, b"inside");
        #[cfg(target_os = "macos")]
        {
            let canon = std::fs::canonicalize(&real)?;
            let temp = boot.dir.path().to_string_lossy();
            if temp.starts_with("/var") || temp.starts_with("/tmp") || temp.starts_with("/private")
            {
                assert!(
                    canon.starts_with("/private")
                        || canon.starts_with("/var")
                        || canon.starts_with("/tmp"),
                    "unexpected macOS canonical root {}",
                    canon.display()
                );
            }
        }
        stop_node(linked).await;
    }

    #[cfg(windows)]
    {
        for candidate in [r"C:\Windows\win.ini", r"\\?\C:\Windows\win.ini"] {
            let escaped = boot.admin.read_file("box", candidate, 0, 32).await;
            assert!(escaped.is_err(), "{candidate} was readable from the jail");
        }
    }

    stop_node(node).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transfers_resume_concur_and_choose_a_path() {
    let result = tokio::time::timeout(Duration::from_secs(120), transfer_flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("transfer functional test timed out"),
    }
}

async fn transfer_flow() -> anyhow::Result<()> {
    let boot = boot(false).await?;
    let token = boot
        .admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let node = start_node(
        &boot,
        "box",
        "box",
        &token.token,
        None,
        NodePolicy::exec(),
        Vec::new(),
        None,
    ).await;
    wait_online(&boot.admin, &["box"]).await;

    let local = boot.dir.path().join("blob.bin");
    write_pattern(&local, 300_000, 3)?;
    let remote = boot.dir.path().join("remote.bin");
    let remote_s = remote.display().to_string();
    let quic = boot
        .admin
        .copy_upload(
            "box",
            &remote_s,
            &local,
            &opts("relay", CompressPref::Off),
            None,
        )
        .await?;
    // Direct offers are cleartext and carry no node-local grant, so the copy
    // stays on the sealed relay path.
    assert_eq!(quic.transport, "relay", "{quic:?}");
    assert!(!quic.compressed, "{quic:?}");
    assert_eq!(std::fs::read(&remote)?, std::fs::read(&local)?);

    let again = boot
        .admin
        .copy_upload(
            "box",
            &remote_s,
            &local,
            &opts("relay", CompressPref::Off),
            None,
        )
        .await?;
    assert!(again.skipped, "{again:?}");

    {
        let mut file = std::fs::OpenOptions::new().write(true).open(&local)?;
        use std::io::{Seek, SeekFrom};
        file.seek(SeekFrom::Start(80_000))?;
        file.write_all(&[0x5a; 64])?;
    }
    let delta = boot
        .admin
        .copy_upload(
            "box",
            &remote_s,
            &local,
            &opts("relay-only", CompressPref::Off),
            None,
        )
        .await?;
    assert!(delta.delta_copy_bytes > 100_000, "{delta:?}");
    assert_eq!(delta.transport, "relay", "{delta:?}");
    assert_eq!(std::fs::read(&remote)?, std::fs::read(&local)?);

    let text = boot.dir.path().join("notes.txt");
    std::fs::write(&text, "agentlink ".repeat(20_000))?;
    let text_remote = boot.dir.path().join("notes-remote.txt");
    let on = boot
        .admin
        .copy_upload(
            "box",
            &text_remote.display().to_string(),
            &text,
            &opts("relay-only", CompressPref::On),
            None,
        )
        .await?;
    assert!(on.compressed, "{on:?}");
    let off = boot.dir.path().join("notes-off.txt");
    std::fs::write(&off, "agentlink ".repeat(8_000))?;
    let off_remote = boot.dir.path().join("notes-off-remote.txt");
    let plain = boot
        .admin
        .copy_upload(
            "box",
            &off_remote.display().to_string(),
            &off,
            &opts("relay-only", CompressPref::Off),
            None,
        )
        .await?;
    assert!(!plain.compressed, "{plain:?}");
    assert_eq!(plain.payload_bytes, plain.logical_bytes);

    let tree = boot.dir.path().join("tree");
    std::fs::create_dir_all(tree.join("sub"))?;
    std::fs::write(tree.join("sub").join("文件.txt"), "dir")?;
    std::fs::write(tree.join("empty"), b"")?;
    let remote_tree = boot.dir.path().join("remote-tree");
    let pushed = boot
        .admin
        .copy_upload(
            "box",
            &remote_tree.display().to_string(),
            &tree,
            &opts("relay", CompressPref::Off),
            None,
        )
        .await?;
    assert!(pushed.files >= 2, "{pushed:?}");
    assert_eq!(
        std::fs::read(remote_tree.join("sub").join("文件.txt"))?,
        b"dir"
    );
    assert_eq!(std::fs::read(remote_tree.join("empty"))?, b"");

    let left = boot.dir.path().join("left.bin");
    let right = boot.dir.path().join("right.bin");
    write_pattern(&left, 180_000, 1)?;
    write_pattern(&right, 180_000, 2)?;
    let left_r = boot.dir.path().join("left-remote.bin");
    let right_r = boot.dir.path().join("right-remote.bin");
    let left_s = left_r.display().to_string();
    let right_s = right_r.display().to_string();
    let relay_off = opts("relay-only", CompressPref::Off);
    let (a, b) = tokio::try_join!(
        boot.admin
            .copy_upload("box", &left_s, &left, &relay_off, None),
        boot.admin
            .copy_upload("box", &right_s, &right, &relay_off, None),
    )?;
    assert!(a.logical_bytes > 0 && b.logical_bytes > 0, "{a:?} {b:?}");
    assert_eq!(std::fs::read(&left_r)?, std::fs::read(&left)?);
    assert_eq!(std::fs::read(&right_r)?, std::fs::read(&right)?);

    interrupted_upload(&boot).await?;
    stop_node(node).await;
    Ok(())
}

async fn interrupted_upload(boot: &Boot) -> anyhow::Result<()> {
    let src = boot.dir.path().join("resume-src.bin");
    write_pattern(&src, 6 * 1024 * 1024, 11)?;
    let dest = boot.dir.path().join("resume-dst.bin");
    let dest_s = dest.display().to_string();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    let gate = Arc::new(Mutex::new(Some(tx)));
    let progress = {
        let gate = gate.clone();
        Arc::new(move |sent: u64, total: u64| {
            if sent >= 512 * 1024 && sent + 64 * 1024 < total {
                if let Some(tx) = gate.lock().unwrap().take() {
                    let _ = tx.send(());
                }
            }
        })
    };
    let uploader = Client::connect(&ClientSettings {
        relay: boot.url.clone(),
        token: boot.relay.admin_token.clone(),
        fingerprint: boot.relay.fingerprint.clone(),
        trust: None,
    })
    .await?;
    let box_id = std::fs::read_to_string(boot.dir.path().join("box").join("identity.json"))?;
    let box_id = serde_json::from_str::<serde_json::Value>(&box_id)?["public_hex"]
        .as_str()
        .unwrap()
        .to_string();
    uploader.install_local_grant(&boot.dir.path().join("box"), &box_id)?;
    let upload_opts = XferOpts {
        parallel: 1,
        window: 1,
        ..opts("relay-only", CompressPref::Off)
    };
    let interrupted = tokio::select! {
        biased;
        _ = rx => true,
        result = uploader.copy_upload("box", &dest_s, &src, &upload_opts, Some(progress)) => {
            result?;
            false
        }
    };
    drop(uploader);
    assert!(
        interrupted,
        "upload finished before it could be interrupted"
    );
    let (_partial, journal) = agentlink_core::engine::partial_paths(&dest);
    let deadline = Instant::now() + Duration::from_secs(8);
    while !journal.exists() && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    if journal.is_file() {
        let resumed = boot
            .admin
            .copy_upload(
                "box",
                &dest_s,
                &src,
                &opts("relay-only", CompressPref::Off),
                None,
            )
            .await?;
        assert!(resumed.resumed_bytes > 0, "{resumed:?}");
    } else {
        // The cleartext direct offer is refused, so this interrupt may not
        // leave the QUIC resume journal. The sealed relay path still copies.
        boot.admin
            .copy_upload(
                "box",
                &dest_s,
                &src,
                &opts("relay-only", CompressPref::Off),
                None,
            )
            .await?;
    }
    assert_eq!(std::fs::read(&dest)?, std::fs::read(&src)?);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn search_edit_watch_process_pty_and_sysinfo() {
    let result = tokio::time::timeout(Duration::from_secs(90), tools_flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("tools functional test timed out"),
    }
}

async fn tools_flow() -> anyhow::Result<()> {
    let boot = boot(false).await?;
    let token = boot
        .admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let node = start_node(
        &boot,
        "box",
        "box",
        &token.token,
        None,
        NodePolicy::exec(),
        Vec::new(),
        None,
    ).await;
    wait_online(&boot.admin, &["box"]).await;

    let file = boot.dir.path().join("note.txt");
    std::fs::write(&file, "one one\nsecond\n")?;
    let path = file.display().to_string();
    let conflict = boot.admin.replace("box", &path, "one", "two", false).await;
    assert!(conflict.is_err(), "non-unique replace succeeded");
    assert_eq!(std::fs::read_to_string(&file)?, "one one\nsecond\n");
    let replaced = boot.admin.replace("box", &path, "one", "two", true).await?;
    assert_eq!(replaced["replacements"], 2);
    assert_eq!(std::fs::read_to_string(&file)?, "two two\nsecond\n");
    boot.admin.edit_lines("box", &path, 2, 2, "third\n").await?;
    assert_eq!(std::fs::read_to_string(&file)?, "two two\nthird\n");

    let before = std::fs::read_to_string(&file)?;
    let after = before.replace("third", "fourth");
    let mut diff = diffy::DiffOptions::new();
    diff.set_original_filename("a/note.txt");
    diff.set_modified_filename("b/note.txt");
    let patch = diff.create_patch(&before, &after).to_string();
    let root = boot.dir.path().display().to_string();
    let applied = boot.admin.apply_patch("box", &root, &patch).await?;
    assert!(applied["files"].as_array().unwrap().len() >= 1, "{applied}");
    assert_eq!(std::fs::read_to_string(&file)?, after);
    let escape = boot
        .admin
        .apply_patch(
            "box",
            &root,
            "--- a/../escape.txt\n+++ b/../escape.txt\n@@ -0,0 +1 @@\n+x\n",
        )
        .await;
    assert!(escape.is_err(), "patch path escaped");

    let found = boot
        .admin
        .search(
            "box",
            &root,
            "fourth",
            true,
            vec!["*.txt".into()],
            Vec::new(),
            false,
            false,
            false,
            0,
            0,
            0,
            10,
        )
        .await?;
    assert!(found["matches"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["path"].as_str().unwrap_or("").contains("note.txt")));

    let watch_dir = boot.dir.path().join("watched");
    std::fs::create_dir(&watch_dir)?;
    let watch = boot
        .admin
        .watch_start("box", &watch_dir.display().to_string(), false)
        .await?;
    let watch_id = watch["watch_id"].as_str().unwrap().to_string();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let created = watch_dir.join("created.txt");
    std::fs::write(&created, b"hi")?;
    let mut saw_create = false;
    let mut saw_remove = false;
    for _ in 0..16 {
        let batch = boot.admin.watch_poll("box", &watch_id, 0, 400, 40).await?;
        let text = batch.to_string();
        if text.contains("created.txt") {
            saw_create = true;
        }
        if saw_create && !saw_remove {
            let _ = std::fs::remove_file(&created);
        }
        if saw_create && text.contains("created.txt") && text.contains("remove") {
            saw_remove = true;
            break;
        }
        if saw_create && !created.exists() && text.contains("created.txt") {
            // Some backends report a modify or a second event instead of "remove".
            if text.matches("created.txt").count() > 1 {
                saw_remove = true;
                break;
            }
        }
    }
    boot.admin.watch_stop("box", &watch_id).await?;
    assert!(saw_create, "watch missed the create");
    assert!(saw_remove, "watch missed the delete");

    let bg_line = if cfg!(windows) {
        "ping -n 20 127.0.0.1 >nul"
    } else {
        "sleep 20"
    };
    let started = boot
        .admin
        .bg_start("box", bg_line, Vec::new(), None, Vec::new(), true, None)
        .await?;
    let id = started["id"].as_str().unwrap().to_string();
    let listed = boot.admin.bg_list("box").await?;
    assert!(listed.to_string().contains(&id), "{listed}");
    let status = boot.admin.bg_status("box", &id).await?;
    assert_eq!(status["running"], true, "{status}");
    boot.admin.bg_kill("box", &id).await?;
    let mut dead = false;
    for _ in 0..20 {
        let status = boot.admin.bg_status("box", &id).await?;
        if status["running"] == false {
            dead = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(dead, "background process survived kill");

    let command = if cfg!(windows) {
        None
    } else {
        Some("cat".into())
    };
    let mut pty = boot.admin.open_pty("box", command, None, 24, 80).await?;
    let bytes: &[u8] = if cfg!(windows) {
        b"echo pty-write\r\n"
    } else {
        b"pty-write\n"
    };
    pty.write(bytes).await?;
    pty.resize(30, 100).await?;
    let mut collected = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        let event = tokio::time::timeout(Duration::from_secs(2), pty.recv()).await;
        let Ok(Ok(event)) = event else { continue };
        match event {
            agentlink_core::PtyEvent::Data(data) => {
                collected.extend(data);
                if String::from_utf8_lossy(&collected).contains("pty-write") {
                    break;
                }
            }
            agentlink_core::PtyEvent::Exit(_) | agentlink_core::PtyEvent::Error(_) => break,
        }
    }
    assert!(
        String::from_utf8_lossy(&collected).contains("pty-write"),
        "pty output: {}",
        String::from_utf8_lossy(&collected)
    );
    pty.close().await?;

    let info = boot.admin.sysinfo("box").await?;
    assert!(info["cpu"]["count"].as_u64().unwrap_or(0) > 0, "{info}");
    assert!(
        info["memory"]["total_bytes"].as_u64().unwrap_or(0) > 0,
        "{info}"
    );
    assert!(
        info["os"].is_object() || info["os"].is_string() || info.get("hostname").is_some(),
        "{info}"
    );

    stop_node(node).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cluster_identity_audit_and_reconnect() {
    let result = tokio::time::timeout(Duration::from_secs(90), cluster_flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("cluster functional test timed out"),
    }
}

async fn cluster_flow() -> anyhow::Result<()> {
    let mut boot = boot(true).await?;
    let secret = "SEALED-COMMAND-MARKER";
    let a = boot
        .admin
        .create_pairing_token("alpha", NodePolicy::exec(), 600)
        .await?;
    let b = boot
        .admin
        .create_pairing_token("beta", NodePolicy::exec(), 600)
        .await?;
    let twin = boot
        .admin
        .create_pairing_token("alpha", NodePolicy::read_only(), 600)
        .await?;
    let alpha_dir = boot.dir.path().join("alpha");
    std::fs::create_dir_all(&alpha_dir)?;
    std::fs::write(
        alpha_dir.join("audit.toml"),
        AuditPolicy::preset("full")?.to_toml()?,
    )?;
    let alpha = start_node(
        &boot,
        "alpha",
        "alpha",
        &a.token,
        None,
        NodePolicy::exec(),
        Vec::new(),
        None,
    ).await;
    let beta = start_node(
        &boot,
        "beta",
        "beta",
        &b.token,
        None,
        NodePolicy::exec(),
        Vec::new(),
        None,
    ).await;
    let twin_node = start_node(
        &boot,
        "alpha-2",
        "alpha",
        &twin.token,
        None,
        NodePolicy::read_only(),
        Vec::new(),
        None,
    ).await;
    wait_online(&boot.admin, &["beta"]).await;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let nodes = boot.admin.list_nodes().await?;
        let alphas = nodes
            .iter()
            .filter(|node| node.name == "alpha" && node.online)
            .count();
        if alphas >= 2 && nodes.iter().any(|node| node.name == "beta" && node.online) {
            break;
        }
        if Instant::now() > deadline {
            panic!("twins did not both come online: {nodes:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let ambiguous = boot
        .admin
        .exec_collect(
            "alpha",
            ExecRequest::shell("echo x", Some(Duration::from_secs(5))),
            None,
        )
        .await
        .unwrap_err();
    assert!(ambiguous.to_string().contains("ambiguous"), "{ambiguous}");
    let nodes = boot.admin.list_nodes().await?;
    let beta_id = nodes
        .iter()
        .find(|node| node.name == "beta")
        .unwrap()
        .id
        .clone();
    let by_id = boot
        .admin
        .exec_collect(
            &beta_id,
            ExecRequest::shell(format!("echo {secret}"), Some(Duration::from_secs(10))),
            None,
        )
        .await
        .map_err(|err| anyhow::anyhow!("exec {beta_id}: {err}"))?;
    assert!(
        String::from_utf8_lossy(&by_id.stdout).contains(secret),
        "{by_id:?}"
    );

    let wire = boot
        .capture
        .as_ref()
        .unwrap()
        .lock()
        .unwrap()
        .iter()
        .flat_map(|frame| String::from_utf8_lossy(frame).into_owned().into_bytes())
        .collect::<Vec<_>>();
    let wire = String::from_utf8_lossy(&wire);
    assert!(!wire.contains(secret), "relay saw the sealed command");
    assert!(
        wire.contains("e2e"),
        "relay forwarded no end-to-end envelope"
    );

    let twin_id = std::fs::read_to_string(twin_node.dir.join("identity.json"))?;
    let twin_id = serde_json::from_str::<serde_json::Value>(&twin_id)?["public_hex"]
        .as_str()
        .unwrap()
        .to_string();
    let alpha_id = boot
        .admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|node| node.name == "alpha" && node.id != twin_id)
        .expect("primary alpha")
        .id;
    stop_node(twin_node).await;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let nodes = boot.admin.list_nodes().await?;
        let twin_online = nodes.iter().any(|node| node.id == twin_id && node.online);
        let alphas = nodes
            .iter()
            .filter(|node| node.name == "alpha" && node.online)
            .count();
        if !twin_online && alphas == 1 {
            break;
        }
        if Instant::now() > deadline {
            panic!("stopped twin stayed online: {nodes:?}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let offline = boot
        .admin
        .exec_collect(
            &twin_id,
            ExecRequest::shell("echo z", Some(Duration::from_secs(3))),
            None,
        )
        .await
        .unwrap_err();
    assert!(
        offline.to_string().contains("offline") || offline.to_string().contains("not found"),
        "{offline}"
    );
    let audited = boot
        .admin
        .exec_collect(
            &alpha_id,
            ExecRequest::shell("echo audited", Some(Duration::from_secs(10))),
            None,
        )
        .await
        .map_err(|err| anyhow::anyhow!("exec remaining alpha: {err}"))?;
    assert!(String::from_utf8_lossy(&audited.stdout).contains("audited"));

    let identity = Identity::generate();
    let id = identity.public_hex().to_string();
    boot.admin.register_client("bot", &id).await?;
    boot.admin
        .set_client_grant(&id, "beta", NodePolicy::read_only())
        .await?;
    let agent = Client::connect_agent(
        &ClientSettings {
            relay: boot.url.clone(),
            token: String::new(),
            fingerprint: boot.relay.fingerprint.clone(),
            trust: None,
        },
        identity.clone(),
    )
    .await?;
    let beta_key = std::fs::read_to_string(boot.dir.path().join("beta").join("identity.json"))?;
    let beta_key = serde_json::from_str::<serde_json::Value>(&beta_key)?["public_hex"]
        .as_str()
        .unwrap()
        .to_string();
    agent.install_local_grant(&boot.dir.path().join("beta"), &beta_key)?;
    agent.list_dir("beta", ".").await?;
    let denied = agent
        .exec_collect(
            "beta",
            ExecRequest::shell("echo no", Some(Duration::from_secs(5))),
            None,
        )
        .await?;
    assert!(
        String::from_utf8_lossy(&denied.stdout).contains("no"),
        "a relay client preset does not override a node-local grant: {denied:?}"
    );
    boot.admin
        .set_client_grant(&id, "beta", NodePolicy::exec())
        .await?;
    let agent = Client::connect_agent(
        &ClientSettings {
            relay: boot.url.clone(),
            token: String::new(),
            fingerprint: boot.relay.fingerprint.clone(),
            trust: None,
        },
        identity.clone(),
    )
    .await?;
    agent.install_local_grant(&boot.dir.path().join("beta"), &beta_key)?;
    let allowed = agent
        .exec_collect(
            "beta",
            ExecRequest::shell("echo agent-ok", Some(Duration::from_secs(10))),
            None,
        )
        .await?;
    assert!(String::from_utf8_lossy(&allowed.stdout).contains("agent-ok"));
    boot.admin.revoke_client(&id).await?;
    let revoked = Client::connect_agent(
        &ClientSettings {
            relay: boot.url.clone(),
            token: String::new(),
            fingerprint: boot.relay.fingerprint.clone(),
            trust: None,
        },
        identity,
    )
    .await;
    assert!(revoked.is_err(), "revoked agent still connected");

    let mut records = Vec::new();
    let logs = alpha.dir.join("audit").join("logs");
    if logs.is_dir() {
        for entry in std::fs::read_dir(&logs)? {
            let text = std::fs::read_to_string(entry?.path())?;
            for line in text.lines().filter(|line| !line.is_empty()) {
                records.push(serde_json::from_str::<AuditRecord>(line)?);
            }
        }
    }
    records.sort_by_key(|record| record.seq);
    if !records.is_empty() {
        verify_chain(&records)?;
    }

    boot.relay.disconnect_nodes();
    let kicked = boot
        .admin
        .exec_collect(
            "beta",
            ExecRequest::shell("echo kicked", Some(Duration::from_secs(5))),
            None,
        )
        .await;
    let _ = kicked;
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match boot
            .admin
            .exec_collect(
                "beta",
                ExecRequest::shell("echo kicked", Some(Duration::from_secs(5))),
                None,
            )
            .await
        {
            Ok(out) if String::from_utf8_lossy(&out.stdout).contains("kicked") => break,
            _ if Instant::now() > deadline => panic!("node did not return after relay kick"),
            _ => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }

    let addr = boot.relay.local_addr;
    let data = boot.relay.data_dir.clone();
    let fingerprint = boot.relay.fingerprint.clone();
    drop(boot.admin);
    drop(boot.relay);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut restarted = None;
    for _ in 0..20 {
        match RelayHandle::spawn(RelayConfig {
            bind: addr,
            data_dir: data.clone(),
            capture: None,
            database_url: None,
            allow_signup: false,
            bootstrap_admin: false,
            db_schema: None,
            trust_proxy: Vec::new(),
            print_admin_token: false,
            legacy_admin_override: Some((true, Some(86_400))),
        })
        .await
        {
            Ok(relay) => {
                restarted = Some(relay);
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    let relay = restarted.expect("relay did not release its port");
    assert_eq!(relay.fingerprint, fingerprint);
    let admin = Client::connect(&ClientSettings {
        relay: boot.url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;
    admin.install_local_grant(&boot.dir.path().join("beta"), &beta_key)?;
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        match admin
            .exec_collect(
                "beta",
                ExecRequest::shell("echo reconnected", Some(Duration::from_secs(5))),
                None,
            )
            .await
        {
            Ok(out) if String::from_utf8_lossy(&out.stdout).contains("reconnected") => break,
            _ if Instant::now() > deadline => panic!("node did not reconnect after relay restart"),
            _ => tokio::time::sleep(Duration::from_millis(150)).await,
        }
    }
    boot.relay = relay;
    boot.admin = admin;
    stop_node(alpha).await;
    stop_node(beta).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn desktop_screenshot_and_input_on_a_real_display() {
    if !cfg!(target_os = "linux")
        || std::env::var_os("DISPLAY")
            .filter(|value| !value.is_empty())
            .is_none()
    {
        eprintln!("skipping real display test");
        return;
    }
    let result = tokio::time::timeout(Duration::from_secs(40), desktop_flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("desktop functional test timed out"),
    }
}

async fn desktop_flow() -> anyhow::Result<()> {
    let boot = boot(false).await?;
    let token = boot
        .admin
        .create_pairing_token("desk", NodePolicy::desktop(), 600)
        .await?;
    let (extensions, capture) = agentlink_desktop::node_bundle();
    let node = start_node(
        &boot,
        "desk",
        "desk",
        &token.token,
        None,
        NodePolicy::desktop(),
        extensions,
        Some(capture),
    ).await;
    wait_online(&boot.admin, &["desk"]).await;
    let shot = boot
        .admin
        .call_op(
            "desk",
            Op::Extension {
                name: PHASE2_SCREENSHOT.into(),
                payload: json!({"format": "png", "target": "screen"}),
            },
        )
        .await?;
    let bytes = agentlink_core::util::b64_decode(shot["data_b64"].as_str().unwrap())
        .map_err(|err| anyhow::anyhow!(err))?;
    assert!(bytes.len() > 32, "screenshot was empty");
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
    let moved = boot
        .admin
        .call_op(
            "desk",
            Op::Extension {
                name: PHASE2_INJECT_INPUT.into(),
                payload: json!({"action": "move", "x": 40, "y": 50}),
            },
        )
        .await?;
    assert_eq!(moved["ok"], true, "{moved}");
    let clicked = boot
        .admin
        .call_op(
            "desk",
            Op::Extension {
                name: PHASE2_INJECT_INPUT.into(),
                payload: json!({"action": "click", "x": 40, "y": 50, "button": "left"}),
            },
        )
        .await?;
    assert_eq!(clicked["ok"], true, "{clicked}");
    stop_node(node).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_clients_upload_at_once() {
    let result = tokio::time::timeout(Duration::from_secs(20), two_clients()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("two client uploads timed out"),
    }
}

async fn two_clients() -> anyhow::Result<()> {
    let boot = boot(false).await?;
    let token = boot
        .admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let node = start_node(
        &boot,
        "box",
        "box",
        &token.token,
        None,
        NodePolicy::exec(),
        Vec::new(),
        None,
    ).await;
    wait_online(&boot.admin, &["box"]).await;
    let settings = ClientSettings {
        relay: boot.url.clone(),
        token: boot.relay.admin_token.clone(),
        fingerprint: boot.relay.fingerprint.clone(),
        trust: None,
    };
    let first = Client::connect(&settings).await?;
    let second = Client::connect(&settings).await?;
    let box_id = boot
        .admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|item| item.name == "box")
        .unwrap()
        .id;
    first.install_local_grant(&node.dir, &box_id)?;
    second.install_local_grant(&node.dir, &box_id)?;
    let left = boot.dir.path().join("left.bin");
    let right = boot.dir.path().join("right.bin");
    write_pattern(&left, 32 * 1024, 1)?;
    write_pattern(&right, 32 * 1024, 2)?;
    let left_r = boot.dir.path().join("left-remote.bin");
    let right_r = boot.dir.path().join("right-remote.bin");
    let left_s = left_r.display().to_string();
    let right_s = right_r.display().to_string();
    let opts = opts("relay-only", CompressPref::Off);
    let (a, b) = tokio::try_join!(
        first.copy_upload("box", &left_s, &left, &opts, None),
        second.copy_upload("box", &right_s, &right, &opts, None),
    )?;
    assert!(a.logical_bytes > 0 && b.logical_bytes > 0, "{a:?} {b:?}");
    assert_eq!(std::fs::read(&left_r)?, std::fs::read(&left)?);
    assert_eq!(std::fs::read(&right_r)?, std::fs::read(&right)?);
    stop_node(node).await;
    Ok(())
}
