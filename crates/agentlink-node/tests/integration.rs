//! In-process relay + node coverage: pairing, files, exec, permissions, PTY, extensions.

use std::sync::Arc;
use std::time::{Duration, Instant};

use agentlink_core::{
    Client, ClientSettings, ExecRequest, NodeExtension, NodePolicy, Op, PHASE2_SCREENSHOT,
};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use serde_json::json;
use tokio_util::sync::CancellationToken;

struct Shot;

impl NodeExtension for Shot {
    fn name(&self) -> &'static str {
        PHASE2_SCREENSHOT
    }

    fn handle(
        &self,
        payload: &serde_json::Value,
    ) -> std::result::Result<serde_json::Value, String> {
        Ok(json!({"phase": 2, "echo": payload}))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn phase1_round_trip() {
    let result = tokio::time::timeout(Duration::from_secs(90), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("integration test timed out"),
    }
}

async fn flow() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

    let dir = tempfile::tempdir()?;
    let relay = RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse()?,
        data_dir: dir.path().join("relay"),
        capture: None,
        database_url: None,
        allow_signup: false,
        bootstrap_admin: false,
        db_schema: None,
        trust_proxy: Vec::new(),
        print_admin_token: false,
    })
    .await?;
    let relay_url = format!("wss://{}/v1/connect", relay.local_addr);
    let admin = Client::connect(&ClientSettings {
        relay: relay_url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;

    let pairing = admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let node_dir = dir.path().join("node");
    let node_shutdown = CancellationToken::new();
    let node_task = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: node_dir.clone(),
            name: "box".into(),
            pairing_token: Some(pairing.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        node_shutdown.clone(),
    ));

    let deadline = Instant::now() + Duration::from_secs(45);
    loop {
        let online = admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|n| n.name == "box" && n.online))
            .unwrap_or(false);
        if online {
            break;
        }
        if node_task.is_finished() {
            match node_task.await {
                Ok(Ok(())) => panic!("node returned before it was online"),
                Ok(Err(err)) => panic!("node failed before it was online: {err}"),
                Err(err) => panic!("node task panicked before it was online: {err}"),
            }
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for the node to come online");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let box_id = admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|node| node.name == "box")
        .unwrap()
        .id;
    admin.install_local_grant(&node_dir, &box_id)?;
    let grant_file = node_dir
        .join(format!(
            "controller-grants-{}",
            admin.public_id().chars().take(16).collect::<String>()
        ))
        .join("grants")
        .join(format!("{}.json", box_id.to_ascii_lowercase()));
    assert!(
        grant_file.is_file(),
        "missing {grant_file:?} for {box_id}"
    );

    let exec = admin
        .exec_collect(
            "box",
            ExecRequest::shell("echo hello-agentlink", Some(Duration::from_secs(15))),
            None,
        )
        .await
        .unwrap_or_else(|err| panic!("box_id={box_id} err={err}"));
    assert_eq!(
        exec.exit_code,
        Some(0),
        "stderr {}",
        String::from_utf8_lossy(&exec.stderr)
    );
    assert!(
        String::from_utf8_lossy(&exec.stdout).contains("hello-agentlink"),
        "stdout {}",
        String::from_utf8_lossy(&exec.stdout)
    );

    let file_path = dir.path().join("roundtrip.txt");
    let file_str = file_path.to_string_lossy().to_string();
    admin
        .write_file("box", &file_str, b"hello from agentlink")
        .await?;
    let read = admin.read_file("box", &file_str, 0, 1024).await?;
    assert_eq!(read, b"hello from agentlink");

    let parent = file_path.parent().unwrap().to_string_lossy().to_string();
    let entries = admin.list_dir("box", &parent).await?;
    assert!(entries.iter().any(|e| e.name == "roundtrip.txt"));

    admin
        .mkdir("box", &dir.path().join("made").to_string_lossy(), true)
        .await?;
    assert!(dir.path().join("made").is_dir());

    let denied = admin
        .call_op(
            "box",
            Op::Extension {
                name: PHASE2_SCREENSHOT.into(),
                payload: json!({}),
            },
        )
        .await
        .unwrap_err();
    assert!(
        denied.to_string().contains("not enabled")
            || denied.to_string().contains("not allowed")
            || denied.to_string().contains("permission"),
        "{denied}"
    );

    let mut session = admin
        .open_pty("box", Some("echo pty-ok".into()), None, 24, 80)
        .await?;
    let mut pty_out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let event = tokio::time::timeout(Duration::from_secs(15), session.recv()).await??;
        match event {
            agentlink_core::PtyEvent::Data(bytes) => pty_out.extend(bytes),
            agentlink_core::PtyEvent::Exit(_) | agentlink_core::PtyEvent::Error(_) => break,
        }
        if String::from_utf8_lossy(&pty_out).contains("pty-ok") || Instant::now() > deadline {
            break;
        }
    }
    assert!(
        String::from_utf8_lossy(&pty_out).contains("pty-ok"),
        "pty output: {}",
        String::from_utf8_lossy(&pty_out)
    );

    // The PTY route still holds a sender clone. Reconnect has to succeed
    // while that route is alive, which is when a kicked socket used to stay open.
    relay.disconnect_nodes();
    let again_deadline = Instant::now() + Duration::from_secs(30);
    let mut last_err = String::from("no exec attempt");
    loop {
        if node_task.is_finished() {
            match node_task.await {
                Ok(Ok(())) => panic!("node exited before reconnect: {last_err}"),
                Ok(Err(err)) => panic!("node failed while reconnecting: {err}"),
                Err(err) => panic!("node task panicked while reconnecting: {err}"),
            }
        }
        match admin
            .exec_collect(
                "box",
                ExecRequest::shell("echo again", Some(Duration::from_secs(5))),
                None,
            )
            .await
        {
            Ok(out) if String::from_utf8_lossy(&out.stdout).contains("again") => break,
            Ok(out) => {
                last_err = format!(
                    "exit {:?} stdout {}",
                    out.exit_code,
                    String::from_utf8_lossy(&out.stdout)
                );
            }
            Err(err) => last_err = err.to_string(),
        }
        if Instant::now() > again_deadline {
            panic!("timed out waiting for the node to reconnect: {last_err}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    drop(session);

    let ro = admin
        .create_pairing_token("reader", NodePolicy::read_only(), 600)
        .await?;
    let ro_shutdown = CancellationToken::new();
    let ro_task = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: dir.path().join("reader"),
            name: "reader".into(),
            pairing_token: Some(ro.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        ro_shutdown.clone(),
    ));
    wait_until(|| async {
        admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|n| n.name == "reader" && n.online))
            .unwrap_or(false)
    })
    .await;
    let reader_id = admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|node| node.name == "reader")
        .unwrap()
        .id;
    admin.install_local_grant(&dir.path().join("reader"), &reader_id)?;
    let read_only = admin.read_file("reader", &file_str, 0, 64).await?;
    assert_eq!(read_only, b"hello from agentlink");
    let exec_ok = admin
        .exec_collect(
            "reader",
            ExecRequest::shell("echo no", Some(Duration::from_secs(5))),
            None,
        )
        .await?;
    assert!(
        String::from_utf8_lossy(&exec_ok.stdout).contains("no"),
        "{exec_ok:?}"
    );

    let mut desktop = NodePolicy::read_only();
    desktop.allow_desktop = true;
    let ext = admin.create_pairing_token("screen", desktop, 600).await?;
    let ext_shutdown = CancellationToken::new();
    let ext_task = tokio::spawn(run(
        NodeConfig {
            relay_url,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: dir.path().join("screen"),
            name: "screen".into(),
            pairing_token: Some(ext.token),
            root: None,
            max_policy: desktop,
            version: "test".into(),
            extensions: vec![Arc::new(Shot)],
            policy_hook: None,
            capture: None,
        },
        ext_shutdown.clone(),
    ));
    wait_until(|| async {
        admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|n| n.name == "screen" && n.online))
            .unwrap_or(false)
    })
    .await;
    let screen_id = admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|node| node.name == "screen")
        .unwrap()
        .id;
    admin.install_local_grant(&dir.path().join("screen"), &screen_id)?;
    let shot = admin
        .call_op(
            "screen",
            Op::Extension {
                name: PHASE2_SCREENSHOT.into(),
                payload: json!({"display": 0}),
            },
        )
        .await?;
    assert_eq!(shot["phase"], 2);
    assert_eq!(shot["echo"]["display"], 0);

    let audit = std::fs::read_to_string(node_dir.join("audit.log"))?;
    assert!(audit.contains("\"op\":\"exec\""), "{audit}");
    assert!(audit.contains("\"op\":\"write\""), "{audit}");

    node_shutdown.cancel();
    ro_shutdown.cancel();
    ext_shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), node_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), ro_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), ext_task).await;
    Ok(())
}

async fn wait_until<F, Fut>(mut probe: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if probe().await {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for condition");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
