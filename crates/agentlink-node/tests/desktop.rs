//! Desktop permission, mock capture, and audit coverage.

use std::sync::Arc;
use std::time::{Duration, Instant};

use agentlink_core::util::b64_decode;
use agentlink_core::{
    Client, ClientSettings, NodePolicy, Op, PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT,
};
use agentlink_desktop::mock_extensions;
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use serde_json::json;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn desktop_preset_allows_mock_capture_and_audits_it() {
    let result = tokio::time::timeout(Duration::from_secs(40), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("desktop integration timed out"),
    }
}

async fn flow() -> anyhow::Result<()> {
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

    let denied_token = admin
        .create_pairing_token("ceiling", NodePolicy::desktop(), 600)
        .await?;
    let denied_dir = dir.path().join("ceiling");
    let denied_shutdown = CancellationToken::new();
    let denied_task = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: denied_dir,
            name: "ceiling".into(),
            pairing_token: Some(denied_token.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: mock_extensions(),
            policy_hook: None,
            capture: Some(agentlink_desktop::mock_capture()),
        },
        denied_shutdown.clone(),
    ));
    wait_online(&admin, "ceiling").await;
    let ceiling_id = admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|node| node.name == "ceiling")
        .unwrap()
        .id;
    admin.install_local_grant(&dir.path().join("ceiling"), &ceiling_id)?;
    let shot = admin
        .call_op(
            "ceiling",
            Op::Extension {
                name: PHASE2_SCREENSHOT.into(),
                payload: json!({"format": "png"}),
            },
        )
        .await;
    assert!(
        shot.is_err(),
        "a local grant cannot raise --max-access above phase1: {shot:?}"
    );

    let token = admin
        .create_pairing_token("desk", NodePolicy::desktop(), 600)
        .await?;
    let node_dir = dir.path().join("desk");
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run(
        NodeConfig {
            relay_url,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: node_dir.clone(),
            name: "desk".into(),
            pairing_token: Some(token.token),
            root: None,
            max_policy: NodePolicy::desktop(),
            version: "test".into(),
            extensions: mock_extensions(),
            policy_hook: None,
            capture: Some(agentlink_desktop::mock_capture()),
        },
        shutdown.clone(),
    ));
    wait_online(&admin, "desk").await;
    let desk_id = admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|node| node.name == "desk")
        .unwrap()
        .id;
    admin.install_local_grant(&node_dir, &desk_id)?;

    let shot = admin
        .call_op(
            "desk",
            Op::Extension {
                name: PHASE2_SCREENSHOT.into(),
                payload: json!({
                    "target": "region",
                    "x": 0,
                    "y": 0,
                    "width": 20,
                    "height": 10,
                    "format": "png",
                    "scale": 0.5,
                }),
            },
        )
        .await?;
    assert_eq!(shot["width"], 10);
    assert_eq!(shot["height"], 5);
    assert_eq!(shot["mime"], "image/png");
    let bytes = b64_decode(shot["data_b64"].as_str().unwrap()).unwrap();
    assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");

    let tree = admin
        .call_op(
            "desk",
            Op::Extension {
                name: PHASE2_INJECT_INPUT.into(),
                payload: json!({"action": "ui_tree"}),
            },
        )
        .await?;
    let text = tree.to_string();
    assert!(text.contains("mock:ok"), "{text}");

    admin
        .call_op(
            "desk",
            Op::Extension {
                name: PHASE2_INJECT_INPUT.into(),
                payload: json!({
                    "action": "act",
                    "id": "mock:title",
                    "op": "set_value",
                    "value": "updated",
                }),
            },
        )
        .await?;
    admin
        .call_op(
            "desk",
            Op::Extension {
                name: PHASE2_INJECT_INPUT.into(),
                payload: json!({"action": "type", "text": "hello desktop"}),
            },
        )
        .await?;

    let audit = std::fs::read_to_string(node_dir.join("audit.log"))?;
    assert!(audit.contains("\"op\":\"ext:screenshot\""), "{audit}");
    assert!(audit.contains("\"op\":\"ext:inject_input\""), "{audit}");
    assert!(audit.contains("region"), "{audit}");
    assert!(!audit.contains("iVBORw0KGgo"), "{audit}");
    assert!(audit.contains("13 chars"), "{audit}");
    assert!(!audit.contains("hello desktop"), "{audit}");

    shutdown.cancel();
    denied_shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), denied_task).await;
    let _ = Arc::new(relay);
    Ok(())
}

async fn wait_online(admin: &Client, name: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let online = admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|node| node.name == name && node.online))
            .unwrap_or(false);
        if online {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for {name}");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
