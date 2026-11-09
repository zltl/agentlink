//! A node on the same machine must come back after the local relay leaf changes.
//!
//! Operator clients keep a strict pin, including when they dial `127.0.0.1`.

use std::time::{Duration, Instant};

use agentlink_core::{Client, ClientSettings, NodePolicy, RelayCert};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loopback_node_adopts_a_rotated_leaf_and_a_client_pin_stays_strict() {
    let result = tokio::time::timeout(Duration::from_secs(60), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("loopback pin test timed out"),
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

    let stale_dir = tempfile::tempdir()?;
    let stale_pin = RelayCert::load_or_create(stale_dir.path())?.fingerprint;
    assert_ne!(stale_pin, relay.fingerprint);

    let client_err = match Client::connect(&ClientSettings {
        relay: relay_url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: stale_pin.clone(),
        trust: None,
    })
    .await
    {
        Ok(_) => anyhow::bail!("a client pin must fail even on loopback"),
        Err(err) => err,
    };
    let client_text = client_err.to_string();
    assert!(
        client_text.contains("certificate fingerprint mismatch"),
        "{client_text}"
    );
    assert!(client_text.contains(&relay.fingerprint), "{client_text}");
    assert!(client_text.contains("fingerprint.txt"), "{client_text}");
    assert!(client_text.contains("tip:"), "{client_text}");
    assert!(!client_err.is_retryable(), "{client_text}");

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
    let shutdown = CancellationToken::new();
    let node = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: stale_pin.clone(),
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
        shutdown.clone(),
    ));

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if node.is_finished() {
            match node.await {
                Ok(Ok(())) => anyhow::bail!("node returned before it was online"),
                Ok(Err(err)) => anyhow::bail!("node failed before it was online: {err}"),
                Err(err) => anyhow::bail!("node task panicked before it was online: {err}"),
            }
        }
        let online = admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|n| n.name == "box" && n.online))
            .unwrap_or(false);
        if online {
            break;
        }
        if Instant::now() > deadline {
            anyhow::bail!("node stayed offline after the loopback certificate changed");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let text = std::fs::read_to_string(node_dir.join("node.json"))?;
    let value: serde_json::Value = serde_json::from_str(&text)?;
    assert_eq!(
        value["fingerprint"].as_str(),
        Some(relay.fingerprint.as_str()),
        "{text}"
    );
    assert_ne!(
        value["fingerprint"].as_str(),
        Some(stale_pin.as_str()),
        "{text}"
    );

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), node).await;
    Ok(())
}
