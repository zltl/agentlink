//! Idle node presence.
//!
//! The relay reports a paired node offline when it has not received a frame
//! from that socket for 75s (`STALE_AFTER`), even if the WebSocket is still
//! open. Heartbeats from `HelloOk` have to refresh `last_seen` inside that
//! window. This sits past the old bug window with no other node traffic.

use std::time::{Duration, Instant};

use agentlink_core::{Client, ClientSettings, NodePolicy};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn idle_node_stays_online_past_stale_window() {
    let result = tokio::time::timeout(Duration::from_secs(150), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("presence test timed out"),
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
    let url = format!("wss://{}/v1/connect", relay.local_addr);
    let admin = Client::connect(&ClientSettings {
        relay: url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;
    let pairing = admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let stop = CancellationToken::new();
    let node = tokio::spawn(run(
        NodeConfig {
            relay_url: url,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: dir.path().join("node"),
            name: "box".into(),
            pairing_token: Some(pairing.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        stop.clone(),
    ));

    let appeared = Instant::now() + Duration::from_secs(20);
    loop {
        if node.is_finished() {
            anyhow::bail!("node exited before it was online");
        }
        let online = admin
            .list_nodes()
            .await?
            .iter()
            .any(|info| info.name == "box" && info.online);
        if online {
            break;
        }
        if Instant::now() > appeared {
            anyhow::bail!("timed out waiting for the node");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Past STALE_AFTER (75s) with no exec, file, or other app traffic.
    // `list_nodes` talks only to the relay, so it does not refresh the node.
    let idle_until = Instant::now() + Duration::from_secs(80);
    while Instant::now() < idle_until {
        if node.is_finished() {
            anyhow::bail!("node exited during the idle window");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    let nodes = admin.list_nodes().await?;
    let info = nodes
        .iter()
        .find(|info| info.name == "box")
        .ok_or_else(|| anyhow::anyhow!("node disappeared: {nodes:?}"))?;
    assert!(
        info.online,
        "idle node went offline while its relay socket was still up: {info:?}"
    );
    let connects = std::fs::read_to_string(relay.data_dir.join("connect.jsonl"))?;
    let node_connects = connects
        .lines()
        .filter(|line| line.contains("\"role\":\"node\"") && line.contains("\"name\":\"box\""))
        .count();
    assert_eq!(
        node_connects, 1,
        "node reconnected during the idle window, so presence was not proved: {connects}"
    );

    stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), node).await;
    Ok(())
}
