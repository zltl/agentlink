//! A logged-in account must not open another account's node, including by
//! rebinding an E2E request id onto a node they do own.

use std::time::{Duration, Instant};

use agentlink_core::e2e::Endpoint;
use agentlink_core::protocol::{Envelope, Role, PROTOCOL_VERSION};
use agentlink_core::ws;
use agentlink_core::{Client, ClientSettings, ExecRequest, Identity, NodePolicy};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cross_account_e2e_cannot_reuse_a_route() {
    let result = tokio::time::timeout(Duration::from_secs(60), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("cross-account test timed out"),
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
    let url = format!("wss://{}/v1/connect", relay.local_addr);
    let admin = Client::connect(&ClientSettings {
        relay: url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;
    admin.user_add("alice", "password-alice", false).await?;
    admin.user_add("bob", "password-bob", false).await?;

    let alice_key = Identity::generate();
    let alice_session = agentlink_core::client::login_user(
        &url,
        &relay.fingerprint,
        None,
        &alice_key,
        "alice",
        "password-alice",
        None,
        "phone",
    )
    .await?;
    let alice = Client::connect_identity(
        &ClientSettings {
            relay: url.clone(),
            token: alice_session.access_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        alice_key.clone(),
        true,
    )
    .await?;
    let alice_token = alice
        .create_pairing_token("alice-box", NodePolicy::full(), 600)
        .await?;
    let bob_key = Identity::generate();
    let bob_session = agentlink_core::client::login_user(
        &url,
        &relay.fingerprint,
        None,
        &bob_key,
        "bob",
        "password-bob",
        None,
        "laptop",
    )
    .await?;
    let bob = Client::connect_identity(
        &ClientSettings {
            relay: url.clone(),
            token: bob_session.access_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        bob_key.clone(),
        true,
    )
    .await?;
    let bob_token = bob
        .create_pairing_token("bob-box", NodePolicy::full(), 600)
        .await?;
    let alice_stop = spawn_node(
        &relay,
        &url,
        &dir.path().join("alice"),
        "alice-box",
        &alice_token.token,
    );
    let bob_stop = spawn_node(
        &relay,
        &url,
        &dir.path().join("bob"),
        "bob-box",
        &bob_token.token,
    );
    wait_online(&admin, &["alice-box", "bob-box"]).await;
    let nodes = admin.list_nodes().await?;
    let alice_id = nodes
        .iter()
        .find(|node| node.name == "alice-box")
        .unwrap()
        .id
        .clone();
    let bob_id = nodes
        .iter()
        .find(|node| node.name == "bob-box")
        .unwrap()
        .id
        .clone();

    let own = alice
        .exec_collect(
            "alice-box",
            ExecRequest::shell("echo owner-ok", Some(Duration::from_secs(10))),
            None,
        )
        .await;
    let own_err = match own {
        Ok(done) => format!("exit {:?} stdout {}", done.exit_code, String::from_utf8_lossy(&done.stdout)),
        Err(err) => err.to_string(),
    };
    assert!(
        own_err.contains("signed grant required"),
        "same-owner login must not skip a local grant: {own_err}"
    );
    let grant = agentlink_core::grant::issue_local_grant(
        &dir.path().join("alice"),
        &alice_id,
        alice.public_id(),
    )?;
    let jti = grant.jti.clone();
    let grant_dir = dir.path().join("alice-controller-grants");
    agentlink_core::grant::save_grant(&grant_dir, &grant)?;
    alice.remember_grants(&grant_dir);
    let own = alice
        .exec_collect(
            "alice-box",
            ExecRequest::shell("echo owner-ok", Some(Duration::from_secs(10))),
            None,
        )
        .await?;
    assert_eq!(own.exit_code, Some(0));
    assert!(String::from_utf8_lossy(&own.stdout).contains("owner-ok"));
    agentlink_core::grant::add_revoked_jti(&dir.path().join("alice"), &jti)?;
    let revoked = alice
        .exec_collect(
            "alice-box",
            ExecRequest::shell("echo revoked", Some(Duration::from_secs(10))),
            None,
        )
        .await;
    let revoked_err = match revoked {
        Ok(done) => format!("exit {:?}", done.exit_code),
        Err(err) => err.to_string(),
    };
    assert!(
        revoked_err.contains("revoked"),
        "local revoke must block the next command: {revoked_err}"
    );
    let foreign = alice
        .exec_collect(
            "bob-box",
            ExecRequest::shell("echo pwned", Some(Duration::from_secs(10))),
            None,
        )
        .await;
    let foreign_err = match &foreign {
        Ok(done) => format!("exit {:?}", done.exit_code),
        Err(err) => err.to_string(),
    };
    assert!(
        foreign.is_err() || foreign_err.contains("signed grant required"),
        "alice ran a command on bob's node: {foreign_err}"
    );

    let mut ws = dial(
        &url,
        &relay.fingerprint,
        &alice_session.access_token,
        &alice_key,
    )
    .await?;
    let endpoint = Endpoint::new(alice_key.clone());
    let pending = endpoint.client_hello(&bob_id)?;
    let hello_id = uuid::Uuid::new_v4().to_string();
    send(
        &mut ws,
        &Envelope::E2eHello {
            request_id: hello_id.clone(),
            node_id: bob_id.clone(),
            message_b64: agentlink_core::util::b64_encode(Endpoint::hello_bytes(&pending)),
        },
    )
    .await?;
    let denied = next_env(&mut ws).await?;
    match denied {
        Envelope::Result {
            ok: false, error, ..
        } => {
            let error = error.unwrap_or_default();
            assert!(
                error.contains("no grant") || error.contains("not allowed"),
                "{error}"
            );
        }
        other => panic!("expected a refusal, got {other:?}"),
    }
    // Rebinding an existing route is covered by the relay router test
    // `existing_route_rejects_a_different_node`. A live node answers hello
    // with a terminal welcome, which deletes the route before a second frame
    // can reuse it, so that race is not this test's assertion.

    alice
        .share_node(&bob_id, "alice", NodePolicy::read_only())
        .await
        .expect_err("alice cannot share a node she does not own");
    bob.share_node(&bob_id, "alice", NodePolicy::read_only())
        .await?;
    let shared = alice
        .exec_collect(
            "bob-box",
            ExecRequest::shell("echo shared-ok", Some(Duration::from_secs(10))),
            None,
        )
        .await;
    let shared_err = match &shared {
        Ok(done) => format!("exit {:?}", done.exit_code),
        Err(err) => err.to_string(),
    };
    assert!(
        shared.is_err(),
        "a relay share is not a local grant: {shared_err}"
    );
    let bob_grant = agentlink_core::grant::issue_local_grant(
        &dir.path().join("bob"),
        &bob_id,
        alice.public_id(),
    )?;
    let bob_grants = dir.path().join("bob-controller-grants");
    agentlink_core::grant::save_grant(&bob_grants, &bob_grant)?;
    alice.remember_grants(&bob_grants);
    let shared = alice
        .exec_collect(
            "bob-box",
            ExecRequest::shell("echo shared-ok", Some(Duration::from_secs(10))),
            None,
        )
        .await?;
    assert!(
        String::from_utf8_lossy(&shared.stdout).contains("shared-ok"),
        "a grant issued on bob's node allows alice"
    );

    alice_stop.cancel();
    bob_stop.cancel();
    Ok(())
}

fn spawn_node(
    relay: &RelayHandle,
    url: &str,
    dir: &std::path::Path,
    name: &str,
    token: &str,
) -> CancellationToken {
    let stop = CancellationToken::new();
    tokio::spawn(run(
        NodeConfig {
            relay_url: url.into(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: dir.into(),
            name: name.into(),
            pairing_token: Some(token.into()),
            root: None,
            max_policy: NodePolicy::full(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        stop.clone(),
    ));
    stop
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

async fn dial(
    url: &str,
    fingerprint: &str,
    token: &str,
    identity: &Identity,
) -> anyhow::Result<
    tokio_tungstenite::WebSocketStream<
        tokio_rustls::client::TlsStream<TcpStream>,
    >,
> {
    let relay = agentlink_core::parse_relay_url(url)?;
    let trust = agentlink_core::tls::RelayTrust::parse(fingerprint, None)?;
    let tcp = TcpStream::connect((relay.host.as_str(), relay.port)).await?;
    let connector =
        tokio_rustls::TlsConnector::from(agentlink_core::tls::client_config_for(&trust)?);
    let name = agentlink_core::tls::server_name(&relay.host, &trust)?;
    let tls = connector.connect(name, tcp).await?;
    let ws_url = format!("ws://{}:{}{}", relay.bracket_host(), relay.port, relay.path);
    let (mut ws, _) =
        tokio_tungstenite::client_async_with_config(ws_url, tls, Some(agentlink_core::ws::ws_config()))
            .await?;
    let hello = Envelope::Hello {
        role: Role::Client,
        protocol: PROTOCOL_VERSION,
        token: Some(token.into()),
        node_id: None,
        public_key: Some(identity.public_hex().to_string()),
        name: Some("phone".into()),
        pairing_token: None,
        hostname: None,
        os: None,
        arch: None,
        version: None,
        ceiling: None,
        has_display: None,
    };
    ws.send(Message::Text(serde_json::to_string(&hello)?.into()))
        .await?;
    match next_env(&mut ws).await? {
        Envelope::Challenge { nonce } => {
            let signature = identity.sign_nonce(&nonce);
            ws.send(Message::Text(
                serde_json::to_string(&Envelope::Authenticate { signature })?.into(),
            ))
            .await?;
            match next_env(&mut ws).await? {
                Envelope::HelloOk { .. } => Ok(ws),
                other => anyhow::bail!("hello failed: {other:?}"),
            }
        }
        Envelope::HelloOk { .. } => Ok(ws),
        other => anyhow::bail!("unexpected hello: {other:?}"),
    }
}

async fn send(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
    env: &Envelope,
) -> anyhow::Result<()> {
    let out = ws::encode(env)?;
    let msg = match out {
        ws::Outbound::Text(text) => Message::Text(text.into()),
        ws::Outbound::Binary(bytes) => Message::Binary(bytes.into()),
        ws::Outbound::Pong(bytes) => Message::Pong(bytes.into()),
    };
    ws.send(msg).await?;
    Ok(())
}

async fn next_env(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
) -> anyhow::Result<Envelope> {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let msg = tokio::time::timeout(left, ws.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("socket closed"))??;
        match msg {
            Message::Text(text) => return Ok(serde_json::from_str(&text)?),
            Message::Binary(bytes) => {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    if let Ok(env) = serde_json::from_str::<Envelope>(text) {
                        return Ok(env);
                    }
                }
            }
            Message::Ping(_) | Message::Pong(_) => continue,
            Message::Close(_) => anyhow::bail!("closed"),
            _ => continue,
        }
    }
}
