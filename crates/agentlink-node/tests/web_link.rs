//! Browser dashboard files and terminal, through a live node and the relay.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use agentlink_core::tls::client_config;
use agentlink_core::{parse_fingerprint, util, Client, ClientSettings, Identity, NodePolicy};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dashboard_control_is_rejected_without_a_sealed_grant() {
    let result = tokio::time::timeout(Duration::from_secs(90), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("web link test timed out"),
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
        legacy_admin_override: Some((true, Some(86_400))),
    })
    .await?;
    let url = format!("wss://127.0.0.1:{}", relay.local_addr.port());
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
            token: alice_session.access_token,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        alice_key,
        true,
    )
    .await?;
    let exec_token = alice
        .create_pairing_token("box", NodePolicy::exec(), 3600)
        .await?;
    let ro_token = alice
        .create_pairing_token("locked", NodePolicy::read_only(), 3600)
        .await?;

    let box_root = dir.path().join("box-root");
    let locked_root = dir.path().join("locked-root");
    std::fs::create_dir_all(&box_root)?;
    std::fs::create_dir_all(&locked_root)?;
    std::fs::write(box_root.join("seed.txt"), b"seed")?;
    std::fs::write(locked_root.join("seed.txt"), b"locked-seed")?;

    let box_stop = CancellationToken::new();
    let locked_stop = CancellationToken::new();
    let box_task = tokio::spawn(run(
        node_config(
            &url,
            &relay.fingerprint,
            dir.path().join("box-data"),
            "box",
            &exec_token.token,
            box_root.clone(),
        ),
        box_stop.clone(),
    ));
    let locked_task = tokio::spawn(run(
        node_config(
            &url,
            &relay.fingerprint,
            dir.path().join("locked-data"),
            "locked",
            &ro_token.token,
            locked_root,
        ),
        locked_stop.clone(),
    ));
    wait_online(&alice, &["box", "locked"]).await;

    let nodes = alice.list_nodes().await?;
    let box_id = nodes
        .iter()
        .find(|node| node.name == "box")
        .unwrap()
        .id
        .clone();
    alice
        .share_node(&box_id, "bob", NodePolicy::read_only())
        .await?;

    let alice_web = web_login(&relay, "alice", "password-alice").await?;
    let listed = nodes_json(&relay, &alice_web.session).await?;
    let machine = listed["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["name"] == "box")
        .unwrap();
    assert_eq!(machine["allow_read"], true, "{machine}");
    assert_eq!(machine["allow_write"], true, "{machine}");
    assert_eq!(machine["allow_exec"], true, "{machine}");
    let locked = listed["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["name"] == "locked")
        .unwrap();
    assert_eq!(locked["allow_read"], true, "{locked}");
    assert_eq!(locked["allow_exec"], true, "{locked}");
    assert_eq!(locked["allow_write"], true, "{locked}");
    assert_eq!(locked["allow_remote_control"], true, "{locked}");

    let mut ws = connect_web(&relay, &alice_web.session, &alice_web.csrf).await?;
    let hello = recv_json(&mut ws).await?;
    assert_eq!(hello["type"], "hello_ok");

    let denied = call(
        &mut ws,
        &serde_json::json!({
            "type": "invoke",
            "request_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1",
            "node_id": box_id,
            "client_id": "",
            "op": { "op": "list_dir", "path": "." }
        }),
    )
    .await?;
    let text = denied.to_string();
    assert!(
        denied["ok"] == false || text.contains("disabled") || text.contains("plaintext"),
        "web control must fail closed: {denied}"
    );
    let err = denied["error"].as_str().unwrap_or("");
    assert!(
        err.contains("disabled") || err.contains("plaintext") || err.contains("grant"),
        "{denied}"
    );

    let mut shell = connect_web(&relay, &alice_web.session, &alice_web.csrf).await?;
    let _ = recv_json(&mut shell).await?;
    let shell_denied = call(
        &mut shell,
        &serde_json::json!({
            "type": "invoke",
            "request_id": "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1",
            "node_id": box_id,
            "client_id": "",
            "op": { "op": "pty_open", "rows": 24, "cols": 80 }
        }),
    )
    .await?;
    let shell_err = shell_denied["error"].as_str().unwrap_or("");
    assert!(
        shell_err.contains("disabled") || shell_err.contains("plaintext"),
        "{shell_denied}"
    );

    box_stop.cancel();
    locked_stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), box_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), locked_task).await;
    Ok(())
}

fn node_config(
    url: &str,
    fingerprint: &str,
    data_dir: PathBuf,
    name: &str,
    token: &str,
    root: PathBuf,
) -> NodeConfig {
    NodeConfig {
        relay_url: format!("{url}/v1/connect"),
        fingerprint: fingerprint.to_string(),
        trust: None,
        data_dir,
        name: name.to_string(),
        pairing_token: Some(token.to_string()),
        root: Some(root),
        max_policy: NodePolicy::phase1_ceiling(),
        version: "test".into(),
        extensions: Vec::new(),
        policy_hook: None,
        capture: None,
    }
}

async fn wait_online(client: &Client, names: &[&str]) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let ready = client
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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

struct WebLogin {
    session: String,
    csrf: String,
}

async fn web_login(relay: &RelayHandle, user: &str, password: &str) -> anyhow::Result<WebLogin> {
    let body = format!("{{\"username\":\"{user}\",\"password\":\"{password}\"}}");
    let response = http(
        relay,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await?;
    anyhow::ensure!(response.contains("200"), "{response}");
    Ok(WebLogin {
        session: cookie(&response, "agentlink_session"),
        csrf: cookie(&response, "agentlink_csrf"),
    })
}

async fn nodes_json(relay: &RelayHandle, session: &str) -> anyhow::Result<serde_json::Value> {
    let response = http(
        relay,
        &format!(
            "GET /api/nodes HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: agentlink_session={session}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await?;
    anyhow::ensure!(response.contains("200"), "{response}");
    Ok(serde_json::from_str(body_of(&response))?)
}

type WebSocket = tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

async fn connect_web(relay: &RelayHandle, session: &str, csrf: &str) -> anyhow::Result<WebSocket> {
    let tls = tls_stream(relay).await?;
    let mut request = format!(
        "wss://127.0.0.1:{}/v1/web?csrf={csrf}",
        relay.local_addr.port()
    )
    .into_client_request()?;
    request.headers_mut().insert(
        "cookie",
        HeaderValue::from_str(&format!("agentlink_session={session}"))?,
    );
    let (ws, _) = tokio_tungstenite::client_async(request, tls).await?;
    Ok(ws)
}

async fn call(ws: &mut WebSocket, env: &serde_json::Value) -> anyhow::Result<serde_json::Value> {
    send_json(ws, env).await?;
    let response = recv_json(ws).await?;
    anyhow::ensure!(response["type"] == "result", "{response}");
    Ok(response)
}

async fn read_file(
    ws: &mut WebSocket,
    node: &str,
    path: &str,
    request_id: &str,
) -> anyhow::Result<Vec<u8>> {
    send_json(
        ws,
        &serde_json::json!({
            "type": "invoke",
            "request_id": request_id,
            "node_id": node,
            "client_id": "",
            "op": { "op": "read_file", "path": path, "offset": 0, "max_bytes": 65536 }
        }),
    )
    .await?;
    let mut out = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let env = recv_json(ws).await?;
        match env["type"].as_str() {
            Some("chunk") => out.extend(util::b64_decode(env["data_b64"].as_str().unwrap_or(""))?),
            Some("end") => {
                if let Some(error) = env["error"].as_str() {
                    anyhow::bail!(error.to_string());
                }
                return Ok(out);
            }
            Some("result") => anyhow::bail!("read failed: {env}"),
            _ => {}
        }
        if Instant::now() > deadline {
            anyhow::bail!("timed out reading {path}");
        }
    }
}

async fn collect_until(
    ws: &mut WebSocket,
    needle: &str,
    wait: Duration,
) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::new();
    let deadline = Instant::now() + wait;
    while Instant::now() < deadline {
        let left = deadline.saturating_duration_since(Instant::now());
        let env = match tokio::time::timeout(left, recv_json(ws)).await {
            Ok(value) => value?,
            Err(_) => break,
        };
        if env["type"] == "chunk" {
            out.extend(util::b64_decode(env["data_b64"].as_str().unwrap_or(""))?);
            if String::from_utf8_lossy(&out).contains(needle) {
                return Ok(out);
            }
        }
        if env["type"] == "result" && env["ok"] == false {
            anyhow::bail!("pty failed: {env}");
        }
    }
    Ok(out)
}

async fn recv_json(ws: &mut WebSocket) -> anyhow::Result<serde_json::Value> {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(20), ws.next())
            .await?
            .ok_or_else(|| anyhow::anyhow!("socket closed"))??;
        if let Message::Text(text) = msg {
            return Ok(serde_json::from_str(text.as_ref())?);
        }
    }
}

async fn send_json(ws: &mut WebSocket, value: &serde_json::Value) -> anyhow::Result<()> {
    ws.send(Message::Text(value.to_string().into())).await?;
    Ok(())
}

async fn tls_stream(
    relay: &RelayHandle,
) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let pin = parse_fingerprint(&relay.fingerprint)?;
    let config = client_config(pin)?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(relay.local_addr).await?;
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("agentlink")
        .unwrap()
        .to_owned();
    Ok(connector.connect(name, tcp).await?)
}

async fn http(relay: &RelayHandle, request: &str) -> anyhow::Result<String> {
    let pin = parse_fingerprint(&relay.fingerprint)?;
    let config = client_config(pin)?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(relay.local_addr).await?;
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("agentlink")
        .unwrap()
        .to_owned();
    let mut tls = connector.connect(name, tcp).await?;
    tls.write_all(request.as_bytes()).await?;
    tls.flush().await?;
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut buf)).await;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn body_of(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or("")
}

fn cookie(response: &str, name: &str) -> String {
    for line in response.lines() {
        let Some((header, value)) = line.split_once(':') else {
            continue;
        };
        if !header.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        let value = value.trim();
        if let Some(rest) = value.strip_prefix(&format!("{name}=")) {
            return rest.split(';').next().unwrap_or("").to_string();
        }
    }
    String::new()
}
