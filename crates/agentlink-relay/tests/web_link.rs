//! Dashboard socket for files and a terminal. Cookie session, not a device key.

use std::time::Duration;

use agentlink_core::parse_fingerprint;
use agentlink_core::tls::client_config;
use agentlink_relay::{RelayConfig, RelayHandle};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::Message;

#[tokio::test]
async fn web_socket_requires_the_dashboard_session_and_only_file_or_pty_ops() {
    let dir = tempfile::tempdir().unwrap();
    let relay = RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        capture: None,
        database_url: None,
        allow_signup: false,
        bootstrap_admin: false,
        db_schema: None,
        trust_proxy: Vec::new(),
        print_admin_token: false,
    })
    .await
    .unwrap();
    let admin = agentlink_core::Client::connect(&agentlink_core::ClientSettings {
        relay: format!("wss://127.0.0.1:{}", relay.local_addr.port()),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await
    .unwrap();
    admin
        .user_add("alice", "password-alice", false)
        .await
        .unwrap();

    let page = http(
        &relay,
        "GET / HTTP/1.1\r\nHost: relay.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let html = body_of(&page);
    assert!(html.contains("not available in the browser"), "{html}");
    assert!(!html.contains("openSession(\"terminal\""), "{html}");
    assert!(!html.contains("t(\"card.desktop\")"), "{html}");
    assert!(html.contains("/v1/web?csrf="), "{html}");
    assert!(!html.contains("<script src"), "{html}");

    let plain = http(
        &relay,
        "GET /v1/web HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(plain.contains("426"), "{plain}");

    let anon = ws_error(&relay, "", "nope").await;
    assert!(anon.contains("401"), "{anon}");

    let login = http(
        &relay,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{{\"username\":\"alice\",\"password\":\"password-alice\"}}",
            "{\"username\":\"alice\",\"password\":\"password-alice\"}".len()
        ),
    )
    .await;
    assert!(login.contains("200"), "{login}");
    let session = cookie(&login, "agentlink_session");
    let csrf = cookie(&login, "agentlink_csrf");
    assert!(!session.is_empty() && !csrf.is_empty(), "{login}");

    let bad = ws_error(&relay, &session, "not-the-csrf").await;
    assert!(bad.contains("403"), "{bad}");

    let mut ws = connect_web(&relay, &session, &csrf).await;
    let hello = next_json(&mut ws).await;
    assert_eq!(hello["type"], "hello_ok", "{hello}");

    send_json(
        &mut ws,
        &serde_json::json!({
            "type": "set_policy",
            "request_id": "11111111-1111-4111-8111-111111111111",
            "node_id": "missing",
            "policy": {
                "allow_read": true,
                "allow_write": false,
                "allow_exec": false,
                "allow_desktop": false,
                "allow_desktop_stream": false,
                "allow_remote_view": false,
                "allow_remote_control": false
            }
        }),
    )
    .await;
    let denied = next_json(&mut ws).await;
    assert_eq!(denied["ok"], false, "{denied}");
    assert!(
        denied["error"]
            .as_str()
            .unwrap_or("")
            .contains("browser control is disabled"),
        "{denied}"
    );

    send_json(
        &mut ws,
        &serde_json::json!({
            "type": "invoke",
            "request_id": "22222222-2222-4222-8222-222222222222",
            "node_id": "missing-node",
            "client_id": "",
            "op": { "op": "list_dir", "path": "." }
        }),
    )
    .await;
    let missing = next_json(&mut ws).await;
    assert_eq!(missing["type"], "result", "{missing}");
    assert_eq!(missing["ok"], false, "{missing}");

    let logout_body = "";
    let logout = http(
        &relay,
        &format!(
            "POST /auth/logout HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: agentlink_session={session}\r\nX-CSRF-Token: {csrf}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{logout_body}",
            logout_body.len()
        ),
    )
    .await;
    assert!(logout.contains("200"), "{logout}");

    send_json(&mut ws, &serde_json::json!({ "type": "ping" })).await;
    let expired = next_json(&mut ws).await;
    assert_eq!(expired["ok"], false, "{expired}");
    assert!(
        expired["error"]
            .as_str()
            .unwrap_or("")
            .contains("session expired"),
        "{expired}"
    );
}

async fn connect_web(
    relay: &RelayHandle,
    session: &str,
    csrf: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>> {
    let tls = tls_stream(relay).await;
    let mut request = format!(
        "wss://127.0.0.1:{}/v1/web?csrf={csrf}",
        relay.local_addr.port()
    )
    .into_client_request()
    .unwrap();
    request.headers_mut().insert(
        "cookie",
        HeaderValue::from_str(&format!("agentlink_session={session}")).unwrap(),
    );
    let (ws, _) = tokio_tungstenite::client_async(request, tls).await.unwrap();
    ws
}

async fn ws_error(relay: &RelayHandle, session: &str, csrf: &str) -> String {
    let tls = tls_stream(relay).await;
    let mut request = format!(
        "wss://127.0.0.1:{}/v1/web?csrf={csrf}",
        relay.local_addr.port()
    )
    .into_client_request()
    .unwrap();
    if !session.is_empty() {
        request.headers_mut().insert(
            "cookie",
            HeaderValue::from_str(&format!("agentlink_session={session}")).unwrap(),
        );
    }
    match tokio_tungstenite::client_async(request, tls).await {
        Ok(_) => "unexpected handshake success".into(),
        Err(err) => err.to_string(),
    }
}

async fn tls_stream(relay: &RelayHandle) -> tokio_rustls::client::TlsStream<TcpStream> {
    let pin = parse_fingerprint(&relay.fingerprint).unwrap();
    let config = client_config(pin).unwrap();
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(relay.local_addr).await.unwrap();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("agentlink")
        .unwrap()
        .to_owned();
    connector.connect(name, tcp).await.unwrap()
}

async fn next_json(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
) -> serde_json::Value {
    let deadline = Duration::from_secs(10);
    let msg = tokio::time::timeout(deadline, ws.next())
        .await
        .expect("timed out waiting for a dashboard frame")
        .expect("socket closed")
        .expect("socket error");
    let Message::Text(text) = msg else {
        panic!("expected text, got {msg:?}");
    };
    serde_json::from_str(text.as_ref()).unwrap()
}

async fn send_json(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>,
    value: &serde_json::Value,
) {
    ws.send(Message::Text(value.to_string().into()))
        .await
        .unwrap();
}

async fn http(relay: &RelayHandle, request: &str) -> String {
    let pin = parse_fingerprint(&relay.fingerprint).unwrap();
    let config = client_config(pin).unwrap();
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(relay.local_addr).await.unwrap();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("agentlink")
        .unwrap()
        .to_owned();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn body_of(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or("")
}

#[tokio::test]
async fn public_ice_hides_turn_secrets_and_minting_requires_a_session_or_ticket() {
    let _env = TurnEnv::set(&[
        (
            "AGENTLINK_TURN_URLS",
            "turn:turn.example:3478,turns:turn.example:443?transport=tcp",
        ),
        ("AGENTLINK_TURN_SECRET", "test-turn-secret"),
        ("AGENTLINK_TURN_USERNAME", "static-user-must-not-leak"),
        ("AGENTLINK_TURN_PASSWORD", "static-password-must-not-leak"),
    ]);

    let dir = tempfile::tempdir().unwrap();
    let relay = RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.path().to_path_buf(),
        capture: None,
        database_url: None,
        allow_signup: false,
        bootstrap_admin: false,
        db_schema: None,
        trust_proxy: Vec::new(),
        print_admin_token: false,
    })
    .await
    .unwrap();

    let public_cfg = exchange(&relay, "GET", "/view/config.json", "", "").await;
    assert!(public_cfg.contains("200"), "{public_cfg}");
    let public_body = body_of(&public_cfg);
    let public_json: serde_json::Value = serde_json::from_str(public_body).unwrap();
    assert_eq!(public_json["media"], "dtls-srtp");
    assert_eq!(public_json["turn_auth"], "rest");
    assert_eq!(public_json["turn"][0]["urls"][0], "turn:turn.example:3478");
    assert!(public_json["turn"][0].get("username").is_none());
    assert!(public_json["turn"][0].get("credential").is_none());
    assert!(
        !public_body.contains("static-password-must-not-leak")
            && !public_body.contains("static-user-must-not-leak")
            && !public_body.contains("test-turn-secret"),
        "{public_body}"
    );

    let anon = exchange(
        &relay,
        "POST",
        "/api/ice",
        "Content-Type: application/json",
        "{}",
    )
    .await;
    assert!(anon.contains("401"), "{anon}");

    let bogus = exchange(
        &relay,
        "POST",
        "/api/ice",
        "Content-Type: application/json",
        "{\"ticket\":\"not-a-real-ticket\"}",
    )
    .await;
    assert!(bogus.contains("401"), "{bogus}");
    assert!(
        !body_of(&bogus).contains("static-password-must-not-leak"),
        "{bogus}"
    );

    let admin = agentlink_core::Client::connect(&agentlink_core::ClientSettings {
        relay: format!("wss://127.0.0.1:{}", relay.local_addr.port()),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await
    .unwrap();
    admin
        .user_add("alice", "password-alice", false)
        .await
        .unwrap();
    let login_body = "{\"username\":\"alice\",\"password\":\"password-alice\"}";
    let login = exchange(
        &relay,
        "POST",
        "/auth/login",
        "Content-Type: application/json",
        login_body,
    )
    .await;
    assert!(login.contains("200"), "{login}");
    let session = cookie(&login, "agentlink_session");
    let csrf = cookie(&login, "agentlink_csrf");
    let authed = exchange(
        &relay,
        "POST",
        "/api/ice",
        &format!(
            "Content-Type: application/json\r\nCookie: agentlink_session={session}\r\nX-CSRF-Token: {csrf}"
        ),
        "{}",
    )
    .await;
    assert!(authed.contains("200"), "{authed}");
    let ice: serde_json::Value = serde_json::from_str(body_of(&authed)).unwrap();
    assert_eq!(ice["media"], "dtls-srtp");
    assert_eq!(ice["turn_auth"], "rest");
    let username = ice["turn"][0]["username"].as_str().unwrap();
    let credential = ice["turn"][0]["credential"].as_str().unwrap();
    assert!(username.ends_with(":web:alice"), "{username}");
    let expiry: i64 = username.split(':').next().unwrap().parse().unwrap();
    let now = agentlink_core::util::unix_now();
    let ttl = expiry.abs_diff(now);
    assert!(
        (580..=620).contains(&ttl),
        "TURN REST ttl {ttl}s is outside the default 10 minute window"
    );
    assert_eq!(
        credential,
        agentlink_core::rest_credential("test-turn-secret", username).unwrap()
    );
    assert!(!credential.contains("static-password"));
    assert!(ice["attempts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["ice_transport_policy"] == "relay"
            && item["ice_servers"][0]["credential"] == credential));

    let missing = exchange(
        &relay,
        "POST",
        "/api/view-ticket",
        &format!(
            "Content-Type: application/json\r\nCookie: agentlink_session={session}\r\nX-CSRF-Token: {csrf}"
        ),
        "{\"node\":\"missing\"}",
    )
    .await;
    assert!(missing.contains("403"), "{missing}");

    let revoked = exchange(
        &relay,
        "POST",
        "/api/view-ticket/revoke",
        &format!(
            "Content-Type: application/json\r\nCookie: agentlink_session={session}\r\nX-CSRF-Token: {csrf}"
        ),
        "{\"ticket\":\"missing\"}",
    )
    .await;
    assert!(revoked.contains("404"), "{revoked}");

    let audit = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
    assert!(audit.contains("\"op\":\"ice.mint\""), "{audit}");
    assert!(
        audit.contains("legacy.admin"),
        "the admin client hello should record the legacy token: {audit}"
    );
}

struct TurnEnv {
    saved: Vec<(&'static str, Option<String>)>,
}

impl TurnEnv {
    fn set(pairs: &[(&'static str, &str)]) -> Self {
        let saved = pairs
            .iter()
            .map(|(key, value)| {
                let previous = std::env::var(key).ok();
                std::env::set_var(key, value);
                (*key, previous)
            })
            .collect();
        Self { saved }
    }
}

impl Drop for TurnEnv {
    fn drop(&mut self) {
        for (key, previous) in &self.saved {
            match previous {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}

async fn exchange(
    relay: &RelayHandle,
    method: &str,
    path: &str,
    extra: &str,
    body: &str,
) -> String {
    let extra = if extra.is_empty() {
        String::new()
    } else {
        format!("{extra}\r\n")
    };
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n{extra}\r\n{body}",
        body.len()
    );
    http(relay, &request).await
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
