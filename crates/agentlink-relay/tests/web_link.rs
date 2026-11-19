//! Browser surfaces: info/account stay; former control admissions fail closed.

use std::time::Duration;

use agentlink_core::parse_fingerprint;
use agentlink_core::tls::client_config;
use agentlink_relay::{RelayConfig, RelayHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;

#[tokio::test]
async fn browser_control_admissions_are_gone_while_dashboard_session_works() {
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
        legacy_admin_override: Some((true, Some(86_400))),
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
    assert!(!html.contains("/v1/web"), "{html}");
    assert!(!html.contains("/api/view-ticket"), "{html}");
    assert!(!html.contains("createTerm"), "{html}");
    assert!(html.contains("openGuide"), "{html}");
    assert!(!html.contains("<script src"), "{html}");

    let plain = http(
        &relay,
        "GET /v1/web HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(plain.contains("410"), "{plain}");
    assert!(
        plain.to_ascii_lowercase().contains("browser control is disabled")
            || body_of(&plain).contains("browser control is disabled"),
        "{plain}"
    );

    let anon = ws_error(&relay, "", "nope").await;
    assert!(
        anon.contains("410") || anon.contains("Gone") || anon.contains("401"),
        "{anon}"
    );

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

    // Even with a valid dashboard session, the control socket must not upgrade.
    let authed_ws = ws_error(&relay, &session, &csrf).await;
    assert!(
        authed_ws.contains("410") || authed_ws.contains("Gone"),
        "logged-in /v1/web upgrade must be 410 Gone, got {authed_ws}"
    );

    let nodes = exchange(
        &relay,
        "GET",
        "/api/nodes",
        &format!("Cookie: agentlink_session={session}\r\nX-CSRF-Token: {csrf}"),
        "",
    )
    .await;
    assert!(nodes.contains("200"), "{nodes}");

    let ticket = exchange(
        &relay,
        "POST",
        "/api/view-ticket",
        &format!(
            "Content-Type: application/json\r\nCookie: agentlink_session={session}\r\nX-CSRF-Token: {csrf}"
        ),
        "{\"node\":\"missing\"}",
    )
    .await;
    assert!(ticket.contains("410"), "{ticket}");
    assert!(!body_of(&ticket).contains("\"ticket\""), "{ticket}");

    let revoke = exchange(
        &relay,
        "POST",
        "/api/view-ticket/revoke",
        &format!(
            "Content-Type: application/json\r\nCookie: agentlink_session={session}\r\nX-CSRF-Token: {csrf}"
        ),
        "{\"ticket\":\"missing\"}",
    )
    .await;
    assert!(revoke.contains("410"), "{revoke}");

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
}

#[tokio::test]
async fn public_ice_still_mints_for_dashboard_session_without_view_tickets() {
    let _env = TurnEnv::set(&[
        ("AGENTLINK_TURN_URLS", "turn:turn.example:3478?transport=udp"),
        ("AGENTLINK_TURN_SECRET", "test-turn-secret"),
        ("AGENTLINK_TURN_TTL_SECS", "600"),
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
        legacy_admin_override: Some((true, Some(86_400))),
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

    let login = http(
        &relay,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{{\"username\":\"alice\",\"password\":\"password-alice\"}}",
            "{\"username\":\"alice\",\"password\":\"password-alice\"}".len()
        ),
    )
    .await;
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
    assert!(missing.contains("410"), "{missing}");
    assert!(!body_of(&missing).contains("\"ticket\""), "{missing}");

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
    assert!(revoked.contains("410"), "{revoked}");

    let audit = std::fs::read_to_string(dir.path().join("audit.jsonl")).unwrap_or_default();
    assert!(audit.contains("\"op\":\"ice.mint\""), "{audit}");
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

async fn http(relay: &RelayHandle, request: &str) -> String {
    let mut tls = tls_stream(relay).await;
    tls.write_all(request.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tls.read_to_end(&mut buf)).await;
    String::from_utf8_lossy(&buf).into_owned()
}

fn body_of(response: &str) -> &str {
    response
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or(response)
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
