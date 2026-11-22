//! Wave 1 relay security, multi-tenancy, native TURN/ICE, HTTP hardening, and UX
//! end-to-end integration tests.

use std::sync::OnceLock;
use std::time::Duration;

use agentlink_core::protocol::{Envelope, Role, PROTOCOL_VERSION};
use agentlink_core::{Client, ClientSettings, Identity, NodePolicy};
use agentlink_relay::{
    set_max_concurrent_downloads_for_test, set_public_url_for_test, RelayConfig, RelayHandle,
};
use futures_util::{SinkExt, StreamExt};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

fn global_env_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

async fn spawn(dir: &std::path::Path, bootstrap_admin: bool) -> RelayHandle {
    RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_path_buf(),
        capture: None,
        database_url: None,
        allow_signup: false,
        bootstrap_admin,
        db_schema: None,
        trust_proxy: Vec::new(),
        print_admin_token: false,
        legacy_admin_override: Some((true, Some(86_400))),
    })
    .await
    .unwrap()
}

async fn tls_connect(relay: &RelayHandle) -> tokio_rustls::client::TlsStream<TcpStream> {
    let pin = agentlink_core::parse_fingerprint(&relay.fingerprint).unwrap();
    let config = agentlink_core::tls::client_config(pin).unwrap();
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(relay.local_addr).await.unwrap();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("agentlink")
        .unwrap()
        .to_owned();
    connector.connect(name, tcp).await.unwrap()
}

async fn https_raw(relay: &RelayHandle, request: &str) -> Vec<u8> {
    let mut tls = tls_connect(relay).await;
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(10), tls.read_to_end(&mut buf)).await;
    buf
}

async fn https(relay: &RelayHandle, request: &str) -> String {
    String::from_utf8_lossy(&https_raw(relay, request).await).into_owned()
}

fn split_response(resp: &str) -> (&str, &str) {
    resp.split_once("\r\n\r\n").unwrap_or((resp, ""))
}

fn cookie(response: &str, name: &str) -> String {
    for line in response.lines() {
        let Some((header, value)) = line.split_once(':') else {
            continue;
        };
        if !header.eq_ignore_ascii_case("set-cookie") {
            continue;
        }
        if let Some(rest) = value.trim().strip_prefix(&format!("{name}=")) {
            return rest.split(';').next().unwrap_or("").to_string();
        }
    }
    String::new()
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

#[tokio::test]
async fn healthz_returns_200_ok_json_with_security_headers() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), false).await;
    let host = format!("127.0.0.1:{}", relay.local_addr.port());

    let resp = https(
        &relay,
        &format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    let (head, body) = split_response(&resp);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(head.to_ascii_lowercase().contains("application/json"), "{head}");
    assert!(head.to_ascii_lowercase().contains("x-frame-options: deny"), "{head}");
    assert!(head.to_ascii_lowercase().contains("x-content-type-options: nosniff"), "{head}");
    assert!(head.to_ascii_lowercase().contains("cache-control: no-store"), "{head}");
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed, serde_json::json!({"status": "ok"}));

    let head_resp = https(
        &relay,
        &format!("HEAD /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    let (head2, body2) = split_response(&head_resp);
    assert!(head2.starts_with("HTTP/1.1 200 OK"), "{head2}");
    assert!(body2.is_empty(), "HEAD /healthz must omit body: {body2}");
}

#[tokio::test]
async fn audit_endpoints_carry_full_security_headers_and_avoid_session_storage() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), false).await;
    let host = format!("127.0.0.1:{}", relay.local_addr.port());

    let page = https(
        &relay,
        &format!("GET /audit HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    let (head, html) = split_response(&page);
    let lower = head.to_ascii_lowercase();
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    assert!(lower.contains("content-security-policy:"), "{head}");
    assert!(lower.contains("frame-ancestors 'none'"), "{head}");
    assert!(lower.contains("x-frame-options: deny"), "{head}");
    assert!(lower.contains("x-content-type-options: nosniff"), "{head}");
    assert!(lower.contains("cache-control: no-store"), "{head}");
    assert!(lower.contains("referrer-policy: no-referrer"), "{head}");
    assert!(!html.contains("sessionStorage"), "audit HTML must not use sessionStorage");
    assert!(!html.contains("localStorage"), "audit HTML must not use localStorage");

    let recs = https(
        &relay,
        &format!(
            "GET /audit/records?limit=10 HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n",
            relay.admin_token
        ),
    )
    .await;
    let (rhead, rbody) = split_response(&recs);
    let rlower = rhead.to_ascii_lowercase();
    assert!(rhead.starts_with("HTTP/1.1 200 OK"), "{rhead}");
    assert!(rlower.contains("content-security-policy:"), "{rhead}");
    assert!(rlower.contains("x-frame-options: deny"), "{rhead}");
    assert!(rlower.contains("x-content-type-options: nosniff"), "{rhead}");
    assert!(rlower.contains("cache-control: no-store"), "{rhead}");
    assert!(serde_json::from_str::<serde_json::Value>(rbody).unwrap().is_array());
}

#[tokio::test]
async fn post_api_ice_accepts_bearer_without_csrf_and_denies_zero_node_and_revoked_callers() {
    let _guard = global_env_lock().lock().await;
    let _env = TurnEnv::set(&[
        ("AGENTLINK_TURN_URLS", "turn:turn.example:3478?transport=udp"),
        ("AGENTLINK_TURN_SECRET", "wave1-turn-secret"),
        ("AGENTLINK_TURN_TTL_SECS", "600"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), false).await;
    let relay_url = format!("wss://127.0.0.1:{}", relay.local_addr.port());
    let host = format!("127.0.0.1:{}", relay.local_addr.port());

    let admin = Client::connect_identity(
        &ClientSettings {
            relay: relay_url.clone(),
            token: relay.admin_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        Identity::generate(),
        true,
    )
    .await
    .unwrap();
    admin
        .user_add("alice", "password-alice", false)
        .await
        .unwrap();
    admin.user_add("bob", "password-bob", false).await.unwrap();

    let alice_key = Identity::generate();
    let alice_session = agentlink_core::client::login_user(
        &relay_url,
        &relay.fingerprint,
        None,
        &alice_key,
        "alice",
        "password-alice",
        None,
        "cli",
    )
    .await
    .unwrap();

    // 1. Native Bearer auth WITHOUT CSRF, while Alice has 0 nodes -> 403 Forbidden (SEC-16).
    let zero_node = https(
        &relay,
        &format!(
            "POST /api/ice HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",
            alice_session.access_token
        ),
    )
    .await;
    assert!(
        zero_node.starts_with("HTTP/1.1 403"),
        "0-node Bearer caller must be denied with 403: {zero_node}"
    );

    // 2. Invalid Bearer token -> 401 Unauthorized.
    let bad_bearer = https(
        &relay,
        &format!(
            "POST /api/ice HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer atk.not-a-real-token\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
        ),
    )
    .await;
    assert!(bad_bearer.starts_with("HTTP/1.1 401"), "{bad_bearer}");

    // 3. Enroll a node for Alice; now Bearer token WITHOUT CSRF succeeds with `ice_servers` + `ttl_secs`!
    let alice_client = Client::connect_identity(
        &ClientSettings {
            relay: relay_url.clone(),
            token: alice_session.access_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        alice_key,
        true,
    )
    .await
    .unwrap();
    alice_client
        .enroll_self("alice-desk", &Identity::generate(), Some(NodePolicy::full()))
        .await
        .unwrap();

    let ok = https(
        &relay,
        &format!(
            "POST /api/ice HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",
            alice_session.access_token
        ),
    )
    .await;
    let (head, body) = split_response(&ok);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let ice: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(ice["ttl_secs"], 600);
    let servers = ice["ice_servers"].as_array().expect("ice_servers array");
    let turn = servers
        .iter()
        .find(|s| s.get("credential").is_some())
        .expect("TURN entry with minted REST credentials");
    let username = turn["username"].as_str().unwrap();
    let credential = turn["credential"].as_str().unwrap();
    assert!(username.ends_with(":user:alice"), "{username}");
    assert_eq!(
        credential,
        agentlink_core::rest_credential("wave1-turn-secret", username).unwrap()
    );

    // 3b. Cross-crate verification: `agentlink_core::fetch_relay_ice_servers` over
    //     pinned TLS against live `POST /api/ice` parses the exact Bearer response
    //     (and does not short-circuit on relay-side `AGENTLINK_TURN_URLS` + `AGENTLINK_TURN_SECRET`).
    let trust = agentlink_core::tls::RelayTrust::parse(&relay.fingerprint, None).unwrap();
    let core_ice = agentlink_core::fetch_relay_ice_servers(
        &relay_url,
        &trust,
        &alice_session.access_token,
    )
    .await
    .expect("core fetch_relay_ice_servers against live TLS relay");
    assert_eq!(core_ice.ttl_secs, 600);
    let core_json = core_ice.to_json_servers();
    let core_turn = core_json
        .iter()
        .find(|s| s.get("credential").is_some())
        .expect("core_ice TURN entry with minted REST credentials");
    let core_user = core_turn["username"].as_str().unwrap();
    let core_cred = core_turn["credential"].as_str().unwrap();
    assert!(core_user.ends_with(":user:alice"), "{core_user}");
    assert_eq!(
        core_cred,
        agentlink_core::rest_credential("wave1-turn-secret", core_user).unwrap()
    );

    // 4. Revoke Alice's device -> Bearer token is immediately rejected with 401!
    admin
        .revoke_device(&alice_session.device_id)
        .await
        .unwrap();
    let revoked = https(
        &relay,
        &format!(
            "POST /api/ice HTTP/1.1\r\nHost: {host}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}",
            alice_session.access_token
        ),
    )
    .await;
    assert!(
        revoked.starts_with("HTTP/1.1 401"),
        "revoked device Bearer token must return 401: {revoked}"
    );
}

#[tokio::test]
async fn public_url_overrides_untrusted_host_header_and_strict_host_rejects_bad_headers() {
    let _guard = global_env_lock().lock().await;

    struct ResetPublicUrl;
    impl Drop for ResetPublicUrl {
        fn drop(&mut self) {
            set_public_url_for_test(None);
        }
    }
    let _reset = ResetPublicUrl;

    // 1. With public URL configured, poisoned Host header is NEVER reflected.
    set_public_url_for_test(Some("https://canonical.example:8443"));
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), false).await;
    let admin = Client::connect_identity(
        &ClientSettings {
            relay: format!("wss://127.0.0.1:{}", relay.local_addr.port()),
            token: relay.admin_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        Identity::generate(),
        true,
    )
    .await
    .unwrap();
    admin
        .user_add("alice", "password-alice", false)
        .await
        .unwrap();

    let sh = https(
        &relay,
        "GET /install.sh HTTP/1.1\r\nHost: evil.attacker\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(sh.starts_with("HTTP/1.1 200 OK"), "{sh}");
    assert!(sh.contains("wss://canonical.example:8443"), "{sh}");
    assert!(!sh.contains("evil.attacker"), "{sh}");

    let ps1 = https(
        &relay,
        "GET /install.ps1 HTTP/1.1\r\nHost: evil.attacker\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(ps1.starts_with("HTTP/1.1 200 OK"), "{ps1}");
    assert!(ps1.contains("wss://canonical.example:8443"), "{ps1}");
    assert!(!ps1.contains("evil.attacker"), "{ps1}");

    let login_body = r#"{"username":"alice","password":"password-alice"}"#;
    let login = https(
        &relay,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{login_body}",
            relay.local_addr.port(),
            login_body.len()
        ),
    )
    .await;
    let sess = cookie(&login, "agentlink_session");
    let csrf = cookie(&login, "agentlink_csrf");
    let tok_body = r#"{"name":"box","access":"exec","ttl_secs":600,"uses":1}"#;
    let tok = https(
        &relay,
        &format!(
            "POST /api/tokens HTTP/1.1\r\nHost: evil.attacker\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCookie: agentlink_session={sess}\r\nX-CSRF-Token: {csrf}\r\nConnection: close\r\n\r\n{tok_body}",
            tok_body.len()
        ),
    )
    .await;
    assert!(tok.starts_with("HTTP/1.1 200 OK"), "{tok}");
    assert!(tok.contains("https://canonical.example:8443/install.sh"), "{tok}");
    assert!(!tok.contains("evil.attacker"), "{tok}");

    // 2. Without public URL configured, malformed or duplicate Host headers return 400.
    set_public_url_for_test(None);
    let dir2 = tempfile::tempdir().unwrap();
    let relay2 = spawn(dir2.path(), false).await;
    let bad_host = https(
        &relay2,
        "GET /install.sh HTTP/1.1\r\nHost: evil.com;rm\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(bad_host.starts_with("HTTP/1.1 400"), "{bad_host}");
    let dup_host = https(
        &relay2,
        "GET /install.sh HTTP/1.1\r\nHost: a.example\r\nHost: b.example\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(dup_host.starts_with("HTTP/1.1 400"), "{dup_host}");
}

#[tokio::test]
async fn dl_streams_async_rejects_traversal_and_enforces_concurrency_cap() {
    let _guard = global_env_lock().lock().await;
    struct ResetDlCap;
    impl Drop for ResetDlCap {
        fn drop(&mut self) {
            set_max_concurrent_downloads_for_test(None);
        }
    }
    let _reset = ResetDlCap;
    set_max_concurrent_downloads_for_test(Some(1));

    let dir = tempfile::tempdir().unwrap();
    let dist = dir.path().join("dist");
    std::fs::create_dir_all(&dist).unwrap();
    let payload: Vec<u8> = (0..262_144u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dist.join("artifact.bin"), &payload).unwrap();

    let relay = spawn(dir.path(), false).await;
    let host = format!("127.0.0.1:{}", relay.local_addr.port());

    // Traversal names are rejected with 400.
    let dotdot = https(
        &relay,
        &format!("GET /dl/.. HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(dotdot.starts_with("HTTP/1.1 400"), "{dotdot}");

    // HEAD reports exact Content-Length without body.
    let head = https(
        &relay,
        &format!("HEAD /dl/artifact.bin HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    let (hhead, hbody) = split_response(&head);
    assert!(hhead.starts_with("HTTP/1.1 200 OK"), "{hhead}");
    assert!(
        hhead.contains(&format!("Content-Length: {}", payload.len())),
        "{hhead}"
    );
    assert!(hbody.is_empty());

    // GET streams the exact 256 KiB payload asynchronously.
    let raw = https_raw(
        &relay,
        &format!("GET /dl/artifact.bin HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    let pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("http separator");
    assert_eq!(&raw[pos + 4..], payload.as_slice());

    // Hold a slow download (large file, client doesn't drain yet) -> 2nd concurrent download gets 503.
    let big = vec![0x55u8; 4 * 1024 * 1024];
    std::fs::write(dist.join("big.bin"), &big).unwrap();
    let mut slow = tls_connect(&relay).await;
    slow.write_all(
        format!("GET /dl/big.bin HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").as_bytes(),
    )
    .await
    .unwrap();
    slow.flush().await.unwrap();
    // Read only 16 bytes so server is mid-stream holding the single download permit.
    let mut tiny = [0u8; 16];
    let _ = tokio::time::timeout(Duration::from_secs(3), slow.read_exact(&mut tiny)).await;

    let busy = https(
        &relay,
        &format!("GET /dl/big.bin HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(
        busy.starts_with("HTTP/1.1 503"),
        "excess concurrent download must return 503: {busy}"
    );
    drop(slow);
}

#[tokio::test]
async fn bootstrap_admin_login_error_is_actionable_and_never_doubled() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), true).await;
    let relay_url = format!("wss://127.0.0.1:{}", relay.local_addr.port());
    assert!(relay.bootstrap_password.is_some());
    assert!(dir.path().join("bootstrap.password").is_file());

    let err = agentlink_core::client::login_user(
        &relay_url,
        &relay.fingerprint,
        None,
        &Identity::generate(),
        "admin",
        "wrong-bootstrap-pw",
        None,
        "cli",
    )
    .await
    .unwrap_err();
    let text = err.to_string();
    assert!(
        !text.contains("authentication failed: authentication failed:"),
        "error message must not double 'authentication failed:': {text}"
    );
    assert!(
        text.contains("bootstrap admin password must be rotated first"),
        "{text}"
    );
    assert!(text.contains("agentlink relay --data-dir"), "{text}");
    assert!(text.contains("user passwd admin"), "{text}");

    // HTTP login also returns a clean non-doubled message.
    let body = r#"{"username":"admin","password":"wrong-bootstrap-pw"}"#;
    let resp = https(
        &relay,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            relay.local_addr.port(),
            body.len()
        ),
    )
    .await;
    let (head, rbody) = split_response(&resp);
    assert!(head.starts_with("HTTP/1.1 401"), "{head}");
    assert!(!rbody.contains("authentication failed:"), "{rbody}");
    assert!(rbody.contains("agentlink relay --data-dir"), "{rbody}");
}

#[tokio::test]
async fn e2e_ws_agent_cannot_user_passwd_or_set_policy_and_wire_reauth_works() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), false).await;
    let relay_url = format!("wss://127.0.0.1:{}", relay.local_addr.port());

    let admin = Client::connect_identity(
        &ClientSettings {
            relay: relay_url.clone(),
            token: relay.admin_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        Identity::generate(),
        true,
    )
    .await
    .unwrap();
    admin
        .user_add("alice", "alice-pw-init", false)
        .await
        .unwrap();

    let alice_key = Identity::generate();
    let alice_session = agentlink_core::client::login_user(
        &relay_url,
        &relay.fingerprint,
        None,
        &alice_key,
        "alice",
        "alice-pw-init",
        None,
        "cli",
    )
    .await
    .unwrap();
    let alice = Client::connect_identity(
        &ClientSettings {
            relay: relay_url.clone(),
            token: alice_session.access_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        alice_key.clone(),
        true,
    )
    .await
    .unwrap();
    let node_id_obj = Identity::generate();
    alice
        .enroll_self("alice-box", &node_id_obj, Some(NodePolicy::read_only()))
        .await
        .unwrap();
    let agent_id = Identity::generate();
    alice
        .register_client("narrow-agent", agent_id.public_hex())
        .await
        .unwrap();

    // Connect directly over WS as the registered Agent key and send UserPasswd + SetPolicy.
    let tls = tls_connect(&relay).await;
    let (mut agent_ws, _) = tokio_tungstenite::client_async(
        format!("wss://127.0.0.1:{}/v1/connect", relay.local_addr.port()),
        tls,
    )
    .await
    .unwrap();
    agent_ws
        .send(Message::Text(
            serde_json::to_string(&Envelope::Hello {
                role: Role::Client,
                protocol: PROTOCOL_VERSION,
                token: None,
                node_id: None,
                public_key: Some(agent_id.public_hex().to_string()),
                name: Some("narrow-agent".into()),
                pairing_token: None,
                hostname: None,
                os: None,
                arch: None,
                version: None,
                ceiling: None,
                has_display: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let challenge_txt = agent_ws.next().await.unwrap().unwrap().into_text().unwrap();
    let Envelope::Challenge { nonce } = serde_json::from_str(&challenge_txt).unwrap() else {
        panic!("expected challenge");
    };
    let sig = agent_id.sign_nonce(&nonce);
    agent_ws
        .send(Message::Text(
            serde_json::to_string(&Envelope::Authenticate { signature: sig })
                .unwrap()
                .into(),
        ))
        .await
        .unwrap();
    let hello_ok = agent_ws.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(matches!(
        serde_json::from_str::<Envelope>(&hello_ok).unwrap(),
        Envelope::HelloOk { .. }
    ));

    // Agent tries UserPasswd targeting owner Alice -> DENIED.
    agent_ws
        .send(Message::Text(
            serde_json::json!({
                "type": "user_passwd",
                "request_id": "a-pw",
                "username": "alice",
                "password": "pwned-password",
                "current_password": "alice-pw-init"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let pw_reply: Envelope =
        serde_json::from_str(&agent_ws.next().await.unwrap().unwrap().into_text().unwrap())
            .unwrap();
    assert!(matches!(pw_reply, Envelope::Result { ok: false, .. }));

    // Agent tries SetPolicy targeting owner's node -> DENIED.
    agent_ws
        .send(Message::Text(
            serde_json::to_string(&Envelope::SetPolicy {
                request_id: "a-pol".into(),
                node_id: node_id_obj.public_hex().to_string(),
                policy: NodePolicy::full(),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let pol_reply: Envelope =
        serde_json::from_str(&agent_ws.next().await.unwrap().unwrap().into_text().unwrap())
            .unwrap();
    assert!(matches!(pol_reply, Envelope::Result { ok: false, .. }));

    // Now connect over raw WS as Operator Alice and verify wire-level reauth on UserPasswd.
    let tls2 = tls_connect(&relay).await;
    let (mut op_ws, _) = tokio_tungstenite::client_async(
        format!("wss://127.0.0.1:{}/v1/connect", relay.local_addr.port()),
        tls2,
    )
    .await
    .unwrap();
    op_ws
        .send(Message::Text(
            serde_json::to_string(&Envelope::Hello {
                role: Role::Client,
                protocol: PROTOCOL_VERSION,
                token: Some(alice_session.access_token.clone()),
                node_id: None,
                public_key: Some(alice_key.public_hex().to_string()),
                name: Some("cli".into()),
                pairing_token: None,
                hostname: None,
                os: None,
                arch: None,
                version: None,
                ceiling: None,
                has_display: None,
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let ch2 = op_ws.next().await.unwrap().unwrap().into_text().unwrap();
    let Envelope::Challenge { nonce: nonce2 } = serde_json::from_str(&ch2).unwrap() else {
        panic!("expected challenge");
    };
    op_ws
        .send(Message::Text(
            serde_json::to_string(&Envelope::Authenticate {
                signature: alice_key.sign_nonce(&nonce2),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let _ = op_ws.next().await.unwrap().unwrap(); // HelloOk

    // Missing current_password on self UserPasswd -> denied.
    op_ws
        .send(Message::Text(
            serde_json::json!({
                "type": "user_passwd",
                "request_id": "op-pw-1",
                "username": "alice",
                "password": "alice-pw-new"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let r1: Envelope =
        serde_json::from_str(&op_ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert!(matches!(r1, Envelope::Result { ok: false, .. }));

    // Valid current_password on self UserPasswd -> succeeds!
    op_ws
        .send(Message::Text(
            serde_json::json!({
                "type": "user_passwd",
                "request_id": "op-pw-2",
                "username": "alice",
                "password": "alice-pw-new",
                "current_password": "alice-pw-init"
            })
            .to_string()
            .into(),
        ))
        .await
        .unwrap();
    let r2: Envelope =
        serde_json::from_str(&op_ws.next().await.unwrap().unwrap().into_text().unwrap()).unwrap();
    assert!(matches!(r2, Envelope::Result { ok: true, .. }));

    // Verify new password works on fresh login.
    let logged_in = agentlink_core::client::login_user(
        &relay_url,
        &relay.fingerprint,
        None,
        &Identity::generate(),
        "alice",
        "alice-pw-new",
        None,
        "cli-2",
    )
    .await;
    assert!(logged_in.is_ok(), "new password must log in cleanly");
}

#[tokio::test]
async fn e2e_audit_chain_has_no_off_hashes_and_http_audit_blocks_node_user_spoof() {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), false).await;
    let relay_url = format!("wss://127.0.0.1:{}", relay.local_addr.port());
    let host = format!("127.0.0.1:{}", relay.local_addr.port());

    // Admin (legacy token -> note_legacy_use) creates alice and bob.
    let admin = Client::connect_identity(
        &ClientSettings {
            relay: relay_url.clone(),
            token: relay.admin_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        Identity::generate(),
        true,
    )
    .await
    .unwrap();
    admin
        .user_add("alice", "alice-pw-1234", false)
        .await
        .unwrap();
    admin.user_add("bob", "bob-pw-12345", false).await.unwrap();

    // Enroll a node for Bob via Bob's account session.
    let bob_dev = Identity::generate();
    let bob_sess = agentlink_core::client::login_user(
        &relay_url,
        &relay.fingerprint,
        None,
        &bob_dev,
        "bob",
        "bob-pw-12345",
        None,
        "bob-cli",
    )
    .await
    .unwrap();
    let bob_client = Client::connect_identity(
        &ClientSettings {
            relay: relay_url.clone(),
            token: bob_sess.access_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        bob_dev,
        true,
    )
    .await
    .unwrap();
    let bob_node_key = Identity::generate();
    let bob_node_id = bob_node_key.public_hex().to_string();
    bob_client
        .enroll_self("bob-box", &bob_node_key, Some(NodePolicy::full()))
        .await
        .unwrap();

    // Connect Bob's node over WS and send an AuditBatch spoofing `user: "alice"`.
    let tls = tls_connect(&relay).await;
    let (mut node_ws, _) = tokio_tungstenite::client_async(
        format!("wss://127.0.0.1:{}/v1/connect", relay.local_addr.port()),
        tls,
    )
    .await
    .unwrap();
    node_ws
        .send(Message::Text(
            serde_json::to_string(&Envelope::Hello {
                role: Role::Node,
                protocol: PROTOCOL_VERSION,
                name: Some("bob-box".into()),
                node_id: Some(bob_node_id.clone()),
                public_key: Some(bob_node_id.clone()),
                token: None,
                pairing_token: None,
                hostname: Some("bob-box".into()),
                os: Some("linux".into()),
                arch: Some("x86_64".into()),
                version: Some("0.1.0".into()),
                ceiling: Some(NodePolicy::full()),
                has_display: Some(false),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let ch = node_ws.next().await.unwrap().unwrap().into_text().unwrap();
    let Envelope::Challenge { nonce } = serde_json::from_str(&ch).unwrap() else {
        panic!("expected challenge, got {ch}");
    };
    node_ws
        .send(Message::Text(
            serde_json::to_string(&Envelope::Authenticate {
                signature: bob_node_key.sign_nonce(&nonce),
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    let hello_ok = node_ws.next().await.unwrap().unwrap().into_text().unwrap();
    assert!(
        matches!(
            serde_json::from_str::<Envelope>(&hello_ok).unwrap(),
            Envelope::HelloOk { .. }
        ),
        "expected HelloOk, got {hello_ok}"
    );
    node_ws
        .send(Message::Text(
            serde_json::to_string(&Envelope::AuditBatch {
                node_id: bob_node_id.clone(),
                records: vec![serde_json::json!({
                    "seq": 1,
                    "ts": format!("{}", agentlink_core::util::unix_now()),
                    "node_id": "relay",
                    "node_name": "relay",
                    "client_id": "forged",
                    "category": "exec",
                    "op": "bob.forged.alice.record",
                    "result": "ok",
                    "duration_ms": 0,
                    "prev_hash": "0",
                    "hash": "1",
                    "user": "alice",
                })],
            })
            .unwrap()
            .into(),
        ))
        .await
        .unwrap();
    // Ping-pong so relay has processed the preceding AuditBatch frame.
    node_ws
        .send(Message::Text(
            serde_json::to_string(&Envelope::Ping {}).unwrap().into(),
        ))
        .await
        .unwrap();
    let _ = node_ws.next().await;

    // Alice logs in over HTTP -> writes chained web.login to audit.jsonl.
    let login_body = r#"{"username":"alice","password":"alice-pw-1234"}"#;
    let login = https(
        &relay,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{login_body}",
            login_body.len()
        ),
    )
    .await;
    assert!(login.starts_with("HTTP/1.1 200 OK"), "{login}");
    let sess = cookie(&login, "agentlink_session");

    // 1. GET /audit/records for Alice must NOT contain Bob's spoofed record, while
    //    returning Alice's own relay-authored web.login event.
    let audit_resp = https(
        &relay,
        &format!(
            "GET /audit/records?limit=100 HTTP/1.1\r\nHost: {host}\r\nCookie: agentlink_session={sess}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    let (head, body) = split_response(&audit_resp);
    assert!(head.starts_with("HTTP/1.1 200 OK"), "{head}");
    let rows: Vec<serde_json::Value> = serde_json::from_str(body).unwrap();
    assert!(
        rows.iter().all(|r| r["op"] != "bob.forged.alice.record"),
        "Bob's spoofed AuditBatch record must not appear in Alice's /audit/records: {rows:?}"
    );
    assert!(
        rows.iter().any(|r| r["op"] == "web.login"),
        "Alice's own web.login record should appear in /audit/records: {rows:?}"
    );

    // 2. Relay audit.jsonl combines legacy admin auth + normal login + web.login
    //    with a valid continuous hash chain and zero "hash": "off" records.
    let relay_records = agentlink_core::audit::page_from_jsonl(
        &dir.path().join("audit.jsonl"),
        200,
        0,
        |_| true,
    );
    assert!(
        relay_records.len() >= 3,
        "expected legacy + bob login + alice web.login records, got {}",
        relay_records.len()
    );
    assert!(
        relay_records
            .iter()
            .all(|r| r.hash != "off" && r.prev_hash != "off" && !r.hash.is_empty()),
        "relay audit.jsonl must not contain 'off' hashes: {relay_records:?}"
    );
    agentlink_core::audit::verify_chain(&relay_records).unwrap();
}
