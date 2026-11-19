//! J-02 regressions: trusted-proxy rate limiting on plain HTTP, body read
//! timeout, query-token rejection, and bounded `/audit/records`.

use std::time::Duration;

use agentlink_relay::{RelayConfig, RelayHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

async fn spawn(dir: &std::path::Path, trust_proxy: Vec<String>) -> RelayHandle {
    RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_path_buf(),
        capture: None,
        database_url: None,
        allow_signup: false,
        bootstrap_admin: false,
        db_schema: None,
        trust_proxy,
        print_admin_token: false,
        legacy_admin_override: Some((true, Some(86_400))),
    })
    .await
    .unwrap()
}

async fn https(addr: std::net::SocketAddr, fingerprint: &str, request: &str) -> String {
    let pin = agentlink_core::parse_fingerprint(fingerprint).unwrap();
    let config = agentlink_core::tls::client_config(pin).unwrap();
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(addr).await.unwrap();
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

fn login_req(port: u16, xff: Option<&str>, body: &str) -> String {
    let mut headers = format!(
        "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nOrigin: https://127.0.0.1:{port}\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(xff) = xff {
        headers.push_str(&format!("X-Forwarded-For: {xff}\r\n"));
    }
    headers.push_str("Connection: close\r\n\r\n");
    headers.push_str(body);
    headers
}

#[tokio::test]
async fn trusted_proxy_rates_by_forwarded_ip_not_tcp_peer() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), vec!["127.0.0.1/32".into()]).await;
    let port = relay.local_addr.port();
    let body = r#"{"username":"nobody","password":"wrong"}"#;

    // 30 failed logins from attacker IP 203.0.113.99 should fill that bucket.
    for _ in 0..30 {
        let resp = https(
            relay.local_addr,
            &relay.fingerprint,
            &login_req(port, Some("203.0.113.99"), body),
        )
        .await;
        assert!(
            resp.contains("401") || resp.contains("429"),
            "expected auth failure, got: {resp}"
        );
    }
    // 31st from the same forwarded IP is rate-limited.
    let blocked = https(
        relay.local_addr,
        &relay.fingerprint,
        &login_req(port, Some("203.0.113.99"), body),
    )
    .await;
    assert!(
        blocked.contains("429"),
        "attacker bucket must trip: {blocked}"
    );

    // A different client behind the same trusted proxy must still be allowed.
    let other = https(
        relay.local_addr,
        &relay.fingerprint,
        &login_req(port, Some("198.51.100.42"), body),
    )
    .await;
    assert!(
        other.contains("401"),
        "legitimate peer must not share attacker bucket: {other}"
    );
}

#[tokio::test]
async fn untrusted_xff_is_ignored_for_http_login_rate() {
    let dir = tempfile::tempdir().unwrap();
    // No --trust-proxy: every connection rates by the real TCP peer (127.0.0.1).
    let relay = spawn(dir.path(), Vec::new()).await;
    let port = relay.local_addr.port();
    let body = r#"{"username":"nobody","password":"wrong"}"#;

    for i in 0..30u32 {
        let spoofed = format!("203.0.113.{i}");
        let resp = https(
            relay.local_addr,
            &relay.fingerprint,
            &login_req(port, Some(&spoofed), body),
        )
        .await;
        assert!(
            resp.contains("401"),
            "untrusted XFF must not create fresh buckets (#{i}): {resp}"
        );
    }
    let blocked = https(
        relay.local_addr,
        &relay.fingerprint,
        &login_req(port, Some("198.51.100.1"), body),
    )
    .await;
    assert!(
        blocked.contains("429"),
        "TCP peer bucket must trip when XFF is untrusted: {blocked}"
    );
}

#[tokio::test]
async fn audit_records_rejects_query_token_and_caps_page() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), Vec::new()).await;
    let port = relay.local_addr.port();
    let token = &relay.admin_token;

    // Seed more than the default page size.
    let audit_path = dir.path().join("audit.jsonl");
    let mut lines = String::new();
    for i in 0..250 {
        lines.push_str(&format!(
            "{{\"seq\":{i},\"ts\":\"2026-01-01T00:00:00Z\",\"node_id\":\"n\",\"node_name\":\"n\",\"client_id\":\"c\",\"category\":\"op\",\"op\":\"op{i}\",\"result\":\"ok\",\"duration_ms\":0,\"hash\":\"{i:064x}\",\"prev_hash\":\"{:064x}\"}}\n",
            0
        ));
    }
    std::fs::write(&audit_path, lines).unwrap();

    let rejected = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "GET /audit/records?token={token} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(
        rejected.contains("401"),
        "query token must be rejected: {rejected}"
    );

    let ok = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "GET /audit/records?limit=50 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(ok.contains("200"), "bearer auth must work: {ok}");
    let body = ok.split("\r\n\r\n").nth(1).unwrap_or("");
    let parsed: serde_json::Value = serde_json::from_str(body).expect(body);
    let arr = parsed.as_array().expect("json array");
    assert_eq!(arr.len(), 50, "page must honor limit=50");
}

#[tokio::test]
async fn incomplete_http_body_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), Vec::new()).await;
    let pin = agentlink_core::parse_fingerprint(&relay.fingerprint).unwrap();
    let config = agentlink_core::tls::client_config(pin).unwrap();
    let connector = tokio_rustls::TlsConnector::from(config);
    let tcp = TcpStream::connect(relay.local_addr).await.unwrap();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("agentlink")
        .unwrap()
        .to_owned();
    let mut tls = connector.connect(name, tcp).await.unwrap();
    let port = relay.local_addr.port();
    // Announce a body then send nothing — must not hang past HANDSHAKE_TIMEOUT.
    let head = format!(
        "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nOrigin: https://127.0.0.1:{port}\r\nContent-Length: 64\r\nConnection: close\r\n\r\n"
    );
    tls.write_all(head.as_bytes()).await.unwrap();
    tls.flush().await.unwrap();
    let mut buf = Vec::new();
    let timed = tokio::time::timeout(Duration::from_secs(15), tls.read_to_end(&mut buf)).await;
    assert!(
        timed.is_ok(),
        "Slowloris body must close within handshake timeout"
    );
}

#[tokio::test]
async fn connection_semaphore_blocks_beyond_cap_until_slot_frees() {
    use agentlink_relay::set_max_concurrent_connections_for_test;
    use tokio::io::AsyncReadExt;

    struct ResetCap;
    impl Drop for ResetCap {
        fn drop(&mut self) {
            set_max_concurrent_connections_for_test(None);
        }
    }
    let _reset = ResetCap;
    set_max_concurrent_connections_for_test(Some(2));

    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path(), Vec::new()).await;
    let pin = agentlink_core::parse_fingerprint(&relay.fingerprint).unwrap();
    let config = agentlink_core::tls::client_config(pin).unwrap();
    let connector = tokio_rustls::TlsConnector::from(config);
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("agentlink")
        .unwrap()
        .to_owned();

    // Hold two Slowloris bodies so both semaphore slots stay occupied.
    let mut held = Vec::new();
    for _ in 0..2 {
        let tcp = TcpStream::connect(relay.local_addr).await.unwrap();
        let mut tls = connector.connect(name.clone(), tcp).await.unwrap();
        let head = format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nOrigin: https://127.0.0.1:{}\r\nContent-Length: 64\r\nConnection: close\r\n\r\n",
            relay.local_addr.port(),
            relay.local_addr.port()
        );
        tls.write_all(head.as_bytes()).await.unwrap();
        tls.flush().await.unwrap();
        held.push(tls);
    }

    // Third TCP connect may succeed (kernel backlog), but TLS accept waits on the semaphore.
    let third = TcpStream::connect(relay.local_addr).await.unwrap();
    let pending = connector.connect(name.clone(), third);
    let blocked = tokio::time::timeout(Duration::from_millis(400), pending).await;
    assert!(
        blocked.is_err(),
        "3rd handshake must wait while 2 slots are held"
    );

    // Free one slot; a fresh dial must then complete.
    drop(held.pop());
    let tcp = TcpStream::connect(relay.local_addr).await.unwrap();
    let mut tls = tokio::time::timeout(Duration::from_secs(5), connector.connect(name, tcp))
        .await
        .expect("handshake after free must not hang")
        .expect("tls ok");
    let mut buf = [0u8; 1];
    let _ = tokio::time::timeout(Duration::from_millis(50), tls.read(&mut buf)).await;
}
