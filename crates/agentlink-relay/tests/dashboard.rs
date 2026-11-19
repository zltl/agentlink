//! Dashboard login, per-user machine list, and the one-step install command.

use std::time::Duration;

use agentlink_core::{Client, ClientSettings, Identity, NodePolicy};
use agentlink_relay::{RelayConfig, RelayHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn dashboard_lists_only_the_callers_machines_and_mints_one_install_command() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path()).await;
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
        "phone",
    )
    .await
    .unwrap();
    let alice = Client::connect_identity(
        &ClientSettings {
            relay: relay_url.clone(),
            token: alice_session.access_token,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        alice_key,
        true,
    )
    .await
    .unwrap();
    alice
        .enroll_self(
            "alice-box",
            &Identity::generate(),
            Some(NodePolicy::read_only()),
        )
        .await
        .unwrap();

    let page = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!("GET / HTTP/1.1\r\nHost: relay.example.com\r\nConnection: close\r\n\r\n"),
    )
    .await;
    assert!(page.contains("200"), "{page}");
    let html = body_of(&page);
    assert!(html.contains("id=\"login-user\""), "{html}");
    assert!(html.contains("id=\"install-command\""), "{html}");
    assert!(html.contains("id=\"refresh-btn\""), "{html}");
    assert!(html.contains("/download/agentlink.apk"));
    assert!(!html.contains("<script src"));

    let dash = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "GET /dashboard HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            relay.local_addr.port()
        ),
    )
    .await;
    assert!(body_of(&dash).contains("id=\"login-pass\""), "{dash}");

    let anon = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "GET /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            relay.local_addr.port()
        ),
    )
    .await;
    assert!(anon.contains("401"), "{anon}");

    let bad = login(&relay, "alice", "nope").await;
    assert!(bad.contains("401"), "{bad}");
    assert!(
        body_of(&bad).contains("invalid username or password"),
        "{bad}"
    );

    let bob_login = login(&relay, "bob", "password-bob").await;
    assert!(bob_login.contains("200"), "{bob_login}");
    let bob_session = cookie(&bob_login, "agentlink_session");
    let bob_csrf = cookie(&bob_login, "agentlink_csrf");
    let bob_nodes = nodes(&relay, &bob_session).await;
    assert!(!body_of(&bob_nodes).contains("alice-box"), "{bob_nodes}");

    let alice_login = login(&relay, "alice", "password-alice").await;
    let alice_cookie = cookie(&alice_login, "agentlink_session");
    let alice_csrf = cookie(&alice_login, "agentlink_csrf");
    let alice_nodes = nodes(&relay, &alice_cookie).await;
    let listed: serde_json::Value = serde_json::from_str(body_of(&alice_nodes)).unwrap();
    let machine = listed["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|node| node["name"] == "alice-box")
        .expect("alice sees her machine");
    assert_eq!(machine["online"], false);
    assert_eq!(machine["os"], "client");
    assert!(machine.get("arch").is_some(), "{machine}");
    assert!(machine["last_seen_unix"].as_i64().unwrap() > 0, "{machine}");
    assert_eq!(machine["access"], "full");
    assert_eq!(machine["allow_exec"], true);
    assert_eq!(machine["allow_remote_control"], true);
    assert_eq!(machine["relation"], "owner");

    let host = format!("127.0.0.1:{}", relay.local_addr.port());
    let denied = create_token(&relay, &host, &alice_cookie, "", "lab top", "desktop").await;
    assert!(denied.contains("403"), "{denied}");

    let created = create_token(
        &relay,
        &host,
        &alice_cookie,
        &alice_csrf,
        "lab top",
        "desktop",
    )
    .await;
    assert!(created.contains("200"), "{created}");
    let issued: serde_json::Value = serde_json::from_str(body_of(&created)).unwrap();
    let command = issued["command"].as_str().unwrap();
    assert_eq!(issued["linux"], issued["command"]);
    assert!(
        command.starts_with(&format!(
            "curl -fsSL https://{host}/install.sh | env AGENTLINK_TOKEN="
        )),
        "{command}"
    );
    assert!(command.contains(" sh -s -- "), "{command}");
    assert!(command.contains("--name 'lab top'"), "{command}");
    assert!(command.contains("--access 'desktop'"), "{command}");
    assert!(command.contains("--max-access 'desktop'"), "{command}");
    assert!(
        command.contains(issued["token"].as_str().unwrap()),
        "{command}"
    );
    assert!(
        !command.contains("--token "),
        "token must ride env, not argv: {command}"
    );
    assert_eq!(issued["relay"], format!("wss://{host}"));
    assert_eq!(issued["trust"], "");
    let token_id = issued["id"].as_str().unwrap();

    let bob_after = nodes(&relay, &bob_session).await;
    assert!(!body_of(&bob_after).contains(token_id), "{bob_after}");
    assert!(!body_of(&bob_after).contains("lab top"), "{bob_after}");

    let public_script = https(
        relay.local_addr,
        &relay.fingerprint,
        "GET /install.sh HTTP/1.1\r\nHost: relay.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let prelude = body_of(&public_script).split("#!/bin/sh").next().unwrap();
    assert!(prelude.contains("wss://relay.example.com"), "{prelude}");
    assert!(prelude.contains("AGENTLINK_ENROLL"), "{prelude}");
    assert!(prelude.contains("AGENTLINK_FINGERPRINT"), "{prelude}");
    assert!(prelude.contains(&relay.fingerprint), "{prelude}");
    assert!(!prelude.contains("AGENTLINK_TRUST"), "{prelude}");

    let local_script = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!("GET /install.sh HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"),
    )
    .await;
    let local_prelude = body_of(&local_script).split("#!/bin/sh").next().unwrap();
    assert!(
        local_prelude.contains(&format!("wss://{host}")),
        "{local_prelude}"
    );
    assert!(
        local_prelude.contains(&relay.fingerprint),
        "{local_prelude}"
    );
    assert!(
        !local_prelude.contains("AGENTLINK_TRUST"),
        "{local_prelude}"
    );

    let public_ps = https(
        relay.local_addr,
        &relay.fingerprint,
        "GET /install.ps1 HTTP/1.1\r\nHost: relay.example.com\r\nConnection: close\r\n\r\n",
    )
    .await;
    let ps = body_of(&public_ps);
    assert!(
        ps.contains("$AgentlinkServeRelay = \"wss://relay.example.com\""),
        "{ps}"
    );
    assert!(
        ps.contains(&format!("$AgentlinkServeFingerprint = \"{}\"", relay.fingerprint)),
        "{ps}"
    );

    let stolen = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /api/tokens/revoke HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCookie: agentlink_session={bob_session}\r\nX-CSRF-Token: {bob_csrf}\r\nConnection: close\r\n\r\n{{\"id\":\"{token_id}\"}}",
            format!("{{\"id\":\"{token_id}\"}}").len(),
        ),
    )
    .await;
    assert!(stolen.contains("404"), "{stolen}");

    let revoke_body = format!("{{\"id\":\"{token_id}\"}}");
    let revoked = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /api/tokens/revoke HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCookie: agentlink_session={alice_cookie}\r\nX-CSRF-Token: {alice_csrf}\r\nConnection: close\r\n\r\n{revoke_body}",
            revoke_body.len()
        ),
    )
    .await;
    assert!(revoked.contains("200"), "{revoked}");
    let after = nodes(&relay, &alice_cookie).await;
    let tokens: serde_json::Value = serde_json::from_str(body_of(&after)).unwrap();
    let row = tokens["tokens"]
        .as_array()
        .unwrap()
        .iter()
        .find(|token| token["id"] == token_id)
        .unwrap();
    assert_eq!(row["state"], "revoked");

    let logout = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /auth/logout HTTP/1.1\r\nHost: {host}\r\nCookie: agentlink_session={alice_cookie}\r\nX-CSRF-Token: {alice_csrf}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(logout.contains("200"), "{logout}");
    let expired = nodes(&relay, &alice_cookie).await;
    assert!(expired.contains("401"), "{expired}");
}

#[tokio::test]
async fn bob_cannot_mint_view_ticket_for_alice_node() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path()).await;
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
    admin.user_add("bob", "password-bob", false).await.unwrap();
    let alice_key = Identity::generate();
    let alice_session = agentlink_core::client::login_user(
        &format!("wss://127.0.0.1:{}", relay.local_addr.port()),
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
    let alice = Client::connect_identity(
        &ClientSettings {
            relay: format!("wss://127.0.0.1:{}", relay.local_addr.port()),
            token: alice_session.access_token,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        alice_key,
        true,
    )
    .await
    .unwrap();
    alice
        .enroll_self(
            "alice-desk",
            &Identity::generate(),
            Some(NodePolicy::full()),
        )
        .await
        .unwrap();
    let alice_nodes = alice.list_nodes().await.unwrap();
    let node_id = alice_nodes[0].id.clone();
    drop(alice);
    drop(admin);

    let bob_login = login(&relay, "bob", "password-bob").await;
    let bob_session = cookie(&bob_login, "agentlink_session");
    let bob_csrf = cookie(&bob_login, "agentlink_csrf");
    let host = format!("127.0.0.1:{}", relay.local_addr.port());
    let body = format!("{{\"node\":\"{node_id}\",\"control\":true}}");
    let denied = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /api/view-ticket HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCookie: agentlink_session={bob_session}\r\nX-CSRF-Token: {bob_csrf}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await;
    assert!(
        denied.contains("410")
            || denied.contains("403")
            || denied.contains("404")
            || denied.contains("not found"),
        "{denied}"
    );
    assert!(!body_of(&denied).contains("\"ticket\""), "{denied}");
}

async fn login(relay: &RelayHandle, user: &str, password: &str) -> String {
    let body = format!("{{\"username\":\"{user}\",\"password\":\"{password}\"}}");
    https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            relay.local_addr.port(),
            body.len()
        ),
    )
    .await
}

async fn nodes(relay: &RelayHandle, session: &str) -> String {
    https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "GET /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: agentlink_session={session}\r\nConnection: close\r\n\r\n",
            relay.local_addr.port()
        ),
    )
    .await
}

async fn create_token(
    relay: &RelayHandle,
    host: &str,
    session: &str,
    csrf: &str,
    name: &str,
    access: &str,
) -> String {
    let body =
        format!("{{\"name\":\"{name}\",\"access\":\"{access}\",\"ttl_secs\":900,\"uses\":1}}");
    https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /api/tokens HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCookie: agentlink_session={session}\r\nX-CSRF-Token: {csrf}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ),
    )
    .await
}

async fn spawn(dir: &std::path::Path) -> RelayHandle {
    RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_path_buf(),
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

fn body_of(response: &str) -> &str {
    response.split("\r\n\r\n").nth(1).unwrap_or("")
}

fn cookie(response: &str, name: &str) -> String {
    for line in response.lines() {
        let Some(value) = line.split_once(':').and_then(|(header, value)| {
            if header.eq_ignore_ascii_case("set-cookie") {
                Some(value.trim())
            } else {
                None
            }
        }) else {
            continue;
        };
        if let Some(rest) = value.strip_prefix(&format!("{name}=")) {
            return rest.split(';').next().unwrap_or("").to_string();
        }
    }
    String::new()
}
