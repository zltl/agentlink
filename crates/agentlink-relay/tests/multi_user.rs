//! Two accounts, sharing, revocation, web login, and a relay restart.

use std::time::Duration;

use agentlink_core::{Client, ClientSettings, Identity, NodePolicy};
use agentlink_relay::{RelayConfig, RelayHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn users_are_isolated_until_shared_and_revocation_is_immediate() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path()).await;
    let relay_url = format!("wss://127.0.0.1:{}", relay.local_addr.port());
    let admin_settings = ClientSettings {
        relay: relay_url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    };
    let admin = Client::connect_identity(&admin_settings, Identity::generate(), true)
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
            token: alice_session.access_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        alice_key.clone(),
        true,
    )
    .await
    .unwrap();
    let phone = Identity::generate();
    alice
        .enroll_self("phone", &phone, Some(NodePolicy::read_only()))
        .await
        .unwrap();
    let alice_nodes = alice.list_nodes().await.unwrap();
    assert_eq!(alice_nodes.len(), 1);
    assert_eq!(alice_nodes[0].owner, "alice");
    assert_eq!(alice_nodes[0].relation, "owner");

    let bob_key = Identity::generate();
    let bob_session = agentlink_core::client::login_user(
        &relay_url,
        &relay.fingerprint,
        None,
        &bob_key,
        "bob",
        "password-bob",
        None,
        "laptop",
    )
    .await
    .unwrap();
    let bob = Client::connect_identity(
        &ClientSettings {
            relay: relay_url.clone(),
            token: bob_session.access_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        bob_key,
        true,
    )
    .await
    .unwrap();
    assert!(bob.list_nodes().await.unwrap().is_empty());
    alice
        .share_node(&alice_nodes[0].id, "bob", NodePolicy::read_only())
        .await
        .unwrap();
    let shared = bob.list_nodes().await.unwrap();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].relation, "shared");

    admin.revoke_device(&alice_session.device_id).await.unwrap();
    let revoked = alice.list_nodes().await.unwrap_err();
    assert!(
        revoked.to_string().contains("revoked") || revoked.to_string().contains("closed"),
        "{revoked}"
    );

    let body = "{\"username\":\"bob\",\"password\":\"password-bob\"}".to_string();
    let login = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            relay.local_addr.port(),
            body.len()
        ),
    )
    .await;
    assert!(login.contains("200"), "{login}");
    assert!(login.contains("\"user\":\"bob\""), "{login}");
    let session = cookie(&login, "agentlink_session");
    let csrf = cookie(&login, "agentlink_csrf");
    assert!(!session.is_empty());
    assert!(!csrf.is_empty());
    let nodes = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "GET /api/nodes HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nCookie: agentlink_session={session}\r\nConnection: close\r\n\r\n",
            relay.local_addr.port()
        ),
    )
    .await;
    assert!(nodes.contains("phone"), "{nodes}");
    let page = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "GET /view HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nConnection: close\r\n\r\n",
            relay.local_addr.port()
        ),
    )
    .await;
    assert!(page.contains("Browser control is not available"), "{page}");
    assert!(!page.contains("stat-fps"), "{page}");
    assert!(!page.contains("login-user"), "{page}");

    let refresh = alice_session.refresh_token.clone();
    let fingerprint = relay.fingerprint.clone();
    drop(alice);
    drop(bob);
    drop(admin);
    drop(relay);
    tokio::time::sleep(Duration::from_millis(200)).await;
    let relay = spawn(dir.path()).await;
    let resumed = agentlink_core::client::refresh_user(
        &format!("wss://127.0.0.1:{}", relay.local_addr.port()),
        &fingerprint,
        None,
        &alice_key,
        &refresh,
    )
    .await;
    // Alice's device was revoked, so the refresh must fail.
    assert!(resumed.is_err(), "revoked device kept its refresh token");

    let bob_refresh = bob_session.refresh_token;
    let resumed = agentlink_core::client::refresh_user(
        &format!("wss://127.0.0.1:{}", relay.local_addr.port()),
        &relay.fingerprint,
        None,
        &Identity::generate(),
        &bob_refresh,
    )
    .await;
    // Wrong device key is rejected. A matching key after restart succeeds below.
    assert!(resumed.is_err());
    let _ = bob_session.access_token;
}

#[tokio::test]
async fn refresh_survives_relay_restart() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path()).await;
    let url = format!("wss://127.0.0.1:{}", relay.local_addr.port());
    let admin = Client::connect_identity(
        &ClientSettings {
            relay: url.clone(),
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
        .user_add("cara", "password-cara", false)
        .await
        .unwrap();
    drop(admin);
    let key = Identity::generate();
    let session = agentlink_core::client::login_user(
        &url,
        &relay.fingerprint,
        None,
        &key,
        "cara",
        "password-cara",
        None,
        "cli",
    )
    .await
    .unwrap();
    let fingerprint = relay.fingerprint.clone();
    let refresh = session.refresh_token.clone();
    drop(relay);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let relay = spawn(dir.path()).await;
    let resumed = agentlink_core::client::refresh_user(
        &format!("wss://127.0.0.1:{}", relay.local_addr.port()),
        &fingerprint,
        None,
        &key,
        &refresh,
    )
    .await
    .unwrap();
    assert_eq!(resumed.user, "cara");
    assert_ne!(resumed.access_token, session.access_token);
}

#[tokio::test]
async fn login_rejects_cross_site_and_non_json() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path()).await;
    admin_add(&relay, "erin", "password-erin").await;
    let body = "{\"username\":\"erin\",\"password\":\"password-erin\"}";
    let bad_type = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: text/plain\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            port = relay.local_addr.port(),
            len = body.len(),
        ),
    )
    .await;
    assert!(bad_type.contains("415"), "{bad_type}");
    let cross = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nOrigin: https://evil.example\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            port = relay.local_addr.port(),
            len = body.len(),
        ),
    )
    .await;
    assert!(cross.contains("403"), "{cross}");
    let ok = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nOrigin: https://127.0.0.1:{port}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            port = relay.local_addr.port(),
            len = body.len(),
        ),
    )
    .await;
    assert!(ok.contains("200"), "{ok}");
    let port = relay.local_addr.port();
    let scheme = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len(),
        ),
    )
    .await;
    assert!(scheme.contains("403"), "{scheme}");
    let forwarded = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nOrigin: https://evil.example\r\nX-Forwarded-Host: evil.example\r\nX-Forwarded-Proto: https\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len(),
        ),
    )
    .await;
    assert!(forwarded.contains("403"), "{forwarded}");
    let proxy = https(
        relay.local_addr,
        &relay.fingerprint,
        &format!(
            "POST /auth/login HTTP/1.1\r\nHost: relay.example.com\r\nContent-Type: application/json\r\nOrigin: https://relay.example.com\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n{body}",
            len = body.len(),
        ),
    )
    .await;
    assert!(
        proxy.contains("200"),
        "public host without a port still matches https default 443: {proxy}"
    );
}

#[tokio::test]
async fn deleted_account_nodes_are_not_inherited() {
    let dir = tempfile::tempdir().unwrap();
    let relay = spawn(dir.path()).await;
    let url = format!("wss://127.0.0.1:{}", relay.local_addr.port());
    let admin = Client::connect_identity(
        &ClientSettings {
            relay: url.clone(),
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
        .user_add("dana", "password-dana", false)
        .await
        .unwrap();
    let key = Identity::generate();
    let session = agentlink_core::client::login_user(
        &url,
        &relay.fingerprint,
        None,
        &key,
        "dana",
        "password-dana",
        None,
        "phone",
    )
    .await
    .unwrap();
    let dana = Client::connect_identity(
        &ClientSettings {
            relay: url.clone(),
            token: session.access_token,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        key.clone(),
        true,
    )
    .await
    .unwrap();
    dana.enroll_self("phone", &Identity::generate(), None)
        .await
        .unwrap();
    assert_eq!(dana.list_nodes().await.unwrap().len(), 1);
    admin.user_remove("dana").await.unwrap();
    admin
        .user_add("dana", "password-dana-2", false)
        .await
        .unwrap();
    let key2 = Identity::generate();
    let session2 = agentlink_core::client::login_user(
        &url,
        &relay.fingerprint,
        None,
        &key2,
        "dana",
        "password-dana-2",
        None,
        "phone",
    )
    .await
    .unwrap();
    let again = Client::connect_identity(
        &ClientSettings {
            relay: url,
            token: session2.access_token,
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        key2,
        true,
    )
    .await
    .unwrap();
    assert!(
        again.list_nodes().await.unwrap().is_empty(),
        "recreated account inherited the deleted user's node"
    );
}

async fn admin_add(relay: &RelayHandle, user: &str, password: &str) {
    let url = format!("wss://127.0.0.1:{}", relay.local_addr.port());
    let admin = Client::connect_identity(
        &ClientSettings {
            relay: url,
            token: relay.admin_token.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        Identity::generate(),
        true,
    )
    .await
    .unwrap();
    admin.user_add(user, password, false).await.unwrap();
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

#[tokio::test]
async fn long_lived_gui_client_refreshes_across_expiry_and_parallel_cli_but_fails_on_revoke() {
    let dir = tempfile::tempdir().unwrap();
    let relay_dir = dir.path().join("relay");
    let cfg_dir = dir.path().join("client-cfg");
    std::fs::create_dir_all(&relay_dir).unwrap();
    std::fs::create_dir_all(&cfg_dir).unwrap();

    let relay = spawn(&relay_dir).await;
    let addr = relay.local_addr;
    let fp = relay.fingerprint.clone();
    let relay_url = format!("wss://127.0.0.1:{}", addr.port());

    admin_add(&relay, "alice", "password-alice").await;

    let device = Identity::generate();
    let initial = agentlink_core::client::login_user(
        &relay_url,
        &fp,
        None,
        &device,
        "alice",
        "password-alice",
        None,
        "controller",
    )
    .await
    .unwrap();

    let settings = ClientSettings {
        relay: relay_url.clone(),
        token: initial.access_token.clone(),
        fingerprint: fp.clone(),
        trust: None,
    };
    agentlink_core::config::save_session(
        &cfg_dir,
        &settings,
        &initial.user,
        &initial.refresh_token,
        initial.access_expires_unix,
    )
    .unwrap();

    let gui = Client::connect_identity(&settings, device.clone(), true)
        .await
        .unwrap();
    gui.remember_session(&cfg_dir);
    assert!(gui.list_nodes().await.is_ok());

    // 1. Parallel CLI + GUI sharing the exact same config.json rotate cleanly without conflict.
    let (cli_a, cli_b) = tokio::join!(
        agentlink_core::client::maintain_session_skew(&cfg_dir, &device, 3600),
        agentlink_core::client::maintain_session_skew(&cfg_dir, &device, 3600),
    );
    assert!(cli_a.is_ok() && cli_b.is_ok(), "{cli_a:?} / {cli_b:?}");

    // Expire the GUI's initial access token in the relay SQLite DB (simulates >20m elapsed).
    let db_url = format!("sqlite://{}", relay_dir.join("relay.db").display());
    let pool = sqlx::SqlitePool::connect(&db_url).await.unwrap();
    let initial_hash = agentlink_core::accounts::token_hash(&initial.access_token);
    sqlx::query("UPDATE access_tokens SET expires_unix = 1 WHERE token_hash = ?1")
        .bind(&initial_hash)
        .execute(&pool)
        .await
        .unwrap();

    // Open GUI socket stays usable because the same active device rotated a fresh token.
    assert!(
        gui.list_nodes().await.is_ok(),
        "open GUI socket must stay valid after sibling CLI rotated config.json"
    );

    // 2. Un-upgraded relay socket-drop / restart simulation: expire ALL currently minted
    // access tokens in DB and local config, then restart the relay on the same port so
    // the GUI Client must reconnect and rotate its refresh token in `supervise`!
    sqlx::query("UPDATE access_tokens SET expires_unix = 1")
        .execute(&pool)
        .await
        .unwrap();
    pool.close().await;
    {
        let file = agentlink_core::config::load_file(&cfg_dir).unwrap();
        agentlink_core::config::save_session(
            &cfg_dir,
            &ClientSettings {
                relay: relay_url.clone(),
                token: file.token.unwrap(),
                fingerprint: fp.clone(),
                trust: None,
            },
            "alice",
            &file.refresh_token.unwrap(),
            1, // expired locally as well
        )
        .unwrap();
    }
    drop(relay);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let relay = RelayHandle::spawn(RelayConfig {
        bind: addr,
        data_dir: relay_dir.clone(),
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

    // GUI Client automatically refreshes via `remember_session` during reconnect instead
    // of failing permanently with `session expired or revoked`.
    let recovered = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match gui.list_nodes().await {
                Ok(_) => return Ok::<(), String>(()),
                Err(err) => {
                    let msg = err.to_string();
                    assert!(
                        !msg.contains("session expired or revoked"),
                        "expired access token must refresh instead of failing with: {msg}"
                    );
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            }
        }
    })
    .await
    .expect("GUI client reconnect timeout");
    assert!(recovered.is_ok());
    assert!(gui.is_alive());

    // 3. True revocation (`revoke_device`) must still fail closed immediately and stay dead.
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
    admin.revoke_device(&initial.device_id).await.unwrap();

    let err = gui
        .list_nodes()
        .await
        .expect_err("revoked device must fail");
    assert!(
        err.to_string().contains("revoked") || err.to_string().contains("closed"),
        "unexpected error after true revocation: {err}"
    );
    // Give supervise a moment to hit refresh rejection and shut down.
    for _ in 0..40 {
        if !gui.is_alive() {
            break;
        }
        let _ = gui.list_nodes().await;
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(
        !gui.is_alive(),
        "genuinely revoked session must terminate Client instead of bypassing revocation"
    );
    drop(relay);
}
