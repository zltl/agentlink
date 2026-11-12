//! Repository tests for both SQLite and PostgreSQL.
//!
//! PostgreSQL runs when `AGENTLINK_TEST_DATABASE_URL` is set, or when a local
//! agentlink database accepts one of the default URLs. It is skipped otherwise.
//! `AGENTLINK_DATABASE_URL` is the production DSN and is not used here.

use std::path::Path;
use std::time::Duration;

use agentlink_core::accounts::{
    ACCESS_SKEW_SECS, ACCESS_TTL_SECS, REFRESH_GRACE_SECS, REFRESH_IDLE_SECS, REFRESH_TTL_SECS,
};
use agentlink_core::util;
use agentlink_core::NodePolicy;

use crate::db::{Database, OpenOptions};
use crate::models::{Caller, NodeMeta};

#[tokio::test]
async fn sqlite_display_report_does_not_rewrite_policy() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path(), None, None).await;
    db.create_user("alice", "password-alice", "user")
        .await
        .unwrap();
    let issued = db
        .create_token("alice", "quant", NodePolicy::exec(), 600, 1)
        .await
        .unwrap();
    let key = "cd".repeat(32);
    let mut headless = meta("quant");
    headless.ceiling = NodePolicy::exec();
    headless.has_display = Some(false);
    let node = db
        .enroll(Some(&issued.token), &key, headless)
        .await
        .unwrap();
    assert_eq!(node.policy, NodePolicy::exec());
    assert_eq!(node.policy.preset_name(), "exec");
    assert_eq!(node.has_display, Some(false));

    let mut quiet = meta("quant");
    quiet.ceiling = NodePolicy::exec();
    quiet.has_display = None;
    let kept = db.enroll(None, &key, quiet).await.unwrap();
    assert_eq!(kept.policy, NodePolicy::exec());
    assert_eq!(kept.has_display, Some(false));

    let mut screen = meta("quant");
    screen.ceiling = NodePolicy::exec();
    screen.has_display = Some(true);
    let reported = db.enroll(None, &key, screen).await.unwrap();
    assert_eq!(reported.policy, NodePolicy::exec());
    assert_eq!(reported.policy.preset_name(), "exec");
    assert_ne!(reported.policy, NodePolicy::full());
    assert_eq!(reported.has_display, Some(true));
}

#[tokio::test]
async fn sqlite_accounts_isolation_tokens_and_restart() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path(), None, None).await;
    let (access, web) = exercise(&db).await;
    drop(db);
    let again = open_db(dir.path(), None, None).await;
    assert!(again.access_session(&access).await.unwrap().is_some());
    assert!(again.web_session(&web).await.unwrap().is_some());
    let users = again.list_users().await.unwrap();
    assert!(users.iter().any(|user| user.username == "alice"));
}

#[tokio::test]
async fn sqlite_import_assigns_legacy_nodes_to_admin() {
    let dir = tempfile::tempdir().unwrap();
    let key = "ab".repeat(32);
    let store = dir.path().join("store.json");
    std::fs::write(
        &store,
        format!(
            r#"{{"admin_token":"legacy-admin-token","nodes":{{"{key}":{{"id":"{key}","name":"box","public_key_hex":"{key}","policy":{{"allow_read":true}},"enrolled_unix":1}}}}}}"#
        ),
    )
    .unwrap();
    let db = open_db(dir.path(), None, None).await;
    let nodes = db.list_nodes().await.unwrap();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].owner, "admin");
    assert!(dir.path().join("store.json.bak").exists() || !store.exists());
    assert!(!store.exists());
    let admin = db.account("admin").await.unwrap().unwrap();
    assert_eq!(admin.role, "admin");
}

#[tokio::test]
async fn refresh_survives_a_month_idle_and_slides_on_use() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path(), None, None).await;
    db.create_user("ada", "password-ada", "user").await.unwrap();
    let device = util::random_hex(32);
    let issued = db.issue_session("ada", &device, "phone").await.unwrap();
    let now = util::unix_now();
    let access_left = issued.access_expires_unix - now;
    let refresh_left = issued.refresh_expires_unix - now;
    assert!(
        (ACCESS_TTL_SECS - 2..=ACCESS_TTL_SECS).contains(&access_left),
        "access ttl {access_left}"
    );
    assert!(
        refresh_left > REFRESH_IDLE_SECS,
        "idle for 30 days must still refresh, left {refresh_left}"
    );
    assert!(
        (REFRESH_TTL_SECS - 2..=REFRESH_TTL_SECS).contains(&refresh_left),
        "refresh ttl {refresh_left}"
    );

    // Issued life is idle + grace. Leaving only the grace is 30 days of idleness.
    let after_month_idle = util::unix_now() + REFRESH_GRACE_SECS;
    db.testing_set_refresh_expiry(&issued.refresh_token, after_month_idle)
        .await
        .unwrap();
    let rotated = db
        .rotate_refresh(&issued.refresh_token, &device)
        .await
        .unwrap();
    assert_ne!(rotated.refresh_token, issued.refresh_token);
    assert_ne!(rotated.access_token, issued.access_token);
    let slid = rotated.refresh_expires_unix - util::unix_now();
    assert!(
        slid > REFRESH_IDLE_SECS,
        "refresh must slide the inactivity window, left {slid}"
    );
    // The open socket keeps its access token. Using the new one commits the rotation.
    assert!(db
        .access_session(&issued.access_token)
        .await
        .unwrap()
        .is_some());
    assert!(db
        .access_session(&rotated.access_token)
        .await
        .unwrap()
        .is_some());
    let reused = db
        .rotate_refresh(&issued.refresh_token, &device)
        .await
        .unwrap_err();
    assert!(
        reused.to_string().contains("invalid") || reused.to_string().contains("revoked"),
        "{reused}"
    );

    db.testing_set_refresh_expiry(&rotated.refresh_token, util::unix_now() - 1)
        .await
        .unwrap();
    let expired = db
        .rotate_refresh(&rotated.refresh_token, &device)
        .await
        .unwrap_err();
    assert!(
        expired.to_string().contains("invalid") || expired.to_string().contains("revoked"),
        "{expired}"
    );
}

#[tokio::test]
async fn lost_refresh_response_can_be_retried_until_the_new_token_is_used() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path(), None, None).await;
    db.create_user("ada", "password-ada", "user").await.unwrap();
    let device = util::random_hex(32);
    let issued = db.issue_session("ada", &device, "phone").await.unwrap();
    let rotated = db
        .rotate_refresh(&issued.refresh_token, &device)
        .await
        .unwrap();

    let retried = db
        .rotate_refresh(&issued.refresh_token, &device)
        .await
        .unwrap();
    assert_ne!(retried.refresh_token, rotated.refresh_token);
    assert_ne!(retried.access_token, rotated.access_token);
    let abandoned = db
        .rotate_refresh(&rotated.refresh_token, &device)
        .await
        .unwrap_err();
    assert!(
        abandoned.to_string().contains("invalid") || abandoned.to_string().contains("revoked"),
        "{abandoned}"
    );

    assert!(db
        .access_session(&retried.access_token)
        .await
        .unwrap()
        .is_some());
    let replay = db
        .rotate_refresh(&issued.refresh_token, &device)
        .await
        .unwrap_err();
    assert!(
        replay.to_string().contains("invalid") || replay.to_string().contains("revoked"),
        "{replay}"
    );
    // The committed token still slides. The replay did not revoke it.
    let next = db
        .rotate_refresh(&retried.refresh_token, &device)
        .await
        .unwrap();
    assert_ne!(next.refresh_token, retried.refresh_token);
}

#[tokio::test]
async fn access_token_survives_a_few_minutes_of_clock_skew() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path(), None, None).await;
    db.create_user("ada", "password-ada", "user").await.unwrap();
    let device = util::random_hex(32);
    let issued = db.issue_session("ada", &device, "phone").await.unwrap();
    db.testing_set_access_expiry(&issued.access_token, util::unix_now() - 60)
        .await
        .unwrap();
    assert!(
        db.access_session(&issued.access_token)
            .await
            .unwrap()
            .is_some(),
        "a minute of skew must not look like a logged-out session"
    );
    db.testing_set_access_expiry(
        &issued.access_token,
        util::unix_now() - ACCESS_SKEW_SECS - 30,
    )
    .await
    .unwrap();
    assert!(db
        .access_session(&issued.access_token)
        .await
        .unwrap()
        .is_none());
}

#[tokio::test]
async fn postgres_accounts_when_available() {
    let Some(url) = postgres_url().await else {
        eprintln!("postgres unavailable; skipping repository test");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let schema = format!("t_{}_{}", std::process::id(), util::random_hex(4));
    let db = open_db(dir.path(), Some(&url), Some(&schema)).await;
    let (access, web) = exercise(&db).await;
    drop(db);
    let again = open_db(dir.path(), Some(&url), Some(&schema)).await;
    assert!(again.access_session(&access).await.unwrap().is_some());
    assert!(again.web_session(&web).await.unwrap().is_some());
    again.drop_test_schema().await.unwrap();
}

#[test]
fn install_script_dry_run_skips_the_network() {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../install.sh");
    let output = agentlink_core::process::hidden("sh")
        .arg(&script)
        .arg("--dry-run")
        .env("PATH", "/usr/bin:/bin")
        .output()
        .expect("sh");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("dry-run"), "{text}");

    let enrolled = agentlink_core::process::hidden("sh")
        .arg(&script)
        .args([
            "--dry-run",
            "--token",
            "abc",
            "--relay",
            "wss://relay.example.com",
            "--max-access",
            "desktop",
            "--name",
            "lab top",
        ])
        .env("AGENTLINK_ENROLL", "1")
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    assert!(enrolled.status.success());
    let text = String::from_utf8_lossy(&enrolled.stdout);
    assert!(text.contains("pairing=abc"), "{text}");
    assert!(text.contains("token= "), "{text}");
    assert!(text.contains("enroll=1"), "{text}");
    assert!(text.contains("max_access=desktop"), "{text}");
}

async fn exercise(db: &Database) -> (String, String) {
    db.create_user("alice", "password-alice", "user")
        .await
        .unwrap();
    db.create_user("bob", "password-bob", "user").await.unwrap();
    for _ in 0..5 {
        let err = db
            .check_login("alice", "wrong-password", None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid username or password"),
            "{err}"
        );
    }
    let locked = db
        .check_login("alice", "password-alice", None)
        .await
        .unwrap_err();
    assert!(
        locked.to_string().contains("temporarily locked"),
        "{locked}"
    );
    // A second account is not locked by Alice's failures.
    db.check_login("bob", "password-bob", None).await.unwrap();
    db.note_success("bob").await.unwrap();

    let issued = db
        .create_token("alice", "laptop", NodePolicy::read_only(), 3600, 1)
        .await
        .unwrap();
    let node = db
        .enroll(Some(&issued.token), &util::random_hex(32), meta("laptop"))
        .await
        .unwrap();
    assert_eq!(node.owner, "alice");
    let again = db
        .enroll(Some(&issued.token), &util::random_hex(32), meta("other"))
        .await
        .unwrap_err();
    assert!(
        again.to_string().contains("already used") || again.to_string().contains("invalid"),
        "{again}"
    );

    let short = db
        .create_token("alice", "soon", NodePolicy::read_only(), 1, 1)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let expired = db
        .enroll(Some(&short.token), &util::random_hex(32), meta("soon"))
        .await
        .unwrap_err();
    assert!(
        expired.to_string().contains("expired") || expired.to_string().contains("invalid"),
        "{expired}"
    );

    let alice = Caller {
        user: "alice".into(),
        admin: false,
    };
    let bob = Caller {
        user: "bob".into(),
        admin: false,
    };
    assert_eq!(db.visible(&alice).await.unwrap().len(), 1);
    assert!(db.visible(&bob).await.unwrap().is_empty());
    db.share(&alice, &node.id, "bob", NodePolicy::read_only())
        .await
        .unwrap();
    let shared = db.visible(&bob).await.unwrap();
    assert_eq!(shared.len(), 1);
    assert_eq!(shared[0].relation.as_str(), "shared");
    let bob_tokens = db.list_tokens(Some("bob")).await.unwrap();
    assert!(bob_tokens.is_empty());

    let session = db
        .issue_session("bob", &util::random_hex(32), "cli")
        .await
        .unwrap();
    assert!(db
        .access_session(&session.access_token)
        .await
        .unwrap()
        .is_some());
    let (web_token, web) = db.create_web_session("bob").await.unwrap();
    assert_eq!(web.user, "bob");
    db.revoke_device(&session.device_id, Some("bob"))
        .await
        .unwrap();
    assert!(db
        .session_by_hash(&agentlink_core::accounts::token_hash(&session.access_token))
        .await
        .unwrap()
        .is_none());
    assert!(db.web_session(&web_token).await.unwrap().is_some());
    let kept = db
        .issue_session("alice", &util::random_hex(32), "kept")
        .await
        .unwrap();
    let (kept_web, _) = db.create_web_session("alice").await.unwrap();
    (kept.access_token, kept_web)
}


#[tokio::test]
async fn register_client_cannot_steal_another_users_agent() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path(), None, None).await;
    db.create_user("alice", "password-alice", "user")
        .await
        .unwrap();
    db.create_user("bob", "password-bob", "user").await.unwrap();
    let key = "ab".repeat(32);
    let alice_client = db
        .register_client("alice", "phone-agent", &key)
        .await
        .unwrap();
    assert_eq!(alice_client.owner, "alice");
    let stolen = db.register_client("bob", "evil", &key).await.unwrap_err();
    assert!(
        stolen.to_string().contains("another user"),
        "{stolen}"
    );
    let kept = db.client_record(&alice_client.id).await.unwrap().unwrap();
    assert_eq!(kept.owner, "alice");
    assert_eq!(kept.name, "phone-agent");
    let again = db
        .register_client("alice", "phone-agent-2", &key)
        .await
        .unwrap();
    assert_eq!(again.owner, "alice");
    assert_eq!(again.name, "phone-agent-2");
}

#[tokio::test]
async fn pairing_token_cannot_claim_another_users_node() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path(), None, None).await;
    db.create_user("alice", "password-alice", "user")
        .await
        .unwrap();
    db.create_user("bob", "password-bob", "user").await.unwrap();
    let issued = db
        .create_token("alice", "box", NodePolicy::exec(), 600, 1)
        .await
        .unwrap();
    let key = "cd".repeat(32);
    let node = db
        .enroll(Some(&issued.token), &key, meta("box"))
        .await
        .unwrap();
    assert_eq!(node.owner, "alice");
    let bob_token = db
        .create_token("bob", "box", NodePolicy::full(), 600, 1)
        .await
        .unwrap();
    let denied = db
        .enroll(Some(&bob_token.token), &key, meta("box"))
        .await
        .unwrap_err();
    assert!(
        denied.to_string().contains("someone else") || denied.to_string().contains("another"),
        "{denied}"
    );
    let kept = db.resolve_node(&node.id).await.unwrap();
    assert_eq!(kept.owner, "alice");
    assert_eq!(kept.policy, NodePolicy::exec());
}

#[tokio::test]
async fn bob_cannot_access_alice_node_by_id_or_name() {
    let dir = tempfile::tempdir().unwrap();
    let db = open_db(dir.path(), None, None).await;
    db.create_user("alice", "password-alice", "user")
        .await
        .unwrap();
    db.create_user("bob", "password-bob", "user").await.unwrap();
    let issued = db
        .create_token("alice", "secret-box", NodePolicy::full(), 600, 1)
        .await
        .unwrap();
    let node = db
        .enroll(Some(&issued.token), &"ef".repeat(32), meta("secret-box"))
        .await
        .unwrap();
    let bob = Caller {
        user: "bob".into(),
        admin: false,
    };
    let err = db.access_to(&bob, &node.id).await.unwrap_err();
    assert!(
        err.to_string().contains("not found") || err.to_string().contains("secret-box"),
        "{err}"
    );
    let err_name = db.access_to(&bob, "secret-box").await.unwrap_err();
    assert!(err_name.to_string().contains("not found"), "{err_name}");
}

async fn open_db(dir: &Path, url: Option<&str>, schema: Option<&str>) -> Database {
    Database::open(OpenOptions {
        data_dir: dir,
        database_url: url,
        schema,
        bootstrap_admin: false,
        mint_legacy_admin: false,
    })
    .await
    .unwrap()
    .db
}

fn meta(name: &str) -> NodeMeta {
    NodeMeta {
        name: name.into(),
        hostname: "host".into(),
        os: "linux".into(),
        arch: "x86_64".into(),
        version: "test".into(),
        ceiling: NodePolicy::remote_control(),
        has_display: None,
    }
}

async fn postgres_url() -> Option<String> {
    if let Ok(url) = std::env::var("AGENTLINK_TEST_DATABASE_URL") {
        if url.trim().is_empty() {
            return None;
        }
        if probe(&url).await {
            return Some(url);
        }
        panic!("AGENTLINK_TEST_DATABASE_URL is set but Postgres did not accept a connection");
    }
    for url in [
        "postgres://agentlink:agentlink@127.0.0.1:5432/agentlink",
        "postgres://agentlink@127.0.0.1:5432/agentlink",
        "postgres://postgres@127.0.0.1:5432/postgres",
    ] {
        if probe(url).await {
            return Some(url.to_string());
        }
    }
    None
}

async fn probe(url: &str) -> bool {
    let Ok(pool) = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(2))
        .connect(url)
        .await
    else {
        return false;
    };
    let ok = sqlx::query("SELECT 1").execute(&pool).await.is_ok();
    pool.close().await;
    ok
}
