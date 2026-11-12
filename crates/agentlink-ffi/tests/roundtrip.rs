//! Relay + phone node: pairing, fast transfer, exec, permissions, audit.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentlink_core::engine::XferOpts;
use agentlink_core::{Client, ClientSettings, ExecRequest, NodePolicy, Op, PHASE2_SCREENSHOT};
use agentlink_ffi::{host_err, host_ok, serve_node, NodeHost, NodeIo, ServeConfig};
use agentlink_relay::{RelayConfig, RelayHandle};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

struct PhoneHost {
    status: Mutex<String>,
    sessions: Mutex<std::collections::HashMap<String, Session>>,
}

struct Session {
    chunks: Vec<(String, Vec<u8>)>,
    exit_code: i32,
    sent: usize,
    closed: bool,
}

impl NodeHost for PhoneHost {
    fn unary(&self, kind: String, payload_json: String) -> String {
        if kind == "device_info" {
            return host_ok(json!({"model": "test-phone", "os": "android"}));
        }
        if kind == "extension" {
            let payload: Value = serde_json::from_str(&payload_json).unwrap_or(Value::Null);
            let name = payload.get("name").and_then(|v| v.as_str()).unwrap_or("");
            return match name {
                "screenshot" => host_ok(json!({
                    "mime": "image/jpeg",
                    "width": 2,
                    "height": 2,
                    "data_b64": "aa",
                })),
                "inject_input" => host_ok(json!({"ok": true})),
                "webrtc_signal" => host_ok(json!({
                    "status": "unavailable",
                    "fallback": "screenshot",
                    "reason": "phase 3 WebRTC is not on this build",
                })),
                other => host_err(format!("extension '{other}' is not enabled on this node")),
            };
        }
        if kind == "pty_resize" {
            return host_ok(json!({}));
        }
        host_err(format!("unexpected unary {kind}"))
    }

    fn open_session(&self, kind: String, payload_json: String) -> String {
        let payload: Value = serde_json::from_str(&payload_json).unwrap_or(Value::Null);
        let session_id = payload
            .get("session_id")
            .and_then(|v| v.as_str())
            .unwrap_or("session")
            .to_string();
        let (chunks, exit_code) = if kind == "exec" {
            let program = payload
                .get("program")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let text = program.strip_prefix("echo ").unwrap_or(program);
            (vec![("stdout".into(), format!("{text}\n").into_bytes())], 0)
        } else if kind == "pty" {
            (vec![("pty".into(), b"pty-ok\n".to_vec())], 0)
        } else {
            return host_err(format!("unknown session {kind}"));
        };
        self.sessions.lock().unwrap().insert(
            session_id.clone(),
            Session {
                chunks,
                exit_code,
                sent: 0,
                closed: false,
            },
        );
        host_ok(json!({"session_id": session_id}))
    }

    fn poll_session(&self, session_id: String) -> String {
        let mut map = self.sessions.lock().unwrap();
        let Some(session) = map.get_mut(&session_id) else {
            return host_err("unknown session");
        };
        if session.closed {
            return host_ok(json!({"event": "exit", "code": session.exit_code}));
        }
        if session.sent < session.chunks.len() {
            let (stream, data) = &session.chunks[session.sent];
            session.sent += 1;
            return host_ok(json!({
                "event": "chunk",
                "stream": stream,
                "data_b64": agentlink_core::util::b64_encode(data),
            }));
        }
        host_ok(json!({"event": "exit", "code": session.exit_code}))
    }

    fn session_input(&self, _session_id: String, data_b64: String) -> String {
        host_ok(json!({"bytes": data_b64.len()}))
    }

    fn close_session(&self, session_id: String) -> String {
        if let Some(session) = self.sessions.lock().unwrap().get_mut(&session_id) {
            session.closed = true;
        }
        host_ok(json!({"closed": session_id}))
    }

    fn prepare_path(&self, _guest: String, _write: bool) -> String {
        host_err("this test has no SAF grants")
    }

    fn publish_path(&self, _guest: String, _real_path: String) -> String {
        host_ok(json!({}))
    }

    fn on_status(&self, status_json: String) {
        *self.status.lock().unwrap() = status_json;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn phone_node_round_trip() {
    let result = tokio::time::timeout(Duration::from_secs(90), flow()).await;
    match result {
        Ok(Ok(())) => {}
        Ok(Err(err)) => panic!("{err:#}"),
        Err(_) => panic!("phone node test timed out"),
    }
}

async fn flow() -> anyhow::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();

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
    let relay_url = format!("wss://{}/v1/connect", relay.local_addr);
    let admin = Client::connect(&ClientSettings {
        relay: relay_url.clone(),
        token: relay.admin_token.clone(),
        fingerprint: relay.fingerprint.clone(),
        trust: None,
    })
    .await?;

    let pairing = admin
        .create_pairing_token("phone", NodePolicy::exec(), 600)
        .await?;
    let mut ceiling = NodePolicy::exec();
    ceiling.allow_desktop = true;
    ceiling.allow_desktop_stream = true;
    let files = dir.path().join("files");
    let cache = dir.path().join("cache");
    std::fs::create_dir_all(&files)?;
    std::fs::create_dir_all(&cache)?;
    let host = Arc::new(PhoneHost {
        status: Mutex::new(String::new()),
        sessions: Mutex::new(std::collections::HashMap::new()),
    });
    let shutdown = CancellationToken::new();
    let io = NodeIo {
        status: Arc::new(Mutex::new(String::new())),
        node_id: Arc::new(Mutex::new(String::new())),
    };
    let node_task = tokio::spawn(serve_node(
        ServeConfig {
            relay_url: relay_url.clone(),
            fingerprint: relay.fingerprint.clone(),
            data_dir: dir.path().join("node"),
            files_dir: files.clone(),
            cache_dir: cache,
            storage_dir: None,
            name: "phone".into(),
            pairing_token: Some(pairing.token),
            hostname: "pixel".into(),
            os: "android".into(),
            arch: "aarch64".into(),
            version: "0.1.0".into(),
            ceiling,
            trust: None,
        },
        host.clone(),
        shutdown.clone(),
        io,
    ));

    wait_until(|| async {
        admin
            .list_nodes()
            .await
            .ok()
            .map(|nodes| nodes.iter().any(|n| n.name == "phone" && n.online))
            .unwrap_or(false)
    })
    .await;

    let phone_id = admin
        .list_nodes()
        .await?
        .into_iter()
        .find(|node| node.name == "phone")
        .unwrap()
        .id;
    admin.install_local_grant(&dir.path().join("node"), &phone_id)?;
    let exec = admin
        .exec_collect(
            "phone",
            ExecRequest::shell("echo hello-agentlink", Some(Duration::from_secs(10))),
            None,
        )
        .await?;
    assert_eq!(
        exec.exit_code,
        Some(0),
        "{}",
        String::from_utf8_lossy(&exec.stderr)
    );
    assert!(String::from_utf8_lossy(&exec.stdout).contains("hello-agentlink"));

    // The relay admin is a connected account session, so access is full.
    // The phone ceiling already allows desktop, and that ceiling is the cap.
    // The exec preset on the pairing token does not narrow this session.
    let early = admin
        .call_op(
            "phone",
            Op::Extension {
                name: PHASE2_SCREENSHOT.into(),
                payload: json!({}),
            },
        )
        .await?;
    assert_eq!(early["mime"], "image/jpeg");

    let mut desktop = NodePolicy::exec();
    desktop.allow_desktop = true;
    admin.set_policy("phone", desktop).await?;
    wait_until(|| async {
        host.status
            .lock()
            .ok()
            .map(|raw| raw.contains("\"allow_desktop\":true"))
            .unwrap_or(false)
    })
    .await;
    let shot = admin
        .call_op(
            "phone",
            Op::Extension {
                name: PHASE2_SCREENSHOT.into(),
                payload: json!({"display": 0}),
            },
        )
        .await?;
    assert_eq!(shot["mime"], "image/jpeg");

    let local = dir.path().join("payload.bin");
    let payload = vec![7u8; 1_500_000];
    std::fs::write(&local, &payload)?;
    let opts = XferOpts {
        transport: "relay-only".into(),
        ..XferOpts::default()
    };
    let up = admin
        .copy_upload("phone", "app:/files/payload.bin", &local, &opts, None)
        .await?;
    assert_eq!(up.logical_bytes, payload.len() as u64, "{up:?}");
    assert_eq!(up.transport, "relay");
    assert!(!up.skipped);
    let again = admin
        .copy_upload("phone", "app:/files/payload.bin", &local, &opts, None)
        .await?;
    assert!(
        again.skipped,
        "identical file should BLAKE3-skip: {again:?}"
    );

    let downloaded = dir.path().join("down.bin");
    let down = admin
        .copy_download("phone", "app:/files/payload.bin", &downloaded, &opts, None)
        .await?;
    assert_eq!(down.logical_bytes, payload.len() as u64);
    assert_eq!(std::fs::read(&downloaded)?, payload);

    let mut streamed = Vec::new();
    admin
        .stream_upload(
            "phone",
            "app:/files/note.txt",
            &mut std::io::Cursor::new(b"hello from agentlink".to_vec()),
            &opts,
        )
        .await?;
    admin
        .stream_download(
            "phone",
            "app:/files/note.txt",
            0,
            None,
            &mut streamed,
            &opts,
        )
        .await?;
    assert_eq!(streamed, b"hello from agentlink");

    let entries = admin.list_dir("phone", "app:/files").await?;
    assert!(entries.iter().any(|e| e.name == "payload.bin"));
    let escaped = admin
        .stat("phone", "app:/files/../../secret")
        .await
        .unwrap_err();
    assert!(escaped.to_string().contains("escapes"), "{escaped}");

    let info = admin
        .read_file("phone", "app:/device.json", 0, 4096)
        .await?;
    assert!(String::from_utf8_lossy(&info).contains("test-phone"));

    let found = admin
        .search(
            "phone",
            "app:/files",
            "hello from agentlink",
            true,
            Vec::new(),
            Vec::new(),
            true,
            false,
            false,
            0,
            0,
            0,
            20,
        )
        .await?;
    let matches = found["matches"].as_array().expect("search matches");
    assert_eq!(matches.len(), 1, "{found}");
    assert!(
        matches[0]["path"]
            .as_str()
            .unwrap_or("")
            .ends_with("note.txt"),
        "{found}"
    );
    let replaced = admin
        .replace(
            "phone",
            "app:/files/note.txt",
            "hello from agentlink",
            "edited by agentlink",
            false,
        )
        .await?;
    assert_eq!(replaced["replacements"], 1, "{replaced}");
    let sys = admin.sysinfo("phone").await?;
    assert!(sys["cpu"]["count"].as_u64().unwrap_or(0) > 0, "{sys}");
    assert!(
        sys["memory"]["total_bytes"].as_u64().unwrap_or(0) > 0,
        "{sys}"
    );

    let audit = std::fs::read_to_string(dir.path().join("node/audit.log"))?;
    assert!(audit.contains("\"op\":\"exec\""), "{audit}");
    assert!(audit.contains("\"op\":\"push\""), "{audit}");
    assert!(audit.contains("\"op\":\"ext:screenshot\""), "{audit}");
    assert!(audit.contains("\"op\":\"search\""), "{audit}");
    assert!(audit.contains("\"op\":\"replace\""), "{audit}");
    assert!(audit.contains("\"op\":\"sys_info\""), "{audit}");

    shutdown.cancel();
    let _ = tokio::time::timeout(Duration::from_secs(5), node_task).await;
    Ok(())
}

async fn wait_until<F, Fut>(mut probe: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if probe().await {
            return;
        }
        if Instant::now() > deadline {
            panic!("timed out waiting for condition");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
