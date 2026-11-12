//! Read-only diagnostic: send webrtc list_monitors / offer to an existing
//! node (default: sufa) with the already-authorized client identity.
//! Does not create an identity or grant, does not print tokens, and closes
//! the session after a short wait for a selected ICE pair or first frame.

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentlink_core::client::maintain_session;
use agentlink_core::config::{self, ClientSettings};
use agentlink_core::{apply_relay_defaults, Client, Identity, Op, PHASE3_WEBRTC_SIGNAL};
use agentlink_view::{is_screenshot_fallback, LiveOptions, Signal, Viewer};
use serde_json::{json, Value};

struct ClientSignal {
    client: Arc<Client>,
    handle: tokio::runtime::Handle,
    node: String,
}

impl Signal for ClientSignal {
    fn signal(&self, payload: &Value) -> Result<Value, String> {
        let client = Arc::clone(&self.client);
        let node = self.node.clone();
        let payload = payload.clone();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        self.handle.spawn(async move {
            let result = tokio::time::timeout(
                Duration::from_secs(25),
                client.call_op(
                    &node,
                    Op::Extension {
                        name: PHASE3_WEBRTC_SIGNAL.to_string(),
                        payload,
                    },
                ),
            )
            .await;
            let _ = tx.send(match result {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(err)) => Err(err.to_string()),
                Err(_) => Err("webrtc_signal timed out".into()),
            });
        });
        rx.recv().map_err(|err| err.to_string())?
    }
}

fn summarize(value: &Value) -> String {
    let status = value.get("status").and_then(Value::as_str).unwrap_or("-");
    let fallback = value.get("fallback").and_then(Value::as_str).unwrap_or("-");
    let encoder = value.get("encoder").and_then(Value::as_str).unwrap_or("-");
    let hardware = value.get("hardware").and_then(Value::as_bool);
    let sdp_len = value
        .get("sdp")
        .and_then(Value::as_str)
        .map(str::len)
        .unwrap_or(0);
    let session_len = value
        .get("session_id")
        .and_then(Value::as_str)
        .map(str::len)
        .unwrap_or(0);
    let monitors = value
        .get("monitors")
        .and_then(Value::as_array)
        .map(|items| items.len())
        .unwrap_or(0);
    let err = value.get("error").and_then(Value::as_str).unwrap_or("-");
    format!(
        "status={status} fallback={fallback} encoder={encoder} hardware={hardware:?} sdp_len={sdp_len} session_len={session_len} monitors={monitors} error={err} screenshot_fallback={}",
        is_screenshot_fallback(value)
    )
}

#[tokio::main]
async fn main() {
    let node = env::args().nth(1).unwrap_or_else(|| "sufa".to_string());
    let config_dir = env::var("AGENTLINK_CONFIG_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| config::default_config_dir().expect("config dir"));
    eprintln!(
        "t449-probe: config_dir={} node={} (Identity::load only, no new grant)",
        config_dir.display(),
        node
    );

    let identity = match Identity::load(&config_dir.join("identity.json")) {
        Ok(id) => id,
        Err(err) => {
            eprintln!("t449-probe: identity load failed: {err}");
            std::process::exit(2);
        }
    };
    if let Err(err) = maintain_session(&config_dir, &identity).await {
        eprintln!("t449-probe: session refresh failed: {err}");
        std::process::exit(2);
    }
    let file = config::load_file(&config_dir).unwrap_or_default();
    let token = file.token.clone().filter(|t| !t.is_empty());
    let Some(token) = token else {
        eprintln!("t449-probe: no saved session token");
        std::process::exit(2);
    };
    let mut relay = file.relay.clone().unwrap_or_default();
    let fingerprint = file.fingerprint.clone().unwrap_or_default();
    let mut trust = file.trust.clone();
    apply_relay_defaults(&mut relay, &fingerprint, &mut trust);
    // Do not print relay URL if it might include credentials; just length.
    eprintln!(
        "t449-probe: relay_len={} trust_set={}",
        relay.len(),
        trust.is_some()
    );
    let client = match Client::connect_identity(
        &ClientSettings {
            relay,
            token,
            fingerprint,
            trust,
        },
        identity,
        true,
    )
    .await
    {
        Ok(c) => c,
        Err(err) => {
            eprintln!("t449-probe: connect failed: {err}");
            std::process::exit(2);
        }
    };
    client.remember_node_pins(&config_dir);
    client.remember_grants(&config_dir);
    let client = Arc::new(client);

    let nodes = match client.list_nodes().await {
        Ok(n) => n,
        Err(err) => {
            eprintln!("t449-probe: list_nodes failed: {err}");
            std::process::exit(2);
        }
    };
    let target = nodes
        .iter()
        .find(|n| n.name == node || n.id.starts_with(&node));
    let Some(target) = target else {
        eprintln!(
            "t449-probe: node '{node}' not in list (names: {})",
            nodes
                .iter()
                .map(|n| format!(
                    "{}:{}:{}",
                    n.name,
                    if n.online { "up" } else { "down" },
                    n.has_display
                        .map(|d| if d { "desktop" } else { "headless" })
                        .unwrap_or("unknown")
                ))
                .collect::<Vec<_>>()
                .join(", ")
        );
        std::process::exit(2);
    };
    eprintln!(
        "t449-probe: found name={} online={} display={:?} os={} arch={} version={} access={}",
        target.name,
        target.online,
        target.has_display,
        target.os,
        target.arch,
        target.version,
        target.access
    );
    let node_id = target.id.clone();

    eprintln!("t449-probe: stage=list_monitors sent");
    let started = Instant::now();
    let list = tokio::time::timeout(
        Duration::from_secs(25),
        client.call_op(
            &node_id,
            Op::Extension {
                name: PHASE3_WEBRTC_SIGNAL.to_string(),
                payload: json!({"action": "list_monitors"}),
            },
        ),
    )
    .await;
    match list {
        Ok(Ok(value)) => {
            eprintln!(
                "t449-probe: stage=list_monitors ok {}ms {}",
                started.elapsed().as_millis(),
                summarize(&value)
            );
        }
        Ok(Err(err)) => {
            eprintln!(
                "t449-probe: stage=list_monitors error {}ms: {err}",
                started.elapsed().as_millis()
            );
        }
        Err(_) => {
            eprintln!("t449-probe: stage=list_monitors timed out after 25s");
        }
    }

    let handle = tokio::runtime::Handle::current();
    let signal: Arc<dyn Signal> = Arc::new(ClientSignal {
        client: Arc::clone(&client),
        handle,
        node: node_id,
    });
    let on_stage: Arc<dyn Fn(&str) + Send + Sync> =
        Arc::new(|msg: &str| eprintln!("t449-probe: viewer {msg}"));
    let opts = LiveOptions {
        viewer: "desktop".into(),
        control: false,
        on_stage: Some(on_stage),
        ..LiveOptions::default()
    };
    eprintln!("t449-probe: stage=Viewer::connect starting (60s deadline, view-only, then close)");
    let connect_started = Instant::now();
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    let thread_signal = Arc::clone(&signal);
    let spawn = std::thread::Builder::new()
        .name("t449-probe-connect".into())
        .spawn(move || {
            let _ = tx.send(Viewer::connect(thread_signal, opts));
        });
    if let Err(err) = spawn {
        eprintln!("t449-probe: failed to spawn connect thread: {err}");
        std::process::exit(2);
    }
    match rx.recv_timeout(Duration::from_secs(60)) {
        Ok(Ok(viewer)) => {
            let info = viewer.info();
            eprintln!(
                "t449-probe: Viewer::connect ok {}ms encoder={} hardware={} path={} {}x{} codec={}",
                connect_started.elapsed().as_millis(),
                info.encoder,
                info.hardware,
                info.path,
                info.width,
                info.height,
                info.codec
            );
            // 15s covers the Controller's 12s no-pair / no-first-frame
            // deadline plus a little slack for logging the pair.
            let deadline = Instant::now() + Duration::from_secs(15);
            let mut frames = 0u32;
            let mut logged_pair = false;
            while Instant::now() < deadline {
                if viewer.failed() {
                    eprintln!("t449-probe: viewer.failed() before first frame");
                    break;
                }
                if !logged_pair {
                    if let Some(snap) = viewer.transport() {
                        logged_pair = true;
                        eprintln!(
                            "t449-probe: selected pair path={} local={} {} remote={} {} proto={} inventory={}",
                            snap.path,
                            snap.local_typ,
                            snap.local_addr,
                            snap.remote_typ,
                            snap.remote_addr,
                            snap.protocol,
                            snap.sdp_inventory
                        );
                    }
                }
                if let Some(frame) = viewer.poll_frame(Duration::from_millis(200)) {
                    frames += 1;
                    eprintln!(
                        "t449-probe: h264 frame #{} key={} {}x{} bytes={}",
                        frames,
                        frame.keyframe,
                        frame.width,
                        frame.height,
                        frame.annex_b.len()
                    );
                    if frames >= 2 {
                        break;
                    }
                }
            }
            if !logged_pair {
                eprintln!(
                    "t449-probe: no selected ICE pair within 15s after connect (failed={})",
                    viewer.failed()
                );
            } else if frames == 0 {
                eprintln!(
                    "t449-probe: no H.264 frame within 15s after a selected ICE pair (failed={})",
                    viewer.failed()
                );
            }
            let checks = viewer.ice_checks();
            if checks.is_empty() {
                eprintln!("t449-probe: ice checks snapshot empty (stats not yet populated)");
            } else {
                eprintln!("t449-probe: ice checks {checks}");
            }
            viewer.close();
            eprintln!("t449-probe: viewer closed");
        }
        Ok(Err(err)) => {
            eprintln!(
                "t449-probe: Viewer::connect error {}ms: {err}",
                connect_started.elapsed().as_millis()
            );
        }
        Err(_) => {
            eprintln!(
                "t449-probe: Viewer::connect timed out after {}ms",
                connect_started.elapsed().as_millis()
            );
        }
    }
}
