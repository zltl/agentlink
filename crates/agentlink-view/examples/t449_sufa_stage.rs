//! Read-only diagnostic: send webrtc list_monitors / offer to an existing
//! node (default: sufa) with the already-authorized client identity.
//! Does not create an identity or grant, does not print tokens, and closes
//! the session after a timed wait for a selected ICE pair and decoded frames.
//!
//! Portability: pure Viewer + Identity::load; no GUI, no input, no Unix debug
//! socket (unlike `controller --headless`, which requires unix). Safe on
//! Windows with the probe config dir.
//!
//! Annex-B access units from `poll_frame` are **not** decoded frames. This
//! probe also runs the same openh264 `Decoder` path as Controller
//! `H264Decoder`, but only keeps width×height (drops YUV; no RGBA, no pixels
//! saved, no paint). Do not claim GUI presentation from this tool alone.
//!
//! Sustained stats (after Viewer::connect): wall duration, received bytes,
//! decoded_fps (openh264 pictures / wall — not GUI presented fps), avg/max
//! decode_us, decode_errors, stalled receive intervals. Does **not** call
//! `drain_keep_latest` (that drops dependency frames and would skew decode).

use std::env;
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentlink_core::client::maintain_session;
use agentlink_core::config::{self, ClientSettings};
use agentlink_core::{apply_relay_defaults, Client, Identity, Op, PHASE3_WEBRTC_SIGNAL};
use agentlink_view::{
    is_screenshot_fallback, parse_bounded_u64, parse_max_decoded, LiveOptions, Signal, Viewer,
};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use openh264::nal_units;
use serde_json::{json, Value};

/// Dimension-only mirror of Controller `H264Decoder` (openh264 Decoder +
/// `nal_units`). Skips the RGBA conversion that paint uses.
struct ProbeH264 {
    inner: Option<Decoder>,
}

impl ProbeH264 {
    fn new() -> Self {
        Self {
            inner: Decoder::new().ok(),
        }
    }

    fn available(&self) -> bool {
        self.inner.is_some()
    }

    /// Last decoded picture dims in this access unit, plus openh264 errors.
    fn decode_dims(&mut self, annex_b: &[u8]) -> (Option<(usize, usize)>, u32) {
        let Some(decoder) = self.inner.as_mut() else {
            return (None, 0);
        };
        let mut last = None;
        let mut errors = 0u32;
        for nal in nal_units(annex_b) {
            match decoder.decode(nal) {
                Ok(Some(yuv)) => {
                    let (width, height) = yuv.dimensions();
                    if width == 0 || height == 0 {
                        continue;
                    }
                    // Drop YUV immediately — counters/dims only.
                    last = Some((width, height));
                }
                Ok(None) => {}
                Err(_) => {
                    errors += 1;
                    break;
                }
            }
        }
        (last, errors)
    }
}

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

fn probe_seconds() -> u64 {
    // Default 15s; clamp so a typo cannot run for hours.
    parse_bounded_u64(
        env::var("AGENTLINK_PROBE_SECONDS").ok().as_deref(),
        15,
        1,
        120,
    )
}

/// Cap decoded pictures so a long probe stays CPU-friendly.
/// Default `0` = no early stop (full window) — needed for ~30s sustained stats.
fn probe_max_decoded() -> u32 {
    parse_max_decoded(
        env::var("AGENTLINK_PROBE_MAX_DECODED").ok().as_deref(),
        0,
        10_000,
    )
}

fn log_unit(n: u32) -> bool {
    n <= 3 || n % 30 == 0
}

#[tokio::main]
async fn main() {
    let node = env::args().nth(1).unwrap_or_else(|| "sufa".to_string());
    let config_dir = env::var("AGENTLINK_CONFIG_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|_| config::default_config_dir().expect("config dir"));
    let wait_secs = probe_seconds();
    let max_decoded = probe_max_decoded();
    eprintln!(
        "t449-probe: config_dir={} node={} wait={}s max_decoded={} (0=full window; Identity::load only, no new grant; annex-b≠decoded; no drain_keep_latest)",
        config_dir.display(),
        node,
        wait_secs,
        max_decoded
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
    eprintln!(
        "t449-probe: stage=Viewer::connect starting (60s deadline, view-only, then close; no input)"
    );
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
                "t449-probe: Viewer::connect ok {}ms encoder={} hardware={} path={} offer_meta={}x{} codec={}",
                connect_started.elapsed().as_millis(),
                info.encoder,
                info.hardware,
                info.path,
                info.width,
                info.height,
                info.codec
            );
            let mut decoder = ProbeH264::new();
            eprintln!(
                "t449-probe: openh264 decoder available={} (same path as Controller H264Decoder; dims only; no pixels saved)",
                decoder.available()
            );
            let media_started = Instant::now();
            let deadline = media_started + Duration::from_secs(wait_secs);
            let mut annex_b_units = 0u32;
            let mut decoded_frames = 0u32;
            let mut received_bytes = 0u64;
            let mut decode_errors = 0u32;
            let mut decode_attempts = 0u32;
            let mut stalled_intervals = 0u32;
            let mut decode_us_total = 0u64;
            let mut decode_us_max = 0u64;
            let mut last_decoded_w = 0usize;
            let mut last_decoded_h = 0usize;
            let mut logged_pair = false;
            let mut saw_annex = false;
            let mut last_annex_at = Instant::now();
            while Instant::now() < deadline {
                if viewer.failed() {
                    eprintln!("t449-probe: viewer.failed() during probe window");
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
                let Some(frame) = viewer.poll_frame(Duration::from_millis(200)) else {
                    // Match controller stall heuristic: gap after media started.
                    if saw_annex && last_annex_at.elapsed() > Duration::from_millis(200) {
                        stalled_intervals += 1;
                        last_annex_at = Instant::now();
                    }
                    continue;
                };
                if saw_annex && last_annex_at.elapsed() > Duration::from_millis(500) {
                    stalled_intervals += 1;
                }
                saw_annex = true;
                last_annex_at = Instant::now();
                annex_b_units += 1;
                received_bytes += frame.annex_b.len() as u64;
                if log_unit(annex_b_units) {
                    eprintln!(
                        "t449-probe: annex-b unit #{} key={} offer_meta={}x{} bytes={} (not yet decoded)",
                        annex_b_units,
                        frame.keyframe,
                        frame.width,
                        frame.height,
                        frame.annex_b.len()
                    );
                }
                if !decoder.available() {
                    continue;
                }
                decode_attempts += 1;
                let decode_started = Instant::now();
                let (dims, errs) = decoder.decode_dims(&frame.annex_b);
                let decode_us = decode_started.elapsed().as_micros() as u64;
                decode_us_total += decode_us;
                if decode_us > decode_us_max {
                    decode_us_max = decode_us;
                }
                decode_errors += errs;
                if let Some((w, h)) = dims {
                    decoded_frames += 1;
                    last_decoded_w = w;
                    last_decoded_h = h;
                    if log_unit(decoded_frames) {
                        eprintln!(
                            "t449-probe: decoded frame #{decoded_frames} {w}x{h} decode_us={decode_us} (YUV dropped; no pixels saved)"
                        );
                    }
                    if max_decoded > 0 && decoded_frames >= max_decoded {
                        eprintln!("t449-probe: reached max_decoded={max_decoded}; stopping early");
                        break;
                    }
                } else if log_unit(annex_b_units) {
                    eprintln!(
                        "t449-probe: annex-b unit #{annex_b_units} produced no decoded picture yet (SPS/PPS, incomplete AU, or decode_error={errs})"
                    );
                }
            }
            let media_secs = media_started.elapsed().as_secs_f64().max(0.001);
            let decoded_fps = decoded_frames as f64 / media_secs;
            let avg_decode_us = if decode_attempts > 0 {
                decode_us_total / u64::from(decode_attempts)
            } else {
                0
            };
            if !logged_pair {
                eprintln!(
                    "t449-probe: no selected ICE pair within {wait_secs}s after connect (failed={})",
                    viewer.failed()
                );
            }
            let checks = viewer.ice_checks();
            if checks.is_empty() {
                eprintln!("t449-probe: ice checks snapshot empty (stats not yet populated)");
            } else {
                eprintln!("t449-probe: ice checks {checks}");
            }
            eprintln!(
                "t449-probe: summary duration_s={media_secs:.3} annex_b_units={annex_b_units} received_bytes={received_bytes} decoded_frames={decoded_frames} decoded_fps={decoded_fps:.2} avg_decode_us={avg_decode_us} max_decode_us={decode_us_max} decode_errors={decode_errors} stalled_intervals={stalled_intervals} last_decoded={}x{} pair={} failed={} (decoded_fps≠GUI presented_fps; no pixels saved)",
                last_decoded_w,
                last_decoded_h,
                logged_pair,
                viewer.failed()
            );
            if annex_b_units > 0 && decoded_frames == 0 {
                eprintln!(
                    "t449-probe: WARNING annex-b arrived but openh264 yielded 0 pictures — do not treat NAL receipt as decode success"
                );
            }
            viewer.close();
            eprintln!("t449-probe: viewer closed (no GUI paint claimed)");
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
