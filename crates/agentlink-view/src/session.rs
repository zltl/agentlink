//! Offer/answer against the node's `webrtc_signal` handler.
//!
//! The sequence matches the browser page: recvonly H.264, data channels
//! named `input`, `cursor`, and `meta`, then `offer` / `ice` / `keyframe` /
//! `close`. RTP is reassembled here. The platform only sees Annex-B.

use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rtc::peer_connection::configuration::RTCOfferOptions;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::rtp_transceiver::rtp_sender::{RTCRtpCodec, RTCRtpCodecParameters, RtpCodecKind};
use rtc::rtp_transceiver::{RTCRtpTransceiverDirection, RTCRtpTransceiverInit};
use serde_json::{json, Value};
use tokio::sync::mpsc::{self, UnboundedSender};
use webrtc::data_channel::{DataChannel, DataChannelEvent};
use webrtc::media_stream::track_remote::{TrackRemote, TrackRemoteEvent};
use webrtc::peer_connection::{
    register_default_interceptors, MediaEngine, PeerConnection, PeerConnectionBuilder,
    PeerConnectionEventHandler, RTCConfigurationBuilder, RTCIceGatheringState, RTCIceServer,
    RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription, RTCStatsReport,
    RTCStatsReportEntry, Registry, SettingEngineBuilder, StatsSelector,
};
use webrtc::runtime::default_runtime;

use agentlink_core::{
    prefer_on_link_hosts_in_candidate, prefer_on_link_hosts_in_sdp, HOST_ACCEPTANCE_MIN_WAIT,
};

use crate::h264::{
    addr_scope, classify_media_path, classify_selected_path, describe_ice_candidates,
    detect_tailscale_reason, feedback_ratio, is_screenshot_fallback, media_path_hint, AccessUnit,
    AddrScope, H264Depacketizer, LossWindow,
};
use crate::queue::{FrameBus, Queued};

const GATHER_WAIT: Duration = Duration::from_millis(1500);

#[derive(Clone)]
pub struct LiveOptions {
    pub max_fps: u32,
    pub bitrate: u32,
    pub monitor: u32,
    pub viewer: String,
    pub ice_servers: Vec<Value>,
    /// When false, the offer sets `_allow_control` so a view-only session
    /// cannot drive a node whose account grant includes remote control.
    pub control: bool,
    /// Capture downscale before encode (`1.0` = native). Clamped on the node.
    pub scale: f32,
    /// Requested cursor presentation (`"metadata"` for RDP-style local sprite
    /// when the node can exclude the embedded pointer; `"legacy"` otherwise).
    pub cursor_mode: String,
    /// Test-only ICE fault. Production always leaves this as [`IceFault::None`].
    /// It is never read from the environment and never forbids direct by default.
    pub ice_fault: IceFault,
    /// Optional handshake reporter (Controller HUD / tests). Not a media path.
    pub on_stage: Option<Arc<dyn Fn(&str) + Send + Sync>>,
}

impl std::fmt::Debug for LiveOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LiveOptions")
            .field("max_fps", &self.max_fps)
            .field("bitrate", &self.bitrate)
            .field("monitor", &self.monitor)
            .field("viewer", &self.viewer)
            .field("ice_servers", &self.ice_servers)
            .field("control", &self.control)
            .field("scale", &self.scale)
            .field("cursor_mode", &self.cursor_mode)
            .field("ice_fault", &self.ice_fault)
            .field("on_stage", &self.on_stage.is_some())
            .finish()
    }
}

/// Deterministic ICE faults for isolated tests. Not a product default.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum IceFault {
    #[default]
    None,
    /// Gather only relay candidates and include no TURN server, so ICE
    /// cannot connect. Used to prove JPEG fallback without a firewall change.
    RelayPolicyWithoutTurn,
    /// After a real offer/answer, drop remote ICE candidates so no pair
    /// can form. Used to exercise the 12s no-pair timeout and JPEG stills
    /// HUD without changing the network or a remote node.
    NoPairAfterSignaling,
}

impl Default for LiveOptions {
    fn default() -> Self {
        Self {
            max_fps: 30,
            bitrate: 2_000_000,
            monitor: 0,
            viewer: "android".into(),
            ice_servers: Vec::new(),
            control: true,
            scale: 1.0,
            // Desktop Controller asks for metadata; nodes without exclude stay legacy.
            cursor_mode: "metadata".into(),
            ice_fault: IceFault::None,
            on_stage: None,
        }
    }
}

/// Remove `a=candidate` lines from an SDP. Test-only helper for
/// [`IceFault::NoPairAfterSignaling`]; production never strips a live answer.
fn strip_sdp_ice_candidates(sdp: &str) -> String {
    let crlf = sdp.contains("\r\n");
    let sep = if crlf { "\r\n" } else { "\n" };
    let text = sdp
        .lines()
        .filter(|line| !line.trim().to_ascii_lowercase().starts_with("a=candidate"))
        .collect::<Vec<_>>()
        .join(sep);
    if sdp.ends_with('\n') && !text.ends_with('\n') {
        format!("{text}{sep}")
    } else {
        text
    }
}

/// Raise on-link physical LAN host priority on a remote ICE candidate string.
/// Overlay/`100.x`/srflx/relay stay present — preference only, never a filter.
fn prefer_remote_ice(mut init: RTCIceCandidateInit) -> RTCIceCandidateInit {
    if !init.candidate.is_empty() {
        init.candidate = prefer_on_link_hosts_in_candidate(&init.candidate);
    }
    init
}

fn report_stage(opts: &LiveOptions, msg: &str) {
    eprintln!("agentlink live-webrtc: {msg}");
    if let Some(cb) = &opts.on_stage {
        cb(msg);
    }
}

#[derive(Clone, Debug)]
pub struct LiveInfo {
    pub session_id: String,
    pub codec: String,
    pub encoder: String,
    pub hardware: bool,
    pub width: u32,
    pub height: u32,
    /// True content size before encode macroblock pad (0 ⇒ treat as width/height).
    pub src_width: u32,
    pub src_height: u32,
    pub control: bool,
    /// Confirmed media path: `host`, `stun`, `turn`, `tailscale`,
    /// `connecting`, `unknown`, or `relay` (legacy). Set from the selected
    /// ICE pair once ICE connects, not from the answer SDP inventory.
    pub path: String,
    /// `classify_media_path` of the answer SDP. Log-only; never the HUD path.
    pub sdp_inventory: String,
    /// Negotiated cursor presentation: `"legacy"` (default) or `"metadata"`.
    /// Missing on old nodes ⇒ legacy. Never paint a second local sprite in legacy.
    pub cursor_presentation: String,
}

/// Selected ICE pair as observed on the viewer's peer connection.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransportSnapshot {
    pub path: String,
    pub local_typ: String,
    pub remote_typ: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub sdp_inventory: String,
    pub note: String,
}

#[derive(Clone, Debug)]
pub struct LiveFrame {
    pub annex_b: Vec<u8>,
    pub keyframe: bool,
    pub captured_unix_ms: i64,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug)]
pub struct LiveCursor {
    pub x: i32,
    pub y: i32,
    pub shape: String,
    /// Remote OS pointer visibility — distinct from capture exclusion.
    pub visible: bool,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub bitmap_w: u32,
    pub bitmap_h: u32,
    /// Tightly packed RGBA8 when the node sent a custom sprite.
    pub bitmap_rgba: Option<Vec<u8>>,
}

/// Unicode clipboard text received on the `input` data channel.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveClipboard {
    pub text: String,
    pub truncated: bool,
}

#[derive(Clone, Debug, Default)]
pub struct LiveStats {
    pub frames: u64,
    pub bytes: u64,
    pub loss: f64,
    pub latency_ms: i64,
    pub frames_dropped: u64,
}

pub trait Signal: Send + Sync {
    fn signal(&self, payload: &Value) -> Result<Value, String>;
}

#[derive(Debug)]
enum Cmd {
    Control(String),
    Keyframe,
    Close,
}

pub struct Viewer {
    cmd: mpsc::Sender<Cmd>,
    frames: Arc<FrameBus>,
    info: Arc<Mutex<LiveInfo>>,
    transport: Arc<Mutex<Option<TransportSnapshot>>>,
    cursor: Arc<Mutex<Option<LiveCursor>>>,
    clipboard: Arc<Mutex<Option<LiveClipboard>>>,
    stats: Arc<Mutex<LiveStats>>,
    /// Safe ICE check snapshot (typ, raddr, proto, pair state, send/recv counts).
    /// No ICE ufrag/pwd, certificates, or packet payloads.
    ice_checks: Arc<Mutex<String>>,
    input_open: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    close_notify: Arc<tokio::sync::Notify>,
    closed: AtomicBool,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

impl Viewer {
    pub fn connect(signal: Arc<dyn Signal>, opts: LiveOptions) -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("agentlink-view")
            .build()
            .map_err(|err| err.to_string())?;
        let built = runtime.block_on(connect_inner(signal, opts))?;
        Ok(Self {
            cmd: built.cmd,
            frames: built.frames,
            info: built.info,
            transport: built.transport,
            cursor: built.cursor,
            clipboard: built.clipboard,
            stats: built.stats,
            ice_checks: built.ice_checks,
            input_open: built.input_open,
            failed: built.failed,
            stop: built.stop,
            stopped: built.stopped,
            close_notify: built.close_notify,
            closed: built.closed,
            runtime: Mutex::new(Some(runtime)),
        })
    }

    pub fn info(&self) -> LiveInfo {
        let mut info = self
            .info
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        if let Some(snap) = self.transport() {
            if !snap.path.is_empty() {
                info.path = snap.path;
            }
        }
        info
    }

    /// Selected ICE pair once ICE has picked one. `None` until then.
    pub fn transport(&self) -> Option<TransportSnapshot> {
        self.transport
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    /// Latest safe ICE check snapshot from the WebRTC stats API.
    /// Empty until the first drive tick after connect.
    pub fn ice_checks(&self) -> String {
        self.ice_checks
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    pub fn poll_frame(&self, timeout: Duration) -> Option<LiveFrame> {
        let queued = self.frames.pop(timeout)?;
        if let Ok(mut stats) = self.stats.lock() {
            stats.frames += 1;
            stats.bytes += queued.bytes.len() as u64;
        }
        Some(LiveFrame {
            annex_b: queued.bytes,
            keyframe: queued.keyframe,
            captured_unix_ms: queued.captured_unix_ms,
            width: self.info().width,
            height: self.info().height,
        })
    }

    /// After a slow decode, discard backlog and keep only the newest unit.
    pub fn drain_keep_latest(&self) -> Option<LiveFrame> {
        let queued = self.frames.drain_keep_latest()?;
        if let Ok(mut stats) = self.stats.lock() {
            stats.frames += 1;
            stats.bytes += queued.bytes.len() as u64;
            stats.frames_dropped = stats.frames_dropped.saturating_add(1);
        }
        Some(LiveFrame {
            annex_b: queued.bytes,
            keyframe: queued.keyframe,
            captured_unix_ms: queued.captured_unix_ms,
            width: self.info().width,
            height: self.info().height,
        })
    }

    pub fn poll_cursor(&self) -> Option<LiveCursor> {
        self.cursor
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    /// Take the latest remote clipboard payload, if any. Consumed once so a
    /// session cannot replay an old copy after the user has moved on.
    pub fn poll_clipboard(&self) -> Option<LiveClipboard> {
        self.clipboard
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take()
    }

    /// True after [`Self::close`] or a peer failure. Clipboard share tasks
    /// use this so they exit instead of leaving a residual watcher.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
            || self.stop.load(Ordering::Relaxed)
            || self.stopped.load(Ordering::Relaxed)
    }

    pub fn stats(&self) -> LiveStats {
        self.stats
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    pub fn send_control(&self, json: &str) -> bool {
        self.send_control_move(json)
    }

    /// Coalescable move path — try_send only; OK to drop under saturation.
    pub fn send_control_move(&self, json: &str) -> bool {
        if !self.input_open.load(Ordering::Relaxed) {
            return false;
        }
        self.cmd.try_send(Cmd::Control(json.to_string())).is_ok()
    }

    /// Barrier path — await queue space so later clicks cannot leapfrog a
    /// queued RTC down via Extension fallback. Returns false if the channel
    /// is closed or input is down (caller must **not** switch routes).
    pub async fn send_control_barrier(&self, json: &str) -> bool {
        if !self.input_open.load(Ordering::Relaxed) || self.stop.load(Ordering::Relaxed) {
            return false;
        }
        let send = self.cmd.send(Cmd::Control(json.to_string()));
        match tokio::time::timeout(Duration::from_secs(2), send).await {
            Ok(Ok(())) => true,
            Ok(Err(_)) => false,
            Err(_) => {
                // Timed out waiting for capacity while still open — still no
                // alternate route; drop rather than reorder.
                false
            }
        }
    }

    pub fn request_keyframe(&self) {
        let _ = self.cmd.try_send(Cmd::Keyframe);
    }

    pub fn failed(&self) -> bool {
        self.failed.load(Ordering::Relaxed)
    }

    pub fn close(&self) {
        self.request_close();
        // 0111/0133 panicked here on the controller worker runtime:
        // `blocking_send` and `thread::sleep` cannot run on
        // `agentlink-controller-net` (session.rs:214, Cmd::PtyOpen
        // calls stop_live → Viewer::close). Wait only off-runtime.
        if in_tokio_runtime() {
            return;
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !self.stopped.load(Ordering::Relaxed) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn request_close(&self) {
        if self.closed.swap(true, Ordering::Relaxed) {
            return;
        }
        self.stop.store(true, Ordering::Release);
        self.close_notify.notify_waiters();
        // Never use blocking_send. A full queue still wakes `drive` via
        // stop + Notify, so Close cannot be lost.
        if self.cmd.try_send(Cmd::Close).is_err() && self.cmd.is_closed() {
            self.stopped.store(true, Ordering::Relaxed);
        }
    }
}

impl Drop for Viewer {
    fn drop(&mut self) {
        self.request_close();
        if let Some(runtime) = self
            .runtime
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .take()
        {
            // shutdown_timeout also parks the thread and panics inside a
            // runtime. The viewer runtime is not the current one, but Tokio
            // still forbids blocking on agentlink-controller-net.
            if in_tokio_runtime() {
                runtime.shutdown_background();
            } else {
                runtime.shutdown_timeout(Duration::from_secs(2));
            }
        }
    }
}

fn in_tokio_runtime() -> bool {
    tokio::runtime::Handle::try_current().is_ok()
}

struct Built {
    cmd: mpsc::Sender<Cmd>,
    frames: Arc<FrameBus>,
    info: Arc<Mutex<LiveInfo>>,
    transport: Arc<Mutex<Option<TransportSnapshot>>>,
    cursor: Arc<Mutex<Option<LiveCursor>>>,
    clipboard: Arc<Mutex<Option<LiveClipboard>>>,
    stats: Arc<Mutex<LiveStats>>,
    ice_checks: Arc<Mutex<String>>,
    input_open: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    close_notify: Arc<tokio::sync::Notify>,
    closed: AtomicBool,
}

async fn connect_inner(signal: Arc<dyn Signal>, opts: LiveOptions) -> Result<Built, String> {
    let no_pair_after_signaling = matches!(opts.ice_fault, IceFault::NoPairAfterSignaling);
    report_stage(&opts, "list_monitors sent");
    match roundtrip(&signal, json!({"action": "list_monitors"})).await {
        Ok(value) if is_screenshot_fallback(&value) => {
            report_stage(&opts, "list_monitors returned screenshot fallback");
            return Err("live video is not available; fallback screenshot".into());
        }
        Ok(_) => report_stage(&opts, "list_monitors ok"),
        Err(err) if unknown_action(&err) => {
            report_stage(&opts, "list_monitors skipped (unknown action)");
        }
        Err(err) => {
            report_stage(&opts, &format!("list_monitors error: {err}"));
            return Err(err);
        }
    }

    let (fps, bitrate) = crate::h264::clamp_offer(opts.max_fps, opts.bitrate);
    let ice_servers = if matches!(opts.ice_fault, IceFault::RelayPolicyWithoutTurn) {
        Vec::new()
    } else {
        offer_servers(&opts.ice_servers)
    };
    let frames = Arc::new(FrameBus::new(3));
    let loss = Arc::new(Mutex::new(LossWindow::default()));
    let stats = Arc::new(Mutex::new(LiveStats::default()));
    let cursor = Arc::new(Mutex::new(None));
    let clipboard = Arc::new(Mutex::new(None));
    let failed = Arc::new(AtomicBool::new(false));
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::new(AtomicBool::new(false));
    let close_notify = Arc::new(tokio::sync::Notify::new());
    let input_open = Arc::new(AtomicBool::new(false));
    let captured = Arc::new(AtomicI64::new(0));
    let (ice_tx, mut ice_rx) = mpsc::unbounded_channel();
    let gather_done = Arc::new(AtomicBool::new(false));
    let input_slot: Arc<Mutex<Option<Arc<dyn DataChannel>>>> = Arc::new(Mutex::new(None));

    let disconnected_at_ms = Arc::new(AtomicI64::new(0));
    let handler = Arc::new(ViewHandler {
        gather_done: gather_done.clone(),
        ice_tx,
        frames: frames.clone(),
        loss: loss.clone(),
        failed: failed.clone(),
        stop: stop.clone(),
        captured: captured.clone(),
        disconnected_at_ms: disconnected_at_ms.clone(),
    });

    report_stage(&opts, "building peer connection");
    let runtime =
        default_runtime().ok_or_else(|| "tokio runtime is required for WebRTC".to_string())?;
    let mut media = MediaEngine::default();
    media
        .register_codec(h264_codec(), RtpCodecKind::Video)
        .map_err(|err| err.to_string())?;
    let registry = register_default_interceptors(Registry::new(), &mut media)
        .map_err(|err| err.to_string())?;
    let mut cfg = RTCConfigurationBuilder::new().with_ice_servers(rtc_ice(&ice_servers));
    if matches!(opts.ice_fault, IceFault::RelayPolicyWithoutTurn) {
        cfg = RTCConfigurationBuilder::new()
            .with_ice_servers(Vec::new())
            .with_ice_transport_policy(
                rtc::peer_connection::configuration::RTCIceTransportPolicy::Relay,
            );
    }
    let setting_engine = SettingEngineBuilder::new()
        .with_host_acceptance_min_wait(Some(HOST_ACCEPTANCE_MIN_WAIT))
        .build();
    let pc = PeerConnectionBuilder::new()
        .with_configuration(cfg.build())
        .with_setting_engine(setting_engine)
        .with_media_engine(media)
        .with_interceptor_registry(registry)
        .with_handler(handler.clone() as Arc<dyn PeerConnectionEventHandler>)
        .with_runtime(runtime)
        .with_udp_addrs(vec!["0.0.0.0:0".to_string()])
        .build()
        .await
        .map_err(|err| err.to_string())?;

    let input = PeerConnection::create_data_channel(&pc, "input", None)
        .await
        .map_err(|err| err.to_string())?;
    let cursor_ch = PeerConnection::create_data_channel(&pc, "cursor", None)
        .await
        .map_err(|err| err.to_string())?;
    let meta_ch = PeerConnection::create_data_channel(&pc, "meta", None)
        .await
        .map_err(|err| err.to_string())?;
    *input_slot.lock().unwrap_or_else(|err| err.into_inner()) = Some(input.clone());
    watch_input(input, input_open.clone(), clipboard.clone(), stop.clone());
    watch_cursor(cursor_ch, cursor.clone(), stop.clone());
    watch_meta(meta_ch, captured.clone(), stats.clone(), stop.clone());

    let init = RTCRtpTransceiverInit {
        direction: RTCRtpTransceiverDirection::Recvonly,
        ..Default::default()
    };
    PeerConnection::add_transceiver_from_kind(&pc, RtpCodecKind::Video, Some(init))
        .await
        .map_err(|err| err.to_string())?;

    report_stage(&opts, "creating local offer, gathering ICE (1.5s)");
    let offer = PeerConnection::create_offer(&pc, None)
        .await
        .map_err(|err| err.to_string())?;
    PeerConnection::set_local_description(&pc, offer)
        .await
        .map_err(|err| err.to_string())?;
    let deadline = Instant::now() + GATHER_WAIT;
    while !gather_done.load(Ordering::Relaxed) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let local = PeerConnection::local_description(&pc)
        .await
        .ok_or_else(|| "local description was not set".to_string())?;
    let stun_n = ice_servers
        .iter()
        .flat_map(|e| {
            e.get("urls")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        })
        .filter(|u| u.as_str().unwrap_or("").starts_with("stun:"))
        .count();
    let turn_n = ice_servers
        .iter()
        .flat_map(|e| {
            e.get("urls")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default()
        })
        .filter(|u| {
            let s = u.as_str().unwrap_or("");
            s.starts_with("turn:") || s.starts_with("turns:")
        })
        .count();
    report_stage(
        &opts,
        &format!(
            "local offer ready (sdp_len={}, gather_complete={}, stun={}, turn={}, candidates={})",
            local.sdp.len(),
            gather_done.load(Ordering::Relaxed),
            stun_n,
            turn_n,
            describe_ice_candidates(&local.sdp)
        ),
    );
    report_stage(&opts, "sending webrtc offer");
    let offer_sdp = if no_pair_after_signaling {
        let stripped = strip_sdp_ice_candidates(&local.sdp);
        eprintln!(
            "agentlink live-webrtc: test IceFault::NoPairAfterSignaling omitted local ICE candidates from the offer and will not trickle"
        );
        stripped
    } else {
        local.sdp.clone()
    };
    let answer = roundtrip(
        &signal,
        json!({
            "action": "offer",
            "sdp": offer_sdp,
            "viewer": opts.viewer,
            "monitor": opts.monitor,
            "codec": "h264",
            "max_fps": fps,
            "bitrate": bitrate,
            "scale": opts.scale.clamp(0.05, 1.0),
            "audio": false,
            "ice_servers": ice_servers,
            "gather_ms": 4000,
            "_allow_control": opts.control,
            // Additive: old nodes ignore. New nodes open Mutter metadata when able.
            "cursor_mode": if opts.cursor_mode.eq_ignore_ascii_case("legacy") {
                "legacy"
            } else {
                "metadata"
            },
        }),
    )
    .await?;
    if is_screenshot_fallback(&answer) {
        report_stage(&opts, "offer returned screenshot fallback (no live video)");
        let _ = PeerConnection::close(&pc).await;
        return Err("live video is not available; fallback screenshot".into());
    }
    let session_id = answer
        .get("session_id")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let mut sdp = answer
        .get("sdp")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    if no_pair_after_signaling {
        sdp = strip_sdp_ice_candidates(&sdp);
        eprintln!(
            "agentlink live-webrtc: test IceFault::NoPairAfterSignaling stripped remote ICE candidates"
        );
    }
    if session_id.is_empty() || sdp.is_empty() {
        report_stage(
            &opts,
            &format!("offer response missing session/sdp: {}", brief(&answer)),
        );
        let _ = PeerConnection::close(&pc).await;
        return Err(format!(
            "offer did not return a session: {}",
            brief(&answer)
        ));
    }
    let extra_candidates = answer
        .get("candidates")
        .and_then(|value| value.as_array())
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.get("candidate").and_then(|v| v.as_str()))
                .collect::<Vec<_>>()
                .join(
                    "
",
                )
        })
        .unwrap_or_default();
    report_stage(
        &opts,
        &format!(
            "offer answered (session_len={}, sdp_len={}, encoder={}, hardware={}, sdp_candidates={}, extra_candidates={})",
            session_id.len(),
            sdp.len(),
            answer.get("encoder").and_then(|v| v.as_str()).unwrap_or(""),
            answer.get("hardware").and_then(|v| v.as_bool()).unwrap_or(false),
            describe_ice_candidates(&sdp),
            describe_ice_candidates(&extra_candidates)
        ),
    );
    let info = LiveInfo {
        session_id: session_id.clone(),
        codec: answer
            .get("codec")
            .and_then(|value| value.as_str())
            .unwrap_or("h264")
            .to_string(),
        encoder: answer
            .get("encoder")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string(),
        hardware: answer
            .get("hardware")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        width: json_u32(&answer, "width"),
        height: json_u32(&answer, "height"),
        src_width: {
            let src = json_u32(&answer, "src_width");
            if src > 0 {
                src
            } else {
                json_u32(&answer, "width")
            }
        },
        src_height: {
            let src = json_u32(&answer, "src_height");
            if src > 0 {
                src
            } else {
                json_u32(&answer, "height")
            }
        },
        control: answer
            .get("control")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        path: "connecting".into(),
        sdp_inventory: classify_media_path(&sdp).to_string(),
        // Empty when the node omitted the field (pre-negotiation) — Controller
        // must not hide the OS cursor as if embedding were known.
        cursor_presentation: answer
            .get("cursor_presentation")
            .and_then(|value| value.as_str())
            .unwrap_or("")
            .to_string(),
    };
    let info = Arc::new(Mutex::new(info));
    let transport = Arc::new(Mutex::new(None));
    let ice_checks = Arc::new(Mutex::new(String::new()));

    report_stage(&opts, "applying remote answer, ICE in progress");
    let pull_ufrag_early = sdp_ice_ufrag(&sdp);
    let sdp = prefer_on_link_hosts_in_sdp(&sdp);
    let remote = RTCSessionDescription::answer(sdp).map_err(|err| err.to_string())?;
    PeerConnection::set_remote_description(&pc, remote)
        .await
        .map_err(|err| err.to_string())?;
    if !no_pair_after_signaling {
        if let Some(candidates) = answer.get("candidates").and_then(|value| value.as_array()) {
            for candidate in candidates {
                if let Ok(init) = serde_json::from_value::<RTCIceCandidateInit>(candidate.clone()) {
                    let _ = PeerConnection::add_ice_candidate(&pc, prefer_remote_ice(init)).await;
                }
            }
        }
    }

    let peer = Arc::new(OwnedPeer { inner: pc });
    let (cmd_tx, cmd_rx) = mpsc::channel(32);
    let peer_loop = peer.clone();
    let signal_loop = signal.clone();
    let session_loop = session_id.clone();
    let frames_loop = frames.clone();
    let loss_loop = loss.clone();
    let stats_loop = stats.clone();
    let input_loop = input_slot.clone();
    let input_flag = input_open.clone();
    let stop_loop = stop.clone();
    let stopped_loop = stopped.clone();
    let close_notify_loop = close_notify.clone();
    let failed_loop = failed.clone();
    let gather_ice = gather_done.clone();
    let disc_loop = disconnected_at_ms;
    let info_loop = info.clone();
    let transport_loop = transport.clone();
    let ice_checks_loop = ice_checks.clone();
    tokio::spawn(async move {
        drive(
            peer_loop,
            cmd_rx,
            signal_loop,
            session_loop,
            frames_loop,
            loss_loop,
            stats_loop,
            input_loop,
            input_flag,
            stop_loop,
            stopped_loop,
            close_notify_loop,
            failed_loop,
            gather_ice,
            disc_loop,
            info_loop,
            transport_loop,
            ice_checks_loop,
        )
        .await;
    });

    let signal_ice = signal.clone();
    let session_ice = session_id.clone();
    let stop_ice = stop.clone();
    let suppress_trickle = no_pair_after_signaling;
    tokio::spawn(async move {
        while let Some(candidate) = ice_rx.recv().await {
            if stop_ice.load(Ordering::Relaxed) {
                break;
            }
            if suppress_trickle {
                continue;
            }
            let typ_addr = candidate
                .get("candidate")
                .and_then(|value| value.as_str())
                .unwrap_or("");
            let result = roundtrip(
                &signal_ice,
                json!({
                    "action": "ice",
                    "session_id": session_ice,
                    "candidate": candidate,
                }),
            )
            .await;
            match result {
                Ok(_) => eprintln!(
                    "agentlink live-webrtc: trickle ice sent ok ({})",
                    describe_ice_candidates(typ_addr)
                ),
                Err(err) => eprintln!(
                    "agentlink live-webrtc: trickle ice error ({err}) ({})",
                    describe_ice_candidates(typ_addr)
                ),
            }
        }
    });

    let pull_advertised = answer
        .get("ice_pull")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    let pull_after = answer
        .get("candidates")
        .and_then(|value| value.as_array())
        .map(|arr| arr.len() as u64)
        .unwrap_or(0);
    let pull_ufrag = pull_ufrag_early;
    let pull_signal = signal.clone();
    let pull_session = session_id.clone();
    let pull_stop = stop.clone();
    let pull_peer = peer.clone();
    tokio::spawn(async move {
        pull_late_ice(
            pull_signal,
            pull_session,
            pull_peer,
            pull_stop,
            pull_advertised,
            no_pair_after_signaling,
            pull_after,
            pull_ufrag,
        )
        .await;
    });

    report_stage(&opts, "requesting keyframe");
    let _ = roundtrip(
        &signal,
        json!({"action": "keyframe", "session_id": session_id}),
    )
    .await;
    report_stage(&opts, "signaling complete, waiting for ICE pair / video");

    Ok(Built {
        cmd: cmd_tx,
        frames,
        info,
        transport,
        cursor,
        clipboard,
        stats,
        ice_checks,
        input_open,
        failed,
        stop,
        stopped,
        close_notify,
        closed: AtomicBool::new(false),
    })
}

async fn drive(
    peer: Arc<dyn LivePeer>,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    signal: Arc<dyn Signal>,
    session_id: String,
    frames: Arc<FrameBus>,
    loss: Arc<Mutex<LossWindow>>,
    stats: Arc<Mutex<LiveStats>>,
    input: Arc<Mutex<Option<Arc<dyn DataChannel>>>>,
    input_open: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    close_notify: Arc<tokio::sync::Notify>,
    failed: Arc<AtomicBool>,
    gather_done: Arc<AtomicBool>,
    disconnected_at_ms: Arc<AtomicI64>,
    info: Arc<Mutex<LiveInfo>>,
    transport: Arc<Mutex<Option<TransportSnapshot>>>,
    ice_checks: Arc<Mutex<String>>,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.tick().await;
    let mut last_ice_restart = Instant::now() - Duration::from_secs(30);
    let mut ice_restart_fails = 0u32;
    let mut last_ice_log = String::new();
    let mut last_ice_log_at = Instant::now() - Duration::from_secs(30);
    loop {
        if stop.load(Ordering::Relaxed) {
            stop.store(true, Ordering::Relaxed);
            publish_ice_checks(&peer, &ice_checks, &mut last_ice_log, true).await;
            let _ = roundtrip(
                &signal,
                json!({"action": "close", "session_id": session_id}),
            )
            .await;
            peer.close().await;
            stopped.store(true, Ordering::Relaxed);
            break;
        }
        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(Cmd::Control(text)) => {
                        let _ = send_text(&input, &input_open, &text).await;
                    }
                    Some(Cmd::Keyframe) => {
                        ask_keyframe(&signal, &session_id, &input, &input_open).await;
                    }
                    Some(Cmd::Close) | None => {
                        stop.store(true, Ordering::Relaxed);
                    }
                }
            }
            _ = close_notify.notified() => {
                stop.store(true, Ordering::Relaxed);
            }
            _ = tick.tick() => {
                let (dropped, shown, needs) = frames.take_feedback();
                let rtp = loss
                    .lock()
                    .unwrap_or_else(|err| err.into_inner())
                    .take_ratio();
                if let Some(rtp) = rtp.or(if dropped > 0 { Some(0.0) } else { None }) {
                    let ratio = feedback_ratio(rtp, dropped, shown);
                    if let Ok(mut stats) = stats.lock() {
                        stats.loss = ratio;
                        stats.frames_dropped = stats.frames_dropped.saturating_add(dropped);
                    }
                    let _ = send_text(
                        &input,
                        &input_open,
                        &json!({"type": "feedback", "loss": ratio}).to_string(),
                    )
                    .await;
                }
                if needs || !frames.saw_keyframe() {
                    ask_keyframe(&signal, &session_id, &input, &input_open).await;
                }
                refresh_transport(&peer, &info, &transport).await;
                let force = last_ice_log_at.elapsed() >= Duration::from_secs(4);
                if publish_ice_checks(&peer, &ice_checks, &mut last_ice_log, force).await {
                    last_ice_log_at = Instant::now();
                }
                // ICE/DTLS left Connected: restart within 1s (throttle 5s).
                // A gone node session must be treated as a hard ICE/session
                // loss so the Controller can resume JPEG — do not retry
                // ice_restart in a tight loop.
                let disc = disconnected_at_ms.load(Ordering::Relaxed);
                if disc > 0 {
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    if now_ms.saturating_sub(disc) >= 1000
                        && last_ice_restart.elapsed() >= Duration::from_secs(5)
                    {
                        last_ice_restart = Instant::now();
                        match ice_restart(&peer, &signal, &session_id, &gather_done).await
                        {
                            Ok(()) => {
                                disconnected_at_ms.store(0, Ordering::Relaxed);
                                ask_keyframe(&signal, &session_id, &input, &input_open)
                                    .await;
                            }
                            Err(err) if signaling_session_gone(&err) => {
                                eprintln!(
                                    "agentlink live-webrtc: session gone ({err}); ending live video"
                                );
                                failed.store(true, Ordering::Relaxed);
                            }
                            Err(err) => {
                                ice_restart_fails += 1;
                                eprintln!(
                                    "agentlink live-webrtc: ice_restart error ({ice_restart_fails}): {err}"
                                );
                                if ice_restart_fails >= 3 {
                                    failed.store(true, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn signaling_session_gone(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("unknown stream session")
        || lower.contains("unknown session")
        || lower.contains("no such session")
        || lower.contains("session not found")
        || lower.contains("session closed")
        || lower.contains("already closed")
}

async fn ice_restart(
    peer: &Arc<dyn LivePeer>,
    signal: &Arc<dyn Signal>,
    session_id: &str,
    gather_done: &Arc<AtomicBool>,
) -> Result<(), String> {
    gather_done.store(false, Ordering::Relaxed);
    let sdp = peer.create_ice_restart_offer().await?;
    let deadline = Instant::now() + Duration::from_millis(800);
    while !gather_done.load(Ordering::Relaxed) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let sdp = peer.local_sdp().await.unwrap_or(sdp);
    let answer = roundtrip(
        signal,
        json!({
            "action": "ice_restart",
            "session_id": session_id,
            "sdp": sdp,
        }),
    )
    .await?;
    let remote = answer
        .get("sdp")
        .and_then(Value::as_str)
        .ok_or_else(|| "ice_restart missing sdp".to_string())?;
    peer.apply_remote_answer(remote).await?;
    if let Some(candidates) = answer.get("candidates").and_then(Value::as_array) {
        for candidate in candidates {
            if let Ok(init) = serde_json::from_value::<RTCIceCandidateInit>(candidate.clone()) {
                let _ = peer.add_ice_candidate(prefer_remote_ice(init)).await;
            }
        }
    }
    Ok(())
}

async fn ask_keyframe(
    signal: &Arc<dyn Signal>,
    session_id: &str,
    input: &Mutex<Option<Arc<dyn DataChannel>>>,
    input_open: &AtomicBool,
) {
    let _ = send_text(input, input_open, r#"{"type":"keyframe"}"#).await;
    let _ = roundtrip(
        signal,
        json!({"action": "keyframe", "session_id": session_id}),
    )
    .await;
}

async fn send_text(
    input: &Mutex<Option<Arc<dyn DataChannel>>>,
    input_open: &AtomicBool,
    text: &str,
) -> bool {
    if !input_open.load(Ordering::Relaxed) {
        return false;
    }
    let channel = input.lock().unwrap_or_else(|err| err.into_inner()).clone();
    let Some(channel) = channel else {
        return false;
    };
    channel.send_text(text).await.is_ok()
}

/// Soft cap matching the node clipboard contract. The viewer must not
/// materialize an uncapped payload even if a peer sends one.
const CLIPBOARD_MAX_CHARS: usize = 1_048_576;

fn parse_clipboard_set(value: &Value) -> Option<LiveClipboard> {
    if value.get("type").and_then(Value::as_str) != Some("clipboard") {
        return None;
    }
    let text = value.get("text").and_then(Value::as_str)?;
    let truncated_flag = value
        .get("truncated")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut text = text.to_string();
    let mut truncated = truncated_flag;
    if text.chars().count() > CLIPBOARD_MAX_CHARS {
        text = text.chars().take(CLIPBOARD_MAX_CHARS).collect();
        truncated = true;
    }
    Some(LiveClipboard { text, truncated })
}

fn watch_input(
    channel: Arc<dyn DataChannel>,
    open: Arc<AtomicBool>,
    clipboard: Arc<Mutex<Option<LiveClipboard>>>,
    stop: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match channel.poll().await {
                Some(DataChannelEvent::OnOpen) => open.store(true, Ordering::Relaxed),
                Some(DataChannelEvent::OnMessage(message)) => {
                    if let Ok(value) = serde_json::from_slice::<Value>(&message.data) {
                        if let Some(clip) = parse_clipboard_set(&value) {
                            *clipboard.lock().unwrap_or_else(|err| err.into_inner()) = Some(clip);
                        }
                    }
                }
                Some(DataChannelEvent::OnClose) | None => {
                    open.store(false, Ordering::Relaxed);
                    break;
                }
                _ => {}
            }
        }
    });
}

fn watch_cursor(
    channel: Arc<dyn DataChannel>,
    slot: Arc<Mutex<Option<LiveCursor>>>,
    stop: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match channel.poll().await {
                Some(DataChannelEvent::OnMessage(message)) => {
                    if let Ok(value) = serde_json::from_slice::<Value>(&message.data) {
                        let bitmap_w = value
                            .get("bitmap_w")
                            .and_then(|item| item.as_u64())
                            .unwrap_or(0) as u32;
                        let bitmap_h = value
                            .get("bitmap_h")
                            .and_then(|item| item.as_u64())
                            .unwrap_or(0) as u32;
                        let bitmap_rgba = value
                            .get("bitmap_rgba_b64")
                            .and_then(|item| item.as_str())
                            .and_then(|b64| {
                                use base64::Engine;
                                let bytes =
                                    base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
                                let need = (bitmap_w as usize)
                                    .checked_mul(bitmap_h as usize)?
                                    .checked_mul(4)?;
                                if bitmap_w == 0 || bitmap_h == 0 || bytes.len() < need {
                                    return None;
                                }
                                Some(bytes[..need].to_vec())
                            });
                        let cursor = LiveCursor {
                            x: json_i32(&value, "x"),
                            y: json_i32(&value, "y"),
                            shape: value
                                .get("shape")
                                .and_then(|item| item.as_str())
                                .unwrap_or("unknown")
                                .to_string(),
                            // Missing visible ⇒ assume shown (old nodes).
                            visible: value
                                .get("visible")
                                .and_then(|item| item.as_bool())
                                .unwrap_or(true),
                            hotspot_x: value
                                .get("hotspot_x")
                                .and_then(|item| item.as_u64())
                                .unwrap_or(0) as u16,
                            hotspot_y: value
                                .get("hotspot_y")
                                .and_then(|item| item.as_u64())
                                .unwrap_or(0) as u16,
                            bitmap_w,
                            bitmap_h,
                            bitmap_rgba,
                        };
                        *slot.lock().unwrap_or_else(|err| err.into_inner()) = Some(cursor);
                    }
                }
                Some(DataChannelEvent::OnClose) | None => break,
                _ => {}
            }
        }
    });
}

fn watch_meta(
    channel: Arc<dyn DataChannel>,
    captured: Arc<AtomicI64>,
    stats: Arc<Mutex<LiveStats>>,
    stop: Arc<AtomicBool>,
) {
    tokio::spawn(async move {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match channel.poll().await {
                Some(DataChannelEvent::OnMessage(message)) => {
                    if let Ok(value) = serde_json::from_slice::<Value>(&message.data) {
                        let stamp = value.get("t").and_then(|item| item.as_i64()).unwrap_or(0);
                        if stamp > 0 {
                            captured.store(stamp, Ordering::Relaxed);
                            let now = unix_ms();
                            if let Ok(mut stats) = stats.lock() {
                                stats.latency_ms = (now - stamp).max(0);
                            }
                        }
                    }
                }
                Some(DataChannelEvent::OnClose) | None => break,
                _ => {}
            }
        }
    });
}

struct ViewHandler {
    gather_done: Arc<AtomicBool>,
    ice_tx: UnboundedSender<Value>,
    frames: Arc<FrameBus>,
    loss: Arc<Mutex<LossWindow>>,
    failed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    captured: Arc<AtomicI64>,
    /// Set when ICE/DTLS leave the connected state so drive can ice_restart fast.
    disconnected_at_ms: Arc<AtomicI64>,
}

#[async_trait::async_trait]
impl PeerConnectionEventHandler for ViewHandler {
    async fn on_ice_candidate(&self, event: RTCPeerConnectionIceEvent) {
        if let Ok(init) = event.candidate.to_json() {
            if let Ok(value) = serde_json::to_value(&init) {
                let _ = self.ice_tx.send(value);
            }
        }
    }

    async fn on_ice_gathering_state_change(&self, state: RTCIceGatheringState) {
        if state == RTCIceGatheringState::Complete {
            self.gather_done.store(true, Ordering::Relaxed);
        }
    }

    async fn on_connection_state_change(&self, state: RTCPeerConnectionState) {
        eprintln!("agentlink live-webrtc: peer connection state={state:?}");
        if self.stop.load(Ordering::Relaxed) {
            return;
        }
        match state {
            RTCPeerConnectionState::Connected => {
                self.disconnected_at_ms.store(0, Ordering::Relaxed);
            }
            RTCPeerConnectionState::Disconnected => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                let _ = self.disconnected_at_ms.compare_exchange(
                    0,
                    now,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            RTCPeerConnectionState::Failed | RTCPeerConnectionState::Closed => {
                self.failed.store(true, Ordering::Relaxed);
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map(|d| d.as_millis() as i64)
                    .unwrap_or(0);
                let _ = self.disconnected_at_ms.compare_exchange(
                    0,
                    now,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                );
            }
            _ => {}
        }
    }

    async fn on_track(&self, track: Arc<dyn TrackRemote>) {
        let frames = self.frames.clone();
        let loss = self.loss.clone();
        let stop = self.stop.clone();
        let captured = self.captured.clone();
        tokio::spawn(async move {
            let mut depay = H264Depacketizer::new();
            while !stop.load(Ordering::Relaxed) {
                match track.poll().await {
                    Some(TrackRemoteEvent::OnRtpPacket(packet)) => {
                        loss.lock()
                            .unwrap_or_else(|err| err.into_inner())
                            .observe(packet.header.sequence_number);
                        if let Some(AccessUnit { bytes, keyframe }) =
                            depay.push(&packet.payload, packet.header.marker)
                        {
                            frames.push(Queued {
                                bytes,
                                keyframe,
                                captured_unix_ms: captured.load(Ordering::Relaxed),
                            });
                        }
                    }
                    Some(TrackRemoteEvent::OnEnded) | None => break,
                    _ => {}
                }
            }
        });
    }
}

#[async_trait::async_trait]
trait LivePeer: Send + Sync {
    async fn close(&self);
    async fn create_ice_restart_offer(&self) -> Result<String, String>;
    async fn local_sdp(&self) -> Option<String>;
    async fn apply_remote_answer(&self, sdp: &str) -> Result<(), String>;
    async fn add_ice_candidate(&self, candidate: RTCIceCandidateInit) -> Result<(), String>;
    async fn selected_ice_pair(&self) -> Option<(String, String, String, String, String)>;
    async fn ice_check_snapshot(&self) -> String;
}

struct OwnedPeer<P> {
    inner: P,
}

#[async_trait::async_trait]
impl<P> LivePeer for OwnedPeer<P>
where
    P: PeerConnection,
{
    async fn close(&self) {
        let _ = PeerConnection::close(&self.inner).await;
    }

    async fn create_ice_restart_offer(&self) -> Result<String, String> {
        let offer = PeerConnection::create_offer(
            &self.inner,
            Some(RTCOfferOptions {
                ice_restart: true,
                ..Default::default()
            }),
        )
        .await
        .map_err(|err| err.to_string())?;
        let sdp = offer.sdp.clone();
        PeerConnection::set_local_description(&self.inner, offer)
            .await
            .map_err(|err| err.to_string())?;
        Ok(sdp)
    }

    async fn local_sdp(&self) -> Option<String> {
        PeerConnection::local_description(&self.inner)
            .await
            .map(|desc| desc.sdp)
    }

    async fn apply_remote_answer(&self, sdp: &str) -> Result<(), String> {
        let sdp = prefer_on_link_hosts_in_sdp(sdp);
        let remote = RTCSessionDescription::answer(sdp).map_err(|err| err.to_string())?;
        PeerConnection::set_remote_description(&self.inner, remote)
            .await
            .map_err(|err| err.to_string())
    }

    async fn add_ice_candidate(&self, candidate: RTCIceCandidateInit) -> Result<(), String> {
        PeerConnection::add_ice_candidate(&self.inner, prefer_remote_ice(candidate))
            .await
            .map_err(|err| err.to_string())
    }

    async fn selected_ice_pair(&self) -> Option<(String, String, String, String, String)> {
        let sctp = PeerConnection::sctp(&self.inner).await?;
        let ice = sctp.transport().ice_transport();
        let pair = ice.get_selected_candidate_pair().await.ok().flatten()?;
        let local = pair.local();
        let remote = pair.remote();
        Some((
            local.typ.to_string(),
            format_candidate_addr(local.address.as_str(), local.port),
            remote.typ.to_string(),
            format_candidate_addr(remote.address.as_str(), remote.port),
            local.protocol.to_string(),
        ))
    }

    async fn ice_check_snapshot(&self) -> String {
        let report =
            PeerConnection::get_stats(&self.inner, Instant::now(), StatsSelector::None).await;
        format_ice_checks(&report)
    }
}

fn format_candidate_addr(address: &str, port: u16) -> String {
    if address.contains(':') && !address.starts_with('[') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

async fn publish_ice_checks(
    peer: &Arc<dyn LivePeer>,
    slot: &Arc<Mutex<String>>,
    last_logged: &mut String,
    force: bool,
) -> bool {
    let snapshot = peer.ice_check_snapshot().await;
    if let Ok(mut guard) = slot.lock() {
        *guard = snapshot.clone();
    }
    if snapshot.is_empty() {
        return false;
    }
    // `force` (close) always logs a final copy. Periodic ticks only log changes.
    if snapshot == *last_logged && !force {
        return false;
    }
    if snapshot == *last_logged && force {
        eprintln!("agentlink live-ice: final {snapshot}");
        return true;
    }
    eprintln!("agentlink live-ice: {snapshot}");
    *last_logged = snapshot;
    true
}

/// When the library only exposes selected-pair stats, a zero request count
/// is not evidence that checks were never sent.
fn ice_check_counts_label(
    pair_count: usize,
    req_sent: u64,
    req_recv: u64,
    resp_sent: u64,
    resp_recv: u64,
) -> String {
    if pair_count == 0 {
        "checks=unavailable-selected-stats-only".into()
    } else {
        format!(
            "req_sent={req_sent} req_recv={req_recv} resp_sent={resp_sent} resp_recv={resp_recv}"
        )
    }
}

fn sdp_ice_ufrag(sdp: &str) -> Option<String> {
    for line in sdp.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("a=ice-ufrag:") {
            let value = trimmed[trimmed.len() - rest.len()..].trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn ice_ufrag_matches(remote_ufrag: Option<&str>, fragment: Option<&str>) -> bool {
    match (remote_ufrag, fragment) {
        (Some(want), Some(got)) if !got.is_empty() => want == got,
        _ => true,
    }
}

/// Bounded request/response pull of candidates gathered after the answer.
/// Old nodes that omit `ice_pull` are skipped once. A single "unknown
/// action" error also stops the loop so a missing handler cannot storm.
async fn pull_late_ice(
    signal: Arc<dyn Signal>,
    session_id: String,
    peer: Arc<dyn LivePeer>,
    stop: Arc<AtomicBool>,
    advertised: bool,
    suppress: bool,
    mut after: u64,
    remote_ufrag: Option<String>,
) {
    if suppress {
        return;
    }
    if !advertised {
        eprintln!("agentlink live-webrtc: late ice pull skipped (node did not advertise ice_pull)");
        return;
    }
    const PULL_MAX: u32 = 10;
    let deadline = Instant::now() + Duration::from_secs(4);
    let mut fails = 0u32;
    let mut empty_after_done = 0u32;
    for n in 0..PULL_MAX {
        if stop.load(Ordering::Relaxed) || Instant::now() >= deadline {
            break;
        }
        if n > 0 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let result = roundtrip(
            &signal,
            json!({
                "action": "ice_pull",
                "session_id": session_id,
                "after": after,
            }),
        )
        .await;
        match result {
            Ok(value) => {
                let candidates = value
                    .get("candidates")
                    .and_then(|v| v.as_array())
                    .cloned()
                    .unwrap_or_default();
                if let Some(next) = value.get("after").and_then(|v| v.as_u64()) {
                    after = next;
                } else {
                    after += candidates.len() as u64;
                }
                let mut added = 0u32;
                for candidate in &candidates {
                    let typ = candidate
                        .get("candidate")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let typ_hint = describe_ice_candidates(typ);
                    match serde_json::from_value::<RTCIceCandidateInit>(candidate.clone()) {
                        Ok(init) => {
                            if !ice_ufrag_matches(
                                remote_ufrag.as_deref(),
                                init.username_fragment.as_deref(),
                            ) {
                                eprintln!(
                                    "agentlink live-webrtc: late ice rejected stale generation ({typ_hint})"
                                );
                                continue;
                            }
                            match peer.add_ice_candidate(init).await {
                                Ok(()) => {
                                    added += 1;
                                    eprintln!("agentlink live-webrtc: late ice added ({typ_hint})");
                                }
                                Err(err) => eprintln!(
                                    "agentlink live-webrtc: late ice add error ({err}) ({typ_hint})"
                                ),
                            }
                        }
                        Err(_) => {
                            eprintln!(
                                "agentlink live-webrtc: late ice parse rejected ({typ_hint})"
                            );
                        }
                    }
                }
                let gather_done = value
                    .get("gather_done")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                eprintln!(
                    "agentlink live-webrtc: late ice pull ok new={} added={added} gather_done={gather_done}", candidates.len()
                );
                if candidates.is_empty() && gather_done {
                    empty_after_done += 1;
                    if empty_after_done >= 2 {
                        break;
                    }
                } else {
                    empty_after_done = 0;
                }
            }
            Err(err) => {
                let lower = err.to_ascii_lowercase();
                if lower.contains("unknown webrtc_signal action")
                    || lower.contains("unknown action")
                {
                    eprintln!(
                        "agentlink live-webrtc: late ice pull not supported by node; using answer candidates only"
                    );
                    return;
                }
                fails += 1;
                eprintln!("agentlink live-webrtc: late ice pull error ({fails}): {err}");
                if fails >= 2 {
                    return;
                }
            }
        }
    }
}

/// Format ICE stats without credentials, username fragments, certificates,
/// or packet payloads. Records typ / raddr / proto / check state / counts.
fn format_ice_checks(report: &RTCStatsReport) -> String {
    let mut role = "-".to_string();
    let mut ice_state = "-".to_string();
    let mut selected = "-".to_string();
    let mut pair_changes = 0u32;
    let mut cands: Vec<(String, String, String, u16, String, String, String, String)> = Vec::new();
    // id -> (dir, typ, addr, port, proto, raddr, url)
    let mut by_id = std::collections::HashMap::<String, String>::new();
    let mut pairs = Vec::new();
    let mut req_sent = 0u64;
    let mut req_recv = 0u64;
    let mut resp_sent = 0u64;
    let mut resp_recv = 0u64;
    let mut nominated = 0u32;
    let mut succeeded = 0u32;
    let mut failed = 0u32;
    let mut in_progress = 0u32;
    let mut waiting = 0u32;
    let mut frozen = 0u32;

    for entry in report.iter() {
        match entry {
            RTCStatsReportEntry::Transport(t) => {
                role = format!("{:?}", t.ice_role).to_ascii_lowercase();
                ice_state = format!("{:?}", t.ice_state).to_ascii_lowercase();
                if !t.selected_candidate_pair_id.is_empty() {
                    selected = t.selected_candidate_pair_id.clone();
                }
                pair_changes = t.selected_candidate_pair_changes;
            }
            RTCStatsReportEntry::LocalCandidate(c) | RTCStatsReportEntry::RemoteCandidate(c) => {
                let dir = if matches!(entry, RTCStatsReportEntry::LocalCandidate(_)) {
                    "local"
                } else {
                    "remote"
                };
                let typ = format!("{:?}", c.candidate_type).to_ascii_lowercase();
                let addr = c.address.clone().unwrap_or_else(|| "-".into());
                let proto = c.protocol.to_ascii_lowercase();
                let raddr = if c.related_address.is_empty() {
                    "-".to_string()
                } else {
                    format!("{}:{}", c.related_address, c.related_port)
                };
                let url = safe_ice_url(&c.url);
                let id = c.stats.id.clone();
                by_id.insert(
                    id.clone(),
                    format!(
                        "{dir} typ={typ} {addr}:{} proto={proto} raddr={raddr}",
                        c.port
                    ),
                );
                cands.push((dir.to_string(), typ, addr, c.port, proto, raddr, url, id));
            }
            RTCStatsReportEntry::IceCandidatePair(p) => {
                req_sent += p.requests_sent;
                req_recv += p.requests_received;
                resp_sent += p.responses_sent;
                resp_recv += p.responses_received;
                if p.nominated {
                    nominated += 1;
                }
                let state = format!("{:?}", p.state).to_ascii_lowercase();
                if state.contains("succeeded") {
                    succeeded += 1;
                } else if state.contains("failed") {
                    failed += 1;
                } else if state.contains("inprogress") || state.contains("in_progress") {
                    in_progress += 1;
                } else if state.contains("waiting") {
                    waiting += 1;
                } else if state.contains("frozen") {
                    frozen += 1;
                }
                pairs.push((
                    p.stats.id.clone(),
                    p.local_candidate_id.clone(),
                    p.remote_candidate_id.clone(),
                    state,
                    p.nominated,
                    p.requests_sent,
                    p.requests_received,
                    p.responses_sent,
                    p.responses_received,
                ));
            }
            _ => {}
        }
    }

    if cands.is_empty() && pairs.is_empty() && ice_state == "-" {
        return String::new();
    }

    let mut out = format!(
        "role={role} ice_state={ice_state} selected={selected} pair_changes={pair_changes} pairs={} succeeded={succeeded} failed={failed} in_progress={in_progress} waiting={waiting} frozen={frozen} nominated={nominated} {}",
        pairs.len(),
        ice_check_counts_label(pairs.len(), req_sent, req_recv, resp_sent, resp_recv)
    );
    for (dir, typ, addr, port, proto, raddr, url, _id) in &cands {
        out.push_str(&format!(
            " | {dir} typ={typ} {addr}:{port} proto={proto} raddr={raddr}"
        ));
        if !url.is_empty() {
            out.push_str(&format!(" url={url}"));
        }
    }
    for (id, local_id, remote_id, state, nom, qs, qr, ps, pr) in &pairs {
        let local = by_id.get(local_id).map(String::as_str).unwrap_or(local_id);
        let remote = by_id
            .get(remote_id)
            .map(String::as_str)
            .unwrap_or(remote_id);
        let mark = if *id == selected { " selected" } else { "" };
        out.push_str(&format!(
            " | pair{mark} state={state} nominated={nom} req_sent={qs} req_recv={qr} resp_sent={ps} resp_recv={pr} local=({local}) remote=({remote})"
        ));
    }
    out
}

fn safe_ice_url(url: &str) -> String {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains('@') || lower.contains("credential") || lower.contains("password") {
        return String::new();
    }
    trimmed.to_string()
}

async fn refresh_transport(
    peer: &Arc<dyn LivePeer>,
    info: &Arc<Mutex<LiveInfo>>,
    transport: &Arc<Mutex<Option<TransportSnapshot>>>,
) {
    let Some((local_typ, local_addr, remote_typ, remote_addr, protocol)) =
        peer.selected_ice_pair().await
    else {
        return;
    };
    let inventory = info
        .lock()
        .unwrap_or_else(|err| err.into_inner())
        .sdp_inventory
        .clone();
    let local_ip = strip_port(&local_addr);
    let remote_ip = strip_port(&remote_addr);
    let path = classify_selected_path(&local_typ, &remote_typ, local_ip, remote_ip).to_string();
    let note = selected_pair_note(&path, local_ip, remote_ip);
    let snap = TransportSnapshot {
        path: path.clone(),
        local_typ,
        remote_typ,
        local_addr,
        remote_addr,
        protocol,
        sdp_inventory: inventory,
        note: note.clone(),
    };
    let changed = transport
        .lock()
        .ok()
        .and_then(|slot| {
            slot.as_ref().map(|prev| {
                prev.path != snap.path
                    || prev.local_addr != snap.local_addr
                    || prev.remote_addr != snap.remote_addr
                    || prev.local_typ != snap.local_typ
                    || prev.remote_typ != snap.remote_typ
            })
        })
        .unwrap_or(true);
    if changed {
        eprintln!(
            "agentlink live-path: path={} local={} {} remote={} {} proto={} inventory={} note={}",
            snap.path,
            snap.local_typ,
            snap.local_addr,
            snap.remote_typ,
            snap.remote_addr,
            snap.protocol,
            snap.sdp_inventory,
            snap.note
        );
    }
    if let Ok(mut slot) = info.lock() {
        slot.path = path;
    }
    if let Ok(mut slot) = transport.lock() {
        *slot = Some(snap);
    }
}

fn strip_port(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    if addr.chars().filter(|c| *c == ':').count() == 1 {
        return addr.rsplit_once(':').map(|(h, _)| h).unwrap_or(addr);
    }
    addr
}

fn selected_pair_note(path: &str, local_ip: &str, remote_ip: &str) -> String {
    let hint = media_path_hint("h264", path);
    if let Some(reason) = detect_tailscale_reason(local_ip, remote_ip) {
        return format!("{hint} ({reason})");
    }
    let scopes = [addr_scope(local_ip), addr_scope(remote_ip)];
    let extra = if scopes.contains(&AddrScope::Loopback) {
        "loopback addresses; same host only"
    } else if scopes.contains(&AddrScope::Cgnat) {
        "100.64.0.0/10 is RFC 6598 CGNAT, not a Tailscale confirmation"
    } else if scopes.contains(&AddrScope::Private) {
        "private addresses may be LAN, VPN, or routed"
    } else if scopes.contains(&AddrScope::Public) {
        "public typ host is not a public-NAT-success claim"
    } else {
        ""
    };
    if extra.is_empty() {
        hint.to_string()
    } else {
        format!("{hint} ({extra})")
    }
}

fn h264_codec() -> RTCRtpCodecParameters {
    RTCRtpCodecParameters {
        rtp_codec: RTCRtpCodec {
            mime_type: "video/H264".into(),
            clock_rate: 90000,
            channels: 0,
            sdp_fmtp_line: "level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f"
                .into(),
            rtcp_feedback: Vec::new(),
        },
        payload_type: 102,
    }
}

/// ICE servers from the caller, or `AGENTLINK_STUN_URLS` when the caller
/// passed none. Unset uses the public STUN defaults. The same list goes in
/// the offer so the node gathers against it.
fn offer_servers(servers: &[Value]) -> Vec<Value> {
    if !servers.is_empty() {
        return servers.to_vec();
    }
    let urls = agentlink_core::stun_urls_ready_for_ice();
    if urls.is_empty() {
        Vec::new()
    } else {
        vec![json!({ "urls": urls })]
    }
}

fn rtc_ice(servers: &[Value]) -> Vec<RTCIceServer> {
    let mut out = Vec::new();
    for entry in servers {
        let urls = entry
            .get("urls")
            .and_then(|value| value.as_array())
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str())
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if urls.is_empty() {
            continue;
        }
        out.push(RTCIceServer {
            urls,
            username: entry
                .get("username")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string(),
            credential: entry
                .get("credential")
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_string(),
        });
    }
    out
}

async fn roundtrip(signal: &Arc<dyn Signal>, payload: Value) -> Result<Value, String> {
    let signal = Arc::clone(signal);
    tokio::task::spawn_blocking(move || signal.signal(&payload))
        .await
        .map_err(|err| err.to_string())?
}

fn unknown_action(err: &str) -> bool {
    err.contains("unknown webrtc_signal action")
}

fn brief(value: &Value) -> String {
    let text = value.to_string();
    if text.len() > 180 {
        format!("{}…", &text[..180])
    } else {
        text
    }
}

fn json_u32(value: &Value, key: &str) -> u32 {
    value
        .get(key)
        .and_then(|item| item.as_u64())
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32
}

fn json_i32(value: &Value, key: &str) -> i32 {
    value
        .get(key)
        .and_then(|item| {
            item.as_i64()
                .or_else(|| item.as_f64().map(|number| number as i64))
        })
        .unwrap_or(0) as i32
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Script {
        seen: Mutex<Option<Value>>,
    }

    impl Signal for Script {
        fn signal(&self, payload: &Value) -> Result<Value, String> {
            match payload.get("action").and_then(|value| value.as_str()) {
                Some("list_monitors") => Ok(json!({"monitors": []})),
                Some("offer") => {
                    *self.seen.lock().unwrap() = Some(payload.clone());
                    Err("stop after offer".into())
                }
                other => Err(format!("unexpected {other:?}")),
            }
        }
    }

    #[test]
    fn empty_offer_uses_the_process_stun_list() {
        let servers = super::offer_servers(&[]);
        let expected = agentlink_core::stun_urls_ready_for_ice();
        if expected.is_empty() {
            assert!(servers.is_empty());
        } else {
            let urls = servers[0]["urls"].as_array().unwrap();
            assert_eq!(urls.len(), expected.len());
            assert_eq!(urls[0], expected[0]);
        }
        let custom = super::offer_servers(&[json!({"urls": ["stun:turn.example:3478"]})]);
        assert_eq!(custom[0]["urls"][0], "stun:turn.example:3478");
    }

    #[test]
    fn offer_sdp_is_recvonly_h264() {
        let script = Arc::new(Script {
            seen: Mutex::new(None),
        });
        let err = match Viewer::connect(script.clone(), LiveOptions::default()) {
            Err(err) => err,
            Ok(_) => panic!("offer should stop before a session exists"),
        };
        assert!(err.contains("stop after offer"), "{err}");
        let payload = script.seen.lock().unwrap().clone().expect("offer");
        assert_eq!(payload["codec"], "h264");
        assert_eq!(payload["max_fps"], 30);
        assert_eq!(payload["bitrate"], 2_000_000);
        assert_eq!(payload["audio"], false);
        let sdp = payload["sdp"].as_str().unwrap().to_ascii_lowercase();
        assert!(sdp.contains("h264"), "{sdp}");
        assert!(sdp.contains("recvonly"), "{sdp}");
        assert!(sdp.contains("m=video"), "{sdp}");
        assert!(sdp.contains("m=application"), "{sdp}");
    }

    fn test_viewer(cmd_cap: usize) -> (Viewer, mpsc::Receiver<Cmd>) {
        let (cmd, rx) = mpsc::channel(cmd_cap);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("agentlink-view-test")
            .build()
            .expect("test viewer runtime");
        let viewer = Viewer {
            cmd,
            frames: Arc::new(FrameBus::new(1)),
            info: Arc::new(Mutex::new(LiveInfo {
                session_id: "test".into(),
                codec: "h264".into(),
                encoder: "test".into(),
                hardware: false,
                width: 1,
                height: 1,
                src_width: 1,
                src_height: 1,
                control: false,
                path: "relay".into(),
                sdp_inventory: String::new(),
                cursor_presentation: "legacy".into(),
            })),
            transport: Arc::new(Mutex::new(None)),
            cursor: Arc::new(Mutex::new(None)),
            clipboard: Arc::new(Mutex::new(None)),
            stats: Arc::new(Mutex::new(LiveStats::default())),
            ice_checks: Arc::new(Mutex::new(String::new())),
            input_open: Arc::new(AtomicBool::new(false)),
            failed: Arc::new(AtomicBool::new(false)),
            stop: Arc::new(AtomicBool::new(false)),
            stopped: Arc::new(AtomicBool::new(false)),
            close_notify: Arc::new(tokio::sync::Notify::new()),
            closed: AtomicBool::new(false),
            runtime: Mutex::new(Some(runtime)),
        };
        (viewer, rx)
    }

    #[test]
    fn parse_clipboard_set_requires_type_and_text() {
        assert!(parse_clipboard_set(&serde_json::json!({"type": "error", "text": "x"})).is_none());
        assert!(parse_clipboard_set(&serde_json::json!({"type": "clipboard"})).is_none());
        let clip = parse_clipboard_set(&serde_json::json!({
            "type": "clipboard",
            "text": "hello",
            "chars": 5
        }))
        .expect("set");
        assert_eq!(clip.text, "hello");
        assert!(!clip.truncated);
    }

    #[test]
    fn poll_clipboard_is_consumed_once() {
        let (viewer, _rx) = test_viewer(1);
        assert!(viewer.poll_clipboard().is_none());
        *viewer.clipboard.lock().expect("clipboard") = Some(LiveClipboard {
            text: "from-node".into(),
            truncated: false,
        });
        let first = viewer.poll_clipboard().expect("payload");
        assert_eq!(first.text, "from-node");
        assert!(viewer.poll_clipboard().is_none());
        viewer.close();
        assert!(viewer.is_closed());
    }

    /// 0111/0133: `Viewer::close` used `blocking_send` at session.rs:214
    /// and panicked on `agentlink-controller-net` when `Cmd::PtyOpen`
    /// called `stop_live`. These tests run close/drop inside a tokio
    /// runtime so a green suite cannot hide that panic.
    #[test]
    fn close_from_inside_a_tokio_runtime_does_not_panic() {
        let (viewer, mut rx) = test_viewer(4);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async {
            viewer.close();
            assert!(viewer.stop.load(Ordering::Relaxed));
            match rx.try_recv() {
                Ok(Cmd::Close) => {}
                other => panic!("expected Close, got {other:?}"),
            }
        });
    }

    #[test]
    fn drop_from_inside_a_tokio_runtime_does_not_panic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("current-thread runtime");
        runtime.block_on(async {
            let (viewer, _rx) = test_viewer(1);
            drop(viewer);
        });
    }

    #[test]
    fn close_then_drop_on_the_controller_net_runtime_does_not_panic() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("agentlink-controller-net")
            .build()
            .expect("controller-net runtime");
        runtime.block_on(async {
            let (viewer, mut rx) = test_viewer(1);
            // Saturate the bounded command queue the way input events would.
            assert!(viewer.cmd.try_send(Cmd::Control("{}".into())).is_ok());
            viewer.close();
            assert!(viewer.stop.load(Ordering::Relaxed));
            let first = rx.try_recv().ok();
            assert!(matches!(first, Some(Cmd::Control(_))), "{first:?}");
            drop(viewer);
        });
        runtime.shutdown_timeout(Duration::from_secs(2));
    }

    /// Mirrors the worker path: stop_live (Viewer::close/drop) then open a
    /// PTY and close it, all on agentlink-controller-net. This is not a
    /// GUI test and does not cover every Quit/X path.
    #[test]
    fn stop_live_then_open_pty_on_controller_net_does_not_panic() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .thread_name("agentlink-controller-net")
            .build()
            .expect("controller-net runtime");
        runtime.block_on(async {
            let (viewer, _rx) = test_viewer(1);
            viewer.close();
            drop(viewer);
            let first = agentlink_core::client::PtySession::test_io();
            let _ = first.session.close().await;
            let second = agentlink_core::client::PtySession::test_io();
            let _ = second.session.close().await;
        });
        runtime.shutdown_timeout(Duration::from_secs(2));
    }

    /// Off the GUI/net runtime, `close` waits for drive to set `stopped`
    /// (up to 2s) and `drop` shuts down the viewer runtime (up to 2s).
    /// A simulated drive that exits on `Cmd::Close` must finish well
    /// inside those deadlines and leave no runtime in the viewer.
    #[test]
    fn close_off_runtime_finishes_within_deadline_and_releases_runtime() {
        let (viewer, mut rx) = test_viewer(4);
        let stopped = Arc::clone(&viewer.stopped);
        let drive = std::thread::Builder::new()
            .name("t449-sim-drive".into())
            .spawn(move || {
                let _ = rx.blocking_recv();
                stopped.store(true, Ordering::Relaxed);
            })
            .expect("sim drive");
        let started = Instant::now();
        viewer.close();
        let close_wait = started.elapsed();
        assert!(
            close_wait < Duration::from_secs(2),
            "close must return before the 2s wait when drive exits, got {close_wait:?}"
        );
        assert!(viewer.stop.load(Ordering::Relaxed));
        assert!(viewer.stopped.load(Ordering::Relaxed));
        let started = Instant::now();
        drop(viewer);
        let drop_wait = started.elapsed();
        assert!(
            drop_wait < Duration::from_secs(3),
            "runtime shutdown_timeout is 2s; drop must finish, got {drop_wait:?}"
        );
        drive.join().expect("sim drive join");
    }

    #[test]
    fn strip_sdp_ice_candidates_keeps_ufrag_and_drops_candidates() {
        let sdp = "v=0\r\nm=video 9 UDP/TLS/RTP/SAVPF 96\r\na=candidate:1 1 udp 2130706431 192.0.2.1 9 typ host\r\na=ice-ufrag:abc\r\n";
        let out = super::strip_sdp_ice_candidates(sdp);
        assert!(!out.to_ascii_lowercase().contains("a=candidate"), "{out}");
        assert!(out.contains("a=ice-ufrag:abc"), "{out}");
        assert!(out.contains("m=video"), "{out}");
    }

    #[test]
    fn ice_check_counts_label_does_not_claim_zero_means_unsent() {
        assert_eq!(
            super::ice_check_counts_label(0, 0, 0, 0, 0),
            "checks=unavailable-selected-stats-only"
        );
        assert_eq!(
            super::ice_check_counts_label(1, 4, 8, 8, 6),
            "req_sent=4 req_recv=8 resp_sent=8 resp_recv=6"
        );
        assert_ne!(
            super::ice_check_counts_label(0, 0, 0, 0, 0),
            "req_sent=0 req_recv=0 resp_sent=0 resp_recv=0"
        );
    }

    #[test]
    fn ice_ufrag_matches_admits_empty_fragment_and_rejects_stale() {
        assert!(super::ice_ufrag_matches(Some("genA"), None));
        assert!(super::ice_ufrag_matches(Some("genA"), Some("genA")));
        assert!(!super::ice_ufrag_matches(Some("genA"), Some("genB")));
    }
}
