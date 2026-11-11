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
    RTCPeerConnectionIceEvent, RTCPeerConnectionState, RTCSessionDescription, Registry,
};
use webrtc::runtime::default_runtime;

use crate::h264::{
    feedback_ratio, is_screenshot_fallback, AccessUnit, H264Depacketizer, LossWindow,
};
use crate::queue::{FrameBus, Queued};

const GATHER_WAIT: Duration = Duration::from_millis(1500);

#[derive(Clone, Debug)]
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
        }
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
    pub control: bool,
    /// `host`, `stun`, `turn`, `quic`, or `relay`.
    pub path: String,
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
    info: LiveInfo,
    cursor: Arc<Mutex<Option<LiveCursor>>>,
    stats: Arc<Mutex<LiveStats>>,
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
            cursor: built.cursor,
            stats: built.stats,
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
        self.info.clone()
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
            width: self.info.width,
            height: self.info.height,
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
            width: self.info.width,
            height: self.info.height,
        })
    }

    pub fn poll_cursor(&self) -> Option<LiveCursor> {
        self.cursor
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    pub fn stats(&self) -> LiveStats {
        self.stats
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    pub fn send_control(&self, json: &str) -> bool {
        if !self.input_open.load(Ordering::Relaxed) {
            return false;
        }
        self.cmd.try_send(Cmd::Control(json.to_string())).is_ok()
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
    info: LiveInfo,
    cursor: Arc<Mutex<Option<LiveCursor>>>,
    stats: Arc<Mutex<LiveStats>>,
    input_open: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    stopped: Arc<AtomicBool>,
    close_notify: Arc<tokio::sync::Notify>,
    closed: AtomicBool,
}

async fn connect_inner(signal: Arc<dyn Signal>, opts: LiveOptions) -> Result<Built, String> {
    match roundtrip(&signal, json!({"action": "list_monitors"})).await {
        Ok(value) if is_screenshot_fallback(&value) => {
            return Err("live video is not available; fallback screenshot".into());
        }
        Ok(_) => {}
        Err(err) if unknown_action(&err) => {}
        Err(err) => return Err(err),
    }

    let (fps, bitrate) = crate::h264::clamp_offer(opts.max_fps, opts.bitrate);
    let ice_servers = offer_servers(&opts.ice_servers);
    let frames = Arc::new(FrameBus::new(3));
    let loss = Arc::new(Mutex::new(LossWindow::default()));
    let stats = Arc::new(Mutex::new(LiveStats::default()));
    let cursor = Arc::new(Mutex::new(None));
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

    let runtime =
        default_runtime().ok_or_else(|| "tokio runtime is required for WebRTC".to_string())?;
    let mut media = MediaEngine::default();
    media
        .register_codec(h264_codec(), RtpCodecKind::Video)
        .map_err(|err| err.to_string())?;
    let registry = register_default_interceptors(Registry::new(), &mut media)
        .map_err(|err| err.to_string())?;
    let pc = PeerConnectionBuilder::new()
        .with_configuration(
            RTCConfigurationBuilder::new()
                .with_ice_servers(rtc_ice(&ice_servers))
                .build(),
        )
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
    watch_input(input, input_open.clone(), stop.clone());
    watch_cursor(cursor_ch, cursor.clone(), stop.clone());
    watch_meta(meta_ch, captured.clone(), stats.clone(), stop.clone());

    let init = RTCRtpTransceiverInit {
        direction: RTCRtpTransceiverDirection::Recvonly,
        ..Default::default()
    };
    PeerConnection::add_transceiver_from_kind(&pc, RtpCodecKind::Video, Some(init))
        .await
        .map_err(|err| err.to_string())?;

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

    let answer = roundtrip(
        &signal,
        json!({
            "action": "offer",
            "sdp": local.sdp,
            "viewer": opts.viewer,
            "monitor": opts.monitor,
            "codec": "h264",
            "max_fps": fps,
            "bitrate": bitrate,
            "scale": opts.scale.clamp(0.05, 1.0),
            "audio": false,
            "ice_servers": ice_servers,
            "_allow_control": opts.control,
        }),
    )
    .await?;
    if is_screenshot_fallback(&answer) {
        let _ = PeerConnection::close(&pc).await;
        return Err("live video is not available; fallback screenshot".into());
    }
    let session_id = answer
        .get("session_id")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    let sdp = answer
        .get("sdp")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    if session_id.is_empty() || sdp.is_empty() {
        let _ = PeerConnection::close(&pc).await;
        return Err(format!(
            "offer did not return a session: {}",
            brief(&answer)
        ));
    }
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
        control: answer
            .get("control")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        path: crate::h264::classify_media_path(&sdp).to_string(),
    };

    let remote = RTCSessionDescription::answer(sdp).map_err(|err| err.to_string())?;
    PeerConnection::set_remote_description(&pc, remote)
        .await
        .map_err(|err| err.to_string())?;
    if let Some(candidates) = answer.get("candidates").and_then(|value| value.as_array()) {
        for candidate in candidates {
            if let Ok(init) = serde_json::from_value::<RTCIceCandidateInit>(candidate.clone()) {
                let _ = PeerConnection::add_ice_candidate(&pc, init).await;
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
        )
        .await;
    });

    let signal_ice = signal.clone();
    let session_ice = session_id.clone();
    let stop_ice = stop.clone();
    tokio::spawn(async move {
        while let Some(candidate) = ice_rx.recv().await {
            if stop_ice.load(Ordering::Relaxed) {
                break;
            }
            let _ = roundtrip(
                &signal_ice,
                json!({
                    "action": "ice",
                    "session_id": session_ice,
                    "candidate": candidate,
                }),
            )
            .await;
        }
    });

    let _ = roundtrip(
        &signal,
        json!({"action": "keyframe", "session_id": session_id}),
    )
    .await;

    Ok(Built {
        cmd: cmd_tx,
        frames,
        info,
        cursor,
        stats,
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
    _failed: Arc<AtomicBool>,
    gather_done: Arc<AtomicBool>,
    disconnected_at_ms: Arc<AtomicI64>,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.tick().await;
    let mut last_ice_restart = Instant::now() - Duration::from_secs(30);
    loop {
        if stop.load(Ordering::Relaxed) {
            stop.store(true, Ordering::Relaxed);
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
                // ICE/DTLS left Connected: restart within 1s (throttle 5s).
                let disc = disconnected_at_ms.load(Ordering::Relaxed);
                if disc > 0 {
                    let now_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as i64)
                        .unwrap_or(0);
                    if now_ms.saturating_sub(disc) >= 1000
                        && last_ice_restart.elapsed() >= Duration::from_secs(5)
                    {
                        if ice_restart(&peer, &signal, &session_id, &gather_done)
                            .await
                            .is_ok()
                        {
                            last_ice_restart = Instant::now();
                            disconnected_at_ms.store(0, Ordering::Relaxed);
                            ask_keyframe(&signal, &session_id, &input, &input_open).await;
                        }
                    }
                }
            }
        }
    }
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
                let _ = peer.add_ice_candidate(init).await;
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

fn watch_input(channel: Arc<dyn DataChannel>, open: Arc<AtomicBool>, stop: Arc<AtomicBool>) {
    tokio::spawn(async move {
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match channel.poll().await {
                Some(DataChannelEvent::OnOpen) => open.store(true, Ordering::Relaxed),
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
                        let cursor = LiveCursor {
                            x: json_i32(&value, "x"),
                            y: json_i32(&value, "y"),
                            shape: value
                                .get("shape")
                                .and_then(|item| item.as_str())
                                .unwrap_or("arrow")
                                .to_string(),
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
        let remote =
            RTCSessionDescription::answer(sdp.to_string()).map_err(|err| err.to_string())?;
        PeerConnection::set_remote_description(&self.inner, remote)
            .await
            .map_err(|err| err.to_string())
    }

    async fn add_ice_candidate(&self, candidate: RTCIceCandidateInit) -> Result<(), String> {
        PeerConnection::add_ice_candidate(&self.inner, candidate)
            .await
            .map_err(|err| err.to_string())
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
    let urls = agentlink_core::stun_urls_from_env();
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
        let expected = agentlink_core::stun_urls_from_env();
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
            info: LiveInfo {
                session_id: "test".into(),
                codec: "h264".into(),
                encoder: "test".into(),
                hardware: false,
                width: 1,
                height: 1,
                control: false,
                path: "relay".into(),
            },
            cursor: Arc::new(Mutex::new(None)),
            stats: Arc::new(Mutex::new(LiveStats::default())),
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
}
