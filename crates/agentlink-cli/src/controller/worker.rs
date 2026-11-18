//! Account, shell, files, and desktop session on one client runtime.
//!
//! Signaling uses [`agentlink_view::Viewer`], the same offerer the Android
//! app uses. The window thread only receives events and pictures.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentlink_core::client::{login_user, maintain_session_skew};
use agentlink_core::{
    apply_relay_defaults, parse_access, Client, ClientSettings, DirEntry, Identity, NodeInfo, Op,
    PtyEvent, PtySession, RelayTrust, PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT, PHASE3_WEBRTC_SIGNAL,
};
use agentlink_view::{is_screenshot_fallback, IceFault, LiveOptions, Signal, Viewer};
use base64::Engine;
use serde_json::{json, Value};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::decode::{decode_image, H264Decoder};
use super::diagnostics::{self, DiagEvent};
use super::model::enroll_command;

fn identity_fp_for(config_dir: &std::path::Path) -> Option<String> {
    Identity::load(&config_dir.join("identity.json"))
        .ok()
        .map(|id| diagnostics::identity_fingerprint(id.public_hex()))
}

fn diag_client(
    config_dir: &std::path::Path,
    stage: &'static str,
    cmd: Option<&'static str>,
    client: Option<&Client>,
    rebootstrap: Option<bool>,
) {
    diag_with_closure(
        config_dir,
        stage,
        cmd,
        client,
        client.map(Client::transport_status),
        rebootstrap,
    );
}

fn diag_with_closure(
    config_dir: &std::path::Path,
    stage: &'static str,
    cmd: Option<&'static str>,
    client: Option<&Client>,
    closure: Option<agentlink_core::TransportStatus>,
    rebootstrap: Option<bool>,
) {
    diagnostics::emit_lossy(DiagEvent {
        stage,
        cmd,
        config_dir: config_dir.to_path_buf(),
        identity_fp: identity_fp_for(config_dir),
        client_alive: client.map(Client::is_alive),
        closure,
        rebootstrap,
    });
}

/// Persist first transport closure as it happens (idle GUI / crash before next
/// Cmd). Sink must not run under the core observer mutex (core guarantees that).
fn attach_closure_sink(client: &Client, config_dir: &std::path::Path) {
    let config_dir = config_dir.to_path_buf();
    let identity_fp = identity_fp_for(&config_dir);
    client.set_transport_sink(Some(std::sync::Arc::new(move |status| {
        if status.category == agentlink_core::ClosureCategory::None {
            return;
        }
        diagnostics::emit_lossy(DiagEvent {
            stage: "first_closure",
            cmd: None,
            config_dir: config_dir.clone(),
            identity_fp: identity_fp.clone(),
            client_alive: Some(false),
            closure: Some(status),
            rebootstrap: None,
        });
    })));
}

#[derive(Clone, Debug)]
pub struct Picture {
    pub rgba: Vec<u8>,
    pub width: usize,
    pub height: usize,
    pub kind: String,
    pub path: String,
    pub seq: u64,
}

#[derive(Clone, Debug)]
pub struct MonitorEntry {
    pub index: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
    /// Absent on old nodes → treat as capturable.
    pub capturable: Option<bool>,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct LiveHud {
    pub path: String,
    pub kind: String,
    pub width: u32,
    pub height: u32,
    pub latency_ms: i64,
    pub fps: f32,
    pub bitrate_kbps: u32,
    pub encoder: String,
    pub hardware: bool,
    pub frames_dropped: u64,
    /// Human-readable path explanation (not a candidate inventory).
    pub path_note: String,
    /// WebRTC handshake / negotiation stage. Independent of the painted media path.
    pub handshake: String,
    /// Negotiated cursor presentation (`legacy` default / `metadata`).
    pub cursor_presentation: String,
    /// True content height before encode pad (0 ⇒ use `height`).
    pub src_width: u32,
    pub src_height: u32,
}

/// Latest remote cursor sprite metadata from the `cursor` data channel.
#[derive(Clone, Debug, Default)]
pub struct DeskCursor {
    pub shape: String,
    pub visible: bool,
    pub hotspot_x: u16,
    pub hotspot_y: u16,
    pub bitmap_w: u32,
    pub bitmap_h: u32,
    pub bitmap_rgba: Option<Vec<u8>>,
}

/// Sliding client-side timing samples (microseconds / counts) for `--perf-log` and debug `state`.
#[derive(Default)]
pub struct ClientPerf {
    pub decode_us_ema: AtomicU64,
    pub present_us_ema: AtomicU64,
    pub recv_gap_us_ema: AtomicU64,
    pub recv_gap_p95_us: AtomicU64,
    pub fps_window_x100: AtomicU64,
    pub input_rtt_us_ema: AtomicU64,
    pub stalls: AtomicU64,
    pub frames: AtomicU64,
    /// Last mouse-move send unix ms for approximate input RTT.
    pub last_move_unix_ms: AtomicI64,
}

impl ClientPerf {
    pub fn note_decode_us(&self, us: u64) {
        update_ema(&self.decode_us_ema, us);
    }

    pub fn note_present_us(&self, us: u64) {
        update_ema(&self.present_us_ema, us);
    }

    pub fn note_recv_gap_us(&self, us: u64) {
        update_ema(&self.recv_gap_us_ema, us);
        // Cheap p95 proxy: keep the max of recent samples decaying toward EMA.
        let prev = self.recv_gap_p95_us.load(Ordering::Relaxed);
        let next = if us > prev {
            us
        } else {
            prev - (prev >> 4) + (us >> 4)
        };
        self.recv_gap_p95_us.store(next, Ordering::Relaxed);
    }

    pub fn note_fps(&self, fps: f32) {
        self.fps_window_x100
            .store((fps * 100.0).round().max(0.0) as u64, Ordering::Relaxed);
    }

    pub fn note_input_rtt_us(&self, us: u64) {
        update_ema(&self.input_rtt_us_ema, us);
    }

    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "recv_gap_p95_ms": self.recv_gap_p95_us.load(Ordering::Relaxed) as f64 / 1000.0,
            "decode_ms": self.decode_us_ema.load(Ordering::Relaxed) as f64 / 1000.0,
            "present_ms": self.present_us_ema.load(Ordering::Relaxed) as f64 / 1000.0,
            "fps_window": self.fps_window_x100.load(Ordering::Relaxed) as f64 / 100.0,
            "input_rtt_ms": self.input_rtt_us_ema.load(Ordering::Relaxed) as f64 / 1000.0,
            "stalls": self.stalls.load(Ordering::Relaxed),
            "frames": self.frames.load(Ordering::Relaxed),
        })
    }
}

fn update_ema(slot: &AtomicU64, sample: u64) {
    let prev = slot.load(Ordering::Relaxed);
    let next = if prev == 0 {
        sample
    } else {
        prev - (prev >> 3) + (sample >> 3)
    };
    slot.store(next, Ordering::Relaxed);
}

pub enum UiEvent {
    Ready {
        user: Option<String>,
    },
    Nodes(Vec<NodeInfo>),
    Failed(String),
    TotpRequired(String),
    Notice(String),
    Pty(Vec<u8>),
    PtyDone,
    Dir {
        path: String,
        entries: Vec<DirEntry>,
    },
    File {
        path: String,
        text: String,
    },
    Enrolled(String),
    Link(String),
    Pins(Vec<String>),
    Monitors(Vec<MonitorEntry>),
    Hud(LiveHud),
    /// Handshake/negotiation stage only; must not change the painted media path.
    Handshake(String),
}

pub enum Cmd {
    Bootstrap,
    Login {
        username: String,
        password: String,
        totp: String,
        relay: String,
        pin: String,
        trust: String,
    },
    Logout,
    Refresh,
    PtyOpen {
        node: String,
        rows: u16,
        cols: u16,
    },
    PtyWrite {
        data: Vec<u8>,
    },
    PtyResize {
        rows: u16,
        cols: u16,
    },
    PtyClose,
    List {
        node: String,
        path: String,
    },
    Read {
        node: String,
        path: String,
    },
    Write {
        node: String,
        path: String,
        text: String,
    },
    Mkdir {
        node: String,
        path: String,
    },
    Remove {
        node: String,
        path: String,
    },
    /// Start or restart a live session. Offer carries `monitor`; `quality`
    /// maps to bitrate when `max_fps` is zero. `scale` downscales capture.
    Live {
        node: String,
        control: bool,
        monitor: u32,
        quality: u32,
        scale: f32,
        /// When non-zero, overrides the quality-derived fps cap.
        max_fps: u32,
        /// True when sent from desktop Retry (vs first View open).
        retry: bool,
    },
    LiveStop,
    Input {
        node: String,
        live: String,
        inject: String,
        /// Barrier events must stay on one ordered live route (no Extension
        /// fallback on saturation). Moves may drop/coalesce.
        barrier: bool,
    },
    Monitors {
        node: String,
        /// True when sent from desktop Retry (vs first View open).
        retry: bool,
    },
    Clipboard {
        node: String,
        text: String,
    },
    Shot {
        node: String,
        path: String,
    },
    Enroll {
        name: String,
        access: String,
        minutes: u64,
    },
}

enum PtyCmd {
    Write(Vec<u8>),
    Resize(u16, u16),
    Close(Option<tokio::sync::oneshot::Sender<()>>),
}

pub struct Shared {
    events: Mutex<Vec<UiEvent>>,
    picture: Mutex<Option<Picture>>,
    cursor: Mutex<DeskCursor>,
    seq: AtomicU64,
    /// Once a terminal handshake is published, progress/cleanup stages
    /// must not overwrite it until the next live attempt.
    terminal_handshake: AtomicBool,
    pub perf: ClientPerf,
}

impl Shared {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            picture: Mutex::new(None),
            cursor: Mutex::new(DeskCursor::default()),
            seq: AtomicU64::new(0),
            terminal_handshake: AtomicBool::new(false),
            perf: ClientPerf::default(),
        }
    }

    pub fn push(&self, event: UiEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    pub fn drain(&self) -> Vec<UiEvent> {
        self.events
            .lock()
            .map(|mut events| std::mem::take(&mut *events))
            .unwrap_or_default()
    }

    pub fn set_picture(&self, rgba: Vec<u8>, width: usize, height: usize, kind: &str, path: &str) {
        if rgba.len() != width.saturating_mul(height).saturating_mul(4) || width == 0 {
            return;
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        if let Ok(mut slot) = self.picture.lock() {
            *slot = Some(Picture {
                rgba,
                width,
                height,
                kind: kind.to_string(),
                path: path.to_string(),
                seq,
            });
        }
    }

    pub fn latest_picture(&self) -> Option<Picture> {
        self.picture.lock().ok().and_then(|mut slot| slot.take())
    }

    pub fn set_hud(&self, hud: LiveHud) {
        self.push(UiEvent::Hud(hud));
    }

    pub fn set_cursor(&self, cursor: DeskCursor) {
        if let Ok(mut slot) = self.cursor.lock() {
            *slot = cursor;
        }
    }

    pub fn latest_cursor(&self) -> DeskCursor {
        self.cursor
            .lock()
            .map(|slot| slot.clone())
            .unwrap_or_default()
    }

    /// Start a new live attempt: later progress stages may update the HUD again.
    pub fn begin_handshake(&self) {
        self.terminal_handshake.store(false, Ordering::Relaxed);
    }

    /// Progress stage. Ignored after a terminal reason has been recorded.
    pub fn set_handshake(&self, stage: impl Into<String>) {
        let stage = stage.into();
        if handshake_is_cleanup(&stage) {
            return;
        }
        if self.terminal_handshake.load(Ordering::Relaxed) {
            return;
        }
        self.push(UiEvent::Handshake(stage));
    }

    /// Terminal negotiation result. Survives cleanup/close until the next attempt.
    pub fn set_handshake_terminal(&self, stage: impl Into<String>) {
        self.terminal_handshake.store(true, Ordering::Relaxed);
        self.push(UiEvent::Handshake(stage.into()));
    }
}

/// Close/cleanup and routine trickle/keyframe acks belong in the log, not
/// the stats handshake line. Matches the 0910 GUI sequence where
/// `signal close ok 1098ms` overwrote the negotiation failure.
pub fn handshake_is_cleanup(msg: &str) -> bool {
    let lower = msg.trim().to_ascii_lowercase();
    if lower.contains("signal close") {
        return true;
    }
    let routine = lower.starts_with("signal ice") || lower.starts_with("signal keyframe");
    routine && !lower.contains("error") && !lower.contains("fallback")
}

/// Stills refresh rate from actual JPEG publish times.
///
/// Needs at least two samples spanning 20ms. Otherwise `None` so the
/// Session stats popover can show `stills  n/a` instead of a fake `fps  0.0`.
pub fn stills_rate_hz(times: &[Instant]) -> Option<f32> {
    let (first, last) = match (times.first(), times.last()) {
        (Some(first), Some(last)) if times.len() >= 2 => (*first, *last),
        _ => return None,
    };
    let span = last.saturating_duration_since(first);
    if span < Duration::from_millis(20) {
        return None;
    }
    Some((times.len() - 1) as f32 / span.as_secs_f32())
}

/// Bounded renegotiation after a soft WebRTC miss.
///
/// JPEG stills stay on the relay the whole time (the analogue of
/// Tailscale starting on DERP and upgrading). This is not a media
/// TURN/DERP substitute and does not claim hard-NAT traversal.
/// Production uses three attempts, 12s ICE wait each, then 3s and 6s
/// backoffs, with a session offer budget so a flapping path cannot
/// hammer a node.
#[derive(Clone, Debug)]
pub struct LiveSchedule {
    pub attempt_max: u32,
    pub ice_wait: Duration,
    pub backoff: Vec<Duration>,
    pub offer_budget: u32,
}

impl Default for LiveSchedule {
    fn default() -> Self {
        Self {
            attempt_max: 3,
            ice_wait: Duration::from_secs(12),
            backoff: vec![Duration::from_secs(3), Duration::from_secs(6)],
            offer_budget: 6,
        }
    }
}

impl LiveSchedule {
    /// Single attempt, same 12s wait as 0938/0951. Used by older
    /// one-shot harness tests so they do not grow to 3×12s.
    pub fn once() -> Self {
        Self {
            attempt_max: 1,
            ice_wait: Duration::from_secs(12),
            backoff: Vec::new(),
            offer_budget: 1,
        }
    }
}

/// Backoff after `failed_in_streak` soft failures (1-based). `None`
/// means the streak is exhausted and retries must stop.
pub fn live_retry_backoff(schedule: &LiveSchedule, failed_in_streak: u32) -> Option<Duration> {
    if failed_in_streak == 0 || failed_in_streak >= schedule.attempt_max {
        return None;
    }
    schedule
        .backoff
        .get((failed_in_streak - 1) as usize)
        .copied()
}

fn wait_interruptible(stop: &AtomicBool, total: Duration) -> bool {
    let deadline = Instant::now() + total;
    while Instant::now() < deadline {
        if stop.load(Ordering::Relaxed) {
            return false;
        }
        let slice = Duration::from_millis(50);
        let remain = deadline.saturating_duration_since(Instant::now());
        if remain.is_zero() {
            break;
        }
        std::thread::sleep(slice.min(remain));
    }
    !stop.load(Ordering::Relaxed)
}

struct TracingSignal {
    inner: Arc<dyn Signal>,
    on_stage: Arc<dyn Fn(&str) + Send + Sync>,
}

impl Signal for TracingSignal {
    fn signal(&self, payload: &Value) -> Result<Value, String> {
        let action = payload
            .get("action")
            .and_then(|value| value.as_str())
            .unwrap_or("signal");
        let sdp_len = payload
            .get("sdp")
            .and_then(|value| value.as_str())
            .map(str::len);
        let extra = match sdp_len {
            Some(n) => format!(" sdp_len={n}"),
            None => String::new(),
        };
        let sent = format!("signal {action} sent{extra}");
        eprintln!("agentlink live-webrtc: {sent}");
        (self.on_stage)(&sent);
        let started = Instant::now();
        let result = self.inner.signal(payload);
        let ms = started.elapsed().as_millis();
        match &result {
            Ok(value) if is_screenshot_fallback(value) => {
                let msg = format!("signal {action} screenshot-fallback {ms}ms");
                eprintln!("agentlink live-webrtc: {msg}");
                (self.on_stage)(&msg);
            }
            Ok(value) => {
                let answer_sdp = value
                    .get("sdp")
                    .and_then(|item| item.as_str())
                    .map(str::len);
                let session_len = value
                    .get("session_id")
                    .and_then(|item| item.as_str())
                    .map(str::len)
                    .unwrap_or(0);
                let detail = match answer_sdp {
                    Some(n) => format!(" sdp_len={n} session_len={session_len}"),
                    None => String::new(),
                };
                let msg = format!("signal {action} ok {ms}ms{detail}");
                eprintln!("agentlink live-webrtc: {msg}");
                (self.on_stage)(&msg);
            }
            Err(err) => {
                let msg = format!("signal {action} error {ms}ms: {err}");
                eprintln!("agentlink live-webrtc: {msg}");
                (self.on_stage)(&msg);
            }
        }
        result
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
            let mapped = match result {
                Ok(Ok(value)) => Ok(value),
                Ok(Err(err)) => Err(err.to_string()),
                Err(_) => Err("webrtc_signal timed out".into()),
            };
            let _ = tx.send(mapped);
        });
        rx.recv()
            .map_err(|_| "client runtime stopped".to_string())?
    }
}

struct Live {
    stop: Arc<AtomicBool>,
    viewer: Arc<Mutex<Option<Arc<Viewer>>>>,
}

pub fn run(mut rx: UnboundedReceiver<Cmd>, shared: Arc<Shared>, config_dir: std::path::PathBuf) {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("agentlink-controller")
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            shared.push(UiEvent::Failed(err.to_string()));
            return;
        }
    };
    runtime.block_on(async move {
        let mut client: Option<Arc<Client>> = None;
        let mut pty: Option<UnboundedSender<PtyCmd>> = None;
        let mut live: Option<Live> = None;
        let mut shots: Option<tokio::task::JoinHandle<()>> = None;
        loop {
            let Some(cmd) = rx.recv().await else {
                break;
            };
            match cmd {
                Cmd::Bootstrap => {
                    diag_client(
                        &config_dir,
                        "bootstrap_begin",
                        Some("Bootstrap"),
                        None,
                        None,
                    );
                    match saved_client(&config_dir).await {
                        Ok(Some((next, user))) => {
                            diag_client(
                                &config_dir,
                                "bootstrap_ok",
                                Some("Bootstrap"),
                                Some(next.as_ref()),
                                None,
                            );
                            client = Some(next);
                            shared.push(UiEvent::Ready { user: Some(user) });
                            refresh(client.as_ref(), &shared).await;
                        }
                        Ok(None) => {
                            diag_client(
                                &config_dir,
                                "bootstrap_none",
                                Some("Bootstrap"),
                                None,
                                None,
                            );
                            shared.push(UiEvent::Ready { user: None });
                        }
                        Err(err) => {
                            // Typed connect failures already emitted inside `saved_client`.
                            shared.push(UiEvent::Ready { user: None });
                            shared.push(UiEvent::Failed(err));
                        }
                    }
                }
                Cmd::Login {
                    username,
                    password,
                    totp,
                    relay,
                    pin,
                    trust,
                } => match sign_in(
                    &config_dir,
                    &username,
                    &password,
                    &totp,
                    &relay,
                    &pin,
                    &trust,
                )
                .await
                {
                    Ok((next, user)) => {
                        client = Some(next);
                        shared.push(UiEvent::Ready {
                            user: Some(user.clone()),
                        });
                        shared.push(UiEvent::Notice(format!("Signed in as {user}")));
                        refresh(client.as_ref(), &shared).await;
                    }
                    Err(err) => {
                        if super::model::asks_for_totp(&err) {
                            shared.push(UiEvent::TotpRequired(err));
                        } else {
                            shared.push(UiEvent::Failed(err));
                        }
                    }
                },
                Cmd::Logout => {
                    stop_live(&mut live, &mut shots);
                    close_pty(&mut pty).await;
                    client = None;
                    if let Err(err) = crate::tray::sign_out(&config_dir).await {
                        shared.push(UiEvent::Failed(err.to_string()));
                    }
                    shared.push(UiEvent::Ready { user: None });
                    shared.push(UiEvent::Notice("Signed out".into()));
                }
                Cmd::Refresh => {
                    if let Err(err) = ensure_worker_client(&mut client, &config_dir, false).await {
                        shared.push(UiEvent::Failed(err));
                    } else {
                        refresh(client.as_ref(), &shared).await;
                    }
                }
                Cmd::PtyOpen { node, rows, cols } => {
                    close_pty(&mut pty).await;
                    match client.as_ref() {
                        Some(current) => {
                            match current.open_pty(&node, None, None, rows, cols).await {
                                Ok(session) => {
                                    pty = Some(spawn_pty(session, Arc::clone(&shared)));
                                }
                                Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                            }
                        }
                        None => shared.push(UiEvent::Failed("Sign in first.".into())),
                    }
                }
                Cmd::PtyWrite { data } => {
                    if let Some(tx) = &pty {
                        let _ = tx.send(PtyCmd::Write(data));
                    }
                }
                Cmd::PtyResize { rows, cols } => {
                    if let Some(tx) = &pty {
                        let _ = tx.send(PtyCmd::Resize(rows, cols));
                    }
                }
                Cmd::PtyClose => close_pty(&mut pty).await,
                Cmd::List { node, path } => match client.as_ref() {
                    Some(current) => match current.list_dir(&node, &path).await {
                        Ok(entries) => shared.push(UiEvent::Dir { path, entries }),
                        Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                    },
                    None => shared.push(UiEvent::Failed("Sign in first.".into())),
                },
                Cmd::Read { node, path } => match client.as_ref() {
                    Some(current) => match current.read_file(&node, &path, 0, 256 * 1024).await {
                        Ok(bytes) if super::model::looks_textual(&bytes) => {
                            let text = String::from_utf8_lossy(&bytes).to_string();
                            shared.push(UiEvent::File { path, text });
                        }
                        Ok(_) => shared.push(UiEvent::Failed(
                            "That file is not text. The browser can still download it.".into(),
                        )),
                        Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                    },
                    None => shared.push(UiEvent::Failed("Sign in first.".into())),
                },
                Cmd::Write { node, path, text } => match client.as_ref() {
                    Some(current) => {
                        match current.write_file(&node, &path, text.as_bytes()).await {
                            Ok(()) => {
                                shared.push(UiEvent::Notice(format!("Saved {path}")));
                                shared.push(UiEvent::File { path, text });
                            }
                            Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                        }
                    }
                    None => shared.push(UiEvent::Failed("Sign in first.".into())),
                },
                Cmd::Mkdir { node, path } => match client.as_ref() {
                    Some(current) => match current.mkdir(&node, &path, true).await {
                        Ok(()) => {
                            let parent = super::model::parent_path(&path);
                            match current.list_dir(&node, &parent).await {
                                Ok(entries) => shared.push(UiEvent::Dir {
                                    path: parent,
                                    entries,
                                }),
                                Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                            }
                        }
                        Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                    },
                    None => shared.push(UiEvent::Failed("Sign in first.".into())),
                },
                Cmd::Remove { node, path } => match client.as_ref() {
                    Some(current) => match current.remove(&node, &path, false).await {
                        Ok(()) => {
                            let parent = super::model::parent_path(&path);
                            match current.list_dir(&node, &parent).await {
                                Ok(entries) => shared.push(UiEvent::Dir {
                                    path: parent,
                                    entries,
                                }),
                                Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                            }
                        }
                        Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                    },
                    None => shared.push(UiEvent::Failed("Sign in first.".into())),
                },
                Cmd::Live {
                    node,
                    control,
                    monitor,
                    quality,
                    scale,
                    max_fps,
                    retry,
                } => {
                    stop_live(&mut live, &mut shots);
                    diag_client(
                        &config_dir,
                        if retry { "retry" } else { "cmd" },
                        Some("Live"),
                        client.as_ref().map(|c| c.as_ref()),
                        None,
                    );
                    let current = match ensure_worker_client(&mut client, &config_dir, false).await
                    {
                        Ok(current) => current,
                        Err(err) => {
                            diag_client(&config_dir, "live_ensure_err", Some("Live"), None, None);
                            shared.push(UiEvent::Failed(err));
                            continue;
                        }
                    };
                    diag_client(
                        &config_dir,
                        "live_ensure_ok",
                        Some("Live"),
                        Some(current.as_ref()),
                        None,
                    );
                    shared.push(UiEvent::Link(if control {
                        "connecting · control".into()
                    } else {
                        "connecting · view".into()
                    }));
                    let started = start_live(
                        current,
                        node,
                        control,
                        monitor,
                        quality,
                        scale,
                        max_fps,
                        Arc::clone(&shared),
                    );
                    shots = Some(started.shots);
                    live = Some(started.live);
                }
                Cmd::LiveStop => {
                    stop_live(&mut live, &mut shots);
                    shared.set_hud(LiveHud::default());
                    shared.push(UiEvent::Link("relay".into()));
                }
                Cmd::Input {
                    node,
                    live: body,
                    inject,
                    barrier,
                } => {
                    // One ordered live route: never switch to Extension while a
                    // viewer exists (saturation would reorder barriers ahead of
                    // queued RTC downs). Extension only when there is no live
                    // session (stills / pre-connect).
                    let viewer = live
                        .as_ref()
                        .and_then(|session| session.viewer.lock().ok())
                        .and_then(|slot| slot.clone());
                    if let Some(viewer) = viewer {
                        let _sent = if barrier {
                            viewer.send_control_barrier(&body).await
                        } else {
                            viewer.send_control_move(&body)
                        };
                        // Closed/saturated barrier: do not Extension-bypass.
                    } else if let Some(current) = &client {
                        let payload = serde_json::from_str(&inject).unwrap_or(json!({}));
                        if let Err(err) = current
                            .call_op(
                                &node,
                                Op::Extension {
                                    name: PHASE2_INJECT_INPUT.to_string(),
                                    payload,
                                },
                            )
                            .await
                        {
                            shared.push(UiEvent::Failed(err.to_string()));
                        }
                    }
                }
                Cmd::Monitors { node, retry } => {
                    diag_client(
                        &config_dir,
                        if retry { "retry" } else { "cmd" },
                        Some("Monitors"),
                        client.as_ref().map(|c| c.as_ref()),
                        None,
                    );
                    match list_monitors_with_once_rebootstrap(
                        &mut client,
                        &node,
                        |slot, force| {
                            let config_dir = config_dir.clone();
                            Box::pin(
                                async move { ensure_worker_client(slot, &config_dir, force).await },
                            )
                        },
                        |current, node| {
                            Box::pin(async move { list_monitors(&current, &node).await })
                        },
                    )
                    .await
                    {
                        Ok(MonitorsOutcome {
                            monitors,
                            reconnected,
                        }) => {
                            diag_client(
                                &config_dir,
                                "monitors_ok",
                                Some("Monitors"),
                                client.as_ref().map(|c| c.as_ref()),
                                Some(reconnected),
                            );
                            if reconnected {
                                shared.push(UiEvent::Notice(
                                    "Reconnected after a closed relay session.".into(),
                                ));
                            }
                            shared.push(UiEvent::Monitors(monitors));
                        }
                        Err(err) => {
                            diag_client(
                                &config_dir,
                                "monitors_err",
                                Some("Monitors"),
                                client.as_ref().map(|c| c.as_ref()),
                                None,
                            );
                            shared.push(UiEvent::Failed(err));
                        }
                    }
                }
                Cmd::Clipboard { node, text } => {
                    let body = json!({"type": "clipboard", "text": text}).to_string();
                    let viewer = live
                        .as_ref()
                        .and_then(|session| session.viewer.lock().ok())
                        .and_then(|slot| slot.clone());
                    let sent = match viewer {
                        Some(viewer) => viewer.send_control_barrier(&body).await,
                        None => false,
                    };
                    if !sent {
                        shared.push(UiEvent::Failed(
                            "Clipboard needs a live session. Reconnect desktop first.".into(),
                        ));
                        let _ = node;
                    } else {
                        shared.push(UiEvent::Notice("Clipboard sent to the machine.".into()));
                    }
                }
                Cmd::Shot { node, path } => match client.as_ref() {
                    Some(current) => match save_screenshot(current, &node, &path).await {
                        Ok(saved) => shared.push(UiEvent::Notice(format!("Saved {saved}"))),
                        Err(err) => shared.push(UiEvent::Failed(err)),
                    },
                    None => shared.push(UiEvent::Failed("Sign in first.".into())),
                },
                Cmd::Enroll {
                    name,
                    access,
                    minutes,
                } => match client.as_ref() {
                    Some(current) => match parse_access(&access) {
                        Ok(policy) => {
                            let ttl = minutes.clamp(1, 7 * 24 * 60) * 60;
                            match current.create_enrollment_token(&name, policy, ttl, 1).await {
                                Ok(info) => {
                                    let command = enroll_command(&info.token, &name, &access);
                                    shared.push(UiEvent::Enrolled(format!(
                                        "{command}\n\nToken: {}",
                                        info.token
                                    )));
                                }
                                Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                            }
                        }
                        Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                    },
                    None => shared.push(UiEvent::Failed("Sign in first.".into())),
                },
            }
        }
        // Await PTY close on this worker runtime only. Drop of PtySession
        // never block_on (it only try_sends), so teardown cannot nest a
        // runtime inside this one.
        close_pty(&mut pty).await;
        stop_live(&mut live, &mut shots);
    });
}

struct Started {
    live: Live,
    shots: tokio::task::JoinHandle<()>,
}

fn quality_offer(quality: u32) -> (u32, u32) {
    let q = quality.clamp(1, 100);
    if q >= 85 {
        (60, 6_000_000)
    } else if q >= 60 {
        (30, 2_500_000)
    } else if q >= 35 {
        (24, 1_500_000)
    } else {
        (15, 800_000)
    }
}

fn live_path_for_hud(viewer: &Viewer) -> (String, String) {
    let snap = viewer.transport();
    let info = viewer.info();
    let raw = if let Some(ref snap) = snap {
        snap.path.clone()
    } else if info.path != "connecting" && !info.path.is_empty() {
        info.path.clone()
    } else {
        "unknown".into()
    };
    let path = super::model::connection_label(&raw).to_string();
    let note = if let Some(ref snap) = snap {
        if !snap.note.is_empty() {
            snap.note.clone()
        } else {
            super::model::connection_path_hint("h264", &path).to_string()
        }
    } else {
        super::model::connection_path_hint("h264", &path).to_string()
    };
    (path, note)
}

enum JpegSource {
    Client {
        client: Arc<Client>,
        node: String,
        monitor: u32,
        quality: u32,
    },
    Injected(Arc<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>),
}

fn start_live(
    client: Arc<Client>,
    node: String,
    control: bool,
    monitor: u32,
    quality: u32,
    scale: f32,
    max_fps_override: u32,
    shared: Arc<Shared>,
) -> Started {
    let handle = tokio::runtime::Handle::current();
    start_live_from(
        Arc::new(ClientSignal {
            client: Arc::clone(&client),
            handle,
            node: node.clone(),
        }),
        JpegSource::Client {
            client,
            node,
            monitor,
            quality: quality.clamp(40, 95),
        },
        control,
        monitor,
        quality,
        scale,
        max_fps_override,
        shared,
        Duration::from_millis(800),
        LiveSchedule::default(),
        Arc::new(|_| IceFault::None),
    )
}

fn start_live_from(
    signal: Arc<dyn Signal>,
    jpeg: JpegSource,
    control: bool,
    monitor: u32,
    quality: u32,
    scale: f32,
    max_fps_override: u32,
    shared: Arc<Shared>,
    shot_interval: Duration,
    schedule: LiveSchedule,
    ice_fault_for: Arc<dyn Fn(u32) -> IceFault + Send + Sync>,
) -> Started {
    let stop = Arc::new(AtomicBool::new(false));
    let h264 = Arc::new(AtomicBool::new(false));
    let viewer = Arc::new(Mutex::new(None));
    let thread_stop = Arc::clone(&stop);
    let thread_h264 = Arc::clone(&h264);
    let thread_viewer = Arc::clone(&viewer);
    let thread_shared = Arc::clone(&shared);
    let (quality_fps, bitrate) = quality_offer(quality);
    let max_fps = if max_fps_override > 0 {
        max_fps_override.min(60)
    } else {
        quality_fps
    };
    let scale = scale.clamp(0.05, 1.0);
    std::thread::Builder::new()
        .name("agentlink-desktop-view".into())
        .spawn(move || {
            const CONNECT_TIMEOUT: Duration = Duration::from_secs(60);
            let last_stage = Arc::new(Mutex::new("starting".to_string()));
            let on_stage: Arc<dyn Fn(&str) + Send + Sync> = {
                let last_stage = Arc::clone(&last_stage);
                let events = Arc::clone(&thread_shared);
                Arc::new(move |msg: &str| {
                    if let Ok(mut slot) = last_stage.lock() {
                        *slot = msg.to_string();
                    }
                    events.set_handshake(msg);
                })
            };
            let traced: Arc<dyn Signal> = Arc::new(TracingSignal {
                inner: signal,
                on_stage: Arc::clone(&on_stage),
            });
            let wait_label = if schedule.ice_wait.as_secs() >= 1
                && schedule.ice_wait.subsec_millis() == 0
            {
                format!("{}s", schedule.ice_wait.as_secs())
            } else {
                format!("{}ms", schedule.ice_wait.as_millis())
            };
            let mut offers_sent = 0u32;
            let mut streak = 0u32;
            let mut last_soft: Option<String> = None;

            'live: loop {
                if thread_stop.load(Ordering::Relaxed) {
                    break;
                }
                if offers_sent >= schedule.offer_budget || streak >= schedule.attempt_max {
                    break;
                }
                offers_sent += 1;
                streak += 1;
                let ice_fault = ice_fault_for(offers_sent);
                if let Ok(mut slot) = last_stage.lock() {
                    *slot = "starting".to_string();
                }
                thread_shared.begin_handshake();
                if offers_sent == 1 {
                    thread_shared.set_handshake("webrtc: starting");
                } else {
                    thread_shared.set_handshake(format!(
                        "webrtc: starting attempt {offers_sent} (JPEG stills remain)"
                    ));
                }
                let opts = LiveOptions {
                    viewer: "desktop".into(),
                    control,
                    monitor,
                    max_fps,
                    bitrate,
                    scale,
                    ice_fault,
                    on_stage: Some(Arc::clone(&on_stage)),
                    ..LiveOptions::default()
                };
                let (tx, rx) = std::sync::mpsc::sync_channel(1);
                let connect_traced = Arc::clone(&traced);
                let spawn_ok = std::thread::Builder::new()
                    .name("agentlink-desktop-connect".into())
                    .spawn(move || {
                        let _ = tx.send(Viewer::connect(connect_traced, opts));
                    })
                    .is_ok();
                let connected = if !spawn_ok {
                    Err("failed to start WebRTC connect thread".into())
                } else {
                    match rx.recv_timeout(CONNECT_TIMEOUT) {
                        Ok(result) => result,
                        Err(_) => {
                            let stage = last_stage
                                .lock()
                                .ok()
                                .map(|slot| slot.clone())
                                .unwrap_or_else(|| "unknown".into());
                            Err(format!(
                                "WebRTC connect timed out after {}s during {stage}",
                                CONNECT_TIMEOUT.as_secs()
                            ))
                        }
                    }
                };
                let viewer = match connected {
                    Ok(viewer) => Arc::new(viewer),
                    Err(err) => {
                        if super::model::webrtc_connect_is_hard_reject(&err) {
                            thread_shared
                                .set_handshake_terminal(format!("webrtc: failed ({err})"));
                            thread_stop.store(true, Ordering::Relaxed);
                            thread_shared.push(UiEvent::Failed(err));
                            let _ = control;
                            return;
                        }
                        last_soft = Some(format!("webrtc: failed ({err})"));
                        thread_shared.push(UiEvent::Notice(format!(
                            "Live video is not up ({err}). Showing JPEG over the relay."
                        )));
                        thread_shared.push(UiEvent::Link("jpeg · relay".into()));
                        if let Some(delay) = live_retry_backoff(&schedule, streak) {
                            thread_shared.set_handshake(format!(
                                "webrtc: retry in {}s after connect failure (attempt {offers_sent}; JPEG stills remain)",
                                delay.as_secs().max(1)
                            ));
                            if !wait_interruptible(&thread_stop, delay) {
                                break 'live;
                            }
                            continue;
                        }
                        break 'live;
                    }
                };
                if let Ok(mut slot) = thread_viewer.lock() {
                    *slot = Some(Arc::clone(&viewer));
                }
                let info = viewer.info();
                if agentlink_desktop::share_allowed(control, info.control) {
                    spawn_session_clipboard(Arc::clone(&viewer), Arc::clone(&thread_stop));
                }
                // Handshake is independent of the painted media path. JPEG stills
                // may still be on screen until the first decoded H.264 frame.
                // Never publish kind=h264 / path=connecting here — that would
                // overwrite an already-rendered jpeg · relay HUD.
                let encoder = if info.encoder.is_empty() {
                    if info.hardware {
                        "h264_hw".into()
                    } else {
                        "minih264".into()
                    }
                } else {
                    info.encoder.clone()
                };
                thread_shared.set_handshake(
                    "webrtc: signaling complete, waiting for ICE pair / video".to_string(),
                );
                let ice_deadline = Instant::now() + schedule.ice_wait;
                let mut decoder = H264Decoder::new();
                if !decoder.available() {
                    thread_shared.push(UiEvent::Notice(
                        "H.264 frames are arriving, but this build could not open a decoder. JPEG stays on."
                            .into(),
                    ));
                }
                let mut window_start = Instant::now();
                let mut window_frames = 0u32;
                let mut saw_frame = false;
                let mut last_recv = Instant::now();
                let mut last_frame_at = Instant::now();
                let mut last_decoded_at = Instant::now();
                let mut soft: Option<String> = None;
                let mut hard = false;
                while !thread_stop.load(Ordering::Relaxed) {
                    let Some(frame) = viewer.poll_frame(Duration::from_millis(50)) else {
                        if viewer.failed() {
                            if super::model::webrtc_loss_keeps_jpeg(saw_frame) {
                                thread_h264.store(false, Ordering::Relaxed);
                                soft = Some(
                                    "webrtc: connection lost; JPEG stills remain".to_string(),
                                );
                                thread_shared.push(UiEvent::Notice(
                                    "WebRTC live video is not up. Showing JPEG over the relay."
                                        .into(),
                                ));
                                thread_shared.push(UiEvent::Link("jpeg · relay".into()));
                                break;
                            }
                            thread_shared
                                .push(UiEvent::Failed("WebRTC connection failed".into()));
                            hard = true;
                            break;
                        }
                        if !saw_frame && Instant::now() >= ice_deadline {
                            let has_pair = viewer.transport().is_some();
                            let reason = if has_pair {
                                format!(
                                    "webrtc: no H.264 frame within {wait_label} after a selected ICE pair; JPEG stills remain"
                                )
                            } else {
                                format!(
                                    "webrtc: no selected ICE pair within {wait_label}; JPEG stills remain"
                                )
                            };
                            let checks = viewer.ice_checks();
                            if !checks.is_empty() {
                                eprintln!("agentlink live-ice: timeout snapshot {checks}");
                            }
                            thread_h264.store(false, Ordering::Relaxed);
                            thread_shared.push(UiEvent::Notice(
                                "WebRTC live video is not up. Showing JPEG over the relay."
                                    .into(),
                            ));
                            thread_shared.push(UiEvent::Link("jpeg · relay".into()));
                            soft = Some(reason);
                            break;
                        }
                        if saw_frame && last_decoded_at.elapsed() > Duration::from_secs(8) {
                            if super::model::webrtc_loss_keeps_jpeg(saw_frame) {
                                thread_h264.store(false, Ordering::Relaxed);
                                soft = Some(
                                    "webrtc: no H.264 frame for 8s after takeover; JPEG stills remain"
                                        .to_string(),
                                );
                                thread_shared.push(UiEvent::Notice(
                                    "WebRTC live video is not up. Showing JPEG over the relay."
                                        .into(),
                                ));
                                thread_shared.push(UiEvent::Link("jpeg · relay".into()));
                                break;
                            }
                        }
                        if saw_frame && last_frame_at.elapsed() > Duration::from_millis(200) {
                            thread_shared.perf.stalls.fetch_add(1, Ordering::Relaxed);
                            last_frame_at = Instant::now();
                        }
                        continue;
                    };
                    let gap_us = last_recv.elapsed().as_micros() as u64;
                    last_recv = Instant::now();
                    if saw_frame {
                        thread_shared.perf.note_recv_gap_us(gap_us);
                    }
                    let decode_started = Instant::now();
                    let decoded = decoder.decode(&frame.annex_b);
                    let decode_us = decode_started.elapsed().as_micros() as u64;
                    thread_shared.perf.note_decode_us(decode_us);
                    // Drop backlog when decode overruns a 60fps budget.
                    let frame = if decode_us > 16_000 {
                        if let Some(newer) = viewer.drain_keep_latest() {
                            let again_started = Instant::now();
                            let again = decoder.decode(&newer.annex_b);
                            thread_shared
                                .perf
                                .note_decode_us(again_started.elapsed().as_micros() as u64);
                            again
                        } else {
                            decoded
                        }
                    } else {
                        decoded
                    };
                    if let Some((rgba, width, height)) = frame {
                        let first_h264 = !saw_frame;
                        saw_frame = true;
                        last_frame_at = Instant::now();
                        last_decoded_at = last_frame_at;
                        thread_h264.store(true, Ordering::Relaxed);
                        if first_h264 {
                            // A live path was established; the next loss
                            // starts a fresh retry streak, still limited by
                            // the session offer budget.
                            streak = 0;
                            thread_shared.set_handshake_terminal("webrtc: receiving video");
                        }
                        let move_ms = thread_shared
                            .perf
                            .last_move_unix_ms
                            .load(Ordering::Relaxed);
                        if move_ms > 0 {
                            let now_ms = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_millis() as i64)
                                .unwrap_or(0);
                            let rtt = now_ms.saturating_sub(move_ms).max(0) as u64 * 1000;
                            if rtt > 0 && rtt < 5_000_000 {
                                thread_shared.perf.note_input_rtt_us(rtt);
                            }
                        }
                        thread_shared.perf.frames.fetch_add(1, Ordering::Relaxed);
                        let (path_label, path_note) = live_path_for_hud(&viewer);
                        thread_shared.set_picture(rgba, width, height, "h264", &path_label);
                        if let Some(cursor) = viewer.poll_cursor() {
                            thread_shared.set_cursor(DeskCursor {
                                shape: cursor.shape,
                                visible: cursor.visible,
                                hotspot_x: cursor.hotspot_x,
                                hotspot_y: cursor.hotspot_y,
                                bitmap_w: cursor.bitmap_w,
                                bitmap_h: cursor.bitmap_h,
                                bitmap_rgba: cursor.bitmap_rgba,
                            });
                        }
                        window_frames += 1;
                        let elapsed = window_start.elapsed();
                        if elapsed >= Duration::from_millis(500) || first_h264 {
                            let fps = if elapsed >= Duration::from_millis(500) {
                                window_frames as f32 / elapsed.as_secs_f32().max(0.001)
                            } else {
                                0.0
                            };
                            let stats = viewer.stats();
                            thread_shared.set_hud(LiveHud {
                                path: path_label,
                                kind: "h264".into(),
                                width: width as u32,
                                height: height as u32,
                                latency_ms: stats.latency_ms,
                                fps,
                                bitrate_kbps: (bitrate / 1000).max(1),
                                encoder: encoder.clone(),
                                hardware: info.hardware,
                                frames_dropped: stats.frames_dropped,
                                path_note,
                                handshake: "webrtc: receiving video".into(),
                                cursor_presentation: info.cursor_presentation.clone(),
                                src_width: info.src_width,
                                src_height: info.src_height,
                            });
                            window_start = Instant::now();
                            window_frames = 0;
                        }
                    }
                }
                viewer.close();
                if let Ok(mut slot) = thread_viewer.lock() {
                    *slot = None;
                }
                if hard || thread_stop.load(Ordering::Relaxed) {
                    let _ = control;
                    return;
                }
                if let Some(reason) = soft {
                    last_soft = Some(reason);
                    if let Some(delay) = live_retry_backoff(&schedule, streak) {
                        thread_shared.set_handshake(format!(
                            "webrtc: retry in {}s ({}); JPEG stills remain",
                            if delay.as_secs() >= 1 {
                                delay.as_secs().to_string()
                            } else {
                                format!("{:.1}", delay.as_secs_f32())
                            },
                            last_soft.as_deref().unwrap_or("soft failure")
                        ));
                        if !wait_interruptible(&thread_stop, delay) {
                            break 'live;
                        }
                        continue;
                    }
                }
                break;
            }

            if let Some(reason) = last_soft {
                let terminal = if offers_sent > 1 {
                    format!("{reason} (stopped after {offers_sent} attempts)")
                } else {
                    reason
                };
                thread_shared.set_handshake_terminal(terminal);
                thread_shared.push(UiEvent::Notice(
                    "WebRTC live video is not up. Showing JPEG over the relay.".into(),
                ));
                thread_shared.push(UiEvent::Link("jpeg · relay".into()));
            }
            let _ = control;
        })
        .ok();

    let shot_stop = Arc::clone(&stop);
    let shot_h264 = Arc::clone(&h264);
    let shots = tokio::spawn(async move {
        let mut tick = tokio::time::interval(shot_interval);
        let mut still_times: Vec<Instant> = Vec::new();
        loop {
            tick.tick().await;
            if shot_stop.load(Ordering::Relaxed) {
                break;
            }
            if shot_h264.load(Ordering::Relaxed) {
                continue;
            }
            let grabbed = match &jpeg {
                JpegSource::Injected(grab) => grab(),
                JpegSource::Client {
                    client,
                    node,
                    monitor,
                    quality,
                } => client_jpeg(client, node, *monitor, *quality).await,
            };
            match grabbed {
                Ok(bytes) => {
                    if shot_h264.load(Ordering::Relaxed) {
                        continue;
                    }
                    if let Some((rgba, width, height)) = decode_image(&bytes) {
                        shared.set_picture(rgba, width, height, "jpeg", "relay");
                        let now = Instant::now();
                        still_times.push(now);
                        still_times.retain(|t| {
                            now.saturating_duration_since(*t) <= Duration::from_secs(5)
                        });
                        let stills_hz = stills_rate_hz(&still_times).unwrap_or(0.0);
                        shared.set_hud(LiveHud {
                            path: "relay".into(),
                            kind: "jpeg".into(),
                            width: width as u32,
                            height: height as u32,
                            fps: stills_hz,
                            encoder: "jpeg".into(),
                            path_note: super::model::connection_path_hint("jpeg", "relay").into(),
                            ..LiveHud::default()
                        });
                    }
                }
                Err(err) => {
                    if super::model::webrtc_connect_is_hard_reject(&err) {
                        shared.push(UiEvent::Failed(err));
                        break;
                    }
                    shared.push(UiEvent::Notice(format!("JPEG still failed ({err})")));
                }
            }
        }
    });
    Started {
        live: Live { stop, viewer },
        shots,
    }
}

async fn client_jpeg(
    client: &Client,
    node: &str,
    monitor: u32,
    quality: u32,
) -> Result<Vec<u8>, String> {
    match client
        .call_op(
            node,
            Op::Extension {
                name: PHASE2_SCREENSHOT.to_string(),
                payload: json!({
                    "target": "monitor",
                    "monitor": monitor,
                    "format": "jpeg",
                    "quality": quality
                }),
            },
        )
        .await
    {
        Ok(value) => screenshot_bytes(&value).ok_or_else(|| "screenshot missing data".into()),
        Err(err) => {
            let value = client
                .call_op(
                    node,
                    Op::Extension {
                        name: PHASE2_SCREENSHOT.to_string(),
                        payload: json!({
                            "target": "screen",
                            "format": "jpeg",
                            "quality": quality
                        }),
                    },
                )
                .await
                .map_err(|inner| inner.to_string())?;
            screenshot_bytes(&value).ok_or_else(|| err.to_string())
        }
    }
}

async fn list_monitors(client: &Client, node: &str) -> Result<Vec<MonitorEntry>, String> {
    let signal = client
        .call_op(
            node,
            Op::Extension {
                name: PHASE3_WEBRTC_SIGNAL.to_string(),
                payload: json!({"action": "list_monitors"}),
            },
        )
        .await;
    let value = match signal {
        Ok(value) => value,
        Err(_) => client
            .call_op(
                node,
                Op::Extension {
                    name: PHASE2_SCREENSHOT.to_string(),
                    payload: json!({"target": "monitors"}),
                },
            )
            .await
            .map_err(|err| err.to_string())?,
    };
    Ok(parse_monitors(&value))
}

fn parse_monitors(value: &Value) -> Vec<MonitorEntry> {
    let Some(items) = value.get("monitors").and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| {
            let index = item.get("index").and_then(Value::as_u64)? as u32;
            let name = item
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("Display")
                .to_string();
            let width = item.get("width").and_then(Value::as_u64).unwrap_or(0) as u32;
            let height = item.get("height").and_then(Value::as_u64).unwrap_or(0) as u32;
            let primary = item
                .get("primary")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let capturable = item.get("capturable").and_then(Value::as_bool);
            let reason = item
                .get("reason")
                .and_then(Value::as_str)
                .map(str::to_string)
                .or_else(|| {
                    value
                        .get("reason")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                });
            Some(MonitorEntry {
                index,
                name,
                width,
                height,
                primary,
                capturable,
                reason,
            })
        })
        .collect()
}

async fn save_screenshot(client: &Client, node: &str, path: &str) -> Result<String, String> {
    let value = client
        .call_op(
            node,
            Op::Extension {
                name: PHASE2_SCREENSHOT.to_string(),
                payload: json!({
                    "target": "screen",
                    "format": "png",
                    "quality": 90
                }),
            },
        )
        .await
        .map_err(|err| err.to_string())?;
    let bytes =
        screenshot_bytes(&value).ok_or_else(|| "screenshot response has no image".to_string())?;
    if let Some(parent) = std::path::Path::new(path).parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|err| err.to_string())?;
        }
    }
    std::fs::write(path, bytes).map_err(|err| err.to_string())?;
    Ok(path.to_string())
}

fn spawn_session_clipboard(viewer: Arc<Viewer>, stop: Arc<AtomicBool>) {
    let _ = std::thread::Builder::new()
        .name("agentlink-clipboard-share".into())
        .spawn(move || {
            let mut state = agentlink_desktop::ClipboardWatchState::new();
            while !stop.load(Ordering::Relaxed) && !viewer.is_closed() {
                std::thread::sleep(agentlink_desktop::CLIPBOARD_POLL_INTERVAL);
                if stop.load(Ordering::Relaxed) || viewer.is_closed() {
                    break;
                }
                if let Some(incoming) = viewer.poll_clipboard() {
                    if agentlink_desktop::write_clipboard(&incoming.text).is_ok() {
                        state.note_applied(&incoming.text);
                    }
                }
                if let Some(clip) = state.poll_outgoing() {
                    let body = agentlink_desktop::set_payload(&clip).to_string();
                    let mut sent = false;
                    for _ in 0..20 {
                        if stop.load(Ordering::Relaxed) || viewer.is_closed() {
                            break;
                        }
                        if viewer.send_control(&body) {
                            sent = true;
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    if !sent {
                        state.send_failed();
                    }
                }
            }
        });
}

fn stop_live(live: &mut Option<Live>, shots: &mut Option<tokio::task::JoinHandle<()>>) {
    if let Some(session) = live.take() {
        session.stop.store(true, Ordering::Relaxed);
        if let Ok(slot) = session.viewer.lock() {
            if let Some(viewer) = slot.as_ref() {
                viewer.close();
            }
        }
    }
    if let Some(task) = shots.take() {
        task.abort();
    }
}

fn screenshot_bytes(value: &Value) -> Option<Vec<u8>> {
    let text = value.get("data_b64")?.as_str()?;
    base64::engine::general_purpose::STANDARD.decode(text).ok()
}

async fn close_pty(pty: &mut Option<UnboundedSender<PtyCmd>>) {
    let Some(tx) = pty.take() else {
        return;
    };
    let (done, done_rx) = tokio::sync::oneshot::channel();
    if tx.send(PtyCmd::Close(Some(done))).is_err() {
        return;
    }
    let _ = tokio::time::timeout(Duration::from_secs(2), done_rx).await;
}

fn spawn_pty(mut session: PtySession, shared: Arc<Shared>) -> UnboundedSender<PtyCmd> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                event = session.recv() => {
                    match event {
                        Ok(PtyEvent::Data(bytes)) => shared.push(UiEvent::Pty(bytes)),
                        Ok(PtyEvent::Exit(code)) => {
                            shared.push(UiEvent::Notice(format!("Shell exited ({code})")));
                            shared.push(UiEvent::PtyDone);
                            break;
                        }
                        Ok(PtyEvent::Error(message)) => {
                            shared.push(UiEvent::Failed(message));
                            shared.push(UiEvent::PtyDone);
                            break;
                        }
                        Err(err) => {
                            shared.push(UiEvent::Failed(err.to_string()));
                            shared.push(UiEvent::PtyDone);
                            break;
                        }
                    }
                }
                cmd = rx.recv() => {
                    match cmd {
                        Some(PtyCmd::Write(bytes)) => {
                            if let Err(err) = session.write(&bytes).await {
                                shared.push(UiEvent::Failed(err.to_string()));
                            }
                        }
                        Some(PtyCmd::Resize(rows, cols)) => {
                            let _ = session.resize(rows, cols).await;
                        }
                        Some(PtyCmd::Close(ack)) => {
                            let _ = session.close().await;
                            if let Some(ack) = ack {
                                let _ = ack.send(());
                            }
                            break;
                        }
                        None => {
                            let _ = session.close().await;
                            break;
                        }
                    }
                }
            }
        }
    });
    tx
}

async fn refresh(client: Option<&Arc<Client>>, shared: &Shared) {
    let Some(client) = client else {
        shared.push(UiEvent::Failed("Sign in first.".into()));
        return;
    };
    match client.list_nodes().await {
        Ok(mut nodes) => {
            nodes.sort_by(|left, right| {
                right
                    .online
                    .cmp(&left.online)
                    .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
            });
            let pins = client.node_pin_warnings();
            if !pins.is_empty() {
                shared.push(UiEvent::Pins(pins));
            }
            shared.push(UiEvent::Nodes(nodes));
        }
        Err(err) => shared.push(UiEvent::Failed(err.to_string())),
    }
}

/// Result of `Cmd::Monitors` after at most one transport rebootstrap.
#[derive(Debug)]
struct MonitorsOutcome {
    monitors: Vec<MonitorEntry>,
    reconnected: bool,
}

/// Reuse a worker handle when it is still alive; otherwise clear the slot so
/// the caller can rebuild. `force` drops a still-held handle after transport
/// `connection closed` so Retry cannot stick on a drained session.
fn replace_worker_client_slot<C>(
    client: &mut Option<Arc<C>>,
    force: bool,
    is_alive: impl FnOnce(&C) -> bool,
) -> Option<Arc<C>> {
    if !force {
        if let Some(current) = client.as_ref() {
            if is_alive(current) {
                return Some(Arc::clone(current));
            }
        }
    }
    *client = None;
    None
}

/// Monitors with one forced Client recreate on transport death.
///
/// Grant / owner / revoke denials stay immediate failures via
/// [`super::model::session_needs_rebootstrap`]. The bootstrap closure runs at
/// most twice (initial ensure + one force), never in a loop.
async fn list_monitors_with_once_rebootstrap<C, Ensure, List>(
    client: &mut Option<Arc<C>>,
    node: &str,
    mut ensure: Ensure,
    mut list: List,
) -> Result<MonitorsOutcome, String>
where
    C: 'static,
    Ensure: for<'a> FnMut(
        &'a mut Option<Arc<C>>,
        bool,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Arc<C>, String>> + 'a>,
    >,
    List: FnMut(
        Arc<C>,
        String,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Vec<MonitorEntry>, String>>>,
    >,
{
    let current = ensure(client, false).await?;
    match list(Arc::clone(&current), node.to_string()).await {
        Ok(monitors) => Ok(MonitorsOutcome {
            monitors,
            reconnected: false,
        }),
        Err(err) if super::model::session_needs_rebootstrap(&err) => {
            // Dead/drained Client: recreate once (grants still load from disk
            // on the next call_op).
            let current = ensure(client, true).await?;
            let monitors = list(current, node.to_string()).await?;
            Ok(MonitorsOutcome {
                monitors,
                reconnected: true,
            })
        }
        Err(err) => Err(err),
    }
}

/// Reuse the worker `Client` when it is still alive; otherwise rebuild it the
/// same way Bootstrap does (`maintain_session` + `connect_identity` +
/// `remember_grants`). `force` drops a still-held handle after a transport
/// `connection closed` so Retry cannot stick on a drained session.
async fn ensure_worker_client(
    client: &mut Option<Arc<Client>>,
    config_dir: &std::path::Path,
    force: bool,
) -> Result<Arc<Client>, String> {
    if let Some(current) = replace_worker_client_slot(client, force, Client::is_alive) {
        diag_client(
            config_dir,
            if force {
                "ensure_reuse_forced_alive"
            } else {
                "ensure_reuse_alive"
            },
            None,
            Some(current.as_ref()),
            Some(force),
        );
        return Ok(current);
    }
    diag_client(
        config_dir,
        if force {
            "ensure_rebootstrap"
        } else {
            "ensure_bootstrap"
        },
        None,
        None,
        Some(force),
    );
    match saved_client(config_dir).await {
        Ok(Some((next, _user))) => {
            diag_client(
                config_dir,
                "ensure_ok",
                None,
                Some(next.as_ref()),
                Some(force),
            );
            *client = Some(Arc::clone(&next));
            Ok(next)
        }
        Ok(None) => Err("Sign in first.".into()),
        Err(err) => Err(err),
    }
}

async fn saved_client(
    config_dir: &std::path::Path,
) -> Result<Option<(Arc<Client>, String)>, String> {
    let identity = Identity::load_or_create(&config_dir.join("identity.json")).map_err(|err| {
        diag_client(config_dir, "bootstrap_err", Some("Bootstrap"), None, None);
        err.to_string()
    })?;
    // Refresh if the stored 15m access token already spent >3m so opening the
    // GUI never starts on an aged token that expires a few minutes later.
    if let Err(err) = maintain_session_skew(config_dir, &identity, 12 * 60).await {
        diag_client(config_dir, "bootstrap_err", Some("Bootstrap"), None, None);
        return Err(err.to_string());
    }
    let file = agentlink_core::config::load_file(config_dir).unwrap_or_default();
    let Some(settings) = settings_of(&file) else {
        return Ok(None);
    };
    let user = file.user.clone().filter(|user| !user.is_empty());
    let client = match Client::connect_identity_observed(&settings, identity, true).await {
        Ok(client) => client,
        Err(obs) => {
            // Typed category survives even when no Client handle is returned.
            diag_with_closure(
                config_dir,
                "bootstrap_err",
                Some("Bootstrap"),
                None,
                Some(obs.status),
                None,
            );
            return Err(obs.error.to_string());
        }
    };
    attach_closure_sink(&client, config_dir);
    client.remember_node_pins(config_dir);
    client.remember_grants(config_dir);
    client.remember_session(config_dir);
    Ok(Some((
        Arc::new(client),
        user.unwrap_or_else(|| "signed in".into()),
    )))
}

async fn sign_in(
    config_dir: &std::path::Path,
    username: &str,
    password: &str,
    totp: &str,
    relay: &str,
    pin: &str,
    trust: &str,
) -> Result<(Arc<Client>, String), String> {
    let identity = Identity::load_or_create(&config_dir.join("identity.json"))
        .map_err(|err| err.to_string())?;
    let mut relay = relay.trim().to_string();
    if relay.is_empty() {
        return Err("relay URL missing (enter a relay or set AGENTLINK_RELAY)".into());
    }
    let pin = pin.trim();
    let mut trust = if trust.trim().is_empty() {
        None
    } else {
        Some(trust.trim().to_string())
    };
    apply_relay_defaults(&mut relay, pin, &mut trust);
    let parsed = RelayTrust::parse(pin, trust.as_deref()).map_err(|err| err.to_string())?;
    let totp = {
        let code = totp.trim();
        if code.is_empty() {
            None
        } else {
            Some(code)
        }
    };
    let session = login_user(
        &relay,
        &parsed.fingerprint_value(),
        parsed.trust_value().as_deref(),
        &identity,
        username.trim(),
        password,
        totp,
        "desktop",
    )
    .await
    .map_err(|err| err.to_string())?;
    let settings = ClientSettings {
        relay,
        token: session.access_token.clone(),
        fingerprint: parsed.fingerprint_value(),
        trust: parsed.trust_value(),
    };
    agentlink_core::config::save_session(
        config_dir,
        &settings,
        &session.user,
        &session.refresh_token,
        session.access_expires_unix,
    )
    .map_err(|err| err.to_string())?;
    let client = match Client::connect_identity_observed(&settings, identity, true).await {
        Ok(client) => client,
        Err(obs) => {
            diag_with_closure(
                config_dir,
                "bootstrap_err",
                Some("Bootstrap"),
                None,
                Some(obs.status),
                None,
            );
            return Err(obs.error.to_string());
        }
    };
    attach_closure_sink(&client, config_dir);
    client.remember_node_pins(config_dir);
    client.remember_grants(config_dir);
    client.remember_session(config_dir);
    Ok((Arc::new(client), session.user))
}

fn settings_of(file: &agentlink_core::config::FileConfig) -> Option<ClientSettings> {
    let token = file.token.clone().filter(|token| !token.is_empty())?;
    let mut relay = file.relay.clone().unwrap_or_default();
    let fingerprint = file.fingerprint.clone().unwrap_or_default();
    let mut trust = file.trust.clone();
    apply_relay_defaults(&mut relay, &fingerprint, &mut trust);
    if relay.is_empty() {
        return None;
    }
    Some(ClientSettings {
        relay,
        token,
        fingerprint,
        trust,
    })
}

#[cfg(test)]
mod live_pipeline_tests {
    use super::*;
    use agentlink_core::{NodeExtension, NodePolicy};
    use agentlink_desktop::{ConsentMode, Desktop, StreamHandler, StreamSettings};
    use agentlink_view::IceFault;
    use serde_json::json;
    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
    use std::thread;
    use std::time::{Duration, Instant};

    struct NodeSignal {
        handler: Arc<StreamHandler>,
    }

    impl Signal for NodeSignal {
        fn signal(&self, payload: &Value) -> Result<Value, String> {
            self.handler.handle_peer(payload, "desktop-test")
        }
    }

    struct DenySignal;

    impl Signal for DenySignal {
        fn signal(&self, _payload: &Value) -> Result<Value, String> {
            Err("not allowed: missing grant".into())
        }
    }

    fn encode_jpeg(seq: u32) -> Vec<u8> {
        let mut img = image::RgbImage::new(16, 16);
        let v = (seq % 200 + 20) as u8;
        for px in img.pixels_mut() {
            *px = image::Rgb([v, 40, 80]);
        }
        let mut out = Vec::new();
        let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 70);
        enc.encode(img.as_raw(), 16, 16, image::ExtendedColorType::Rgb8)
            .expect("jpeg encode");
        out
    }

    fn jpeg_source() -> (
        Arc<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>,
        Arc<AtomicU32>,
    ) {
        let seq = Arc::new(AtomicU32::new(0));
        let tick = Arc::clone(&seq);
        let grab = Arc::new(move || {
            let n = tick.fetch_add(1, AtomicOrdering::Relaxed) + 1;
            Ok(encode_jpeg(n))
        });
        (grab, seq)
    }

    fn mock_handler() -> Arc<StreamHandler> {
        let handler = Arc::new(StreamHandler::new(Desktop::mock()));
        handler.configure(StreamSettings {
            policy: NodePolicy::remote_view(),
            audit_path: std::env::temp_dir().join("agentlink-t449-live-harness.log"),
            consent: ConsentMode::Auto,
            on_audit: None,

            grant_active: None,
        });
        handler
    }

    #[derive(Debug)]
    struct HudSnap {
        kind: String,
        path: String,
        note: String,
        fps: f32,
    }

    struct Harness {
        runtime: tokio::runtime::Runtime,
        shared: Arc<Shared>,
        started: Option<Started>,
        last: Option<Picture>,
        last_hud: Option<HudSnap>,
        hud_history: Vec<(String, String, f32)>,
        notices: Vec<String>,
        failed: Vec<String>,
        links: Vec<String>,
        handshakes: Vec<String>,
    }

    impl Harness {
        fn start(
            signal: Arc<dyn Signal>,
            jpeg: Arc<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>,
            ice_fault: IceFault,
        ) -> Self {
            Self::start_scheduled(signal, jpeg, LiveSchedule::once(), {
                let fault = ice_fault;
                Arc::new(move |_| fault.clone())
            })
        }

        fn start_scheduled(
            signal: Arc<dyn Signal>,
            jpeg: Arc<dyn Fn() -> Result<Vec<u8>, String> + Send + Sync>,
            schedule: LiveSchedule,
            ice_fault_for: Arc<dyn Fn(u32) -> IceFault + Send + Sync>,
        ) -> Self {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("t449-live-harness")
                .build()
                .expect("runtime");
            let _enter = runtime.enter();
            let shared = Arc::new(Shared::new());
            let started = start_live_from(
                signal,
                JpegSource::Injected(jpeg),
                false,
                0,
                60,
                1.0,
                15,
                Arc::clone(&shared),
                Duration::from_millis(50),
                schedule,
                ice_fault_for,
            );
            Self {
                runtime,
                shared,
                started: Some(started),
                last: None,
                last_hud: None,
                hud_history: Vec::new(),
                notices: Vec::new(),
                failed: Vec::new(),
                links: Vec::new(),
                handshakes: Vec::new(),
            }
        }

        fn pump(&mut self) {
            if let Some(pic) = self.shared.latest_picture() {
                self.last = Some(pic);
            }
            for ev in self.shared.drain() {
                match ev {
                    UiEvent::Hud(hud) => {
                        self.hud_history
                            .push((hud.kind.clone(), hud.path.clone(), hud.fps));
                        self.last_hud = Some(HudSnap {
                            kind: hud.kind.clone(),
                            path: hud.path.clone(),
                            note: hud.path_note.clone(),
                            fps: hud.fps,
                        });
                    }
                    UiEvent::Handshake(text) => self.handshakes.push(text),
                    UiEvent::Notice(text) => self.notices.push(text),
                    UiEvent::Failed(text) => self.failed.push(text),
                    UiEvent::Link(text) => self.links.push(text),
                    _ => {}
                }
            }
        }

        fn wait_picture(&mut self, kind: &str, timeout: Duration) -> Picture {
            let deadline = Instant::now() + timeout;
            loop {
                self.pump();
                if let Some(pic) = self.last.clone() {
                    if pic.kind == kind {
                        return pic;
                    }
                }
                if Instant::now() >= deadline {
                    panic!(
                        "timed out waiting for {kind} picture (last={:?} hud={:?} notices={:?} failed={:?} links={:?})",
                        self.last.as_ref().map(|p| format!("{} · {} #{}", p.kind, p.path, p.seq)),
                        self.last_hud,
                        self.notices,
                        self.failed,
                        self.links
                    );
                }
                thread::sleep(Duration::from_millis(20));
            }
        }

        fn wait_hud(&mut self, kind: &str, path: &str, timeout: Duration) {
            let deadline = Instant::now() + timeout;
            loop {
                self.pump();
                if let Some(hud) = &self.last_hud {
                    if hud.kind == kind && hud.path == path {
                        return;
                    }
                }
                if Instant::now() >= deadline {
                    panic!(
                        "timed out waiting for hud {kind} · {path} (hud={:?} last={:?} notices={:?} failed={:?})",
                        self.last_hud,
                        self.last.as_ref().map(|p| format!("{} · {}", p.kind, p.path)),
                        self.notices,
                        self.failed
                    );
                }
                thread::sleep(Duration::from_millis(20));
            }
        }

        fn close_node(&self, handler: &StreamHandler) {
            let session_id = self
                .started
                .as_ref()
                .and_then(|s| s.live.viewer.lock().ok())
                .and_then(|slot| slot.as_ref().map(|v| v.info().session_id.clone()))
                .unwrap_or_default();
            if !session_id.is_empty() {
                let _ = handler.handle_peer(
                    &json!({"action": "close", "session_id": session_id}),
                    "desktop-test",
                );
            }
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            if let Some(started) = self.started.take() {
                let _enter = self.runtime.enter();
                started.live.stop.store(true, AtomicOrdering::Relaxed);
                started.shots.abort();
            }
        }
    }

    #[test]
    fn jpeg_stays_visible_when_ice_cannot_connect() {
        let (jpeg, seq) = jpeg_source();
        let mut h = Harness::start(
            Arc::new(NodeSignal {
                handler: mock_handler(),
            }),
            jpeg,
            IceFault::RelayPolicyWithoutTurn,
        );
        let first = h.wait_picture("jpeg", Duration::from_secs(4));
        assert_eq!(first.path, "relay");
        h.wait_hud("jpeg", "relay", Duration::from_secs(2));
        // Real JPEG payload: decoded pixels match the encoder's marker.
        assert_eq!(first.width, 16);
        assert_eq!(first.height, 16);
        assert!(first.rgba.len() == 16 * 16 * 4);
        let first_seq = first.seq;
        // Connect can take several seconds, then the 12s no-pair deadline
        // has to fire before the explicit terminal reason is published.
        let deadline = Instant::now() + Duration::from_secs(25);
        let mut later = first.clone();
        let mut saw_webrtc_fail = false;
        while Instant::now() < deadline {
            h.pump();
            if let Some(pic) = h.last.clone() {
                later = pic;
            }
            if h.notices
                .iter()
                .any(|n| n.contains("JPEG over the relay") || n.contains("Live video is not up"))
                || h.links.iter().any(|l| l == "jpeg · relay")
            {
                saw_webrtc_fail = true;
            }
            if later.seq > first_seq && later.kind == "jpeg" && saw_webrtc_fail {
                break;
            }
            thread::sleep(Duration::from_millis(40));
        }
        assert_eq!(
            later.kind, "jpeg",
            "fallback picture must stay jpeg, got {:?}",
            later
        );
        assert_eq!(later.path, "relay");
        assert!(
            later.seq > first_seq,
            "JPEG frames must keep refreshing after ICE cannot connect (first={} later={})",
            first_seq,
            later.seq
        );
        assert!(
            saw_webrtc_fail,
            "expected a recorded WebRTC/ICE failure notice, got notices={:?} links={:?}",
            h.notices, h.links
        );
        if let Some(hud) = &h.last_hud {
            assert_eq!(hud.path, "relay");
            assert!(hud.note.contains("not WebRTC P2P"), "{}", hud.note);
            assert!(
                hud.fps > 0.05,
                "refreshing JPEG stills must report a measured stills rate, got fps={}",
                hud.fps
            );
            let rate = super::super::chrome::session_stats_rate_line("jpeg", hud.fps);
            assert!(
                rate.starts_with("stills  ") && rate.ends_with(" Hz"),
                "0938-style popover must not show fps  0.0 for refreshing stills, got {rate}"
            );
            assert_ne!(rate, "fps  0.0");
        } else {
            panic!("expected a JPEG HUD after stills kept refreshing");
        }
        assert!(
            h.failed.is_empty(),
            "soft ICE failure must not hard-fail: {:?}",
            h.failed
        );
        assert!(seq.load(AtomicOrdering::Relaxed) >= 2);
        assert!(
            !h.hud_history
                .iter()
                .any(|(k, p, _)| k == "h264" || p == "connecting"),
            "handshake must not pollute the painted media path: {:?}",
            h.hud_history
        );
        assert!(
            h.links.iter().all(|l| l != "h264 · connecting"),
            "link must not be set to h264 · connecting before a decoded frame: {:?}",
            h.links
        );
        assert!(
            !h.handshakes.is_empty(),
            "expected visible webrtc handshake stages, got none"
        );
        let last_hs = h.handshakes.last().cloned().unwrap_or_default();
        assert!(
            last_hs.contains("no selected ICE pair")
                || last_hs.contains("no H.264 frame")
                || last_hs.contains("connection lost")
                || last_hs.contains("webrtc: failed"),
            "terminal handshake must state the failure, not a cleanup ack: {last_hs:?} all={:?}",
            h.handshakes
        );
        assert!(
            h.handshakes.iter().all(|hs| !hs.contains("signal close")),
            "cleanup must not occupy handshake: {:?}",
            h.handshakes
        );
        // Same-host ICE fail is not public NAT evidence.
        eprintln!(
            "t449 harness ice-fail: jpeg seq {} -> {}, hud={:?}, notices={:?}, handshakes={:?}",
            first_seq, later.seq, h.last_hud, h.notices, h.handshakes
        );
    }

    #[test]
    fn jpeg_resumes_after_h264_endpoint_disconnect() {
        let (jpeg, _) = jpeg_source();
        let handler = mock_handler();
        let mut h = Harness::start(
            Arc::new(NodeSignal {
                handler: Arc::clone(&handler),
            }),
            jpeg,
            IceFault::None,
        );
        let jpeg1 = h.wait_picture("jpeg", Duration::from_secs(4));
        assert_eq!(jpeg1.path, "relay");
        h.pump();
        assert!(
            !h.hud_history
                .iter()
                .any(|(k, p, _)| k == "h264" || p == "connecting"),
            "must not publish h264 · connecting over a rendered JPEG path: {:?} handshakes={:?}",
            h.hud_history,
            h.handshakes
        );
        let mut video = h.wait_picture("h264", Duration::from_secs(20));
        // First decoded frame may precede the selected-pair observation
        // (`unknown`). Wait briefly for a classified path; do not require
        // the first frame's path to already be settled.
        let settle = Instant::now() + Duration::from_secs(5);
        while Instant::now() < settle
            && !matches!(
                video.path.as_str(),
                "loopback" | "private" | "host" | "stun"
            )
        {
            h.pump();
            if let Some(pic) = h.last.clone() {
                if pic.kind == "h264" {
                    video = pic;
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            matches!(
                video.path.as_str(),
                "loopback" | "private" | "host" | "stun"
            ),
            "unexpected h264 path {} (hud={:?} handshakes={:?})",
            video.path,
            h.last_hud,
            h.handshakes
        );
        assert_ne!(
            video.path, "relay",
            "h264 must not be labeled as websocket relay"
        );
        assert_ne!(video.path, "tailscale");
        h.wait_hud("h264", &video.path, Duration::from_secs(3));
        let before_drop = video.seq;
        h.close_node(&handler);
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut resumed = None;
        while Instant::now() < deadline {
            h.pump();
            if let Some(pic) = &h.last {
                if pic.kind == "jpeg" && pic.path == "relay" && pic.seq > before_drop {
                    resumed = Some(pic.clone());
                    break;
                }
            }
            thread::sleep(Duration::from_millis(40));
        }
        let resumed = resumed.expect(&format!(
            "JPEG must refresh after H.264 endpoint disconnect (before={before_drop} last={:?} hud={:?} notices={:?} failed={:?})",
            h.last.as_ref().map(|p| format!("{} · {} #{}", p.kind, p.path, p.seq)),
            h.last_hud,
            h.notices,
            h.failed
        ));
        h.wait_hud("jpeg", "relay", Duration::from_secs(2));
        if let Some(hud) = &h.last_hud {
            assert!(hud.note.contains("not WebRTC P2P"), "{}", hud.note);
        }
        assert!(h
            .notices
            .iter()
            .any(|n| n.contains("JPEG over the relay") || n.contains("Live video is not up")));
        assert!(
            h.failed.is_empty(),
            "disconnect fallback must not hard-fail: {:?}",
            h.failed
        );
        eprintln!(
            "t449 harness h264-then-jpeg: h264 {} · {} #{}, resumed jpeg #{}",
            video.kind, video.path, video.seq, resumed.seq
        );
    }

    #[test]
    fn missing_grant_is_rejected_and_does_not_show_p2p() {
        let jpeg = Arc::new(|| Err("not allowed: missing grant".to_string()));
        let mut h = Harness::start(Arc::new(DenySignal), jpeg, IceFault::None);
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && h.failed.is_empty() {
            h.pump();
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            h.failed
                .iter()
                .any(|e| e.to_ascii_lowercase().contains("not allowed")),
            "missing grant must fail, got {:?}",
            h.failed
        );
        if let Some(pic) = &h.last {
            panic!("no-grant session published a picture: {pic:?}");
        }
        if let Some(hud) = &h.last_hud {
            assert_ne!(hud.path, "host");
            assert_ne!(hud.path, "private");
            assert_ne!(hud.kind, "h264");
        }
        eprintln!("t449 harness no-grant: failed={:?}", h.failed);
    }

    #[test]
    fn jpeg_stills_rate_is_measured_from_a_real_sequence() {
        let (jpeg, seq) = jpeg_source();
        let mut h = Harness::start(
            Arc::new(NodeSignal {
                handler: mock_handler(),
            }),
            jpeg,
            IceFault::RelayPolicyWithoutTurn,
        );
        let first = h.wait_picture("jpeg", Duration::from_secs(4));
        assert_eq!(first.kind, "jpeg");
        let deadline = Instant::now() + Duration::from_secs(4);
        let mut later = first.clone();
        while Instant::now() < deadline {
            h.pump();
            if let Some(pic) = h.last.clone() {
                later = pic;
            }
            if later.seq >= first.seq + 4 {
                if let Some(hud) = &h.last_hud {
                    if hud.kind == "jpeg" && hud.fps > 0.05 {
                        break;
                    }
                }
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            later.seq >= first.seq + 4,
            "need a real stills sequence, first={} later={}",
            first.seq,
            later.seq
        );
        let hud = h.last_hud.as_ref().expect("JPEG HUD after stills sequence");
        assert_eq!(hud.kind, "jpeg");
        assert_eq!(hud.path, "relay");
        assert!(
            hud.fps > 0.05,
            "measured stills rate must be > 0 after several JPEGs, got {}",
            hud.fps
        );
        // Harness injects stills every 50ms (~20 Hz). Allow jitter, but
        // reject a zero / near-zero that would display as fps  0.0.
        assert!(
            hud.fps >= 5.0 && hud.fps <= 40.0,
            "stills rate should track the 50ms inject interval, got {} Hz (seq {} -> {}, grabs={})",
            hud.fps,
            first.seq,
            later.seq,
            seq.load(AtomicOrdering::Relaxed)
        );
        let rate = super::super::chrome::session_stats_rate_line("jpeg", hud.fps);
        assert!(
            rate.starts_with("stills  ") && rate.ends_with(" Hz"),
            "popover must show a stills Hz, not fps  0.0: {rate}"
        );
        assert_ne!(rate, "fps  0.0");
        assert_eq!(
            super::super::chrome::session_stats_bitrate_line("jpeg", 0),
            "bitrate  n/a"
        );
        assert_eq!(
            super::super::chrome::session_stats_latency_line("jpeg", 0),
            "latency  n/a"
        );
        eprintln!(
            "t449 harness stills-rate: seq {} -> {}, hud fps={:.1}, line={rate}",
            first.seq, later.seq, hud.fps
        );
    }

    #[test]
    fn negotiation_hud_stays_jpeg_through_offer_answer_wait_timeout_and_close() {
        // 0938 GUI path: JPEG already on screen, offer/answer complete,
        // waiting for a pair, 12s no-pair timeout, then close. The painted
        // path must stay jpeg · relay the whole time; stats must not say
        // H.264 or P2P, and must not show fps  0.0 once stills are measured.
        let (jpeg, _) = jpeg_source();
        let mut h = Harness::start(
            Arc::new(NodeSignal {
                handler: mock_handler(),
            }),
            jpeg,
            IceFault::NoPairAfterSignaling,
        );
        let first = h.wait_picture("jpeg", Duration::from_secs(4));
        assert_eq!(first.path, "relay");
        h.wait_hud("jpeg", "relay", Duration::from_secs(2));

        let mut saw_offer = false;
        let mut saw_answer = false;
        let mut saw_waiting = false;
        let mut saw_timeout = false;
        // Connect + 12s no-pair deadline, plus slack for logging/close.
        let deadline = Instant::now() + Duration::from_secs(25);
        while Instant::now() < deadline {
            h.pump();
            for hs in &h.handshakes {
                let lower = hs.to_ascii_lowercase();
                if lower.contains("sending webrtc offer")
                    || lower.contains("signal offer")
                    || lower.contains("local offer")
                {
                    saw_offer = true;
                }
                if lower.contains("offer answered") || lower.contains("applying remote answer") {
                    saw_answer = true;
                }
                if lower.contains("waiting for ice pair") {
                    saw_waiting = true;
                }
                if lower.contains("no selected ice pair") {
                    saw_timeout = true;
                }
            }
            if saw_timeout {
                break;
            }
            // Mid-negotiation: already-rendered JPEG must not be overwritten
            // by a speculative h264 / connecting / P2P HUD.
            assert!(
                !h.hud_history
                    .iter()
                    .any(|(k, p, _)| k == "h264" || p == "connecting"),
                "HUD must stay off h264/connecting during negotiation: {:?} handshakes={:?}",
                h.hud_history,
                h.handshakes
            );
            assert!(
                h.links
                    .iter()
                    .all(|l| l != "h264 · connecting" && !l.to_ascii_lowercase().contains("h264")),
                "link must not claim H.264 before a decoded frame: {:?}",
                h.links
            );
            if let Some(pic) = &h.last {
                assert_eq!(
                    pic.kind, "jpeg",
                    "picture flipped off JPEG mid-negotiation: {pic:?}"
                );
                assert_eq!(pic.path, "relay");
            }
            thread::sleep(Duration::from_millis(40));
        }
        assert!(
            saw_offer,
            "expected an offer stage, handshakes={:?}",
            h.handshakes
        );
        assert!(
            saw_answer,
            "expected an answered offer, handshakes={:?}",
            h.handshakes
        );
        assert!(
            saw_waiting,
            "expected waiting for ICE pair / video, handshakes={:?}",
            h.handshakes
        );
        assert!(
            saw_timeout,
            "expected 12s no-selected-pair terminal reason, handshakes={:?}",
            h.handshakes
        );
        let last_hs = h.handshakes.last().cloned().unwrap_or_default();
        assert!(
            last_hs.contains("no selected ICE pair"),
            "terminal handshake must keep the no-pair reason: {last_hs:?} all={:?}",
            h.handshakes
        );
        assert!(
            h.handshakes.iter().all(|hs| !hs.contains("signal close")),
            "cleanup must not occupy handshake: {:?}",
            h.handshakes
        );
        let hud = h.last_hud.as_ref().expect("HUD after timeout");
        assert_eq!(hud.kind, "jpeg");
        assert_eq!(hud.path, "relay");
        assert!(hud.note.contains("not WebRTC P2P"), "{}", hud.note);
        assert!(
            hud.fps > 0.05,
            "stills were refreshing through the timeout; rate must be measured, got {}",
            hud.fps
        );
        let rate = super::super::chrome::session_stats_rate_line("jpeg", hud.fps);
        assert_ne!(rate, "fps  0.0");
        assert!(rate.starts_with("stills  "), "{rate}");

        // Close the live session the same way the controller does on exit.
        if let Some(started) = h.started.take() {
            let _enter = h.runtime.enter();
            started.live.stop.store(true, AtomicOrdering::Relaxed);
            started.shots.abort();
            if let Ok(slot) = started.live.viewer.lock() {
                if let Some(viewer) = slot.as_ref() {
                    viewer.close();
                }
            }
        }
        // Allow close acks to drain; handshake must stay on the terminal reason.
        let settle = Instant::now() + Duration::from_secs(2);
        while Instant::now() < settle {
            h.pump();
            thread::sleep(Duration::from_millis(20));
        }
        let last_hs = h.handshakes.last().cloned().unwrap_or_default();
        assert!(
            last_hs.contains("no selected ICE pair"),
            "close must not overwrite the terminal no-pair reason: {last_hs:?} all={:?}",
            h.handshakes
        );
        assert!(
            !h.hud_history
                .iter()
                .any(|(k, p, _)| k == "h264" || p == "connecting"),
            "close must not publish h264/connecting: {:?}",
            h.hud_history
        );
        if let Some(pic) = &h.last {
            assert_eq!(pic.kind, "jpeg");
            assert_eq!(pic.path, "relay");
        }
        eprintln!(
            "t449 harness negotiation-lifecycle: last_hs={last_hs:?} hud={:?} fps={:.1} stills_line={rate} pictures={} notices={:?}",
            h.last_hud.as_ref().map(|h| format!("{} · {}", h.kind, h.path)),
            h.last_hud.as_ref().map(|h| h.fps).unwrap_or(0.0),
            h.last.as_ref().map(|p| p.seq).unwrap_or(0),
            h.notices
        );
    }

    fn short_retry_schedule() -> LiveSchedule {
        LiveSchedule {
            attempt_max: 3,
            ice_wait: Duration::from_millis(800),
            backoff: vec![Duration::from_millis(80), Duration::from_millis(80)],
            offer_budget: 3,
        }
    }

    fn offer_sent_count(h: &Harness) -> usize {
        h.handshakes
            .iter()
            .filter(|hs| hs.contains("sending webrtc offer"))
            .count()
    }

    #[test]
    fn jpeg_retries_then_recovers_h264_without_claiming_p2p_early() {
        let (jpeg, _) = jpeg_source();
        let mut h = Harness::start_scheduled(
            Arc::new(NodeSignal {
                handler: mock_handler(),
            }),
            jpeg,
            short_retry_schedule(),
            Arc::new(|n| {
                if n < 3 {
                    IceFault::NoPairAfterSignaling
                } else {
                    IceFault::None
                }
            }),
        );
        let first = h.wait_picture("jpeg", Duration::from_secs(4));
        assert_eq!(first.path, "relay");
        // Wait through two short no-pair attempts and a third real connect.
        let deadline = Instant::now() + Duration::from_secs(25);
        let mut video = None;
        while Instant::now() < deadline {
            h.pump();
            if let Some(pic) = &h.last {
                if pic.kind == "h264" {
                    video = Some(pic.clone());
                    break;
                }
            }
            // Mid-retry the painted path must stay JPEG / not a fake P2P claim.
            if video.is_none() {
                if let Some(pic) = &h.last {
                    assert_eq!(
                        pic.kind, "jpeg",
                        "must keep JPEG until a real frame: {pic:?}"
                    );
                    assert_eq!(pic.path, "relay");
                }
                assert!(
                    !h.hud_history
                        .iter()
                        .any(|(k, p, _)| k == "h264" || p == "connecting"),
                    "retry attempts must not publish h264/connecting: {:?} hs={:?}",
                    h.hud_history,
                    h.handshakes
                );
            }
            thread::sleep(Duration::from_millis(30));
        }
        let video =
            video.expect(&format!(
            "third attempt should take over with H.264, last={:?} hud={:?} hs={:?} notices={:?}",
            h.last.as_ref().map(|p| format!("{} · {} #{}", p.kind, p.path, p.seq)),
            h.last_hud,
            h.handshakes,
            h.notices
        ));
        assert_ne!(video.path, "relay", "recovered H.264 is not the JPEG relay");
        assert_ne!(video.path, "tailscale");
        assert!(
            offer_sent_count(&h) >= 3,
            "expected three offers (two misses + recover), got {} hs={:?}",
            offer_sent_count(&h),
            h.handshakes
        );
        assert!(
            offer_sent_count(&h) <= 6,
            "must not hammer the node: {}",
            offer_sent_count(&h)
        );
        assert!(
            h.handshakes
                .iter()
                .any(|hs| hs.contains("starting attempt") || hs.contains("retry in")),
            "retry progress should be visible: {:?}",
            h.handshakes
        );
        assert!(
            h.failed.is_empty(),
            "recovery must not hard-fail: {:?}",
            h.failed
        );
        eprintln!(
            "t450 harness retry-recover: jpeg #{} then {} · {} #{}, offers={} hs_last={:?}",
            first.seq,
            video.kind,
            video.path,
            video.seq,
            offer_sent_count(&h),
            h.handshakes.last()
        );
    }

    #[test]
    fn exhausted_retries_keep_jpeg_release_viewer_and_stop() {
        let (jpeg, seq) = jpeg_source();
        let mut h = Harness::start_scheduled(
            Arc::new(NodeSignal {
                handler: mock_handler(),
            }),
            jpeg,
            short_retry_schedule(),
            Arc::new(|_| IceFault::NoPairAfterSignaling),
        );
        let first = h.wait_picture("jpeg", Duration::from_secs(4));
        let deadline = Instant::now() + Duration::from_secs(20);
        let mut terminal = None;
        while Instant::now() < deadline {
            h.pump();
            if let Some(hs) = h
                .handshakes
                .iter()
                .rev()
                .find(|hs| hs.contains("stopped after") && hs.contains("no selected ICE pair"))
            {
                terminal = Some(hs.clone());
                break;
            }
            if let Some(pic) = &h.last {
                assert_eq!(pic.kind, "jpeg");
                assert_eq!(pic.path, "relay");
            }
            thread::sleep(Duration::from_millis(30));
        }
        let terminal = terminal.expect(&format!(
            "expected terminal after 3 attempts, hs={:?} notices={:?}",
            h.handshakes, h.notices
        ));
        assert!(
            !h.hud_history.iter().any(|(k, _, _)| k == "h264"),
            "exhausted retries must not claim H.264: {:?}",
            h.hud_history
        );
        let offers = offer_sent_count(&h);
        assert_eq!(
            offers, 3,
            "offer budget is 3, got {offers} hs={:?}",
            h.handshakes
        );
        // Resource release: the attempt viewer must be closed and dropped.
        if let Some(started) = &h.started {
            let slot = started
                .live
                .viewer
                .lock()
                .unwrap_or_else(|err| err.into_inner());
            assert!(
                slot.is_none(),
                "viewer slot must be released after the last attempt"
            );
        }
        assert!(
            seq.load(AtomicOrdering::Relaxed) >= 2,
            "JPEG stills must keep refreshing after retries stop"
        );
        assert!(first.seq >= 1);
        eprintln!(
            "t450 harness retry-exhausted: terminal={terminal:?} offers={offers} jpeg_seq={}",
            seq.load(AtomicOrdering::Relaxed)
        );
    }

    #[test]
    fn missing_grant_does_not_spend_retry_budget() {
        let jpeg = Arc::new(|| Err("not allowed: missing grant".to_string()));
        let mut h = Harness::start_scheduled(
            Arc::new(DenySignal),
            jpeg,
            short_retry_schedule(),
            Arc::new(|_| IceFault::None),
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline && h.failed.is_empty() {
            h.pump();
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            h.failed
                .iter()
                .any(|e| e.to_ascii_lowercase().contains("not allowed")),
            "missing grant must fail, got {:?}",
            h.failed
        );
        assert_eq!(
            offer_sent_count(&h),
            0,
            "hard reject must not send renegotiation offers: {:?}",
            h.handshakes
        );
        assert!(
            h.handshakes
                .iter()
                .all(|hs| !hs.contains("starting attempt 2") && !hs.contains("retry in")),
            "must not retry a missing grant: {:?}",
            h.handshakes
        );
        if let Some(pic) = &h.last {
            panic!("no-grant session published a picture: {pic:?}");
        }
        eprintln!(
            "t450 harness no-grant-no-retry: failed={:?} hs={:?}",
            h.failed, h.handshakes
        );
    }
}

#[cfg(test)]
mod handshake_retention_tests {
    use super::{
        handshake_is_cleanup, live_retry_backoff, stills_rate_hz, LiveSchedule, Shared, UiEvent,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn stills_rate_hz_needs_a_real_span_and_does_not_invent_zero() {
        assert_eq!(stills_rate_hz(&[]), None);
        let t0 = Instant::now();
        assert_eq!(stills_rate_hz(&[t0]), None);
        assert_eq!(stills_rate_hz(&[t0, t0]), None);
        let t1 = t0 + Duration::from_millis(800);
        let t2 = t0 + Duration::from_millis(1600);
        let hz = stills_rate_hz(&[t0, t1, t2]).expect("three 800ms stills");
        assert!(
            (hz - 1.25).abs() < 0.01,
            "800ms stills should be 1.25 Hz, got {hz}"
        );
    }

    #[test]
    fn live_retry_backoff_is_bounded_and_does_not_run_forever() {
        let schedule = LiveSchedule::default();
        assert_eq!(schedule.attempt_max, 3);
        assert_eq!(schedule.offer_budget, 6);
        assert_eq!(live_retry_backoff(&schedule, 0), None);
        assert_eq!(
            live_retry_backoff(&schedule, 1),
            Some(Duration::from_secs(3))
        );
        assert_eq!(
            live_retry_backoff(&schedule, 2),
            Some(Duration::from_secs(6))
        );
        assert_eq!(live_retry_backoff(&schedule, 3), None);
        assert_eq!(live_retry_backoff(&schedule, 10), None);
        let once = LiveSchedule::once();
        assert_eq!(once.attempt_max, 1);
        assert_eq!(live_retry_backoff(&once, 1), None);
    }

    #[test]
    fn cleanup_and_keyframe_acks_do_not_count_as_handshake_progress() {
        assert!(handshake_is_cleanup("signal close sent"));
        assert!(handshake_is_cleanup("signal close ok 1098ms"));
        assert!(handshake_is_cleanup("signal keyframe ok 474ms"));
        assert!(handshake_is_cleanup("signal ice sent"));
        assert!(handshake_is_cleanup("signal ice ok 631ms"));
        assert!(!handshake_is_cleanup(
            "signaling complete, waiting for ICE pair / video"
        ));
        assert!(!handshake_is_cleanup("signal offer ok 2241ms sdp_len=2308"));
        assert!(!handshake_is_cleanup(
            "signal offer error 25000ms: webrtc_signal timed out"
        ));
        assert!(!handshake_is_cleanup(
            "webrtc: no selected ICE pair within 12s; JPEG stills remain"
        ));
    }

    #[test]
    fn close_ok_does_not_overwrite_terminal_negotiation_failure() {
        // Real 0910 GUI sequence: offer/answer, wait for pair/video,
        // keyframes, fallback notice, then signal close ok 1098ms which
        // previously replaced the stats handshake.
        let shared = Shared::new();
        shared.begin_handshake();
        shared.set_handshake("webrtc: starting");
        shared.set_handshake("list_monitors ok");
        shared.set_handshake("sending webrtc offer");
        shared.set_handshake("signal offer ok 2241ms sdp_len=2308 session_len=78");
        shared.set_handshake("signaling complete, waiting for ICE pair / video");
        shared.set_handshake("signal keyframe sent");
        shared.set_handshake("signal keyframe ok 1267ms");
        let reason = "webrtc: no selected ICE pair within 12s; JPEG stills remain";
        shared.set_handshake_terminal(reason);
        shared.set_handshake("signal close sent");
        shared.set_handshake("signal close ok 1098ms");
        let stages: Vec<String> = shared
            .drain()
            .into_iter()
            .filter_map(|ev| match ev {
                UiEvent::Handshake(text) => Some(text),
                _ => None,
            })
            .collect();
        assert!(
            stages.iter().any(|s| s == reason),
            "terminal reason missing: {stages:?}"
        );
        assert_eq!(
            stages.last().map(String::as_str),
            Some(reason),
            "close must not overwrite the terminal reason, got {stages:?}"
        );
        assert!(
            stages.iter().all(|s| !s.contains("signal close")),
            "cleanup stages must not appear in the handshake HUD: {stages:?}"
        );
        assert!(
            stages
                .iter()
                .all(|s| !s.starts_with("signal keyframe") && !s.starts_with("signal ice ")),
            "routine ice/keyframe acks must not occupy handshake: {stages:?}"
        );
    }

    #[test]
    fn next_attempt_can_replace_a_previous_terminal_reason() {
        let shared = Shared::new();
        shared
            .set_handshake_terminal("webrtc: no selected ICE pair within 12s; JPEG stills remain");
        shared.begin_handshake();
        shared.set_handshake("webrtc: starting");
        let stages: Vec<String> = shared
            .drain()
            .into_iter()
            .filter_map(|ev| match ev {
                UiEvent::Handshake(text) => Some(text),
                _ => None,
            })
            .collect();
        assert_eq!(stages.last().map(String::as_str), Some("webrtc: starting"));
    }
}

#[cfg(test)]
mod worker_client_recovery_tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};
    use std::sync::Mutex;

    struct FakeClient {
        id: u32,
        alive: AtomicBool,
        lists: Mutex<Vec<Result<Vec<MonitorEntry>, String>>>,
    }

    impl FakeClient {
        fn alive(id: u32, lists: Vec<Result<Vec<MonitorEntry>, String>>) -> Arc<Self> {
            Arc::new(Self {
                id,
                alive: AtomicBool::new(true),
                lists: Mutex::new(lists),
            })
        }

        fn dead(id: u32) -> Arc<Self> {
            Arc::new(Self {
                id,
                alive: AtomicBool::new(false),
                lists: Mutex::new(Vec::new()),
            })
        }

        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::SeqCst)
        }

        fn list_monitors(&self) -> Result<Vec<MonitorEntry>, String> {
            let mut q = self.lists.lock().expect("lists");
            if q.is_empty() {
                return Err("connection closed".into());
            }
            q.remove(0)
        }
    }

    fn sample_monitor() -> MonitorEntry {
        MonitorEntry {
            index: 0,
            name: "Display".into(),
            width: 1280,
            height: 720,
            primary: true,
            capturable: Some(true),
            reason: None,
        }
    }

    #[test]
    fn replace_slot_keeps_alive_unless_forced() {
        let mut slot = Some(FakeClient::alive(1, Vec::new()));
        let kept = replace_worker_client_slot(&mut slot, false, FakeClient::is_alive)
            .expect("alive client");
        assert_eq!(kept.id, 1);
        assert!(slot.is_some());

        let forced = replace_worker_client_slot(&mut slot, true, FakeClient::is_alive);
        assert!(forced.is_none());
        assert!(slot.is_none());
    }

    #[test]
    fn replace_slot_clears_dead_client() {
        let mut slot = Some(FakeClient::dead(7));
        assert!(replace_worker_client_slot(&mut slot, false, FakeClient::is_alive).is_none());
        assert!(slot.is_none());
    }

    #[tokio::test]
    async fn closed_client_rebootstrap_retries_list_once() {
        let connects = Arc::new(AtomicU32::new(0));
        let mut slot: Option<Arc<FakeClient>> =
            Some(FakeClient::alive(1, vec![Err("connection closed".into())]));
        let connects_ensure = Arc::clone(&connects);
        let out = list_monitors_with_once_rebootstrap(
            &mut slot,
            "workstation",
            |slot, force| {
                let connects = Arc::clone(&connects_ensure);
                Box::pin(async move {
                    if let Some(current) =
                        replace_worker_client_slot(slot, force, FakeClient::is_alive)
                    {
                        return Ok(current);
                    }
                    let n = connects.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                    let next = FakeClient::alive(n + 1, vec![Ok(vec![sample_monitor()])]);
                    *slot = Some(Arc::clone(&next));
                    Ok(next)
                })
            },
            |current, _node| Box::pin(async move { current.list_monitors() }),
        )
        .await
        .expect("recovered");
        assert!(out.reconnected);
        assert_eq!(out.monitors.len(), 1);
        assert_eq!(connects.load(AtomicOrdering::SeqCst), 1);
        assert_eq!(slot.as_ref().map(|c| c.id), Some(2));
    }

    #[tokio::test]
    async fn grant_deny_does_not_spend_rebootstrap() {
        let connects = Arc::new(AtomicU32::new(0));
        let mut slot: Option<Arc<FakeClient>> = Some(FakeClient::alive(
            1,
            vec![Err("not allowed: missing grant".into())],
        ));
        let connects_ensure = Arc::clone(&connects);
        let err = list_monitors_with_once_rebootstrap(
            &mut slot,
            "workstation",
            |slot, force| {
                let connects = Arc::clone(&connects_ensure);
                Box::pin(async move {
                    if let Some(current) =
                        replace_worker_client_slot(slot, force, FakeClient::is_alive)
                    {
                        return Ok(current);
                    }
                    connects.fetch_add(1, AtomicOrdering::SeqCst);
                    Err("should not reconnect on grant deny".into())
                })
            },
            |current, _node| Box::pin(async move { current.list_monitors() }),
        )
        .await
        .expect_err("grant deny stays fatal");
        assert!(err.contains("not allowed"), "{err}");
        assert_eq!(connects.load(AtomicOrdering::SeqCst), 0);
        assert_eq!(slot.as_ref().map(|c| c.id), Some(1));
    }

    #[tokio::test]
    async fn second_closed_list_fails_without_another_bootstrap() {
        let connects = Arc::new(AtomicU32::new(0));
        let mut slot: Option<Arc<FakeClient>> =
            Some(FakeClient::alive(1, vec![Err("connection closed".into())]));
        let connects_ensure = Arc::clone(&connects);
        let err = list_monitors_with_once_rebootstrap(
            &mut slot,
            "workstation",
            |slot, force| {
                let connects = Arc::clone(&connects_ensure);
                Box::pin(async move {
                    if let Some(current) =
                        replace_worker_client_slot(slot, force, FakeClient::is_alive)
                    {
                        return Ok(current);
                    }
                    let n = connects.fetch_add(1, AtomicOrdering::SeqCst) + 1;
                    let next = FakeClient::alive(n + 1, vec![Err("connection closed".into())]);
                    *slot = Some(Arc::clone(&next));
                    Ok(next)
                })
            },
            |current, _node| Box::pin(async move { current.list_monitors() }),
        )
        .await
        .expect_err("bounded once");
        assert_eq!(err, "connection closed");
        assert_eq!(
            connects.load(AtomicOrdering::SeqCst),
            1,
            "must not loop saved_client forever"
        );
    }
}
