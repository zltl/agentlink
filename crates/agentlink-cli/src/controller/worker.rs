//! Account, shell, files, and desktop session on one client runtime.
//!
//! Signaling uses [`agentlink_view::Viewer`], the same offerer the Android
//! app uses. The window thread only receives events and pictures.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentlink_core::client::{login_user, maintain_session};
use agentlink_core::{
    apply_relay_defaults, parse_access, Client, ClientSettings, DirEntry, Identity, NodeInfo, Op,
    PtyEvent, PtySession, RelayTrust, PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT, PHASE3_WEBRTC_SIGNAL,
};
use agentlink_view::{is_screenshot_fallback, IceFault, LiveOptions, Signal, Viewer};
use base64::Engine;
use serde_json::{json, Value};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::decode::{decode_image, H264Decoder};
use super::model::enroll_command;

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
    },
    LiveStop,
    Input {
        node: String,
        live: String,
        inject: String,
    },
    Monitors {
        node: String,
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
                Cmd::Bootstrap => match saved_client(&config_dir).await {
                    Ok(Some((next, user))) => {
                        client = Some(next);
                        shared.push(UiEvent::Ready { user: Some(user) });
                        refresh(client.as_ref(), &shared).await;
                    }
                    Ok(None) => shared.push(UiEvent::Ready { user: None }),
                    Err(err) => {
                        shared.push(UiEvent::Ready { user: None });
                        shared.push(UiEvent::Failed(err));
                    }
                },
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
                Cmd::Refresh => refresh(client.as_ref(), &shared).await,
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
                } => {
                    stop_live(&mut live, &mut shots);
                    let Some(current) = client.clone() else {
                        shared.push(UiEvent::Failed("Sign in first.".into()));
                        continue;
                    };
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
                } => {
                    let sent = live
                        .as_ref()
                        .and_then(|session| session.viewer.lock().ok())
                        .and_then(|slot| slot.clone())
                        .is_some_and(|viewer| viewer.send_control(&body));
                    if !sent {
                        if let Some(current) = &client {
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
                }
                Cmd::Monitors { node } => match client.as_ref() {
                    Some(current) => match list_monitors(current, &node).await {
                        Ok(monitors) => shared.push(UiEvent::Monitors(monitors)),
                        Err(err) => shared.push(UiEvent::Failed(err)),
                    },
                    None => shared.push(UiEvent::Failed("Sign in first.".into())),
                },
                Cmd::Clipboard { node, text } => {
                    let body = json!({"type": "clipboard", "text": text}).to_string();
                    let sent = live
                        .as_ref()
                        .and_then(|session| session.viewer.lock().ok())
                        .and_then(|slot| slot.clone())
                        .is_some_and(|viewer| viewer.send_control(&body));
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
        IceFault::None,
        Duration::from_millis(800),
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
    ice_fault: IceFault,
    shot_interval: Duration,
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
            let opts = LiveOptions {
                viewer: "desktop".into(),
                control,
                monitor,
                max_fps,
                bitrate,
                scale,
                ice_fault,
                on_stage: Some(on_stage),
                ..LiveOptions::default()
            };
            thread_shared.begin_handshake();
            thread_shared.set_handshake("webrtc: starting");
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
                    thread_shared.set_handshake_terminal(format!("webrtc: failed ({err})"));
                    // Keep JPEG bootstrap for soft failures, but surface hard rejects.
                    if super::model::webrtc_connect_is_hard_reject(&err) {
                        thread_stop.store(true, Ordering::Relaxed);
                        thread_shared.push(UiEvent::Failed(err));
                        return;
                    }
                    thread_shared.push(UiEvent::Notice(format!(
                        "Live video is not up ({err}). Showing JPEG over the relay."
                    )));
                    thread_shared.push(UiEvent::Link("jpeg · relay".into()));
                    thread_shared.set_hud(LiveHud {
                        path: "relay".into(),
                        kind: "jpeg".into(),
                        encoder: "jpeg".into(),
                        path_note: super::model::connection_path_hint("jpeg", "relay").into(),
                        ..LiveHud::default()
                    });
                    let _ = control;
                    return;
                }
            };
            if let Ok(mut slot) = thread_viewer.lock() {
                *slot = Some(Arc::clone(&viewer));
            }
            let info = viewer.info();
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
            const ICE_WAIT: Duration = Duration::from_secs(12);
            let ice_deadline = Instant::now() + ICE_WAIT;
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
            while !thread_stop.load(Ordering::Relaxed) {
                let Some(frame) = viewer.poll_frame(Duration::from_millis(50)) else {
                    if viewer.failed() {
                        // Direct video dropped (before or after the first
                        // H.264 frame). Resume JPEG stills over the relay.
                        if super::model::webrtc_loss_keeps_jpeg(saw_frame) {
                            thread_h264.store(false, Ordering::Relaxed);
                            thread_shared.set_handshake_terminal(
                                "webrtc: connection lost; JPEG stills remain".to_string(),
                            );
                            thread_shared.push(UiEvent::Notice(
                                "WebRTC live video is not up. Showing JPEG over the relay."
                                    .into(),
                            ));
                            thread_shared.push(UiEvent::Link("jpeg · relay".into()));
                            thread_shared.set_hud(LiveHud {
                                path: "relay".into(),
                                kind: "jpeg".into(),
                                encoder: "jpeg".into(),
                                path_note: super::model::connection_path_hint("jpeg", "relay")
                                    .into(),
                                ..LiveHud::default()
                            });
                            break;
                        }
                        thread_shared.push(UiEvent::Failed("WebRTC connection failed".into()));
                        break;
                    }
                    if !saw_frame && Instant::now() >= ice_deadline {
                        let has_pair = viewer
                            .transport()
                            .is_some();
                        let reason = if has_pair {
                            "webrtc: no H.264 frame within 12s after a selected ICE pair; JPEG stills remain"
                        } else {
                            "webrtc: no selected ICE pair within 12s; JPEG stills remain"
                        };
                        let checks = viewer.ice_checks();
                        if !checks.is_empty() {
                            eprintln!("agentlink live-ice: timeout snapshot {checks}");
                        }
                        thread_h264.store(false, Ordering::Relaxed);
                        thread_shared.set_handshake_terminal(reason);
                        thread_shared.push(UiEvent::Notice(
                            "WebRTC live video is not up. Showing JPEG over the relay."
                                .into(),
                        ));
                        thread_shared.push(UiEvent::Link("jpeg · relay".into()));
                        thread_shared.set_hud(LiveHud {
                            path: "relay".into(),
                            kind: "jpeg".into(),
                            encoder: "jpeg".into(),
                            path_note: super::model::connection_path_hint("jpeg", "relay")
                                .into(),
                            ..LiveHud::default()
                        });
                        break;
                    }
                    if saw_frame && last_decoded_at.elapsed() > Duration::from_secs(8) {
                        if super::model::webrtc_loss_keeps_jpeg(saw_frame) {
                            thread_h264.store(false, Ordering::Relaxed);
                            thread_shared.set_handshake_terminal(
                                "webrtc: no H.264 frame for 8s after takeover; JPEG stills remain".to_string(),
                            );
                            thread_shared.push(UiEvent::Notice(
                                "WebRTC live video is not up. Showing JPEG over the relay."
                                    .into(),
                            ));
                            thread_shared.push(UiEvent::Link("jpeg · relay".into()));
                            thread_shared.set_hud(LiveHud {
                                path: "relay".into(),
                                kind: "jpeg".into(),
                                encoder: "jpeg".into(),
                                path_note: super::model::connection_path_hint("jpeg", "relay")
                                    .into(),
                                ..LiveHud::default()
                            });
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
                        thread_shared.set_handshake_terminal("webrtc: receiving video");
                    }
                    // Approximate input RTT: move timestamp → frame with meta latency.
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
                        });
                        window_start = Instant::now();
                        window_frames = 0;
                    }
                }
            }
            viewer.close();
            let _ = control;
        })
        .ok();
    let shot_stop = Arc::clone(&stop);
    let shot_h264 = Arc::clone(&h264);
    let shots = tokio::spawn(async move {
        let mut tick = tokio::time::interval(shot_interval);
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
                        shared.set_hud(LiveHud {
                            path: "relay".into(),
                            kind: "jpeg".into(),
                            width: width as u32,
                            height: height as u32,
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

async fn saved_client(
    config_dir: &std::path::Path,
) -> Result<Option<(Arc<Client>, String)>, String> {
    let identity = Identity::load_or_create(&config_dir.join("identity.json"))
        .map_err(|err| err.to_string())?;
    let _ = maintain_session(config_dir, &identity)
        .await
        .map_err(|err| err.to_string())?;
    let file = agentlink_core::config::load_file(config_dir).unwrap_or_default();
    let Some(settings) = settings_of(&file) else {
        return Ok(None);
    };
    let user = file.user.clone().filter(|user| !user.is_empty());
    let client = Client::connect_identity(&settings, identity, true)
        .await
        .map_err(|err| err.to_string())?;
    client.remember_node_pins(config_dir);
    client.remember_grants(config_dir);
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
    let client = Client::connect_identity(&settings, identity, true)
        .await
        .map_err(|err| err.to_string())?;
    client.remember_node_pins(config_dir);
    client.remember_grants(config_dir);
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
        });
        handler
    }

    struct Harness {
        runtime: tokio::runtime::Runtime,
        shared: Arc<Shared>,
        started: Option<Started>,
        last: Option<Picture>,
        last_hud: Option<(String, String, String)>,
        hud_history: Vec<(String, String)>,
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
                ice_fault,
                Duration::from_millis(50),
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
                        self.hud_history.push((hud.kind.clone(), hud.path.clone()));
                        self.last_hud =
                            Some((hud.kind.clone(), hud.path.clone(), hud.path_note.clone()));
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
                if let Some((k, p, _)) = &self.last_hud {
                    if k == kind && p == path {
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
        if let Some((_, path, note)) = &h.last_hud {
            assert_eq!(path, "relay");
            assert!(note.contains("not WebRTC P2P"), "{note}");
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
                .any(|(k, p)| k == "h264" || p == "connecting"),
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
                .any(|(k, p)| k == "h264" || p == "connecting"),
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
        if let Some((_, _, note)) = &h.last_hud {
            assert!(note.contains("not WebRTC P2P"), "{note}");
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
        if let Some((kind, path, _)) = &h.last_hud {
            assert_ne!(path, "host");
            assert_ne!(path, "private");
            assert_ne!(kind, "h264");
        }
        eprintln!("t449 harness no-grant: failed={:?}", h.failed);
    }
}

#[cfg(test)]
mod handshake_retention_tests {
    use super::{handshake_is_cleanup, Shared, UiEvent};

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
