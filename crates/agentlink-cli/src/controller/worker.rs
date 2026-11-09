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
    PtyEvent, PtySession, RelayTrust, PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT,
    PHASE3_WEBRTC_SIGNAL,
};
use agentlink_view::{LiveOptions, Signal, Viewer};
use base64::Engine;
use serde_json::{json, Value};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

use super::decode::{decode_image, H264Decoder};
use super::model::enroll_command;

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
    Ready { user: Option<String> },
    Nodes(Vec<NodeInfo>),
    Failed(String),
    TotpRequired(String),
    Notice(String),
    Pty(Vec<u8>),
    PtyDone,
    Dir { path: String, entries: Vec<DirEntry> },
    File { path: String, text: String },
    Enrolled(String),
    Link(String),
    Pins(Vec<String>),
    Monitors(Vec<MonitorEntry>),
    Hud(LiveHud),
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
    PtyOpen { node: String, rows: u16, cols: u16 },
    PtyWrite { data: Vec<u8> },
    PtyResize { rows: u16, cols: u16 },
    PtyClose,
    List { node: String, path: String },
    Read { node: String, path: String },
    Write { node: String, path: String, text: String },
    Mkdir { node: String, path: String },
    Remove { node: String, path: String },
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
    Input { node: String, live: String, inject: String },
    Monitors { node: String },
    Clipboard { node: String, text: String },
    Shot { node: String, path: String },
    Enroll { name: String, access: String, minutes: u64 },
}

enum PtyCmd {
    Write(Vec<u8>),
    Resize(u16, u16),
}

pub struct Shared {
    events: Mutex<Vec<UiEvent>>,
    picture: Mutex<Option<Picture>>,
    seq: AtomicU64,
    pub perf: ClientPerf,
}

impl Shared {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            picture: Mutex::new(None),
            seq: AtomicU64::new(0),
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
                } => match sign_in(&config_dir, &username, &password, &totp, &relay, &pin, &trust).await
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
                    pty = None;
                    client = None;
                    if let Err(err) = crate::tray::sign_out(&config_dir).await {
                        shared.push(UiEvent::Failed(err.to_string()));
                    }
                    shared.push(UiEvent::Ready { user: None });
                    shared.push(UiEvent::Notice("Signed out".into()));
                }
                Cmd::Refresh => refresh(client.as_ref(), &shared).await,
                Cmd::PtyOpen { node, rows, cols } => {
                    pty = None;
                    match client.as_ref() {
                        Some(current) => match current.open_pty(&node, None, None, rows, cols).await {
                            Ok(session) => {
                                pty = Some(spawn_pty(session, Arc::clone(&shared)));
                            }
                            Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                        },
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
                Cmd::PtyClose => pty = None,
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
                    Some(current) => match current.write_file(&node, &path, text.as_bytes()).await {
                        Ok(()) => {
                            shared.push(UiEvent::Notice(format!("Saved {path}")));
                            shared.push(UiEvent::File { path, text });
                        }
                        Err(err) => shared.push(UiEvent::Failed(err.to_string())),
                    },
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
                Cmd::Input { node, live: body, inject } => {
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
                Cmd::Enroll { name, access, minutes } => match client.as_ref() {
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
    let stop = Arc::new(AtomicBool::new(false));
    let h264 = Arc::new(AtomicBool::new(false));
    let viewer = Arc::new(Mutex::new(None));
    let handle = tokio::runtime::Handle::current();
    let thread_stop = Arc::clone(&stop);
    let thread_h264 = Arc::clone(&h264);
    let thread_viewer = Arc::clone(&viewer);
    let thread_shared = Arc::clone(&shared);
    let thread_client = Arc::clone(&client);
    let thread_node = node.clone();
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
            let connected = Viewer::connect(
                Arc::new(ClientSignal {
                    client: thread_client,
                    handle,
                    node: thread_node,
                }),
                LiveOptions {
                    viewer: "desktop".into(),
                    control,
                    monitor,
                    max_fps,
                    bitrate,
                    scale,
                    ..LiveOptions::default()
                },
            );
            let viewer = match connected {
                Ok(viewer) => Arc::new(viewer),
                Err(err) => {
                    // Keep JPEG bootstrap for soft failures, but surface hard rejects.
                    let lower = err.to_ascii_lowercase();
                    if lower.contains("not allowed")
                        || lower.contains("offline")
                        || lower.contains("forbidden")
                        || lower.contains("denied")
                        || lower.contains("unauthorized")
                    {
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
            let path_label = super::model::connection_label(&info.path).to_string();
            let encoder = if info.encoder.is_empty() {
                if info.hardware {
                    "h264_hw".into()
                } else {
                    "minih264".into()
                }
            } else {
                info.encoder.clone()
            };
            thread_shared.push(UiEvent::Link(format!("h264 · {path_label}")));
            thread_shared.set_hud(LiveHud {
                path: path_label.clone(),
                kind: "h264".into(),
                width: info.width,
                height: info.height,
                bitrate_kbps: (bitrate / 1000).max(1),
                encoder: encoder.clone(),
                hardware: info.hardware,
                ..LiveHud::default()
            });
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
            while !thread_stop.load(Ordering::Relaxed) {
                let Some(frame) = viewer.poll_frame(Duration::from_millis(50)) else {
                    if viewer.failed() {
                        // Peer failed/closed: surface immediately. Do not leave
                        // the UI spinning on "Connecting…".
                        let msg = if saw_frame {
                            "WebRTC connection failed".to_string()
                        } else {
                            "WebRTC connection failed before the first frame".to_string()
                        };
                        thread_shared.push(UiEvent::Failed(msg));
                        break;
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
                    saw_frame = true;
                    last_frame_at = Instant::now();
                    thread_h264.store(true, Ordering::Relaxed);
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
                    thread_shared.set_picture(rgba, width, height, "h264", &info.path);
                    window_frames += 1;
                    let elapsed = window_start.elapsed();
                    if elapsed >= Duration::from_millis(500) {
                        let fps = window_frames as f32 / elapsed.as_secs_f32().max(0.001);
                        thread_shared.perf.note_fps(fps);
                        let stats = viewer.stats();
                        thread_shared.set_hud(LiveHud {
                            path: path_label.clone(),
                            kind: "h264".into(),
                            width: width as u32,
                            height: height as u32,
                            latency_ms: stats.latency_ms,
                            fps,
                            bitrate_kbps: (bitrate / 1000).max(1),
                            encoder: encoder.clone(),
                            hardware: info.hardware,
                            frames_dropped: stats.frames_dropped,
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
    let shot_monitor = monitor;
    let shot_quality = quality.clamp(40, 95);
    let shots = tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_millis(800));
        loop {
            tick.tick().await;
            if shot_stop.load(Ordering::Relaxed) || shot_h264.load(Ordering::Relaxed) {
                break;
            }
            match client
                .call_op(
                    &node,
                    Op::Extension {
                        name: PHASE2_SCREENSHOT.to_string(),
                        payload: json!({
                            "target": "monitor",
                            "monitor": shot_monitor,
                            "format": "jpeg",
                            "quality": shot_quality
                        }),
                    },
                )
                .await
            {
                Ok(value) => {
                    if shot_h264.load(Ordering::Relaxed) {
                        break;
                    }
                    if let Some(bytes) = screenshot_bytes(&value) {
                        if let Some((rgba, width, height)) = decode_image(&bytes) {
                            shared.set_picture(rgba, width, height, "jpeg", "relay");
                            shared.set_hud(LiveHud {
                                path: "relay".into(),
                                kind: "jpeg".into(),
                                width: width as u32,
                                height: height as u32,
                                encoder: "jpeg".into(),
                                ..LiveHud::default()
                            });
                        }
                    }
                }
                Err(err) => {
                    // Whole-desktop fallback when monitor index is unavailable.
                    match client
                        .call_op(
                            &node,
                            Op::Extension {
                                name: PHASE2_SCREENSHOT.to_string(),
                                payload: json!({
                                    "target": "screen",
                                    "format": "jpeg",
                                    "quality": shot_quality
                                }),
                            },
                        )
                        .await
                    {
                        Ok(value) => {
                            if let Some(bytes) = screenshot_bytes(&value) {
                                if let Some((rgba, width, height)) = decode_image(&bytes) {
                                    shared.set_picture(rgba, width, height, "jpeg", "relay");
                                }
                            }
                        }
                        Err(_) => {
                            shared.push(UiEvent::Failed(err.to_string()));
                            break;
                        }
                    }
                }
            }
        }
    });
    Started {
        live: Live { stop, viewer },
        shots,
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
    let bytes = screenshot_bytes(&value).ok_or_else(|| "screenshot response has no image".to_string())?;
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
                        None => break,
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
                right.online.cmp(&left.online).then_with(|| {
                    left.name.to_lowercase().cmp(&right.name.to_lowercase())
                })
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

async fn saved_client(config_dir: &std::path::Path) -> Result<Option<(Arc<Client>, String)>, String> {
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
