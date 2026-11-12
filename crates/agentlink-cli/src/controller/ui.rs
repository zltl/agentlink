//! Linear-dark controller window shared by Windows and Linux.
//!
//! The window is egui. The session, shell, files, and WebRTC viewer stay in
//! [`super::worker`] on the same client the phone uses. Visual tokens live in
//! [`super::theme`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

use agentlink_core::{NodeInfo, NodePolicy};
use eframe::egui;
use serde_json::{json, Value};
use tokio::sync::mpsc::UnboundedSender;

use super::chrome::{
    classify_connect_error, connection_bar_visible, encoder_label, estimate_right_width_with,
    link_is_connecting, pick_bar_density, session_chrome_top_height, session_phase, stats_chip,
    stats_line, text_advance, BarDensity, BarMeasure, ConnDot, SessionPhase, SessionSignals,
    BAR_HEIGHT,
};
use super::model::{
    self, access_summary, card_buttons, connection_label, display_note, has_saved_session,
    node_presence_label, Action, CardButtonKind,
};
use super::term::Emulator;
use super::theme;
use super::viewport::{hit_content, native_zoom, point_to_fraction, viewport_rect};
use super::worker::{Cmd, LiveHud, MonitorEntry, Picture, Shared, UiEvent};

use std::collections::HashSet;

/// Rect recorded from a real egui `Response` / layout pass (`[x, y, w, h]`).
#[derive(Clone, Debug, Default)]
pub struct DebugLayout {
    pub toolbar_visible: bool,
    pub toolbar_rect: [f32; 4],
    pub toolbar_items: Vec<(String, [f32; 4])>,
    pub pane_rect: [f32; 4],
    pub content_rect: [f32; 4],
    /// Session machine rail slot when visible; otherwise zeros.
    pub rail_rect: [f32; 4],
    /// Main column beside the rail (or the full chrome column when the rail is folded).
    pub main_rect: [f32; 4],
    /// Primary page body (machines list / terminal / files pane).
    /// Stored as the widget rect intersected with the active clip rect so a
    /// crushed `ui.horizontal()` row cannot report a large raw rect that is
    /// mostly invisible (parent saw black after wide→narrow resize).
    pub page_rect: [f32; 4],
    /// Visible clip of the machines/session body (not the scrolled content bounds).
    pub visible_clip: [f32; 4],
    pub texts: Vec<String>,
}

impl DebugLayout {
    fn clear(&mut self) {
        self.toolbar_visible = false;
        self.toolbar_rect = [0.0; 4];
        self.toolbar_items.clear();
        self.pane_rect = [0.0; 4];
        self.content_rect = [0.0; 4];
        self.rail_rect = [0.0; 4];
        self.main_rect = [0.0; 4];
        self.page_rect = [0.0; 4];
        self.visible_clip = [0.0; 4];
        self.texts.clear();
    }

    fn note_item(&mut self, id: &str, rect: egui::Rect) {
        self.toolbar_items.push((id.to_string(), rect_xywh(rect)));
    }

    /// Record the clip-visible bounds of a widget (`rect ∩ clip`).
    fn note_visible(&mut self, id: &str, rect: egui::Rect, clip: egui::Rect) {
        self.note_item(id, visible_rect(rect, clip));
    }

    /// Raw widget rect plus clip-visible rect for label/button regressions.
    fn note_button_raw_vis(&mut self, id: &str, rect: egui::Rect, clip: egui::Rect) {
        self.note_item(&format!("{id}:raw"), rect);
        self.note_item(&format!("{id}:vis"), visible_rect(rect, clip));
    }

    fn set_page_visible(&mut self, rect: egui::Rect, clip: egui::Rect) {
        self.page_rect = rect_xywh(visible_rect(rect, clip));
    }

    fn set_visible_clip(&mut self, clip: egui::Rect) {
        self.visible_clip = rect_xywh(clip);
    }

    fn note_focus(&mut self, id: &str, response: &egui::Response, clip: egui::Rect) {
        if response.has_focus() {
            self.note_item(&format!("focus:{id}"), response.rect);
            self.note_visible(&format!("focus_ring:{id}"), response.rect, clip);
        }
    }
}

fn rect_xywh(rect: egui::Rect) -> [f32; 4] {
    [rect.min.x, rect.min.y, rect.width(), rect.height()]
}

fn visible_rect(rect: egui::Rect, clip: egui::Rect) -> egui::Rect {
    rect.intersect(clip)
}

fn innermost_avail(ui: &egui::Ui) -> f32 {
    let avail = ui.available_rect_before_wrap();
    let visible = avail.intersect(ui.clip_rect());
    let scroll = ui.spacing().scroll;
    model::innermost_content_width(
        avail.width(),
        visible.width(),
        scroll.bar_width,
        scroll.floating,
    )
}

/// One debug-bus request delivered from the Unix socket thread.
pub enum DebugInbox {
    Req {
        id: u64,
        cmd: String,
        args: Value,
        reply: Sender<Value>,
    },
}

/// Options for the controller window / headless harness.
pub struct EnterOpts {
    pub config_dir: std::path::PathBuf,
    pub data_dir: std::path::PathBuf,
    pub tray: bool,
    pub background: bool,
    pub mock: bool,
    #[allow(dead_code)]
    pub headless: bool,
    pub fail_connect: bool,
    pub connect_timeout_secs: u64,
    pub max_fps: u32,
    /// Append a CSV perf row every 2s when set.
    pub perf_log: Option<std::path::PathBuf>,
    pub debug_inbox: Option<Receiver<DebugInbox>>,
    pub logical_size: (f32, f32),
    /// Open this node's desktop once the machine list arrives.
    pub open_desktop: Option<String>,
    /// Isolated layout fixture. Never uses the caller's account or auto-start.
    pub preview_ui: bool,
}

const PRESETS: &[&str] = &[
    "exec",
    "full",
    "read-write",
    "read-only",
    "desktop",
    "remote-view",
    "remote-control",
];

pub struct TrayFlags {
    pub open: Arc<AtomicBool>,
    pub quit: Arc<AtomicBool>,
}

enum Screen {
    Login,
    Restoring,
    Machines,
    Terminal { id: String, name: String },
    Files { id: String, name: String },
    Desktop { id: String, name: String },
}

struct Editor {
    path: String,
    text: String,
}

pub struct ControllerApp {
    tx: UnboundedSender<Cmd>,
    shared: Arc<Shared>,
    config_dir: std::path::PathBuf,
    data_dir: std::path::PathBuf,
    tray: bool,
    /// When true, the title-bar close button hides to the status icon.
    /// False for a normal foreground window so close actually quits.
    hide_on_close: bool,
    flags: TrayFlags,
    screen: Screen,
    username: String,
    password: String,
    totp: String,
    ask_totp: bool,
    show_password: bool,
    advanced: bool,
    relay: String,
    pin: String,
    trust: String,
    user: Option<String>,
    nodes: Vec<NodeInfo>,
    control: std::collections::HashMap<String, bool>,
    error: String,
    notice: String,
    pins: Vec<String>,
    terminal: Emulator,
    term_size: (u16, u16),
    /// When the current shell open was requested; None once output arrives.
    term_open: Option<Instant>,
    term_got_output: bool,
    file_path: String,
    files: Vec<agentlink_core::DirEntry>,
    files_loading: bool,
    editor: Option<Editor>,
    folder_name: String,
    new_file_name: String,
    link: String,
    picture: Option<Picture>,
    texture: Option<egui::TextureHandle>,
    seen_seq: u64,
    enroll_open: bool,
    enroll_name: String,
    enroll_access: String,
    enroll_minutes: String,
    enroll_out: String,
    node_line: String,
    autostart: bool,
    last_node: Instant,
    // Remote desktop pane.
    desk_monitors: Vec<MonitorEntry>,
    desk_monitor: u32,
    desk_quality: u32,
    desk_zoom: f32,
    desk_pan: egui::Vec2,
    desk_fit: bool,
    desk_fullscreen: bool,
    desk_capture_keys: bool,
    desk_held_keys: HashSet<String>,
    desk_held_buttons: HashSet<&'static str>,
    desk_sticky: HashSet<&'static str>,
    desk_last_move: Instant,
    desk_last_frame: Option<Instant>,
    desk_hud: LiveHud,
    desk_await_paste: bool,
    desk_last_frac: (f64, f64),
    desk_mods: (bool, bool, bool, bool),
    /// User hit Disconnect (or a fatal connect error); stay on the session page.
    desk_user_stopped: bool,
    desk_disconnect_reason: String,
    /// True when the session ended from timeout / peer fail / reject (not Disconnect).
    desk_connect_failed: bool,
    /// When the current connect attempt began (for `--connect-timeout-secs`).
    desk_connect_started: Option<Instant>,
    /// Short-lived toast drawn over the canvas (not the sticker banner).
    desk_toast: Option<(String, Instant)>,
    /// Last pointer activity used for fullscreen bar auto-hide.
    desk_ui_pointer: Instant,
    /// Local stats popover over the connection bar (not sent to the node).
    desk_stats_open: bool,
    /// `--mock`: local frames, no relay.
    mock: bool,
    /// Mock: land in the failed state instead of painting frames.
    fail_connect: bool,
    connect_timeout_secs: u64,
    max_fps: u32,
    pub(super) perf_log: Option<std::path::PathBuf>,
    perf_log_written_header: bool,
    last_perf_log: Instant,
    /// Logical canvas size (headless / debug resize).
    logical_size: (f32, f32),
    /// Last window title pushed to the viewport / debug bus.
    window_title: String,
    /// Last layout probe filled during `ui_frame`.
    debug_layout: DebugLayout,
    /// Optional debug bus (non-headless eframe path).
    debug_inbox: Option<Receiver<DebugInbox>>,
    /// Synthetic input queued by the debug bus for the next frames.
    debug_events: Vec<egui::Event>,
    debug_quit: bool,
    /// Latest session RGBA for PNG export without a GPU readback.
    debug_rgba: Option<(u32, u32, Vec<u8>)>,
    /// Mock frame counter for fps estimation.
    mock_frame_window_start: Instant,
    mock_frame_window_count: u32,
    /// Node whose desktop is opened as soon as the machine list arrives.
    open_desktop: Option<String>,
    /// Set once the auto-open ran so a refresh cannot yank the user back.
    auto_opened: bool,
    /// Selected machine on the Machines page (and highlighted in the nav).
    selected_id: Option<String>,
    /// Settings / About panel (pairing, start-on-login, version).
    settings_open: bool,
    /// Isolated preview fixture; not a live account.
    preview_ui: bool,
    /// Live autostart / view / data-dir hooks (counted; skipped in preview).
    live: super::LiveHooks,
}

pub fn enter(
    config_dir: std::path::PathBuf,
    data_dir: std::path::PathBuf,
    tray: bool,
    background: bool,
) -> i32 {
    enter_with_opts(EnterOpts {
        config_dir,
        data_dir,
        tray,
        background,
        mock: false,
        headless: false,
        fail_connect: false,
        connect_timeout_secs: 12,
        max_fps: 30,
        perf_log: None,
        debug_inbox: None,
        logical_size: (1080.0, 760.0),
        open_desktop: None,
        preview_ui: false,
    })
}

pub fn enter_with_opts(mut opts: EnterOpts) -> i32 {
    if opts.preview_ui {
        // Force a throwaway directory. Never read or write the caller's
        // production config, data dir, or start-on-login state.
        let root =
            std::env::temp_dir().join(format!("agentlink-preview-ui-{}", std::process::id()));
        let _ = std::fs::create_dir_all(root.join("config"));
        let _ = std::fs::create_dir_all(root.join("data"));
        opts.config_dir = root.join("config");
        opts.data_dir = root.join("data");
        opts.tray = false;
        opts.background = false;
        opts.mock = true;
    }
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let shared = Arc::new(Shared::new());
    if !opts.mock {
        let worker_shared = Arc::clone(&shared);
        let worker_dir = opts.config_dir.clone();
        std::thread::Builder::new()
            .name("agentlink-controller-net".into())
            .spawn(move || super::worker::run(rx, worker_shared, worker_dir))
            .ok();
        let _ = tx.send(Cmd::Bootstrap);
    } else {
        drop(rx);
    }
    let flags = TrayFlags {
        open: Arc::new(AtomicBool::new(false)),
        quit: Arc::new(AtomicBool::new(false)),
    };
    let mut tray_ready = false;
    if opts.tray && !opts.mock {
        tray_ready = super::indicator::spawn(Arc::clone(&flags.open), Arc::clone(&flags.quit));
        if !tray_ready {
            opts.background = false;
        }
    }
    let hide_on_close = model::hides_window_on_close(tray_ready, opts.background, false);
    let mut app = ControllerApp::new_debug(
        tx,
        shared,
        opts.config_dir,
        opts.data_dir,
        tray_ready,
        flags,
        opts.mock,
        opts.logical_size,
        opts.fail_connect,
        opts.connect_timeout_secs,
        opts.max_fps,
        opts.preview_ui,
        super::LiveHooks::production(),
    );
    app.hide_on_close = hide_on_close;
    app.perf_log = opts.perf_log;
    app.debug_inbox = opts.debug_inbox;
    app.open_desktop = opts.open_desktop;
    if opts.preview_ui {
        app.apply_preview_fixture();
    }
    let (iw, ih) = opts.logical_size;
    // Min size stays below the intentional rail fold breakpoint and below the
    // 725-wide narrow layout parent uses in GUI. Not a root cause of the
    // ~1085 restored-window rail (that was SHOW_AT=980 < 1085).
    let viewport = egui::ViewportBuilder::default()
        .with_title(app.window_title.clone())
        .with_inner_size([iw, ih])
        .with_min_inner_size([640.0, 480.0])
        .with_visible(!opts.background);
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    match eframe::run_native(
        "agentlink",
        options,
        Box::new(|cc| {
            theme::apply(&cc.egui_ctx);
            theme::apply_platform_zoom(&cc.egui_ctx);
            Ok(Box::new(app))
        }),
    ) {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("controller window: {err}");
            1
        }
    }
}

pub fn apply_theme_public(ctx: &egui::Context) {
    theme::apply(ctx);
}

impl ControllerApp {
    fn new(
        tx: UnboundedSender<Cmd>,
        shared: Arc<Shared>,
        config_dir: std::path::PathBuf,
        data_dir: std::path::PathBuf,
        tray: bool,
        flags: TrayFlags,
        preview_ui: bool,
        live: super::LiveHooks,
    ) -> Self {
        let (relay, pin, trust, node_line, autostart, saved_session) = if preview_ui {
            (
                String::new(),
                String::new(),
                String::new(),
                super::PREVIEW_NODE_LINE.to_string(),
                false,
                false,
            )
        } else {
            let file = agentlink_core::config::load_file(&config_dir).unwrap_or_default();
            let relay = file
                .relay
                .filter(|value| !value.is_empty())
                .unwrap_or_default();
            let pin = file.fingerprint.unwrap_or_default();
            let trust = file.trust.unwrap_or_default();
            let node_line = node_summary(&live, &data_dir, &config_dir);
            let autostart = live.start_on_login();
            let saved_session = {
                let file = agentlink_core::config::load_file(&config_dir).unwrap_or_default();
                has_saved_session(file.refresh_token.as_deref())
            };
            (relay, pin, trust, node_line, autostart, saved_session)
        };
        Self {
            tx,
            shared,
            config_dir,
            data_dir,
            tray,
            hide_on_close: false,
            flags,
            screen: if saved_session {
                Screen::Restoring
            } else {
                Screen::Login
            },
            username: String::new(),
            password: String::new(),
            totp: String::new(),
            ask_totp: false,
            show_password: false,
            advanced: !pin.is_empty() || trust_is_custom(&trust) || !relay.is_empty(),
            relay,
            pin,
            trust,
            user: None,
            nodes: Vec::new(),
            control: std::collections::HashMap::new(),
            error: String::new(),
            notice: String::new(),
            pins: Vec::new(),
            terminal: Emulator::new(24, 80),
            term_size: (24, 80),
            term_open: None,
            term_got_output: false,
            file_path: ".".into(),
            files: Vec::new(),
            files_loading: false,
            editor: None,
            folder_name: String::new(),
            new_file_name: String::new(),
            link: "relay".into(),
            picture: None,
            texture: None,
            seen_seq: 0,
            enroll_open: false,
            enroll_name: "laptop".into(),
            enroll_access: "exec".into(),
            enroll_minutes: "15".into(),
            enroll_out: String::new(),
            node_line,
            autostart,
            last_node: Instant::now(),
            desk_monitors: Vec::new(),
            desk_monitor: 0,
            desk_quality: 70,
            desk_zoom: 1.0,
            desk_pan: egui::Vec2::ZERO,
            desk_fit: true,
            desk_fullscreen: false,
            desk_capture_keys: false,
            desk_held_keys: HashSet::new(),
            desk_held_buttons: HashSet::new(),
            desk_sticky: HashSet::new(),
            desk_last_move: Instant::now() - Duration::from_secs(1),
            desk_last_frame: None,
            desk_hud: LiveHud::default(),
            desk_await_paste: false,
            desk_last_frac: (0.5, 0.5),
            desk_mods: (false, false, false, false),
            desk_user_stopped: false,
            desk_disconnect_reason: String::new(),
            desk_connect_failed: false,
            desk_connect_started: None,
            desk_toast: None,
            desk_ui_pointer: Instant::now(),
            desk_stats_open: false,
            mock: false,
            fail_connect: false,
            connect_timeout_secs: 12,
            max_fps: 30,
            perf_log: None,
            perf_log_written_header: false,
            last_perf_log: Instant::now(),
            logical_size: (1080.0, 760.0),
            window_title: "agentlink controller".into(),
            debug_layout: DebugLayout::default(),
            debug_inbox: None,
            debug_events: Vec::new(),
            debug_quit: false,
            debug_rgba: None,
            mock_frame_window_start: Instant::now(),
            mock_frame_window_count: 0,
            open_desktop: None,
            auto_opened: false,
            selected_id: None,
            settings_open: false,
            preview_ui,
            live,
        }
    }

    pub(super) fn new_debug(
        tx: UnboundedSender<Cmd>,
        shared: Arc<Shared>,
        config_dir: std::path::PathBuf,
        data_dir: std::path::PathBuf,
        tray: bool,
        flags: TrayFlags,
        mock: bool,
        logical_size: (f32, f32),
        fail_connect: bool,
        connect_timeout_secs: u64,
        max_fps: u32,
        preview_ui: bool,
        live: super::LiveHooks,
    ) -> Self {
        let mut app = Self::new(
            tx, shared, config_dir, data_dir, tray, flags, preview_ui, live,
        );
        app.mock = mock;
        app.logical_size = logical_size;
        app.fail_connect = fail_connect;
        app.connect_timeout_secs = connect_timeout_secs.max(1);
        app.max_fps = max_fps.clamp(1, 60);
        app
    }

    fn send(&self, cmd: Cmd) {
        let _ = self.tx.send(cmd);
    }

    fn pump(&mut self, ctx: &egui::Context) {
        if self.last_node.elapsed() > Duration::from_secs(2) {
            self.last_node = Instant::now();
            if !self.preview_ui {
                self.node_line = node_summary(&self.live, &self.data_dir, &self.config_dir);
                self.autostart = self.live.start_on_login();
            }
        }
        for event in self.shared.drain() {
            match event {
                UiEvent::Ready { user } => {
                    self.user = user.clone();
                    if user.is_some() {
                        if matches!(self.screen, Screen::Login | Screen::Restoring) {
                            self.screen = Screen::Machines;
                        }
                        self.password.clear();
                        self.totp.clear();
                    } else if matches!(self.screen, Screen::Restoring | Screen::Login) {
                        self.screen = Screen::Login;
                    }
                }
                UiEvent::Nodes(nodes) => {
                    self.nodes = nodes;
                    self.ensure_selection();
                    self.maybe_auto_open_desktop();
                }
                UiEvent::Failed(message) => {
                    self.files_loading = false;
                    if matches!(self.screen, Screen::Restoring) {
                        self.screen = Screen::Login;
                        self.error = message;
                    } else if matches!(self.screen, Screen::Desktop { .. }) {
                        let connecting = link_is_connecting(&self.link) || self.texture.is_none();
                        if connecting || self.desk_user_stopped || self.texture.is_none() {
                            self.fail_desktop_session(&message);
                        } else {
                            self.desk_toast = Some((message.clone(), Instant::now()));
                        }
                        self.error.clear();
                    } else {
                        self.error = message;
                    }
                }
                UiEvent::TotpRequired(message) => {
                    self.ask_totp = true;
                    self.error = message;
                }
                UiEvent::Notice(message) => {
                    if matches!(self.screen, Screen::Desktop { .. }) {
                        self.desk_toast = Some((message, Instant::now()));
                        self.notice.clear();
                    } else {
                        self.notice = message;
                    }
                }
                UiEvent::Pty(bytes) => {
                    if !bytes.is_empty() {
                        self.term_got_output = true;
                        self.term_open = None;
                    }
                    self.terminal.feed(&bytes);
                    let replies = self.terminal.take_writes();
                    if !replies.is_empty() {
                        self.send(Cmd::PtyWrite { data: replies });
                    }
                }
                UiEvent::PtyDone => {
                    self.term_open = None;
                    if !self.term_got_output
                        && matches!(self.screen, Screen::Terminal { .. })
                        && self.error.is_empty()
                    {
                        self.error = "The shell session ended before any output arrived.".into();
                    }
                }
                UiEvent::Dir { path, entries } => {
                    self.file_path = path;
                    self.files = entries;
                    self.files_loading = false;
                    self.forget_missing_editor();
                }
                UiEvent::File { path, text } => {
                    self.editor = Some(Editor { path, text });
                }
                UiEvent::Enrolled(text) => self.enroll_out = text,
                UiEvent::Link(label) => self.link = label,
                UiEvent::Pins(pins) => self.pins = pins,
                UiEvent::Monitors(monitors) => {
                    if let Some(blocked) = monitors.iter().find(|m| m.capturable == Some(false)) {
                        self.notice = blocked
                            .reason
                            .clone()
                            .unwrap_or_else(|| "secure desktop".into());
                        self.notice = format!("Remote screen is not capturable ({})", self.notice);
                    }
                    self.desk_monitors = monitors;
                    if let Some(primary) = self.desk_monitors.iter().find(|m| m.primary) {
                        if !self
                            .desk_monitors
                            .iter()
                            .any(|m| m.index == self.desk_monitor)
                        {
                            self.desk_monitor = primary.index;
                        }
                    } else if let Some(first) = self.desk_monitors.first() {
                        if !self
                            .desk_monitors
                            .iter()
                            .any(|m| m.index == self.desk_monitor)
                        {
                            self.desk_monitor = first.index;
                        }
                    }
                }
                UiEvent::Hud(hud) => {
                    let keep = if hud.handshake.is_empty() {
                        self.desk_hud.handshake.clone()
                    } else {
                        hud.handshake.clone()
                    };
                    self.desk_hud = hud;
                    self.desk_hud.handshake = keep;
                    if !self.desk_hud.kind.is_empty() {
                        self.link = format!(
                            "{} · {}",
                            self.desk_hud.kind,
                            if self.desk_hud.path.is_empty() {
                                "relay"
                            } else {
                                &self.desk_hud.path
                            }
                        );
                    }
                }
                UiEvent::Handshake(stage) => {
                    self.desk_hud.handshake = stage;
                }
            }
            ctx.request_repaint();
        }
        let mut got_frame = false;
        if let Some(picture) = self.shared.latest_picture() {
            if picture.seq != self.seen_seq {
                self.seen_seq = picture.seq;
                let present_started = Instant::now();
                let (w, h, rgba) =
                    fit_rgba_for_egui(picture.width, picture.height, picture.rgba, ctx);
                let image = egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba);
                if let Some(texture) = &mut self.texture {
                    texture.set(image, egui::TextureOptions::LINEAR);
                } else {
                    self.texture =
                        Some(ctx.load_texture("desktop", image, egui::TextureOptions::LINEAR));
                }
                self.shared
                    .perf
                    .note_present_us(present_started.elapsed().as_micros() as u64);
                self.link = format!("{} · {}", picture.kind, connection_label(&picture.path));
                self.desk_last_frame = Some(Instant::now());
                self.desk_connect_started = None;
                self.desk_connect_failed = false;
                // Only retain a debug snapshot when a screenshot may be needed —
                // cloning full RGBA every frame was a third present-path copy.
                if self.debug_inbox.is_some() {
                    self.debug_rgba = Some((w as u32, h as u32, rgba.clone()));
                }
                self.picture = Some(Picture {
                    rgba,
                    width: w,
                    height: h,
                    kind: picture.kind,
                    path: picture.path,
                    seq: picture.seq,
                });
                got_frame = true;
                ctx.request_repaint();
            }
        }
        self.check_connect_timeout();
        self.sync_window_title(ctx);
        self.maybe_write_perf_log();
        if self.desk_await_paste {
            let pasted = ctx.input(|input| {
                input.events.iter().find_map(|event| match event {
                    egui::Event::Paste(text) => Some(text.clone()),
                    _ => None,
                })
            });
            if let Some(text) = pasted {
                self.desk_await_paste = false;
                if let Screen::Desktop { id, .. } = &self.screen {
                    let id = id.clone();
                    if !text.is_empty() {
                        self.send(Cmd::Clipboard { node: id, text });
                    }
                }
            }
        }
        // Follow frame arrivals; idle connecting still needs a slow poll.
        if !got_frame {
            let after = if matches!(self.screen, Screen::Desktop { .. })
                && self.desk_last_frame.is_some()
            {
                Duration::from_millis(33)
            } else {
                Duration::from_millis(80)
            };
            ctx.request_repaint_after(after);
        }
    }

    fn maybe_write_perf_log(&mut self) {
        let Some(path) = self.perf_log.clone() else {
            return;
        };
        if self.last_perf_log.elapsed() < Duration::from_secs(2) {
            return;
        }
        self.last_perf_log = Instant::now();
        let snap = self.shared.perf.snapshot();
        let line = format!(
            "{},{:.2},{:.2},{:.2},{:.2},{:.2},{},{}\n",
            chrono_now_secs(),
            snap["fps_window"].as_f64().unwrap_or(0.0),
            snap["recv_gap_p95_ms"].as_f64().unwrap_or(0.0),
            snap["decode_ms"].as_f64().unwrap_or(0.0),
            snap["present_ms"].as_f64().unwrap_or(0.0),
            snap["input_rtt_ms"].as_f64().unwrap_or(0.0),
            snap["stalls"].as_u64().unwrap_or(0),
            snap["frames"].as_u64().unwrap_or(0),
        );
        let mut file = match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            Ok(f) => f,
            Err(err) => {
                tracing::warn!(error = %err, path = %path.display(), "perf-log open failed");
                return;
            }
        };
        use std::io::Write;
        if !self.perf_log_written_header {
            let _ = writeln!(
                file,
                "unix_s,fps_window,recv_gap_p95_ms,decode_ms,present_ms,input_rtt_ms,stalls,frames"
            );
            self.perf_log_written_header = true;
        }
        let _ = file.write_all(line.as_bytes());
    }

    fn open_terminal(&mut self, node: &NodeInfo) {
        if let Screen::Terminal { id, .. } = &self.screen {
            if id == &node.id {
                self.terminal.focused = true;
                return;
            }
        }
        self.terminal = Emulator::new(self.term_size.0, self.term_size.1);
        self.terminal.focused = true;
        self.term_got_output = false;
        self.term_open = Some(Instant::now());
        self.error.clear();
        self.send(Cmd::PtyOpen {
            node: node.id.clone(),
            rows: self.term_size.0,
            cols: self.term_size.1,
        });
        self.selected_id = Some(node.id.clone());
        self.screen = Screen::Terminal {
            id: node.id.clone(),
            name: node.name.clone(),
        };
    }

    fn open_files(&mut self, node: &NodeInfo) {
        self.files.clear();
        self.editor = None;
        self.file_path = ".".into();
        self.files_loading = true;
        self.error.clear();
        self.send(Cmd::List {
            node: node.id.clone(),
            path: ".".into(),
        });
        self.selected_id = Some(node.id.clone());
        self.screen = Screen::Files {
            id: node.id.clone(),
            name: node.name.clone(),
        };
    }

    fn clear_editor_if_deleted(&mut self, deleted: &str) {
        let Some(path) = self.editor.as_ref().map(|editor| editor.path.clone()) else {
            return;
        };
        if !model::editor_is_stale(&path, deleted) {
            return;
        }
        if model::notice_refers_to_path(&self.notice, &path) {
            self.notice.clear();
        }
        self.editor = None;
    }

    fn forget_missing_editor(&mut self) {
        let Some(path) = self.editor.as_ref().map(|editor| editor.path.clone()) else {
            return;
        };
        let parent = model::parent_path(&path);
        let same_dir = parent == self.file_path
            || (parent == "." && (self.file_path == "." || self.file_path.is_empty()));
        if !same_dir {
            return;
        }
        let name = path.rsplit(['/', '\\']).next().unwrap_or(path.as_str());
        if self.files.iter().any(|entry| entry.name == name) {
            return;
        }
        if model::notice_refers_to_path(&self.notice, &path) {
            self.notice.clear();
        }
        self.editor = None;
    }

    /// `--open-desktop <node>`: jump straight into a session as soon as the
    /// machine list lands, so screenshots and smoke tests need no synthetic
    /// clicks (Wayland apps ignore most injected pointer devices).
    fn maybe_auto_open_desktop(&mut self) {
        if self.auto_opened {
            return;
        }
        let Some(wanted) = self.open_desktop.clone() else {
            return;
        };
        let found = self
            .nodes
            .iter()
            .find(|node| node.name == wanted || node.id == wanted)
            .cloned();
        let Some(node) = found else {
            eprintln!("auto-open: node '{wanted}' not in the machine list yet");
            return;
        };
        eprintln!("auto-open: opening desktop for '{}'", node.name);
        self.auto_opened = true;
        self.user.get_or_insert_with(|| "controller".into());
        self.open_desktop(&node, true);
    }

    fn open_desktop(&mut self, node: &NodeInfo, control: bool) {
        self.selected_id = Some(node.id.clone());
        self.control.insert(node.id.clone(), control);
        self.reset_desktop_session();
        self.error.clear();
        self.desk_connect_started = Some(Instant::now());
        if self.mock {
            self.desk_monitors = mock_monitors();
            self.desk_monitor = 0;
            self.desk_hud = LiveHud {
                path: "mock".into(),
                kind: "mock".into(),
                width: 960,
                height: 480,
                latency_ms: 12,
                fps: 0.0,
                bitrate_kbps: 2000,
                encoder: "minih264".into(),
                hardware: false,
                frames_dropped: 0,
                path_note: String::new(),
                handshake: String::new(),
            };
            self.screen = Screen::Desktop {
                id: node.id.clone(),
                name: node.name.clone(),
            };
            if self.fail_connect {
                self.link = if control {
                    "connecting · control".into()
                } else {
                    "connecting · view".into()
                };
                // Stay connecting until timeout or `fail connect`.
            } else {
                self.link = "connected · mock".into();
                self.desk_connect_started = None;
            }
            // Do not touch `window_title` here — `sync_window_title` owns the
            // cache vs ViewportCommand::Title compare. Updating the cache first
            // suppressed the native Title command (stale "sufa" after Back).
            return;
        }
        self.link = if control {
            "connecting · control".into()
        } else {
            "connecting · view".into()
        };
        self.send(Cmd::Monitors {
            node: node.id.clone(),
        });
        self.send(Cmd::Live {
            node: node.id.clone(),
            control,
            monitor: self.desk_monitor,
            quality: self.desk_quality,
            scale: self.live_scale_for_monitor(),
            max_fps: self.max_fps,
        });
        self.screen = Screen::Desktop {
            id: node.id.clone(),
            name: node.name.clone(),
        };
        // Title sync is deferred to `sync_window_title` (see mock branch).
    }

    fn live_scale_for_monitor(&self) -> f32 {
        let (win_w, win_h) = self.logical_size;
        let (src_w, src_h) = self
            .desk_monitors
            .iter()
            .find(|m| m.index == self.desk_monitor)
            .map(|m| (m.width.max(1) as f32, m.height.max(1) as f32))
            .unwrap_or((1920.0, 1080.0));
        // Prefer fitting the controller window; also keep a 1280px encode cap so
        // full-panel 2736×1824 sessions stay realtime on the pixel path.
        let cap = 1280.0;
        let scale_x = (win_w / src_w).min(cap / src_w).clamp(0.05, 1.0);
        let scale_y = (win_h / src_h).min(cap / src_h).clamp(0.05, 1.0);
        scale_x.min(scale_y).clamp(0.05, 1.0)
    }

    fn reset_desktop_session(&mut self) {
        self.release_remote_input();
        self.picture = None;
        self.texture = None;
        self.seen_seq = 0;
        self.desk_zoom = 1.0;
        self.desk_pan = egui::Vec2::ZERO;
        self.desk_fit = true;
        self.desk_capture_keys = false;
        self.desk_last_frame = None;
        self.desk_hud = LiveHud::default();
        self.desk_await_paste = false;
        self.desk_sticky.clear();
        self.desk_user_stopped = false;
        self.desk_disconnect_reason.clear();
        self.desk_connect_failed = false;
        self.desk_connect_started = None;
        self.desk_toast = None;
        self.desk_stats_open = false;
        self.desk_ui_pointer = Instant::now();
        self.mock_frame_window_start = Instant::now();
        self.mock_frame_window_count = 0;
    }

    fn back_to_machines(&mut self) {
        self.release_remote_input();
        self.send(Cmd::PtyClose);
        self.send(Cmd::LiveStop);
        if self.desk_fullscreen {
            // Caller must also clear fullscreen via viewport cmd when a ctx is handy.
            self.desk_fullscreen = false;
        }
        self.desk_user_stopped = false;
        self.desk_disconnect_reason.clear();
        self.desk_connect_failed = false;
        self.desk_connect_started = None;
        self.desk_toast = None;
        self.desk_stats_open = false;
        self.screen = Screen::Machines;
        self.link = "relay".into();
        // Leave `window_title` alone — `sync_window_title` must see a change
        // so it can emit ViewportCommand::Title (clear / no-session default).
    }

    fn restart_live(&mut self, node: &str) {
        self.release_remote_input();
        self.picture = None;
        self.texture = None;
        self.seen_seq = 0;
        self.desk_last_frame = None;
        self.desk_user_stopped = false;
        self.desk_disconnect_reason.clear();
        self.desk_connect_failed = false;
        self.desk_stats_open = false;
        self.error.clear();
        let control = self.control.get(node).copied().unwrap_or(false);
        self.link = if control {
            "connecting · control".into()
        } else {
            "connecting · view".into()
        };
        self.desk_connect_started = Some(Instant::now());
        if self.mock {
            if self.fail_connect {
                return;
            }
            self.link = "connected · mock".into();
            self.desk_connect_started = None;
            return;
        }
        self.send(Cmd::Live {
            node: node.to_string(),
            control,
            monitor: self.desk_monitor,
            quality: self.desk_quality,
            scale: self.live_scale_for_monitor(),
            max_fps: self.max_fps,
        });
    }

    fn stop_desktop_session(&mut self, reason: &str) {
        self.release_remote_input();
        self.send(Cmd::LiveStop);
        self.picture = None;
        self.texture = None;
        self.seen_seq = 0;
        self.desk_last_frame = None;
        self.desk_capture_keys = false;
        self.desk_user_stopped = true;
        self.desk_connect_failed = false;
        self.desk_connect_started = None;
        self.desk_disconnect_reason = reason.to_string();
        self.desk_stats_open = false;
        self.link = "disconnected".into();
    }

    fn fail_desktop_session(&mut self, reason: &str) {
        self.release_remote_input();
        self.send(Cmd::LiveStop);
        self.picture = None;
        self.texture = None;
        self.seen_seq = 0;
        self.desk_last_frame = None;
        self.desk_capture_keys = false;
        self.desk_user_stopped = true;
        self.desk_connect_failed = true;
        self.desk_connect_started = None;
        self.desk_disconnect_reason = classify_connect_error(reason);
        self.desk_stats_open = false;
        self.link = "failed".into();
    }

    fn check_connect_timeout(&mut self) {
        if !matches!(self.screen, Screen::Desktop { .. }) {
            return;
        }
        if self.texture.is_some() || self.desk_connect_failed || self.desk_user_stopped {
            return;
        }
        let Some(started) = self.desk_connect_started else {
            return;
        };
        let limit = Duration::from_secs(self.connect_timeout_secs.max(1));
        if started.elapsed() >= limit {
            self.fail_desktop_session(&format!(
                "Connection timed out after {}s",
                self.connect_timeout_secs
            ));
        }
    }

    fn sync_window_title(&mut self, ctx: &egui::Context) {
        let title = self.compute_window_title();
        if title != self.window_title {
            self.window_title = title.clone();
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
        }
    }

    fn compute_window_title(&self) -> String {
        match &self.screen {
            Screen::Desktop { name, .. } => {
                let w = self.desk_hud.width;
                let h = self.desk_hud.height;
                if w > 0 && h > 0 {
                    format!("{name} — {w}×{h} — agentlink")
                } else {
                    format!("{name} — agentlink")
                }
            }
            Screen::Terminal { name, .. } => format!("{name} — terminal — agentlink"),
            Screen::Files { name, .. } => format!("{name} — files — agentlink"),
            // Login / Restoring / Machines: no active session.
            Screen::Login | Screen::Restoring | Screen::Machines => {
                if self.preview_ui {
                    "agentlink controller (preview)".into()
                } else {
                    "agentlink controller".into()
                }
            }
        }
    }

    fn session_mode(&self) -> &'static str {
        match &self.screen {
            Screen::Desktop { id, .. } => {
                if self.control.get(id).copied().unwrap_or(false) {
                    "control"
                } else {
                    "view"
                }
            }
            _ => "view",
        }
    }

    fn desktop_phase(&self) -> SessionPhase {
        session_phase(SessionSignals {
            user_stopped: self.desk_user_stopped,
            link_connecting: link_is_connecting(&self.link),
            has_texture: self.texture.is_some(),
            since_frame: self.desk_last_frame.map(|t| t.elapsed()),
            fatal_error: if self.desk_disconnect_reason.is_empty() {
                ""
            } else {
                &self.desk_disconnect_reason
            },
            connect_failed: self.desk_connect_failed,
        })
    }
}

impl eframe::App for ControllerApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        #[cfg(unix)]
        if let Some(inbox) = self.debug_inbox.take() {
            super::debug::pump_eframe_debug(self, ctx, &inbox);
            self.debug_inbox = Some(inbox);
        }
        if self.debug_quit || self.flags.quit.load(Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
        if self.flags.open.swap(false, Ordering::Relaxed) {
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        }
        if self.hide_on_close
            && !self.flags.quit.load(Ordering::Relaxed)
            && ctx.input(|input| input.viewport().close_requested())
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        self.ui_frame(ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.flags.quit.store(true, Ordering::Relaxed);
        self.send(Cmd::PtyClose);
        self.send(Cmd::LiveStop);
    }
}

impl ControllerApp {
    /// One UI pass shared by eframe and the headless debug loop.
    pub(super) fn ui_frame(&mut self, ctx: &egui::Context) {
        if std::env::var_os("AGENTLINK_UI_DEBUG_STYLE").is_some() {
            let v = ctx.style().visuals.clone();
            eprintln!(
                "ui-style panel={:?} window={:?} dark={} theme_bg={:?}",
                v.panel_fill,
                v.window_fill,
                v.dark_mode,
                theme::BG_PAGE
            );
        }
        self.debug_layout.clear();
        self.sync_window_size(ctx);
        self.pump(ctx);
        if matches!(self.screen, Screen::Terminal { .. }) && self.terminal.focused {
            self.terminal.consume_focused_keys(ctx);
        }
        if self.mock {
            self.refresh_mock_picture(ctx);
        }
        if matches!(self.screen, Screen::Desktop { .. }) {
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE.fill(theme::BG_PAGE))
                .show(ctx, |ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_XS, 0.0);
                    self.desktop(ui);
                });
        } else {
            let show_rail = matches!(
                self.screen,
                Screen::Machines | Screen::Terminal { .. } | Screen::Files { .. }
            ) && model::machine_rail_visible_at(
                ctx.screen_rect().width(),
                ctx.pixels_per_point(),
            );
            egui::CentralPanel::default()
                .frame(egui::Frame::NONE.fill(theme::BG_PAGE))
                .show(ctx, |ui| {
                    // Compact page margin (not SPACE_2XL). Header spans the
                    // window; the device nav fills the remaining height.
                    egui::Frame::NONE
                        .inner_margin(egui::Margin::same(theme::SPACE_MD as i8))
                        .show(ui, |ui| {
                            ui.spacing_mut().item_spacing =
                                egui::vec2(theme::SPACE_SM, theme::SPACE_SM);
                            self.paint_chrome(ui);
                            if show_rail {
                                // Full remaining height, left-to-right split.
                                let avail = ui.available_size();
                                // Zero gap: tests require rail and main to abut
                                // within 2 px. Main padding is inside main_rect.
                                ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                                ui.allocate_ui_with_layout(
                                    avail,
                                    egui::Layout::left_to_right(egui::Align::Min),
                                    |ui| {
                                        let rail_w = model::MACHINE_RAIL_WIDTH;
                                        let row_h = ui.max_rect().height().max(1.0);
                                        let (rail_rect, _) = ui.allocate_exact_size(
                                            egui::vec2(rail_w, row_h),
                                            egui::Sense::hover(),
                                        );
                                        {
                                            let mut rail_ui = ui.new_child(
                                                egui::UiBuilder::new()
                                                    .id_salt("machine-rail")
                                                    .max_rect(rail_rect)
                                                    .layout(egui::Layout::top_down(
                                                        egui::Align::Min,
                                                    )),
                                            );
                                            rail_ui.set_clip_rect(rail_rect);
                                            egui::Frame::NONE
                                                .fill(theme::BG_SURFACE)
                                                .inner_margin(egui::Margin::same(
                                                    theme::SPACE_MD as i8,
                                                ))
                                                .stroke(theme::stroke_border_subtle())
                                                .show(&mut rail_ui, |ui| {
                                                    ui.set_min_size(ui.max_rect().size());
                                                    ui.set_max_size(ui.max_rect().size());
                                                    self.machine_rail(ui);
                                                });
                                        }
                                        let main_w = ui.available_width().max(1.0);
                                        let (main_rect, _) = ui.allocate_exact_size(
                                            egui::vec2(main_w, row_h),
                                            egui::Sense::hover(),
                                        );
                                        {
                                            let mut main_ui = ui.new_child(
                                                egui::UiBuilder::new()
                                                    .id_salt("session-main")
                                                    .max_rect(main_rect)
                                                    .layout(egui::Layout::top_down(
                                                        egui::Align::Min,
                                                    )),
                                            );
                                            main_ui.set_clip_rect(main_rect);
                                            egui::Frame::NONE
                                                .inner_margin(egui::Margin::symmetric(
                                                    theme::SPACE_MD as i8,
                                                    0,
                                                ))
                                                .show(&mut main_ui, |ui| {
                                                    self.paint_page(ui);
                                                });
                                        }
                                        self.debug_layout.rail_rect = rect_xywh(rail_rect);
                                        self.debug_layout.main_rect = rect_xywh(main_rect);
                                    },
                                );
                            } else {
                                let main_rect = ui.available_rect_before_wrap();
                                self.debug_layout.main_rect = rect_xywh(main_rect);
                                self.paint_page(ui);
                            }
                        });
                });
        }
    }
}

impl ControllerApp {
    fn paint_chrome(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_SM, theme::SPACE_SM);
        self.header(ui);
        if !self.error.is_empty() {
            banner(ui, &self.error, true);
        }
        if !self.notice.is_empty() {
            banner(ui, &self.notice, false);
        }
        if !super::fonts::report().loaded {
            ui.label(theme::muted_text(super::fonts::missing_font_hint()));
        }
    }

    fn paint_page(&mut self, ui: &mut egui::Ui) {
        ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_SM, theme::SPACE_SM);
        match self.screen {
            Screen::Login => self.login(ui),
            Screen::Restoring => self.restoring(ui),
            Screen::Machines => self.machines(ui),
            Screen::Terminal { .. } => self.terminal(ui),
            Screen::Files { .. } => self.files(ui),
            Screen::Desktop { .. } => {}
        }
    }

    fn header(&mut self, ui: &mut egui::Ui) {
        let clip = ui.clip_rect();
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_SM, theme::SPACE_XS);
            ui.label(
                egui::RichText::new("Agentlink")
                    .size(16.0)
                    .color(theme::TEXT_PRIMARY)
                    .strong(),
            );
            let link_label = if self.preview_ui {
                "Isolated preview"
            } else if self.link.is_empty() {
                "Not connected"
            } else {
                self.link.as_str()
            };
            let pill = status_pill(ui, link_label, theme::TEXT_MUTED, None);
            self.debug_layout
                .note_visible("header_status", pill.rect, clip);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_SM, theme::SPACE_XS);
                let quit = ui
                    .push_id("header-quit", |ui| ui.add(theme::secondary_button("Quit")))
                    .inner
                    .on_hover_text("Exit the controller. The window close button also exits unless this was started with --background and a status icon is running.");
                self.debug_layout.note_visible("header_quit", quit.rect, clip);
                self.debug_layout.note_focus("header_quit", &quit, clip);
                if quit.clicked() {
                    self.flags.quit.store(true, Ordering::Relaxed);
                    self.send(Cmd::PtyClose);
                    self.send(Cmd::LiveStop);
                    ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                }
                let can_account =
                    self.user.is_some() && !matches!(self.screen, Screen::Login | Screen::Restoring);
                if can_account {
                    if !self.preview_ui {
                        let logout = ui.add(theme::secondary_button("Log out"));
                        self.debug_layout
                            .note_visible("header_logout", logout.rect, clip);
                        self.debug_layout.note_focus("header_logout", &logout, clip);
                        if logout.clicked() {
                            self.back_to_machines();
                            self.send(Cmd::Logout);
                        }
                        let refresh = ui.add(theme::secondary_button("Refresh"));
                        self.debug_layout
                            .note_visible("header_refresh", refresh.rect, clip);
                        self.debug_layout.note_focus("header_refresh", &refresh, clip);
                        if refresh.clicked() {
                            self.send(Cmd::Refresh);
                        }
                    }
                    if let Some(user) = &self.user {
                        status_pill(ui, user, theme::TEXT_MUTED, None);
                    }
                }
                let settings = ui
                    .push_id("header-settings", |ui| {
                        ui.add(theme::secondary_button(if self.settings_open {
                            "Close settings"
                        } else {
                            "Settings"
                        }))
                    })
                    .inner;
                self.debug_layout
                    .note_visible("header_settings", settings.rect, clip);
                self.debug_layout.note_focus("header_settings", &settings, clip);
                if settings.clicked() {
                    self.settings_open = !self.settings_open;
                }
            });
        });
        if self.preview_ui {
            let banner = banner(
                ui,
                "Isolated preview — fixture machines, not a live account or production auto-start.",
                false,
            );
            self.debug_layout
                .note_visible("preview_banner", banner.rect, clip);
        }
        if self.settings_open {
            self.settings_panel(ui);
        }
        ui.add_space(theme::SPACE_SM);
    }

    fn login(&mut self, ui: &mut egui::Ui) {
        let width = ui.available_width().min(400.0);
        ui.vertical_centered(|ui| {
            ui.set_max_width(width);
            ui.add_space(theme::SPACE_XL);
            ui.label(theme::title_text("Sign in"));
            ui.add_space(theme::SPACE_SM);
            ui.label(theme::body_text(
                "Username and password. Set the relay URL; nothing is selected for you.",
            ));
            ui.label(theme::muted_text(
                "The sign-in stays for 30 days of use, same as the phone. An authenticator code appears when the account uses one.",
            ));
            ui.add_space(theme::SPACE_MD);
            labeled(ui, "Username", &mut self.username, false);
            ui.add_space(theme::SPACE_SM);
            ui.label(theme::muted_text("Password"));
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = theme::SPACE_SM;
                ui.set_height(theme::BTN_PRIMARY_H);
                let btn_w = 72.0;
                let edit = egui::TextEdit::singleline(&mut self.password)
                    .password(!self.show_password)
                    .desired_width((ui.available_width() - btn_w - theme::SPACE_SM).max(80.0))
                    .min_size(egui::vec2(0.0, theme::BTN_PRIMARY_H))
                    .margin(egui::Margin::symmetric(theme::BTN_PAD_X as i8, 0));
                style_text_edit(ui, edit);
                if ui
                    .add_sized(
                        [btn_w, theme::BTN_PRIMARY_H],
                        theme::secondary_button(if self.show_password {
                            "Hide"
                        } else {
                            "Show"
                        }),
                    )
                    .clicked()
                {
                    self.show_password = !self.show_password;
                }
            });
            if self.ask_totp || !self.totp.is_empty() {
                ui.add_space(theme::SPACE_SM);
                labeled(ui, "Authenticator code", &mut self.totp, false);
            }
            ui.add_space(theme::SPACE_MD);
            if ui
                .add_sized([width, theme::BTN_PRIMARY_H], theme::primary_button("Sign in"))
                .clicked()
            {
                self.submit_login();
            }
            ui.add_space(theme::SPACE_MD);
            egui::CollapsingHeader::new(theme::muted_text("Advanced"))
                .default_open(self.advanced)
                .show(ui, |ui| {
                    ui.label(theme::muted_text(
                        "Relay address, certificate pin, and trust. Pair a machine after you sign in.",
                    ));
                    labeled(ui, "Relay URL", &mut self.relay, false);
                    labeled(ui, "Certificate pin", &mut self.pin, false);
                    labeled(
                        ui,
                        "Trust (system, webpki, or system+webpki)",
                        &mut self.trust,
                        false,
                    );
                    ui.label(theme::muted_text(
                        "Leave the pin empty only when this relay uses public roots (system or webpki). Otherwise pin sha256:, spki:sha256:, or intermediate:sha256:.",
                    ));
                });
        });
    }

    fn submit_login(&mut self) {
        self.error.clear();
        if let Some(problem) = model::login_problem(
            &self.username,
            &self.password,
            &self.relay,
            &self.pin,
            &self.trust,
        ) {
            self.error = problem;
            return;
        }
        self.send(Cmd::Login {
            username: self.username.trim().to_string(),
            password: self.password.clone(),
            totp: self.totp.trim().to_string(),
            relay: self.relay.trim().to_string(),
            pin: self.pin.trim().to_string(),
            trust: self.trust.trim().to_string(),
        });
    }

    fn machines(&mut self, ui: &mut egui::Ui) {
        self.ensure_selection();
        self.debug_layout.set_visible_clip(ui.clip_rect());
        egui::ScrollArea::vertical()
            .id_salt("machines-page")
            .drag_to_scroll(false)
            .auto_shrink([false, true])
            .show(ui, |ui| {
                ui.set_width(innermost_avail(ui));
                self.machines_inner(ui);
            });
    }

    fn machines_inner(&mut self, ui: &mut egui::Ui) {
        let pins = self.pins.clone();
        for pin in &pins {
            banner(ui, pin, true);
        }

        let loading = self.nodes.is_empty()
            && self.user.is_some()
            && (link_is_connecting(&self.link) || self.link == "relay");
        let rail = self.rail_visible_for(ui.ctx());
        let clip = ui.clip_rect();
        if self.nodes.is_empty() {
            let avail = ui.available_size();
            let empty = ui.allocate_ui_with_layout(
                avail,
                egui::Layout::centered_and_justified(egui::Direction::TopDown),
                |ui| {
                    ui.vertical_centered(|ui| {
                        ui.spinner();
                        ui.add_space(theme::SPACE_SM);
                        ui.label(theme::muted_text(if loading {
                            "Loading machines…"
                        } else {
                            "No machines yet — pair one to get started."
                        }));
                    });
                },
            );
            self.debug_layout
                .set_page_visible(empty.response.rect, clip);
        } else {
            if !rail {
                self.machine_list(ui, true);
                ui.add_space(theme::SPACE_SM);
            }
            if let Some(node) = self.selected_node() {
                let start = ui.min_rect().min;
                self.machine_detail(ui, &node);
                let rect = egui::Rect::from_min_max(start, ui.min_rect().max);
                self.debug_layout.set_page_visible(rect, clip);
            } else {
                let hint = ui.label(theme::muted_text("Select a machine."));
                self.debug_layout.set_page_visible(hint.rect, clip);
            }
        }
        if !rail {
            ui.add_space(theme::SPACE_SM);
            self.pair_toggle(ui);
        } else if self.enroll_open {
            ui.add_space(theme::SPACE_SM);
            self.enroll(ui);
        }
        if !rail && self.enroll_open {
            self.enroll(ui);
        }
    }

    fn pair_toggle(&mut self, ui: &mut egui::Ui) {
        let label = if self.enroll_open {
            "Hide pairing"
        } else {
            "Pair a machine"
        };
        let button = theme::secondary_button(label);
        let resp = if self.preview_ui {
            ui.add_enabled(false, button)
                .on_hover_text("Pairing is disabled in isolated preview.")
        } else {
            ui.add(button)
        };
        self.debug_layout
            .note_visible("pair_toggle", resp.rect, ui.clip_rect());
        self.debug_layout
            .note_focus("pair_toggle", &resp, ui.clip_rect());
        if self.preview_ui {
            self.debug_layout
                .note_visible("pair_toggle_disabled", resp.rect, ui.clip_rect());
            return;
        }
        if resp.clicked() {
            self.enroll_open = !self.enroll_open;
        }
    }

    fn apply_preview_fixture(&mut self) {
        self.preview_ui = true;
        self.mock = true;
        self.hide_on_close = false;
        self.autostart = false;
        self.user = Some("Preview (not signed in)".into());
        self.nodes = model::preview_fixture_nodes();
        self.selected_id = self.nodes.first().map(|n| n.id.clone());
        self.screen = Screen::Machines;
        self.link = "isolated preview".into();
        self.window_title = "agentlink controller (preview)".into();
        self.node_line = super::PREVIEW_NODE_LINE.into();
        self.error.clear();
        self.notice.clear();
    }

    fn ensure_selection(&mut self) {
        if let Some(id) = &self.selected_id {
            if self.nodes.iter().any(|node| &node.id == id) {
                return;
            }
        }
        self.selected_id = self.nodes.first().map(|node| node.id.clone());
    }

    fn selected_node(&self) -> Option<NodeInfo> {
        let id = self.selected_id.as_deref()?;
        self.nodes.iter().find(|node| node.id == id).cloned()
    }

    fn machine_list(&mut self, ui: &mut egui::Ui, compact: bool) {
        let nodes = self.nodes.clone();
        let clip = ui.clip_rect();
        // When the list is stacked in the page ScrollArea, paint every fixture
        // in-flow so one vertical scroll reaches the last row and Details.
        // The sidebar rail keeps its own list scroll (see machine_rail).
        if compact {
            let start = ui.min_rect().min;
            ui.set_width(ui.available_width());
            for node in &nodes {
                self.machine_row(ui, node);
                ui.add_space(theme::SPACE_XS);
            }
            let rect = egui::Rect::from_min_max(start, ui.min_rect().max);
            self.debug_layout.note_visible("machine_list", rect, clip);
            return;
        }
        let max_h = ui.available_height();
        let list = egui::ScrollArea::vertical()
            .id_salt("machine-list")
            .auto_shrink([false, true])
            .max_height(max_h)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.set_max_width(ui.available_width());
                for node in &nodes {
                    self.machine_row(ui, node);
                    ui.add_space(theme::SPACE_XS);
                }
            });
        self.debug_layout
            .note_visible("machine_list", list.inner_rect, clip);
    }

    fn machine_row(&mut self, ui: &mut egui::Ui, node: &NodeInfo) {
        let selected = self.selected_id.as_deref() == Some(node.id.as_str());
        let session = match &self.screen {
            Screen::Terminal { id, .. } | Screen::Files { id, .. } | Screen::Desktop { id, .. } => {
                id.as_str() == node.id
            }
            _ => false,
        };
        let hover_id = ui.id().with("machine-row-hover").with(&node.id);
        let hovered = ui.data(|d| d.get_temp::<bool>(hover_id).unwrap_or(false));
        let fill = if selected || session {
            theme::BG_HOVER
        } else if hovered {
            theme::BG_PANEL
        } else {
            theme::BG_SURFACE
        };
        let inner_w = ui.available_width();
        let response = ui
            .push_id(("machine-row", node.id.as_str()), |ui| {
                let frame_resp = egui::Frame::new()
                    .fill(fill)
                    .stroke(if selected {
                        theme::stroke_border()
                    } else {
                        theme::stroke_border_subtle()
                    })
                    .inner_margin(egui::Margin::symmetric(
                        theme::SPACE_SM as i8,
                        theme::SPACE_XS as i8,
                    ))
                    .corner_radius(egui::CornerRadius::same(theme::RADIUS_CONTROL))
                    .show(ui, |ui| {
                        ui.set_width(inner_w);
                        ui.set_max_width(inner_w);
                        let (name_rect, badge_rect) = machine_name_and_status(
                            ui,
                            &node.name,
                            node.online,
                            theme::TEXT_PRIMARY,
                            false,
                        );
                        self.debug_layout.note_visible(
                            &format!("nav_name:{}", node.id),
                            name_rect,
                            ui.clip_rect(),
                        );
                        self.debug_layout.note_visible(
                            &format!("nav_badge:{}", node.id),
                            badge_rect,
                            ui.clip_rect(),
                        );
                        ui.label(theme::muted_text(node_presence_label(
                            node.online,
                            node.has_display,
                        )));
                        if session {
                            ui.label(theme::muted_text("This session"));
                        }
                    })
                    .response;
                let id = ui.id().with("machine-row-focus").with(node.id.as_str());
                ui.interact(frame_resp.rect, id, egui::Sense::click())
            })
            .inner;
        let response = if response.has_focus() {
            let focused = response.clone();
            ui.painter().rect_stroke(
                focused.rect.expand(1.0),
                egui::CornerRadius::same(theme::RADIUS_CONTROL),
                theme::focus_stroke(),
                egui::StrokeKind::Outside,
            );
            focused
        } else {
            response
        };
        self.debug_layout
            .note_item(&format!("nav_row:{}", node.id), response.rect);
        self.debug_layout
            .note_focus(&format!("nav_row:{}", node.id), &response, ui.clip_rect());
        ui.data_mut(|d| d.insert_temp(hover_id, response.hovered()));
        if response.clicked() {
            self.selected_id = Some(node.id.clone());
        }
    }

    fn machine_detail(&mut self, ui: &mut egui::Ui, node: &NodeInfo) {
        let clip = ui.clip_rect();
        let content_w = innermost_avail(ui).min(model::connect_detail_max_width());
        ui.vertical(|ui| {
            ui.set_width(content_w);
            ui.set_max_width(content_w);
            let (name_rect, badge_rect) =
                machine_name_and_status(ui, &node.name, node.online, theme::TEXT_PRIMARY, true);
            self.debug_layout
                .note_visible("detail_name", name_rect, clip);
            self.debug_layout
                .note_visible("detail_badge", badge_rect, clip);
            let host = [node.hostname.as_str(), node.os.as_str(), node.arch.as_str()]
                .into_iter()
                .filter(|part| !part.is_empty())
                .collect::<Vec<_>>()
                .join(" · ");
            let presence = node_presence_label(node.online, node.has_display);
            let subtitle = if host.is_empty() {
                presence.to_string()
            } else {
                format!("{presence} · {host}")
            };
            ui.label(theme::muted_text(&subtitle));
            ui.label(theme::muted_text(format!(
                "Access: {}",
                access_summary(&node.access, node.effective)
            )));
            if let Some(note) = display_note(node.has_display, node.effective) {
                let resp = ui.add(egui::Label::new(theme::muted_text(note)).wrap());
                self.debug_layout
                    .note_visible("display_note", resp.rect, clip);
            }
            ui.add_space(theme::SPACE_MD);
            let prompt = ui.label(theme::section_text("Choose how to connect"));
            self.debug_layout
                .note_visible("connect_prompt", prompt.rect, clip);
            if self.preview_ui {
                ui.label(theme::muted_text(
                    "Sample actions for layout review. This is not a live session.",
                ));
            } else if matches!(self.screen, Screen::Machines) {
                ui.label(theme::muted_text(
                    "Start a terminal, files, or desktop session when the machine allows it.",
                ));
            }
            ui.add_space(theme::SPACE_SM);
            self.session_actions(ui, node, false);
            ui.add_space(theme::SPACE_LG);
            let details = egui::CollapsingHeader::new("Details")
                .default_open(false)
                .show(ui, |ui| {
                    if !node.id.is_empty() {
                        ui.label(theme::muted_text("Node id"));
                        truncated_copy_line(ui, &node.id, &mut self.notice);
                        self.debug_layout.note_item("detail_node_id", ui.min_rect());
                    }
                    if !node.version.is_empty() {
                        ui.label(theme::muted_text(format!("Version: {}", node.version)));
                    }
                    if !node.owner.is_empty() {
                        ui.label(theme::muted_text(format!("Owner: {}", node.owner)));
                    }
                });
            self.debug_layout
                .note_item("details", details.header_response.rect);
            self.debug_layout
                .note_visible("details", details.header_response.rect, clip);
            self.debug_layout
                .note_focus("details", &details.header_response, clip);
        });
    }

    fn session_actions(&mut self, ui: &mut egui::Ui, node: &NodeInfo, compact: bool) {
        let clip = ui.clip_rect();
        let mut disabled = Vec::new();
        if compact {
            ui.horizontal_wrapped(|ui| {
                ui.set_width(ui.available_width());
                ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_SM, theme::SPACE_SM);
                for button in card_buttons(node.online, node.has_display, node.effective) {
                    let action = Action {
                        enabled: button.enabled,
                        reason: button.reason,
                    };
                    let id = format!("action:{}:{}", node.id, button.label);
                    let response = action_button_response(ui, &id, button.label, &action);
                    self.debug_layout.note_button_raw_vis(
                        &format!("action_btn:{}:{}", node.id, button.label),
                        response.rect,
                        clip,
                    );
                    // Keep session-page buttons from taking Enter away from the terminal.
                    if response.has_focus() {
                        response.surrender_focus();
                    }
                    if !action.enabled {
                        disabled.push((button.label, action.reason));
                    }
                    if response.clicked() {
                        self.activate(node, &action, button.kind);
                    }
                }
            });
        } else {
            let gap = model::CONNECT_CARD_GAP;
            let avail = innermost_avail(ui);
            let buttons = card_buttons(node.online, node.has_display, node.effective);
            let (cols, card_w) = model::connect_card_layout(avail, buttons.len());
            // Rows of horizontal groups shrink to content. A Grid inside a
            // tall ScrollArea stretches the last row through the leftover page.
            for row in buttons.chunks(cols) {
                ui.horizontal(|ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(gap, gap);
                    for button in row {
                        let action = Action {
                            enabled: button.enabled,
                            reason: button.reason,
                        };
                        let blurb = action_card_blurb(button.kind);
                        let response = action_card(
                            ui,
                            ("connect-card", node.id.as_str(), button.label),
                            card_w,
                            button.label,
                            blurb,
                            &action,
                        );
                        self.debug_layout.note_button_raw_vis(
                            &format!("action_btn:{}:{}", node.id, button.label),
                            response.rect,
                            clip,
                        );
                        self.debug_layout.note_visible(
                            &format!("action_card:{}:{}", node.id, button.label),
                            response.rect,
                            clip,
                        );
                        self.debug_layout.note_focus(
                            &format!("action_card:{}:{}", node.id, button.label),
                            &response,
                            clip,
                        );
                        if !action.enabled {
                            disabled.push((button.label, action.reason));
                        }
                        if response.clicked() {
                            self.activate(node, &action, button.kind);
                        }
                    }
                });
                ui.add_space(gap);
            }
        }
        for (label, reason) in disabled {
            let resp =
                ui.add(egui::Label::new(theme::muted_text(format!("{label}: {reason}"))).wrap());
            self.debug_layout.note_visible(
                &format!("action_reason:{}:{label}", node.id),
                resp.rect,
                clip,
            );
        }
    }

    fn settings_panel(&mut self, ui: &mut egui::Ui) {
        let clip = ui.clip_rect();
        let frame = theme::card_frame().show(ui, |ui| {
            ui.label(theme::section_text("Settings"));
            ui.label(theme::muted_text(&self.node_line));
            if self.preview_ui {
                ui.label(theme::muted_text(
                    "Start on login is disabled in isolated preview.",
                ));
            } else {
                let label = if self.autostart {
                    "Start on login: on"
                } else {
                    "Start on login: off"
                };
                let resp = ui.add(theme::secondary_button(label));
                self.debug_layout
                    .note_visible("settings_autostart", resp.rect, clip);
                self.debug_layout
                    .note_focus("settings_autostart", &resp, clip);
                if resp.clicked() {
                    self.toggle_autostart();
                }
            }
            ui.add_space(theme::SPACE_XS);
            ui.label(theme::muted_text(format!(
                "About · Agentlink controller {}",
                env!("CARGO_PKG_VERSION")
            )));
            if self.preview_ui {
                ui.label(theme::muted_text(
                    "This window is an isolated layout fixture. It is not a live account.",
                ));
            }
        });
        self.debug_layout
            .note_visible("settings_panel", frame.response.rect, clip);
    }

    fn toggle_autostart(&mut self) {
        let binary = match crate::tray::current_binary() {
            Ok(binary) => binary,
            Err(err) => {
                self.error = err.to_string();
                return;
            }
        };
        let result = if self.autostart {
            #[cfg(windows)]
            {
                crate::tray::remove_user_autostart()
            }
            #[cfg(not(windows))]
            {
                let _ = &binary;
                super::autostart::remove()
            }
        } else {
            #[cfg(windows)]
            {
                crate::tray::install_user_autostart(&binary, &self.data_dir)
            }
            #[cfg(not(windows))]
            {
                super::autostart::install(&binary, &self.data_dir)
            }
        };
        match result {
            Ok(()) => {
                self.autostart = self.live.start_on_login();
                self.notice = if self.autostart {
                    "Start on login is on.".into()
                } else {
                    "Start on login is off.".into()
                };
            }
            Err(err) => self.error = err.to_string(),
        }
    }

    fn activate(&mut self, node: &NodeInfo, action: &Action, kind: CardButtonKind) {
        if !action.enabled {
            self.error = action.reason.to_string();
            return;
        }
        self.error.clear();
        match kind {
            CardButtonKind::Terminal => self.open_terminal(node),
            CardButtonKind::Files => self.open_files(node),
            CardButtonKind::ViewDesktop => self.open_desktop(node, false),
            CardButtonKind::ControlDesktop => self.open_desktop(node, true),
        }
    }

    fn restoring(&mut self, ui: &mut egui::Ui) {
        let avail = ui.available_size();
        ui.allocate_ui_with_layout(
            avail,
            egui::Layout::centered_and_justified(egui::Direction::TopDown),
            |ui| {
                ui.vertical_centered(|ui| {
                    ui.spinner();
                    ui.add_space(theme::SPACE_SM);
                    ui.label(theme::title_text("Restoring session…"));
                    ui.add_space(theme::SPACE_SM);
                    ui.label(theme::muted_text(
                        "You stay signed in when a saved session is still valid. The sign-in form appears only if it is not.",
                    ));
                });
            },
        );
    }

    fn machine_rail(&mut self, ui: &mut egui::Ui) {
        self.ensure_selection();
        let in_session = matches!(
            self.screen,
            Screen::Terminal { .. } | Screen::Files { .. } | Screen::Desktop { .. }
        );
        if in_session {
            let back = ui.add(theme::secondary_button("Back to machines"));
            self.debug_layout
                .note_visible("rail_back", back.rect, ui.clip_rect());
            self.debug_layout
                .note_focus("rail_back", &back, ui.clip_rect());
            if back.clicked() {
                self.back_to_machines();
                return;
            }
            ui.add_space(theme::SPACE_SM);
        }
        ui.label(theme::muted_text("Machines"));
        ui.add_space(theme::SPACE_XS);
        let rail_inner_w = (model::MACHINE_RAIL_WIDTH - theme::SPACE_MD * 2.0)
            .floor()
            .max(1.0);
        ui.set_max_width(rail_inner_w);
        let pair_reserve = if !in_session { 40.0 } else { 0.0 };
        let list_h = (ui.available_height() - pair_reserve).max(48.0);
        let nodes = self.nodes.clone();
        egui::ScrollArea::vertical()
            .id_salt("machine-rail-list")
            .drag_to_scroll(false)
            .max_width(rail_inner_w)
            .max_height(list_h)
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_max_width(rail_inner_w);
                ui.set_width(rail_inner_w);
                for node in &nodes {
                    self.machine_row(ui, node);
                    ui.add_space(theme::SPACE_XS);
                }
            });
        if !in_session {
            ui.add_space(theme::SPACE_SM);
            self.pair_toggle(ui);
        }
    }

    fn enroll(&mut self, ui: &mut egui::Ui) {
        theme::card_frame().show(ui, |ui| {
            ui.label(theme::section_text("Pair a machine"));
            ui.label(theme::muted_text(
                "Creates one install command. exec is shell and files. full adds the desktop.",
            ));
            labeled(ui, "Name", &mut self.enroll_name, false);
            ui.label(theme::muted_text("Access"));
            egui::ComboBox::from_id_salt("enroll-access")
                .selected_text(&self.enroll_access)
                .show_ui(ui, |ui| {
                    for preset in PRESETS {
                        ui.selectable_value(
                            &mut self.enroll_access,
                            (*preset).to_string(),
                            *preset,
                        );
                    }
                });
            labeled(ui, "Minutes", &mut self.enroll_minutes, false);
            let create = ui.add_enabled(
                !self.preview_ui,
                theme::primary_button("Create install command"),
            );
            if self.preview_ui {
                self.debug_layout.note_visible(
                    "enroll_create_disabled",
                    create.rect,
                    ui.clip_rect(),
                );
            }
            if create.clicked() && !self.preview_ui {
                let minutes = self.enroll_minutes.trim().parse::<u64>().unwrap_or(15);
                let name = if self.enroll_name.trim().is_empty() {
                    "machine".into()
                } else {
                    self.enroll_name.trim().to_string()
                };
                self.send(Cmd::Enroll {
                    name,
                    access: self.enroll_access.clone(),
                    minutes,
                });
            }
            if !self.enroll_out.is_empty() {
                ui.label(theme::muted_text("Install command"));
                ui.add(
                    egui::TextEdit::multiline(&mut self.enroll_out)
                        .desired_width(f32::INFINITY)
                        .desired_rows(5)
                        .font(egui::TextStyle::Monospace),
                );
                if ui.add(theme::secondary_button("Copy")).clicked() {
                    ui.ctx().copy_text(self.enroll_out.clone());
                    self.notice = "Copied.".into();
                }
            }
        });
    }

    fn session_back_row(&mut self, ui: &mut egui::Ui, title: String) {
        ui.horizontal_wrapped(|ui| {
            // On a wide window the machine list stays in the left nav, but
            // the back button remains so a narrow layout (or a resized
            // window) never strands the user in a session.
            let back = ui.add(theme::secondary_button("Back to machines"));
            self.debug_layout
                .note_visible("back", back.rect, ui.clip_rect());
            if back.clicked() {
                self.back_to_machines();
            }
            ui.label(theme::section_text(title));
        });
        let link = if self.preview_ui {
            "Isolated preview — not a live connection".to_string()
        } else {
            format!("Connection: {}", self.link)
        };
        ui.label(theme::muted_text(link));
        let id = match &self.screen {
            Screen::Terminal { id, .. } | Screen::Files { id, .. } | Screen::Desktop { id, .. } => {
                Some(id.clone())
            }
            _ => None,
        };
        if let Some(node) = id.and_then(|id| self.nodes.iter().find(|n| n.id == id).cloned()) {
            self.session_actions(ui, &node, true);
        }
    }

    fn terminal(&mut self, ui: &mut egui::Ui) {
        let (id, name) = match &self.screen {
            Screen::Terminal { id, name } => (id.clone(), name.clone()),
            _ => return,
        };
        self.session_back_row(ui, format!("{name} · terminal"));
        ui.label(theme::muted_text(
            "Type in the terminal. Ctrl+Shift+C copies, Ctrl+Shift+V pastes. Ctrl+C sends interrupt.",
        ));
        if !self.term_got_output {
            ui.horizontal(|ui| {
                ui.spinner();
                let waited = self
                    .term_open
                    .map(|started| started.elapsed().as_secs())
                    .unwrap_or(0);
                if waited >= 8 {
                    ui.label(theme::muted_text(
                        "The shell has not sent any output yet. Waiting for the node to open a session…",
                    ));
                } else {
                    ui.label(theme::muted_text("Starting shell…"));
                }
                ui.ctx().request_repaint_after(std::time::Duration::from_millis(250));
            });
        }
        let frame = egui::Frame::new()
            .fill(egui::Color32::from_rgb(0x0D, 0x0D, 0x12))
            .stroke(theme::stroke_border_subtle())
            .inner_margin(egui::Margin::same(theme::SPACE_XS as i8))
            .corner_radius(egui::CornerRadius::same(theme::RADIUS_CARD));
        let shown = frame.show(ui, |ui| {
            ui.set_min_size(egui::vec2(
                ui.available_width(),
                ui.available_height().max(120.0),
            ));
            self.terminal.show(ui)
        });
        self.debug_layout
            .set_page_visible(shown.response.rect, ui.clip_rect());
        let output = shown.inner;
        if let Some((rows, cols)) = output.resized {
            self.term_size = (rows, cols);
            self.send(Cmd::PtyResize { rows, cols });
        }
        if !output.writes.is_empty() {
            self.send(Cmd::PtyWrite {
                data: output.writes,
            });
        }
        let _ = id;
    }

    fn files(&mut self, ui: &mut egui::Ui) {
        let (id, name, can_write) = match &self.screen {
            Screen::Files { id, name } => {
                let policy = self
                    .nodes
                    .iter()
                    .find(|node| node.id == *id)
                    .map(|node| node.effective);
                let can_write = policy.is_some_and(|policy| policy.allow_write);
                (id.clone(), name.clone(), can_write)
            }
            _ => return,
        };
        self.session_back_row(ui, format!("{name} · files"));
        ui.horizontal_wrapped(|ui| {
            if ui.add(theme::secondary_button("Up")).clicked() {
                let path = model::parent_path(&self.file_path);
                self.files_loading = true;
                self.send(Cmd::List {
                    node: id.clone(),
                    path,
                });
            }
            if ui.add(theme::secondary_button("Refresh")).clicked() {
                self.files_loading = true;
                self.send(Cmd::List {
                    node: id.clone(),
                    path: self.file_path.clone(),
                });
            }
            ui.label(theme::mono_text(&self.file_path));
        });
        if self.files_loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(theme::muted_text("Loading files…"));
            });
        } else if self.files.is_empty() && self.error.is_empty() {
            ui.label(theme::muted_text("This folder is empty."));
        }
        let list_h = (ui.available_height() - 160.0).max(160.0);
        let list = egui::ScrollArea::vertical()
            .max_height(list_h)
            .show(ui, |ui| {
                let mut entries = self.files.clone();
                entries.sort_by(|left, right| {
                    right
                        .is_dir
                        .cmp(&left.is_dir)
                        .then_with(|| left.name.cmp(&right.name))
                });
                for entry in entries {
                    ui.horizontal(|ui| {
                        let label = if entry.is_dir {
                            format!("{}/", entry.name)
                        } else {
                            format!("{}  {}", entry.name, entry.size)
                        };
                        if ui.add(theme::secondary_button(&label)).clicked() {
                            let path = model::child_path(&self.file_path, &entry.name);
                            if entry.is_dir {
                                self.editor = None;
                                self.files_loading = true;
                                self.send(Cmd::List {
                                    node: id.clone(),
                                    path,
                                });
                            } else {
                                self.send(Cmd::Read {
                                    node: id.clone(),
                                    path,
                                });
                            }
                        }
                        if can_write && ui.add(theme::secondary_button("Delete")).clicked() {
                            let path = model::child_path(&self.file_path, &entry.name);
                            self.clear_editor_if_deleted(&path);
                            self.send(Cmd::Remove {
                                node: id.clone(),
                                path,
                            });
                        }
                    });
                }
            });
        let clip = ui.clip_rect();
        let mut page = visible_rect(list.inner_rect, clip);
        if can_write {
            ui.horizontal_wrapped(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.folder_name)
                        .hint_text("New folder name")
                        .desired_width(180.0),
                );
                if ui.add(theme::secondary_button("Create folder")).clicked()
                    && !self.folder_name.trim().is_empty()
                {
                    let path = model::child_path(&self.file_path, self.folder_name.trim());
                    self.folder_name.clear();
                    self.send(Cmd::Mkdir {
                        node: id.clone(),
                        path,
                    });
                }
                ui.add(
                    egui::TextEdit::singleline(&mut self.new_file_name)
                        .hint_text("New file name")
                        .desired_width(180.0),
                );
                if ui.add(theme::secondary_button("New file")).clicked()
                    && !self.new_file_name.trim().is_empty()
                {
                    let path = model::child_path(&self.file_path, self.new_file_name.trim());
                    self.new_file_name.clear();
                    self.editor = Some(Editor {
                        path,
                        text: String::new(),
                    });
                }
            });
        }
        let save = if let Some(editor) = &mut self.editor {
            ui.label(&editor.path);
            let edit = ui.add(
                egui::TextEdit::multiline(&mut editor.text)
                    .desired_width(f32::INFINITY)
                    .desired_rows(12)
                    .font(egui::TextStyle::Monospace),
            );
            self.debug_layout
                .note_visible("editor", edit.rect, ui.clip_rect());
            page = page.union(visible_rect(edit.rect, ui.clip_rect()));
            can_write
                .then(|| ui.add(theme::primary_button("Save")).clicked())
                .unwrap_or(false)
                .then(|| (editor.path.clone(), editor.text.clone()))
        } else {
            None
        };
        self.debug_layout.page_rect = rect_xywh(page);
        if let Some((path, text)) = save {
            self.send(Cmd::Write {
                node: id,
                path,
                text,
            });
        }
    }

    fn desktop(&mut self, ui: &mut egui::Ui) {
        let (id, name) = match &self.screen {
            Screen::Desktop { id, name } => (id.clone(), name.clone()),
            _ => return,
        };
        let control = self.control.get(&id).copied().unwrap_or(false);
        let is_windows = self
            .nodes
            .iter()
            .find(|node| node.id == id)
            .is_some_and(|node| node.os.to_ascii_lowercase().contains("windows"));

        // Track pointer motion for fullscreen connection-bar auto-hide.
        let (pointer_y, pointer_moved) = ui.ctx().input(|input| {
            (
                input.pointer.hover_pos().map(|p| p.y),
                input.pointer.is_moving(),
            )
        });
        if pointer_moved {
            self.desk_ui_pointer = Instant::now();
        }
        if let Some(toast_at) = self.desk_toast.as_ref().map(|(_, t)| *t) {
            if toast_at.elapsed() > Duration::from_secs(4) {
                self.desk_toast = None;
            }
        }

        // F11 toggles fullscreen; Esc releases keyboard capture / sticky keys.
        let mut toggle_fs = false;
        let mut release_keys = false;
        ui.ctx().input(|input| {
            for event in &input.events {
                if let egui::Event::Key {
                    key: egui::Key::F11,
                    pressed: true,
                    repeat: false,
                    ..
                } = event
                {
                    toggle_fs = true;
                }
                if let egui::Event::Key {
                    key: egui::Key::Escape,
                    pressed: true,
                    repeat: false,
                    ..
                } = event
                {
                    if self.desk_capture_keys || !self.desk_held_keys.is_empty() {
                        release_keys = true;
                    }
                }
            }
        });
        if toggle_fs {
            self.desk_fullscreen = !self.desk_fullscreen;
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.desk_fullscreen));
            self.desk_ui_pointer = Instant::now();
        }
        if release_keys {
            self.desk_capture_keys = false;
            self.release_remote_input_on(&id);
        }

        let phase = self.desktop_phase();
        let bar_visible = connection_bar_visible(
            self.desk_fullscreen,
            self.desk_ui_pointer.elapsed(),
            pointer_y,
        );
        // One active session today; tab strip height stays zero until multi-session lands.
        let _top_chrome = session_chrome_top_height(1, bar_visible);

        let bar_fade = ui
            .ctx()
            .animate_bool(egui::Id::new("desktop-connection-bar-fade"), bar_visible);
        self.debug_layout.toolbar_visible = bar_visible || bar_fade > 0.01;
        if bar_fade > 0.01 {
            let bar_resp = egui::Frame::new()
                .fill(theme::BG_PANEL)
                .inner_margin(egui::Margin::symmetric(theme::SPACE_SM as i8, 0))
                .show(ui, |ui| {
                    ui.set_opacity(bar_fade);
                    ui.set_min_height(BAR_HEIGHT);
                    ui.set_max_height(BAR_HEIGHT);
                    self.desktop_connection_bar(ui, &id, &name, control, is_windows, phase);
                });
            // Hairline under the bar (RDP-style), not a full card border.
            let edge = bar_resp.response.rect;
            self.debug_layout.toolbar_rect = rect_xywh(edge);
            ui.painter().add(egui::Shape::line_segment(
                [
                    egui::pos2(edge.left(), edge.bottom()),
                    egui::pos2(edge.right(), edge.bottom()),
                ],
                egui::Stroke::new(1.0_f32, theme::BORDER_SUBTLE.linear_multiply(bar_fade)),
            ));
        } else {
            // Keep layout math honest when the bar is auto-hidden.
            ui.allocate_exact_size(egui::vec2(ui.available_width(), 0.0), egui::Sense::hover());
        }

        let available = egui::vec2(ui.available_width(), ui.available_height().max(1.0));
        let pane = egui::Frame::new()
            .fill(egui::Color32::BLACK)
            .inner_margin(egui::Margin::ZERO);
        pane.show(ui, |ui| {
            ui.set_min_size(available);
            ui.set_max_size(available);
            let pane_rect = ui.max_rect();
            self.debug_layout.pane_rect = rect_xywh(pane_rect);
            match phase {
                SessionPhase::Disconnected | SessionPhase::Failed => {
                    self.desktop_disconnected_overlay(
                        ui,
                        &id,
                        &name,
                        pane_rect,
                        phase == SessionPhase::Failed,
                    );
                }
                SessionPhase::Connecting => {
                    self.desktop_connecting_overlay(ui, &name, pane_rect);
                }
                SessionPhase::Live | SessionPhase::Stale => {
                    self.desktop_canvas(ui, &id, control, is_windows, pane_rect);
                    if phase == SessionPhase::Stale {
                        self.desktop_stale_toast(ui, pane_rect);
                    }
                }
            }
            if self.desk_stats_open {
                self.desktop_stats_popover(ui, pane_rect);
            }
            self.desktop_draw_toast(ui, pane_rect);
        });
    }

    fn desktop_connection_bar(
        &mut self,
        ui: &mut egui::Ui,
        id: &str,
        name: &str,
        control: bool,
        is_windows: bool,
        phase: SessionPhase,
    ) {
        let mut restart = false;
        let mut go_back = false;
        let mut disconnect = false;
        let mut fit = false;
        let mut one_to_one = false;
        let mut toggle_fs = false;
        let mut toggle_keys = false;
        let mut paste = false;
        let mut shot = false;
        let mut cad = false;

        ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_XS, 0.0);
        ui.spacing_mut().button_padding = egui::vec2(theme::SPACE_SM, 0.0);
        ui.spacing_mut().interact_size.y = theme::BTN_TOOLBAR_H;

        let monitor_label = self
            .desk_monitors
            .iter()
            .find(|m| m.index == self.desk_monitor)
            .map(|m| {
                if m.primary {
                    format!("{} · primary", m.name)
                } else {
                    format!("{} · {}", m.name, m.index)
                }
            })
            .unwrap_or_else(|| format!("Monitor {}", self.desk_monitor));
        let resolution = if self.desk_hud.width > 0 && self.desk_hud.height > 0 {
            Some(format!("{}×{}", self.desk_hud.width, self.desk_hud.height))
        } else {
            None
        };
        let stats = stats_chip(self.desk_hud.fps, self.desk_hud.latency_ms);
        let zoom_label = format!("{:.0}%", self.desk_zoom * 100.0);
        let fs_label = if self.desk_fullscreen { "Exit" } else { "Full" };
        let tip = if !self.desk_disconnect_reason.is_empty() {
            self.desk_disconnect_reason.as_str()
        } else if !self.error.is_empty() {
            self.error.as_str()
        } else {
            ""
        };

        let measure = BarMeasure {
            node_name: name,
            monitor_label: &monitor_label,
            resolution: resolution.as_deref(),
            stats: stats.as_deref(),
            zoom_label: &zoom_label,
            fullscreen_label: fs_label,
            has_cad: is_windows,
            control,
        };
        let avail = ui.available_width().max(1.0);
        // Step density down until estimated chrome fits, then paint into two
        // exclusive strips (LTR identity/meta | RTL tools) so a mis-estimate
        // clips instead of overlapping.
        let density = pick_bar_density(avail, &measure);
        let right_need = estimate_right_width_with(density, &measure, text_advance)
            .clamp(56.0, (avail * 0.55).max(56.0));
        let gap = theme::SPACE_SM;
        let left_budget = (avail - right_need - gap).max(120.0);

        ui.horizontal(|ui| {
            ui.set_min_height(theme::BAR_HEIGHT);
            ui.set_max_height(theme::BAR_HEIGHT);
            ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_XS, 0.0);
            ui.spacing_mut().button_padding = egui::vec2(theme::SPACE_SM, 0.0);

            ui.allocate_ui_with_layout(
                egui::vec2(left_budget, theme::BAR_HEIGHT),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.set_max_width(left_budget);
                    ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_XS, 0.0);
                    ui.spacing_mut().button_padding = egui::vec2(theme::SPACE_SM, 0.0);

                    let back_label = match density {
                        BarDensity::Icons | BarDensity::Minimal => "←",
                        _ => "← Back",
                    };
                    let back = chrome_bar_button(ui, back_label, "Return to machine list", false);
                    self.debug_layout.note_item("back", back.rect);
                    if back.clicked() {
                        go_back = true;
                    }

                    ui.label(
                        egui::RichText::new(name)
                            .color(theme::TEXT_PRIMARY)
                            .size(theme::SECONDARY_SIZE),
                    );
                    status_dot(ui, phase.dot(), tip);

                    if density != BarDensity::Minimal {
                        let mode_badge = mode_badge_widget(ui, control);
                        self.debug_layout.note_item("mode", mode_badge.rect);
                        chrome_vsep(ui);
                    }

                    let monitor_w = match density {
                        BarDensity::Minimal => 110.0,
                        BarDensity::Icons => 120.0,
                        _ => 140.0,
                    };
                    let monitor_resp = egui::ComboBox::from_id_salt("desk-monitor")
                        .selected_text(theme::bar_text(monitor_label.clone()))
                        .height(theme::BTN_TOOLBAR_H)
                        .width(monitor_w)
                        .show_ui(ui, |ui| {
                            if self.desk_monitors.is_empty() {
                                ui.label(theme::muted_text("No monitors listed yet"));
                            }
                            for monitor in self.desk_monitors.clone() {
                                let label = if monitor.primary {
                                    format!(
                                        "{} ({}×{}) · primary",
                                        monitor.name, monitor.width, monitor.height
                                    )
                                } else {
                                    format!(
                                        "{} ({}×{}) · {}",
                                        monitor.name, monitor.width, monitor.height, monitor.index
                                    )
                                };
                                if ui
                                    .selectable_value(&mut self.desk_monitor, monitor.index, label)
                                    .changed()
                                {
                                    restart = true;
                                }
                            }
                        });
                    self.debug_layout
                        .note_item("monitor", monitor_resp.response.rect);

                    match density {
                        BarDensity::Full | BarDensity::Compact => {
                            if let Some(res) = resolution.as_ref() {
                                ui.label(theme::mono_bar_text(res.clone()));
                            }
                            if let Some(stats) = stats.as_ref() {
                                let stats_btn = ui.add(
                                    egui::Button::new(theme::mono_bar_text(stats.clone()))
                                        .fill(if self.desk_stats_open {
                                            theme::BG_HOVER
                                        } else {
                                            theme::BG_PANEL
                                        })
                                        .stroke(egui::Stroke::NONE)
                                        .corner_radius(egui::CornerRadius::same(
                                            theme::RADIUS_CONTROL,
                                        ))
                                        .min_size(egui::vec2(
                                            theme::ICON_BTN,
                                            theme::BTN_TOOLBAR_H,
                                        )),
                                );
                                self.debug_layout.note_item("stats", stats_btn.rect);
                                if stats_btn.on_hover_text("Session stats").clicked() {
                                    self.desk_stats_open = !self.desk_stats_open;
                                }
                            }
                        }
                        BarDensity::Icons => {
                            if let Some(merged) = stats_line(
                                self.desk_hud.width,
                                self.desk_hud.height,
                                self.desk_hud.fps,
                                self.desk_hud.latency_ms,
                            ) {
                                let stats_btn = ui.add(
                                    egui::Button::new(theme::mono_bar_text(merged))
                                        .fill(if self.desk_stats_open {
                                            theme::BG_HOVER
                                        } else {
                                            theme::BG_PANEL
                                        })
                                        .stroke(egui::Stroke::NONE)
                                        .corner_radius(egui::CornerRadius::same(
                                            theme::RADIUS_CONTROL,
                                        ))
                                        .min_size(egui::vec2(
                                            theme::ICON_BTN,
                                            theme::BTN_TOOLBAR_H,
                                        )),
                                );
                                self.debug_layout.note_item("stats", stats_btn.rect);
                                if stats_btn.on_hover_text("Session stats").clicked() {
                                    self.desk_stats_open = !self.desk_stats_open;
                                }
                            }
                        }
                        BarDensity::Minimal => {}
                    }
                },
            );

            ui.add_space(gap);

            ui.allocate_ui_with_layout(
                egui::vec2(
                    ui.available_width().max(right_need.min(avail)),
                    theme::BAR_HEIGHT,
                ),
                egui::Layout::right_to_left(egui::Align::Center),
                |ui| {
                    ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_XS, 0.0);
                    ui.spacing_mut().button_padding = egui::vec2(theme::SPACE_SM, 0.0);

                    let (fs_text, fs_tip) = match density {
                        BarDensity::Icons | BarDensity::Minimal => {
                            ("FS", "Toggle fullscreen (F11)")
                        }
                        _ => (fs_label, "Toggle fullscreen (F11)"),
                    };
                    let (disc_label, disc_tip) = match density {
                        BarDensity::Icons | BarDensity::Minimal => ("X", "Disconnect"),
                        _ => ("Disconnect", "Stop the remote session"),
                    };
                    let disconnect_btn = chrome_bar_button(ui, disc_label, disc_tip, false);
                    self.debug_layout
                        .note_item("disconnect", disconnect_btn.rect);
                    if disconnect_btn.clicked() {
                        disconnect = true;
                    }
                    if density == BarDensity::Minimal {
                        let fs_btn = chrome_bar_button(ui, fs_text, fs_tip, false);
                        self.debug_layout.note_item("fullscreen", fs_btn.rect);
                        if fs_btn.clicked() {
                            toggle_fs = true;
                        }
                        return;
                    }
                    ui.add_space(theme::SPACE_XS);
                    chrome_vsep(ui);
                    if is_windows {
                        let cad_btn = chrome_bar_button(ui, "CAD", "Send Ctrl+Alt+Del", false);
                        self.debug_layout.note_item("ctrl_alt_del", cad_btn.rect);
                        if cad_btn.clicked() {
                            cad = true;
                        }
                    }
                    let (shot_l, clip_l, key_l) = match density {
                        BarDensity::Icons => ("Sc", "Cb", "Kb"),
                        _ => ("Shot", "Clip", "Keys"),
                    };
                    let shot_btn = chrome_bar_button(ui, shot_l, "Save a remote screenshot", false);
                    self.debug_layout.note_item("shot", shot_btn.rect);
                    if shot_btn.clicked() {
                        shot = true;
                    }
                    let clip_btn =
                        chrome_bar_button(ui, clip_l, "Send local clipboard to the node", false);
                    self.debug_layout.note_item("clipboard", clip_btn.rect);
                    if clip_btn.clicked() {
                        paste = true;
                    }
                    let key_tip = if self.desk_capture_keys {
                        "Keyboard captured — Esc releases"
                    } else {
                        "Capture keyboard for the remote session"
                    };
                    let key = ui.add_enabled(
                        control,
                        theme::icon_button(key_l, self.desk_capture_keys).stroke(
                            if self.desk_capture_keys {
                                egui::Stroke::new(1.0_f32, theme::SUCCESS)
                            } else {
                                egui::Stroke::NONE
                            },
                        ),
                    );
                    self.debug_layout.note_item("keyboard", key.rect);
                    if self.desk_capture_keys {
                        let rect = key.rect;
                        ui.painter().circle_filled(
                            egui::pos2(rect.right() - 4.0, rect.top() + 4.0),
                            2.5,
                            theme::SUCCESS,
                        );
                    }
                    if key.on_hover_text(key_tip).clicked() {
                        toggle_keys = true;
                    }
                    ui.add_space(theme::SPACE_XS);
                    chrome_vsep(ui);
                    let fs_btn = chrome_bar_button(ui, fs_text, fs_tip, false);
                    self.debug_layout.note_item("fullscreen", fs_btn.rect);
                    if fs_btn.clicked() {
                        toggle_fs = true;
                    }
                    match density {
                        BarDensity::Full => {
                            let zoom_btn = chrome_bar_button(ui, &zoom_label, "Zoom", false);
                            let zoom_popup = ui.make_persistent_id("desk-zoom-popup");
                            if zoom_btn.clicked() {
                                ui.memory_mut(|mem| mem.toggle_popup(zoom_popup));
                            }
                            egui::popup::popup_below_widget(
                                ui,
                                zoom_popup,
                                &zoom_btn,
                                egui::popup::PopupCloseBehavior::CloseOnClickOutside,
                                |ui| {
                                    theme::panel_frame().show(ui, |ui| {
                                        ui.set_min_width(180.0);
                                        ui.label(theme::muted_text("Zoom"));
                                        let slider = ui.add(
                                            egui::Slider::new(&mut self.desk_zoom, 0.25..=4.0)
                                                .show_value(true)
                                                .min_decimals(2)
                                                .max_decimals(2),
                                        );
                                        if slider.changed() {
                                            self.desk_fit = false;
                                        }
                                    });
                                },
                            );
                        }
                        BarDensity::Compact | BarDensity::Icons => {
                            ui.label(theme::mono_bar_text(zoom_label.clone()));
                        }
                        BarDensity::Minimal => {}
                    }
                    let one_btn = chrome_bar_button(ui, "1:1", "Native pixel scale", false);
                    if one_btn.clicked() {
                        one_to_one = true;
                    }
                    let fit_btn = chrome_bar_button(ui, "Fit", "Fit picture to the window", false);
                    self.debug_layout.note_item("fit", fit_btn.rect);
                    if fit_btn.clicked() {
                        fit = true;
                    }
                },
            );
        });

        if go_back {
            if self.desk_fullscreen {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                self.desk_fullscreen = false;
            }
            self.back_to_machines();
            return;
        }
        if disconnect {
            if self.desk_fullscreen {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                self.desk_fullscreen = false;
            }
            self.stop_desktop_session("Disconnected");
            return;
        }
        if fit {
            self.desk_fit = true;
            self.desk_zoom = 1.0;
            self.desk_pan = egui::Vec2::ZERO;
        }
        if one_to_one {
            self.desk_fit = false;
            if let Some(texture) = &self.texture {
                let avail = ui.ctx().available_rect().size() - egui::vec2(0.0, BAR_HEIGHT);
                self.desk_zoom = native_zoom(texture.size_vec2(), avail);
            } else {
                self.desk_zoom = 1.0;
            }
            self.desk_pan = egui::Vec2::ZERO;
        }
        if toggle_fs {
            self.desk_fullscreen = !self.desk_fullscreen;
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.desk_fullscreen));
            self.desk_ui_pointer = Instant::now();
        }
        if toggle_keys {
            if self.desk_capture_keys {
                self.desk_capture_keys = false;
                self.release_remote_input_on(id);
            } else {
                self.desk_capture_keys = true;
            }
        }
        if paste {
            self.desk_await_paste = true;
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::RequestPaste);
        }
        if shot {
            let path = default_shot_path();
            self.send(Cmd::Shot {
                node: id.to_string(),
                path,
            });
        }
        if cad {
            self.inject_keys_tap(id, &["ctrl", "alt", "delete"]);
        }
        if restart {
            self.restart_live(id);
        }
    }

    fn desktop_canvas(
        &mut self,
        ui: &mut egui::Ui,
        id: &str,
        control: bool,
        is_windows: bool,
        pane_rect: egui::Rect,
    ) {
        let Some(texture) = self.texture.clone() else {
            return;
        };
        let image_size = texture.size_vec2();
        if self.desk_fit {
            self.desk_zoom = 1.0;
            self.desk_pan = egui::Vec2::ZERO;
        }
        let content = viewport_rect(image_size, pane_rect, self.desk_zoom, self.desk_pan);
        self.debug_layout.content_rect = rect_xywh(content);
        let response = ui.allocate_rect(pane_rect, egui::Sense::click_and_drag());
        egui::Image::new(&texture)
            .fit_to_exact_size(content.size())
            .paint_at(ui, content);

        // Ctrl+wheel zooms; shift+primary (or middle) pans when not capturing input.
        if response.hovered() {
            let (zoom_delta, scroll, ctrl) = ui.ctx().input(|input| {
                (
                    input.zoom_delta(),
                    input.raw_scroll_delta,
                    input.modifiers.ctrl || input.modifiers.command,
                )
            });
            if ctrl && (zoom_delta - 1.0).abs() > 0.001 {
                self.desk_fit = false;
                self.desk_zoom = (self.desk_zoom * zoom_delta).clamp(0.25, 8.0);
            } else if ctrl && scroll.y.abs() > 0.1 {
                self.desk_fit = false;
                let factor = if scroll.y > 0.0 { 1.1 } else { 1.0 / 1.1 };
                self.desk_zoom = (self.desk_zoom * factor).clamp(0.25, 8.0);
            }
        }
        if response.dragged() {
            let pan_gesture = ui.ctx().input(|i| {
                i.pointer.middle_down() || (i.modifiers.shift && i.pointer.primary_down())
            });
            if pan_gesture && (!control || !self.desk_capture_keys) {
                self.desk_fit = false;
                self.desk_pan += response.drag_delta();
            }
        }

        // Local RDP-style menu on right-click; Shift+right goes to the node.
        let shift_right = ui.ctx().input(|i| i.modifiers.shift);
        let menu_open = response.context_menu_opened();
        if !shift_right || menu_open {
            let mut action: Option<DeskMenuAction> = None;
            response.context_menu(|ui| {
                ui.set_min_width(180.0);
                ui.spacing_mut().item_spacing = egui::vec2(0.0, 0.0);
                ui.spacing_mut().button_padding = egui::vec2(theme::BTN_PAD_X, theme::SPACE_XS);
                ui.visuals_mut().window_fill = theme::BG_SURFACE;
                ui.visuals_mut().widgets.hovered.weak_bg_fill = theme::BG_HOVER;
                let item = |ui: &mut egui::Ui, label: &str| {
                    ui.add(
                        egui::Button::new(
                            egui::RichText::new(label.to_owned())
                                .size(theme::SECONDARY_SIZE)
                                .color(theme::TEXT_BODY),
                        )
                        .fill(egui::Color32::TRANSPARENT)
                        .stroke(egui::Stroke::NONE)
                        .corner_radius(egui::CornerRadius::same(theme::RADIUS_CONTROL))
                        .min_size(egui::vec2(ui.available_width(), theme::BTN_TOOLBAR_H)),
                    )
                };
                if is_windows && item(ui, "Send Ctrl+Alt+Del").clicked() {
                    action = Some(DeskMenuAction::Cad);
                    ui.close_menu();
                }
                if item(
                    ui,
                    if self.desk_fullscreen {
                        "Exit fullscreen"
                    } else {
                        "Toggle fullscreen"
                    },
                )
                .clicked()
                {
                    action = Some(DeskMenuAction::Fullscreen);
                    ui.close_menu();
                }
                if item(ui, "Fit to window").clicked() {
                    action = Some(DeskMenuAction::Fit);
                    ui.close_menu();
                }
                if item(ui, "1:1").clicked() {
                    action = Some(DeskMenuAction::OneToOne);
                    ui.close_menu();
                }
                if item(ui, "Release keyboard").clicked() {
                    action = Some(DeskMenuAction::ReleaseKeys);
                    ui.close_menu();
                }
                if item(ui, "Disconnect").clicked() {
                    action = Some(DeskMenuAction::Disconnect);
                    ui.close_menu();
                }
            });
            if let Some(action) = action {
                self.apply_desk_menu(ui, id, action, pane_rect);
            }
        }

        if control {
            // Plain right-click is local menu; Shift+right is forwarded.
            self.desktop_pointer(&id, ui, &response, content, true);
            if self.desk_capture_keys {
                self.desktop_keys(&id, ui);
            } else if response.clicked() {
                self.desk_capture_keys = true;
            }
        }

        // View-only: quiet centered pill. Control without capture: click hint pill.
        if !control || !self.desk_capture_keys {
            let painter = ui.painter_at(pane_rect);
            let label = if !control {
                "View only — keyboard and mouse stay local"
            } else {
                "Click to capture keyboard · Esc releases"
            };
            let galley = painter.layout_no_wrap(
                label.to_string(),
                egui::FontId::proportional(theme::SECONDARY_SIZE),
                theme::TEXT_BODY,
            );
            let pad = egui::vec2(theme::SPACE_MD, theme::SPACE_SM);
            let size = galley.size() + pad * 2.0;
            let rect = egui::Rect::from_center_size(pane_rect.center(), size);
            let fill = egui::Color32::from_rgba_unmultiplied(0x19, 0x1a, 0x1b, 217);
            painter.rect_filled(rect, egui::CornerRadius::same(theme::RADIUS_CONTROL), fill);
            painter.rect_stroke(
                rect,
                egui::CornerRadius::same(theme::RADIUS_CONTROL),
                theme::stroke_border_subtle(),
                egui::StrokeKind::Inside,
            );
            painter.galley(rect.min + pad, galley, theme::TEXT_BODY);
        }
    }

    fn desktop_stats_popover(&mut self, ui: &mut egui::Ui, pane_rect: egui::Rect) {
        let size = egui::vec2(280.0, 256.0);
        let origin = egui::pos2(
            (pane_rect.center().x - size.x / 2.0).max(pane_rect.left() + theme::SPACE_SM),
            pane_rect.top() + theme::SPACE_MD,
        );
        let rect = egui::Rect::from_min_size(origin, size);
        let encoder = encoder_label(
            &self.desk_hud.kind,
            &self.desk_hud.encoder,
            self.desk_hud.hardware,
        );
        let mut close = false;
        ui.scope_builder(egui::UiBuilder::new().max_rect(rect), |ui| {
            theme::panel_frame().show(ui, |ui| {
                ui.set_min_width(size.x - 20.0);
                ui.horizontal(|ui| {
                    ui.label(theme::section_text("Session stats"));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if ui.add(theme::secondary_button("Close")).clicked() {
                            close = true;
                        }
                    });
                });
                ui.add_space(theme::SPACE_XS);
                let path = if self.desk_hud.path.is_empty() {
                    "unknown".to_string()
                } else {
                    self.desk_hud.path.clone()
                };
                let path_line = format!("{} · {}", self.desk_hud.kind, path);
                let hint = if self.desk_hud.path_note.is_empty() {
                    super::model::connection_path_hint(&self.desk_hud.kind, &path).to_string()
                } else {
                    self.desk_hud.path_note.clone()
                };
                let handshake = if self.desk_hud.handshake.is_empty() {
                    "idle".to_string()
                } else {
                    self.desk_hud.handshake.clone()
                };
                let lines = [
                    format!("path  {path_line}"),
                    format!("handshake  {handshake}"),
                    super::chrome::session_stats_rate_line(&self.desk_hud.kind, self.desk_hud.fps),
                    super::chrome::session_stats_bitrate_line(
                        &self.desk_hud.kind,
                        self.desk_hud.bitrate_kbps,
                    ),
                    super::chrome::session_stats_latency_line(
                        &self.desk_hud.kind,
                        self.desk_hud.latency_ms,
                    ),
                    format!("encoder  {encoder}"),
                    format!("dropped  {}", self.desk_hud.frames_dropped),
                    format!(
                        "resolution  {}×{}",
                        self.desk_hud.width, self.desk_hud.height
                    ),
                    hint,
                ];
                for line in lines {
                    ui.label(theme::mono_bar_text(line));
                }
            });
        });
        if close {
            self.desk_stats_open = false;
        }
    }

    fn apply_desk_menu(
        &mut self,
        ui: &mut egui::Ui,
        id: &str,
        action: DeskMenuAction,
        pane_rect: egui::Rect,
    ) {
        match action {
            DeskMenuAction::Cad => self.inject_keys_tap(id, &["ctrl", "alt", "delete"]),
            DeskMenuAction::Fullscreen => {
                self.desk_fullscreen = !self.desk_fullscreen;
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Fullscreen(self.desk_fullscreen));
                self.desk_ui_pointer = Instant::now();
            }
            DeskMenuAction::Fit => {
                self.desk_fit = true;
                self.desk_zoom = 1.0;
                self.desk_pan = egui::Vec2::ZERO;
            }
            DeskMenuAction::OneToOne => {
                self.desk_fit = false;
                if let Some(texture) = &self.texture {
                    self.desk_zoom = native_zoom(texture.size_vec2(), pane_rect.size());
                } else {
                    self.desk_zoom = 1.0;
                }
                self.desk_pan = egui::Vec2::ZERO;
            }
            DeskMenuAction::ReleaseKeys => {
                self.desk_capture_keys = false;
                self.release_remote_input_on(id);
            }
            DeskMenuAction::Disconnect => {
                if self.desk_fullscreen {
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                    self.desk_fullscreen = false;
                }
                self.stop_desktop_session("Disconnected");
            }
        }
    }

    fn desktop_connecting_overlay(&mut self, ui: &mut egui::Ui, name: &str, pane_rect: egui::Rect) {
        let title = format!("Connecting to {name}");
        self.debug_layout.texts.push(title.clone());
        ui.scope_builder(egui::UiBuilder::new().max_rect(pane_rect), |ui| {
            ui.centered_and_justified(|ui| {
                ui.vertical_centered(|ui| {
                    ui.spinner();
                    ui.add_space(theme::SPACE_SM);
                    ui.label(
                        egui::RichText::new(title)
                            .size(theme::SECTION_SIZE)
                            .color(theme::TEXT_PRIMARY)
                            .strong(),
                    );
                    ui.label(theme::muted_text("Negotiating the remote desktop session…"));
                });
            });
        });
    }

    fn desktop_disconnected_overlay(
        &mut self,
        ui: &mut egui::Ui,
        id: &str,
        name: &str,
        pane_rect: egui::Rect,
        failed: bool,
    ) {
        let title = if failed {
            format!("Could not reach {name}")
        } else {
            format!("Disconnected from {name}")
        };
        let reason = if self.desk_disconnect_reason.is_empty() {
            if failed {
                "Connection failed".to_string()
            } else {
                String::new()
            }
        } else {
            self.desk_disconnect_reason.clone()
        };
        let mut reconnect = false;
        let mut back = false;
        ui.scope_builder(egui::UiBuilder::new().max_rect(pane_rect), |ui| {
            ui.centered_and_justified(|ui| {
                ui.vertical_centered(|ui| {
                    let (resp, painter) = ui.allocate_painter(
                        egui::vec2(theme::SPACE_LG, theme::SPACE_LG),
                        egui::Sense::hover(),
                    );
                    painter.circle_filled(resp.rect.center(), theme::STATUS_DOT, theme::DANGER);
                    ui.add_space(theme::SPACE_SM);
                    ui.label(
                        egui::RichText::new(title)
                            .size(theme::SECTION_SIZE)
                            .color(theme::TEXT_PRIMARY)
                            .strong(),
                    );
                    if !reason.is_empty() {
                        ui.label(theme::muted_text(reason));
                    }
                    ui.add_space(theme::SPACE_MD);
                    ui.horizontal(|ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_SM, 0.0);
                        if ui
                            .add_sized([96.0, theme::BTN_PRIMARY_H], theme::primary_button("Retry"))
                            .clicked()
                        {
                            reconnect = true;
                        }
                        if ui
                            .add_sized(
                                [96.0, theme::BTN_PRIMARY_H],
                                theme::secondary_button("Back"),
                            )
                            .clicked()
                        {
                            back = true;
                        }
                    });
                });
            });
        });
        if reconnect {
            self.restart_live(id);
        }
        if back {
            if self.desk_fullscreen {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                self.desk_fullscreen = false;
            }
            self.back_to_machines();
        }
    }

    fn desktop_stale_toast(&self, ui: &mut egui::Ui, pane_rect: egui::Rect) {
        let painter = ui.painter_at(pane_rect);
        let anchor = egui::pos2(pane_rect.max.x - 12.0, pane_rect.min.y + 12.0);
        let line1 = "No frames for 3s";
        let line2 = if !self.desk_disconnect_reason.is_empty() {
            self.desk_disconnect_reason.as_str()
        } else if !self.error.is_empty() {
            self.error.as_str()
        } else {
            ""
        };
        let galley1 = painter.layout_no_wrap(
            line1.to_string(),
            egui::FontId::proportional(theme::BAR_SIZE),
            theme::TEXT_BODY,
        );
        let width = galley1.size().x.max(if line2.is_empty() {
            0.0
        } else {
            painter
                .layout_no_wrap(
                    line2.to_string(),
                    egui::FontId::proportional(theme::BAR_SIZE),
                    theme::TEXT_MUTED,
                )
                .size()
                .x
        }) + theme::SPACE_LG;
        let height = if line2.is_empty() {
            theme::BTN_TOOLBAR_H
        } else {
            44.0
        };
        let rect = egui::Rect::from_min_size(
            egui::pos2(anchor.x - width, anchor.y),
            egui::vec2(width, height),
        );
        painter.rect_filled(
            rect,
            egui::CornerRadius::same(theme::RADIUS_CONTROL),
            theme::OVERLAY_STRONG,
        );
        painter.text(
            rect.left_top() + egui::vec2(theme::SPACE_SM, 6.0),
            egui::Align2::LEFT_TOP,
            line1,
            egui::FontId::proportional(theme::BAR_SIZE),
            theme::TEXT_BODY,
        );
        if !line2.is_empty() {
            painter.text(
                rect.left_top() + egui::vec2(theme::SPACE_SM, 22.0),
                egui::Align2::LEFT_TOP,
                line2,
                egui::FontId::proportional(theme::BAR_SIZE),
                theme::TEXT_MUTED,
            );
        }
    }

    fn desktop_draw_toast(&self, ui: &mut egui::Ui, pane_rect: egui::Rect) {
        let Some((text, at)) = &self.desk_toast else {
            return;
        };
        if at.elapsed() > Duration::from_secs(4) {
            return;
        }
        let painter = ui.painter_at(pane_rect);
        let anchor = egui::pos2(pane_rect.center().x, pane_rect.min.y + theme::SPACE_LG);
        let galley = painter.layout_no_wrap(
            text.clone(),
            egui::FontId::proportional(theme::BAR_SIZE),
            theme::TEXT_BODY,
        );
        let size = galley.size() + egui::vec2(20.0, theme::SPACE_MD);
        let rect = egui::Rect::from_center_size(anchor, size);
        painter.rect_filled(
            rect,
            egui::CornerRadius::same(theme::RADIUS_CONTROL),
            theme::OVERLAY_STRONG,
        );
        painter.galley(rect.min + egui::vec2(10.0, 6.0), galley, theme::TEXT_BODY);
    }

    fn desktop_pointer(
        &mut self,
        node: &str,
        ui: &mut egui::Ui,
        response: &egui::Response,
        content: egui::Rect,
        // When true, right-click belongs to the local context menu (unless Shift).
        local_right_menu: bool,
    ) {
        let pointer = ui.ctx().input(|input| {
            let pos = input.pointer.interact_pos().or(input.pointer.hover_pos());
            let primary = input.pointer.button_pressed(egui::PointerButton::Primary);
            let primary_up = input.pointer.button_released(egui::PointerButton::Primary);
            let secondary = input.pointer.button_pressed(egui::PointerButton::Secondary);
            let secondary_up = input
                .pointer
                .button_released(egui::PointerButton::Secondary);
            let middle = input.pointer.button_pressed(egui::PointerButton::Middle);
            let middle_up = input.pointer.button_released(egui::PointerButton::Middle);
            let double = input
                .pointer
                .button_double_clicked(egui::PointerButton::Primary);
            let moved = input.pointer.is_moving();
            let scroll = input.raw_scroll_delta;
            let ctrl = input.modifiers.ctrl || input.modifiers.command;
            let shift = input.modifiers.shift;
            (
                pos,
                primary,
                primary_up,
                secondary,
                secondary_up,
                middle,
                middle_up,
                double,
                moved,
                scroll,
                ctrl,
                shift,
            )
        });
        let (
            Some(pos),
            primary,
            primary_up,
            secondary,
            secondary_up,
            middle,
            middle_up,
            double,
            moved,
            scroll,
            ctrl,
            shift,
        ) = pointer
        else {
            return;
        };
        if !response.rect.contains(pos) {
            return;
        }
        let (x, y) = point_to_fraction(content, pos);
        self.desk_last_frac = (x, y);

        if primary {
            self.desk_held_buttons.insert("left");
            self.inject_mouse(node, MouseEvent::new("down", x, y, "left"));
        }
        if primary_up && self.desk_held_buttons.remove("left") {
            self.inject_mouse(node, MouseEvent::new("up", x, y, "left"));
        }
        // RDP: plain right-click opens the local menu; Shift+right goes remote.
        let send_right = secondary && !ctrl && (!local_right_menu || shift);
        if send_right {
            self.desk_held_buttons.insert("right");
            self.inject_mouse(node, MouseEvent::new("down", x, y, "right"));
        }
        if secondary_up && self.desk_held_buttons.remove("right") {
            self.inject_mouse(node, MouseEvent::new("up", x, y, "right"));
        }
        if middle {
            self.desk_held_buttons.insert("middle");
            self.inject_mouse(node, MouseEvent::new("down", x, y, "middle"));
        }
        if middle_up && self.desk_held_buttons.remove("middle") {
            self.inject_mouse(node, MouseEvent::new("up", x, y, "middle"));
        }
        if double {
            let mut event = MouseEvent::new("click", x, y, "left");
            event.count = 2;
            self.inject_mouse(node, event);
        }

        // Coalesce moves to the last position in this UI frame — no time throttle.
        let holding = !self.desk_held_buttons.is_empty();
        if (moved || holding) && hit_content(content, pos) {
            self.desk_last_move = Instant::now();
            self.inject_mouse(node, MouseEvent::new("move", x, y, "left"));
        }
        if response.hovered() && !ctrl && (scroll.x.abs() > 0.5 || scroll.y.abs() > 0.5) {
            let mut event = MouseEvent::new("scroll", x, y, "left");
            // Protocol unit is notches (WHEEL_DELTA=120). egui gives pixels.
            event.dx = pixel_delta_to_notches(scroll.x.round() as i32);
            event.dy = pixel_delta_to_notches((-scroll.y).round() as i32);
            self.inject_mouse(node, event);
        }
    }

    fn desktop_keys(&mut self, node: &str, ui: &mut egui::Ui) {
        // Steal focus so TextEdit widgets do not eat keystrokes.
        ui.memory_mut(|mem| mem.request_focus(egui::Id::new("desk-key-capture")));
        let mut edges: Vec<(String, bool)> = Vec::new();
        let mut texts: Vec<String> = Vec::new();
        let mods = ui.ctx().input(|input| {
            for event in &input.events {
                match event {
                    egui::Event::Key {
                        key,
                        pressed,
                        repeat,
                        ..
                    } if !*repeat => {
                        if let Some(name) = egui_key_name(*key) {
                            if name == "escape" && *pressed {
                                continue;
                            }
                            edges.push((name.to_string(), *pressed));
                        }
                    }
                    egui::Event::Text(text) if !text.is_ascii() => texts.push(text.clone()),
                    _ => {}
                }
            }
            (
                input.modifiers.ctrl,
                input.modifiers.alt,
                input.modifiers.shift,
                input.modifiers.command || input.modifiers.mac_cmd,
            )
        });
        // Modifier keys rarely arrive as Key events; mirror egui modifier state.
        let prev = self.desk_mods;
        self.desk_mods = mods;
        for (name, was, now) in [
            ("ctrl", prev.0, mods.0),
            ("alt", prev.1, mods.1),
            ("shift", prev.2, mods.2),
            ("meta", prev.3, mods.3),
        ] {
            if was != now {
                edges.push((name.to_string(), now));
            }
        }
        for text in texts {
            self.inject_text(node, &text);
        }
        for (name, down) in edges {
            if down {
                if self.desk_held_keys.insert(name.clone()) {
                    self.inject_key_edge(node, &name, true);
                }
            } else if self.desk_held_keys.remove(&name) {
                self.inject_key_edge(node, &name, false);
            }
        }
        ui.allocate_exact_size(
            egui::vec2(0.0, 0.0),
            egui::Sense::focusable_noninteractive(),
        );
    }

    fn release_remote_input(&mut self) {
        if let Screen::Desktop { id, .. } = &self.screen {
            let id = id.clone();
            self.release_remote_input_on(&id);
        } else {
            self.desk_held_keys.clear();
            self.desk_held_buttons.clear();
            self.desk_sticky.clear();
        }
    }

    fn release_remote_input_on(&mut self, node: &str) {
        let keys: Vec<String> = self.desk_held_keys.drain().collect();
        for key in keys {
            self.inject_key_edge(node, &key, false);
        }
        let buttons: Vec<&'static str> = self.desk_held_buttons.drain().collect();
        let (x, y) = self.desk_last_frac;
        for button in buttons {
            self.inject_mouse(node, MouseEvent::new("up", x, y, button));
        }
        self.desk_sticky.clear();
        self.desk_mods = (false, false, false, false);
    }

    fn inject_mouse(&self, node: &str, event: MouseEvent<'_>) {
        let mut live = serde_json::json!({
            "type": "mouse",
            "action": event.action,
            "x": event.x,
            "y": event.y,
            "dx": event.dx,
            "dy": event.dy,
            "button": event.button,
            "monitor": self.desk_monitor,
        });
        if event.action == "click" {
            live["count"] = serde_json::json!(event.count);
        }
        let mut inject = serde_json::json!({
            "action": event.action,
            "x": event.x,
            "y": event.y,
            "dx": event.dx,
            "dy": event.dy,
            "button": event.button,
            "monitor": self.desk_monitor,
        });
        if event.action == "click" {
            inject["count"] = serde_json::json!(event.count);
        }
        if event.action == "move" {
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as i64)
                .unwrap_or(0);
            self.shared
                .perf
                .last_move_unix_ms
                .store(now_ms, std::sync::atomic::Ordering::Relaxed);
            // Mouse motion should wake the UI without waiting for the idle timer.
            // (Repaint is requested by the caller via egui response.)
        }
        self.send(Cmd::Input {
            node: node.to_string(),
            live: live.to_string(),
            inject: inject.to_string(),
        });
    }

    fn inject_text(&self, node: &str, text: &str) {
        let live = serde_json::json!({"type": "type", "text": text}).to_string();
        let inject = serde_json::json!({"action": "type", "text": text}).to_string();
        self.send(Cmd::Input {
            node: node.to_string(),
            live,
            inject,
        });
    }

    fn inject_key_edge(&self, node: &str, key: &str, down: bool) {
        let live = serde_json::json!({"type": "key", "keys": [key], "down": down}).to_string();
        let inject = serde_json::json!({"action": "key", "keys": key, "down": down}).to_string();
        self.send(Cmd::Input {
            node: node.to_string(),
            live,
            inject,
        });
    }

    fn inject_keys_tap(&self, node: &str, keys: &[&str]) {
        let live = serde_json::json!({"type": "key", "keys": keys}).to_string();
        let inject = serde_json::json!({"action": "key", "keys": keys.join("+")}).to_string();
        self.send(Cmd::Input {
            node: node.to_string(),
            live,
            inject,
        });
    }

    fn refresh_mock_picture(&mut self, ctx: &egui::Context) {
        if !matches!(self.screen, Screen::Desktop { .. }) {
            return;
        }
        if self.fail_connect || self.desk_connect_failed || self.desk_user_stopped {
            return;
        }
        // Pace mock frames by `--max-fps` (default 30) so fps stats are honest.
        let min_interval = Duration::from_secs_f32(1.0 / self.max_fps.max(1) as f32);
        if self
            .desk_last_frame
            .is_some_and(|t| t.elapsed() < min_interval)
        {
            return;
        }
        let frame = match agentlink_desktop::MockDesktop::frames(960, 480) {
            Ok(frame) => frame,
            Err(_) => return,
        };
        let rgba = agentlink_desktop_bgra_to_rgba(frame.pixels(), frame.width, frame.height);
        self.debug_rgba = Some((frame.width, frame.height, rgba.clone()));
        let image = egui::ColorImage::from_rgba_unmultiplied(
            [frame.width as usize, frame.height as usize],
            &rgba,
        );
        if let Some(texture) = &mut self.texture {
            texture.set(image, egui::TextureOptions::LINEAR);
        } else {
            self.texture =
                Some(ctx.load_texture("mock-desktop", image, egui::TextureOptions::LINEAR));
        }
        self.desk_last_frame = Some(Instant::now());
        self.desk_connect_started = None;
        self.desk_hud.width = frame.width;
        self.desk_hud.height = frame.height;
        self.mock_frame_window_count += 1;
        let elapsed = self.mock_frame_window_start.elapsed();
        if elapsed >= Duration::from_millis(500) {
            self.desk_hud.fps =
                self.mock_frame_window_count as f32 / elapsed.as_secs_f32().max(0.001);
            self.mock_frame_window_start = Instant::now();
            self.mock_frame_window_count = 0;
        }
        self.picture = Some(Picture {
            rgba,
            width: frame.width as usize,
            height: frame.height as usize,
            kind: "mock".into(),
            path: "mock".into(),
            seq: self.seen_seq + 1,
        });
        self.seen_seq += 1;
    }

    fn sync_window_size(&mut self, ctx: &egui::Context) {
        let rect = ctx.screen_rect();
        if rect.width() > 1.0 && rect.height() > 1.0 {
            self.logical_size = (rect.width(), rect.height());
        }
    }

    fn rail_visible_for(&self, ctx: &egui::Context) -> bool {
        model::machine_rail_visible_at(self.logical_size.0, ctx.pixels_per_point())
    }

    pub(super) fn debug_is_mock(&self) -> bool {
        self.mock
    }

    pub(super) fn debug_window_size(&self) -> (f32, f32) {
        self.logical_size
    }

    pub(super) fn debug_resize(&mut self, w: f32, h: f32) {
        self.logical_size = (w, h);
    }

    pub(super) fn debug_request_quit(&mut self) {
        self.debug_quit = true;
        self.flags.quit.store(true, Ordering::Relaxed);
    }

    pub(super) fn debug_queue_raw(&mut self, cmd: &str, args: &Value) {
        match cmd {
            "move" => {
                let x = args.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                let y = args.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                self.debug_events
                    .push(egui::Event::PointerMoved(egui::pos2(x, y)));
            }
            "click" => {
                let x = args.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                let y = args.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                let button = match args
                    .get("button")
                    .and_then(|v| v.as_str())
                    .unwrap_or("left")
                {
                    "right" => egui::PointerButton::Secondary,
                    "middle" => egui::PointerButton::Middle,
                    _ => egui::PointerButton::Primary,
                };
                let pos = egui::pos2(x, y);
                self.debug_events.push(egui::Event::PointerMoved(pos));
                self.debug_events.push(egui::Event::PointerButton {
                    pos,
                    button,
                    pressed: true,
                    modifiers: egui::Modifiers::default(),
                });
                self.debug_events.push(egui::Event::PointerButton {
                    pos,
                    button,
                    pressed: false,
                    modifiers: egui::Modifiers::default(),
                });
            }
            "scroll" => {
                let x = args.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                let y = args.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                let dx = args.get("dx").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                let dy = args.get("dy").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                self.debug_events
                    .push(egui::Event::PointerMoved(egui::pos2(x, y)));
                self.debug_events.push(egui::Event::MouseWheel {
                    unit: egui::MouseWheelUnit::Point,
                    delta: egui::vec2(dx, dy),
                    modifiers: egui::Modifiers::default(),
                });
            }
            _ => {}
        }
    }

    pub(super) fn debug_nav(
        &mut self,
        ctx: &egui::Context,
        to: &str,
        node: &str,
        mode: Option<&str>,
    ) -> Option<String> {
        match to {
            "login" => {
                self.back_to_machines();
                self.user = None;
                self.screen = Screen::Login;
                None
            }
            "machines" | "desktop" => {
                if self.user.is_none() {
                    self.user = Some("debug".into());
                }
                if self.mock && self.nodes.is_empty() {
                    self.nodes.push(mock_node(node));
                    self.control.insert(node.to_string(), true);
                }
                self.back_to_machines();
                None
            }
            "session" => {
                if self.user.is_none() {
                    self.user = Some("debug".into());
                }
                let info = self
                    .nodes
                    .iter()
                    .find(|n| n.id == node || n.name == node)
                    .cloned()
                    .unwrap_or_else(|| mock_node(node));
                if !self.nodes.iter().any(|n| n.id == info.id) {
                    self.nodes.push(info.clone());
                }
                let control = match mode.map(|m| m.to_ascii_lowercase()) {
                    Some(m) if m == "view" => false,
                    Some(m) if m == "control" => true,
                    Some(other) => {
                        return Some(format!("unknown mode '{other}'"));
                    }
                    None => true,
                };
                self.open_desktop(&info, control);
                if self.mock && !self.fail_connect {
                    self.refresh_mock_picture(ctx);
                }
                None
            }
            other => Some(format!("unknown screen '{other}'")),
        }
    }

    pub(super) fn debug_fail(&mut self, what: &str) -> Option<String> {
        match what {
            "connect" => {
                if !matches!(self.screen, Screen::Desktop { .. }) {
                    return Some("not in a session".into());
                }
                self.fail_desktop_session("WebRTC connection failed (debug)");
                None
            }
            other => Some(format!("unknown fail target '{other}'")),
        }
    }

    pub(super) fn debug_state(&self) -> Value {
        let (w, h) = self.logical_size;
        let screen = match &self.screen {
            Screen::Login => "login",
            Screen::Restoring => "restoring",
            Screen::Machines => "machines",
            Screen::Desktop { .. } => "session",
            Screen::Terminal { .. } => "terminal",
            Screen::Files { .. } => "files",
        };
        let node = match &self.screen {
            Screen::Desktop { id, .. } | Screen::Terminal { id, .. } | Screen::Files { id, .. } => {
                Value::String(id.clone())
            }
            _ => Value::Null,
        };
        let phase = self.desktop_phase();
        let conn_state = match phase {
            SessionPhase::Live | SessionPhase::Stale => "connected",
            SessionPhase::Connecting => "connecting",
            SessionPhase::Failed => "failed",
            SessionPhase::Disconnected => "disconnected",
        };
        let bitrate = if self.desk_hud.bitrate_kbps > 0 {
            self.desk_hud.bitrate_kbps
        } else if self.mock && matches!(self.screen, Screen::Desktop { .. }) {
            2000
        } else {
            0
        };
        let encoder = encoder_label(
            &self.desk_hud.kind,
            &self.desk_hud.encoder,
            self.desk_hud.hardware,
        );
        let fit = if self.desk_fit { "fit" } else { "free" };
        let items: Vec<Value> = self
            .debug_layout
            .toolbar_items
            .iter()
            .map(|(id, rect)| json!({"id": id, "rect": rect}))
            .collect();
        let errors = if self.error.is_empty() {
            Vec::<String>::new()
        } else {
            vec![self.error.clone()]
        };
        let conn_error = if self.desk_disconnect_reason.is_empty() {
            Value::Null
        } else {
            Value::String(self.desk_disconnect_reason.clone())
        };
        json!({
            "screen": screen,
            "node": node,
            "title": self.window_title,
            "window": {"w": w, "h": h},
            "fullscreen": self.desk_fullscreen,
            "stats_open": self.desk_stats_open,
            "connection": {
                "state": conn_state,
                "mode": self.session_mode(),
                "error": conn_error,
                "kind": self.desk_hud.kind,
                "path": self.desk_hud.path,
                "path_note": self.desk_hud.path_note,
                "handshake": self.desk_hud.handshake,
                "link": self.link,
                "fps": self.desk_hud.fps,
                "bitrate_kbps": bitrate,
                "latency_ms": self.desk_hud.latency_ms,
                "encoder": encoder,
                "frames_dropped": self.desk_hud.frames_dropped,
            },
            "perf": self.shared.perf.snapshot(),
            "toolbar": {
                "visible": self.debug_layout.toolbar_visible,
                "height": self.debug_layout.toolbar_rect[3],
                "rect": self.debug_layout.toolbar_rect,
                "items": items,
            },
            "viewport": {
                "image_rect": self.debug_layout.pane_rect,
                "content_rect": self.debug_layout.content_rect,
                "zoom": self.desk_zoom,
                "pan": [self.desk_pan.x, self.desk_pan.y],
                "fit": fit,
            },
            "keyboard_captured": self.desk_capture_keys,
            "texts": self.debug_layout.texts,
            "errors": errors,
        })
    }

    pub(super) fn debug_layout_json(&self) -> Value {
        let items: Vec<Value> = self
            .debug_layout
            .toolbar_items
            .iter()
            .map(|(id, rect)| json!({"id": id, "rect": rect}))
            .collect();
        json!({
            "toolbar": {
                "visible": self.debug_layout.toolbar_visible,
                "height": self.debug_layout.toolbar_rect[3],
                "rect": self.debug_layout.toolbar_rect,
                "items": items,
            },
            "viewport": {
                "image_rect": self.debug_layout.pane_rect,
                "content_rect": self.debug_layout.content_rect,
            },
            "session": {
                "rail_rect": self.debug_layout.rail_rect,
                "main_rect": self.debug_layout.main_rect,
                "page_rect": self.debug_layout.page_rect,
            },
            "window": {
                "w": self.logical_size.0,
                "h": self.logical_size.1,
            },
        })
    }

    pub(super) fn debug_screenshot(&self, path: &str) -> Result<(), String> {
        if path.is_empty() {
            return Err("missing path".into());
        }
        let Some((w, h, rgba)) = self.debug_rgba.as_ref() else {
            return Err("no-renderer".into());
        };
        image::save_buffer(path, rgba, *w, *h, image::ColorType::Rgba8).map_err(|e| e.to_string())
    }
}

fn mock_node(name: &str) -> NodeInfo {
    let policy = NodePolicy::full();
    NodeInfo {
        id: name.to_string(),
        name: name.to_string(),
        hostname: name.to_string(),
        os: "windows".into(),
        arch: "x86_64".into(),
        version: "0.0.0-mock".into(),
        online: true,
        policy: policy.clone(),
        effective: policy,
        owner: String::new(),
        relation: "owner".into(),
        access: "full".into(),
        has_display: Some(true),
    }
}

fn mock_monitors() -> Vec<MonitorEntry> {
    vec![
        MonitorEntry {
            index: 0,
            name: "mock-0".into(),
            width: 960,
            height: 480,
            primary: true,
            capturable: Some(true),
            reason: None,
        },
        MonitorEntry {
            index: 1,
            name: "mock-1".into(),
            width: 320,
            height: 480,
            primary: false,
            capturable: Some(true),
            reason: None,
        },
    ]
}

fn agentlink_desktop_bgra_to_rgba(bgra: &[u8], width: u32, height: u32) -> Vec<u8> {
    let mut rgba = vec![0u8; width as usize * height as usize * 4];
    for (src, dst) in bgra.chunks_exact(4).zip(rgba.chunks_exact_mut(4)) {
        dst[0] = src[2];
        dst[1] = src[1];
        dst[2] = src[0];
        dst[3] = src[3];
    }
    rgba
}

/// egui / wgpu reject textures larger than `max_texture_side` (often 2048/8192).
/// Keep the on-screen copy within that limit; HUD still reports the source size.
/// Takes ownership so the common no-scale path avoids an extra RGBA clone.
fn fit_rgba_for_egui(
    width: usize,
    height: usize,
    rgba: Vec<u8>,
    ctx: &egui::Context,
) -> (usize, usize, Vec<u8>) {
    let max_side = ctx.input(|i| i.max_texture_side).max(512);
    let edge = width.max(height).max(1);
    if edge <= max_side && rgba.len() >= width.saturating_mul(height).saturating_mul(4) {
        return (width, height, rgba);
    }
    let scale = (max_side as f32) / edge as f32;
    let out_w = ((width as f32) * scale).round().max(1.0) as usize;
    let out_h = ((height as f32) * scale).round().max(1.0) as usize;
    let mut out = vec![0u8; out_w.saturating_mul(out_h).saturating_mul(4)];
    for y in 0..out_h {
        let src_y = ((y as f32 + 0.5) / scale).floor() as usize;
        let src_y = src_y.min(height.saturating_sub(1));
        for x in 0..out_w {
            let src_x = ((x as f32 + 0.5) / scale).floor() as usize;
            let src_x = src_x.min(width.saturating_sub(1));
            let si = (src_y * width + src_x) * 4;
            let di = (y * out_w + x) * 4;
            if si + 4 <= rgba.len() && di + 4 <= out.len() {
                out[di..di + 4].copy_from_slice(&rgba[si..si + 4]);
            }
        }
    }
    (out_w, out_h, out)
}

fn chrono_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

enum DeskMenuAction {
    Cad,
    Fullscreen,
    Fit,
    OneToOne,
    ReleaseKeys,
    Disconnect,
}

struct MouseEvent<'a> {
    action: &'a str,
    x: f64,
    y: f64,
    dx: i32,
    dy: i32,
    button: &'a str,
    count: u32,
}

impl<'a> MouseEvent<'a> {
    fn new(action: &'a str, x: f64, y: f64, button: &'a str) -> Self {
        Self {
            action,
            x,
            y,
            dx: 0,
            dy: 0,
            button,
            count: 1,
        }
    }
}

fn chrome_bar_button(ui: &mut egui::Ui, label: &str, tip: &str, active: bool) -> egui::Response {
    ui.add(theme::icon_button(label, active)).on_hover_text(tip)
}

fn chrome_vsep(ui: &mut egui::Ui) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(1.0, 16.0), egui::Sense::hover());
    ui.painter().rect_filled(rect, 0.0, theme::BORDER_SUBTLE);
}

fn mode_badge_widget(ui: &mut egui::Ui, control: bool) -> egui::Response {
    let (label, text) = if control {
        ("CONTROL", theme::ACCENT)
    } else {
        ("VIEW", theme::TEXT_MUTED)
    };
    let response = egui::Frame::new()
        .fill(egui::Color32::TRANSPARENT)
        .stroke(theme::stroke_border())
        .inner_margin(egui::Margin::symmetric(6, 2))
        .corner_radius(egui::CornerRadius::same(4))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(label)
                    .size(theme::PILL_SIZE)
                    .extra_letter_spacing(0.4)
                    .color(text),
            );
        })
        .response;
    response.on_hover_text(if control {
        "Control session"
    } else {
        "View-only session"
    })
}

fn status_dot(ui: &mut egui::Ui, dot: ConnDot, error: &str) {
    let (response, painter) = ui.allocate_painter(
        egui::vec2(
            theme::STATUS_DOT + theme::SPACE_SM,
            theme::STATUS_DOT + theme::SPACE_SM,
        ),
        egui::Sense::hover(),
    );
    let color = match dot {
        ConnDot::Connected => theme::SUCCESS,
        ConnDot::Reconnecting => theme::WARN,
        ConnDot::Disconnected => theme::DANGER,
    };
    painter.circle_filled(response.rect.center(), theme::STATUS_DOT * 0.5, color);
    response.on_hover_text(dot.tooltip(error));
}

fn default_shot_path() -> String {
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let name = format!("agentlink-{stamp}.png");
    if let Some(home) = std::env::var_os("HOME").or_else(|| std::env::var_os("USERPROFILE")) {
        let pictures = std::path::PathBuf::from(home).join("Pictures");
        return pictures.join(name).to_string_lossy().into_owned();
    }
    name
}

fn egui_key_name(key: egui::Key) -> Option<&'static str> {
    match key {
        egui::Key::Enter => Some("enter"),
        egui::Key::Escape => Some("escape"),
        egui::Key::Tab => Some("tab"),
        egui::Key::Backspace => Some("backspace"),
        egui::Key::Delete => Some("delete"),
        egui::Key::ArrowLeft => Some("left"),
        egui::Key::ArrowRight => Some("right"),
        egui::Key::ArrowUp => Some("up"),
        egui::Key::ArrowDown => Some("down"),
        egui::Key::PageUp => Some("pageup"),
        egui::Key::PageDown => Some("pagedown"),
        egui::Key::Home => Some("home"),
        egui::Key::End => Some("end"),
        egui::Key::Space => Some("space"),
        egui::Key::Minus => Some("minus"),
        egui::Key::Equals => Some("equal"),
        egui::Key::A => Some("a"),
        egui::Key::B => Some("b"),
        egui::Key::C => Some("c"),
        egui::Key::D => Some("d"),
        egui::Key::E => Some("e"),
        egui::Key::F => Some("f"),
        egui::Key::G => Some("g"),
        egui::Key::H => Some("h"),
        egui::Key::I => Some("i"),
        egui::Key::J => Some("j"),
        egui::Key::K => Some("k"),
        egui::Key::L => Some("l"),
        egui::Key::M => Some("m"),
        egui::Key::N => Some("n"),
        egui::Key::O => Some("o"),
        egui::Key::P => Some("p"),
        egui::Key::Q => Some("q"),
        egui::Key::R => Some("r"),
        egui::Key::S => Some("s"),
        egui::Key::T => Some("t"),
        egui::Key::U => Some("u"),
        egui::Key::V => Some("v"),
        egui::Key::W => Some("w"),
        egui::Key::X => Some("x"),
        egui::Key::Y => Some("y"),
        egui::Key::Z => Some("z"),
        egui::Key::Num0 => Some("0"),
        egui::Key::Num1 => Some("1"),
        egui::Key::Num2 => Some("2"),
        egui::Key::Num3 => Some("3"),
        egui::Key::Num4 => Some("4"),
        egui::Key::Num5 => Some("5"),
        egui::Key::Num6 => Some("6"),
        egui::Key::Num7 => Some("7"),
        egui::Key::Num8 => Some("8"),
        egui::Key::Num9 => Some("9"),
        _ => None,
    }
}

fn banner(ui: &mut egui::Ui, text: &str, alert: bool) -> egui::Response {
    let (fill, color, stroke) = if alert {
        (theme::DANGER_SOFT, theme::DANGER, theme::DANGER)
    } else {
        (theme::ACCENT_SOFT, theme::TEXT_BODY, theme::BORDER)
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0_f32, stroke))
        .inner_margin(egui::Margin::same(theme::SPACE_SM as i8))
        .corner_radius(egui::CornerRadius::same(theme::RADIUS_CARD))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(text)
                    .size(theme::SECONDARY_SIZE)
                    .color(color),
            );
        })
        .response
}

fn status_pill(
    ui: &mut egui::Ui,
    text: &str,
    color: egui::Color32,
    dot: Option<egui::Color32>,
) -> egui::Response {
    egui::Frame::new()
        .fill(theme::BG_SURFACE)
        .stroke(theme::stroke_border_subtle())
        .inner_margin(egui::Margin::symmetric(
            theme::SPACE_SM as i8,
            theme::SPACE_XS as i8,
        ))
        .corner_radius(egui::CornerRadius::same(255))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_XS, 0.0);
                if let Some(dot) = dot {
                    let (resp, painter) = ui.allocate_painter(
                        egui::vec2(theme::STATUS_DOT, theme::STATUS_DOT),
                        egui::Sense::hover(),
                    );
                    painter.circle_filled(resp.rect.center(), theme::STATUS_DOT * 0.5, dot);
                }
                ui.label(
                    egui::RichText::new(text)
                        .size(theme::SECONDARY_SIZE)
                        .color(color),
                );
            });
        })
        .response
}

/// Name on its own row (wraps, full text in the tooltip). Status pill on
/// the next row so a long name cannot clip the badge.
fn machine_name_and_status(
    ui: &mut egui::Ui,
    name: &str,
    online: bool,
    color: egui::Color32,
    heading: bool,
) -> (egui::Rect, egui::Rect) {
    let size = if heading {
        theme::TITLE_SIZE
    } else {
        theme::BODY_SIZE
    };
    let name_resp = ui.add(
        egui::Label::new(egui::RichText::new(name).size(size).color(color).strong())
            .wrap()
            .sense(egui::Sense::hover()),
    );
    let name_resp = name_resp.on_hover_text(name);
    let badge_resp = online_pill(ui, online);
    (name_resp.rect, badge_resp.rect)
}

fn online_pill(ui: &mut egui::Ui, online: bool) -> egui::Response {
    let (label, color) = if online {
        ("ONLINE", theme::SUCCESS)
    } else {
        ("OFFLINE", theme::TEXT_FAINT)
    };
    egui::Frame::new()
        .fill(egui::Color32::TRANSPARENT)
        .stroke(theme::stroke_border_subtle())
        .inner_margin(egui::Margin::symmetric(
            theme::SPACE_SM as i8,
            theme::SPACE_XS as i8,
        ))
        .corner_radius(egui::CornerRadius::same(theme::RADIUS_CONTROL))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_XS, 0.0);
                let (resp, painter) = ui.allocate_painter(
                    egui::vec2(theme::STATUS_DOT, theme::STATUS_DOT),
                    egui::Sense::hover(),
                );
                painter.circle_filled(resp.rect.center(), theme::STATUS_DOT * 0.5, color);
                ui.label(
                    egui::RichText::new(label)
                        .size(theme::SECONDARY_SIZE)
                        .color(theme::TEXT_MUTED),
                );
            });
        })
        .response
}

fn action_card_blurb(kind: CardButtonKind) -> &'static str {
    match kind {
        CardButtonKind::Terminal => "Open a shell on this machine.",
        CardButtonKind::Files => "Browse and transfer files.",
        CardButtonKind::ViewDesktop => "Watch the remote display.",
        CardButtonKind::ControlDesktop => "Control the remote display.",
    }
}

fn action_card(
    ui: &mut egui::Ui,
    id: impl std::hash::Hash,
    width: f32,
    label: &str,
    blurb: &str,
    action: &Action,
) -> egui::Response {
    // Native egui Button so Tab/Enter use built-in focus (widgets.active 2px ring).
    // Do not pin fill/stroke — that would hide the focused stroke.
    let color = if action.enabled {
        theme::TEXT_BODY
    } else {
        theme::TEXT_FAINT
    };
    let text = format!("{label}\n{blurb}\n{}", action.reason);
    let btn = egui::Button::new(
        egui::RichText::new(text)
            .size(theme::BODY_SIZE)
            .color(color),
    )
    .wrap_mode(egui::TextWrapMode::Wrap)
    .corner_radius(egui::CornerRadius::same(theme::RADIUS_CARD))
    .min_size(egui::vec2(width, 88.0));
    let inner = ui.push_id(id, |ui| {
        ui.set_min_width(width);
        ui.set_max_width(width);
        ui.add_enabled(action.enabled, btn)
    });
    let mut response = inner.inner.on_hover_text(action.reason);
    if !action.enabled {
        response = response.on_disabled_hover_text(action.reason);
    }
    response
}

fn labeled(ui: &mut egui::Ui, name: &str, text: &mut String, secret: bool) {
    ui.label(theme::muted_text(name));
    let edit = egui::TextEdit::singleline(text)
        .password(secret)
        .desired_width(f32::INFINITY)
        .min_size(egui::vec2(0.0, theme::BTN_PRIMARY_H))
        .margin(egui::Margin::symmetric(theme::BTN_PAD_X as i8, 0));
    style_text_edit(ui, edit);
}

fn style_text_edit(ui: &mut egui::Ui, edit: egui::TextEdit<'_>) -> egui::Response {
    let mut visuals = ui.visuals().clone();
    visuals.extreme_bg_color = theme::BG_SURFACE;
    visuals.selection.bg_fill = theme::ACCENT_BG;
    visuals.widgets.inactive.bg_stroke = theme::stroke_border_subtle();
    visuals.widgets.hovered.bg_stroke = egui::Stroke::new(1.0_f32, theme::ACCENT);
    visuals.widgets.active.bg_stroke = egui::Stroke::new(1.0_f32, theme::ACCENT);
    ui.scope(|ui| {
        *ui.visuals_mut() = visuals;
        ui.add(edit)
    })
    .inner
}

fn truncated_copy_line(ui: &mut egui::Ui, text: &str, notice: &mut String) {
    let response = ui.add(
        egui::Label::new(
            egui::RichText::new(text)
                .size(12.0)
                .monospace()
                .color(theme::TEXT_MUTED),
        )
        .truncate()
        .sense(egui::Sense::click()),
    );
    let tip = format!(
        "{text}
Click to copy"
    );
    let response = response.on_hover_text(tip);
    if response.clicked() {
        ui.ctx().copy_text(text.to_string());
        *notice = "Copied.".into();
    }
}

/// Full on-screen width of an action label, including pad + stroke.
///
/// Under-counting (pad only) let Terminal|Files|View desktop share one rail
/// row by a few pixels; the rail clip then ate the final glyph of
/// "View desktop" (max-session GUI screenshot).
fn action_button_min_width(ui: &egui::Ui, label: &str, color: egui::Color32) -> f32 {
    let font = egui::FontId::proportional(theme::SECONDARY_SIZE);
    let text_w = ui.fonts(|fonts| fonts.layout_no_wrap(label.to_owned(), font, color).size().x);
    let stroke = theme::stroke_border_subtle().width;
    (text_w + theme::BTN_PAD_X * 2.0 + stroke * 2.0).ceil()
}

fn action_button_response(
    ui: &mut egui::Ui,
    id: &str,
    label: &str,
    action: &Action,
) -> egui::Response {
    let (fill, color) = if action.enabled {
        (theme::BG_SURFACE, theme::TEXT_BODY)
    } else {
        (theme::BG_PANEL, theme::TEXT_FAINT)
    };
    let min_w = action_button_min_width(ui, label, color);
    let btn = egui::Button::new(
        egui::RichText::new(label.to_owned())
            .size(theme::SECONDARY_SIZE)
            .color(color),
    )
    .fill(fill)
    .stroke(theme::stroke_border_subtle())
    .corner_radius(egui::CornerRadius::same(theme::RADIUS_CONTROL))
    .wrap_mode(egui::TextWrapMode::Extend)
    .min_size(egui::vec2(min_w, theme::BTN_TOOLBAR_H));
    ui.push_id(id, |ui| ui.add_enabled(action.enabled, btn))
        .inner
        .on_hover_text(action.reason)
}

fn action_button(ui: &mut egui::Ui, id: &str, label: &str, action: &Action) -> bool {
    let response = action_button_response(ui, id, label, action);
    // These starts are click actions only. Enter in a focused terminal must
    // never activate a rail or card button and switch the session target.
    if response.has_focus() {
        response.surrender_focus();
    }
    response.clicked()
}

fn node_summary(
    live: &super::LiveHooks,
    data_dir: &std::path::Path,
    config_dir: &std::path::Path,
) -> String {
    let view = live.load_view(data_dir, config_dir);
    format!(
        "This computer: {} · {} · {}",
        view.connection, view.pairing, view.account
    )
}

fn trust_is_custom(trust: &str) -> bool {
    let trust = trust.trim();
    !trust.is_empty() && trust != "system+webpki"
}

/// Convert egui pixel wheel deltas to protocol notches (WHEEL_DELTA = 120).
fn pixel_delta_to_notches(delta: i32) -> i32 {
    if delta == 0 {
        return 0;
    }
    let n = delta / 120;
    if n == 0 {
        if delta > 0 {
            1
        } else {
            -1
        }
    } else {
        n
    }
}

#[cfg(test)]
mod geometry_tests {
    use super::*;
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    /// Visible page / Back must cover a real fraction of the window.
    /// A crushed `ui.horizontal()` row leaves ≈ interact height; raw widget
    /// rects alone can still look tall while clip-visible bounds are tiny.
    fn min_page_visible_h(window_h: f32) -> f32 {
        (window_h * 0.35).max(160.0)
    }

    fn min_main_visible_w(window_w: f32) -> f32 {
        if model::machine_rail_visible(window_w) {
            (window_w - model::MACHINE_RAIL_WIDTH) * 0.45
        } else {
            window_w * 0.55
        }
    }

    fn min_back_visible_w() -> f32 {
        120.0
    }

    struct Harness {
        app: ControllerApp,
        cmd_rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
        _tmpdir: TempDir,
        ctx: egui::Context,
        time: f64,
        pending_events: Vec<egui::Event>,
        pixels_per_point: f32,
    }

    impl Harness {
        fn new(w: f32, h: f32) -> Self {
            Self::new_with(w, h, false, super::super::LiveHooks::production())
        }

        /// `w`/`h` are physical pixels. `pixels_per_point` is the platform scale.
        fn new_physical(phys_w: f32, phys_h: f32, pixels_per_point: f32) -> Self {
            let ppp = pixels_per_point.max(0.01);
            let mut harn = Self::new(phys_w / ppp, phys_h / ppp);
            harn.pixels_per_point = ppp;
            harn
        }

        fn preview(w: f32, h: f32, live: super::super::LiveHooks) -> Self {
            let mut harn = Self::new_with(w, h, true, live);
            harn.app.apply_preview_fixture();
            harn
        }

        fn new_with(w: f32, h: f32, preview_ui: bool, live: super::super::LiveHooks) -> Self {
            let tmp = TempDir::new().expect("tmpdir");
            let config = tmp.path().join("config");
            let data = tmp.path().join("data");
            std::fs::create_dir_all(&config).expect("config dir");
            std::fs::create_dir_all(&data).expect("data dir");
            let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
            let shared = Arc::new(Shared::new());
            let flags = TrayFlags {
                open: Arc::new(AtomicBool::new(false)),
                quit: Arc::new(AtomicBool::new(false)),
            };
            let mut app = ControllerApp::new_debug(
                tx,
                shared,
                config,
                data,
                false,
                flags,
                true,
                (w, h),
                false,
                12,
                30,
                preview_ui,
                live,
            );
            if !preview_ui {
                app.user = Some("debug".into());
                // Realistic session rail: exec-only + full-capability desktop node
                // (sufa) so "View desktop" is present for clip regressions.
                app.nodes = realistic_nodes();
                for node in &app.nodes {
                    app.control.insert(node.id.clone(), true);
                }
                app.screen = Screen::Machines;
            }
            let ctx = egui::Context::default();
            apply_theme_public(&ctx);
            Self {
                app,
                cmd_rx: rx,
                _tmpdir: tmp,
                ctx,
                time: 0.0,
                pending_events: Vec::new(),
                pixels_per_point: 1.0,
            }
        }

        fn resize(&mut self, w: f32, h: f32) {
            self.app.debug_resize(w, h);
        }

        fn pass(&mut self) {
            let _ = self.pass_output();
        }

        /// One UI pass; returns egui viewport commands emitted this frame.
        fn pass_output(&mut self) -> egui::FullOutput {
            let (w, h) = self.app.debug_window_size();
            let screen = egui::Rect::from_min_size(egui::pos2(0.0, 0.0), egui::vec2(w, h));
            let mut viewports = egui::ViewportIdMap::default();
            viewports.insert(
                egui::ViewportId::ROOT,
                egui::ViewportInfo {
                    native_pixels_per_point: Some(self.pixels_per_point),
                    inner_rect: Some(screen),
                    ..Default::default()
                },
            );
            let raw = egui::RawInput {
                screen_rect: Some(screen),
                viewports,
                time: Some(self.time),
                predicted_dt: 1.0 / 60.0,
                focused: true,
                events: std::mem::take(&mut self.pending_events),
                ..Default::default()
            };
            self.time += 1.0 / 60.0;
            self.ctx.run(raw, |ctx| {
                self.app.ui_frame(ctx);
            })
        }

        fn click_item(&mut self, id: &str) {
            let rect = item_rect(&self.app.debug_layout, id).expect(id);
            let pos = egui::pos2(rect[0] + rect[2] / 2.0, rect[1] + rect[3] / 2.0);
            self.pending_events.push(egui::Event::PointerMoved(pos));
            self.pending_events.push(egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            });
            self.pass();
            self.pending_events.push(egui::Event::PointerMoved(pos));
            self.pending_events.push(egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            });
            self.pass();
        }

        fn titles_from(output: &egui::FullOutput) -> Vec<String> {
            let mut titles = Vec::new();
            for viewport in output.viewport_output.values() {
                for cmd in &viewport.commands {
                    if let egui::ViewportCommand::Title(title) = cmd {
                        titles.push(title.clone());
                    }
                }
            }
            titles
        }

        fn min_inner_sizes_from(output: &egui::FullOutput) -> Vec<[f32; 2]> {
            let mut sizes = Vec::new();
            for viewport in output.viewport_output.values() {
                for cmd in &viewport.commands {
                    if let egui::ViewportCommand::MinInnerSize(size) = cmd {
                        sizes.push([size.x, size.y]);
                    }
                }
            }
            sizes
        }

        fn open_sufa_desktop(&mut self) {
            let desk = self
                .app
                .nodes
                .iter()
                .find(|n| n.id == "sufa")
                .cloned()
                .expect("sufa");
            self.app.open_desktop(&desk, false);
        }

        fn populate_files(&mut self) {
            self.app.files_loading = false;
            self.app.file_path = ".".into();
            self.app.files = vec![
                agentlink_core::DirEntry {
                    name: "src".into(),
                    is_dir: true,
                    is_file: false,
                    is_symlink: false,
                    size: 0,
                    modified_unix_ms: None,
                    mode: None,
                },
                agentlink_core::DirEntry {
                    name: "readme.txt".into(),
                    is_dir: false,
                    is_file: true,
                    is_symlink: false,
                    size: 12,
                    modified_unix_ms: None,
                    mode: None,
                },
            ];
            self.app.editor = Some(Editor {
                path: "readme.txt".into(),
                text: "hello from geometry test\n".into(),
            });
        }

        fn press_key(&mut self, key: egui::Key, modifiers: egui::Modifiers) {
            self.pending_events.push(egui::Event::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            });
            self.pass();
            self.pending_events.push(egui::Event::Key {
                key,
                physical_key: None,
                pressed: false,
                repeat: false,
                modifiers,
            });
            self.pass();
        }

        fn press_tab(&mut self, shift: bool) {
            let mut modifiers = egui::Modifiers::default();
            modifiers.shift = shift;
            self.press_key(egui::Key::Tab, modifiers);
        }

        fn press_enter(&mut self) {
            self.press_key(egui::Key::Enter, egui::Modifiers::default());
        }

        fn scroll_content(&mut self, dy: f32) {
            let clip = self.app.debug_layout.visible_clip;
            let pos = if clip[2] > 1.0 && clip[3] > 1.0 {
                egui::pos2(clip[0] + clip[2] * 0.5, clip[1] + clip[3] * 0.5)
            } else {
                let (w, h) = self.app.debug_window_size();
                egui::pos2(w * 0.5, h * 0.5)
            };
            self.pending_events.push(egui::Event::PointerMoved(pos));
            self.pending_events.push(egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, dy),
                modifiers: egui::Modifiers::default(),
            });
            self.pass();
        }

        fn focused_ids(&self) -> Vec<String> {
            self.app
                .debug_layout
                .toolbar_items
                .iter()
                .filter(|(id, _)| id.starts_with("focus:"))
                .map(|(id, _)| id.clone())
                .collect()
        }

        fn open_quant_terminal(&mut self) {
            let node = self
                .app
                .nodes
                .iter()
                .find(|n| n.id == "quant67")
                .cloned()
                .expect("quant67");
            self.app.open_terminal(&node);
        }
    }

    fn realistic_nodes() -> Vec<NodeInfo> {
        let mut quant = mock_node("quant67");
        quant.has_display = Some(false);
        quant.policy = NodePolicy::exec();
        quant.effective = NodePolicy::exec();
        quant.access = "exec".into();

        let mut sufa = mock_node("sufa");
        sufa.has_display = Some(true);
        sufa.policy = NodePolicy::full();
        sufa.effective = NodePolicy::full();
        sufa.access = "full".into();

        let mut tccn = mock_node("tc-cn");
        tccn.has_display = Some(false);
        tccn.policy = NodePolicy::exec();
        tccn.effective = NodePolicy::exec();

        vec![quant, sufa, tccn]
    }

    fn item_rect(layout: &DebugLayout, id: &str) -> Option<[f32; 4]> {
        layout
            .toolbar_items
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, rect)| *rect)
    }

    fn assert_back_clip_visible(layout: &DebugLayout, window: (f32, f32)) {
        let back = item_rect(layout, "back")
            .or_else(|| item_rect(layout, "rail_back"))
            .expect("Back to machines visible rect");
        assert!(
            back[2] >= min_back_visible_w(),
            "back clip-visible width too small: {back:?} win={window:?}"
        );
        assert!(
            back[3] >= 20.0,
            "back clip-visible height too small: {back:?} win={window:?}"
        );
        assert!(
            back[0] >= -1.0 && back[1] >= -1.0,
            "back visible origin off-screen: {back:?}"
        );
        assert!(
            back[0] + back[2] <= window.0 + 1.0,
            "back visible past right: {back:?} win={window:?}"
        );
        assert!(
            back[1] + back[3] <= window.1 + 1.0,
            "back visible past bottom: {back:?} win={window:?}"
        );
    }

    fn assert_session_clip_geometry(layout: &DebugLayout, w: f32, h: f32, expect_rail: bool) {
        let main = layout.main_rect;
        assert!(
            main[2] >= min_main_visible_w(w),
            "main width crushed: {main:?} at {w}x{h}"
        );
        assert!(
            main[3] >= min_page_visible_h(h),
            "main height crushed (black remainder): {main:?} at {w}x{h}"
        );
        if expect_rail {
            let rail = layout.rail_rect;
            assert!(
                (rail[2] - model::MACHINE_RAIL_WIDTH).abs() < 1.0,
                "rail width: {rail:?}"
            );
            assert!(
                rail[3] >= min_page_visible_h(h),
                "rail height crushed: {rail:?} at {w}x{h}"
            );
            assert!(
                (rail[0] + rail[2] - main[0]).abs() < 2.0,
                "gap between rail and main: rail={rail:?} main={main:?}"
            );
        } else {
            assert_eq!(layout.rail_rect, [0.0; 4], "rail should fold below show-at");
        }
        let page = layout.page_rect;
        assert!(
            page[2] >= 80.0,
            "page clip-visible width: {page:?} at {w}x{h}"
        );
        assert!(
            page[3] >= min_page_visible_h(h) * 0.55,
            "page clip-visible height too small (black pane): {page:?} at {w}x{h}"
        );
        assert!(
            page[1] + page[3] <= h + 1.0,
            "page visible past bottom: {page:?} at {w}x{h}"
        );
        assert_back_clip_visible(layout, (w, h));
    }

    fn assert_action_fully_visible(layout: &DebugLayout, key: &str, window_w: f32) {
        let raw = item_rect(layout, &format!("{key}:raw")).unwrap_or_else(|| {
            panic!(
                "missing raw rect for {key}; have {:?}",
                layout
                    .toolbar_items
                    .iter()
                    .map(|(k, _)| k)
                    .collect::<Vec<_>>()
            )
        });
        let vis = item_rect(layout, &format!("{key}:vis")).expect("vis rect");
        let min_w = if key.ends_with("View desktop") || key.ends_with("Control desktop") {
            90.0
        } else {
            48.0
        };
        assert!(
            raw[2] >= min_w,
            "{key} raw width too small (label incomplete?): {raw:?}"
        );
        assert!(
            (vis[2] - raw[2]).abs() <= 1.0 && (vis[3] - raw[3]).abs() <= 1.0,
            "{key} clipped: raw={raw:?} vis={vis:?}"
        );
        assert!(
            vis[0] >= 0.0 && vis[0] + vis[2] <= window_w + 1.0,
            "{key} vis outside window: {vis:?} w={window_w}"
        );
    }

    fn assert_view_desktop_fully_in_clip(layout: &DebugLayout) {
        // Actions live in the detail / session toolbar, not the compact nav.
        let w = if layout.main_rect[2] > 0.0 {
            layout.main_rect[0] + layout.main_rect[2]
        } else {
            1920.0
        };
        assert_action_fully_visible(layout, "action_btn:sufa:View desktop", w);
    }

    #[test]
    fn session_geometry_terminal_files_machines_desktop_wide_and_narrow() {
        // 725 (true narrow), 1080 (restored ≈1085 physical), 1280, 1920.
        for &(w, h) in &[
            (725.0_f32, 800.0_f32),
            (1080.0_f32, 800.0_f32),
            (1280.0_f32, 800.0_f32),
            (1920.0_f32, 1200.0_f32),
        ] {
            let mut harn = Harness::new(w, h);
            harn.pass();
            harn.pass();

            harn.app.screen = Screen::Machines;
            harn.pass();
            let main = harn.app.debug_layout.main_rect;
            assert!(main[2] > w * 0.5, "machines main width {main:?} at {w}x{h}");
            assert!(
                main[3] > h * 0.5,
                "machines main height {main:?} at {w}x{h}"
            );

            let expect_rail = model::machine_rail_visible(w);
            harn.open_quant_terminal();
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, h, expect_rail);
            if !expect_rail {
                assert_eq!(harn.app.debug_layout.rail_rect, [0.0; 4]);
            }
            // quant67 is headless: toolbar has Terminal/Files, not a fake desktop.
            assert_action_fully_visible(&harn.app.debug_layout, "action_btn:quant67:Terminal", w);

            let node = harn.app.nodes[0].clone();
            harn.app.open_files(&node);
            harn.populate_files();
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, h, expect_rail);
            assert!(
                item_rect(&harn.app.debug_layout, "editor")
                    .is_some_and(|r| r[2] > 80.0 && r[3] > 40.0),
                "editor clip-visible missing/small at {w}"
            );

            let desk = harn
                .app
                .nodes
                .iter()
                .find(|n| n.id == "sufa")
                .cloned()
                .unwrap();
            harn.app.open_desktop(&desk, true);
            harn.pass();
            harn.pass();
            let pane = harn.app.debug_layout.pane_rect;
            assert!(pane[2] > w * 0.5, "desktop pane width {pane:?} at {w}x{h}");
            assert!(pane[3] > h * 0.4, "desktop pane height {pane:?} at {w}x{h}");
        }
    }

    #[test]
    fn rail_view_desktop_label_fully_visible_when_rail_shown() {
        let mut harn = Harness::new(1280.0, 800.0);
        harn.app.selected_id = Some("sufa".into());
        harn.app.screen = Screen::Machines;
        harn.pass();
        harn.pass();
        assert!(model::machine_rail_visible(1280.0));
        assert_view_desktop_fully_in_clip(&harn.app.debug_layout);
        assert_action_fully_visible(
            &harn.app.debug_layout,
            "action_btn:sufa:Control desktop",
            1280.0,
        );
        let sufa = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "sufa")
            .cloned()
            .unwrap();
        harn.app.open_terminal(&sufa);
        harn.pass();
        harn.pass();
        assert_view_desktop_fully_in_clip(&harn.app.debug_layout);
        assert_action_fully_visible(
            &harn.app.debug_layout,
            "action_btn:sufa:Control desktop",
            1280.0,
        );
    }

    #[test]
    fn restored_1080_and_true_725_fold_rail_1280_keeps_it() {
        // Compact nav stays at 1024 / restored ~1080. Only truly narrow
        // frames (719 / 725) fold it.
        for &(w, expect_rail) in &[
            (719.0_f32, false),
            (725.0_f32, false),
            (799.0_f32, false),
            (800.0_f32, true),
            (1024.0_f32, true),
            (1080.0_f32, true),
            (1085.0_f32, true),
            (1280.0_f32, true),
            (1920.0_f32, true),
        ] {
            assert_eq!(
                model::machine_rail_visible(w),
                expect_rail,
                "rail policy at {w}"
            );
            let mut harn = Harness::new(w, 800.0);
            harn.open_quant_terminal();
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, 800.0, expect_rail);
        }
    }

    #[test]
    fn session_geometry_survives_wide_restored_narrow_wide_resize() {
        let mut harn = Harness::new(1280.0, 800.0);
        harn.pass();
        harn.pass();
        let node = harn.app.nodes[0].clone();

        for kind in ["terminal", "files"] {
            match kind {
                "terminal" => harn.app.open_terminal(&node),
                _ => {
                    harn.app.open_files(&node);
                    harn.populate_files();
                }
            }
            harn.resize(1280.0, 800.0);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, 1280.0, 800.0, true);
            assert_action_fully_visible(
                &harn.app.debug_layout,
                "action_btn:quant67:Terminal",
                1280.0,
            );

            // Restored-window size from screenshot (~1085), not the preview 725.
            harn.resize(1080.0, 800.0);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, 1080.0, 800.0, true);
            assert_action_fully_visible(
                &harn.app.debug_layout,
                "action_btn:quant67:Terminal",
                1080.0,
            );

            harn.resize(725.0, 800.0);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, 725.0, 800.0, false);
            if kind == "files" {
                assert!(
                    item_rect(&harn.app.debug_layout, "editor")
                        .is_some_and(|r| r[2] > 80.0 && r[3] > 40.0),
                    "editor vanished after narrow resize"
                );
            }

            harn.resize(1920.0, 1200.0);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, 1920.0, 1200.0, true);
            assert_action_fully_visible(
                &harn.app.debug_layout,
                "action_btn:quant67:Terminal",
                1920.0,
            );

            harn.resize(1280.0, 800.0);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, 1280.0, 800.0, true);
        }
    }

    #[test]
    fn clip_visible_gates_reject_interact_height_strip_and_partial_label() {
        let interact = theme::BTN_TOOLBAR_H;
        let fake_page = [280.0, 40.0, 900.0, interact];
        let fake_back = [280.0, 8.0, 40.0, interact.min(24.0)];
        assert!(
            fake_page[3] < min_page_visible_h(800.0) * 0.55,
            "gates must reject crushed page visible height"
        );
        assert!(
            fake_back[2] < min_back_visible_w(),
            "gates must reject clipped Back width"
        );
        // Partial "View deskto" visible width must not pass full-label gate.
        let raw = [12.0, 40.0, 118.0, 28.0];
        let vis = [12.0, 40.0, 96.0, 28.0];
        assert!(
            f32::abs(vis[2] - raw[2]) > 1.0,
            "partial label fixture must differ raw vs vis"
        );
    }

    /// Parent GUI: readonly sufa Desktop → Back → quant67 Terminal left the
    /// native title stuck on "sufa — …". Transitions used to assign
    /// `window_title` before `sync_window_title`, so the compare suppressed
    /// ViewportCommand::Title. Assert the *outgoing* Title commands.
    #[test]
    fn native_title_commands_follow_session_and_clear_on_back() {
        let mut harn = Harness::new(1280.0, 800.0);
        harn.pass();
        assert_eq!(harn.app.window_title, "agentlink controller");

        harn.open_sufa_desktop();
        let out = harn.pass_output();
        let titles = Harness::titles_from(&out);
        assert!(
            titles.iter().any(|t| t.starts_with("sufa —")),
            "expected Title for sufa desktop, got {titles:?}; cache={}",
            harn.app.window_title
        );
        assert!(
            harn.app.window_title.starts_with("sufa —"),
            "cache should match desktop: {}",
            harn.app.window_title
        );

        // No-session: Back must emit the default title (not leave native on sufa).
        harn.app.back_to_machines();
        let out = harn.pass_output();
        let titles = Harness::titles_from(&out);
        assert_eq!(
            titles,
            vec!["agentlink controller".to_string()],
            "Back must emit Title clear; cache={}",
            harn.app.window_title
        );

        // Old → new node: quant67 Terminal must emit a quant67 Title.
        harn.open_quant_terminal();
        let out = harn.pass_output();
        let titles = Harness::titles_from(&out);
        assert_eq!(
            titles,
            vec!["quant67 — terminal — agentlink".to_string()],
            "terminal Title must name quant67; cache={}",
            harn.app.window_title
        );

        // Stable frame: no redundant Title when unchanged.
        let out = harn.pass_output();
        assert!(
            Harness::titles_from(&out).is_empty(),
            "unchanged session must not re-emit Title"
        );

        // Terminal → Files on the same node still changes the mode suffix.
        let node = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "quant67")
            .cloned()
            .unwrap();
        harn.app.open_files(&node);
        let out = harn.pass_output();
        assert_eq!(
            Harness::titles_from(&out),
            vec!["quant67 — files — agentlink".to_string()]
        );

        // Files → different node Terminal.
        let sufa = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "sufa")
            .cloned()
            .unwrap();
        harn.app.open_terminal(&sufa);
        let out = harn.pass_output();
        assert_eq!(
            Harness::titles_from(&out),
            vec!["sufa — terminal — agentlink".to_string()]
        );

        harn.app.back_to_machines();
        let out = harn.pass_output();
        assert_eq!(
            Harness::titles_from(&out),
            vec!["agentlink controller".to_string()]
        );
    }

    /// Premature cache update used to hide Title: open_desktop assigning
    /// window_title before sync made the compare a no-op. Mutation guard.
    #[test]
    fn title_sync_still_emits_when_cache_was_not_pre_assigned() {
        let mut harn = Harness::new(1280.0, 800.0);
        harn.pass();
        // Simulate the old bug: cache already matches the new screen title
        // before the first sync after transition.
        harn.open_sufa_desktop();
        harn.app.window_title = harn.app.compute_window_title();
        let out = harn.pass_output();
        assert!(
            Harness::titles_from(&out).is_empty(),
            "pre-assigned cache correctly suppresses Title (documents the bug class)"
        );
        // A real transition that does not pre-assign must emit.
        harn.app.back_to_machines();
        // Intentionally leave cache as the desktop title (no pre-assign).
        let out = harn.pass_output();
        assert_eq!(
            Harness::titles_from(&out),
            vec!["agentlink controller".to_string()],
            "sync must emit when only screen changed"
        );
    }

    /// Offscreen raw viewport at the declared 640×480 minimum and at true
    /// 725. Layout must stay usable; we must not emit MinInnerSize that would
    /// raise the native floor. Does **not** claim the parent GUI's inability
    /// to drag below ≈1080 is fixed (WM/drag may still pin).
    #[test]
    fn offscreen_640_and_725_session_geometry_without_raising_min_inner() {
        for &(w, h) in &[
            (640.0_f32, 480.0_f32),
            (725.0_f32, 480.0_f32),
            (725.0_f32, 800.0_f32),
        ] {
            let mut harn = Harness::new(w, h);
            harn.pass();
            harn.open_quant_terminal();
            let out = harn.pass_output();
            assert!(
                Harness::min_inner_sizes_from(&out).is_empty(),
                "app must not emit MinInnerSize at {w}x{h}; got {:?}",
                Harness::min_inner_sizes_from(&out)
            );
            harn.pass();
            let expect_rail = model::machine_rail_visible(w);
            assert_session_clip_geometry(&harn.app.debug_layout, w, h, expect_rail);

            let node = harn.app.nodes[0].clone();
            harn.app.open_files(&node);
            harn.populate_files();
            let out = harn.pass_output();
            assert!(
                Harness::min_inner_sizes_from(&out).is_empty(),
                "files session must not emit MinInnerSize at {w}x{h}"
            );
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, h, expect_rail);
            assert!(
                item_rect(&harn.app.debug_layout, "editor")
                    .is_some_and(|r| r[2] > 40.0 && r[3] > 24.0),
                "editor must remain visible at declared min {w}x{h}: {:?}",
                item_rect(&harn.app.debug_layout, "editor")
            );

            // Page/editor must not report a raw width that exceeds the window
            // (overflow that could pin a native resize in some WMs).
            let page = harn.app.debug_layout.page_rect;
            assert!(
                page[0] + page[2] <= w + 1.0,
                "page overflows window width at {w}: {page:?}"
            );
            if let Some(editor) = item_rect(&harn.app.debug_layout, "editor") {
                assert!(
                    editor[0] + editor[2] <= w + 1.0,
                    "editor overflows window width at {w}: {editor:?}"
                );
            }
        }
    }

    fn assert_no_overflow(layout: &DebugLayout, w: f32, h: f32) {
        for (id, rect) in &layout.toolbar_items {
            if id.ends_with(":raw")
                || id.starts_with("nav_row:")
                || id == "machine_list"
                || id == "detail_node_id"
                || id == "pair_toggle"
                || id == "details"
                || id.starts_with("action_reason:")
            {
                continue;
            }
            if rect[2] <= 0.0 || rect[3] <= 0.0 {
                continue;
            }
            assert!(
                rect[0] + rect[2] <= w + 1.5,
                "{id} overflows right: {rect:?} at {w}x{h}"
            );
            assert!(
                rect[1] + rect[3] <= h + 1.5,
                "{id} overflows bottom: {rect:?} at {w}x{h}"
            );
        }
        let main = layout.main_rect;
        assert!(
            main[0] + main[2] <= w + 1.5,
            "main overflows: {main:?} at {w}x{h}"
        );
    }

    fn assert_machines_shell(harn: &Harness, w: f32, h: f32, expect_rail: bool) {
        let layout = &harn.app.debug_layout;
        let main = layout.main_rect;
        assert!(
            main[2] > w * 0.45,
            "machines main width crushed: {main:?} at {w}x{h}"
        );
        assert!(
            main[3] > h * 0.35,
            "machines main height crushed: {main:?} at {w}x{h}"
        );
        if expect_rail {
            let rail = layout.rail_rect;
            assert!(
                (rail[2] - model::MACHINE_RAIL_WIDTH).abs() < 1.0,
                "rail width: {rail:?} at {w}"
            );
            assert!(
                rail[3] >= min_page_visible_h(h) * 0.8,
                "rail short: {rail:?}"
            );
        } else {
            assert_eq!(layout.rail_rect, [0.0; 4], "rail should fold at {w}");
        }
        assert!(
            item_rect(layout, "header_settings").is_some(),
            "Settings missing at {w}x{h}"
        );
        assert!(
            item_rect(layout, "header_quit").is_some(),
            "Quit missing at {w}x{h}"
        );
        for node in &harn.app.nodes {
            assert!(
                item_rect(layout, &format!("nav_row:{}", node.id)).is_some(),
                "nav row missing for {} at {w}x{h}",
                node.id
            );
        }
        let selected = harn.app.selected_id.clone().expect("selection");
        for label in ["Terminal", "Files"] {
            let key = format!("action_btn:{selected}:{label}");
            assert_action_fully_visible(layout, &key, w);
        }
        assert_no_overflow(layout, w, h);
    }

    #[test]
    fn machines_geometry_1024_719_1280() {
        for &(w, h, expect_rail) in &[
            (1024.0_f32, 756.0_f32, true),
            (719.0_f32, 756.0_f32, false),
            (1280.0_f32, 800.0_f32, true),
        ] {
            let mut harn = Harness::new(w, h);
            harn.app.screen = Screen::Machines;
            harn.app.selected_id = Some("sufa".into());
            harn.pass();
            harn.pass();
            assert_eq!(model::machine_rail_visible(w), expect_rail);
            assert_machines_shell(&harn, w, h, expect_rail);

            let node = harn.app.nodes[0].clone();
            harn.app.open_terminal(&node);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, h, expect_rail);
            assert!(
                item_rect(&harn.app.debug_layout, "back").is_some()
                    || item_rect(&harn.app.debug_layout, "rail_back").is_some(),
                "Back missing in terminal at {w}x{h}"
            );
            assert_no_overflow(&harn.app.debug_layout, w, h);
        }
    }

    #[test]
    fn headless_hides_desktop_starts_and_shows_reason() {
        let mut harn = Harness::new(1024.0, 756.0);
        let mut node = harn.app.nodes[0].clone();
        node.id = "headless-node".into();
        node.name = "headless-box".into();
        node.has_display = Some(false);
        harn.app.nodes.insert(0, node.clone());
        harn.app.selected_id = Some(node.id.clone());
        harn.app.screen = Screen::Machines;
        harn.pass();
        harn.pass();
        let layout = &harn.app.debug_layout;
        assert!(
            item_rect(layout, "action_btn:headless-node:View desktop:raw").is_none(),
            "headless must not show View desktop: {:?}",
            layout.toolbar_items
        );
        assert!(
            item_rect(layout, "action_btn:headless-node:Control desktop:raw").is_none(),
            "headless must not show Control desktop"
        );
        assert!(
            item_rect(layout, "display_note").is_some(),
            "headless needs an on-screen reason"
        );
        assert_action_fully_visible(layout, "action_btn:headless-node:Terminal", 1024.0);
        assert_action_fully_visible(layout, "action_btn:headless-node:Files", 1024.0);
    }

    #[test]
    fn view_only_disables_control_with_reason() {
        let mut harn = Harness::new(1024.0, 756.0);
        let mut node = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "sufa")
            .cloned()
            .expect("sufa");
        node.effective = NodePolicy::remote_view();
        node.policy = NodePolicy::remote_view();
        node.access = "remote-view".into();
        node.has_display = Some(true);
        if let Some(existing) = harn.app.nodes.iter_mut().find(|n| n.id == "sufa") {
            *existing = node;
        }
        harn.app.selected_id = Some("sufa".into());
        harn.app.screen = Screen::Machines;
        harn.pass();
        harn.pass();
        let layout = &harn.app.debug_layout;
        assert_action_fully_visible(layout, "action_btn:sufa:View desktop", 1024.0);
        let raw = item_rect(layout, "action_btn:sufa:Control desktop:raw")
            .expect("Control desktop should stay visible (disabled, not hidden)");
        let vis = item_rect(layout, "action_btn:sufa:Control desktop:vis").expect("control vis");
        assert!(
            (vis[2] - raw[2]).abs() <= 1.0,
            "Control clipped: {raw:?} {vis:?}"
        );
        let reason = item_rect(layout, "action_reason:sufa:Control desktop");
        assert!(reason.is_some(), "disabled Control needs an inline reason");
    }

    #[test]
    fn preview_fixture_is_isolated_and_labeled() {
        let mut harn = Harness::preview(1024.0, 756.0, super::super::LiveHooks::production());
        harn.pass();
        let out = harn.pass_output();
        let titles = Harness::titles_from(&out);
        assert!(
            harn.app.window_title.contains("preview"),
            "title cache: {}",
            harn.app.window_title
        );
        assert!(
            titles.iter().any(|t| t.contains("preview"))
                || harn.app.window_title == "agentlink controller (preview)",
            "preview title missing: {titles:?}"
        );
        assert!(harn.app.preview_ui && harn.app.mock);
        assert!(!harn.app.hide_on_close);
        assert!(!harn.app.autostart);
        assert!(harn
            .app
            .nodes
            .iter()
            .all(|n| n.id.starts_with("preview-fixture-")
                && n.name.contains("Fixture")
                && n.name.contains("sample")));
        let layout = &harn.app.debug_layout;
        assert!(
            item_rect(layout, "preview_banner").is_some(),
            "preview banner missing"
        );
        assert!(item_rect(layout, "header_logout").is_none());
        assert!(item_rect(layout, "header_refresh").is_none());
        assert_machines_shell(&harn, 1024.0, 756.0, true);
        let headless = "preview-fixture-headless";
        harn.app.selected_id = Some(headless.into());
        harn.pass();
        harn.pass();
        assert!(
            item_rect(
                &harn.app.debug_layout,
                &format!("action_btn:{headless}:View desktop:raw")
            )
            .is_none(),
            "preview headless must not look like a usable desktop"
        );
        assert!(item_rect(&harn.app.debug_layout, "display_note").is_some());
    }

    #[test]
    fn preview_entry_and_pump_skip_live_resolver_autostart_and_load() {
        let live = super::super::LiveHooks::production();
        let mut harn = Harness::preview(1024.0, 756.0, live.clone());
        assert_eq!(
            live.counts(),
            (0, 0, 0),
            "preview construction must not resolve data-dir, read autostart, or load_view"
        );
        assert_eq!(harn.app.node_line, super::super::PREVIEW_NODE_LINE);
        assert!(!harn.app.autostart);
        assert!(harn
            .app
            .nodes
            .iter()
            .all(|n| n.id.starts_with("preview-fixture-")));
        harn.app.last_node = Instant::now() - Duration::from_secs(3);
        harn.pass();
        harn.pass();
        assert_eq!(
            live.counts(),
            (0, 0, 0),
            "pump past 2s must not call live resolver/autostart/load in preview"
        );
        assert_eq!(harn.app.node_line, super::super::PREVIEW_NODE_LINE);
        assert!(harn
            .app
            .nodes
            .iter()
            .all(|n| n.id.starts_with("preview-fixture-")));
        assert!(!harn.app.hide_on_close);
        assert!(item_rect(&harn.app.debug_layout, "preview_banner").is_some());
    }

    #[test]
    fn preview_pair_toggle_is_disabled_and_drops_no_enroll() {
        let mut harn = Harness::preview(1024.0, 756.0, super::super::LiveHooks::production());
        harn.pass();
        harn.pass();
        assert!(
            item_rect(&harn.app.debug_layout, "pair_toggle").is_some(),
            "Pair stays visible (disabled) so layout does not regress"
        );
        assert!(item_rect(&harn.app.debug_layout, "pair_toggle_disabled").is_some());
        assert!(!harn.app.enroll_open);
        harn.click_item("pair_toggle");
        assert!(
            !harn.app.enroll_open,
            "disabled Pair must not open the enroll panel"
        );
        assert!(
            harn.cmd_rx.try_recv().is_err(),
            "preview must not queue an enroll command"
        );
    }

    #[test]
    fn settings_and_logout_fit_on_narrow_header() {
        for &(w, h) in &[
            (719.0_f32, 756.0_f32),
            (1024.0_f32, 756.0_f32),
            (1280.0_f32, 800.0_f32),
        ] {
            let mut harn = Harness::new(w, h);
            harn.app.screen = Screen::Machines;
            harn.app.selected_id = Some("sufa".into());
            harn.pass();
            harn.pass();
            assert!(item_rect(&harn.app.debug_layout, "header_settings").is_some());
            assert!(item_rect(&harn.app.debug_layout, "header_logout").is_some());
            assert!(item_rect(&harn.app.debug_layout, "header_quit").is_some());
            harn.app.settings_open = true;
            harn.pass();
            harn.pass();
            assert!(
                item_rect(&harn.app.debug_layout, "settings_panel").is_some(),
                "settings panel missing at {w}x{h}"
            );
            assert_no_overflow(&harn.app.debug_layout, w, h);
        }
    }

    #[test]
    fn hash_and_version_are_not_primary_machine_meta() {
        let mut harn = Harness::new(1024.0, 756.0);
        if let Some(node) = harn.app.nodes.iter_mut().find(|n| n.id == "sufa") {
            node.version = "cd30c9ed52337645".into();
        }
        harn.app.selected_id = Some("sufa".into());
        harn.app.screen = Screen::Machines;
        harn.pass();
        harn.pass();
        assert!(item_rect(&harn.app.debug_layout, "nav_row:sufa").is_some());
        assert!(
            item_rect(&harn.app.debug_layout, "detail_node_id").is_none(),
            "collapsed Details must not push the node id into the primary column"
        );
    }

    #[test]
    fn rail_geometry_includes_dpi_and_folds_719_physical() {
        // Keep a 756-point-tall frame so scale tests are about width/DPI,
        // not a chopped window. Physical height is 756 * ppp.
        for &(phys_w, ppp, expect_rail) in &[
            (719.0_f32, 1.0_f32, false),
            (1024.0, 1.0, true),
            (1080.0, 1.0, true),
            // Sub-1 scale: 719 physical must fold even if logical is ~1078.5.
            (719.0, 2.0 / 3.0, false),
            (1024.0, 2.0 / 3.0, true),
            // Windows 150%: 1024 points (1536 physical) keeps the rail.
            (1536.0, 1.5, true),
        ] {
            let phys_h = 756.0 * ppp;
            let mut harn = Harness::new_physical(phys_w, phys_h, ppp);
            harn.app.screen = Screen::Machines;
            harn.pass();
            harn.pass();
            let logical_w = phys_w / ppp;
            assert_eq!(
                model::machine_rail_visible_at(logical_w, ppp),
                expect_rail,
                "breakpoint at phys={phys_w} ppp={ppp}"
            );
            assert_eq!(
                harn.ctx.pixels_per_point(),
                ppp,
                "harness ppp at {phys_w}/{ppp}"
            );
            assert_machines_shell(&harn, logical_w, 756.0, expect_rail);
        }
        // 1024 physical at 150% is 682.67 points and must fold. Do not
        // require the connect cards to fit un-scrolled in that short frame.
        let mut harn = Harness::new_physical(1024.0, 756.0, 1.5);
        harn.app.screen = Screen::Machines;
        harn.pass();
        harn.pass();
        assert!(!model::machine_rail_visible_at(1024.0 / 1.5, 1.5));
        assert_eq!(harn.app.debug_layout.rail_rect, [0.0; 4]);
    }

    #[test]
    fn long_offline_name_keeps_badge_and_does_not_share_the_name_row() {
        let mut harn = Harness::new(1024.0, 756.0);
        let mut node = harn.app.nodes[0].clone();
        node.id = "long-offline".into();
        node.name = "Fixture · offline workstation with a long display name (sample)".into();
        node.online = false;
        harn.app.nodes.insert(0, node);
        harn.app.selected_id = Some("long-offline".into());
        harn.app.screen = Screen::Machines;
        harn.pass();
        harn.pass();
        let layout = &harn.app.debug_layout;
        let name = item_rect(layout, "nav_name:long-offline").expect("nav name");
        let badge = item_rect(layout, "nav_badge:long-offline").expect("nav badge");
        assert!(
            badge[1] + 0.5 >= name[1] + name[3] - 1.0,
            "badge must sit on the next row, not beside the name: name={name:?} badge={badge:?}"
        );
        assert!(
            badge[2] >= 64.0 && badge[3] >= 16.0,
            "offline badge clipped: {badge:?}"
        );
        assert!(
            name[2] >= 140.0,
            "name should use the rail width, not a leftover strip: {name:?}"
        );
        let detail_badge = item_rect(layout, "detail_badge").expect("detail badge");
        assert!(
            detail_badge[2] >= 64.0,
            "detail offline badge clipped: {detail_badge:?}"
        );
    }

    #[test]
    fn unconnected_detail_shows_connect_cards_not_empty_toolbar() {
        let mut harn = Harness::new(1024.0, 756.0);
        harn.app.screen = Screen::Machines;
        harn.pass();
        harn.pass();
        let layout = &harn.app.debug_layout;
        assert!(
            item_rect(layout, "connect_prompt").is_some(),
            "Choose how to connect missing"
        );
        let selected = harn.app.selected_id.clone().expect("selection");
        for label in ["Terminal", "Files"] {
            let card = item_rect(layout, &format!("action_card:{selected}:{label}"))
                .unwrap_or_else(|| panic!("missing action card {label}"));
            assert!(
                card[2] >= 199.0 && card[3] >= 80.0,
                "{label} card too small (still a tiny toolbar?): {card:?}"
            );
            assert_action_fully_visible(layout, &format!("action_btn:{selected}:{label}"), 1024.0);
        }
    }

    fn card_items(layout: &DebugLayout) -> Vec<(String, [f32; 4])> {
        layout
            .toolbar_items
            .iter()
            .filter(|(id, _)| id.starts_with("action_card:"))
            .cloned()
            .collect()
    }

    fn rect_max_x(rect: [f32; 4]) -> f32 {
        rect[0] + rect[2]
    }

    fn rect_max_y(rect: [f32; 4]) -> f32 {
        rect[1] + rect[3]
    }

    fn assert_cards_inside_visible_clip(layout: &DebugLayout) {
        let clip = layout.visible_clip;
        assert!(
            clip[2] > 1.0 && clip[3] > 1.0,
            "visible_clip was not recorded: {clip:?}"
        );
        let clip_max_x = rect_max_x(clip);
        let cards = card_items(layout);
        assert!(!cards.is_empty(), "no connect cards recorded");
        for (id, rect) in &cards {
            assert!(
                rect_max_x(*rect) <= clip_max_x + 0.5,
                "{id} raw max.x {} exceeds visible clip max.x {} (rect={rect:?} clip={clip:?})",
                rect_max_x(*rect),
                clip_max_x
            );
        }
    }

    #[test]
    fn narrow_721_page_keeps_connect_cards_inside_visible_clip() {
        // Real 721x759 client, including header, page margins, and scrollbar.
        let mut harn = Harness::new(721.0, 759.0);
        harn.app.screen = Screen::Machines;
        harn.app.selected_id = Some("sufa".into());
        harn.pass();
        harn.pass();
        assert!(
            !model::machine_rail_visible(721.0),
            "721 must fold the rail"
        );
        let selected = harn.app.selected_id.clone().expect("selection");
        let cards = card_items(&harn.app.debug_layout);
        let ours: Vec<_> = cards
            .iter()
            .filter(|(id, _)| id.starts_with(&format!("action_card:{selected}:")))
            .cloned()
            .collect();
        assert!(
            ours.len() >= 3,
            "expected Terminal/Files/View cards at 721, got {ours:?}"
        );
        let xs: Vec<i32> = {
            let mut v: Vec<i32> = ours.iter().map(|(_, r)| r[0].round() as i32).collect();
            v.sort();
            v.dedup();
            v
        };
        assert!(
            xs.len() <= 2,
            "721 must use one or two columns, not three: xs={xs:?} cards={ours:?}"
        );
        assert_cards_inside_visible_clip(&harn.app.debug_layout);

        let last = harn
            .app
            .debug_layout
            .toolbar_items
            .iter()
            .filter(|(id, _)| {
                id.starts_with("action_card:") || id == "details" || id.starts_with("nav_row:")
            })
            .max_by(|a, b| rect_max_y(a.1).partial_cmp(&rect_max_y(b.1)).unwrap())
            .cloned()
            .expect("last card or details");
        let mut reached = false;
        for _ in 0..40 {
            let clip = harn.app.debug_layout.visible_clip;
            let rect = item_rect(&harn.app.debug_layout, &last.0).unwrap_or(last.1);
            if rect[1] >= clip[1] - 1.0 && rect_max_y(rect) <= rect_max_y(clip) + 1.0 {
                reached = true;
                break;
            }
            // Reveal content below: move the scrolled content up.
            harn.scroll_content(-120.0);
        }
        assert!(
            reached,
            "could not scroll to last item {} at {:?}; clip={:?} items={:?}",
            last.0,
            item_rect(&harn.app.debug_layout, &last.0),
            harn.app.debug_layout.visible_clip,
            harn.app
                .debug_layout
                .toolbar_items
                .iter()
                .map(|(k, r)| (k, r))
                .collect::<Vec<_>>()
        );
        assert_cards_inside_visible_clip(&harn.app.debug_layout);
    }

    #[test]
    fn wide_connect_cards_use_two_by_two_not_three_plus_one() {
        for (w, h) in [(1026.0, 759.0), (1080.0, 760.0), (1920.0, 1135.0)] {
            let mut harn = Harness::new(w, h);
            harn.app.screen = Screen::Machines;
            harn.app.selected_id = Some("sufa".into());
            harn.pass();
            harn.pass();
            let selected = harn.app.selected_id.clone().expect("selection");
            let ours: Vec<_> = card_items(&harn.app.debug_layout)
                .into_iter()
                .filter(|(id, _)| id.starts_with(&format!("action_card:{selected}:")))
                .collect();
            assert_eq!(
                ours.len(),
                4,
                "desktop node should show four cards at {w}x{h}"
            );
            let mut ys: Vec<i32> = ours.iter().map(|(_, r)| r[1].round() as i32).collect();
            ys.sort();
            ys.dedup();
            assert_eq!(
                ys.len(),
                2,
                "four cards should be a 2x2, not 3+1, at {w}: ys={ys:?} cards={ours:?}"
            );
            assert_cards_inside_visible_clip(&harn.app.debug_layout);
        }
    }

    #[test]
    fn tab_shift_tab_and_enter_use_native_focus_on_machines_page() {
        let mut harn = Harness::preview(1080.0, 760.0, super::super::LiveHooks::production());
        harn.app.screen = Screen::Machines;
        harn.pass();
        harn.pass();
        assert!(
            harn.ctx.style().visuals.widgets.active.bg_stroke.width >= 2.0,
            "theme must give focused widgets a 2px high-contrast ring"
        );
        assert!(
            harn.focused_ids().is_empty(),
            "no widget should start focused: {:?}",
            harn.focused_ids()
        );

        let mut seen: Vec<String> = Vec::new();
        let mut found_header = false;
        let mut found_card = false;
        let mut found_row = false;
        for _ in 0..24 {
            harn.press_tab(false);
            let ids = harn.focused_ids();
            if ids.is_empty() {
                continue;
            }
            // A recorded focus_ring means the widget was painted as focused
            // (native Button uses widgets.active; rows paint theme::focus_stroke).
            let rings: Vec<_> = harn
                .app
                .debug_layout
                .toolbar_items
                .iter()
                .filter(|(id, _)| id.starts_with("focus_ring:"))
                .map(|(id, _)| id.clone())
                .collect();
            assert_eq!(
                rings.len(),
                ids.len(),
                "every focused widget must record a visible focus ring: focus={ids:?} rings={rings:?}"
            );
            for id in &ids {
                if !seen.contains(id) {
                    seen.push(id.clone());
                }
                if id.contains("header_settings") || id.contains("header_quit") {
                    found_header = true;
                }
                if id.contains("action_card:") {
                    found_card = true;
                }
                if id.contains("nav_row:") {
                    found_row = true;
                }
            }
        }
        assert!(
            seen.len() >= 2,
            "Tab should visit more than one widget: {seen:?}"
        );
        assert!(
            found_header,
            "Settings/Quit should take Tab focus: {seen:?}"
        );
        assert!(
            found_card || found_row,
            "machine list or connect cards should take Tab focus: {seen:?}"
        );

        let after_tabs = harn.focused_ids();
        harn.press_tab(true);
        let after_shift = harn.focused_ids();
        assert!(!after_shift.is_empty(), "Shift+Tab lost focus entirely");
        assert_ne!(
            after_shift, after_tabs,
            "Shift+Tab should move focus backward: {after_tabs:?} -> {after_shift:?}"
        );

        // Walk Tab until the enabled Terminal card is focused, then Enter.
        let selected = harn.app.selected_id.clone().expect("selection");
        let terminal_id = format!("focus:action_card:{selected}:Terminal");
        let mut on_terminal = harn.focused_ids().contains(&terminal_id);
        for _ in 0..32 {
            if on_terminal {
                break;
            }
            harn.press_tab(false);
            on_terminal = harn.focused_ids().contains(&terminal_id);
        }
        assert!(
            on_terminal,
            "never focused the Terminal card with Tab events: {:?}",
            harn.focused_ids()
        );
        harn.press_enter();
        assert!(
            matches!(harn.app.screen, Screen::Terminal { .. }),
            "Enter on an enabled Terminal card should start the (preview) mock session"
        );

        // Disabled actions must not activate. Select the offline fixture and
        // try Enter on its Terminal card (machine is offline).
        harn.app.back_to_machines();
        harn.app.selected_id = Some("preview-fixture-offline".into());
        harn.pass();
        harn.pass();
        let offline_terminal = "focus:action_card:preview-fixture-offline:Terminal";
        let mut focused_disabled = false;
        for _ in 0..32 {
            harn.press_tab(false);
            if harn.focused_ids().iter().any(|id| id == offline_terminal) {
                focused_disabled = true;
                break;
            }
        }
        if focused_disabled {
            harn.press_enter();
            assert!(
                matches!(harn.app.screen, Screen::Machines),
                "Enter on a disabled card must not start a session"
            );
        } else {
            // Disabled buttons may be skipped by Tab; a click must still not activate.
            if item_rect(
                &harn.app.debug_layout,
                "action_card:preview-fixture-offline:Terminal",
            )
            .is_some()
            {
                harn.click_item("action_card:preview-fixture-offline:Terminal");
            }
            assert!(
                matches!(harn.app.screen, Screen::Machines),
                "disabled Terminal card activated"
            );
        }
    }
}
