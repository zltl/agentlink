//! Linear-dark controller window shared by Windows and Linux.
//!
//! The window is egui. The session, shell, files, and WebRTC viewer stay in
//! [`super::worker`] on the same client the phone uses. Visual tokens live in
//! [`super::theme`].

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentlink_core::{Identity, NodeInfo, NodePolicy};
use eframe::egui;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc::UnboundedSender;

use super::chrome::{
    classify_connect_error, encoder_label, estimate_right_width_with, link_is_connecting,
    pick_bar_density, session_phase, stats_chip, stats_line, text_advance, top_chrome_visible,
    BarDensity, BarMeasure, ConnDot, SessionPhase, SessionSignals, BAR_HEIGHT,
};
use super::model::{
    self, access_summary, card_buttons, connection_label, display_note, has_saved_session,
    node_presence_label, Action, CardButtonKind, LocalGrantBadge,
};
use super::tabs::{self, TabDot, TabIcon, TabId, TabShortcut, MACHINES_TAB_ID};
use super::term::Emulator;
use super::theme;
use super::viewport::{
    content_rect_excluding_pad, content_uv_excluding_pad, hit_content, native_zoom_for_dpi,
    viewport_rect,
};
use super::worker::{Cmd, LiveHud, MonitorEntry, Shared, UiEvent};

/// Rect recorded from a real egui `Response` / layout pass (`[x, y, w, h]`).
#[derive(Clone, Debug, Default)]
pub struct DebugLayout {
    pub tab_bar_rect: [f32; 4],
    pub tab_items: Vec<(String, [f32; 4])>,
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
        self.tab_bar_rect = [0.0; 4];
        self.tab_items.clear();
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

    fn note_tab_item(&mut self, id: &str, rect: egui::Rect) {
        self.tab_items.push((id.to_string(), rect_xywh(rect)));
    }

    fn note_tab_visible(&mut self, id: &str, rect: egui::Rect, clip: egui::Rect) {
        let vis = visible_rect(rect, clip);
        if vis.width() > 0.5 && vis.height() > 0.5 {
            self.note_tab_item(id, vis);
        }
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

    fn note_painted_focus_ring(
        &mut self,
        id: &str,
        widget: egui::Rect,
        ring: egui::Rect,
        outer: egui::Rect,
        clip: egui::Rect,
    ) {
        self.note_item(&format!("focus:{id}"), widget);
        // Raw painted ring and its stroke outer bounds — not the
        // already-intersected widget vis rect.
        self.note_item(&format!("focus_ring:{id}"), ring);
        self.note_item(&format!("focus_outer:{id}"), outer);
        self.note_item(&format!("focus_clip:{id}"), clip);
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

/// Keep the 2px focus stroke fully inside the visible clip (sidebar or
/// scrolling list). Half the stroke width plus a small inset.
const FOCUS_RING_INSET: f32 = 1.0;

fn inset_focus_ring_rect(widget: egui::Rect, clip: egui::Rect) -> Option<egui::Rect> {
    let pad = theme::focus_stroke().width * 0.5 + FOCUS_RING_INSET;
    let ring = widget.intersect(clip).shrink(pad);
    if ring.width() > 2.0 && ring.height() > 2.0 {
        Some(ring)
    } else {
        None
    }
}

fn stroke_outer_rect(rect: egui::Rect, width: f32, kind: egui::StrokeKind) -> egui::Rect {
    match kind {
        egui::StrokeKind::Inside => rect,
        egui::StrokeKind::Middle => rect.expand(width * 0.5),
        egui::StrokeKind::Outside => rect.expand(width),
    }
}

/// Paint a 2px high-contrast ring whose stroke stays inside `clip`.
/// Returns (stroke rect, outer bounds of the stroke).
fn paint_focus_ring(
    ui: &egui::Ui,
    widget: egui::Rect,
    clip: egui::Rect,
) -> Option<(egui::Rect, egui::Rect)> {
    let ring = inset_focus_ring_rect(widget, clip)?;
    let stroke = theme::focus_stroke();
    let kind = egui::StrokeKind::Inside;
    ui.painter().rect_stroke(
        ring,
        egui::CornerRadius::same(theme::RADIUS_CONTROL),
        stroke,
        kind,
    );
    Some((ring, stroke_outer_rect(ring, stroke.width, kind)))
}

fn paint_and_note_focus_ring(
    layout: &mut DebugLayout,
    ui: &egui::Ui,
    id: &str,
    response: &egui::Response,
    clip: egui::Rect,
) {
    if !response.has_focus() {
        return;
    }
    if let Some((ring, outer)) = paint_focus_ring(ui, response.rect, clip) {
        layout.note_painted_focus_ring(id, response.rect, ring, outer, clip);
    } else {
        layout.note_focus(id, response, clip);
    }
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AuthScreen {
    Restoring,
    Login,
    Workspace,
}

struct Editor {
    path: String,
    text: String,
    saved_text: String,
    read_only: bool,
    read_only_reason: Option<String>,
    total_size: Option<u64>,
}

impl Editor {
    fn editable(path: String, text: String) -> Self {
        let len = text.len() as u64;
        Self {
            path,
            saved_text: text.clone(),
            text,
            read_only: false,
            read_only_reason: None,
            total_size: Some(len),
        }
    }

    fn is_dirty(&self) -> bool {
        !self.read_only && self.text != self.saved_text
    }
}

/// An independent remote PTY terminal tab.
struct TerminalTab {
    id: TabId,
    node_id: String,
    node_name: String,
    gen: u64,
    emulator: Emulator,
    size: (u16, u16),
    open: Option<Instant>,
    got_output: bool,
    alive: bool,
    exited: Option<i32>,
    notice: String,
    error: String,
}

/// An independent WebRTC / stills remote desktop session tab.
struct DesktopTab {
    id: TabId,
    node_id: String,
    node_name: String,
    control: bool,
    link: String,
    monitors: Vec<MonitorEntry>,
    monitor: u32,
    quality: u32,
    scale_mode: DeskScaleMode,
    max_fps: u32,
    zoom: f32,
    pan: egui::Vec2,
    fit: bool,
    fullscreen: bool,
    capture_keys: bool,
    held_keys: HashSet<String>,
    key_state: super::desk_keys::KeyPairState,
    input_blocked: bool,
    send_menu: bool,
    sticky: HashSet<&'static str>,
    last_move: Instant,
    last_frame: Option<Instant>,
    hud: LiveHud,
    texture: Option<egui::TextureHandle>,
    size: (usize, usize),
    seen_seq: u64,
    cursor_tex: Option<(u64, egui::TextureHandle)>,
    ime_allowed: bool,
    ungrab_armed: bool,
    await_paste_frames: u8,
    adapter: super::input_adapter::AdapterState,
    user_stopped: bool,
    disconnect_reason: String,
    connect_failed: bool,
    connect_started: Option<Instant>,
    toast: Option<(String, Instant)>,
    ui_pointer: Instant,
    stats_open: bool,
    notice: String,
    error: String,
    mock_frame_window_start: Instant,
    mock_frame_window_count: u32,
}

impl DesktopTab {
    fn new(id: TabId, node: &NodeInfo, control: bool, max_fps: u32) -> Self {
        Self {
            id,
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            control,
            link: if control {
                "connecting · control".into()
            } else {
                "connecting · view".into()
            },
            monitors: Vec::new(),
            monitor: 0,
            quality: 70,
            scale_mode: DeskScaleMode::Auto,
            max_fps,
            zoom: 1.0,
            pan: egui::Vec2::ZERO,
            fit: true,
            fullscreen: false,
            capture_keys: false,
            held_keys: HashSet::new(),
            key_state: super::desk_keys::KeyPairState::default(),
            input_blocked: false,
            send_menu: false,
            sticky: HashSet::new(),
            last_move: Instant::now() - Duration::from_secs(1),
            last_frame: None,
            hud: LiveHud::default(),
            texture: None,
            size: (0, 0),
            seen_seq: 0,
            cursor_tex: None,
            ime_allowed: false,
            ungrab_armed: false,
            await_paste_frames: 0,
            adapter: super::input_adapter::AdapterState::default(),
            user_stopped: false,
            disconnect_reason: String::new(),
            connect_failed: false,
            connect_started: Some(Instant::now()),
            toast: None,
            ui_pointer: Instant::now(),
            stats_open: false,
            notice: String::new(),
            error: String::new(),
            mock_frame_window_start: Instant::now(),
            mock_frame_window_count: 0,
        }
    }

    fn phase(&self) -> SessionPhase {
        session_phase(SessionSignals {
            user_stopped: self.user_stopped,
            link_connecting: link_is_connecting(&self.link),
            has_texture: self.texture.is_some(),
            since_frame: self.last_frame.map(|t| t.elapsed()),
            fatal_error: if self.disconnect_reason.is_empty() {
                ""
            } else {
                &self.disconnect_reason
            },
            connect_failed: self.connect_failed,
        })
    }

    fn live_scale_for_monitor(&self, logical_size: (f32, f32)) -> f32 {
        match self.scale_mode {
            DeskScaleMode::Native100 => return 1.0,
            DeskScaleMode::Scale75 => return 0.75,
            DeskScaleMode::Scale50 => return 0.50,
            DeskScaleMode::Auto => {}
        }
        let (win_w, win_h) = logical_size;
        let (src_w, src_h) = self
            .monitors
            .iter()
            .find(|m| m.index == self.monitor)
            .map(|m| (m.width.max(1) as f32, m.height.max(1) as f32))
            .unwrap_or((1920.0, 1080.0));
        // Auto mode fits the controller window up to 1920px wide; user can
        // choose 100% Native in the toolbar Stream/Zoom menu (`DESK-12`).
        let cap = 1920.0;
        let scale_x = (win_w / src_w).min(cap / src_w).clamp(0.05, 1.0);
        let scale_y = (win_h / src_h).min(cap / src_h).clamp(0.05, 1.0);
        scale_x.min(scale_y).clamp(0.05, 1.0)
    }

    fn drain_release_events(&mut self) -> (Vec<String>, Vec<&'static str>, f64, f64) {
        self.key_state.clear();
        let keys: Vec<String> = self.held_keys.drain().collect();
        let buttons: Vec<&'static str> = self.adapter.reducer.held.iter().copied().collect();
        self.adapter.reducer.held.clear();
        let (x, y) = (self.adapter.reducer.last_x, self.adapter.reducer.last_y);
        self.sticky.clear();
        self.adapter.mods = super::input_adapter::ModSnapshot::default();
        self.adapter.pointer = None;
        (keys, buttons, x, y)
    }
}

/// An independent remote file browser & editor tab.
struct FilesTab {
    id: TabId,
    node_id: String,
    node_name: String,
    dir: String,
    path_input: String,
    entries: Vec<agentlink_core::DirEntry>,
    loading: bool,
    editor: Option<Editor>,
    folder_name: String,
    new_file_name: String,
    upload_local: String,
    pending_delete: Option<String>,
    pending_nav: Option<PendingFileNav>,
    notice: String,
    error: String,
}

impl FilesTab {
    fn new(id: TabId, node: &NodeInfo) -> Self {
        Self {
            id,
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            dir: ".".into(),
            path_input: ".".into(),
            entries: Vec::new(),
            loading: true,
            editor: None,
            folder_name: String::new(),
            new_file_name: String::new(),
            upload_local: String::new(),
            pending_delete: None,
            pending_nav: None,
            notice: String::new(),
            error: String::new(),
        }
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
        let same_dir =
            parent == self.dir || (parent == "." && (self.dir == "." || self.dir.is_empty()));
        if !same_dir {
            return;
        }
        let name = path.rsplit(['/', '\\']).next().unwrap_or(path.as_str());
        if self.entries.iter().any(|entry| entry.name == name) {
            return;
        }
        if model::notice_refers_to_path(&self.notice, &path) {
            self.notice.clear();
        }
        self.editor = None;
    }
}

/// Any closable workspace tab (alongside the pinned Machines tab).
enum Tab {
    Terminal(TerminalTab),
    Desktop(DesktopTab),
    Files(FilesTab),
    Settings { id: TabId },
}

impl Tab {
    fn id(&self) -> TabId {
        match self {
            Self::Terminal(t) => t.id,
            Self::Desktop(d) => d.id,
            Self::Files(f) => f.id,
            Self::Settings { id } => *id,
        }
    }

    fn node_id(&self) -> Option<&str> {
        match self {
            Self::Terminal(t) => Some(&t.node_id),
            Self::Desktop(d) => Some(&d.node_id),
            Self::Files(f) => Some(&f.node_id),
            Self::Settings { .. } => None,
        }
    }

    fn kind_key(&self) -> u8 {
        match self {
            Self::Terminal(_) => 0,
            Self::Desktop(_) => 1,
            Self::Files(_) => 2,
            Self::Settings { .. } => 3,
        }
    }

    fn base_label(&self) -> &str {
        match self {
            Self::Terminal(t) => &t.node_name,
            Self::Desktop(d) => &d.node_name,
            Self::Files(f) => &f.node_name,
            Self::Settings { .. } => "Settings",
        }
    }

    fn icon(&self) -> TabIcon {
        match self {
            Self::Terminal(_) => TabIcon::Terminal,
            Self::Desktop(d) => TabIcon::Desktop { control: d.control },
            Self::Files(_) => TabIcon::Files,
            Self::Settings { .. } => TabIcon::Settings,
        }
    }

    fn dot(&self) -> TabDot {
        match self {
            Self::Terminal(t) => {
                if !t.error.is_empty() {
                    TabDot::Error
                } else if t.alive {
                    TabDot::Connected
                } else if t.open.is_some() {
                    TabDot::Connecting
                } else {
                    TabDot::Inactive
                }
            }
            Self::Desktop(d) => match d.phase() {
                SessionPhase::Live => TabDot::Connected,
                SessionPhase::Connecting | SessionPhase::Stale => TabDot::Connecting,
                SessionPhase::Failed => TabDot::Error,
                SessionPhase::Disconnected => TabDot::Inactive,
            },
            Self::Files(f) => {
                if !f.error.is_empty() {
                    TabDot::Error
                } else if f.loading {
                    TabDot::Connecting
                } else {
                    TabDot::Connected
                }
            }
            Self::Settings { .. } => TabDot::None,
        }
    }

    fn kind_label(&self) -> &'static str {
        match self {
            Self::Terminal(_) => "Terminal",
            Self::Desktop(d) => {
                if d.control {
                    "Desktop (Control)"
                } else {
                    "Desktop (View)"
                }
            }
            Self::Files(_) => "Files",
            Self::Settings { .. } => "Settings",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EnrollTab {
    Unix,
    PowerShell,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DeskScaleMode {
    Auto,
    Native100,
    Scale75,
    Scale50,
}

impl DeskScaleMode {
    fn label(self) -> &'static str {
        match self {
            Self::Auto => "Auto (fit)",
            Self::Native100 => "100% Native",
            Self::Scale75 => "75%",
            Self::Scale50 => "50%",
        }
    }
}

#[derive(Clone, Debug)]
enum PendingFileNav {
    OpenFile { node: String, path: String, size: Option<u64> },
    OpenDir { node: String, path: String },
    CloseEditor,
    CloseTab,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct ControllerPrefs {
    #[serde(default)]
    allow_osc52: bool,
    #[serde(default)]
    desk_clipboard_sync: bool,
    #[serde(default)]
    font_hint_dismissed: bool,
}

fn load_controller_prefs(config_dir: &std::path::Path) -> ControllerPrefs {
    let path = config_dir.join("controller-prefs.json");
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_controller_prefs(config_dir: &std::path::Path, prefs: &ControllerPrefs) {
    let _ = std::fs::create_dir_all(config_dir);
    let path = config_dir.join("controller-prefs.json");
    if let Ok(json) = serde_json::to_string_pretty(prefs) {
        let _ = std::fs::write(&path, json);
    }
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
    auth: AuthScreen,
    tabs: Vec<Tab>,
    active_tab: TabId,
    next_tab_id: TabId,
    next_pty_gen: u64,
    quick_menu_open: bool,
    quick_menu_anchor: Option<egui::Rect>,
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
    /// True once the first `UiEvent::Nodes` response has arrived so a 0-node
    /// account stops the `"Loading machines..."` spinner cleanly (`DESK-09`).
    nodes_loaded: bool,
    control: HashMap<String, bool>,
    error: String,
    notice: String,
    pins: Vec<String>,
    /// Persisted user preferences (`allow_osc52`, `desk_clipboard_sync`, `font_hint_dismissed`).
    prefs: ControllerPrefs,
    /// Local controller Ed25519 public identity hex (for grant grantee verification & offer UI).
    controller_id: Option<String>,
    /// Paste buffer for importing a SignedGrant JSON or GrantOffer on Machine Detail.
    grant_paste_input: String,
    window_focused: bool,
    file_download_dir: String,
    link: String,
    enroll_open: bool,
    enroll_name: String,
    enroll_access: String,
    enroll_minutes: String,
    enroll_out: String,
    enroll_out_ps: String,
    enroll_token: String,
    enroll_tab: EnrollTab,
    node_line: String,
    autostart: bool,
    last_node: Instant,
    /// Async node-status / autostart poll slot so `pump()` never blocks the render thread (`DESK-11`).
    bg_status: Arc<Mutex<Option<(String, bool)>>>,
    bg_status_busy: Arc<AtomicBool>,
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
    /// Node whose desktop is opened as soon as the machine list arrives.
    open_desktop: Option<String>,
    /// Set once the auto-open ran so a refresh cannot yank the user back.
    auto_opened: bool,
    /// Selected machine on the Machines page (and highlighted in the rail).
    selected_id: Option<String>,
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
        tray_ready = super::indicator::spawn(
            Arc::clone(&flags.open),
            Arc::clone(&flags.quit),
            opts.data_dir.clone(),
            shared.egui_ctx_slot(),
        );
        if !tray_ready {
            opts.background = false;
        }
    }
    let hide_on_close = model::hides_window_on_close(tray_ready, opts.background, false);
    let egui_shared = Arc::clone(&shared);
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
        Box::new(move |cc| {
            egui_shared.set_egui_ctx(cc.egui_ctx.clone());
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
        let (relay, pin, trust, node_line, autostart, saved_session, prefs, controller_id) =
            if preview_ui {
                (
                    String::new(),
                    String::new(),
                    String::new(),
                    super::PREVIEW_NODE_LINE.to_string(),
                    false,
                    false,
                    ControllerPrefs::default(),
                    None,
                )
            } else {
                let file = agentlink_core::config::load_file(&config_dir).unwrap_or_default();
                // Pre-fill relay from AGENTLINK_RELAY when saved config has no relay (`DESK-09`).
                let relay = file
                    .relay
                    .filter(|value| !value.trim().is_empty())
                    .or_else(|| {
                        std::env::var("AGENTLINK_RELAY")
                            .ok()
                            .filter(|v| !v.trim().is_empty())
                    })
                    .unwrap_or_default();
                let pin = file
                    .fingerprint
                    .filter(|value| !value.trim().is_empty())
                    .or_else(|| {
                        std::env::var("AGENTLINK_FINGERPRINT")
                            .ok()
                            .filter(|v| !v.trim().is_empty())
                    })
                    .unwrap_or_default();
                let trust = file
                    .trust
                    .filter(|value| !value.trim().is_empty())
                    .or_else(|| {
                        std::env::var("AGENTLINK_TRUST")
                            .ok()
                            .filter(|v| !v.trim().is_empty())
                    })
                    .unwrap_or_default();
                let node_line = node_summary(&live, &data_dir, &config_dir);
                let autostart = live.start_on_login();
                let saved_session = has_saved_session(file.refresh_token.as_deref());
                let prefs = load_controller_prefs(&config_dir);
                let controller_id = Identity::load(&config_dir.join("identity.json"))
                    .ok()
                    .map(|id| id.public_hex().to_ascii_lowercase());
                (
                    relay,
                    pin,
                    trust,
                    node_line,
                    autostart,
                    saved_session,
                    prefs,
                    controller_id,
                )
            };
        if !preview_ui && prefs.desk_clipboard_sync {
            let _ = tx.send(Cmd::ClipboardSync { enabled: true });
        }
        let default_download_dir = std::env::var_os("HOME")
            .or_else(|| std::env::var_os("USERPROFILE"))
            .map(|h| std::path::PathBuf::from(h).join("Downloads"))
            .unwrap_or_else(|| std::path::PathBuf::from("."))
            .to_string_lossy()
            .into_owned();
        Self {
            tx,
            shared,
            config_dir,
            data_dir,
            tray,
            hide_on_close: false,
            flags,
            auth: if saved_session {
                AuthScreen::Restoring
            } else {
                AuthScreen::Login
            },
            tabs: Vec::new(),
            active_tab: MACHINES_TAB_ID,
            next_tab_id: 1,
            next_pty_gen: 1,
            quick_menu_open: false,
            quick_menu_anchor: None,
            username: String::new(),
            password: String::new(),
            totp: String::new(),
            ask_totp: false,
            show_password: false,
            advanced: !pin.is_empty() || trust_is_custom(&trust),
            relay,
            pin,
            trust,
            user: None,
            nodes: Vec::new(),
            nodes_loaded: false,
            control: HashMap::new(),
            error: String::new(),
            notice: String::new(),
            pins: Vec::new(),
            prefs,
            controller_id,
            grant_paste_input: String::new(),
            window_focused: true,
            file_download_dir: default_download_dir,
            link: "relay".into(),
            enroll_open: false,
            enroll_name: "laptop".into(),
            enroll_access: "exec".into(),
            enroll_minutes: "15".into(),
            enroll_out: String::new(),
            enroll_out_ps: String::new(),
            enroll_token: String::new(),
            enroll_tab: if cfg!(windows) {
                EnrollTab::PowerShell
            } else {
                EnrollTab::Unix
            },
            node_line,
            autostart,
            last_node: Instant::now(),
            bg_status: Arc::new(Mutex::new(None)),
            bg_status_busy: Arc::new(AtomicBool::new(false)),
            mock: false,
            fail_connect: false,
            connect_timeout_secs: 12,
            max_fps: 30,
            perf_log: None,
            perf_log_written_header: false,
            last_perf_log: Instant::now(),
            logical_size: (1080.0, 760.0),
            window_title: "AgentLink".into(),
            debug_layout: DebugLayout::default(),
            debug_inbox: None,
            debug_events: Vec::new(),
            debug_quit: false,
            debug_rgba: None,
            open_desktop: None,
            auto_opened: false,
            selected_id: None,
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

    fn poll_bg_status(&mut self) {
        if let Ok(mut slot) = self.bg_status.try_lock() {
            if let Some((node_line, autostart)) = slot.take() {
                self.node_line = node_line;
                self.autostart = autostart;
            }
        }
        if !self.preview_ui
            && !self.mock
            && self.last_node.elapsed() > Duration::from_secs(5)
            && !self.bg_status_busy.swap(true, Ordering::AcqRel)
        {
            self.last_node = Instant::now();
            let live = self.live.clone();
            let data_dir = self.data_dir.clone();
            let config_dir = self.config_dir.clone();
            let out = Arc::clone(&self.bg_status);
            let busy = Arc::clone(&self.bg_status_busy);
            let shared = Arc::clone(&self.shared);
            let _ = std::thread::Builder::new()
                .name("agentlink-ctrl-status".into())
                .spawn(move || {
                    let node_line = node_summary(&live, &data_dir, &config_dir);
                    let autostart = live.start_on_login();
                    if let Ok(mut slot) = out.lock() {
                        *slot = Some((node_line, autostart));
                    }
                    busy.store(false, Ordering::Release);
                    shared.request_repaint();
                });
        }
    }

    fn alloc_tab_id(&mut self) -> TabId {
        let id = self.next_tab_id.max(1);
        self.next_tab_id = id.wrapping_add(1).max(1);
        id
    }

    fn alloc_pty_gen(&mut self) -> u64 {
        let gen = self.next_pty_gen.max(1);
        self.next_pty_gen = gen.wrapping_add(1).max(1);
        gen
    }

    fn active_tab_ref(&self) -> Option<&Tab> {
        if self.active_tab == MACHINES_TAB_ID {
            None
        } else {
            self.tabs.iter().find(|t| t.id() == self.active_tab)
        }
    }

    fn active_tab_mut(&mut self) -> Option<&mut Tab> {
        let target = self.active_tab;
        if target == MACHINES_TAB_ID {
            None
        } else {
            self.tabs.iter_mut().find(|t| t.id() == target)
        }
    }

    fn active_desktop_id(&self) -> Option<TabId> {
        match self.active_tab_ref() {
            Some(Tab::Desktop(d)) => Some(d.id),
            _ => None,
        }
    }

    fn terminal_by_gen_mut(&mut self, gen: u64) -> Option<&mut TerminalTab> {
        self.tabs.iter_mut().find_map(|t| match t {
            Tab::Terminal(term) if term.gen == gen => Some(term),
            _ => None,
        })
    }

    fn terminal_by_id_mut(&mut self, id: TabId) -> Option<&mut TerminalTab> {
        self.tabs.iter_mut().find_map(|t| match t {
            Tab::Terminal(term) if term.id == id => Some(term),
            _ => None,
        })
    }

    fn desktop_by_id_mut(&mut self, id: TabId) -> Option<&mut DesktopTab> {
        self.tabs.iter_mut().find_map(|t| match t {
            Tab::Desktop(desk) if desk.id == id => Some(desk),
            _ => None,
        })
    }

    fn files_by_id_mut(&mut self, id: TabId) -> Option<&mut FilesTab> {
        self.tabs.iter_mut().find_map(|t| match t {
            Tab::Files(files) if files.id == id => Some(files),
            _ => None,
        })
    }

    fn compute_tab_labels(&self) -> Vec<(TabId, String)> {
        let mut counts: HashMap<(u8, String), usize> = HashMap::new();
        for tab in &self.tabs {
            let key = (
                tab.kind_key(),
                tab.node_id().unwrap_or("settings").to_string(),
            );
            *counts.entry(key).or_insert(0) += 1;
        }
        let mut seen: HashMap<(u8, String), usize> = HashMap::new();
        self.tabs
            .iter()
            .map(|tab| {
                let key = (
                    tab.kind_key(),
                    tab.node_id().unwrap_or("settings").to_string(),
                );
                let total = counts.get(&key).copied().unwrap_or(1);
                let ordinal = {
                    let entry = seen.entry(key).or_insert(0);
                    *entry += 1;
                    *entry
                };
                let label = tabs::disambiguated_label(tab.base_label(), ordinal, total);
                (tab.id(), label)
            })
            .collect()
    }

    fn release_desktop_tab_input(&mut self, id: TabId) {
        let Some((node_id, keys, buttons, x, y, monitor)) = self
            .desktop_by_id_mut(id)
            .map(|d| {
                d.capture_keys = false;
                d.ungrab_armed = false;
                let (keys, buttons, x, y) = d.drain_release_events();
                (d.node_id.clone(), keys, buttons, x, y, d.monitor)
            })
        else {
            return;
        };
        for key in keys {
            self.inject_key_edge(id, &node_id, &key, false, false);
        }
        for button in buttons {
            self.inject_mouse_raw(
                id,
                &node_id,
                monitor,
                MouseEvent::new("up", x, y, button),
                true,
                false,
            );
        }
    }

    fn release_all_desktop_inputs(&mut self) {
        let ids: Vec<TabId> = self
            .tabs
            .iter()
            .filter_map(|t| match t {
                Tab::Desktop(d) => Some(d.id),
                _ => None,
            })
            .collect();
        for id in ids {
            self.release_desktop_tab_input(id);
        }
    }

    fn activate_tab(&mut self, ctx: Option<&egui::Context>, target: TabId) {
        if target != MACHINES_TAB_ID && !self.tabs.iter().any(|t| t.id() == target) {
            return;
        }
        if self.active_tab == target {
            return;
        }
        self.quick_menu_open = false;
        if let Some(prev_desk) = self.active_desktop_id() {
            self.release_desktop_tab_input(prev_desk);
            if let Some(d) = self.desktop_by_id_mut(prev_desk) {
                if d.fullscreen {
                    d.fullscreen = false;
                    if let Some(ctx) = ctx {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                    }
                }
                if d.ime_allowed {
                    d.ime_allowed = false;
                    if let Some(ctx) = ctx {
                        ctx.send_viewport_cmd(egui::ViewportCommand::IMEAllowed(false));
                    }
                }
            }
        }
        self.active_tab = target;
        match self.tabs.iter().find(|t| t.id() == target) {
            Some(Tab::Desktop(d)) => {
                self.shared.set_active_desktop_session(d.id);
                self.selected_id = Some(d.node_id.clone());
            }
            Some(Tab::Terminal(t)) => {
                self.shared.set_active_desktop_session(0);
                self.selected_id = Some(t.node_id.clone());
                let gen = t.gen;
                if let Some(t) = self.terminal_by_id_mut(target) {
                    t.emulator.focused = true;
                }
                if let Some(ctx) = ctx {
                    ctx.memory_mut(|m| {
                        if let Some(f) = m.focused() {
                            m.surrender_focus(f);
                        }
                    });
                }
                if !self.preview_ui {
                    self.send(Cmd::PtySelect { gen });
                }
            }
            Some(Tab::Files(f)) => {
                self.shared.set_active_desktop_session(0);
                self.selected_id = Some(f.node_id.clone());
            }
            Some(Tab::Settings { .. }) | None => {
                self.shared.set_active_desktop_session(0);
            }
        }
        if let Some(ctx) = ctx {
            ctx.request_repaint();
        }
    }

    fn open_terminal_tab(&mut self, node: &NodeInfo) -> TabId {
        let id = self.alloc_tab_id();
        let gen = self.alloc_pty_gen();
        let size = (24u16, 80u16);
        let mut emulator = Emulator::new(size.0, size.1);
        emulator.set_allow_osc52(self.prefs.allow_osc52);
        emulator.reset_local_echo(gen);
        let mut tab = TerminalTab {
            id,
            node_id: node.id.clone(),
            node_name: node.name.clone(),
            gen,
            emulator,
            size,
            open: Some(Instant::now()),
            got_output: false,
            alive: true,
            exited: None,
            notice: String::new(),
            error: String::new(),
        };
        tab.emulator.focused = true;
        self.tabs.push(Tab::Terminal(tab));
        self.selected_id = Some(node.id.clone());
        self.error.clear();
        if !self.preview_ui {
            self.send(Cmd::PtyOpen {
                node: node.id.clone(),
                rows: size.0,
                cols: size.1,
                gen,
            });
        }
        self.activate_tab(None, id);
        id
    }

    fn restart_terminal_tab(&mut self, tab_id: TabId) {
        let new_gen = self.alloc_pty_gen();
        let allow_osc52 = self.prefs.allow_osc52;
        let Some((node_id, size, old_gen)) = self.terminal_by_id_mut(tab_id).map(|t| {
            let old_gen = t.gen;
            t.gen = new_gen;
            t.emulator = Emulator::new(t.size.0, t.size.1);
            t.emulator.set_allow_osc52(allow_osc52);
            t.emulator.reset_local_echo(new_gen);
            t.emulator.focused = true;
            t.open = Some(Instant::now());
            t.got_output = false;
            t.alive = true;
            t.exited = None;
            t.error.clear();
            t.notice.clear();
            (t.node_id.clone(), t.size, old_gen)
        }) else {
            return;
        };
        if !self.preview_ui {
            if old_gen != 0 {
                self.send(Cmd::PtyCloseGen { gen: old_gen });
            }
            self.send(Cmd::PtyOpen {
                node: node_id,
                rows: size.0,
                cols: size.1,
                gen: new_gen,
            });
        }
    }

    fn open_desktop_tab(&mut self, node: &NodeInfo, control: bool) -> TabId {
        self.selected_id = Some(node.id.clone());
        self.control.insert(node.id.clone(), control);
        self.error.clear();
        let existing_id = self.tabs.iter().find_map(|t| match t {
            Tab::Desktop(d) if d.node_id == node.id => Some(d.id),
            _ => None,
        });
        if let Some(id) = existing_id {
            let mode_changed = self.desktop_by_id_mut(id).is_some_and(|d| {
                let changed = d.control != control;
                if changed {
                    d.control = control;
                    if !control {
                        d.capture_keys = false;
                    }
                }
                changed
            });
            self.activate_tab(None, id);
            if mode_changed {
                self.restart_live(id);
            }
            return id;
        }
        let id = self.alloc_tab_id();
        let mut desk = DesktopTab::new(id, node, control, self.max_fps);
        if self.mock {
            desk.monitors = mock_monitors();
            desk.hud = LiveHud {
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
                cursor_presentation: "legacy".into(),
                src_width: 960,
                src_height: 480,
            };
            if !self.fail_connect {
                desk.link = "connected · mock".into();
                desk.connect_started = None;
            }
            self.tabs.push(Tab::Desktop(desk));
            self.activate_tab(None, id);
            return id;
        }
        let monitor = desk.monitor;
        let quality = desk.quality;
        let scale = desk.live_scale_for_monitor(self.logical_size);
        let max_fps = desk.max_fps;
        self.tabs.push(Tab::Desktop(desk));
        self.activate_tab(None, id);
        if !self.preview_ui {
            self.send(Cmd::Monitors {
                session: id,
                node: node.id.clone(),
                retry: false,
            });
            self.send(Cmd::Live {
                session: id,
                node: node.id.clone(),
                control,
                monitor,
                quality,
                scale,
                max_fps,
                retry: false,
            });
        }
        id
    }

    fn open_files_tab(&mut self, node: &NodeInfo) -> TabId {
        self.selected_id = Some(node.id.clone());
        self.error.clear();
        if let Some(existing_id) = self.tabs.iter().find_map(|t| match t {
            Tab::Files(f) if f.node_id == node.id => Some(f.id),
            _ => None,
        }) {
            self.activate_tab(None, existing_id);
            return existing_id;
        }
        let id = self.alloc_tab_id();
        self.tabs.push(Tab::Files(FilesTab::new(id, node)));
        if !self.preview_ui {
            self.send(Cmd::List {
                session: id,
                node: node.id.clone(),
                path: ".".into(),
            });
        }
        self.activate_tab(None, id);
        id
    }

    fn open_settings_tab(&mut self) -> TabId {
        if let Some(id) = self.tabs.iter().find_map(|t| match t {
            Tab::Settings { id } => Some(*id),
            _ => None,
        }) {
            self.activate_tab(None, id);
            return id;
        }
        let id = self.alloc_tab_id();
        self.tabs.push(Tab::Settings { id });
        self.activate_tab(None, id);
        id
    }

    fn request_close_tab(&mut self, ctx: Option<&egui::Context>, id: TabId) {
        if id == MACHINES_TAB_ID {
            return;
        }
        let is_dirty_files = self.tabs.iter().any(|t| {
            matches!(t, Tab::Files(f) if f.id == id && f.editor.as_ref().is_some_and(Editor::is_dirty))
        });
        if is_dirty_files {
            self.activate_tab(ctx, id);
            if let Some(f) = self.files_by_id_mut(id) {
                f.pending_nav = Some(PendingFileNav::CloseTab);
            }
            return;
        }
        self.force_close_tab(ctx, id);
    }

    fn force_close_tab(&mut self, ctx: Option<&egui::Context>, id: TabId) {
        if id == MACHINES_TAB_ID {
            return;
        }
        let Some(idx) = self.tabs.iter().position(|t| t.id() == id) else {
            return;
        };
        if matches!(self.tabs[idx], Tab::Desktop(_)) {
            self.release_desktop_tab_input(id);
        }
        let next_active = if self.active_tab == id {
            if idx + 1 < self.tabs.len() {
                self.tabs[idx + 1].id()
            } else if idx > 0 {
                self.tabs[idx - 1].id()
            } else {
                MACHINES_TAB_ID
            }
        } else {
            self.active_tab
        };
        let removed = self.tabs.remove(idx);
        match removed {
            Tab::Terminal(t) => {
                if !self.preview_ui && t.gen != 0 {
                    self.send(Cmd::PtyCloseGen { gen: t.gen });
                }
            }
            Tab::Desktop(d) => {
                if d.fullscreen {
                    if let Some(ctx) = ctx {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                    }
                }
                if d.ime_allowed {
                    if let Some(ctx) = ctx {
                        ctx.send_viewport_cmd(egui::ViewportCommand::IMEAllowed(false));
                    }
                }
                if !self.preview_ui {
                    self.send(Cmd::LiveStopSession { session: d.id });
                }
                self.shared.remove_desktop_slot(d.id);
            }
            Tab::Files(_) | Tab::Settings { .. } => {}
        }
        if self.active_tab == id {
            self.active_tab = next_active;
            match self.tabs.iter().find(|t| t.id() == next_active) {
                Some(Tab::Desktop(d)) => {
                    self.shared.set_active_desktop_session(d.id);
                }
                Some(Tab::Terminal(t)) => {
                    self.shared.set_active_desktop_session(0);
                    let gen = t.gen;
                    if let Some(t) = self.terminal_by_id_mut(next_active) {
                        t.emulator.focused = true;
                    }
                    if !self.preview_ui {
                        self.send(Cmd::PtySelect { gen });
                    }
                }
                _ => {
                    self.shared.set_active_desktop_session(0);
                }
            }
        }
        if let Some(ctx) = ctx {
            ctx.request_repaint();
        }
    }

    fn close_other_tabs(&mut self, ctx: Option<&egui::Context>, keep: TabId) {
        let others: Vec<TabId> = self
            .tabs
            .iter()
            .filter_map(|t| if t.id() != keep { Some(t.id()) } else { None })
            .collect();
        for id in others {
            self.request_close_tab(ctx, id);
            if self.tabs.iter().any(|t| {
                matches!(t, Tab::Files(f) if f.id == id && f.pending_nav.is_some())
            }) {
                break;
            }
        }
    }

    fn cycle_tab(&mut self, ctx: &egui::Context, forward: bool) {
        let mut order: Vec<TabId> = Vec::with_capacity(self.tabs.len() + 1);
        order.push(MACHINES_TAB_ID);
        for t in &self.tabs {
            order.push(t.id());
        }
        if order.len() <= 1 {
            return;
        }
        let pos = order
            .iter()
            .position(|&id| id == self.active_tab)
            .unwrap_or(0);
        let next_pos = if forward {
            (pos + 1) % order.len()
        } else {
            (pos + order.len() - 1) % order.len()
        };
        self.activate_tab(Some(ctx), order[next_pos]);
    }

    fn quick_new_terminal_target(&self) -> Option<NodeInfo> {
        if let Some(node_id) = self.active_tab_ref().and_then(|t| t.node_id()) {
            if let Some(node) = self.nodes.iter().find(|n| n.id == node_id) {
                if model::terminal_action(node.online, node.effective).enabled {
                    return Some(node.clone());
                }
            }
        }
        if let Some(node) = self.selected_node() {
            if model::terminal_action(node.online, node.effective).enabled {
                return Some(node);
            }
        }
        self.nodes
            .iter()
            .find(|n| model::terminal_action(n.online, n.effective).enabled)
            .cloned()
    }

    fn back_to_machines(&mut self, ctx: Option<&egui::Context>) {
        self.activate_tab(ctx, MACHINES_TAB_ID);
    }

    fn reset_to_login(&mut self, ctx: Option<&egui::Context>, err: Option<String>) {
        self.release_all_desktop_inputs();
        for tab in &self.tabs {
            if let Tab::Desktop(d) = tab {
                if d.fullscreen {
                    if let Some(ctx) = ctx {
                        ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                    }
                }
                if d.ime_allowed {
                    if let Some(ctx) = ctx {
                        ctx.send_viewport_cmd(egui::ViewportCommand::IMEAllowed(false));
                    }
                }
            }
        }
        if !self.preview_ui {
            self.send(Cmd::PtyCloseAll);
            self.send(Cmd::LiveStop);
        }
        self.shared.clear_all_desktop_slots();
        self.shared.set_active_desktop_session(0);
        self.tabs.clear();
        self.active_tab = MACHINES_TAB_ID;
        self.quick_menu_open = false;
        self.user = None;
        self.nodes.clear();
        self.nodes_loaded = false;
        self.auth = AuthScreen::Login;
        if let Some(msg) = err {
            self.error = msg;
        }
    }

    fn restart_live(&mut self, id: TabId) {
        self.release_desktop_tab_input(id);
        self.shared.reset_cursor_for(id);
        let logical = self.logical_size;
        let max_fps_fallback = self.max_fps;
        let is_mock = self.mock;
        let fail_connect = self.fail_connect;
        let override_control = self.tabs.iter().find_map(|t| match t {
            Tab::Desktop(d) if d.id == id => self.control.get(&d.node_id).copied(),
            _ => None,
        });
        let Some((node_id, control, monitor, quality, scale, max_fps)) =
            self.desktop_by_id_mut(id).map(|d| {
                d.cursor_tex = None;
                d.texture = None;
                d.size = (0, 0);
                d.seen_seq = 0;
                d.last_frame = None;
                d.user_stopped = false;
                d.disconnect_reason.clear();
                d.connect_failed = false;
                d.stats_open = false;
                d.input_blocked = false;
                d.send_menu = false;
                d.error.clear();
                let control = override_control.unwrap_or(d.control);
                d.control = control;
                d.link = if control {
                    "connecting · control".into()
                } else {
                    "connecting · view".into()
                };
                d.connect_started = Some(Instant::now());
                if is_mock && !fail_connect {
                    d.link = "connected · mock".into();
                    d.connect_started = None;
                }
                let fps = if d.max_fps > 0 { d.max_fps } else { max_fps_fallback };
                (
                    d.node_id.clone(),
                    control,
                    d.monitor,
                    d.quality,
                    d.live_scale_for_monitor(logical),
                    fps,
                )
            })
        else {
            return;
        };
        if is_mock || self.preview_ui {
            return;
        }
        // Same prelude as `open_desktop_tab`: Monitors runs on the worker before
        // Live and can rebootstrap a dead Client after `connection closed`.
        self.send(Cmd::Monitors {
            session: id,
            node: node_id.clone(),
            retry: true,
        });
        self.send(Cmd::Live {
            session: id,
            node: node_id,
            control,
            monitor,
            quality,
            scale,
            max_fps,
            retry: true,
        });
    }

    fn stop_desktop_tab_session(&mut self, id: TabId, reason: &str) {
        self.release_desktop_tab_input(id);
        if !self.preview_ui {
            self.send(Cmd::LiveStopSession { session: id });
        }
        self.shared.reset_cursor_for(id);
        self.shared.clear_picture_for(id);
        if let Some(d) = self.desktop_by_id_mut(id) {
            d.cursor_tex = None;
            d.texture = None;
            d.size = (0, 0);
            d.seen_seq = 0;
            d.last_frame = None;
            d.capture_keys = false;
            d.input_blocked = false;
            d.send_menu = false;
            d.user_stopped = true;
            d.connect_failed = false;
            d.connect_started = None;
            d.disconnect_reason = reason.to_string();
            d.stats_open = false;
            d.link = "disconnected".into();
        }
    }

    fn fail_desktop_tab_session(&mut self, id: TabId, reason: &str) {
        self.release_desktop_tab_input(id);
        if !self.preview_ui {
            self.send(Cmd::LiveStopSession { session: id });
        }
        self.shared.reset_cursor_for(id);
        self.shared.clear_picture_for(id);
        if let Some(d) = self.desktop_by_id_mut(id) {
            d.cursor_tex = None;
            d.texture = None;
            d.size = (0, 0);
            d.seen_seq = 0;
            d.last_frame = None;
            d.capture_keys = false;
            d.input_blocked = false;
            d.send_menu = false;
            d.user_stopped = true;
            d.connect_failed = true;
            d.connect_started = None;
            d.disconnect_reason = classify_connect_error(reason);
            d.stats_open = false;
            d.link = "failed".into();
        }
    }

    fn check_connect_timeout(&mut self) {
        let limit = Duration::from_secs(self.connect_timeout_secs.max(1));
        let timed_out: Vec<TabId> = self
            .tabs
            .iter()
            .filter_map(|t| match t {
                Tab::Desktop(d)
                    if d.texture.is_none()
                        && !d.connect_failed
                        && !d.user_stopped
                        && d.connect_started.is_some_and(|s| s.elapsed() >= limit) =>
                {
                    Some(d.id)
                }
                _ => None,
            })
            .collect();
        for id in timed_out {
            self.fail_desktop_tab_session(
                id,
                &format!("Connection timed out after {}s", self.connect_timeout_secs),
            );
        }
    }

    fn pump(&mut self, ctx: &egui::Context) {
        self.poll_bg_status();
        for event in self.shared.drain() {
            match event {
                UiEvent::Ready { user } => {
                    self.user = user.clone();
                    if user.is_some() {
                        if !self.preview_ui && self.controller_id.is_none() {
                            self.controller_id =
                                Identity::load(&self.config_dir.join("identity.json"))
                                    .ok()
                                    .map(|id| id.public_hex().to_ascii_lowercase());
                        }
                        if matches!(self.auth, AuthScreen::Login | AuthScreen::Restoring) {
                            self.auth = AuthScreen::Workspace;
                        }
                        self.password.clear();
                        self.totp.clear();
                    } else if !self.preview_ui {
                        self.reset_to_login(Some(ctx), None);
                    }
                }
                UiEvent::Nodes(nodes) => {
                    self.nodes = nodes;
                    self.nodes_loaded = true;
                    self.ensure_selection();
                    self.maybe_auto_open_desktop();
                }
                UiEvent::Failed(message) => {
                    if !self.preview_ui
                        && !self.mock
                        && model::auth_error_requires_login(&message)
                    {
                        self.reset_to_login(Some(ctx), Some(message));
                    } else if matches!(self.auth, AuthScreen::Restoring) {
                        self.auth = AuthScreen::Login;
                        self.error = message;
                    } else if let Some(Tab::Desktop(d)) = self.active_tab_mut() {
                        let desk_id = d.id;
                        if super::desk_keys::failure_revokes_input(&message) {
                            self.release_desktop_tab_input(desk_id);
                            if let Some(d) = self.desktop_by_id_mut(desk_id) {
                                d.input_blocked = true;
                            }
                        }
                        let should_fail = self.desktop_by_id_mut(desk_id).is_some_and(|d| {
                            link_is_connecting(&d.link) || d.user_stopped || d.texture.is_none()
                        });
                        if should_fail {
                            self.fail_desktop_tab_session(desk_id, &message);
                        } else if let Some(d) = self.desktop_by_id_mut(desk_id) {
                            d.toast = Some((message, Instant::now()));
                        }
                        self.error.clear();
                    } else if let Some(Tab::Files(f)) = self.active_tab_mut() {
                        f.loading = false;
                        f.error = message;
                    } else {
                        self.error = message;
                    }
                }
                UiEvent::TotpRequired(message) => {
                    self.ask_totp = true;
                    self.error = message;
                }
                UiEvent::Notice(message) => {
                    if let Some(Tab::Desktop(d)) = self.active_tab_mut() {
                        d.toast = Some((message, Instant::now()));
                        self.notice.clear();
                    } else {
                        self.notice = message;
                    }
                }
                UiEvent::Pty { gen, bytes } => {
                    let replies = if let Some(t) = self.terminal_by_gen_mut(gen) {
                        if !bytes.is_empty() {
                            t.got_output = true;
                            t.open = None;
                            t.alive = true;
                            t.exited = None;
                        }
                        t.emulator.feed(&bytes);
                        t.emulator.take_writes()
                    } else {
                        Vec::new()
                    };
                    if !replies.is_empty() && !self.preview_ui {
                        self.send(Cmd::PtyWriteGen { gen, data: replies });
                    }
                }
                UiEvent::PtyExited { gen, code } => {
                    if let Some(t) = self.terminal_by_gen_mut(gen) {
                        t.open = None;
                        t.alive = false;
                        t.exited = Some(code);
                        t.notice = format!("Shell exited ({code})");
                    }
                }
                UiEvent::PtyFailed { gen, message } => {
                    if let Some(t) = self.terminal_by_gen_mut(gen) {
                        t.open = None;
                        t.alive = false;
                        t.error = message;
                    }
                }
                UiEvent::PtyDone { gen } => {
                    if let Some(t) = self.terminal_by_gen_mut(gen) {
                        t.open = None;
                        t.alive = false;
                        if !t.got_output && t.error.is_empty() && t.exited.is_none() {
                            t.error =
                                "The shell session ended before any output arrived.".into();
                        }
                    }
                }
                UiEvent::Dir {
                    session,
                    path,
                    entries,
                } => {
                    if let Some(f) = self.files_by_id_mut(session) {
                        f.dir = path.clone();
                        f.path_input = path;
                        f.entries = entries;
                        f.loading = false;
                        f.error.clear();
                        f.forget_missing_editor();
                    }
                }
                UiEvent::File { session, file } => {
                    if let Some(f) = self.files_by_id_mut(session) {
                        f.error.clear();
                        f.editor = Some(Editor {
                            path: file.path,
                            saved_text: file.text.clone(),
                            text: file.text,
                            read_only: file.read_only,
                            read_only_reason: file.read_only_reason,
                            total_size: file.total_size,
                        });
                    }
                }
                UiEvent::FilesFailed { session, message } => {
                    if !self.preview_ui
                        && !self.mock
                        && model::auth_error_requires_login(&message)
                    {
                        self.reset_to_login(Some(ctx), Some(message));
                    } else if let Some(f) = self.files_by_id_mut(session) {
                        f.loading = false;
                        f.error = message;
                    } else {
                        self.error = message;
                    }
                }
                UiEvent::FilesNotice { session, message } => {
                    if let Some(f) = self.files_by_id_mut(session) {
                        f.notice = message;
                    }
                }
                UiEvent::Enrolled {
                    unix,
                    powershell,
                    token,
                } => {
                    self.enroll_out = unix;
                    self.enroll_out_ps = powershell;
                    self.enroll_token = token;
                }
                UiEvent::Link { session, label } => {
                    if session == 0 {
                        self.link = label;
                    } else if let Some(d) = self.desktop_by_id_mut(session) {
                        d.link = label;
                    }
                }
                UiEvent::Pins(pins) => self.pins = pins,
                UiEvent::Monitors { session, monitors } => {
                    if let Some(d) = self.desktop_by_id_mut(session) {
                        if let Some(blocked) = monitors.iter().find(|m| m.capturable == Some(false))
                        {
                            let reason = blocked
                                .reason
                                .clone()
                                .unwrap_or_else(|| "secure desktop".into());
                            d.toast = Some((
                                format!("Remote screen is not capturable ({reason})"),
                                Instant::now(),
                            ));
                        }
                        d.monitors = monitors;
                        if let Some(primary) = d.monitors.iter().find(|m| m.primary) {
                            if !d.monitors.iter().any(|m| m.index == d.monitor) {
                                d.monitor = primary.index;
                            }
                        } else if let Some(first) = d.monitors.first() {
                            if !d.monitors.iter().any(|m| m.index == d.monitor) {
                                d.monitor = first.index;
                            }
                        }
                    }
                }
                UiEvent::Hud { session, hud } => {
                    if let Some(d) = self.desktop_by_id_mut(session) {
                        let keep = if hud.handshake.is_empty() {
                            d.hud.handshake.clone()
                        } else {
                            hud.handshake.clone()
                        };
                        d.hud = hud;
                        d.hud.handshake = keep;
                        if !d.hud.kind.is_empty() {
                            d.link = format!(
                                "{} · {}",
                                d.hud.kind,
                                if d.hud.path.is_empty() {
                                    "relay"
                                } else {
                                    &d.hud.path
                                }
                            );
                        }
                    }
                }
                UiEvent::Handshake { session, stage } => {
                    if let Some(d) = self.desktop_by_id_mut(session) {
                        d.hud.handshake = stage;
                    }
                }
                UiEvent::DesktopFailed { session, message } => {
                    if !self.preview_ui
                        && !self.mock
                        && model::auth_error_requires_login(&message)
                    {
                        self.reset_to_login(Some(ctx), Some(message));
                    } else if self.desktop_by_id_mut(session).is_some() {
                        if super::desk_keys::failure_revokes_input(&message) {
                            self.release_desktop_tab_input(session);
                            if let Some(d) = self.desktop_by_id_mut(session) {
                                d.input_blocked = true;
                            }
                        }
                        let should_fail = self.desktop_by_id_mut(session).is_some_and(|d| {
                            link_is_connecting(&d.link) || d.user_stopped || d.texture.is_none()
                        });
                        if should_fail {
                            self.fail_desktop_tab_session(session, &message);
                        } else if let Some(d) = self.desktop_by_id_mut(session) {
                            d.toast = Some((message, Instant::now()));
                        }
                    }
                }
                UiEvent::DesktopNotice { session, message } => {
                    if let Some(d) = self.desktop_by_id_mut(session) {
                        d.toast = Some((message, Instant::now()));
                    }
                }
            }
            ctx.request_repaint();
        }

        let mut got_frame = false;
        let active_id = self.active_tab;
        let has_debug_inbox = self.debug_inbox.is_some();
        for tab in &mut self.tabs {
            let Tab::Desktop(d) = tab else {
                continue;
            };
            if let Some(at) = self.shared.last_frame_at_for(d.id) {
                d.last_frame = Some(at);
            }
            if d.id == active_id || d.texture.is_none() {
                if let Some(picture) = self.shared.latest_picture_for(d.id) {
                    if picture.seq != d.seen_seq {
                        d.seen_seq = picture.seq;
                        let present_started = Instant::now();
                        let (w, h, rgba) =
                            fit_rgba_for_egui(picture.width, picture.height, picture.rgba, ctx);
                        let image = egui::ColorImage::from_rgba_unmultiplied([w, h], &rgba);
                        if let Some(texture) = &mut d.texture {
                            texture.set(image, egui::TextureOptions::LINEAR);
                        } else {
                            d.texture = Some(ctx.load_texture(
                                format!("desktop-{}", d.id),
                                image,
                                egui::TextureOptions::LINEAR,
                            ));
                        }
                        d.size = (w, h);
                        self.shared
                            .perf
                            .note_present_us(present_started.elapsed().as_micros() as u64);
                        d.link = format!("{} · {}", picture.kind, connection_label(&picture.path));
                        d.last_frame = Some(Instant::now());
                        d.connect_started = None;
                        d.connect_failed = false;
                        if d.id == active_id && has_debug_inbox {
                            self.debug_rgba = Some((w as u32, h as u32, rgba.clone()));
                        }
                        // Recycle the RGBA buffer back to the decoder pool instead of
                        // keeping a dead 4-33 MiB `self.picture` copy (`DESK-11`).
                        self.shared.recycle_rgba(rgba);
                        got_frame = true;
                        ctx.request_repaint();
                    } else {
                        self.shared.recycle_rgba(picture.rgba);
                    }
                }
            }
        }

        self.check_connect_timeout();
        self.sync_window_title(ctx);
        self.maybe_write_perf_log();

        let paste_target = match self.active_tab_mut() {
            Some(Tab::Desktop(d)) if d.await_paste_frames > 0 => Some(d.id),
            _ => None,
        };
        if let Some(desk_id) = paste_target {
            let pasted = ctx.input(|input| {
                input.events.iter().find_map(|event| match event {
                    egui::Event::Paste(text) => Some(text.clone()),
                    _ => None,
                })
            });
            if let Some(text) = pasted {
                if let Some(d) = self.desktop_by_id_mut(desk_id) {
                    d.await_paste_frames = 0;
                    let node = d.node_id.clone();
                    if !text.is_empty() {
                        self.send(Cmd::Clipboard {
                            session: desk_id,
                            node,
                            text,
                        });
                    } else if let Some(d) = self.desktop_by_id_mut(desk_id) {
                        d.toast = Some(("Local clipboard is empty.".into(), Instant::now()));
                    }
                }
            } else if let Some(d) = self.desktop_by_id_mut(desk_id) {
                d.await_paste_frames -= 1;
                if d.await_paste_frames == 0 {
                    d.toast = Some((
                        "Local clipboard is empty or not text.".into(),
                        Instant::now(),
                    ));
                } else {
                    ctx.request_repaint();
                }
            }
        }

        // Event-driven repaints (`DESK-11`): `Shared` calls `ctx.request_repaint()`
        // on every frame, cursor, and UI event. Only schedule a slow timer when an
        // active UI animation/timeout needs wall-clock ticks (never burn 12.5fps idle!).
        if !got_frame {
            let active_mock_live = self.mock
                && matches!(
                    self.active_tab_ref(),
                    Some(Tab::Desktop(d)) if !d.user_stopped
                );
            let any_pending = self.tabs.iter().any(|t| match t {
                Tab::Desktop(d) => d.connect_started.is_some() || d.toast.is_some(),
                Tab::Terminal(term) => term.open.is_some(),
                Tab::Files(f) => f.loading,
                Tab::Settings { .. } => false,
            });
            let active_fs = matches!(self.active_tab_ref(), Some(Tab::Desktop(d)) if d.fullscreen);
            if active_mock_live {
                ctx.request_repaint_after(Duration::from_millis(33));
            } else if any_pending
                || matches!(self.auth, AuthScreen::Restoring)
                || (matches!(self.auth, AuthScreen::Workspace)
                    && self.active_tab == MACHINES_TAB_ID
                    && !self.nodes_loaded
                    && self.user.is_some())
            {
                ctx.request_repaint_after(Duration::from_millis(250));
            } else if active_fs {
                ctx.request_repaint_after(Duration::from_millis(500));
            }
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
        self.auth = AuthScreen::Workspace;
        self.open_desktop_tab(&node, true);
    }

    fn sync_window_title(&mut self, ctx: &egui::Context) {
        let title = self.compute_window_title();
        if title != self.window_title {
            self.window_title = title.clone();
            ctx.send_viewport_cmd(egui::ViewportCommand::Title(title));
        }
    }

    fn compute_window_title(&self) -> String {
        if !matches!(self.auth, AuthScreen::Workspace) || self.active_tab == MACHINES_TAB_ID {
            return if self.preview_ui {
                "AgentLink (Preview)".into()
            } else {
                "AgentLink".into()
            };
        }
        match self.active_tab_ref() {
            Some(Tab::Desktop(d)) => {
                let mode = if d.control { "control" } else { "view" };
                let (w, h) = (d.hud.width, d.hud.height);
                if w > 0 && h > 0 {
                    format!("Desktop — {} ({w}×{h}, {mode}) · AgentLink", d.node_name)
                } else {
                    format!("Desktop — {} ({mode}) · AgentLink", d.node_name)
                }
            }
            Some(Tab::Terminal(t)) => format!("Terminal — {} · AgentLink", t.node_name),
            Some(Tab::Files(f)) => format!("Files — {} · AgentLink", f.node_name),
            Some(Tab::Settings { .. }) => "Settings · AgentLink".into(),
            None => "AgentLink".into(),
        }
    }

    fn session_mode(&self) -> &'static str {
        match self.active_tab_ref() {
            Some(Tab::Desktop(d)) if d.control => "control",
            _ => "view",
        }
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
            self.release_all_desktop_inputs();
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
        }
        self.ui_frame(ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.flags.quit.store(true, Ordering::Relaxed);
        self.release_all_desktop_inputs();
        if !self.preview_ui {
            self.send(Cmd::PtyCloseAll);
            self.send(Cmd::LiveStop);
        }
    }
}

impl ControllerApp {
    fn handle_tab_shortcuts(&mut self, ctx: &egui::Context) {
        if !matches!(self.auth, AuthScreen::Workspace) {
            return;
        }
        let desktop_captured = matches!(self.active_tab_ref(), Some(Tab::Desktop(d)) if d.capture_keys);
        if desktop_captured {
            return;
        }
        let matched = ctx.input(|i| tabs::detect_tab_shortcut(&i.events));
        let Some((idx, shortcut)) = matched else {
            return;
        };
        ctx.input_mut(|i| {
            if idx < i.events.len() {
                i.events.remove(idx);
            }
        });
        match shortcut {
            TabShortcut::NewTab => {
                if let Some(node) = self.quick_new_terminal_target() {
                    self.open_terminal_tab(&node);
                } else {
                    self.quick_menu_open = true;
                }
            }
            TabShortcut::CloseTab => {
                let target = self.active_tab;
                self.request_close_tab(Some(ctx), target);
            }
            TabShortcut::NextTab => self.cycle_tab(ctx, true),
            TabShortcut::PrevTab => self.cycle_tab(ctx, false),
            TabShortcut::GoMachines => self.activate_tab(Some(ctx), MACHINES_TAB_ID),
            TabShortcut::OpenSettings => {
                self.open_settings_tab();
            }
        }
    }

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

        let win_focused = ctx.input(|i| i.focused);
        let regained_window_focus = win_focused && !self.window_focused;
        self.window_focused = win_focused;
        if regained_window_focus {
            if let Some(Tab::Terminal(t)) = self.active_tab_ref() {
                if t.alive && t.open.is_none() && !self.preview_ui {
                    let gen = t.gen;
                    self.send(Cmd::PtyProbeGen { gen });
                }
            }
        }

        self.release_keyboard_if_ungated(ctx);
        if let Some(Tab::Desktop(d)) = self.active_tab_mut() {
            if d.ime_allowed && !(d.capture_keys && !d.input_blocked) {
                d.ime_allowed = false;
                ctx.send_viewport_cmd(egui::ViewportCommand::IMEAllowed(false));
            }
        }

        // Intercept global Windows Terminal–style shortcuts before any terminal
        // emulator consumes keys for the PTY, and leave captured Desktop keys untouched.
        self.handle_tab_shortcuts(ctx);

        if !self.quick_menu_open {
            if let Some(Tab::Terminal(t)) = self.active_tab_mut() {
                if t.emulator.focused && (t.alive || t.open.is_some()) {
                    t.emulator.consume_focused_keys(ctx);
                }
            }
        }

        if self.mock {
            self.refresh_mock_picture(ctx);
        }

        match self.auth {
            AuthScreen::Login => {
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE.fill(theme::BG_PAGE))
                    .show(ctx, |ui| {
                        egui::Frame::NONE
                            .inner_margin(egui::Margin::same(theme::SPACE_MD as i8))
                            .show(ui, |ui| {
                                self.paint_auth_banners(ui);
                                let main_rect = ui.available_rect_before_wrap();
                                self.debug_layout.main_rect = rect_xywh(main_rect);
                                self.login(ui);
                            });
                    });
            }
            AuthScreen::Restoring => {
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE.fill(theme::BG_PAGE))
                    .show(ctx, |ui| {
                        egui::Frame::NONE
                            .inner_margin(egui::Margin::same(theme::SPACE_MD as i8))
                            .show(ui, |ui| {
                                self.paint_auth_banners(ui);
                                let main_rect = ui.available_rect_before_wrap();
                                self.debug_layout.main_rect = rect_xywh(main_rect);
                                self.restoring(ui);
                            });
                    });
            }
            AuthScreen::Workspace => {
                let (pointer_y, pointer_moved) = ctx.input(|input| {
                    (
                        input.pointer.hover_pos().map(|p| p.y),
                        input.pointer.is_moving(),
                    )
                });
                let is_desktop = matches!(self.active_tab_ref(), Some(Tab::Desktop(_)));
                let desktop_fs = match self.active_tab_mut() {
                    Some(Tab::Desktop(d)) => {
                        if pointer_moved {
                            d.ui_pointer = Instant::now();
                        }
                        if let Some(toast_at) = d.toast.as_ref().map(|(_, t)| *t) {
                            if toast_at.elapsed() > Duration::from_secs(4) {
                                d.toast = None;
                            }
                        }
                        let mut toggle_fs = false;
                        if !d.capture_keys {
                            ctx.input(|input| {
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
                                }
                            });
                        }
                        if toggle_fs {
                            d.fullscreen = !d.fullscreen;
                            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(d.fullscreen));
                            d.ui_pointer = Instant::now();
                        }
                        if d.fullscreen {
                            Some(d.ui_pointer.elapsed())
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                let show_tab_bar = match desktop_fs {
                    Some(idle_for) => top_chrome_visible(
                        true,
                        idle_for,
                        pointer_y,
                        theme::TAB_BAR_HEIGHT + BAR_HEIGHT,
                    ),
                    None => true,
                };
                if show_tab_bar {
                    self.paint_tab_bar(ctx);
                }

                let active = self.active_tab;
                if is_desktop {
                    egui::CentralPanel::default()
                        .frame(egui::Frame::NONE.fill(theme::BG_PAGE))
                        .show(ctx, |ui| {
                            ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_XS, 0.0);
                            self.desktop_tab(ui, active, show_tab_bar);
                        });
                } else if matches!(self.active_tab_ref(), Some(Tab::Terminal(_))) {
                    egui::CentralPanel::default()
                        .frame(
                            egui::Frame::NONE
                                .fill(theme::BG_TERMINAL)
                                .inner_margin(egui::Margin::symmetric(8, 6)),
                        )
                        .show(ctx, |ui| {
                            self.debug_layout.rail_rect = [0.0; 4];
                            self.debug_layout.main_rect = rect_xywh(ui.available_rect_before_wrap());
                            self.terminal_tab(ui, active);
                        });
                } else if matches!(self.active_tab_ref(), Some(Tab::Files(_))) {
                    egui::CentralPanel::default()
                        .frame(
                            egui::Frame::NONE
                                .fill(theme::BG_PANEL)
                                .inner_margin(egui::Margin::same(theme::SPACE_MD as i8)),
                        )
                        .show(ctx, |ui| {
                            ui.spacing_mut().item_spacing =
                                egui::vec2(theme::SPACE_SM, theme::SPACE_SM);
                            self.debug_layout.rail_rect = [0.0; 4];
                            self.debug_layout.main_rect = rect_xywh(ui.available_rect_before_wrap());
                            self.files_tab(ui, active);
                        });
                } else if matches!(self.active_tab_ref(), Some(Tab::Settings { .. })) {
                    egui::CentralPanel::default()
                        .frame(
                            egui::Frame::NONE
                                .fill(theme::BG_PANEL)
                                .inner_margin(egui::Margin::same(theme::SPACE_MD as i8)),
                        )
                        .show(ctx, |ui| {
                            ui.spacing_mut().item_spacing =
                                egui::vec2(theme::SPACE_SM, theme::SPACE_SM);
                            self.debug_layout.rail_rect = [0.0; 4];
                            self.debug_layout.main_rect = rect_xywh(ui.available_rect_before_wrap());
                            self.settings_tab(ui);
                        });
                } else {
                    self.machines_workspace(ctx);
                }

                if self.quick_menu_open {
                    self.paint_quick_connect_popup(ctx);
                }
            }
        }
        self.sync_window_title(ctx);
    }
}

impl ControllerApp {
    fn paint_auth_banners(&self, ui: &mut egui::Ui) {
        if !self.error.is_empty() {
            banner(ui, &self.error, true);
        }
        if !self.notice.is_empty() {
            banner(ui, &self.notice, false);
        }
    }

    fn machines_workspace(&mut self, ctx: &egui::Context) {
        let show_rail = model::machine_rail_visible_at(
            ctx.screen_rect().width(),
            ctx.pixels_per_point(),
        );
        egui::CentralPanel::default()
            .frame(egui::Frame::NONE.fill(theme::BG_PANEL))
            .show(ctx, |ui| {
                egui::Frame::NONE
                    .inner_margin(egui::Margin::same(theme::SPACE_MD as i8))
                    .show(ui, |ui| {
                        ui.spacing_mut().item_spacing =
                            egui::vec2(theme::SPACE_SM, theme::SPACE_SM);
                        if self.preview_ui {
                            let clip = ui.clip_rect();
                            let b = banner(
                                ui,
                                "Isolated preview — fixture machines, not a live account or production auto-start.",
                                false,
                            );
                            self.debug_layout
                                .note_visible("preview_banner", b.rect, clip);
                        }
                        self.paint_auth_banners(ui);
                        if show_rail {
                            let avail = ui.available_size();
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
                                                .layout(egui::Layout::top_down(egui::Align::Min)),
                                        );
                                        rail_ui.set_clip_rect(rail_rect);
                                        egui::Frame::NONE
                                            .fill(theme::BG_SURFACE)
                                            .inner_margin(egui::Margin::same(theme::SPACE_MD as i8))
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
                                                .id_salt("machines-main")
                                                .max_rect(main_rect)
                                                .layout(egui::Layout::top_down(egui::Align::Min)),
                                        );
                                        main_ui.set_clip_rect(main_rect);
                                        egui::Frame::NONE
                                            .inner_margin(egui::Margin::symmetric(
                                                theme::SPACE_MD as i8,
                                                0,
                                            ))
                                            .show(&mut main_ui, |ui| {
                                                self.machines(ui);
                                            });
                                    }
                                    self.debug_layout.rail_rect = rect_xywh(rail_rect);
                                    self.debug_layout.main_rect = rect_xywh(main_rect);
                                },
                            );
                        } else {
                            let main_rect = ui.available_rect_before_wrap();
                            self.debug_layout.rail_rect = [0.0; 4];
                            self.debug_layout.main_rect = rect_xywh(main_rect);
                            self.machines(ui);
                        }
                    });
            });
    }

    fn paint_tab_bar(&mut self, ctx: &egui::Context) {
        let mut switch_to: Option<TabId> = None;
        let mut close_tab: Option<TabId> = None;
        let mut duplicate_node: Option<NodeInfo> = None;
        let mut close_others: Option<TabId> = None;
        let mut new_terminal = false;
        let mut toggle_menu = false;
        let mut open_settings = false;

        let labels = self.compute_tab_labels();
        let tab_metas: Vec<(TabId, String, TabIcon, TabDot, &'static str, bool, Option<String>)> =
            self.tabs
                .iter()
                .zip(labels.into_iter())
                .map(|(tab, (id, label))| {
                    let is_terminal = matches!(tab, Tab::Terminal(_));
                    let node_id = tab.node_id().map(ToString::to_string);
                    (
                        id,
                        label,
                        tab.icon(),
                        tab.dot(),
                        tab.kind_label(),
                        is_terminal,
                        node_id,
                    )
                })
                .collect();

        let bar_resp = egui::TopBottomPanel::top("tab_bar")
            .exact_height(theme::TAB_BAR_HEIGHT)
            .show_separator_line(false)
            .frame(
                egui::Frame::NONE
                    .fill(theme::TAB_STRIP_BG)
                    .inner_margin(egui::Margin::symmetric(6, 0)),
            )
            .show(ctx, |ui| {
                ui.spacing_mut().item_spacing = egui::vec2(3.0, 0.0);
                let full_rect = ui.max_rect();
                let bar_w = full_rect.width().max(1.0);
                let show_account = bar_w >= 580.0;

                let account_text = if self.preview_ui {
                    Some("Preview".to_string())
                } else {
                    self.user.as_ref().map(|u| {
                        if u.chars().count() > 14 {
                            let prefix: String = u.chars().take(13).collect();
                            format!("{prefix}…")
                        } else {
                            u.clone()
                        }
                    })
                };
                let account_w = if show_account {
                    account_text
                        .as_deref()
                        .map(|t| (text_advance(t, theme::SECONDARY_SIZE, false) + 18.0).clamp(48.0, 118.0))
                        .unwrap_or(0.0)
                } else {
                    0.0
                };
                let settings_w = 28.0_f32;
                let right_w = settings_w + if account_w > 0.0 { account_w + 6.0 } else { 0.0 };
                let pinned_w = theme::TAB_PINNED_WIDTH;
                let split_w = 52.0_f32;
                let gap_budget = tab_metas.len().saturating_sub(1) as f32 * 3.0;
                let session_avail_w =
                    (bar_w - pinned_w - right_w - split_w - 22.0).max(0.0);
                let (tab_w, needs_scroll) = tabs::compute_session_tab_width(
                    (session_avail_w - gap_budget).max(0.0),
                    tab_metas.len(),
                );

                ui.horizontal_centered(|ui| {
                    // 1. Pinned Machines tab
                    let is_machines_active = self.active_tab == MACHINES_TAB_ID;
                    let machines_resp = self.paint_single_tab_widget(
                        ui,
                        MACHINES_TAB_ID,
                        "Machines",
                        TabIcon::Machines,
                        TabDot::None,
                        pinned_w,
                        is_machines_active,
                        false,
                        false,
                        "All machines (Ctrl+Shift+M)",
                    );
                    self.debug_layout
                        .note_tab_item("tab_machines", machines_resp.rect);
                    if machines_resp.clicked {
                        switch_to = Some(MACHINES_TAB_ID);
                    }

                    // 2. Closable session / settings tabs
                    if !tab_metas.is_empty() {
                        if needs_scroll && session_avail_w > 40.0 {
                            ui.allocate_ui_with_layout(
                                egui::vec2(session_avail_w, theme::TAB_BAR_HEIGHT),
                                egui::Layout::left_to_right(egui::Align::Center),
                                |ui| {
                                    ui.set_max_width(session_avail_w);
                                    egui::ScrollArea::horizontal()
                                        .id_salt("tab-strip-scroll")
                                        .scroll_bar_visibility(
                                            egui::scroll_area::ScrollBarVisibility::AlwaysHidden,
                                        )
                                        .auto_shrink([false, false])
                                        .show(ui, |ui| {
                                            ui.spacing_mut().item_spacing = egui::vec2(3.0, 0.0);
                                            let sclip = ui.clip_rect();
                                            for (
                                                id,
                                                label,
                                                icon,
                                                dot,
                                                kind_lbl,
                                                is_term,
                                                node_id,
                                            ) in &tab_metas
                                            {
                                                let active = self.active_tab == *id;
                                                let active_is_term = active && *is_term;
                                                let r = self.paint_single_tab_widget(
                                                    ui,
                                                    *id,
                                                    label,
                                                    *icon,
                                                    *dot,
                                                    tab_w,
                                                    active,
                                                    true,
                                                    active_is_term,
                                                    &format!("{kind_lbl} · {label}"),
                                                );
                                                self.debug_layout.note_tab_visible(
                                                    &format!("tab:{id}"),
                                                    r.rect,
                                                    sclip,
                                                );
                                                if let Some(c_rect) = r.close_rect {
                                                    self.debug_layout.note_tab_visible(
                                                        &format!("tab_close:{id}"),
                                                        c_rect,
                                                        sclip,
                                                    );
                                                }
                                                if r.close_clicked || r.middle_clicked {
                                                    close_tab = Some(*id);
                                                } else if r.clicked {
                                                    switch_to = Some(*id);
                                                }
                                                if r.ctx_duplicate {
                                                    if let Some(nid) = node_id {
                                                        duplicate_node = Some(
                                                            self.terminal_target_node(nid, label),
                                                        );
                                                    }
                                                }
                                                if r.ctx_close {
                                                    close_tab = Some(*id);
                                                }
                                                if r.ctx_close_others {
                                                    close_others = Some(*id);
                                                }
                                            }
                                        });
                                },
                            );
                        } else {
                            let clip = ui.clip_rect();
                            for (id, label, icon, dot, kind_lbl, is_term, node_id) in &tab_metas {
                                let active = self.active_tab == *id;
                                let active_is_term = active && *is_term;
                                let r = self.paint_single_tab_widget(
                                    ui,
                                    *id,
                                    label,
                                    *icon,
                                    *dot,
                                    tab_w,
                                    active,
                                    true,
                                    active_is_term,
                                    &format!("{kind_lbl} · {label}"),
                                );
                                self.debug_layout
                                    .note_tab_visible(&format!("tab:{id}"), r.rect, clip);
                                if let Some(c_rect) = r.close_rect {
                                    self.debug_layout.note_tab_visible(
                                        &format!("tab_close:{id}"),
                                        c_rect,
                                        clip,
                                    );
                                }
                                if r.close_clicked || r.middle_clicked {
                                    close_tab = Some(*id);
                                } else if r.clicked {
                                    switch_to = Some(*id);
                                }
                                if r.ctx_duplicate {
                                    if let Some(nid) = node_id {
                                        duplicate_node =
                                            Some(self.terminal_target_node(nid, label));
                                    }
                                }
                                if r.ctx_close {
                                    close_tab = Some(*id);
                                }
                                if r.ctx_close_others {
                                    close_others = Some(*id);
                                }
                            }
                        }
                    }

                    // 3. Split [ + | ▾ ] button
                    let (plus_rect, plus_resp) = ui.allocate_exact_size(
                        egui::vec2(28.0, 26.0),
                        egui::Sense::click(),
                    );
                    if plus_resp.hovered() {
                        ui.painter().rect_filled(
                            plus_rect,
                            egui::CornerRadius {
                                nw: 5,
                                ne: 0,
                                sw: 5,
                                se: 0,
                            },
                            theme::TAB_HOVER_BG,
                        );
                    }
                    let plus_col = if plus_resp.hovered() {
                        theme::TEXT_PRIMARY
                    } else {
                        theme::TEXT_BODY
                    };
                    tabs::paint_plus_glyph(ui.painter(), plus_rect, plus_col);
                    self.debug_layout.note_tab_item("tab_new", plus_rect);
                    let plus_resp = plus_resp.on_hover_text("New terminal tab (Ctrl+Shift+T)");
                    if plus_resp.has_focus()
                        && matches!(self.active_tab_ref(), Some(Tab::Terminal(_)))
                    {
                        plus_resp.surrender_focus();
                    }
                    if plus_resp.clicked() {
                        new_terminal = true;
                    }

                    let (menu_rect, menu_resp) = ui.allocate_exact_size(
                        egui::vec2(22.0, 26.0),
                        egui::Sense::click(),
                    );
                    if menu_resp.hovered() || self.quick_menu_open {
                        ui.painter().rect_filled(
                            menu_rect,
                            egui::CornerRadius {
                                nw: 0,
                                ne: 5,
                                sw: 0,
                                se: 5,
                            },
                            theme::TAB_HOVER_BG,
                        );
                    }
                    let menu_col = if menu_resp.hovered() || self.quick_menu_open {
                        theme::TEXT_PRIMARY
                    } else {
                        theme::TEXT_MUTED
                    };
                    tabs::paint_chevron_down_glyph(ui.painter(), menu_rect, menu_col);
                    self.debug_layout.note_tab_item("tab_menu", menu_rect);
                    self.quick_menu_anchor = Some(plus_rect.union(menu_rect));
                    let menu_resp = menu_resp.on_hover_text("Quick connect & window menu");
                    if menu_resp.clicked() {
                        toggle_menu = true;
                    }

                    // 4. Right side: Settings icon + compact account pill
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.spacing_mut().item_spacing = egui::vec2(6.0, 0.0);
                        let is_settings_active =
                            matches!(self.active_tab_ref(), Some(Tab::Settings { .. }));
                        let (set_rect, set_resp) = ui.allocate_exact_size(
                            egui::vec2(settings_w, 26.0),
                            egui::Sense::click(),
                        );
                        if set_resp.hovered() || is_settings_active {
                            ui.painter().rect_filled(
                                set_rect,
                                egui::CornerRadius::same(5),
                                if is_settings_active {
                                    theme::TAB_ACTIVE_BG
                                } else {
                                    theme::TAB_HOVER_BG
                                },
                            );
                        }
                        tabs::paint_tab_icon(
                            ui.painter(),
                            set_rect.shrink(6.0),
                            TabIcon::Settings,
                            if set_resp.hovered() || is_settings_active {
                                theme::TEXT_PRIMARY
                            } else {
                                theme::TEXT_MUTED
                            },
                        );
                        self.debug_layout
                            .note_tab_item("header_settings", set_rect);
                        if set_resp.on_hover_text("Settings (Ctrl+,)").clicked() {
                            open_settings = true;
                        }

                        if show_account {
                            if let Some(acct) = account_text.as_deref() {
                                let (pill_rect, _) = ui.allocate_exact_size(
                                    egui::vec2(account_w, 22.0),
                                    egui::Sense::hover(),
                                );
                                ui.painter().rect_filled(
                                    pill_rect,
                                    egui::CornerRadius::same(11),
                                    theme::BG_SURFACE,
                                );
                                ui.painter().rect_stroke(
                                    pill_rect,
                                    egui::CornerRadius::same(11),
                                    theme::stroke_border_subtle(),
                                    egui::StrokeKind::Inside,
                                );
                                ui.painter()
                                    .with_clip_rect(pill_rect.shrink2(egui::vec2(6.0, 0.0)))
                                    .text(
                                        pill_rect.center(),
                                        egui::Align2::CENTER_CENTER,
                                        acct,
                                        egui::FontId::proportional(theme::BAR_SIZE),
                                        theme::TEXT_MUTED,
                                    );
                            }
                        }
                    });
                });
            });

        let bar_rect = bar_resp.response.rect;
        self.debug_layout.tab_bar_rect = rect_xywh(bar_rect);
        let painter = ctx.layer_painter(egui::LayerId::new(
            egui::Order::Middle,
            egui::Id::new("tab-bar-hairline"),
        ));
        painter.line_segment(
            [
                egui::pos2(bar_rect.left(), bar_rect.bottom()),
                egui::pos2(bar_rect.right(), bar_rect.bottom()),
            ],
            egui::Stroke::new(1.0_f32, theme::BORDER_SUBTLE),
        );

        if let Some(id) = close_tab {
            self.request_close_tab(Some(ctx), id);
        } else if let Some(keep) = close_others {
            self.close_other_tabs(Some(ctx), keep);
        } else if let Some(node) = duplicate_node {
            self.open_terminal_tab(&node);
        } else if let Some(target) = switch_to {
            self.activate_tab(Some(ctx), target);
        }
        if new_terminal {
            self.quick_menu_open = false;
            if let Some(node) = self.quick_new_terminal_target() {
                self.open_terminal_tab(&node);
            } else {
                self.quick_menu_open = true;
            }
        }
        if toggle_menu {
            self.quick_menu_open = !self.quick_menu_open;
        }
        if open_settings {
            self.quick_menu_open = false;
            self.open_settings_tab();
        }
    }

    fn paint_single_tab_widget(
        &self,
        ui: &mut egui::Ui,
        id: TabId,
        label: &str,
        icon: TabIcon,
        dot: TabDot,
        width: f32,
        active: bool,
        closable: bool,
        is_terminal: bool,
        tooltip: &str,
    ) -> TabWidgetOutcome {
        let (outer, _) = ui.allocate_exact_size(
            egui::vec2(width.max(48.0), theme::TAB_BAR_HEIGHT),
            egui::Sense::hover(),
        );
        // Anchor tab 4pt from top, flush with bottom hairline like Windows Terminal.
        let tab_rect = egui::Rect::from_min_max(
            egui::pos2(outer.left(), outer.bottom() - theme::TAB_HEIGHT),
            outer.max,
        );
        let close_w = if closable { 18.0 } else { 0.0 };
        let close_rect = if closable {
            Some(egui::Rect::from_center_size(
                egui::pos2(tab_rect.right() - 13.0, tab_rect.center().y),
                egui::vec2(16.0, 16.0),
            ))
        } else {
            None
        };

        let body_resp = ui.interact(
            tab_rect,
            ui.id().with(("wt-tab-body", id)),
            egui::Sense::click(),
        );
        let close_resp = close_rect.map(|r| {
            ui.interact(
                r,
                ui.id().with(("wt-tab-close", id)),
                egui::Sense::click(),
            )
        });
        let hovered = body_resp.hovered()
            || close_resp.as_ref().is_some_and(|r| r.hovered());

        let fill = if active {
            if is_terminal {
                theme::BG_TERMINAL
            } else {
                theme::TAB_ACTIVE_BG
            }
        } else if hovered {
            theme::TAB_HOVER_BG
        } else {
            egui::Color32::TRANSPARENT
        };
        let corner = egui::CornerRadius {
            nw: 6,
            ne: 6,
            sw: 0,
            se: 0,
        };
        if fill != egui::Color32::TRANSPARENT {
            ui.painter().rect_filled(tab_rect, corner, fill);
        }
        if active {
            ui.painter().line_segment(
                [
                    egui::pos2(tab_rect.left() + 6.0, tab_rect.top() + 0.5),
                    egui::pos2(tab_rect.right() - 6.0, tab_rect.top() + 0.5),
                ],
                egui::Stroke::new(2.0_f32, theme::ACCENT),
            );
        } else {
            ui.painter().line_segment(
                [
                    egui::pos2(tab_rect.right() - 0.5, tab_rect.top() + 7.0),
                    egui::pos2(tab_rect.right() - 0.5, tab_rect.bottom() - 7.0),
                ],
                egui::Stroke::new(1.0_f32, theme::BORDER_SUBTLE),
            );
        }

        let icon_rect = egui::Rect::from_center_size(
            egui::pos2(tab_rect.left() + 14.0, tab_rect.center().y),
            egui::vec2(13.0, 13.0),
        );
        let fg = if active {
            theme::TEXT_PRIMARY
        } else {
            theme::TEXT_MUTED
        };
        tabs::paint_tab_icon(ui.painter(), icon_rect, icon, fg);

        let mut text_left = icon_rect.right() + 6.0;
        if let Some(dot_color) = dot.color() {
            ui.painter().circle_filled(
                egui::pos2(text_left + 3.0, tab_rect.center().y),
                3.0,
                dot_color,
            );
            text_left += 9.0;
        }
        let text_right = tab_rect.right() - if closable { close_w + 8.0 } else { 8.0 };
        if text_right > text_left + 8.0 {
            let text_clip = egui::Rect::from_min_max(
                egui::pos2(text_left, tab_rect.top()),
                egui::pos2(text_right, tab_rect.bottom()),
            );
            let galley = ui.painter().layout_no_wrap(
                label.to_string(),
                egui::FontId::proportional(theme::SECONDARY_SIZE),
                fg,
            );
            let ty = tab_rect.center().y - galley.size().y * 0.5;
            ui.painter()
                .with_clip_rect(text_clip)
                .galley(egui::pos2(text_left, ty), galley, fg);
        }

        if let (Some(c_rect), Some(c_resp)) = (close_rect, &close_resp) {
            if active || hovered {
                if c_resp.hovered() {
                    ui.painter().rect_filled(
                        c_rect,
                        egui::CornerRadius::same(4),
                        theme::BG_HOVER,
                    );
                }
                let x_col = if c_resp.hovered() {
                    theme::TEXT_PRIMARY
                } else {
                    theme::TEXT_MUTED
                };
                tabs::paint_close_glyph(ui.painter(), c_rect, x_col);
            }
        }

        let mut ctx_duplicate = false;
        let mut ctx_close = false;
        let mut ctx_close_others = false;
        let allow_dup = matches!(icon, TabIcon::Terminal);
        if closable {
            body_resp.context_menu(|ui| {
                ui.set_min_width(150.0);
                if allow_dup && ui.button("New tab on node").clicked() {
                    ctx_duplicate = true;
                    ui.close_menu();
                }
                if ui.button("Close tab").clicked() {
                    ctx_close = true;
                    ui.close_menu();
                }
                if ui.button("Close other tabs").clicked() {
                    ctx_close_others = true;
                    ui.close_menu();
                }
            });
        }

        let body_tip = body_resp.on_hover_text(tooltip);
        if body_tip.has_focus() && is_terminal {
            body_tip.surrender_focus();
        }
        let close_clicked = close_resp.as_ref().is_some_and(|r| r.clicked());
        let middle_clicked = closable && body_tip.middle_clicked();
        let clicked = body_tip.clicked() && !close_clicked;

        TabWidgetOutcome {
            rect: tab_rect,
            close_rect,
            clicked,
            close_clicked,
            middle_clicked,
            ctx_duplicate,
            ctx_close,
            ctx_close_others,
        }
    }

    fn paint_quick_connect_popup(&mut self, ctx: &egui::Context) {
        if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
            self.quick_menu_open = false;
            return;
        }
        let anchor = self.quick_menu_anchor.unwrap_or_else(|| {
            egui::Rect::from_min_size(
                egui::pos2(110.0, theme::TAB_BAR_HEIGHT),
                egui::vec2(52.0, 26.0),
            )
        });
        let win_w = ctx.screen_rect().width().max(320.0);
        let popup_w = 340.0_f32.min(win_w - 16.0);
        let pos = egui::pos2(
            anchor.left().min(win_w - popup_w - 8.0).max(8.0),
            anchor.bottom() + 4.0,
        );

        let mut open_action: Option<(NodeInfo, CardButtonKind)> = None;
        let mut go_machines = false;
        let mut open_pair = false;
        let mut do_refresh = false;
        let mut open_settings = false;
        let mut do_logout = false;
        let mut do_quit = false;

        let nodes = self.nodes.clone();
        let area_resp = egui::Area::new(egui::Id::new("quick-connect-popup"))
            .order(egui::Order::Foreground)
            .fixed_pos(pos)
            .show(ctx, |ui| {
                theme::panel_frame().show(ui, |ui| {
                    ui.set_min_width(popup_w - 20.0);
                    ui.set_max_width(popup_w - 20.0);
                    ui.label(theme::section_text("New tab / Quick connect"));
                    ui.add_space(theme::SPACE_XS);
                    let online_nodes: Vec<NodeInfo> =
                        nodes.into_iter().filter(|n| n.online).collect();
                    if online_nodes.is_empty() {
                        ui.label(theme::muted_text("No online machines available."));
                    } else {
                        egui::ScrollArea::vertical()
                            .id_salt("quick-connect-list")
                            .max_height(240.0)
                            .show(ui, |ui| {
                                for node in &online_nodes {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(
                                            egui::RichText::new(&node.name)
                                                .color(theme::TEXT_PRIMARY)
                                                .size(theme::SECONDARY_SIZE)
                                                .strong(),
                                        );
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                let buttons = card_buttons(
                                                    node.online,
                                                    node.has_display,
                                                    node.effective,
                                                );
                                                for btn in buttons.into_iter().rev() {
                                                    if !btn.enabled {
                                                        continue;
                                                    }
                                                    let short = match btn.kind {
                                                        CardButtonKind::Terminal => "Term",
                                                        CardButtonKind::ControlDesktop => "Desk",
                                                        CardButtonKind::ViewDesktop => "View",
                                                        CardButtonKind::Files => "Files",
                                                    };
                                                    if ui.add(theme::secondary_button(short)).clicked()
                                                    {
                                                        open_action =
                                                            Some((node.clone(), btn.kind));
                                                    }
                                                }
                                            },
                                        );
                                    });
                                }
                            });
                    }
                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        if ui.add(theme::secondary_button("All machines")).clicked() {
                            go_machines = true;
                        }
                        if ui
                            .add_enabled(
                                !self.preview_ui,
                                theme::secondary_button("Pair machine"),
                            )
                            .clicked()
                        {
                            open_pair = true;
                        }
                        if !self.preview_ui
                            && ui.add(theme::secondary_button("Refresh")).clicked()
                        {
                            do_refresh = true;
                        }
                        if ui.add(theme::secondary_button("Settings")).clicked() {
                            open_settings = true;
                        }
                        if !self.preview_ui
                            && self.user.is_some()
                            && ui.add(theme::secondary_button("Log out")).clicked()
                        {
                            do_logout = true;
                        }
                        if ui.add(theme::secondary_button("Quit")).clicked() {
                            do_quit = true;
                        }
                    });
                });
            })
            .response;

        if area_resp.clicked_elsewhere() {
            let clicked_menu_btn = self
                .quick_menu_anchor
                .is_some_and(|r| ctx.input(|i| i.pointer.interact_pos().is_some_and(|p| r.contains(p))));
            if !clicked_menu_btn {
                self.quick_menu_open = false;
            }
        }
        if let Some((node, kind)) = open_action {
            self.quick_menu_open = false;
            match kind {
                CardButtonKind::Terminal => {
                    self.open_terminal_tab(&node);
                }
                CardButtonKind::Files => {
                    self.open_files_tab(&node);
                }
                CardButtonKind::ViewDesktop => {
                    self.open_desktop_tab(&node, false);
                }
                CardButtonKind::ControlDesktop => {
                    self.open_desktop_tab(&node, true);
                }
            }
        } else if go_machines {
            self.quick_menu_open = false;
            self.activate_tab(Some(ctx), MACHINES_TAB_ID);
        } else if open_pair && !self.preview_ui {
            self.quick_menu_open = false;
            self.enroll_open = true;
            self.activate_tab(Some(ctx), MACHINES_TAB_ID);
        } else if do_refresh && !self.preview_ui {
            self.quick_menu_open = false;
            self.send(Cmd::Refresh);
        } else if open_settings {
            self.quick_menu_open = false;
            self.open_settings_tab();
        } else if do_logout && !self.preview_ui {
            self.quick_menu_open = false;
            self.reset_to_login(Some(ctx), None);
            self.send(Cmd::Logout);
        } else if do_quit {
            self.quick_menu_open = false;
            self.flags.quit.store(true, Ordering::Relaxed);
            if !self.preview_ui {
                self.send(Cmd::PtyCloseAll);
                self.send(Cmd::LiveStop);
            }
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

struct TabWidgetOutcome {
    rect: egui::Rect,
    close_rect: Option<egui::Rect>,
    clicked: bool,
    close_clicked: bool,
    middle_clicked: bool,
    ctx_duplicate: bool,
    ctx_close: bool,
    ctx_close_others: bool,
}

impl ControllerApp {
    fn login(&mut self, ui: &mut egui::Ui) {
        let width = ui.available_width().min(400.0);
        let enter_pressed = ui.input(|i| i.key_pressed(egui::Key::Enter));
        let mut submit = false;
        ui.vertical_centered(|ui| {
            ui.set_max_width(width);
            ui.add_space(theme::SPACE_XL);
            ui.label(theme::title_text("Sign in"));
            ui.add_space(theme::SPACE_SM);
            ui.label(theme::body_text(
                "Username, password, and relay URL. Nothing is selected for you.",
            ));
            ui.label(theme::muted_text(
                "The sign-in stays for 30 days of use, same as the phone. An authenticator code appears when the account uses one.",
            ));
            ui.add_space(theme::SPACE_MD);
            if labeled(ui, "Relay URL", &mut self.relay, false).lost_focus() && enter_pressed {
                submit = true;
            }
            ui.add_space(theme::SPACE_SM);
            if labeled(ui, "Username", &mut self.username, false).lost_focus() && enter_pressed {
                submit = true;
            }
            ui.add_space(theme::SPACE_SM);
            ui.label(theme::muted_text("Password"));
            ui.horizontal(|ui| {
                ui.spacing_mut().item_spacing.x = theme::SPACE_SM;
                ui.set_height(theme::BTN_PRIMARY_H);
                let btn_w = 72.0;
                let ppp = ui.ctx().pixels_per_point();
                let vpad = super::field_pad::text_edit_v_margin(
                    theme::BTN_PRIMARY_H,
                    theme::BODY_SIZE,
                    ppp,
                );
                let v = vpad.round().clamp(0.0, 40.0) as i8;
                let edit = egui::TextEdit::singleline(&mut self.password)
                    .password(!self.show_password)
                    .desired_width((ui.available_width() - btn_w - theme::SPACE_SM).max(80.0))
                    .min_size(egui::vec2(0.0, theme::BTN_PRIMARY_H))
                    .margin(egui::Margin::symmetric(theme::BTN_PAD_X as i8, v));
                if style_text_edit(ui, edit).lost_focus() && enter_pressed {
                    submit = true;
                }
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
                if labeled(ui, "Authenticator code", &mut self.totp, false).lost_focus()
                    && enter_pressed
                {
                    submit = true;
                }
            }
            ui.add_space(theme::SPACE_MD);
            if ui
                .add_sized([width, theme::BTN_PRIMARY_H], theme::primary_button("Sign in"))
                .clicked()
            {
                submit = true;
            }
            ui.add_space(theme::SPACE_MD);
            let advanced = egui::CollapsingHeader::new(theme::muted_text("Advanced"))
                .default_open(self.advanced)
                .show(ui, |ui| {
                    ui.label(theme::muted_text(
                        "Certificate pin and TLS trust. Pair a machine after you sign in.",
                    ));
                    if labeled(ui, "Certificate pin", &mut self.pin, false).lost_focus()
                        && enter_pressed
                    {
                        submit = true;
                    }
                    if labeled(
                        ui,
                        "Trust (system, webpki, or system+webpki)",
                        &mut self.trust,
                        false,
                    )
                    .lost_focus()
                        && enter_pressed
                    {
                        submit = true;
                    }
                    ui.label(theme::muted_text(
                        "Leave the pin empty only when this relay uses public roots (system or webpki). Otherwise pin sha256:, spki:sha256:, or intermediate:sha256:.",
                    ));
                });
            paint_and_note_focus_ring(
                &mut self.debug_layout,
                ui,
                "advanced",
                &advanced.header_response,
                ui.clip_rect(),
            );
        });
        if submit {
            self.submit_login();
        }
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
            && !self.nodes_loaded
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
                        if loading {
                            ui.spinner();
                            ui.add_space(theme::SPACE_SM);
                        }
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
        self.nodes_loaded = true;
        self.selected_id = self.nodes.first().map(|n| n.id.clone());
        self.tabs.clear();
        self.active_tab = MACHINES_TAB_ID;
        self.auth = AuthScreen::Workspace;
        self.link = "isolated preview".into();
        self.window_title = "AgentLink (Preview)".into();
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
        let open_tabs = self
            .tabs
            .iter()
            .filter(|t| t.node_id() == Some(node.id.as_str()))
            .count();
        let hover_id = ui.id().with("machine-row-hover").with(&node.id);
        let hovered = ui.data(|d| d.get_temp::<bool>(hover_id).unwrap_or(false));
        let fill = if selected {
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
                        if open_tabs == 1 {
                            ui.label(theme::muted_text("1 tab open"));
                        } else if open_tabs > 1 {
                            ui.label(theme::muted_text(format!("{open_tabs} tabs open")));
                        }
                    })
                    .response;
                let id = ui.id().with("machine-row-focus").with(node.id.as_str());
                ui.interact(frame_resp.rect, id, egui::Sense::click())
            })
            .inner;
        self.debug_layout
            .note_item(&format!("nav_row:{}", node.id), response.rect);
        paint_and_note_focus_ring(
            &mut self.debug_layout,
            ui,
            &format!("nav_row:{}", node.id),
            &response,
            ui.clip_rect(),
        );
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
            if !self.preview_ui && !self.mock {
                let badge = model::inspect_local_grant(
                    &self.config_dir,
                    &node.id,
                    self.controller_id.as_deref(),
                );
                let (grant_text, grant_color, dot_color) = match &badge {
                    LocalGrantBadge::Active { summary, policy } => (
                        format!("Grant: {summary} · {policy}"),
                        theme::TEXT_BODY,
                        theme::SUCCESS,
                    ),
                    LocalGrantBadge::Expired { summary } => (
                        format!("Grant: {summary}"),
                        theme::WARN,
                        theme::WARN,
                    ),
                    LocalGrantBadge::GranteeMismatch { summary } => (
                        format!("Grant: {summary}"),
                        theme::DANGER,
                        theme::DANGER,
                    ),
                    LocalGrantBadge::Missing => (
                        "Grant: missing — issue or paste a grant below".to_string(),
                        theme::WARN,
                        theme::WARN,
                    ),
                    LocalGrantBadge::Error(err) => (
                        format!("Grant: unreadable ({err})"),
                        theme::DANGER,
                        theme::DANGER,
                    ),
                };
                status_pill(ui, &grant_text, grant_color, Some(dot_color));
            }
            if let Some(note) = display_note(node.has_display, node.effective) {
                let resp = ui.add(egui::Label::new(theme::muted_text(note)).wrap());
                self.debug_layout
                    .note_visible("display_note", resp.rect, clip);
            }
            let open_node_tabs: Vec<(TabId, &'static str)> = self
                .tabs
                .iter()
                .filter(|t| t.node_id() == Some(node.id.as_str()))
                .map(|t| (t.id(), t.kind_label()))
                .collect();
            if !open_node_tabs.is_empty() {
                ui.add_space(theme::SPACE_XS);
                let mut jump_to: Option<TabId> = None;
                ui.horizontal_wrapped(|ui| {
                    ui.label(theme::muted_text("Open tabs:"));
                    for (tab_id, kind) in open_node_tabs {
                        if ui
                            .add(theme::secondary_button(&format!("{kind} #{tab_id}")))
                            .clicked()
                        {
                            jump_to = Some(tab_id);
                        }
                    }
                });
                if let Some(tab_id) = jump_to {
                    self.activate_tab(Some(ui.ctx()), tab_id);
                }
            }
            ui.add_space(theme::SPACE_MD);
            let prompt = ui.label(theme::section_text("Choose how to connect"));
            self.debug_layout
                .note_visible("connect_prompt", prompt.rect, clip);
            if self.preview_ui {
                ui.label(theme::muted_text(
                    "Sample actions for layout review. This is not a live session.",
                ));
            } else {
                ui.label(theme::muted_text(
                    "Start a terminal, files, or desktop tab when the machine allows it.",
                ));
            }
            ui.add_space(theme::SPACE_SM);
            self.session_actions(ui, node, false);
            if !self.preview_ui && !self.mock {
                ui.add_space(theme::SPACE_SM);
                self.grant_panel(ui, node);
            }
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
            paint_and_note_focus_ring(
                &mut self.debug_layout,
                ui,
                "details",
                &details.header_response,
                ui.clip_rect(),
            );
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

    fn settings_tab(&mut self, ui: &mut egui::Ui) {
        let clip = ui.clip_rect();
        let mut do_refresh = false;
        let mut do_logout = false;
        let mut do_quit = false;

        egui::ScrollArea::vertical()
            .id_salt("settings-page")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.set_width(innermost_avail(ui));
                ui.vertical_centered(|ui| {
                    ui.set_max_width(640.0);
                    ui.with_layout(egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.label(theme::title_text("Settings"));
                        ui.add_space(theme::SPACE_SM);

                        let panel_resp = theme::card_frame().show(ui, |ui| {
                            ui.label(theme::section_text("Account & Relay"));
                            ui.add_space(theme::SPACE_XS);
                            if self.preview_ui {
                                ui.label(theme::muted_text("Mode: Isolated preview (not signed in)"));
                            } else {
                                if let Some(user) = &self.user {
                                    ui.label(theme::body_text(format!("Signed in as: {user}")));
                                } else {
                                    ui.label(theme::muted_text("Not signed in"));
                                }
                                if !self.relay.is_empty() {
                                    ui.label(theme::muted_text(format!("Relay: {}", self.relay)));
                                }
                                ui.label(theme::muted_text(format!("Status: {}", self.link)));
                            }
                            ui.add_space(theme::SPACE_XS);
                            ui.horizontal_wrapped(|ui| {
                                if !self.preview_ui && self.user.is_some() {
                                    let refresh = ui.add(theme::secondary_button("Refresh machines"));
                                    self.debug_layout.note_visible(
                                        "settings_refresh",
                                        refresh.rect,
                                        clip,
                                    );
                                    if refresh.clicked() {
                                        do_refresh = true;
                                    }
                                    let logout = ui.add(theme::secondary_button("Log out"));
                                    self.debug_layout.note_visible(
                                        "settings_logout",
                                        logout.rect,
                                        clip,
                                    );
                                    if logout.clicked() {
                                        do_logout = true;
                                    }
                                }
                                let quit = ui.add(theme::secondary_button("Quit controller"));
                                self.debug_layout
                                    .note_visible("settings_quit", quit.rect, clip);
                                if quit.clicked() {
                                    do_quit = true;
                                }
                            });

                            ui.separator();
                            ui.label(theme::section_text("This computer"));
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

                            ui.separator();
                            ui.label(theme::section_text("Terminal"));
                            if !self.preview_ui {
                                let osc_label = if self.prefs.allow_osc52 {
                                    "Terminal OSC 52 clipboard: on (≤64 KiB)"
                                } else {
                                    "Terminal OSC 52 clipboard: off"
                                };
                                let osc_resp = ui
                                    .add(theme::secondary_button(osc_label))
                                    .on_hover_text("Allow remote terminal programs to copy up to 64 KiB to the local clipboard via OSC 52. Off by default; persisted across sessions.");
                                self.debug_layout
                                    .note_visible("settings_osc52", osc_resp.rect, clip);
                                self.debug_layout
                                    .note_focus("settings_osc52", &osc_resp, clip);
                                if osc_resp.clicked() {
                                    self.prefs.allow_osc52 = !self.prefs.allow_osc52;
                                    for tab in &mut self.tabs {
                                        if let Tab::Terminal(t) = tab {
                                            t.emulator.set_allow_osc52(self.prefs.allow_osc52);
                                        }
                                    }
                                    save_controller_prefs(&self.config_dir, &self.prefs);
                                }
                            }

                            ui.separator();
                            ui.label(theme::section_text("Remote Desktop"));
                            if !self.preview_ui {
                                let clip_label = if self.prefs.desk_clipboard_sync {
                                    "Desktop auto-sync clipboard: on"
                                } else {
                                    "Desktop auto-sync clipboard: off (manual only)"
                                };
                                let clip_resp = ui
                                    .add(theme::secondary_button(clip_label))
                                    .on_hover_text("When enabled, copies made after connecting sync automatically during control sessions (pre-existing clipboard text is never pushed on connect).");
                                if clip_resp.clicked() {
                                    self.prefs.desk_clipboard_sync =
                                        !self.prefs.desk_clipboard_sync;
                                    save_controller_prefs(&self.config_dir, &self.prefs);
                                    self.send(Cmd::ClipboardSync {
                                        enabled: self.prefs.desk_clipboard_sync,
                                    });
                                }
                            }

                            ui.separator();
                            ui.label(theme::section_text("Keyboard Shortcuts"));
                            ui.label(theme::muted_text(
                                "Shortcuts pause when Desktop keyboard capture is active so remote keys are never intercepted.",
                            ));
                            egui::Grid::new("settings-shortcuts-grid")
                                .num_columns(2)
                                .spacing([theme::SPACE_LG, theme::SPACE_XS])
                                .show(ui, |ui| {
                                    for (keys, desc) in [
                                        ("Ctrl+Shift+T", "New terminal tab"),
                                        ("Ctrl+Shift+W", "Close active tab"),
                                        ("Ctrl+Tab / Ctrl+Shift+Tab", "Next / previous tab"),
                                        ("Ctrl+Shift+M", "Switch to Machines tab"),
                                        ("Ctrl+,", "Open Settings tab"),
                                        ("F11", "Toggle Desktop fullscreen"),
                                        ("Ctrl+Alt+Shift", "Release Desktop keyboard capture"),
                                    ] {
                                        ui.label(theme::mono_bar_text(keys.to_string()));
                                        ui.label(theme::body_text(desc));
                                        ui.end_row();
                                    }
                                });

                            ui.separator();
                            ui.label(theme::muted_text(format!(
                                "About · AgentLink controller {}",
                                env!("CARGO_PKG_VERSION")
                            )));
                            if self.preview_ui {
                                ui.label(theme::muted_text(
                                    "This window is an isolated layout fixture. It is not a live account.",
                                ));
                            }
                        });
                        let panel_vis = visible_rect(panel_resp.response.rect, clip);
                        self.debug_layout
                            .note_visible("settings_panel", panel_resp.response.rect, clip);
                        self.debug_layout.page_rect = rect_xywh(panel_vis);
                    });
                });
            });

        if do_refresh && !self.preview_ui {
            self.send(Cmd::Refresh);
        } else if do_logout && !self.preview_ui {
            self.reset_to_login(Some(ui.ctx()), None);
            self.send(Cmd::Logout);
        } else if do_quit {
            self.flags.quit.store(true, Ordering::Relaxed);
            if !self.preview_ui {
                self.send(Cmd::PtyCloseAll);
                self.send(Cmd::LiveStop);
            }
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
        }
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
            CardButtonKind::Terminal => {
                self.open_terminal_tab(node);
            }
            CardButtonKind::Files => {
                self.open_files_tab(node);
            }
            CardButtonKind::ViewDesktop => {
                self.open_desktop_tab(node, false);
            }
            CardButtonKind::ControlDesktop => {
                self.open_desktop_tab(node, true);
            }
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
        ui.horizontal(|ui| {
            ui.label(theme::muted_text("Machines"));
            if !self.preview_ui {
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    let refresh = ui
                        .add(theme::secondary_button("Refresh"))
                        .on_hover_text("Reload machine list");
                    self.debug_layout
                        .note_visible("rail_refresh", refresh.rect, ui.clip_rect());
                    if refresh.clicked() {
                        self.send(Cmd::Refresh);
                    }
                });
            }
        });
        ui.add_space(theme::SPACE_XS);
        let rail_inner_w = (model::MACHINE_RAIL_WIDTH - theme::SPACE_MD * 2.0)
            .floor()
            .max(1.0);
        ui.set_max_width(rail_inner_w);
        let pair_reserve = 40.0;
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
        ui.add_space(theme::SPACE_SM);
        self.pair_toggle(ui);
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
            if !self.enroll_out.is_empty() || !self.enroll_out_ps.is_empty() {
                ui.add_space(theme::SPACE_SM);
                ui.horizontal(|ui| {
                    if ui
                        .selectable_label(self.enroll_tab == EnrollTab::Unix, "Linux / macOS")
                        .clicked()
                    {
                        self.enroll_tab = EnrollTab::Unix;
                    }
                    if ui
                        .selectable_label(
                            self.enroll_tab == EnrollTab::PowerShell,
                            "Windows PowerShell",
                        )
                        .clicked()
                    {
                        self.enroll_tab = EnrollTab::PowerShell;
                    }
                });
                let active_cmd = match self.enroll_tab {
                    EnrollTab::Unix => &mut self.enroll_out,
                    EnrollTab::PowerShell => &mut self.enroll_out_ps,
                };
                ui.label(theme::muted_text("Install command"));
                ui.add(
                    egui::TextEdit::multiline(active_cmd)
                        .desired_width(f32::INFINITY)
                        .desired_rows(4)
                        .font(egui::TextStyle::Monospace),
                );
                let to_copy = active_cmd.clone();
                ui.horizontal(|ui| {
                    if ui.add(theme::secondary_button("Copy command")).clicked() {
                        ui.ctx().copy_text(to_copy);
                        self.notice = "Install command copied.".into();
                    }
                    if !self.enroll_token.is_empty()
                        && ui.add(theme::secondary_button("Copy token")).clicked()
                    {
                        ui.ctx().copy_text(self.enroll_token.clone());
                        self.notice = "Enrollment token copied.".into();
                    }
                });
            }
        });
    }

    fn copy_grant_offer_code(
        &mut self,
        ui: &egui::Ui,
        node: &NodeInfo,
        ttl_secs: u64,
        notice_prefix: &str,
    ) {
        match Identity::load_or_create(&self.config_dir.join("identity.json")) {
            Ok(id) => {
                let now = agentlink_core::util::unix_now();
                let cfg = agentlink_core::config::load_file(&self.config_dir).unwrap_or_default();
                let relay_fp = cfg.fingerprint.as_deref().filter(|s| !s.trim().is_empty());
                match agentlink_core::grant_offer::issue_offer(
                    &id,
                    node.effective,
                    ttl_secs,
                    now,
                    600,
                    Some(&node.id),
                    relay_fp,
                )
                .and_then(|offer| agentlink_core::grant_offer::encode_offer(&offer))
                {
                    Ok(code) => {
                        ui.ctx().copy_text(code);
                        self.notice = format!("{notice_prefix} {} (valid 10m).", node.name);
                    }
                    Err(err) => self.error = err.to_string(),
                }
            }
            Err(err) => self.error = err.to_string(),
        }
    }

    fn grant_panel(&mut self, ui: &mut egui::Ui, node: &NodeInfo) {
        egui::CollapsingHeader::new("Grant & identity")
            .id_salt(("grant-panel", node.id.as_str()))
            .default_open(false)
            .show(ui, |ui| {
                let ctrl_hex = self.controller_id.clone().unwrap_or_default();
                if !ctrl_hex.is_empty() {
                    let fp = agentlink_core::grant_offer::sha256_ssh_fingerprint(&ctrl_hex)
                        .unwrap_or_else(|_| "SHA256:?".into());
                    ui.label(theme::muted_text(format!("Controller fingerprint: {fp}")));
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add(theme::secondary_button("Copy identity code (grant offer)"))
                            .on_hover_text("Create a signed grant offer code to paste on the target node.")
                            .clicked()
                        {
                            self.copy_grant_offer_code(
                                ui,
                                node,
                                7 * 24 * 3600,
                                "Copied signed grant offer code for",
                            );
                        }
                        if ui
                            .add(theme::secondary_button("Copy permanent offer"))
                            .on_hover_text("Create a signed permanent grant offer code to paste on the target node.")
                            .clicked()
                        {
                            self.copy_grant_offer_code(
                                ui,
                                node,
                                agentlink_core::grant::PERMANENT_GRANT_TTL_SECS,
                                "Copied signed permanent grant offer code for",
                            );
                        }
                        if ui.add(theme::secondary_button("Copy CLI issue command")).clicked() {
                            let cmd = format!(
                                "agentlink grant issue --node {} --grantee {} --policy {} --ttl permanent",
                                model::shell_quote(&node.name),
                                ctrl_hex,
                                model::access_summary(&node.access, node.effective),
                            );
                            ui.ctx().copy_text(cmd);
                            self.notice = "Copied `agentlink grant issue` command.".into();
                        }
                    });
                    // Local self-node or operator-issuer issuance when `grant-issuer.json`
                    // exists locally and matches this node.
                    let local_node_matches =
                        agentlink_core::grant_request::node_public_hex(&self.data_dir)
                            .ok()
                            .is_some_and(|hex| hex.eq_ignore_ascii_case(&node.id));
                    if local_node_matches
                        && ui
                            .add(theme::secondary_button("Issue local grant (this machine)"))
                            .clicked()
                    {
                        match agentlink_core::grant::issue_local_permanent_grant(
                            &self.data_dir,
                            &node.id,
                            &ctrl_hex,
                        )
                        .and_then(|grant| agentlink_core::grant::save_grant(&self.config_dir, &grant))
                        {
                            Ok(_) => {
                                self.notice = format!("Issued and saved local grant for {}.", node.name);
                                self.error.clear();
                            }
                            Err(err) => self.error = err.to_string(),
                        }
                    }
                }
                ui.add_space(theme::SPACE_XS);
                ui.label(theme::muted_text(
                    "Paste a SignedGrant JSON (to authorize this controller) or a GrantOffer code (to record a request on a local node):",
                ));
                ui.add(
                    egui::TextEdit::multiline(&mut self.grant_paste_input)
                        .desired_width(f32::INFINITY)
                        .desired_rows(3)
                        .font(egui::TextStyle::Monospace),
                );
                if ui
                    .add(theme::secondary_button("Import grant / paste offer"))
                    .clicked()
                {
                    let raw = self.grant_paste_input.trim().to_string();
                    if raw.is_empty() {
                        self.error = "Paste a SignedGrant JSON or grant offer code first.".into();
                    } else if raw.starts_with('{') {
                        match serde_json::from_str::<agentlink_core::grant::SignedGrant>(&raw) {
                            Ok(grant) => {
                                let now = agentlink_core::util::unix_now();
                                let check = grant.verify_signature().and_then(|()| {
                                    if let Some(ctrl) = self.controller_id.as_deref() {
                                        agentlink_core::grant::validate_grant_for(
                                            &grant, &node.id, ctrl, now,
                                        )
                                    } else {
                                        Ok(())
                                    }
                                });
                                match check.and_then(|()| {
                                    agentlink_core::grant::save_grant(&self.config_dir, &grant)
                                }) {
                                    Ok(_) => {
                                        self.grant_paste_input.clear();
                                        self.error.clear();
                                        self.notice = format!("Imported signed grant for {}.", node.name);
                                    }
                                    Err(err) => self.error = err.to_string(),
                                }
                            }
                            Err(err) => self.error = format!("Invalid SignedGrant JSON: {err}"),
                        }
                    } else {
                        match agentlink_core::grant_offer::decode_offer(&raw) {
                            Ok(offer) => {
                                let now = agentlink_core::util::unix_now();
                                match agentlink_core::grant_request::node_public_hex(&self.data_dir)
                                    .and_then(|local_node_id| {
                                        let relay_fp =
                                            agentlink_core::grant_offer::load_node_relay_fingerprint(
                                                &self.data_dir,
                                            )
                                            .ok()
                                            .flatten();
                                        agentlink_core::grant_offer::paste_offer_as_request(
                                            &self.data_dir,
                                            &offer,
                                            &local_node_id,
                                            relay_fp.as_deref(),
                                            now,
                                        )
                                    }) {
                                    Ok(req) => {
                                        self.grant_paste_input.clear();
                                        self.error.clear();
                                        self.notice = format!(
                                            "Recorded pending grant request {} on this node.",
                                            req.request_id
                                        );
                                    }
                                    Err(err) => self.error = err.to_string(),
                                }
                            }
                            Err(err) => self.error = format!("Invalid grant offer code: {err}"),
                        }
                    }
                }
            });
    }

    fn terminal_target_node(&self, id: &str, name: &str) -> NodeInfo {
        self.nodes
            .iter()
            .find(|n| n.id == id)
            .cloned()
            .unwrap_or_else(|| NodeInfo {
                id: id.to_string(),
                name: name.to_string(),
                hostname: String::new(),
                os: String::new(),
                arch: String::new(),
                version: String::new(),
                online: true,
                policy: NodePolicy::exec(),
                effective: NodePolicy::exec(),
                owner: String::new(),
                relation: String::new(),
                access: "exec".into(),
                has_display: None,
            })
    }

    fn terminal_tab(&mut self, ui: &mut egui::Ui, tab_id: TabId) {
        let font_missing = !super::fonts::report().loaded && !self.prefs.font_hint_dismissed;
        let mut do_restart = false;
        let mut do_close = false;
        let mut dismiss_font = false;
        let mut send_gen_resize: Option<(u64, u16, u16)> = None;
        let mut send_gen_write: Option<(u64, Vec<u8>)> = None;
        let ctx = ui.ctx().clone();
        let clip = ui.clip_rect();
        let mut page_rect: Option<egui::Rect> = None;

        if let Some(t) = self.terminal_by_id_mut(tab_id) {
            // Slim inline status strips only when starting, exited, error, notice, or font warning.
            if let Some(started) = t.open {
                if !t.got_output {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        let waited = started.elapsed().as_secs();
                        let msg = if waited >= 8 {
                            "The shell has not sent any output yet. Waiting for the node to open a session…"
                        } else {
                            "Starting shell…"
                        };
                        ui.label(theme::muted_text(msg));
                        ctx.request_repaint_after(Duration::from_millis(250));
                    });
                }
            } else if t.exited.is_some() || !t.alive || !t.error.is_empty() {
                if !t.error.is_empty() {
                    banner(ui, &t.error, true);
                }
                ui.horizontal_wrapped(|ui| {
                    let msg = if let Some(code) = t.exited {
                        format!("Shell exited ({code})")
                    } else if t.got_output {
                        "Shell session ended.".to_string()
                    } else {
                        "Shell session is not open.".to_string()
                    };
                    ui.label(theme::muted_text(msg));
                    let restart = ui.add(theme::secondary_button("Restart shell"));
                    if restart.has_focus() {
                        restart.surrender_focus();
                    }
                    if restart.clicked() {
                        do_restart = true;
                    }
                    let close = ui.add(theme::secondary_button("Close tab"));
                    if close.has_focus() {
                        close.surrender_focus();
                    }
                    if close.clicked() {
                        do_close = true;
                    }
                });
            }
            if !t.notice.is_empty() && t.exited.is_none() {
                banner(ui, &t.notice, false);
            }
            if font_missing {
                ui.horizontal_wrapped(|ui| {
                    ui.label(theme::muted_text(super::fonts::missing_font_hint()));
                    let dismiss = ui.add(theme::secondary_button("Dismiss"));
                    if dismiss.has_focus() {
                        dismiss.surrender_focus();
                    }
                    if dismiss.clicked() {
                        dismiss_font = true;
                    }
                });
            }

            let avail = egui::vec2(ui.available_width(), ui.available_height().max(120.0));
            let shown = ui.allocate_ui(avail, |ui| {
                ui.set_min_size(avail);
                t.emulator.show(ui)
            });
            page_rect = Some(shown.response.rect);
            let output = shown.inner;
            if let Some((rows, cols)) = output.resized {
                t.size = (rows, cols);
                send_gen_resize = Some((t.gen, rows, cols));
            }
            if let Some(chars) = output.osc52_copied_chars {
                t.notice = format!("Terminal copied {chars} chars to clipboard (OSC 52).");
            }
            if !output.writes.is_empty() {
                send_gen_write = Some((t.gen, output.writes));
            }
        }
        if let Some(rect) = page_rect {
            self.debug_layout.set_page_visible(rect, clip);
        }

        if dismiss_font {
            self.prefs.font_hint_dismissed = true;
            if !self.preview_ui {
                save_controller_prefs(&self.config_dir, &self.prefs);
            }
        }
        if !self.preview_ui {
            if let Some((gen, rows, cols)) = send_gen_resize {
                self.send(Cmd::PtyResizeGen { gen, rows, cols });
            }
            if let Some((gen, data)) = send_gen_write {
                self.send(Cmd::PtyWriteGen { gen, data });
            }
        }
        if do_restart {
            self.restart_terminal_tab(tab_id);
        } else if do_close {
            self.force_close_tab(Some(&ctx), tab_id);
        }
    }

    fn apply_file_nav_for(&mut self, tab_id: TabId, ctx: &egui::Context, nav: PendingFileNav) {
        let preview = self.preview_ui;
        match nav {
            PendingFileNav::OpenFile { node, path, size } => {
                if !preview {
                    self.send(Cmd::Read {
                        session: tab_id,
                        node,
                        path,
                        size_hint: size,
                    });
                }
            }
            PendingFileNav::OpenDir { node, path } => {
                if let Some(f) = self.files_by_id_mut(tab_id) {
                    f.editor = None;
                    f.loading = !preview;
                    f.path_input = path.clone();
                }
                if !preview {
                    self.send(Cmd::List {
                        session: tab_id,
                        node,
                        path,
                    });
                }
            }
            PendingFileNav::CloseEditor => {
                if let Some(f) = self.files_by_id_mut(tab_id) {
                    f.editor = None;
                }
            }
            PendingFileNav::CloseTab => {
                self.force_close_tab(Some(ctx), tab_id);
            }
        }
    }

    fn request_file_nav_for(&mut self, tab_id: TabId, ctx: &egui::Context, nav: PendingFileNav) {
        let is_dirty = self
            .files_by_id_mut(tab_id)
            .is_some_and(|f| f.editor.as_ref().is_some_and(Editor::is_dirty));
        if is_dirty {
            if let Some(f) = self.files_by_id_mut(tab_id) {
                f.pending_nav = Some(nav);
            }
        } else {
            self.apply_file_nav_for(tab_id, ctx, nav);
        }
    }

    fn files_tab(&mut self, ui: &mut egui::Ui, tab_id: TabId) {
        let Some((node_id, node_name, current_dir)) = self
            .tabs
            .iter()
            .find_map(|t| match t {
                Tab::Files(f) if f.id == tab_id => {
                    Some((f.node_id.clone(), f.node_name.clone(), f.dir.clone()))
                }
                _ => None,
            })
        else {
            return;
        };
        let policy = self
            .nodes
            .iter()
            .find(|node| node.id == node_id)
            .map(|node| node.effective);
        let can_write = policy.is_some_and(|policy| policy.allow_write);
        let can_read = policy.map_or(true, |policy| policy.allow_read);
        let ctx = ui.ctx().clone();
        let preview = self.preview_ui;

        let mut cmds: Vec<Cmd> = Vec::new();
        let mut pending_nav: Option<PendingFileNav> = None;
        let mut close_tab_requested = false;
        let mut del_confirmed: Option<String> = None;
        let mut modal_nav_confirm: Option<PendingFileNav> = None;

        // Drag-and-drop local files onto the Files tab to upload (`DESK-02`).
        if can_write && !preview {
            let dropped: Vec<std::path::PathBuf> = ctx.input(|i| {
                i.raw
                    .dropped_files
                    .iter()
                    .filter_map(|f| f.path.clone())
                    .collect()
            });
            for local_path in dropped {
                if let Some(fname) = local_path.file_name().and_then(|s| s.to_str()) {
                    let remote_path = model::child_path(&current_dir, fname);
                    cmds.push(Cmd::Upload {
                        session: tab_id,
                        node: node_id.clone(),
                        local_path,
                        remote_path,
                    });
                }
            }
        }

        let download_dir_str = &mut self.file_download_dir;
        let clip = ui.clip_rect();
        if let Some(f) = self.tabs.iter_mut().find_map(|t| match t {
            Tab::Files(f) if f.id == tab_id => Some(f),
            _ => None,
        }) {
            ui.horizontal_wrapped(|ui| {
                ui.label(theme::section_text(format!("{node_name} · files")));
                if ui.add(theme::secondary_button("Close tab")).clicked() {
                    close_tab_requested = true;
                }
            });
            if !f.error.is_empty() {
                banner(ui, &f.error, true);
            }
            if !f.notice.is_empty() {
                banner(ui, &f.notice, false);
            }

            // Editable path bar + navigation buttons (`DESK-02`).
            ui.horizontal_wrapped(|ui| {
                if ui.add(theme::secondary_button("Up")).clicked() {
                    let path = model::parent_path(&f.dir);
                    pending_nav = Some(PendingFileNav::OpenDir {
                        node: node_id.clone(),
                        path,
                    });
                }
                if ui.add(theme::secondary_button("Refresh")).clicked() {
                    if !preview {
                        f.loading = true;
                        cmds.push(Cmd::List {
                            session: tab_id,
                            node: node_id.clone(),
                            path: f.dir.clone(),
                        });
                    }
                }
                let path_edit = ui.add(
                    egui::TextEdit::singleline(&mut f.path_input)
                        .font(egui::TextStyle::Monospace)
                        .desired_width((ui.available_width() - 60.0).clamp(120.0, 380.0)),
                );
                let go_enter =
                    path_edit.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if go_enter || ui.add(theme::secondary_button("Go")).clicked() {
                    let target = f.path_input.trim();
                    let target = if target.is_empty() { "." } else { target };
                    pending_nav = Some(PendingFileNav::OpenDir {
                        node: node_id.clone(),
                        path: target.to_string(),
                    });
                }
            });

            // Clickable path breadcrumbs (`DESK-02`).
            {
                let cur = f.dir.clone();
                let sep = if cur.contains('\\') && !cur.contains('/') {
                    '\\'
                } else {
                    '/'
                };
                let parts: Vec<&str> = cur
                    .split(sep)
                    .filter(|p| !p.is_empty() && *p != ".")
                    .collect();
                if !parts.is_empty() {
                    ui.horizontal_wrapped(|ui| {
                        if ui.small_button(".").clicked() {
                            pending_nav = Some(PendingFileNav::OpenDir {
                                node: node_id.clone(),
                                path: ".".into(),
                            });
                        }
                        let mut acc = if cur.starts_with(sep) {
                            sep.to_string()
                        } else {
                            String::new()
                        };
                        for (idx, part) in parts.iter().enumerate() {
                            ui.label(theme::muted_text("/"));
                            if idx > 0 || (!acc.is_empty() && !acc.ends_with(sep)) {
                                if !acc.ends_with(sep) && !acc.is_empty() {
                                    acc.push(sep);
                                }
                            }
                            acc.push_str(part);
                            let target = acc.clone();
                            if ui.small_button(*part).clicked() {
                                pending_nav = Some(PendingFileNav::OpenDir {
                                    node: node_id.clone(),
                                    path: target,
                                });
                            }
                        }
                    });
                }
            }

            if f.loading {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(theme::muted_text("Loading files…"));
                });
            } else if f.entries.is_empty() && f.error.is_empty() {
                ui.label(theme::muted_text("This folder is empty."));
            }
            let has_editor = f.editor.is_some();
            let list_h = if has_editor {
                (ui.available_height() * 0.34).clamp(110.0, 240.0)
            } else {
                (ui.available_height() - 120.0).max(160.0)
            };
            let list = egui::ScrollArea::vertical()
                .id_salt(("files-list-scroll", tab_id))
                .max_height(list_h)
                .show(ui, |ui| {
                    let mut entries = f.entries.clone();
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
                                format!("{}  ({} B)", entry.name, entry.size)
                            };
                            if ui.add(theme::secondary_button(&label)).clicked() {
                                let path = model::child_path(&f.dir, &entry.name);
                                if entry.is_dir {
                                    pending_nav = Some(PendingFileNav::OpenDir {
                                        node: node_id.clone(),
                                        path,
                                    });
                                } else {
                                    pending_nav = Some(PendingFileNav::OpenFile {
                                        node: node_id.clone(),
                                        path,
                                        size: Some(entry.size),
                                    });
                                }
                            }
                            if !entry.is_dir
                                && can_read
                                && ui.add(theme::secondary_button("Download")).clicked()
                                && !preview
                            {
                                let remote_path = model::child_path(&f.dir, &entry.name);
                                let dir = download_dir_str.trim();
                                let local_dir = if dir.is_empty() {
                                    std::path::PathBuf::from(".")
                                } else {
                                    std::path::PathBuf::from(dir)
                                };
                                let local_path = local_dir.join(&entry.name);
                                cmds.push(Cmd::Download {
                                    session: tab_id,
                                    node: node_id.clone(),
                                    remote_path,
                                    local_path,
                                });
                            }
                            if can_write && ui.add(theme::secondary_button("Delete")).clicked() {
                                let path = model::child_path(&f.dir, &entry.name);
                                f.pending_delete = Some(path);
                            }
                        });
                    }
                });
            let mut page = visible_rect(list.inner_rect, clip);
            if can_write {
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut f.folder_name)
                            .hint_text("New folder name")
                            .desired_width(150.0),
                    );
                    if ui.add(theme::secondary_button("Create folder")).clicked()
                        && !f.folder_name.trim().is_empty()
                        && !preview
                    {
                        let path = model::child_path(&f.dir, f.folder_name.trim());
                        f.folder_name.clear();
                        cmds.push(Cmd::Mkdir {
                            session: tab_id,
                            node: node_id.clone(),
                            path,
                        });
                    }
                    ui.add(
                        egui::TextEdit::singleline(&mut f.new_file_name)
                            .hint_text("New file name")
                            .desired_width(150.0),
                    );
                    if ui.add(theme::secondary_button("New file")).clicked()
                        && !f.new_file_name.trim().is_empty()
                    {
                        let path = model::child_path(&f.dir, f.new_file_name.trim());
                        f.new_file_name.clear();
                        f.editor = Some(Editor::editable(path, String::new()));
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut f.upload_local)
                            .hint_text("Local file path to upload (or drag-and-drop file here)")
                            .desired_width(260.0),
                    );
                    if ui.add(theme::secondary_button("Upload")).clicked()
                        && !f.upload_local.trim().is_empty()
                        && !preview
                    {
                        let local_path = std::path::PathBuf::from(f.upload_local.trim());
                        match local_path.file_name().and_then(|s| s.to_str()) {
                            Some(fname) => {
                                let remote_path = model::child_path(&f.dir, fname);
                                f.upload_local.clear();
                                cmds.push(Cmd::Upload {
                                    session: tab_id,
                                    node: node_id.clone(),
                                    local_path,
                                    remote_path,
                                });
                            }
                            None => f.error = "Enter a valid local file path to upload.".into(),
                        }
                    }
                    if can_read {
                        ui.label(theme::muted_text("Save downloads to:"));
                        ui.add(
                            egui::TextEdit::singleline(download_dir_str).desired_width(180.0),
                        );
                    }
                });
            } else if can_read {
                ui.horizontal_wrapped(|ui| {
                    ui.label(theme::muted_text("Save downloads to:"));
                    ui.add(
                        egui::TextEdit::singleline(download_dir_str).desired_width(220.0),
                    );
                });
            }

            // Scrollable multiline editor with sticky Save / Download / Close bar (`DESK-02`).
            if let Some(editor) = &mut f.editor {
                let dirty = editor.is_dirty();
                let ro = editor.read_only;
                let header = if ro {
                    format!("{} (read-only)", editor.path)
                } else if dirty {
                    format!("{} (unsaved changes)", editor.path)
                } else {
                    editor.path.clone()
                };
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    ui.label(egui::RichText::new(header).strong().color(theme::TEXT_PRIMARY));
                    if can_write && !ro {
                        if ui
                            .add_enabled(
                                dirty || editor.saved_text.is_empty(),
                                theme::primary_button("Save"),
                            )
                            .clicked()
                            && !preview
                        {
                            cmds.push(Cmd::Write {
                                session: tab_id,
                                node: node_id.clone(),
                                path: editor.path.clone(),
                                text: editor.text.clone(),
                            });
                        }
                    }
                    if can_read
                        && ui.add(theme::secondary_button("Download")).clicked()
                        && !preview
                    {
                        let remote_path = editor.path.clone();
                        let fname = remote_path
                            .rsplit(['/', '\\'])
                            .next()
                            .unwrap_or("download.bin")
                            .to_string();
                        let dir = download_dir_str.trim();
                        let local_dir = if dir.is_empty() {
                            std::path::PathBuf::from(".")
                        } else {
                            std::path::PathBuf::from(dir)
                        };
                        cmds.push(Cmd::Download {
                            session: tab_id,
                            node: node_id.clone(),
                            remote_path,
                            local_path: local_dir.join(fname),
                        });
                    }
                    if ui.add(theme::secondary_button("Close")).clicked() {
                        pending_nav = Some(PendingFileNav::CloseEditor);
                    }
                });
                if let Some(reason) = &editor.read_only_reason {
                    banner(ui, reason, true);
                }
                let editor_h = ui.available_height().max(120.0);
                let scroll = egui::ScrollArea::vertical()
                    .id_salt(("file-editor-scroll", tab_id))
                    .max_height(editor_h)
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        let edit = ui.add(
                            egui::TextEdit::multiline(&mut editor.text)
                                .interactive(!ro && can_write)
                                .desired_width(f32::INFINITY)
                                .desired_rows(12)
                                .font(egui::TextStyle::Monospace),
                        );
                        self.debug_layout
                            .note_visible("editor", edit.rect, ui.clip_rect());
                        edit
                    });
                page = page.union(visible_rect(scroll.inner_rect, clip));
            }
            self.debug_layout.page_rect = rect_xywh(page);

            // Delete confirmation modal (`DESK-02`).
            if let Some(del_path) = f.pending_delete.clone() {
                let mut open = true;
                let mut confirm = false;
                let mut cancel = false;
                egui::Window::new("Confirm delete")
                    .collapsible(false)
                    .resizable(false)
                    .open(&mut open)
                    .show(&ctx, |ui| {
                        ui.label(format!("Permanently delete `{del_path}`?"));
                        ui.label(theme::muted_text("This cannot be undone."));
                        ui.add_space(theme::SPACE_SM);
                        ui.horizontal(|ui| {
                            if ui.add(theme::primary_button("Delete permanently")).clicked() {
                                confirm = true;
                            }
                            if ui.add(theme::secondary_button("Cancel")).clicked() {
                                cancel = true;
                            }
                        });
                    });
                if confirm {
                    f.pending_delete = None;
                    f.clear_editor_if_deleted(&del_path);
                    del_confirmed = Some(del_path);
                } else if cancel || !open {
                    f.pending_delete = None;
                }
            }

            // Unsaved-changes guard modal (`DESK-02`).
            if let Some(nav) = f.pending_nav.clone() {
                let mut open = true;
                let mut discard = false;
                let mut cancel = false;
                egui::Window::new("Unsaved changes")
                    .collapsible(false)
                    .resizable(false)
                    .open(&mut open)
                    .show(&ctx, |ui| {
                        ui.label("You have unsaved edits in the open file.");
                        ui.add_space(theme::SPACE_SM);
                        ui.horizontal(|ui| {
                            if ui.add(theme::primary_button("Discard changes")).clicked() {
                                discard = true;
                            }
                            if ui.add(theme::secondary_button("Keep editing")).clicked() {
                                cancel = true;
                            }
                        });
                    });
                if discard {
                    f.pending_nav = None;
                    modal_nav_confirm = Some(nav);
                } else if cancel || !open {
                    f.pending_nav = None;
                }
            }
        }

        if let Some(del_path) = del_confirmed {
            if !preview {
                self.send(Cmd::Remove {
                    session: tab_id,
                    node: node_id.clone(),
                    path: del_path,
                });
            }
        }
        for cmd in cmds {
            self.send(cmd);
        }
        if close_tab_requested {
            self.request_close_tab(Some(&ctx), tab_id);
        }
        if let Some(nav) = pending_nav {
            self.request_file_nav_for(tab_id, &ctx, nav);
        }
        if let Some(nav) = modal_nav_confirm {
            self.apply_file_nav_for(tab_id, &ctx, nav);
        }
    }

    fn desktop_tab(&mut self, ui: &mut egui::Ui, tab_id: TabId, chrome_visible: bool) {
        let Some((node_id, node_name, control, phase, send_menu, stats_open, bar_avail)) =
            self.desktop_by_id_mut(tab_id).map(|d| {
                let d_phase = d.phase();
                (
                    d.node_id.clone(),
                    d.node_name.clone(),
                    d.control,
                    d_phase,
                    d.send_menu,
                    d.stats_open,
                    ui.available_size(),
                )
            })
        else {
            return;
        };

        let bar_fade = ui.ctx().animate_bool(
            egui::Id::new(("desktop-connection-bar-fade", tab_id)),
            chrome_visible,
        );
        let showing_bar = bar_fade > 0.01;
        let pane_avail_for_1to1 = egui::vec2(
            bar_avail.x,
            (bar_avail.y - if showing_bar { BAR_HEIGHT } else { 0.0 }).max(1.0),
        );
        self.debug_layout.toolbar_visible = chrome_visible || showing_bar;
        if showing_bar {
            let bar_resp = egui::Frame::new()
                .fill(theme::BG_PANEL)
                .inner_margin(egui::Margin::symmetric(theme::SPACE_SM as i8, 0))
                .show(ui, |ui| {
                    ui.set_opacity(bar_fade);
                    ui.set_min_height(BAR_HEIGHT);
                    ui.set_max_height(BAR_HEIGHT);
                    self.desktop_connection_bar(
                        ui,
                        tab_id,
                        &node_id,
                        &node_name,
                        control,
                        phase,
                        pane_avail_for_1to1,
                    );
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
                        tab_id,
                        &node_name,
                        pane_rect,
                        phase == SessionPhase::Failed,
                    );
                }
                SessionPhase::Connecting => {
                    self.desktop_connecting_overlay(ui, &node_name, pane_rect);
                }
                SessionPhase::Live | SessionPhase::Stale => {
                    self.desktop_canvas(ui, tab_id, &node_id, control, pane_rect);
                    if phase == SessionPhase::Stale {
                        self.desktop_stale_toast(ui, tab_id, pane_rect);
                    }
                }
            }
            if stats_open {
                self.desktop_stats_popover(ui, tab_id, pane_rect);
            }
            self.desktop_draw_toast(ui, tab_id, pane_rect);
        });
        if send_menu {
            self.remote_send_popup(ui.ctx(), tab_id, &node_id, control);
        }
    }

    fn remote_send_popup(
        &mut self,
        ctx: &egui::Context,
        tab_id: TabId,
        node_id: &str,
        control: bool,
    ) {
        let Some((mut open, input_blocked)) = self
            .desktop_by_id_mut(tab_id)
            .map(|d| (d.send_menu, d.input_blocked))
        else {
            return;
        };
        let mut close = false;
        let mut send_chord: Option<&'static [&'static str]> = None;
        let mut toast_msg: Option<String> = None;
        egui::Window::new("Send to remote")
            .id(egui::Id::new(("remote-send-popup", tab_id)))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.set_min_width(280.0);
                if !control || input_blocked {
                    ui.label(theme::muted_text(
                        "View only — keyboard shortcuts stay on this computer.",
                    ));
                } else {
                    ui.label(theme::muted_text(
                        "These chords are injected on the remote machine. The local OS may swallow the physical keys.",
                    ));
                    for chord in super::desk_keys::explicit_remote_chords() {
                        if ui.button(chord.label).clicked() {
                            send_chord = Some(chord.keys);
                            toast_msg = Some(chord.limit.to_string());
                            close = true;
                        }
                        ui.label(theme::muted_text(chord.limit));
                    }
                }
                ui.add_space(theme::SPACE_SM);
                ui.label(
                    egui::RichText::new(super::desk_keys::SECURE_ATTENTION_NOTE)
                        .size(theme::SECONDARY_SIZE)
                        .color(theme::TEXT_MUTED),
                );
            });
        if let Some(keys) = send_chord {
            let allowed = control && !input_blocked;
            send_keys_tap_cmd(&self.tx, tab_id, node_id, allowed, keys);
        }
        if let Some(d) = self.desktop_by_id_mut(tab_id) {
            d.send_menu = open && !close;
            if let Some(msg) = toast_msg {
                d.toast = Some((msg, Instant::now()));
            }
        }
    }

    fn desktop_connection_bar(
        &mut self,
        ui: &mut egui::Ui,
        tab_id: TabId,
        id: &str,
        name: &str,
        control: bool,
        phase: SessionPhase,
        pane_avail: egui::Vec2,
    ) {
        let mut restart = false;
        let mut disconnect = false;
        let mut fit = false;
        let mut one_to_one = false;
        let mut toggle_fs = false;
        let mut toggle_keys = false;
        let mut toggle_mode = false;
        let mut clip_sync_changed: Option<bool> = None;
        let mut paste = false;
        let mut shot = false;
        let mut cad = false;
        let can_control_policy = self
            .nodes
            .iter()
            .find(|n| n.id == id)
            .is_some_and(|n| n.effective.allows_remote_control());
        let global_err = self.error.clone();
        let allow_clipboard_sync = &mut self.prefs.desk_clipboard_sync;
        let preview_ui = self.preview_ui;
        let config_dir = &self.config_dir;
        let debug_layout = &mut self.debug_layout;
        let ctx = ui.ctx().clone();

        let Some(d) = self.tabs.iter_mut().find_map(|t| match t {
            Tab::Desktop(d) if d.id == tab_id => Some(d),
            _ => None,
        }) else {
            return;
        };

        ui.spacing_mut().item_spacing = egui::vec2(theme::SPACE_XS, 0.0);
        ui.spacing_mut().button_padding = egui::vec2(theme::SPACE_SM, 0.0);
        ui.spacing_mut().interact_size.y = theme::BTN_TOOLBAR_H;

        let monitor_label = d
            .monitors
            .iter()
            .find(|m| m.index == d.monitor)
            .map(|m| {
                if m.primary {
                    format!("{} · primary", m.name)
                } else {
                    format!("{} · {}", m.name, m.index)
                }
            })
            .unwrap_or_else(|| format!("Monitor {}", d.monitor));
        let resolution = if d.hud.width > 0 && d.hud.height > 0 {
            Some(format!("{}×{}", d.hud.width, d.hud.height))
        } else {
            None
        };
        let stats = stats_chip(d.hud.fps, d.hud.latency_ms);
        let zoom_label = format!("{:.0}%", d.zoom * 100.0);
        let fs_label = if d.fullscreen { "Exit" } else { "Full" };
        let tip = if !d.disconnect_reason.is_empty() {
            d.disconnect_reason.as_str()
        } else if !global_err.is_empty() {
            global_err.as_str()
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
            has_cad: true,
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

                    ui.label(
                        egui::RichText::new(name)
                            .color(theme::TEXT_PRIMARY)
                            .size(theme::SECONDARY_SIZE),
                    );
                    status_dot(ui, phase.dot(), tip);

                    if density != BarDensity::Minimal {
                        let mode_badge = mode_badge_widget(ui, control, can_control_policy);
                        debug_layout.note_item("mode", mode_badge.rect);
                        if can_control_policy && mode_badge.clicked() {
                            toggle_mode = true;
                        }
                        chrome_vsep(ui);
                    }

                    let monitor_w = match density {
                        BarDensity::Minimal => 110.0,
                        BarDensity::Icons => 120.0,
                        _ => 140.0,
                    };
                    let monitor_resp = egui::ComboBox::from_id_salt(("desk-monitor", tab_id))
                        .selected_text(theme::bar_text(monitor_label.clone()))
                        .height(theme::BTN_TOOLBAR_H)
                        .width(monitor_w)
                        .show_ui(ui, |ui| {
                            if d.monitors.is_empty() {
                                ui.label(theme::muted_text("No monitors listed yet"));
                            }
                            for monitor in d.monitors.clone() {
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
                                    .selectable_value(&mut d.monitor, monitor.index, label)
                                    .changed()
                                {
                                    restart = true;
                                }
                            }
                        });
                    debug_layout.note_item("monitor", monitor_resp.response.rect);

                    match density {
                        BarDensity::Full | BarDensity::Compact => {
                            if let Some(res) = resolution.as_ref() {
                                ui.label(theme::mono_bar_text(res.clone()));
                            }
                            if let Some(stats) = stats.as_ref() {
                                let stats_btn = ui.add(
                                    egui::Button::new(theme::mono_bar_text(stats.clone()))
                                        .fill(if d.stats_open {
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
                                debug_layout.note_item("stats", stats_btn.rect);
                                if stats_btn.on_hover_text("Session stats").clicked() {
                                    d.stats_open = !d.stats_open;
                                }
                            }
                        }
                        BarDensity::Icons => {
                            if let Some(merged) = stats_line(
                                d.hud.width,
                                d.hud.height,
                                d.hud.fps,
                                d.hud.latency_ms,
                            ) {
                                let stats_btn = ui.add(
                                    egui::Button::new(theme::mono_bar_text(merged))
                                        .fill(if d.stats_open {
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
                                debug_layout.note_item("stats", stats_btn.rect);
                                if stats_btn.on_hover_text("Session stats").clicked() {
                                    d.stats_open = !d.stats_open;
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
                    debug_layout.note_item("disconnect", disconnect_btn.rect);
                    if disconnect_btn.clicked() {
                        disconnect = true;
                    }
                    if density == BarDensity::Minimal {
                        let fs_btn = chrome_bar_button(ui, fs_text, fs_tip, false);
                        debug_layout.note_item("fullscreen", fs_btn.rect);
                        if fs_btn.clicked() {
                            toggle_fs = true;
                        }
                        return;
                    }
                    ui.add_space(theme::SPACE_XS);
                    chrome_vsep(ui);
                    let send_btn = chrome_bar_button(
                        ui,
                        "Send",
                        "Send a chord the local OS may swallow. Ctrl+Alt+Del cannot be injected.",
                        d.send_menu,
                    );
                    debug_layout.note_item("send_remote", send_btn.rect);
                    if send_btn.clicked() {
                        cad = true;
                    }
                    let (shot_l, clip_l, key_l) = match density {
                        BarDensity::Icons => ("Sc", "Cb", "Kb"),
                        _ => ("Shot", "Clip", "Keys"),
                    };
                    let shot_btn = chrome_bar_button(ui, shot_l, "Save a remote screenshot", false);
                    debug_layout.note_item("shot", shot_btn.rect);
                    if shot_btn.clicked() {
                        shot = true;
                    }
                    let clip_tip = if !control {
                        "Clipboard sharing needs a control session, not view-only."
                    } else if *allow_clipboard_sync {
                        "Auto-sync clipboard is ON (toggle in Zoom/Stream menu). Click to send current local text now."
                    } else {
                        "Auto-sync clipboard is OFF (toggle in Zoom/Stream menu). Click to send current local text now."
                    };
                    let clip_btn = ui.add_enabled(
                        control,
                        theme::icon_button(clip_l, *allow_clipboard_sync),
                    );
                    let clip_btn = clip_btn.on_hover_text(clip_tip);
                    debug_layout.note_item("clipboard", clip_btn.rect);
                    if clip_btn.clicked() {
                        paste = true;
                    }
                    let key_tip = if d.capture_keys {
                        "Keyboard captured — Ctrl+Alt+Shift or Keys releases (Esc goes to remote)"
                    } else {
                        "Capture keyboard for the remote session"
                    };
                    let key = ui.add_enabled(
                        control,
                        theme::icon_button(key_l, d.capture_keys).stroke(if d.capture_keys {
                            egui::Stroke::new(1.0_f32, theme::SUCCESS)
                        } else {
                            egui::Stroke::NONE
                        }),
                    );
                    debug_layout.note_item("keyboard", key.rect);
                    if d.capture_keys {
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
                    debug_layout.note_item("fullscreen", fs_btn.rect);
                    if fs_btn.clicked() {
                        toggle_fs = true;
                    }
                    match density {
                        BarDensity::Full => {
                            let zoom_btn = chrome_bar_button(
                                ui,
                                &zoom_label,
                                "Zoom, stream scale/quality, mode & clipboard sync",
                                false,
                            );
                            let zoom_popup = ui.make_persistent_id(("desk-zoom-popup", tab_id));
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
                                        ui.set_min_width(220.0);
                                        ui.label(theme::muted_text("Zoom"));
                                        let slider = ui.add(
                                            egui::Slider::new(&mut d.zoom, 0.25..=4.0)
                                                .show_value(true)
                                                .min_decimals(2)
                                                .max_decimals(2),
                                        );
                                        if slider.changed() {
                                            d.fit = false;
                                        }
                                        ui.separator();
                                        ui.label(theme::muted_text("Stream scale"));
                                        ui.horizontal_wrapped(|ui| {
                                            for mode in [
                                                DeskScaleMode::Auto,
                                                DeskScaleMode::Native100,
                                                DeskScaleMode::Scale75,
                                                DeskScaleMode::Scale50,
                                            ] {
                                                if ui
                                                    .selectable_value(
                                                        &mut d.scale_mode,
                                                        mode,
                                                        mode.label(),
                                                    )
                                                    .changed()
                                                {
                                                    restart = true;
                                                }
                                            }
                                        });
                                        ui.label(theme::muted_text("Quality / FPS"));
                                        ui.horizontal_wrapped(|ui| {
                                            for (lbl, q) in [
                                                ("Low", 30u32),
                                                ("Med", 55),
                                                ("High", 75),
                                                ("Ultra", 90),
                                            ] {
                                                if ui
                                                    .selectable_value(&mut d.quality, q, lbl)
                                                    .changed()
                                                {
                                                    restart = true;
                                                }
                                            }
                                        });
                                        ui.horizontal_wrapped(|ui| {
                                            for fps in [15u32, 30, 60] {
                                                if ui
                                                    .selectable_value(
                                                        &mut d.max_fps,
                                                        fps,
                                                        format!("{fps} fps"),
                                                    )
                                                    .changed()
                                                {
                                                    restart = true;
                                                }
                                            }
                                        });
                                        ui.separator();
                                        if can_control_policy {
                                            let mode_lbl = if control {
                                                "Switch to View only"
                                            } else {
                                                "Switch to Control"
                                            };
                                            if ui.add(theme::secondary_button(mode_lbl)).clicked() {
                                                toggle_mode = true;
                                            }
                                        }
                                        if control {
                                            let mut sync_on = *allow_clipboard_sync;
                                            if ui
                                                .checkbox(&mut sync_on, "Auto-sync clipboard")
                                                .changed()
                                            {
                                                *allow_clipboard_sync = sync_on;
                                                clip_sync_changed = Some(sync_on);
                                            }
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
                    debug_layout.note_item("fit", fit_btn.rect);
                    if fit_btn.clicked() {
                        fit = true;
                    }
                },
            );
        });

        let selected_monitor = d.monitor;
        if fit {
            d.fit = true;
            d.zoom = 1.0;
            d.pan = egui::Vec2::ZERO;
        }
        if one_to_one {
            d.fit = false;
            if let Some(texture) = &d.texture {
                d.zoom = native_zoom_for_dpi(texture.size_vec2(), pane_avail, ctx.pixels_per_point());
            } else {
                d.zoom = 1.0;
            }
            d.pan = egui::Vec2::ZERO;
        }
        if toggle_fs {
            d.fullscreen = !d.fullscreen;
            ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(d.fullscreen));
            d.ui_pointer = Instant::now();
        }
        if paste {
            // Bounded 4-frame window so empty/non-text clipboards never stay
            // latched waiting for `Event::Paste` (`DESK-12`).
            d.await_paste_frames = 4;
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
        }
        if cad {
            d.send_menu = !d.send_menu;
        }
        let d_fullscreen_now = d.fullscreen;
        let d_capture_now = d.capture_keys;

        if disconnect {
            if d_fullscreen_now {
                ctx.send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                if let Some(d) = self.desktop_by_id_mut(tab_id) {
                    d.fullscreen = false;
                }
            }
            self.stop_desktop_tab_session(tab_id, "Disconnected");
            return;
        }
        if let Some(enabled) = clip_sync_changed {
            if !preview_ui {
                save_controller_prefs(config_dir, &self.prefs);
                self.send(Cmd::ClipboardSync { enabled });
            }
        }
        if toggle_mode && can_control_policy {
            let next_control = !control;
            self.control.insert(id.to_string(), next_control);
            if let Some(d) = self.desktop_by_id_mut(tab_id) {
                d.control = next_control;
                if !next_control {
                    d.capture_keys = false;
                }
            }
            if !next_control {
                self.release_desktop_tab_input(tab_id);
            }
            restart = true;
        }
        if toggle_keys {
            if d_capture_now {
                self.release_desktop_tab_input(tab_id);
            } else if let Some(d) = self.desktop_by_id_mut(tab_id) {
                d.capture_keys = true;
            }
        }
        if shot && !self.preview_ui {
            let path = default_shot_path();
            self.send(Cmd::Shot {
                session: tab_id,
                node: id.to_string(),
                path,
                monitor: Some(selected_monitor),
            });
        }
        if restart {
            self.restart_live(tab_id);
        }
    }

    fn desktop_canvas(
        &mut self,
        ui: &mut egui::Ui,
        tab_id: TabId,
        id: &str,
        control: bool,
        pane_rect: egui::Rect,
    ) {
        let target_os = self
            .nodes
            .iter()
            .find(|n| n.id == id)
            .map(|n| super::desk_keys::TargetOs::from_node_os(&n.os))
            .unwrap_or_default();
        let preview_ui = self.preview_ui;
        let tx = &self.tx;
        let shared = &self.shared;
        let debug_layout = &mut self.debug_layout;
        let Some(d) = self.tabs.iter_mut().find_map(|t| match t {
            Tab::Desktop(d) if d.id == tab_id => Some(d),
            _ => None,
        }) else {
            return;
        };

        let Some(texture) = d.texture.clone() else {
            return;
        };
        let image_size = texture.size_vec2();
        if d.fit {
            d.zoom = 1.0;
            d.pan = egui::Vec2::ZERO;
        }
        let full = viewport_rect(image_size, pane_rect, d.zoom, d.pan);
        let encode_w = image_size.x.round().max(1.0) as u32;
        let encode_h = image_size.y.round().max(1.0) as u32;
        let src_w = if d.hud.src_width > 0 {
            d.hud.src_width
        } else {
            encode_w
        };
        let src_h = if d.hud.src_height > 0 {
            d.hud.src_height
        } else {
            encode_h
        };
        // Crop macroblock encode pad (e.g. 11 rows under 853→864) out of both
        // the painted UV and the interactive content rect.
        let content = content_rect_excluding_pad(full, src_w, src_h, encode_w, encode_h);
        let uv = content_uv_excluding_pad(src_w, src_h, encode_w, encode_h);
        debug_layout.content_rect = rect_xywh(content);
        let response = ui.allocate_rect(pane_rect, egui::Sense::click_and_drag());
        egui::Image::new(&texture)
            .uv(uv)
            .fit_to_exact_size(content.size())
            .paint_at(ui, content);

        // Local gestures (Ctrl+wheel zoom, Shift/middle pan, capture-pill click,
        // and Ctrl+Alt+Shift ungrab chord) are consumed BEFORE `desktop_input()`
        // so they never double-fire on the remote desktop (`DESK-12`).
        let mut consumed_local_pointer = false;
        let mut ungrabbed_now = false;
        if response.hovered() {
            let (zoom_delta, scroll, ctrl) = ui.ctx().input(|input| {
                (
                    input.zoom_delta(),
                    input.raw_scroll_delta,
                    input.modifiers.ctrl || input.modifiers.command,
                )
            });
            if ctrl && (zoom_delta - 1.0).abs() > 0.001 {
                d.fit = false;
                d.zoom = (d.zoom * zoom_delta).clamp(0.25, 8.0);
                ui.ctx().input_mut(|input| {
                    input.events.retain(|ev| {
                        !matches!(
                            ev,
                            egui::Event::MouseWheel { modifiers, .. }
                                if modifiers.ctrl || modifiers.command
                        )
                    });
                });
            } else if ctrl && scroll.y.abs() > 0.1 {
                d.fit = false;
                let factor = if scroll.y > 0.0 { 1.1 } else { 1.0 / 1.1 };
                d.zoom = (d.zoom * factor).clamp(0.25, 8.0);
                ui.ctx().input_mut(|input| {
                    input.events.retain(|ev| {
                        !matches!(
                            ev,
                            egui::Event::MouseWheel { modifiers, .. }
                                if modifiers.ctrl || modifiers.command
                        )
                    });
                });
            }
        }
        let pan_gesture_active = ui.ctx().input(|i| {
            i.pointer.middle_down() || (i.modifiers.shift && i.pointer.primary_down())
        });
        if pan_gesture_active && (!control || !d.capture_keys) {
            consumed_local_pointer = true;
            if response.dragged() {
                d.fit = false;
                d.pan += response.drag_delta();
            }
        }

        // Pre-compute capture hint pill rect so clicking the pill consumes the
        // primary click before `desktop_input()` rather than clicking remotely (`DESK-12`).
        let pill_info = if !control || !d.capture_keys {
            let painter = ui.painter_at(pane_rect);
            let label = if !control || d.input_blocked {
                "View only — keyboard and mouse stay local"
            } else {
                "Click to capture keyboard · Ctrl+Alt+Shift or Keys releases"
            };
            let galley = painter.layout_no_wrap(
                label.to_string(),
                egui::FontId::proportional(theme::SECONDARY_SIZE),
                theme::TEXT_BODY,
            );
            let pad = egui::vec2(theme::SPACE_MD, theme::SPACE_SM);
            let size = galley.size() + pad * 2.0;
            let rect = egui::Rect::from_center_size(pane_rect.center(), size);
            Some((rect, pad, galley))
        } else {
            None
        };

        if control && !d.input_blocked && !d.capture_keys {
            if let Some((pill_rect, _, _)) = &pill_info {
                let primary_on_pill = ui.ctx().input(|input| {
                    input.events.iter().any(|ev| {
                        matches!(
                            ev,
                            egui::Event::PointerButton {
                                pos,
                                button: egui::PointerButton::Primary,
                                ..
                            } if pill_rect.contains(*pos)
                        )
                    })
                });
                if primary_on_pill {
                    consumed_local_pointer = true;
                    let pressed_on_pill = ui.ctx().input(|input| {
                        input.events.iter().any(|ev| {
                            matches!(
                                ev,
                                egui::Event::PointerButton {
                                    pos,
                                    button: egui::PointerButton::Primary,
                                    pressed: true,
                                    ..
                                } if pill_rect.contains(*pos)
                            )
                        })
                    });
                    if pressed_on_pill {
                        d.capture_keys = true;
                    }
                }
            }
        }

        // Explicit ungrab chord while captured: Ctrl+Alt+Shift (press+release
        // cleanly or Ctrl+Alt+Shift+Esc/U) releases keyboard capture (`DESK-12`).
        if control && d.capture_keys && !d.input_blocked {
            let (all_three, has_non_mod_key, immediate_ungrab) = ui.ctx().input(|input| {
                let m = input.modifiers;
                let all_three = m.ctrl && m.alt && m.shift;
                let mut any_key = false;
                let mut imm = false;
                for ev in &input.events {
                    if let egui::Event::Key {
                        key,
                        pressed: true,
                        modifiers,
                        ..
                    } = ev
                    {
                        any_key = true;
                        if modifiers.ctrl
                            && modifiers.alt
                            && modifiers.shift
                            && matches!(key, egui::Key::Escape | egui::Key::U)
                        {
                            imm = true;
                        }
                    }
                }
                (all_three, any_key, imm)
            });
            if immediate_ungrab {
                ungrabbed_now = true;
            } else if all_three && !has_non_mod_key {
                d.ungrab_armed = true;
            } else if has_non_mod_key {
                d.ungrab_armed = false;
            } else if d.ungrab_armed && !all_three {
                ungrabbed_now = true;
            }
            if ungrabbed_now {
                d.ungrab_armed = false;
                d.capture_keys = false;
                let (keys, buttons, x, y) = d.drain_release_events();
                let monitor = d.monitor;
                for key in keys {
                    send_key_edge_cmd(tx, tab_id, id, false, &key, false);
                }
                for button in buttons {
                    send_mouse_cmd(
                        tx,
                        shared,
                        tab_id,
                        id,
                        monitor,
                        false,
                        MouseEvent::new("up", x, y, button),
                        true,
                    );
                }
                d.toast = Some((
                    "Keyboard released (click canvas or Keys to capture)".into(),
                    Instant::now(),
                ));
                ui.ctx().input_mut(|input| {
                    input.events.retain(|ev| !egui_event_is_keyboard(ev));
                });
            }
        } else {
            d.ungrab_armed = false;
        }

        // Local session menu: toolbar always; letterbox / view-only pane OK.
        // Controllable image must NOT steal right-click — plain and Shift both
        // go remote so the node's context menu opens (t483). Hit-test the
        // visible clipped content (content ∩ pane ∩ ui clip), not the full
        // letterboxed rect that can extend under the toolbar when zoomed.
        let clip = ui.clip_rect();
        let visible = content.intersect(response.rect).intersect(clip);
        let over_image = ui.ctx().input(|i| {
            i.pointer
                .interact_pos()
                .or(i.pointer.hover_pos())
                .is_some_and(|pos| hit_content(visible, pos))
        });
        let allow_local_menu = !control || !over_image || response.context_menu_opened();
        let mut pending_menu_action: Option<DeskMenuAction> = None;
        if allow_local_menu {
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
                if control {
                    for chord in super::desk_keys::explicit_remote_chords() {
                        if item(ui, chord.label).clicked() {
                            pending_menu_action = Some(DeskMenuAction::SendChord(chord.keys));
                            ui.close_menu();
                        }
                    }
                }
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(super::desk_keys::SECURE_ATTENTION_NOTE)
                            .size(theme::SECONDARY_SIZE)
                            .color(theme::TEXT_MUTED),
                    )
                    .wrap(),
                );
                if item(
                    ui,
                    if d.fullscreen {
                        "Exit fullscreen"
                    } else {
                        "Toggle fullscreen"
                    },
                )
                .clicked()
                {
                    pending_menu_action = Some(DeskMenuAction::Fullscreen);
                    ui.close_menu();
                }
                if item(ui, "Fit to window").clicked() {
                    pending_menu_action = Some(DeskMenuAction::Fit);
                    ui.close_menu();
                }
                if item(ui, "1:1").clicked() {
                    pending_menu_action = Some(DeskMenuAction::OneToOne);
                    ui.close_menu();
                }
                if item(ui, "Release keyboard").clicked() {
                    pending_menu_action = Some(DeskMenuAction::ReleaseKeys);
                    ui.close_menu();
                }
                if item(ui, "Disconnect").clicked() {
                    pending_menu_action = Some(DeskMenuAction::Disconnect);
                    ui.close_menu();
                }
            });
        }

        if control && !d.input_blocked {
            // Ordered mouse (+ keys when captured) via STD input_policy reducer.
            // Plain / Shift / Ctrl right-click over the image all go remote;
            // toolbar / letterbox keep the local menu above.
            if !consumed_local_pointer && !ungrabbed_now {
                Self::desktop_input_on(d, tx, shared, target_os, ui, &response, content);
            }
            Self::apply_negotiated_cursor_on(d, shared, ui, over_image, content, src_w, src_h);
            if !d.capture_keys
                && !consumed_local_pointer
                && !ungrabbed_now
                && response.clicked_by(egui::PointerButton::Primary)
            {
                d.capture_keys = true;
            }
        } else if control {
            if over_image {
                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
            }
        } else {
            // View-only: leave the platform cursor alone (no overlay).
            if over_image {
                ui.ctx().set_cursor_icon(egui::CursorIcon::Default);
            }
        }

        // View-only: quiet centered pill. Control without capture: click hint pill.
        if !control || !d.capture_keys {
            if let Some((rect, pad, galley)) = pill_info {
                let painter = ui.painter_at(pane_rect);
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
        let _ = preview_ui;

        if let Some(action) = pending_menu_action {
            self.apply_desk_menu(ui, tab_id, id, action, pane_rect);
        }
    }

    fn desktop_stats_popover(&mut self, ui: &mut egui::Ui, tab_id: TabId, pane_rect: egui::Rect) {
        let Some((kind, encoder_name, hardware, path, path_note, handshake, fps, bitrate, latency, dropped, width, height)) =
            self.desktop_by_id_mut(tab_id).map(|d| {
                (
                    d.hud.kind.clone(),
                    d.hud.encoder.clone(),
                    d.hud.hardware,
                    d.hud.path.clone(),
                    d.hud.path_note.clone(),
                    d.hud.handshake.clone(),
                    d.hud.fps,
                    d.hud.bitrate_kbps,
                    d.hud.latency_ms,
                    d.hud.frames_dropped,
                    d.hud.width,
                    d.hud.height,
                )
            })
        else {
            return;
        };
        let size = egui::vec2(280.0, 256.0);
        let origin = egui::pos2(
            (pane_rect.center().x - size.x / 2.0).max(pane_rect.left() + theme::SPACE_SM),
            pane_rect.top() + theme::SPACE_MD,
        );
        let rect = egui::Rect::from_min_size(origin, size);
        let encoder = encoder_label(&kind, &encoder_name, hardware);
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
                let path = if path.is_empty() {
                    "unknown".to_string()
                } else {
                    path
                };
                let path_line = format!("{kind} · {path}");
                let hint = if path_note.is_empty() {
                    super::model::connection_path_hint(&kind, &path).to_string()
                } else {
                    path_note
                };
                let handshake = if handshake.is_empty() {
                    "idle".to_string()
                } else {
                    handshake
                };
                let lines = [
                    format!("path  {path_line}"),
                    format!("handshake  {handshake}"),
                    super::chrome::session_stats_rate_line(&kind, fps),
                    super::chrome::session_stats_bitrate_line(&kind, bitrate),
                    super::chrome::session_stats_latency_line(&kind, latency),
                    format!("encoder  {encoder}"),
                    format!("dropped  {dropped}"),
                    format!("resolution  {width}×{height}"),
                    hint,
                ];
                for line in lines {
                    ui.label(theme::mono_bar_text(line));
                }
            });
        });
        if close {
            if let Some(d) = self.desktop_by_id_mut(tab_id) {
                d.stats_open = false;
            }
        }
    }

    fn apply_desk_menu(
        &mut self,
        ui: &mut egui::Ui,
        tab_id: TabId,
        id: &str,
        action: DeskMenuAction,
        pane_rect: egui::Rect,
    ) {
        match action {
            DeskMenuAction::SendChord(keys) => {
                let allowed = self
                    .desktop_by_id_mut(tab_id)
                    .is_some_and(|d| d.control && !d.input_blocked);
                if allowed && !agentlink_desktop::is_secure_attention_sequence(keys) {
                    send_keys_tap_cmd(&self.tx, tab_id, id, true, keys);
                    if let Some(chord) = super::desk_keys::explicit_remote_chords()
                        .iter()
                        .find(|chord| chord.keys == keys)
                    {
                        if let Some(d) = self.desktop_by_id_mut(tab_id) {
                            d.toast = Some((chord.limit.to_string(), Instant::now()));
                        }
                    }
                }
            }
            DeskMenuAction::Fullscreen => {
                if let Some(d) = self.desktop_by_id_mut(tab_id) {
                    d.fullscreen = !d.fullscreen;
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Fullscreen(d.fullscreen));
                    d.ui_pointer = Instant::now();
                }
            }
            DeskMenuAction::Fit => {
                if let Some(d) = self.desktop_by_id_mut(tab_id) {
                    d.fit = true;
                    d.zoom = 1.0;
                    d.pan = egui::Vec2::ZERO;
                }
            }
            DeskMenuAction::OneToOne => {
                let ppp = ui.ctx().pixels_per_point();
                if let Some(d) = self.desktop_by_id_mut(tab_id) {
                    d.fit = false;
                    if let Some(texture) = &d.texture {
                        d.zoom = native_zoom_for_dpi(texture.size_vec2(), pane_rect.size(), ppp);
                    } else {
                        d.zoom = 1.0;
                    }
                    d.pan = egui::Vec2::ZERO;
                }
            }
            DeskMenuAction::ReleaseKeys => {
                self.release_desktop_tab_input(tab_id);
            }
            DeskMenuAction::Disconnect => {
                let was_fs = self
                    .desktop_by_id_mut(tab_id)
                    .is_some_and(|d| d.fullscreen);
                if was_fs {
                    ui.ctx()
                        .send_viewport_cmd(egui::ViewportCommand::Fullscreen(false));
                    if let Some(d) = self.desktop_by_id_mut(tab_id) {
                        d.fullscreen = false;
                    }
                }
                self.stop_desktop_tab_session(tab_id, "Disconnected");
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
        tab_id: TabId,
        name: &str,
        pane_rect: egui::Rect,
        failed: bool,
    ) {
        let title = if failed {
            format!("Could not reach {name}")
        } else {
            format!("Disconnected from {name}")
        };
        let reason_raw = self
            .desktop_by_id_mut(tab_id)
            .map(|d| d.disconnect_reason.clone())
            .unwrap_or_default();
        let reason = if reason_raw.is_empty() {
            if failed {
                "Connection failed".to_string()
            } else {
                String::new()
            }
        } else {
            reason_raw
        };
        let mut reconnect = false;
        let mut close_tab = false;
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
                                theme::secondary_button("Close tab"),
                            )
                            .clicked()
                        {
                            close_tab = true;
                        }
                    });
                });
            });
        });
        if reconnect {
            self.restart_live(tab_id);
        } else if close_tab {
            let ctx = ui.ctx().clone();
            self.force_close_tab(Some(&ctx), tab_id);
        }
    }

    fn desktop_stale_toast(&self, ui: &mut egui::Ui, tab_id: TabId, pane_rect: egui::Rect) {
        let painter = ui.painter_at(pane_rect);
        let anchor = egui::pos2(pane_rect.max.x - 12.0, pane_rect.min.y + 12.0);
        let line1 = "No frames for 3s";
        let disc = self
            .tabs
            .iter()
            .find_map(|t| match t {
                Tab::Desktop(d) if d.id == tab_id => Some(d.disconnect_reason.as_str()),
                _ => None,
            })
            .unwrap_or("");
        let line2 = if !disc.is_empty() {
            disc
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

    fn desktop_draw_toast(&self, ui: &mut egui::Ui, tab_id: TabId, pane_rect: egui::Rect) {
        let Some((text, at)) = self.tabs.iter().find_map(|t| match t {
            Tab::Desktop(d) if d.id == tab_id => d.toast.as_ref(),
            _ => None,
        }) else {
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

    /// Apply the negotiated cursor presentation over the remote image.
    ///
    /// - `metadata`: local sprite (stock egui icon or custom RGBA bitmap).
    /// - `legacy`: hide the OS cursor only when the node explicitly negotiated
    ///   legacy (embedded capture known). Missing/unknown presentation keeps
    ///   the pre-b7 OS cursor so the user cannot lose the only pointer.
    /// - custom/unknown stock without a bitmap falls back to Default — never
    ///   CursorIcon::None as a "success" for an unknown shape.
    fn apply_negotiated_cursor_on(
        d: &mut DesktopTab,
        shared: &Shared,
        ui: &mut egui::Ui,
        over_image: bool,
        content: egui::Rect,
        src_w: u32,
        src_h: u32,
    ) {
        if !over_image {
            return;
        }
        let presentation = d.hud.cursor_presentation.to_ascii_lowercase();
        if presentation != "metadata" {
            if presentation == "legacy" {
                // Negotiated embedded capture — avoid a second local arrow.
                ui.ctx().set_cursor_icon(egui::CursorIcon::None);
            }
            // else: unknown/empty (old node) — preserve OS cursor.
            return;
        }
        let remote = shared.latest_cursor_for(d.id);
        if !remote.visible {
            ui.ctx().set_cursor_icon(egui::CursorIcon::None);
            return;
        }
        if let (Some(rgba), w, h) = (
            remote.bitmap_rgba.as_ref(),
            remote.bitmap_w,
            remote.bitmap_h,
        ) {
            if w > 0 && h > 0 && rgba.len() >= (w as usize) * (h as usize) * 4 {
                // Paint a cached local sprite at the pointer scaled by the
                // content display/zoom ratio (`DESK-11`).
                ui.ctx().set_cursor_icon(egui::CursorIcon::None);
                let needs_upload = d
                    .cursor_tex
                    .as_ref()
                    .map(|(rev, _)| *rev != remote.rev)
                    .unwrap_or(true);
                if needs_upload {
                    let color_image = egui::ColorImage::from_rgba_unmultiplied(
                        [w as usize, h as usize],
                        &rgba[..(w as usize) * (h as usize) * 4],
                    );
                    if let Some((rev, tex)) = &mut d.cursor_tex {
                        tex.set(color_image, egui::TextureOptions::NEAREST);
                        *rev = remote.rev;
                    } else {
                        let tex = ui.ctx().load_texture(
                            format!("agentlink-remote-cursor-{}", d.id),
                            color_image,
                            egui::TextureOptions::NEAREST,
                        );
                        d.cursor_tex = Some((remote.rev, tex));
                    }
                }
                if let (Some((_, tex)), Some(pos)) =
                    (d.cursor_tex.as_ref(), ui.ctx().pointer_interact_pos())
                {
                    let scale_x = (content.width() / src_w.max(1) as f32).clamp(0.25, 4.0);
                    let scale_y = (content.height() / src_h.max(1) as f32).clamp(0.25, 4.0);
                    let draw_w = w as f32 * scale_x;
                    let draw_h = h as f32 * scale_y;
                    let origin = egui::pos2(
                        pos.x - remote.hotspot_x as f32 * scale_x,
                        pos.y - remote.hotspot_y as f32 * scale_y,
                    );
                    ui.painter().image(
                        tex.id(),
                        egui::Rect::from_min_size(origin, egui::vec2(draw_w, draw_h)),
                        egui::Rect::from_min_max(egui::pos2(0.0, 0.0), egui::pos2(1.0, 1.0)),
                        egui::Color32::WHITE,
                    );
                }
                return;
            }
        }
        ui.ctx().set_cursor_icon(stock_cursor_icon(&remote.shape));
    }

    /// Collect ordered egui raw events via the STD adapter, then inject.
    /// Mouse always runs in control mode; keys join when keyboard capture is on.
    fn desktop_input_on(
        d: &mut DesktopTab,
        tx: &UnboundedSender<Cmd>,
        shared: &Shared,
        target_os: super::desk_keys::TargetOs,
        ui: &mut egui::Ui,
        response: &egui::Response,
        content: egui::Rect,
    ) {
        use super::desk_keys::{self, Slot};
        use super::input_adapter::{
            adapt_frame, is_barrier_out, ContentGeom, FrameEvent, ModSnapshot, WheelUnit,
        };
        use super::input_policy::{Button, OutEvent};

        if d.capture_keys {
            ui.memory_mut(|mem| mem.request_focus(egui::Id::new(("desk-key-capture", d.id))));
            // Enable OS CJK/compose IME on Desktop canvas (`DESK-01`).
            if !d.ime_allowed {
                d.ime_allowed = true;
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::IMEAllowed(true));
            }
            let ime_anchor = ui
                .ctx()
                .pointer_hover_pos()
                .filter(|p| content.contains(*p))
                .unwrap_or_else(|| egui::pos2(content.min.x + 16.0, content.max.y - 32.0));
            ui.ctx().send_viewport_cmd(egui::ViewportCommand::IMERect(
                egui::Rect::from_min_size(ime_anchor, egui::vec2(2.0, 20.0)),
            ));
        } else if d.ime_allowed {
            d.ime_allowed = false;
            ui.ctx()
                .send_viewport_cmd(egui::ViewportCommand::IMEAllowed(false));
        }

        let capture_keys = d.capture_keys;
        let clip = ui.clip_rect();
        let geom = ContentGeom::intersect3(
            (content.min.x, content.min.y, content.max.x, content.max.y),
            (
                response.rect.min.x,
                response.rect.min.y,
                response.rect.max.x,
                response.rect.max.y,
            ),
            (clip.min.x, clip.min.y, clip.max.x, clip.max.y),
        );

        // On Windows/Linux, egui sets `m.command = m.ctrl`. Map `command` from
        // `m.mac_cmd` ONLY so Ctrl+<key> never injects Win/Super (`DESK-01`).
        let snap = |m: egui::Modifiers| ModSnapshot {
            ctrl: m.ctrl,
            alt: m.alt,
            shift: m.shift,
            command: m.mac_cmd,
        };

        let (slots, final_mods) = ui.ctx().input(|input| {
            let frame_mods = snap(input.modifiers);
            let mut slots: Vec<Slot> = Vec::new();
            for event in &input.events {
                match event {
                    egui::Event::PointerMoved(pos) => {
                        slots.push(Slot::Pointer(FrameEvent::PointerMoved {
                            x: pos.x,
                            y: pos.y,
                        }));
                    }
                    egui::Event::PointerButton {
                        pos,
                        button,
                        pressed,
                        modifiers,
                    } => {
                        let button = match button {
                            egui::PointerButton::Primary => Button::Left,
                            egui::PointerButton::Secondary => Button::Right,
                            egui::PointerButton::Middle => Button::Middle,
                            _ => continue,
                        };
                        slots.push(Slot::Pointer(FrameEvent::PointerButton {
                            x: pos.x,
                            y: pos.y,
                            button,
                            pressed: *pressed,
                            mods: snap(*modifiers),
                        }));
                    }
                    egui::Event::MouseWheel {
                        unit,
                        delta,
                        modifiers,
                    } => {
                        let unit = match unit {
                            egui::MouseWheelUnit::Point => WheelUnit::Point,
                            egui::MouseWheelUnit::Line => WheelUnit::Line,
                            egui::MouseWheelUnit::Page => WheelUnit::Page,
                        };
                        // Never attach final-frame hover here — the adapter
                        // uses the evolving pointer from earlier Move events
                        // (seeded from the previous frame). Passing hover
                        // would map Move A, wheel, Move B → wheel at B.
                        slots.push(Slot::Pointer(FrameEvent::MouseWheel {
                            x: None,
                            y: None,
                            delta_x: delta.x,
                            delta_y: delta.y,
                            unit,
                            mods: snap(*modifiers),
                        }));
                    }
                    egui::Event::PointerGone => {
                        slots.push(Slot::Pointer(FrameEvent::PointerGone));
                    }
                    other if capture_keys => {
                        if let Some(host) = host_key_from_egui(other, frame_mods, snap) {
                            slots.push(Slot::Key(host));
                        }
                    }
                    _ => {}
                }
            }
            (slots, frame_mods)
        });
        if capture_keys {
            // Keys belong to the remote session. Leave pointer events so the
            // picture and local chrome still see the mouse.
            ui.ctx().input_mut(|input| {
                input.events.retain(|event| !egui_event_is_keyboard(event));
            });
        }
        let events = desk_keys::interleave_with_state(
            true,
            capture_keys,
            target_os,
            &mut d.key_state,
            &slots,
            final_mods,
        );

        let out = adapt_frame(
            &mut d.adapter,
            geom,
            &events,
            Some(final_mods),
            capture_keys,
        );
        let allowed = d.control && !d.input_blocked;

        for ev in out {
            let barrier = is_barrier_out(&ev);
            match ev {
                OutEvent::Mouse {
                    action,
                    button,
                    x,
                    y,
                    dx,
                    dy,
                } => {
                    if action == "move" {
                        d.last_move = Instant::now();
                    }
                    let mut event = MouseEvent::new(action, x, y, button);
                    event.dx = dx;
                    event.dy = dy;
                    send_mouse_cmd(
                        tx,
                        shared,
                        d.id,
                        &d.node_id,
                        d.monitor,
                        allowed,
                        event,
                        barrier,
                    );
                }
                OutEvent::Key {
                    name,
                    pressed,
                    repeat,
                } => {
                    if pressed {
                        let fresh = d.held_keys.insert(name.clone());
                        if fresh || repeat {
                            send_key_edge_cmd(tx, d.id, &d.node_id, allowed, &name, true);
                        }
                    } else if d.held_keys.remove(&name) {
                        send_key_edge_cmd(tx, d.id, &d.node_id, allowed, &name, false);
                    }
                }
                OutEvent::Text { text } => {
                    send_text_cmd(tx, d.id, &d.node_id, allowed, &text);
                }
            }
        }
        ui.allocate_exact_size(
            egui::vec2(0.0, 0.0),
            egui::Sense::focusable_noninteractive(),
        );
    }

    fn release_keyboard_if_ungated(&mut self, ctx: &egui::Context) {
        let focused = ctx.input(|input| {
            let lost_event = input
                .events
                .iter()
                .any(|ev| matches!(ev, egui::Event::WindowFocused(false)));
            !lost_event && input.viewport().focused.unwrap_or(true)
        });
        let exiting = self.flags.quit.load(Ordering::Relaxed) || self.debug_quit;
        let Some((id, control, has_held)) = (match self.active_tab_ref() {
            Some(Tab::Desktop(d)) => Some((
                d.id,
                d.control && !d.input_blocked,
                d.capture_keys || !d.held_keys.is_empty(),
            )),
            _ => None,
        }) else {
            return;
        };
        let gate = super::desk_keys::HoldGate {
            on_desktop: true,
            control_granted: control,
            viewport_focused: focused,
            exiting,
        };
        if has_held && !super::desk_keys::hold_keyboard(&gate) {
            self.release_desktop_tab_input(id);
        }
    }

    fn inject_mouse_raw(
        &self,
        session: TabId,
        node: &str,
        monitor: u32,
        event: MouseEvent<'_>,
        barrier: bool,
        allowed: bool,
    ) {
        send_mouse_cmd(
            &self.tx,
            &self.shared,
            session,
            node,
            monitor,
            allowed,
            event,
            barrier,
        );
    }

    fn inject_key_edge(&self, session: TabId, node: &str, key: &str, down: bool, allowed: bool) {
        send_key_edge_cmd(&self.tx, session, node, allowed, key, down);
    }

    fn refresh_mock_picture(&mut self, ctx: &egui::Context) {
        let active_id = self.active_tab;
        let fail_connect = self.fail_connect;
        let max_fps = self.max_fps;
        let debug_enabled = self.debug_inbox.is_some();
        let mut next_rgba: Option<(u32, u32, Vec<u8>)> = None;

        if let Some(d) = self.desktop_by_id_mut(active_id) {
            if fail_connect || d.connect_failed || d.user_stopped {
                return;
            }
            // Pace mock frames by `--max-fps` (default 30) so fps stats are honest.
            let min_interval = Duration::from_secs_f32(1.0 / max_fps.max(1) as f32);
            if d.last_frame.is_some_and(|t| t.elapsed() < min_interval) {
                return;
            }
            let frame = match agentlink_desktop::MockDesktop::frames(960, 480) {
                Ok(frame) => frame,
                Err(_) => return,
            };
            let rgba = agentlink_desktop_bgra_to_rgba(frame.pixels(), frame.width, frame.height);
            if debug_enabled {
                next_rgba = Some((frame.width, frame.height, rgba.clone()));
            }
            let image = egui::ColorImage::from_rgba_unmultiplied(
                [frame.width as usize, frame.height as usize],
                &rgba,
            );
            if let Some(texture) = &mut d.texture {
                texture.set(image, egui::TextureOptions::LINEAR);
            } else {
                d.texture = Some(ctx.load_texture(
                    format!("mock-desktop-{}", d.id),
                    image,
                    egui::TextureOptions::LINEAR,
                ));
            }
            d.size = (frame.width as usize, frame.height as usize);
            d.last_frame = Some(Instant::now());
            d.connect_started = None;
            d.hud.width = frame.width;
            d.hud.height = frame.height;
            d.mock_frame_window_count += 1;
            let elapsed = d.mock_frame_window_start.elapsed();
            if elapsed >= Duration::from_millis(500) {
                d.hud.fps = d.mock_frame_window_count as f32 / elapsed.as_secs_f32().max(0.001);
                d.mock_frame_window_start = Instant::now();
                d.mock_frame_window_count = 0;
            }
            d.seen_seq += 1;
        }
        if let Some(rgba) = next_rgba {
            self.debug_rgba = Some(rgba);
        }
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
                self.reset_to_login(Some(ctx), None);
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
                self.auth = AuthScreen::Workspace;
                self.back_to_machines(Some(ctx));
                None
            }
            "session" => {
                if self.user.is_none() {
                    self.user = Some("debug".into());
                }
                self.auth = AuthScreen::Workspace;
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
                self.open_desktop_tab(&info, control);
                if self.mock && !self.fail_connect {
                    self.refresh_mock_picture(ctx);
                }
                None
            }
            "terminal" => {
                if self.user.is_none() {
                    self.user = Some("debug".into());
                }
                self.auth = AuthScreen::Workspace;
                let info = self
                    .nodes
                    .iter()
                    .find(|n| n.id == node || n.name == node)
                    .cloned()
                    .unwrap_or_else(|| mock_node(node));
                if !self.nodes.iter().any(|n| n.id == info.id) {
                    self.nodes.push(info.clone());
                }
                self.open_terminal_tab(&info);
                None
            }
            "files" => {
                if self.user.is_none() {
                    self.user = Some("debug".into());
                }
                self.auth = AuthScreen::Workspace;
                let info = self
                    .nodes
                    .iter()
                    .find(|n| n.id == node || n.name == node)
                    .cloned()
                    .unwrap_or_else(|| mock_node(node));
                if !self.nodes.iter().any(|n| n.id == info.id) {
                    self.nodes.push(info.clone());
                }
                self.open_files_tab(&info);
                None
            }
            "settings" => {
                self.auth = AuthScreen::Workspace;
                self.open_settings_tab();
                None
            }
            other => Some(format!("unknown screen '{other}'")),
        }
    }

    pub(super) fn debug_fail(&mut self, what: &str) -> Option<String> {
        match what {
            "connect" => {
                let Some(desk_id) = self.active_desktop_id() else {
                    return Some("not in a session".into());
                };
                self.fail_desktop_tab_session(desk_id, "WebRTC connection failed (debug)");
                None
            }
            other => Some(format!("unknown fail target '{other}'")),
        }
    }

    pub(super) fn debug_state(&self) -> Value {
        let (w, h) = self.logical_size;
        let screen = match self.auth {
            AuthScreen::Login => "login",
            AuthScreen::Restoring => "restoring",
            AuthScreen::Workspace => match self.active_tab_ref() {
                None => "machines",
                Some(Tab::Desktop(_)) => "session",
                Some(Tab::Terminal(_)) => "terminal",
                Some(Tab::Files(_)) => "files",
                Some(Tab::Settings { .. }) => "settings",
            },
        };
        let node = match self.active_tab_ref().and_then(|t| t.node_id()) {
            Some(id) => Value::String(id.to_string()),
            None => Value::Null,
        };
        let active_desk = match self.active_tab_ref() {
            Some(Tab::Desktop(d)) => Some(d),
            _ => None,
        };
        let conn_state = match active_desk.map(DesktopTab::phase) {
            Some(SessionPhase::Live | SessionPhase::Stale) => "connected",
            Some(SessionPhase::Connecting) => "connecting",
            Some(SessionPhase::Failed) => "failed",
            Some(SessionPhase::Disconnected) | None => "disconnected",
        };
        let bitrate = if let Some(d) = active_desk {
            if d.hud.bitrate_kbps > 0 {
                d.hud.bitrate_kbps
            } else if self.mock {
                2000
            } else {
                0
            }
        } else {
            0
        };
        let (
            kind,
            path,
            path_note,
            handshake,
            link,
            fps,
            latency_ms,
            encoder_name,
            hardware,
            frames_dropped,
            conn_err_raw,
            fullscreen,
            stats_open,
            zoom,
            pan,
            fit,
            capture_keys,
        ) = if let Some(d) = active_desk {
            (
                d.hud.kind.clone(),
                d.hud.path.clone(),
                d.hud.path_note.clone(),
                d.hud.handshake.clone(),
                d.link.clone(),
                d.hud.fps,
                d.hud.latency_ms,
                d.hud.encoder.clone(),
                d.hud.hardware,
                d.hud.frames_dropped,
                d.disconnect_reason.clone(),
                d.fullscreen,
                d.stats_open,
                d.zoom,
                [d.pan.x, d.pan.y],
                if d.fit { "fit" } else { "free" },
                d.capture_keys,
            )
        } else {
            (
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                self.link.clone(),
                0.0,
                0,
                String::new(),
                false,
                0,
                String::new(),
                false,
                false,
                1.0,
                [0.0, 0.0],
                "fit",
                false,
            )
        };
        let encoder = encoder_label(&kind, &encoder_name, hardware);
        let items: Vec<Value> = self
            .debug_layout
            .toolbar_items
            .iter()
            .map(|(id, rect)| json!({"id": id, "rect": rect}))
            .collect();
        let tab_items: Vec<Value> = self
            .debug_layout
            .tab_items
            .iter()
            .map(|(id, rect)| json!({"id": id, "rect": rect}))
            .collect();
        let errors = if self.error.is_empty() {
            Vec::<String>::new()
        } else {
            vec![self.error.clone()]
        };
        let conn_error = if conn_err_raw.is_empty() {
            Value::Null
        } else {
            Value::String(conn_err_raw)
        };
        json!({
            "screen": screen,
            "node": node,
            "title": self.window_title,
            "window": {"w": w, "h": h},
            "fullscreen": fullscreen,
            "stats_open": stats_open,
            "tabs_count": self.tabs.len(),
            "connection": {
                "state": conn_state,
                "mode": self.session_mode(),
                "error": conn_error,
                "kind": kind,
                "path": path,
                "path_note": path_note,
                "handshake": handshake,
                "link": link,
                "fps": fps,
                "bitrate_kbps": bitrate,
                "latency_ms": latency_ms,
                "encoder": encoder,
                "frames_dropped": frames_dropped,
            },
            "perf": self.shared.perf.snapshot(),
            "tab_bar": {
                "rect": self.debug_layout.tab_bar_rect,
                "items": tab_items,
            },
            "toolbar": {
                "visible": self.debug_layout.toolbar_visible,
                "height": self.debug_layout.toolbar_rect[3],
                "rect": self.debug_layout.toolbar_rect,
                "items": items,
            },
            "viewport": {
                "image_rect": self.debug_layout.pane_rect,
                "content_rect": self.debug_layout.content_rect,
                "zoom": zoom,
                "pan": pan,
                "fit": fit,
            },
            "keyboard_captured": capture_keys,
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
        let tab_items: Vec<Value> = self
            .debug_layout
            .tab_items
            .iter()
            .map(|(id, rect)| json!({"id": id, "rect": rect}))
            .collect();
        json!({
            "tab_bar": {
                "rect": self.debug_layout.tab_bar_rect,
                "items": tab_items,
            },
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

fn send_mouse_cmd(
    tx: &UnboundedSender<Cmd>,
    shared: &Shared,
    session: TabId,
    node: &str,
    monitor: u32,
    allowed: bool,
    event: MouseEvent<'_>,
    barrier: bool,
) {
    // Button releases still go out after a grant rejection so buttons do not stick.
    if event.action != "up" && !allowed {
        return;
    }
    let mut live = serde_json::json!({
        "type": "mouse",
        "action": event.action,
        "x": event.x,
        "y": event.y,
        "dx": event.dx,
        "dy": event.dy,
        "button": event.button,
        "monitor": monitor,
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
        "monitor": monitor,
    });
    if event.action == "click" {
        inject["count"] = serde_json::json!(event.count);
    }
    if event.action == "move" {
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        shared
            .perf
            .last_move_unix_ms
            .store(now_ms, std::sync::atomic::Ordering::Relaxed);
    }
    let _ = tx.send(Cmd::Input {
        session,
        node: node.to_string(),
        live: live.to_string(),
        inject: inject.to_string(),
        barrier,
    });
}

fn send_text_cmd(
    tx: &UnboundedSender<Cmd>,
    session: TabId,
    node: &str,
    allowed: bool,
    text: &str,
) {
    if !allowed {
        return;
    }
    let live = serde_json::json!({"type": "type", "text": text}).to_string();
    let inject = serde_json::json!({"action": "type", "text": text}).to_string();
    let _ = tx.send(Cmd::Input {
        session,
        node: node.to_string(),
        live,
        inject,
        barrier: true,
    });
}

fn send_key_edge_cmd(
    tx: &UnboundedSender<Cmd>,
    session: TabId,
    node: &str,
    allowed: bool,
    key: &str,
    down: bool,
) {
    // Key-up is allowed after a grant rejection so a held modifier cannot stick.
    if down && !allowed {
        return;
    }
    let live = serde_json::json!({"type": "key", "keys": [key], "down": down}).to_string();
    let inject = serde_json::json!({"action": "key", "keys": key, "down": down}).to_string();
    let _ = tx.send(Cmd::Input {
        session,
        node: node.to_string(),
        live,
        inject,
        barrier: true,
    });
}

fn send_keys_tap_cmd(
    tx: &UnboundedSender<Cmd>,
    session: TabId,
    node: &str,
    allowed: bool,
    keys: &[&str],
) {
    if !allowed || agentlink_desktop::is_secure_attention_sequence(keys) {
        return;
    }
    let live = serde_json::json!({"type": "key", "keys": keys}).to_string();
    let inject = serde_json::json!({"action": "key", "keys": keys.join("+")}).to_string();
    let _ = tx.send(Cmd::Input {
        session,
        node: node.to_string(),
        live,
        inject,
        barrier: true,
    });
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
    SendChord(&'static [&'static str]),
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

fn mode_badge_widget(ui: &mut egui::Ui, control: bool, can_toggle: bool) -> egui::Response {
    let (label, text) = if control {
        ("CONTROL", theme::ACCENT)
    } else {
        ("VIEW", theme::TEXT_MUTED)
    };
    let frame_resp = egui::Frame::new()
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
    let response = if can_toggle {
        ui.interact(
            frame_resp.rect,
            ui.id().with("mode-badge-toggle"),
            egui::Sense::click(),
        )
    } else {
        frame_resp
    };
    response.on_hover_text(match (control, can_toggle) {
        (true, true) => "Control session — click to switch to View only",
        (false, true) => "View-only session — click to switch to Control",
        (true, false) => "Control session",
        (false, false) => "View-only session",
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

fn egui_event_is_keyboard(event: &egui::Event) -> bool {
    matches!(
        event,
        egui::Event::Key { .. }
            | egui::Event::Text(_)
            | egui::Event::Copy
            | egui::Event::Cut
            | egui::Event::Paste(_)
            | egui::Event::Ime(_)
    )
}

fn host_key_from_egui(
    event: &egui::Event,
    frame_mods: super::input_adapter::ModSnapshot,
    snap: impl Fn(egui::Modifiers) -> super::input_adapter::ModSnapshot,
) -> Option<super::desk_keys::HostKey> {
    use super::desk_keys::HostKey;
    match event {
        egui::Event::Key {
            key,
            physical_key,
            pressed,
            repeat,
            modifiers,
        } => {
            let name = egui_key_name(*key).or_else(|| physical_key.and_then(egui_key_name))?;
            let physical = physical_key.and_then(egui_key_name).map(str::to_string);
            Some(HostKey::Key {
                name: name.to_string(),
                physical,
                pressed: *pressed,
                repeat: *repeat,
                mods: snap(*modifiers),
            })
        }
        egui::Event::Text(text) => Some(HostKey::Text(text.clone())),
        egui::Event::Copy => Some(HostKey::Copy { mods: frame_mods }),
        egui::Event::Cut => Some(HostKey::Cut { mods: frame_mods }),
        // Clipboard bytes stay on the desktop clipboard channel. A captured
        // paste is the remote Ctrl+V (or Shift+Insert) chord, not typed text.
        egui::Event::Paste(_) => Some(HostKey::Paste { mods: frame_mods }),
        egui::Event::Ime(egui::ImeEvent::Preedit(text)) => Some(HostKey::ImePreedit(text.clone())),
        egui::Event::Ime(egui::ImeEvent::Commit(text)) => Some(HostKey::ImeCommit(text.clone())),
        egui::Event::Ime(_) => None,
        _ => None,
    }
}

fn egui_key_name(key: egui::Key) -> Option<&'static str> {
    match key {
        egui::Key::Enter => Some("enter"),
        egui::Key::Escape => Some("escape"),
        egui::Key::Tab => Some("tab"),
        egui::Key::Backspace => Some("backspace"),
        egui::Key::Delete => Some("delete"),
        egui::Key::Insert => Some("insert"),
        egui::Key::ArrowLeft => Some("left"),
        egui::Key::ArrowRight => Some("right"),
        egui::Key::ArrowUp => Some("up"),
        egui::Key::ArrowDown => Some("down"),
        egui::Key::PageUp => Some("pageup"),
        egui::Key::PageDown => Some("pagedown"),
        egui::Key::Home => Some("home"),
        egui::Key::End => Some("end"),
        egui::Key::Space => Some("space"),
        egui::Key::Copy => Some("copy"),
        egui::Key::Cut => Some("cut"),
        egui::Key::Paste => Some("paste"),
        egui::Key::Minus => Some("-"),
        egui::Key::Plus => Some("+"),
        egui::Key::Equals => Some("="),
        egui::Key::Comma => Some(","),
        egui::Key::Period => Some("."),
        egui::Key::Slash => Some("/"),
        egui::Key::Backslash => Some("\\"),
        egui::Key::Pipe => Some("|"),
        egui::Key::Colon => Some(":"),
        egui::Key::Semicolon => Some(";"),
        egui::Key::Quote => Some("'"),
        egui::Key::Questionmark => Some("?"),
        egui::Key::Exclamationmark => Some("!"),
        egui::Key::OpenBracket => Some("["),
        egui::Key::CloseBracket => Some("]"),
        egui::Key::OpenCurlyBracket => Some("{"),
        egui::Key::CloseCurlyBracket => Some("}"),
        egui::Key::Backtick => Some("`"),
        egui::Key::F1 => Some("f1"),
        egui::Key::F2 => Some("f2"),
        egui::Key::F3 => Some("f3"),
        egui::Key::F4 => Some("f4"),
        egui::Key::F5 => Some("f5"),
        egui::Key::F6 => Some("f6"),
        egui::Key::F7 => Some("f7"),
        egui::Key::F8 => Some("f8"),
        egui::Key::F9 => Some("f9"),
        egui::Key::F10 => Some("f10"),
        egui::Key::F11 => Some("f11"),
        egui::Key::F12 => Some("f12"),
        egui::Key::F13 => Some("f13"),
        egui::Key::F14 => Some("f14"),
        egui::Key::F15 => Some("f15"),
        egui::Key::F16 => Some("f16"),
        egui::Key::F17 => Some("f17"),
        egui::Key::F18 => Some("f18"),
        egui::Key::F19 => Some("f19"),
        egui::Key::F20 => Some("f20"),
        egui::Key::F21 => Some("f21"),
        egui::Key::F22 => Some("f22"),
        egui::Key::F23 => Some("f23"),
        egui::Key::F24 => Some("f24"),
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

fn labeled(ui: &mut egui::Ui, name: &str, text: &mut String, secret: bool) -> egui::Response {
    ui.label(theme::muted_text(name));
    let edit = centered_singleline(ui, text, secret);
    style_text_edit(ui, edit)
}

/// Shared TextEdit for Username / Password / Relay / Certificate pin / Trust /
/// authenticator — vertical margin from font metrics so glyphs and password
/// bullets stay centered in the tall field (t484). Never logs `text`.
fn centered_singleline<'a>(
    ui: &egui::Ui,
    text: &'a mut String,
    secret: bool,
) -> egui::TextEdit<'a> {
    let ppp = ui.ctx().pixels_per_point();
    let font_size = theme::BODY_SIZE;
    let vpad = super::field_pad::text_edit_v_margin(theme::BTN_PRIMARY_H, font_size, ppp);
    // egui Margin uses i8; clamp to a sane range for extreme DPI.
    let v = vpad.round().clamp(0.0, 40.0) as i8;
    egui::TextEdit::singleline(text)
        .password(secret)
        .desired_width(f32::INFINITY)
        .min_size(egui::vec2(0.0, theme::BTN_PRIMARY_H))
        .margin(egui::Margin::symmetric(theme::BTN_PAD_X as i8, v))
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
/// Map a negotiated stock shape id to an egui cursor.
///
/// `"unknown"` / `"custom"` without a bitmap must **not** become
/// [`CursorIcon::None`] — that removes the only pointer. Fall back to Default
/// so the user keeps a visible caret; the custom RGBA path paints when present.
fn stock_cursor_icon(shape: &str) -> egui::CursorIcon {
    match shape {
        "arrow" => egui::CursorIcon::Default,
        "ibeam" => egui::CursorIcon::Text,
        "hand" => egui::CursorIcon::PointingHand,
        "sizeall" => egui::CursorIcon::AllScroll,
        "sizens" => egui::CursorIcon::ResizeVertical,
        "sizewe" => egui::CursorIcon::ResizeHorizontal,
        "sizenwse" => egui::CursorIcon::ResizeNwSe,
        "sizenesw" => egui::CursorIcon::ResizeNeSw,
        "cross" => egui::CursorIcon::Crosshair,
        "wait" => egui::CursorIcon::Progress,
        "no" => egui::CursorIcon::NotAllowed,
        "help" => egui::CursorIcon::Help,
        _ => egui::CursorIcon::Default,
    }
}

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

    /// Visible page must cover a real fraction of the window.
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
            // Inert hooks: geometry tests must not read/write production
            // autostart (HKCU Run) or resolve the real user data-dir.
            Self::new_with(w, h, false, super::super::LiveHooks::inert_for_tests())
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
                app.nodes = realistic_nodes();
                for node in &app.nodes {
                    app.control.insert(node.id.clone(), true);
                }
                app.auth = AuthScreen::Workspace;
                app.active_tab = MACHINES_TAB_ID;
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

        fn click_rect(&mut self, rect: [f32; 4]) {
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

        fn click_item(&mut self, id: &str) {
            let rect = item_rect(&self.app.debug_layout, id).expect(id);
            self.click_rect(rect);
        }

        fn click_tab_item(&mut self, id: &str) {
            let rect = tab_item_rect(&self.app.debug_layout, id).expect(id);
            self.click_rect(rect);
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

        fn open_sufa_desktop(&mut self) -> TabId {
            let desk = self
                .app
                .nodes
                .iter()
                .find(|n| n.id == "workstation")
                .cloned()
                .expect("workstation");
            self.app.open_desktop_tab(&desk, false)
        }

        fn populate_files(&mut self, tab_id: TabId) {
            let f = self.app.files_by_id_mut(tab_id).expect("files tab");
            f.loading = false;
            f.dir = ".".into();
            f.entries = vec![
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
            f.editor = Some(Editor::editable(
                "readme.txt".into(),
                "hello from geometry test\n".into(),
            ));
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

        fn open_quant_terminal(&mut self) -> TabId {
            let node = self
                .app
                .nodes
                .iter()
                .find(|n| n.id == "quant67")
                .cloned()
                .expect("quant67");
            self.app.open_terminal_tab(&node)
        }

        fn active_terminal(&self) -> &TerminalTab {
            match self.app.active_tab_ref() {
                Some(Tab::Terminal(t)) => t,
                _ => panic!("expected active Terminal tab"),
            }
        }

        fn active_desktop(&self) -> &DesktopTab {
            match self.app.active_tab_ref() {
                Some(Tab::Desktop(d)) => d,
                _ => panic!("expected active Desktop tab"),
            }
        }

        fn active_files(&self) -> &FilesTab {
            match self.app.active_tab_ref() {
                Some(Tab::Files(f)) => f,
                _ => panic!("expected active Files tab"),
            }
        }
    }

    fn realistic_nodes() -> Vec<NodeInfo> {
        let mut quant = mock_node("quant67");
        quant.has_display = Some(false);
        quant.policy = NodePolicy::exec();
        quant.effective = NodePolicy::exec();
        quant.access = "exec".into();

        let mut workstation = mock_node("workstation");
        workstation.has_display = Some(true);
        workstation.policy = NodePolicy::full();
        workstation.effective = NodePolicy::full();
        workstation.access = "full".into();

        let mut tccn = mock_node("tc-cn");
        tccn.has_display = Some(false);
        tccn.policy = NodePolicy::exec();
        tccn.effective = NodePolicy::exec();

        vec![quant, workstation, tccn]
    }

    fn item_rect(layout: &DebugLayout, id: &str) -> Option<[f32; 4]> {
        layout
            .toolbar_items
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, rect)| *rect)
    }

    fn tab_item_rect(layout: &DebugLayout, id: &str) -> Option<[f32; 4]> {
        layout
            .tab_items
            .iter()
            .find(|(key, _)| key == id)
            .map(|(_, rect)| *rect)
    }

    fn assert_tab_bar_visible(layout: &DebugLayout, window: (f32, f32)) {
        let bar = layout.tab_bar_rect;
        assert!(
            (bar[3] - theme::TAB_BAR_HEIGHT).abs() <= 1.0,
            "tab_bar_rect height mismatch: {bar:?} win={window:?}"
        );
        assert!(
            bar[2] >= window.0 - 2.0,
            "tab_bar_rect does not span window width: {bar:?} win={window:?}"
        );
        for required in ["tab_machines", "tab_new", "tab_menu", "header_settings"] {
            let rect = tab_item_rect(layout, required).unwrap_or_else(|| {
                panic!("missing {required} in tab_items: {:?}", layout.tab_items)
            });
            assert!(
                rect[0] >= -1.0 && rect[0] + rect[2] <= window.0 + 1.5,
                "{required} overflows window width: {rect:?} win={window:?}"
            );
            assert!(
                rect[1] >= -1.0 && rect[1] + rect[3] <= bar[1] + bar[3] + 1.5,
                "{required} overflows tab bar height: {rect:?} bar={bar:?}"
            );
        }
    }

    fn assert_session_clip_geometry(layout: &DebugLayout, w: f32, h: f32) {
        assert_eq!(
            layout.rail_rect, [0.0; 4],
            "session tabs must be full-bleed without the left machine rail at {w}x{h}"
        );
        let main = layout.main_rect;
        assert!(
            main[2] >= min_main_visible_w(w),
            "main width crushed: {main:?} at {w}x{h}"
        );
        assert!(
            main[3] >= min_page_visible_h(h),
            "main height crushed (black remainder): {main:?} at {w}x{h}"
        );
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
        assert_tab_bar_visible(layout, (w, h));
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

    /// Raw vs clip-visible *x* bounds. A card may be only partly inside the
    /// vertical scroll viewport, so height is allowed to differ until the
    /// card is scrolled fully into view.
    fn assert_action_x_fully_visible(layout: &DebugLayout, key: &str, window_w: f32) {
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
            (vis[0] - raw[0]).abs() <= 1.0,
            "{key} left edge clipped: raw={raw:?} vis={vis:?}"
        );
        assert!(
            (vis[2] - raw[2]).abs() <= 1.0,
            "{key} right edge clipped (raw width vs visible width): raw={raw:?} vis={vis:?}"
        );
        assert!(
            vis[0] >= 0.0 && vis[0] + vis[2] <= window_w + 1.0,
            "{key} vis outside window: {vis:?} w={window_w}"
        );
        assert!(
            raw[0] >= 0.0 && raw[0] + raw[2] <= window_w + 1.0,
            "{key} raw outside window: {raw:?} w={window_w}"
        );
        let clip = layout.visible_clip;
        if clip[2] > 1.0 {
            assert!(
                raw[0] + raw[2] <= clip[0] + clip[2] + 0.5,
                "{key} raw max.x {} exceeds visible clip max.x {} (raw={raw:?} clip={clip:?})",
                raw[0] + raw[2],
                clip[0] + clip[2]
            );
        }
    }

    fn action_vis_is_on_screen(vis: [f32; 4]) -> bool {
        vis[2] > 0.5 && vis[3] > 0.5
    }

    fn assert_view_desktop_fully_in_clip(layout: &DebugLayout) {
        let w = if layout.main_rect[2] > 0.0 {
            layout.main_rect[0] + layout.main_rect[2]
        } else {
            1920.0
        };
        assert_action_fully_visible(layout, "action_btn:workstation:View desktop", w);
    }

    #[test]
    fn session_geometry_terminal_files_machines_desktop_wide_and_narrow() {
        for &(w, h) in &[
            (725.0_f32, 800.0_f32),
            (1080.0_f32, 800.0_f32),
            (1280.0_f32, 800.0_f32),
            (1920.0_f32, 1200.0_f32),
        ] {
            let mut harn = Harness::new(w, h);
            harn.pass();
            harn.pass();

            let expect_rail = model::machine_rail_visible(w);
            assert_machines_shell(&harn, w, h, expect_rail);

            let _tid = harn.open_quant_terminal();
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, h);

            let node = harn.app.nodes[0].clone();
            let fid = harn.app.open_files_tab(&node);
            harn.populate_files(fid);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, h);
            assert!(
                item_rect(&harn.app.debug_layout, "editor")
                    .is_some_and(|r| r[2] > 80.0 && r[3] > 40.0),
                "editor clip-visible missing/small at {w}"
            );

            let desk = harn
                .app
                .nodes
                .iter()
                .find(|n| n.id == "workstation")
                .cloned()
                .unwrap();
            harn.app.open_desktop_tab(&desk, true);
            harn.pass();
            harn.pass();
            assert_eq!(harn.app.debug_layout.rail_rect, [0.0; 4]);
            let pane = harn.app.debug_layout.pane_rect;
            assert!(pane[2] > w * 0.5, "desktop pane width {pane:?} at {w}x{h}");
            assert!(pane[3] > h * 0.4, "desktop pane height {pane:?} at {w}x{h}");
            assert_tab_bar_visible(&harn.app.debug_layout, (w, h));
        }
    }

    #[test]
    fn rail_view_desktop_label_fully_visible_when_rail_shown() {
        let mut harn = Harness::new(1280.0, 800.0);
        harn.app.selected_id = Some("workstation".into());
        harn.pass();
        harn.pass();
        assert!(model::machine_rail_visible(1280.0));
        assert_view_desktop_fully_in_clip(&harn.app.debug_layout);
        assert_action_fully_visible(
            &harn.app.debug_layout,
            "action_btn:workstation:Control desktop",
            1280.0,
        );
        let workstation = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .unwrap();
        harn.app.open_terminal_tab(&workstation);
        harn.pass();
        // Return to pinned Machines tab: open-tab jump chip appears and cards stay clipped cleanly.
        harn.app.back_to_machines(None);
        harn.pass();
        harn.pass();
        assert_view_desktop_fully_in_clip(&harn.app.debug_layout);
        assert_action_fully_visible(
            &harn.app.debug_layout,
            "action_btn:workstation:Control desktop",
            1280.0,
        );
    }

    #[test]
    fn restored_1080_and_true_725_fold_rail_1280_keeps_it() {
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
            harn.pass();
            harn.pass();
            assert_machines_shell(&harn, w, 800.0, expect_rail);

            harn.open_quant_terminal();
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, 800.0);
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
                "terminal" => {
                    harn.app.open_terminal_tab(&node);
                }
                _ => {
                    let fid = harn.app.open_files_tab(&node);
                    harn.populate_files(fid);
                }
            }
            harn.resize(1280.0, 800.0);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, 1280.0, 800.0);

            harn.resize(1080.0, 800.0);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, 1080.0, 800.0);

            harn.resize(725.0, 800.0);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, 725.0, 800.0);
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
            assert_session_clip_geometry(&harn.app.debug_layout, 1920.0, 1200.0);

            harn.resize(1280.0, 800.0);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, 1280.0, 800.0);
        }
    }

    #[test]
    fn clip_visible_gates_reject_interact_height_strip_and_partial_label() {
        let interact = theme::BTN_TOOLBAR_H;
        let fake_page = [280.0, 40.0, 900.0, interact];
        assert!(
            fake_page[3] < min_page_visible_h(800.0) * 0.55,
            "gates must reject crushed page visible height"
        );
        let raw = [12.0, 40.0, 118.0, 28.0];
        let vis = [12.0, 40.0, 96.0, 28.0];
        assert!(
            f32::abs(vis[2] - raw[2]) > 1.0,
            "partial label fixture must differ raw vs vis"
        );
    }

    /// Parent GUI: readonly workstation Desktop → Back → quant67 Terminal left the
    /// native title stuck on "workstation — …". Transitions used to assign
    /// `window_title` before `sync_window_title`, so the compare suppressed
    /// ViewportCommand::Title. Assert the *outgoing* Title commands.
    #[test]
    fn native_title_commands_follow_session_and_clear_on_back() {
        let mut harn = Harness::new(1280.0, 800.0);
        harn.pass();
        assert_eq!(harn.app.window_title, "AgentLink");

        harn.open_sufa_desktop();
        let out = harn.pass_output();
        let titles = Harness::titles_from(&out);
        assert!(
            titles
                .iter()
                .any(|t| t.contains("workstation") && t.starts_with("Desktop —")),
            "expected Title for workstation desktop, got {titles:?}; cache={}",
            harn.app.window_title
        );
        assert!(
            harn.app.window_title.contains("workstation"),
            "cache should match desktop: {}",
            harn.app.window_title
        );

        // No-session: Machines tab must emit the default title (not leave native on workstation).
        harn.app.back_to_machines(None);
        let out = harn.pass_output();
        let titles = Harness::titles_from(&out);
        assert_eq!(
            titles,
            vec!["AgentLink".to_string()],
            "Machines tab must emit Title clear; cache={}",
            harn.app.window_title
        );

        // Old → new node: quant67 Terminal must emit a quant67 Title.
        harn.open_quant_terminal();
        let out = harn.pass_output();
        let titles = Harness::titles_from(&out);
        assert_eq!(
            titles,
            vec!["Terminal — quant67 · AgentLink".to_string()],
            "terminal Title must name quant67; cache={}",
            harn.app.window_title
        );

        // Stable frame: no redundant Title when unchanged.
        let out = harn.pass_output();
        assert!(
            Harness::titles_from(&out).is_empty(),
            "unchanged session must not re-emit Title"
        );

        // Terminal → Files on the same node still changes the mode prefix.
        let node = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "quant67")
            .cloned()
            .unwrap();
        harn.app.open_files_tab(&node);
        let out = harn.pass_output();
        assert_eq!(
            Harness::titles_from(&out),
            vec!["Files — quant67 · AgentLink".to_string()]
        );

        // Files → different node Terminal.
        let workstation = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .unwrap();
        harn.app.open_terminal_tab(&workstation);
        let out = harn.pass_output();
        assert_eq!(
            Harness::titles_from(&out),
            vec!["Terminal — workstation · AgentLink".to_string()]
        );

        harn.app.back_to_machines(None);
        let out = harn.pass_output();
        assert_eq!(
            Harness::titles_from(&out),
            vec!["AgentLink".to_string()]
        );
    }

    /// Premature cache update used to hide Title: open_desktop assigning
    /// window_title before sync made the compare a no-op. Mutation guard.
    #[test]
    fn title_sync_still_emits_when_cache_was_not_pre_assigned() {
        let mut harn = Harness::new(1280.0, 800.0);
        harn.pass();
        harn.open_sufa_desktop();
        harn.app.window_title = harn.app.compute_window_title();
        let out = harn.pass_output();
        assert!(
            Harness::titles_from(&out).is_empty(),
            "pre-assigned cache correctly suppresses Title (documents the bug class)"
        );
        harn.app.back_to_machines(None);
        let out = harn.pass_output();
        assert_eq!(
            Harness::titles_from(&out),
            vec!["AgentLink".to_string()],
            "sync must emit when only screen changed"
        );
    }

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
            assert_session_clip_geometry(&harn.app.debug_layout, w, h);

            let node = harn.app.nodes[0].clone();
            let fid = harn.app.open_files_tab(&node);
            harn.populate_files(fid);
            let out = harn.pass_output();
            assert!(
                Harness::min_inner_sizes_from(&out).is_empty(),
                "files session must not emit MinInnerSize at {w}x{h}"
            );
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, h);
            assert!(
                item_rect(&harn.app.debug_layout, "editor")
                    .is_some_and(|r| r[2] > 40.0 && r[3] > 24.0),
                "editor must remain visible at declared min {w}x{h}: {:?}",
                item_rect(&harn.app.debug_layout, "editor")
            );

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
        for (id, rect) in layout
            .toolbar_items
            .iter()
            .chain(layout.tab_items.iter())
        {
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
            assert_eq!(layout.rail_rect, [0.0; 4], "rail should fold below show-at at {w}");
        }
        assert_tab_bar_visible(layout, (w, h));
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
            harn.app.selected_id = Some("workstation".into());
            harn.pass();
            harn.pass();
            assert_eq!(model::machine_rail_visible(w), expect_rail);
            assert_machines_shell(&harn, w, h, expect_rail);

            let node = harn.app.nodes[0].clone();
            let tid = harn.app.open_terminal_tab(&node);
            harn.pass();
            harn.pass();
            assert_session_clip_geometry(&harn.app.debug_layout, w, h);
            assert!(
                tab_item_rect(&harn.app.debug_layout, &format!("tab:{tid}")).is_some(),
                "terminal tab missing in tab bar at {w}x{h}"
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
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("workstation");
        node.effective = NodePolicy::remote_view();
        node.policy = NodePolicy::remote_view();
        node.access = "remote-view".into();
        node.has_display = Some(true);
        if let Some(existing) = harn.app.nodes.iter_mut().find(|n| n.id == "workstation") {
            *existing = node;
        }
        harn.app.selected_id = Some("workstation".into());
        harn.pass();
        harn.pass();
        let layout = &harn.app.debug_layout;
        assert_action_fully_visible(layout, "action_btn:workstation:View desktop", 1024.0);
        let raw = item_rect(layout, "action_btn:workstation:Control desktop:raw")
            .expect("Control desktop should stay visible (disabled, not hidden)");
        let vis = item_rect(layout, "action_btn:workstation:Control desktop:vis").expect("control vis");
        assert!(
            (vis[2] - raw[2]).abs() <= 1.0,
            "Control clipped: {raw:?} {vis:?}"
        );
        let reason = item_rect(layout, "action_reason:workstation:Control desktop");
        assert!(reason.is_some(), "disabled Control needs an inline reason");
    }

    #[test]
    fn preview_fixture_is_isolated_and_labeled() {
        let mut harn = Harness::preview(1024.0, 756.0, super::super::LiveHooks::production());
        harn.pass();
        let out = harn.pass_output();
        let titles = Harness::titles_from(&out);
        assert!(
            harn.app.window_title.contains("Preview"),
            "title cache: {}",
            harn.app.window_title
        );
        assert!(
            titles.iter().any(|t| t.contains("Preview"))
                || harn.app.window_title == "AgentLink (Preview)",
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
        assert!(
            item_rect(&harn.app.debug_layout, "preview_banner").is_some(),
            "preview banner missing"
        );
        assert_machines_shell(&harn, 1024.0, 756.0, true);

        // Open Settings tab in preview mode: account refresh/logout must remain hidden.
        harn.click_tab_item("header_settings");
        harn.pass();
        assert!(item_rect(&harn.app.debug_layout, "settings_panel").is_some());
        assert!(item_rect(&harn.app.debug_layout, "settings_logout").is_none());
        assert!(item_rect(&harn.app.debug_layout, "settings_refresh").is_none());
        assert!(item_rect(&harn.app.debug_layout, "rail_refresh").is_none());

        harn.click_tab_item("tab_machines");
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
            (640.0_f32, 480.0_f32),
            (719.0_f32, 756.0_f32),
            (1024.0_f32, 756.0_f32),
            (1280.0_f32, 800.0_f32),
        ] {
            let mut harn = Harness::new(w, h);
            harn.app.selected_id = Some("workstation".into());
            harn.pass();
            harn.pass();
            assert_tab_bar_visible(&harn.app.debug_layout, (w, h));
            assert_no_overflow(&harn.app.debug_layout, w, h);

            harn.click_tab_item("header_settings");
            harn.pass();
            assert!(
                item_rect(&harn.app.debug_layout, "settings_panel").is_some(),
                "settings panel missing at {w}x{h}"
            );
            assert!(item_rect(&harn.app.debug_layout, "settings_logout").is_some());
            assert!(item_rect(&harn.app.debug_layout, "settings_quit").is_some());
            assert_no_overflow(&harn.app.debug_layout, w, h);
        }
    }

    #[test]
    fn hash_and_version_are_not_primary_machine_meta() {
        let mut harn = Harness::new(1024.0, 756.0);
        if let Some(node) = harn.app.nodes.iter_mut().find(|n| n.id == "workstation") {
            node.version = "cd30c9ed52337645".into();
        }
        harn.app.selected_id = Some("workstation".into());
        harn.pass();
        harn.pass();
        assert!(item_rect(&harn.app.debug_layout, "nav_row:workstation").is_some());
        assert!(
            item_rect(&harn.app.debug_layout, "detail_node_id").is_none(),
            "collapsed Details must not push the node id into the primary column"
        );
    }

    #[test]
    fn rail_geometry_includes_dpi_and_folds_719_physical() {
        for &(phys_w, ppp, expect_rail) in &[
            (719.0_f32, 1.0_f32, false),
            (1024.0, 1.0, true),
            (1080.0, 1.0, true),
            (719.0, 2.0 / 3.0, false),
            (1024.0, 2.0 / 3.0, true),
            (1536.0, 1.5, true),
        ] {
            let phys_h = 756.0 * ppp;
            let mut harn = Harness::new_physical(phys_w, phys_h, ppp);
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
        let mut harn = Harness::new_physical(1024.0, 756.0, 1.5);
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
        const WIN_W: f32 = 721.0;
        const WIN_H: f32 = 759.0;
        let mut harn = Harness::new(WIN_W, WIN_H);
        harn.app.selected_id = Some("workstation".into());
        harn.pass();
        harn.pass();
        assert!(
            !model::machine_rail_visible(WIN_W),
            "721 must fold the rail"
        );
        let selected = harn.app.selected_id.clone().expect("selection");
        let labels = ["Terminal", "Files", "View desktop", "Control desktop"];
        let keys: Vec<String> = labels
            .iter()
            .map(|label| format!("action_btn:{selected}:{label}"))
            .collect();
        for key in &keys {
            assert!(
                item_rect(&harn.app.debug_layout, &format!("{key}:raw")).is_some(),
                "missing {key}:raw after 721 paint; have {:?}",
                harn.app
                    .debug_layout
                    .toolbar_items
                    .iter()
                    .map(|(k, _)| k)
                    .collect::<Vec<_>>()
            );
        }
        let cards = card_items(&harn.app.debug_layout);
        let ours: Vec<_> = cards
            .iter()
            .filter(|(id, _)| id.starts_with(&format!("action_card:{selected}:")))
            .cloned()
            .collect();
        assert_eq!(
            ours.len(),
            4,
            "desktop node should show four cards at 721, got {ours:?}"
        );
        let xs: Vec<i32> = {
            let mut v: Vec<i32> = keys
                .iter()
                .filter_map(|key| {
                    item_rect(&harn.app.debug_layout, &format!("{key}:raw"))
                        .map(|r| r[0].round() as i32)
                })
                .collect();
            v.sort();
            v.dedup();
            v
        };
        assert!(
            xs.len() <= 2,
            "721 must use one or two columns, not three: xs={xs:?}"
        );

        for key in &keys {
            let vis = item_rect(&harn.app.debug_layout, &format!("{key}:vis")).expect("vis");
            if action_vis_is_on_screen(vis) {
                assert_action_x_fully_visible(&harn.app.debug_layout, key, WIN_W);
            }
        }

        for key in &keys {
            assert!(
                scroll_action_fully_into_view(&mut harn, key),
                "could not scroll {key} fully into the 721x759 viewport; raw={:?} vis={:?} clip={:?}",
                item_rect(&harn.app.debug_layout, &format!("{key}:raw")),
                item_rect(&harn.app.debug_layout, &format!("{key}:vis")),
                harn.app.debug_layout.visible_clip
            );
            assert_action_fully_visible(&harn.app.debug_layout, key, WIN_W);
            assert_action_x_fully_visible(&harn.app.debug_layout, key, WIN_W);
        }
    }

    fn action_raw_matches_vis(raw: [f32; 4], vis: [f32; 4]) -> bool {
        (vis[0] - raw[0]).abs() <= 1.0
            && (vis[2] - raw[2]).abs() <= 1.0
            && (vis[1] - raw[1]).abs() <= 1.0
            && (vis[3] - raw[3]).abs() <= 1.0
    }

    fn scroll_action_fully_into_view(harn: &mut Harness, key: &str) -> bool {
        for _ in 0..60 {
            let raw = match item_rect(&harn.app.debug_layout, &format!("{key}:raw")) {
                Some(raw) => raw,
                None => return false,
            };
            let vis = match item_rect(&harn.app.debug_layout, &format!("{key}:vis")) {
                Some(vis) => vis,
                None => return false,
            };
            if action_raw_matches_vis(raw, vis) {
                return true;
            }
            let overflow_top = (vis[1] - raw[1]).max(0.0);
            let overflow_bottom = if action_vis_is_on_screen(vis) {
                (rect_max_y(raw) - rect_max_y(vis)).max(0.0)
            } else {
                0.0
            };
            let dy = if !action_vis_is_on_screen(vis) {
                let clip = harn.app.debug_layout.visible_clip;
                if raw[1] < clip[1] {
                    120.0
                } else {
                    -120.0
                }
            } else if overflow_top > 1.0 {
                overflow_top.min(120.0)
            } else if overflow_bottom > 1.0 {
                -overflow_bottom.min(120.0)
            } else {
                return true;
            };
            harn.scroll_content(dy);
        }
        false
    }

    #[test]
    fn narrow_721_long_offline_name_keeps_badge_in_page_width() {
        const WIN_W: f32 = 721.0;
        let mut harn = Harness::new(WIN_W, 759.0);
        let mut node = harn.app.nodes[0].clone();
        node.id = "long-offline".into();
        node.name = "Fixture · offline workstation with a long display name (sample)".into();
        node.online = false;
        harn.app.nodes.insert(0, node);
        harn.app.selected_id = Some("long-offline".into());
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
            "offline badge clipped at 721: {badge:?}"
        );
        assert!(
            name[0] + name[2] <= WIN_W + 1.0,
            "long offline name exceeds 721 page width: {name:?}"
        );
        assert!(
            badge[0] + badge[2] <= WIN_W + 1.0,
            "offline badge exceeds 721 page width: {badge:?}"
        );
        let detail_badge = item_rect(layout, "detail_badge").expect("detail badge");
        assert!(
            detail_badge[2] >= 64.0,
            "detail offline badge clipped at 721: {detail_badge:?}"
        );
        assert!(
            detail_badge[0] + detail_badge[2] <= WIN_W + 1.0,
            "detail offline badge exceeds 721 page width: {detail_badge:?}"
        );
    }

    #[test]
    fn wide_connect_cards_use_two_by_two_not_three_plus_one() {
        for (w, h) in [(1026.0, 759.0), (1080.0, 760.0), (1920.0, 1135.0)] {
            let mut harn = Harness::new(w, h);
            harn.app.selected_id = Some("workstation".into());
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
        let mut found_card = false;
        let mut found_row = false;
        for _ in 0..24 {
            harn.press_tab(false);
            let ids = harn.focused_ids();
            if ids.is_empty() {
                continue;
            }
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
            matches!(harn.app.active_tab_ref(), Some(Tab::Terminal(_))),
            "Enter on an enabled Terminal card should open a Terminal tab"
        );

        // Disabled actions must not activate. Return to Machines, select offline fixture.
        harn.app.back_to_machines(None);
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
            assert_eq!(
                harn.app.active_tab,
                MACHINES_TAB_ID,
                "Enter on a disabled card must not leave Machines tab"
            );
        } else {
            if item_rect(
                &harn.app.debug_layout,
                "action_card:preview-fixture-offline:Terminal",
            )
            .is_some()
            {
                harn.click_item("action_card:preview-fixture-offline:Terminal");
            }
            assert_eq!(
                harn.app.active_tab,
                MACHINES_TAB_ID,
                "disabled Terminal card activated"
            );
        }
    }

    fn tab_until_focus(harn: &mut Harness, id: &str, max_tabs: usize) -> bool {
        if harn.focused_ids().iter().any(|got| got == id) {
            return true;
        }
        for _ in 0..max_tabs {
            harn.press_tab(false);
            if harn.focused_ids().iter().any(|got| got == id) {
                return true;
            }
        }
        false
    }

    fn assert_painted_focus_outer_inside_clip(layout: &DebugLayout, id: &str) {
        let outer = item_rect(layout, &format!("focus_outer:{id}")).unwrap_or_else(|| {
            panic!(
                "missing painted focus_outer:{id} (need the stroke outer bounds, not an intersected vis rect); have {:?}",
                layout
                    .toolbar_items
                    .iter()
                    .map(|(k, _)| k)
                    .collect::<Vec<_>>()
            )
        });
        let clip = item_rect(layout, &format!("focus_clip:{id}")).unwrap_or_else(|| {
            panic!(
                "missing focus_clip:{id}; have {:?}",
                layout
                    .toolbar_items
                    .iter()
                    .map(|(k, _)| k)
                    .collect::<Vec<_>>()
            )
        });
        let ring = item_rect(layout, &format!("focus_ring:{id}")).expect("focus_ring");
        assert!(
            outer[2] > 2.0 && outer[3] > 2.0,
            "painted focus ring is degenerate: outer={outer:?} ring={ring:?} clip={clip:?}"
        );
        assert!(
            outer[0] >= clip[0] - 0.01,
            "{id} focus ring left edge clipped: outer={outer:?} clip={clip:?}"
        );
        assert!(
            outer[1] >= clip[1] - 0.01,
            "{id} focus ring top edge clipped: outer={outer:?} clip={clip:?}"
        );
        assert!(
            outer[0] + outer[2] <= clip[0] + clip[2] + 0.01,
            "{id} focus ring right edge clipped: outer={outer:?} clip={clip:?}"
        );
        assert!(
            outer[1] + outer[3] <= clip[1] + clip[3] + 0.01,
            "{id} focus ring bottom edge clipped: outer={outer:?} clip={clip:?}"
        );
    }

    fn scroll_item_fully_into_view(harn: &mut Harness, key: &str) -> bool {
        for _ in 0..60 {
            let raw = match item_rect(&harn.app.debug_layout, key) {
                Some(raw) => raw,
                None => return false,
            };
            let clip = harn.app.debug_layout.visible_clip;
            if raw[1] >= clip[1] - 1.0 && rect_max_y(raw) <= rect_max_y(clip) + 1.0 {
                return true;
            }
            let dy = if raw[1] < clip[1] { 120.0 } else { -120.0 };
            harn.scroll_content(dy);
        }
        false
    }

    #[test]
    fn tab_from_control_card_to_details_paints_ring_and_enter_expands() {
        for (w, h) in [(1080.0_f32, 760.0_f32), (721.0, 759.0)] {
            let mut harn = Harness::preview(w, h, super::super::LiveHooks::production());
            harn.app.selected_id = Some("preview-fixture-desktop".into());
            harn.pass();
            harn.pass();
            let control = "focus:action_card:preview-fixture-desktop:Control desktop";
            let details = "focus:details";
            assert!(
                tab_until_focus(&mut harn, control, 40),
                "never focused Control desktop at {w}x{h}: {:?}",
                harn.focused_ids()
            );
            harn.press_tab(false);
            let _ = scroll_item_fully_into_view(&mut harn, "details");
            assert!(
                harn.focused_ids().iter().any(|id| id == details),
                "Tab after Control should focus Details at {w}x{h}, got {:?}",
                harn.focused_ids()
            );
            assert_painted_focus_outer_inside_clip(&harn.app.debug_layout, "details");
            assert!(
                item_rect(&harn.app.debug_layout, "detail_node_id").is_none(),
                "Details should start collapsed at {w}x{h}"
            );
            harn.press_enter();
            assert!(
                item_rect(&harn.app.debug_layout, "detail_node_id").is_some(),
                "Enter on focused Details should expand the section at {w}x{h}"
            );
            if harn.focused_ids().iter().any(|id| id == details) {
                assert_painted_focus_outer_inside_clip(&harn.app.debug_layout, "details");
            }
        }
    }

    #[test]
    fn machine_row_focus_ring_stays_inside_clip_on_rail_and_narrow_list() {
        for (w, h) in [(1080.0_f32, 760.0_f32), (1026.0, 759.0), (721.0, 759.0)] {
            let mut harn = Harness::new(w, h);
            harn.app.selected_id = Some("workstation".into());
            harn.pass();
            harn.pass();
            if w >= model::MACHINE_RAIL_SHOW_AT {
                assert!(
                    model::machine_rail_visible(w),
                    "expected a {0} pt rail at {w}",
                    model::MACHINE_RAIL_WIDTH
                );
            } else {
                assert!(!model::machine_rail_visible(w), "721 must fold the rail");
            }
            let mut row_id = None;
            for _ in 0..32 {
                harn.press_tab(false);
                if let Some(id) = harn
                    .focused_ids()
                    .into_iter()
                    .find(|id| id.starts_with("focus:nav_row:"))
                {
                    row_id = Some(id.trim_start_matches("focus:").to_string());
                    break;
                }
            }
            let row_id = row_id.unwrap_or_else(|| {
                panic!(
                    "never focused a machine row at {w}x{h}: {:?}",
                    harn.focused_ids()
                )
            });
            let _ = scroll_item_fully_into_view(&mut harn, &row_id);
            assert_painted_focus_outer_inside_clip(&harn.app.debug_layout, &row_id);
        }
    }

    fn drain_mouse_inputs(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    ) -> Vec<(String, String, f64, f64)> {
        let mut out = Vec::new();
        while let Ok(cmd) = rx.try_recv() {
            let Cmd::Input { inject, .. } = cmd else {
                continue;
            };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&inject) else {
                continue;
            };
            let action = v
                .get("action")
                .and_then(|a| a.as_str())
                .unwrap_or("")
                .to_string();
            let button = v
                .get("button")
                .and_then(|b| b.as_str())
                .unwrap_or("")
                .to_string();
            let x = v.get("x").and_then(|x| x.as_f64()).unwrap_or(0.0);
            let y = v.get("y").and_then(|y| y.as_f64()).unwrap_or(0.0);
            out.push((action, button, x, y));
        }
        out
    }

    fn content_center(layout: &DebugLayout) -> egui::Pos2 {
        let r = layout.content_rect;
        assert!(
            r[2] > 8.0 && r[3] > 8.0,
            "content_rect missing/small: {r:?}"
        );
        egui::pos2(r[0] + r[2] * 0.5, r[1] + r[3] * 0.5)
    }

    fn right_click_at(harn: &mut Harness, pos: egui::Pos2, shift: bool) {
        let mut modifiers = egui::Modifiers::default();
        modifiers.shift = shift;
        secondary_click_at(harn, pos, modifiers);
    }

    fn secondary_click_at(harn: &mut Harness, pos: egui::Pos2, modifiers: egui::Modifiers) {
        harn.pending_events.push(egui::Event::PointerMoved(pos));
        harn.pass();
        let _ = drain_mouse_inputs(&mut harn.cmd_rx);
        harn.pending_events.push(egui::Event::PointerMoved(pos));
        harn.pending_events.push(egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Secondary,
            pressed: true,
            modifiers,
        });
        harn.pass();
        harn.pending_events.push(egui::Event::PointerMoved(pos));
        harn.pending_events.push(egui::Event::PointerButton {
            pos,
            button: egui::PointerButton::Secondary,
            pressed: false,
            modifiers,
        });
        harn.pass();
    }

    #[test]
    fn controllable_image_plain_and_shift_right_click_go_remote() {
        let mut harn = Harness::new(1280.0, 800.0);
        let desk = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("workstation");
        harn.app.open_desktop_tab(&desk, true);
        harn.pass();
        harn.pass();
        assert!(
            harn.active_desktop().texture.is_some(),
            "mock desktop texture required for pointer tests"
        );
        let pos = content_center(&harn.app.debug_layout);
        let _ = drain_mouse_inputs(&mut harn.cmd_rx);

        right_click_at(&mut harn, pos, false);
        let plain = drain_mouse_inputs(&mut harn.cmd_rx);
        assert!(
            plain.iter().any(|(a, b, _, _)| a == "down" && b == "right"),
            "plain right-click must inject secondary down: {plain:?}"
        );
        assert!(
            plain.iter().any(|(a, b, _, _)| a == "up" && b == "right"),
            "plain right-click must inject secondary up: {plain:?}"
        );
        let down_idx = plain
            .iter()
            .position(|(a, b, _, _)| a == "down" && b == "right")
            .expect("down");
        assert!(
            plain[..down_idx].iter().any(|(a, _, _, _)| a == "move"),
            "move-before-click ordering missing before secondary down: {plain:?}"
        );

        right_click_at(&mut harn, pos, true);
        let shifted = drain_mouse_inputs(&mut harn.cmd_rx);
        assert!(
            shifted
                .iter()
                .any(|(a, b, _, _)| a == "down" && b == "right"),
            "Shift+right must also inject secondary down: {shifted:?}"
        );
        assert!(
            shifted.iter().any(|(a, b, _, _)| a == "up" && b == "right"),
            "Shift+right must also inject secondary up: {shifted:?}"
        );
    }

    #[test]
    fn controllable_image_ctrl_right_click_goes_remote() {
        let mut harn = Harness::new(1280.0, 800.0);
        let desk = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("workstation");
        harn.app.open_desktop_tab(&desk, true);
        harn.pass();
        harn.pass();
        let pos = content_center(&harn.app.debug_layout);
        let _ = drain_mouse_inputs(&mut harn.cmd_rx);
        let mut modifiers = egui::Modifiers::default();
        modifiers.ctrl = true;
        secondary_click_at(&mut harn, pos, modifiers);
        let events = drain_mouse_inputs(&mut harn.cmd_rx);
        assert!(
            events
                .iter()
                .any(|(a, b, _, _)| a == "down" && b == "right"),
            "Ctrl+right must inject secondary down inside image: {events:?}"
        );
        assert!(
            events.iter().any(|(a, b, _, _)| a == "up" && b == "right"),
            "Ctrl+right must inject secondary up inside image: {events:?}"
        );
    }

    #[test]
    fn view_only_desktop_does_not_inject_right_click() {
        let mut harn = Harness::new(1280.0, 800.0);
        let desk = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("workstation");
        harn.app.open_desktop_tab(&desk, false);
        harn.pass();
        harn.pass();
        assert!(harn.active_desktop().texture.is_some());
        let pos = content_center(&harn.app.debug_layout);
        let _ = drain_mouse_inputs(&mut harn.cmd_rx);
        right_click_at(&mut harn, pos, false);
        let events = drain_mouse_inputs(&mut harn.cmd_rx);
        assert!(
            events
                .iter()
                .all(|(a, b, _, _)| !(b == "right" && (a == "down" || a == "up"))),
            "view-only must never inject remote right button: {events:?}"
        );
    }

    fn drain_key_inputs(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Cmd>) -> Vec<(String, Option<bool>)> {
        let mut out = Vec::new();
        while let Ok(cmd) = rx.try_recv() {
            if let Cmd::Input { inject, .. } = cmd {
                let Ok(val) = serde_json::from_str::<serde_json::Value>(&inject) else {
                    continue;
                };
                if val.get("action").and_then(|v| v.as_str()) == Some("key") {
                    let keys = val
                        .get("keys")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let down = val.get("down").and_then(|v| v.as_bool());
                    out.push((keys, down));
                }
            }
        }
        out
    }

    #[test]
    fn egui_key_table_maps_shifted_punctuation_and_f1_through_f24() {
        for &key in egui::Key::ALL {
            if matches!(
                key,
                egui::Key::F25
                    | egui::Key::F26
                    | egui::Key::F27
                    | egui::Key::F28
                    | egui::Key::F29
                    | egui::Key::F30
                    | egui::Key::F31
                    | egui::Key::F32
                    | egui::Key::F33
                    | egui::Key::F34
                    | egui::Key::F35
            ) {
                continue;
            }
            assert!(
                egui_key_name(key).is_some(),
                "egui::Key::{key:?} must be mapped in egui_key_name"
            );
        }
    }

    #[test]
    fn captured_desktop_releases_held_keys_on_window_focus_loss_and_pairs_shifted_plus() {
        let mut harn = Harness::new(1280.0, 800.0);
        let desk = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("desktop fixture");
        let did = harn.app.open_desktop_tab(&desk, true);
        harn.pass();
        harn.pass();
        harn.app.desktop_by_id_mut(did).unwrap().capture_keys = true;
        harn.pass();
        let _ = drain_key_inputs(&mut harn.cmd_rx);

        let mut shift_mods = egui::Modifiers::default();
        shift_mods.shift = true;
        harn.pending_events.push(egui::Event::Key {
            key: egui::Key::Plus,
            physical_key: Some(egui::Key::Equals),
            pressed: true,
            repeat: false,
            modifiers: shift_mods,
        });
        harn.pass();
        harn.pending_events.push(egui::Event::Key {
            key: egui::Key::Equals,
            physical_key: Some(egui::Key::Equals),
            pressed: false,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        harn.pass();
        let edges = drain_key_inputs(&mut harn.cmd_rx);
        assert!(edges.contains(&("+".into(), Some(true))), "{edges:?}");
        assert!(edges.contains(&("+".into(), Some(false))), "{edges:?}");
        assert!(
            !harn.active_desktop().held_keys.contains("+"),
            "shifted '+' must not stay stuck: {:?}",
            harn.active_desktop().held_keys
        );

        harn.pending_events.push(egui::Event::Key {
            key: egui::Key::A,
            physical_key: Some(egui::Key::A),
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        });
        harn.pass();
        assert!(harn.active_desktop().held_keys.contains("a"));
        let _ = drain_key_inputs(&mut harn.cmd_rx);

        harn.pending_events.push(egui::Event::WindowFocused(false));
        harn.pass();
        let released = drain_key_inputs(&mut harn.cmd_rx);
        assert!(!harn.active_desktop().capture_keys, "focus loss must drop capture");
        assert!(harn.active_desktop().held_keys.is_empty());
        assert!(
            released.contains(&("a".into(), Some(false))),
            "focus loss must emit key-up for held keys: {released:?}"
        );
    }

    #[test]
    fn terminal_reopens_after_exit_and_clears_spinner_on_pty_open_failure() {
        let mut harn = Harness::new(1280.0, 800.0);
        let node = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("fixture node");
        while harn.cmd_rx.try_recv().is_ok() {}

        // 1. Open terminal -> shell sends output -> shell exits (`exit` -> PtyDone).
        let tid = harn.app.open_terminal_tab(&node);
        let gen1 = harn.active_terminal().gen;
        let mut saw_open_1 = false;
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            if matches!(cmd, Cmd::PtyOpen { gen, .. } if gen == gen1) {
                saw_open_1 = true;
            }
        }
        assert!(saw_open_1);
        harn.app.shared.push(UiEvent::Pty {
            gen: gen1,
            bytes: b"sufa$ ".to_vec(),
        });
        harn.pass();
        assert!(harn.active_terminal().got_output);
        harn.app.shared.push(UiEvent::PtyExited {
            gen: gen1,
            code: 130,
        });
        harn.app.shared.push(UiEvent::PtyDone { gen: gen1 });
        harn.pass();
        assert_eq!(harn.active_terminal().notice, "Shell exited (130)");
        assert_eq!(harn.active_terminal().exited, Some(130));

        // Restarting the shell tab emits a fresh Cmd::PtyOpen AND clears the stale notice!
        harn.app.restart_terminal_tab(tid);
        let gen2 = harn.active_terminal().gen;
        assert_ne!(gen1, gen2);
        assert!(
            harn.active_terminal().notice.is_empty(),
            "stale shell exit notice survived restart: {:?}",
            harn.active_terminal().notice
        );
        let mut saw_open_2 = false;
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            if matches!(cmd, Cmd::PtyOpen { gen, .. } if gen == gen2) {
                saw_open_2 = true;
            }
        }
        assert!(saw_open_2, "restart_terminal_tab did not send Cmd::PtyOpen!");

        // Stale exit/done events from `gen1` arriving late MUST NOT clobber `gen2`!
        harn.app.shared.push(UiEvent::PtyExited {
            gen: gen1,
            code: 130,
        });
        harn.app.shared.push(UiEvent::PtyDone { gen: gen1 });
        harn.pass();
        assert!(
            harn.active_terminal().alive && harn.active_terminal().notice.is_empty(),
            "late gen1 event clobbered active gen2 shell"
        );

        // 2. When PtyOpen fails, UiEvent::PtyFailed + PtyDone MUST clear spinner and allow retry!
        harn.app.shared.push(UiEvent::PtyFailed {
            gen: gen2,
            message: "node offline: workstation".into(),
        });
        harn.app.shared.push(UiEvent::PtyDone { gen: gen2 });
        harn.pass();
        assert!(
            harn.active_terminal().open.is_none() && !harn.active_terminal().alive,
            "PtyFailed left open/alive stuck!"
        );
        harn.app.restart_terminal_tab(tid);
        let gen3 = harn.active_terminal().gen;
        let mut saw_open_3 = false;
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            if matches!(cmd, Cmd::PtyOpen { gen, .. } if gen == gen3) {
                saw_open_3 = true;
            }
        }
        assert!(saw_open_3, "restart after Failed did not retry Cmd::PtyOpen!");
    }

    #[test]
    fn terminal_window_refocus_probes_liveness_and_restart_shell_preserves_terminal_focus() {
        let mut harn = Harness::new(1280.0, 800.0);
        let node = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("fixture node");
        while harn.cmd_rx.try_recv().is_ok() {}

        let tid = harn.app.open_terminal_tab(&node);
        let gen1 = harn.active_terminal().gen;
        while harn.cmd_rx.try_recv().is_ok() {}
        harn.app.shared.push(UiEvent::Pty {
            gen: gen1,
            bytes: b"ltl@surf:~$ ".to_vec(),
        });
        harn.pass();
        assert!(harn.active_terminal().alive);
        assert!(harn.active_terminal().emulator.focused);

        let mut unfocus = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            focused: false,
            ..Default::default()
        };
        let _ = harn.ctx.run(unfocus.take(), |ctx| harn.app.ui_frame(ctx));
        while harn.cmd_rx.try_recv().is_ok() {}

        let mut refocus = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            focused: true,
            ..Default::default()
        };
        let _ = harn.ctx.run(refocus.take(), |ctx| harn.app.ui_frame(ctx));
        let mut saw_probe = false;
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            if matches!(cmd, Cmd::PtyProbeGen { gen } if gen == gen1) {
                saw_probe = true;
            }
        }
        assert!(
            saw_probe,
            "regaining OS window focus on active Terminal did not emit Cmd::PtyProbeGen!"
        );

        harn.app.terminal_by_id_mut(tid).unwrap().notice = "Shell exited (130)".into();
        harn.app.restart_terminal_tab(tid);
        let gen2 = harn.active_terminal().gen;
        assert_eq!(gen2, gen1 + 1);
        assert!(harn.active_terminal().notice.is_empty());
        assert!(harn.active_terminal().emulator.focused);
        let mut saw_restart_open = false;
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            if matches!(cmd, Cmd::PtyOpen { gen, .. } if gen == gen2) {
                saw_restart_open = true;
            }
        }
        assert!(saw_restart_open, "Restart shell did not send Cmd::PtyOpen!");
    }

    #[test]
    fn desktop_ctrl_key_does_not_set_meta_modifier_desk_01() {
        let mut harn = Harness::new(1280.0, 800.0);
        let desk = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("workstation");
        let did = harn.app.open_desktop_tab(&desk, true);
        harn.app.desktop_by_id_mut(did).unwrap().capture_keys = true;
        harn.pass();
        while harn.cmd_rx.try_recv().is_ok() {}

        let modifiers = egui::Modifiers {
            ctrl: true,
            command: true,
            mac_cmd: false,
            ..Default::default()
        };
        let mut raw = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            modifiers,
            events: vec![egui::Event::Key {
                key: egui::Key::D,
                physical_key: Some(egui::Key::D),
                pressed: true,
                repeat: false,
                modifiers,
            }],
            ..Default::default()
        };
        let _ = harn.ctx.run(raw.take(), |ctx| harn.app.ui_frame(ctx));
        let keys = drain_key_inputs(&mut harn.cmd_rx);
        assert!(
            keys.iter().any(|(k, down)| k == "ctrl" && *down == Some(true))
                && keys.iter().any(|(k, down)| k == "d" && *down == Some(true)),
            "Ctrl+D on Windows/Linux must press 'ctrl' and 'd' without 'meta': {keys:?}"
        );
        assert!(
            keys.iter().all(|(k, _)| !k.contains("meta") && !k.contains("super") && !k.contains("win")),
            "Ctrl+D must NEVER emit Win/Meta modifier: {keys:?}"
        );
    }

    #[test]
    fn desktop_ungrab_chord_releases_capture_without_remote_injection_desk_12() {
        let mut harn = Harness::new(1280.0, 800.0);
        let desk = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("workstation");
        let did = harn.app.open_desktop_tab(&desk, true);
        harn.app.desktop_by_id_mut(did).unwrap().capture_keys = true;
        harn.pass();
        while harn.cmd_rx.try_recv().is_ok() {}

        let chord = egui::Modifiers {
            ctrl: true,
            alt: true,
            shift: true,
            command: true,
            mac_cmd: false,
        };
        let mut arm = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            modifiers: chord,
            ..Default::default()
        };
        let _ = harn.ctx.run(arm.take(), |ctx| harn.app.ui_frame(ctx));
        assert!(harn.active_desktop().capture_keys);

        let mut release = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1280.0, 800.0),
            )),
            modifiers: egui::Modifiers::default(),
            ..Default::default()
        };
        let _ = harn.ctx.run(release.take(), |ctx| harn.app.ui_frame(ctx));
        assert!(
            !harn.active_desktop().capture_keys,
            "Releasing Ctrl+Alt+Shift must release keyboard capture"
        );
    }

    #[test]
    fn nodes_loaded_and_parked_terminal_switch_preserve_session_desk_09_10() {
        let mut harn = Harness::new(1280.0, 800.0);
        let template = harn
            .app
            .nodes
            .iter()
            .find(|n| n.id == "workstation")
            .cloned()
            .expect("workstation fixture");
        harn.app.nodes_loaded = false;
        harn.app.shared.push(UiEvent::Nodes(Vec::new()));
        harn.pass();
        assert!(
            harn.app.nodes_loaded,
            "Empty UiEvent::Nodes must flip nodes_loaded=true so spinner stops"
        );

        let mut node_a = template.clone();
        node_a.id = "node-a".into();
        node_a.name = "Alpha".into();
        node_a.online = true;
        let mut node_b = template;
        node_b.id = "node-b".into();
        node_b.name = "Beta".into();
        node_b.online = true;
        harn.app.nodes = vec![node_a.clone(), node_b.clone()];
        harn.app.prefs.allow_osc52 = true;
        let tab_a = harn.app.open_terminal_tab(&node_a);
        let gen_a = harn.active_terminal().gen;
        assert!(harn.active_terminal().emulator.allows_osc52());
        harn.app.shared.push(UiEvent::Pty {
            gen: gen_a,
            bytes: b"alpha$ ".to_vec(),
        });
        harn.pass();
        assert!(harn.active_terminal().alive);
        while harn.cmd_rx.try_recv().is_ok() {}

        // Open node B terminal tab -> node A tab remains open & alive, NOT closed!
        let _tab_b = harn.app.open_terminal_tab(&node_b);
        let gen_b = harn.active_terminal().gen;
        assert_ne!(gen_a, gen_b);
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            assert!(
                !matches!(cmd, Cmd::PtyClose | Cmd::PtyCloseGen { .. } | Cmd::PtyCloseAll),
                "opening node B tab must preserve node A PTY"
            );
        }

        // Switch back to tab_a -> restores gen_a without reopening a duplicate PTY!
        harn.app.activate_tab(None, tab_a);
        assert_eq!(harn.active_terminal().gen, gen_a);
        assert!(harn.active_terminal().alive);
        assert!(harn.active_terminal().emulator.allows_osc52());
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            assert!(
                !matches!(cmd, Cmd::PtyOpen { .. }),
                "switching back to tab A must not spawn a duplicate PTY"
            );
        }
    }

    #[test]
    fn read_only_file_preview_and_auth_expiry_redirect_desk_02_10() {
        let mut harn = Harness::new(1280.0, 800.0);
        let node = harn.app.nodes[0].clone();
        let fid = harn.app.open_files_tab(&node);
        harn.app.shared.push(UiEvent::File {
            session: fid,
            file: super::model::LoadedFile {
                path: "/tmp/huge.log".into(),
                text: "preview only".into(),
                total_size: Some(512 * 1024),
                read_only: true,
                read_only_reason: Some("File exceeds 256 KiB.".into()),
            },
        });
        harn.pass();
        let ed = harn
            .active_files()
            .editor
            .as_ref()
            .expect("editor loaded");
        assert!(ed.read_only);
        assert_eq!(ed.saved_text, "preview only");

        // Auth expiry error must kick the user back to AuthScreen::Login and close all tabs (`DESK-10`).
        harn.app.mock = false;
        harn.app.preview_ui = false;
        harn.app.back_to_machines(None);
        harn.app
            .shared
            .push(UiEvent::Failed("401 unauthorized: refresh token expired".into()));
        harn.pass();
        assert!(
            matches!(harn.app.auth, AuthScreen::Login),
            "expired auth error must return to AuthScreen::Login"
        );
        assert!(
            harn.app.tabs.is_empty(),
            "expired auth error must tear down all open tabs"
        );
    }

    #[test]
    fn multi_tab_terminals_same_and_different_nodes_stay_isolated() {
        let mut harn = Harness::new(1280.0, 800.0);
        let node_a = harn.app.nodes[0].clone(); // quant67
        let node_b = harn.app.nodes[1].clone(); // workstation

        let t1 = harn.app.open_terminal_tab(&node_a);
        let g1 = harn.active_terminal().gen;
        let t2 = harn.app.open_terminal_tab(&node_a);
        let g2 = harn.active_terminal().gen;
        let t3 = harn.app.open_terminal_tab(&node_b);
        let g3 = harn.active_terminal().gen;

        assert_ne!(t1, t2);
        assert_ne!(t2, t3);
        assert_ne!(g1, g2);
        assert_ne!(g2, g3);
        assert_eq!(harn.app.tabs.len(), 3);

        // Same-node terminals are disambiguated, different-node terminal stays plain.
        let labels = harn.app.compute_tab_labels();
        assert_eq!(labels[0], (t1, "quant67 (1)".to_string()));
        assert_eq!(labels[1], (t2, "quant67 (2)".to_string()));
        assert_eq!(labels[2], (t3, "workstation".to_string()));

        // Routing: output for g2 must mark only t2 as having output without disturbing t1/t3.
        harn.app.shared.push(UiEvent::Pty {
            gen: g2,
            bytes: b"tab2-only\r\n".to_vec(),
        });
        harn.pass();
        assert!(!harn.app.terminal_by_id_mut(t1).unwrap().got_output);
        assert!(harn.app.terminal_by_id_mut(t2).unwrap().got_output);
        assert!(!harn.app.terminal_by_id_mut(t3).unwrap().got_output);

        // Closing t1 closes only g1 while leaving t2 and t3 open and intact.
        while harn.cmd_rx.try_recv().is_ok() {}
        harn.app.force_close_tab(None, t1);
        let mut closed_gens = Vec::new();
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            if let Cmd::PtyCloseGen { gen } = cmd {
                closed_gens.push(gen);
            }
        }
        assert_eq!(closed_gens, vec![g1]);
        assert_eq!(harn.app.tabs.len(), 2);
        assert_eq!(
            harn.app.compute_tab_labels(),
            vec![
                (t2, "quant67".to_string()),
                (t3, "workstation".to_string()),
            ]
        );
    }

    #[test]
    fn mixed_terminal_and_desktop_tabs_switch_without_disconnecting() {
        let mut harn = Harness::new(1280.0, 800.0);
        let quant = harn.app.nodes[0].clone();
        let desk = harn.app.nodes[1].clone();

        let term_id = harn.app.open_terminal_tab(&quant);
        let desk_id = harn.app.open_desktop_tab(&desk, true);
        let files_id = harn.app.open_files_tab(&quant);
        harn.pass();
        while harn.cmd_rx.try_recv().is_ok() {}

        // Switching across Desktop, Terminal, Files, and Machines sends zero closes/stops.
        harn.app.activate_tab(None, desk_id);
        assert_eq!(harn.app.active_tab, desk_id);
        harn.app.activate_tab(None, term_id);
        assert_eq!(harn.app.active_tab, term_id);
        harn.app.activate_tab(None, files_id);
        assert_eq!(harn.app.active_tab, files_id);
        harn.app.activate_tab(None, MACHINES_TAB_ID);
        assert_eq!(harn.app.active_tab, MACHINES_TAB_ID);
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            assert!(
                !matches!(
                    cmd,
                    Cmd::PtyClose | Cmd::PtyCloseGen { .. } | Cmd::PtyCloseAll | Cmd::LiveStopSession { .. } | Cmd::LiveStop
                ),
                "switching tabs must never tear down background sessions: got close cmd"
            );
        }
        assert_eq!(harn.app.tabs.len(), 3);

        // Background desktop slot still accepts frames without clobbering state.
        harn.app.mock = false;
        harn.app.shared.set_picture_for(
            desk_id,
            vec![12, 34, 56, 255].repeat(4),
            2,
            2,
            "live",
            "webrtc",
        );
        harn.pass();
        let desk_tab = harn.app.desktop_by_id_mut(desk_id).unwrap();
        assert!(desk_tab.last_frame.is_some());
        assert!(desk_tab.texture.is_some());
        assert!(!desk_tab.connect_failed);
    }

    #[test]
    fn multiple_concurrent_desktop_tabs_isolate_sessions_and_close_independently() {
        let mut harn = Harness::new(1280.0, 800.0);
        harn.app.mock = false;
        let mut d1_node = harn.app.nodes[1].clone();
        d1_node.id = "desk-alpha".into();
        d1_node.name = "DeskAlpha".into();
        let mut d2_node = harn.app.nodes[1].clone();
        d2_node.id = "desk-beta".into();
        d2_node.name = "DeskBeta".into();
        harn.app.nodes.push(d1_node.clone());
        harn.app.nodes.push(d2_node.clone());

        let s1 = harn.app.open_desktop_tab(&d1_node, true);
        let s2 = harn.app.open_desktop_tab(&d2_node, false);
        assert_ne!(s1, s2);

        let mut live_sessions = Vec::new();
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            if let Cmd::Live { session, node, control, .. } = cmd {
                live_sessions.push((session, node, control));
            }
        }
        assert_eq!(
            live_sessions,
            vec![
                (s1, "desk-alpha".to_string(), true),
                (s2, "desk-beta".to_string(), false),
            ]
        );

        harn.app.shared.push(UiEvent::Handshake {
            session: s1,
            stage: "alpha-ice".into(),
        });
        harn.app.shared.push(UiEvent::Handshake {
            session: s2,
            stage: "beta-webrtc".into(),
        });
        harn.app.shared.set_picture_for(
            s1,
            vec![200, 10, 10, 255].repeat(4),
            2,
            2,
            "live",
            "webrtc",
        );
        harn.app.shared.set_picture_for(
            s2,
            vec![10, 10, 200, 255].repeat(4),
            2,
            2,
            "live",
            "relay",
        );
        harn.pass();

        assert_eq!(
            harn.app.desktop_by_id_mut(s1).unwrap().hud.handshake,
            "alpha-ice"
        );
        assert_eq!(
            harn.app.desktop_by_id_mut(s2).unwrap().hud.handshake,
            "beta-webrtc"
        );

        while harn.cmd_rx.try_recv().is_ok() {}
        harn.app.force_close_tab(None, s1);
        let mut stopped = Vec::new();
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            if let Cmd::LiveStopSession { session } = cmd {
                stopped.push(session);
            }
        }
        assert_eq!(stopped, vec![s1]);
        assert!(harn.app.desktop_by_id_mut(s1).is_none());
        assert!(harn.app.desktop_by_id_mut(s2).is_some());
        assert_eq!(harn.app.active_tab, s2);
    }

    #[test]
    fn windows_terminal_shortcuts_manage_tabs_without_leaking_to_pty_or_captured_desktop() {
        let mut harn = Harness::new(1280.0, 800.0);
        let ctrl_shift = egui::Modifiers {
            ctrl: true,
            shift: true,
            command: true,
            ..Default::default()
        };
        let ctrl_only = egui::Modifiers {
            ctrl: true,
            command: true,
            ..Default::default()
        };

        harn.pass();
        while harn.cmd_rx.try_recv().is_ok() {}

        // 1. Ctrl+Shift+T opens a terminal tab.
        harn.press_key(egui::Key::T, ctrl_shift);
        assert_eq!(harn.app.tabs.len(), 1);
        let t1 = harn.app.active_tab;
        assert!(matches!(harn.app.active_tab_ref(), Some(Tab::Terminal(_))));

        // 2. Ctrl+Shift+T again opens a second terminal tab; none leak as PtyWriteGen.
        harn.press_key(egui::Key::T, ctrl_shift);
        assert_eq!(harn.app.tabs.len(), 2);
        let t2 = harn.app.active_tab;
        assert_ne!(t1, t2);
        while let Ok(cmd) = harn.cmd_rx.try_recv() {
            assert!(
                !matches!(cmd, Cmd::PtyWrite { .. } | Cmd::PtyWriteGen { .. }),
                "tab shortcut must be stripped before PTY input"
            );
        }

        // 3. Ctrl+Tab / Ctrl+Shift+Tab cycle Machines -> t1 -> t2 -> Machines.
        harn.press_key(egui::Key::Tab, ctrl_only);
        assert_eq!(harn.app.active_tab, MACHINES_TAB_ID);
        harn.press_key(egui::Key::Tab, ctrl_only);
        assert_eq!(harn.app.active_tab, t1);
        harn.press_key(egui::Key::Tab, ctrl_shift);
        assert_eq!(harn.app.active_tab, MACHINES_TAB_ID);

        // 4. Ctrl+, opens singleton Settings tab.
        harn.press_key(egui::Key::Comma, ctrl_only);
        let s_id = harn.app.active_tab;
        assert!(matches!(
            harn.app.active_tab_ref(),
            Some(Tab::Settings { .. })
        ));
        harn.press_key(egui::Key::Comma, ctrl_only);
        assert_eq!(harn.app.tabs.len(), 3);
        assert_eq!(harn.app.active_tab, s_id);

        // 5. Ctrl+Shift+M jumps directly to Machines tab.
        harn.press_key(egui::Key::M, ctrl_shift);
        assert_eq!(harn.app.active_tab, MACHINES_TAB_ID);

        // 6. Ctrl+Shift+W closes Settings tab when active, does nothing on Machines.
        harn.press_key(egui::Key::W, ctrl_shift);
        assert_eq!(harn.app.tabs.len(), 3); // Machines cannot be closed
        harn.app.activate_tab(None, s_id);
        harn.press_key(egui::Key::W, ctrl_shift);
        assert_eq!(harn.app.tabs.len(), 2);

        // 7. When a Desktop tab has capture_keys==true, shortcuts are NOT intercepted locally.
        let desk = harn.app.nodes[1].clone();
        let did = harn.app.open_desktop_tab(&desk, true);
        harn.pass();
        harn.app.desktop_by_id_mut(did).unwrap().capture_keys = true;
        while harn.cmd_rx.try_recv().is_ok() {}
        let tabs_before = harn.app.tabs.len();
        harn.press_key(egui::Key::W, ctrl_shift);
        assert_eq!(
            harn.app.tabs.len(),
            tabs_before,
            "Ctrl+Shift+W must NOT close captured Desktop tab"
        );
        assert_eq!(harn.app.active_tab, did);
        let forwarded = drain_key_inputs(&mut harn.cmd_rx);
        assert!(
            forwarded.iter().any(|(k, down)| k == "w" && *down == Some(true)),
            "captured Ctrl+Shift+W should forward to remote Desktop: {forwarded:?}"
        );
    }

    #[test]
    fn closing_dirty_files_tab_prompts_before_discarding() {
        let mut harn = Harness::new(1280.0, 800.0);
        let node = harn.app.nodes[0].clone();
        let fid = harn.app.open_files_tab(&node);
        harn.populate_files(fid);
        {
            let f = harn.app.files_by_id_mut(fid).unwrap();
            f.editor.as_mut().unwrap().text.push_str("unsaved edit\n");
        }
        harn.pass();

        harn.app.request_close_tab(None, fid);
        assert_eq!(
            harn.app.tabs.len(),
            1,
            "dirty files tab must NOT close before user confirmation"
        );
        assert!(
            matches!(
                harn.app.files_by_id_mut(fid).unwrap().pending_nav,
                Some(PendingFileNav::CloseTab)
            ),
            "pending_nav must record PendingFileNav::CloseTab"
        );
        harn.pass();

        // Confirming discard closes the tab cleanly.
        let ctx = harn.ctx.clone();
        harn.app.files_by_id_mut(fid).unwrap().pending_nav = None;
        harn.app.apply_file_nav_for(fid, &ctx, PendingFileNav::CloseTab);
        assert!(harn.app.tabs.is_empty());
        assert_eq!(harn.app.active_tab, MACHINES_TAB_ID);
    }

    #[test]
    fn tab_bar_fits_narrow_and_many_tabs_without_overflow() {
        const WIN_W: f32 = 640.0;
        const WIN_H: f32 = 480.0;
        let mut harn = Harness::new(WIN_W, WIN_H);
        let quant = harn.app.nodes[0].clone();
        for _ in 0..8 {
            harn.app.open_terminal_tab(&quant);
        }
        harn.pass();
        harn.pass();

        let layout = &harn.app.debug_layout;
        assert_tab_bar_visible(layout, (WIN_W, WIN_H));
        assert_no_overflow(layout, WIN_W, WIN_H);

        let top_level: Vec<&(String, [f32; 4])> = layout
            .tab_items
            .iter()
            .filter(|(id, r)| !id.starts_with("tab_close:") && r[2] > 0.5 && r[3] > 0.5)
            .collect();
        for i in 0..top_level.len() {
            let (id_a, a) = top_level[i];
            assert!(
                a[0] >= -1.0 && a[0] + a[2] <= WIN_W + 1.5,
                "tab item {id_a} out of bounds: {a:?}"
            );
            for (id_b, b) in &top_level[i + 1..] {
                let overlap_x = a[0] < b[0] + b[2] - 0.5 && a[0] + a[2] > b[0] + 0.5;
                let overlap_y = a[1] < b[1] + b[3] - 0.5 && a[1] + a[3] > b[1] + 0.5;
                assert!(
                    !(overlap_x && overlap_y),
                    "tab bar items overlap: {id_a}={a:?} vs {id_b}={b:?}"
                );
            }
        }
    }
}
