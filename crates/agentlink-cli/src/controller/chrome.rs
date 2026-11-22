//! RDP-style session chrome: connection-bar layout and status math.
//!
//! Presentation lives in [`super::ui`]; this module stays free of egui widgets so
//! the bar state, auto-hide, and stats formatting can be unit-tested. A zero-height
//! tab-strip hook is reserved for a future multi-session client.

use std::time::Duration;

use super::theme;

/// Outer window / letterbox behind the remote picture.
pub const SESSION_BG: (u8, u8, u8) = theme::RGB_BG_PAGE;
/// Connection bar fill.
pub const BAR_BG: (u8, u8, u8) = theme::RGB_BG_PANEL;
/// Compact control hover.
pub const BAR_HOVER: (u8, u8, u8) = theme::RGB_BG_HOVER;
/// 1px hairline under the bar (approximates `border.subtle` for RGB consumers).
pub const BAR_EDGE: (u8, u8, u8) = (0x28, 0x28, 0x2c);
/// Primary label.
pub const TEXT: (u8, u8, u8) = theme::RGB_TEXT_BODY;
/// Secondary / stats.
pub const TEXT_DIM: (u8, u8, u8) = theme::RGB_TEXT_MUTED;
/// Accent (links, active capture).
pub const ACCENT: (u8, u8, u8) = theme::RGB_ACCENT;
/// Connected status.
pub const STATUS_OK: (u8, u8, u8) = theme::RGB_SUCCESS;
/// Reconnecting / connecting.
pub const STATUS_WARN: (u8, u8, u8) = theme::RGB_WARN;
/// Disconnected / fatal.
pub const STATUS_ERR: (u8, u8, u8) = theme::RGB_DANGER;

/// Target connection-bar height in points.
pub const BAR_HEIGHT: f32 = theme::BAR_HEIGHT;
/// Hide the bar after this idle time while fullscreen.
pub const BAR_HIDE_AFTER: Duration = Duration::from_secs(3);
/// Pointer within this many points of the top edge reveals the bar.
pub const BAR_REVEAL_PAD: f32 = 4.0;
/// Stale-frame toast after this silence.
pub const FRAME_STALE_AFTER: Duration = Duration::from_secs(3);

/// Traffic-light state shown next to the node name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnDot {
    Connected,
    Reconnecting,
    Disconnected,
}

impl ConnDot {
    pub fn rgb(self) -> (u8, u8, u8) {
        match self {
            Self::Connected => STATUS_OK,
            Self::Reconnecting => STATUS_WARN,
            Self::Disconnected => STATUS_ERR,
        }
    }

    pub fn tooltip<'a>(self, error: &'a str) -> &'a str {
        match self {
            Self::Connected => "Connected",
            Self::Reconnecting => {
                if error.is_empty() {
                    "Connecting…"
                } else {
                    error
                }
            }
            Self::Disconnected => {
                if error.is_empty() {
                    "Disconnected"
                } else {
                    error
                }
            }
        }
    }
}

/// High-level session surface behind the picture.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionPhase {
    /// Offer / JPEG bootstrap in flight; no picture yet.
    Connecting,
    /// At least one frame is on screen.
    Live,
    /// Picture exists but no fresh frame for a while (toast only).
    Stale,
    /// Connect timed out, peer failed/closed, or the node rejected the session.
    Failed,
    /// User stopped the session (Disconnect / Back).
    Disconnected,
}

impl SessionPhase {
    pub fn dot(self) -> ConnDot {
        match self {
            Self::Connecting | Self::Stale => ConnDot::Reconnecting,
            Self::Live => ConnDot::Connected,
            Self::Failed | Self::Disconnected => ConnDot::Disconnected,
        }
    }
}

/// Inputs that decide [`SessionPhase`]. Pure so the UI and tests share one path.
#[derive(Clone, Copy, Debug)]
pub struct SessionSignals<'a> {
    pub user_stopped: bool,
    pub link_connecting: bool,
    pub has_texture: bool,
    pub since_frame: Option<Duration>,
    pub fatal_error: &'a str,
    /// True when the fatal error is a connect/peer failure (not a clean Disconnect).
    pub connect_failed: bool,
}

pub fn session_phase(s: SessionSignals<'_>) -> SessionPhase {
    if s.connect_failed {
        return SessionPhase::Failed;
    }
    if s.user_stopped {
        return SessionPhase::Disconnected;
    }
    if !s.has_texture {
        if !s.fatal_error.is_empty() && !s.link_connecting {
            return SessionPhase::Failed;
        }
        return SessionPhase::Connecting;
    }
    match s.since_frame {
        Some(elapsed) if elapsed >= FRAME_STALE_AFTER => SessionPhase::Stale,
        _ => SessionPhase::Live,
    }
}

/// Classify a connect failure for the session overlay and debug bus.
pub fn classify_connect_error(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("timed out") || lower.contains("timeout") {
        return if raw.is_empty() {
            "Connection timed out".into()
        } else {
            raw.to_string()
        };
    }
    if lower.contains("remote_control")
        || lower.contains("remote-control")
        || lower.contains("not allowed")
        || lower.contains("control not allowed")
    {
        return if raw.is_empty() {
            "Remote control not allowed".into()
        } else {
            raw.to_string()
        };
    }
    if lower.contains("offline")
        || lower.contains("not found")
        || lower.contains("no such node")
        || lower.contains("unreachable")
    {
        return if raw.is_empty() {
            "Node is offline".into()
        } else {
            raw.to_string()
        };
    }
    if raw.is_empty() {
        "Connection failed".into()
    } else {
        raw.to_string()
    }
}

/// True when the top chrome (tab strip + connection bar) should paint (fullscreen auto-hide).
pub fn top_chrome_visible(
    fullscreen: bool,
    idle_for: Duration,
    pointer_y: Option<f32>,
    chrome_height: f32,
) -> bool {
    if !fullscreen {
        return true;
    }
    if pointer_y.is_some_and(|y| y <= chrome_height + BAR_REVEAL_PAD) {
        return true;
    }
    idle_for < BAR_HIDE_AFTER
}

/// True when the connection bar should paint (fullscreen auto-hide).
pub fn connection_bar_visible(
    fullscreen: bool,
    idle_for: Duration,
    pointer_y: Option<f32>,
) -> bool {
    top_chrome_visible(fullscreen, idle_for, pointer_y, BAR_HEIGHT)
}

/// Height of the top multi-session tab strip.
pub fn session_tab_strip_height(tab_count: usize) -> f32 {
    if tab_count > 0 {
        theme::TAB_BAR_HEIGHT
    } else {
        0.0
    }
}

/// Total top chrome height for the active desktop session shell.
pub fn session_chrome_top_height(tab_count: usize, bar_visible: bool) -> f32 {
    if bar_visible {
        session_tab_strip_height(tab_count) + BAR_HEIGHT
    } else {
        0.0
    }
}

/// How much chrome the connection bar can afford at the current width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum BarDensity {
    /// Full labels + zoom popup. Target ≥1200.
    Full,
    /// Labels kept; zoom is a value chip only (no slider popup). Target 1000–1200.
    Compact,
    /// Icon-sized controls; resolution + fps merged. Target 860–1000.
    Icons,
    /// Back · name · monitor · fullscreen · disconnect only. Target <860.
    Minimal,
}

impl BarDensity {
    pub fn from_width(available: f32) -> Self {
        // Design tiers (measure-then-step-down may go denser):
        // ≥1200 Full · 1000–1200 Compact · 860–1000 Icons · <860 Minimal.
        if available >= 1200.0 {
            Self::Full
        } else if available >= 1000.0 {
            Self::Compact
        } else if available >= 860.0 {
            Self::Icons
        } else {
            Self::Minimal
        }
    }

    pub fn step_down(self) -> Option<Self> {
        match self {
            Self::Full => Some(Self::Compact),
            Self::Compact => Some(Self::Icons),
            Self::Icons => Some(Self::Minimal),
            Self::Minimal => None,
        }
    }
}

/// Inputs used to estimate connection-bar width before painting.
#[derive(Clone, Debug)]
pub struct BarMeasure<'a> {
    pub node_name: &'a str,
    pub monitor_label: &'a str,
    pub resolution: Option<&'a str>,
    pub stats: Option<&'a str>,
    pub zoom_label: &'a str,
    pub fullscreen_label: &'a str,
    pub has_cad: bool,
    pub control: bool,
}

fn btn_w(text_w: f32) -> f32 {
    (text_w + 2.0 * theme::SPACE_SM).max(theme::ICON_BTN)
}

pub fn text_advance(text: &str, size: f32, mono: bool) -> f32 {
    // Inter / JetBrains averages used when fonts are not available (unit tests /
    // density pre-pass). Slightly generous so we step down before widgets clip.
    let avg = if mono { 0.68 } else { 0.62 };
    text.chars().count() as f32 * size * avg
}

/// Estimate total bar width (left + gap + right) for a density.
pub fn estimate_bar_width(density: BarDensity, m: &BarMeasure<'_>) -> f32 {
    estimate_bar_width_with(density, m, text_advance)
}

/// Estimate with a custom text-width function (egui `layout_no_wrap` in UI).
pub fn estimate_bar_width_with(
    density: BarDensity,
    m: &BarMeasure<'_>,
    mut advance: impl FnMut(&str, f32, bool) -> f32,
) -> f32 {
    let gap = theme::SPACE_SM;
    let item = theme::SPACE_XS;
    let vsep = 1.0 + item * 2.0;

    let name = advance(m.node_name, theme::SECONDARY_SIZE, false);
    let dot = theme::STATUS_DOT + theme::SPACE_SM;
    let mode = if density == BarDensity::Minimal {
        0.0
    } else {
        let label = if m.control { "CONTROL" } else { "VIEW" };
        advance(label, theme::PILL_SIZE, false) + 12.0 + item
    };

    let monitor: f32 = match density {
        BarDensity::Minimal => 110.0,
        BarDensity::Icons => 120.0,
        _ => 140.0,
    };
    // ComboBox reports roughly selected_text + chrome; clamp to configured width.
    let monitor_w = monitor
        .min(advance(m.monitor_label, theme::BAR_SIZE, false) + 28.0)
        .max(88.0);

    let (meta_w, right_w) = match density {
        BarDensity::Full | BarDensity::Compact => {
            let res = m
                .resolution
                .map(|s| advance(s, theme::BAR_SIZE, true) + item)
                .unwrap_or(0.0);
            let stats = m
                .stats
                .map(|s| btn_w(advance(s, theme::BAR_SIZE, true)) + item)
                .unwrap_or(0.0);
            let left_extra = res + stats;
            let zoom = if density == BarDensity::Full {
                btn_w(advance(m.zoom_label, theme::BAR_SIZE, false))
            } else {
                advance(m.zoom_label, theme::BAR_SIZE, false) + theme::SPACE_XS
            };
            let tools = btn_w(advance("Fit", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("1:1", theme::BAR_SIZE, false))
                + item
                + zoom
                + item
                + btn_w(advance(m.fullscreen_label, theme::BAR_SIZE, false))
                + vsep
                + btn_w(advance("Keys", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Clip", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Shot", theme::BAR_SIZE, false))
                + if m.has_cad {
                    item + btn_w(advance("Send", theme::BAR_SIZE, false))
                } else {
                    0.0
                }
                + vsep
                + btn_w(advance("Disconnect", theme::BAR_SIZE, false));
            (left_extra, tools)
        }
        BarDensity::Icons => {
            let merged = match (m.resolution, m.stats) {
                (Some(r), Some(s)) => Some(format!("{r}  {s}")),
                (Some(r), None) => Some(r.to_string()),
                (None, Some(s)) => Some(s.to_string()),
                (None, None) => None,
            };
            let meta = merged
                .as_deref()
                .map(|s| btn_w(advance(s, theme::BAR_SIZE, true)) + item)
                .unwrap_or(0.0);
            let tools = btn_w(advance("Fit", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("1:1", theme::BAR_SIZE, false))
                + item
                + advance(m.zoom_label, theme::BAR_SIZE, false)
                + item
                + btn_w(advance("FS", theme::BAR_SIZE, false))
                + vsep
                + btn_w(advance("Kb", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Cb", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Sc", theme::BAR_SIZE, false))
                + if m.has_cad {
                    item + btn_w(advance("Send", theme::BAR_SIZE, false))
                } else {
                    0.0
                }
                + vsep
                + btn_w(advance("X", theme::BAR_SIZE, false));
            (meta, tools)
        }
        BarDensity::Minimal => {
            let tools = btn_w(advance("FS", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("X", theme::BAR_SIZE, false));
            (0.0, tools)
        }
    };

    let left = name
        + item
        + dot
        + mode
        + if density == BarDensity::Minimal {
            item
        } else {
            vsep
        }
        + monitor_w
        + meta_w;

    left + gap + right_w
}

/// Width of the trailing control cluster alone (Fit…Disconnect).
pub fn estimate_right_width_with(
    density: BarDensity,
    m: &BarMeasure<'_>,
    mut advance: impl FnMut(&str, f32, bool) -> f32,
) -> f32 {
    let item = theme::SPACE_XS;
    let vsep = 1.0 + item * 2.0;
    match density {
        BarDensity::Full => {
            let zoom = btn_w(advance(m.zoom_label, theme::BAR_SIZE, false));
            btn_w(advance("Fit", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("1:1", theme::BAR_SIZE, false))
                + item
                + zoom
                + item
                + btn_w(advance(m.fullscreen_label, theme::BAR_SIZE, false))
                + vsep
                + btn_w(advance("Keys", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Clip", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Shot", theme::BAR_SIZE, false))
                + if m.has_cad {
                    item + btn_w(advance("Send", theme::BAR_SIZE, false))
                } else {
                    0.0
                }
                + vsep
                + btn_w(advance("Disconnect", theme::BAR_SIZE, false))
        }
        BarDensity::Compact => {
            advance(m.zoom_label, theme::BAR_SIZE, false)
                + item
                + btn_w(advance("Fit", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("1:1", theme::BAR_SIZE, false))
                + item
                + btn_w(advance(m.fullscreen_label, theme::BAR_SIZE, false))
                + vsep
                + btn_w(advance("Keys", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Clip", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Shot", theme::BAR_SIZE, false))
                + if m.has_cad {
                    item + btn_w(advance("Send", theme::BAR_SIZE, false))
                } else {
                    0.0
                }
                + vsep
                + btn_w(advance("Disconnect", theme::BAR_SIZE, false))
        }
        BarDensity::Icons => {
            advance(m.zoom_label, theme::BAR_SIZE, false)
                + item
                + btn_w(advance("Fit", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("1:1", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("FS", theme::BAR_SIZE, false))
                + vsep
                + btn_w(advance("Kb", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Cb", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("Sc", theme::BAR_SIZE, false))
                + if m.has_cad {
                    item + btn_w(advance("Send", theme::BAR_SIZE, false))
                } else {
                    0.0
                }
                + vsep
                + btn_w(advance("X", theme::BAR_SIZE, false))
        }
        BarDensity::Minimal => {
            btn_w(advance("FS", theme::BAR_SIZE, false))
                + item
                + btn_w(advance("X", theme::BAR_SIZE, false))
        }
    }
}

/// Choose the densest tier that fits `available`, starting from the width hint.
pub fn pick_bar_density(available: f32, m: &BarMeasure<'_>) -> BarDensity {
    pick_bar_density_with(available, m, text_advance)
}

pub fn pick_bar_density_with(
    available: f32,
    m: &BarMeasure<'_>,
    mut advance: impl FnMut(&str, f32, bool) -> f32,
) -> BarDensity {
    // Generous slack for ComboBox / button chrome the estimator under-counts.
    let budget = (available - 80.0).max(0.0);
    let mut density = BarDensity::from_width(available);
    loop {
        let need = estimate_bar_width_with(density, m, &mut advance);
        if need <= budget || density.step_down().is_none() {
            return density;
        }
        density = density.step_down().unwrap();
    }
}

/// Compact monospace stats for the connection bar. Omits empty fields.
pub fn stats_line(width: u32, height: u32, fps: f32, latency_ms: i64) -> Option<String> {
    let mut parts = Vec::new();
    if width > 0 && height > 0 {
        parts.push(format!("{width}×{height}"));
    }
    if fps > 0.5 {
        parts.push(format!("{:.0} fps", fps));
    }
    if latency_ms > 0 {
        parts.push(format!("{latency_ms} ms"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join("  "))
    }
}

/// Session-stats popover rate line. JPEG stills that are actually
/// refreshing must not be labeled `fps  0.0` (that reads as a stalled
/// video). A measured stills rate is shown in Hz; an unmeasured window
/// is `n/a`, never a fabricated zero.
pub fn session_stats_rate_line(kind: &str, fps: f32) -> String {
    if kind.eq_ignore_ascii_case("jpeg") {
        if fps > 0.05 {
            format!("stills  {:.1} Hz", fps)
        } else {
            "stills  n/a".into()
        }
    } else {
        format!("fps  {:.1}", fps)
    }
}

/// Bitrate is a live-video statistic. JPEG stills do not invent a kbps.
pub fn session_stats_bitrate_line(kind: &str, bitrate_kbps: u32) -> String {
    if kind.eq_ignore_ascii_case("jpeg") {
        "bitrate  n/a".into()
    } else {
        format!("bitrate  {bitrate_kbps} kbps")
    }
}

/// Latency is a live-video statistic. JPEG stills do not invent 0 ms.
pub fn session_stats_latency_line(kind: &str, latency_ms: i64) -> String {
    if kind.eq_ignore_ascii_case("jpeg") {
        "latency  n/a".into()
    } else {
        format!("latency  {latency_ms} ms")
    }
}

/// Compact fps/latency chip used as the clickable stats target.
pub fn stats_chip(fps: f32, latency_ms: i64) -> Option<String> {
    let mut parts = Vec::new();
    if fps > 0.5 {
        parts.push(format!("{:.0} fps", fps));
    }
    if latency_ms > 0 {
        parts.push(format!("{latency_ms} ms"));
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(" "))
    }
}

/// Map encoder names from the answer / HUD into the debug-bus vocabulary.
pub fn encoder_label(kind: &str, encoder: &str, hardware: bool) -> &'static str {
    let kind = kind.to_ascii_lowercase();
    if kind == "jpeg" {
        return "jpeg";
    }
    let enc = encoder.to_ascii_lowercase();
    if enc.contains("mini") || enc == "minih264" {
        return "minih264";
    }
    if hardware
        || enc.contains("nvenc")
        || enc.contains("qsv")
        || enc.contains("vaapi")
        || enc.contains("amf")
        || enc.contains("videotoolbox")
        || enc.contains("mf")
        || enc == "h264_hw"
    {
        return "h264_hw";
    }
    if kind == "h264" || kind == "mock" {
        if enc.is_empty() {
            return if kind == "mock" {
                "minih264"
            } else {
                "h264_hw"
            };
        }
        return "minih264";
    }
    "minih264"
}

/// True when `link` is still in the worker's connecting label.
pub fn link_is_connecting(link: &str) -> bool {
    let lower = link.to_ascii_lowercase();
    lower.contains("connecting")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connecting_before_picture() {
        let phase = session_phase(SessionSignals {
            user_stopped: false,
            link_connecting: true,
            has_texture: false,
            since_frame: None,
            fatal_error: "",
            connect_failed: false,
        });
        assert_eq!(phase, SessionPhase::Connecting);
        assert_eq!(phase.dot(), ConnDot::Reconnecting);
    }

    #[test]
    fn live_with_fresh_frame() {
        let phase = session_phase(SessionSignals {
            user_stopped: false,
            link_connecting: false,
            has_texture: true,
            since_frame: Some(Duration::from_millis(200)),
            fatal_error: "",
            connect_failed: false,
        });
        assert_eq!(phase, SessionPhase::Live);
        assert_eq!(phase.dot(), ConnDot::Connected);
    }

    #[test]
    fn stale_after_three_seconds() {
        let phase = session_phase(SessionSignals {
            user_stopped: false,
            link_connecting: false,
            has_texture: true,
            since_frame: Some(Duration::from_secs(3)),
            fatal_error: "timeout",
            connect_failed: false,
        });
        assert_eq!(phase, SessionPhase::Stale);
        assert_eq!(phase.dot(), ConnDot::Reconnecting);
    }

    #[test]
    fn user_stop_wins() {
        let phase = session_phase(SessionSignals {
            user_stopped: true,
            link_connecting: true,
            has_texture: true,
            since_frame: Some(Duration::from_millis(10)),
            fatal_error: "",
            connect_failed: false,
        });
        assert_eq!(phase, SessionPhase::Disconnected);
        assert_eq!(phase.dot(), ConnDot::Disconnected);
    }

    #[test]
    fn fatal_without_texture_fails() {
        let phase = session_phase(SessionSignals {
            user_stopped: false,
            link_connecting: false,
            has_texture: false,
            since_frame: None,
            fatal_error: "node offline",
            connect_failed: false,
        });
        assert_eq!(phase, SessionPhase::Failed);
    }

    #[test]
    fn connect_failed_flag_wins() {
        let phase = session_phase(SessionSignals {
            user_stopped: true,
            link_connecting: false,
            has_texture: false,
            since_frame: None,
            fatal_error: "Connection timed out",
            connect_failed: true,
        });
        assert_eq!(phase, SessionPhase::Failed);
    }

    #[test]
    fn classify_connect_error_kinds() {
        assert!(classify_connect_error("webrtc_signal timed out").contains("timed out"));
        assert!(classify_connect_error("remote_control not allowed")
            .to_ascii_lowercase()
            .contains("not allowed"));
        assert!(classify_connect_error("node offline")
            .to_ascii_lowercase()
            .contains("offline"));
    }

    #[test]
    fn bar_always_visible_windowed() {
        assert!(connection_bar_visible(
            false,
            Duration::from_secs(30),
            Some(500.0)
        ));
    }

    #[test]
    fn bar_hides_when_fullscreen_idle() {
        assert!(!connection_bar_visible(
            true,
            Duration::from_secs(3),
            Some(400.0)
        ));
    }

    #[test]
    fn bar_shows_on_top_edge_when_fullscreen() {
        assert!(connection_bar_visible(
            true,
            Duration::from_secs(30),
            Some(2.0)
        ));
    }

    #[test]
    fn bar_shows_while_recently_moved() {
        assert!(connection_bar_visible(
            true,
            Duration::from_millis(500),
            Some(400.0)
        ));
    }

    #[test]
    fn stats_omit_empty_fields() {
        assert_eq!(stats_line(0, 0, 0.0, 0), None);
        assert_eq!(stats_line(1920, 1080, 0.0, 0).as_deref(), Some("1920×1080"));
        assert_eq!(
            stats_line(1920, 1080, 28.0, 42).as_deref(),
            Some("1920×1080  28 fps  42 ms")
        );
    }

    #[test]
    fn session_stats_jpeg_stills_are_labeled_not_zero_fps() {
        // 0938 GUI: refreshing JPEG stills showed `fps  0.0` / `bitrate  0`
        // / `latency  0 ms` in the popover. Those zeros are unmeasured
        // video metrics, not a stills rate of zero.
        assert_eq!(session_stats_rate_line("jpeg", 0.0), "stills  n/a");
        assert_eq!(session_stats_rate_line("JPEG", 1.25), "stills  1.2 Hz");
        assert_eq!(session_stats_rate_line("JPEG", 1.3), "stills  1.3 Hz");
        assert_eq!(session_stats_bitrate_line("jpeg", 0), "bitrate  n/a");
        assert_eq!(session_stats_bitrate_line("jpeg", 400), "bitrate  n/a");
        assert_eq!(session_stats_latency_line("jpeg", 0), "latency  n/a");
        assert_eq!(session_stats_latency_line("jpeg", 42), "latency  n/a");
        assert_eq!(session_stats_rate_line("h264", 28.0), "fps  28.0");
        assert_eq!(
            session_stats_bitrate_line("h264", 2000),
            "bitrate  2000 kbps"
        );
        assert_eq!(session_stats_latency_line("h264", 42), "latency  42 ms");
        assert_ne!(session_stats_rate_line("jpeg", 0.0), "fps  0.0");
    }

    #[test]
    fn chrome_height_reserves_tab_strip() {
        assert_eq!(session_tab_strip_height(0), 0.0);
        assert_eq!(session_tab_strip_height(1), theme::TAB_BAR_HEIGHT);
        assert_eq!(
            session_chrome_top_height(1, true),
            theme::TAB_BAR_HEIGHT + BAR_HEIGHT
        );
        assert_eq!(session_chrome_top_height(0, true), BAR_HEIGHT);
        assert_eq!(session_chrome_top_height(1, false), 0.0);
    }

    #[test]
    fn top_chrome_visible_uses_combined_tab_and_connection_bar_height() {
        let combined = theme::TAB_BAR_HEIGHT + BAR_HEIGHT;
        assert!(top_chrome_visible(
            false,
            Duration::from_secs(30),
            Some(500.0),
            combined
        ));
        assert!(!top_chrome_visible(
            true,
            Duration::from_secs(30),
            Some(combined + BAR_REVEAL_PAD + 1.0),
            combined
        ));
        assert!(top_chrome_visible(
            true,
            Duration::from_secs(30),
            Some(combined + BAR_REVEAL_PAD),
            combined
        ));
        assert!(top_chrome_visible(
            true,
            Duration::from_millis(500),
            Some(500.0),
            combined
        ));
    }

    #[test]
    fn link_connecting_detects_worker_labels() {
        assert!(link_is_connecting("connecting · control"));
        assert!(link_is_connecting("Connecting…"));
        assert!(!link_is_connecting("h264 · relay"));
    }

    fn sample_measure() -> BarMeasure<'static> {
        BarMeasure {
            node_name: "box",
            monitor_label: "mock-0 · primary",
            resolution: Some("960×480"),
            stats: Some("30 fps 12 ms"),
            zoom_label: "100%",
            fullscreen_label: "Full",
            has_cad: false,
            control: true,
        }
    }

    #[test]
    fn bar_density_thresholds() {
        assert_eq!(BarDensity::from_width(1440.0), BarDensity::Full);
        assert_eq!(BarDensity::from_width(1200.0), BarDensity::Full);
        assert_eq!(BarDensity::from_width(1100.0), BarDensity::Compact);
        assert_eq!(BarDensity::from_width(1000.0), BarDensity::Compact);
        assert_eq!(BarDensity::from_width(960.0), BarDensity::Icons);
        assert_eq!(BarDensity::from_width(860.0), BarDensity::Icons);
        assert_eq!(BarDensity::from_width(859.0), BarDensity::Minimal);
        assert_eq!(BarDensity::from_width(800.0), BarDensity::Minimal);
    }

    #[test]
    fn bar_density_steps_down_until_fit() {
        let m = sample_measure();
        let d = pick_bar_density(960.0, &m);
        // 960 starts at Icons; may stay or step to Minimal if chrome overruns.
        assert!(d == BarDensity::Icons || d == BarDensity::Minimal);
        let budget = (960.0_f32 - 80.0).max(0.0);
        assert!(estimate_bar_width(d, &m) <= budget + 1.0);
        let tight = pick_bar_density(720.0, &m);
        assert_eq!(tight, BarDensity::Minimal);
        assert!(estimate_bar_width(tight, &m) <= 720.0 + 40.0);
    }

    #[test]
    fn denser_tiers_need_more_width() {
        let m = sample_measure();
        let full = estimate_bar_width(BarDensity::Full, &m);
        let compact = estimate_bar_width(BarDensity::Compact, &m);
        let icons = estimate_bar_width(BarDensity::Icons, &m);
        let minimal = estimate_bar_width(BarDensity::Minimal, &m);
        assert!(full >= compact);
        assert!(compact >= icons);
        assert!(icons >= minimal);
    }
}
