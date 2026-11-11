//! Controller decisions that do not need a window.
//!
//! Login checks, capability gates, terminal scrollback, and path joins live
//! here so `cargo test` can cover them without opening a display.

use std::collections::VecDeque;

use agentlink_core::{NodePolicy, RelayTrust};

pub const SCROLLBACK: usize = 1000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub enabled: bool,
    pub reason: &'static str,
}

pub fn terminal_action(online: bool, policy: NodePolicy) -> Action {
    if !online {
        return Action {
            enabled: false,
            reason: "Unavailable while offline",
        };
    }
    if !policy.allow_exec {
        return Action {
            enabled: false,
            reason: "Needs exec permission",
        };
    }
    Action {
        enabled: true,
        reason: "Open a shell on this machine",
    }
}

pub fn files_action(online: bool, policy: NodePolicy) -> Action {
    if !online {
        return Action {
            enabled: false,
            reason: "Unavailable while offline",
        };
    }
    if !policy.allow_read && !policy.allow_write {
        return Action {
            enabled: false,
            reason: "File transfer is turned off",
        };
    }
    if policy.allow_read && policy.allow_write {
        return Action {
            enabled: true,
            reason: "Browse, upload, and download",
        };
    }
    if policy.allow_read {
        return Action {
            enabled: true,
            reason: "Browse and download. Upload is turned off",
        };
    }
    Action {
        enabled: true,
        reason: "Upload is allowed. Listing files is turned off",
    }
}

pub fn desktop_allowed(policy: NodePolicy) -> bool {
    policy.allow_desktop || policy.allows_remote_view() || policy.allows_remote_control()
}

pub fn desktop_action(online: bool, has_display: Option<bool>, policy: NodePolicy) -> Action {
    if has_display == Some(false) {
        return Action {
            enabled: false,
            reason: "Headless machine. No desktop session.",
        };
    }
    if !online {
        return Action {
            enabled: false,
            reason: "Unavailable while offline",
        };
    }
    if has_display == Some(true) && !desktop_allowed(policy) {
        return Action {
            enabled: false,
            reason: "This machine has a screen. Set access to full to open Desktop.",
        };
    }
    Action {
        enabled: true,
        reason: "Open the desktop viewer",
    }
}

pub fn display_note(has_display: Option<bool>, policy: NodePolicy) -> Option<&'static str> {
    if has_display == Some(false) {
        return Some("Headless. Shell and files only.");
    }
    if has_display == Some(true) && !desktop_allowed(policy) {
        return Some("Screen detected. Set access to full to open Desktop.");
    }
    None
}

/// Whether the machines card should offer desktop start buttons.
/// Headless nodes never get a fake desktop entry, even when the account
/// policy would allow a session on a machine that has a screen.
pub fn show_desktop_starts(has_display: Option<bool>, policy: NodePolicy) -> bool {
    match has_display {
        Some(false) => false,
        Some(true) => true,
        None => desktop_allowed(policy),
    }
}

pub fn view_desktop_action(online: bool, has_display: Option<bool>, policy: NodePolicy) -> Action {
    desktop_action(online, has_display, policy)
}

pub fn control_desktop_action(
    online: bool,
    has_display: Option<bool>,
    policy: NodePolicy,
) -> Action {
    let base = desktop_action(online, has_display, policy);
    if !base.enabled {
        return base;
    }
    if !policy.allows_remote_control() {
        return Action {
            enabled: false,
            reason: "Control needs remote-control on this account. Use View desktop.",
        };
    }
    Action {
        enabled: true,
        reason: "Open the desktop with keyboard and mouse",
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CardButtonKind {
    Terminal,
    Files,
    ViewDesktop,
    ControlDesktop,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CardButton {
    pub label: &'static str,
    pub kind: CardButtonKind,
    pub enabled: bool,
    pub reason: &'static str,
}

/// Visible primary actions on a machines card. Labels are the real start
/// actions. There is no silent View/Control mode toggle — those words only
/// appear as "View desktop" / "Control desktop", and only when the node
/// actually has (or may have) a screen.
pub fn card_buttons(
    online: bool,
    has_display: Option<bool>,
    policy: NodePolicy,
) -> Vec<CardButton> {
    let terminal = terminal_action(online, policy);
    let files = files_action(online, policy);
    let mut out = vec![
        CardButton {
            label: "Terminal",
            kind: CardButtonKind::Terminal,
            enabled: terminal.enabled,
            reason: terminal.reason,
        },
        CardButton {
            label: "Files",
            kind: CardButtonKind::Files,
            enabled: files.enabled,
            reason: files.reason,
        },
    ];
    if !show_desktop_starts(has_display, policy) {
        return out;
    }
    let view = view_desktop_action(online, has_display, policy);
    let control = control_desktop_action(online, has_display, policy);
    out.push(CardButton {
        label: "View desktop",
        kind: CardButtonKind::ViewDesktop,
        enabled: view.enabled,
        reason: view.reason,
    });
    out.push(CardButton {
        label: "Control desktop",
        kind: CardButtonKind::ControlDesktop,
        enabled: control.enabled,
        reason: control.reason,
    });
    out
}

/// True when the config file holds a refresh token (value is not logged).
pub fn has_saved_session(refresh_token: Option<&str>) -> bool {
    refresh_token
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
}

/// `host` beats `stun`, which beats `turn`. Empty input is the relay socket.
pub fn connection_label(raw: &str) -> &'static str {
    let lower = raw.to_ascii_lowercase();
    if lower.contains("quic") {
        "quic"
    } else if lower.contains("host") {
        "host"
    } else if lower.contains("stun") || lower.contains("srflx") {
        "stun"
    } else if lower.contains("turn") || lower.contains(" typ relay") {
        "turn"
    } else {
        "relay"
    }
}

pub fn asks_for_totp(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("totp") || lower.contains("authenticator")
}

pub fn login_problem(
    username: &str,
    password: &str,
    relay: &str,
    pin: &str,
    trust: &str,
) -> Option<String> {
    if username.trim().is_empty() {
        return Some("Username is required.".into());
    }
    if password.is_empty() {
        return Some("Password is required.".into());
    }
    if !relay.trim().is_empty() {
        if let Err(err) = agentlink_core::parse_relay_url(relay) {
            return Some(err.to_string());
        }
    }
    let pin = pin.trim();
    let trust = trust.trim();
    if !pin.is_empty() || !trust.is_empty() {
        let trust = if trust.is_empty() { None } else { Some(trust) };
        if let Err(err) = RelayTrust::parse(pin, trust) {
            return Some(err.to_string());
        }
    }
    None
}

pub fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// Install line for a freshly minted enrollment token.
pub fn enroll_command(token: &str, name: &str, access: &str) -> String {
    format!(
        "curl -fsSL https://relay.example.com/install.sh | sh -s -- --token {} --name {} --access {} --max-access {}",
        shell_quote(token),
        shell_quote(name),
        shell_quote(access),
        shell_quote(access),
    )
}

pub fn child_path(parent: &str, name: &str) -> String {
    let parent = parent.trim();
    if parent.is_empty() || parent == "." {
        return name.to_string();
    }
    let sep = if parent.contains('\\') && !parent.contains('/') {
        '\\'
    } else {
        '/'
    };
    if parent.ends_with(sep) {
        format!("{parent}{name}")
    } else {
        format!("{parent}{sep}{name}")
    }
}

pub fn parent_path(path: &str) -> String {
    let path = path.trim().trim_end_matches(['/', '\\']);
    if path.is_empty() || path == "." {
        return ".".into();
    }
    let sep = if path.contains('\\') && !path.contains('/') {
        '\\'
    } else {
        '/'
    };
    match path.rsplit_once(sep) {
        Some((parent, _)) if !parent.is_empty() => parent.to_string(),
        _ => ".".into(),
    }
}

pub fn looks_textual(bytes: &[u8]) -> bool {
    !bytes.contains(&0)
}

/// Hide the window into the status icon only when a tray icon actually
/// started *and* this process was launched with `--background`. A normal
/// Controller window must quit on close so test processes do not accumulate.
pub fn hides_window_on_close(
    tray_icon_ready: bool,
    background: bool,
    quit_requested: bool,
) -> bool {
    tray_icon_ready && background && !quit_requested
}

/// True when the open editor is the deleted path, or a file inside a deleted folder.
pub fn editor_is_stale(editor_path: &str, deleted: &str) -> bool {
    let editor = editor_path.trim();
    let deleted = deleted.trim().trim_end_matches(['/', '\\']);
    if editor.is_empty() || deleted.is_empty() {
        return false;
    }
    if editor == deleted {
        return true;
    }
    let slash = format!("{deleted}/");
    let back = format!("{deleted}\\");
    editor.starts_with(&slash) || editor.starts_with(&back)
}

/// "Saved <path>" notices that should disappear with the editor.
pub fn notice_refers_to_path(notice: &str, path: &str) -> bool {
    let notice = notice.trim();
    let path = path.trim();
    !path.is_empty() && notice.starts_with("Saved ") && notice.contains(path)
}

/// Width of the session machine rail, including its frame margin.
pub const MACHINE_RAIL_WIDTH: f32 = 260.0;

/// Comfortable main-column width beside the rail (terminal/files chrome).
///
/// Parent GUI at a restored ~1085 px window still showed the rail with the
/// old 980 show-at. That was the threshold policy, not a viewport min-size
/// pin (screenshot physical width ≈ 1085; Read preview 1280-wide made it
/// look like ~725). Fold when the window cannot keep rail + this main.
pub const SESSION_MAIN_COMFORT_WIDTH: f32 = 840.0;

/// Hide the session rail below this window width; the session page still
/// has an explicit Back to machines button.
///
/// Intentional breakpoint: `MACHINE_RAIL_WIDTH + SESSION_MAIN_COMFORT_WIDTH`
/// (1100). Distinct from the View-desktop rail clipping bug.
pub const MACHINE_RAIL_SHOW_AT: f32 = MACHINE_RAIL_WIDTH + SESSION_MAIN_COMFORT_WIDTH;

/// The Machines list is a single compact column.
///
/// 0133 used a two-column `Grid` once the list was ≥ 860 px. In the
/// maximized retest the first cell inherited the leftover panel width,
/// so cards stretched across the window, metadata overlapped, and the
/// second column (sufa, tc-external, probe) overflowed off the right
/// edge. A compact single column that truncates long hostnames/ids and
/// wraps whole action buttons is the maintainable layout.
pub fn machine_card_columns(_available_width: f32) -> usize {
    1
}

/// Content width for one Machines card, capped to the list's available width.
pub fn machine_card_width(available_width: f32, columns: usize, gap: f32) -> f32 {
    let columns = columns.max(1) as f32;
    let inner = (available_width - gap * (columns - 1.0)).max(1.0);
    (inner / columns)
        .floor()
        .clamp(200.0, available_width.max(200.0))
}

/// Shorten a hostname, node id, or policy note for one line. The full
/// string is kept for hover/copy in the UI.
pub fn ellipsize_chars(text: &str, max_chars: usize) -> String {
    let text = text.trim();
    if max_chars == 0 {
        return String::new();
    }
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let take = max_chars.saturating_sub(1);
    let mut out: String = text.chars().take(take).collect();
    out.push('…');
    out
}

pub fn machine_rail_visible(window_width: f32) -> bool {
    window_width >= MACHINE_RAIL_SHOW_AT
}

/// Plain-text terminal with a fixed scrollback. Cursor motion is enough for
/// shells and progress lines; full-screen TUI apps stay on the web viewer.
#[derive(Clone, Debug)]
pub struct Scrollback {
    lines: VecDeque<String>,
    current: Vec<char>,
    col: usize,
    cap: usize,
    escape: Escape,
}

#[derive(Clone, Debug)]
enum Escape {
    None,
    Esc,
    Csi,
}

impl Default for Scrollback {
    fn default() -> Self {
        Self::new(SCROLLBACK)
    }
}

impl Scrollback {
    pub fn new(cap: usize) -> Self {
        Self {
            lines: VecDeque::new(),
            current: Vec::new(),
            col: 0,
            cap: cap.max(1),
            escape: Escape::None,
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) {
        let text = String::from_utf8_lossy(bytes);
        for ch in text.chars() {
            self.push_char(ch);
        }
    }

    pub fn text(&self) -> String {
        let mut out = String::new();
        for line in &self.lines {
            out.push_str(line);
            out.push('\n');
        }
        if !self.current.is_empty() {
            out.extend(self.current.iter().copied());
        }
        out
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn line_count(&self) -> usize {
        self.lines.len() + usize::from(!self.current.is_empty())
    }

    fn push_char(&mut self, ch: char) {
        match self.escape {
            Escape::None => self.plain(ch),
            Escape::Esc => match ch {
                '[' => self.escape = Escape::Csi,
                _ => self.escape = Escape::None,
            },
            Escape::Csi => {
                if ('@'..='~').contains(&ch) {
                    self.escape = Escape::None;
                }
            }
        }
    }

    fn plain(&mut self, ch: char) {
        match ch {
            '\u{1b}' => self.escape = Escape::Esc,
            '\n' => self.commit(),
            '\r' => self.col = 0,
            '\u{8}' => {
                if self.col > 0 {
                    self.col -= 1;
                    if self.col < self.current.len() {
                        self.current.remove(self.col);
                    }
                }
            }
            other if other.is_control() => {}
            other => {
                if self.col < self.current.len() {
                    self.current[self.col] = other;
                } else {
                    self.current.push(other);
                }
                self.col += 1;
                if self.current.len() > 8192 {
                    self.commit();
                }
            }
        }
    }

    fn commit(&mut self) {
        let line: String = self.current.iter().collect();
        self.lines.push_back(line);
        while self.lines.len() > self.cap {
            self.lines.pop_front();
        }
        self.current.clear();
        self.col = 0;
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn pty_key(name: &str, ctrl: bool) -> Option<Vec<u8>> {
    if ctrl {
        let byte = match name {
            "c" => Some(0x03),
            "d" => Some(0x04),
            "z" => Some(0x1a),
            "a" => Some(0x01),
            "e" => Some(0x05),
            "l" => Some(0x0c),
            _ => None,
        };
        if let Some(byte) = byte {
            return Some(vec![byte]);
        }
    }
    let bytes: &[u8] = match name {
        "enter" => b"\r",
        "backspace" => b"\x7f",
        "tab" => b"\t",
        "escape" => b"\x1b",
        "up" => b"\x1b[A",
        "down" => b"\x1b[B",
        "right" => b"\x1b[C",
        "left" => b"\x1b[D",
        "home" => b"\x1b[H",
        "end" => b"\x1b[F",
        _ => return None,
    };
    Some(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentlink_core::NodePolicy;

    #[test]
    fn headless_desktop_is_off_and_shell_stays_on() {
        let full = NodePolicy::full();
        let desktop = desktop_action(true, Some(false), full);
        assert!(!desktop.enabled);
        assert!(desktop.reason.contains("Headless"));
        assert!(terminal_action(true, full).enabled);
        assert!(files_action(true, full).enabled);
        assert_eq!(
            display_note(Some(false), full),
            Some("Headless. Shell and files only.")
        );
        let buttons = card_buttons(true, Some(false), full);
        let labels: Vec<_> = buttons.iter().map(|b| b.label).collect();
        assert_eq!(labels, ["Terminal", "Files"]);
        assert!(!labels
            .iter()
            .any(|l| l.contains("View") || l.contains("Control") || l.contains("Desktop")));
    }

    #[test]
    fn card_buttons_start_desktop_instead_of_silent_mode_toggle() {
        let full = NodePolicy::full();
        let buttons = card_buttons(true, Some(true), full);
        let labels: Vec<_> = buttons.iter().map(|b| b.label).collect();
        assert_eq!(
            labels,
            ["Terminal", "Files", "View desktop", "Control desktop"]
        );
        assert!(buttons.iter().all(|b| b.enabled));
        // Bare "View"/"Control" must not appear — those were a mode toggle
        // that stayed on the machines list with no session and no error.
        assert!(!labels.contains(&"View"));
        assert!(!labels.contains(&"Control"));
        assert!(!labels.contains(&"Desktop"));

        let exec = NodePolicy::exec();
        let limited = card_buttons(true, Some(true), exec);
        let desk: Vec<_> = limited
            .iter()
            .filter(|b| {
                matches!(
                    b.kind,
                    CardButtonKind::ViewDesktop | CardButtonKind::ControlDesktop
                )
            })
            .collect();
        assert_eq!(desk.len(), 2);
        assert!(desk.iter().all(|b| !b.enabled));
    }

    #[test]
    fn saved_session_looks_only_at_token_presence() {
        assert!(has_saved_session(Some("present")));
        assert!(!has_saved_session(Some("")));
        assert!(!has_saved_session(Some("   ")));
        assert!(!has_saved_session(None));
    }

    #[test]
    fn exec_hides_desktop_when_a_screen_is_reported() {
        let exec = NodePolicy::exec();
        let desktop = desktop_action(true, Some(true), exec);
        assert!(!desktop.enabled);
        assert!(desktop.reason.contains("full"));
        assert!(!desktop_allowed(exec));
        assert!(desktop_allowed(NodePolicy::full()));
        assert!(terminal_action(false, exec).reason.contains("offline"));
        let files = files_action(true, NodePolicy::remote_view());
        assert!(files.enabled);
        assert!(files.reason.contains("Upload is turned off"));
    }

    #[test]
    fn connection_labels_name_the_path() {
        assert_eq!(connection_label("wss://relay.example.com"), "relay");
        assert_eq!(connection_label("typ host"), "host");
        assert_eq!(connection_label("via STUN srflx"), "stun");
        assert_eq!(connection_label("TURN udp"), "turn");
        assert_eq!(connection_label("quic"), "quic");
    }

    #[test]
    fn totp_errors_open_the_code_field() {
        assert!(asks_for_totp("totp code required"));
        assert!(asks_for_totp("Authenticator required"));
        assert!(!asks_for_totp("wrong password"));
    }

    #[test]
    fn login_rejects_a_blank_user_and_a_bad_relay() {
        assert!(login_problem("", "secret", "", "", "").is_some());
        assert!(login_problem("ada", "", "", "", "").is_some());
        assert!(login_problem("ada", "secret", "not a url :::", "", "").is_some());
        assert!(login_problem("ada", "secret", "", "", "").is_none());
        assert!(login_problem("ada", "secret", "wss://relay.example:7443", "", "system").is_none());
    }

    #[test]
    fn scrollback_overwrites_on_cr_strips_color_and_caps() {
        let mut one = Scrollback::new(4);
        one.push_bytes(b"hello\rxy");
        assert_eq!(one.text(), "xyllo");
        let mut screen = Scrollback::new(2);
        screen.push_bytes(b"hello\rxy\n");
        screen.push_bytes(b"\x1b[31mred\x1b[0m\n");
        screen.push_bytes(b"third\n");
        let text = screen.text();
        assert!(text.contains("red\n"), "{text}");
        assert!(text.contains("third"), "{text}");
        assert!(!text.contains("xyllo"), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
        assert_eq!(screen.line_count(), 2);
    }

    #[test]
    fn paths_join_and_pty_keys_are_stable() {
        assert_eq!(child_path(".", "notes"), "notes");
        assert_eq!(child_path("/tmp", "a"), "/tmp/a");
        assert_eq!(parent_path("/tmp/a"), "/tmp");
        assert_eq!(parent_path("."), ".");
        assert_eq!(child_path(r"C:\work", "a"), r"C:\work\a");
        assert_eq!(pty_key("enter", false).unwrap(), b"\r");
        assert_eq!(pty_key("c", true).unwrap(), vec![0x03]);
        assert!(enroll_command("tok'en", "lab top", "exec").contains("--token 'tok'\\''en'"));
        assert!(looks_textual(b"hi"));
        assert!(!looks_textual(b"a\0b"));
    }
    #[test]
    fn editor_clears_when_its_file_or_folder_is_deleted() {
        assert!(editor_is_stale("dir/probe.txt", "dir/probe.txt"));
        assert!(editor_is_stale("dir/probe.txt", "dir"));
        assert!(!editor_is_stale("dir/probe.txt", "dir/other.txt"));
        assert!(!editor_is_stale("directory/a.txt", "dir"));
        assert!(notice_refers_to_path(
            "Saved dir/probe.txt",
            "dir/probe.txt"
        ));
        assert!(!notice_refers_to_path("Copied.", "dir/probe.txt"));
    }

    #[test]
    fn machine_list_stays_a_single_column_even_when_wide() {
        assert_eq!(machine_card_columns(800.0), 1);
        assert_eq!(machine_card_columns(1080.0), 1);
        assert_eq!(machine_card_columns(1280.0), 1);
        assert_eq!(machine_card_columns(1920.0), 1);
        let wide = machine_card_width(1216.0, 1, 16.0);
        assert_eq!(wide, 1216.0);
        let narrow = machine_card_width(736.0, 1, 16.0);
        assert_eq!(narrow, 736.0);
        // Intentional fold below rail + comfortable main (1100), so a restored
        // ~1080 window hides the sidebar. 1280/1920 keep the rail.
        assert_eq!(MACHINE_RAIL_SHOW_AT, 1100.0);
        assert!(machine_rail_visible(1280.0));
        assert!(machine_rail_visible(1920.0));
        assert!(!machine_rail_visible(1080.0));
        assert!(!machine_rail_visible(1085.0));
        assert!(!machine_rail_visible(800.0));
        assert!(!machine_rail_visible(725.0));
        assert_eq!(
            ellipsize_chars("iZ7xv88es0zy9ogs1ny63Z", 12),
            "iZ7xv88es0z…"
        );
        assert_eq!(ellipsize_chars("short", 12), "short");
    }

    #[test]
    fn window_close_quits_unless_a_background_tray_is_ready() {
        assert!(!hides_window_on_close(false, true, false));
        assert!(!hides_window_on_close(true, false, false));
        assert!(hides_window_on_close(true, true, false));
        assert!(!hides_window_on_close(true, true, true));
    }
}
