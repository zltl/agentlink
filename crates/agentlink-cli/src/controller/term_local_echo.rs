//! Speculative local echo (type-ahead) for the desktop Controller terminal.
//!
//! Design follows the **mosh / VS Code overlay** model (see
//! https://github.com/microsoft/vscode/issues/115949): predictions live in a
//! **separate overlay**, never in the alacritty grid. Remote PTY bytes are
//! always applied unchanged via [`super::term::Emulator::feed`]; the overlay is
//! then reconciled against parsed cells.
//!
//! # Privacy model (fail-closed — honest limits)
//!
//! The agentlink PTY protocol does **not** expose host `termios` ECHO state.
//! Without that signal we **cannot** guarantee password/no-echo safety from
//! prompt matching, TTLs, or “previous glyph echoed.” Policy:
//!
//! - Catch-up re-probe: when the pending queue is **empty**, the next printable
//!   is always an **unpainted** expect (`echo_ready` cleared). Sticky readiness
//!   after an empty queue is what painted secrets after a silent ECHO-off
//!   (E1b). While ahead of the remote (non-empty pending) and established,
//!   further keystrokes may paint for low-latency shell typing.
//! - Line/control/IME/mode/generation/resize → [`SpeculativeEcho::invalidate`].
//! - Remote feed that confirms nothing while pending is empty clears readiness
//!   (password prompts / redraws without a local Enter).
//! - [`SpeculativeEcho::tick`] runs every UI frame (even with a silent remote)
//!   so blank-grace and TTL expire overlays without waiting for `feed`.
//!
//! # Latency claims
//!
//! `note_outbound` is **enqueue** latency (no network). egui frame/paint timing
//! is not asserted here.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Term, TermMode};
use unicode_width::UnicodeWidthChar;

use super::term::TermHost;

/// Hard cap on unconfirmed overlay + expect entries (DoS / runaway paste).
pub const MAX_PENDING: usize = 256;
/// Drop predictions that the remote never confirmed.
pub const PREDICTION_TTL: Duration = Duration::from_millis(1_500);
/// Painted (or expected) glyphs that stay blank this long → treat as no-echo.
pub const BLANK_NOECHO_GRACE: Duration = Duration::from_millis(120);
/// After this many consecutive confirms in a burst, further ahead-of-echo
/// keystrokes may paint.
const ECHO_ESTABLISH_STREAK: u32 = 1;

/// One predicted (or expected) glyph at a grid point.
#[derive(Debug, Clone)]
pub struct Prediction {
    pub line: i32,
    pub col: usize,
    pub ch: char,
    pub cells: usize,
    pub created: Instant,
    /// When true, also painted faintly; when false, used only to learn echo.
    pub painted: bool,
}

/// Snapshot used by paint / tests — viewport-relative row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayCell {
    pub row: usize,
    pub col: usize,
    pub ch: char,
    pub cells: usize,
}

#[derive(Debug)]
pub struct SpeculativeEcho {
    pending: VecDeque<Prediction>,
    /// Speculative cursor after the last pending prediction (grid coords).
    cursor_line: i32,
    cursor_col: usize,
    /// May paint further keystrokes **while pending is non-empty** (burst).
    echo_ready: bool,
    confirm_streak: u32,
    /// Generation identity; bumps on reconnect / emulator rebuild.
    generation: u64,
    /// Last known unsafe-mode latch so we clear once on enter.
    blocked: bool,
}

impl Default for SpeculativeEcho {
    fn default() -> Self {
        Self::new(0)
    }
}

impl SpeculativeEcho {
    pub fn new(generation: u64) -> Self {
        Self {
            pending: VecDeque::new(),
            cursor_line: 0,
            cursor_col: 0,
            echo_ready: false,
            confirm_streak: 0,
            generation,
            blocked: false,
        }
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn reset(&mut self, generation: u64) {
        *self = Self::new(generation);
    }

    /// Drop pending overlay entries only (keeps readiness). Prefer
    /// [`Self::invalidate`] at any ambiguous boundary.
    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }

    /// Fail-closed: drop pending **and** forget that echo was established.
    pub fn invalidate(&mut self) {
        self.pending.clear();
        self.echo_ready = false;
        self.confirm_streak = 0;
    }

    /// Backward-compatible name used by paint/IME paths — must invalidate.
    pub fn clear(&mut self) {
        self.invalidate();
    }

    pub fn echo_ready(&self) -> bool {
        self.echo_ready
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub fn painted_len(&self) -> usize {
        self.pending.iter().filter(|p| p.painted).count()
    }

    #[cfg(test)]
    pub(super) fn pending_front(&self) -> Option<&Prediction> {
        self.pending.front()
    }

    #[cfg(test)]
    pub(super) fn pending_front_mut(&mut self) -> Option<&mut Prediction> {
        self.pending.front_mut()
    }

    /// Sync speculative cursor from the authoritative term (call before predict).
    pub fn sync_cursor_from_term(&mut self, term: &Term<TermHost>) {
        if self.pending.is_empty() {
            let content = term.renderable_content();
            self.cursor_line = content.cursor.point.line.0;
            self.cursor_col = content.cursor.point.column.0;
        }
    }

    /// Mode gate: alt-screen / insert are unsafe for predictions.
    pub fn modes_safe(term: &Term<TermHost>) -> bool {
        let mode = term.mode();
        !mode.contains(TermMode::ALT_SCREEN) && !mode.contains(TermMode::INSERT)
    }

    /// Observe modes after remote feed; invalidate when entering unsafe modes.
    pub fn observe_modes(&mut self, term: &Term<TermHost>) {
        let safe = Self::modes_safe(term);
        if !safe {
            if !self.blocked {
                self.invalidate();
            }
            self.blocked = true;
        } else if self.blocked {
            self.blocked = false;
            self.invalidate();
        }
    }

    /// Active expiry without a remote feed (call from the UI frame).
    ///
    /// Blank-grace and TTL must not depend on `feed` — silent no-echo leaves
    /// the remote quiet while painted secrets would otherwise stick (E1b-C).
    pub fn tick(&mut self, term: &Term<TermHost>) -> bool {
        let before = self.painted_len();
        self.observe_modes(term);
        if self.blocked {
            return before > 0 && self.painted_len() == 0;
        }
        self.expire_stale(term);
        before > 0 && self.painted_len() == 0
    }

    /// Classify outbound PTY bytes and update the overlay / expect queue.
    ///
    /// Returns whether any new painted prediction was added (enqueue only).
    pub fn note_outbound(&mut self, term: &Term<TermHost>, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        // Frame-local expiry even when the user types during silence.
        self.expire_stale(term);

        self.observe_modes(term);
        if self.blocked || !Self::modes_safe(term) {
            self.invalidate();
            return false;
        }

        if bytes.iter().any(|&b| matches!(b, 0x03 | 0x04 | 0x1a | 0x1c)) {
            self.invalidate();
            return false;
        }

        if bytes.contains(&0x1b) {
            self.invalidate();
            return false;
        }

        if bytes.iter().all(|&b| matches!(b, 0x08 | 0x7f)) {
            if let Some(last) = self.pending.pop_back() {
                self.cursor_line = last.line;
                self.cursor_col = last.col;
            } else {
                self.invalidate();
            }
            return false;
        }

        if bytes.iter().any(|&b| matches!(b, b'\r' | b'\n' | b'\t')) {
            self.invalidate();
            return false;
        }

        if bytes.len() > 64 || bytes.windows(6).any(|w| w == b"\x1b[200~") {
            self.invalidate();
            return false;
        }

        let Ok(text) = std::str::from_utf8(bytes) else {
            self.invalidate();
            return false;
        };
        if text.chars().any(|c| c.is_control()) {
            self.invalidate();
            return false;
        }

        // E1b: caught up with remote → force re-probe. Sticky echo_ready with
        // an empty queue paints the next glyphs after a silent ECHO-off.
        if self.pending.is_empty() {
            self.echo_ready = false;
            self.confirm_streak = 0;
        }

        self.sync_cursor_from_term(term);
        let mut painted_any = false;
        for ch in text.chars() {
            if !is_predictable_char(ch) {
                self.invalidate();
                return painted_any;
            }
            let cells = cell_width(ch);
            if cells == 0 {
                self.invalidate();
                return painted_any;
            }
            if self.pending.len() >= MAX_PENDING {
                self.invalidate();
                return painted_any;
            }
            let cols = term.columns();
            if self.cursor_col + cells > cols {
                self.invalidate();
                return painted_any;
            }
            let painted = self.echo_ready;
            self.pending.push_back(Prediction {
                line: self.cursor_line,
                col: self.cursor_col,
                ch,
                cells,
                created: Instant::now(),
                painted,
            });
            self.cursor_col += cells;
            if painted {
                painted_any = true;
            }
        }
        painted_any
    }

    /// After remote bytes were fed into `term`, confirm / drop predictions.
    ///
    /// `remote_drove` is true when the feed was non-empty. Remote activity that
    /// confirms nothing while we have no pending clears sticky readiness
    /// (password prompt / redraw without a local Enter).
    pub fn reconcile(&mut self, term: &Term<TermHost>, remote_drove: bool) {
        self.observe_modes(term);
        if self.blocked {
            return;
        }
        self.expire_stale(term);

        let now_cursor = {
            let content = term.renderable_content();
            (content.cursor.point.line.0, content.cursor.point.column.0)
        };

        let mut confirmed = 0usize;
        while let Some(front) = self.pending.front() {
            let cell = cell_at(term, front.line, front.col);
            let Some((ch, _wide)) = cell else {
                break;
            };
            if ch == ' ' || ch == '\0' {
                if front.painted
                    && Instant::now().duration_since(front.created) >= BLANK_NOECHO_GRACE
                {
                    self.invalidate();
                    return;
                }
                break;
            }
            if ch == front.ch {
                let past = now_cursor.0 > front.line
                    || (now_cursor.0 == front.line && now_cursor.1 >= front.col + front.cells);
                if past || !front.painted {
                    self.pending.pop_front();
                    confirmed += 1;
                    continue;
                }
                break;
            }
            self.invalidate();
            self.sync_cursor_from_term(term);
            return;
        }

        if confirmed > 0 {
            self.confirm_streak = self.confirm_streak.saturating_add(confirmed as u32);
            if self.confirm_streak >= ECHO_ESTABLISH_STREAK {
                self.echo_ready = true;
                // Promote remaining expects in this burst so ahead-of-echo
                // keystrokes become visible once echo is proven for the burst.
                for p in self.pending.iter_mut() {
                    p.painted = true;
                }
            }
            if self.pending.is_empty() {
                self.sync_cursor_from_term(term);
            }
        } else if remote_drove && self.pending.is_empty() {
            // Remote wrote (prompt/redraw) without confirming us — readiness
            // from the previous burst must not authorize the next glyphs.
            self.echo_ready = false;
            self.confirm_streak = 0;
        }
    }

    fn expire_stale(&mut self, term: &Term<TermHost>) {
        let now = Instant::now();

        // Blank-grace for painted cells even when reconcile is not called.
        if let Some(front) = self.pending.front() {
            if front.painted && now.duration_since(front.created) >= BLANK_NOECHO_GRACE {
                let cell = cell_at(term, front.line, front.col);
                let blank = matches!(cell, Some((' ', _)) | Some(('\0', _)) | None);
                if blank {
                    self.invalidate();
                    return;
                }
            }
        }

        let before = self.pending.len();
        self.pending
            .retain(|p| now.duration_since(p.created) <= PREDICTION_TTL);
        if self.pending.len() < before {
            self.invalidate();
        }
    }

    /// Overlay cells in viewport coordinates for painting / tests.
    pub fn overlay_cells(&self, term: &Term<TermHost>) -> Vec<OverlayCell> {
        let content = term.renderable_content();
        let display_offset = content.display_offset as i32;
        let rows = term.screen_lines();
        let cols = term.columns();
        let mut out = Vec::new();
        for p in self.pending.iter().filter(|p| p.painted) {
            let row = p.line + display_offset;
            if row < 0 || row as usize >= rows || p.col >= cols {
                continue;
            }
            out.push(OverlayCell {
                row: row as usize,
                col: p.col,
                ch: p.ch,
                cells: p.cells,
            });
        }
        out
    }

    /// Speculative cursor (viewport row, col) when overlay is active.
    pub fn speculative_cursor(&self, term: &Term<TermHost>) -> Option<(usize, usize)> {
        if self.pending.iter().all(|p| !p.painted) {
            return None;
        }
        let content = term.renderable_content();
        let display_offset = content.display_offset as i32;
        let row = self.cursor_line + display_offset;
        if row < 0 {
            return None;
        }
        Some((row as usize, self.cursor_col))
    }
}

fn is_predictable_char(ch: char) -> bool {
    if ch.is_control() || ch == '\u{7f}' {
        return false;
    }
    true
}

/// Cell width using the same `unicode_width` semantics as alacritty:
/// combining / zero-width → 0, ASCII → 1, East-Asian wide → 2.
pub fn cell_width(ch: char) -> usize {
    UnicodeWidthChar::width(ch).unwrap_or(0)
}

fn cell_at(term: &Term<TermHost>, line: i32, col: usize) -> Option<(char, bool)> {
    let content = term.renderable_content();
    let target = Point::new(Line(line), Column(col));
    for indexed in content.display_iter {
        if indexed.point == target {
            if indexed.cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                return Some((' ', false));
            }
            let wide = indexed.cell.flags.contains(Flags::WIDE_CHAR);
            return Some((indexed.cell.c, wide));
        }
    }
    let cell = &term.grid()[Line(line)][Column(col)];
    let wide = cell.flags.contains(Flags::WIDE_CHAR);
    Some((cell.c, wide))
}

/// Faint overlay color — lighter than normal fg, distinct from IME preedit tint.
pub fn faint_fg() -> eframe::egui::Color32 {
    eframe::egui::Color32::from_rgb(0x9A, 0x9A, 0xA8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::term::Emulator;
    use std::thread;

    #[test]
    fn no_paint_until_echo_established_password_safe() {
        let mut emu = Emulator::new(24, 80);
        let painted = emu.note_local_echo_outbound(b"s");
        assert!(!painted);
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert_eq!(emu.local_echo().pending_len(), 1);
        assert!(!emu.local_echo().echo_ready());
    }

    #[test]
    fn establish_echo_then_paint_ahead_in_burst() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().pending_len(), 0);

        // Caught up → next key is a probe (unpainted), not sticky paint.
        let painted_probe = emu.note_local_echo_outbound(b"b");
        assert!(!painted_probe, "empty-queue re-probe must not paint");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert_eq!(emu.local_echo().pending_len(), 1);

        // Confirm probe; remaining burst may paint.
        emu.feed_raw(b"b");
        assert!(emu.local_echo().echo_ready());

        // Type ahead of echo while pending non-empty after starting next probe…
        // Start next char as probe again if empty; keep ahead-of-echo path:
        emu.note_local_echo_outbound(b"c"); // probe (empty queue cleared ready)
        assert_eq!(emu.local_echo().painted_len(), 0);
        emu.note_local_echo_outbound(b"d"); // still !ready → unpainted
        emu.feed_raw(b"c"); // confirms c, sets ready, promotes d to painted
        assert!(emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().painted_len(), 1);
        assert_eq!(emu.local_echo().overlay_cells(emu.term_ref())[0].ch, 'd');

        let t0 = Instant::now();
        let painted = emu.note_local_echo_outbound(b"e");
        let enqueue_latency = t0.elapsed();
        assert!(painted, "ahead-of-echo keystroke may paint after burst establish");
        assert!(
            enqueue_latency < Duration::from_millis(5),
            "enqueue must not wait on network; took {enqueue_latency:?} (not egui paint)"
        );
    }

    /// E1: shell echo → Enter → password typing must not paint.
    #[test]
    fn shell_enter_then_noecho_typing_never_paints_secret() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"whoami");
        emu.feed_raw(b"whoami");
        assert!(emu.local_echo().echo_ready());
        emu.note_local_echo_outbound(b"\r");
        assert!(!emu.local_echo().echo_ready());
        emu.feed_raw(b"\r\nPassword: ");
        let painted = emu.note_local_echo_outbound(b"sekrit");
        assert!(!painted);
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
    }

    /// E1b-B: establish → no local CR → type secret must not paint (sticky ready).
    #[test]
    fn remote_only_echo_off_without_local_enter_never_paints_secret() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().pending_len(), 0);
        // No local CR/LF/Tab. Remote may have flipped ECHO off silently.
        let painted = emu.note_local_echo_outbound(b"sekrit");
        assert!(!painted, "E1b: empty-queue must re-probe, not paint secrets");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert_eq!(emu.local_echo().pending_len(), 6);
        assert!(!emu.local_echo().echo_ready());
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
    }

    /// E1b: remote prints a password prompt without a local Enter.
    #[test]
    fn remote_password_prompt_without_local_enter_clears_readiness() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(emu.local_echo().echo_ready());
        // Remote-only prompt (sudo-style) — no local CR.
        emu.feed_raw(b"\r\nPassword: ");
        assert!(
            !emu.local_echo().echo_ready(),
            "remote-driven prompt must clear sticky readiness"
        );
        let painted = emu.note_local_echo_outbound(b"x");
        assert!(!painted);
        assert_eq!(emu.local_echo().painted_len(), 0);
    }

    /// E1b-C: age painted overlay with no feed — tick must clear without feed.
    #[test]
    fn tick_expires_painted_blank_without_remote_feed() {
        let mut emu = Emulator::new(24, 80);
        // Build a painted pending via burst: probe+confirm+ahead.
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b"); // probe
        emu.note_local_echo_outbound(b"c"); // unpainted
        emu.feed_raw(b"b"); // promotes c
        assert_eq!(emu.local_echo().painted_len(), 1);
        emu.age_local_echo_front(BLANK_NOECHO_GRACE + Duration::from_millis(1));
        // No feed — only tick (UI frame).
        let cleared = emu.tick_local_echo();
        assert!(cleared || emu.local_echo().painted_len() == 0);
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(!emu.local_echo().echo_ready());
    }

    #[test]
    fn stale_generation_reset_drops_overlay() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b");
        emu.note_local_echo_outbound(b"c");
        emu.feed_raw(b"b");
        assert!(emu.local_echo().painted_len() > 0);
        emu.reset_local_echo(99);
        assert_eq!(emu.local_echo().generation(), 99);
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(!emu.local_echo().echo_ready());
    }

    #[test]
    fn tab_and_lf_also_invalidate_readiness() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(emu.local_echo().echo_ready());
        emu.note_local_echo_outbound(b"\t");
        assert!(!emu.local_echo().echo_ready());
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"\n");
        assert!(!emu.local_echo().echo_ready());
    }

    #[test]
    fn resize_invalidates_readiness() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(emu.resize(30, 100));
        assert!(!emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().pending_len(), 0);
    }

    #[test]
    fn no_echo_timeout_disables_predictions() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"x");
        emu.feed_raw(b"x");
        emu.note_local_echo_outbound(b"y");
        emu.note_local_echo_outbound(b"z");
        emu.feed_raw(b"y");
        assert_eq!(emu.local_echo().painted_len(), 1);
        emu.age_local_echo_front(PREDICTION_TTL + Duration::from_millis(1));
        emu.tick_local_echo();
        assert!(!emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().pending_len(), 0);
    }

    #[test]
    fn alt_screen_clears_and_blocks() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b");
        emu.note_local_echo_outbound(b"c");
        emu.feed_raw(b"b");
        assert!(emu.local_echo().painted_len() > 0);
        emu.feed_raw(b"\x1b[?1049h");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(!emu.local_echo().echo_ready());
        assert!(!emu.note_local_echo_outbound(b"c"));
    }

    #[test]
    fn ctrl_c_invalidates_overlay() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b");
        emu.note_local_echo_outbound(&[0x03]);
        assert_eq!(emu.local_echo().pending_len(), 0);
        assert!(!emu.local_echo().echo_ready());
    }

    #[test]
    fn backspace_pops_last_prediction() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"x");
        emu.note_local_echo_outbound(b"y");
        emu.feed_raw(b"x"); // promotes y
        assert_eq!(emu.local_echo().painted_len(), 1);
        emu.note_local_echo_outbound(&[0x7f]);
        assert_eq!(emu.local_echo().painted_len(), 0);
    }

    #[test]
    fn mismatch_clears_without_deleting_remote_cells() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b");
        emu.feed_raw(b"Z");
        assert_eq!(emu.local_echo().pending_len(), 0);
        assert!(emu.viewport_text().contains('Z') || emu.viewport_text().contains('a'));
    }

    #[test]
    fn wide_cjk_and_combining_width() {
        assert_eq!(cell_width('中'), 2);
        assert_eq!(cell_width('\u{0301}'), 0);
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound("中".as_bytes());
        assert_eq!(emu.local_echo().pending_front().unwrap().cells, 2);
        emu.feed_raw("中".as_bytes());
        assert!(emu.local_echo().echo_ready());
        let painted = emu.note_local_echo_outbound("\u{0301}".as_bytes());
        assert!(!painted);
        assert!(!emu.local_echo().echo_ready());
    }

    #[test]
    fn reset_on_generation_change() {
        let mut echo = SpeculativeEcho::new(1);
        echo.echo_ready = true;
        echo.reset(2);
        assert_eq!(echo.generation(), 2);
        assert!(!echo.echo_ready());
    }

    #[test]
    fn delayed_remote_echo_reconciles_without_duplication() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b");
        emu.note_local_echo_outbound(b"c");
        emu.feed_raw(b"b");
        assert_eq!(emu.local_echo().painted_len(), 1);
        thread::sleep(Duration::from_millis(20));
        emu.feed_raw(b"c");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.viewport_text().contains('c'));
    }
}
