//! Speculative local echo (type-ahead) for the desktop Controller terminal.
//!
//! Design follows the **mosh / VS Code overlay** model (see
//! https://github.com/microsoft/vscode/issues/115949): predictions live in a
//! **separate overlay**, never in the alacritty grid. Remote PTY bytes are
//! always applied unchanged via [`super::term::Emulator::feed`]; the overlay is
//! then reconciled against parsed cells.
//!
//! # Privacy model (fail-closed)
//!
//! Previous echo confirmation is **not** permission to speculate at the next
//! prompt. Classic `sudo` / `ssh` / `read -s` flip to no-echo without
//! alt-screen. Therefore:
//!
//! - Paint only while `echo_ready` is true for the **current line**.
//! - Any line / control / prompt / IME / mode / generation / resize boundary
//!   calls [`SpeculativeEcho::invalidate`] (clears pending **and** readiness).
//! - Blank cells under a painted prediction are treated as no-echo after a
//!   short grace (not only the long TTL).
//! - Heuristics **cannot** know TTY echo mode; we never claim guaranteed
//!   no-echo safety — only that we refuse to paint across ambiguous transitions.
//!
//! # Latency claims
//!
//! `note_outbound` updates the overlay struct locally (no network wait). That
//! is **enqueue** latency, not egui frame/paint latency. Callers may
//! `request_repaint`; pixel timing is not asserted here.

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
/// After this many consecutive confirms **on the current line**, paint further
/// printables on that same line.
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
    /// Echo appears to match typed printables **on this line** — may paint.
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
    /// Used at line/control/prompt/IME/mode/generation/resize transitions.
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
            // Leaving alt-screen / insert: still require fresh establish.
            self.blocked = false;
            self.invalidate();
        }
    }

    /// Classify outbound PTY bytes and update the overlay / expect queue.
    ///
    /// Returns whether any new painted prediction was added (caller may
    /// request an egui repaint). This return is about **enqueue**, not frame
    /// paint timing.
    pub fn note_outbound(&mut self, term: &Term<TermHost>, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        self.observe_modes(term);
        if self.blocked || !Self::modes_safe(term) {
            self.invalidate();
            return false;
        }

        // Signals / controls: invalidate readiness (new prompt / interrupt).
        if bytes.iter().any(|&b| matches!(b, 0x03 | 0x04 | 0x1a | 0x1c)) {
            self.invalidate();
            return false;
        }

        // Escape / CSI / SS3 — cursor keys, function keys, mode sets.
        if bytes.contains(&0x1b) {
            self.invalidate();
            return false;
        }

        // Backspace / DEL: drop last prediction if any; else invalidate.
        if bytes.iter().all(|&b| matches!(b, 0x08 | 0x7f)) {
            if let Some(last) = self.pending.pop_back() {
                self.cursor_line = last.line;
                self.cursor_col = last.col;
            } else {
                // No local prediction to edit — ambiguous remote line state.
                self.invalidate();
            }
            return false;
        }

        // CR / LF / Tab: line / completion boundary — must forget readiness
        // so a following password/no-echo prompt cannot paint secrets.
        if bytes.iter().any(|&b| matches!(b, b'\r' | b'\n' | b'\t')) {
            self.invalidate();
            return false;
        }

        // Bracketed paste markers or very large blobs: do not speculate.
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

        self.sync_cursor_from_term(term);
        let mut painted_any = false;
        for ch in text.chars() {
            if !is_predictable_char(ch) {
                self.invalidate();
                return painted_any;
            }
            let cells = cell_width(ch);
            // Combining / zero-width: do not open a new cell prediction
            // (matches alacritty zerowidth attachment). Refuse to speculate.
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
                // Wrap prediction is fragile; skip rather than mis-draw.
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
    pub fn reconcile(&mut self, term: &Term<TermHost>) {
        self.observe_modes(term);
        if self.blocked {
            return;
        }
        self.expire_stale();

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
                // Blank under a painted prediction past grace → no-echo.
                if front.painted
                    && Instant::now().duration_since(front.created) >= BLANK_NOECHO_GRACE
                {
                    self.invalidate();
                    return;
                }
                // Unpainted expect still learning — wait (TTL handles abandon).
                break;
            }
            if ch == front.ch {
                // Confirmed only when cursor has advanced past the cell
                // (avoids false confirm on in-place placeholders).
                let past = now_cursor.0 > front.line
                    || (now_cursor.0 == front.line && now_cursor.1 >= front.col + front.cells);
                if past || !front.painted {
                    self.pending.pop_front();
                    confirmed += 1;
                    continue;
                }
                // Glyph matches but cursor has not moved past — wait.
                break;
            }
            // Mismatch: foreign content — drop this and all later predictions.
            self.invalidate();
            self.sync_cursor_from_term(term);
            return;
        }

        if confirmed > 0 {
            self.confirm_streak = self.confirm_streak.saturating_add(confirmed as u32);
            if self.confirm_streak >= ECHO_ESTABLISH_STREAK {
                self.echo_ready = true;
            }
            if self.pending.is_empty() {
                self.sync_cursor_from_term(term);
            }
        }
    }

    fn expire_stale(&mut self) {
        let now = Instant::now();
        let before = self.pending.len();
        // Painted blanks past grace already handled in reconcile; TTL is the
        // hard ceiling for any remaining expects.
        self.pending
            .retain(|p| now.duration_since(p.created) <= PREDICTION_TTL);
        if self.pending.len() < before {
            // Timed-out expects → treat as no-echo / abandon line.
            self.echo_ready = false;
            self.confirm_streak = 0;
            self.pending.clear();
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
    fn establish_echo_then_paint_faint_then_confirm() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(emu.local_echo().echo_ready(), "first confirm establishes echo");
        assert_eq!(emu.local_echo().pending_len(), 0);

        let t0 = Instant::now();
        let painted = emu.note_local_echo_outbound(b"b");
        let enqueue_latency = t0.elapsed();
        assert!(painted);
        assert!(
            enqueue_latency < Duration::from_millis(5),
            "keystroke→overlay enqueue must not wait on network; took {enqueue_latency:?} \
             (this is not egui paint/frame latency)"
        );
        assert_eq!(emu.local_echo().painted_len(), 1);
        let overlay = emu.local_echo().overlay_cells(emu.term_ref());
        assert_eq!(overlay.len(), 1);
        assert_eq!(overlay[0].ch, 'b');

        thread::sleep(Duration::from_millis(20));
        emu.feed_raw(b"b");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.viewport_text().contains('b'));
    }

    /// E1: shell echo established → Enter → password/no-echo typing must not paint.
    #[test]
    fn shell_enter_then_noecho_typing_never_paints_secret() {
        let mut emu = Emulator::new(24, 80);
        // Establish echo on a normal shell line.
        emu.note_local_echo_outbound(b"whoami");
        emu.feed_raw(b"whoami");
        assert!(emu.local_echo().echo_ready());
        // Line boundary (Enter): readiness must die.
        emu.note_local_echo_outbound(b"\r");
        assert!(!emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().pending_len(), 0);
        // Remote shows a password-style prompt (no TTY echo mode bit available).
        emu.feed_raw(b"\r\nPassword: ");
        // Sensitive typing — stand-in glyphs, not a real secret.
        let painted = emu.note_local_echo_outbound(b"sekrit");
        assert!(!painted, "must not paint after line boundary");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(!emu.local_echo().echo_ready());
        // Expects may exist for learning, but none painted.
        let overlay = emu.local_echo().overlay_cells(emu.term_ref());
        assert!(overlay.is_empty());
        // No-echo remote: blanks only — still no paint after grace.
        thread::sleep(BLANK_NOECHO_GRACE + Duration::from_millis(30));
        emu.reconcile_local_echo();
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
        assert!(emu.local_echo().echo_ready());
        emu.note_local_echo_outbound(b"\n");
        assert!(!emu.local_echo().echo_ready());
    }

    #[test]
    fn prompt_without_newline_cr_only_still_invalidates() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"x");
        emu.feed_raw(b"x");
        assert!(emu.local_echo().echo_ready());
        // Some prompts redraw with CR without LF.
        emu.note_local_echo_outbound(b"\r");
        assert!(!emu.local_echo().echo_ready());
        let painted = emu.note_local_echo_outbound(b"y");
        assert!(!painted);
    }

    #[test]
    fn ansi_partial_remote_output_does_not_keep_readiness_across_invalidate() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(emu.local_echo().echo_ready());
        emu.note_local_echo_outbound(b"\r");
        // Fragmented CSI from remote after line boundary.
        emu.feed_raw(b"\x1b[");
        emu.feed_raw(b"0mPassword: ");
        let painted = emu.note_local_echo_outbound(b"z");
        assert!(!painted);
        assert_eq!(emu.local_echo().painted_len(), 0);
    }

    #[test]
    fn resize_invalidates_readiness() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(emu.local_echo().echo_ready());
        assert!(emu.resize(30, 100));
        assert!(!emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().pending_len(), 0);
    }

    #[test]
    fn no_echo_timeout_disables_predictions() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"x");
        emu.feed_raw(b"x");
        assert!(emu.local_echo().echo_ready());
        emu.note_local_echo_outbound(b"y");
        assert_eq!(emu.local_echo().painted_len(), 1);
        emu.age_local_echo_front(PREDICTION_TTL + Duration::from_millis(1));
        emu.reconcile_local_echo();
        assert!(!emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().pending_len(), 0);
    }

    #[test]
    fn painted_blank_grace_treats_as_noecho() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b");
        assert_eq!(emu.local_echo().painted_len(), 1);
        emu.age_local_echo_front(BLANK_NOECHO_GRACE + Duration::from_millis(1));
        // Remote stays blank (noecho) — reconcile must invalidate, not wait TTL.
        emu.reconcile_local_echo();
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(!emu.local_echo().echo_ready());
    }

    #[test]
    fn alt_screen_clears_and_blocks() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b");
        assert_eq!(emu.local_echo().painted_len(), 1);
        emu.feed_raw(b"\x1b[?1049h");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(!emu.local_echo().echo_ready());
        let painted = emu.note_local_echo_outbound(b"c");
        assert!(!painted);
        assert_eq!(emu.local_echo().pending_len(), 0);
    }

    #[test]
    fn ctrl_c_invalidates_overlay() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b");
        assert!(emu.local_echo().painted_len() > 0);
        emu.note_local_echo_outbound(&[0x03]);
        assert_eq!(emu.local_echo().pending_len(), 0);
        assert!(!emu.local_echo().echo_ready());
    }

    #[test]
    fn backspace_pops_last_prediction() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"xy");
        assert_eq!(emu.local_echo().painted_len(), 2);
        emu.note_local_echo_outbound(&[0x7f]);
        assert_eq!(emu.local_echo().painted_len(), 1);
        let cells = emu.local_echo().overlay_cells(emu.term_ref());
        assert_eq!(cells[0].ch, 'x');
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
    fn wide_cjk_prediction_uses_two_cells() {
        assert_eq!(cell_width('中'), 2);
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound("中".as_bytes());
        assert_eq!(emu.local_echo().pending_len(), 1);
        assert_eq!(emu.local_echo().pending_front().unwrap().cells, 2);
    }

    #[test]
    fn combining_mark_has_zero_width_and_is_not_predicted() {
        assert_eq!(cell_width('\u{0301}'), 0); // combining acute
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(emu.local_echo().echo_ready());
        // Combining mark alone must invalidate rather than mis-advance.
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
        assert_eq!(echo.pending_len(), 0);
    }

    #[test]
    fn same_line_echo_still_paints_after_establish() {
        // Legitimate instant echo on the same line must keep working.
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"h");
        emu.feed_raw(b"h");
        assert!(emu.local_echo().echo_ready());
        assert!(emu.note_local_echo_outbound(b"i"));
        assert_eq!(emu.local_echo().painted_len(), 1);
        emu.feed_raw(b"i");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().echo_ready(), "same-line confirms keep readiness");
    }
}
