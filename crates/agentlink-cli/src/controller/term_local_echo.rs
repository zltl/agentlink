//! Speculative local echo (type-ahead) for the desktop Controller terminal.
//!
//! Design follows the **mosh / VS Code overlay** model (see
//! https://github.com/microsoft/vscode/issues/115949 and xterm predictive
//! echo addons): predictions live in a **separate overlay**, never in the
//! alacritty grid. Remote PTY bytes are always applied unchanged via
//! [`super::term::Emulator::feed`]; the overlay is then reconciled against
//! parsed cells. Confirmed glyphs disappear (remote paint takes over at the
//! same pixels); mismatches or unsafe modes clear the overlay.
//!
//! Safety rules (conservative — prefer lag over leaking secrets):
//! - No paint until echo is **established** (at least one successful
//!   invisible expect→cell match). Password / `noecho` never lights the overlay.
//! - Disable / clear on alt-screen, insert mode, signals, cursor keys, Enter,
//!   Tab, large/multiline paste, IME preedit, resize, reconnect, TTL expiry.
//! - Bound pending queue size and per-prediction TTL.
//! - Never duplicate bytes on the wire; authorization and write path unchanged.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Term, TermMode};

use super::term::TermHost;

/// Hard cap on unconfirmed overlay + expect entries (DoS / runaway paste).
pub const MAX_PENDING: usize = 256;
/// Drop predictions that the remote never confirmed.
pub const PREDICTION_TTL: Duration = Duration::from_millis(1_500);
/// After this many consecutive confirms, keep predicting until a mismatch.
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
    /// Echo appears to match typed printables — safe to paint faintly.
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

    pub fn clear(&mut self) {
        self.pending.clear();
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

    /// Observe modes after remote feed; clear when entering unsafe modes.
    pub fn observe_modes(&mut self, term: &Term<TermHost>) {
        let safe = Self::modes_safe(term);
        if !safe {
            if !self.blocked {
                self.clear();
                self.echo_ready = false;
                self.confirm_streak = 0;
            }
            self.blocked = true;
        } else {
            self.blocked = false;
        }
    }

    /// Classify outbound PTY bytes and update the overlay / expect queue.
    ///
    /// Returns whether any new painted prediction was added (caller may
    /// request an immediate egui repaint — no network wait).
    pub fn note_outbound(&mut self, term: &Term<TermHost>, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        self.observe_modes(term);
        if self.blocked || !Self::modes_safe(term) {
            self.clear();
            return false;
        }

        // Signals / controls: invalidate.
        if bytes.iter().any(|&b| matches!(b, 0x03 | 0x04 | 0x1a | 0x1c)) {
            self.clear();
            self.echo_ready = false;
            self.confirm_streak = 0;
            return false;
        }

        // Escape / CSI / SS3 — cursor keys, function keys: do not predict.
        if bytes.contains(&0x1b) {
            self.clear();
            return false;
        }

        // Backspace / DEL: drop last prediction if any; else clear expects.
        if bytes.iter().all(|&b| matches!(b, 0x08 | 0x7f)) {
            if let Some(last) = self.pending.pop_back() {
                self.cursor_line = last.line;
                self.cursor_col = last.col;
            } else {
                self.clear();
            }
            return false;
        }

        // CR / LF / Tab: line-editing boundary — clear overlay.
        if bytes.iter().any(|&b| matches!(b, b'\r' | b'\n' | b'\t')) {
            self.clear();
            return false;
        }

        // Bracketed paste markers or very large blobs: do not speculate.
        if bytes.len() > 64 || bytes.windows(6).any(|w| w == b"\x1b[200~") {
            self.clear();
            return false;
        }

        let Ok(text) = std::str::from_utf8(bytes) else {
            self.clear();
            return false;
        };
        if text.chars().any(|c| c.is_control()) {
            self.clear();
            return false;
        }

        self.sync_cursor_from_term(term);
        let mut painted_any = false;
        for ch in text.chars() {
            if !is_predictable_char(ch) {
                self.clear();
                return painted_any;
            }
            if self.pending.len() >= MAX_PENDING {
                self.clear();
                self.echo_ready = false;
                return painted_any;
            }
            let cells = cell_width(ch);
            let cols = term.columns();
            if self.cursor_col + cells > cols {
                // Wrap prediction is fragile; skip rather than mis-draw.
                self.clear();
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
        self.expire_ttl();

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
                // Not yet echoed — leave pending (blank is neutral).
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
            self.pending.clear();
            self.echo_ready = false;
            self.confirm_streak = 0;
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

    fn expire_ttl(&mut self) {
        let now = Instant::now();
        let before = self.pending.len();
        self.pending.retain(|p| now.duration_since(p.created) <= PREDICTION_TTL);
        if self.pending.len() < before {
            // Timed-out expects → treat as no-echo (password / silent).
            if self.pending.is_empty() {
                self.echo_ready = false;
                self.confirm_streak = 0;
            }
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
    // Space is predictable for normal echo shells; still gated by echo_ready.
    true
}

/// Terminal cell width heuristic (ASCII=1, common CJK/wide=2) without new deps.
pub fn cell_width(ch: char) -> usize {
    if ch.is_ascii() {
        return 1;
    }
    match ch {
        '\u{1100}'..='\u{115f}'
        | '\u{2329}'..='\u{232a}'
        | '\u{2e80}'..='\u{a4cf}'
        | '\u{ac00}'..='\u{d7a3}'
        | '\u{f900}'..='\u{faff}'
        | '\u{fe10}'..='\u{fe19}'
        | '\u{fe30}'..='\u{fe6f}'
        | '\u{ff01}'..='\u{ff60}'
        | '\u{ffe0}'..='\u{ffe6}'
        | '\u{1f300}'..='\u{1f64f}'
        | '\u{1f900}'..='\u{1f9ff}'
        | '\u{20000}'..='\u{2fffd}'
        | '\u{30000}'..='\u{3fffd}' => 2,
        _ => 1,
    }
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
    // Fallback: read via grid if not in display_iter (scrolled out).
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
        // First keystroke: expect only, no paint (password / unknown echo).
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
        // Remote echoes 'a' and advances cursor.
        emu.feed_raw(b"a");
        assert!(emu.local_echo().echo_ready(), "first confirm establishes echo");
        assert_eq!(emu.local_echo().pending_len(), 0);

        let t0 = Instant::now();
        let painted = emu.note_local_echo_outbound(b"b");
        let local_latency = t0.elapsed();
        assert!(painted);
        assert!(
            local_latency < Duration::from_millis(5),
            "keystroke→overlay must not wait on network; took {local_latency:?}"
        );
        assert_eq!(emu.local_echo().painted_len(), 1);
        let overlay = emu.local_echo().overlay_cells(emu.term_ref());
        assert_eq!(overlay.len(), 1);
        assert_eq!(overlay[0].ch, 'b');

        // Delayed remote echo — reconcile removes overlay without duplication.
        thread::sleep(Duration::from_millis(20));
        emu.feed_raw(b"b");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.viewport_text().contains('b'));
    }

    #[test]
    fn no_echo_timeout_disables_predictions() {
        let mut emu = Emulator::new(24, 80);
        // Force a short TTL path by manually aging — establish first.
        emu.note_local_echo_outbound(b"x");
        emu.feed_raw(b"x");
        assert!(emu.local_echo().echo_ready());
        emu.note_local_echo_outbound(b"y");
        assert_eq!(emu.local_echo().painted_len(), 1);
        // Simulate TTL expiry.
        emu.age_local_echo_front(PREDICTION_TTL + Duration::from_millis(1));
        emu.reconcile_local_echo();
        assert!(!emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().pending_len(), 0);
    }

    #[test]
    fn alt_screen_clears_and_blocks() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        emu.note_local_echo_outbound(b"b");
        assert_eq!(emu.local_echo().painted_len(), 1);
        emu.feed_raw(b"\x1b[?1049h"); // enter alt screen
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
        // Remote prints something else at cursor (shell redraw).
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
    fn reset_on_generation_change() {
        let mut echo = SpeculativeEcho::new(1);
        echo.echo_ready = true;
        echo.reset(2);
        assert_eq!(echo.generation(), 2);
        assert!(!echo.echo_ready());
        assert_eq!(echo.pending_len(), 0);
    }
}
