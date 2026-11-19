//! Terminal input bookkeeping for the desktop Controller.
//!
//! # Safe default (fail-closed)
//!
//! The agentlink PTY protocol does **not** carry host `termios` ECHO (or any
//! other authoritative per-keystroke “safe to predict” bit). Without that,
//! **no** local heuristic — previous echoed glyph, burst promotion, TTL,
//! prompt text, or sampled ECHO snapshots — can authorize painting glyphs the
//! remote has not confirmed. In-flight `stty -echo` / `sudo` / `read -s`
//! races make sticky or promoted prediction a password-disclosure bug (E1b).
//!
//! Therefore this module’s **default and only** shipped policy is:
//!
//! - **Never paint** unconfirmed glyphs (`painted` is always false;
//!   [`overlay_cells`] is always empty).
//! - Keystrokes still go to the remote PTY immediately (unchanged wire path);
//!   the UI waits for **remote echo** for visible characters.
//! - Optional expect/reconcile bookkeeping may remain for future protocol work;
//!   it must not expose an overlay.
//!
//! This is **not** completed t537 “instant faint speculative echo.” That
//! feature stays unsatisfied until an end-to-end signal can establish safe
//! semantics. Latency wins that do not predict (immediate dispatch, local
//! repaint scheduling) live outside this file.
//!
//! Remote PTY bytes are always applied unchanged via
//! [`super::term::Emulator::feed`].

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Term, TermMode};
use unicode_width::UnicodeWidthChar;

use super::term::TermHost;

/// Hard cap on expect-queue entries (DoS / runaway paste).
pub const MAX_PENDING: usize = 256;
/// Drop expects the remote never matched.
pub const PREDICTION_TTL: Duration = Duration::from_millis(1_500);

/// One expect at a grid point (never painted under the safe default).
#[derive(Debug, Clone)]
pub struct Prediction {
    pub line: i32,
    pub col: usize,
    pub ch: char,
    pub cells: usize,
    pub created: Instant,
    /// Always false in the shipped safe default.
    pub painted: bool,
}

/// Snapshot type retained for paint hooks; safe default yields none.
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
    cursor_line: i32,
    cursor_col: usize,
    generation: u64,
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

    pub fn clear_pending(&mut self) {
        self.pending.clear();
    }

    pub fn invalidate(&mut self) {
        self.pending.clear();
    }

    pub fn clear(&mut self) {
        self.invalidate();
    }

    /// Always false: safe default never authorizes paint.
    pub fn echo_ready(&self) -> bool {
        false
    }

    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }

    /// Always zero under the safe default.
    pub fn painted_len(&self) -> usize {
        0
    }

    #[cfg(test)]
    pub(super) fn pending_front(&self) -> Option<&Prediction> {
        self.pending.front()
    }

    #[cfg(test)]
    pub(super) fn pending_front_mut(&mut self) -> Option<&mut Prediction> {
        self.pending.front_mut()
    }

    pub fn sync_cursor_from_term(&mut self, term: &Term<TermHost>) {
        if self.pending.is_empty() {
            let content = term.renderable_content();
            self.cursor_line = content.cursor.point.line.0;
            self.cursor_col = content.cursor.point.column.0;
        }
    }

    pub fn modes_safe(term: &Term<TermHost>) -> bool {
        let mode = term.mode();
        !mode.contains(TermMode::ALT_SCREEN) && !mode.contains(TermMode::INSERT)
    }

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

    /// UI-frame housekeeping (TTL). Never introduces painted cells.
    pub fn tick(&mut self, term: &Term<TermHost>) -> bool {
        let _ = term;
        let before = self.pending.len();
        self.expire_ttl();
        before != self.pending.len()
    }

    /// Record outbound bytes for expect bookkeeping.
    ///
    /// **Always returns false** — the safe default never enqueues painted
    /// overlay cells. Callers must not treat a true return as authorization
    /// to show predicted glyphs.
    pub fn note_outbound(&mut self, term: &Term<TermHost>, bytes: &[u8]) -> bool {
        if bytes.is_empty() {
            return false;
        }
        self.expire_ttl();
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

        self.sync_cursor_from_term(term);
        for ch in text.chars() {
            if !is_predictable_char(ch) {
                self.invalidate();
                return false;
            }
            let cells = cell_width(ch);
            if cells == 0 {
                self.invalidate();
                return false;
            }
            if self.pending.len() >= MAX_PENDING {
                self.invalidate();
                return false;
            }
            let cols = term.columns();
            if self.cursor_col + cells > cols {
                self.invalidate();
                return false;
            }
            // Safe default: never mark painted. No promotion path exists.
            self.pending.push_back(Prediction {
                line: self.cursor_line,
                col: self.cursor_col,
                ch,
                cells,
                created: Instant::now(),
                painted: false,
            });
            self.cursor_col += cells;
        }
        false
    }

    /// Reconcile expects against the remote-authoritative grid.
    ///
    /// Confirms drop expects; mismatches invalidate. **Never** promotes
    /// remaining expects to painted (that was E1b challenge 2).
    pub fn reconcile(&mut self, term: &Term<TermHost>, _remote_drove: bool) {
        self.observe_modes(term);
        if self.blocked {
            return;
        }
        self.expire_ttl();

        let now_cursor = {
            let content = term.renderable_content();
            (content.cursor.point.line.0, content.cursor.point.column.0)
        };

        while let Some(front) = self.pending.front() {
            let cell = cell_at(term, front.line, front.col);
            let Some((ch, _wide)) = cell else {
                break;
            };
            if ch == ' ' || ch == '\0' {
                break;
            }
            if ch == front.ch {
                let past = now_cursor.0 > front.line
                    || (now_cursor.0 == front.line && now_cursor.1 >= front.col + front.cells);
                // Unpainted expects confirm on glyph match (learning only).
                if past || !front.painted {
                    self.pending.pop_front();
                    continue;
                }
                break;
            }
            self.invalidate();
            self.sync_cursor_from_term(term);
            return;
        }
        if self.pending.is_empty() {
            self.sync_cursor_from_term(term);
        }
    }

    fn expire_ttl(&mut self) {
        let now = Instant::now();
        let before = self.pending.len();
        self.pending
            .retain(|p| now.duration_since(p.created) <= PREDICTION_TTL);
        if self.pending.len() < before {
            self.pending.clear();
        }
    }

    /// Safe default: no overlay cells are ever returned.
    pub fn overlay_cells(&self, _term: &Term<TermHost>) -> Vec<OverlayCell> {
        Vec::new()
    }

    pub fn speculative_cursor(&self, _term: &Term<TermHost>) -> Option<(usize, usize)> {
        None
    }
}

fn is_predictable_char(ch: char) -> bool {
    if ch.is_control() || ch == '\u{7f}' {
        return false;
    }
    true
}

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

pub fn faint_fg() -> eframe::egui::Color32 {
    eframe::egui::Color32::from_rgb(0x9A, 0x9A, 0xA8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller::term::Emulator;

    #[test]
    fn safe_default_never_paints_on_establish_or_burst() {
        let mut emu = Emulator::new(24, 80);
        assert!(!emu.note_local_echo_outbound(b"a"));
        emu.feed_raw(b"a");
        assert!(!emu.local_echo().echo_ready());
        assert_eq!(emu.local_echo().painted_len(), 0);
        // Ahead-of-echo typing after a confirm still must not paint.
        assert!(!emu.note_local_echo_outbound(b"bcdef"));
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
    }

    /// Review challenge (1): nonempty “burst” then silent ECHO-off → SEKRET
    /// must not paint (stand-in glyphs, not a real secret).
    #[test]
    fn challenge_nonempty_burst_then_silent_echo_off_zero_paint() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"hi");
        emu.feed_raw(b"hi");
        // Type ahead while remote is silent (ECHO flipped off).
        assert!(!emu.note_local_echo_outbound(b"SEKRET"));
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
        // Even if a future buggy path set painted flags, overlay_cells is empty.
        if let Some(p) = emu.local_echo_mut().pending_front_mut() {
            p.painted = true;
        }
        assert!(
            emu.local_echo().overlay_cells(emu.term_ref()).is_empty(),
            "safe default must refuse to expose overlay even if a flag is forced"
        );
    }

    /// Review challenge (2): unpainted probe `sekrit`, remote confirms only `s`
    /// → remaining `ekrit` must never be promoted/painted.
    #[test]
    fn challenge_partial_confirm_must_not_paint_remaining_tail() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"sekrit");
        assert_eq!(emu.local_echo().pending_len(), 6);
        assert_eq!(emu.local_echo().painted_len(), 0);
        emu.feed_raw(b"s");
        // Tail may still be pending as expects, but never painted / never overlay.
        assert!(emu.local_echo().pending_len() >= 1, "ekrit tail should remain as expects");
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
        // Even if every remaining expect flag is forced painted, overlay stays empty
        // (no promotion API; safe default hard-disables overlay emission).
        if let Some(p) = emu.local_echo_mut().pending_front_mut() {
            p.painted = true;
        }
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
    }

    /// Models isolated `stty -echo`: remote stops echoing after a normal burst.
    #[test]
    fn challenge_stty_echo_off_transition_zero_unconfirmed_overlay() {
        let mut emu = Emulator::new(24, 80);
        // Normal echoing shell.
        emu.note_local_echo_outbound(b"echo");
        emu.feed_raw(b"echo");
        emu.note_local_echo_outbound(b"\r");
        emu.feed_raw(b"\r\n");
        // Remote-only: program enables no-echo (no local CR required).
        emu.feed_raw(b"Password: ");
        // Stand-in nonsecret glyphs typed under no-echo.
        assert!(!emu.note_local_echo_outbound(b"xxxx"));
        // Silent remote (no echo bytes).
        emu.tick_local_echo();
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
        assert!(!emu.viewport_text().contains("xxxx"));
    }

    #[test]
    fn shell_enter_password_path_zero_paint() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"whoami");
        emu.feed_raw(b"whoami");
        emu.note_local_echo_outbound(b"\r");
        emu.feed_raw(b"\r\nPassword: ");
        assert!(!emu.note_local_echo_outbound(b"sekrit"));
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
    }

    #[test]
    fn remote_only_noecho_without_local_enter_zero_paint() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"a");
        assert!(!emu.note_local_echo_outbound(b"sekrit"));
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
    }

    #[test]
    fn note_outbound_enqueue_is_local_not_paint() {
        let mut emu = Emulator::new(24, 80);
        let t0 = Instant::now();
        let painted = emu.note_local_echo_outbound(b"xyz");
        assert!(t0.elapsed() < Duration::from_millis(5));
        assert!(!painted);
        assert_eq!(emu.local_echo().painted_len(), 0);
    }

    #[test]
    fn alt_screen_and_ctrl_c_invalidate_expects() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"ab");
        assert!(emu.local_echo().pending_len() > 0);
        emu.note_local_echo_outbound(&[0x03]);
        assert_eq!(emu.local_echo().pending_len(), 0);
        emu.note_local_echo_outbound(b"a");
        emu.feed_raw(b"\x1b[?1049h");
        assert_eq!(emu.local_echo().pending_len(), 0);
    }

    #[test]
    fn resize_and_generation_reset_clear() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"ab");
        assert!(emu.resize(30, 100));
        assert_eq!(emu.local_echo().pending_len(), 0);
        emu.note_local_echo_outbound(b"ab");
        emu.reset_local_echo(7);
        assert_eq!(emu.local_echo().generation(), 7);
        assert_eq!(emu.local_echo().pending_len(), 0);
        assert_eq!(emu.local_echo().painted_len(), 0);
    }

    #[test]
    fn wide_cjk_and_combining_still_tracked_unpainted() {
        assert_eq!(cell_width('中'), 2);
        assert_eq!(cell_width('\u{0301}'), 0);
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound("中".as_bytes());
        assert_eq!(emu.local_echo().pending_front().unwrap().cells, 2);
        assert!(!emu.local_echo().pending_front().unwrap().painted);
        assert!(!emu.note_local_echo_outbound("\u{0301}".as_bytes()));
    }

    #[test]
    fn remote_echo_still_updates_viewport_without_overlay() {
        let mut emu = Emulator::new(24, 80);
        emu.note_local_echo_outbound(b"hi");
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
        emu.feed_raw(b"hi");
        assert!(emu.viewport_text().contains("hi"));
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
    }
}

/// Isolated local PTY via Python's `pty` + `stty -echo`. Typed stand-in glyphs
/// are noted on the Emulator the same way the Controller would; the safe
/// default must keep the overlay empty even when the PTY stays silent.
#[cfg(all(test, unix, not(target_env = "musl")))]
mod pty_stty_echo_off_tests {
    use crate::controller::term::Emulator;
    use std::io::Read;
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    #[test]
    fn local_pty_stty_echo_off_zero_unconfirmed_overlay() {
        let python = which("python3").or_else(|| which("python"));
        let Some(python) = python else {
            eprintln!("skipping: python not on PATH");
            return;
        };
        let mut child = Command::new(python)
            .arg("-u")
            .arg("-c")
            .arg(
                r#"
import os, pty, sys, termios, tty
pid, fd = pty.fork()
if pid == 0:
    attrs = termios.tcgetattr(0)
    attrs[3] = attrs[3] & ~termios.ECHO
    termios.tcsetattr(0, termios.TCSANOW, attrs)
    # Read four stand-in glyphs then exit (no echo).
    data = os.read(0, 4)
    os.write(1, b"ACK:" + data)
    os._exit(0)
# Parent: wait briefly for child to disable ECHO, then write stand-ins.
import time
time.sleep(0.05)
os.write(fd, b"xxxx")
# Collect child output with a short deadline.
deadline = time.time() + 2.0
out = b""
while time.time() < deadline:
    import select
    r, _, _ = select.select([fd], [], [], 0.05)
    if not r:
        # check if child exited
        wpid, status = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            break
        continue
    chunk = os.read(fd, 256)
    if not chunk:
        break
    out += chunk
    if b"ACK:" in out:
        break
os.close(fd)
sys.stdout.buffer.write(out)
sys.stdout.buffer.flush()
"#,
            )
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn python pty helper");

        let mut emu = Emulator::new(24, 80);
        assert!(!emu.note_local_echo_outbound(b"xxxx"));
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());

        let mut stdout = child.stdout.take().expect("stdout");
        let mut buf = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            let mut tmp = [0u8; 128];
            match stdout.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&tmp[..n]);
                    emu.feed_raw(&tmp[..n]);
                    assert_eq!(emu.local_echo().painted_len(), 0);
                    assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
                    if buf.windows(4).any(|w| w == b"ACK:") {
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
        let status = child.wait().expect("wait python pty helper");
        assert!(
            status.success() || buf.windows(4).any(|w| w == b"ACK:"),
            "pty helper failed; status={status:?} out={buf:?}"
        );
        // Stand-ins must never have been painted locally under no-echo.
        assert_eq!(emu.local_echo().painted_len(), 0);
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
        if !buf.is_empty() {
            emu.feed_raw(&buf);
        }
        assert!(emu.local_echo().overlay_cells(emu.term_ref()).is_empty());
    }

    fn which(bin: &str) -> Option<std::path::PathBuf> {
        let path = std::env::var_os("PATH")?;
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join(bin);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        None
    }
}
