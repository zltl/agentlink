//! Remote PTY terminal for the desktop Controller.
//!
//! Emulation is Alacritty's `alacritty_terminal` grid and VTE parser
//! (Apache-2.0, https://github.com/alacritty/alacritty, crate 0.25.1).
//! Bytes come from the agentlink PTY; we never spawn a local tty or SSH
//! session. The egui view is our own (the `egui_term` crate talks to a
//! local PTY backend we cannot use here).
//!
//! Local-echo bookkeeping lives in [`super::term_local_echo`]. The shipped
//! safe default **never paints** unconfirmed glyphs (no speculative overlay);
//! the UI waits for remote echo. See that module’s privacy docs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use alacritty_terminal::event::{Event, EventListener};
use alacritty_terminal::grid::{Dimensions, Scroll};
use alacritty_terminal::index::{Column, Line, Point, Side};
use alacritty_terminal::selection::{Selection, SelectionType};
use alacritty_terminal::term::cell::Flags;
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, NamedColor, Processor};
use eframe::egui::{
    self, Color32, Event as GuiEvent, ImeEvent, Key, PointerButton, Pos2, Rect, Vec2,
};

use super::term_local_echo::{self, SpeculativeEcho};

/// Maximum decoded UTF-8 byte length accepted from OSC 52 when explicitly enabled.
pub const OSC52_MAX_BYTES: usize = 64 * 1024;

const DEFAULT_FONT_SIZE: f32 = 13.0;
const MIN_FONT_SIZE: f32 = 8.0;
const MAX_FONT_SIZE: f32 = 32.0;
const FONT_SIZE_STEP: f32 = 1.0;

/// Bytes the UI should write to the remote PTY after one frame.
#[derive(Debug, Default)]
pub struct TermOutput {
    pub writes: Vec<u8>,
    pub resized: Option<(u16, u16)>,
    pub osc52_copied_chars: Option<usize>,
}

struct TermDims {
    cols: usize,
    rows: usize,
}

impl Dimensions for TermDims {
    fn total_lines(&self) -> usize {
        self.rows
    }
    fn screen_lines(&self) -> usize {
        self.rows
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

#[derive(Clone, Default)]
pub(super) struct TermHost {
    pending: Arc<Mutex<Vec<u8>>>,
    title: Arc<Mutex<String>>,
    clipboard: Arc<Mutex<Option<String>>>,
    /// Default `false`: remote PTY output cannot silently overwrite the host clipboard.
    allow_osc52: Arc<AtomicBool>,
}

impl EventListener for TermHost {
    fn send_event(&self, event: Event) {
        match event {
            Event::PtyWrite(text) => self
                .pending
                .lock()
                .expect("term host")
                .extend(text.into_bytes()),
            Event::Title(title) => *self.title.lock().expect("term host") = title,
            Event::ResetTitle => self.title.lock().expect("term host").clear(),
            Event::ClipboardStore(_, text) => {
                if self.allow_osc52.load(Ordering::Relaxed)
                    && !text.is_empty()
                    && text.len() <= OSC52_MAX_BYTES
                    && !text.contains('\0')
                {
                    *self.clipboard.lock().expect("term host") = Some(text);
                }
            }
            _ => {}
        }
    }
}

pub struct Emulator {
    term: Term<TermHost>,
    parser: Processor,
    host: TermHost,
    rows: u16,
    cols: u16,
    font_size: f32,
    ime_preedit: String,
    pub focused: bool,
    pending_refocus: bool,
    selecting: bool,
    /// GUI keystrokes already taken this frame (so show() does not double-read).
    keys_taken: bool,
    pending_gui_writes: Vec<u8>,
    /// Local-echo expects (safe default: never painted; remote grid authoritative).
    local_echo: SpeculativeEcho,
}

impl Default for Emulator {
    fn default() -> Self {
        Self::new(24, 80)
    }
}

impl Emulator {
    pub fn new(rows: u16, cols: u16) -> Self {
        let host = TermHost::default();
        let rows = rows.max(2);
        let cols = cols.max(8);
        let dims = TermDims {
            cols: cols as usize,
            rows: rows as usize,
        };
        let mut config = Config::default();
        config.scrolling_history = 5_000;
        let term = Term::new(config, &dims, host.clone());
        Self {
            term,
            parser: Processor::new(),
            host,
            rows,
            cols,
            font_size: DEFAULT_FONT_SIZE,
            ime_preedit: String::new(),
            focused: false,
            pending_refocus: false,
            selecting: false,
            keys_taken: false,
            pending_gui_writes: Vec::new(),
            local_echo: SpeculativeEcho::new(0),
        }
    }

    pub fn size(&self) -> (u16, u16) {
        (self.rows, self.cols)
    }

    pub fn font_size(&self) -> f32 {
        self.font_size
    }

    fn apply_zoom(&mut self, zoom: ZoomAction) {
        match zoom {
            ZoomAction::In => {
                self.font_size = (self.font_size + FONT_SIZE_STEP).min(MAX_FONT_SIZE);
            }
            ZoomAction::Out => {
                self.font_size = (self.font_size - FONT_SIZE_STEP).max(MIN_FONT_SIZE);
            }
            ZoomAction::Reset => {
                self.font_size = DEFAULT_FONT_SIZE;
            }
        }
    }

    /// Reset speculative echo for a new PTY generation (reconnect / reopen).
    pub fn reset_local_echo(&mut self, generation: u64) {
        self.local_echo.reset(generation);
    }

    pub fn local_echo(&self) -> &SpeculativeEcho {
        &self.local_echo
    }

    pub fn local_echo_mut(&mut self) -> &mut SpeculativeEcho {
        &mut self.local_echo
    }

    pub(super) fn term_ref(&self) -> &Term<TermHost> {
        &self.term
    }

    /// Record outbound PTY bytes for speculative echo (paint is local-only).
    pub fn note_local_echo_outbound(&mut self, bytes: &[u8]) -> bool {
        self.local_echo.note_outbound(&self.term, bytes)
    }

    pub fn reconcile_local_echo(&mut self) {
        self.local_echo.reconcile(&self.term, false);
    }

    /// UI-frame tick: expire painted blanks / TTL without waiting on remote feed.
    pub fn tick_local_echo(&mut self) -> bool {
        self.local_echo.tick(&self.term)
    }

    #[cfg(test)]
    pub(super) fn age_local_echo_front(&mut self, age: std::time::Duration) {
        if let Some(p) = self.local_echo.pending_front_mut() {
            p.created = std::time::Instant::now()
                .checked_sub(age)
                .unwrap_or_else(std::time::Instant::now);
        }
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.parser.advance(&mut self.term, bytes);
            self.local_echo.reconcile(&self.term, true);
        }
    }

    /// Alias used by local-echo tests (same as [`Self::feed`]).
    #[cfg(test)]
    pub(super) fn feed_raw(&mut self, bytes: &[u8]) {
        self.feed(bytes);
    }

    pub fn take_writes(&self) -> Vec<u8> {
        std::mem::take(&mut *self.host.pending.lock().expect("term host"))
    }

    pub fn take_osc52_copy(&self) -> Option<String> {
        if !self.allows_osc52() {
            let _ = self.host.clipboard.lock().expect("term host").take();
            return None;
        }
        self.host.clipboard.lock().expect("term host").take()
    }

    pub fn allows_osc52(&self) -> bool {
        self.host.allow_osc52.load(Ordering::Relaxed)
    }

    pub fn set_allow_osc52(&self, allow: bool) {
        self.host.allow_osc52.store(allow, Ordering::Relaxed);
        if !allow {
            let _ = self.host.clipboard.lock().expect("term host").take();
        }
    }

    pub fn title(&self) -> String {
        self.host.title.lock().expect("term host").clone()
    }

    pub fn resize(&mut self, rows: u16, cols: u16) -> bool {
        let rows = rows.max(2);
        let cols = cols.max(8);
        if rows == self.rows && cols == self.cols {
            return false;
        }
        self.rows = rows;
        self.cols = cols;
        self.term.resize(TermDims {
            cols: cols as usize,
            rows: rows as usize,
        });
        // Grid geometry changed — drop overlay rather than misplace glyphs.
        self.local_echo.clear();
        true
    }

    pub fn app_cursor(&self) -> bool {
        self.term.mode().contains(TermMode::APP_CURSOR)
    }

    /// Visible viewport as plain lines. Wide cells occupy two columns.
    pub fn viewport_text(&self) -> String {
        let content = self.term.renderable_content();
        let cols = self.term.columns();
        let rows = self.term.screen_lines();
        let mut lines = vec![" ".repeat(cols); rows];
        for indexed in content.display_iter {
            if indexed.cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                continue;
            }
            let row = (Line(indexed.point.line.0 + content.display_offset as i32)).0;
            let col = indexed.point.column.0;
            if row < 0 || row as usize >= rows || col >= cols {
                continue;
            }
            let line = &mut lines[row as usize];
            let mut chars: Vec<char> = line.chars().collect();
            if col < chars.len() {
                chars[col] = if indexed.cell.c == '\0' {
                    ' '
                } else {
                    indexed.cell.c
                };
                *line = chars.into_iter().collect();
            }
        }
        let mut out = lines.join("\n");
        while out.ends_with('\n') || out.ends_with(' ') {
            if out.ends_with("\n") {
                out.pop();
            } else if out.ends_with(' ') && !out.ends_with(" \n") {
                // trim trailing spaces on the last line only for test compare
                if out.chars().rev().take_while(|c| *c == ' ').count() > 0
                    && !out.trim_end().is_empty()
                {
                    out = out
                        .lines()
                        .map(|l| l.trim_end())
                        .collect::<Vec<_>>()
                        .join("\n");
                }
                break;
            } else {
                break;
            }
        }
        out.lines()
            .map(|l| l.trim_end())
            .collect::<Vec<_>>()
            .join("\n")
    }

    pub fn cursor_pos(&self) -> (usize, usize) {
        let content = self.term.renderable_content();
        let row = (Line(content.cursor.point.line.0 + content.display_offset as i32))
            .0
            .max(0) as usize;
        (row, content.cursor.point.column.0)
    }

    pub fn cell_fg_named_is_red(&self, row: usize, col: usize) -> bool {
        let content = self.term.renderable_content();
        for indexed in content.display_iter {
            let r = (Line(indexed.point.line.0 + content.display_offset as i32)).0;
            if r >= 0 && r as usize == row && indexed.point.column.0 == col {
                return matches!(
                    indexed.cell.fg,
                    Color::Named(NamedColor::Red | NamedColor::BrightRed)
                ) || matches!(indexed.cell.fg, Color::Indexed(1 | 9));
            }
        }
        false
    }

    pub fn cell_width_at(&self, row: usize, col: usize) -> usize {
        let content = self.term.renderable_content();
        for indexed in content.display_iter {
            let r = (Line(indexed.point.line.0 + content.display_offset as i32)).0;
            if r >= 0 && r as usize == row && indexed.point.column.0 == col {
                if indexed.cell.flags.contains(Flags::WIDE_CHAR) {
                    return 2;
                }
                if indexed.cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                    return 0;
                }
                return 1;
            }
        }
        0
    }

    pub fn selection_text(&self) -> Option<String> {
        let text = self.term.selection_to_string()?;
        let trimmed = text.trim_end_matches('\n').to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(text)
        }
    }

    /// Encode a named key to PTY bytes (xterm defaults, plus application cursor).
    pub fn encode_key(
        name: &str,
        ctrl: bool,
        alt: bool,
        shift: bool,
        app_cursor: bool,
    ) -> Option<Vec<u8>> {
        let key = name.to_ascii_lowercase();
        if ctrl {
            if let Some(byte) = ctrl_byte(&key) {
                let mut out = Vec::new();
                if alt {
                    out.push(0x1b);
                }
                out.push(byte);
                return Some(out);
            }
        }
        let seq: &[u8] = match key.as_str() {
            "enter" | "return" => b"\r",
            "backspace" => b"\x7f",
            "tab" if shift => b"\x1b[Z",
            "tab" => b"\t",
            "escape" => b"\x1b",
            "up" | "arrowup" => {
                return Some(csi_letter(b'A', app_cursor, ctrl, alt, shift));
            }
            "down" | "arrowdown" => {
                return Some(csi_letter(b'B', app_cursor, ctrl, alt, shift));
            }
            "right" | "arrowright" => {
                return Some(csi_letter(b'C', app_cursor, ctrl, alt, shift));
            }
            "left" | "arrowleft" => {
                return Some(csi_letter(b'D', app_cursor, ctrl, alt, shift));
            }
            "home" => {
                return Some(csi_letter(b'H', app_cursor, ctrl, alt, shift));
            }
            "end" => {
                return Some(csi_letter(b'F', app_cursor, ctrl, alt, shift));
            }
            "insert" => return Some(csi_tilde(2, ctrl, alt, shift)),
            "delete" => return Some(csi_tilde(3, ctrl, alt, shift)),
            "pageup" => return Some(csi_tilde(5, ctrl, alt, shift)),
            "pagedown" => return Some(csi_tilde(6, ctrl, alt, shift)),
            "f1" => return Some(csi_f1_f4(b'P', ctrl, alt, shift)),
            "f2" => return Some(csi_f1_f4(b'Q', ctrl, alt, shift)),
            "f3" => return Some(csi_f1_f4(b'R', ctrl, alt, shift)),
            "f4" => return Some(csi_f1_f4(b'S', ctrl, alt, shift)),
            "f5" => return Some(csi_tilde(15, ctrl, alt, shift)),
            "f6" => return Some(csi_tilde(17, ctrl, alt, shift)),
            "f7" => return Some(csi_tilde(18, ctrl, alt, shift)),
            "f8" => return Some(csi_tilde(19, ctrl, alt, shift)),
            "f9" => return Some(csi_tilde(20, ctrl, alt, shift)),
            "f10" => return Some(csi_tilde(21, ctrl, alt, shift)),
            "f11" => return Some(csi_tilde(23, ctrl, alt, shift)),
            "f12" => return Some(csi_tilde(24, ctrl, alt, shift)),
            _ => {
                if alt && !ctrl {
                    if let Some(ch) = alt_char(&key, shift) {
                        return Some(vec![0x1b, ch as u8]);
                    }
                }
                return None;
            }
        };
        let mut out = Vec::new();
        if alt && seq != b"\x1b" {
            out.push(0x1b);
        }
        out.extend_from_slice(seq);
        Some(out)
    }

    pub fn encode_text(text: &str, alt: bool) -> Vec<u8> {
        let mut out = Vec::new();
        for ch in text.chars() {
            if alt {
                out.push(0x1b);
            }
            match ch {
                '\n' => out.push(b'\r'),
                c => out.extend(c.encode_utf8(&mut [0; 4]).as_bytes()),
            }
        }
        out
    }

    /// Drop Text events that would double-type an IME commit, a composing
    /// preview, or a special key already encoded in this frame.
    pub fn skip_duplicate_text(
        text: &str,
        ime_commits: &[String],
        preedit_active: bool,
        control_key_sent: bool,
    ) -> bool {
        if preedit_active {
            return true;
        }
        if ime_commits.iter().any(|commit| commit == text) {
            return true;
        }
        control_key_sent && matches!(text, "\n" | "\r" | "\t" | "\u{1b}")
    }

    /// Strip inner bracketed-paste delimiters (including nested reassemblies,
    /// zero-padded forms, and C1 CSI) plus every remaining ESC (`0x1b`) and
    /// C1 CSI (`0x9b` / U+009B) so clipboard payloads can never close
    /// bracketed paste or inject raw terminal control sequences.
    ///
    /// Valid multi-byte UTF-8 characters whose continuation byte happens to be
    /// `0x9b` (e.g., `国`, `回`, `丛`) are preserved intact.
    pub fn sanitize_bracketed_paste(data: &[u8]) -> Vec<u8> {
        #[derive(Clone, Copy, PartialEq, Eq)]
        enum PasteUnit {
            Char(char),
            Raw(u8),
        }

        fn trim_trailing_paste_delimiter(units: &mut Vec<PasteUnit>) {
            let len = units.len();
            if len < 5 || units[len - 1] != PasteUnit::Char('~') {
                return;
            }
            if !matches!(units[len - 2], PasteUnit::Char('0' | '1'))
                || units[len - 3] != PasteUnit::Char('0')
                || units[len - 4] != PasteUnit::Char('2')
            {
                return;
            }
            let mut j = len - 4;
            while j > 0 && units[j - 1] == PasteUnit::Char('0') {
                j -= 1;
            }
            if j >= 2
                && units[j - 2] == PasteUnit::Char('\x1b')
                && units[j - 1] == PasteUnit::Char('[')
            {
                units.truncate(j - 2);
            } else if j >= 1
                && matches!(
                    units[j - 1],
                    PasteUnit::Char('\u{009b}') | PasteUnit::Raw(0x9b)
                )
            {
                units.truncate(j - 1);
            }
        }

        let mut units: Vec<PasteUnit> = Vec::with_capacity(data.len());
        for chunk in data.utf8_chunks() {
            for ch in chunk.valid().chars() {
                units.push(PasteUnit::Char(ch));
                if ch == '~' {
                    trim_trailing_paste_delimiter(&mut units);
                }
            }
            for &b in chunk.invalid() {
                units.push(PasteUnit::Raw(b));
            }
        }

        let mut out = Vec::with_capacity(data.len());
        let mut utf8_buf = [0u8; 4];
        for unit in units {
            match unit {
                PasteUnit::Char('\x1b' | '\u{009b}') => {}
                PasteUnit::Char(ch) => {
                    out.extend_from_slice(ch.encode_utf8(&mut utf8_buf).as_bytes());
                }
                PasteUnit::Raw(0x1b | 0x9b) => {}
                PasteUnit::Raw(b) => out.push(b),
            }
        }
        out
    }

    pub fn wrap_paste(data: &[u8], bracketed: bool) -> Vec<u8> {
        let sanitized = if bracketed {
            Self::sanitize_bracketed_paste(data)
        } else {
            data.to_vec()
        };
        let normalized = normalize_paste_newlines(&sanitized);
        if bracketed {
            let mut out = Vec::with_capacity(normalized.len() + 12);
            out.extend_from_slice(b"\x1b[200~");
            out.extend_from_slice(&normalized);
            out.extend_from_slice(b"\x1b[201~");
            out
        } else {
            normalized
        }
    }

    pub fn history_lines(&self) -> usize {
        self.term.history_size()
    }

    /// Keyboard, IME, and clipboard events that belong to a focused terminal.
    /// Pointer and scroll events are not captured so machine-rail clicks still work.
    pub fn is_captured_event(event: &GuiEvent) -> bool {
        matches!(
            event,
            GuiEvent::Key { .. }
                | GuiEvent::Text(_)
                | GuiEvent::Ime(_)
                | GuiEvent::Copy
                | GuiEvent::Cut
                | GuiEvent::Paste(_)
        )
    }

    /// Drain captured events from the egui context *before* any other widget
    /// is drawn. This stops Enter / arrows from activating a default or
    /// colliding machine-rail button (a cross-node session switch).
    pub fn consume_focused_keys(&mut self, ctx: &egui::Context) {
        let window_lost_focus = ctx.input(|i| {
            i.events
                .iter()
                .any(|e| matches!(e, GuiEvent::WindowFocused(false)))
        });
        if window_lost_focus {
            self.ime_preedit.clear();
        }
        if !self.focused {
            self.ime_preedit.clear();
            return;
        }
        let modifiers = ctx.input(|i| i.modifiers);
        let mut captured = Vec::new();
        ctx.input_mut(|i| {
            let mut rest = Vec::new();
            for event in i.events.drain(..) {
                if Self::is_captured_event(&event) {
                    captured.push(event);
                } else {
                    rest.push(event);
                }
            }
            i.events = rest;
        });
        let plan = self.collect_writes(&captured, modifiers);
        if let Some(text) = plan.copy_text {
            if !text.is_empty() {
                ctx.copy_text(text);
            }
        }
        let had_paste = plan.paste_text.is_some();
        if let Some(text) = plan.paste_text {
            self.pending_gui_writes.extend(Self::wrap_paste(
                text.as_bytes(),
                self.term.mode().contains(TermMode::BRACKETED_PASTE),
            ));
        }
        if plan.want_paste {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
        }
        if !plan.writes.is_empty() || had_paste {
            if self.term.grid().display_offset() > 0 {
                self.term.scroll_display(Scroll::Bottom);
            }
            self.pending_gui_writes.extend(plan.writes);
        }
        if plan.clear_selection || plan.scroll.is_some() || plan.zoom.is_some() {
            ctx.request_repaint();
        }
        self.keys_taken = true;
    }

    fn collect_writes(&mut self, events: &[GuiEvent], modifiers: egui::Modifiers) -> PlannedEvents {
        let selection = self.term.selection_to_string();
        let alt_screen = self.term.mode().contains(TermMode::ALT_SCREEN);
        let plan = plan_terminal_events_full(
            events,
            selection.as_deref(),
            self.app_cursor(),
            modifiers,
            alt_screen,
        );
        if let Some(text) = &plan.preedit {
            self.ime_preedit = text.clone();
        }
        if plan.clear_selection {
            self.term.selection = None;
        }
        if let Some(scroll) = plan.scroll {
            self.term.scroll_display(scroll);
        }
        if let Some(zoom) = plan.zoom {
            self.apply_zoom(zoom);
        }
        plan
    }

    /// Draw the emulator and collect PTY input for this frame.
    pub fn show(&mut self, ui: &mut egui::Ui) -> TermOutput {
        let mut out = TermOutput {
            writes: self.take_writes(),
            resized: None,
            osc52_copied_chars: None,
        };
        let font = egui::FontId::monospace(self.font_size);
        let (cell_w, cell_h) = ui.fonts(|fonts| {
            let galley = fonts.layout_no_wrap("W".to_owned(), font.clone(), Color32::WHITE);
            let w = galley.size().x.max(7.0);
            let h = galley.size().y.max(font.size * 1.25);
            (w, h)
        });
        let avail = ui.available_size();
        let cols = ((avail.x / cell_w).floor() as u16).clamp(8, 400);
        let rows = ((avail.y / cell_h).floor() as u16).clamp(4, 200);
        if self.resize(rows, cols) {
            out.resized = Some((rows, cols));
        }

        let desired = Vec2::new(cols as f32 * cell_w, rows as f32 * cell_h);
        let (id, rect) = ui.allocate_space(desired);
        let response = ui.interact(rect, id, egui::Sense::click_and_drag());
        let window_lost_focus = ui.input(|i| {
            i.events
                .iter()
                .any(|e| matches!(e, GuiEvent::WindowFocused(false)))
                || i.viewport().focused == Some(false)
        });
        if self.pending_refocus {
            self.pending_refocus = false;
            self.focused = true;
            response.request_focus();
        } else if self.focused && !response.has_focus() {
            response.request_focus();
        }
        if response.clicked() || response.dragged() {
            response.request_focus();
            self.focused = true;
        }
        if response.lost_focus() || window_lost_focus {
            if !self.pending_refocus {
                self.focused = false;
                self.ime_preedit.clear();
            }
        }
        if response.has_focus() && !window_lost_focus {
            self.focused = true;
        }
        if !self.focused {
            self.ime_preedit.clear();
        }

        // Right-click Copy/Paste context menu (and font zoom controls).
        response.context_menu(|menu_ui| {
            let sel = self.selection_text();
            if menu_ui
                .add_enabled(sel.is_some(), egui::Button::new("Copy"))
                .clicked()
            {
                if let Some(text) = sel {
                    if !text.is_empty() {
                        menu_ui.ctx().copy_text(text);
                    }
                    self.term.selection = None;
                }
                self.pending_refocus = true;
                menu_ui.close_menu();
            }
            if menu_ui.button("Paste").clicked() {
                menu_ui
                    .ctx()
                    .send_viewport_cmd(egui::ViewportCommand::RequestPaste);
                self.pending_refocus = true;
                menu_ui.close_menu();
            }
            menu_ui.separator();
            if menu_ui.button("Zoom In (Ctrl+=)").clicked() {
                self.apply_zoom(ZoomAction::In);
                self.pending_refocus = true;
                menu_ui.close_menu();
            }
            if menu_ui.button("Zoom Out (Ctrl+-)").clicked() {
                self.apply_zoom(ZoomAction::Out);
                self.pending_refocus = true;
                menu_ui.close_menu();
            }
            if (self.font_size - DEFAULT_FONT_SIZE).abs() > f32::EPSILON
                && menu_ui.button("Reset Zoom (Ctrl+0)").clicked()
            {
                self.apply_zoom(ZoomAction::Reset);
                self.pending_refocus = true;
                menu_ui.close_menu();
            }
        });

        // Scrollback and pointer selection run BEFORE `renderable_content()` so
        // drags, double-clicks, triple-clicks, and click-clears paint in the very same frame.
        if response.hovered() {
            let scroll = ui.input(|i| i.raw_scroll_delta.y);
            if scroll > 0.5 {
                self.term
                    .scroll_display(Scroll::Delta(scroll as i32 / 20 + 1));
            } else if scroll < -0.5 {
                self.term
                    .scroll_display(Scroll::Delta(scroll as i32 / 20 - 1));
            }
        }

        let grid_display_offset = self.term.grid().display_offset();
        let to_point = |pos: Pos2| -> Point {
            let col = ((pos.x - rect.min.x) / cell_w)
                .floor()
                .clamp(0.0, (cols - 1) as f32) as usize;
            let row = ((pos.y - rect.min.y) / cell_h)
                .floor()
                .clamp(0.0, (rows - 1) as f32) as i32;
            let line = Line(row - grid_display_offset as i32);
            Point::new(line, Column(col))
        };

        let drag_started = response.drag_started_by(PointerButton::Primary);
        let dragged = response.dragged_by(PointerButton::Primary);
        let drag_stopped = response.drag_stopped();

        if drag_started {
            let origin = ui
                .input(|i| i.pointer.press_origin())
                .or_else(|| response.interact_pointer_pos());
            if let Some(start_pos) = origin {
                let mut sel =
                    Selection::new(SelectionType::Simple, to_point(start_pos), Side::Left);
                if let Some(cur_pos) = response.interact_pointer_pos() {
                    sel.update(to_point(cur_pos), Side::Right);
                }
                sel.include_all();
                self.term.selection = Some(sel);
                self.selecting = true;
                ui.ctx().request_repaint();
            }
        } else if self.selecting && dragged {
            if let Some(pos) = response.interact_pointer_pos() {
                if let Some(sel) = self.term.selection.as_mut() {
                    sel.update(to_point(pos), Side::Right);
                    sel.include_all();
                    ui.ctx().request_repaint();
                }
            }
        }
        if drag_stopped && self.selecting {
            if let Some(pos) = response.interact_pointer_pos() {
                if let Some(sel) = self.term.selection.as_mut() {
                    sel.update(to_point(pos), Side::Right);
                    sel.include_all();
                }
            }
            self.selecting = false;
            ui.ctx().request_repaint();
        }
        let double_clicked = response.double_clicked_by(PointerButton::Primary);
        let triple_clicked = response.triple_clicked_by(PointerButton::Primary);
        if primary_click_clears_selection(
            response.clicked_by(PointerButton::Primary),
            dragged || drag_started || drag_stopped,
            double_clicked || triple_clicked,
        ) {
            if self.term.selection.take().is_some() {
                ui.ctx().request_repaint();
            }
        }
        if triple_clicked {
            if let Some(pos) = response.interact_pointer_pos() {
                let point = to_point(pos);
                self.term.selection =
                    Some(Selection::new(SelectionType::Lines, point, Side::Left));
                ui.ctx().request_repaint();
            }
        } else if double_clicked {
            if let Some(pos) = response.interact_pointer_pos() {
                let point = to_point(pos);
                self.term.selection =
                    Some(Selection::new(SelectionType::Semantic, point, Side::Left));
                ui.ctx().request_repaint();
            }
        }

        let painter = ui.painter_at(rect);
        let default_bg = palette_bg();
        painter.rect_filled(rect, 0.0, default_bg);

        let history_lines = self.term.history_size();
        let display_offset;
        let cursor_point;
        let cursor_hidden;
        {
            let content = self.term.renderable_content();
            display_offset = content.display_offset;
            cursor_point = content.cursor.point;
            cursor_hidden = matches!(
                content.cursor.shape,
                alacritty_terminal::vte::ansi::CursorShape::Hidden
            );
            let selection = content.selection;
            let show_cursor = self.focused && !cursor_hidden;

            struct BgRun {
                row: i32,
                start_col: usize,
                end_col: usize,
                color: Color32,
            }
            struct LineRun {
                row: i32,
                start_col: usize,
                end_col: usize,
                color: Color32,
            }
            struct TextRun {
                row: i32,
                start_col: usize,
                next_col: usize,
                fg: Color32,
                bold: bool,
                italic: bool,
                text: String,
            }

            let mut bg_run: Option<BgRun> = None;
            let mut ul_run: Option<LineRun> = None;
            let mut st_run: Option<LineRun> = None;
            let mut text_run: Option<TextRun> = None;

            let flush_bg = |run: &mut Option<BgRun>| {
                if let Some(r) = run.take() {
                    let run_rect = Rect::from_min_size(
                        Pos2::new(
                            rect.min.x + r.start_col as f32 * cell_w,
                            rect.min.y + r.row as f32 * cell_h,
                        ),
                        Vec2::new((r.end_col - r.start_col) as f32 * cell_w, cell_h),
                    );
                    painter.rect_filled(run_rect, 0.0, r.color);
                }
            };
            let flush_line = |run: &mut Option<LineRun>, y_offset: f32| {
                if let Some(r) = run.take() {
                    let y = rect.min.y + r.row as f32 * cell_h + y_offset;
                    let x0 = rect.min.x + r.start_col as f32 * cell_w;
                    let x1 = rect.min.x + r.end_col as f32 * cell_w;
                    painter.line_segment(
                        [Pos2::new(x0, y), Pos2::new(x1, y)],
                        egui::Stroke::new(1.0_f32, r.color),
                    );
                }
            };
            let flush_text = |run: &mut Option<TextRun>| {
                if let Some(r) = run.take() {
                    let leading_spaces = r.text.bytes().take_while(|&b| b == b' ').count();
                    let trimmed = r.text[leading_spaces..].trim_end_matches(' ');
                    if !trimmed.is_empty() {
                        let start_col = r.start_col + leading_spaces;
                        paint_styled_run(
                            ui,
                            &painter,
                            rect,
                            r.row,
                            start_col,
                            cell_w,
                            cell_h,
                            &font,
                            trimmed,
                            r.fg,
                            r.bold,
                            r.italic,
                        );
                    }
                }
            };

            let underline_y = cell_h - 2.0;
            let strikeout_y = cell_h * 0.52;

            for indexed in content.display_iter {
                if indexed.cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                    continue;
                }
                let row = (indexed.point.line + display_offset as i32).0;
                let col = indexed.point.column.0;
                if row < 0 || row as usize >= rows as usize || col >= cols as usize {
                    continue;
                }
                let flags = indexed.cell.flags;
                let wide = flags.contains(Flags::WIDE_CHAR);
                let width_cells: usize = if wide { 2 } else { 1 };
                let end_col = (col + width_cells).min(cols as usize);

                let bold = flags.contains(Flags::BOLD);
                let italic = flags.contains(Flags::ITALIC);
                let dim = flags.contains(Flags::DIM);
                let selected = selection.is_some_and(|s| {
                    s.contains(indexed.point)
                        || (wide
                            && s.contains(Point::new(indexed.point.line, indexed.point.column + 1)))
                });
                let raw_fg = if bold && !dim && !selected {
                    resolve_bold_color(indexed.cell.fg)
                } else {
                    resolve_color(indexed.cell.fg, true)
                };
                let mut fg = raw_fg;
                let mut bg = resolve_color(indexed.cell.bg, false);
                if flags.contains(Flags::INVERSE) {
                    std::mem::swap(&mut fg, &mut bg);
                }
                if selected {
                    bg = selection_bg();
                    fg = Color32::WHITE;
                }
                if dim && !selected {
                    fg = Color32::from_rgb(
                        (fg.r() as u16 * 2 / 3) as u8,
                        (fg.g() as u16 * 2 / 3) as u8,
                        (fg.b() as u16 * 2 / 3) as u8,
                    );
                }

                // Backgrounds: paint selected cells individually (preserving per-cell
                // selection rects) and merge contiguous non-default bg runs.
                if selected {
                    flush_bg(&mut bg_run);
                    let cell_rect = Rect::from_min_size(
                        Pos2::new(
                            rect.min.x + col as f32 * cell_w,
                            rect.min.y + row as f32 * cell_h,
                        ),
                        Vec2::new(cell_w * width_cells as f32, cell_h),
                    );
                    painter.rect_filled(cell_rect, 0.0, bg);
                } else if bg != default_bg {
                    match bg_run.as_mut() {
                        Some(r) if r.row == row && r.end_col == col && r.color == bg => {
                            r.end_col = end_col;
                        }
                        _ => {
                            flush_bg(&mut bg_run);
                            bg_run = Some(BgRun {
                                row,
                                start_col: col,
                                end_col,
                                color: bg,
                            });
                        }
                    }
                } else {
                    flush_bg(&mut bg_run);
                }

                // Underline runs (including on spaces / hidden cells).
                if flags.intersects(Flags::ALL_UNDERLINES) {
                    match ul_run.as_mut() {
                        Some(r) if r.row == row && r.end_col == col && r.color == fg => {
                            r.end_col = end_col;
                        }
                        _ => {
                            flush_line(&mut ul_run, underline_y);
                            ul_run = Some(LineRun {
                                row,
                                start_col: col,
                                end_col,
                                color: fg,
                            });
                        }
                    }
                } else {
                    flush_line(&mut ul_run, underline_y);
                }

                // Strikeout runs.
                if flags.contains(Flags::STRIKEOUT) {
                    match st_run.as_mut() {
                        Some(r) if r.row == row && r.end_col == col && r.color == fg => {
                            r.end_col = end_col;
                        }
                        _ => {
                            flush_line(&mut st_run, strikeout_y);
                            st_run = Some(LineRun {
                                row,
                                start_col: col,
                                end_col,
                                color: fg,
                            });
                        }
                    }
                } else {
                    flush_line(&mut st_run, strikeout_y);
                }

                if flags.contains(Flags::HIDDEN) {
                    flush_text(&mut text_run);
                    continue;
                }

                let ch = indexed.cell.c;
                let zw = indexed.cell.zerowidth();
                let has_zw = zw.is_some_and(|s| !s.is_empty());
                let is_blank = ch == ' ' || ch == '\0';

                if is_blank && !has_zw {
                    if let Some(r) = text_run.as_mut() {
                        if r.row == row
                            && r.next_col == col
                            && r.fg == fg
                            && r.bold == bold
                            && r.italic == italic
                        {
                            r.text.push(' ');
                            r.next_col = end_col;
                        } else {
                            flush_text(&mut text_run);
                        }
                    }
                } else if !wide && !has_zw && ch.is_ascii_graphic() {
                    match text_run.as_mut() {
                        Some(r)
                            if r.row == row
                                && r.next_col == col
                                && r.fg == fg
                                && r.bold == bold
                                && r.italic == italic =>
                        {
                            r.text.push(ch);
                            r.next_col = end_col;
                        }
                        _ => {
                            flush_text(&mut text_run);
                            let mut text = String::with_capacity(16);
                            text.push(ch);
                            text_run = Some(TextRun {
                                row,
                                start_col: col,
                                next_col: end_col,
                                fg,
                                bold,
                                italic,
                                text,
                            });
                        }
                    }
                } else {
                    // Wide CJK, non-ASCII, or combining-mark cells anchor at their exact column.
                    flush_text(&mut text_run);
                    let mut cell_text = String::with_capacity(4);
                    cell_text.push(if ch == '\0' { ' ' } else { ch });
                    if let Some(marks) = zw {
                        for &m in marks {
                            cell_text.push(m);
                        }
                    }
                    paint_styled_run(
                        ui,
                        &painter,
                        rect,
                        row,
                        col,
                        cell_w,
                        cell_h,
                        &font,
                        &cell_text,
                        fg,
                        bold,
                        italic,
                    );
                }
            }

            flush_bg(&mut bg_run);
            flush_line(&mut ul_run, underline_y);
            flush_line(&mut st_run, strikeout_y);
            flush_text(&mut text_run);

            if show_cursor {
                let row = (Line(cursor_point.line.0 + display_offset as i32)).0;
                let col = cursor_point.column.0;
                if row >= 0 && (row as usize) < rows as usize && col < cols as usize {
                    let cursor_rect = Rect::from_min_size(
                        Pos2::new(
                            rect.min.x + col as f32 * cell_w,
                            rect.min.y + row as f32 * cell_h,
                        ),
                        Vec2::new(2.0, cell_h),
                    );
                    painter.rect_filled(cursor_rect, 0.0, Color32::from_rgb(0xE6, 0xE6, 0xE6));
                }
            }
        } // drop renderable_content before mutating the term

        // Scrollbar indicator when scrollback history is available.
        if let Some((track_rect, thumb_rect)) =
            scrollbar_thumb_rect(rect, history_lines, rows as usize, display_offset)
        {
            if display_offset > 0 {
                painter.rect_filled(
                    track_rect,
                    3.0,
                    Color32::from_rgba_unmultiplied(0xFF, 0xFF, 0xFF, 0x14),
                );
            }
            let thumb_color = if display_offset > 0 {
                Color32::from_rgba_unmultiplied(0xC8, 0xCC, 0xD8, 0xB0)
            } else {
                Color32::from_rgba_unmultiplied(0x9A, 0x9F, 0xAE, 0x55)
            };
            painter.rect_filled(thumb_rect, 3.0, thumb_color);
        }

        // Active expiry even when the remote is silent (E1b — no feed required).
        if self.tick_local_echo() {
            ui.ctx().request_repaint();
        }

        // Speculative local echo: faint overlay on top of remote cells. Never
        // mutates the alacritty grid; confirmed glyphs are cleared in reconcile.
        {
            let overlay = self.local_echo.overlay_cells(&self.term);
            let faint = term_local_echo::faint_fg();
            for cell in overlay {
                let cell_rect = Rect::from_min_size(
                    Pos2::new(
                        rect.min.x + cell.col as f32 * cell_w,
                        rect.min.y + cell.row as f32 * cell_h,
                    ),
                    Vec2::new(cell_w * cell.cells as f32, cell_h),
                );
                painter.text(
                    cell_rect.min + Vec2::new(0.0, (cell_h - font.size) * 0.2),
                    egui::Align2::LEFT_TOP,
                    cell.ch,
                    font.clone(),
                    faint,
                );
            }
            if let Some((row, col)) = self.local_echo.speculative_cursor(&self.term) {
                if self.focused && row < rows as usize && col < cols as usize {
                    let cursor_rect = Rect::from_min_size(
                        Pos2::new(
                            rect.min.x + col as f32 * cell_w,
                            rect.min.y + row as f32 * cell_h,
                        ),
                        Vec2::new(2.0, cell_h),
                    );
                    painter.rect_filled(
                        cursor_rect,
                        0.0,
                        Color32::from_rgba_unmultiplied(0xE6, 0xE6, 0xE6, 0x90),
                    );
                }
            }
        }

        if self.focused {
            let (row, col) = self.cursor_pos();
            let preedit_galley = if !self.ime_preedit.is_empty() {
                // IME preedit stays a separate tint; never mixed into speculative echo.
                self.local_echo.clear();
                Some(ui.fonts(|fonts| {
                    fonts.layout_no_wrap(
                        self.ime_preedit.clone(),
                        font.clone(),
                        Color32::from_rgb(0xE6, 0xE8, 0xFF),
                    )
                }))
            } else {
                None
            };
            let preedit_w = preedit_galley
                .as_ref()
                .map(|g| g.size().x.max(cell_w))
                .unwrap_or(cell_w);
            let (preedit_rect, cursor_rect) = clamped_ime_rects(
                rect,
                row,
                col,
                rows as usize,
                cols as usize,
                cell_w,
                cell_h,
                preedit_w,
            );
            if let Some(galley) = preedit_galley {
                let preedit_bg = Color32::from_rgb(0x1E, 0x20, 0x30);
                let preedit_fg = Color32::from_rgb(0xE6, 0xE8, 0xFF);
                let preedit_ul = Color32::from_rgb(0x9C, 0xA8, 0xFF);
                painter.rect_filled(preedit_rect, 2.0, preedit_bg);
                painter.galley(
                    preedit_rect.min + Vec2::new(0.0, (cell_h - font.size) * 0.2),
                    galley,
                    preedit_fg,
                );
                let ul_y = preedit_rect.max.y - 1.5;
                painter.line_segment(
                    [
                        Pos2::new(preedit_rect.min.x, ul_y),
                        Pos2::new(preedit_rect.max.x, ul_y),
                    ],
                    egui::Stroke::new(1.5_f32, preedit_ul),
                );
            }
            ui.ctx().output_mut(|o| {
                o.ime = Some(egui::output::IMEOutput { rect, cursor_rect });
            });
        }

        let mut gui_writes: Vec<u8> = Vec::new();
        if (response.has_focus() || self.focused) && !self.keys_taken {
            let events = ui.input(|i| i.events.clone());
            let modifiers = ui.input(|i| i.modifiers);
            let plan = self.collect_writes(&events, modifiers);
            if let Some(text) = plan.copy_text {
                if !text.is_empty() {
                    ui.ctx().copy_text(text);
                }
            }
            if let Some(text) = plan.paste_text {
                gui_writes.extend(Self::wrap_paste(
                    text.as_bytes(),
                    self.term.mode().contains(TermMode::BRACKETED_PASTE),
                ));
            }
            if plan.want_paste
                && !events
                    .iter()
                    .any(|event| matches!(event, GuiEvent::Paste(_)))
            {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::RequestPaste);
            }
            if plan.clear_selection || plan.scroll.is_some() || plan.zoom.is_some() {
                ui.ctx().request_repaint();
            }
            gui_writes.extend(plan.writes);
        }
        gui_writes.extend(std::mem::take(&mut self.pending_gui_writes));
        self.keys_taken = false;

        // Speculative echo is local paint only — GUI bytes still go to the remote
        // PTY exactly once (no duplication, no auth change). Host PtyWrite replies
        // are excluded so DA/DSR answers never enter the overlay.
        if !gui_writes.is_empty() {
            if self.term.grid().display_offset() > 0 {
                self.term.scroll_display(Scroll::Bottom);
                ui.ctx().request_repaint();
            }
            let painted = self.note_local_echo_outbound(&gui_writes);
            if painted {
                ui.ctx().request_repaint();
            }
            out.writes.extend(gui_writes);
        }

        if let Some(osc) = self.take_osc52_copy() {
            let chars = osc.chars().count();
            ui.ctx().copy_text(osc);
            out.osc52_copied_chars = Some(chars);
        }

        out
    }
}

/// A plain click (not a drag, not a double-click) clears the terminal selection
/// so the next Ctrl+C can interrupt instead of copying a stale range.
pub(crate) fn primary_click_clears_selection(
    clicked: bool,
    dragged: bool,
    double_clicked: bool,
) -> bool {
    clicked && !dragged && !double_clicked
}

fn plain_ctrl(modifiers: egui::Modifiers) -> bool {
    (modifiers.ctrl || modifiers.command) && !modifiers.shift && !modifiers.alt
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ZoomAction {
    In,
    Out,
    Reset,
}

#[derive(Debug, Default)]
struct PlannedEvents {
    writes: Vec<u8>,
    copy_text: Option<String>,
    paste_text: Option<String>,
    want_paste: bool,
    preedit: Option<String>,
    clear_selection: bool,
    scroll: Option<Scroll>,
    zoom: Option<ZoomAction>,
}

/// Turn a frame of native egui events into PTY bytes.
///
/// Windows egui can emit [`GuiEvent::Copy`] for Ctrl+C without [`GuiEvent::Key`]
/// `C`. An empty selection then has to interrupt (`^C`). A non-empty selection
/// still copies (and clears selection in [`Emulator`] so a second Ctrl+C
/// interrupts). Copy plus Key(C) in the same frame produces one interrupt,
/// not two. Paste text goes to the PTY, not the remote-desktop clipboard.
#[cfg(test)]
pub(crate) fn plan_terminal_events(
    events: &[GuiEvent],
    selection: Option<&str>,
    app_cursor: bool,
    frame_modifiers: egui::Modifiers,
) -> (Vec<u8>, Option<String>, Option<String>, bool, Option<String>) {
    let plan = plan_terminal_events_full(events, selection, app_cursor, frame_modifiers, false);
    (
        plan.writes,
        plan.copy_text,
        plan.paste_text,
        plan.want_paste,
        plan.preedit,
    )
}

fn plan_terminal_events_full(
    events: &[GuiEvent],
    selection: Option<&str>,
    app_cursor: bool,
    frame_modifiers: egui::Modifiers,
    alt_screen: bool,
) -> PlannedEvents {
    let selected = selection.filter(|text| !text.is_empty());
    let mut saw_copy = false;
    let mut saw_cut = false;
    let mut saw_paste = false;
    let mut ime_commits: Vec<String> = Vec::new();
    let mut preedit_active = false;
    for event in events {
        match event {
            GuiEvent::Copy => saw_copy = true,
            GuiEvent::Cut => saw_cut = true,
            GuiEvent::Paste(_) => saw_paste = true,
            GuiEvent::Ime(ImeEvent::Preedit(text)) if !text.is_empty() => {
                preedit_active = true;
            }
            GuiEvent::Ime(ImeEvent::Commit(text)) => {
                ime_commits.push(text.clone());
            }
            _ => {}
        }
    }

    let has_printable_text = events.iter().any(|event| {
        let GuiEvent::Text(text) = event else {
            return false;
        };
        !text.is_empty()
            && !text.chars().all(|c| c.is_control())
            && !Emulator::skip_duplicate_text(text, &ime_commits, preedit_active, false)
    });

    let mut plan = PlannedEvents::default();
    let mut interrupt_from_copy = false;
    let mut cut_from_event = false;
    if saw_copy {
        if let Some(text) = selected {
            plan.copy_text = Some(text.to_string());
            plan.clear_selection = true;
        } else if frame_modifiers.mac_cmd && !frame_modifiers.ctrl {
            // macOS Cmd+C with empty selection: neither wipe clipboard nor send ^C.
        } else if let Some(bytes) = Emulator::encode_key("c", true, false, false, app_cursor) {
            plan.writes.extend(bytes);
            interrupt_from_copy = true;
        }
    }
    if saw_cut {
        // Never hijack Ctrl+X as Copy in a terminal; always forward ^X (0x18).
        if let Some(bytes) = Emulator::encode_key("x", true, false, false, app_cursor) {
            plan.writes.extend(bytes);
            cut_from_event = true;
        }
    }

    let mut control_key_sent = false;
    for event in events {
        match event {
            GuiEvent::Copy | GuiEvent::Cut => {}
            GuiEvent::Paste(text) => {
                plan.paste_text = Some(text.clone());
            }
            GuiEvent::Ime(ImeEvent::Enabled) => {}
            GuiEvent::Ime(ImeEvent::Preedit(text)) => {
                plan.preedit = Some(text.clone());
            }
            GuiEvent::Ime(ImeEvent::Commit(text)) => {
                plan.writes.extend(Emulator::encode_text(text, false));
                plan.preedit = Some(String::new());
            }
            GuiEvent::Ime(ImeEvent::Disabled) => {
                plan.preedit = Some(String::new());
            }
            GuiEvent::Key {
                key,
                pressed,
                modifiers,
                ..
            } if *pressed => {
                if interrupt_from_copy && plain_ctrl(*modifiers) && matches!(key, Key::C) {
                    continue;
                }
                if cut_from_event && plain_ctrl(*modifiers) && matches!(key, Key::X) {
                    continue;
                }
                if saw_paste && plain_ctrl(*modifiers) && matches!(key, Key::V) {
                    continue;
                }
                if saw_copy && plain_ctrl(*modifiers) && matches!(key, Key::C) {
                    continue;
                }

                // Local scrollback via Shift+PageUp / Shift+PageDown when not in alt screen.
                if !alt_screen
                    && modifiers.shift
                    && !modifiers.ctrl
                    && !modifiers.alt
                    && !modifiers.command
                {
                    if matches!(key, Key::PageUp) {
                        plan.scroll = Some(Scroll::PageUp);
                        continue;
                    }
                    if matches!(key, Key::PageDown) {
                        plan.scroll = Some(Scroll::PageDown);
                        continue;
                    }
                }

                // Font-size zoom: Ctrl+= / Ctrl++ zooms in, plain Ctrl+- zooms out
                // (while Ctrl+Shift+- = Ctrl+_ still sends 0x1f), Ctrl+0 resets.
                if (modifiers.ctrl || modifiers.command) && !modifiers.alt {
                    if matches!(key, Key::Equals | Key::Plus) {
                        plan.zoom = Some(ZoomAction::In);
                        continue;
                    }
                    if matches!(key, Key::Minus) && !modifiers.shift {
                        plan.zoom = Some(ZoomAction::Out);
                        continue;
                    }
                    if matches!(key, Key::Num0) && !modifiers.shift {
                        plan.zoom = Some(ZoomAction::Reset);
                        continue;
                    }
                }

                match clipboard_shortcut(*key, *modifiers, selection.map(str::to_string)) {
                    TermClipboardShortcut::Copy(text) => {
                        if !text.is_empty() {
                            plan.copy_text = Some(text);
                            plan.clear_selection = true;
                        }
                        continue;
                    }
                    TermClipboardShortcut::CopyEmpty => {
                        // Never wipe the system clipboard or send ^C when Copy shortcut
                        // is pressed with no active selection.
                        continue;
                    }
                    TermClipboardShortcut::Paste => {
                        plan.want_paste = true;
                        continue;
                    }
                    TermClipboardShortcut::None => {}
                }

                let name = key_name(*key);

                // European Windows AltGr synthesizes ctrl+alt alongside a printable Text
                // event. Let the Text loop emit the composed glyph instead of emitting
                // Ctrl+Alt+<key>.
                if modifiers.ctrl
                    && modifiers.alt
                    && !modifiers.mac_cmd
                    && has_printable_text
                    && is_printable_key_name(name)
                {
                    continue;
                }

                // When Alt+<printable> already produced a Text event in this frame
                // (e.g. X11/macOS), let the Text loop emit ESC+<text> once to avoid
                // doubling. On Windows where no Text arrives, encode_key handles it.
                if modifiers.alt
                    && !modifiers.ctrl
                    && !modifiers.command
                    && has_printable_text
                    && is_printable_key_name(name)
                {
                    continue;
                }

                if matches!(key, Key::Enter | Key::Tab) && !modifiers.ctrl {
                    control_key_sent = true;
                }
                if let Some(bytes) = Emulator::encode_key(
                    name,
                    modifiers.ctrl,
                    modifiers.alt,
                    modifiers.shift,
                    app_cursor,
                ) {
                    plan.writes.extend(bytes);
                }
            }
            _ => {}
        }
    }

    let is_altgr = frame_modifiers.ctrl && frame_modifiers.alt && !frame_modifiers.mac_cmd;
    for event in events {
        let GuiEvent::Text(text) = event else {
            continue;
        };
        if (frame_modifiers.ctrl || frame_modifiers.command) && !is_altgr {
            continue;
        }
        if is_altgr && text.chars().all(|c| c.is_control()) {
            continue;
        }
        if Emulator::skip_duplicate_text(text, &ime_commits, preedit_active, control_key_sent) {
            continue;
        }
        let alt_prefix = frame_modifiers.alt && !is_altgr;
        plan.writes.extend(Emulator::encode_text(text, alt_prefix));
    }
    plan
}

/// Keyboard shortcuts that should copy or paste instead of sending a control
/// character.
///
/// - `Ctrl+Shift+C` / `Ctrl+Shift+V` (and macOS `Cmd+C` / `Cmd+V`) handle
///   clipboard copy/paste, never wiping the clipboard when selection is empty.
/// - Plain `Ctrl+C` copies when there is an active selection (clearing it so a
///   second `Ctrl+C` interrupts), otherwise falls through as interrupt (`^C`).
/// - Plain `Ctrl+V` is **never** hijacked so Vim visual-block / readline `^V`
///   reaches the PTY intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TermClipboardShortcut {
    Copy(String),
    CopyEmpty,
    Paste,
    None,
}

pub(crate) fn clipboard_shortcut(
    key: Key,
    modifiers: egui::Modifiers,
    selection: Option<String>,
) -> TermClipboardShortcut {
    if modifiers.alt {
        return TermClipboardShortcut::None;
    }
    let non_empty = selection.filter(|s| !s.is_empty());
    // macOS Cmd+C / Cmd+V (without Ctrl).
    if modifiers.mac_cmd && !modifiers.ctrl && !modifiers.shift {
        return match key {
            Key::C => non_empty.map_or(
                TermClipboardShortcut::CopyEmpty,
                TermClipboardShortcut::Copy,
            ),
            Key::V => TermClipboardShortcut::Paste,
            _ => TermClipboardShortcut::None,
        };
    }
    let ctrl_chord = modifiers.ctrl || modifiers.command;
    if !ctrl_chord {
        return TermClipboardShortcut::None;
    }
    // Strict Ctrl+Shift+C / Ctrl+Shift+V.
    if modifiers.shift {
        return match key {
            Key::C => non_empty.map_or(
                TermClipboardShortcut::CopyEmpty,
                TermClipboardShortcut::Copy,
            ),
            Key::V => TermClipboardShortcut::Paste,
            _ => TermClipboardShortcut::None,
        };
    }
    // Plain Ctrl+C copies when a selection is active; otherwise sends ^C.
    if matches!(key, Key::C) {
        if let Some(text) = non_empty {
            return TermClipboardShortcut::Copy(text);
        }
    }
    // Plain Ctrl+V and Ctrl+X are NOT hijacked — they must reach the remote PTY.
    TermClipboardShortcut::None
}

fn ctrl_byte(key: &str) -> Option<u8> {
    match key {
        "a" | "A" => Some(0x01),
        "b" | "B" => Some(0x02),
        "c" | "C" => Some(0x03),
        "d" | "D" => Some(0x04),
        "e" | "E" => Some(0x05),
        "f" | "F" => Some(0x06),
        "g" | "G" => Some(0x07),
        "h" | "H" => Some(0x08),
        "i" | "I" => Some(0x09),
        "j" | "J" => Some(0x0a),
        "k" | "K" => Some(0x0b),
        "l" | "L" => Some(0x0c),
        "m" | "M" => Some(0x0d),
        "n" | "N" => Some(0x0e),
        "o" | "O" => Some(0x0f),
        "p" | "P" => Some(0x10),
        "q" | "Q" => Some(0x11),
        "r" | "R" => Some(0x12),
        "s" | "S" => Some(0x13),
        "t" | "T" => Some(0x14),
        "u" | "U" => Some(0x15),
        "v" | "V" => Some(0x16),
        "w" | "W" => Some(0x17),
        "x" | "X" => Some(0x18),
        "y" | "Y" => Some(0x19),
        "z" | "Z" => Some(0x1a),
        "[" => Some(0x1b),
        "\\" | "|" => Some(0x1c),
        "]" => Some(0x1d),
        "^" | "6" => Some(0x1e),
        "_" | "-" | "/" => Some(0x1f),
        "backspace" => Some(0x7f),
        "space" | "@" => Some(0x00),
        _ => None,
    }
}

fn alt_char(key: &str, shift: bool) -> Option<char> {
    if key == "space" {
        return Some(' ');
    }
    let mut chars = key.chars();
    let ch = chars.next()?;
    if chars.next().is_some() || !ch.is_ascii_graphic() {
        return None;
    }
    if ch.is_ascii_alphabetic() {
        return Some(if shift {
            ch.to_ascii_uppercase()
        } else {
            ch.to_ascii_lowercase()
        });
    }
    if !shift {
        return Some(ch);
    }
    let shifted = match ch {
        '0' => ')',
        '1' => '!',
        '2' => '@',
        '3' => '#',
        '4' => '$',
        '5' => '%',
        '6' => '^',
        '7' => '&',
        '8' => '*',
        '9' => '(',
        '-' => '_',
        '=' => '+',
        '[' => '{',
        ']' => '}',
        '\\' => '|',
        ';' => ':',
        '\'' => '"',
        ',' => '<',
        '.' => '>',
        '/' => '?',
        '`' => '~',
        other => other,
    };
    Some(shifted)
}

fn is_printable_key_name(name: &str) -> bool {
    if name == "space" {
        return true;
    }
    let mut chars = name.chars();
    matches!((chars.next(), chars.next()), (Some(c), None) if c.is_ascii_graphic())
}

fn xterm_mod(ctrl: bool, alt: bool, shift: bool) -> Option<u8> {
    // xterm modifier: 1 + shift=1 + alt=2 + ctrl=4
    let mut mods = 1u8;
    if shift {
        mods += 1;
    }
    if alt {
        mods += 2;
    }
    if ctrl {
        mods += 4;
    }
    (mods > 1).then_some(mods)
}

fn csi_letter(letter: u8, app_cursor: bool, ctrl: bool, alt: bool, shift: bool) -> Vec<u8> {
    if let Some(mods) = xterm_mod(ctrl, alt, shift) {
        format!("\x1b[1;{mods}{}", letter as char).into_bytes()
    } else if app_cursor {
        vec![0x1b, b'O', letter]
    } else {
        vec![0x1b, b'[', letter]
    }
}

fn csi_f1_f4(letter: u8, ctrl: bool, alt: bool, shift: bool) -> Vec<u8> {
    if let Some(mods) = xterm_mod(ctrl, alt, shift) {
        format!("\x1b[1;{mods}{}", letter as char).into_bytes()
    } else {
        vec![0x1b, b'O', letter]
    }
}

fn csi_tilde(code: u8, ctrl: bool, alt: bool, shift: bool) -> Vec<u8> {
    if let Some(mods) = xterm_mod(ctrl, alt, shift) {
        format!("\x1b[{code};{mods}~").into_bytes()
    } else {
        format!("\x1b[{code}~").into_bytes()
    }
}

fn normalize_paste_newlines(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\r' => {
                out.push(b'\r');
                if i + 1 < data.len() && data[i + 1] == b'\n' {
                    i += 2;
                } else {
                    i += 1;
                }
            }
            b'\n' => {
                out.push(b'\r');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    out
}

fn key_name(key: Key) -> &'static str {
    match key {
        Key::Enter => "enter",
        Key::Backspace => "backspace",
        Key::Tab => "tab",
        Key::Escape => "escape",
        Key::ArrowUp => "up",
        Key::ArrowDown => "down",
        Key::ArrowRight => "right",
        Key::ArrowLeft => "left",
        Key::Home => "home",
        Key::End => "end",
        Key::PageUp => "pageup",
        Key::PageDown => "pagedown",
        Key::Insert => "insert",
        Key::Delete => "delete",
        Key::A => "a",
        Key::B => "b",
        Key::C => "c",
        Key::D => "d",
        Key::E => "e",
        Key::F => "f",
        Key::G => "g",
        Key::H => "h",
        Key::I => "i",
        Key::J => "j",
        Key::K => "k",
        Key::L => "l",
        Key::M => "m",
        Key::N => "n",
        Key::O => "o",
        Key::P => "p",
        Key::Q => "q",
        Key::R => "r",
        Key::S => "s",
        Key::T => "t",
        Key::U => "u",
        Key::V => "v",
        Key::W => "w",
        Key::X => "x",
        Key::Y => "y",
        Key::Z => "z",
        Key::Num0 => "0",
        Key::Num1 => "1",
        Key::Num2 => "2",
        Key::Num3 => "3",
        Key::Num4 => "4",
        Key::Num5 => "5",
        Key::Num6 => "6",
        Key::Num7 => "7",
        Key::Num8 => "8",
        Key::Num9 => "9",
        Key::Space => "space",
        Key::OpenBracket => "[",
        Key::CloseBracket => "]",
        Key::OpenCurlyBracket => "{",
        Key::CloseCurlyBracket => "}",
        Key::Backslash => "\\",
        Key::Pipe => "|",
        Key::Minus => "-",
        Key::Equals => "=",
        Key::Plus => "+",
        Key::Period => ".",
        Key::Comma => ",",
        Key::Slash => "/",
        Key::Semicolon => ";",
        Key::Colon => ":",
        Key::Quote => "'",
        Key::Backtick => "`",
        Key::Questionmark => "?",
        Key::Exclamationmark => "!",
        Key::F1 => "f1",
        Key::F2 => "f2",
        Key::F3 => "f3",
        Key::F4 => "f4",
        Key::F5 => "f5",
        Key::F6 => "f6",
        Key::F7 => "f7",
        Key::F8 => "f8",
        Key::F9 => "f9",
        Key::F10 => "f10",
        Key::F11 => "f11",
        Key::F12 => "f12",
        _ => "",
    }
}

#[allow(clippy::too_many_arguments)]
fn paint_styled_run(
    ui: &egui::Ui,
    painter: &egui::Painter,
    rect: Rect,
    row: i32,
    start_col: usize,
    cell_w: f32,
    cell_h: f32,
    font: &egui::FontId,
    text: &str,
    fg: Color32,
    bold: bool,
    italic: bool,
) {
    let pos = Pos2::new(
        rect.min.x + start_col as f32 * cell_w,
        rect.min.y + row as f32 * cell_h + (cell_h - font.size) * 0.2,
    );
    let job = egui::text::LayoutJob::single_section(
        text.to_owned(),
        egui::TextFormat {
            font_id: font.clone(),
            color: fg,
            italics: italic,
            ..Default::default()
        },
    );
    let galley = ui.fonts(|fonts| fonts.layout_job(job));
    if bold {
        painter.galley(pos + Vec2::new(0.6, 0.0), galley.clone(), fg);
    }
    painter.galley(pos, galley, fg);
}

fn resolve_bold_color(color: Color) -> Color32 {
    match color {
        Color::Named(NamedColor::Black) => ansi(8),
        Color::Named(NamedColor::Red) => ansi(9),
        Color::Named(NamedColor::Green) => ansi(10),
        Color::Named(NamedColor::Yellow) => ansi(11),
        Color::Named(NamedColor::Blue) => ansi(12),
        Color::Named(NamedColor::Magenta) => ansi(13),
        Color::Named(NamedColor::Cyan) => ansi(14),
        Color::Named(NamedColor::White) => ansi(15),
        Color::Named(NamedColor::Foreground) => Color32::WHITE,
        Color::Indexed(i) if i < 8 => ansi(i + 8),
        other => resolve_color(other, true),
    }
}

fn scrollbar_thumb_rect(
    rect: Rect,
    history: usize,
    rows: usize,
    display_offset: usize,
) -> Option<(Rect, Rect)> {
    if history == 0 || rows == 0 || rect.height() < 16.0 || rect.width() < 16.0 {
        return None;
    }
    let bar_w = 6.0_f32;
    let pad = 2.0_f32;
    let track = Rect::from_min_max(
        Pos2::new(rect.max.x - bar_w - pad, rect.min.y + pad),
        Pos2::new(rect.max.x - pad, rect.max.y - pad),
    );
    let track_h = track.height().max(1.0);
    let total = (history + rows) as f32;
    let thumb_h = (track_h * (rows as f32 / total)).clamp(16.0_f32.min(track_h), track_h);
    let top_ratio = 1.0 - (display_offset.min(history) as f32 / history as f32);
    let thumb_y = track.min.y + top_ratio * (track_h - thumb_h);
    let thumb = Rect::from_min_size(Pos2::new(track.min.x, thumb_y), Vec2::new(bar_w, thumb_h));
    Some((track, thumb))
}

#[allow(clippy::too_many_arguments)]
fn clamped_ime_rects(
    rect: Rect,
    row: usize,
    col: usize,
    rows: usize,
    cols: usize,
    cell_w: f32,
    cell_h: f32,
    preedit_w: f32,
) -> (Rect, Rect) {
    let clamped_row = row.min(rows.saturating_sub(1));
    let clamped_col = col.min(cols.saturating_sub(1));
    let cursor_w = 2.0_f32.min(rect.width());
    let cursor_h = cell_h.min(rect.height());
    let cx = (rect.min.x + clamped_col as f32 * cell_w)
        .clamp(rect.min.x, (rect.max.x - cursor_w).max(rect.min.x));
    let cy = (rect.min.y + clamped_row as f32 * cell_h)
        .clamp(rect.min.y, (rect.max.y - cursor_h).max(rect.min.y));
    let cursor_rect = Rect::from_min_size(Pos2::new(cx, cy), Vec2::new(cursor_w, cursor_h));
    let w = preedit_w.clamp(cursor_w, rect.width().max(cursor_w));
    let px = cx.clamp(rect.min.x, (rect.max.x - w).max(rect.min.x));
    let preedit_rect = Rect::from_min_size(Pos2::new(px, cy), Vec2::new(w, cursor_h));
    (preedit_rect, cursor_rect)
}

fn palette_bg() -> Color32 {
    Color32::from_rgb(0x0D, 0x0D, 0x12)
}

fn selection_bg() -> Color32 {
    Color32::from_rgb(0x2F, 0x65, 0xB8)
}

fn palette_fg() -> Color32 {
    Color32::from_rgb(0xE6, 0xE6, 0xE6)
}

fn ansi(index: u8) -> Color32 {
    const COLORS: [Color32; 16] = [
        Color32::from_rgb(0x1C, 0x1C, 0x1C),
        Color32::from_rgb(0xC4, 0x3E, 0x3E),
        Color32::from_rgb(0x4E, 0x9A, 0x4E),
        Color32::from_rgb(0xC4, 0xA0, 0x3E),
        Color32::from_rgb(0x3E, 0x6E, 0xC4),
        Color32::from_rgb(0x8E, 0x3E, 0xC4),
        Color32::from_rgb(0x3E, 0xB4, 0xC4),
        Color32::from_rgb(0xC8, 0xC8, 0xC8),
        Color32::from_rgb(0x5A, 0x5A, 0x5A),
        Color32::from_rgb(0xE0, 0x5A, 0x5A),
        Color32::from_rgb(0x6E, 0xC4, 0x6E),
        Color32::from_rgb(0xE0, 0xC4, 0x5A),
        Color32::from_rgb(0x5A, 0x8A, 0xE0),
        Color32::from_rgb(0xB4, 0x5A, 0xE0),
        Color32::from_rgb(0x5A, 0xD0, 0xE0),
        Color32::from_rgb(0xFF, 0xFF, 0xFF),
    ];
    COLORS[index as usize % 16]
}

fn resolve_color(color: Color, foreground: bool) -> Color32 {
    match color {
        Color::Named(name) => match name {
            NamedColor::Foreground => palette_fg(),
            NamedColor::Background => palette_bg(),
            NamedColor::Cursor => Color32::from_rgb(0xE6, 0xE6, 0xE6),
            NamedColor::DimForeground => Color32::from_rgb(0x96, 0x96, 0x96),
            NamedColor::BrightForeground => Color32::WHITE,
            NamedColor::Black => ansi(0),
            NamedColor::Red => ansi(1),
            NamedColor::Green => ansi(2),
            NamedColor::Yellow => ansi(3),
            NamedColor::Blue => ansi(4),
            NamedColor::Magenta => ansi(5),
            NamedColor::Cyan => ansi(6),
            NamedColor::White => ansi(7),
            NamedColor::BrightBlack => ansi(8),
            NamedColor::BrightRed => ansi(9),
            NamedColor::BrightGreen => ansi(10),
            NamedColor::BrightYellow => ansi(11),
            NamedColor::BrightBlue => ansi(12),
            NamedColor::BrightMagenta => ansi(13),
            NamedColor::BrightCyan => ansi(14),
            NamedColor::BrightWhite => ansi(15),
            _ => {
                if foreground {
                    palette_fg()
                } else {
                    palette_bg()
                }
            }
        },
        Color::Indexed(i) if i < 16 => ansi(i),
        Color::Indexed(i) if i < 232 => {
            let i = i - 16;
            let r = i / 36;
            let g = (i % 36) / 6;
            let b = i % 6;
            let step = |v: u8| if v == 0 { 0 } else { 55 + 40 * v };
            Color32::from_rgb(step(r), step(g), step(b))
        }
        Color::Indexed(i) => {
            let v = 8 + 10 * (i - 232);
            Color32::from_rgb(v, v, v)
        }
        Color::Spec(rgb) => Color32::from_rgb(rgb.r, rgb.g, rgb.b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_bytes_appear_in_order() {
        let mut term = Emulator::new(24, 80);
        term.feed(b"hello");
        assert!(
            term.viewport_text().starts_with("hello"),
            "{}",
            term.viewport_text()
        );
        assert_eq!(term.cursor_pos(), (0, 5));
    }

    #[test]
    fn cjk_ideograph_occupies_two_cells() {
        let mut term = Emulator::new(24, 80);
        term.feed("中".as_bytes());
        assert_eq!(term.cell_width_at(0, 0), 2, "中 must be two cells");
        assert_eq!(term.cell_width_at(0, 1), 0, "spacer follows the wide cell");
        assert_eq!(term.cursor_pos(), (0, 2));
        term.feed(b"A");
        assert_eq!(term.cursor_pos(), (0, 3));
        let text = term.viewport_text();
        assert!(text.contains('中'), "{text}");
        assert!(text.contains('A'), "{text}");
    }

    #[test]
    fn split_utf8_and_csi_still_parse() {
        let mut term = Emulator::new(24, 80);
        // UTF-8 for 中 is E4 B8 AD, fed in three chunks.
        term.feed(&[0xE4]);
        term.feed(&[0xB8]);
        term.feed(&[0xAD]);
        assert_eq!(term.cell_width_at(0, 0), 2);
        // Split CSI: red 'X' then reset.
        term.feed(b"\x1b[");
        term.feed(b"31mX\x1b[0m");
        assert!(
            term.cell_fg_named_is_red(0, 2),
            "X should be red after split CSI"
        );
        assert_eq!(term.cursor_pos(), (0, 3));
    }

    #[test]
    fn sgr_color_and_cursor_addressing() {
        let mut term = Emulator::new(24, 80);
        term.feed(b"\x1b[2;5H\x1b[31mZ");
        assert_eq!(term.cursor_pos(), (1, 5));
        assert!(term.cell_fg_named_is_red(1, 4), "Z at row 2 col 5 is red");
    }

    #[test]
    fn backspace_and_resize_keep_contents() {
        let mut term = Emulator::new(24, 80);
        term.feed(b"abc");
        term.feed(b"\x08\x08");
        // cursor moved back; overwrite
        term.feed(b"X");
        let text = term.viewport_text();
        assert!(text.starts_with("aXc"), "{text}");
        assert!(term.resize(12, 40));
        let text = term.viewport_text();
        assert!(text.contains("aXc"), "{text}");
        assert_eq!(term.size(), (12, 40));
    }

    #[test]
    fn keys_encode_enter_ctrl_c_and_arrows() {
        assert_eq!(
            Emulator::encode_key("enter", false, false, false, false).unwrap(),
            b"\r"
        );
        assert_eq!(
            Emulator::encode_key("c", true, false, false, false).unwrap(),
            vec![0x03]
        );
        assert_eq!(
            Emulator::encode_key("up", false, false, false, false).unwrap(),
            b"\x1b[A"
        );
        assert_eq!(
            Emulator::encode_key("up", false, false, false, true).unwrap(),
            b"\x1bOA"
        );
        assert_eq!(Emulator::encode_text("hi", false), b"hi");
        assert_ne!(
            Emulator::encode_key("c", true, false, false, false).unwrap(),
            Emulator::encode_text("c", false)
        );
    }

    #[test]
    fn ime_commit_is_not_repeated_and_preedit_is_not_sent() {
        let commits = vec!["中".to_string()];
        assert!(Emulator::skip_duplicate_text("中", &commits, false, false));
        assert!(Emulator::skip_duplicate_text("ni", &[], true, false));
        assert!(!Emulator::skip_duplicate_text("a", &commits, false, false));
        assert!(Emulator::skip_duplicate_text("\n", &[], false, true));
        assert!(!Emulator::skip_duplicate_text("a", &[], false, true));
    }

    #[test]
    fn bracketed_paste_strips_inner_terminators() {
        let dirty = b"hello\x1b[201~rm -rf /\x1b[200~";
        let wrapped = Emulator::wrap_paste(dirty, true);
        assert!(wrapped.starts_with(b"\x1b[200~"));
        assert!(wrapped.ends_with(b"\x1b[201~"));
        let inner = &wrapped[6..wrapped.len() - 6];
        assert_eq!(inner, b"hellorm -rf /");
        assert_eq!(inner.iter().filter(|b| **b == 0x1b).count(), 0);
        assert_eq!(Emulator::wrap_paste(b"plain", false), b"plain");
    }

    #[test]
    fn combining_mark_stays_in_the_base_cell() {
        let mut term = Emulator::new(24, 80);
        term.feed(b"e");
        term.feed("\u{0301}".as_bytes());
        assert_eq!(term.cursor_pos(), (0, 1));
        // Combining marks attach to the base cell; the next column is a
        // normal empty cell, not a wide-char spacer.
        assert_eq!(term.cell_width_at(0, 0), 1);
        assert_ne!(term.cell_width_at(0, 1), 2);
        let text = term.viewport_text();
        assert!(
            text.contains('\u{0301}') || text.contains('é') || text.starts_with('e'),
            "{text:?}"
        );
    }

    #[test]
    fn scrollback_history_is_capped() {
        let mut term = Emulator::new(24, 80);
        let mut bytes = Vec::new();
        for i in 0..6000 {
            bytes.extend(format!("L{i}\n").into_bytes());
        }
        bytes.extend(b"TAIL");
        term.feed(&bytes);
        assert!(
            term.history_lines() <= 5000,
            "history {} exceeded the configured cap",
            term.history_lines()
        );
        assert!(
            term.viewport_text().contains("TAIL"),
            "{}",
            term.viewport_text()
        );
    }

    #[test]
    fn ctrl_c_copies_selection_but_interrupts_when_empty() {
        let mods = egui::Modifiers {
            ctrl: true,
            ..egui::Modifiers::NONE
        };
        assert_eq!(
            clipboard_shortcut(Key::C, mods, Some("copied".into())),
            TermClipboardShortcut::Copy("copied".into())
        );
        assert_eq!(
            clipboard_shortcut(Key::C, mods, Some(String::new())),
            TermClipboardShortcut::None
        );
        assert_eq!(
            clipboard_shortcut(Key::C, mods, None),
            TermClipboardShortcut::None
        );
        // Plain Ctrl+V must NOT be hijacked (needed in Vim visual-block / readline).
        assert_eq!(
            clipboard_shortcut(Key::V, mods, None),
            TermClipboardShortcut::None
        );
        let shift = egui::Modifiers {
            ctrl: true,
            shift: true,
            ..egui::Modifiers::NONE
        };
        assert_eq!(
            clipboard_shortcut(Key::C, shift, Some("sel".into())),
            TermClipboardShortcut::Copy("sel".into())
        );
        // Empty selection on Ctrl+Shift+C must NOT yield Copy("") (would wipe clipboard).
        assert_eq!(
            clipboard_shortcut(Key::C, shift, None),
            TermClipboardShortcut::CopyEmpty
        );
        assert_eq!(
            clipboard_shortcut(Key::C, shift, Some(String::new())),
            TermClipboardShortcut::CopyEmpty
        );
        assert_eq!(
            clipboard_shortcut(Key::V, shift, None),
            TermClipboardShortcut::Paste
        );
        let mac_cmd = egui::Modifiers {
            mac_cmd: true,
            command: true,
            ..egui::Modifiers::NONE
        };
        assert_eq!(
            clipboard_shortcut(Key::C, mac_cmd, Some("mac".into())),
            TermClipboardShortcut::Copy("mac".into())
        );
        assert_eq!(
            clipboard_shortcut(Key::C, mac_cmd, None),
            TermClipboardShortcut::CopyEmpty
        );
        assert_eq!(
            clipboard_shortcut(Key::V, mac_cmd, None),
            TermClipboardShortcut::Paste
        );
        assert_eq!(
            clipboard_shortcut(Key::C, egui::Modifiers::NONE, Some("sel".into())),
            TermClipboardShortcut::None
        );
    }

    #[test]
    fn enter_and_arrows_are_captured_keyboard_events() {
        assert!(Emulator::is_captured_event(&GuiEvent::Key {
            key: Key::Enter,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }));
        assert!(Emulator::is_captured_event(&GuiEvent::Key {
            key: Key::Backspace,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: egui::Modifiers::NONE,
        }));
        assert!(Emulator::is_captured_event(&GuiEvent::Text("a".into())));
        assert!(!Emulator::is_captured_event(&GuiEvent::PointerButton {
            pos: egui::pos2(0.0, 0.0),
            button: PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        }));
    }

    fn key_c(mods: egui::Modifiers) -> GuiEvent {
        GuiEvent::Key {
            key: Key::C,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: mods,
        }
    }

    fn ctrl_mods() -> egui::Modifiers {
        egui::Modifiers {
            ctrl: true,
            ..egui::Modifiers::NONE
        }
    }

    #[test]
    fn copy_event_without_selection_interrupts_once() {
        let (bytes, copy, paste, want_paste, _) =
            plan_terminal_events(&[GuiEvent::Copy], None, false, egui::Modifiers::NONE);
        assert_eq!(bytes, vec![0x03], "native Copy with no selection must be ^C");
        assert!(copy.is_none());
        assert!(paste.is_none());
        assert!(!want_paste);
    }

    #[test]
    fn copy_event_with_selection_copies_and_does_not_interrupt() {
        let (bytes, copy, _, _, _) =
            plan_terminal_events(&[GuiEvent::Copy], Some("_COPY_OK"), false, egui::Modifiers::NONE);
        assert!(bytes.is_empty());
        assert_eq!(copy.as_deref(), Some("_COPY_OK"));
    }

    #[test]
    fn copy_event_plus_key_c_interrupts_only_once() {
        let events = [GuiEvent::Copy, key_c(ctrl_mods())];
        let (bytes, copy, _, _, _) =
            plan_terminal_events(&events, None, false, ctrl_mods());
        assert_eq!(bytes, vec![0x03]);
        assert!(copy.is_none());
    }

    #[test]
    fn key_c_without_copy_event_still_interrupts_when_empty() {
        let (bytes, copy, _, _, _) =
            plan_terminal_events(&[key_c(ctrl_mods())], Some(""), false, ctrl_mods());
        assert_eq!(bytes, vec![0x03]);
        assert!(copy.is_none());
    }

    #[test]
    fn key_c_with_selection_copies_instead_of_interrupting() {
        let (bytes, copy, _, _, _) =
            plan_terminal_events(&[key_c(ctrl_mods())], Some("sel"), false, ctrl_mods());
        assert!(bytes.is_empty());
        assert_eq!(copy.as_deref(), Some("sel"));
    }

    #[test]
    fn cut_event_without_selection_sends_ctrl_x_once() {
        let key_x = GuiEvent::Key {
            key: Key::X,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: ctrl_mods(),
        };
        let (alone, _, _, _, _) =
            plan_terminal_events(&[GuiEvent::Cut], None, false, egui::Modifiers::NONE);
        assert_eq!(alone, vec![0x18]);
        let (both, _, _, _, _) =
            plan_terminal_events(&[GuiEvent::Cut, key_x], None, false, ctrl_mods());
        assert_eq!(both, vec![0x18]);
    }

    #[test]
    fn paste_event_is_pty_text_and_does_not_request_a_second_paste() {
        let key_v = GuiEvent::Key {
            key: Key::V,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: ctrl_mods(),
        };
        let (bytes, copy, paste, want_paste, _) = plan_terminal_events(
            &[GuiEvent::Paste("echo ok".into()), key_v],
            None,
            false,
            ctrl_mods(),
        );
        assert!(bytes.is_empty(), "paste must not also inject key bytes: {bytes:?}");
        assert!(copy.is_none());
        assert_eq!(paste.as_deref(), Some("echo ok"));
        assert!(!want_paste, "Paste event already carries the text");
    }

    #[test]
    fn ctrl_shift_c_still_copies_without_a_copy_event() {
        let mods = egui::Modifiers {
            ctrl: true,
            shift: true,
            ..egui::Modifiers::NONE
        };
        let event = GuiEvent::Key {
            key: Key::C,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: mods,
        };
        let (bytes, copy, _, want_paste, _) =
            plan_terminal_events(&[event], Some("sel"), false, mods);
        assert!(bytes.is_empty());
        assert_eq!(copy.as_deref(), Some("sel"));
        assert!(!want_paste);
    }

    #[test]
    fn plain_click_clears_selection_and_a_drag_does_not() {
        assert!(primary_click_clears_selection(true, false, false));
        assert!(!primary_click_clears_selection(true, true, false));
        assert!(!primary_click_clears_selection(true, false, true));
        assert!(!primary_click_clears_selection(false, false, false));
    }

    #[test]
    fn osc52_clipboard_is_denied_by_default_and_bounded_when_opted_in() {
        let mut term = Emulator::new(24, 80);
        assert!(!term.allows_osc52(), "OSC 52 must be disabled by default");
        // Base64("secret-clip") = "c2VjcmV0LWNsaXA="
        term.feed(b"\x1b]52;c;c2VjcmV0LWNsaXA=\x07");
        assert_eq!(
            term.take_osc52_copy(),
            None,
            "default-deny must drop remote OSC 52 clipboard writes"
        );

        term.set_allow_osc52(true);
        term.feed(b"\x1b]52;c;c2VjcmV0LWNsaXA=\x07");
        assert_eq!(term.take_osc52_copy().as_deref(), Some("secret-clip"));

        // Oversized OSC 52 (> 64 KiB decoded) must be rejected even when opted in.
        let huge = vec![b'A'; OSC52_MAX_BYTES + 16];
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&huge);
        let seq = format!("\x1b]52;c;{b64}\x07");
        term.feed(seq.as_bytes());
        assert_eq!(
            term.take_osc52_copy(),
            None,
            "OSC 52 payload exceeding OSC52_MAX_BYTES must be dropped"
        );

        // Turning opt-in back off clears any queued value.
        term.feed(b"\x1b]52;c;c2VjcmV0LWNsaXA=\x07");
        term.set_allow_osc52(false);
        assert_eq!(term.take_osc52_copy(), None);
    }

    fn count_selection_rects(shapes: &[egui::epaint::ClippedShape]) -> usize {
        fn walk(shape: &egui::epaint::Shape) -> usize {
            match shape {
                egui::epaint::Shape::Rect(rect) if rect.fill == selection_bg() => 1,
                egui::epaint::Shape::Vec(items) => items.iter().map(walk).sum(),
                _ => 0,
            }
        }
        shapes.iter().map(|cs| walk(&cs.shape)).sum()
    }

    #[test]
    fn real_egui_three_frame_drag_highlights_copies_and_plain_click_clears() {
        let ctx = egui::Context::default();
        let mut term = Emulator::new(24, 80);
        term.focused = true;
        term.feed(b"echo COPY_OK_99 done\r\n");

        let screen = Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 480.0));
        let mut time = 0.0_f64;
        let mut step = |term: &mut Emulator, events: Vec<GuiEvent>| -> (TermOutput, egui::FullOutput) {
            let mut out = TermOutput::default();
            let raw = egui::RawInput {
                screen_rect: Some(screen),
                time: Some(time),
                predicted_dt: 1.0 / 60.0,
                focused: true,
                events,
                ..Default::default()
            };
            time += 0.1;
            let full = ctx.run(raw, |ctx| {
                term.consume_focused_keys(ctx);
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE)
                    .show(ctx, |ui| {
                        out = term.show(ui);
                    });
            });
            (out, full)
        };

        // Warm-up frame so fonts and cell metrics settle.
        let _ = step(&mut term, Vec::new());
        let font = egui::FontId::monospace(13.0);
        let (cell_w, cell_h) = ctx.fonts(|fonts| {
            let galley = fonts.layout_no_wrap("W".to_owned(), font.clone(), Color32::WHITE);
            (galley.size().x.max(7.0), galley.size().y.max(font.size * 1.25))
        });
        let cell_center = |col: usize, row: usize| -> Pos2 {
            Pos2::new((col as f32 + 0.5) * cell_w, (row as f32 + 0.5) * cell_h)
        };

        // Columns 5..=14 on row 0 are "COPY_OK_99".
        // Reproduce the exact 3-frame VNC/GUI drag: Down(5,0) -> Move(14,0) -> Up(14,0).
        let start = cell_center(5, 0);
        let end = cell_center(14, 0);
        let _ = step(
            &mut term,
            vec![
                GuiEvent::PointerMoved(start),
                GuiEvent::PointerButton {
                    pos: start,
                    button: PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
        let (_, move_frame) = step(&mut term, vec![GuiEvent::PointerMoved(end)]);
        assert_eq!(
            count_selection_rects(&move_frame.shapes),
            10,
            "same-frame drag must paint 10 highlighted selection cells"
        );
        let (_, up_frame) = step(
            &mut term,
            vec![GuiEvent::PointerButton {
                pos: end,
                button: PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert_eq!(term.selection_text().as_deref(), Some("COPY_OK_99"));
        assert_eq!(count_selection_rects(&up_frame.shapes), 10);

        // Native Copy (`Ctrl+C`) copies the selection and does NOT send `^C`.
        let (copy_out, copy_full) = step(&mut term, vec![GuiEvent::Copy]);
        assert!(copy_out.writes.is_empty(), "selected Ctrl+C must not send ^C");
        let copied = copy_full
            .platform_output
            .commands
            .iter()
            .find_map(|cmd| match cmd {
                egui::OutputCommand::CopyText(t) => Some(t.clone()),
                _ => None,
            });
        assert_eq!(copied.as_deref(), Some("COPY_OK_99"));

        // Plain primary click clears selection, and the next Copy sends `^C` (`0x03`).
        let click_pt = cell_center(1, 0);
        let _ = step(
            &mut term,
            vec![
                GuiEvent::PointerMoved(click_pt),
                GuiEvent::PointerButton {
                    pos: click_pt,
                    button: PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
        let (_, clear_frame) = step(
            &mut term,
            vec![GuiEvent::PointerButton {
                pos: click_pt,
                button: PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert_eq!(term.selection_text(), None);
        assert_eq!(count_selection_rects(&clear_frame.shapes), 0);

        let (intr_out, _) = step(&mut term, vec![GuiEvent::Copy]);
        assert_eq!(intr_out.writes, vec![0x03]);

        // Right-to-left drag (col 14 -> col 5) also selects all 10 characters.
        let _ = step(
            &mut term,
            vec![
                GuiEvent::PointerMoved(end),
                GuiEvent::PointerButton {
                    pos: end,
                    button: PointerButton::Primary,
                    pressed: true,
                    modifiers: egui::Modifiers::NONE,
                },
            ],
        );
        let _ = step(&mut term, vec![GuiEvent::PointerMoved(start)]);
        let _ = step(
            &mut term,
            vec![GuiEvent::PointerButton {
                pos: start,
                button: PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::NONE,
            }],
        );
        assert_eq!(term.selection_text().as_deref(), Some("COPY_OK_99"));
    }

    #[test]
    fn bracketed_paste_blocks_nested_reassembly_zero_padded_c1_and_normalizes_crlf() {
        // Nested reassembly: inner removal would reconstruct \x1b[201~ in a single-pass stripper.
        let nested = b"pre\x1b[20\x1b[201~1~evil";
        let clean = Emulator::sanitize_bracketed_paste(nested);
        assert_eq!(clean, b"preevil");
        assert!(!clean.contains(&0x1b));

        // Deeply nested reassembly.
        let deep = b"a\x1b[20\x1b[20\x1b[201~1~1~b";
        assert_eq!(Emulator::sanitize_bracketed_paste(deep), b"ab");

        // Zero-padded CSI terminators.
        let zero_pad = b"x\x1b[0201~y\x1b[000200~z";
        assert_eq!(Emulator::sanitize_bracketed_paste(zero_pad), b"xyz");

        // UTF-8 C1 CSI (U+009B = 0xC2 0x9B) terminator and arbitrary CSI.
        let c1_utf8 = "a\u{009b}201~b\u{009b}0201~c\u{009b}31md".as_bytes();
        let clean_c1 = Emulator::sanitize_bracketed_paste(c1_utf8);
        assert_eq!(clean_c1, b"abc31md");
        assert!(!String::from_utf8_lossy(&clean_c1).contains('\u{009b}'));

        // Raw 8-bit C1 CSI byte 0x9b (non-UTF-8).
        let c1_raw = b"a\x9b201~b\x9b31mc";
        let clean_raw = Emulator::sanitize_bracketed_paste(c1_raw);
        assert_eq!(clean_raw, b"ab31mc");
        assert!(!clean_raw.contains(&0x9b));

        // Stray ESC / arbitrary CSI must also be stripped completely.
        let stray_esc = b"ok\x1b[31mred\x1b";
        let clean_esc = Emulator::sanitize_bracketed_paste(stray_esc);
        assert_eq!(clean_esc, b"ok[31mred");
        assert!(!clean_esc.contains(&0x1b));

        // Valid CJK UTF-8 containing 0x9b continuation bytes (国=E5 9B BD, 回=E5 9B 9E, 丛=E4 B8 9B)
        // must be preserved intact!
        let cjk = "中国回车丛201~".as_bytes();
        assert_eq!(Emulator::sanitize_bracketed_paste(cjk), cjk);

        // CRLF and LF normalize to CR in both bracketed and unbracketed wrap_paste.
        let wrapped = Emulator::wrap_paste(b"line1\r\nline2\nline3\r", true);
        assert_eq!(wrapped, b"\x1b[200~line1\rline2\rline3\r\x1b[201~");
        assert_eq!(
            Emulator::wrap_paste(b"a\r\nb\nc", false),
            b"a\rb\rc"
        );
    }

    #[test]
    fn altgr_ctrl_alt_text_is_emitted_without_esc_or_ctrl_drop() {
        let altgr_mods = egui::Modifiers {
            ctrl: true,
            alt: true,
            command: true,
            ..egui::Modifiers::NONE
        };
        // European Windows AltGr+Q -> '@', accompanied by Key::Q.
        let events = [
            GuiEvent::Key {
                key: Key::Q,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: altgr_mods,
            },
            GuiEvent::Text("@".into()),
        ];
        let (bytes, _, _, _, _) = plan_terminal_events(&events, None, false, altgr_mods);
        assert_eq!(bytes, b"@", "AltGr must emit '@' without ESC or ^Q");

        // AltGr+7 -> '{' (Text-only frame).
        let (braces, _, _, _, _) =
            plan_terminal_events(&[GuiEvent::Text("{".into())], None, false, altgr_mods);
        assert_eq!(braces, b"{");

        // True Ctrl+Alt+A (no Text event) still sends ESC + ^A.
        let ctrl_alt_a = [GuiEvent::Key {
            key: Key::A,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: altgr_mods,
        }];
        let (ca, _, _, _, _) = plan_terminal_events(&ctrl_alt_a, None, false, altgr_mods);
        assert_eq!(ca, vec![0x1b, 0x01]);
    }

    #[test]
    fn windows_alt_letter_encodes_from_key_without_doubling_when_text_arrives() {
        let alt_mods = egui::Modifiers {
            alt: true,
            ..egui::Modifiers::NONE
        };
        let alt_shift = egui::Modifiers {
            alt: true,
            shift: true,
            ..egui::Modifiers::NONE
        };
        for (key, expected) in [
            (Key::B, b"\x1bb".as_slice()),
            (Key::F, b"\x1bf".as_slice()),
            (Key::D, b"\x1bd".as_slice()),
            (Key::Period, b"\x1b.".as_slice()),
        ] {
            let ev = [GuiEvent::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: alt_mods,
            }];
            let (bytes, _, _, _, _) = plan_terminal_events(&ev, None, false, alt_mods);
            assert_eq!(bytes, expected, "Windows Alt+{key:?}");
        }
        // Alt+Shift+B -> ESC B.
        let ev_upper = [GuiEvent::Key {
            key: Key::B,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: alt_shift,
        }];
        let (upper, _, _, _, _) = plan_terminal_events(&ev_upper, None, false, alt_shift);
        assert_eq!(upper, b"\x1bB");

        // Platform that sends both Key::B(alt) and Text("b") must emit ESC b only once.
        let both = [
            GuiEvent::Key {
                key: Key::B,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: alt_mods,
            },
            GuiEvent::Text("b".into()),
        ];
        let (once, _, _, _, _) = plan_terminal_events(&both, None, false, alt_mods);
        assert_eq!(once, b"\x1bb");
    }

    #[test]
    fn ctrl_punctuation_and_space_encode_control_bytes() {
        assert_eq!(Emulator::encode_key("[", true, false, false, false), Some(vec![0x1b]));
        assert_eq!(Emulator::encode_key("\\", true, false, false, false), Some(vec![0x1c]));
        assert_eq!(Emulator::encode_key("]", true, false, false, false), Some(vec![0x1d]));
        assert_eq!(Emulator::encode_key("^", true, false, false, false), Some(vec![0x1e]));
        assert_eq!(Emulator::encode_key("6", true, false, false, false), Some(vec![0x1e]));
        assert_eq!(Emulator::encode_key("_", true, false, false, false), Some(vec![0x1f]));
        assert_eq!(Emulator::encode_key("-", true, false, false, false), Some(vec![0x1f]));
        assert_eq!(Emulator::encode_key("space", true, false, false, false), Some(vec![0x00]));

        let ctrl = ctrl_mods();
        let ctrl_shift = egui::Modifiers {
            ctrl: true,
            shift: true,
            ..egui::Modifiers::NONE
        };
        for (key, mods, expected) in [
            (Key::OpenBracket, ctrl, vec![0x1b]),
            (Key::Backslash, ctrl, vec![0x1c]),
            (Key::CloseBracket, ctrl, vec![0x1d]),
            (Key::Num6, ctrl, vec![0x1e]),
            (Key::Num6, ctrl_shift, vec![0x1e]),
            (Key::Minus, ctrl_shift, vec![0x1f]),
            (Key::Space, ctrl, vec![0x00]),
        ] {
            let ev = [GuiEvent::Key {
                key,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers: mods,
            }];
            let (bytes, _, _, _, _) = plan_terminal_events(&ev, None, false, mods);
            assert_eq!(bytes, expected, "Ctrl chord for {key:?}");
        }
    }

    #[test]
    fn xterm_modified_nav_and_function_keys() {
        // Unmodified F1-F4 use SS3 (\x1bOP..S), F5-F12 use CSI tilde.
        assert_eq!(Emulator::encode_key("f1", false, false, false, false).unwrap(), b"\x1bOP");
        assert_eq!(Emulator::encode_key("f2", false, false, false, false).unwrap(), b"\x1bOQ");
        assert_eq!(Emulator::encode_key("f3", false, false, false, false).unwrap(), b"\x1bOR");
        assert_eq!(Emulator::encode_key("f4", false, false, false, false).unwrap(), b"\x1bOS");
        assert_eq!(Emulator::encode_key("f5", false, false, false, false).unwrap(), b"\x1b[15~");
        assert_eq!(Emulator::encode_key("f12", false, false, false, false).unwrap(), b"\x1b[24~");

        // Modified F1-F4 switch to CSI 1;{mod}P..S.
        assert_eq!(Emulator::encode_key("f1", false, false, true, false).unwrap(), b"\x1b[1;2P");
        assert_eq!(Emulator::encode_key("f2", false, true, false, false).unwrap(), b"\x1b[1;3Q");
        assert_eq!(Emulator::encode_key("f3", true, false, false, false).unwrap(), b"\x1b[1;5R");
        assert_eq!(Emulator::encode_key("f4", true, true, true, false).unwrap(), b"\x1b[1;8S");

        // Modified F5-F12 use CSI {code};{mod}~.
        assert_eq!(Emulator::encode_key("f5", true, false, false, false).unwrap(), b"\x1b[15;5~");
        assert_eq!(Emulator::encode_key("f12", false, true, false, false).unwrap(), b"\x1b[24;3~");

        // Modified Arrows, Home, End, Insert, Delete, PageUp, PageDown.
        assert_eq!(Emulator::encode_key("left", true, false, false, false).unwrap(), b"\x1b[1;5D");
        assert_eq!(Emulator::encode_key("right", false, true, false, false).unwrap(), b"\x1b[1;3C");
        assert_eq!(Emulator::encode_key("home", true, false, false, false).unwrap(), b"\x1b[1;5H");
        assert_eq!(Emulator::encode_key("end", false, false, true, false).unwrap(), b"\x1b[1;2F");
        assert_eq!(Emulator::encode_key("insert", false, false, true, false).unwrap(), b"\x1b[2;2~");
        assert_eq!(Emulator::encode_key("delete", true, false, false, false).unwrap(), b"\x1b[3;5~");
        assert_eq!(Emulator::encode_key("pageup", true, false, false, false).unwrap(), b"\x1b[5;5~");
        assert_eq!(Emulator::encode_key("pagedown", false, true, false, false).unwrap(), b"\x1b[6;3~");
    }

    #[test]
    fn ctrl_v_and_ctrl_x_pass_through_and_empty_copy_never_wipes_clipboard() {
        // Plain Ctrl+V sends 0x16 (^V) instead of requesting paste.
        let key_v = GuiEvent::Key {
            key: Key::V,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: ctrl_mods(),
        };
        let (bytes, copy, paste, want_paste, _) =
            plan_terminal_events(&[key_v], None, false, ctrl_mods());
        assert_eq!(bytes, vec![0x16]);
        assert!(copy.is_none());
        assert!(paste.is_none());
        assert!(!want_paste);

        // Ctrl+X with an active selection MUST still forward ^X (0x18), never hijack as Copy.
        let (cut_bytes, cut_copy, _, _, _) =
            plan_terminal_events(&[GuiEvent::Cut], Some("selected"), false, ctrl_mods());
        assert_eq!(cut_bytes, vec![0x18]);
        assert!(cut_copy.is_none());

        // Ctrl+Shift+C with empty selection must NOT return Copy("") or send ^C.
        let ctrl_shift = egui::Modifiers {
            ctrl: true,
            shift: true,
            ..egui::Modifiers::NONE
        };
        let key_csc = GuiEvent::Key {
            key: Key::C,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: ctrl_shift,
        };
        let (csc_bytes, csc_copy, _, _, _) =
            plan_terminal_events(&[key_csc], None, false, ctrl_shift);
        assert!(csc_bytes.is_empty(), "Ctrl+Shift+C with empty selection must not send ^C");
        assert!(csc_copy.is_none(), "Ctrl+Shift+C with empty selection must not wipe clipboard");
    }

    #[test]
    fn ctrl_c_copy_clears_selection_so_second_ctrl_c_interrupts() {
        let ctx = egui::Context::default();
        let mut term = Emulator::new(24, 80);
        term.focused = true;
        term.feed(b"hello world");
        let mut sel = Selection::new(SelectionType::Simple, Point::new(Line(0), Column(0)), Side::Left);
        sel.update(Point::new(Line(0), Column(4)), Side::Right);
        sel.include_all();
        term.term.selection = Some(sel);

        let screen = Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 480.0));
        let run_step = |term: &mut Emulator, events: Vec<GuiEvent>, mods: egui::Modifiers| {
            let mut out = TermOutput::default();
            let raw = egui::RawInput {
                screen_rect: Some(screen),
                focused: true,
                modifiers: mods,
                events,
                ..Default::default()
            };
            let full = ctx.run(raw, |ctx| {
                term.consume_focused_keys(ctx);
                egui::CentralPanel::default().show(ctx, |ui| {
                    out = term.show(ui);
                });
            });
            (out, full)
        };

        // 1st Ctrl+C copies selection and clears it.
        let (out1, full1) = run_step(&mut term, vec![key_c(ctrl_mods())], ctrl_mods());
        assert!(out1.writes.is_empty());
        assert!(term.selection_text().is_none(), "selection must clear on copy");
        let copied = full1.platform_output.commands.iter().find_map(|c| match c {
            egui::OutputCommand::CopyText(t) => Some(t.clone()),
            _ => None,
        });
        assert_eq!(copied.as_deref(), Some("hello"));

        // 2nd Ctrl+C immediately interrupts with 0x03 without needing a click!
        let (out2, full2) = run_step(&mut term, vec![key_c(ctrl_mods())], ctrl_mods());
        assert_eq!(out2.writes, vec![0x03]);
        assert!(!full2.platform_output.commands.iter().any(|c| matches!(c, egui::OutputCommand::CopyText(_))));
    }

    #[test]
    fn shift_pageup_scrolls_keyboard_jumps_to_bottom_and_zoom_changes_font_size() {
        let mut term = Emulator::new(10, 40);
        term.focused = true;
        for i in 0..80 {
            term.feed(format!("line {i}\r\n").as_bytes());
        }
        assert_eq!(term.term.grid().display_offset(), 0);

        // Shift+PageUp scrolls into history (no PTY bytes).
        let shift = egui::Modifiers {
            shift: true,
            ..egui::Modifiers::NONE
        };
        let pgup = GuiEvent::Key {
            key: Key::PageUp,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: shift,
        };
        let plan = term.collect_writes(&[pgup.clone()], shift);
        assert!(plan.writes.is_empty());
        assert!(term.term.grid().display_offset() > 0);
        let scrolled_up = term.term.grid().display_offset();

        // Shift+PageDown scrolls back down.
        let pgdn = GuiEvent::Key {
            key: Key::PageDown,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: shift,
        };
        let dn_plan = term.collect_writes(&[pgdn], shift);
        assert!(dn_plan.writes.is_empty());
        assert!(term.term.grid().display_offset() < scrolled_up);

        // Scroll back up so we can test keyboard jump-to-bottom.
        term.collect_writes(&[pgup.clone()], shift);
        assert!(term.term.grid().display_offset() > 0);

        // In alt screen, Shift+PageUp forwards \x1b[5;2~ instead of scrolling.
        let alt_plan = plan_terminal_events_full(&[pgup], None, false, shift, true);
        assert_eq!(alt_plan.writes, b"\x1b[5;2~");
        assert!(alt_plan.scroll.is_none());

        // Keyboard input via consume_focused_keys jumps back to bottom.
        let ctx = egui::Context::default();
        let raw = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(640.0, 320.0))),
            focused: true,
            events: vec![GuiEvent::Text("a".into())],
            ..Default::default()
        };
        let _ = ctx.run(raw, |ctx| {
            term.consume_focused_keys(ctx);
            egui::CentralPanel::default().show(ctx, |ui| {
                let out = term.show(ui);
                assert_eq!(out.writes, b"a");
            });
        });
        assert_eq!(term.term.grid().display_offset(), 0);

        // Font-size zoom: Ctrl+=, Ctrl+-, Ctrl+0.
        let base = term.font_size();
        let ctrl = ctrl_mods();
        let eq = GuiEvent::Key {
            key: Key::Equals,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: ctrl,
        };
        let minus = GuiEvent::Key {
            key: Key::Minus,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: ctrl,
        };
        let zero = GuiEvent::Key {
            key: Key::Num0,
            physical_key: None,
            pressed: true,
            repeat: false,
            modifiers: ctrl,
        };
        let p_in = term.collect_writes(&[eq.clone()], ctrl);
        assert!(p_in.writes.is_empty());
        assert_eq!(term.font_size(), base + FONT_SIZE_STEP);
        let p_out = term.collect_writes(&[minus], ctrl);
        assert!(p_out.writes.is_empty());
        assert_eq!(term.font_size(), base);
        term.collect_writes(&[eq.clone()], ctrl);
        term.collect_writes(&[eq], ctrl);
        assert_eq!(term.font_size(), base + 2.0 * FONT_SIZE_STEP);
        term.collect_writes(&[zero], ctrl);
        assert_eq!(term.font_size(), DEFAULT_FONT_SIZE);
    }

    #[test]
    fn scrollbar_and_clamped_ime_geometry_and_focus_loss_clear_preedit() {
        let rect = Rect::from_min_size(Pos2::new(10.0, 20.0), Vec2::new(400.0, 200.0));
        assert!(scrollbar_thumb_rect(rect, 0, 24, 0).is_none());
        let (track_bot, thumb_bot) = scrollbar_thumb_rect(rect, 100, 24, 0).unwrap();
        let (_, thumb_top) = scrollbar_thumb_rect(rect, 100, 24, 100).unwrap();
        assert!((thumb_bot.max.y - track_bot.max.y).abs() < 0.01);
        assert!((thumb_top.min.y - track_bot.min.y).abs() < 0.01);

        // Even when cursor row/col are far off-screen (scrolled up), IME rects stay clamped inside rect.
        let (preedit_rect, cursor_rect) =
            clamped_ime_rects(rect, 999, 999, 24, 80, 8.0, 16.0, 120.0);
        assert!(rect.contains_rect(preedit_rect), "{preedit_rect:?} not in {rect:?}");
        assert!(rect.contains_rect(cursor_rect), "{cursor_rect:?} not in {rect:?}");

        // Focus loss clears IME preedit.
        let ctx = egui::Context::default();
        let mut term = Emulator::new(24, 80);
        term.focused = true;
        term.ime_preedit = "nihao".into();
        let raw = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(640.0, 320.0))),
            focused: false,
            events: vec![GuiEvent::WindowFocused(false)],
            ..Default::default()
        };
        let _ = ctx.run(raw, |ctx| {
            term.consume_focused_keys(ctx);
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = term.show(ui);
            });
        });
        assert!(term.ime_preedit.is_empty(), "IME preedit must clear on focus loss");
    }

    #[test]
    fn styled_runs_and_combining_marks_render_cleanly_in_egui() {
        let ctx = egui::Context::default();
        let mut term = Emulator::new(24, 80);
        term.focused = true;
        // Bold + italic + underline + strikeout + combining mark + wide CJK + plain run.
        term.feed(
            "\x1b[1mBOLD\x1b[0m \x1b[3mITALIC\x1b[0m \x1b[4mUNDER\x1b[0m \x1b[9mSTRIKE\x1b[0m e\u{0301} 中文 plain text run"
                .as_bytes(),
        );
        let raw = egui::RawInput {
            screen_rect: Some(Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 480.0))),
            focused: true,
            ..Default::default()
        };
        let full = ctx.run(raw, |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                let _ = term.show(ui);
            });
        });
        // Verify shapes were produced and text batching kept total text shapes well below cell count.
        fn count_text_shapes(shape: &egui::epaint::Shape) -> usize {
            match shape {
                egui::epaint::Shape::Text(_) => 1,
                egui::epaint::Shape::Vec(items) => items.iter().map(count_text_shapes).sum(),
                _ => 0,
            }
        }
        let text_shapes: usize = full.shapes.iter().map(|cs| count_text_shapes(&cs.shape)).sum();
        assert!(text_shapes > 0, "styled terminal must paint text");
        // Line has >40 visible characters; batched runs must produce far fewer text shapes than chars.
        assert!(
            text_shapes < 20,
            "expected batched text runs (<20 shapes), got {text_shapes}"
        );
    }

    #[test]
    fn triple_click_selects_entire_line_in_egui() {
        let ctx = egui::Context::default();
        let mut term = Emulator::new(24, 80);
        term.focused = true;
        term.feed(b"first word second third\r\nsecond line\r\n");

        let screen = Rect::from_min_size(Pos2::ZERO, Vec2::new(800.0, 480.0));
        let mut time = 0.0_f64;
        let mut step = |term: &mut Emulator, events: Vec<GuiEvent>| {
            let raw = egui::RawInput {
                screen_rect: Some(screen),
                time: Some(time),
                predicted_dt: 1.0 / 60.0,
                focused: true,
                events,
                ..Default::default()
            };
            time += 0.05;
            let _ = ctx.run(raw, |ctx| {
                term.consume_focused_keys(ctx);
                egui::CentralPanel::default()
                    .frame(egui::Frame::NONE)
                    .show(ctx, |ui| {
                        let _ = term.show(ui);
                    });
            });
        };

        step(&mut term, Vec::new());
        let font = egui::FontId::monospace(term.font_size());
        let (cell_w, cell_h) = ctx.fonts(|fonts| {
            let galley = fonts.layout_no_wrap("W".to_owned(), font.clone(), Color32::WHITE);
            (galley.size().x.max(7.0), galley.size().y.max(font.size * 1.25))
        });
        let pt = Pos2::new(2.5 * cell_w, 0.5 * cell_h);

        // Three rapid primary clicks at the same cell trigger triple-click line selection.
        for _ in 0..3 {
            step(
                &mut term,
                vec![
                    GuiEvent::PointerMoved(pt),
                    GuiEvent::PointerButton {
                        pos: pt,
                        button: PointerButton::Primary,
                        pressed: true,
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
            step(
                &mut term,
                vec![GuiEvent::PointerButton {
                    pos: pt,
                    button: PointerButton::Primary,
                    pressed: false,
                    modifiers: egui::Modifiers::NONE,
                }],
            );
        }
        let sel = term.selection_text().expect("triple click must select line");
        assert!(
            sel.contains("first word second third"),
            "expected full first line selected, got {sel:?}"
        );
    }
}
