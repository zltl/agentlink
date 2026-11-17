//! Remote PTY terminal for the desktop Controller.
//!
//! Emulation is Alacritty's `alacritty_terminal` grid and VTE parser
//! (Apache-2.0, https://github.com/alacritty/alacritty, crate 0.25.1).
//! Bytes come from the agentlink PTY; we never spawn a local tty or SSH
//! session. The egui view is our own (the `egui_term` crate talks to a
//! local PTY backend we cannot use here).

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

/// Bytes the UI should write to the remote PTY after one frame.
#[derive(Debug, Default)]
pub struct TermOutput {
    pub writes: Vec<u8>,
    pub resized: Option<(u16, u16)>,
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
struct TermHost {
    pending: Arc<Mutex<Vec<u8>>>,
    title: Arc<Mutex<String>>,
    clipboard: Arc<Mutex<Option<String>>>,
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
                *self.clipboard.lock().expect("term host") = Some(text);
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
    ime_preedit: String,
    pub focused: bool,
    selecting: bool,
    /// GUI keystrokes already taken this frame (so show() does not double-read).
    keys_taken: bool,
    pending_gui_writes: Vec<u8>,
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
            ime_preedit: String::new(),
            focused: false,
            selecting: false,
            keys_taken: false,
            pending_gui_writes: Vec::new(),
        }
    }

    pub fn size(&self) -> (u16, u16) {
        (self.rows, self.cols)
    }

    pub fn feed(&mut self, bytes: &[u8]) {
        if !bytes.is_empty() {
            self.parser.advance(&mut self.term, bytes);
        }
    }

    pub fn take_writes(&self) -> Vec<u8> {
        std::mem::take(&mut *self.host.pending.lock().expect("term host"))
    }

    pub fn take_osc52_copy(&self) -> Option<String> {
        self.host.clipboard.lock().expect("term host").take()
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
                return Some(arrow(b"A", app_cursor, ctrl, alt, shift));
            }
            "down" | "arrowdown" => {
                return Some(arrow(b"B", app_cursor, ctrl, alt, shift));
            }
            "right" | "arrowright" => {
                return Some(arrow(b"C", app_cursor, ctrl, alt, shift));
            }
            "left" | "arrowleft" => {
                return Some(arrow(b"D", app_cursor, ctrl, alt, shift));
            }
            "home" => {
                return Some(if app_cursor {
                    b"\x1bOH".to_vec()
                } else {
                    b"\x1b[H".to_vec()
                });
            }
            "end" => {
                return Some(if app_cursor {
                    b"\x1bOF".to_vec()
                } else {
                    b"\x1b[F".to_vec()
                });
            }
            "pageup" => b"\x1b[5~",
            "pagedown" => b"\x1b[6~",
            "insert" => b"\x1b[2~",
            "delete" => b"\x1b[3~",
            "f1" => b"\x1bOP",
            "f2" => b"\x1bOQ",
            "f3" => b"\x1bOR",
            "f4" => b"\x1bOS",
            "f5" => b"\x1b[15~",
            "f6" => b"\x1b[17~",
            "f7" => b"\x1b[18~",
            "f8" => b"\x1b[19~",
            "f9" => b"\x1b[20~",
            "f10" => b"\x1b[21~",
            "f11" => b"\x1b[23~",
            "f12" => b"\x1b[24~",
            _ => return None,
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

    /// Strip inner bracketed-paste delimiters so a clipboard payload cannot
    /// close the wrapping sequence and inject raw CSI into the PTY.
    pub fn sanitize_bracketed_paste(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        let mut i = 0;
        while i < data.len() {
            if data[i] == 0x1b
                && i + 6 <= data.len()
                && data[i + 1] == b'['
                && data[i + 5] == b'~'
                && (data[i + 2..i + 5] == *b"200" || data[i + 2..i + 5] == *b"201")
            {
                i += 6;
                continue;
            }
            out.push(data[i]);
            i += 1;
        }
        out
    }

    pub fn wrap_paste(data: &[u8], bracketed: bool) -> Vec<u8> {
        if bracketed {
            let mut out = b"[200~".to_vec();
            out.extend(Self::sanitize_bracketed_paste(data));
            out.extend_from_slice(b"[201~");
            out
        } else {
            data.to_vec()
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
        if !self.focused {
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
        let (writes, copy_text, paste_text, want_paste) = self.collect_writes(&captured, modifiers);
        if let Some(text) = copy_text {
            ctx.copy_text(text);
        }
        if let Some(text) = paste_text {
            self.pending_gui_writes.extend(Self::wrap_paste(
                text.as_bytes(),
                self.term.mode().contains(TermMode::BRACKETED_PASTE),
            ));
        }
        if want_paste {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaste);
        }
        self.pending_gui_writes.extend(writes);
        self.keys_taken = true;
    }

    fn collect_writes(
        &mut self,
        events: &[GuiEvent],
        modifiers: egui::Modifiers,
    ) -> (Vec<u8>, Option<String>, Option<String>, bool) {
        let selection = self.term.selection_to_string();
        let (writes, copy_text, paste_text, want_paste, preedit) = plan_terminal_events(
            events,
            selection.as_deref(),
            self.app_cursor(),
            modifiers,
        );
        if let Some(text) = preedit {
            self.ime_preedit = text;
        }
        (writes, copy_text, paste_text, want_paste)
    }

    /// Draw the emulator and collect PTY input for this frame.
    pub fn show(&mut self, ui: &mut egui::Ui) -> TermOutput {
        let mut out = TermOutput {
            writes: self.take_writes(),
            resized: None,
        };
        let font = egui::FontId::monospace(13.0);
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
        if self.focused && !response.has_focus() {
            response.request_focus();
        }
        if response.clicked() || response.dragged() {
            response.request_focus();
            self.focused = true;
        }
        if response.lost_focus() {
            self.focused = false;
        }
        if response.has_focus() {
            self.focused = true;
        }

        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 0.0, palette_bg());

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

            for indexed in content.display_iter {
                if indexed.cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                    continue;
                }
                let row = (indexed.point.line + display_offset as i32).0;
                let col = indexed.point.column.0;
                if row < 0 || col >= cols as usize {
                    continue;
                }
                let wide = indexed.cell.flags.contains(Flags::WIDE_CHAR);
                let width_cells = if wide { 2.0 } else { 1.0 };
                let cell_rect = Rect::from_min_size(
                    Pos2::new(
                        rect.min.x + col as f32 * cell_w,
                        rect.min.y + row as f32 * cell_h,
                    ),
                    Vec2::new(cell_w * width_cells, cell_h),
                );
                let mut fg = resolve_color(indexed.cell.fg, true);
                let mut bg = resolve_color(indexed.cell.bg, false);
                let inverse = indexed.cell.flags.contains(Flags::INVERSE)
                    || selection.is_some_and(|s| s.contains(indexed.point));
                if inverse {
                    std::mem::swap(&mut fg, &mut bg);
                }
                if indexed.cell.flags.contains(Flags::DIM) {
                    fg = Color32::from_rgb(
                        (fg.r() as u16 * 2 / 3) as u8,
                        (fg.g() as u16 * 2 / 3) as u8,
                        (fg.b() as u16 * 2 / 3) as u8,
                    );
                }
                if bg != palette_bg() {
                    painter.rect_filled(cell_rect, 0.0, bg);
                }
                if indexed.cell.flags.contains(Flags::HIDDEN) {
                    continue;
                }
                let ch = indexed.cell.c;
                if ch != ' ' && ch != '\0' {
                    painter.text(
                        cell_rect.min + Vec2::new(0.0, (cell_h - font.size) * 0.2),
                        egui::Align2::LEFT_TOP,
                        ch,
                        font.clone(),
                        fg,
                    );
                }
                if indexed.cell.flags.intersects(Flags::ALL_UNDERLINES) {
                    let y = cell_rect.max.y - 2.0;
                    painter.line_segment(
                        [Pos2::new(cell_rect.min.x, y), Pos2::new(cell_rect.max.x, y)],
                        egui::Stroke::new(1.0, fg),
                    );
                }
            }

            if show_cursor {
                let row = (Line(cursor_point.line.0 + display_offset as i32)).0;
                let col = cursor_point.column.0;
                if row >= 0 && col < cols as usize {
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

        if self.focused && !self.ime_preedit.is_empty() {
            let (row, col) = self.cursor_pos();
            let pos = Pos2::new(
                rect.min.x + col as f32 * cell_w,
                rect.min.y + row as f32 * cell_h,
            );
            painter.text(
                pos,
                egui::Align2::LEFT_TOP,
                &self.ime_preedit,
                font.clone(),
                Color32::from_rgb(0xC8, 0xC8, 0xFF),
            );
        }

        if self.focused {
            let (row, col) = self.cursor_pos();
            let cursor_rect = Rect::from_min_size(
                Pos2::new(
                    rect.min.x + col as f32 * cell_w,
                    rect.min.y + row as f32 * cell_h,
                ),
                Vec2::new(2.0, cell_h),
            );
            ui.ctx().output_mut(|o| {
                o.ime = Some(egui::output::IMEOutput { rect, cursor_rect });
            });
        }

        // Scrollback
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

        let to_point = |pos: Pos2| -> Point {
            let col = ((pos.x - rect.min.x) / cell_w)
                .floor()
                .clamp(0.0, (cols - 1) as f32) as usize;
            let row = ((pos.y - rect.min.y) / cell_h)
                .floor()
                .clamp(0.0, (rows - 1) as f32) as i32;
            let line = Line(row - display_offset as i32);
            Point::new(line, Column(col))
        };

        if response.drag_started_by(PointerButton::Primary) {
            if let Some(pos) = response.interact_pointer_pos() {
                let point = to_point(pos);
                self.term.selection =
                    Some(Selection::new(SelectionType::Simple, point, Side::Left));
                self.selecting = true;
            }
        } else if self.selecting && response.dragged_by(PointerButton::Primary) {
            if let Some(pos) = response.interact_pointer_pos() {
                if let Some(sel) = self.term.selection.as_mut() {
                    sel.update(to_point(pos), Side::Right);
                }
            }
        } else if response.drag_stopped() {
            self.selecting = false;
        }
        if primary_click_clears_selection(
            response.clicked_by(PointerButton::Primary),
            response.dragged_by(PointerButton::Primary),
            response.double_clicked_by(PointerButton::Primary),
        ) {
            self.term.selection = None;
        }
        if response.double_clicked() {
            if let Some(pos) = response.interact_pointer_pos() {
                let point = to_point(pos);
                self.term.selection =
                    Some(Selection::new(SelectionType::Semantic, point, Side::Left));
            }
        }

        if (response.has_focus() || self.focused) && !self.keys_taken {
            let events = ui.input(|i| i.events.clone());
            let modifiers = ui.input(|i| i.modifiers);
            let (writes, copy_text, paste_text, want_paste) =
                self.collect_writes(&events, modifiers);
            if let Some(text) = copy_text {
                ui.ctx().copy_text(text);
            }
            if let Some(text) = paste_text {
                out.writes.extend(Self::wrap_paste(
                    text.as_bytes(),
                    self.term.mode().contains(TermMode::BRACKETED_PASTE),
                ));
            }
            if want_paste
                && !events
                    .iter()
                    .any(|event| matches!(event, GuiEvent::Paste(_)))
            {
                ui.ctx()
                    .send_viewport_cmd(egui::ViewportCommand::RequestPaste);
            }
            out.writes.extend(writes);
        }
        out.writes
            .extend(std::mem::take(&mut self.pending_gui_writes));
        self.keys_taken = false;

        if let Some(osc) = self.take_osc52_copy() {
            ui.ctx().copy_text(osc);
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

/// Turn a frame of native egui events into PTY bytes.
///
/// Windows egui can emit [`GuiEvent::Copy`] for Ctrl+C without [`GuiEvent::Key`]
/// `C`. An empty selection then has to interrupt (`^C`). A non-empty selection
/// still copies. Copy plus Key(C) in the same frame produces one interrupt,
/// not two. Paste text goes to the PTY, not the remote-desktop clipboard.
pub(crate) fn plan_terminal_events(
    events: &[GuiEvent],
    selection: Option<&str>,
    app_cursor: bool,
    frame_modifiers: egui::Modifiers,
) -> (Vec<u8>, Option<String>, Option<String>, bool, Option<String>) {
    let selected = selection.filter(|text| !text.is_empty());
    let mut saw_copy = false;
    let mut saw_cut = false;
    let mut saw_paste = false;
    for event in events {
        match event {
            GuiEvent::Copy => saw_copy = true,
            GuiEvent::Cut => saw_cut = true,
            GuiEvent::Paste(_) => saw_paste = true,
            _ => {}
        }
    }

    let mut writes: Vec<u8> = Vec::new();
    let mut copy_text: Option<String> = None;
    let mut paste_text: Option<String> = None;
    let mut want_paste = false;
    let mut interrupt_from_copy = false;
    let mut cut_from_event = false;
    if saw_copy {
        if let Some(text) = selected {
            copy_text = Some(text.to_string());
        } else if let Some(bytes) = Emulator::encode_key("c", true, false, false, app_cursor) {
            writes.extend(bytes);
            interrupt_from_copy = true;
        }
    }
    if saw_cut {
        if let Some(text) = selected {
            copy_text = Some(text.to_string());
        } else if let Some(bytes) = Emulator::encode_key("x", true, false, false, app_cursor) {
            writes.extend(bytes);
            cut_from_event = true;
        }
    }

    let mut ime_commits: Vec<String> = Vec::new();
    let mut preedit_active = false;
    let mut control_key_sent = false;
    let mut preedit = None;
    for event in events {
        match event {
            GuiEvent::Copy | GuiEvent::Cut => {}
            GuiEvent::Paste(text) => {
                paste_text = Some(text.clone());
            }
            GuiEvent::Ime(ImeEvent::Enabled) => {}
            GuiEvent::Ime(ImeEvent::Preedit(text)) => {
                if !text.is_empty() {
                    preedit_active = true;
                }
                preedit = Some(text.clone());
            }
            GuiEvent::Ime(ImeEvent::Commit(text)) => {
                ime_commits.push(text.clone());
                writes.extend(Emulator::encode_text(text, false));
                preedit = Some(String::new());
            }
            GuiEvent::Ime(ImeEvent::Disabled) => {
                preedit = Some(String::new());
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
                if saw_copy && selected.is_some() && plain_ctrl(*modifiers) && matches!(key, Key::C)
                {
                    continue;
                }
                if saw_cut && selected.is_some() && plain_ctrl(*modifiers) && matches!(key, Key::X)
                {
                    continue;
                }
                let name = key_name(*key);
                match clipboard_shortcut(*key, *modifiers, selection.map(str::to_string)) {
                    TermClipboardShortcut::Copy(text) => {
                        copy_text = Some(text);
                        continue;
                    }
                    TermClipboardShortcut::Paste => {
                        want_paste = true;
                        continue;
                    }
                    TermClipboardShortcut::None => {}
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
                    writes.extend(bytes);
                }
            }
            _ => {}
        }
    }
    for event in events {
        let GuiEvent::Text(text) = event else {
            continue;
        };
        if frame_modifiers.ctrl || frame_modifiers.command {
            continue;
        }
        if Emulator::skip_duplicate_text(text, &ime_commits, preedit_active, control_key_sent) {
            continue;
        }
        writes.extend(Emulator::encode_text(text, frame_modifiers.alt));
    }
    (writes, copy_text, paste_text, want_paste, preedit)
}

/// Keyboard shortcuts that should copy or paste instead of sending a control
/// character. Ctrl+Shift+C/V always copy/paste (classic terminal). Ctrl+C
/// copies when there is a selection, otherwise it falls through as interrupt
/// (`^C`). Ctrl+V always pastes. Command modifiers follow the same rules on
/// macOS when egui does not already emit Copy/Paste events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TermClipboardShortcut {
    Copy(String),
    Paste,
    None,
}

pub(crate) fn clipboard_shortcut(
    key: Key,
    modifiers: egui::Modifiers,
    selection: Option<String>,
) -> TermClipboardShortcut {
    let chord = modifiers.ctrl || modifiers.command;
    if !chord || modifiers.alt {
        return TermClipboardShortcut::None;
    }
    if modifiers.shift && matches!(key, Key::C) {
        return TermClipboardShortcut::Copy(selection.unwrap_or_default());
    }
    if modifiers.shift && matches!(key, Key::V) {
        return TermClipboardShortcut::Paste;
    }
    if modifiers.shift {
        return TermClipboardShortcut::None;
    }
    if matches!(key, Key::C) {
        if let Some(text) = selection {
            if !text.is_empty() {
                return TermClipboardShortcut::Copy(text);
            }
        }
        return TermClipboardShortcut::None;
    }
    if matches!(key, Key::V) {
        return TermClipboardShortcut::Paste;
    }
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
        "backspace" => Some(0x7f),
        "space" => Some(0x00),
        _ => None,
    }
}

fn arrow(letter: &[u8], app_cursor: bool, ctrl: bool, alt: bool, shift: bool) -> Vec<u8> {
    if !ctrl && !alt && !shift {
        if app_cursor {
            let mut out = b"\x1bO".to_vec();
            out.extend_from_slice(letter);
            return out;
        }
        let mut out = b"\x1b[".to_vec();
        out.extend_from_slice(letter);
        return out;
    }
    // xterm modifier: 1 + shift=1 + alt=2 + ctrl=4
    let mut mods = 1;
    if shift {
        mods += 1;
    }
    if alt {
        mods += 2;
    }
    if ctrl {
        mods += 4;
    }
    format!(
        "\x1b[1;{}{}",
        mods,
        std::str::from_utf8(letter).unwrap_or("A")
    )
    .into_bytes()
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
        Key::Space => "space",
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

fn palette_bg() -> Color32 {
    Color32::from_rgb(0x0D, 0x0D, 0x12)
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
        assert_eq!(
            clipboard_shortcut(Key::V, mods, None),
            TermClipboardShortcut::Paste
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
        assert_eq!(
            clipboard_shortcut(Key::V, shift, None),
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
}
