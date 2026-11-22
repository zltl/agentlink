//! Raw local terminal for `agentlink shell`.
//!
//! Keyboard and resize events are translated to VT sequences and sent to the
//! remote PTY. Mouse events stay local. If the local stdin is not a terminal,
//! the caller falls back to line mode.

use std::io::{stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use agentlink_core::PtySession;
use anyhow::Result;
use crossterm::event::{
    self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEvent, KeyEventKind,
    KeyModifiers,
};
use crossterm::execute;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use tokio::sync::mpsc;

const MAX_COALESCE_BYTES: usize = 16 * 1024;

pub fn terminal_size() -> (u16, u16) {
    match size() {
        Ok((cols, rows)) => (rows.max(1), cols.max(1)),
        Err(_) => (24, 80),
    }
}

/// RAII guard that restores terminal raw mode and bracketed paste on drop,
/// including early returns, Ctrl-C, or panics.
struct RawModeGuard {
    bracketed_paste: bool,
}

impl RawModeGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        let bracketed_paste = execute!(stdout(), EnableBracketedPaste).is_ok();
        Ok(Self { bracketed_paste })
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.bracketed_paste {
            let _ = execute!(stdout(), DisableBracketedPaste);
        }
        let _ = disable_raw_mode();
    }
}

/// Carries up to 3 trailing bytes of an incomplete UTF-8 sequence across PTY
/// chunks so Windows `WriteConsoleW` never rejects split CJK/emoji sequences
/// with `InvalidData` and drops an entire 4 KiB output chunk.
pub(crate) struct Utf8ConsoleWriter {
    carry: Vec<u8>,
}

impl Utf8ConsoleWriter {
    pub(crate) fn new() -> Self {
        Self {
            carry: Vec::with_capacity(8),
        }
    }

    pub(crate) fn write_chunk<W: Write>(&mut self, out: &mut W, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        let mut combined;
        let slice: &[u8] = if self.carry.is_empty() {
            chunk
        } else {
            combined = Vec::with_capacity(self.carry.len() + chunk.len());
            combined.extend_from_slice(&self.carry);
            combined.extend_from_slice(chunk);
            self.carry.clear();
            &combined
        };
        let mut rest = slice;
        while !rest.is_empty() {
            match std::str::from_utf8(rest) {
                Ok(valid) => {
                    let _ = out.write_all(valid.as_bytes());
                    break;
                }
                Err(err) => {
                    let valid_up_to = err.valid_up_to();
                    if valid_up_to > 0 {
                        let _ = out.write_all(&rest[..valid_up_to]);
                    }
                    match err.error_len() {
                        None => {
                            // Incomplete multi-byte UTF-8 sequence (1..=3 bytes) at chunk end.
                            let tail = &rest[valid_up_to..];
                            let keep = tail.len().min(4);
                            self.carry.extend_from_slice(&tail[..keep]);
                            break;
                        }
                        Some(invalid_len) => {
                            // Genuinely invalid byte(s): emit replacement char instead of
                            // letting Windows WriteConsoleW fail and drop the rest of the chunk.
                            let _ = out.write_all("\u{FFFD}".as_bytes());
                            rest = &rest[valid_up_to + invalid_len..];
                        }
                    }
                }
            }
        }
        let _ = out.flush();
    }

    pub(crate) fn finish<W: Write>(&mut self, out: &mut W) {
        if !self.carry.is_empty() {
            self.carry.clear();
            let _ = out.write_all("\u{FFFD}".as_bytes());
            let _ = out.flush();
        }
    }
}

/// Tracks SSH-style `~.` local disconnect escape after a newline (`\r` / `\n`).
#[derive(Debug, Default)]
struct EscapeTracker {
    at_line_start: bool,
    pending_tilde: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum EscapeAction {
    Send(Vec<u8>),
    Hold,
    Disconnect,
}

impl EscapeTracker {
    fn new() -> Self {
        Self {
            at_line_start: true,
            pending_tilde: false,
        }
    }

    fn feed(&mut self, bytes: Vec<u8>) -> EscapeAction {
        if self.pending_tilde {
            self.pending_tilde = false;
            if bytes == b"." {
                return EscapeAction::Disconnect;
            }
            if bytes == b"~" {
                self.at_line_start = false;
                return EscapeAction::Send(b"~".to_vec());
            }
            self.update_line_start(&bytes);
            let mut out = Vec::with_capacity(1 + bytes.len());
            out.push(b'~');
            out.extend_from_slice(&bytes);
            return EscapeAction::Send(out);
        }
        if self.at_line_start && bytes == b"~" {
            self.pending_tilde = true;
            return EscapeAction::Hold;
        }
        self.update_line_start(&bytes);
        EscapeAction::Send(bytes)
    }

    fn update_line_start(&mut self, bytes: &[u8]) {
        if let Some(&last) = bytes.last() {
            self.at_line_start = last == b'\r' || last == b'\n';
        }
    }
}

pub async fn interact(session: &mut PtySession, line: bool) -> Result<i32> {
    if line {
        return Ok(session.interact_lines().await?);
    }
    let guard = match RawModeGuard::enter() {
        Ok(guard) => guard,
        Err(_) => return Ok(session.interact_lines().await?),
    };
    let result = interact_raw(session).await;
    drop(guard);
    result
}

enum LocalInput {
    Data(Vec<u8>),
    Resize(u16, u16),
    Disconnect,
}

async fn interact_raw(session: &mut PtySession) -> Result<i32> {
    let (tx, mut rx) = mpsc::unbounded_channel::<LocalInput>();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_reader = Arc::clone(&stop);
    let reader_handle = std::thread::spawn(move || {
        let mut escape = EscapeTracker::new();
        while !stop_reader.load(Ordering::Relaxed) {
            let ready = match event::poll(Duration::from_millis(50)) {
                Ok(ready) => ready,
                Err(_) => break,
            };
            if !ready {
                continue;
            }
            let Ok(event) = event::read() else {
                break;
            };
            match event {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Release {
                        continue;
                    }
                    if let Some(bytes) = encode_key(key) {
                        match escape.feed(bytes) {
                            EscapeAction::Hold => continue,
                            EscapeAction::Disconnect => {
                                let _ = tx.send(LocalInput::Disconnect);
                                break;
                            }
                            EscapeAction::Send(out) => {
                                if tx.send(LocalInput::Data(out)).is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
                Event::Resize(cols, rows) => {
                    if tx.send(LocalInput::Resize(rows, cols)).is_err() {
                        break;
                    }
                }
                Event::Paste(text) => {
                    // Normalize CRLF/LF -> CR for interactive PTYs, and chunk to
                    // avoid flooding a single oversized RPC frame.
                    let normalized = text.replace("\r\n", "\r").replace('\n', "\r");
                    let bytes = normalized.into_bytes();
                    if let Some(&last) = bytes.last() {
                        escape.at_line_start = last == b'\r' || last == b'\n';
                    }
                    escape.pending_tilde = false;
                    for chunk in bytes.chunks(MAX_COALESCE_BYTES) {
                        if tx.send(LocalInput::Data(chunk.to_vec())).is_err() {
                            return;
                        }
                    }
                }
                _ => {}
            }
        }
    });

    let mut console_writer = Utf8ConsoleWriter::new();
    let result = loop {
        tokio::select! {
            biased;
            input = rx.recv() => {
                match input {
                    Some(LocalInput::Disconnect) => {
                        eprint!("\r\n[agentlink: disconnected via ~.]\r\n");
                        let _ = std::io::stderr().flush();
                        break Ok(0);
                    }
                    Some(LocalInput::Resize(rows, cols)) => {
                        if let Err(err) = session.resize(rows, cols).await {
                            break Err(err.into());
                        }
                    }
                    Some(LocalInput::Data(mut bytes)) => {
                        // Coalesce queued input bytes up to 16 KiB into one RPC write.
                        let mut pending_resize: Option<(u16, u16)> = None;
                        let mut disconnect = false;
                        while bytes.len() < MAX_COALESCE_BYTES {
                            match rx.try_recv() {
                                Ok(LocalInput::Data(more)) => bytes.extend_from_slice(&more),
                                Ok(LocalInput::Resize(r, c)) => {
                                    pending_resize = Some((r, c));
                                    break;
                                }
                                Ok(LocalInput::Disconnect) => {
                                    disconnect = true;
                                    break;
                                }
                                Err(_) => break,
                            }
                        }
                        if let Err(err) = session.write(&bytes).await {
                            break Err(err.into());
                        }
                        if let Some((r, c)) = pending_resize {
                            if let Err(err) = session.resize(r, c).await {
                                break Err(err.into());
                            }
                        }
                        if disconnect {
                            eprint!("\r\n[agentlink: disconnected via ~.]\r\n");
                            let _ = std::io::stderr().flush();
                            break Ok(0);
                        }
                    }
                    None => break Ok(0),
                }
            }
            event = session.recv() => {
                match event {
                    Ok(agentlink_core::PtyEvent::Data(bytes)) => {
                        let mut out = stdout().lock();
                        console_writer.write_chunk(&mut out, &bytes);
                    }
                    Ok(agentlink_core::PtyEvent::Exit(code)) => break Ok(code),
                    Ok(agentlink_core::PtyEvent::Error(err)) => {
                        break Err(anyhow::anyhow!(err));
                    }
                    Err(err) => break Err(err.into()),
                }
            }
        }
    };

    stop.store(true, Ordering::Relaxed);
    {
        let mut out = stdout().lock();
        console_writer.finish(&mut out);
    }
    let _ = reader_handle.join();
    result
}

pub fn encode_key(key: KeyEvent) -> Option<Vec<u8>> {
    let mods = key.modifiers;
    let ctrl = mods.contains(KeyModifiers::CONTROL);
    let alt = mods.contains(KeyModifiers::ALT);
    match key.code {
        // AltGr on Windows/European keyboards arrives as CONTROL | ALT with the
        // composed printable symbol (e.g. `{`, `}`, `[`, `]`, `\`, `|`, `@`, `~`, `€`).
        // Emit the UTF-8 character directly without an ESC prefix.
        KeyCode::Char(ch) if ctrl && alt && is_altgr_printable(ch) => {
            Some(ch.to_string().into_bytes())
        }
        KeyCode::Char(ch) if ctrl => {
            let ctrl_byte = ctrl_char_byte(ch)?;
            if alt {
                Some(vec![0x1b, ctrl_byte])
            } else {
                Some(vec![ctrl_byte])
            }
        }
        KeyCode::Char(ch) if alt => {
            let mut bytes = vec![0x1b];
            bytes.extend(ch.to_string().into_bytes());
            Some(bytes)
        }
        KeyCode::Char(ch) => Some(ch.to_string().into_bytes()),
        KeyCode::Enter => {
            if alt {
                Some(b"\x1b\r".to_vec())
            } else {
                Some(vec![b'\r'])
            }
        }
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::BackTab => Some(b"\x1b[Z".to_vec()),
        KeyCode::Backspace => {
            if alt {
                Some(vec![0x1b, 0x7f])
            } else if ctrl {
                Some(vec![0x08])
            } else {
                Some(vec![0x7f])
            }
        }
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Up => Some(csi_letter(b'A', mods)),
        KeyCode::Down => Some(csi_letter(b'B', mods)),
        KeyCode::Right => Some(csi_letter(b'C', mods)),
        KeyCode::Left => Some(csi_letter(b'D', mods)),
        KeyCode::Home => Some(csi_letter(b'H', mods)),
        KeyCode::End => Some(csi_letter(b'F', mods)),
        KeyCode::Insert => Some(csi_tilde(2, mods)),
        KeyCode::Delete => Some(csi_tilde(3, mods)),
        KeyCode::PageUp => Some(csi_tilde(5, mods)),
        KeyCode::PageDown => Some(csi_tilde(6, mods)),
        KeyCode::F(n) => fn_key(n, mods),
        _ => None,
    }
}

fn is_altgr_printable(ch: char) -> bool {
    !ch.is_ascii_alphabetic() && !ch.is_ascii_control() && ch != ' '
}

fn ctrl_char_byte(ch: char) -> Option<u8> {
    match ch {
        'a'..='z' => Some(ch as u8 - b'a' + 1),
        'A'..='Z' => Some(ch as u8 - b'A' + 1),
        ' ' | '@' | '2' => Some(0x00),
        '[' | '3' => Some(0x1b),
        '\\' | '4' => Some(0x1c),
        ']' | '5' => Some(0x1d),
        '^' | '6' => Some(0x1e),
        '_' | '/' | '7' => Some(0x1f),
        '?' | '8' => Some(0x7f),
        _ => None,
    }
}

fn mod_param(mods: KeyModifiers) -> usize {
    1 + usize::from(mods.contains(KeyModifiers::SHIFT))
        + 2 * usize::from(mods.contains(KeyModifiers::ALT))
        + 4 * usize::from(mods.contains(KeyModifiers::CONTROL))
}

fn csi_letter(code: u8, mods: KeyModifiers) -> Vec<u8> {
    let param = mod_param(mods);
    if param == 1 {
        vec![0x1b, b'[', code]
    } else {
        format!("\x1b[1;{param}{ch}", ch = code as char).into_bytes()
    }
}

fn csi_tilde(num: u8, mods: KeyModifiers) -> Vec<u8> {
    let param = mod_param(mods);
    if param == 1 {
        format!("\x1b[{num}~").into_bytes()
    } else {
        format!("\x1b[{num};{param}~").into_bytes()
    }
}

fn fn_key(n: u8, mods: KeyModifiers) -> Option<Vec<u8>> {
    let param = mod_param(mods);
    match n {
        1 => Some(if param == 1 {
            b"\x1bOP".to_vec()
        } else {
            format!("\x1b[1;{param}P").into_bytes()
        }),
        2 => Some(if param == 1 {
            b"\x1bOQ".to_vec()
        } else {
            format!("\x1b[1;{param}Q").into_bytes()
        }),
        3 => Some(if param == 1 {
            b"\x1bOR".to_vec()
        } else {
            format!("\x1b[1;{param}R").into_bytes()
        }),
        4 => Some(if param == 1 {
            b"\x1bOS".to_vec()
        } else {
            format!("\x1b[1;{param}S").into_bytes()
        }),
        5 => Some(csi_tilde(15, mods)),
        6 => Some(csi_tilde(17, mods)),
        7 => Some(csi_tilde(18, mods)),
        8 => Some(csi_tilde(19, mods)),
        9 => Some(csi_tilde(20, mods)),
        10 => Some(csi_tilde(21, mods)),
        11 => Some(csi_tilde(23, mods)),
        12 => Some(csi_tilde(24, mods)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_arrows_ctrl_altgr_and_xterm_fkeys() {
        let up = encode_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)).unwrap();
        assert_eq!(up, b"\x1b[A");
        let ctrl_c = encode_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)).unwrap();
        assert_eq!(ctrl_c, vec![3]);
        let letter = encode_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE)).unwrap();
        assert_eq!(letter, b"a");
        let f1 = encode_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE)).unwrap();
        assert_eq!(f1, b"\x1bOP");
        let shift_f1 = encode_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::SHIFT)).unwrap();
        assert_eq!(shift_f1, b"\x1b[1;2P");
        let ctrl_del = encode_key(KeyEvent::new(KeyCode::Delete, KeyModifiers::CONTROL)).unwrap();
        assert_eq!(ctrl_del, b"\x1b[3;5~");

        // Full Ctrl control bytes
        assert_eq!(
            encode_key(KeyEvent::new(KeyCode::Char(' '), KeyModifiers::CONTROL)).unwrap(),
            vec![0x00]
        );
        assert_eq!(
            encode_key(KeyEvent::new(KeyCode::Char('['), KeyModifiers::CONTROL)).unwrap(),
            vec![0x1b]
        );
        assert_eq!(
            encode_key(KeyEvent::new(KeyCode::Char('\\'), KeyModifiers::CONTROL)).unwrap(),
            vec![0x1c]
        );
        assert_eq!(
            encode_key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL)).unwrap(),
            vec![0x1d]
        );
        assert_eq!(
            encode_key(KeyEvent::new(KeyCode::Char('^'), KeyModifiers::CONTROL)).unwrap(),
            vec![0x1e]
        );
        assert_eq!(
            encode_key(KeyEvent::new(KeyCode::Char('_'), KeyModifiers::CONTROL)).unwrap(),
            vec![0x1f]
        );

        // AltGr (CONTROL | ALT + composed printable) must NOT prepend ESC
        let altgr = KeyModifiers::CONTROL | KeyModifiers::ALT;
        assert_eq!(encode_key(KeyEvent::new(KeyCode::Char('{'), altgr)).unwrap(), b"{");
        assert_eq!(encode_key(KeyEvent::new(KeyCode::Char('@'), altgr)).unwrap(), b"@");
        assert_eq!(
            encode_key(KeyEvent::new(KeyCode::Char('€'), altgr)).unwrap(),
            "€".as_bytes()
        );
    }

    #[test]
    fn utf8_console_writer_reassembles_split_cjk_and_emoji_chunks() {
        let text = "hello 你好 🚀 world!";
        let raw = text.as_bytes();
        // Feed 1 byte at a time to stress every possible split boundary.
        let mut writer = Utf8ConsoleWriter::new();
        let mut out = Vec::new();
        for byte in raw {
            writer.write_chunk(&mut out, std::slice::from_ref(byte));
        }
        writer.finish(&mut out);
        assert_eq!(String::from_utf8(out).unwrap(), text);

        // Invalid bytes are replaced with U+FFFD without dropping following valid text.
        let mut writer = Utf8ConsoleWriter::new();
        let mut out = Vec::new();
        writer.write_chunk(&mut out, b"ab\xffcd");
        writer.finish(&mut out);
        assert_eq!(String::from_utf8(out).unwrap(), "ab\u{FFFD}cd");
    }

    #[test]
    fn escape_tracker_handles_tilde_dot_and_literal_tilde() {
        let mut esc = EscapeTracker::new();
        // Start of session is at line start: `~` followed by `.` disconnects.
        assert_eq!(esc.feed(b"~".to_vec()), EscapeAction::Hold);
        assert_eq!(esc.feed(b".".to_vec()), EscapeAction::Disconnect);

        // Mid-line `~.` is passed straight through.
        let mut esc = EscapeTracker::new();
        assert_eq!(esc.feed(b"a".to_vec()), EscapeAction::Send(b"a".to_vec()));
        assert_eq!(esc.feed(b"~".to_vec()), EscapeAction::Send(b"~".to_vec()));
        assert_eq!(esc.feed(b".".to_vec()), EscapeAction::Send(b".".to_vec()));

        // After Enter, `~~` sends one literal `~`, and `~x` sends `~x`.
        assert_eq!(esc.feed(b"\r".to_vec()), EscapeAction::Send(b"\r".to_vec()));
        assert_eq!(esc.feed(b"~".to_vec()), EscapeAction::Hold);
        assert_eq!(esc.feed(b"~".to_vec()), EscapeAction::Send(b"~".to_vec()));
        assert_eq!(esc.feed(b"\r".to_vec()), EscapeAction::Send(b"\r".to_vec()));
        assert_eq!(esc.feed(b"~".to_vec()), EscapeAction::Hold);
        assert_eq!(esc.feed(b"x".to_vec()), EscapeAction::Send(b"~x".to_vec()));
    }
}
