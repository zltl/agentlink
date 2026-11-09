//! Raw local terminal for `agentlink shell`.
//!
//! Keyboard and resize events are translated to VT sequences and sent to the
//! remote PTY. Mouse events stay local. If the local stdin is not a terminal,
//! the caller falls back to line mode.

use agentlink_core::PtySession;
use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, size};
use std::io::{stdout, Write};
use tokio::sync::mpsc;

pub fn terminal_size() -> (u16, u16) {
    match size() {
        Ok((cols, rows)) => (rows.max(1), cols.max(1)),
        Err(_) => (24, 80),
    }
}

pub async fn interact(session: &mut PtySession, line: bool) -> Result<i32> {
    if line || enable_raw_mode().is_err() {
        return Ok(session.interact_lines().await?);
    }
    let result = interact_raw(session).await;
    disable_raw_mode().ok();
    Ok(result?)
}

enum LocalInput {
    Data(Vec<u8>),
    Resize(u16, u16),
}

async fn interact_raw(session: &mut PtySession) -> Result<i32> {
    let (tx, mut rx) = mpsc::unbounded_channel::<LocalInput>();
    std::thread::spawn(move || loop {
        let Ok(event) = event::read() else {
            break;
        };
        let input = match event {
            Event::Key(key) => {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                encode_key(key).map(LocalInput::Data)
            }
            Event::Resize(cols, rows) => Some(LocalInput::Resize(rows, cols)),
            Event::Paste(text) => Some(LocalInput::Data(text.into_bytes())),
            _ => None,
        };
        if let Some(input) = input {
            if tx.send(input).is_err() {
                break;
            }
        }
    });

    loop {
        tokio::select! {
            event = session.recv() => {
                match event? {
                    agentlink_core::PtyEvent::Data(bytes) => {
                        let mut out = stdout();
                        out.write_all(&bytes).ok();
                        out.flush().ok();
                    }
                    agentlink_core::PtyEvent::Exit(code) => return Ok(code),
                    agentlink_core::PtyEvent::Error(err) => {
                        return Err(anyhow::anyhow!(err));
                    }
                }
            }
            input = rx.recv() => {
                match input {
                    Some(LocalInput::Resize(rows, cols)) => session.resize(rows, cols).await?,
                    Some(LocalInput::Data(bytes)) => session.write(&bytes).await?,
                    None => return Ok(0),
                }
            }
        }
    }
}

pub fn encode_key(key: KeyEvent) -> Option<Vec<u8>> {
    let mods = key.modifiers;
    match key.code {
        KeyCode::Char(ch) if mods.contains(KeyModifiers::CONTROL) && ch.is_ascii_alphabetic() => {
            let byte = ch.to_ascii_lowercase() as u8 - b'a' + 1;
            Some(vec![byte])
        }
        KeyCode::Char(ch) if mods.contains(KeyModifiers::ALT) => {
            let mut bytes = vec![0x1b];
            bytes.extend(ch.to_string().into_bytes());
            Some(bytes)
        }
        KeyCode::Char(ch) => Some(ch.to_string().into_bytes()),
        KeyCode::Enter => Some(vec![b'\r']),
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::BackTab => Some(b"\x1b[Z".to_vec()),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Up => Some(arrow(b'A', mods)),
        KeyCode::Down => Some(arrow(b'B', mods)),
        KeyCode::Right => Some(arrow(b'C', mods)),
        KeyCode::Left => Some(arrow(b'D', mods)),
        KeyCode::Home => Some(b"\x1b[H".to_vec()),
        KeyCode::End => Some(b"\x1b[F".to_vec()),
        KeyCode::PageUp => Some(b"\x1b[5~".to_vec()),
        KeyCode::PageDown => Some(b"\x1b[6~".to_vec()),
        KeyCode::Insert => Some(b"\x1b[2~".to_vec()),
        KeyCode::Delete => Some(b"\x1b[3~".to_vec()),
        KeyCode::F(n) => fn_key(n),
        _ => None,
    }
}

fn arrow(code: u8, mods: KeyModifiers) -> Vec<u8> {
    let param = 1
        + usize::from(mods.contains(KeyModifiers::SHIFT))
        + 2 * usize::from(mods.contains(KeyModifiers::ALT))
        + 4 * usize::from(mods.contains(KeyModifiers::CONTROL));
    if param == 1 {
        vec![0x1b, b'[', code]
    } else {
        format!("\x1b[1;{param}{ch}", ch = code as char).into_bytes()
    }
}

fn fn_key(n: u8) -> Option<Vec<u8>> {
    let seq = match n {
        1 => "\x1b[11~",
        2 => "\x1b[12~",
        3 => "\x1b[13~",
        4 => "\x1b[14~",
        5 => "\x1b[15~",
        6 => "\x1b[17~",
        7 => "\x1b[18~",
        8 => "\x1b[19~",
        9 => "\x1b[20~",
        10 => "\x1b[21~",
        11 => "\x1b[23~",
        12 => "\x1b[24~",
        _ => return None,
    };
    Some(seq.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_arrows_ctrl_and_text() {
        let up = encode_key(KeyEvent::new(KeyCode::Up, KeyModifiers::NONE)).unwrap();
        assert_eq!(up, b"\x1b[A");
        let ctrl_c = encode_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)).unwrap();
        assert_eq!(ctrl_c, vec![3]);
        let letter = encode_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE)).unwrap();
        assert_eq!(letter, b"a");
        let f1 = encode_key(KeyEvent::new(KeyCode::F(1), KeyModifiers::NONE)).unwrap();
        assert_eq!(f1, b"\x1b[11~");
    }
}
