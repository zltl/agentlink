//! Cross-platform clipboard read/write for remote control.
//!
//! Windows uses the Win32 clipboard API (no `clip.exe`, so no console flash).
//! macOS keeps `pbcopy` / `pbpaste`. Linux keeps `wl-copy`/`wl-paste` with an
//! `xclip` fallback — no native Wayland/X dependency in this crate.

use crate::error::{msg, Result};

/// Soft ceiling for a remote clipboard payload. Longer text is truncated.
pub const CLIPBOARD_MAX_CHARS: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardText {
    pub text: String,
    pub truncated: bool,
}

impl ClipboardText {
    pub fn capped(mut text: String) -> Self {
        let truncated = text.chars().count() > CLIPBOARD_MAX_CHARS;
        if truncated {
            text = text.chars().take(CLIPBOARD_MAX_CHARS).collect();
        }
        Self { text, truncated }
    }
}

pub fn read_clipboard() -> Result<ClipboardText> {
    let text = platform_read()?;
    Ok(ClipboardText::capped(text))
}

pub fn write_clipboard(text: &str) -> Result<()> {
    let capped = ClipboardText::capped(text.to_string());
    platform_write(&capped.text)
}

#[cfg(target_os = "windows")]
fn platform_read() -> Result<String> {
    windows_clip::read()
}

#[cfg(target_os = "windows")]
fn platform_write(text: &str) -> Result<()> {
    windows_clip::write(text)
}

#[cfg(target_os = "macos")]
fn platform_read() -> Result<String> {
    read_stdout("pbpaste", &[])
}

#[cfg(target_os = "macos")]
fn platform_write(text: &str) -> Result<()> {
    write_stdin("pbcopy", &[], text)
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_read() -> Result<String> {
    if let Ok(text) = read_stdout("wl-paste", &["--no-newline"]) {
        return Ok(text);
    }
    read_stdout("xclip", &["-selection", "clipboard", "-o"])
}

#[cfg(not(any(target_os = "macos", target_os = "windows")))]
fn platform_write(text: &str) -> Result<()> {
    if write_stdin("wl-copy", &[], text).is_ok() {
        return Ok(());
    }
    write_stdin("xclip", &["-selection", "clipboard"], text)
}

#[cfg(not(target_os = "windows"))]
fn write_stdin(program: &str, args: &[&str], text: &str) -> Result<()> {
    use std::io::Write;
    let mut child = agentlink_core::process::hidden(program)
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|err| msg(format!("{program}: {err}")))?;
    let Some(mut stdin) = child.stdin.take() else {
        return Err(msg(format!("{program}: no stdin")));
    };
    stdin
        .write_all(text.as_bytes())
        .map_err(|err| msg(format!("{program} write: {err}")))?;
    drop(stdin);
    let status = child
        .wait()
        .map_err(|err| msg(format!("{program} wait: {err}")))?;
    if status.success() {
        Ok(())
    } else {
        Err(msg(format!("{program} exited with {status}")))
    }
}

#[cfg(not(target_os = "windows"))]
fn read_stdout(program: &str, args: &[&str]) -> Result<String> {
    let output = agentlink_core::process::hidden(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|err| msg(format!("{program}: {err}")))?;
    if !output.status.success() {
        return Err(msg(format!("{program} exited with {}", output.status)));
    }
    String::from_utf8(output.stdout).map_err(|err| msg(format!("{program} utf8: {err}")))
}

#[cfg(target_os = "windows")]
mod windows_clip {
    use super::*;
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    use windows::core::PWSTR;
    use windows::Win32::Foundation::{HANDLE, HGLOBAL};
    use windows::Win32::System::DataExchange::{
        CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData,
    };
    use windows::Win32::System::Memory::{
        GlobalAlloc, GlobalLock, GlobalUnlock, GMEM_MOVEABLE,
    };
    use windows::Win32::System::Ole::CF_UNICODETEXT;

    pub fn read() -> Result<String> {
        unsafe {
            OpenClipboard(None).map_err(|err| msg(format!("OpenClipboard: {err}")))?;
            let result = (|| {
                let handle = GetClipboardData(CF_UNICODETEXT.0 as u32)
                    .map_err(|err| msg(format!("GetClipboardData: {err}")))?;
                if handle.is_invalid() {
                    return Ok(String::new());
                }
                let hglobal = HGLOBAL(handle.0);
                let ptr = GlobalLock(hglobal);
                if ptr.is_null() {
                    return Err(msg("GlobalLock failed for clipboard"));
                }
                let wide = PWSTR(ptr as *mut u16);
                let text = wide.to_string().unwrap_or_default();
                let _ = GlobalUnlock(hglobal);
                Ok(text)
            })();
            let _ = CloseClipboard();
            result
        }
    }

    pub fn write(text: &str) -> Result<()> {
        let mut wide: Vec<u16> = OsStr::new(text).encode_wide().collect();
        wide.push(0);
        let bytes = wide.len() * 2;
        unsafe {
            OpenClipboard(None).map_err(|err| msg(format!("OpenClipboard: {err}")))?;
            let result = (|| {
                EmptyClipboard().map_err(|err| msg(format!("EmptyClipboard: {err}")))?;
                let hglobal = GlobalAlloc(GMEM_MOVEABLE, bytes)
                    .map_err(|err| msg(format!("GlobalAlloc: {err}")))?;
                let ptr = GlobalLock(hglobal);
                if ptr.is_null() {
                    return Err(msg("GlobalLock failed for clipboard write"));
                }
                std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr as *mut u16, wide.len());
                let _ = GlobalUnlock(hglobal);
                SetClipboardData(CF_UNICODETEXT.0 as u32, Some(HANDLE(hglobal.0)))
                    .map_err(|err| msg(format!("SetClipboardData: {err}")))?;
                // Ownership of hglobal transferred to the clipboard.
                Ok(())
            })();
            let _ = CloseClipboard();
            result
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_long_text_and_marks_truncated() {
        let long = "a".repeat(CLIPBOARD_MAX_CHARS + 10);
        let capped = ClipboardText::capped(long);
        assert!(capped.truncated);
        assert_eq!(capped.text.chars().count(), CLIPBOARD_MAX_CHARS);
    }

    #[test]
    fn short_text_is_not_truncated() {
        let capped = ClipboardText::capped("hi".into());
        assert!(!capped.truncated);
        assert_eq!(capped.text, "hi");
    }
}
