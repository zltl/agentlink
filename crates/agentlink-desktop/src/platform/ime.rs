//! Temporary per-call IME bypass for literal keysym typing.
//!
//! Remote `NotifyKeyboardKeysym` / XTest injection still goes through the
//! session input method. With a Chinese (or other composing) IME active, ASCII
//! markers are mangled into candidates. This module switches to a Latin /
//! passthrough engine for the duration of one `type` call and restores the
//! previous engine afterward. Prefer AT-SPI `InsertText` when available; this
//! is the recoverable fallback when keysyms must be used.

use std::process::Command;

use agentlink_core::process::hidden;

/// Holds the previous IME engine and restores it on drop.
pub struct ImeGuard {
    backend: Backend,
    previous: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Backend {
    IBus,
    Fcitx5,
}

impl ImeGuard {
    /// Switch to a Latin/passthrough engine when a composing IME is active.
    /// Returns `None` when no supported IME is running or the session is
    /// already on a passthrough engine (nothing to restore).
    pub fn engage() -> Option<Self> {
        if let Some(guard) = engage_ibus() {
            return Some(guard);
        }
        engage_fcitx5()
    }
}

impl Drop for ImeGuard {
    fn drop(&mut self) {
        let _ = match self.backend {
            Backend::IBus => set_ibus(&self.previous),
            Backend::Fcitx5 => set_fcitx5(&self.previous),
        };
    }
}

fn engage_ibus() -> Option<ImeGuard> {
    let previous = current_ibus()?;
    if previous.is_empty() || is_passthrough_engine(&previous) {
        return None;
    }
    let latin = ibus_latin_candidate().unwrap_or_else(|| "xkb:us::eng".into());
    set_ibus(&latin).ok()?;
    Some(ImeGuard {
        backend: Backend::IBus,
        previous,
    })
}

fn engage_fcitx5() -> Option<ImeGuard> {
    let previous = current_fcitx5()?;
    if previous.is_empty() || is_passthrough_engine(&previous) {
        return None;
    }
    let latin = fcitx5_latin_candidate().unwrap_or_else(|| "keyboard-us".into());
    set_fcitx5(&latin).ok()?;
    Some(ImeGuard {
        backend: Backend::Fcitx5,
        previous,
    })
}

fn current_ibus() -> Option<String> {
    let output = hidden("ibus")
        .args(["engine"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn set_ibus(engine: &str) -> Result<(), ()> {
    let status = hidden("ibus")
        .args(["engine", engine])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| ())?;
    if status.success() {
        Ok(())
    } else {
        Err(())
    }
}

fn ibus_latin_candidate() -> Option<String> {
    let output = Command::new("ibus")
        .args(["list-engine"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    pick_ibus_latin(&text).map(str::to_string)
}

fn current_fcitx5() -> Option<String> {
    let output = hidden("fcitx5-remote")
        .args(["-n"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn set_fcitx5(engine: &str) -> Result<(), ()> {
    let status = hidden("fcitx5-remote")
        .args(["-s", engine])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|_| ())?;
    if status.success() {
        Ok(())
    } else {
        Err(())
    }
}

fn fcitx5_latin_candidate() -> Option<String> {
    // fcitx5-remote -n lists the current IM only; prefer the common US keyboard
    // addon name. Callers fall back to keyboard-us when this returns None.
    Some("keyboard-us".into())
}

/// True when the engine already commits Latin/keysyms without composition.
pub fn is_passthrough_engine(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return true;
    }
    lower.starts_with("xkb:")
        || lower.starts_with("keyboard-")
        || lower.starts_with("keyboard:")
        || lower == "eng"
        || lower == "us"
        || lower.contains("xkb:us")
        || lower.ends_with("::eng")
}

/// Prefer a US English XKB engine from `ibus list-engine` output.
pub fn pick_ibus_latin(list_engine_output: &str) -> Option<&str> {
    let mut fallback = None;
    for line in list_engine_output.lines() {
        // Lines look like: `  xkb:us::eng - English (US)`
        let name = line.split_whitespace().next().unwrap_or("").trim();
        if name.is_empty() || name.ends_with(':') {
            continue;
        }
        let lower = name.to_ascii_lowercase();
        if lower == "xkb:us::eng" || lower == "xkb:us::" {
            return Some(name);
        }
        if fallback.is_none() && (lower.starts_with("xkb:us") || lower.starts_with("xkb:")) {
            fallback = Some(name);
        }
    }
    fallback
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passthrough_engines_are_detected() {
        for name in [
            "xkb:us::eng",
            "xkb:us::",
            "keyboard-us",
            "keyboard:us",
            "us",
            "eng",
        ] {
            assert!(is_passthrough_engine(name), "{name}");
        }
        for name in ["libpinyin", "rime", "mozc-jp", "hangul", "table:wubi"] {
            assert!(!is_passthrough_engine(name), "{name}");
        }
    }

    #[test]
    fn picks_us_engine_from_ibus_list() {
        let listing = "\
language: English
  xkb:us::eng - English (US)
language: Chinese
  libpinyin - Intelligent Pinyin
";
        assert_eq!(pick_ibus_latin(listing), Some("xkb:us::eng"));
    }
}
