//! Subprocess helpers that never flash a console window on Windows.
//!
//! `agentlink` is built with `windows_subsystem = "windows"`, so it has no
//! console. Spawning a console-subsystem helper (`cmd.exe`, `powershell.exe`,
//! `schtasks.exe`, `ffmpeg`, …) without [`CREATE_NO_WINDOW`] would allocate a
//! visible console that flashes and closes when the helper exits.
//!
//! Do **not** combine [`CREATE_NO_WINDOW`] with `DETACHED_PROCESS` (`0x8`):
//! Windows ignores `CREATE_NO_WINDOW` when that bit is set. Interactive PTY
//! sessions stay on portable-pty / ConPTY and must not use these helpers.

use std::ffi::OsStr;
use std::process::{Command, Stdio};

/// `CREATE_NO_WINDOW` (`0x08000000`).
///
/// Useful when a third-party builder (for example `command-group`) replaces
/// flags already set on a `Command` and the no-window bit must be applied on
/// that builder instead.
pub const WINDOWS_NO_WINDOW: u32 = 0x0800_0000;

/// Build a [`Command`] that never flashes a console window on Windows.
///
/// On other platforms this is a plain `Command::new`.
pub fn hidden(program: impl AsRef<OsStr>) -> Command {
    let mut cmd = Command::new(program);
    hide_console(&mut cmd);
    cmd
}

/// Same as [`hidden`], but fully detached from the parent for long-lived
/// daemons: stdin / stdout / stderr default to null.
///
/// Intentionally does **not** set `DETACHED_PROCESS`. That flag makes Windows
/// ignore [`CREATE_NO_WINDOW`], which reintroduces the console flash for
/// console-subsystem children such as `cmd.exe`.
pub fn detached(program: impl AsRef<OsStr>) -> Command {
    let mut cmd = hidden(program);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    cmd
}

/// Apply [`WINDOWS_NO_WINDOW`] to an existing [`Command`]. No-op off Windows.
pub fn hide_console(cmd: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(WINDOWS_NO_WINDOW);
    }
    #[cfg(not(windows))]
    {
        let _ = cmd;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_no_window_hides_the_console_without_detaching() {
        assert_eq!(WINDOWS_NO_WINDOW, 0x0800_0000);
        // Must stay clear of DETACHED_PROCESS and CREATE_NEW_CONSOLE.
        assert_eq!(WINDOWS_NO_WINDOW & 0x0000_0008, 0);
        assert_eq!(WINDOWS_NO_WINDOW & 0x0000_0010, 0);
        let _ = hidden("agentlink-hide-console-test");
        let _ = detached("agentlink-detach-console-test");
    }
}
