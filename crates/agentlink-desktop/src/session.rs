//! Whether this process is attached to a graphical session.
//!
//! This does not open a capture device and does not prompt for screen
//! recording. Linux looks at `DISPLAY`, `WAYLAND_DISPLAY`, and
//! `XDG_SESSION_TYPE`. Windows session 0 is a service and has no interactive
//! desktop. macOS counts a GUI login (`SECURITYSESSIONID`).

/// Signals used by [`display_from_signals`]. Empty strings are absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisplaySignals {
    pub os: &'static str,
    pub display: Option<String>,
    pub wayland_display: Option<String>,
    pub session_type: Option<String>,
    pub security_session_id: Option<String>,
    /// Windows process session. `Some(0)` is session 0, a non-interactive service.
    pub windows_session: Option<u32>,
}

impl DisplaySignals {
    pub fn current() -> Self {
        Self {
            os: std::env::consts::OS,
            display: env_string("DISPLAY"),
            wayland_display: env_string("WAYLAND_DISPLAY"),
            session_type: env_string("XDG_SESSION_TYPE"),
            security_session_id: env_string("SECURITYSESSIONID"),
            windows_session: current_windows_session(),
        }
    }
}

/// True when `signals` describe a machine the owner can watch.
pub fn display_from_signals(signals: &DisplaySignals) -> bool {
    match signals.os {
        "windows" => matches!(signals.windows_session, Some(id) if id != 0),
        "macos" | "ios" => signals.security_session_id.is_some(),
        "android" => true,
        _ => {
            signals.display.is_some()
                || signals.wayland_display.is_some()
                || matches!(
                    signals.session_type.as_deref(),
                    Some("x11" | "wayland" | "mir")
                )
        }
    }
}

/// Whether this process can see a graphical session.
pub fn has_display() -> bool {
    display_from_signals(&DisplaySignals::current())
}

fn env_string(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(windows)]
fn current_windows_session() -> Option<u32> {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentProcessId() -> u32;
        fn ProcessIdToSessionId(pid: u32, session_id: *mut u32) -> i32;
    }
    unsafe {
        let mut session = 0u32;
        if ProcessIdToSessionId(GetCurrentProcessId(), &mut session) == 0 {
            None
        } else {
            Some(session)
        }
    }
}

#[cfg(not(windows))]
fn current_windows_session() -> Option<u32> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bare(os: &'static str) -> DisplaySignals {
        DisplaySignals {
            os,
            display: None,
            wayland_display: None,
            session_type: None,
            security_session_id: None,
            windows_session: None,
        }
    }

    #[test]
    fn headless_linux_is_not_a_desktop() {
        let mut signals = bare("linux");
        assert!(!display_from_signals(&signals));
        signals.session_type = Some("tty".into());
        assert!(!display_from_signals(&signals));
        signals.display = Some(":0".into());
        assert!(display_from_signals(&signals));
        signals.display = None;
        signals.wayland_display = Some("wayland-0".into());
        assert!(display_from_signals(&signals));
        signals.wayland_display = None;
        signals.session_type = Some("wayland".into());
        assert!(display_from_signals(&signals));
        signals.session_type = Some("x11".into());
        assert!(display_from_signals(&signals));
    }

    #[test]
    fn windows_session_zero_is_headless() {
        let mut signals = bare("windows");
        assert!(!display_from_signals(&signals));
        signals.windows_session = Some(0);
        assert!(!display_from_signals(&signals));
        signals.windows_session = Some(1);
        assert!(display_from_signals(&signals));
    }

    #[test]
    fn macos_needs_a_gui_login_and_android_has_a_screen() {
        let mut mac = bare("macos");
        assert!(!display_from_signals(&mac));
        mac.security_session_id = Some("186a1".into());
        assert!(display_from_signals(&mac));
        assert!(display_from_signals(&bare("android")));
    }
}
