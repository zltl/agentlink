//! How to tear down a Mutter RemoteDesktop session.
//!
//! Kept independent of libpipewire so the close policy can be tested on
//! builders that do not have the PipeWire headers.

/// True when Mutter rejected `Stop` because `Start` was never called.
///
/// Those unstarted session objects stay on the bus even after the creating
/// process exits, unless the creating connection starts and then stops them.
pub(crate) fn mutter_session_not_started(err: &str) -> bool {
    let text = err.to_ascii_lowercase();
    text.contains("session not started") || text.contains("notstarted")
}

/// How to tear down a RemoteDesktop session created by this process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteDesktopClose {
    /// Session was started; `Stop` is enough.
    Stop,
    /// `Stop` failed with "Session not started"; `Start` then `Stop` is the
    /// only way the creating connection can destroy the object.
    StartThenStop,
}

pub(crate) fn remote_desktop_close_action(stop_err: Option<&str>) -> RemoteDesktopClose {
    match stop_err {
        Some(err) if mutter_session_not_started(err) => RemoteDesktopClose::StartThenStop,
        _ => RemoteDesktopClose::Stop,
    }
}

pub(crate) fn capture_needs_reconnect(message: &str) -> bool {
    message.contains("has not delivered a frame yet")
        || message.contains("did not add a PipeWire stream")
        || message.contains("closed the ScreenCast stream")
}

/// Non-empty ScreenCast object path created before a later setup step failed.
/// Both the ScreenCast session and the outer RemoteDesktop session must be
/// stopped so a partial failure does not leave an unstarted ScreenCast object
/// on the GNOME session bus.
pub(crate) fn screencast_path_to_stop_on_error(created_path: Option<&str>) -> Option<&str> {
    created_path.map(str::trim).filter(|path| !path.is_empty())
}

#[cfg(test)]
mod tests {
    use super::{
        capture_needs_reconnect, mutter_session_not_started, remote_desktop_close_action,
        RemoteDesktopClose,
    };

    #[test]
    fn unstarted_stop_error_needs_start_then_stop() {
        assert!(mutter_session_not_started("Session not started"));
        assert!(mutter_session_not_started(
            "org.freedesktop.DBus.Error.Failed: Session not started"
        ));
        assert!(!mutter_session_not_started("Access denied"));
        assert_eq!(
            remote_desktop_close_action(Some("Session not started")),
            RemoteDesktopClose::StartThenStop
        );
        assert_eq!(remote_desktop_close_action(None), RemoteDesktopClose::Stop);
        assert_eq!(
            remote_desktop_close_action(Some("Access denied")),
            RemoteDesktopClose::Stop
        );
    }

    #[test]
    fn stalled_capture_errors_trigger_a_reconnect() {
        assert!(capture_needs_reconnect(
            "Mutter ScreenCast has not delivered a frame yet"
        ));
        assert!(capture_needs_reconnect(
            "PipeWire has not delivered a frame yet"
        ));
        assert!(capture_needs_reconnect(
            "Mutter did not add a PipeWire stream within 10s"
        ));
        assert!(!capture_needs_reconnect("session bus: disconnected"));
    }

    #[test]
    fn partial_screencast_error_identifies_created_session_for_stop() {
        assert_eq!(
            super::screencast_path_to_stop_on_error(Some(
                "/org/gnome/Mutter/ScreenCast/Session/u1"
            )),
            Some("/org/gnome/Mutter/ScreenCast/Session/u1")
        );
        assert_eq!(super::screencast_path_to_stop_on_error(Some("  ")), None);
        assert_eq!(super::screencast_path_to_stop_on_error(None), None);
    }
}
