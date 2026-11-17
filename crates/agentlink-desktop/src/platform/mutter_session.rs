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
}
