//! Desktop capture, input, accessibility, and the phase 3 remote desktop.
//!
//! The node registers [`node_extensions`]: `screenshot`, `inject_input`, and
//! `webrtc_signal`. Screenshots are allowed by `allow_desktop` or remote view.
//! `inject_input` is allowed by `allow_desktop` or `allow_remote_control`.
//! A stream stays behind `allow_remote_view`. Pointer and keyboard from the
//! viewer stay behind `allow_remote_control`.
//!
//! Continuous capture lives in [`capture`]. A parallel audit recorder should
//! pull [`capture::Frame`] values from a [`capture::FrameSource`], or subscribe
//! with [`register_frame_tap`] for frames a live stream already captured.
//! This crate does not define `ScreenRecorder`. Frames share pixels through an `Arc`.

#![allow(clippy::too_many_arguments)]

mod a11y;
mod capture;
mod clipboard;
mod control_indicator;
mod cursor_meta_policy;
mod cursor_negotiate;
mod cursor_shape;
mod encode;
mod error;
mod handlers;
mod input;
mod keys;
mod mock;
mod platform;
mod session;
mod stream;
mod worker;

use std::sync::Arc;

use agentlink_core::NodeExtension;

pub use crate::cursor_meta_policy::{exclude_cap_allowed, CursorAlpha, MUTTER_CURSOR_ALPHA};
pub use crate::cursor_negotiate::{
    bitmap_within_bound, content_fraction_with_pad, encode_pad_content_size,
    negotiate_presentation, scale_hotspot, CursorCaps, CursorPresentation, MAX_CURSOR_BITMAP_EDGE,
};

use crate::a11y::A11yBackend;
use crate::capture::CaptureBackend;
use crate::handlers::{InjectHandler, ScreenshotHandler};
use crate::input::HidBackend;

pub use a11y::{A11yBackend as Accessibility, ElementOp, UiNode};
pub use capture::{
    drive_frames, CaptureBackend as ScreenCapture, CaptureRequest, CaptureTarget,
    CursorCaptureMode, Frame, FrameSource, MonitorInfo, PixelFormat, Rect, StreamMode,
};
pub use clipboard::{
    parse_set_message, set_payload, share_allowed, write_clipboard, ClipboardText,
    ClipboardWatchState, CLIPBOARD_POLL_INTERVAL,
};
pub use control_indicator::{note_control_session, note_inject_input};
pub use error::{DesktopError, Result};
pub use input::{HidBackend as InputInjector, InputAction, MouseButton};
pub use mock::MockDesktop;
pub use session::{display_from_signals, has_display, DisplaySignals};
pub use stream::{
    close_all_streams, close_expired_streams, close_inactive_streams, close_streams_for_jti,
    configure_stream, register_frame_tap, unregister_frame_tap, update_stream_policy, ConsentMode,
    GrantActiveHook, StreamAudit, StreamHandler, StreamSettings, StreamTapEvent, TapId,
};

/// Capture, input, and accessibility bound to one backend.
#[derive(Clone)]
pub struct Desktop {
    pub(crate) capture: Arc<dyn CaptureBackend>,
    pub(crate) hid: Arc<dyn HidBackend>,
    pub(crate) a11y: Arc<dyn A11yBackend>,
}

impl Desktop {
    pub fn mock() -> Arc<Self> {
        let backend = mock::SharedMock::new();
        Arc::new(Self {
            capture: backend.clone(),
            hid: backend.clone(),
            a11y: backend,
        })
    }

    pub fn platform() -> Arc<Self> {
        if matches!(
            std::env::var("AGENTLINK_DESKTOP").ok().as_deref(),
            Some("mock")
        ) {
            return Self::mock();
        }
        platform::open()
    }

    pub fn capture_backend(&self) -> Arc<dyn CaptureBackend> {
        self.capture.clone()
    }
}

/// Handlers for `agentlink node`. Platform setup is lazy and happens on a
/// dedicated thread, so constructing this does not open the display.
pub fn node_extensions() -> Vec<Arc<dyn NodeExtension>> {
    node_bundle().0
}

/// Handlers and the capture backend they share. The audit recorder should
/// call [`CaptureBackend::open_session`] on this backend instead of opening
/// a second screen handle.
pub fn node_bundle() -> (Vec<Arc<dyn NodeExtension>>, Arc<dyn CaptureBackend>) {
    let desktop = Desktop::platform();
    let capture = desktop.capture_backend();
    (bind(desktop), capture)
}

/// Same handlers backed by the in-memory desktop. Integration tests use this
/// so CI does not need a physical display.
pub fn mock_extensions() -> Vec<Arc<dyn NodeExtension>> {
    bind(Desktop::mock())
}

/// Capture half of [`Desktop::platform`], for a recorder that only needs frames.
pub fn platform_capture() -> Result<Arc<dyn CaptureBackend>> {
    Ok(Desktop::platform().capture_backend())
}

/// Capture half of the mock desktop.
pub fn mock_capture() -> Arc<dyn CaptureBackend> {
    Desktop::mock().capture_backend()
}

fn bind(desktop: Arc<Desktop>) -> Vec<Arc<dyn NodeExtension>> {
    vec![
        Arc::new(ScreenshotHandler::new(desktop.clone())),
        Arc::new(InjectHandler::new(desktop.clone())),
        Arc::new(StreamHandler::new(desktop)),
    ]
}

/// Close in-flight official ScreenCast pickers when the client cancels or times out.
pub fn abort_live_portal_pickers() {
    #[cfg(target_os = "linux")]
    crate::platform::portal_window::request_portal_cleanup();
}
