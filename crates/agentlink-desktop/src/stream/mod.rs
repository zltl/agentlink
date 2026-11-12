//! Phase 3 remote desktop: damage, encode, WebRTC, and the frame tap.
//!
//! A `ScreenRecorder` in another crate should keep using [`crate::FrameSource`].
//! Streaming sessions also publish [`StreamTapEvent`] values so an audit
//! recorder can reuse the same pixels without opening a second screen handle.

mod audio;
#[allow(dead_code)]
mod bench;
mod consent;
mod damage;
mod encode;
mod ffmpeg;
mod handler;
mod hw;
mod pipeline;
mod tap;
mod webrtc_session;

#[cfg(target_os = "windows")]
mod media_foundation;
#[cfg(pipewire_headers)]
pub(crate) mod pipewire;
#[cfg(target_os = "macos")]
mod videotoolbox;

pub use consent::ConsentMode;
pub use handler::{
    close_expired_streams, close_streams_for_jti, configure_stream, update_stream_policy, GrantActiveHook, StreamAudit,
    StreamHandler, StreamSettings,
};
pub use tap::{register_frame_tap, unregister_frame_tap, StreamTapEvent, TapId};

pub(crate) use handler::StreamShared;
