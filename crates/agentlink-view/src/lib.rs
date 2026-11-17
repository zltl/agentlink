//! Android (and any other native) viewer for the phase-3 desktop stream.
//!
//! This crate is the offerer half of `webrtc_signal`. The node in
//! `agentlink-desktop` stays the answerer: it captures, drops unchanged
//! tiles, encodes H.264, and sends RTP. This side depacketizes to Annex-B
//! so a platform decoder (Android MediaCodec) can play it. Pointer and
//! keyboard stay on the `input` data channel, the same channel the browser
//! uses for congestion feedback.

mod h264;
mod probe_bounds;
mod queue;
mod session;

pub use h264::{
    access_unit_is_idr, addr_scope, clamp_offer, classify_media_path, classify_selected_path,
    classify_selected_path_with, describe_ice_candidates, detect_tailscale_reason, feedback_ratio,
    is_screenshot_fallback, is_tailscale_ula_prefix, media_path_hint, AddrScope,
};
pub use probe_bounds::{parse_bounded_u64, parse_max_decoded};
pub use session::{
    IceFault, LiveClipboard, LiveCursor, LiveFrame, LiveInfo, LiveOptions, LiveStats, Signal,
    TransportSnapshot, Viewer,
};
