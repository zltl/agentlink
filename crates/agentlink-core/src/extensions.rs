//! Extension points for later phases.
//!
//! Phase 1 does not capture the screen or open a remote desktop. The relay
//! already forwards [`crate::protocol::Op::Extension`] and binary WebSocket
//! frames are rejected on purpose. A future build registers handlers here and
//! flips the matching permission flag on both the relay policy and the node
//! ceiling.

use std::any::Any;

use serde_json::Value;

/// Phase 2: capture a display. Payload shape is owned by the handler.
pub const PHASE2_SCREENSHOT: &str = "screenshot";

/// Phase 2: inject mouse and keyboard events.
pub const PHASE2_INJECT_INPUT: &str = "inject_input";

/// Phase 3: opaque WebRTC signaling (SDP / ICE) between a human client and a node.
/// Media itself does not go through the JSON relay; this slot is only for
/// signaling. The browser viewer and the Android viewer (`agentlink-view`)
/// speak the same actions: `list_monitors`, `offer`, `ice`, `ice_restart`,
/// `keyframe`, and `close`. Picture bytes are RTP, not these JSON bodies.
pub const PHASE3_WEBRTC_SIGNAL: &str = "webrtc_signal";

/// Which permission flag gates a named extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtensionPerm {
    Desktop,
    DesktopStream,
    /// Not a known extension. Always denied.
    Unknown,
}

pub fn permission_for_extension(name: &str) -> ExtensionPerm {
    match name {
        PHASE2_SCREENSHOT | PHASE2_INJECT_INPUT => ExtensionPerm::Desktop,
        PHASE3_WEBRTC_SIGNAL => ExtensionPerm::DesktopStream,
        _ => ExtensionPerm::Unknown,
    }
}

/// Implemented by a node to handle one future capability.
///
/// Handlers are synchronous. The node runs them on the runtime; a phase-2
/// screenshot implementation can do its own blocking work and return JSON.
pub trait NodeExtension: Send + Sync {
    fn name(&self) -> &'static str;
    fn handle(&self, payload: &Value) -> std::result::Result<Value, String>;

    /// Same as [`handle`](Self::handle), plus the relay client id of the caller.
    ///
    /// The stream handler uses the id as the viewer identity in the audit log.
    fn handle_peer(&self, payload: &Value, _peer: &str) -> std::result::Result<Value, String> {
        self.handle(payload)
    }

    /// Downcast hook so the CLI can configure the stream handler it registered.
    fn as_any(&self) -> Option<&dyn Any> {
        None
    }
}

/// Look up a registered handler. Unknown names fail even if a permission flag
/// was turned on, so the default node stays phase-1 only.
pub fn dispatch_extension(
    extensions: &[std::sync::Arc<dyn NodeExtension>],
    name: &str,
    payload: &Value,
) -> std::result::Result<Value, String> {
    match extensions.iter().find(|ext| ext.name() == name) {
        Some(ext) => ext.handle(payload),
        None => Err(format!(
            "extension '{name}' is not enabled on this node (reserved for a later phase)"
        )),
    }
}

/// [`dispatch_extension`] with the calling client id.
pub fn dispatch_extension_as(
    extensions: &[std::sync::Arc<dyn NodeExtension>],
    name: &str,
    payload: &Value,
    peer: &str,
) -> std::result::Result<Value, String> {
    match extensions.iter().find(|ext| ext.name() == name) {
        Some(ext) => ext.handle_peer(payload, peer),
        None => Err(format!(
            "extension '{name}' is not enabled on this node (reserved for a later phase)"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    struct Echo;

    impl NodeExtension for Echo {
        fn name(&self) -> &'static str {
            PHASE2_SCREENSHOT
        }

        fn handle(&self, payload: &Value) -> std::result::Result<Value, String> {
            Ok(serde_json::json!({"echo": payload}))
        }
    }

    #[test]
    fn missing_handler_is_rejected() {
        let err = dispatch_extension(&[], PHASE2_SCREENSHOT, &Value::Null).unwrap_err();
        assert!(err.contains("not enabled"));
    }

    #[test]
    fn registered_handler_runs() {
        let ext: Arc<dyn NodeExtension> = Arc::new(Echo);
        let out =
            dispatch_extension(&[ext], PHASE2_SCREENSHOT, &serde_json::json!({"n": 1})).unwrap();
        assert_eq!(out["echo"]["n"], 1);
    }
}
