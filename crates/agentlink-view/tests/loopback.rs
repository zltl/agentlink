//! Offer against the in-memory desktop and read one H.264 IDR back.
//!
//! This is the same `webrtc_signal` contract the phone uses. No display and
//! no Android emulator: the node is `Desktop::mock()`, consent is auto, and
//! the policy is remote control so the input channel is honored.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentlink_core::{NodeExtension, NodePolicy};
use agentlink_desktop::{ConsentMode, Desktop, StreamHandler, StreamSettings};
use agentlink_view::{LiveOptions, Signal, Viewer, access_unit_is_idr};
use serde_json::Value;

struct NodeSignal {
    handler: Arc<StreamHandler>,
}

impl Signal for NodeSignal {
    fn signal(&self, payload: &Value) -> Result<Value, String> {
        self.handler.handle_peer(payload, "android-test")
    }
}

#[test]
fn mock_desktop_delivers_an_idr_and_a_mouse() {
    let audits = Arc::new(Mutex::new(Vec::new()));
    let recorded = audits.clone();
    let handler = Arc::new(StreamHandler::new(Desktop::mock()));
    handler.configure(StreamSettings {
        policy: NodePolicy::remote_control(),
        audit_path: std::env::temp_dir().join("agentlink-view-loopback.log"),
        consent: ConsentMode::Auto,
        on_audit: Some(Arc::new(move |event| {
            recorded
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .push(event.action.clone());
        })),
    });

    let viewer = Viewer::connect(
        Arc::new(NodeSignal { handler }),
        LiveOptions {
            viewer: "android-test".into(),
            ..LiveOptions::default()
        },
    )
    .expect("offer");

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut idr = false;
    while Instant::now() < deadline {
        if viewer.failed() {
            break;
        }
        if let Some(frame) = viewer.poll_frame(Duration::from_millis(200)) {
            if frame.keyframe && access_unit_is_idr(&frame.annex_b) {
                idr = true;
                assert!(frame.width > 0 && frame.height > 0);
                break;
            }
        }
    }
    assert!(
        idr,
        "no Annex-B IDR (failed={}, stats={:?}, audits={:?})",
        viewer.failed(),
        viewer.stats(),
        audits.lock().unwrap_or_else(|err| err.into_inner())
    );

    // Selected ICE pair, not the answer SDP inventory. Addresses on this
    // machine may be loopback or private (bridge/VPN/routed). That is not
    // a public NAT traversal result and not automatically "same LAN".
    let path_deadline = Instant::now() + Duration::from_secs(5);
    let mut snap = viewer.transport();
    while snap.is_none() && Instant::now() < path_deadline {
        std::thread::sleep(Duration::from_millis(50));
        snap = viewer.transport();
    }
    let snap = snap.expect("selected ICE pair was not observed after an IDR");
    eprintln!(
        "agentlink live-path loopback: path={} local={} {} remote={} {} proto={} inventory={} note={}",
        snap.path,
        snap.local_typ,
        snap.local_addr,
        snap.remote_typ,
        snap.remote_addr,
        snap.protocol,
        snap.sdp_inventory,
        snap.note
    );
    assert!(
        matches!(snap.path.as_str(), "loopback" | "private" | "host"),
        "same-host typ host should be loopback, private, or public host, got {snap:?}"
    );
    assert_eq!(viewer.info().path, snap.path);
    assert_ne!(snap.path, "tailscale");
    assert_ne!(snap.path, "cgnat");
    if snap.path == "host" {
        assert!(
            snap.note.to_ascii_lowercase().contains("not a claim of public nat"),
            "public typ host must not be reported as NAT success: {snap:?}"
        );
    }
    // Inventory is log-only. A host inventory is not itself the media path.
    assert!(
        !snap.sdp_inventory.is_empty(),
        "expected the answer SDP inventory to be recorded, got {snap:?}"
    );
    let local_is_loop = snap.local_addr.starts_with("127.")
        || snap.local_addr.starts_with("[::1]")
        || snap.local_addr.starts_with("::1");
    let remote_is_loop = snap.remote_addr.starts_with("127.")
        || snap.remote_addr.starts_with("[::1]")
        || snap.remote_addr.starts_with("::1");
    assert!(
        local_is_loop
            || remote_is_loop
            || snap.note.contains("loopback")
            || snap.note.contains("private")
            || snap.path == "private",
        "expected loopback or private typ host facts, got {snap:?}"
    );
    assert_ne!(
        snap.path, "relay",
        "must not label a host ICE pair as relay"
    );

    let input_deadline = Instant::now() + Duration::from_secs(5);
    let mut sent = false;
    while Instant::now() < input_deadline {
        if viewer.send_control(r#"{"type":"mouse","action":"move","x":12,"y":8}"#) {
            sent = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(40));
    }
    assert!(sent, "input channel did not open");

    let audit_deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < audit_deadline {
        let actions = audits.lock().unwrap_or_else(|err| err.into_inner());
        if actions.iter().any(|action| action == "mouse") {
            break;
        }
        drop(actions);
        std::thread::sleep(Duration::from_millis(40));
    }
    let close_started = Instant::now();
    viewer.close();
    let close_wait = close_started.elapsed();
    assert!(
        close_wait <= Duration::from_secs(3),
        "Viewer::close must finish within the 2s wait plus slack, got {close_wait:?}"
    );
    let stop_deadline = Instant::now() + Duration::from_secs(4);
    while Instant::now() < stop_deadline {
        let actions = audits.lock().unwrap_or_else(|err| err.into_inner());
        if actions.iter().any(|action| action == "stream_stop") {
            break;
        }
        drop(actions);
        std::thread::sleep(Duration::from_millis(40));
    }
    let actions = audits.lock().unwrap_or_else(|err| err.into_inner()).clone();
    assert!(
        actions.iter().any(|action| action == "mouse"),
        "mouse audit missing: {actions:?}"
    );
    assert!(
        actions.iter().any(|action| action == "stream_stop"),
        "stream_stop missing: {actions:?}"
    );
}

struct DenySignal;

impl Signal for DenySignal {
    fn signal(&self, _payload: &Value) -> Result<Value, String> {
        Err("not allowed: missing grant".into())
    }
}

struct ScreenshotFallbackSignal;

impl Signal for ScreenshotFallbackSignal {
    fn signal(&self, _payload: &Value) -> Result<Value, String> {
        Ok(serde_json::json!({
            "status": "unavailable",
            "fallback": "screenshot"
        }))
    }
}

#[test]
fn webrtc_offer_without_a_grant_is_rejected() {
    let err = match Viewer::connect(
        Arc::new(DenySignal),
        LiveOptions {
            viewer: "desktop".into(),
            control: false,
            ..LiveOptions::default()
        },
    ) {
        Ok(_) => panic!("missing grant must not open a live session"),
        Err(err) => err,
    };
    let lower = err.to_ascii_lowercase();
    assert!(
        lower.contains("not allowed") || lower.contains("grant"),
        "unexpected reject: {err}"
    );
}

#[test]
fn screenshot_fallback_does_not_look_like_p2p() {
    let err = match Viewer::connect(
        Arc::new(ScreenshotFallbackSignal),
        LiveOptions {
            viewer: "desktop".into(),
            control: false,
            ..LiveOptions::default()
        },
    ) {
        Ok(_) => panic!("screenshot fallback must not return a Viewer"),
        Err(err) => err,
    };
    assert!(
        err.contains("fallback screenshot") || err.contains("live video is not available"),
        "unexpected fallback: {err}"
    );
}
