//! Offer against the in-memory desktop and read one H.264 IDR back.
//!
//! This is the same `webrtc_signal` contract the phone uses. No display and
//! no Android emulator: the node is `Desktop::mock()`, consent is auto, and
//! the policy is remote control so the input channel is honored.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentlink_core::{NodeExtension, NodePolicy};
use agentlink_desktop::{ConsentMode, Desktop, StreamHandler, StreamSettings};
use agentlink_view::{access_unit_is_idr, LiveOptions, Signal, Viewer};
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
    viewer.close();
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
