//! Real X11 screenshot and XTest pointer roundtrip. Skips unless this is Linux
//! and `DISPLAY` is set, which is how the Linux CI job runs (Xvfb).

#[test]
fn screenshot_is_nonempty_and_pointer_roundtrips() {
    if !cfg!(target_os = "linux")
        || std::env::var_os("DISPLAY")
            .filter(|value| !value.is_empty())
            .is_none()
    {
        eprintln!("skipping X11 roundtrip: needs Linux and DISPLAY");
        return;
    }
    #[cfg(target_os = "linux")]
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {
    use std::time::Duration;

    use agentlink_core::extensions::dispatch_extension;
    use agentlink_core::{PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT};
    use agentlink_desktop::node_bundle;
    use serde_json::json;
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt as _;

    pub fn run() {
        let (extensions, _capture) = node_bundle();
        let shot = dispatch_extension(
            &extensions,
            PHASE2_SCREENSHOT,
            &json!({"format": "png", "target": "screen"}),
        )
        .expect("screenshot");
        let bytes = agentlink_core::util::b64_decode(shot["data_b64"].as_str().unwrap())
            .expect("png base64");
        assert!(bytes.len() > 32, "screenshot was empty");
        assert_eq!(&bytes[..8], b"\x89PNG\r\n\x1a\n");
        assert!(shot["width"].as_u64().unwrap_or(0) > 0);
        assert!(shot["height"].as_u64().unwrap_or(0) > 0);

        let (conn, screen) = x11rb::connect(None).expect("x11");
        let root = conn.setup().roots[screen].root;
        dispatch_extension(
            &extensions,
            PHASE2_INJECT_INPUT,
            &json!({"action": "move", "x": 40, "y": 50}),
        )
        .expect("move");
        std::thread::sleep(Duration::from_millis(50));
        let pointer = conn.query_pointer(root).unwrap().reply().unwrap();
        assert!(
            (i32::from(pointer.root_x) - 40).abs() <= 1,
            "pointer x {}",
            pointer.root_x
        );
        assert!(
            (i32::from(pointer.root_y) - 50).abs() <= 1,
            "pointer y {}",
            pointer.root_y
        );

        dispatch_extension(
            &extensions,
            PHASE2_INJECT_INPUT,
            &json!({"action": "click", "x": 40, "y": 50, "button": "left"}),
        )
        .expect("click");
    }
}
