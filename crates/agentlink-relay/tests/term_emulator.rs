//! Former dashboard terminal emulator is retired with browser control (t544).
//!
//! The Node harness that exercised `createTerm` no longer applies: the
//! dashboard must not ship a PTY/term client. Sealed clients use the native
//! alacritty-based Controller instead.

#[test]
fn dashboard_does_not_ship_browser_term_emulator() {
    let html = include_str!("../src/dashboard.html");
    assert!(
        !html.contains("createTerm"),
        "dashboard must not embed a browser terminal emulator"
    );
    assert!(
        !html.contains("/v1/web"),
        "dashboard must not open the retired control websocket"
    );
    assert!(
        html.contains("not available in the browser"),
        "dashboard should still explain the sealed-client boundary"
    );
}
