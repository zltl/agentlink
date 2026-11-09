//! Headless controller debug-bus regression tests (unix only).

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tempfile::TempDir;

/// Serialize controller spawns. Parallel children racing the ~large debug
/// binary under memory pressure produced empty-EOF replies; one live
/// controller at a time keeps the suite deterministic without forcing
/// `--test-threads=1` on the whole crate.
fn controller_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
}

struct DebugSession {
    child: Child,
    stream: UnixStream,
    reader: BufReader<UnixStream>,
    _tmpdir: TempDir,
    next_id: u64,
    stderr_path: PathBuf,
    _guard: std::sync::MutexGuard<'static, ()>,
}

impl DebugSession {
    fn start() -> Self {
        Self::start_with(&[])
    }

    fn start_with(extra: &[&str]) -> Self {
        let guard = controller_lock();
        let tmpdir = TempDir::new().expect("tmpdir");
        let sock = tmpdir.path().join("al-debug.sock");
        let config_dir = tmpdir.path().join("config");
        let data_dir = tmpdir.path().join("data");
        let stderr_path = tmpdir.path().join("stderr.log");
        std::fs::create_dir_all(&config_dir).expect("config dir");
        std::fs::create_dir_all(&data_dir).expect("data dir");
        let bin = env!("CARGO_BIN_EXE_agentlink");
        let mut args = vec![
            "--config-dir",
            config_dir.to_str().unwrap(),
            "controller",
            "--mock",
            "--headless",
            "--debug-socket",
            sock.to_str().unwrap(),
            "--data-dir",
            data_dir.to_str().unwrap(),
        ];
        args.extend_from_slice(extra);
        let stderr_file = std::fs::File::create(&stderr_path).expect("stderr file");
        let child = Command::new(bin)
            .args(&args)
            .stdout(Stdio::null())
            .stderr(Stdio::from(stderr_file))
            .spawn()
            .expect("spawn controller");

        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match UnixStream::connect(&sock) {
                Ok(s) => break s,
                Err(err) => {
                    if Instant::now() >= deadline {
                        let err_tail = std::fs::read_to_string(&stderr_path).unwrap_or_default();
                        panic!("connect debug socket: {err}\nstderr:\n{err_tail}");
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        let mut session = Self {
            child,
            stream,
            reader,
            _tmpdir: tmpdir,
            next_id: 1,
            stderr_path,
            _guard: guard,
        };
        let pong = session.req("ping", json!({}));
        assert_eq!(pong["ok"], true, "{pong}");
        session
    }

    fn req(&mut self, cmd: &str, mut args: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        if !args.is_object() {
            args = json!({});
        }
        let obj = args.as_object_mut().unwrap();
        obj.insert("id".into(), json!(id));
        obj.insert("cmd".into(), json!(cmd));
        let line = format!("{args}\n");
        self.stream.write_all(line.as_bytes()).expect("write");
        self.stream.flush().ok();
        let mut resp = String::new();
        match self.reader.read_line(&mut resp) {
            Ok(0) => {
                let status = self.child.try_wait().ok().flatten();
                let err_tail = std::fs::read_to_string(&self.stderr_path).unwrap_or_default();
                panic!(
                    "EOF from controller on cmd={cmd} id={id} status={status:?}\nstderr:\n{err_tail}"
                );
            }
            Ok(_) => {}
            Err(err) => {
                let status = self.child.try_wait().ok().flatten();
                let err_tail = std::fs::read_to_string(&self.stderr_path).unwrap_or_default();
                panic!(
                    "read response failed on cmd={cmd} id={id}: {err}; status={status:?}\nstderr:\n{err_tail}"
                );
            }
        }
        serde_json::from_str(resp.trim()).unwrap_or_else(|e| panic!("bad json `{resp}`: {e}"))
    }

    fn state(&mut self) -> Value {
        let resp = self.req("state", json!({}));
        assert_eq!(resp["ok"], true, "{resp}");
        resp["state"].clone()
    }

    fn quit(mut self) {
        let resp = self.req("quit", json!({}));
        assert_eq!(resp["ok"], true, "{resp}");
        let status = wait_exit(&mut self.child, Duration::from_secs(5));
        assert!(status.success(), "exit status {status}");
    }
}

impl Drop for DebugSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn wait_exit(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            return child.wait().expect("wait after kill");
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn rects_overlap(a: &[f64], b: &[f64]) -> bool {
    // [x, y, w, h]
    let ax2 = a[0] + a[2];
    let ay2 = a[1] + a[3];
    let bx2 = b[0] + b[2];
    let by2 = b[1] + b[3];
    a[0] < bx2 && ax2 > b[0] && a[1] < by2 && ay2 > b[1]
}

fn as_rect(v: &Value) -> Vec<f64> {
    v.as_array()
        .expect("rect array")
        .iter()
        .map(|n| n.as_f64().unwrap())
        .collect()
}

fn item_center(state: &Value, id: &str) -> (f64, f64) {
    let items = state["toolbar"]["items"].as_array().expect("items");
    let item = items
        .iter()
        .find(|it| it["id"] == id)
        .unwrap_or_else(|| panic!("missing toolbar item {id} in {items:?}"));
    let r = as_rect(&item["rect"]);
    (r[0] + r[2] / 2.0, r[1] + r[3] / 2.0)
}

fn area(rect: &[f64]) -> f64 {
    rect[2].max(0.0) * rect[3].max(0.0)
}

fn assert_toolbar_ok(state: &Value) {
    let win_w = state["window"]["w"].as_f64().unwrap();
    let win_h = state["window"]["h"].as_f64().unwrap();
    let items = state["toolbar"]["items"].as_array().unwrap();
    assert!(!items.is_empty(), "toolbar items empty");
    let rects: Vec<Vec<f64>> = items.iter().map(|it| as_rect(&it["rect"])).collect();
    for (i, a) in rects.iter().enumerate() {
        assert!(a[2] > 0.0 && a[3] > 0.0, "item {i} zero-size {a:?}");
        assert!(a[0] >= -1.0 && a[1] >= -1.0, "item {i} origin {a:?}");
        assert!(
            a[0] + a[2] <= win_w + 1.0 && a[1] + a[3] <= win_h + 1.0,
            "item {i} outside window {a:?} win={win_w}x{win_h}"
        );
        for (j, b) in rects.iter().enumerate() {
            if i >= j {
                continue;
            }
            assert!(
                !rects_overlap(a, b),
                "toolbar items {i} and {j} overlap: {a:?} vs {b:?}"
            );
        }
    }
}

#[test]
fn controller_debug_bus_session_layout_and_actions() {
    let mut s = DebugSession::start();

    let nav = s.req("nav", json!({"to": "session", "node": "box"}));
    assert_eq!(nav["ok"], true, "{nav}");

    let state = s.state();
    assert_eq!(state["screen"], "session", "{state}");
    let height = state["toolbar"]["height"].as_f64().unwrap();
    assert!(
        (24.0..40.0).contains(&height),
        "toolbar.height={height}"
    );
    assert_toolbar_ok(&state);

    let before = s.state();
    let image_before = as_rect(&before["viewport"]["image_rect"]);
    let area_before = area(&image_before);

    let resize = s.req("resize", json!({"w": 1920, "h": 1080}));
    assert_eq!(resize["ok"], true, "{resize}");
    let after = s.state();
    assert_eq!(after["window"]["w"], 1920.0);
    assert_eq!(after["window"]["h"], 1080.0);
    let image_after = as_rect(&after["viewport"]["image_rect"]);
    assert!(
        area(&image_after) > area_before,
        "image_rect should grow: before={image_before:?} after={image_after:?}"
    );
    let content = as_rect(&after["viewport"]["content_rect"]);
    assert!(content[2] > 0.0 && content[3] > 0.0, "{content:?}");
    // Mock frames are 960x480 → 2:1 aspect.
    let aspect = content[2] / content[3];
    assert!(
        (aspect - 2.0).abs() < 0.05 || (content[2] - content[3] * 2.0).abs() <= 1.0,
        "content aspect not 2:1: {content:?} aspect={aspect}"
    );
    assert!(
        content[0] + content[2] <= 1920.0 + 1.0 && content[1] + content[3] <= 1080.0 + 1.0,
        "content exceeds window: {content:?}"
    );

    // Fit: leave fit mode then re-enter.
    let (x, y) = item_center(&after, "fit");
    // First force free via a 1:1-equivalent: click fit should still observe fit=="fit".
    let _ = s.req("click", json!({"x": x, "y": y, "button": "left"}));
    let fitted = s.state();
    assert_eq!(fitted["viewport"]["fit"], "fit", "{fitted}");

    let before_fs = fitted["fullscreen"].as_bool().unwrap_or(false);
    let (fx, fy) = item_center(&fitted, "fullscreen");
    let _ = s.req("click", json!({"x": fx, "y": fy, "button": "left"}));
    let after_fs = s.state();
    assert_ne!(
        after_fs["fullscreen"].as_bool().unwrap_or(before_fs),
        before_fs,
        "fullscreen should toggle: before={before_fs} after={after_fs}"
    );

    let before_kb = after_fs["keyboard_captured"].as_bool().unwrap();
    let (kx, ky) = item_center(&after_fs, "keyboard");
    let _ = s.req("click", json!({"x": kx, "y": ky, "button": "left"}));
    let after_kb = s.state();
    assert_ne!(
        after_kb["keyboard_captured"].as_bool().unwrap(),
        before_kb,
        "keyboard_captured should flip"
    );

    let layout_path: PathBuf = s._tmpdir.path().join("layout.json");
    let layout = s.req(
        "layout",
        json!({"path": layout_path.to_string_lossy()}),
    );
    assert_eq!(layout["ok"], true, "{layout}");
    let raw = std::fs::read_to_string(&layout_path).expect("read layout");
    let parsed: Value = serde_json::from_str(&raw).expect("layout json");
    assert!(
        parsed["toolbar"]["items"].as_array().is_some_and(|a| !a.is_empty()),
        "layout missing toolbar.items: {parsed}"
    );

    s.quit();
}

#[test]
fn controller_debug_title_and_mode() {
    let mut s = DebugSession::start();
    let nav = s.req(
        "nav",
        json!({"to": "session", "node": "box", "mode": "control"}),
    );
    assert_eq!(nav["ok"], true, "{nav}");
    let state = s.state();
    let title = state["title"].as_str().unwrap_or("");
    assert!(title.contains("box"), "title missing node: {title}");
    assert!(
        title.contains('×') || title.contains('x'),
        "title missing resolution: {title}"
    );
    assert_eq!(state["connection"]["mode"], "control", "{state}");

    let view = s.req(
        "nav",
        json!({"to": "session", "node": "box", "mode": "view"}),
    );
    assert_eq!(view["ok"], true, "{view}");
    let viewed = s.state();
    assert_eq!(viewed["connection"]["mode"], "view", "{viewed}");
    s.quit();
}

#[test]
fn controller_debug_resize_960_toolbar_fits() {
    let mut s = DebugSession::start();
    let nav = s.req("nav", json!({"to": "session", "node": "box"}));
    assert_eq!(nav["ok"], true, "{nav}");
    let resize = s.req("resize", json!({"w": 960, "h": 600}));
    assert_eq!(resize["ok"], true, "{resize}");
    let state = s.state();
    assert_eq!(state["window"]["w"], 960.0);
    assert_eq!(state["window"]["h"], 600.0);
    assert_toolbar_ok(&state);
    s.quit();
}

#[test]
fn controller_debug_stats_popover_toggle() {
    let mut s = DebugSession::start();
    let nav = s.req("nav", json!({"to": "session", "node": "box"}));
    assert_eq!(nav["ok"], true, "{nav}");
    let state = s.state();
    assert_eq!(state["stats_open"], false, "{state}");
    let (x, y) = item_center(&state, "stats");
    let _ = s.req("click", json!({"x": x, "y": y, "button": "left"}));
    let open = s.state();
    assert_eq!(open["stats_open"], true, "{open}");
    let (x2, y2) = item_center(&open, "stats");
    let _ = s.req("click", json!({"x": x2, "y": y2, "button": "left"}));
    let closed = s.state();
    assert_eq!(closed["stats_open"], false, "{closed}");
    s.quit();
}

#[test]
fn controller_debug_fail_connect_sets_error() {
    let mut s = DebugSession::start();
    let nav = s.req("nav", json!({"to": "session", "node": "box"}));
    assert_eq!(nav["ok"], true, "{nav}");
    let fail = s.req("fail", json!({"what": "connect"}));
    assert_eq!(fail["ok"], true, "{fail}");
    let state = s.state();
    assert_eq!(state["connection"]["state"], "failed", "{state}");
    let err = state["connection"]["error"].as_str().unwrap_or("");
    assert!(!err.is_empty(), "expected non-empty error: {state}");
    s.quit();
}

#[test]
fn controller_debug_fail_connect_flag() {
    let mut s = DebugSession::start_with(&["--fail-connect", "--connect-timeout-secs", "1"]);
    let nav = s.req("nav", json!({"to": "session", "node": "box"}));
    assert_eq!(nav["ok"], true, "{nav}");
    // Wait for the session-layer timeout to fire inside the headless loop.
    let deadline = Instant::now() + Duration::from_secs(5);
    let last = loop {
        // Advance the UI clock with a state poll.
        let resp = s.req("state", json!({}));
        assert_eq!(resp["ok"], true, "state while waiting for timeout: {resp}");
        let state = resp["state"].clone();
        if state["connection"]["state"] == "failed" {
            break state;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for failed state: {state}"
        );
        std::thread::sleep(Duration::from_millis(100));
    };
    let err = last["connection"]["error"].as_str().unwrap_or("");
    assert!(!err.is_empty(), "expected timeout error: {last}");
    assert!(
        err.to_ascii_lowercase().contains("timed out")
            || err.to_ascii_lowercase().contains("timeout"),
        "unexpected error text: {err}"
    );
    s.quit();
}
