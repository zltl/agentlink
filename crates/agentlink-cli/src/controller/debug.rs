//! Unix-domain debug bus for headless / automated controller tests.
//!
//! JSON lines: one request object per line, one response object per line.
//! Headless mode drives egui via [`egui::Context::run`] with no window or GPU.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use eframe::egui;
use serde_json::{json, Value};

use super::ui::{self, ControllerApp, DebugInbox, EnterOpts, TrayFlags};

const DEFAULT_W: f32 = 1440.0;
const DEFAULT_H: f32 = 900.0;

pub struct DebugOpts {
    pub socket: PathBuf,
    pub mock: bool,
    pub headless: bool,
    pub fail_connect: bool,
    pub connect_timeout_secs: u64,
    pub max_fps: u32,
    pub perf_log: Option<PathBuf>,
}

/// Run the controller with a debug socket. Headless uses a pure egui loop.
pub fn enter_debug(
    config_dir: PathBuf,
    data_dir: PathBuf,
    tray: bool,
    background: bool,
    debug: DebugOpts,
) -> i32 {
    if debug.headless {
        return run_headless(config_dir, data_dir, debug);
    }
    let (inbox, sock_thread) = match spawn_socket_server(&debug.socket) {
        Ok(pair) => (Some(pair.0), Some(pair.1)),
        Err(err) => {
            eprintln!("debug-socket: {err}");
            return 1;
        }
    };
    let code = ui::enter_with_opts(EnterOpts {
        config_dir,
        data_dir,
        tray,
        background,
        mock: debug.mock,
        headless: false,
        fail_connect: debug.fail_connect,
        connect_timeout_secs: debug.connect_timeout_secs,
        max_fps: debug.max_fps,
        open_desktop: None,
        perf_log: debug.perf_log,
        debug_inbox: inbox,
        logical_size: (DEFAULT_W, DEFAULT_H),
    });
    // Detach: eframe may never see a quit, and join would block on accept().
    drop(sock_thread);
    code
}

fn run_headless(config_dir: PathBuf, data_dir: PathBuf, debug: DebugOpts) -> i32 {
    let (inbox, sock_thread) = match spawn_socket_server(&debug.socket) {
        Ok(pair) => pair,
        Err(err) => {
            eprintln!("debug-socket: {err}");
            return 1;
        }
    };

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let shared = Arc::new(super::worker::Shared::new());
    if debug.mock {
        // Mock never dials the relay; keep a drain so send() stays cheap.
        drop(rx);
    } else {
        let worker_shared = Arc::clone(&shared);
        let worker_dir = config_dir.clone();
        std::thread::Builder::new()
            .name("agentlink-controller-net".into())
            .spawn(move || super::worker::run(rx, worker_shared, worker_dir))
            .ok();
        let _ = tx.send(super::worker::Cmd::Bootstrap);
    }
    let flags = TrayFlags {
        open: Arc::new(AtomicBool::new(false)),
        quit: Arc::new(AtomicBool::new(false)),
    };
    let mut app = ControllerApp::new_debug(
        tx,
        shared,
        config_dir,
        data_dir,
        false,
        flags,
        debug.mock,
        (DEFAULT_W, DEFAULT_H),
        debug.fail_connect,
        debug.connect_timeout_secs,
        debug.max_fps,
    );
    app.perf_log = debug.perf_log;

    let ctx = egui::Context::default();
    ui::apply_theme_public(&ctx);

    let mut time = 0.0_f64;
    let mut pending: Vec<(u64, String, Value, Sender<Value>)> = Vec::new();
    let mut input_queue: Vec<egui::Event> = Vec::new();
    let mut quit = false;

    // Warm-up passes so fonts / style settle before the first click.
    for _ in 0..2 {
        run_pass(&ctx, &mut app, &mut time, &[], None);
    }

    while !quit {
        // Pull socket requests without blocking the UI forever.
        let deadline = Instant::now() + Duration::from_millis(50);
        loop {
            match inbox.try_recv() {
                Ok(DebugInbox::Req {
                    id,
                    cmd,
                    args,
                    reply,
                }) => pending.push((id, cmd, args, reply)),
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    quit = true;
                    break;
                }
            }
            if Instant::now() >= deadline {
                break;
            }
        }

        if pending.is_empty() && input_queue.is_empty() {
            // Idle tick keeps mock frames / timers honest.
            run_pass(&ctx, &mut app, &mut time, &[], None);
            thread::sleep(Duration::from_millis(10));
            continue;
        }

        // Process at most one high-level command per outer loop so multi-frame
        // gestures (click) can interleave with egui passes.
        if let Some((id, cmd, args, reply)) = pending.first().cloned() {
            let done = match cmd.as_str() {
                "ping" => {
                    let _ = reply.send(json!({
                        "id": id,
                        "ok": true,
                        "version": crate::version::current(),
                        "mode": mode_label(debug.mock, true),
                        "headless": true,
                        "mock": debug.mock,
                    }));
                    true
                }
                "nav" => {
                    let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("");
                    let node = args
                        .get("node")
                        .and_then(|v| v.as_str())
                        .unwrap_or("box");
                    let mode = args.get("mode").and_then(|v| v.as_str());
                    let err = app.debug_nav(&ctx, to, node, mode);
                    let body = match err {
                        None => json!({"id": id, "ok": true}),
                        Some(reason) => json!({"id": id, "ok": false, "reason": reason}),
                    };
                    let _ = reply.send(body);
                    true
                }
                "fail" => {
                    let what = args
                        .get("what")
                        .or_else(|| args.get("to"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("connect");
                    let err = app.debug_fail(what);
                    let body = match err {
                        None => json!({"id": id, "ok": true}),
                        Some(reason) => json!({"id": id, "ok": false, "reason": reason}),
                    };
                    let _ = reply.send(body);
                    true
                }
                "state" => {
                    // Fresh layout from the last pass; run one more for honesty.
                    run_pass(&ctx, &mut app, &mut time, &[], None);
                    let _ = reply.send(json!({
                        "id": id,
                        "ok": true,
                        "state": app.debug_state(),
                    }));
                    true
                }
                "layout" => {
                    run_pass(&ctx, &mut app, &mut time, &[], None);
                    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let body = write_layout(&app, path, id);
                    let _ = reply.send(body);
                    true
                }
                "screenshot" => {
                    let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
                    let body = match app.debug_screenshot(path) {
                        Ok(()) => json!({"id": id, "ok": true, "path": path}),
                        Err(reason) => json!({"id": id, "ok": false, "reason": reason}),
                    };
                    let _ = reply.send(body);
                    true
                }
                "resize" => {
                    let w = args.get("w").and_then(|v| v.as_f64()).unwrap_or(DEFAULT_W as f64)
                        as f32;
                    let h = args.get("h").and_then(|v| v.as_f64()).unwrap_or(DEFAULT_H as f64)
                        as f32;
                    app.debug_resize(w.max(320.0), h.max(240.0));
                    run_pass(&ctx, &mut app, &mut time, &[], None);
                    let _ = reply.send(json!({"id": id, "ok": true}));
                    true
                }
                "click" => {
                    let x = args.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                    let y = args.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                    let button = args
                        .get("button")
                        .and_then(|v| v.as_str())
                        .unwrap_or("left");
                    let pb = match button {
                        "right" => egui::PointerButton::Secondary,
                        "middle" => egui::PointerButton::Middle,
                        _ => egui::PointerButton::Primary,
                    };
                    // Three-pass gesture so hover then click hits real widgets.
                    run_pass(
                        &ctx,
                        &mut app,
                        &mut time,
                        &[egui::Event::PointerMoved(egui::pos2(x, y))],
                        None,
                    );
                    run_pass(
                        &ctx,
                        &mut app,
                        &mut time,
                        &[egui::Event::PointerButton {
                            pos: egui::pos2(x, y),
                            button: pb,
                            pressed: true,
                            modifiers: egui::Modifiers::default(),
                        }],
                        None,
                    );
                    run_pass(
                        &ctx,
                        &mut app,
                        &mut time,
                        &[egui::Event::PointerButton {
                            pos: egui::pos2(x, y),
                            button: pb,
                            pressed: false,
                            modifiers: egui::Modifiers::default(),
                        }],
                        None,
                    );
                    let _ = reply.send(json!({"id": id, "ok": true}));
                    true
                }
                "move" => {
                    let x = args.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                    let y = args.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                    run_pass(
                        &ctx,
                        &mut app,
                        &mut time,
                        &[egui::Event::PointerMoved(egui::pos2(x, y))],
                        None,
                    );
                    let _ = reply.send(json!({"id": id, "ok": true}));
                    true
                }
                "scroll" => {
                    let x = args.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                    let y = args.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                    let dx = args.get("dx").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                    let dy = args.get("dy").and_then(|v| v.as_f64()).unwrap_or(0.0) as f32;
                    run_pass(
                        &ctx,
                        &mut app,
                        &mut time,
                        &[
                            egui::Event::PointerMoved(egui::pos2(x, y)),
                            egui::Event::MouseWheel {
                                unit: egui::MouseWheelUnit::Point,
                                delta: egui::vec2(dx, dy),
                                modifiers: egui::Modifiers::default(),
                            },
                        ],
                        None,
                    );
                    let _ = reply.send(json!({"id": id, "ok": true}));
                    true
                }
                "key" => {
                    let key = args.get("key").and_then(|v| v.as_str()).unwrap_or("");
                    let down = args.get("down").and_then(|v| v.as_bool()).unwrap_or(true);
                    let events = synth_keys(key, down);
                    run_pass(&ctx, &mut app, &mut time, &events, None);
                    let _ = reply.send(json!({"id": id, "ok": true}));
                    true
                }
                "quit" => {
                    let _ = reply.send(json!({"id": id, "ok": true}));
                    quit = true;
                    true
                }
                other => {
                    let _ = reply.send(json!({
                        "id": id,
                        "ok": false,
                        "reason": format!("unknown cmd '{other}'"),
                    }));
                    true
                }
            };
            if done {
                pending.remove(0);
            }
            let _ = (cmd, args, id);
        }

        if !input_queue.is_empty() {
            let events = std::mem::take(&mut input_queue);
            run_pass(&ctx, &mut app, &mut time, &events, None);
        }
    }

    // Join after quit so the socket thread can flush the final reply before
    // process teardown (avoids empty-EOF flakes under parallel test load).
    let _ = sock_thread.join();
    let _ = std::fs::remove_file(&debug.socket);
    let _ = inbox;
    0
}

fn write_layout(app: &ControllerApp, path: &str, id: u64) -> Value {
    if path.is_empty() {
        return json!({"id": id, "ok": false, "reason": "missing path"});
    }
    let layout = app.debug_layout_json();
    match std::fs::write(path, layout.to_string()) {
        Ok(()) => json!({"id": id, "ok": true, "path": path}),
        Err(err) => json!({"id": id, "ok": false, "reason": err.to_string()}),
    }
}

fn run_pass(
    ctx: &egui::Context,
    app: &mut ControllerApp,
    time: &mut f64,
    events: &[egui::Event],
    _extra: Option<()>,
) {
    let (w, h) = app.debug_window_size();
    let mut raw = egui::RawInput {
        screen_rect: Some(egui::Rect::from_min_size(
            egui::pos2(0.0, 0.0),
            egui::vec2(w, h),
        )),
        time: Some(*time),
        predicted_dt: 1.0 / 60.0,
        focused: true,
        ..Default::default()
    };
    raw.events.extend(events.iter().cloned());
    *time += 1.0 / 60.0;
    let _ = ctx.run(raw, |ctx| {
        app.ui_frame(ctx);
    });
}

fn mode_label(mock: bool, headless: bool) -> &'static str {
    match (mock, headless) {
        (true, true) => "mock-headless",
        (true, false) => "mock",
        (false, true) => "headless",
        (false, false) => "live",
    }
}

fn synth_keys(spec: &str, down: bool) -> Vec<egui::Event> {
    let mut events = Vec::new();
    let mut modifiers = egui::Modifiers::default();
    for part in spec.split('+') {
        let part = part.trim().to_ascii_lowercase();
        match part.as_str() {
            "ctrl" | "control" => modifiers.ctrl = true,
            "alt" => modifiers.alt = true,
            "shift" => modifiers.shift = true,
            "meta" | "cmd" | "super" => {
                modifiers.command = true;
                modifiers.mac_cmd = true;
            }
            "del" | "delete" => events.push(egui::Event::Key {
                key: egui::Key::Delete,
                physical_key: Some(egui::Key::Delete),
                pressed: down,
                repeat: false,
                modifiers,
            }),
            "esc" | "escape" => events.push(egui::Event::Key {
                key: egui::Key::Escape,
                physical_key: Some(egui::Key::Escape),
                pressed: down,
                repeat: false,
                modifiers,
            }),
            "f11" => events.push(egui::Event::Key {
                key: egui::Key::F11,
                physical_key: Some(egui::Key::F11),
                pressed: down,
                repeat: false,
                modifiers,
            }),
            other if other.len() == 1 => {
                if let Some(ch) = other.chars().next() {
                    if let Some(key) = egui::Key::from_name(&ch.to_ascii_uppercase().to_string()) {
                        events.push(egui::Event::Key {
                            key,
                            physical_key: Some(key),
                            pressed: down,
                            repeat: false,
                            modifiers,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    events
}

fn spawn_socket_server(path: &Path) -> Result<(Receiver<DebugInbox>, JoinHandle<()>), String> {
    let _ = std::fs::remove_file(path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let listener = UnixListener::bind(path).map_err(|e| e.to_string())?;
    listener
        .set_nonblocking(false)
        .map_err(|e| e.to_string())?;
    let (tx, rx) = mpsc::channel();
    let path_owned = path.to_path_buf();
    let handle = thread::Builder::new()
        .name("agentlink-debug-sock".into())
        .spawn(move || {
            // Accept one client at a time; tests use a single connection.
            while let Ok((stream, _)) = listener.accept() {
                if handle_client(stream, &tx) {
                    break;
                }
            }
            let _ = std::fs::remove_file(path_owned);
        })
        .map_err(|e| e.to_string())?;
    Ok((rx, handle))
}

/// Returns true when the UI should quit (client sent quit, or channel died).
fn handle_client(stream: UnixStream, tx: &Sender<DebugInbox>) -> bool {
    let mut reader = BufReader::new(stream.try_clone().expect("clone unix stream"));
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        match reader.read_line(&mut line) {
            Ok(0) => return false,
            Ok(_) => {}
            Err(_) => return false,
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(err) => {
                let _ = writeln!(
                    writer,
                    "{}",
                    json!({"id": 0, "ok": false, "reason": err.to_string()})
                );
                continue;
            }
        };
        let id = parsed.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
        let cmd = parsed
            .get("cmd")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let args = parsed
            .get("args")
            .cloned()
            .unwrap_or_else(|| parsed.clone());
        let (reply_tx, reply_rx) = mpsc::channel();
        if tx
            .send(DebugInbox::Req {
                id,
                cmd: cmd.clone(),
                args,
                reply: reply_tx,
            })
            .is_err()
        {
            return true;
        }
        match reply_rx.recv_timeout(Duration::from_secs(30)) {
            Ok(resp) => {
                if writeln!(writer, "{resp}").is_err() {
                    return false;
                }
                let _ = writer.flush();
                if cmd == "quit" {
                    return true;
                }
            }
            Err(_) => {
                let _ = writeln!(
                    writer,
                    "{}",
                    json!({"id": id, "ok": false, "reason": "timeout"})
                );
            }
        }
    }
}

/// Process one debug request from the eframe update path (non-headless).
pub fn pump_eframe_debug(app: &mut ControllerApp, ctx: &egui::Context, inbox: &Receiver<DebugInbox>) {
    let Ok(DebugInbox::Req {
        id,
        cmd,
        args,
        reply,
    }) = inbox.try_recv()
    else {
        return;
    };
    let body = match cmd.as_str() {
        "ping" => json!({
            "id": id,
            "ok": true,
            "version": crate::version::current(),
            "mode": mode_label(app.debug_is_mock(), false),
            "headless": false,
            "mock": app.debug_is_mock(),
        }),
        "nav" => {
            let to = args.get("to").and_then(|v| v.as_str()).unwrap_or("");
            let node = args
                .get("node")
                .and_then(|v| v.as_str())
                .unwrap_or("box");
            let mode = args.get("mode").and_then(|v| v.as_str());
            match app.debug_nav(ctx, to, node, mode) {
                None => json!({"id": id, "ok": true}),
                Some(reason) => json!({"id": id, "ok": false, "reason": reason}),
            }
        }
        "fail" => {
            let what = args
                .get("what")
                .or_else(|| args.get("to"))
                .and_then(|v| v.as_str())
                .unwrap_or("connect");
            match app.debug_fail(what) {
                None => json!({"id": id, "ok": true}),
                Some(reason) => json!({"id": id, "ok": false, "reason": reason}),
            }
        }
        "state" => json!({"id": id, "ok": true, "state": app.debug_state()}),
        "layout" => {
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            write_layout(app, path, id)
        }
        "screenshot" => {
            let path = args.get("path").and_then(|v| v.as_str()).unwrap_or("");
            match app.debug_screenshot(path) {
                Ok(()) => json!({"id": id, "ok": true, "path": path}),
                Err(reason) => json!({"id": id, "ok": false, "reason": reason}),
            }
        }
        "resize" => {
            let w = args.get("w").and_then(|v| v.as_f64()).unwrap_or(DEFAULT_W as f64) as f32;
            let h = args.get("h").and_then(|v| v.as_f64()).unwrap_or(DEFAULT_H as f64) as f32;
            app.debug_resize(w.max(320.0), h.max(240.0));
            ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(w, h)));
            json!({"id": id, "ok": true})
        }
        "click" | "move" | "scroll" | "key" => {
            // Non-headless path: inject into egui input for the next frames via
            // events stored on the app; applied at the start of ui_frame.
            app.debug_queue_raw(cmd.as_str(), &args);
            json!({"id": id, "ok": true})
        }
        "quit" => {
            app.debug_request_quit();
            json!({"id": id, "ok": true})
        }
        other => json!({
            "id": id,
            "ok": false,
            "reason": format!("unknown cmd '{other}'"),
        }),
    };
    let _ = reply.send(body);
}
