//! In-memory desktop used by tests and by `AGENTLINK_DESKTOP=mock`.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::a11y::{limit_tree, A11yBackend, ElementOp, UiNode};
use crate::capture::{
    check_pixels, frame_interval, scale_frame, unix_ms, wait_until_due, CaptureBackend,
    CaptureRequest, CaptureTarget, Frame, FrameSource, MonitorInfo, Rect, StreamMode,
};
use crate::error::{msg, Result};
use crate::input::{perform, HidBackend, InputAction, Pointer};

const WIDTH: u32 = 960;
const HEIGHT: u32 = 480;

pub struct MockDesktop {
    events: Mutex<Vec<String>>,
    tree: Mutex<UiNode>,
    tick: Mutex<u32>,
}

impl MockDesktop {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            tree: Mutex::new(demo_tree()),
            tick: Mutex::new(0),
        }
    }

    /// One BGRA frame at `(width, height)` for controller `--mock` / tests.
    pub fn frames(width: u32, height: u32) -> Result<Frame> {
        Self::new().render(0, 0, width, height)
    }

    pub fn events(&self) -> Vec<String> {
        self.events
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone()
    }

    fn record(&self, event: String) {
        self.events
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(event);
    }

    fn render(&self, origin_x: i32, origin_y: i32, width: u32, height: u32) -> Result<Frame> {
        check_pixels(width, height)?;
        let mut tick = self.tick.lock().unwrap_or_else(|err| err.into_inner());
        *tick = tick.wrapping_add(1);
        let stamp = *tick;
        drop(tick);
        let mut raw = vec![0u8; width as usize * height as usize * 4];
        for y in 0..height as i32 {
            for x in 0..width as i32 {
                let vx = origin_x + x;
                let vy = origin_y + y;
                let index = ((y as usize) * width as usize + x as usize) * 4;
                raw[index] = (vx as u8).wrapping_mul(3);
                raw[index + 1] = vy as u8;
                raw[index + 2] = vx.wrapping_add(vy) as u8;
                raw[index + 3] = 255;
            }
        }
        raw[0] = stamp as u8;
        Frame::from_bgra(width, height, width * 4, &raw, "mock")
    }

    fn grab(&self, target: &CaptureTarget) -> Result<Frame> {
        match target {
            CaptureTarget::FullScreen => self.render(0, 0, WIDTH, HEIGHT),
            CaptureTarget::Monitor(index) => {
                let monitor = monitor(*index)?;
                self.render(monitor.x, monitor.y, monitor.width, monitor.height)
            }
            CaptureTarget::Region(rect) => {
                if rect.x < 0
                    || rect.y < 0
                    || rect.x as u32 + rect.width > WIDTH
                    || rect.y as u32 + rect.height > HEIGHT
                {
                    return Err(msg("region is outside the mock desktop"));
                }
                self.render(rect.x, rect.y, rect.width, rect.height)
            }
            CaptureTarget::Window(id) => {
                let rect = window_rect(id)?;
                self.render(rect.x, rect.y, rect.width, rect.height)
            }
        }
    }
}

impl Default for MockDesktop {
    fn default() -> Self {
        Self::new()
    }
}

impl CaptureBackend for MockDesktop {
    fn backend_name(&self) -> &str {
        "mock"
    }

    fn list_monitors(&self) -> Result<Vec<MonitorInfo>> {
        Ok(vec![monitor(0)?, monitor(1)?])
    }

    fn capture(&self, request: &CaptureRequest) -> Result<Frame> {
        let frame = self.grab(&request.target)?;
        scale_frame(frame, request.scale)
    }

    fn open_session(&self, request: &CaptureRequest) -> Result<Box<dyn FrameSource>> {
        Ok(Box::new(MockSession {
            desktop: Arc::new(self_as_arc_placeholder(self)),
            request: request.clone(),
            interval: frame_interval(request.max_fps),
            last: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
        }))
    }
}

/// `open_session` needs shared ownership. The public constructors always wrap
/// the mock in an `Arc` before this is called; the inherent method below is
/// the one the handlers use. This inherent impl exists so a bare `MockDesktop`
/// still satisfies [`CaptureBackend`] for one-shot tests.
fn self_as_arc_placeholder(desktop: &MockDesktop) -> MockDesktop {
    MockDesktop {
        events: Mutex::new(desktop.events()),
        tree: Mutex::new(
            desktop
                .tree
                .lock()
                .unwrap_or_else(|err| err.into_inner())
                .clone(),
        ),
        tick: Mutex::new(*desktop.tick.lock().unwrap_or_else(|err| err.into_inner())),
    }
}

struct MockSession {
    desktop: Arc<MockDesktop>,
    request: CaptureRequest,
    interval: Duration,
    last: Instant,
}

impl FrameSource for MockSession {
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>> {
        wait_until_due(self.last, self.interval);
        self.last = Instant::now();
        let mut frame = self.desktop.capture(&self.request)?;
        frame.captured_unix_ms = unix_ms();
        Ok(Some(frame))
    }

    fn mode(&self) -> StreamMode {
        StreamMode::Surface {
            backend: "mock".into(),
        }
    }
}

struct EventLog<'a> {
    events: &'a Mutex<Vec<String>>,
}

impl Pointer for EventLog<'_> {
    fn mouse_move(&mut self, x: i32, y: i32) -> Result<()> {
        self.push(format!("move {x},{y}"));
        Ok(())
    }

    fn mouse_button(&mut self, button: crate::input::MouseButton, down: bool) -> Result<()> {
        let state = if down { "down" } else { "up" };
        self.push(format!("button {button:?} {state}"));
        Ok(())
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> Result<()> {
        self.push(format!("scroll {dx},{dy}"));
        Ok(())
    }

    fn key_down(&mut self, key: &str) -> Result<()> {
        self.push(format!("down {key}"));
        Ok(())
    }

    fn key_up(&mut self, key: &str) -> Result<()> {
        self.push(format!("up {key}"));
        Ok(())
    }

    fn type_text(&mut self, text: &str) -> Result<()> {
        self.push(format!("type {text}"));
        Ok(())
    }
}

impl EventLog<'_> {
    fn push(&self, event: String) {
        self.events
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .push(event);
    }
}

impl HidBackend for MockDesktop {
    fn backend_name(&self) -> &str {
        "mock"
    }

    fn inject(&self, action: &InputAction) -> Result<()> {
        let mut log = EventLog {
            events: &self.events,
        };
        perform(&mut log, action)
    }
}

impl A11yBackend for MockDesktop {
    fn backend_name(&self) -> &str {
        "mock"
    }

    fn tree(&self, max_depth: u32, max_nodes: u32) -> Result<UiNode> {
        let tree = self
            .tree
            .lock()
            .unwrap_or_else(|err| err.into_inner())
            .clone();
        Ok(limit_tree(tree, max_depth, max_nodes))
    }

    fn act(&self, id: &str, op: ElementOp, value: Option<&str>) -> Result<()> {
        let mut tree = self.tree.lock().unwrap_or_else(|err| err.into_inner());
        let node = find_mut(&mut tree, id).ok_or_else(|| msg(format!("unknown element '{id}'")))?;
        match op {
            ElementOp::Click => {
                let bounds = node.bounds;
                drop(tree);
                self.record(format!("act click {id}"));
                self.inject(&InputAction::Click {
                    x: bounds.x + bounds.width as i32 / 2,
                    y: bounds.y + bounds.height as i32 / 2,
                    button: crate::input::MouseButton::Left,
                    count: 1,
                })?;
            }
            ElementOp::Focus => {
                clear_focus(&mut tree);
                let node = find_mut(&mut tree, id).unwrap();
                node.focused = true;
                self.record(format!("act focus {id}"));
            }
            ElementOp::SetValue => {
                let text = value.unwrap_or("").to_string();
                node.value = text.clone();
                self.record(format!("act set_value {id} {text}"));
            }
        }
        Ok(())
    }
}

pub struct SharedMock {
    inner: Arc<MockDesktop>,
}

impl SharedMock {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Arc::new(MockDesktop::new()),
        })
    }
}

impl CaptureBackend for SharedMock {
    fn backend_name(&self) -> &str {
        "mock"
    }

    fn list_monitors(&self) -> Result<Vec<MonitorInfo>> {
        self.inner.list_monitors()
    }

    fn capture(&self, request: &CaptureRequest) -> Result<Frame> {
        self.inner.capture(request)
    }

    fn open_session(&self, request: &CaptureRequest) -> Result<Box<dyn FrameSource>> {
        Ok(Box::new(MockSession {
            desktop: self.inner.clone(),
            request: request.clone(),
            interval: frame_interval(request.max_fps),
            last: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
        }))
    }
}

impl HidBackend for SharedMock {
    fn backend_name(&self) -> &str {
        "mock"
    }

    fn inject(&self, action: &InputAction) -> Result<()> {
        self.inner.inject(action)
    }
}

impl A11yBackend for SharedMock {
    fn backend_name(&self) -> &str {
        "mock"
    }

    fn tree(&self, max_depth: u32, max_nodes: u32) -> Result<UiNode> {
        self.inner.tree(max_depth, max_nodes)
    }

    fn act(&self, id: &str, op: ElementOp, value: Option<&str>) -> Result<()> {
        self.inner.act(id, op, value)
    }
}

fn monitor(index: u32) -> Result<MonitorInfo> {
    match index {
        0 => Ok(MonitorInfo {
            index: 0,
            name: "mock-0".into(),
            x: 0,
            y: 0,
            width: 640,
            height: HEIGHT,
            primary: true,
        }),
        1 => Ok(MonitorInfo {
            index: 1,
            name: "mock-1".into(),
            x: 640,
            y: 0,
            width: 320,
            height: HEIGHT,
            primary: false,
        }),
        other => Err(msg(format!("mock monitor {other} does not exist"))),
    }
}

fn window_rect(id: &str) -> Result<Rect> {
    let id = id.to_ascii_lowercase();
    if id == "win-1" || id == "calculator" || id.contains("calc") {
        Ok(Rect {
            x: 40,
            y: 40,
            width: 120,
            height: 80,
        })
    } else {
        Err(msg(format!("mock window '{id}' was not found")))
    }
}

fn demo_tree() -> UiNode {
    UiNode {
        id: "mock:root".into(),
        role: "desktop".into(),
        name: "Mock Desktop".into(),
        bounds: Rect {
            x: 0,
            y: 0,
            width: WIDTH,
            height: HEIGHT,
        },
        value: String::new(),
        focused: false,
        children: vec![
            UiNode {
                id: "mock:ok".into(),
                role: "button".into(),
                name: "OK".into(),
                bounds: Rect {
                    x: 40,
                    y: 40,
                    width: 80,
                    height: 30,
                },
                value: String::new(),
                focused: false,
                children: Vec::new(),
            },
            UiNode {
                id: "mock:title".into(),
                role: "text".into(),
                name: "Title".into(),
                bounds: Rect {
                    x: 40,
                    y: 80,
                    width: 200,
                    height: 24,
                },
                value: "hello".into(),
                focused: false,
                children: Vec::new(),
            },
        ],
    }
}

fn find_mut<'a>(node: &'a mut UiNode, id: &str) -> Option<&'a mut UiNode> {
    if node.id == id {
        return Some(node);
    }
    for child in &mut node.children {
        if let Some(found) = find_mut(child, id) {
            return Some(found);
        }
    }
    None
}

fn clear_focus(node: &mut UiNode) {
    node.focused = false;
    for child in &mut node.children {
        clear_focus(child);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_timeout_does_not_end_a_paced_session() {
        let backend = SharedMock::new();
        let mut session = backend
            .open_session(&CaptureRequest {
                target: CaptureTarget::Region(Rect {
                    x: 0,
                    y: 0,
                    width: 4,
                    height: 2,
                }),
                scale: 1.0,
                max_fps: 30.0,
                max_width: 0,
                cursor_mode: crate::capture::CursorCaptureMode::Embedded,
            })
            .unwrap();
        assert!(session
            .next_frame(Duration::from_millis(1))
            .unwrap()
            .is_some());
        let frame = session
            .next_frame(Duration::from_millis(1))
            .unwrap()
            .expect("a short timeout waits for the next paced frame");
        assert_eq!((frame.width, frame.height), (4, 2));
    }
}
