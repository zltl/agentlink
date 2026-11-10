//! Linux desktop: X11 (XShm + XTest) or Wayland (xdg-desktop-portal), plus AT-SPI.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::runtime::Runtime;
use zbus::Connection;

use crate::a11y::{A11yBackend, ElementOp, UiNode};
use crate::capture::{
    scale_frame, stream_interval, unix_ms, wait_until_due, CaptureBackend, CaptureRequest,
    CaptureTarget, CursorSample, Frame, FrameSource, MonitorInfo, StreamMode,
};
use crate::error::{msg, Result};
use crate::input::{perform, HidBackend, InputAction, Pointer};
use crate::worker::Worker;
use crate::Desktop;

#[cfg(pipewire_headers)]
use super::mutter::{self, MutterDesk};
use super::wayland::{self, WaylandDesk};
use super::x11::X11Desk;

enum DisplayConn {
    X11(X11Desk),
    Wayland(WaylandDesk),
    #[cfg(pipewire_headers)]
    Mutter(MutterDesk),
}

struct Session {
    request: CaptureRequest,
    last: Option<Frame>,
    #[cfg(pipewire_headers)]
    pipewire: Option<crate::stream::pipewire::PwCapture>,
    #[cfg(pipewire_headers)]
    dma_buf: bool,
}

struct LinuxState {
    rt: Runtime,
    display: Option<DisplayConn>,
    sessions: HashMap<u64, Session>,
    next_id: u64,
}

impl LinuxState {
    fn new() -> Self {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("desktop tokio runtime");
        Self {
            rt,
            display: None,
            sessions: HashMap::new(),
            next_id: 1,
        }
    }

    fn ensure(&mut self) -> Result<()> {
        if self.display.is_some() {
            return Ok(());
        }
        self.display = Some(connect_display(&self.rt)?);
        Ok(())
    }

    fn capture(&mut self, request: &CaptureRequest) -> Result<Frame> {
        self.capture_frame(request, 1000)
    }

    fn capture_frame(
        &mut self,
        request: &CaptureRequest,
        #[cfg_attr(not(pipewire_headers), allow(unused_variables))] wait_ms: i32,
    ) -> Result<Frame> {
        self.ensure()?;
        let frame = match self.display.as_mut().unwrap() {
            DisplayConn::X11(desk) => capture_x11(desk, &request.target)?,
            DisplayConn::Wayland(desk) => self.rt.block_on(desk.capture(&request.target))?,
            #[cfg(pipewire_headers)]
            DisplayConn::Mutter(desk) => {
                if let CaptureTarget::Window(query) = &request.target {
                    match self
                        .rt
                        .block_on(desk.capture_window(query, wait_ms, request.max_width))
                    {
                        Ok(frame) => frame,
                        Err(err) => match X11Desk::connect()
                            .and_then(|mut x11| x11.capture_window(query))
                        {
                            Ok(frame) => {
                                tracing::info!(
                                    error = %err,
                                    "Mutter RecordWindow unavailable; captured the X11 window drawable"
                                );
                                frame
                            }
                            Err(x11_err) => {
                                return Err(msg(format!(
                                    "{err}; X11 window fallback also failed ({x11_err}). On this GNOME session, Shell Introspect GetWindows and ScreenshotWindow are AccessDenied to regular clients, and Wayland-native windows have no X11 drawable. Full-screen or monitor capture still works."
                                )));
                            }
                        },
                    }
                } else {
                    desk.capture_wait(&request.target, wait_ms, request.max_width)?
                }
            }
        };
        // PipeWire/Mutter already applied max_width capture-side; scale_frame
        // is a no-op when request.scale ≈ 1.0 (the live stream path).
        scale_frame(frame, request.scale)
    }

    fn open_session(&mut self, request: &CaptureRequest) -> Result<(u64, StreamMode)> {
        self.ensure()?;
        #[allow(unused_mut)]
        let mut mode = match self.display.as_mut().unwrap() {
            DisplayConn::X11(desk) => StreamMode::Surface {
                backend: desk.backend_name().into(),
            },
            DisplayConn::Wayland(desk) => StreamMode::PortalSampled {
                pipewire_node: self.rt.block_on(desk.pipewire_node()),
            },
            // The Mutter consumer lives on the desk so screenshots and the
            // session share it; a second PipeWire link stays idle.
            #[cfg(pipewire_headers)]
            DisplayConn::Mutter(desk) => StreamMode::PipeWire {
                node: desk.node(),
                dma_buf: false,
            },
        };
        let id = self.next_id;
        self.next_id += 1;
        #[allow(unused_mut)]
        let mut session = Session {
            request: request.clone(),
            last: None,
            #[cfg(pipewire_headers)]
            pipewire: None,
            #[cfg(pipewire_headers)]
            dma_buf: false,
        };
        #[cfg(pipewire_headers)]
        if let DisplayConn::Wayland(desk) = self.display.as_mut().unwrap() {
            if std::env::var("AGENTLINK_DESKTOP_PIPEWIRE").ok().as_deref() != Some("0") {
                if let Some((fd, node)) = self.rt.block_on(desk.open_pipewire()) {
                    match crate::stream::pipewire::PwCapture::open(fd, node) {
                        Ok(capture) => {
                            session.pipewire = Some(capture);
                            mode = StreamMode::PipeWire {
                                node,
                                dma_buf: false,
                            };
                        }
                        Err(err) => {
                            tracing::info!(error = %err, "PipeWire map failed; using the portal")
                        }
                    }
                }
            }
        }
        self.sessions.insert(id, session);
        Ok((id, mode))
    }

    fn grab_session(&mut self, id: u64) -> Result<Frame> {
        #[cfg(pipewire_headers)]
        {
            let use_pw = self
                .sessions
                .get(&id)
                .map(|session| session.pipewire.is_some())
                .unwrap_or(false);
            if use_pw {
                return self.grab_pipewire(id);
            }
        }
        let request = self
            .sessions
            .get(&id)
            .ok_or_else(|| msg("capture session is closed"))?
            .request
            .clone();
        if let Some(DisplayConn::X11(desk)) = self.display.as_mut() {
            if !desk.screen_changed() {
                if let Some(prev) = self
                    .sessions
                    .get(&id)
                    .and_then(|session| session.last.clone())
                {
                    let mut frame = prev;
                    frame.mark_unchanged();
                    frame.captured_unix_ms = unix_ms();
                    return Ok(frame);
                }
            }
        }
        let frame = self.capture_frame(&request, 30)?;
        if let Some(session) = self.sessions.get_mut(&id) {
            session.last = Some(frame.clone());
        }
        Ok(frame)
    }

    #[cfg(pipewire_headers)]
    fn grab_pipewire(&mut self, id: u64) -> Result<Frame> {
        let taken = {
            let session = self
                .sessions
                .get_mut(&id)
                .ok_or_else(|| msg("capture session is closed"))?;
            let target =
                crate::stream::pipewire::resolve_target_width(session.request.max_width);
            let capture = session
                .pipewire
                .as_mut()
                .ok_or_else(|| msg("PipeWire session is closed"))?;
            capture.set_target_width(target);
            capture.take(30)?
        };
        match taken {
            Some((frame, dma)) => {
                if let Some(session) = self.sessions.get_mut(&id) {
                    session.dma_buf = dma;
                    session.last = Some(frame.clone());
                }
                Ok(frame)
            }
            None => {
                if let Some(prev) = self
                    .sessions
                    .get(&id)
                    .and_then(|session| session.last.clone())
                {
                    let mut frame = prev;
                    frame.mark_unchanged();
                    frame.captured_unix_ms = unix_ms();
                    return Ok(frame);
                }
                Err(msg("PipeWire has not delivered a frame yet"))
            }
        }
    }

    fn close_session(&mut self, id: u64) {
        self.sessions.remove(&id);
    }

    fn inject(&mut self, action: &InputAction) -> Result<()> {
        self.ensure()?;
        // Literal text: prefer AT-SPI InsertText (bypasses IME). Otherwise
        // temporarily switch composing IMEs to Latin, type keysyms, restore.
        let _ime_guard = if let InputAction::Type { text } = action {
            match self
                .rt
                .block_on(super::atspi::insert_text_at_focus(text))
            {
                Ok(()) => return Ok(()),
                Err(err) => {
                    tracing::info!(
                        error = %err,
                        "AT-SPI InsertText unavailable; typing keysyms with IME guard"
                    );
                    if !text.chars().all(|ch| {
                        ch.is_ascii() && (ch.is_ascii_graphic() || ch.is_ascii_whitespace())
                    }) {
                        return Err(msg(format!(
                            "{err}. Keysym fallback cannot type non-ASCII literally; InsertText needs a focused editable field"
                        )));
                    }
                }
            }
            super::ime::ImeGuard::engage()
        } else {
            None
        };
        match self.display.take() {
            Some(DisplayConn::X11(mut desk)) => {
                let result = perform(&mut desk, action);
                self.display = Some(DisplayConn::X11(desk));
                result
            }
            Some(DisplayConn::Wayland(mut desk)) => {
                let result = inject_wayland(&self.rt, &mut desk, action);
                self.display = Some(DisplayConn::Wayland(desk));
                result
            }
            #[cfg(pipewire_headers)]
            Some(DisplayConn::Mutter(mut desk)) => {
                let result = inject_mutter(&self.rt, &mut desk, action);
                self.display = Some(DisplayConn::Mutter(desk));
                result
            }
            None => Err(msg("desktop backend is not connected")),
        }
    }

    fn tree(&mut self, depth: u32, nodes: u32) -> Result<UiNode> {
        self.rt.block_on(super::atspi::tree(depth, nodes))
    }

    fn act(&mut self, id: &str, op: ElementOp, value: Option<&str>) -> Result<()> {
        let value = value.map(str::to_string);
        self.rt
            .block_on(async { super::atspi::act(id, op, value.as_deref()).await })
    }

    fn monitors(&mut self) -> Result<Vec<MonitorInfo>> {
        self.ensure()?;
        match self.display.as_ref().unwrap() {
            DisplayConn::X11(desk) => desk.monitors(),
            DisplayConn::Wayland(_) => Ok(vec![MonitorInfo {
                index: 0,
                name: "wayland-session".into(),
                x: 0,
                y: 0,
                width: 0,
                height: 0,
                primary: true,
            }]),
            #[cfg(pipewire_headers)]
            DisplayConn::Mutter(desk) => {
                let monitors = desk.monitors();
                if monitors.is_empty() {
                    Ok(vec![MonitorInfo {
                        index: 0,
                        name: desk.connector().into(),
                        x: 0,
                        y: 0,
                        width: 0,
                        height: 0,
                        primary: true,
                    }])
                } else {
                    Ok(monitors)
                }
            }
        }
    }
}

fn inject_wayland(rt: &Runtime, desk: &mut WaylandDesk, action: &InputAction) -> Result<()> {
    rt.block_on(desk.prepare_input())?;
    let (path, stream) = {
        let (path, stream) = desk.session()?;
        (path.to_string(), stream)
    };
    let conn = desk.connection();
    let mut portal = PortalPointer {
        rt,
        conn,
        path,
        stream,
    };
    perform(&mut portal, action)
}

struct PortalPointer<'a> {
    rt: &'a Runtime,
    conn: Connection,
    path: String,
    stream: u32,
}

impl Pointer for PortalPointer<'_> {
    fn mouse_move(&mut self, x: i32, y: i32) -> Result<()> {
        let conn = self.conn.clone();
        let path = self.path.clone();
        let stream = self.stream;
        self.rt
            .block_on(wayland::notify_motion(&conn, &path, stream, x, y))
    }

    fn mouse_button(&mut self, button: crate::input::MouseButton, down: bool) -> Result<()> {
        let conn = self.conn.clone();
        let path = self.path.clone();
        self.rt
            .block_on(wayland::notify_button(&conn, &path, button.evdev(), down))
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> Result<()> {
        let conn = self.conn.clone();
        let path = self.path.clone();
        self.rt
            .block_on(wayland::notify_axis(&conn, &path, dx as f64, -(dy as f64)))
    }

    fn key_down(&mut self, key: &str) -> Result<()> {
        self.send_key(key, true)
    }

    fn key_up(&mut self, key: &str) -> Result<()> {
        self.send_key(key, false)
    }

    fn type_text(&mut self, text: &str) -> Result<()> {
        let conn = self.conn.clone();
        let path = self.path.clone();
        let text = text.to_string();
        self.rt.block_on(async move {
            for ch in text.chars() {
                if ch == '\r' {
                    continue;
                }
                let keysym = wayland::keysym_for_char(ch);
                wayland::notify_keysym(&conn, &path, keysym, true).await?;
                wayland::notify_keysym(&conn, &path, keysym, false).await?;
            }
            Ok(())
        })
    }
}

impl PortalPointer<'_> {
    fn send_key(&mut self, key: &str, down: bool) -> Result<()> {
        let keysym = wayland::keysym_for_name(key)?;
        let conn = self.conn.clone();
        let path = self.path.clone();
        self.rt
            .block_on(wayland::notify_keysym(&conn, &path, keysym, down))
    }
}

#[cfg(pipewire_headers)]
fn inject_mutter(rt: &Runtime, desk: &mut MutterDesk, action: &InputAction) -> Result<()> {
    let mut pointer = MutterPointer {
        rt,
        conn: desk.connection(),
        session: desk.session().to_string(),
        stream: desk.stream().to_string(),
    };
    perform(&mut pointer, action)
}

#[cfg(pipewire_headers)]
struct MutterPointer<'a> {
    rt: &'a Runtime,
    conn: Connection,
    session: String,
    stream: String,
}

#[cfg(pipewire_headers)]
impl Pointer for MutterPointer<'_> {
    fn mouse_move(&mut self, x: i32, y: i32) -> Result<()> {
        self.rt.block_on(mutter::notify_motion(
            &self.conn,
            &self.session,
            &self.stream,
            x,
            y,
        ))
    }

    fn mouse_button(&mut self, button: crate::input::MouseButton, down: bool) -> Result<()> {
        self.rt.block_on(mutter::notify_button(
            &self.conn,
            &self.session,
            button.evdev(),
            down,
        ))
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> Result<()> {
        self.rt.block_on(mutter::notify_axis(
            &self.conn,
            &self.session,
            dx as f64,
            -(dy as f64),
        ))
    }

    fn key_down(&mut self, key: &str) -> Result<()> {
        self.send_key(key, true)
    }

    fn key_up(&mut self, key: &str) -> Result<()> {
        self.send_key(key, false)
    }

    fn type_text(&mut self, text: &str) -> Result<()> {
        let conn = self.conn.clone();
        let session = self.session.clone();
        let text = text.to_string();
        self.rt.block_on(async move {
            for ch in text.chars() {
                if ch == '\r' {
                    continue;
                }
                let keysym = wayland::keysym_for_char(ch);
                mutter::notify_keysym(&conn, &session, keysym, true).await?;
                mutter::notify_keysym(&conn, &session, keysym, false).await?;
            }
            Ok(())
        })
    }
}

#[cfg(pipewire_headers)]
impl MutterPointer<'_> {
    fn send_key(&mut self, key: &str, down: bool) -> Result<()> {
        let keysym = wayland::keysym_for_name(key)?;
        self.rt
            .block_on(mutter::notify_keysym(&self.conn, &self.session, keysym, down))
    }
}

fn capture_x11(desk: &mut X11Desk, target: &CaptureTarget) -> Result<Frame> {
    match target {
        CaptureTarget::FullScreen => desk.capture_full(),
        CaptureTarget::Monitor(index) => desk.capture_monitor(*index),
        CaptureTarget::Region(rect) => desk.capture_region(*rect),
        CaptureTarget::Window(id) => desk.capture_window(id),
    }
}

fn connect_display(rt: &Runtime) -> Result<DisplayConn> {
    match std::env::var("AGENTLINK_DESKTOP_BACKEND").ok().as_deref() {
        Some("x11") => {
            let x11 = X11Desk::connect()?;
            #[cfg(pipewire_headers)]
            if x11.is_xwayland() && mutter_enabled() {
                match rt.block_on(MutterDesk::connect()) {
                    Ok(desk) => {
                        tracing::info!(
                            connector = desk.connector(),
                            node = desk.node(),
                            "XWayland detected; capturing through Mutter ScreenCast"
                        );
                        return Ok(DisplayConn::Mutter(desk));
                    }
                    Err(err) => {
                        tracing::info!(error = %err, "Mutter ScreenCast unavailable; keeping X11")
                    }
                }
            }
            Ok(DisplayConn::X11(x11))
        }
        Some("wayland") => connect_wayland(rt),
        Some("mutter") => {
            #[cfg(pipewire_headers)]
            {
                Ok(DisplayConn::Mutter(rt.block_on(MutterDesk::connect())?))
            }
            #[cfg(not(pipewire_headers))]
            {
                Err(msg(
                    "this build has no libpipewire-0.3 headers; rebuild with the development package",
                ))
            }
        }
        Some(other) => Err(msg(format!(
            "unknown AGENTLINK_DESKTOP_BACKEND '{other}' (expected x11, wayland, or mutter)"
        ))),
        None => auto_connect(rt),
    }
}

fn connect_wayland(rt: &Runtime) -> Result<DisplayConn> {
    #[cfg(pipewire_headers)]
    if mutter_enabled() {
        match rt.block_on(MutterDesk::connect()) {
            Ok(desk) => {
                tracing::info!(
                    connector = desk.connector(),
                    node = desk.node(),
                    "using Mutter ScreenCast"
                );
                return Ok(DisplayConn::Mutter(desk));
            }
            Err(err) => {
                tracing::info!(error = %err, "Mutter ScreenCast unavailable; trying the portal")
            }
        }
    }
    Ok(DisplayConn::Wayland(
        rt.block_on(WaylandDesk::connect())?,
    ))
}

#[cfg(pipewire_headers)]
fn mutter_enabled() -> bool {
    std::env::var("AGENTLINK_DESKTOP_MUTTER").ok().as_deref() != Some("0")
}

fn auto_connect(rt: &Runtime) -> Result<DisplayConn> {
    let display = std::env::var("DISPLAY")
        .ok()
        .filter(|value| !value.is_empty());
    let wayland = std::env::var("WAYLAND_DISPLAY")
        .ok()
        .filter(|value| !value.is_empty());
    if display.is_some() {
        if let Ok(x11) = X11Desk::connect() {
            if x11.is_xwayland() && wayland.is_some() {
                #[cfg(pipewire_headers)]
                if mutter_enabled() {
                    if let Ok(desk) = rt.block_on(MutterDesk::connect()) {
                        tracing::info!(
                            connector = desk.connector(),
                            node = desk.node(),
                            "XWayland detected; using Mutter ScreenCast"
                        );
                        return Ok(DisplayConn::Mutter(desk));
                    }
                }
                if let Ok(portal) = rt.block_on(WaylandDesk::connect()) {
                    tracing::info!("XWayland detected; using the desktop portal");
                    return Ok(DisplayConn::Wayland(portal));
                }
            }
            tracing::info!(backend = x11.backend_name(), "desktop capture ready");
            return Ok(DisplayConn::X11(x11));
        }
    }
    if wayland.is_some() {
        return connect_wayland(rt);
    }
    if let Ok(x11) = X11Desk::connect() {
        return Ok(DisplayConn::X11(x11));
    }
    Err(msg(
        "no X11 display and no Wayland portal. Set DISPLAY, or run a session with xdg-desktop-portal.",
    ))
}

#[derive(Clone)]
struct LinuxDesktop {
    worker: Worker<LinuxState>,
}

impl LinuxDesktop {
    fn start() -> Self {
        Self {
            worker: Worker::spawn(LinuxState::new),
        }
    }
}

pub fn open() -> Arc<Desktop> {
    let backend = Arc::new(LinuxDesktop::start());
    Arc::new(Desktop {
        capture: backend.clone(),
        hid: backend.clone(),
        a11y: backend,
    })
}

impl CaptureBackend for LinuxDesktop {
    fn backend_name(&self) -> &str {
        "linux"
    }

    fn list_monitors(&self) -> Result<Vec<MonitorInfo>> {
        self.worker.call(|state| state.monitors())
    }

    fn cursor(&self) -> Option<CursorSample> {
        self.worker
            .call(|state| {
                let point = match state.display.as_ref() {
                    Some(DisplayConn::X11(desk)) => desk.pointer(),
                    _ => None,
                };
                Ok(point.map(|(x, y)| {
                    // Stream-pixel cursor → capture-frame pixels when PipeWire
                    // downsampled (out/src). Identity when factor is 1.
                    #[cfg(pipewire_headers)]
                    let (x, y) = {
                        let (out, src) = crate::stream::pipewire::coord_scale();
                        if src > 0 && out > 0 && out != src {
                            (
                                ((x as i64) * (out as i64) / (src as i64)) as i32,
                                ((y as i64) * (out as i64) / (src as i64)) as i32,
                            )
                        } else {
                            (x, y)
                        }
                    };
                    CursorSample {
                        x,
                        y,
                        shape: "arrow".into(),
                    }
                }))
            })
            .ok()
            .flatten()
    }

    fn capture(&self, request: &CaptureRequest) -> Result<Frame> {
        let request = request.clone();
        self.worker.call(move |state| state.capture(&request))
    }

    fn open_session(&self, request: &CaptureRequest) -> Result<Box<dyn FrameSource>> {
        let request = request.clone();
        let interval = stream_interval(request.max_fps);
        let (id, mode) = self
            .worker
            .call(move |state| state.open_session(&request))?;
        Ok(Box::new(LinuxSession {
            worker: self.worker.clone(),
            id,
            mode,
            interval,
            last: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
        }))
    }
}

struct LinuxSession {
    worker: Worker<LinuxState>,
    id: u64,
    mode: StreamMode,
    interval: Duration,
    last: Instant,
}

impl FrameSource for LinuxSession {
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>> {
        wait_until_due(self.last, self.interval);
        let id = self.id;
        let frame = self.worker.call(move |state| state.grab_session(id))?;
        self.last = Instant::now();
        Ok(Some(frame))
    }

    fn mode(&self) -> StreamMode {
        self.mode.clone()
    }
}

impl Drop for LinuxSession {
    fn drop(&mut self) {
        let id = self.id;
        let _ = self.worker.call(move |state| {
            state.close_session(id);
            Ok(())
        });
    }
}

impl HidBackend for LinuxDesktop {
    fn backend_name(&self) -> &str {
        "linux"
    }

    fn inject(&self, action: &InputAction) -> Result<()> {
        let action = action.clone();
        self.worker.call(move |state| state.inject(&action))
    }
}

impl A11yBackend for LinuxDesktop {
    fn backend_name(&self) -> &str {
        "atspi"
    }

    fn tree(&self, max_depth: u32, max_nodes: u32) -> Result<UiNode> {
        self.worker
            .call(move |state| state.tree(max_depth, max_nodes))
    }

    fn act(&self, id: &str, op: ElementOp, value: Option<&str>) -> Result<()> {
        let id = id.to_string();
        let value = value.map(str::to_string);
        self.worker
            .call(move |state| state.act(&id, op, value.as_deref()))
    }
}
