//! Capture and input through Mutter's private ScreenCast + RemoteDesktop APIs.
//!
//! Under GNOME Wayland the X11 root window is an empty XWayland surface, so
//! XShm capture reads black. The xdg-desktop-portal asks for a permission
//! dialog that cannot be answered from a service. Mutter exposes the same
//! capture path to the logged-in user without a portal:
//!
//! 1. `org.gnome.Mutter.RemoteDesktop.CreateSession` gives a session id.
//! 2. `org.gnome.Mutter.ScreenCast.CreateSession` is associated with it via
//!    `remote-desktop-session-id`; the remote desktop session starts and stops
//!    the screencast.
//! 3. `RecordMonitor(connector)` returns a stream path. `PipeWireStreamAdded`
//!    reports the PipeWire node.
//! 4. Input goes to the same remote desktop session. Absolute pointer
//!    positions are in stream pixels, so `NotifyPointerMotionAbsolute` takes
//!    the stream path.
//! 5. Single-window screenshots use a separate ScreenCast session with
//!    `RecordWindow` (Mutter API ≥ 2) and GNOME Shell Introspect window ids.
//!    This is a real compositor window stream (content + geometry + occlusion),
//!    not a cropped monitor frame.
//!
//! The PipeWire node lives on the user's default PipeWire daemon (not a
//! portal-provided fd), so [`PwCapture::open_default`] connects to it directly.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::StreamExt;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use super::mutter_session::{remote_desktop_close_action, RemoteDesktopClose};
use crate::capture::{crop_frame, CaptureTarget, Frame, MonitorInfo};
use crate::error::{msg, Result};
use crate::stream::pipewire::PwCapture;

const MUTTER_RD: &str = "org.gnome.Mutter.RemoteDesktop";
const MUTTER_SC: &str = "org.gnome.Mutter.ScreenCast";
const MUTTER_DISPLAY: &str = "org.gnome.Mutter.DisplayConfig";
const RD_PATH: &str = "/org/gnome/Mutter/RemoteDesktop";
const RD_IFACE: &str = "org.gnome.Mutter.RemoteDesktop";
const RD_SESSION_IFACE: &str = "org.gnome.Mutter.RemoteDesktop.Session";
const SC_PATH: &str = "/org/gnome/Mutter/ScreenCast";
const SC_IFACE: &str = "org.gnome.Mutter.ScreenCast";
const SC_SESSION_IFACE: &str = "org.gnome.Mutter.ScreenCast.Session";
const SC_STREAM_IFACE: &str = "org.gnome.Mutter.ScreenCast.Stream";
const DISPLAY_PATH: &str = "/org/gnome/Mutter/DisplayConfig";
const DISPLAY_IFACE: &str = "org.gnome.Mutter.DisplayConfig";

type MonitorSpec = (String, String, String, String);
type ModeState = (
    String,
    i32,
    i32,
    f64,
    f64,
    Vec<f64>,
    HashMap<String, OwnedValue>,
);
type MonitorState = (MonitorSpec, Vec<ModeState>, HashMap<String, OwnedValue>);
type LogicalState = (
    i32,
    i32,
    f64,
    u32,
    bool,
    Vec<MonitorSpec>,
    HashMap<String, OwnedValue>,
);

pub struct MutterDesk {
    conn: Connection,
    session: String,
    stream: String,
    connector: String,
    node: u32,
    monitors: Vec<MonitorInfo>,
    capture: Option<PwCapture>,
    last: Option<Frame>,
    /// Last `max_width` applied to the shared PipeWire consumer. When this
    /// changes we drop `last` so a full-res screenshot is not reused as a
    /// downsampled stream frame.
    last_target_width: Option<u32>,
}

impl MutterDesk {
    pub async fn connect() -> Result<Self> {
        let conn = Connection::session()
            .await
            .map_err(|err| msg(format!("session bus: {err}")))?;
        let monitors = display_monitors(&conn).await.unwrap_or_default();
        let mut candidates: Vec<String> = Vec::new();
        if let Some(name) = std::env::var("AGENTLINK_DESKTOP_MONITOR")
            .ok()
            .filter(|value| !value.is_empty())
        {
            candidates.push(name);
        }
        for monitor in &monitors {
            if !candidates.iter().any(|name| name == &monitor.name) {
                candidates.push(monitor.name.clone());
            }
        }
        if candidates.is_empty() {
            return Err(msg(
                "Mutter reported no monitor connector; set AGENTLINK_DESKTOP_MONITOR (for example eDP-1)",
            ));
        }
        let mut last_err = String::new();
        for connector in candidates {
            match open_screencast(&conn, &connector).await {
                Ok((session, stream, node)) => {
                    tracing::info!(%connector, node, "Mutter ScreenCast is ready");
                    return Ok(Self {
                        conn,
                        session,
                        stream,
                        connector,
                        node,
                        monitors,
                        capture: None,
                        last: None,
                        last_target_width: None,
                    });
                }
                Err(err) => last_err = err.to_string(),
            }
        }
        Err(msg(format!("Mutter ScreenCast: {last_err}")))
    }

    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn stream(&self) -> &str {
        &self.stream
    }

    pub fn connector(&self) -> &str {
        &self.connector
    }

    pub fn node(&self) -> u32 {
        self.node
    }

    pub fn monitors(&self) -> Vec<MonitorInfo> {
        self.monitors.clone()
    }

    pub fn capture_wait(
        &mut self,
        target: &CaptureTarget,
        wait_ms: i32,
        max_width: u32,
    ) -> Result<Frame> {
        let frame = self
            .take_frame(wait_ms, max_width)?
            .ok_or_else(|| msg("Mutter ScreenCast has not delivered a frame yet"))?;
        match target {
            CaptureTarget::FullScreen | CaptureTarget::Monitor(0) => Ok(frame),
            CaptureTarget::Monitor(index) => Err(msg(format!(
                "Mutter records {} only; monitor {index} is not open",
                self.connector
            ))),
            CaptureTarget::Region(rect) => crop_frame(&frame, *rect),
            CaptureTarget::Window(_) => Err(msg(
                "internal error: Mutter window capture must use capture_window",
            )),
        }
    }

    /// One-shot `RecordWindow` capture. Runs on the caller's tokio runtime.
    pub async fn capture_window(&self, query: &str, wait_ms: i32, max_width: u32) -> Result<Frame> {
        record_window_frame(&self.conn, query, wait_ms.max(500), max_width).await
    }

    /// Reuse one PipeWire consumer for screenshots and the live session: a
    /// second link gets no initial buffer, and dropping the first one leaves
    /// the stream waiting for damage.
    ///
    /// `max_width` is applied capture-side (0 = full stream resolution). Cursor
    /// positions from Mutter stay in stream pixels; callers that expose a
    /// cursor overlay must scale by out/src (see `pipewire::coord_scale`).
    pub fn take_frame(&mut self, wait_ms: i32, max_width: u32) -> Result<Option<Frame>> {
        if self.capture.is_none() {
            self.capture = Some(PwCapture::open_default(self.node)?);
            self.last = None;
            self.last_target_width = None;
        }
        let target = crate::stream::pipewire::resolve_target_width(max_width);
        if self.last_target_width != Some(target) {
            // Drop the cached frame so a full-res screenshot is never reused as
            // a downsampled stream probe (static desktops may not emit damage).
            self.last = None;
            self.last_target_width = Some(target);
        }
        let capture = self.capture.as_mut().unwrap();
        capture.set_target_width(target);
        // First buffer after connect (or after a max_width change) can take
        // multiple seconds on a quiet desktop; poll rather than one short wait.
        let attempts = if self.last.is_none() { 8 } else { 1 };
        let per_wait = if self.last.is_none() {
            wait_ms.max(500)
        } else {
            wait_ms
        };
        for attempt in 0..attempts {
            match capture.take(per_wait)? {
                Some((frame, _dma)) => {
                    self.last = Some(frame.clone());
                    return Ok(Some(frame));
                }
                None => {
                    if let Some(previous) = self.last.clone() {
                        let mut previous = previous;
                        previous.mark_unchanged();
                        previous.captured_unix_ms = crate::capture::unix_ms();
                        return Ok(Some(previous));
                    }
                    if attempt + 1 == attempts {
                        return Err(msg("Mutter ScreenCast has not delivered a frame yet"));
                    }
                }
            }
        }
        Err(msg("Mutter ScreenCast has not delivered a frame yet"))
    }

    /// Open a **separate** ScreenCast session with Mutter cursor-mode=2
    /// (metadata). Does not alter the shared embedded desk stream (mode 1), so
    /// concurrent legacy clients keep their video cursor and this peer gets
    /// exclusion + `SPA_META_Cursor` without a double pointer.
    ///
    /// Returns `(screencast_session_path, pipewire_node)`. Caller owns Stop.
    pub async fn open_metadata_monitor(&self) -> Result<(String, u32)> {
        open_metadata_monitor(&self.conn, &self.connector).await
    }

    /// Drop the PipeWire consumer and stop the RemoteDesktop session.
    pub async fn stop(&mut self) -> Result<()> {
        self.capture = None;
        self.last = None;
        let session = std::mem::take(&mut self.session);
        if session.is_empty() {
            return Ok(());
        }
        stop_remote_desktop_session(&self.conn, &session).await
    }
}

impl Drop for MutterDesk {
    fn drop(&mut self) {
        self.capture = None;
        self.last = None;
        let session = std::mem::take(&mut self.session);
        if session.is_empty() {
            return;
        }
        stop_remote_desktop_session_blocking(&self.conn, &session);
    }
}

/// Stop a ScreenCast session previously opened for metadata capture.
pub async fn stop_screencast_session(conn: &Connection, session_path: &str) -> Result<()> {
    let session = Proxy::new(conn, MUTTER_SC, session_path, SC_SESSION_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter ScreenCast session: {err}")))?;
    session
        .call::<_, _, ()>("Stop", &())
        .await
        .map_err(|err| msg(format!("ScreenCast.Stop: {err}")))
}

/// Stop a RemoteDesktop session created by this connection, including ones
/// that never reached `Start`. Associated ScreenCast streams stop with it.
pub async fn stop_remote_desktop_session(conn: &Connection, session_path: &str) -> Result<()> {
    let session = Proxy::new(conn, MUTTER_RD, session_path, RD_SESSION_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter RemoteDesktop session: {err}")))?;
    match session.call::<_, _, ()>("Stop", &()).await {
        Ok(()) => Ok(()),
        Err(err)
            if remote_desktop_close_action(Some(&err.to_string()))
                == RemoteDesktopClose::StartThenStop =>
        {
            // Brief Start is required to make Stop succeed on this Mutter.
            let _ = session.call::<_, _, ()>("Start", &()).await;
            session
                .call::<_, _, ()>("Stop", &())
                .await
                .map_err(|err| msg(format!("RemoteDesktop.Stop: {err}")))
        }
        Err(err) => Err(msg(format!("RemoteDesktop.Stop: {err}"))),
    }
}

fn stop_remote_desktop_session_blocking(conn: &Connection, session_path: &str) {
    let conn = conn.clone();
    let session_path = session_path.to_string();
    let join = std::thread::Builder::new()
        .name("mutter-rd-stop".into())
        .spawn(move || {
            let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            let _ = rt.block_on(stop_remote_desktop_session(&conn, &session_path));
        });
    if let Ok(handle) = join {
        let _ = handle.join();
    }
}

/// Dedicated metadata RecordMonitor (Mutter cursor-mode=2). Not bound to the
/// RemoteDesktop input session — video-only exclusion for one WebRTC peer.
/// Records the same `connector` as the shared desk (not always primary).
///
/// Every error/timeout after CreateSession stops the session to avoid leaks.
async fn open_metadata_monitor(conn: &Connection, connector: &str) -> Result<(String, u32)> {
    let screencast = Proxy::new(conn, MUTTER_SC, SC_PATH, SC_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter ScreenCast: {err}")))?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    let screencast_path: OwnedObjectPath = screencast
        .call("CreateSession", &(options,))
        .await
        .map_err(|err| msg(format!("ScreenCast.CreateSession (metadata): {err}")))?;
    let path = screencast_path.to_string();
    let result = open_metadata_monitor_inner(conn, connector, &screencast_path).await;
    if result.is_err() {
        let _ = stop_screencast_session(conn, &path).await;
    }
    result.map(|node| (path, node))
}

async fn open_metadata_monitor_inner(
    conn: &Connection,
    connector: &str,
    screencast_path: &OwnedObjectPath,
) -> Result<u32> {
    let screencast_session =
        Proxy::new(conn, MUTTER_SC, screencast_path.as_str(), SC_SESSION_IFACE)
            .await
            .map_err(|err| msg(format!("Mutter ScreenCast session: {err}")))?;
    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    // Mutter ScreenCast cursor-mode (NOT portal bits): 0=hidden 1=embedded
    // 2=metadata. Metadata excludes the OS pointer from the framebuffer and
    // attaches spa_meta_cursor on PipeWire buffers.
    props.insert("cursor-mode", Value::from(2u32));
    let stream_path: OwnedObjectPath = screencast_session
        .call("RecordMonitor", &(connector, props))
        .await
        .map_err(|err| msg(format!("RecordMonitor({connector}) metadata: {err}")))?;
    let stream = Proxy::new(conn, MUTTER_SC, stream_path.as_str(), SC_STREAM_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter ScreenCast stream: {err}")))?;
    let mut signals = stream
        .receive_signal("PipeWireStreamAdded")
        .await
        .map_err(|err| msg(format!("PipeWireStreamAdded: {err}")))?;
    screencast_session
        .call::<_, _, ()>("Start", &())
        .await
        .map_err(|err| msg(format!("ScreenCast.Start (metadata): {err}")))?;
    let message = tokio::time::timeout(Duration::from_secs(10), signals.next())
        .await
        .map_err(|_| msg("Mutter did not add a metadata PipeWire stream within 10s"))?
        .ok_or_else(|| msg("Mutter closed the metadata ScreenCast stream"))?;
    message
        .body()
        .deserialize()
        .map_err(|err| msg(format!("PipeWireStreamAdded node: {err}")))
}

async fn record_window_frame(
    conn: &Connection,
    query: &str,
    wait_ms: i32,
    max_width: u32,
) -> Result<Frame> {
    let window_id = resolve_mutter_window(conn, query).await?;
    let screencast = Proxy::new(conn, MUTTER_SC, SC_PATH, SC_IFACE)
        .await
        .map_err(|err| {
            msg(format!(
                "window capture capability missing: Mutter ScreenCast unavailable ({err})"
            ))
        })?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    let screencast_path: OwnedObjectPath = screencast
        .call("CreateSession", &(options,))
        .await
        .map_err(|err| msg(format!("ScreenCast.CreateSession (window): {err}")))?;
    let path = screencast_path.to_string();
    match record_window_frame_inner(conn, window_id, &screencast_path, wait_ms, max_width).await {
        Ok(frame) => Ok(frame),
        Err(err) => {
            let _ = stop_screencast_session(conn, &path).await;
            Err(err)
        }
    }
}

async fn record_window_frame_inner(
    conn: &Connection,
    window_id: u64,
    screencast_path: &OwnedObjectPath,
    wait_ms: i32,
    max_width: u32,
) -> Result<Frame> {
    let screencast_session =
        Proxy::new(conn, MUTTER_SC, screencast_path.as_str(), SC_SESSION_IFACE)
            .await
            .map_err(|err| msg(format!("Mutter ScreenCast session: {err}")))?;
    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    props.insert("window-id", Value::U64(window_id));
    // Mutter ScreenCast cursor-mode (NOT portal bits): 0=hidden 1=embedded
    // 2=metadata. Keep embedded by default so old/shared clients retain a
    // visible cursor. Do not flip to hidden/metadata without per-session
    // negotiation (and never via global XFixesHideCursor).
    props.insert("cursor-mode", Value::from(1u32));
    let stream_path: OwnedObjectPath = screencast_session
        .call("RecordWindow", &(props,))
        .await
        .map_err(|err| {
            msg(format!(
                "window capture capability missing: Mutter RecordWindow failed ({err}). \
                 Needs Mutter ScreenCast API ≥ 2; use screen/monitor capture otherwise."
            ))
        })?;
    let stream = Proxy::new(conn, MUTTER_SC, stream_path.as_str(), SC_STREAM_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter ScreenCast stream: {err}")))?;
    let mut signals = stream
        .receive_signal("PipeWireStreamAdded")
        .await
        .map_err(|err| msg(format!("PipeWireStreamAdded: {err}")))?;
    screencast_session
        .call::<_, _, ()>("Start", &())
        .await
        .map_err(|err| msg(format!("ScreenCast.Start (window): {err}")))?;
    let message = tokio::time::timeout(Duration::from_secs(10), signals.next())
        .await
        .map_err(|_| msg("Mutter did not add a PipeWire window stream within 10s"))?
        .ok_or_else(|| msg("Mutter closed the window ScreenCast stream"))?;
    let node: u32 = message
        .body()
        .deserialize()
        .map_err(|err| msg(format!("PipeWireStreamAdded node: {err}")))?;
    let mut capture = PwCapture::open_default(node)?;
    let target = crate::stream::pipewire::resolve_target_width(max_width);
    capture.set_target_width(target);
    let mut last_err = msg("Mutter window ScreenCast has not delivered a frame yet");
    for _ in 0..8 {
        match capture.take(wait_ms) {
            Ok(Some((frame, _))) => {
                let _ = screencast_session.call::<_, _, ()>("Stop", &()).await;
                return Ok(frame);
            }
            Ok(None) => {}
            Err(err) => last_err = err,
        }
    }
    let _ = screencast_session.call::<_, _, ()>("Stop", &()).await;
    Err(last_err)
}

async fn resolve_mutter_window(conn: &Connection, query: &str) -> Result<u64> {
    let windows = list_shell_windows(conn).await?;
    super::shell_windows::match_window_query(query, &windows)
}

async fn list_shell_windows(conn: &Connection) -> Result<Vec<super::shell_windows::ShellWindow>> {
    let introspect = Proxy::new(
        conn,
        "org.gnome.Shell.Introspect",
        "/org/gnome/Shell/Introspect",
        "org.gnome.Shell.Introspect",
    )
    .await
    .map_err(|err| {
        msg(format!(
            "window capture capability missing: GNOME Shell Introspect unreachable ({err})"
        ))
    })?;
    let reply: HashMap<u64, HashMap<String, OwnedValue>> =
        introspect.call("GetWindows", &()).await.map_err(|err| {
            msg(format!(
                "window capture capability missing: Shell.GetWindows failed ({err})"
            ))
        })?;
    let mut out = Vec::with_capacity(reply.len());
    for (id, props) in reply {
        let title = owned_str(props.get("title")).unwrap_or_default();
        let hidden = matches!(
            props.get("is-hidden").map(|value| &**value),
            Some(Value::Bool(true))
        );
        out.push(super::shell_windows::ShellWindow { id, title, hidden });
    }
    Ok(out)
}

fn owned_str(value: Option<&OwnedValue>) -> Option<String> {
    match value.map(|value| &**value) {
        Some(Value::Str(text)) => Some(text.to_string()),
        _ => None,
    }
}

async fn open_screencast(conn: &Connection, connector: &str) -> Result<(String, String, u32)> {
    let remote = Proxy::new(conn, MUTTER_RD, RD_PATH, RD_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter RemoteDesktop: {err}")))?;
    let remote_path: OwnedObjectPath = remote
        .call("CreateSession", &())
        .await
        .map_err(|err| msg(format!("RemoteDesktop.CreateSession: {err}")))?;
    let remote_path_str = remote_path.to_string();
    match open_screencast_inner(conn, connector, &remote_path).await {
        Ok((stream_path, node)) => Ok((remote_path_str, stream_path, node)),
        Err(err) => {
            let _ = stop_remote_desktop_session(conn, &remote_path_str).await;
            Err(err)
        }
    }
}

async fn open_screencast_inner(
    conn: &Connection,
    connector: &str,
    remote_path: &OwnedObjectPath,
) -> Result<(String, u32)> {
    let remote_session = Proxy::new(conn, MUTTER_RD, remote_path.as_str(), RD_SESSION_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter RemoteDesktop session: {err}")))?;
    let session_id: String = remote_session
        .get_property("SessionId")
        .await
        .map_err(|err| msg(format!("RemoteDesktop SessionId: {err}")))?;

    let screencast = Proxy::new(conn, MUTTER_SC, SC_PATH, SC_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter ScreenCast: {err}")))?;
    let mut options: HashMap<&str, Value<'_>> = HashMap::new();
    options.insert(
        "remote-desktop-session-id",
        Value::from(session_id.as_str()),
    );
    let screencast_path: OwnedObjectPath = screencast
        .call("CreateSession", &(options,))
        .await
        .map_err(|err| msg(format!("ScreenCast.CreateSession: {err}")))?;
    let sc_path_str = screencast_path.to_string();
    match attach_screencast_stream(conn, connector, &remote_session, &screencast_path).await {
        Ok(out) => Ok(out),
        Err(err) => {
            if let Some(path) =
                super::mutter_session::screencast_path_to_stop_on_error(Some(&sc_path_str))
            {
                let _ = stop_screencast_session(conn, path).await;
            }
            Err(err)
        }
    }
}

async fn attach_screencast_stream(
    conn: &Connection,
    connector: &str,
    remote_session: &Proxy<'_>,
    screencast_path: &OwnedObjectPath,
) -> Result<(String, u32)> {
    let screencast_session =
        Proxy::new(conn, MUTTER_SC, screencast_path.as_str(), SC_SESSION_IFACE)
            .await
            .map_err(|err| msg(format!("Mutter ScreenCast session: {err}")))?;
    let mut props: HashMap<&str, Value<'_>> = HashMap::new();
    // Embedded (1) by default — see RecordWindow note above.
    props.insert("cursor-mode", Value::from(1u32));
    let stream_path: OwnedObjectPath = screencast_session
        .call("RecordMonitor", &(connector, props))
        .await
        .map_err(|err| msg(format!("RecordMonitor({connector}): {err}")))?;
    let stream = Proxy::new(conn, MUTTER_SC, stream_path.as_str(), SC_STREAM_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter ScreenCast stream: {err}")))?;
    let mut signals = stream
        .receive_signal("PipeWireStreamAdded")
        .await
        .map_err(|err| msg(format!("PipeWireStreamAdded: {err}")))?;

    remote_session
        .call::<_, _, ()>("Start", &())
        .await
        .map_err(|err| msg(format!("RemoteDesktop.Start: {err}")))?;
    let message = tokio::time::timeout(Duration::from_secs(10), signals.next())
        .await
        .map_err(|_| msg("Mutter did not add a PipeWire stream within 10s"))?
        .ok_or_else(|| msg("Mutter closed the ScreenCast stream"))?;
    let node: u32 = message
        .body()
        .deserialize()
        .map_err(|err| msg(format!("PipeWireStreamAdded node: {err}")))?;
    Ok((stream_path.to_string(), node))
}

async fn display_monitors(conn: &Connection) -> Result<Vec<MonitorInfo>> {
    let display = Proxy::new(conn, MUTTER_DISPLAY, DISPLAY_PATH, DISPLAY_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter DisplayConfig: {err}")))?;
    let reply = display
        .call_method("GetCurrentState", &())
        .await
        .map_err(|err| msg(format!("DisplayConfig.GetCurrentState: {err}")))?;
    let body = reply.body();
    let (_serial, monitors, logicals, _props): (
        u32,
        Vec<MonitorState>,
        Vec<LogicalState>,
        HashMap<String, OwnedValue>,
    ) = body
        .deserialize()
        .map_err(|err| msg(format!("DisplayConfig state: {err}")))?;

    let mut out = Vec::new();
    for (index, (x, y, _scale, _transform, primary, specs, _props)) in logicals.iter().enumerate() {
        let Some(spec) = specs.first() else {
            continue;
        };
        let (width, height) = monitors
            .iter()
            .find(|monitor| monitor.0 .0 == spec.0)
            .and_then(current_mode)
            .unwrap_or((0, 0));
        out.push(MonitorInfo {
            index: index as u32,
            name: spec.0.clone(),
            x: *x,
            y: *y,
            width,
            height,
            primary: *primary,
        });
    }
    if out.is_empty() {
        for (index, monitor) in monitors.iter().enumerate() {
            let (width, height) = current_mode(monitor).unwrap_or((0, 0));
            out.push(MonitorInfo {
                index: index as u32,
                name: monitor.0 .0.clone(),
                x: 0,
                y: 0,
                width,
                height,
                primary: index == 0,
            });
        }
    }
    Ok(out)
}

fn current_mode(monitor: &MonitorState) -> Option<(u32, u32)> {
    for (_name, width, height, _rate, _scale, _scales, props) in &monitor.1 {
        if matches!(
            props.get("is-current").map(|value| &**value),
            Some(Value::Bool(true))
        ) {
            return Some((*width as u32, *height as u32));
        }
    }
    monitor
        .1
        .first()
        .map(|(_name, width, height, ..)| (*width as u32, *height as u32))
}

async fn remote_session<'a>(conn: &'a Connection, session: &'a str) -> Result<Proxy<'a>> {
    Proxy::new(conn, MUTTER_RD, session, RD_SESSION_IFACE)
        .await
        .map_err(|err| msg(format!("Mutter RemoteDesktop session: {err}")))
}

pub async fn notify_motion(
    conn: &Connection,
    session: &str,
    stream: &str,
    x: i32,
    y: i32,
) -> Result<()> {
    remote_session(conn, session)
        .await?
        .call::<_, _, ()>("NotifyPointerMotionAbsolute", &(stream, x as f64, y as f64))
        .await
        .map_err(|err| msg(format!("pointer motion: {err}")))
}

pub async fn notify_button(
    conn: &Connection,
    session: &str,
    button: u32,
    down: bool,
) -> Result<()> {
    remote_session(conn, session)
        .await?
        .call::<_, _, ()>("NotifyPointerButton", &(button as i32, down))
        .await
        .map_err(|err| msg(format!("pointer button: {err}")))
}

pub async fn notify_axis(conn: &Connection, session: &str, dx: f64, dy: f64) -> Result<()> {
    remote_session(conn, session)
        .await?
        .call::<_, _, ()>("NotifyPointerAxis", &(dx, dy, 0u32))
        .await
        .map_err(|err| msg(format!("pointer axis: {err}")))
}

pub async fn notify_keysym(
    conn: &Connection,
    session: &str,
    keysym: u32,
    down: bool,
) -> Result<()> {
    remote_session(conn, session)
        .await?
        .call::<_, _, ()>("NotifyKeyboardKeysym", &(keysym, down))
        .await
        .map_err(|err| msg(format!("keysym: {err}")))
}
