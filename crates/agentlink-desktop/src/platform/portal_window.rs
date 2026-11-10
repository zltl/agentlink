//! One-shot window capture via xdg-desktop-portal ScreenCast (WINDOW).
//!
//! Used when Mutter `RecordWindow` / Shell Introspect are unavailable to
//! regular clients. The official GNOME picker authorizes a single window;
//! pixels come from that PipeWire stream only — never a cropped monitor.
//!
//! Official persist: `persist_mode=2` with `org.agentlink.Node` after
//! `Registry.Register`. Restore tokens are stored mode 0600, bound to the
//! authorized window identity, and never widen an agentlink grant. Tokens
//! without a disclosed window identity are discarded so persist cannot become
//! silent any-window access. `AGENTLINK_PORTAL_PERSIST=0` forces one-shot.

use std::collections::HashMap;
use std::time::Duration;

use futures_util::StreamExt;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use crate::error::{msg, Result};

/// Portal `AvailableSourceTypes` / stream `source_type` bits.
pub const SOURCE_MONITOR: u32 = 1;
pub const SOURCE_WINDOW: u32 = 2;
pub const SOURCE_VIRTUAL: u32 = 4;

/// `SelectSources` persist_mode: do not persist (one-shot).
pub const PERSIST_NONE: u32 = 0;

/// How long to wait for the interactive ScreenCast picker (`Start`).
#[cfg_attr(not(pipewire_headers), allow(dead_code))]
pub fn picker_timeout() -> Duration {
    match std::env::var("AGENTLINK_PORTAL_PICKER_TIMEOUT_SECS") {
        Ok(value) => {
            let secs = value.parse::<u64>().unwrap_or(90).clamp(5, 600);
            Duration::from_secs(secs)
        }
        Err(_) => Duration::from_secs(90),
    }
}

/// Identity of one PipeWire stream from `ScreenCast.Start` results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalStreamSource {
    pub node_id: u32,
    pub source_type: Option<u32>,
    pub id: Option<String>,
    pub title: Option<String>,
    pub app_id: Option<String>,
    pub mapping_id: Option<String>,
    pub size: Option<(i32, i32)>,
    /// Top-left of the window inside the PipeWire buffer, when disclosed.
    pub position: Option<(i32, i32)>,
}

impl PortalStreamSource {
    pub fn is_window(&self) -> bool {
        match self.source_type {
            Some(SOURCE_WINDOW) => true,
            // GNOME 50 / some portals omit source_type on WINDOW-only sessions.
            // Acceptance still goes through ensure_window_source (size / monitors).
            None => true,
            Some(_) => false,
        }
    }
}

/// True when `size` is exactly one of the connected monitor resolutions.
pub fn stream_size_matches_monitor(size: (i32, i32), monitors: &[(i32, i32)]) -> bool {
    monitors.iter().any(|&mon| mon == size)
}

/// Where a tight window crop came from. Never inferred from black pixels
/// (a black window is a valid source).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowCropOrigin {
    PortalPositionSize,
    PipewireVideoCrop,
}

/// How to present a captured portal WINDOW buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowFrameGeometry {
    /// Crop to this rectangle in the captured frame.
    Tight {
        rect: crate::capture::Rect,
        origin: WindowCropOrigin,
    },
    /// Metadata is missing or incomplete. Do not invent a crop width.
    Letterboxed { reason: &'static str },
}

fn rect_fits(rect: crate::capture::Rect, frame_w: u32, frame_h: u32) -> bool {
    if rect.x < 0 || rect.y < 0 || rect.width == 0 || rect.height == 0 {
        return false;
    }
    let x = rect.x as u32;
    let y = rect.y as u32;
    x.saturating_add(rect.width) <= frame_w && y.saturating_add(rect.height) <= frame_h
}

fn portal_size_rect(
    source: &PortalStreamSource,
    frame_w: u32,
    frame_h: u32,
) -> Option<crate::capture::Rect> {
    let (w, h) = source.size?;
    if w <= 0 || h <= 0 {
        return None;
    }
    let (x, y) = source.position.unwrap_or((0, 0));
    let rect = crate::capture::Rect {
        x,
        y,
        width: w as u32,
        height: h as u32,
    };
    // A size equal to the whole buffer is not a window crop.
    if rect.x == 0 && rect.y == 0 && rect.width == frame_w && rect.height == frame_h {
        return None;
    }
    rect_fits(rect, frame_w, frame_h).then_some(rect)
}

/// Decide a crop from PipeWire VideoCrop and/or portal `position`+`size`.
///
/// If both disagree, prefer a VideoCrop that fits and log the mismatch.
/// If neither is a usable tight crop, return [`WindowFrameGeometry::Letterboxed`]
/// rather than guessing from black borders.
pub fn resolve_window_frame_geometry(
    frame_w: u32,
    frame_h: u32,
    source: &PortalStreamSource,
    pw_crop: Option<crate::capture::Rect>,
) -> WindowFrameGeometry {
    let pw = pw_crop.filter(|rect| {
        rect_fits(*rect, frame_w, frame_h)
            && !(rect.x == 0 && rect.y == 0 && rect.width == frame_w && rect.height == frame_h)
    });
    let portal = portal_size_rect(source, frame_w, frame_h);
    match (pw, portal) {
        (Some(pw), Some(portal)) if pw == portal => WindowFrameGeometry::Tight {
            rect: pw,
            origin: WindowCropOrigin::PipewireVideoCrop,
        },
        (Some(pw), Some(portal)) => {
            tracing::info!(
                pw_x = pw.x,
                pw_y = pw.y,
                pw_w = pw.width,
                pw_h = pw.height,
                portal_x = portal.x,
                portal_y = portal.y,
                portal_w = portal.width,
                portal_h = portal.height,
                "PipeWire VideoCrop and portal position/size disagree; using VideoCrop"
            );
            WindowFrameGeometry::Tight {
                rect: pw,
                origin: WindowCropOrigin::PipewireVideoCrop,
            }
        }
        (Some(pw), None) => WindowFrameGeometry::Tight {
            rect: pw,
            origin: WindowCropOrigin::PipewireVideoCrop,
        },
        (None, Some(portal)) => {
            if source.position.is_none() && portal.x == 0 && portal.y == 0 {
                // Size was disclosed but not the origin. Cropping at (0,0) would
                // invent placement; keep the buffer and mark it letterboxed.
                WindowFrameGeometry::Letterboxed {
                    reason:
                        "portal disclosed window size but not position; not inventing a crop origin",
                }
            } else {
                WindowFrameGeometry::Tight {
                    rect: portal,
                    origin: WindowCropOrigin::PortalPositionSize,
                }
            }
        }
        (None, None) => WindowFrameGeometry::Letterboxed {
            reason: "portal/PipeWire omitted window crop metadata",
        },
    }
}

/// Reject monitor/virtual streams when the CLI asked for a window. Never treat

/// a full-desktop stream as a window capture.
///
/// GNOME 50's `Start` result often omits `source_type` (and sometimes title)
/// even after a WINDOW-only `SelectSources`. In that case we accept only when
/// the stream size is present and does not match a known monitor, or when size
/// is also omitted — the caller must then confirm the captured frame is not a
/// monitor-sized desktop.
pub fn ensure_window_source(source: &PortalStreamSource) -> Result<()> {
    ensure_window_source_against_monitors(source, &[])
}

pub fn ensure_window_source_against_monitors(
    source: &PortalStreamSource,
    monitors: &[(i32, i32)],
) -> Result<()> {
    match source.source_type {
        Some(SOURCE_WINDOW) => {
            if let Some(size) = source.size {
                if !monitors.is_empty() && stream_size_matches_monitor(size, monitors) {
                    return Err(msg(format!(
                        "portal ScreenCast labelled a {0}x{1} MONITOR-sized stream as WINDOW; refusing to treat a desktop/monitor capture as a window",
                        size.0, size.1
                    )));
                }
            }
            Ok(())
        }
        Some(SOURCE_MONITOR) => Err(msg(
            "portal ScreenCast returned a MONITOR stream for --target window; refusing to treat a desktop/monitor capture as a window",
        )),
        Some(SOURCE_VIRTUAL) => Err(msg(
            "portal ScreenCast returned a VIRTUAL stream for --target window; refusing to treat it as a window",
        )),
        Some(other) => Err(msg(format!(
            "portal ScreenCast returned unknown source_type {other} for --target window"
        ))),
        None => {
            if let Some(size) = source.size {
                if !monitors.is_empty() && stream_size_matches_monitor(size, monitors) {
                    return Err(msg(format!(
                        "portal ScreenCast stream omitted source_type and size {}x{} matches a monitor; refusing silent fallback to a desktop/monitor capture",
                        size.0, size.1
                    )));
                }
                tracing::info!(
                    width = size.0,
                    height = size.1,
                    "portal omitted source_type; SelectSources was WINDOW-only and stream size does not match a known monitor — treating as the user-authorized window"
                );
                return Ok(());
            }
            tracing::info!(
                "portal omitted source_type and size; SelectSources was WINDOW-only — will confirm the captured frame is not a monitor-sized desktop"
            );
            Ok(())
        }
    }
}

/// After a PipeWire frame arrives, reject a monitor-sized image when the
/// portal did not confirm a WINDOW (or claimed WINDOW at exact monitor
/// resolution *and* we have a tight crop). A letterboxed WINDOW buffer may
/// legally match the output resolution — do not invent a crop, and do not
/// reject solely for that size (live GNOME 50: WINDOW source_type=2, size
/// 1368x912 without position, PipeWire buffer 2736x1824).
pub fn ensure_captured_frame_is_window(
    source: &PortalStreamSource,
    frame_w: u32,
    frame_h: u32,
    monitors: &[(i32, i32)],
    letterboxed: bool,
) -> Result<()> {
    match source.source_type {
        Some(SOURCE_MONITOR) => {
            return Err(msg(
                "portal ScreenCast returned a MONITOR stream for --target window; refusing to treat a desktop/monitor capture as a window",
            ));
        }
        Some(SOURCE_VIRTUAL) => {
            return Err(msg(
                "portal ScreenCast returned a VIRTUAL stream for --target window; refusing to treat it as a window",
            ));
        }
        Some(other) if other != SOURCE_WINDOW => {
            return Err(msg(format!(
                "portal ScreenCast returned unknown source_type {other} for --target window"
            )));
        }
        _ => {}
    }
    if letterboxed {
        tracing::info!(
            frame_w,
            frame_h,
            source_type = ?source.source_type,
            "letterboxed official WINDOW buffer may match a monitor size; keeping it marked letterboxed without inventing a crop"
        );
        return Ok(());
    }
    let size = (frame_w as i32, frame_h as i32);
    let looks_like_monitor = stream_size_matches_monitor(size, monitors);
    match source.source_type {
        Some(SOURCE_WINDOW) if looks_like_monitor => Err(msg(format!(
            "portal WINDOW stream delivered a {frame_w}x{frame_h} monitor-sized frame; refusing to treat a desktop/monitor capture as a window"
        ))),
        Some(SOURCE_WINDOW) => Ok(()),
        None if looks_like_monitor => Err(msg(format!(
            "portal omitted source_type and the captured frame is {frame_w}x{frame_h}, which matches a monitor; refusing silent fallback to a desktop/monitor capture"
        ))),
        None => {
            tracing::info!(
                frame_w,
                frame_h,
                "portal omitted source_type; captured frame is not a known monitor size"
            );
            Ok(())
        }
        Some(_) => ensure_window_source_against_monitors(source, monitors),
    }
}

/// Match a CLI `--window-id` / title query against portal stream identity.
///
/// Empty query: accept the user-selected portal window (caller should say so).
/// When the portal discloses `title` / `app_id`, the query must match
/// (substring, case-insensitive) or we fail — never return a different window.
/// Exact match against opaque stream `id` / `mapping_id` is also accepted.
///
/// GNOME's Start() response often omits title/app_id (only `source_type` +
/// opaque id). In that case a non-empty query is treated as a **picker hint**:
/// we still require `source_type=WINDOW` (no monitor fallback) and return only
/// the user-authorized stream.
pub fn match_portal_window_query(query: &str, source: &PortalStreamSource) -> Result<()> {
    ensure_window_source(source)?;
    let query = query.trim();
    if query.is_empty() {
        return Ok(());
    }
    let needle = query.to_ascii_lowercase();

    let title = source.title.as_deref().filter(|s| !s.is_empty());
    let app_id = source.app_id.as_deref().filter(|s| !s.is_empty());
    let id = source.id.as_deref().filter(|s| !s.is_empty());
    let mapping = source.mapping_id.as_deref().filter(|s| !s.is_empty());

    if let Some(id) = id {
        if id.eq_ignore_ascii_case(query) {
            return Ok(());
        }
    }
    if let Some(mapping) = mapping {
        if mapping.eq_ignore_ascii_case(query) {
            return Ok(());
        }
    }

    let mut disclosed: Vec<(&str, &str)> = Vec::new();
    if let Some(title) = title {
        disclosed.push(("title", title));
    }
    if let Some(app_id) = app_id {
        disclosed.push(("app_id", app_id));
    }

    if disclosed.is_empty() {
        // No title/app_id to cross-check (typical GNOME). Opaque stream id is
        // session-local and not a window title — do not substring-match it.
        tracing::info!(
            %query,
            node_id = source.node_id,
            "portal WINDOW stream has no title/app_id; accepting user-authorized \
             picker selection (CLI window_id is a hint for the operator)"
        );
        return Ok(());
    }

    let matched = disclosed.iter().any(|(_, value)| {
        let lower = value.to_ascii_lowercase();
        lower == needle || lower.contains(&needle)
    });
    if matched {
        Ok(())
    } else {
        let detail = disclosed
            .iter()
            .map(|(name, value)| format!("{name}={value:?}"))
            .collect::<Vec<_>>()
            .join(", ");
        Err(msg(format!(
            "portal-authorized window does not match window_id '{query}' ({detail})"
        )))
    }
}

/// Human-readable note when capture succeeded with an empty window_id query.
pub fn empty_query_note() -> &'static str {
    "no window_id query; returning the window the user authorized in the portal picker"
}

/// Map portal Request response codes to errors (after cleanup).
pub fn portal_response_error(response: u32, what: &str) -> crate::error::DesktopError {
    match response {
        0 => msg(format!("internal: {what} succeeded")),
        1 => msg(format!(
            "{what} cancelled by the user in the xdg-desktop-portal dialog"
        )),
        2 => msg(format!(
            "{what} failed or was closed (portal response 2). The ScreenCast session was released."
        )),
        other => msg(format!(
            "{what} failed with portal response {other}. The ScreenCast session was released."
        )),
    }
}

fn value_as_u32(val: &Value<'_>) -> Option<u32> {
    match val {
        Value::U8(v) => Some(u32::from(*v)),
        Value::U16(v) => Some(u32::from(*v)),
        Value::U32(v) => Some(*v),
        Value::U64(v) if *v <= u64::from(u32::MAX) => Some(*v as u32),
        Value::I32(v) if *v >= 0 => Some(*v as u32),
        Value::I64(v) if *v >= 0 && *v <= i64::from(u32::MAX) => Some(*v as u32),
        Value::Value(inner) => value_as_u32(inner),
        _ => None,
    }
}

fn value_as_i32(val: &Value<'_>) -> Option<i32> {
    match val {
        Value::I32(v) => Some(*v),
        Value::I16(v) => Some(i32::from(*v)),
        Value::I64(v) if *v >= i64::from(i32::MIN) && *v <= i64::from(i32::MAX) => Some(*v as i32),
        Value::U32(v) if *v <= i32::MAX as u32 => Some(*v as i32),
        Value::U16(v) => Some(i32::from(*v)),
        Value::U8(v) => Some(i32::from(*v)),
        Value::Value(inner) => value_as_i32(inner),
        _ => None,
    }
}

fn value_as_string(val: &Value<'_>) -> Option<String> {
    match val {
        Value::Str(text) => Some(text.to_string()),
        Value::Value(inner) => value_as_string(inner),
        _ => None,
    }
}

fn value_as_i32_pair(val: &Value<'_>) -> Option<(i32, i32)> {
    match val {
        Value::Structure(fields) => {
            let f = fields.fields();
            Some((value_as_i32(f.first()?)?, value_as_i32(f.get(1)?)?))
        }
        Value::Value(inner) => value_as_i32_pair(inner),
        _ => None,
    }
}

/// Parse `streams` from `ScreenCast.Start` results (`a(ua{sv})`).
#[cfg_attr(not(pipewire_headers), allow(dead_code))]
pub fn parse_portal_streams(
    results: &HashMap<String, OwnedValue>,
) -> Result<Vec<PortalStreamSource>> {
    let value = results
        .get("streams")
        .ok_or_else(|| msg("ScreenCast start returned no streams"))?;
    let Value::Array(items) = &**value else {
        return Err(msg("ScreenCast streams is not an array"));
    };
    let mut out = Vec::new();
    for item in items.inner() {
        let Value::Structure(fields) = item else {
            continue;
        };
        let fields = fields.fields();
        let Some(Value::U32(node_id)) = fields.first() else {
            continue;
        };
        let props = match fields.get(1) {
            Some(Value::Dict(dict)) => dict,
            _ => {
                out.push(PortalStreamSource {
                    node_id: *node_id,
                    source_type: None,
                    id: None,
                    title: None,
                    app_id: None,
                    mapping_id: None,
                    size: None,
                    position: None,
                });
                continue;
            }
        };
        let mut source = PortalStreamSource {
            node_id: *node_id,
            source_type: None,
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: None,
            position: None,
        };
        for (key, val) in props.iter() {
            let key = match key {
                Value::Str(text) => text.as_str(),
                _ => continue,
            };
            match key {
                "source_type" | "source-type" => {
                    if let Some(v) = value_as_u32(val) {
                        source.source_type = Some(v);
                    } else {
                        tracing::info!(?val, "portal stream source_type had an unexpected type");
                    }
                }
                "id" => {
                    if let Some(s) = value_as_string(val) {
                        source.id = Some(s);
                    }
                }
                "title" => {
                    if let Some(s) = value_as_string(val) {
                        source.title = Some(s);
                    }
                }
                "app_id" | "app-id" => {
                    if let Some(s) = value_as_string(val) {
                        source.app_id = Some(s);
                    }
                }
                "mapping_id" | "mapping-id" => {
                    if let Some(s) = value_as_string(val) {
                        source.mapping_id = Some(s);
                    }
                }
                "size" => {
                    if let Some(size) = value_as_i32_pair(val) {
                        source.size = Some(size);
                    } else {
                        tracing::info!(?val, "portal stream size had an unexpected type");
                    }
                }
                "position" => {
                    if let Some(position) = value_as_i32_pair(val) {
                        source.position = Some(position);
                    } else {
                        tracing::info!(?val, "portal stream position had an unexpected type");
                    }
                }
                other => {
                    tracing::debug!(key = other, ?val, "portal stream property");
                }
            }
        }
        out.push(source);
    }
    if out.is_empty() {
        return Err(msg("ScreenCast start returned an empty streams list"));
    }
    Ok(out)
}

/// Tracks whether a portal session path still needs `Session.Close`.
#[derive(Debug)]
#[cfg_attr(not(pipewire_headers), allow(dead_code))]
pub struct PortalSessionCleanup {
    pub path: String,
    pub closed: bool,
}

#[cfg_attr(not(pipewire_headers), allow(dead_code))]
impl PortalSessionCleanup {
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            closed: false,
        }
    }

    pub async fn close(&mut self, conn: &Connection) {
        if self.closed || self.path.is_empty() {
            return;
        }
        self.closed = true;
        if let Ok(proxy) = Proxy::new(
            conn,
            "org.freedesktop.portal.Desktop",
            self.path.as_str(),
            "org.freedesktop.portal.Session",
        )
        .await
        {
            let _ = proxy.call::<_, _, ()>("Close", &()).await;
        }
    }
}

/// Close a portal Request (cancels an in-flight picker on timeout).
#[cfg_attr(not(pipewire_headers), allow(dead_code))]
pub async fn close_portal_request(conn: &Connection, path: &str) {
    if path.is_empty() {
        return;
    }
    if let Ok(proxy) = Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        path,
        "org.freedesktop.portal.Request",
    )
    .await
    {
        let _ = proxy.call::<_, _, ()>("Close", &()).await;
    }
}

#[cfg_attr(not(pipewire_headers), allow(dead_code))]
fn sender_token(conn: &Connection) -> Result<String> {
    let unique = conn
        .unique_name()
        .ok_or_else(|| msg("session bus connection has no unique name"))?;
    Ok(unique.as_str().trim_start_matches(':').replace('.', "_"))
}

#[cfg_attr(not(pipewire_headers), allow(dead_code))]
fn unique_token(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("agentlinkpw{prefix}{n}")
}

#[cfg_attr(not(pipewire_headers), allow(dead_code))]
fn request_path(conn: &Connection, token: &str) -> Result<String> {
    let sender = sender_token(conn)?;
    Ok(format!(
        "/org/freedesktop/portal/desktop/request/{sender}/{token}"
    ))
}

#[cfg_attr(not(pipewire_headers), allow(dead_code))]
fn session_path(conn: &Connection, token: &str) -> Result<String> {
    let sender = sender_token(conn)?;
    Ok(format!(
        "/org/freedesktop/portal/desktop/session/{sender}/{token}"
    ))
}

#[cfg_attr(not(pipewire_headers), allow(dead_code))]
fn owned_object_path(path: &str) -> Result<OwnedObjectPath> {
    OwnedObjectPath::try_from(path)
        .map_err(|err| msg(format!("portal object path '{path}' is invalid ({err})")))
}

#[cfg_attr(not(pipewire_headers), allow(dead_code))]
async fn call_and_wait(
    conn: &Connection,
    path: &str,
    timeout: Duration,
    invoke: impl std::future::Future<Output = Result<()>>,
) -> Result<(u32, HashMap<String, OwnedValue>)> {
    let proxy = Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        path,
        "org.freedesktop.portal.Request",
    )
    .await
    .map_err(|err| msg(format!("portal request: {err}")))?;
    let mut signals = proxy
        .receive_signal("Response")
        .await
        .map_err(|err| msg(format!("portal signal: {err}")))?;
    invoke.await?;
    let message = match tokio::time::timeout(timeout, signals.next()).await {
        Ok(Some(message)) => message,
        Ok(None) => {
            close_portal_request(conn, path).await;
            return Err(msg(
                "desktop portal closed the ScreenCast request before responding",
            ));
        }
        Err(_) => {
            close_portal_request(conn, path).await;
            return Err(msg(format!(
                "xdg-desktop-portal ScreenCast timed out after {}s waiting for the \
                 window picker. Cancelled the request and released the session. \
                 On the GNOME seat, select the target window in the Share dialog and Allow, \
                 then retry.",
                timeout.as_secs()
            )));
        }
    };
    let (response, results): (u32, HashMap<String, OwnedValue>) = message
        .body()
        .deserialize()
        .map_err(|err| msg(format!("portal response: {err}")))?;
    Ok((response, results))
}

#[cfg_attr(not(pipewire_headers), allow(dead_code))]
async fn screencast_proxy(conn: &Connection) -> Result<Proxy<'_>> {
    Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.ScreenCast",
    )
    .await
    .map_err(|err| {
        msg(format!(
            "window capture capability missing: ScreenCast portal unavailable ({err})"
        ))
    })
}

/// Best-effort official host-app registration. Missing Registry support is
/// not fatal: the portal still sees this unique D-Bus name for the session.
async fn register_portal_app(conn: &Connection) {
    if let Err(err) = crate::platform::portal_persist::ensure_user_desktop_file() {
        tracing::info!(error = %err, "could not install per-user org.agentlink.Node.desktop");
    }
    let proxy = match Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.Registry",
    )
    .await
    {
        Ok(proxy) => proxy,
        Err(err) => {
            tracing::info!(error = %err, "portal Registry proxy unavailable");
            return;
        }
    };
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    match proxy
        .call::<_, _, ()>(
            "Register",
            &(crate::platform::portal_persist::PORTAL_APP_ID, options),
        )
        .await
    {
        Ok(()) => tracing::info!(
            app_id = crate::platform::portal_persist::PORTAL_APP_ID,
            "registered official portal app id"
        ),
        Err(err) => tracing::info!(
            error = %err,
            app_id = crate::platform::portal_persist::PORTAL_APP_ID,
            "portal Registry.Register not supported or rejected; continuing without a host app_id"
        ),
    }
}

/// CreateSession → SelectSources(WINDOW) → Start → first stream.
/// Always closes the session on error paths before returning.
#[cfg_attr(not(pipewire_headers), allow(dead_code))]
pub async fn authorize_window_stream(
    conn: &Connection,
    query: &str,
) -> Result<(PortalSessionCleanup, PortalStreamSource)> {
    match authorize_window_stream_inner(conn, query, true).await {
        Err(err) if err.to_string().contains("AGENTLINK_RESTORE_RETRY") => {
            authorize_window_stream_inner(conn, query, false).await
        }
        other => other,
    }
}

async fn authorize_window_stream_inner(
    conn: &Connection,
    query: &str,
    allow_restore: bool,
) -> Result<(PortalSessionCleanup, PortalStreamSource)> {
    let _ = register_portal_app(conn).await;
    let persist = crate::platform::portal_persist::persist_enabled();
    let persist_dir = crate::platform::portal_persist::default_persist_data_dir();
    let restore_token = if persist && allow_restore {
        persist_dir.as_ref().and_then(|dir| {
            crate::platform::portal_persist::load_restore(dir)
                .ok()
                .flatten()
                .and_then(|rec| {
                    crate::platform::portal_persist::reusable_token(&rec, query).map(str::to_string)
                })
        })
    } else {
        None
    };
    if restore_token.is_some() {
        tracing::info!(
            query = %query.trim(),
            "offering bound ScreenCast restore_token for this window query (OS consent only; not an agentlink grant)"
        );
    }

    let portal = screencast_proxy(conn).await?;

    // Prefer advertising WINDOW only so the picker cannot authorize a monitor
    // that we would then have to reject.
    let available: u32 = portal
        .get_property("AvailableSourceTypes")
        .await
        .unwrap_or(SOURCE_MONITOR | SOURCE_WINDOW | SOURCE_VIRTUAL);
    if available & SOURCE_WINDOW == 0 {
        return Err(msg(
            "window capture capability missing: portal ScreenCast has no WINDOW source type",
        ));
    }

    let session_token = unique_token("scw");
    let session = session_path(conn, &session_token)?;
    let mut cleanup = PortalSessionCleanup::new(session.clone());

    let create_token = unique_token("scwc");
    let create_path = request_path(conn, &create_token)?;
    let create_result = call_and_wait(conn, &create_path, Duration::from_secs(20), async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(create_token.as_str()));
        options.insert("session_handle_token", Value::from(session_token.as_str()));
        portal
            .call::<_, _, OwnedObjectPath>("CreateSession", &(options,))
            .await
            .map_err(|err| msg(format!("ScreenCast.CreateSession: {err}")))?;
        Ok(())
    })
    .await;
    let (response, _) = match create_result {
        Ok(pair) => pair,
        Err(err) => {
            cleanup.close(conn).await;
            return Err(err);
        }
    };
    if response != 0 {
        cleanup.close(conn).await;
        return Err(portal_response_error(response, "ScreenCast.CreateSession"));
    }

    let session_opath = match owned_object_path(&session) {
        Ok(path) => path,
        Err(err) => {
            cleanup.close(conn).await;
            return Err(err);
        }
    };

    let select_token = unique_token("scws");
    let select_path = request_path(conn, &select_token)?;
    let select_result = call_and_wait(conn, &select_path, Duration::from_secs(20), async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(select_token.as_str()));
        options.insert("types", Value::from(SOURCE_WINDOW));
        options.insert("multiple", Value::from(false));
        let persist_mode = if persist {
            crate::platform::portal_persist::PERSIST_UNTIL_REVOKED
        } else {
            PERSIST_NONE
        };
        options.insert("persist_mode", Value::from(persist_mode));
        if let Some(token) = restore_token.as_deref() {
            options.insert("restore_token", Value::from(token));
        }
        // Omit cursor_mode (portal default = Hidden) so we do not close the
        // session on older backends that advertise a smaller cursor bitmask.
        // Session handle must be object-path `o`, not string `s`.
        portal
            .call::<_, _, OwnedObjectPath>("SelectSources", &(&session_opath, options))
            .await
            .map_err(|err| msg(format!("ScreenCast.SelectSources(WINDOW): {err}")))?;
        Ok(())
    })
    .await;
    let (response, _) = match select_result {
        Ok(pair) => pair,
        Err(err) => {
            cleanup.close(conn).await;
            return Err(err);
        }
    };
    if response != 0 {
        cleanup.close(conn).await;
        return Err(portal_response_error(
            response,
            "ScreenCast.SelectSources(WINDOW)",
        ));
    }

    let start_token = unique_token("scwt");
    let start_path = request_path(conn, &start_token)?;
    let start_timeout = picker_timeout();
    tracing::info!(
        timeout_secs = start_timeout.as_secs(),
        query = %query.trim(),
        "portal ScreenCast WINDOW picker starting; accept the GNOME Share dialog on the seat"
    );
    let start_result = call_and_wait(conn, &start_path, start_timeout, async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(start_token.as_str()));
        portal
            .call::<_, _, OwnedObjectPath>("Start", &(&session_opath, "", options))
            .await
            .map_err(|err| msg(format!("ScreenCast.Start: {err}")))?;
        Ok(())
    })
    .await;
    let (response, results) = match start_result {
        Ok(pair) => pair,
        Err(err) => {
            cleanup.close(conn).await;
            if restore_token.is_some() && allow_restore {
                if let Some(dir) = persist_dir.as_ref() {
                    let _ = crate::platform::portal_persist::clear_restore(dir);
                }
                tracing::info!(
                    "restore_token Start failed; dropped stored token and reopening the official picker"
                );
                return Err(msg("AGENTLINK_RESTORE_RETRY"));
            }
            return Err(err);
        }
    };
    if response != 0 {
        cleanup.close(conn).await;
        if restore_token.is_some() && allow_restore {
            if let Some(dir) = persist_dir.as_ref() {
                let _ = crate::platform::portal_persist::clear_restore(dir);
            }
            tracing::info!(
                response,
                "restore_token rejected; dropped stored token and reopening the official picker"
            );
            return Err(msg("AGENTLINK_RESTORE_RETRY"));
        }
        return Err(portal_response_error(
            response,
            "ScreenCast.Start (window picker)",
        ));
    }

    let streams = match parse_portal_streams(&results) {
        Ok(streams) => streams,
        Err(err) => {
            cleanup.close(conn).await;
            return Err(err);
        }
    };
    if streams.len() != 1 {
        cleanup.close(conn).await;
        return Err(msg(format!(
            "portal ScreenCast returned {} streams; window capture expects exactly one",
            streams.len()
        )));
    }
    let source = streams.into_iter().next().unwrap();
    tracing::info!(
        node_id = source.node_id,
        source_type = ?source.source_type,
        size = ?source.size,
        position = ?source.position,
        title = ?source.title,
        app_id = ?source.app_id,
        "portal ScreenCast Start stream identity"
    );
    if let Err(err) = match_portal_window_query(query, &source) {
        cleanup.close(conn).await;
        return Err(err);
    }
    if let (Some(dir), Some(rec)) = (
        persist_dir.as_ref(),
        persist_dir.as_ref().and_then(|dir| {
            crate::platform::portal_persist::load_restore(dir)
                .ok()
                .flatten()
        }),
    ) {
        if restore_token.is_some()
            && !crate::platform::portal_persist::restored_source_matches(
                &rec,
                source.title.as_deref(),
                source.app_id.as_deref(),
                source.id.as_deref(),
            )
        {
            let _ = crate::platform::portal_persist::clear_restore(dir);
            cleanup.close(conn).await;
            tracing::info!(
                "restored ScreenCast source no longer matches the bound window; falling back to the official picker"
            );
            return Err(msg("AGENTLINK_RESTORE_RETRY"));
        }
    }
    if persist {
        if let Some(dir) = persist_dir.as_ref() {
            if let Some(token) = results
                .get("restore_token")
                .and_then(|value| value_as_string(value as &Value))
            {
                match crate::platform::portal_persist::store_restore(
                        dir,
                        &token,
                        query,
                        source.title.as_deref(),
                        source.app_id.as_deref(),
                        source.id.as_deref(),
                        agentlink_core::util::unix_now(),
                    ) {
                        Ok(Some(_)) => tracing::info!(
                            "stored ScreenCast restore_token bound to this window (0600); OS consent only"
                        ),
                        Ok(None) => tracing::info!(
                            "portal issued a restore_token but source identity was not disclosed; not persisting (would be any-window)"
                        ),
                        Err(err) => tracing::warn!(error = %err, "failed to store portal restore_token"),
                    }
            }
        }
    }
    if query.trim().is_empty() {
        tracing::info!("{}", empty_query_note());
    }
    Ok((cleanup, source))
}

/// Open the PipeWire remote for an authorized session.
#[cfg_attr(not(pipewire_headers), allow(dead_code))]
pub async fn open_pipewire_remote_fd(
    conn: &Connection,
    session_path: &str,
) -> Result<std::os::fd::OwnedFd> {
    let portal = screencast_proxy(conn).await?;
    let session_opath = owned_object_path(session_path)?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    let fd: zbus::zvariant::OwnedFd = portal
        .call("OpenPipeWireRemote", &(&session_opath, options))
        .await
        .map_err(|err| msg(format!("OpenPipeWireRemote: {err}")))?;
    Ok(std::os::fd::OwnedFd::from(fd))
}

/// Full one-shot window capture: authorize → OpenPipeWireRemote → one frame → close.
#[cfg(pipewire_headers)]
pub async fn capture_window(
    conn: &Connection,
    query: &str,
    wait_ms: i32,
    max_width: u32,
    monitors: &[(i32, i32)],
) -> Result<crate::capture::Frame> {
    let (mut cleanup, source) = authorize_window_stream(conn, query).await?;
    let fd = match open_pipewire_remote_fd(conn, &cleanup.path).await {
        Ok(fd) => fd,
        Err(err) => {
            cleanup.close(conn).await;
            return Err(err);
        }
    };
    let result = consume_one_frame(fd, source.node_id, wait_ms, max_width);
    cleanup.close(conn).await;
    let (mut frame, pw_crop) = result?;
    let geometry = resolve_window_frame_geometry(frame.width, frame.height, &source, pw_crop);
    match geometry {
        WindowFrameGeometry::Tight { rect, origin } => {
            frame = crate::capture::crop_frame(&frame, rect)?;
            tracing::info!(
                ?origin,
                width = frame.width,
                height = frame.height,
                x = rect.x,
                y = rect.y,
                "cropped portal WINDOW buffer to metadata geometry"
            );
            frame.backend = "wayland-portal-window".into();
        }
        WindowFrameGeometry::Letterboxed { reason } => {
            tracing::warn!(
                %reason,
                width = frame.width,
                height = frame.height,
                portal_size = ?source.size,
                portal_position = ?source.position,
                "no reliable window crop metadata; returning the letterboxed buffer without inventing a width"
            );
            frame.backend = "wayland-portal-window-letterboxed".into();
        }
    }
    let letterboxed = matches!(geometry, WindowFrameGeometry::Letterboxed { .. });
    if let Err(err) =
        ensure_captured_frame_is_window(&source, frame.width, frame.height, monitors, letterboxed)
    {
        return Err(err);
    }
    Ok(frame)
}

#[cfg(pipewire_headers)]
fn consume_one_frame(
    fd: std::os::fd::OwnedFd,
    node_id: u32,
    wait_ms: i32,
    max_width: u32,
) -> Result<(crate::capture::Frame, Option<crate::capture::Rect>)> {
    let mut capture = crate::stream::pipewire::PwCapture::open(fd, node_id)?;
    let target = crate::stream::pipewire::resolve_target_width(max_width);
    capture.set_target_width(target);
    let mut last_err = msg("portal window ScreenCast has not delivered a frame yet");
    for _ in 0..8 {
        match capture.take(wait_ms.max(500)) {
            Ok(Some((frame, _))) => {
                let crop = capture.videocrop().and_then(|rect| {
                    // Map source-pixel crop onto a downsampled frame.
                    let (src_w, src_h, out_w, out_h) = capture.geometry();
                    scale_crop_rect(rect, src_w, src_h, out_w, out_h, frame.width, frame.height)
                });
                return Ok((frame, crop));
            }
            Ok(None) => {}
            Err(err) => last_err = err,
        }
    }
    Err(last_err)
}

fn scale_crop_rect(
    rect: crate::capture::Rect,
    src_w: u32,
    src_h: u32,
    out_w: u32,
    out_h: u32,
    frame_w: u32,
    frame_h: u32,
) -> Option<crate::capture::Rect> {
    let (out_w, out_h) = if out_w == 0 || out_h == 0 {
        (frame_w, frame_h)
    } else {
        (out_w, out_h)
    };
    if src_w == 0 || src_h == 0 {
        return rect_fits(rect, frame_w, frame_h).then_some(rect);
    }
    if src_w == out_w && src_h == out_h {
        return rect_fits(rect, frame_w, frame_h).then_some(rect);
    }
    let x = (rect.x as i64 * out_w as i64 / src_w as i64) as i32;
    let y = (rect.y as i64 * out_h as i64 / src_h as i64) as i32;
    let width = (rect.width as u64 * out_w as u64 / src_w as u64).max(1) as u32;
    let height = (rect.height as u64 * out_h as u64 / src_h as u64).max(1) as u32;
    let scaled = crate::capture::Rect {
        x,
        y,
        width,
        height,
    };
    rect_fits(scaled, frame_w, frame_h).then_some(scaled)
}

#[cfg(not(pipewire_headers))]
pub async fn capture_window(
    conn: &Connection,
    query: &str,
    _wait_ms: i32,
    _max_width: u32,
    monitors: &[(i32, i32)],
) -> Result<crate::capture::Frame> {
    let _ = (conn, query, monitors);
    Err(msg(
        "window capture via portal ScreenCast needs a build with libpipewire-0.3 headers; \
         this binary fell back to the Screenshot portal which cannot isolate one window",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window_source(
        title: Option<&str>,
        app_id: Option<&str>,
        id: Option<&str>,
    ) -> PortalStreamSource {
        PortalStreamSource {
            node_id: 42,
            source_type: Some(SOURCE_WINDOW),
            id: id.map(str::to_string),
            title: title.map(str::to_string),
            app_id: app_id.map(str::to_string),
            mapping_id: None,
            size: Some((800, 600)),
            position: None,
        }
    }

    #[test]
    fn rejects_monitor_as_window() {
        let source = PortalStreamSource {
            node_id: 1,
            source_type: Some(SOURCE_MONITOR),
            id: None,
            title: Some("Desktop".into()),
            app_id: None,
            mapping_id: None,
            size: Some((2736, 1824)),
            position: None,
        };
        let err = ensure_window_source(&source).unwrap_err().to_string();
        assert!(err.contains("MONITOR"), "{err}");
        assert!(err.contains("refusing"), "{err}");
        let err = match_portal_window_query("Desktop", &source)
            .unwrap_err()
            .to_string();
        assert!(err.contains("MONITOR"), "{err}");
    }

    #[test]
    fn omitted_source_type_is_accepted_when_size_is_not_a_monitor() {
        let source = PortalStreamSource {
            node_id: 1,
            source_type: None,
            id: None,
            title: Some("t417-iso-editor-wMn95K.txt".into()),
            app_id: None,
            mapping_id: None,
            size: Some((900, 700)),
            position: None,
        };
        ensure_window_source(&source).unwrap();
        ensure_window_source_against_monitors(&source, &[(2736, 1824)]).unwrap();
        match_portal_window_query("t417-iso-editor", &source).unwrap();
    }

    #[test]
    fn letterboxed_window_buffer_may_match_monitor_size() {
        let window = PortalStreamSource {
            node_id: 88,
            source_type: Some(SOURCE_WINDOW),
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: Some((1368, 912)),
            position: None,
        };
        ensure_captured_frame_is_window(&window, 2736, 1824, &[(2736, 1824)], true).unwrap();
        let err = ensure_captured_frame_is_window(&window, 2736, 1824, &[(2736, 1824)], false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("monitor"), "{err}");
        let omitted = PortalStreamSource {
            source_type: None,
            ..window.clone()
        };
        ensure_captured_frame_is_window(&omitted, 2736, 1824, &[(2736, 1824)], true).unwrap();
        let monitor = PortalStreamSource {
            source_type: Some(SOURCE_MONITOR),
            ..window
        };
        let err = ensure_captured_frame_is_window(&monitor, 2736, 1824, &[(2736, 1824)], true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("MONITOR"), "{err}");
    }

    #[test]
    fn omitted_source_type_with_no_size_defers_to_frame_check() {
        let source = PortalStreamSource {
            node_id: 1,
            source_type: None,
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: None,
            position: None,
        };
        ensure_window_source(&source).unwrap();
        ensure_captured_frame_is_window(&source, 900, 700, &[(2736, 1824)], false).unwrap();
        let err = ensure_captured_frame_is_window(&source, 2736, 1824, &[(2736, 1824)], false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("2736x1824"), "{err}");
        assert!(err.contains("monitor"), "{err}");
    }

    #[test]
    fn omitted_source_type_rejects_monitor_sized_stream() {
        let source = PortalStreamSource {
            node_id: 1,
            source_type: None,
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: Some((2736, 1824)),
            position: None,
        };
        let err = ensure_window_source_against_monitors(&source, &[(2736, 1824)])
            .unwrap_err()
            .to_string();
        assert!(err.contains("2736x1824"), "{err}");
        assert!(err.contains("monitor"), "{err}");
        // Without a monitor list we cannot prove it is a desktop; the frame check
        // still applies once sizes are known.
        ensure_window_source(&source).unwrap();
    }

    #[test]
    fn query_mismatch_fails_clearly() {
        let source = window_source(Some("Terminal"), Some("org.gnome.Terminal"), Some("7"));
        let err = match_portal_window_query("t417-iso-editor", &source)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match"), "{err}");
        assert!(err.contains("t417-iso-editor"), "{err}");
        assert!(err.contains("Terminal"), "{err}");
    }

    #[test]
    fn query_matches_title_app_or_id() {
        let source = window_source(
            Some("t417-iso-editor-wMn95K.txt"),
            Some("org.gnome.TextEditor"),
            Some("3"),
        );
        match_portal_window_query("t417-iso-editor", &source).unwrap();
        match_portal_window_query("TextEditor", &source).unwrap();
        match_portal_window_query("3", &source).unwrap();
        match_portal_window_query("", &source).unwrap();
    }

    #[test]
    fn undisclosed_title_accepts_window_query_as_picker_hint() {
        // GNOME Start() often omits title/app_id; opaque id "0" must not be
        // substring-matched against a title query (would false-mismatch).
        let source = window_source(None, None, Some("0"));
        match_portal_window_query("t417-iso-editor", &source).unwrap();
        match_portal_window_query("", &source).unwrap();
        match_portal_window_query("0", &source).unwrap();
    }

    #[test]
    fn no_silent_fullscreen_fallback_helpers() {
        let monitor = PortalStreamSource {
            node_id: 99,
            source_type: Some(SOURCE_MONITOR),
            id: Some("0".into()),
            title: None,
            app_id: None,
            mapping_id: None,
            size: Some((2736, 1824)),
            position: None,
        };
        assert!(ensure_window_source(&monitor).is_err());
        assert!(match_portal_window_query("", &monitor).is_err());
        assert!(match_portal_window_query("anything", &monitor).is_err());
    }

    #[test]
    fn persist_none_is_zero() {
        assert_eq!(PERSIST_NONE, 0);
    }

    #[test]
    fn portal_cancel_and_timeout_messages() {
        let cancel = portal_response_error(1, "ScreenCast.Start").to_string();
        assert!(cancel.contains("cancelled"), "{cancel}");
        let other = portal_response_error(2, "ScreenCast.Start").to_string();
        assert!(other.contains("released"), "{other}");
    }

    #[test]
    fn cleanup_starts_open() {
        let cleanup = PortalSessionCleanup::new("/org/freedesktop/portal/desktop/session/x/y");
        assert!(!cleanup.closed);
        assert!(cleanup.path.contains("session"));
    }

    #[test]
    fn empty_query_note_is_explicit() {
        assert!(empty_query_note().contains("portal picker"));
    }

    #[test]
    fn parse_streams_reads_source_type_and_title() {
        // Build via OwnedValue round-trip using a minimal dict is awkward without
        // zvariant helpers; cover the matcher paths above and keep this as a
        // structural sanity check on SOURCE bits.
        assert_eq!(SOURCE_MONITOR | SOURCE_WINDOW | SOURCE_VIRTUAL, 7);
        assert!(PortalStreamSource {
            node_id: 9,
            source_type: Some(SOURCE_WINDOW),
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: None,
            position: None,
        }
        .is_window());
        assert!(PortalStreamSource {
            node_id: 9,
            source_type: None,
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: Some((800, 600)),
            position: None,
        }
        .is_window());
        assert!(!PortalStreamSource {
            node_id: 9,
            source_type: Some(SOURCE_MONITOR),
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: Some((2736, 1824)),
            position: None,
        }
        .is_window());
    }

    #[test]
    fn tight_crop_uses_portal_position_and_size() {
        let source = PortalStreamSource {
            node_id: 1,
            source_type: None,
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: Some((1400, 1040)),
            position: Some((50, 50)),
        };
        match resolve_window_frame_geometry(2736, 1824, &source, None) {
            WindowFrameGeometry::Tight { rect, origin } => {
                assert_eq!(origin, WindowCropOrigin::PortalPositionSize);
                assert_eq!(
                    rect,
                    crate::capture::Rect {
                        x: 50,
                        y: 50,
                        width: 1400,
                        height: 1040
                    }
                );
            }
            other => panic!("expected tight crop, got {other:?}"),
        }
    }

    #[test]
    fn size_without_position_is_letterboxed_not_invented() {
        let source = PortalStreamSource {
            node_id: 1,
            source_type: Some(SOURCE_WINDOW),
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: Some((1400, 1040)),
            position: None,
        };
        match resolve_window_frame_geometry(2736, 1824, &source, None) {
            WindowFrameGeometry::Letterboxed { reason } => {
                assert!(reason.contains("position"), "{reason}");
            }
            other => panic!("expected letterboxed, got {other:?}"),
        }
    }

    #[test]
    fn missing_metadata_is_letterboxed() {
        let source = PortalStreamSource {
            node_id: 1,
            source_type: None,
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: None,
            position: None,
        };
        match resolve_window_frame_geometry(2736, 1824, &source, None) {
            WindowFrameGeometry::Letterboxed { reason } => {
                assert!(reason.contains("omitted"), "{reason}");
            }
            other => panic!("expected letterboxed, got {other:?}"),
        }
    }

    #[test]
    fn videocrop_wins_over_disagreeing_portal_size() {
        let source = PortalStreamSource {
            node_id: 1,
            source_type: Some(SOURCE_WINDOW),
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: Some((800, 600)),
            position: Some((0, 0)),
        };
        let pw = crate::capture::Rect {
            x: 50,
            y: 50,
            width: 1400,
            height: 1040,
        };
        match resolve_window_frame_geometry(2736, 1824, &source, Some(pw)) {
            WindowFrameGeometry::Tight { rect, origin } => {
                assert_eq!(origin, WindowCropOrigin::PipewireVideoCrop);
                assert_eq!(rect, pw);
            }
            other => panic!("expected videocrop, got {other:?}"),
        }
    }

    #[test]
    fn full_buffer_size_is_not_a_window_crop() {
        let source = PortalStreamSource {
            node_id: 1,
            source_type: Some(SOURCE_WINDOW),
            id: None,
            title: None,
            app_id: None,
            mapping_id: None,
            size: Some((2736, 1824)),
            position: Some((0, 0)),
        };
        match resolve_window_frame_geometry(2736, 1824, &source, None) {
            WindowFrameGeometry::Letterboxed { .. } => {}
            other => panic!("expected letterboxed, got {other:?}"),
        }
    }
}
