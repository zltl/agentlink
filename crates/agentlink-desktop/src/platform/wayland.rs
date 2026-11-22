//! Wayland screenshots and input through xdg-desktop-portal.
//!
//! One-shot capture uses the Screenshot portal. A capture session repeats that
//! call at `max_fps` and is reported as [`StreamMode::PortalSampled`](crate::capture::StreamMode).
//!
//! PipeWire: a streaming session opens a ScreenCast and `OpenPipeWireRemote`
//! unless `AGENTLINK_DESKTOP_PIPEWIRE=0`. When this build was compiled with
//! libpipewire headers, those buffers (memfd or dma-buf) are copied once into
//! BGRA. Otherwise the node id is recorded and pixels still come from the
//! Screenshot portal. Xvfb CI is an X11 session, so it never opens the portal.
//!
//! Input uses RemoteDesktop (`NotifyPointerMotionAbsolute`, `NotifyPointerButton`,
//! `NotifyPointerAxis`, `NotifyKeyboardKeysym`). Current xdg-desktop-portal
//! builds deliver those events to the compositor with libei. The node speaks
//! the portal API, which is the supported client side. When `libei.so.1` is
//! installed the backend name is `wayland-portal+libei`.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use futures_util::StreamExt;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use crate::capture::{crop_frame, CaptureTarget, Frame, MonitorInfo, Rect};
use crate::error::{msg, Result};
use crate::keys::key_info;

pub struct WaylandDesk {
    conn: Connection,
    input: Option<RemoteSession>,
    libei: bool,
    monitors: Mutex<Vec<MonitorInfo>>,
    cached_size: Mutex<Option<(u32, u32)>>,
}

struct RemoteSession {
    path: String,
    stream: u32,
}

impl WaylandDesk {
    pub async fn connect() -> Result<Self> {
        let conn = Connection::session()
            .await
            .map_err(|err| msg(format!("session bus: {err}")))?;
        Proxy::new(
            &conn,
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Screenshot",
        )
        .await
        .map_err(|err| {
            msg(format!(
                "screenshot portal: {err}. Wayland capture needs xdg-desktop-portal."
            ))
        })?;
        Ok(Self {
            conn,
            input: None,
            libei: libei_present(),
            monitors: Mutex::new(Vec::new()),
            cached_size: Mutex::new(None),
        })
    }

    pub fn connection(&self) -> Connection {
        self.conn.clone()
    }

    pub fn backend_name(&self) -> String {
        if self.libei {
            "wayland-portal+libei".into()
        } else {
            "wayland-portal".into()
        }
    }

    pub fn monitors(&self) -> Vec<MonitorInfo> {
        if let Ok(list) = self.monitors.lock() {
            if !list.is_empty() {
                return list.clone();
            }
        }
        let (width, height) = self
            .cached_size
            .lock()
            .ok()
            .and_then(|s| *s)
            .unwrap_or((0, 0));
        vec![MonitorInfo {
            index: 0,
            name: "wayland-session".into(),
            x: 0,
            y: 0,
            width,
            height,
            primary: true,
        }]
    }

    fn record_stream_monitors(&self, list: Vec<MonitorInfo>) {
        if !list.is_empty() {
            if let Ok(mut guard) = self.monitors.lock() {
                *guard = list;
            }
        }
    }

    pub fn session(&self) -> Result<(&str, u32)> {
        self.input
            .as_ref()
            .map(|session| (session.path.as_str(), session.stream))
            .ok_or_else(|| msg("Wayland remote desktop session is not started"))
    }

    pub async fn prepare_input(&mut self) -> Result<()> {
        if self.input.is_some() {
            return Ok(());
        }
        let (path, stream, stream_monitors) = remote_desktop_start(&self.conn).await?;
        self.record_stream_monitors(stream_monitors);
        self.input = Some(RemoteSession { path, stream });
        Ok(())
    }

    pub async fn capture(&self, target: &CaptureTarget) -> Result<Frame> {
        let bytes = portal_screenshot(&self.conn).await?;
        let frame = decode_portal_image(&bytes, &self.backend_name())?;
        if frame.width > 0 && frame.height > 0 {
            if let Ok(mut slot) = self.cached_size.lock() {
                *slot = Some((frame.width, frame.height));
            }
        }
        match target {
            CaptureTarget::FullScreen => Ok(frame),
            CaptureTarget::Monitor(0) => Ok(frame),
            CaptureTarget::Monitor(_) => Err(msg(
                "the Wayland screenshot portal returns one image for the session; use target screen or region",
            )),
            CaptureTarget::Region(rect) => crop_frame(&frame, *rect),
            CaptureTarget::Window(query) => {
                // One-shot WINDOW ScreenCast (picker + PipeWire). Not the
                // Screenshot portal, which is full-session only.
                super::portal_window::capture_window(&self.conn, query, 1000, 0, &[]).await
            }
        }
    }

    pub async fn pipewire_node(&self) -> Option<u32> {
        if std::env::var("AGENTLINK_DESKTOP_PIPEWIRE").ok().as_deref() == Some("0") {
            return None;
        }
        if std::env::var("WAYLAND_DISPLAY")
            .ok()
            .filter(|v| !v.is_empty())
            .is_none()
            && std::env::var("XDG_SESSION_TYPE").ok().as_deref() != Some("wayland")
        {
            return None;
        }
        match screencast_node(&self.conn).await {
            Ok((_session, node, stream_monitors)) => {
                self.record_stream_monitors(stream_monitors);
                Some(node)
            }
            Err(err) => {
                tracing::info!(error = %err, "PipeWire screencast was not negotiated");
                None
            }
        }
    }

    /// ScreenCast node plus the PipeWire remote fd. `None` when the portal
    /// is missing or the operator set `AGENTLINK_DESKTOP_PIPEWIRE=0`.
    #[cfg(pipewire_headers)]
    pub async fn open_pipewire(&self) -> Option<(std::os::fd::OwnedFd, u32)> {
        if std::env::var("AGENTLINK_DESKTOP_PIPEWIRE").ok().as_deref() == Some("0") {
            return None;
        }
        match open_pipewire_remote(&self.conn).await {
            Ok((fd, node, stream_monitors)) => {
                self.record_stream_monitors(stream_monitors);
                Some((fd, node))
            }
            Err(err) => {
                tracing::info!(error = %err, "ScreenCast PipeWire remote was not opened");
                None
            }
        }
    }
}

pub async fn notify_motion(
    conn: &Connection,
    session: &str,
    stream: u32,
    x: i32,
    y: i32,
) -> Result<()> {
    let portal = remote_proxy(conn).await?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    portal
        .call::<_, _, ()>(
            "NotifyPointerMotionAbsolute",
            &(session, options, stream, x as f64, y as f64),
        )
        .await
        .map_err(|err| msg(format!("pointer motion: {err}")))
}

pub async fn notify_button(
    conn: &Connection,
    session: &str,
    button: u32,
    down: bool,
) -> Result<()> {
    let portal = remote_proxy(conn).await?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    let state = if down { 1u32 } else { 0u32 };
    portal
        .call::<_, _, ()>("NotifyPointerButton", &(session, options, button, state))
        .await
        .map_err(|err| msg(format!("pointer button: {err}")))
}

pub async fn notify_axis(conn: &Connection, session: &str, dx: f64, dy: f64) -> Result<()> {
    // Protocol `dx`/`dy` are notches; the portal axis is roughly pixel-like, so
    // scale by WHEEL_DELTA the same way Windows SendInput does.
    let scale = crate::input::WHEEL_DELTA as f64;
    let portal = remote_proxy(conn).await?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    portal
        .call::<_, _, ()>(
            "NotifyPointerAxis",
            &(session, options, dx * scale, dy * scale),
        )
        .await
        .map_err(|err| msg(format!("pointer axis: {err}")))
}

pub async fn notify_keysym(
    conn: &Connection,
    session: &str,
    keysym: u32,
    down: bool,
) -> Result<()> {
    let portal = remote_proxy(conn).await?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    let state = if down { 1u32 } else { 0u32 };
    portal
        .call::<_, _, ()>("NotifyKeyboardKeysym", &(session, options, keysym, state))
        .await
        .map_err(|err| msg(format!("keysym: {err}")))
}

pub fn keysym_for_char(ch: char) -> u32 {
    match ch {
        '\n' => 0xff0d,
        '\t' => 0xff09,
        ch if (ch as u32) <= 0xff => ch as u32,
        ch => 0x0100_0000 + ch as u32,
    }
}

pub fn keysym_for_name(name: &str) -> Result<u32> {
    key_info(name)
        .map(|info| info.keysym)
        .ok_or_else(|| msg(format!("unknown key '{name}'")))
}

async fn portal_screenshot(conn: &Connection) -> Result<Vec<u8>> {
    let token = unique_token("shot");
    let path = request_path(conn, &token)?;
    let (response, results) = call_and_wait(conn, &path, async {
        let screenshot = Proxy::new(
            conn,
            "org.freedesktop.portal.Desktop",
            "/org/freedesktop/portal/desktop",
            "org.freedesktop.portal.Screenshot",
        )
        .await
        .map_err(|err| msg(err.to_string()))?;
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(token.as_str()));
        options.insert("interactive", Value::from(false));
        let _handle: OwnedObjectPath = screenshot
            .call(
                "Screenshot",
                &("", options),
            )
            .await
            .map_err(|err| {
                msg(format!(
                    "portal Screenshot: {err}. Accept the screenshot prompt, or check that xdg-desktop-portal is running."
                ))
            })?;
        Ok(())
    })
    .await?;
    if response != 0 {
        return Err(msg(
            "screenshot portal request was denied. Accept the prompt for the user that runs the node.",
        ));
    }
    let uri = results
        .get("uri")
        .and_then(owned_str)
        .ok_or_else(|| msg("screenshot portal response had no uri"))?;
    let path = file_uri_path(&uri)?;
    let bytes =
        fs::read(&path).map_err(|err| msg(format!("read portal screenshot {}: {err}", path.display())));
    // Remove the temporary PNG created by xdg-desktop-portal so ~/Pictures or
    // /tmp does not fill up with stale screenshots during streaming.
    let _ = fs::remove_file(&path);
    bytes
}

fn monitors_from_portal_results(results: &HashMap<String, OwnedValue>) -> Vec<MonitorInfo> {
    let Ok(streams) = super::portal_window::parse_portal_streams(results) else {
        return Vec::new();
    };
    streams
        .into_iter()
        .enumerate()
        .filter_map(|(idx, s)| {
            let (w, h) = s.size?;
            if w <= 0 || h <= 0 {
                return None;
            }
            let (x, y) = s.position.unwrap_or((0, 0));
            Some(MonitorInfo {
                index: idx as u32,
                name: s.id.unwrap_or_else(|| format!("wayland-{idx}")),
                x,
                y,
                width: w as u32,
                height: h as u32,
                primary: idx == 0,
            })
        })
        .collect()
}

async fn remote_desktop_start(conn: &Connection) -> Result<(String, u32, Vec<MonitorInfo>)> {
    let portal = remote_proxy(conn).await?;
    let session_token = unique_token("rd");
    let session = session_path(conn, &session_token)?;

    let create_token = unique_token("rdc");
    let (response, _) = call_and_wait(conn, &request_path(conn, &create_token)?, async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(create_token.as_str()));
        options.insert("session_handle_token", Value::from(session_token.as_str()));
        portal
            .call::<_, _, OwnedObjectPath>("CreateSession", &(options,))
            .await
            .map_err(|err| msg(format!("RemoteDesktop.CreateSession: {err}")))?;
        Ok(())
    })
    .await?;
    ensure_ok(response, "RemoteDesktop session")?;

    let persist_dir = super::portal_persist::default_persist_data_dir();
    let persist = super::portal_persist::persist_enabled();
    let saved_token = persist_dir
        .as_ref()
        .and_then(|dir| {
            super::portal_persist::load_desktop_restore(dir, "remote-desktop")
                .ok()
                .flatten()
        });

    let select_token = unique_token("rds");
    let (response, _) = call_and_wait(conn, &request_path(conn, &select_token)?, async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(select_token.as_str()));
        options.insert("types", Value::from(1u32 | 2u32));
        if persist {
            options.insert(
                "persist_mode",
                Value::from(super::portal_persist::PERSIST_UNTIL_REVOKED),
            );
            if let Some(tok) = saved_token.as_deref() {
                options.insert("restore_token", Value::from(tok));
            }
        }
        portal
            .call::<_, _, OwnedObjectPath>("SelectDevices", &(&session, options))
            .await
            .map_err(|err| msg(format!("RemoteDesktop.SelectDevices: {err}")))?;
        Ok(())
    })
    .await?;
    ensure_ok(response, "RemoteDesktop devices")?;

    // Combine ScreenCast.SelectSources on the same session handle per the
    // freedesktop RemoteDesktop spec so Start returns a valid PipeWire stream
    // id (`stream != 0`) for NotifyPointerMotionAbsolute plus monitor bounds.
    if let Ok(sc_portal) = Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.ScreenCast",
    )
    .await
    {
        let sc_select_token = unique_token("rdsc");
        let sc_res = call_and_wait(conn, &request_path(conn, &sc_select_token)?, async {
            let mut options: HashMap<&str, Value<'_>> = HashMap::new();
            options.insert("handle_token", Value::from(sc_select_token.as_str()));
            options.insert("types", Value::from(1u32));
            if persist {
                options.insert(
                    "persist_mode",
                    Value::from(super::portal_persist::PERSIST_UNTIL_REVOKED),
                );
                if let Some(tok) = saved_token.as_deref() {
                    options.insert("restore_token", Value::from(tok));
                }
            }
            sc_portal
                .call::<_, _, OwnedObjectPath>("SelectSources", &(&session, options))
                .await
                .map_err(|err| msg(format!("ScreenCast.SelectSources (combined): {err}")))?;
            Ok(())
        })
        .await;
        if let Err(err) = sc_res {
            tracing::debug!(error = %err, "combined ScreenCast.SelectSources on RemoteDesktop session skipped");
        }
    }

    let start_token = unique_token("rdt");
    let (response, results) = call_and_wait(conn, &request_path(conn, &start_token)?, async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(start_token.as_str()));
        portal
            .call::<_, _, OwnedObjectPath>("Start", &(&session, "", options))
            .await
            .map_err(|err| msg(format!("RemoteDesktop.Start: {err}")))?;
        Ok(())
    })
    .await?;
    if response != 0 && saved_token.is_some() {
        if let Some(dir) = persist_dir.as_ref() {
            let _ = super::portal_persist::clear_desktop_restore(dir, "remote-desktop");
        }
    }
    ensure_ok(response, "RemoteDesktop start")?;
    if persist {
        if let (Some(dir), Some(tok)) = (
            persist_dir.as_ref(),
            results.get("restore_token").and_then(owned_str),
        ) {
            let _ = super::portal_persist::store_desktop_restore(
                dir,
                "remote-desktop",
                &tok,
                agentlink_core::util::unix_now(),
            );
        }
    }
    let stream = first_stream(&results).unwrap_or(0);
    let stream_monitors = monitors_from_portal_results(&results);
    Ok((session, stream, stream_monitors))
}

async fn screencast_node(conn: &Connection) -> Result<(String, u32, Vec<MonitorInfo>)> {
    let portal = Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.ScreenCast",
    )
    .await
    .map_err(|err| msg(format!("screencast portal: {err}")))?;
    let session_token = unique_token("sc");
    let session = session_path(conn, &session_token)?;

    let create_token = unique_token("scc");
    let (response, _) = call_and_wait(conn, &request_path(conn, &create_token)?, async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(create_token.as_str()));
        options.insert("session_handle_token", Value::from(session_token.as_str()));
        portal
            .call::<_, _, OwnedObjectPath>("CreateSession", &(options,))
            .await
            .map_err(|err| msg(err.to_string()))?;
        Ok(())
    })
    .await?;
    ensure_ok(response, "ScreenCast session")?;

    let persist_dir = super::portal_persist::default_persist_data_dir();
    let persist = super::portal_persist::persist_enabled();
    let saved_token = persist_dir
        .as_ref()
        .and_then(|dir| {
            super::portal_persist::load_desktop_restore(dir, "screencast")
                .ok()
                .flatten()
        });

    let select_token = unique_token("scs");
    let (response, _) = call_and_wait(conn, &request_path(conn, &select_token)?, async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(select_token.as_str()));
        options.insert("types", Value::from(1u32));
        if persist {
            options.insert(
                "persist_mode",
                Value::from(super::portal_persist::PERSIST_UNTIL_REVOKED),
            );
            if let Some(tok) = saved_token.as_deref() {
                options.insert("restore_token", Value::from(tok));
            }
        }
        portal
            .call::<_, _, OwnedObjectPath>("SelectSources", &(&session, options))
            .await
            .map_err(|err| msg(err.to_string()))?;
        Ok(())
    })
    .await?;
    ensure_ok(response, "ScreenCast sources")?;

    let start_token = unique_token("sct");
    let (response, results) = call_and_wait(conn, &request_path(conn, &start_token)?, async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(start_token.as_str()));
        portal
            .call::<_, _, OwnedObjectPath>("Start", &(&session, "", options))
            .await
            .map_err(|err| msg(err.to_string()))?;
        Ok(())
    })
    .await?;
    if response != 0 && saved_token.is_some() {
        if let Some(dir) = persist_dir.as_ref() {
            let _ = super::portal_persist::clear_desktop_restore(dir, "screencast");
        }
    }
    ensure_ok(response, "ScreenCast start")?;
    if persist {
        if let (Some(dir), Some(tok)) = (
            persist_dir.as_ref(),
            results.get("restore_token").and_then(owned_str),
        ) {
            let _ = super::portal_persist::store_desktop_restore(
                dir,
                "screencast",
                &tok,
                agentlink_core::util::unix_now(),
            );
        }
    }
    let node =
        first_stream(&results).ok_or_else(|| msg("ScreenCast start returned no PipeWire node"))?;
    let stream_monitors = monitors_from_portal_results(&results);
    Ok((session, node, stream_monitors))
}

#[cfg(pipewire_headers)]
async fn open_pipewire_remote(
    conn: &Connection,
) -> Result<(std::os::fd::OwnedFd, u32, Vec<MonitorInfo>)> {
    let (session, node, stream_monitors) = screencast_node(conn).await?;
    let portal = Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.ScreenCast",
    )
    .await
    .map_err(|err| msg(format!("screencast portal: {err}")))?;
    let options: HashMap<&str, Value<'_>> = HashMap::new();
    let fd: zbus::zvariant::OwnedFd = portal
        .call("OpenPipeWireRemote", &(&session, options))
        .await
        .map_err(|err| msg(format!("OpenPipeWireRemote: {err}")))?;
    Ok((std::os::fd::OwnedFd::from(fd), node, stream_monitors))
}

async fn call_and_wait<F>(
    conn: &Connection,
    path: &str,
    invoke: F,
) -> Result<(u32, HashMap<String, OwnedValue>)>
where
    F: std::future::Future<Output = Result<()>>,
{
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
    let message = tokio::time::timeout(Duration::from_secs(20), signals.next())
        .await
        .map_err(|_| {
            msg("desktop portal timed out. Accept the permission dialog on the machine, then retry.")
        })?
        .ok_or_else(|| msg("desktop portal closed the request"))?;
    let (response, results): (u32, HashMap<String, OwnedValue>) = message
        .body()
        .deserialize()
        .map_err(|err| msg(format!("portal response: {err}")))?;
    Ok((response, results))
}

fn ensure_ok(response: u32, what: &str) -> Result<()> {
    if response == 0 {
        Ok(())
    } else {
        Err(msg(format!(
            "{what} was denied. Wayland needs a user at the seat to accept the xdg-desktop-portal dialog."
        )))
    }
}

async fn remote_proxy(conn: &Connection) -> Result<Proxy<'_>> {
    Proxy::new(
        conn,
        "org.freedesktop.portal.Desktop",
        "/org/freedesktop/portal/desktop",
        "org.freedesktop.portal.RemoteDesktop",
    )
    .await
    .map_err(|err| msg(format!("remote desktop portal: {err}")))
}

fn request_path(conn: &Connection, token: &str) -> Result<String> {
    let sender = sender_token(conn)?;
    Ok(format!(
        "/org/freedesktop/portal/desktop/request/{sender}/{token}"
    ))
}

fn session_path(conn: &Connection, token: &str) -> Result<String> {
    let sender = sender_token(conn)?;
    Ok(format!(
        "/org/freedesktop/portal/desktop/session/{sender}/{token}"
    ))
}

fn sender_token(conn: &Connection) -> Result<String> {
    let unique = conn
        .unique_name()
        .ok_or_else(|| msg("session bus connection has no unique name"))?;
    Ok(unique.as_str().trim_start_matches(':').replace('.', "_"))
}

fn unique_token(prefix: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    format!("agentlink{prefix}{n}")
}

fn owned_str(value: &OwnedValue) -> Option<String> {
    match &**value {
        Value::Str(text) => Some(text.to_string()),
        _ => None,
    }
}

fn first_stream(results: &HashMap<String, OwnedValue>) -> Option<u32> {
    let value = &**results.get("streams")?;
    let Value::Array(items) = value else {
        return None;
    };
    let first = items.inner().first()?;
    let Value::Structure(fields) = first else {
        return None;
    };
    match fields.fields().first() {
        Some(Value::U32(id)) => Some(*id),
        _ => None,
    }
}

fn file_uri_path(uri: &str) -> Result<PathBuf> {
    let rest = uri
        .strip_prefix("file://")
        .ok_or_else(|| msg(format!("portal uri is not a file uri: {uri}")))?;
    let mut out = Vec::new();
    let bytes = rest.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let Ok(byte) = u8::from_str_radix(
                std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or(""),
                16,
            ) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }
    let text =
        String::from_utf8(out).map_err(|_| msg(format!("portal uri is not utf-8: {uri}")))?;
    Ok(PathBuf::from(text))
}

fn decode_portal_image(bytes: &[u8], backend: &str) -> Result<Frame> {
    let image = image::load_from_memory(bytes)
        .map_err(|err| msg(format!("portal image: {err}")))?
        .to_rgba8();
    let raw = image.as_raw();
    let mut bgra = vec![0u8; raw.len()];
    for (src, dst) in raw.chunks_exact(4).zip(bgra.chunks_exact_mut(4)) {
        dst[0] = src[2];
        dst[1] = src[1];
        dst[2] = src[0];
        dst[3] = src[3];
    }
    Frame::from_bgra(
        image.width(),
        image.height(),
        image.width() * 4,
        &bgra,
        backend,
    )
}

fn libei_present() -> bool {
    // Probe only. The portal, not this process, is the libei client.
    unsafe { libloading::Library::new("libei.so.1").is_ok() }
}

#[allow(dead_code)]
fn _rect(rect: Rect) -> Rect {
    rect
}
