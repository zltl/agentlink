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
use std::time::Duration;

use futures_util::StreamExt;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zbus::{Connection, Proxy};

use crate::capture::{crop_frame, CaptureTarget, Frame, Rect};
use crate::error::{msg, Result};
use crate::keys::key_info;

pub struct WaylandDesk {
    conn: Connection,
    input: Option<RemoteSession>,
    libei: bool,
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
        let (path, stream) = remote_desktop_start(&self.conn).await?;
        self.input = Some(RemoteSession { path, stream });
        Ok(())
    }

    pub async fn capture(&self, target: &CaptureTarget) -> Result<Frame> {
        let bytes = portal_screenshot(&self.conn).await?;
        let frame = decode_portal_image(&bytes, &self.backend_name())?;
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
            Ok((_session, node)) => Some(node),
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
            Ok(pair) => Some(pair),
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
    fs::read(&path).map_err(|err| msg(format!("read portal screenshot {}: {err}", path.display())))
}

async fn remote_desktop_start(conn: &Connection) -> Result<(String, u32)> {
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

    let select_token = unique_token("rds");
    let (response, _) = call_and_wait(conn, &request_path(conn, &select_token)?, async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(select_token.as_str()));
        options.insert("types", Value::from(1u32 | 2u32));
        portal
            .call::<_, _, OwnedObjectPath>("SelectDevices", &(&session, options))
            .await
            .map_err(|err| msg(format!("RemoteDesktop.SelectDevices: {err}")))?;
        Ok(())
    })
    .await?;
    ensure_ok(response, "RemoteDesktop devices")?;

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
    ensure_ok(response, "RemoteDesktop start")?;
    let stream = first_stream(&results).unwrap_or(0);
    Ok((session, stream))
}

async fn screencast_node(conn: &Connection) -> Result<(String, u32)> {
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

    let select_token = unique_token("scs");
    let (response, _) = call_and_wait(conn, &request_path(conn, &select_token)?, async {
        let mut options: HashMap<&str, Value<'_>> = HashMap::new();
        options.insert("handle_token", Value::from(select_token.as_str()));
        options.insert("types", Value::from(1u32));
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
    ensure_ok(response, "ScreenCast start")?;
    let node =
        first_stream(&results).ok_or_else(|| msg("ScreenCast start returned no PipeWire node"))?;
    Ok((session, node))
}

#[cfg(pipewire_headers)]
async fn open_pipewire_remote(conn: &Connection) -> Result<(std::os::fd::OwnedFd, u32)> {
    let (session, node) = screencast_node(conn).await?;
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
    Ok((std::os::fd::OwnedFd::from(fd), node))
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
