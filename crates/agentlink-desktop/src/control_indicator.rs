//! Always-on-top banner while this machine is being remotely controlled.
//!
//! Shown for WebRTC sessions that grant control, and for JPEG/`inject_input`
//! control. Hidden when every control session ends and inject goes idle.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

const INJECT_IDLE: Duration = Duration::from_secs(45);
const BANNER: &str = "AgentLink is controlling this computer";
const BANNER_ZH: &str = "AgentLink 正在远程控制此电脑";

static CONTROL_SESSIONS: AtomicUsize = AtomicUsize::new(0);
static SHOWN: AtomicBool = AtomicBool::new(false);
static STARTED: AtomicBool = AtomicBool::new(false);
static LAST_INJECT: OnceLock<Mutex<Option<Instant>>> = OnceLock::new();

fn last_inject() -> &'static Mutex<Option<Instant>> {
    LAST_INJECT.get_or_init(|| Mutex::new(None))
}

fn banner_text() -> &'static str {
    match std::env::var("LANG")
        .or_else(|_| std::env::var("LC_ALL"))
        .unwrap_or_default()
        .to_lowercase()
    {
        ref lang if lang.starts_with("zh") => BANNER_ZH,
        _ => BANNER,
    }
}

/// A WebRTC (or similar) control-capable session started or stopped.
pub fn note_control_session(active: bool) {
    if active {
        CONTROL_SESSIONS.fetch_add(1, Ordering::SeqCst);
    } else {
        let cur = CONTROL_SESSIONS.load(Ordering::SeqCst);
        CONTROL_SESSIONS.store(cur.saturating_sub(1), Ordering::SeqCst);
    }
    ensure_worker();
    refresh();
}

/// Pointer/keyboard arrived through `inject_input` (JPEG control path).
pub fn note_inject_input() {
    if let Ok(mut slot) = last_inject().lock() {
        *slot = Some(Instant::now());
    }
    ensure_worker();
    refresh();
}

fn inject_recent() -> bool {
    last_inject()
        .lock()
        .ok()
        .and_then(|slot| *slot)
        .map(|at| at.elapsed() < INJECT_IDLE)
        .unwrap_or(false)
}

fn should_show() -> bool {
    CONTROL_SESSIONS.load(Ordering::SeqCst) > 0 || inject_recent()
}

fn refresh() {
    let want = should_show();
    let shown = SHOWN.load(Ordering::SeqCst);
    if want == shown {
        return;
    }
    if want {
        if platform_show(banner_text()) {
            SHOWN.store(true, Ordering::SeqCst);
        }
    } else {
        platform_hide();
        SHOWN.store(false, Ordering::SeqCst);
    }
}

fn ensure_worker() {
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    thread::Builder::new()
        .name("agentlink-control-indicator".into())
        .spawn(|| loop {
            thread::sleep(Duration::from_secs(2));
            refresh();
        })
        .ok();
}

#[cfg(target_os = "linux")]
fn platform_show(text: &str) -> bool {
    linux::show(text)
}

#[cfg(target_os = "linux")]
fn platform_hide() {
    linux::hide();
}

#[cfg(target_os = "windows")]
fn platform_show(text: &str) -> bool {
    windows_banner::show(text)
}

#[cfg(target_os = "windows")]
fn platform_hide() {
    windows_banner::hide();
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn platform_show(text: &str) -> bool {
    tracing::info!(%text, "remote control active (no on-screen indicator on this OS)");
    true
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn platform_hide() {}

#[cfg(target_os = "linux")]
mod linux {
    use std::sync::Mutex;

    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{
        AtomEnum, ConnectionExt as _, CreateGCAux, CreateWindowAux, EventMask, PropMode,
        WindowClass,
    };
    use x11rb::rust_connection::RustConnection;
    use x11rb::wrapper::ConnectionExt as _;

    struct Banner {
        conn: RustConnection,
        window: u32,
    }

    static BANNER: Mutex<Option<Banner>> = Mutex::new(None);

    pub fn show(text: &str) -> bool {
        let mut slot = BANNER.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return true;
        }
        let Ok((conn, screen_num)) = x11rb::connect(None) else {
            tracing::debug!("control indicator: no X11 display");
            return false;
        };
        let screen = &conn.setup().roots[screen_num];
        let root = screen.root;
        let width = screen.width_in_pixels.min(720).max(320) as u16;
        let height = 36u16;
        let x = ((screen.width_in_pixels as i32 - width as i32) / 2).max(0) as i16;
        let y = 8i16;
        let window = match conn.generate_id() {
            Ok(id) => id,
            Err(_) => return false,
        };
        let aux = CreateWindowAux::new()
            .background_pixel(0x00_c4_3e_24) // warm red-orange
            .border_pixel(0)
            .override_redirect(1)
            .event_mask(EventMask::EXPOSURE);
        match conn.create_window(
            screen.root_depth,
            window,
            root,
            x,
            y,
            width,
            height,
            0,
            WindowClass::INPUT_OUTPUT,
            screen.root_visual,
            &aux,
        ) {
            Ok(cookie) => {
                if cookie.check().is_err() {
                    return false;
                }
            }
            Err(_) => return false,
        }
        // Keep above other windows when a WM cooperates; override-redirect
        // already paints over most desktops.
        let _ = set_net_wm_state_above(&conn, window, root);
        let _ = set_wm_name(&conn, window, text);
        if let Ok(cookie) = conn.map_window(window) { let _ = cookie.check(); }
        paint(&conn, window, screen.black_pixel, text);
        let _ = conn.flush();
        *slot = Some(Banner { conn, window });
        true
    }

    pub fn hide() {
        let mut slot = BANNER.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(banner) = slot.take() {
            let _ = banner.conn.unmap_window(banner.window);
            let _ = banner.conn.destroy_window(banner.window);
            let _ = banner.conn.flush();
        }
    }

    fn paint(conn: &RustConnection, window: u32, _black: u32, text: &str) {
        let gc = match conn.generate_id() {
            Ok(id) => id,
            Err(_) => return,
        };
        let _ = conn.create_gc(
            gc,
            window,
            &CreateGCAux::new()
                .foreground(0x00_ff_ff_ff)
                .background(0x00_c4_3e_24),
        );
        let ascii: String = text
            .chars()
            .map(|ch| if ch.is_ascii() { ch } else { '?' })
            .collect();
        let bytes = ascii.as_bytes();
        let _ = conn.image_text8(window, gc, 12, 24, bytes);
        let _ = conn.free_gc(gc);
    }

    fn set_wm_name(conn: &RustConnection, window: u32, text: &str) -> Result<(), ()> {
        let bytes = text.as_bytes();
        conn.change_property(
            PropMode::REPLACE,
            window,
            AtomEnum::WM_NAME,
            AtomEnum::STRING,
            8,
            bytes.len() as u32,
            bytes,
        )
        .map_err(|_| ())?
        .check()
        .map_err(|_| ())
    }

    fn set_net_wm_state_above(
        conn: &RustConnection,
        window: u32,
        root: u32,
    ) -> Result<(), ()> {
        let net_wm_state = intern(conn, b"_NET_WM_STATE")?;
        let above = intern(conn, b"_NET_WM_STATE_ABOVE")?;
        conn.change_property32(
            PropMode::REPLACE,
            window,
            net_wm_state,
            AtomEnum::ATOM,
            &[above],
        )
        .map_err(|_| ())?
        .check()
        .map_err(|_| ())?;
        // Also raise relative to root.
        let _ = conn.configure_window(
            window,
            &x11rb::protocol::xproto::ConfigureWindowAux::new().stack_mode(
                x11rb::protocol::xproto::StackMode::ABOVE,
            ),
        );
        let _ = root;
        Ok(())
    }

    fn intern(conn: &RustConnection, name: &[u8]) -> Result<u32, ()> {
        conn.intern_atom(false, name)
            .map_err(|_| ())?
            .reply()
            .map(|r| r.atom)
            .map_err(|_| ())
    }
}

#[cfg(target_os = "windows")]
mod windows_banner {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::thread;

    use windows::core::w;
    use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, RECT, WPARAM};
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect, SetBkMode,
        SetTextColor, DT_CENTER, DT_SINGLELINE, DT_VCENTER, HGDIOBJ, PAINTSTRUCT, TRANSPARENT,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
        GetMessageW, GetSystemMetrics, LoadCursorW, PostMessageW, RegisterClassW,
        SetLayeredWindowAttributes, SetWindowPos, ShowWindow, TranslateMessage, CS_HREDRAW,
        CS_VREDRAW, HWND_TOPMOST, IDC_ARROW, LWA_ALPHA, MSG, SM_CXSCREEN, SWP_NOACTIVATE,
        SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW, SW_SHOWNOACTIVATE, WM_DESTROY, WM_PAINT, WM_USER,
        WNDCLASSW, WS_EX_LAYERED, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW, WS_EX_TOPMOST,
        WS_EX_TRANSPARENT, WS_POPUP,
    };

    const WM_SHOW_BANNER: u32 = WM_USER + 41;
    const WM_HIDE_BANNER: u32 = WM_USER + 42;

    static HOST: AtomicBool = AtomicBool::new(false);
    static HWND_SLOT: Mutex<isize> = Mutex::new(0);
    static BANNER_HWND: Mutex<isize> = Mutex::new(0);
    static TEXT: Mutex<String> = Mutex::new(String::new());

    pub fn show(text: &str) -> bool {
        ensure_host();
        if let Ok(mut slot) = TEXT.lock() {
            *slot = text.to_string();
        }
        post(WM_SHOW_BANNER);
        true
    }

    pub fn hide() {
        post(WM_HIDE_BANNER);
    }

    fn post(msg: u32) {
        let hwnd = HWND_SLOT.lock().ok().map(|v| *v).unwrap_or(0);
        if hwnd != 0 {
            unsafe {
                let _ = PostMessageW(Some(HWND(hwnd as *mut _)), msg, WPARAM(0), LPARAM(0));
            }
        }
    }

    fn ensure_host() {
        if HOST.swap(true, Ordering::SeqCst) {
            return;
        }
        thread::Builder::new()
            .name("agentlink-control-banner".into())
            .spawn(|| unsafe { message_loop() })
            .ok();
        for _ in 0..50 {
            if HWND_SLOT.lock().ok().map(|v| *v).unwrap_or(0) != 0 {
                break;
            }
            thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    unsafe fn message_loop() {
        let class = w!("AgentLinkControlBanner");
        let wc = WNDCLASSW {
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            lpszClassName: class,
            ..Default::default()
        };
        let _ = RegisterClassW(&wc);
        let Ok(host) = CreateWindowExW(
            WS_EX_NOACTIVATE | WS_EX_TOOLWINDOW,
            class,
            w!("agentlink-banner-host"),
            WS_POPUP,
            0,
            0,
            0,
            0,
            None,
            None,
            None,
            None,
        ) else {
            return;
        };
        if let Ok(mut slot) = HWND_SLOT.lock() {
            *slot = host.0 as isize;
        }
        let mut msg = MSG::default();
        while GetMessageW(&mut msg, None, 0, 0).into() {
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    unsafe extern "system" fn wnd_proc(
        hwnd: HWND,
        msg: u32,
        wparam: WPARAM,
        lparam: LPARAM,
    ) -> LRESULT {
        match msg {
            WM_SHOW_BANNER => {
                show_banner(hwnd);
                LRESULT(0)
            }
            WM_HIDE_BANNER => {
                hide_banner();
                LRESULT(0)
            }
            WM_PAINT => {
                let mut ps = PAINTSTRUCT::default();
                let hdc = BeginPaint(hwnd, &mut ps);
                let brush = CreateSolidBrush(COLORREF(0x0024_3E_C4));
                let mut rc = RECT::default();
                let _ = GetClientRect(hwnd, &mut rc);
                let _ = FillRect(hdc, &rc, brush);
                let _ = DeleteObject(HGDIOBJ(brush.0));
                let _ = SetBkMode(hdc, TRANSPARENT);
                let _ = SetTextColor(hdc, COLORREF(0x00FF_FFFF));
                let text = TEXT.lock().ok().map(|t| t.clone()).unwrap_or_default();
                let mut wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
                let _ = DrawTextW(
                    hdc,
                    &mut wide,
                    &mut rc,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                );
                let _ = EndPaint(hwnd, &ps);
                LRESULT(0)
            }
            WM_DESTROY => LRESULT(0),
            _ => DefWindowProcW(hwnd, msg, wparam, lparam),
        }
    }

    unsafe fn show_banner(host: HWND) {
        let existing = BANNER_HWND.lock().ok().map(|v| *v).unwrap_or(0);
        if existing != 0 {
            let hwnd = HWND(existing as *mut _);
            let _ = SetWindowPos(
                hwnd,
                Some(HWND_TOPMOST),
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
            );
            return;
        }
        let class = w!("AgentLinkControlBanner");
        let width = 720i32;
        let height = 36i32;
        let screen_w = GetSystemMetrics(SM_CXSCREEN);
        let x = ((screen_w - width) / 2).max(0);
        let y = 8i32;
        let Ok(hwnd) = CreateWindowExW(
            WS_EX_TOPMOST
                | WS_EX_TOOLWINDOW
                | WS_EX_NOACTIVATE
                | WS_EX_LAYERED
                | WS_EX_TRANSPARENT,
            class,
            w!("AgentLink remote control"),
            WS_POPUP,
            x,
            y,
            width,
            height,
            Some(host),
            None,
            None,
            None,
        ) else {
            return;
        };
        let _ = SetLayeredWindowAttributes(hwnd, COLORREF(0), 230, LWA_ALPHA);
        let _ = SetWindowPos(
            hwnd,
            Some(HWND_TOPMOST),
            0,
            0,
            0,
            0,
            SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE | SWP_SHOWWINDOW,
        );
        let _ = ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        if let Ok(mut slot) = BANNER_HWND.lock() {
            *slot = hwnd.0 as isize;
        }
    }

    unsafe fn hide_banner() {
        let hwnd = {
            let mut slot = match BANNER_HWND.lock() {
                Ok(s) => s,
                Err(_) => return,
            };
            let val = *slot;
            *slot = 0;
            val
        };
        if hwnd != 0 {
            let _ = DestroyWindow(HWND(hwnd as *mut _));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_refcount_and_inject_toggle_should_show() {
        // Pure logic: sessions and inject_recent drive should_show.
        assert!(!should_show() || CONTROL_SESSIONS.load(Ordering::SeqCst) > 0 || inject_recent());
        note_control_session(true);
        assert!(should_show());
        note_control_session(false);
        note_inject_input();
        assert!(should_show());
    }
}
