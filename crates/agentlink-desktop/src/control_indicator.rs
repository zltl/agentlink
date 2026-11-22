//! Always-on-top banner while this machine is being remotely controlled.
//!
//! Shown for WebRTC sessions that grant control, and for JPEG/`inject_input`
//! control. Hidden when every control session ends and inject goes idle.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::thread;
use std::time::{Duration, Instant};

const INJECT_IDLE: Duration = Duration::from_secs(45);
const BANNER: &str = "AgentLink is controlling this computer";
const BANNER_ZH: &str = "AgentLink 正在远程控制此电脑";

#[derive(Default)]
struct IndicatorState {
    sessions: usize,
    last_inject: Option<Instant>,
    shown: bool,
}

impl IndicatorState {
    fn inject_recent(&self, now: Instant) -> bool {
        self.last_inject
            .map(|at| now.saturating_duration_since(at) < INJECT_IDLE)
            .unwrap_or(false)
    }

    fn should_show(&self, now: Instant) -> bool {
        self.sessions > 0 || self.inject_recent(now)
    }

    fn note_session(&mut self, active: bool) {
        if active {
            self.sessions = self.sessions.saturating_add(1);
        } else {
            self.sessions = self.sessions.saturating_sub(1);
        }
    }

    fn note_inject(&mut self, now: Instant) {
        self.last_inject = Some(now);
    }
}

static STATE: Mutex<IndicatorState> = Mutex::new(IndicatorState {
    sessions: 0,
    last_inject: None,
    shown: false,
});
static STARTED: AtomicBool = AtomicBool::new(false);

fn banner_text_for_lang(lang: &str) -> &'static str {
    if lang.trim().to_ascii_lowercase().starts_with("zh") {
        BANNER_ZH
    } else {
        BANNER
    }
}

#[cfg(any(target_os = "windows", test))]
fn banner_text_for_win_lang_id(lang_id: u16) -> &'static str {
    // PRIMARYLANGID(lang_id) == LANG_CHINESE (0x04)
    if (lang_id & 0x03ff) == 0x04 {
        BANNER_ZH
    } else {
        BANNER
    }
}

fn banner_text() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        let lang_id = unsafe { windows::Win32::Globalization::GetUserDefaultUILanguage() };
        if lang_id != 0 {
            return banner_text_for_win_lang_id(lang_id);
        }
    }
    let env_lang = std::env::var("LANG")
        .or_else(|_| std::env::var("LC_ALL"))
        .unwrap_or_default();
    banner_text_for_lang(&env_lang)
}

/// A WebRTC (or similar) control-capable session started or stopped.
pub fn note_control_session(active: bool) {
    ensure_worker();
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.note_session(active);
    sync_locked(&mut state);
}

/// Pointer/keyboard arrived through `inject_input` (JPEG control path).
pub fn note_inject_input() {
    ensure_worker();
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.note_inject(Instant::now());
    sync_locked(&mut state);
}

#[cfg(test)]
fn should_show() -> bool {
    let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    state.should_show(Instant::now())
}

fn sync_locked(state: &mut IndicatorState) {
    let want = state.should_show(Instant::now());
    if want == state.shown {
        return;
    }
    if want {
        if platform_show(banner_text()) {
            state.shown = true;
        }
    } else {
        platform_hide();
        state.shown = false;
    }
}

fn refresh() {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    sync_locked(&mut state);
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::{
        AtomEnum, Char2b, ConnectionExt as _, CreateGCAux, CreateWindowAux, EventMask, PropMode,
        WindowClass,
    };
    use x11rb::protocol::Event;
    use x11rb::rust_connection::RustConnection;
    use x11rb::wrapper::ConnectionExt as _;

    struct Banner {
        conn: Arc<RustConnection>,
        window: u32,
        stop: Arc<AtomicBool>,
    }

    static BANNER: Mutex<Option<Banner>> = Mutex::new(None);

    const UNICODE_FONTS: &[&str] = &[
        "-*-unifont-*-*-*-*-*-*-*-*-*-*-iso10646-1",
        "-misc-fixed-medium-r-normal--15-*-*-*-*-*-iso10646-1",
        "-misc-fixed-medium-r-normal--14-*-*-*-*-*-iso10646-1",
        "-*-*-medium-r-normal--16-*-*-*-*-*-iso10646-1",
        "-*-*-medium-r-normal--*-*-*-*-*-*-iso10646-1",
    ];

    pub fn show(text: &str) -> bool {
        let mut slot = BANNER.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return true;
        }
        let Ok((conn, screen_num)) = x11rb::connect(None) else {
            tracing::debug!("control indicator: no X11 display");
            return false;
        };
        let conn = Arc::new(conn);
        let screen = &conn.setup().roots[screen_num];
        let root = screen.root;
        let width = screen.width_in_pixels.min(720).max(320);
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
            .event_mask(EventMask::EXPOSURE | EventMask::STRUCTURE_NOTIFY);
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
        if let Ok(cookie) = conn.map_window(window) {
            let _ = cookie.check();
        }
        paint(&conn, window, text);
        let _ = conn.flush();

        let stop = Arc::new(AtomicBool::new(false));
        let loop_conn = conn.clone();
        let loop_stop = stop.clone();
        let loop_text = text.to_string();
        let _ = thread::Builder::new()
            .name("agentlink-x11-banner".into())
            .spawn(move || {
                while !loop_stop.load(Ordering::Relaxed) {
                    match loop_conn.poll_for_event() {
                        Ok(Some(Event::Expose(_))) => {
                            paint(&loop_conn, window, &loop_text);
                            let _ = loop_conn.flush();
                        }
                        Ok(Some(Event::DestroyNotify(_))) => break,
                        Ok(Some(_)) => {}
                        Ok(None) => thread::sleep(Duration::from_millis(50)),
                        Err(_) => break,
                    }
                }
            });

        *slot = Some(Banner { conn, window, stop });
        true
    }

    pub fn hide() {
        let mut slot = BANNER.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(banner) = slot.take() {
            banner.stop.store(true, Ordering::Relaxed);
            let _ = banner.conn.unmap_window(banner.window);
            let _ = banner.conn.destroy_window(banner.window);
            let _ = banner.conn.flush();
        }
    }

    fn open_unicode_font(conn: &RustConnection) -> Option<u32> {
        for pattern in UNICODE_FONTS {
            let Ok(fid) = conn.generate_id() else {
                return None;
            };
            let ok = conn
                .open_font(fid, pattern.as_bytes())
                .ok()
                .and_then(|c| c.check().ok())
                .is_some();
            if ok {
                return Some(fid);
            }
        }
        None
    }

    fn paint(conn: &RustConnection, window: u32, text: &str) {
        let Ok(gc) = conn.generate_id() else {
            return;
        };
        let font = if !text.is_ascii() {
            open_unicode_font(conn)
        } else {
            None
        };
        let mut aux = CreateGCAux::new()
            .foreground(0x00_ff_ff_ff)
            .background(0x00_c4_3e_24);
        if let Some(fid) = font {
            aux = aux.font(fid);
        }
        let _ = conn.create_gc(gc, window, &aux);
        if font.is_some() {
            let chars: Vec<Char2b> = text
                .chars()
                .filter_map(|ch| {
                    let cp = ch as u32;
                    if cp <= 0xffff {
                        Some(Char2b {
                            byte1: (cp >> 8) as u8,
                            byte2: (cp & 0xff) as u8,
                        })
                    } else {
                        None
                    }
                })
                .collect();
            let _ = conn.image_text16(window, gc, 12, 24, &chars);
        } else {
            // Fall back to readable ASCII banner when the X server lacks an
            // iso10646-1 font, instead of rendering non-ASCII text as "???".
            let fallback = if text.is_ascii() { text } else { super::BANNER };
            let _ = conn.image_text8(window, gc, 12, 24, fallback.as_bytes());
        }
        let _ = conn.free_gc(gc);
        if let Some(fid) = font {
            let _ = conn.close_font(fid);
        }
    }

    fn set_wm_name(conn: &RustConnection, window: u32, text: &str) -> Result<(), ()> {
        let ascii = if text.is_ascii() { text } else { super::BANNER };
        conn.change_property(
            PropMode::REPLACE,
            window,
            AtomEnum::WM_NAME,
            AtomEnum::STRING,
            8,
            ascii.len() as u32,
            ascii.as_bytes(),
        )
        .map_err(|_| ())?
        .check()
        .map_err(|_| ())?;
        if let (Ok(net_wm_name), Ok(utf8_string)) =
            (intern(conn, b"_NET_WM_NAME"), intern(conn, b"UTF8_STRING"))
        {
            let _ = conn
                .change_property(
                    PropMode::REPLACE,
                    window,
                    net_wm_name,
                    utf8_string,
                    8,
                    text.len() as u32,
                    text.as_bytes(),
                )
                .ok()
                .and_then(|c| c.check().ok());
        }
        Ok(())
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
    use windows::Win32::Foundation::{COLORREF, HWND, LPARAM, LRESULT, POINT, RECT, WPARAM};
    use windows::Win32::Graphics::Gdi::{
        BeginPaint, CreateFontW, CreateSolidBrush, DeleteObject, DrawTextW, EndPaint, FillRect,
        GetMonitorInfoW, InvalidateRect, MonitorFromPoint, SelectObject, SetBkMode, SetTextColor,
        CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, DEFAULT_CHARSET, DEFAULT_PITCH, DT_CENTER,
        DT_SINGLELINE, DT_VCENTER, FF_DONTCARE, FW_SEMIBOLD, HGDIOBJ, MONITORINFO,
        MONITOR_DEFAULTTOPRIMARY, OUT_DEFAULT_PRECIS, PAINTSTRUCT, TRANSPARENT,
    };
    use windows::Win32::UI::HiDpi::{GetDpiForMonitor, GetDpiForWindow, MDT_EFFECTIVE_DPI};
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetClientRect,
        GetMessageW, GetSystemMetrics, LoadCursorW, PostMessageW, RegisterClassW,
        SetLayeredWindowAttributes, SetWindowPos, ShowWindow, TranslateMessage, CS_HREDRAW,
        CS_VREDRAW, HWND_TOPMOST, IDC_ARROW, LWA_ALPHA, MSG, SM_CXSCREEN, SWP_NOACTIVATE,
        SWP_NOMOVE, SWP_NOSIZE, SWP_NOZORDER, SWP_SHOWWINDOW, SW_SHOWNOACTIVATE, WM_DESTROY,
        WM_DPICHANGED, WM_PAINT, WM_USER, WNDCLASSW, WS_EX_LAYERED, WS_EX_NOACTIVATE,
        WS_EX_TOOLWINDOW, WS_EX_TOPMOST, WS_EX_TRANSPARENT, WS_POPUP,
    };

    const WM_SHOW_BANNER: u32 = WM_USER + 41;
    const WM_HIDE_BANNER: u32 = WM_USER + 42;

    static HOST: AtomicBool = AtomicBool::new(false);
    static HWND_SLOT: Mutex<isize> = Mutex::new(0);
    static BANNER_HWND: Mutex<isize> = Mutex::new(0);
    static TEXT: Mutex<String> = Mutex::new(String::new());

    fn scale_dip(dip: i32, dpi: u32) -> i32 {
        ((dip as i64 * dpi.max(96) as i64) + 48) as i32 / 96
    }

    unsafe fn primary_monitor_geometry(fallback_hwnd: HWND) -> (RECT, u32) {
        let hmon = MonitorFromPoint(POINT { x: 0, y: 0 }, MONITOR_DEFAULTTOPRIMARY);
        let mut info = MONITORINFO {
            cbSize: std::mem::size_of::<MONITORINFO>() as u32,
            ..Default::default()
        };
        let rect = if GetMonitorInfoW(hmon, &mut info).as_bool() {
            info.rcMonitor
        } else {
            RECT {
                left: 0,
                top: 0,
                right: GetSystemMetrics(SM_CXSCREEN).max(720),
                bottom: 720,
            }
        };
        let mut dpi_x = 0u32;
        let mut dpi_y = 0u32;
        let dpi = if GetDpiForMonitor(hmon, MDT_EFFECTIVE_DPI, &mut dpi_x, &mut dpi_y).is_ok()
            && dpi_x >= 96
        {
            dpi_x
        } else {
            let win_dpi = GetDpiForWindow(fallback_hwnd);
            if win_dpi >= 96 {
                win_dpi
            } else {
                96
            }
        };
        (rect, dpi)
    }

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
            WM_DPICHANGED => {
                if lparam.0 != 0 {
                    let suggested = &*(lparam.0 as *const RECT);
                    let _ = SetWindowPos(
                        hwnd,
                        None,
                        suggested.left,
                        suggested.top,
                        suggested.right - suggested.left,
                        suggested.bottom - suggested.top,
                        SWP_NOZORDER | SWP_NOACTIVATE,
                    );
                }
                let _ = InvalidateRect(Some(hwnd), None, true);
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
                let dpi = GetDpiForWindow(hwnd).max(96);
                let font_h = -scale_dip(16, dpi);
                let font = CreateFontW(
                    font_h,
                    0,
                    0,
                    0,
                    FW_SEMIBOLD.0 as i32,
                    0,
                    0,
                    0,
                    DEFAULT_CHARSET,
                    OUT_DEFAULT_PRECIS,
                    CLIP_DEFAULT_PRECIS,
                    CLEARTYPE_QUALITY,
                    (DEFAULT_PITCH.0 | FF_DONTCARE.0) as u32,
                    w!("Segoe UI"),
                );
                let prev_font = if !font.is_invalid() {
                    Some(SelectObject(hdc, HGDIOBJ(font.0)))
                } else {
                    None
                };
                let text = TEXT.lock().ok().map(|t| t.clone()).unwrap_or_default();
                let mut wide: Vec<u16> = text.encode_utf16().chain(std::iter::once(0)).collect();
                let _ = DrawTextW(
                    hdc,
                    &mut wide,
                    &mut rc,
                    DT_CENTER | DT_VCENTER | DT_SINGLELINE,
                );
                if let Some(old) = prev_font {
                    let _ = SelectObject(hdc, old);
                    let _ = DeleteObject(HGDIOBJ(font.0));
                }
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
            let _ = InvalidateRect(Some(hwnd), None, true);
            return;
        }
        let class = w!("AgentLinkControlBanner");
        let (mon_rc, dpi) = primary_monitor_geometry(host);
        let mon_w = (mon_rc.right - mon_rc.left).max(320);
        let width = scale_dip(560, dpi).min((mon_w - 16).max(240));
        let height = scale_dip(36, dpi);
        let x = mon_rc.left + ((mon_w - width) / 2).max(0);
        let y = mon_rc.top + scale_dip(8, dpi);
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
        let mut st = IndicatorState::default();
        let now = Instant::now();
        assert!(!st.should_show(now));

        // Double-deactivate never underflows.
        st.note_session(false);
        assert_eq!(st.sessions, 0);

        st.note_session(true);
        st.note_session(true);
        assert!(st.should_show(now));
        st.note_session(false);
        assert!(st.should_show(now));
        st.note_session(false);
        assert!(!st.should_show(now));

        // Inject shows only while within INJECT_IDLE; expires cleanly after.
        st.note_inject(now);
        assert!(st.should_show(now + Duration::from_secs(44)));
        assert!(!st.should_show(now + INJECT_IDLE));

        // Global synchronized entrypoints still track active state.
        note_control_session(true);
        assert!(should_show());
        note_control_session(false);
    }

    #[test]
    fn banner_locale_selection_matches_env_and_windows_lang_id() {
        assert_eq!(banner_text_for_lang("zh_CN.UTF-8"), BANNER_ZH);
        assert_eq!(banner_text_for_lang("ZH-TW"), BANNER_ZH);
        assert_eq!(banner_text_for_lang("en_US.UTF-8"), BANNER);
        assert_eq!(banner_text_for_lang(""), BANNER);

        assert_eq!(banner_text_for_win_lang_id(0x0804), BANNER_ZH); // zh-CN
        assert_eq!(banner_text_for_win_lang_id(0x0404), BANNER_ZH); // zh-TW
        assert_eq!(banner_text_for_win_lang_id(0x0409), BANNER); // en-US
        assert_eq!(banner_text_for_win_lang_id(0x0411), BANNER); // ja-JP
    }
}
