//! Win32 tray icon and the small status window.
//!
//! The notification-area icon and the window icon are the octopus sticker
//! (`assets/agentlink.ico`). The client area uses that sticker's cream, ink,
//! and teal rather than the stock gray dialog.
//!
//! Window handles live in a UI-thread `RefCell`. `WM_CTLCOLORSTATIC` must not
//! borrow that cell: `SetWindowText` can send the message before it returns.
//! Brushes and text roles live in their own thread-locals for the same reason.
//! Destroying a window also re-enters the window procedure, so those calls
//! happen after the cell is released.

use std::cell::RefCell;
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, COLORREF, ERROR_ALREADY_EXISTS, HANDLE, HINSTANCE, HWND, LPARAM,
    LRESULT, RECT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateBitmap, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, CreatePen,
    CreateSolidBrush, DeleteDC, DeleteObject, DrawFocusRect, DrawTextW, Ellipse, EndPaint,
    FillRect, GetDC, GetSysColorBrush, Rectangle, ReleaseDC, RoundRect, SelectObject, SetBkColor,
    SetBkMode, SetTextColor, CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS, DEFAULT_CHARSET,
    DEFAULT_PITCH, DT_CENTER, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER, FF_DONTCARE, HBRUSH, HDC,
    HFONT, OUT_DEFAULT_PRECIS, PAINTSTRUCT, PS_SOLID, SYS_COLOR_INDEX, TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Controls::{
    CheckDlgButton, InitCommonControlsEx, IsDlgButtonChecked, SetWindowTheme, BST_CHECKED,
    BST_UNCHECKED, DRAWITEMSTRUCT, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, ODS_DISABLED,
    ODS_FOCUS, ODS_SELECTED, ODT_BUTTON,
};
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW, NOTIFY_ICON_MESSAGE,
};
use windows::Win32::UI::HiDpi::{
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, AppendMenuW, CreateIconFromResourceEx, CreateIconIndirect, CreatePopupMenu,
    CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, DispatchMessageW,
    DrawIconEx, FindWindowW, GetClientRect, GetCursorPos, GetMessageW, GetSystemMetrics,
    GetWindowTextLengthW, GetWindowTextW, KillTimer, LoadCursorW, MessageBoxW, PostMessageW,
    PostQuitMessage, RegisterClassExW, SendMessageW, SetForegroundWindow, SetProcessDPIAware,
    SetTimer, SetWindowTextW, ShowWindow, TrackPopupMenu, TranslateMessage, BS_AUTOCHECKBOX,
    BS_OWNERDRAW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, DI_NORMAL, ES_AUTOHSCROLL, ES_PASSWORD,
    HICON, HMENU, ICONINFO, ICON_BIG, ICON_SMALL, IDC_ARROW, IMAGE_FLAGS, MB_ICONERROR, MB_OK,
    MF_SEPARATOR, MF_STRING, MSG, SM_CXICON, SM_CXSMICON, SW_HIDE, SW_SHOW, TPM_RETURNCMD,
    TPM_RIGHTBUTTON, WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CTLCOLORBTN,
    WM_CTLCOLOREDIT, WM_CTLCOLORSTATIC, WM_DESTROY, WM_DRAWITEM, WM_ERASEBKGND, WM_GETFONT,
    WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_PAINT, WM_RBUTTONUP, WM_SETICON, WM_TIMER, WNDCLASSEXW,
    WS_BORDER, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN, WS_MINIMIZEBOX, WS_OVERLAPPED, WS_SYSMENU,
    WS_TABSTOP, WS_VISIBLE,
};

use crate::tray::{
    self, SignInRequest, StatusView, Supervisor, TrayContext, TRAY_CALLBACK, TRAY_QUIT, TRAY_SHOW,
    TRAY_START,
};

const IDC_STATUS: u16 = 101;
const IDC_RELAY: u16 = 102;
const IDC_NODE: u16 = 103;
const IDC_PAIRING: u16 = 104;
const IDC_ACCOUNT: u16 = 105;
const IDC_DETAIL: u16 = 106;
const IDC_HINT: u16 = 107;
const IDC_AUTOSTART: u16 = 201;
const IDC_START: u16 = 202;
const IDC_STOP: u16 = 203;
const IDC_RECONNECT: u16 = 204;
const IDC_SIGNIN: u16 = 205;
const IDC_SIGNOUT: u16 = 206;
const IDC_INVITE: u16 = 207;
const IDC_APPLY: u16 = 208;
const IDC_USER: u16 = 301;
const IDC_PASS: u16 = 302;
const IDC_TOTP: u16 = 303;
const IDC_OK: u16 = 304;
const IDC_CANCEL: u16 = 305;
const IDC_SIGNMSG: u16 = 306;

const MENU_OPEN: u16 = 1;
const MENU_START: u16 = 2;
const MENU_STOP: u16 = 3;
const MENU_RECONNECT: u16 = 4;
const MENU_QUIT: u16 = 5;
const MENU_CONTROLLER: u16 = 6;

const TIMER_REFRESH: usize = 1;
const COLOR_WINDOW: i32 = 5;

/// Client size of the status window. `CreateWindow` receives the outer size.
const CLIENT_W: i32 = 420;
const CLIENT_H: i32 = 560;
const SIGN_W: i32 = 420;
const SIGN_H: i32 = 324;
const MARK: i32 = 48;

// COLORREF is 0x00BBGGRR. Linear dark tokens (same RGB as controller/theme.rs).
const CREAM: u32 = 0x000A_0908; // bg.page #08090a
const INK: u32 = 0x00F8_F8F7; // text.primary #f7f8f8
const MUTED: u32 = 0x0098_8F8A; // text.muted #8a8f98
const SECTION: u32 = 0x00E0_D6D0; // text.body #d0d6e0
const TEAL: u32 = 0x00D2_6A5E; // accent.bg #5e6ad2
const TEAL_DOWN: u32 = 0x00FF_7082; // accent.hover #828fff
const FIELD: u32 = 0x001B_1A19; // bg.surface #191a1b
const MIST: u32 = 0x0011_100F; // bg.panel #0f1011
const ALERT: u32 = 0x004D_48E5; // danger #e5484d

const ICO: &[u8] = include_bytes!("../assets/agentlink.ico");

thread_local! {
    static APP: RefCell<Option<App>> = const { RefCell::new(None) };
}
static EVENTS: Mutex<Vec<UiEvent>> = Mutex::new(Vec::new());
static STATUS_COLOR: AtomicU32 = AtomicU32::new(STOPPED);
static HEADER_ICON: AtomicUsize = AtomicUsize::new(0);
static MAIN_HWND: AtomicUsize = AtomicUsize::new(0);

const ONLINE: u32 = 0x0044_A627; // success #27a644
const CONNECTING: u32 = 0x0023_A6F5; // warn #f5a623
const OFFLINE: u32 = 0x004D_48E5; // danger #e5484d
const STOPPED: u32 = 0x006D_6662; // text.faint #62666d

#[derive(Clone, Copy)]
enum TextRole {
    Title,
    Status,
    Section,
    Body,
    Hint,
    Detail,
    Alert,
}

struct Chrome {
    cream: HBRUSH,
    teal: HBRUSH,
    field: HBRUSH,
    primary: HBRUSH,
    primary_down: HBRUSH,
    secondary: HBRUSH,
    secondary_down: HBRUSH,
}

thread_local! {
    static CHROME: RefCell<Option<Chrome>> = const { RefCell::new(None) };
    static TEXT_ROLES: RefCell<Vec<(usize, TextRole, bool)>> = const { RefCell::new(Vec::new()) };
}

enum UiEvent {
    SignedIn(String),
    SignFailed(String),
    SignedOut,
    SignOutFailed(String),
}

struct SignInDialog {
    hwnd: HWND,
    user: HWND,
    pass: HWND,
    totp: HWND,
    message: HWND,
    busy: bool,
}

struct Icons {
    large: HICON,
    small: HICON,
    header: HICON,
}

struct App {
    hwnd: HWND,
    status: HWND,
    relay: HWND,
    node: HWND,
    pairing: HWND,
    account: HWND,
    detail: HWND,
    hint: HWND,
    invite: HWND,
    signin: Option<SignInDialog>,
    supervisor: Supervisor,
    ctx: TrayContext,
    data_dir: std::path::PathBuf,
    binary: std::path::PathBuf,
    icons: Icons,
    shown_connection: String,
    font: HFONT,
    title_font: HFONT,
    section_font: HFONT,
    status_font: HFONT,
    button_font: HFONT,
    quit: bool,
    mutex: HANDLE,
}

pub fn run(ctx: &TrayContext) -> Result<i32> {
    let data_dir = tray::resolve_data_dir(ctx.data_dir.as_deref())?;
    tray::init_tray_log(&data_dir);
    unsafe {
        // Prefer per-monitor v2 (matches agentlink-desktop). Fall back to the
        // system-DPI v1 call on older Windows builds.
        if SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2).is_err() {
            let _ = SetProcessDPIAware();
        }
        let icc = INITCOMMONCONTROLSEX {
            dwSize: std::mem::size_of::<INITCOMMONCONTROLSEX>() as u32,
            dwICC: ICC_STANDARD_CLASSES,
        };
        let _ = InitCommonControlsEx(&icc);
    }
    let Some(mutex) = claim_single_instance(ctx.background)? else {
        return Ok(0);
    };
    let binary = tray::current_binary()?;
    let instance = module_instance()?;
    ensure_chrome();
    let icons = Icons {
        large: brand_icon(system_metric(SM_CXICON, 32)),
        small: brand_icon(system_metric(SM_CXSMICON, 16)),
        header: brand_icon(MARK),
    };
    HEADER_ICON.store(icons.header.0 as usize, Ordering::Relaxed);
    let font = ui_font(-15, 400);
    let title_font = ui_font(-22, 700);
    let section_font = ui_font(-13, 600);
    let status_font = ui_font(-18, 700);
    let button_font = ui_font(-15, 600);
    register_class(instance, icons.large, icons.small, w!("AgentlinkTray"))?;
    register_class(instance, icons.large, icons.small, w!("AgentlinkSignIn"))?;
    let hwnd = create_main(instance)?;
    stamp_icons(hwnd, icons.large, icons.small);
    let title = labeled(
        hwnd,
        "agentlink",
        80,
        16,
        320,
        26,
        0,
        instance,
        TextRole::Title,
        false,
    );
    let status = labeled(
        hwnd,
        "",
        80,
        44,
        320,
        22,
        IDC_STATUS,
        instance,
        TextRole::Status,
        false,
    );
    let relay_label = labeled(
        hwnd,
        "Relay",
        20,
        80,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        false,
    );
    let relay = labeled(
        hwnd,
        "",
        20,
        98,
        380,
        22,
        IDC_RELAY,
        instance,
        TextRole::Body,
        false,
    );
    let node_label = labeled(
        hwnd,
        "This computer",
        20,
        130,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        false,
    );
    let node = labeled(
        hwnd,
        "",
        20,
        148,
        380,
        22,
        IDC_NODE,
        instance,
        TextRole::Body,
        false,
    );
    let pairing = labeled(
        hwnd,
        "",
        20,
        170,
        380,
        22,
        IDC_PAIRING,
        instance,
        TextRole::Body,
        false,
    );
    let account_label = labeled(
        hwnd,
        "Account",
        20,
        202,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        false,
    );
    let account = labeled(
        hwnd,
        "",
        20,
        220,
        380,
        22,
        IDC_ACCOUNT,
        instance,
        TextRole::Body,
        false,
    );
    let _signin = button(hwnd, "Sign in", 20, 250, 118, 32, IDC_SIGNIN, instance);
    let _signout = button(hwnd, "Sign out", 146, 250, 118, 32, IDC_SIGNOUT, instance);
    let _autostart = checkbox(
        hwnd,
        "Start when I sign in",
        20,
        294,
        280,
        24,
        IDC_AUTOSTART,
        instance,
    );
    let hint = labeled(
        hwnd,
        "No administrator. Starts when you sign in to Windows.",
        20,
        320,
        380,
        36,
        IDC_HINT,
        instance,
        TextRole::Hint,
        false,
    );
    let _start = button(hwnd, "Start", 20, 368, 118, 34, IDC_START, instance);
    let _stop = button(hwnd, "Stop", 146, 368, 118, 34, IDC_STOP, instance);
    let _reconnect = button(
        hwnd,
        "Reconnect",
        272,
        368,
        128,
        34,
        IDC_RECONNECT,
        instance,
    );
    let invite_label = labeled(
        hwnd,
        "Invite or pairing token",
        20,
        416,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        false,
    );
    let invite = edit(hwnd, 20, 434, 380, 28, IDC_INVITE, instance, false);
    let _apply = button(hwnd, "Apply invite", 20, 470, 150, 32, IDC_APPLY, instance);
    let detail = labeled(
        hwnd,
        "",
        20,
        512,
        380,
        40,
        IDC_DETAIL,
        instance,
        TextRole::Detail,
        false,
    );
    apply_font(title, title_font);
    apply_font(status, status_font);
    for control in [relay_label, node_label, account_label, invite_label] {
        apply_font(control, section_font);
    }
    for control in [
        relay, node, pairing, account, detail, hint, _autostart, invite,
    ] {
        apply_font(control, font);
    }
    for control in [_signin, _signout, _start, _stop, _reconnect, _apply] {
        apply_font(control, button_font);
    }
    calm_checkbox(_autostart);
    MAIN_HWND.store(hwnd_key(hwnd), Ordering::Relaxed);
    let app = App {
        hwnd,
        status,
        relay,
        node,
        pairing,
        account,
        detail,
        hint,
        invite,
        signin: None,
        supervisor: Supervisor::new(ctx, data_dir.clone()),
        ctx: ctx.clone(),
        data_dir,
        binary,
        icons,
        shown_connection: String::new(),
        font,
        title_font,
        section_font,
        status_font,
        button_font,
        quit: false,
        mutex,
    };
    APP.with(|slot| {
        *slot.borrow_mut() = Some(app);
    });
    with_app(|app| {
        // Sign-in starts `tray --background` only. Drop a leftover `node` Run
        // value for this data directory, then run the node in this process.
        tray::retire_duplicate_node_autostart(&app.binary, &app.data_dir);
        if let tray::TrayLaunch::Run { connect: true } =
            tray::tray_launch(app.ctx.background, false)
        {
            app.supervisor.start();
        }
    });
    unsafe {
        let _ = SetTimer(Some(hwnd), TIMER_REFRESH, 500, None);
        let _ = CheckDlgButton(
            hwnd,
            IDC_AUTOSTART as i32,
            if tray::autostart_enabled() {
                BST_CHECKED
            } else {
                BST_UNCHECKED
            },
        );
    }
    refresh();
    add_tray_icon();
    if !ctx.background {
        unsafe {
            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = SetForegroundWindow(hwnd);
        }
    }
    message_loop();
    if let Some(app) = APP.with(|slot| slot.borrow_mut().take()) {
        // The window procedure already stopped the loop. Stop the node here,
        // after the UI thread is done borrowing the window.
        let mut app = app;
        app.supervisor.stop();
        unsafe {
            let _ = DestroyIcon(app.icons.large);
            let _ = DestroyIcon(app.icons.small);
            let _ = DestroyIcon(app.icons.header);
            let _ = DeleteObject(app.font.into());
            let _ = DeleteObject(app.title_font.into());
            let _ = DeleteObject(app.section_font.into());
            let _ = DeleteObject(app.status_font.into());
            let _ = DeleteObject(app.button_font.into());
            let _ = CloseHandle(app.mutex);
        }
    }
    Ok(0)
}

pub fn report_error(text: &str) {
    let text = HSTRING::from(text);
    unsafe {
        let _ = MessageBoxW(None, &text, w!("agentlink"), MB_OK | MB_ICONERROR);
    }
}

pub fn post(message: u32) -> bool {
    unsafe {
        let Ok(hwnd) = find_tray_window() else {
            return false;
        };
        PostMessageW(Some(hwnd), message, WPARAM(0), LPARAM(0)).is_ok()
    }
}

fn find_tray_window() -> Result<HWND> {
    unsafe { FindWindowW(w!("AgentlinkTray"), PCWSTR::null()).map_err(|err| anyhow!("{err}")) }
}

fn signal_existing_tray(background: bool) {
    if let tray::TrayLaunch::Signal { message } = tray::tray_launch(background, true) {
        post(message);
    }
}

fn claim_single_instance(background: bool) -> Result<Option<HANDLE>> {
    unsafe {
        match CreateMutexW(None, true, w!("Local\\agentlink-tray")) {
            Ok(handle) if GetLastError() == ERROR_ALREADY_EXISTS => {
                let _ = CloseHandle(handle);
                signal_existing_tray(background);
                Ok(None)
            }
            Ok(handle) => Ok(Some(handle)),
            Err(err)
                if GetLastError() == ERROR_ALREADY_EXISTS
                    || err.code().0 == ERROR_ALREADY_EXISTS.0 as i32 =>
            {
                signal_existing_tray(background);
                Ok(None)
            }
            Err(err) => Err(anyhow!("tray mutex: {err}")),
        }
    }
}

fn module_instance() -> Result<HINSTANCE> {
    let module = unsafe { GetModuleHandleW(None).context("module handle")? };
    Ok(HINSTANCE(module.0))
}

fn message_loop() {
    unsafe {
        let mut msg = MSG::default();
        loop {
            let got = GetMessageW(&mut msg, None, 0, 0);
            if got.0 <= 0 {
                break;
            }
            let _ = TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
}

fn refresh() {
    let close = with_app(|app| {
        app.supervisor.tick();
        let loaded = tray::load_view(&app.data_dir, &app.ctx.config_dir);
        let mut view = tray::apply_supervisor_view(
            loaded,
            app.supervisor.running(),
            app.supervisor.stop_requested(),
            app.supervisor.restarting(),
            app.supervisor.last_exit.as_deref(),
        );
        let close = drain_events(app, &mut view);
        paint(app, &view);
        note_connection(app, &view.connection.clone());
        close
    });
    if let Some(hwnd) = close.flatten() {
        unsafe {
            let _ = DestroyWindow(hwnd);
        }
    }
}

fn drain_events(app: &mut App, view: &mut StatusView) -> Option<HWND> {
    let Ok(mut queue) = EVENTS.lock() else {
        return None;
    };
    let events = std::mem::take(&mut *queue);
    drop(queue);
    let mut close = None;
    for event in events {
        match event {
            UiEvent::SignedIn(user) => {
                close = app.signin.take().map(|dialog| dialog.hwnd);
                view.account = format!("Signed in as {user}");
                view.detail = format!("Signed in as {user}. Reconnecting…");
                app.supervisor.reconnect();
            }
            UiEvent::SignFailed(err) => {
                if let Some(dialog) = app.signin.as_mut() {
                    dialog.busy = false;
                    set_text(dialog.message, &err);
                }
                view.detail = err;
            }
            UiEvent::SignedOut => {
                view.account = "Not signed in".into();
                view.detail = "Signed out".into();
            }
            UiEvent::SignOutFailed(err) => {
                view.detail = err;
            }
        }
    }
    close
}

fn paint(app: &App, view: &StatusView) {
    set_text(app.status, &format!("● {}", view.connection));
    set_text(app.relay, &view.relay);
    set_text(app.node, &view.node_name);
    set_text(app.pairing, &view.pairing);
    set_text(app.account, &view.account);
    set_text(app.detail, &view.detail);
    // Soft-prompt beside the Sign in button when paired without an account session.
    let hint = if view.account == "Paired without account sign-in" {
        "Use Sign in for shares and devices. Pairing alone keeps the node online."
    } else {
        "No administrator. Starts when you sign in to Windows."
    };
    set_text(app.hint, hint);
    STATUS_COLOR.store(status_color(&view.connection), Ordering::Relaxed);
}

fn note_connection(app: &mut App, connection: &str) {
    if app.shown_connection == connection {
        return;
    }
    app.shown_connection = connection.to_string();
    let tip = format!("agentlink — {connection}");
    unsafe {
        shell_icon(app.hwnd, app.icons.small, &tip, NIM_MODIFY);
    }
}

fn status_color(connection: &str) -> u32 {
    match connection {
        "Online" => ONLINE,
        "Connecting" => CONNECTING,
        "Offline" => OFFLINE,
        _ => STOPPED,
    }
}

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    match msg {
        WM_COMMAND => {
            let id = (wparam.0 & 0xffff) as u16;
            on_command(hwnd, id);
            LRESULT(0)
        }
        WM_TIMER => {
            refresh();
            LRESULT(0)
        }
        msg if msg == TRAY_CALLBACK => {
            match lparam.0 as u32 {
                WM_LBUTTONUP | WM_LBUTTONDBLCLK => show_main(),
                WM_RBUTTONUP => show_menu(hwnd),
                _ => {}
            }
            LRESULT(0)
        }
        msg if msg == TRAY_SHOW => {
            show_main();
            LRESULT(0)
        }
        msg if msg == TRAY_QUIT => {
            request_quit();
            LRESULT(0)
        }
        msg if msg == TRAY_START => {
            with_app(|app| app.supervisor.start());
            refresh();
            LRESULT(0)
        }
        WM_CTLCOLORSTATIC => color_static(wparam, lparam),
        WM_CTLCOLOREDIT => color_edit(wparam),
        WM_CTLCOLORBTN => color_button(wparam),
        WM_DRAWITEM => {
            draw_item(lparam);
            LRESULT(1)
        }
        WM_ERASEBKGND => {
            erase_background(hwnd, HDC(wparam.0 as *mut c_void));
            LRESULT(1)
        }
        WM_PAINT => {
            paint_window(hwnd);
            LRESULT(0)
        }
        WM_CLOSE => {
            on_close(hwnd);
            LRESULT(0)
        }
        WM_DESTROY => {
            on_destroy(hwnd);
            LRESULT(0)
        }
        _ => DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

fn on_command(parent: HWND, id: u16) {
    match id {
        IDC_AUTOSTART => toggle_autostart(parent),
        IDC_START => {
            with_app(|app| app.supervisor.start());
        }
        IDC_STOP => {
            with_app(|app| app.supervisor.stop());
        }
        IDC_RECONNECT => {
            with_app(|app| app.supervisor.reconnect());
        }
        IDC_SIGNIN => open_sign_in(),
        IDC_SIGNOUT => begin_sign_out(),
        IDC_APPLY => apply_invite(),
        IDC_OK => begin_sign_in(),
        IDC_CANCEL => dismiss_sign_in(),
        MENU_OPEN => show_main(),
        MENU_CONTROLLER => open_controller(),
        MENU_START => {
            with_app(|app| app.supervisor.start());
        }
        MENU_STOP => {
            with_app(|app| app.supervisor.stop());
        }
        MENU_RECONNECT => {
            with_app(|app| app.supervisor.reconnect());
        }
        MENU_QUIT => request_quit(),
        _ => {}
    }
    let quit = with_app(|app| app.quit).unwrap_or(false);
    if !quit {
        refresh();
    }
}

fn toggle_autostart(parent: HWND) {
    let checked = unsafe { IsDlgButtonChecked(parent, IDC_AUTOSTART as i32) } == BST_CHECKED.0;
    let outcome = with_app(|app| {
        if checked {
            tray::install_user_autostart(&app.binary, &app.data_dir)
                .map(|()| "Start-on-login is on.".to_string())
                .map_err(|err| err.to_string())
        } else {
            tray::remove_user_autostart()
                .map(|()| "Start-on-login is off.".to_string())
                .map_err(|err| err.to_string())
        }
    });
    let Some(outcome) = outcome else {
        return;
    };
    match outcome {
        Ok(message) => {
            with_app(|app| set_text(app.detail, &message));
        }
        Err(err) => {
            unsafe {
                let _ = CheckDlgButton(
                    parent,
                    IDC_AUTOSTART as i32,
                    if tray::autostart_enabled() {
                        BST_CHECKED
                    } else {
                        BST_UNCHECKED
                    },
                );
            }
            with_app(|app| set_text(app.detail, &err));
        }
    }
}

fn apply_invite() {
    let Some((data_dir, text, relay, fingerprint, trust, name)) = with_app(|app| {
        (
            app.data_dir.clone(),
            window_text(app.invite),
            app.ctx.relay.clone(),
            app.ctx.fingerprint.clone(),
            app.ctx.trust.clone(),
            app.ctx.name.clone(),
        )
    }) else {
        return;
    };
    match tray::apply_pairing_text(&data_dir, &text, relay, fingerprint, trust, name) {
        Ok(name) => {
            with_app(|app| {
                set_text(app.invite, "");
                set_text(
                    app.detail,
                    &format!("Saved pairing for {name}. Reconnecting…"),
                );
                app.supervisor.reconnect();
            });
        }
        Err(err) => {
            with_app(|app| set_text(app.detail, &err.to_string()));
        }
    }
}

fn begin_sign_out() {
    let Some(config_dir) = with_app(|app| app.ctx.config_dir.clone()) else {
        return;
    };
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                push_event(UiEvent::SignOutFailed(err.to_string()));
                return;
            }
        };
        let event = match runtime.block_on(tray::sign_out(&config_dir)) {
            Ok(()) => UiEvent::SignedOut,
            Err(err) => UiEvent::SignOutFailed(err.to_string()),
        };
        push_event(event);
    });
}

fn begin_sign_in() {
    let Some(request) = with_app(|app| {
        let Some(dialog) = app.signin.as_ref() else {
            return None;
        };
        if dialog.busy {
            return None;
        }
        let username = window_text(dialog.user);
        let password = window_text(dialog.pass);
        let totp = window_text(dialog.totp);
        let request = SignInRequest {
            config_dir: app.ctx.config_dir.clone(),
            data_dir: app.data_dir.clone(),
            relay: app.ctx.relay.clone(),
            fingerprint: app.ctx.fingerprint.clone(),
            trust: app.ctx.trust.clone(),
            name: app.ctx.name.clone(),
            username,
            password,
            totp: Some(totp),
        };
        if let Some(dialog) = app.signin.as_mut() {
            dialog.busy = true;
            set_text(dialog.pass, "");
            set_text(dialog.message, "Signing in…");
        }
        Some(request)
    })
    .flatten() else {
        return;
    };
    std::thread::spawn(move || {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                push_event(UiEvent::SignFailed(err.to_string()));
                return;
            }
        };
        let event = match runtime.block_on(tray::sign_in_and_enroll(request)) {
            Ok(user) => UiEvent::SignedIn(user),
            Err(err) => UiEvent::SignFailed(err.to_string()),
        };
        push_event(event);
    });
}

fn push_event(event: UiEvent) {
    if let Ok(mut queue) = EVENTS.lock() {
        queue.push(event);
    }
}

fn open_sign_in() {
    let existing = with_app(|app| app.signin.as_ref().map(|dialog| dialog.hwnd)).flatten();
    if let Some(hwnd) = existing {
        unsafe {
            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = SetForegroundWindow(hwnd);
        }
        return;
    }
    let Ok(instance) = module_instance() else {
        return;
    };
    let hwnd = match create_dialog(instance, "Sign in") {
        Ok(hwnd) => hwnd,
        Err(err) => {
            with_app(|app| set_text(app.detail, &err.to_string()));
            return;
        }
    };
    let relay = with_app(|app| window_text(app.relay)).unwrap_or_default();
    let banner = labeled(
        hwnd,
        &format!("Relay  {relay}"),
        20,
        18,
        380,
        22,
        0,
        instance,
        TextRole::Body,
        true,
    );
    let user_label = labeled(
        hwnd,
        "Username",
        20,
        50,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        true,
    );
    let user = edit(hwnd, 20, 70, 380, 28, IDC_USER, instance, false);
    let pass_label = labeled(
        hwnd,
        "Password",
        20,
        108,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        true,
    );
    let pass = edit(hwnd, 20, 128, 380, 28, IDC_PASS, instance, true);
    let totp_label = labeled(
        hwnd,
        "Authenticator code (optional)",
        20,
        166,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        true,
    );
    let totp = edit(hwnd, 20, 186, 380, 28, IDC_TOTP, instance, false);
    let message = labeled(
        hwnd,
        "",
        20,
        222,
        380,
        36,
        IDC_SIGNMSG,
        instance,
        TextRole::Alert,
        true,
    );
    let _cancel = button(hwnd, "Cancel", 200, 270, 90, 32, IDC_CANCEL, instance);
    let _ok = button(hwnd, "Sign in", 300, 270, 100, 32, IDC_OK, instance);
    if let Some((font, section_font, button_font)) =
        with_app(|app| (app.font, app.section_font, app.button_font))
    {
        for control in [banner, user, pass, totp, message] {
            apply_font(control, font);
        }
        for control in [user_label, pass_label, totp_label] {
            apply_font(control, section_font);
        }
        for control in [_cancel, _ok] {
            apply_font(control, button_font);
        }
    }
    with_app(|app| {
        app.signin = Some(SignInDialog {
            hwnd,
            user,
            pass,
            totp,
            message,
            busy: false,
        });
    });
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
}

fn dismiss_sign_in() {
    let hwnd = with_app(|app| app.signin.take().map(|dialog| dialog.hwnd)).flatten();
    if let Some(hwnd) = hwnd {
        forget_dialog_text();
        unsafe {
            let _ = DestroyWindow(hwnd);
        }
    }
}

fn show_main() {
    let Some(hwnd) = with_app(|app| app.hwnd) else {
        return;
    };
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
}

fn request_quit() {
    let Some(hwnd) = with_app(|app| {
        app.quit = true;
        app.supervisor.stop();
        app.hwnd
    }) else {
        return;
    };
    unsafe {
        let _ = DestroyWindow(hwnd);
    }
}

/// Launch the controller window from the tray menu.
///
/// The tray process is a node: without this entry a Windows machine has no way
/// to reach the controller UI short of running `agentlink controller` by hand.
/// `hidden` keeps the helper's console suppressed; the eframe window the child
/// creates is still visible.
fn open_controller() {
    let Ok(exe) = std::env::current_exe() else {
        return;
    };
    let _ = agentlink_core::process::hidden(&exe)
        .arg("controller")
        .spawn();
}

fn show_menu(owner: HWND) {
    unsafe {
        let Ok(menu) = CreatePopupMenu() else {
            return;
        };
        let _ = AppendMenuW(menu, MF_STRING, MENU_OPEN as usize, w!("Open"));
        let _ = AppendMenuW(menu, MF_STRING, MENU_CONTROLLER as usize, w!("Controller..."));
        let _ = AppendMenuW(menu, MF_STRING, MENU_START as usize, w!("Start"));
        let _ = AppendMenuW(menu, MF_STRING, MENU_STOP as usize, w!("Stop"));
        let _ = AppendMenuW(menu, MF_STRING, MENU_RECONNECT as usize, w!("Reconnect"));
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(menu, MF_STRING, MENU_QUIT as usize, w!("Quit"));
        let _ = SetForegroundWindow(owner);
        let mut point = windows::Win32::Foundation::POINT::default();
        let _ = GetCursorPos(&mut point);
        let selected = TrackPopupMenu(
            menu,
            TPM_RETURNCMD | TPM_RIGHTBUTTON,
            point.x,
            point.y,
            None,
            owner,
            None,
        );
        let _ = DestroyMenu(menu);
        let id = selected.0 as u16;
        if id != 0 {
            on_command(owner, id);
        }
    }
}

fn on_close(hwnd: HWND) {
    let role = with_app(|app| {
        if app
            .signin
            .as_ref()
            .is_some_and(|dialog| dialog.hwnd == hwnd)
        {
            app.signin = None;
            CloseRole::Dialog
        } else if app.quit {
            CloseRole::Quit
        } else {
            CloseRole::Hide
        }
    });
    match role {
        Some(CloseRole::Hide) => unsafe {
            let _ = ShowWindow(hwnd, SW_HIDE);
        },
        Some(CloseRole::Dialog) => {
            forget_dialog_text();
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
        }
        Some(CloseRole::Quit) => unsafe {
            let _ = DestroyWindow(hwnd);
        },
        None => {}
    }
}

enum CloseRole {
    Hide,
    Dialog,
    Quit,
}

fn on_destroy(hwnd: HWND) {
    let main = with_app(|app| app.hwnd == hwnd);
    if main == Some(true) {
        unsafe {
            remove_tray_icon(hwnd);
            let _ = KillTimer(Some(hwnd), TIMER_REFRESH);
            PostQuitMessage(0);
        }
    }
}

fn color_static(wparam: WPARAM, lparam: LPARAM) -> LRESULT {
    let child = hwnd_key(HWND(lparam.0 as *mut c_void));
    let role = TEXT_ROLES.with(|roles| {
        roles
            .borrow()
            .iter()
            .find(|(key, _, _)| *key == child)
            .map(|(_, role, _)| *role)
    });
    let color = match role {
        Some(TextRole::Status) => STATUS_COLOR.load(Ordering::Relaxed),
        Some(TextRole::Section) => SECTION,
        Some(TextRole::Hint) | Some(TextRole::Detail) => MUTED,
        Some(TextRole::Alert) => ALERT,
        _ => INK,
    };
    unsafe {
        let hdc = HDC(wparam.0 as *mut c_void);
        let _ = SetTextColor(hdc, COLORREF(color));
        let _ = SetBkMode(hdc, TRANSPARENT);
        LRESULT(cream_brush().0 as isize)
    }
}

fn color_edit(wparam: WPARAM) -> LRESULT {
    unsafe {
        let hdc = HDC(wparam.0 as *mut c_void);
        let _ = SetTextColor(hdc, COLORREF(INK));
        let _ = SetBkColor(hdc, COLORREF(FIELD));
        LRESULT(field_brush().0 as isize)
    }
}

fn color_button(wparam: WPARAM) -> LRESULT {
    unsafe {
        let hdc = HDC(wparam.0 as *mut c_void);
        let _ = SetTextColor(hdc, COLORREF(INK));
        let _ = SetBkMode(hdc, TRANSPARENT);
        LRESULT(cream_brush().0 as isize)
    }
}

fn add_tray_icon() {
    with_app(|app| unsafe {
        shell_icon(app.hwnd, app.icons.small, "agentlink — Stopped", NIM_ADD);
    });
}

fn remove_tray_icon(hwnd: HWND) {
    unsafe {
        let mut nid = NOTIFYICONDATAW::default();
        nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
        nid.hWnd = hwnd;
        nid.uID = 1;
        let _ = Shell_NotifyIconW(NIM_DELETE, &nid);
    }
}

unsafe fn shell_icon(hwnd: HWND, icon: HICON, tip: &str, message: NOTIFY_ICON_MESSAGE) {
    let mut nid = NOTIFYICONDATAW::default();
    nid.cbSize = std::mem::size_of::<NOTIFYICONDATAW>() as u32;
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP;
    nid.uCallbackMessage = TRAY_CALLBACK;
    nid.hIcon = icon;
    let tip: Vec<u16> = tip
        .encode_utf16()
        .take(127)
        .chain(std::iter::once(0))
        .collect();
    nid.szTip[..tip.len()].copy_from_slice(&tip);
    let _ = Shell_NotifyIconW(message, &nid);
}

fn with_app<T>(f: impl FnOnce(&mut App) -> T) -> Option<T> {
    APP.with(|slot| {
        let mut borrowed = slot.borrow_mut();
        borrowed.as_mut().map(f)
    })
}

fn register_class(instance: HINSTANCE, large: HICON, small: HICON, name: PCWSTR) -> Result<()> {
    unsafe {
        let class = WNDCLASSEXW {
            cbSize: std::mem::size_of::<WNDCLASSEXW>() as u32,
            style: CS_HREDRAW | CS_VREDRAW,
            lpfnWndProc: Some(wnd_proc),
            hInstance: instance,
            hIcon: large,
            hCursor: LoadCursorW(None, IDC_ARROW).unwrap_or_default(),
            hbrBackground: cream_brush(),
            lpszClassName: name,
            hIconSm: small,
            ..Default::default()
        };
        if RegisterClassExW(&class) == 0 {
            return Err(anyhow!("register window class"));
        }
    }
    Ok(())
}

fn create_main(instance: HINSTANCE) -> Result<HWND> {
    create_overlapped(
        instance,
        w!("AgentlinkTray"),
        "agentlink",
        CLIENT_W,
        CLIENT_H,
        false,
    )
}

fn create_dialog(instance: HINSTANCE, title: &str) -> Result<HWND> {
    create_overlapped(instance, w!("AgentlinkSignIn"), title, SIGN_W, SIGN_H, true)
}

fn window_style() -> WINDOW_STYLE {
    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN
}

fn outer_size(client_w: i32, client_h: i32) -> (i32, i32) {
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: client_w,
        bottom: client_h,
    };
    unsafe {
        let _ = AdjustWindowRectEx(&mut rect, window_style(), false, WINDOW_EX_STYLE::default());
    }
    (rect.right - rect.left, rect.bottom - rect.top)
}

fn create_overlapped(
    instance: HINSTANCE,
    class: PCWSTR,
    title: &str,
    client_w: i32,
    client_h: i32,
    show: bool,
) -> Result<HWND> {
    let title = HSTRING::from(title);
    let (width, height) = outer_size(client_w, client_h);
    unsafe {
        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            &title,
            window_style(),
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            width,
            height,
            None,
            None,
            Some(instance),
            None,
        )
        .map_err(|err| anyhow!("create window: {err}"))?;
        if show {
            let _ = ShowWindow(hwnd, SW_SHOW);
        }
        Ok(hwnd)
    }
}

fn labeled(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    instance: HINSTANCE,
    role: TextRole,
    dialog: bool,
) -> HWND {
    let hwnd = child(
        parent,
        w!("STATIC"),
        text,
        WS_CHILD | WS_VISIBLE,
        x,
        y,
        w,
        h,
        id,
        instance,
    );
    remember_text(hwnd, role, dialog);
    hwnd
}

fn button(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    instance: HINSTANCE,
) -> HWND {
    child(
        parent,
        w!("BUTTON"),
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_OWNERDRAW as u32),
        x,
        y,
        w,
        h,
        id,
        instance,
    )
}

fn checkbox(
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    instance: HINSTANCE,
) -> HWND {
    child(
        parent,
        w!("BUTTON"),
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
        x,
        y,
        w,
        h,
        id,
        instance,
    )
}

fn edit(
    parent: HWND,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    instance: HINSTANCE,
    password: bool,
) -> HWND {
    let mut style =
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WINDOW_STYLE(ES_AUTOHSCROLL as u32);
    if password {
        style |= WINDOW_STYLE(ES_PASSWORD as u32);
    }
    child(parent, w!("EDIT"), "", style, x, y, w, h, id, instance)
}

fn child(
    parent: HWND,
    class: PCWSTR,
    text: &str,
    style: WINDOW_STYLE,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    instance: HINSTANCE,
) -> HWND {
    let text = HSTRING::from(text);
    unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE::default(),
            class,
            &text,
            style,
            x,
            y,
            w,
            h,
            Some(parent),
            Some(HMENU(id as usize as *mut c_void)),
            Some(instance),
            None,
        )
        .unwrap_or_default()
    }
}

fn apply_font(hwnd: HWND, font: HFONT) {
    if hwnd.0.is_null() {
        return;
    }
    unsafe {
        let _ = SendMessageW(
            hwnd,
            0x0030, // WM_SETFONT
            Some(WPARAM(font.0 as usize)),
            Some(LPARAM(1)),
        );
    }
}

fn set_text(hwnd: HWND, text: &str) {
    if hwnd.0.is_null() {
        return;
    }
    let text = HSTRING::from(text);
    unsafe {
        let _ = SetWindowTextW(hwnd, &text);
    }
}

fn window_text(hwnd: HWND) -> String {
    if hwnd.0.is_null() {
        return String::new();
    }
    unsafe {
        let len = GetWindowTextLengthW(hwnd).max(0) as usize;
        let mut buf = vec![0u16; len + 1];
        let n = GetWindowTextW(hwnd, &mut buf);
        String::from_utf16_lossy(&buf[..n.max(0) as usize])
    }
}

fn ui_font(height: i32, weight: i32) -> HFONT {
    unsafe {
        CreateFontW(
            height,
            0,
            0,
            0,
            weight,
            0,
            0,
            0,
            DEFAULT_CHARSET,
            OUT_DEFAULT_PRECIS,
            CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY,
            (DEFAULT_PITCH.0 as u32) | (FF_DONTCARE.0 as u32),
            w!("Segoe UI"),
        )
    }
}

fn hwnd_key(hwnd: HWND) -> usize {
    hwnd.0 as usize
}

fn calm_checkbox(hwnd: HWND) {
    if hwnd.0.is_null() {
        return;
    }
    // Classic checkbox so the cream page shows through. Themed buttons ignore
    // WM_CTLCOLORBTN and paint a gray box behind the label.
    unsafe {
        let _ = SetWindowTheme(hwnd, w!(" "), w!(" "));
    }
}

fn stamp_icons(hwnd: HWND, large: HICON, small: HICON) {
    unsafe {
        let _ = SendMessageW(
            hwnd,
            WM_SETICON,
            Some(WPARAM(ICON_BIG as usize)),
            Some(LPARAM(large.0 as isize)),
        );
        let _ = SendMessageW(
            hwnd,
            WM_SETICON,
            Some(WPARAM(ICON_SMALL as usize)),
            Some(LPARAM(small.0 as isize)),
        );
    }
}

fn system_metric(
    index: windows::Win32::UI::WindowsAndMessaging::SYSTEM_METRICS_INDEX,
    fallback: i32,
) -> i32 {
    let value = unsafe { GetSystemMetrics(index) };
    if value > 0 {
        value
    } else {
        fallback
    }
}

fn ensure_chrome() {
    CHROME.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_some() {
            return;
        }
        unsafe {
            *slot = Some(Chrome {
                cream: CreateSolidBrush(COLORREF(CREAM)),
                teal: CreateSolidBrush(COLORREF(TEAL)),
                field: CreateSolidBrush(COLORREF(FIELD)),
                primary: CreateSolidBrush(COLORREF(TEAL)),
                primary_down: CreateSolidBrush(COLORREF(TEAL_DOWN)),
                secondary: CreateSolidBrush(COLORREF(FIELD)),
                secondary_down: CreateSolidBrush(COLORREF(MIST)),
            });
        }
    });
}

fn brush_or_sys(pick: impl FnOnce(&Chrome) -> HBRUSH) -> HBRUSH {
    CHROME.with(|slot| {
        if let Some(chrome) = slot.borrow().as_ref() {
            pick(chrome)
        } else {
            unsafe { GetSysColorBrush(SYS_COLOR_INDEX(COLOR_WINDOW)) }
        }
    })
}

fn cream_brush() -> HBRUSH {
    brush_or_sys(|chrome| chrome.cream)
}

fn field_brush() -> HBRUSH {
    brush_or_sys(|chrome| chrome.field)
}

fn remember_text(hwnd: HWND, role: TextRole, dialog: bool) {
    if hwnd.0.is_null() {
        return;
    }
    TEXT_ROLES.with(|roles| roles.borrow_mut().push((hwnd_key(hwnd), role, dialog)));
}

fn forget_dialog_text() {
    TEXT_ROLES.with(|roles| roles.borrow_mut().retain(|(_, _, dialog)| !*dialog));
}

fn erase_background(hwnd: HWND, hdc: HDC) {
    unsafe {
        let mut rect = RECT::default();
        let _ = GetClientRect(hwnd, &mut rect);
        let _ = FillRect(hdc, &rect, cream_brush());
        rect.bottom = 6;
        let _ = FillRect(hdc, &rect, brush_or_sys(|chrome| chrome.teal));
    }
}

fn paint_window(hwnd: HWND) {
    unsafe {
        let mut paint = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut paint);
        let icon = HEADER_ICON.load(Ordering::Relaxed);
        let main = hwnd_key(hwnd) == MAIN_HWND.load(Ordering::Relaxed);
        if main && icon != 0 {
            let _ = DrawIconEx(
                hdc,
                20,
                16,
                HICON(icon as *mut c_void),
                MARK,
                MARK,
                0,
                None,
                DI_NORMAL,
            );
        }
        let _ = EndPaint(hwnd, &paint);
    }
}

fn draw_item(lparam: LPARAM) {
    unsafe {
        let draw = &*(lparam.0 as *const DRAWITEMSTRUCT);
        if draw.CtlType != ODT_BUTTON {
            return;
        }
        draw_button(draw);
    }
}

fn draw_button(draw: &DRAWITEMSTRUCT) {
    let pressed = draw.itemState.0 & ODS_SELECTED.0 != 0;
    let focused = draw.itemState.0 & ODS_FOCUS.0 != 0;
    let disabled = draw.itemState.0 & ODS_DISABLED.0 != 0;
    let primary = matches!(
        draw.CtlID as u16,
        IDC_START | IDC_SIGNIN | IDC_APPLY | IDC_OK
    );
    unsafe {
        let _ = FillRect(draw.hDC, &draw.rcItem, cream_brush());
        let brush = brush_or_sys(|chrome| match (primary, pressed) {
            (true, true) => chrome.primary_down,
            (true, false) => chrome.primary,
            (false, true) => chrome.secondary_down,
            (false, false) => chrome.secondary,
        });
        let pen = CreatePen(PS_SOLID, 2, COLORREF(INK));
        let previous_brush = SelectObject(draw.hDC, brush.into());
        let previous_pen = SelectObject(draw.hDC, pen.into());
        let inset = if pressed { 3 } else { 2 };
        let _ = RoundRect(
            draw.hDC,
            draw.rcItem.left + inset,
            draw.rcItem.top + inset,
            draw.rcItem.right - inset,
            draw.rcItem.bottom - inset,
            12,
            12,
        );
        let _ = SelectObject(draw.hDC, previous_brush);
        let _ = SelectObject(draw.hDC, previous_pen);
        let _ = DeleteObject(pen.into());

        let got = SendMessageW(draw.hwndItem, WM_GETFONT, None, None);
        let font = HFONT(got.0 as *mut c_void);
        let previous_font = if font.0.is_null() {
            None
        } else {
            Some(SelectObject(draw.hDC, font.into()))
        };
        let _ = SetBkMode(draw.hDC, TRANSPARENT);
        let _ = SetTextColor(draw.hDC, COLORREF(if disabled { MUTED } else { INK }));
        let mut text = window_text(draw.hwndItem)
            .encode_utf16()
            .collect::<Vec<_>>();
        if !text.is_empty() {
            let mut rect = draw.rcItem;
            if pressed {
                rect.left += 1;
                rect.top += 1;
            }
            let _ = DrawTextW(
                draw.hDC,
                &mut text,
                &mut rect,
                DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_NOPREFIX,
            );
        }
        if let Some(previous) = previous_font {
            let _ = SelectObject(draw.hDC, previous);
        }
        if focused {
            let focus = RECT {
                left: draw.rcItem.left + 4,
                top: draw.rcItem.top + 4,
                right: draw.rcItem.right - 4,
                bottom: draw.rcItem.bottom - 4,
            };
            let _ = DrawFocusRect(draw.hDC, &focus);
        }
    }
}

fn brand_icon(px: i32) -> HICON {
    if let Some(icon) = icon_from_embedded(px) {
        return icon;
    }
    circle_icon(TEAL)
}

fn icon_from_embedded(px: i32) -> Option<HICON> {
    let images = ico_images(ICO);
    let image = images.iter().min_by_key(|image| (image.size - px).abs())?;
    unsafe { CreateIconFromResourceEx(image.dib, true, 0x0003_0000, px, px, IMAGE_FLAGS(0)).ok() }
}

struct IcoImage<'a> {
    size: i32,
    dib: &'a [u8],
}

fn ico_images(bytes: &[u8]) -> Vec<IcoImage<'_>> {
    if bytes.len() < 6 {
        return Vec::new();
    }
    let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    let mut images = Vec::new();
    for index in 0..count {
        let entry = 6 + index * 16;
        if entry + 16 > bytes.len() {
            break;
        }
        let mut size = bytes[entry] as i32;
        if size == 0 {
            size = 256;
        }
        let bytes_in =
            u32::from_le_bytes(bytes[entry + 8..entry + 12].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(bytes[entry + 12..entry + 16].try_into().unwrap()) as usize;
        if offset + bytes_in > bytes.len() || bytes_in < 16 {
            continue;
        }
        let dib = &bytes[offset..offset + bytes_in];
        if dib.starts_with(b"\x89PNG") {
            continue;
        }
        images.push(IcoImage { size, dib });
    }
    images
}

fn circle_icon(color: u32) -> HICON {
    unsafe {
        let size = 32;
        let screen = GetDC(None);
        let mem = CreateCompatibleDC(Some(screen));
        let bitmap = CreateCompatibleBitmap(screen, size, size);
        let previous = SelectObject(mem, bitmap.into());
        let white = CreateSolidBrush(COLORREF(0x00FF_FFFF));
        let _ = SelectObject(mem, white.into());
        let _ = Rectangle(mem, 0, 0, size, size);
        let brush = CreateSolidBrush(COLORREF(color));
        let pen = CreatePen(PS_SOLID, 1, COLORREF(color));
        let _ = SelectObject(mem, brush.into());
        let _ = SelectObject(mem, pen.into());
        let _ = Ellipse(mem, 2, 2, size - 2, size - 2);
        let _ = SelectObject(mem, previous);
        let mask = CreateBitmap(size, size, 1, 1, None);
        let info = ICONINFO {
            fIcon: true.into(),
            xHotspot: 0,
            yHotspot: 0,
            hbmMask: mask,
            hbmColor: bitmap,
        };
        let icon = CreateIconIndirect(&info).unwrap_or_default();
        let _ = DeleteObject(bitmap.into());
        let _ = DeleteObject(mask.into());
        let _ = DeleteObject(white.into());
        let _ = DeleteObject(brush.into());
        let _ = DeleteObject(pen.into());
        let _ = DeleteDC(mem);
        let _ = ReleaseDC(None, screen);
        icon
    }
}
