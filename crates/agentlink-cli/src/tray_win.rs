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
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use windows::core::{w, HSTRING, PCWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, COLORREF, ERROR_ALREADY_EXISTS, HANDLE, HINSTANCE, HWND, LPARAM,
    LRESULT, POINT, RECT, WPARAM,
};
use windows::Win32::Graphics::Gdi::{
    BeginPaint, CreateBitmap, CreateCompatibleBitmap, CreateCompatibleDC, CreateFontW, CreatePen,
    CreateSolidBrush, DeleteDC, DeleteObject, DrawFocusRect, DrawTextW, Ellipse, EndPaint,
    FillRect, GetDC, GetSysColorBrush, InvalidateRect, Rectangle, ReleaseDC, RoundRect,
    SelectObject, SetBkColor, SetBkMode, SetTextColor, CLEARTYPE_QUALITY, CLIP_DEFAULT_PRECIS,
    DEFAULT_CHARSET, DEFAULT_PITCH, DT_CENTER, DT_NOPREFIX, DT_SINGLELINE, DT_VCENTER,
    FF_DONTCARE, HBRUSH, HDC, HFONT, OUT_DEFAULT_PRECIS, PAINTSTRUCT, PS_SOLID, SYS_COLOR_INDEX,
    TRANSPARENT,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Threading::CreateMutexW;
use windows::Win32::UI::Controls::{
    CheckDlgButton, InitCommonControlsEx, IsDlgButtonChecked, SetWindowTheme, BST_CHECKED,
    BST_UNCHECKED, DRAWITEMSTRUCT, ICC_STANDARD_CLASSES, INITCOMMONCONTROLSEX, ODS_DISABLED,
    ODS_FOCUS, ODS_SELECTED, ODT_BUTTON,
};
use windows::Win32::UI::HiDpi::{
    AdjustWindowRectExForDpi, GetDpiForWindow, GetSystemMetricsForDpi,
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::Shell::{
    Shell_NotifyIconW, NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NIM_MODIFY,
    NOTIFYICONDATAW, NOTIFY_ICON_MESSAGE,
};
use windows::Win32::UI::WindowsAndMessaging::{
    AdjustWindowRectEx, AppendMenuW, CreateIconFromResourceEx, CreateIconIndirect, CreatePopupMenu,
    CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow, DispatchMessageW,
    DrawIconEx, FindWindowW, GetClientRect, GetCursorPos, GetMessageW, GetSystemMetrics,
    GetWindowTextLengthW, GetWindowTextW, IsChild, IsDialogMessageW, KillTimer, LoadCursorW,
    MessageBoxW, MoveWindow, PostMessageW, PostQuitMessage, RegisterClassExW,
    RegisterWindowMessageW, SendMessageW, SetForegroundWindow, SetProcessDPIAware, SetTimer,
    SetWindowPos, SetWindowTextW, ShowWindow, TrackPopupMenu, TranslateMessage, BS_AUTOCHECKBOX,
    BS_OWNERDRAW, CS_HREDRAW, CS_VREDRAW, CW_USEDEFAULT, DI_NORMAL, ES_AUTOHSCROLL, ES_PASSWORD,
    HICON, HMENU, ICONINFO, ICON_BIG, ICON_SMALL, IDCANCEL, IDC_ARROW, IDOK, IMAGE_FLAGS,
    MB_ICONERROR, MB_OK, MF_GRAYED, MF_SEPARATOR, MF_STRING, MSG, SM_CXICON, SM_CXSMICON,
    SWP_NOACTIVATE, SWP_NOZORDER, SW_HIDE, SW_SHOW, TPM_RETURNCMD, TPM_RIGHTBUTTON,
    WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_COMMAND, WM_CTLCOLORBTN, WM_CTLCOLOREDIT,
    WM_CTLCOLORSTATIC, WM_DESTROY, WM_DPICHANGED, WM_DRAWITEM, WM_ERASEBKGND, WM_GETFONT,
    WM_LBUTTONDBLCLK, WM_LBUTTONUP, WM_NULL, WM_PAINT, WM_RBUTTONUP, WM_SETICON, WM_TIMER,
    WM_USER, WNDCLASSEXW, WS_BORDER, WS_CAPTION, WS_CHILD, WS_CLIPCHILDREN, WS_MINIMIZEBOX,
    WS_OVERLAPPED, WS_SYSMENU, WS_TABSTOP, WS_VISIBLE,
};

use crate::tray::{
    self, SignInRequest, StatusView, Supervisor, TrayContext, TRAY_CALLBACK, TRAY_QUIT, TRAY_SHOW,
    TRAY_START,
};

#[link(name = "user32")]
extern "system" {
    fn EnableWindow(hwnd: HWND, enable: i32) -> i32;
    fn GetFocus() -> HWND;
}

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
const IDC_CONTROLLER: u16 = 209;
const IDC_USER: u16 = 301;
const IDC_PASS: u16 = 302;
const IDC_TOTP: u16 = 303;
const IDC_OK: u16 = 304;
const IDC_CANCEL: u16 = 305;
const IDC_SIGNMSG: u16 = 306;
const IDC_SIGN_RELAY: u16 = 307;
const IDC_SIGN_TRUST: u16 = 308;

const MENU_OPEN: u16 = 1;
const MENU_START: u16 = 2;
const MENU_STOP: u16 = 3;
const MENU_RECONNECT: u16 = 4;
const MENU_QUIT: u16 = 5;
const MENU_CONTROLLER: u16 = 6;

const TIMER_REFRESH: usize = 1;
const COLOR_WINDOW: i32 = 5;
const DM_GETDEFID: u32 = WM_USER;
const DC_HASDEFID: usize = 0x534B;

const AUTOSTART_SYNC_INTERVAL: Duration = Duration::from_secs(2);
const NOTICE_INFO_TTL: Duration = Duration::from_secs(6);
const NOTICE_ERROR_TTL: Duration = Duration::from_secs(10);

/// Logical 96-DPI client sizes. Scaled dynamically by `GetDpiForWindow` / `WM_DPICHANGED`.
const CLIENT_W: i32 = 420;
const CLIENT_H: i32 = 568;
const SIGN_W: i32 = 420;
const SIGN_H: i32 = 380;
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
static DETAIL_ALERT: AtomicBool = AtomicBool::new(false);
static HEADER_ICON: AtomicUsize = AtomicUsize::new(0);
static HEADER_DPI: AtomicU32 = AtomicU32::new(96);
static MAIN_HWND: AtomicUsize = AtomicUsize::new(0);
static TASKBAR_CREATED_MSG: AtomicU32 = AtomicU32::new(0);

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

#[derive(Clone, Copy)]
enum FontRole {
    Body,
    Title,
    Section,
    Status,
    Button,
}

struct FontSet {
    body: HFONT,
    title: HFONT,
    section: HFONT,
    status: HFONT,
    button: HFONT,
}

impl FontSet {
    fn for_dpi(dpi: u32) -> Self {
        Self {
            body: ui_font(scale_px(-15, dpi), 400),
            title: ui_font(scale_px(-22, dpi), 700),
            section: ui_font(scale_px(-13, dpi), 600),
            status: ui_font(scale_px(-18, dpi), 700),
            button: ui_font(scale_px(-15, dpi), 600),
        }
    }

    fn pick(&self, role: FontRole) -> HFONT {
        match role {
            FontRole::Body => self.body,
            FontRole::Title => self.title,
            FontRole::Section => self.section,
            FontRole::Status => self.status,
            FontRole::Button => self.button,
        }
    }

    fn delete(self) {
        unsafe {
            let _ = DeleteObject(self.body.into());
            let _ = DeleteObject(self.title.into());
            let _ = DeleteObject(self.section.into());
            let _ = DeleteObject(self.status.into());
            let _ = DeleteObject(self.button.into());
        }
    }
}

/// Logical 96-DPI control geometry so `WM_DPICHANGED` can re-layout cleanly.
struct LayoutItem {
    hwnd: HWND,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    font: FontRole,
}

/// Transient UI banner/toast state kept separate from the 500ms `status.json`
/// poll so `refresh()` never clobbers user feedback immediately after actions.
#[derive(Clone, Debug)]
struct NoticeState {
    message: String,
    is_error: bool,
    expires_at: Instant,
}

#[derive(Default, Clone, Debug)]
struct FeedbackBanner {
    current: Option<NoticeState>,
}

impl FeedbackBanner {
    fn set(&mut self, message: impl Into<String>, is_error: bool, now: Instant) {
        let ttl = if is_error {
            NOTICE_ERROR_TTL
        } else {
            NOTICE_INFO_TTL
        };
        self.current = Some(NoticeState {
            message: message.into(),
            is_error,
            expires_at: now + ttl,
        });
    }

    fn clear(&mut self) {
        self.current = None;
    }

    fn active_at(&mut self, now: Instant) -> Option<(&str, bool)> {
        if self
            .current
            .as_ref()
            .is_some_and(|notice| now >= notice.expires_at)
        {
            self.current = None;
        }
        self.current
            .as_ref()
            .map(|notice| (notice.message.as_str(), notice.is_error))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ButtonStates {
    start: bool,
    stop: bool,
    reconnect: bool,
    signin: bool,
    signout: bool,
    apply: bool,
    controller: bool,
}

impl ButtonStates {
    fn for_view(view: &StatusView, supervisor_running: bool, signing_out: bool) -> Self {
        let running = supervisor_running || view.running;
        let signed_in =
            view.account.starts_with("Signed in as ") || view.account == "Legacy token saved";
        let has_target = view.enrolled || (!view.relay.is_empty() && view.relay != "relay not set");
        Self {
            start: !running,
            stop: running,
            reconnect: running || has_target,
            signin: !signing_out,
            signout: signed_in && !signing_out,
            apply: true,
            controller: true,
        }
    }
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
    SignedIn {
        user: String,
        relay: Option<String>,
        fingerprint: Option<String>,
        trust: Option<String>,
    },
    SignFailed(String),
    SignedOut,
    SignOutFailed(String),
}

struct SignInDialog {
    hwnd: HWND,
    relay: HWND,
    trust: HWND,
    user: HWND,
    pass: HWND,
    totp: HWND,
    message: HWND,
    ok_btn: HWND,
    busy: bool,
    dpi: u32,
    fonts: FontSet,
    controls: Vec<LayoutItem>,
}

struct Icons {
    large: HICON,
    small: HICON,
    header: HICON,
}

impl Icons {
    fn for_dpi(dpi: u32) -> Self {
        Self {
            large: brand_icon(dpi_metric(SM_CXICON, dpi, scale_px(32, dpi))),
            small: brand_icon(dpi_metric(SM_CXSMICON, dpi, scale_px(16, dpi))),
            header: brand_icon(scale_px(MARK, dpi)),
        }
    }

    fn destroy(self) {
        unsafe {
            let _ = DestroyIcon(self.large);
            let _ = DestroyIcon(self.small);
            let _ = DestroyIcon(self.header);
        }
    }
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
    start_btn: HWND,
    stop_btn: HWND,
    reconnect_btn: HWND,
    signin_btn: HWND,
    signout_btn: HWND,
    apply_btn: HWND,
    controller_btn: HWND,
    signin: Option<SignInDialog>,
    supervisor: Supervisor,
    ctx: TrayContext,
    data_dir: PathBuf,
    binary: PathBuf,
    icons: Icons,
    shown_connection: String,
    dpi: u32,
    fonts: FontSet,
    controls: Vec<LayoutItem>,
    feedback: FeedbackBanner,
    signing_out: bool,
    last_autostart_sync: Instant,
    force_autostart_sync: bool,
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
        TASKBAR_CREATED_MSG.store(
            RegisterWindowMessageW(w!("TaskbarCreated")),
            Ordering::Relaxed,
        );
    }
    let Some(mutex) = claim_single_instance(&data_dir, ctx.background)? else {
        return Ok(0);
    };
    let binary = tray::current_binary()?;
    let instance = module_instance()?;
    ensure_chrome();

    let initial_icons = Icons::for_dpi(96);
    let main_class = HSTRING::from(tray::tray_window_class(&data_dir));
    register_class(
        instance,
        initial_icons.large,
        initial_icons.small,
        PCWSTR(main_class.as_ptr()),
    )?;
    register_class(
        instance,
        initial_icons.large,
        initial_icons.small,
        w!("AgentlinkSignIn"),
    )?;
    let hwnd = create_main(instance, PCWSTR(main_class.as_ptr()))?;

    let dpi = window_dpi(hwnd);
    resize_client_for_dpi(hwnd, CLIENT_W, CLIENT_H, dpi);
    let icons = if dpi == 96 {
        initial_icons
    } else {
        initial_icons.destroy();
        Icons::for_dpi(dpi)
    };
    HEADER_ICON.store(icons.header.0 as usize, Ordering::Relaxed);
    HEADER_DPI.store(dpi, Ordering::Relaxed);
    stamp_icons(hwnd, icons.large, icons.small);
    let fonts = FontSet::for_dpi(dpi);

    let mut controls = Vec::new();
    let title = add_label(
        &mut controls,
        hwnd,
        "agentlink",
        80,
        16,
        320,
        26,
        0,
        instance,
        TextRole::Title,
        FontRole::Title,
        false,
        dpi,
    );
    let status = add_label(
        &mut controls,
        hwnd,
        "",
        80,
        44,
        320,
        22,
        IDC_STATUS,
        instance,
        TextRole::Status,
        FontRole::Status,
        false,
        dpi,
    );
    let _relay_label = add_label(
        &mut controls,
        hwnd,
        "Relay",
        20,
        80,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        FontRole::Section,
        false,
        dpi,
    );
    let relay = add_label(
        &mut controls,
        hwnd,
        "",
        20,
        98,
        380,
        22,
        IDC_RELAY,
        instance,
        TextRole::Body,
        FontRole::Body,
        false,
        dpi,
    );
    let _node_label = add_label(
        &mut controls,
        hwnd,
        "This computer",
        20,
        130,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        FontRole::Section,
        false,
        dpi,
    );
    let node = add_label(
        &mut controls,
        hwnd,
        "",
        20,
        148,
        380,
        22,
        IDC_NODE,
        instance,
        TextRole::Body,
        FontRole::Body,
        false,
        dpi,
    );
    let pairing = add_label(
        &mut controls,
        hwnd,
        "",
        20,
        170,
        380,
        22,
        IDC_PAIRING,
        instance,
        TextRole::Body,
        FontRole::Body,
        false,
        dpi,
    );
    let _account_label = add_label(
        &mut controls,
        hwnd,
        "Account",
        20,
        202,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        FontRole::Section,
        false,
        dpi,
    );
    let account = add_label(
        &mut controls,
        hwnd,
        "",
        20,
        220,
        380,
        22,
        IDC_ACCOUNT,
        instance,
        TextRole::Body,
        FontRole::Body,
        false,
        dpi,
    );
    let signin_btn = add_button(
        &mut controls,
        hwnd,
        "Sign in",
        20,
        250,
        118,
        32,
        IDC_SIGNIN,
        instance,
        dpi,
    );
    let signout_btn = add_button(
        &mut controls,
        hwnd,
        "Sign out",
        146,
        250,
        118,
        32,
        IDC_SIGNOUT,
        instance,
        dpi,
    );
    let autostart = add_checkbox(
        &mut controls,
        hwnd,
        "Start when I sign in",
        20,
        294,
        280,
        24,
        IDC_AUTOSTART,
        instance,
        dpi,
    );
    let hint = add_label(
        &mut controls,
        hwnd,
        "No administrator. Starts when you sign in to Windows.",
        20,
        320,
        380,
        36,
        IDC_HINT,
        instance,
        TextRole::Hint,
        FontRole::Body,
        false,
        dpi,
    );
    let start_btn = add_button(
        &mut controls,
        hwnd,
        "Start",
        20,
        368,
        118,
        34,
        IDC_START,
        instance,
        dpi,
    );
    let stop_btn = add_button(
        &mut controls,
        hwnd,
        "Stop",
        146,
        368,
        118,
        34,
        IDC_STOP,
        instance,
        dpi,
    );
    let reconnect_btn = add_button(
        &mut controls,
        hwnd,
        "Reconnect",
        272,
        368,
        128,
        34,
        IDC_RECONNECT,
        instance,
        dpi,
    );
    let _invite_label = add_label(
        &mut controls,
        hwnd,
        "Invite or pairing token",
        20,
        416,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        FontRole::Section,
        false,
        dpi,
    );
    let invite = add_edit(
        &mut controls,
        hwnd,
        20,
        434,
        380,
        28,
        IDC_INVITE,
        instance,
        false,
        dpi,
    );
    let apply_btn = add_button(
        &mut controls,
        hwnd,
        "Apply invite",
        20,
        470,
        150,
        32,
        IDC_APPLY,
        instance,
        dpi,
    );
    let controller_btn = add_button(
        &mut controls,
        hwnd,
        "Open Controller",
        180,
        470,
        220,
        32,
        IDC_CONTROLLER,
        instance,
        dpi,
    );
    let detail = add_label(
        &mut controls,
        hwnd,
        "",
        20,
        512,
        380,
        46,
        IDC_DETAIL,
        instance,
        TextRole::Detail,
        FontRole::Body,
        false,
        dpi,
    );
    let _ = title;
    apply_layout(&controls, &fonts, dpi);
    calm_checkbox(autostart);
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
        start_btn,
        stop_btn,
        reconnect_btn,
        signin_btn,
        signout_btn,
        apply_btn,
        controller_btn,
        signin: None,
        supervisor: Supervisor::new(ctx, data_dir.clone()),
        ctx: ctx.clone(),
        data_dir,
        binary,
        icons,
        shown_connection: String::new(),
        dpi,
        fonts,
        controls,
        feedback: FeedbackBanner::default(),
        signing_out: false,
        last_autostart_sync: Instant::now() - AUTOSTART_SYNC_INTERVAL,
        force_autostart_sync: true,
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
    }
    // Register tray icon BEFORE refresh() so initial NIM_MODIFY updates the tooltip.
    add_tray_icon();
    refresh();
    if !ctx.background {
        unsafe {
            let _ = ShowWindow(hwnd, SW_SHOW);
            let _ = SetForegroundWindow(hwnd);
        }
    }
    message_loop();
    if let Some(app) = APP.with(|slot| slot.borrow_mut().take()) {
        // The window procedure already stopped the loop. Join the embedded node
        // (bounded 3s) and write LinkState::Stopped before exiting.
        let mut app = app;
        app.supervisor.stop();
        if let Some(dialog) = app.signin.take() {
            dialog.fonts.delete();
        }
        app.icons.destroy();
        app.fonts.delete();
        unsafe {
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

#[allow(dead_code)]
pub fn post(message: u32) -> bool {
    post_for(None, message)
}

pub fn post_for(data_dir: Option<&Path>, message: u32) -> bool {
    unsafe {
        let Ok(hwnd) = find_tray_window(data_dir) else {
            return false;
        };
        PostMessageW(Some(hwnd), message, WPARAM(0), LPARAM(0)).is_ok()
    }
}

fn find_tray_window_exact(data_dir: &Path) -> Result<HWND> {
    let class = HSTRING::from(tray::tray_window_class(data_dir));
    unsafe { FindWindowW(PCWSTR(class.as_ptr()), PCWSTR::null()).map_err(|err| anyhow!("{err}")) }
}

fn find_tray_window(data_dir: Option<&Path>) -> Result<HWND> {
    if let Some(dir) = data_dir {
        if let Ok(hwnd) = find_tray_window_exact(dir) {
            return Ok(hwnd);
        }
    }
    unsafe { FindWindowW(w!("AgentlinkTray"), PCWSTR::null()).map_err(|err| anyhow!("{err}")) }
}

fn signal_existing_tray(data_dir: &Path, background: bool) {
    if let tray::TrayLaunch::Signal { message } = tray::tray_launch(background, true) {
        // Retry briefly in case the primary instance acquired the mutex and is
        // still completing CreateWindowExW.
        for attempt in 0..10 {
            if let Ok(hwnd) = find_tray_window_exact(data_dir) {
                if unsafe { PostMessageW(Some(hwnd), message, WPARAM(0), LPARAM(0)).is_ok() } {
                    return;
                }
            }
            if attempt < 9 {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

fn claim_single_instance(data_dir: &Path, background: bool) -> Result<Option<HANDLE>> {
    let mutex_name = HSTRING::from(tray::tray_mutex_name(data_dir));
    unsafe {
        match CreateMutexW(None, true, &mutex_name) {
            Ok(handle) if GetLastError() == ERROR_ALREADY_EXISTS => {
                let _ = CloseHandle(handle);
                signal_existing_tray(data_dir, background);
                Ok(None)
            }
            Ok(handle) => Ok(Some(handle)),
            Err(err)
                if GetLastError() == ERROR_ALREADY_EXISTS
                    || err.code().0 == ERROR_ALREADY_EXISTS.0 as i32 =>
            {
                signal_existing_tray(data_dir, background);
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
            // Copy HWNDs out before calling IsDialogMessageW so synchronous
            // WM_COMMAND dispatch does not re-enter APP's RefCell borrow.
            let (main_hwnd, signin_hwnd) = with_app(|app| {
                (app.hwnd, app.signin.as_ref().map(|dialog| dialog.hwnd))
            })
            .unwrap_or((HWND::default(), None));

            if let Some(dialog_hwnd) = signin_hwnd {
                if (msg.hwnd == dialog_hwnd || IsChild(dialog_hwnd, msg.hwnd).as_bool())
                    && IsDialogMessageW(dialog_hwnd, &msg).as_bool()
                {
                    continue;
                }
            }
            if !main_hwnd.0.is_null()
                && (msg.hwnd == main_hwnd || IsChild(main_hwnd, msg.hwnd).as_bool())
                && IsDialogMessageW(main_hwnd, &msg).as_bool()
            {
                continue;
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
        sync_autostart_checkbox(app);
        note_connection(app, &view.connection.clone());
        close
    });
    if let Some(dialog) = close.flatten() {
        forget_dialog_text();
        unsafe {
            let _ = DestroyWindow(dialog.hwnd);
        }
        dialog.fonts.delete();
    }
}

fn drain_events(app: &mut App, view: &mut StatusView) -> Option<SignInDialog> {
    let Ok(mut queue) = EVENTS.lock() else {
        return None;
    };
    let events = std::mem::take(&mut *queue);
    drop(queue);
    let mut close = None;
    let now = Instant::now();
    for event in events {
        match event {
            UiEvent::SignedIn {
                user,
                relay,
                fingerprint,
                trust,
            } => {
                close = app.signin.take();
                app.supervisor.update_target(relay, fingerprint, trust);
                view.account = format!("Signed in as {user}");
                app.feedback
                    .set(format!("Signed in as {user}. Reconnecting…"), false, now);
                app.supervisor.reconnect();
            }
            UiEvent::SignFailed(err) => {
                if let Some(dialog) = app.signin.as_mut() {
                    dialog.busy = false;
                    set_enabled(dialog.ok_btn, true);
                    set_text(dialog.message, &err);
                }
                app.feedback.set(err, true, now);
            }
            UiEvent::SignedOut => {
                app.signing_out = false;
                view.account = "Not signed in".into();
                app.feedback.set("Signed out.", false, now);
            }
            UiEvent::SignOutFailed(err) => {
                app.signing_out = false;
                app.feedback.set(err, true, now);
            }
        }
    }
    close
}

fn paint(app: &mut App, view: &StatusView) {
    // Store STATUS_COLOR BEFORE updating app.status so the synchronous
    // WM_CTLCOLORSTATIC triggered by SetWindowTextW paints the new state color.
    let next_color = status_color(&view.connection);
    let prev_color = STATUS_COLOR.swap(next_color, Ordering::Relaxed);
    set_text_if_changed(app.status, &format!("● {}", view.connection));
    if prev_color != next_color {
        unsafe {
            let _ = InvalidateRect(Some(app.status), None, true);
        }
    }
    set_text_if_changed(app.relay, &view.relay);
    set_text_if_changed(app.node, &view.node_name);
    set_text_if_changed(app.pairing, &view.pairing);
    set_text_if_changed(app.account, &view.account);

    let (detail_text, is_error) = match app.feedback.active_at(Instant::now()) {
        Some((msg, err)) => (msg.to_string(), err),
        None => (view.detail.clone(), false),
    };
    let prev_alert = DETAIL_ALERT.swap(is_error, Ordering::Relaxed);
    set_text_if_changed(app.detail, &detail_text);
    if prev_alert != is_error {
        unsafe {
            let _ = InvalidateRect(Some(app.detail), None, true);
        }
    }

    // Soft-prompt beside the Sign in button when paired without an account session.
    let hint = if view.account == "Paired without account sign-in" {
        "Use Sign in for shares and devices. Pairing alone keeps the node online."
    } else {
        "No administrator. Starts when you sign in to Windows."
    };
    set_text_if_changed(app.hint, hint);

    let states = ButtonStates::for_view(view, app.supervisor.running(), app.signing_out);
    set_enabled(app.start_btn, states.start);
    set_enabled(app.stop_btn, states.stop);
    set_enabled(app.reconnect_btn, states.reconnect);
    set_enabled(app.signin_btn, states.signin);
    set_enabled(app.signout_btn, states.signout);
    set_enabled(app.apply_btn, states.apply);
    set_enabled(app.controller_btn, states.controller);
}

fn sync_autostart_checkbox(app: &mut App) {
    let now = Instant::now();
    if !app.force_autostart_sync && now.duration_since(app.last_autostart_sync) < AUTOSTART_SYNC_INTERVAL {
        return;
    }
    app.force_autostart_sync = false;
    app.last_autostart_sync = now;
    let desired = if tray::autostart_enabled() {
        BST_CHECKED
    } else {
        BST_UNCHECKED
    };
    let current = unsafe { IsDlgButtonChecked(app.hwnd, IDC_AUTOSTART as i32) };
    if current != desired.0 {
        unsafe {
            let _ = CheckDlgButton(app.hwnd, IDC_AUTOSTART as i32, desired);
        }
    }
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
    let taskbar_msg = TASKBAR_CREATED_MSG.load(Ordering::Relaxed);
    match msg {
        msg if taskbar_msg != 0 && msg == taskbar_msg => {
            recreate_tray_icon();
            LRESULT(0)
        }
        WM_COMMAND => {
            let id = (wparam.0 & 0xffff) as u16;
            on_command(hwnd, id);
            LRESULT(0)
        }
        WM_TIMER => {
            refresh();
            LRESULT(0)
        }
        WM_DPICHANGED => {
            on_dpi_changed(hwnd, wparam, lparam);
            LRESULT(0)
        }
        DM_GETDEFID => get_default_button_id(hwnd),
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
            with_app(|app| {
                app.feedback.clear();
                app.supervisor.start();
            });
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

fn get_default_button_id(hwnd: HWND) -> LRESULT {
    let default_id = with_app(|app| {
        if app.signin.as_ref().is_some_and(|d| d.hwnd == hwnd) {
            Some(IDC_OK)
        } else if app.hwnd == hwnd && unsafe { GetFocus() } == app.invite {
            Some(IDC_APPLY)
        } else {
            None
        }
    })
    .flatten();
    match default_id {
        Some(id) => LRESULT(((DC_HASDEFID << 16) | (id as usize)) as isize),
        None => LRESULT(0),
    }
}

fn on_dpi_changed(hwnd: HWND, wparam: WPARAM, lparam: LPARAM) {
    let new_dpi = (wparam.0 & 0xffff) as u32;
    let new_dpi = if new_dpi >= 48 { new_dpi } else { 96 };
    if lparam.0 != 0 {
        unsafe {
            let rect = &*(lparam.0 as *const RECT);
            let _ = SetWindowPos(
                hwnd,
                None,
                rect.left,
                rect.top,
                rect.right - rect.left,
                rect.bottom - rect.top,
                SWP_NOZORDER | SWP_NOACTIVATE,
            );
        }
    }
    let old_resources = with_app(|app| {
        if app.hwnd == hwnd {
            app.dpi = new_dpi;
            HEADER_DPI.store(new_dpi, Ordering::Relaxed);
            let new_fonts = FontSet::for_dpi(new_dpi);
            apply_layout(&app.controls, &new_fonts, new_dpi);
            let old_fonts = std::mem::replace(&mut app.fonts, new_fonts);
            let new_icons = Icons::for_dpi(new_dpi);
            HEADER_ICON.store(new_icons.header.0 as usize, Ordering::Relaxed);
            stamp_icons(app.hwnd, new_icons.large, new_icons.small);
            let tip = if app.shown_connection.is_empty() {
                "agentlink — Stopped".to_string()
            } else {
                format!("agentlink — {}", app.shown_connection)
            };
            unsafe {
                shell_icon(app.hwnd, new_icons.small, &tip, NIM_MODIFY);
            }
            let old_icons = std::mem::replace(&mut app.icons, new_icons);
            return Some((old_fonts, Some(old_icons)));
        }
        if let Some(dialog) = app.signin.as_mut() {
            if dialog.hwnd == hwnd {
                dialog.dpi = new_dpi;
                let new_fonts = FontSet::for_dpi(new_dpi);
                apply_layout(&dialog.controls, &new_fonts, new_dpi);
                let old_fonts = std::mem::replace(&mut dialog.fonts, new_fonts);
                return Some((old_fonts, None));
            }
        }
        None
    })
    .flatten();
    if let Some((old_fonts, old_icons)) = old_resources {
        old_fonts.delete();
        if let Some(icons) = old_icons {
            icons.destroy();
        }
    }
    unsafe {
        let _ = InvalidateRect(Some(hwnd), None, true);
    }
}

fn on_command(parent: HWND, id: u16) {
    let is_dialog = with_app(|app| app.signin.as_ref().is_some_and(|d| d.hwnd == parent))
        .unwrap_or(false);
    match id {
        id if id == IDOK.0 as u16 => {
            if is_dialog {
                begin_sign_in();
            } else {
                let in_invite = with_app(|app| unsafe { GetFocus() } == app.invite).unwrap_or(false);
                if in_invite {
                    apply_invite();
                }
            }
        }
        id if id == IDCANCEL.0 as u16 => {
            if is_dialog {
                dismiss_sign_in();
            } else {
                on_close(parent);
            }
        }
        IDC_AUTOSTART => toggle_autostart(parent),
        IDC_START => {
            with_app(|app| {
                app.feedback.clear();
                app.supervisor.start();
            });
        }
        IDC_STOP => {
            with_app(|app| {
                app.feedback.clear();
                app.supervisor.request_stop();
            });
        }
        IDC_RECONNECT => {
            with_app(|app| {
                app.feedback.clear();
                app.supervisor.reconnect();
            });
        }
        IDC_SIGNIN => open_sign_in(),
        IDC_SIGNOUT => begin_sign_out(),
        IDC_APPLY => apply_invite(),
        IDC_CONTROLLER => open_controller(),
        IDC_OK => begin_sign_in(),
        IDC_CANCEL => dismiss_sign_in(),
        MENU_OPEN => show_main(),
        MENU_CONTROLLER => open_controller(),
        MENU_START => {
            with_app(|app| {
                app.feedback.clear();
                app.supervisor.start();
            });
        }
        MENU_STOP => {
            with_app(|app| {
                app.feedback.clear();
                app.supervisor.request_stop();
            });
        }
        MENU_RECONNECT => {
            with_app(|app| {
                app.feedback.clear();
                app.supervisor.reconnect();
            });
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
    let now = Instant::now();
    match outcome {
        Ok(message) => {
            with_app(|app| {
                app.force_autostart_sync = true;
                app.feedback.set(message, false, now);
            });
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
            with_app(|app| {
                app.force_autostart_sync = true;
                app.feedback.set(err, true, now);
            });
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
    let now = Instant::now();
    match tray::apply_pairing_text(&data_dir, &text, relay, fingerprint, trust, name) {
        Ok(name) => {
            with_app(|app| {
                set_text(app.invite, "");
                app.feedback
                    .set(format!("Saved pairing for {name}. Reconnecting…"), false, now);
                app.supervisor.reconnect();
            });
        }
        Err(err) => {
            with_app(|app| app.feedback.set(err.to_string(), true, now));
        }
    }
}

fn begin_sign_out() {
    let Some(config_dir) = with_app(|app| {
        if app.signing_out {
            return None;
        }
        app.signing_out = true;
        app.feedback.set("Signing out…", false, Instant::now());
        Some(app.ctx.config_dir.clone())
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
        let Some(dialog) = app.signin.as_mut() else {
            return None;
        };
        if dialog.busy {
            return None;
        }
        let relay_text = window_text(dialog.relay);
        let relay_trimmed = relay_text.trim().to_string();
        let trust_text = window_text(dialog.trust);
        let (fingerprint, trust) = match tray::parse_trust_input(&trust_text) {
            Ok((None, None)) => (app.ctx.fingerprint.clone(), app.ctx.trust.clone()),
            Ok((fp, tr)) => (fp, tr),
            Err(err) => {
                set_text(dialog.message, &err.to_string());
                return None;
            }
        };
        let relay = if relay_trimmed.is_empty() {
            app.ctx.relay.clone()
        } else {
            Some(relay_trimmed)
        };
        let username = window_text(dialog.user);
        let password = window_text(dialog.pass);
        let totp = window_text(dialog.totp);
        let request = SignInRequest {
            config_dir: app.ctx.config_dir.clone(),
            data_dir: app.data_dir.clone(),
            relay,
            fingerprint,
            trust,
            name: app.ctx.name.clone(),
            username,
            password,
            totp: Some(totp),
        };
        dialog.busy = true;
        set_enabled(dialog.ok_btn, false);
        set_text(dialog.pass, "");
        set_text(dialog.message, "Signing in…");
        Some(request)
    })
    .flatten() else {
        return;
    };
    let target_relay = request.relay.clone();
    let target_fp = request.fingerprint.clone();
    let target_trust = request.trust.clone();
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
            Ok(user) => UiEvent::SignedIn {
                user,
                relay: target_relay,
                fingerprint: target_fp,
                trust: target_trust,
            },
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
    let defaults = with_app(|app| tray::prefill_sign_in_defaults(&app.ctx, &app.data_dir))
        .unwrap_or(tray::SignInDefaults {
            relay: String::new(),
            trust: String::new(),
        });
    let hwnd = match create_dialog(instance, "Sign in") {
        Ok(hwnd) => hwnd,
        Err(err) => {
            with_app(|app| app.feedback.set(err.to_string(), true, Instant::now()));
            return;
        }
    };
    let dpi = window_dpi(hwnd);
    resize_client_for_dpi(hwnd, SIGN_W, SIGN_H, dpi);
    let fonts = FontSet::for_dpi(dpi);
    let mut controls = Vec::new();

    let _relay_label = add_label(
        &mut controls,
        hwnd,
        "Relay URL",
        20,
        16,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        FontRole::Section,
        true,
        dpi,
    );
    let relay = add_edit(
        &mut controls,
        hwnd,
        20,
        34,
        380,
        28,
        IDC_SIGN_RELAY,
        instance,
        false,
        dpi,
    );
    let _trust_label = add_label(
        &mut controls,
        hwnd,
        "Certificate trust or pin (system, webpki, or sha256:...)",
        20,
        70,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        FontRole::Section,
        true,
        dpi,
    );
    let trust = add_edit(
        &mut controls,
        hwnd,
        20,
        88,
        380,
        28,
        IDC_SIGN_TRUST,
        instance,
        false,
        dpi,
    );
    let _user_label = add_label(
        &mut controls,
        hwnd,
        "Username",
        20,
        124,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        FontRole::Section,
        true,
        dpi,
    );
    let user = add_edit(
        &mut controls,
        hwnd,
        20,
        142,
        380,
        28,
        IDC_USER,
        instance,
        false,
        dpi,
    );
    let _pass_label = add_label(
        &mut controls,
        hwnd,
        "Password",
        20,
        178,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        FontRole::Section,
        true,
        dpi,
    );
    let pass = add_edit(
        &mut controls,
        hwnd,
        20,
        196,
        380,
        28,
        IDC_PASS,
        instance,
        true,
        dpi,
    );
    let _totp_label = add_label(
        &mut controls,
        hwnd,
        "Authenticator code (optional)",
        20,
        232,
        380,
        16,
        0,
        instance,
        TextRole::Section,
        FontRole::Section,
        true,
        dpi,
    );
    let totp = add_edit(
        &mut controls,
        hwnd,
        20,
        250,
        380,
        28,
        IDC_TOTP,
        instance,
        false,
        dpi,
    );
    let message = add_label(
        &mut controls,
        hwnd,
        "",
        20,
        286,
        380,
        36,
        IDC_SIGNMSG,
        instance,
        TextRole::Alert,
        FontRole::Body,
        true,
        dpi,
    );
    let _cancel = add_button(
        &mut controls,
        hwnd,
        "Cancel",
        200,
        330,
        90,
        32,
        IDC_CANCEL,
        instance,
        dpi,
    );
    let ok_btn = add_button(
        &mut controls,
        hwnd,
        "Sign in",
        300,
        330,
        100,
        32,
        IDC_OK,
        instance,
        dpi,
    );
    apply_layout(&controls, &fonts, dpi);
    if !defaults.relay.is_empty() {
        set_text(relay, &defaults.relay);
    }
    if !defaults.trust.is_empty() {
        set_text(trust, &defaults.trust);
    }
    with_app(|app| {
        stamp_icons(hwnd, app.icons.large, app.icons.small);
        app.signin = Some(SignInDialog {
            hwnd,
            relay,
            trust,
            user,
            pass,
            totp,
            message,
            ok_btn,
            busy: false,
            dpi,
            fonts,
            controls,
        });
    });
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
}

fn dismiss_sign_in() {
    let dialog = with_app(|app| app.signin.take()).flatten();
    if let Some(dialog) = dialog {
        forget_dialog_text();
        unsafe {
            let _ = DestroyWindow(dialog.hwnd);
        }
        dialog.fonts.delete();
    }
}

fn show_main() {
    let Some(hwnd) = with_app(|app| {
        app.force_autostart_sync = true;
        app.hwnd
    }) else {
        return;
    };
    refresh();
    unsafe {
        let _ = ShowWindow(hwnd, SW_SHOW);
        let _ = SetForegroundWindow(hwnd);
    }
}

fn request_quit() {
    let Some((hwnd, dialog)) = with_app(|app| {
        app.quit = true;
        app.supervisor.request_stop();
        (app.hwnd, app.signin.take())
    }) else {
        return;
    };
    if let Some(dialog) = dialog {
        forget_dialog_text();
        unsafe {
            let _ = DestroyWindow(dialog.hwnd);
        }
        dialog.fonts.delete();
    }
    unsafe {
        let _ = DestroyWindow(hwnd);
    }
}

/// Launch the controller window from the tray button or menu.
///
/// Forwards `--config-dir` and `--data-dir` and prefers sibling `agentlink-gui.exe`
/// when installed on disk so launching never flashes a console window.
fn open_controller() {
    let Some((binary, config_dir, data_dir)) =
        with_app(|app| (app.binary.clone(), app.ctx.config_dir.clone(), app.data_dir.clone()))
    else {
        return;
    };
    let exe = tray::preferred_gui_binary(&binary);
    let args = tray::controller_launch_args(&config_dir, &data_dir);
    if let Err(err) = agentlink_core::process::hidden(&exe).args(args).spawn() {
        with_app(|app| {
            app.feedback
                .set(format!("Could not open Controller: {err}"), true, Instant::now());
        });
    }
}

fn show_menu(owner: HWND) {
    let running = with_app(|app| app.supervisor.running() || app.shown_connection == "Online")
        .unwrap_or(false);
    unsafe {
        let Ok(menu) = CreatePopupMenu() else {
            return;
        };
        let _ = AppendMenuW(menu, MF_STRING, MENU_OPEN as usize, w!("Open"));
        let _ = AppendMenuW(
            menu,
            MF_STRING,
            MENU_CONTROLLER as usize,
            w!("Open Controller..."),
        );
        let _ = AppendMenuW(
            menu,
            if running {
                MF_STRING | MF_GRAYED
            } else {
                MF_STRING
            },
            MENU_START as usize,
            w!("Start"),
        );
        let _ = AppendMenuW(
            menu,
            if running {
                MF_STRING
            } else {
                MF_STRING | MF_GRAYED
            },
            MENU_STOP as usize,
            w!("Stop"),
        );
        let _ = AppendMenuW(menu, MF_STRING, MENU_RECONNECT as usize, w!("Reconnect"));
        let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
        let _ = AppendMenuW(menu, MF_STRING, MENU_QUIT as usize, w!("Quit"));
        let _ = SetForegroundWindow(owner);
        let mut point = POINT::default();
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
        // Required per MSDN (KB135788) so clicking outside dismisses the popup cleanly.
        let _ = PostMessageW(Some(owner), WM_NULL, WPARAM(0), LPARAM(0));
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
            CloseRole::Dialog(app.signin.take())
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
        Some(CloseRole::Dialog(dialog)) => {
            forget_dialog_text();
            unsafe {
                let _ = DestroyWindow(hwnd);
            }
            if let Some(dialog) = dialog {
                dialog.fonts.delete();
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
    Dialog(Option<SignInDialog>),
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
        Some(TextRole::Detail) => {
            if DETAIL_ALERT.load(Ordering::Relaxed) {
                ALERT
            } else {
                MUTED
            }
        }
        Some(TextRole::Hint) => MUTED,
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

fn recreate_tray_icon() {
    with_app(|app| unsafe {
        let tip = if app.shown_connection.is_empty() {
            "agentlink — Stopped".to_string()
        } else {
            format!("agentlink — {}", app.shown_connection)
        };
        shell_icon(app.hwnd, app.icons.small, &tip, NIM_ADD);
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

fn create_main(instance: HINSTANCE, class: PCWSTR) -> Result<HWND> {
    create_overlapped(instance, class, "agentlink", CLIENT_W, CLIENT_H, false)
}

fn create_dialog(instance: HINSTANCE, title: &str) -> Result<HWND> {
    create_overlapped(instance, w!("AgentlinkSignIn"), title, SIGN_W, SIGN_H, false)
}

fn window_style() -> WINDOW_STYLE {
    WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN
}

fn scale_px(px_96: i32, dpi: u32) -> i32 {
    let dpi = dpi.max(48) as i32;
    if px_96 >= 0 {
        (px_96 * dpi + 48) / 96
    } else {
        (px_96 * dpi - 48) / 96
    }
}

fn window_dpi(hwnd: HWND) -> u32 {
    let dpi = unsafe { GetDpiForWindow(hwnd) };
    if dpi >= 48 {
        dpi
    } else {
        96
    }
}

fn outer_size_for_dpi(client_w: i32, client_h: i32, dpi: u32) -> (i32, i32) {
    let mut rect = RECT {
        left: 0,
        top: 0,
        right: scale_px(client_w, dpi),
        bottom: scale_px(client_h, dpi),
    };
    unsafe {
        if AdjustWindowRectExForDpi(
            &mut rect,
            window_style(),
            false,
            WINDOW_EX_STYLE::default(),
            dpi,
        )
        .is_err()
        {
            let _ =
                AdjustWindowRectEx(&mut rect, window_style(), false, WINDOW_EX_STYLE::default());
        }
    }
    (rect.right - rect.left, rect.bottom - rect.top)
}

fn resize_client_for_dpi(hwnd: HWND, client_w: i32, client_h: i32, dpi: u32) {
    let (width, height) = outer_size_for_dpi(client_w, client_h, dpi);
    unsafe {
        let _ = SetWindowPos(
            hwnd,
            None,
            0,
            0,
            width,
            height,
            SWP_NOZORDER | SWP_NOACTIVATE | windows::Win32::UI::WindowsAndMessaging::SWP_NOMOVE,
        );
    }
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
    let (width, height) = outer_size_for_dpi(client_w, client_h, 96);
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

#[allow(clippy::too_many_arguments)]
fn add_label(
    controls: &mut Vec<LayoutItem>,
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    instance: HINSTANCE,
    role: TextRole,
    font: FontRole,
    dialog: bool,
    dpi: u32,
) -> HWND {
    let hwnd = child(
        parent,
        w!("STATIC"),
        text,
        WS_CHILD | WS_VISIBLE,
        scale_px(x, dpi),
        scale_px(y, dpi),
        scale_px(w, dpi),
        scale_px(h, dpi),
        id,
        instance,
    );
    remember_text(hwnd, role, dialog);
    controls.push(LayoutItem {
        hwnd,
        x,
        y,
        w,
        h,
        font,
    });
    hwnd
}

#[allow(clippy::too_many_arguments)]
fn add_button(
    controls: &mut Vec<LayoutItem>,
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    instance: HINSTANCE,
    dpi: u32,
) -> HWND {
    let hwnd = child(
        parent,
        w!("BUTTON"),
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_OWNERDRAW as u32),
        scale_px(x, dpi),
        scale_px(y, dpi),
        scale_px(w, dpi),
        scale_px(h, dpi),
        id,
        instance,
    );
    controls.push(LayoutItem {
        hwnd,
        x,
        y,
        w,
        h,
        font: FontRole::Button,
    });
    hwnd
}

#[allow(clippy::too_many_arguments)]
fn add_checkbox(
    controls: &mut Vec<LayoutItem>,
    parent: HWND,
    text: &str,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    instance: HINSTANCE,
    dpi: u32,
) -> HWND {
    let hwnd = child(
        parent,
        w!("BUTTON"),
        text,
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WINDOW_STYLE(BS_AUTOCHECKBOX as u32),
        scale_px(x, dpi),
        scale_px(y, dpi),
        scale_px(w, dpi),
        scale_px(h, dpi),
        id,
        instance,
    );
    controls.push(LayoutItem {
        hwnd,
        x,
        y,
        w,
        h,
        font: FontRole::Body,
    });
    hwnd
}

#[allow(clippy::too_many_arguments)]
fn add_edit(
    controls: &mut Vec<LayoutItem>,
    parent: HWND,
    x: i32,
    y: i32,
    w: i32,
    h: i32,
    id: u16,
    instance: HINSTANCE,
    password: bool,
    dpi: u32,
) -> HWND {
    let mut style =
        WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_BORDER | WINDOW_STYLE(ES_AUTOHSCROLL as u32);
    if password {
        style |= WINDOW_STYLE(ES_PASSWORD as u32);
    }
    let hwnd = child(
        parent,
        w!("EDIT"),
        "",
        style,
        scale_px(x, dpi),
        scale_px(y, dpi),
        scale_px(w, dpi),
        scale_px(h, dpi),
        id,
        instance,
    );
    controls.push(LayoutItem {
        hwnd,
        x,
        y,
        w,
        h,
        font: FontRole::Body,
    });
    hwnd
}

fn apply_layout(controls: &[LayoutItem], fonts: &FontSet, dpi: u32) {
    for item in controls {
        if item.hwnd.0.is_null() {
            continue;
        }
        unsafe {
            let _ = MoveWindow(
                item.hwnd,
                scale_px(item.x, dpi),
                scale_px(item.y, dpi),
                scale_px(item.w, dpi),
                scale_px(item.h, dpi),
                true,
            );
        }
        apply_font(item.hwnd, fonts.pick(item.font));
    }
}

#[allow(clippy::too_many_arguments)]
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

fn set_enabled(hwnd: HWND, enabled: bool) {
    if hwnd.0.is_null() {
        return;
    }
    unsafe {
        let _ = EnableWindow(hwnd, if enabled { 1 } else { 0 });
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

fn set_text_if_changed(hwnd: HWND, text: &str) {
    if hwnd.0.is_null() {
        return;
    }
    if window_text(hwnd) == text {
        return;
    }
    set_text(hwnd, text);
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

fn dpi_metric(
    index: windows::Win32::UI::WindowsAndMessaging::SYSTEM_METRICS_INDEX,
    dpi: u32,
    fallback: i32,
) -> i32 {
    let value = unsafe { GetSystemMetricsForDpi(index, dpi) };
    if value > 0 {
        return value;
    }
    let sys = unsafe { GetSystemMetrics(index) };
    if sys > 0 {
        sys
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
    let dpi = window_dpi(hwnd);
    unsafe {
        let mut rect = RECT::default();
        let _ = GetClientRect(hwnd, &mut rect);
        let _ = FillRect(hdc, &rect, cream_brush());
        rect.bottom = scale_px(6, dpi).max(4);
        let _ = FillRect(hdc, &rect, brush_or_sys(|chrome| chrome.teal));
    }
}

fn paint_window(hwnd: HWND) {
    unsafe {
        let mut paint = PAINTSTRUCT::default();
        let hdc = BeginPaint(hwnd, &mut paint);
        let icon = HEADER_ICON.load(Ordering::Relaxed);
        let dpi = HEADER_DPI.load(Ordering::Relaxed).max(48);
        let main = hwnd_key(hwnd) == MAIN_HWND.load(Ordering::Relaxed);
        if main && icon != 0 {
            let mark = scale_px(MARK, dpi);
            let _ = DrawIconEx(
                hdc,
                scale_px(20, dpi),
                scale_px(16, dpi),
                HICON(icon as *mut c_void),
                mark,
                mark,
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
    let dpi = window_dpi(draw.hwndItem);
    unsafe {
        let _ = FillRect(draw.hDC, &draw.rcItem, cream_brush());
        let brush = brush_or_sys(|chrome| match (primary && !disabled, pressed) {
            (true, true) => chrome.primary_down,
            (true, false) => chrome.primary,
            (false, true) => chrome.secondary_down,
            (false, false) => chrome.secondary,
        });
        let border_color = if disabled { MUTED } else { INK };
        let pen = CreatePen(PS_SOLID, scale_px(2, dpi).max(1), COLORREF(border_color));
        let previous_brush = SelectObject(draw.hDC, brush.into());
        let previous_pen = SelectObject(draw.hDC, pen.into());
        let inset = scale_px(if pressed { 3 } else { 2 }, dpi).max(1);
        let radius = scale_px(12, dpi).max(4);
        let _ = RoundRect(
            draw.hDC,
            draw.rcItem.left + inset,
            draw.rcItem.top + inset,
            draw.rcItem.right - inset,
            draw.rcItem.bottom - inset,
            radius,
            radius,
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
            let pad = scale_px(4, dpi).max(2);
            let focus = RECT {
                left: draw.rcItem.left + pad,
                top: draw.rcItem.top + pad,
                right: draw.rcItem.right - pad,
                bottom: draw.rcItem.bottom - pad,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_px_scales_positive_and_negative_metrics_cleanly() {
        assert_eq!(scale_px(420, 96), 420);
        assert_eq!(scale_px(420, 120), 525);
        assert_eq!(scale_px(420, 144), 630);
        assert_eq!(scale_px(420, 192), 840);
        assert_eq!(scale_px(-15, 96), -15);
        assert_eq!(scale_px(-15, 144), -23);
        assert_eq!(scale_px(-15, 192), -30);
    }

    #[test]
    fn feedback_banner_persists_across_polls_until_expiry_or_clear() {
        let t0 = Instant::now();
        let mut banner = FeedbackBanner::default();
        assert_eq!(banner.active_at(t0), None);

        banner.set("Start-on-login is on.", false, t0);
        assert_eq!(
            banner.active_at(t0 + Duration::from_millis(500)),
            Some(("Start-on-login is on.", false))
        );
        assert_eq!(
            banner.active_at(t0 + NOTICE_INFO_TTL),
            None,
            "info banner expires after TTL"
        );

        banner.set("Auth failed", true, t0);
        assert_eq!(
            banner.active_at(t0 + NOTICE_INFO_TTL),
            Some(("Auth failed", true)),
            "error banner stays visible longer than info banner"
        );
        banner.clear();
        assert_eq!(banner.active_at(t0 + Duration::from_secs(1)), None);
    }

    #[test]
    fn button_states_follow_running_account_and_signout_busy_guard() {
        let stopped = StatusView {
            connection: "Stopped".into(),
            relay: "relay not set".into(),
            node_name: "pc".into(),
            pairing: "Not paired".into(),
            account: "Not signed in".into(),
            detail: String::new(),
            running: false,
            enrolled: false,
        };
        let s0 = ButtonStates::for_view(&stopped, false, false);
        assert!(s0.start);
        assert!(!s0.stop);
        assert!(!s0.reconnect);
        assert!(s0.signin);
        assert!(!s0.signout);
        assert!(s0.controller);

        let online = StatusView {
            connection: "Online".into(),
            relay: "wss://relay.example.com".into(),
            node_name: "pc".into(),
            pairing: "Paired".into(),
            account: "Signed in as ada".into(),
            detail: String::new(),
            running: true,
            enrolled: true,
        };
        let s1 = ButtonStates::for_view(&online, true, false);
        assert!(!s1.start);
        assert!(s1.stop);
        assert!(s1.reconnect);
        assert!(s1.signin);
        assert!(s1.signout);

        let signing_out = ButtonStates::for_view(&online, true, true);
        assert!(!signing_out.signin);
        assert!(!signing_out.signout);
    }
}
