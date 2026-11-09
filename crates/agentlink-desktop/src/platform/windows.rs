//! Windows capture, input, and UI Automation.
//!
//! A monitor grab uses DXGI Desktop Duplication and copies the staging texture
//! once into a [`Frame`](crate::capture::Frame). Full-screen, region, window,
//! and a duplication timeout use GDI (`BitBlt` / `PrintWindow`). Input is
//! `SendInput` in virtual-desktop coordinates. Accessibility ids are
//! `uia|{index}` and stay valid until the next tree request.
//!
//! Per-monitor DPI awareness is requested on the desktop thread. Coordinates
//! are virtual-screen pixels, the same space as `monitor.x` / `monitor.y`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use windows::core::{Interface, BOOL, BSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::Foundation::POINT;
use windows::Win32::Foundation::{GetLastError, HWND, LPARAM, RECT, TRUE};
use windows::Win32::Graphics::Direct3D::D3D_DRIVER_TYPE_UNKNOWN;
use windows::Win32::Graphics::Direct3D11::{
    D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D,
    D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE,
    D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
};
use windows::Win32::Graphics::Dxgi::Common::{DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_SAMPLE_DESC};
use windows::Win32::Graphics::Dxgi::{
    CreateDXGIFactory1, IDXGIAdapter1, IDXGIDevice, IDXGIFactory1, IDXGIOutput, IDXGIOutput1,
    IDXGIOutputDuplication, IDXGIResource, DXGI_ERROR_ACCESS_LOST, DXGI_ERROR_WAIT_TIMEOUT,
    DXGI_OUTDUPL_FRAME_INFO,
};
use windows::Win32::Graphics::Gdi::{
    BitBlt, CreateCompatibleBitmap, CreateCompatibleDC, DeleteDC, DeleteObject,
    EnumDisplayMonitors, GetDC, GetDIBits, GetMonitorInfoW, ReleaseDC, SelectObject, BITMAPINFO,
    BITMAPINFOHEADER, DIB_RGB_COLORS, HDC, HMONITOR, MONITORINFO, MONITORINFOEXW, SRCCOPY,
};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_APARTMENTTHREADED,
};
use windows::Win32::UI::Accessibility::{
    CUIAutomation, IUIAutomation, IUIAutomationElement, IUIAutomationElementArray,
    IUIAutomationInvokePattern, IUIAutomationValuePattern, TreeScope_Children,
    UIA_ButtonControlTypeId, UIA_CheckBoxControlTypeId, UIA_ComboBoxControlTypeId,
    UIA_DocumentControlTypeId, UIA_EditControlTypeId, UIA_GroupControlTypeId,
    UIA_HyperlinkControlTypeId, UIA_ImageControlTypeId, UIA_InvokePatternId, UIA_ListControlTypeId,
    UIA_ListItemControlTypeId, UIA_MenuItemControlTypeId, UIA_PaneControlTypeId,
    UIA_RadioButtonControlTypeId, UIA_TextControlTypeId, UIA_TitleBarControlTypeId,
    UIA_ToolBarControlTypeId, UIA_ValuePatternId, UIA_WindowControlTypeId,
};
use windows::Win32::UI::HiDpi::{
    SetProcessDpiAwarenessContext, DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2,
};
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE,
    MOUSEEVENTF_ABSOLUTE, MOUSEEVENTF_HWHEEL, MOUSEEVENTF_LEFTDOWN, MOUSEEVENTF_LEFTUP,
    MOUSEEVENTF_MIDDLEDOWN, MOUSEEVENTF_MIDDLEUP, MOUSEEVENTF_MOVE, MOUSEEVENTF_RIGHTDOWN,
    MOUSEEVENTF_RIGHTUP, MOUSEEVENTF_VIRTUALDESK, MOUSEEVENTF_WHEEL, MOUSEINPUT, VIRTUAL_KEY,
};
use windows::Win32::System::StationsAndDesktops::{
    CloseDesktop, OpenInputDesktop, DESKTOP_CONTROL_FLAGS, DESKTOP_READOBJECTS,
};
use windows::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, EnumWindows, GetCursorInfo, GetCursorPos, GetSystemMetrics, GetWindowRect,
    GetWindowTextW, IsWindowVisible, LoadCursorW, PeekMessageW, TranslateMessage, CURSORINFO,
    CURSOR_SHOWING, IDC_ARROW, IDC_CROSS, IDC_HAND, IDC_HELP, IDC_IBEAM, IDC_NO, IDC_SIZEALL,
    IDC_SIZENESW, IDC_SIZENS, IDC_SIZENWSE, IDC_SIZEWE, IDC_WAIT, MSG, PM_REMOVE,
    SM_CXVIRTUALSCREEN, SM_CYVIRTUALSCREEN, SM_XVIRTUALSCREEN, SM_YVIRTUALSCREEN,
};

use crate::a11y::{A11yBackend, ElementOp, UiNode};
use crate::capture::{
    scale_frame, stream_interval, unix_ms, wait_until_due, CapturableState, CaptureBackend,
    CaptureRequest, CaptureTarget, CursorSample, Frame, FrameSource, MonitorInfo,
    Rect as DeskRect, StreamMode,
};
use crate::cursor_shape::{normalize_shape, shape_from_win_idc};
use crate::error::{msg, Result};
use crate::input::{perform, HidBackend, InputAction, MouseButton, Pointer, WHEEL_DELTA};
use crate::keys::key_info;
use crate::worker::Worker;
use crate::Desktop;

fn werr(err: windows::core::Error) -> crate::error::DesktopError {
    msg(err.to_string())
}

struct WindowsState {
    dup: Option<Duplication>,
    automation: Option<IUIAutomation>,
    elements: Vec<IUIAutomationElement>,
    last_frame: Option<Frame>,
}

struct Duplication {
    index: u32,
    duplication: IDXGIOutputDuplication,
    context: ID3D11DeviceContext,
    /// Kept so the duplication's device is not released while the output is live.
    #[allow(dead_code)]
    device: ID3D11Device,
}

impl WindowsState {
    fn new() -> Self {
        unsafe {
            let _ = SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
            let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
        }
        Self {
            dup: None,
            automation: None,
            elements: Vec::new(),
            last_frame: None,
        }
    }

    fn capture(&mut self, request: &CaptureRequest) -> Result<Frame> {
        let frame = match &request.target {
            CaptureTarget::FullScreen => capture_virtual("gdi")?,
            CaptureTarget::Monitor(index) => capture_monitor(self, *index)?,
            CaptureTarget::Region(rect) => {
                capture_box(rect.x, rect.y, rect.width, rect.height, "gdi")?
            }
            CaptureTarget::Window(query) => capture_window(query)?,
        };
        let frame = scale_frame(frame, request.scale)?;
        // The offer probe runs this before the pump. A static desktop then
        // times out in DXGI; the stream repeats this image instead of failing
        // the session with no pixels.
        self.last_frame = Some(frame.clone());
        Ok(frame)
    }

    fn monitors(&self) -> Result<Vec<MonitorInfo>> {
        list_monitors()
    }

    /// Session path. A DXGI timeout repeats the previous frame and marks it
    /// unchanged so the encoder sends nothing. A one-shot screenshot still
    /// falls back to GDI.
    fn capture_stream(&mut self, request: &CaptureRequest) -> Result<Frame> {
        let index = match request.target {
            CaptureTarget::Monitor(index) => index,
            _ => 0,
        };
        match grab_dxgi(self, index) {
            DxgiGrab::Frame(frame) => {
                let frame = scale_frame(frame, request.scale)?;
                self.last_frame = Some(frame.clone());
                Ok(frame)
            }
            DxgiGrab::Timeout => {
                if let Some(prev) = self.last_frame.clone() {
                    let mut frame = prev;
                    frame.mark_unchanged();
                    frame.captured_unix_ms = unix_ms();
                    return Ok(frame);
                }
                self.capture(request)
            }
            DxgiGrab::Failed(err) => {
                tracing::warn!(error = %err, "DXGI stream grab failed; using the last frame or GDI");
                self.dup = None;
                match self.capture(request) {
                    Ok(frame) => Ok(frame),
                    Err(gdi_err) => {
                        if let Some(prev) = self.last_frame.clone() {
                            tracing::warn!(error = %gdi_err, "GDI capture failed; repeating the last frame");
                            Ok(prev)
                        } else {
                            Err(gdi_err)
                        }
                    }
                }
            }
        }
    }
}

enum DxgiGrab {
    Frame(Frame),
    Timeout,
    Failed(String),
}

fn grab_dxgi(state: &mut WindowsState, index: u32) -> DxgiGrab {
    if state.dup.as_ref().map(|dup| dup.index) != Some(index) {
        match open_duplication(index) {
            Ok(dup) => state.dup = Some(dup),
            Err(err) => return DxgiGrab::Failed(err.to_string()),
        }
    }
    let dup = state.dup.as_ref().unwrap();
    match unsafe { acquire_frame(dup) } {
        Ok(frame) => DxgiGrab::Frame(frame),
        Err(err) if err.code() == DXGI_ERROR_WAIT_TIMEOUT => DxgiGrab::Timeout,
        Err(err) => {
            // ACCESS_LOST and INVALID_CALL (a frame left acquired) both need a
            // new duplication. Keeping the dead object made every later grab fail.
            state.dup = None;
            DxgiGrab::Failed(err.message().to_string())
        }
    }
}

fn capture_monitor(state: &mut WindowsState, index: u32) -> Result<Frame> {
    match capture_dxgi(state, index) {
        Ok(frame) => Ok(frame),
        Err(err) => {
            tracing::info!(error = %err, monitor = index, "DXGI capture failed; using GDI");
            let monitors = list_monitors()?;
            let monitor = monitors
                .iter()
                .find(|item| item.index == index)
                .ok_or_else(|| msg(format!("no monitor {index}")))?;
            capture_box(monitor.x, monitor.y, monitor.width, monitor.height, "gdi")
        }
    }
}

fn capture_dxgi(state: &mut WindowsState, index: u32) -> Result<Frame> {
    if state.dup.as_ref().map(|dup| dup.index) != Some(index) {
        state.dup = Some(open_duplication(index)?);
    }
    let dup = state.dup.as_ref().unwrap();
    let grabbed = unsafe { acquire_frame(dup) };
    match grabbed {
        Ok(frame) => Ok(frame),
        Err(err)
            if err.code() == DXGI_ERROR_ACCESS_LOST || err.code() == DXGI_ERROR_WAIT_TIMEOUT =>
        {
            if err.code() == DXGI_ERROR_ACCESS_LOST {
                state.dup = None;
            }
            Err(msg(err.message()))
        }
        Err(err) => Err(msg(err.message())),
    }
}

fn open_duplication(index: u32) -> Result<Duplication> {
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1().map_err(werr)?;
        let (adapter, output) = output_at(&factory, index)?;
        let mut device = None;
        let mut context = None;
        D3D11CreateDevice(
            &adapter,
            D3D_DRIVER_TYPE_UNKNOWN,
            HMODULE::default(),
            D3D11_CREATE_DEVICE_BGRA_SUPPORT,
            None,
            D3D11_SDK_VERSION,
            Some(&mut device),
            None,
            Some(&mut context),
        )
        .map_err(werr)?;
        let device = device.ok_or_else(|| msg("D3D11CreateDevice returned no device"))?;
        let context = context.ok_or_else(|| msg("D3D11CreateDevice returned no context"))?;
        let dxgi: IDXGIDevice = device.cast().map_err(werr)?;
        let output1: IDXGIOutput1 = output.cast().map_err(werr)?;
        let duplication = output1.DuplicateOutput(&dxgi).map_err(|err| {
            msg(format!(
                "DXGI DuplicateOutput: {err}. A remote session often needs the GDI fallback, which is used automatically."
            ))
        })?;
        Ok(Duplication {
            index,
            duplication,
            context,
            device,
        })
    }
}

unsafe fn output_at(factory: &IDXGIFactory1, index: u32) -> Result<(IDXGIAdapter1, IDXGIOutput)> {
    let mut seen = 0u32;
    for adapter_index in 0..16u32 {
        let Ok(adapter) = factory.EnumAdapters1(adapter_index) else {
            break;
        };
        for output_index in 0..16u32 {
            let Ok(output) = adapter.EnumOutputs(output_index) else {
                break;
            };
            if seen == index {
                return Ok((adapter, output));
            }
            seen += 1;
        }
    }
    Err(msg(format!("no DXGI output for monitor {index}")))
}

fn pump_desktop_messages() {
    // The desktop worker is an STA thread. DXGI waits on the window queue;
    // leaving messages there makes AcquireNextFrame ignore its timeout.
    unsafe {
        let mut msg = MSG::default();
        while PeekMessageW(std::ptr::addr_of_mut!(msg), None, 0, 0, PM_REMOVE).0 != 0 {
            let _ = TranslateMessage(std::ptr::addr_of!(msg));
            DispatchMessageW(std::ptr::addr_of!(msg));
        }
    }
}

unsafe fn acquire_frame(dup: &Duplication) -> windows::core::Result<Frame> {
    // The first call on a quiet desktop often times out. One more try, then the caller uses GDI.
    let mut last = None;
    for timeout_ms in [0u32, 100] {
        pump_desktop_messages();
        let mut info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut resource = None;
        match dup
            .duplication
            .AcquireNextFrame(timeout_ms, &mut info, &mut resource)
        {
            Ok(()) => {
                let copied = match resource {
                    Some(resource) => copy_duplication(&dup.context, &resource),
                    None => Err(windows::core::Error::from_win32()),
                };
                // Always release. Skipping this returns INVALID_CALL forever after.
                let _ = dup.duplication.ReleaseFrame();
                if info.LastPresentTime != 0 || copied.is_ok() {
                    return copied;
                }
                last = Some(copied);
            }
            Err(err) if err.code() == DXGI_ERROR_WAIT_TIMEOUT => {
                last = Some(Err(err));
            }
            Err(err) => return Err(err),
        }
    }
    last.unwrap_or_else(|| Err(DXGI_ERROR_WAIT_TIMEOUT.into()))
}

unsafe fn copy_duplication(
    context: &ID3D11DeviceContext,
    resource: &IDXGIResource,
) -> windows::core::Result<Frame> {
    let texture: ID3D11Texture2D = resource.cast()?;
    let mut desc = D3D11_TEXTURE2D_DESC::default();
    texture.GetDesc(&mut desc);
    let width = desc.Width;
    let height = desc.Height;
    if width == 0 || height == 0 {
        return Err(windows::core::Error::from_win32());
    }
    desc.Usage = D3D11_USAGE_STAGING;
    desc.BindFlags = 0;
    desc.CPUAccessFlags = D3D11_CPU_ACCESS_READ.0 as u32;
    desc.MiscFlags = 0;
    desc.MipLevels = 1;
    desc.ArraySize = 1;
    desc.Format = DXGI_FORMAT_B8G8R8A8_UNORM;
    desc.SampleDesc = DXGI_SAMPLE_DESC {
        Count: 1,
        Quality: 0,
    };
    let device = context.GetDevice()?;
    let mut staging = None;
    device.CreateTexture2D(&desc, None, Some(&mut staging))?;
    let staging = staging.ok_or_else(windows::core::Error::from_win32)?;
    let src: ID3D11Resource = texture.cast()?;
    let dst: ID3D11Resource = staging.cast()?;
    context.CopyResource(&dst, &src);
    let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
    context.Map(&dst, 0, D3D11_MAP_READ, 0, Some(&mut mapped))?;
    let frame = mapped_frame(mapped, width, height, "dxgi");
    context.Unmap(&dst, 0);
    frame.map_err(|err| windows::core::Error::new(windows::core::HRESULT(-1), err.to_string()))
}

fn mapped_frame(
    mapped: D3D11_MAPPED_SUBRESOURCE,
    width: u32,
    height: u32,
    backend: &str,
) -> Result<Frame> {
    if mapped.pData.is_null() {
        return Err(msg("DXGI map returned no pixels"));
    }
    let stride = mapped.RowPitch;
    let len = stride as usize * height as usize;
    let data = unsafe { std::slice::from_raw_parts(mapped.pData as *const u8, len) };
    Frame::from_bgra(width, height, stride, data, backend)
}

fn capture_virtual(backend: &str) -> Result<Frame> {
    let (x, y, width, height) = virtual_rect()?;
    capture_box(x, y, width, height, backend)
}

fn virtual_rect() -> Result<(i32, i32, u32, u32)> {
    unsafe {
        let x = GetSystemMetrics(SM_XVIRTUALSCREEN);
        let y = GetSystemMetrics(SM_YVIRTUALSCREEN);
        let width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        let height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if width <= 0 || height <= 0 {
            return Err(msg("Windows reported an empty virtual screen"));
        }
        Ok((x, y, width as u32, height as u32))
    }
}

fn capture_box(x: i32, y: i32, width: u32, height: u32, backend: &str) -> Result<Frame> {
    if width == 0 || height == 0 {
        return Err(msg("capture rectangle is empty"));
    }
    unsafe {
        let screen = GetDC(None);
        if screen.is_invalid() {
            return Err(msg("GetDC failed"));
        }
        let memory = CreateCompatibleDC(Some(screen));
        if memory.is_invalid() {
            ReleaseDC(None, screen);
            return Err(msg("CreateCompatibleDC failed"));
        }
        let bitmap = CreateCompatibleBitmap(screen, width as i32, height as i32);
        if bitmap.is_invalid() {
            let _ = DeleteDC(memory);
            ReleaseDC(None, screen);
            return Err(msg("CreateCompatibleBitmap failed"));
        }
        let previous = SelectObject(memory, bitmap.into());
        let copied = BitBlt(
            memory,
            0,
            0,
            width as i32,
            height as i32,
            Some(screen),
            x,
            y,
            SRCCOPY,
        );
        let mut info = bitmap_info(width, height);
        let mut pixels = vec![0u8; width as usize * height as usize * 4];
        let rows = if copied.is_ok() {
            GetDIBits(
                memory,
                bitmap,
                0,
                height,
                Some(pixels.as_mut_ptr().cast()),
                &mut info,
                DIB_RGB_COLORS,
            )
        } else {
            0
        };
        SelectObject(memory, previous);
        let _ = DeleteObject(bitmap.into());
        let _ = DeleteDC(memory);
        ReleaseDC(None, screen);
        if rows == 0 {
            return Err(msg(format!("GDI capture failed ({})", GetLastError().0)));
        }
        Frame::from_bgra(width, height, width * 4, &pixels, backend)
    }
}

fn capture_window(query: &str) -> Result<Frame> {
    let hwnd = find_window(query)?;
    unsafe {
        let mut rect = RECT::default();
        if GetWindowRect(hwnd, &mut rect).is_err() {
            return Err(msg("GetWindowRect failed"));
        }
        let width = rect.right.saturating_sub(rect.left).max(1) as u32;
        let height = rect.bottom.saturating_sub(rect.top).max(1) as u32;
        let screen = GetDC(None);
        let memory = CreateCompatibleDC(Some(screen));
        let bitmap = CreateCompatibleBitmap(screen, width as i32, height as i32);
        let previous = SelectObject(memory, bitmap.into());
        let printed = PrintWindow(hwnd, memory, 2);
        if printed == 0 {
            let _ = BitBlt(
                memory,
                0,
                0,
                width as i32,
                height as i32,
                Some(screen),
                rect.left,
                rect.top,
                SRCCOPY,
            );
        }
        let mut info = bitmap_info(width, height);
        let mut pixels = vec![0u8; width as usize * height as usize * 4];
        let rows = GetDIBits(
            memory,
            bitmap,
            0,
            height,
            Some(pixels.as_mut_ptr().cast()),
            &mut info,
            DIB_RGB_COLORS,
        );
        SelectObject(memory, previous);
        let _ = DeleteObject(bitmap.into());
        let _ = DeleteDC(memory);
        ReleaseDC(None, screen);
        if rows == 0 {
            return Err(msg(format!("window capture failed for '{query}'")));
        }
        Frame::from_bgra(width, height, width * 4, &pixels, "printwindow")
    }
}

fn bitmap_info(width: u32, height: u32) -> BITMAPINFO {
    BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: std::mem::size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: 0,
            biSizeImage: width * height * 4,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        },
        bmiColors: [windows::Win32::Graphics::Gdi::RGBQUAD::default()],
    }
}

fn find_window(query: &str) -> Result<HWND> {
    if let Ok(raw) = query.parse::<isize>() {
        return Ok(HWND(raw as *mut std::ffi::c_void));
    }
    let mut found = HWND::default();
    let query_l = query.to_ascii_lowercase();
    let mut search = FindSearch {
        query: &query_l,
        found: &mut found,
    };
    unsafe {
        let _ = EnumWindows(
            Some(enum_window),
            LPARAM((&mut search as *mut FindSearch) as isize),
        );
    }
    if found.0.is_null() {
        Err(msg(format!("no window title contains '{query}'")))
    } else {
        Ok(found)
    }
}

unsafe extern "system" fn enum_window(hwnd: HWND, data: LPARAM) -> BOOL {
    let search = &mut *(data.0 as *mut FindSearch);
    if IsWindowVisible(hwnd).as_bool() {
        let mut buf = [0u16; 512];
        let n = GetWindowTextW(hwnd, &mut buf);
        if n > 0 {
            let text = String::from_utf16_lossy(&buf[..n as usize]).to_ascii_lowercase();
            if text.contains(search.query) {
                *search.found = hwnd;
                return BOOL(0);
            }
        }
    }
    TRUE
}

struct FindSearch<'a> {
    query: &'a str,
    found: &'a mut HWND,
}

fn list_monitors() -> Result<Vec<MonitorInfo>> {
    let mut monitors = Vec::new();
    unsafe {
        let _ = EnumDisplayMonitors(
            None,
            None,
            Some(enum_monitor),
            LPARAM((&mut monitors as *mut Vec<MonitorInfo>) as isize),
        );
    }
    if monitors.is_empty() {
        let (x, y, width, height) = virtual_rect()?;
        monitors.push(MonitorInfo {
            index: 0,
            name: "virtual".into(),
            x,
            y,
            width,
            height,
            primary: true,
        });
    }
    Ok(monitors)
}

unsafe extern "system" fn enum_monitor(
    monitor: HMONITOR,
    _dc: windows::Win32::Graphics::Gdi::HDC,
    _rect: *mut RECT,
    data: LPARAM,
) -> BOOL {
    let list = &mut *(data.0 as *mut Vec<MonitorInfo>);
    let mut info = MONITORINFOEXW::default();
    info.monitorInfo.cbSize = std::mem::size_of::<MONITORINFOEXW>() as u32;
    if GetMonitorInfoW(monitor, &mut info.monitorInfo as *mut MONITORINFO).as_bool() {
        let rect = info.monitorInfo.rcMonitor;
        let name = utf16_cstr(&info.szDevice);
        let index = list.len() as u32;
        list.push(MonitorInfo {
            index,
            name: if name.is_empty() {
                format!("display-{index}")
            } else {
                name
            },
            x: rect.left,
            y: rect.top,
            width: rect.right.saturating_sub(rect.left).max(0) as u32,
            height: rect.bottom.saturating_sub(rect.top).max(0) as u32,
            primary: info.monitorInfo.dwFlags & 1 != 0,
        });
    }
    TRUE
}

fn utf16_cstr(buf: &[u16]) -> String {
    let end = buf.iter().position(|unit| *unit == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..end])
}

impl Pointer for WindowsState {
    fn mouse_move(&mut self, x: i32, y: i32) -> Result<()> {
        send_mouse(
            x,
            y,
            MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK,
            0,
        )
    }

    fn mouse_button(&mut self, button: MouseButton, down: bool) -> Result<()> {
        let flag = match (button, down) {
            (MouseButton::Left, true) => MOUSEEVENTF_LEFTDOWN,
            (MouseButton::Left, false) => MOUSEEVENTF_LEFTUP,
            (MouseButton::Right, true) => MOUSEEVENTF_RIGHTDOWN,
            (MouseButton::Right, false) => MOUSEEVENTF_RIGHTUP,
            (MouseButton::Middle, true) => MOUSEEVENTF_MIDDLEDOWN,
            (MouseButton::Middle, false) => MOUSEEVENTF_MIDDLEUP,
        };
        send_mouse(0, 0, flag, 0)
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> Result<()> {
        // `dx`/`dy` are notches (see input::normalize_scroll_delta). SendInput
        // wants WHEEL_DELTA units in mouseData, so multiply once here.
        if dy != 0 {
            send_mouse(0, 0, MOUSEEVENTF_WHEEL, (dy * WHEEL_DELTA) as u32)?;
        }
        if dx != 0 {
            send_mouse(0, 0, MOUSEEVENTF_HWHEEL, (dx * WHEEL_DELTA) as u32)?;
        }
        Ok(())
    }

    fn key_down(&mut self, key: &str) -> Result<()> {
        let vk = virtual_key(key)?;
        send_key(vk, false)
    }

    fn key_up(&mut self, key: &str) -> Result<()> {
        let vk = virtual_key(key)?;
        send_key(vk, true)
    }

    fn type_text(&mut self, text: &str) -> Result<()> {
        for ch in text.chars() {
            if ch == '\r' {
                continue;
            }
            if ch == '\n' {
                send_key(0x0d, false)?;
                send_key(0x0d, true)?;
                continue;
            }
            if ch == '\t' {
                send_key(0x09, false)?;
                send_key(0x09, true)?;
                continue;
            }
            let mut units = [0u16; 2];
            let len = ch.encode_utf16(&mut units).len();
            for unit in &units[..len] {
                send_unicode(*unit, false)?;
                send_unicode(*unit, true)?;
            }
        }
        Ok(())
    }
}

fn virtual_key(name: &str) -> Result<u16> {
    key_info(name)
        .map(|info| info.vk)
        .ok_or_else(|| msg(format!("unknown key '{name}'")))
}

fn send_mouse(
    x: i32,
    y: i32,
    flags: windows::Win32::UI::Input::KeyboardAndMouse::MOUSE_EVENT_FLAGS,
    data: u32,
) -> Result<()> {
    let (dx, dy, flags) = if (flags & MOUSEEVENTF_ABSOLUTE).0 != 0 {
        let (vx, vy, vw, vh) = virtual_rect()?;
        let ax = ((x - vx) as i64 * 65535 / (vw as i64 - 1).max(1)) as i32;
        let ay = ((y - vy) as i64 * 65535 / (vh as i64 - 1).max(1)) as i32;
        (ax, ay, flags)
    } else {
        (0, 0, flags)
    };
    unsafe {
        let input = INPUT {
            r#type: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_MOUSE,
            Anonymous: INPUT_0 {
                mi: MOUSEINPUT {
                    dx,
                    dy,
                    mouseData: data,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        if SendInput(&[input], std::mem::size_of::<INPUT>() as i32) == 0 {
            return Err(msg(format!(
                "SendInput mouse failed ({})",
                GetLastError().0
            )));
        }
    }
    Ok(())
}

fn send_key(vk: u16, up: bool) -> Result<()> {
    let flags = if up {
        KEYEVENTF_KEYUP
    } else {
        Default::default()
    };
    unsafe {
        let input = INPUT {
            r#type: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(vk),
                    wScan: 0,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        if SendInput(&[input], std::mem::size_of::<INPUT>() as i32) == 0 {
            return Err(msg(format!("SendInput key failed ({})", GetLastError().0)));
        }
    }
    Ok(())
}

fn send_unicode(unit: u16, up: bool) -> Result<()> {
    let mut flags = KEYEVENTF_UNICODE;
    if up {
        flags |= KEYEVENTF_KEYUP;
    }
    unsafe {
        let input = INPUT {
            r#type: windows::Win32::UI::Input::KeyboardAndMouse::INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: unit,
                    dwFlags: flags,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        if SendInput(&[input], std::mem::size_of::<INPUT>() as i32) == 0 {
            return Err(msg(format!(
                "SendInput unicode failed ({})",
                GetLastError().0
            )));
        }
    }
    Ok(())
}

fn ensure_uia(state: &mut WindowsState) -> Result<&IUIAutomation> {
    if state.automation.is_none() {
        let automation: IUIAutomation = unsafe {
            CoCreateInstance(&CUIAutomation, None, CLSCTX_INPROC_SERVER).map_err(|err| {
                msg(format!(
                    "UI Automation is unavailable: {err}. The desktop session may be headless."
                ))
            })?
        };
        state.automation = Some(automation);
    }
    Ok(state.automation.as_ref().unwrap())
}

fn ui_tree(state: &mut WindowsState, max_depth: u32, max_nodes: u32) -> Result<UiNode> {
    let automation = ensure_uia(state)?.clone();
    state.elements.clear();
    let root = unsafe { automation.GetRootElement() }.map_err(|err| msg(err.to_string()))?;
    let mut budget = max_nodes.max(1);
    walk_uia(&automation, state, root, max_depth.max(1), &mut budget)?
        .ok_or_else(|| msg("UI Automation tree is empty"))
}

fn walk_uia(
    automation: &IUIAutomation,
    state: &mut WindowsState,
    element: IUIAutomationElement,
    depth: u32,
    budget: &mut u32,
) -> Result<Option<UiNode>> {
    if *budget == 0 {
        return Ok(None);
    }
    *budget -= 1;
    state.elements.push(element.clone());
    let index = state.elements.len() - 1;
    let name = unsafe { element.CurrentName() }
        .map(|value| bstr_string(&value))
        .unwrap_or_default();
    let role = unsafe { element.CurrentControlType() }
        .map(role_name)
        .unwrap_or("unknown");
    let bounds = unsafe { element.CurrentBoundingRectangle() }
        .map(rect_from_win)
        .unwrap_or(DeskRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        });
    let value = value_of(&element).unwrap_or_default();
    let focused = unsafe { element.CurrentHasKeyboardFocus() }
        .map(|flag| flag.as_bool())
        .unwrap_or(false);
    let mut node = UiNode {
        id: format!("uia|{index}"),
        role: role.to_string(),
        name,
        bounds,
        value,
        focused,
        children: Vec::new(),
    };
    if depth <= 1 {
        return Ok(Some(node));
    }
    let condition =
        unsafe { automation.CreateTrueCondition() }.map_err(|err| msg(err.to_string()))?;
    let children: IUIAutomationElementArray =
        match unsafe { element.FindAll(TreeScope_Children, &condition) } {
            Ok(children) => children,
            Err(_) => return Ok(Some(node)),
        };
    let count = unsafe { children.Length() }.unwrap_or(0).clamp(0, 64);
    for index in 0..count {
        if *budget == 0 {
            break;
        }
        let Ok(child) = (unsafe { children.GetElement(index) }) else {
            continue;
        };
        if let Some(child) = walk_uia(automation, state, child, depth - 1, budget)? {
            node.children.push(child);
        }
    }
    Ok(Some(node))
}

fn value_of(element: &IUIAutomationElement) -> Option<String> {
    let pattern: IUIAutomationValuePattern =
        unsafe { element.GetCurrentPatternAs(UIA_ValuePatternId) }.ok()?;
    let value = unsafe { pattern.CurrentValue() }.ok()?;
    Some(bstr_string(&value))
}

fn rect_from_win(rect: RECT) -> DeskRect {
    DeskRect {
        x: rect.left,
        y: rect.top,
        width: rect.right.saturating_sub(rect.left).max(0) as u32,
        height: rect.bottom.saturating_sub(rect.top).max(0) as u32,
    }
}

fn bstr_string(value: &BSTR) -> String {
    String::from_utf16_lossy(value)
}

fn role_name(kind: windows::Win32::UI::Accessibility::UIA_CONTROLTYPE_ID) -> &'static str {
    if kind == UIA_ButtonControlTypeId {
        "button"
    } else if kind == UIA_EditControlTypeId
        || kind == UIA_TextControlTypeId
        || kind == UIA_DocumentControlTypeId
    {
        "text"
    } else if kind == UIA_WindowControlTypeId {
        "window"
    } else if kind == UIA_CheckBoxControlTypeId {
        "checkbox"
    } else if kind == UIA_RadioButtonControlTypeId {
        "radio"
    } else if kind == UIA_ComboBoxControlTypeId {
        "combobox"
    } else if kind == UIA_HyperlinkControlTypeId {
        "link"
    } else if kind == UIA_ListControlTypeId {
        "list"
    } else if kind == UIA_ListItemControlTypeId {
        "listitem"
    } else if kind == UIA_MenuItemControlTypeId {
        "menuitem"
    } else if kind == UIA_ImageControlTypeId {
        "image"
    } else if kind == UIA_ToolBarControlTypeId {
        "toolbar"
    } else if kind == UIA_TitleBarControlTypeId {
        "title"
    } else if kind == UIA_GroupControlTypeId || kind == UIA_PaneControlTypeId {
        "group"
    } else {
        "unknown"
    }
}

fn ui_act(state: &mut WindowsState, id: &str, op: ElementOp, value: Option<&str>) -> Result<()> {
    if state.elements.is_empty() {
        return Err(msg("call get_ui_tree before acting on a Windows element"));
    }
    let index = parse_uia_id(id)?;
    let element = state
        .elements
        .get(index)
        .cloned()
        .ok_or_else(|| msg(format!("element '{id}' is not in the last tree")))?;
    match op {
        ElementOp::Focus => {
            unsafe { element.SetFocus() }.map_err(|err| msg(format!("UIA focus: {err}")))
        }
        ElementOp::SetValue => {
            let text = value.unwrap_or("");
            let pattern: IUIAutomationValuePattern =
                unsafe { element.GetCurrentPatternAs(UIA_ValuePatternId) }
                    .map_err(|_| msg(format!("element '{id}' has no value pattern")))?;
            let bstr = BSTR::from(text);
            unsafe { pattern.SetValue(&bstr) }.map_err(|err| msg(format!("UIA set_value: {err}")))
        }
        ElementOp::Click => {
            if let Ok(invoke) = unsafe {
                element.GetCurrentPatternAs::<IUIAutomationInvokePattern>(UIA_InvokePatternId)
            } {
                if unsafe { invoke.Invoke() }.is_ok() {
                    return Ok(());
                }
            }
            let rect = unsafe { element.CurrentBoundingRectangle() }
                .map_err(|err| msg(err.to_string()))?;
            let x = rect.left + (rect.right - rect.left) / 2;
            let y = rect.top + (rect.bottom - rect.top) / 2;
            state.mouse_move(x, y)?;
            state.mouse_button(MouseButton::Left, true)?;
            state.mouse_button(MouseButton::Left, false)?;
            Ok(())
        }
    }
}

fn parse_uia_id(id: &str) -> Result<usize> {
    let rest = id
        .strip_prefix("uia|")
        .ok_or_else(|| msg(format!("element id '{id}' is not a UI Automation id")))?;
    rest.parse::<usize>()
        .map_err(|_| msg(format!("element id '{id}' is not a UI Automation id")))
}

struct WindowsSession {
    worker: Worker<WindowsState>,
    request: CaptureRequest,
    interval: Duration,
    last: Instant,
}

impl FrameSource for WindowsSession {
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>> {
        wait_until_due(self.last, self.interval);
        let request = self.request.clone();
        let frame = self
            .worker
            .call(move |state| state.capture_stream(&request))?;
        self.last = Instant::now();
        Ok(Some(frame))
    }

    fn mode(&self) -> StreamMode {
        StreamMode::Surface {
            backend: "dxgi".into(),
        }
    }
}

#[derive(Clone)]
struct WindowsDesktop {
    worker: Worker<WindowsState>,
}

impl WindowsDesktop {
    fn start() -> Self {
        Self {
            worker: Worker::spawn(WindowsState::new),
        }
    }
}

fn current_cursor_visible() -> bool {
    let mut info = CURSORINFO {
        cbSize: std::mem::size_of::<CURSORINFO>() as u32,
        ..Default::default()
    };
    if unsafe { GetCursorInfo(&mut info) }.is_err() {
        return true;
    }
    info.flags.0 & CURSOR_SHOWING.0 != 0
}

fn current_cursor_shape() -> String {
    let mut info = CURSORINFO {
        cbSize: std::mem::size_of::<CURSORINFO>() as u32,
        ..Default::default()
    };
    if unsafe { GetCursorInfo(&mut info) }.is_err() {
        return "arrow".into();
    }
    let handle = info.hCursor;
    // Compare against stock cursors. Fall back to the MAKEINTRESOURCE id when
    // the handle itself is the low ordinal (some themes do that).
    let stock: &[(windows::core::PCWSTR, &str)] = &[
        (IDC_ARROW, "arrow"),
        (IDC_IBEAM, "ibeam"),
        (IDC_HAND, "hand"),
        (IDC_SIZEALL, "sizeall"),
        (IDC_SIZENS, "sizens"),
        (IDC_SIZEWE, "sizewe"),
        (IDC_SIZENWSE, "sizenwse"),
        (IDC_SIZENESW, "sizenesw"),
        (IDC_CROSS, "cross"),
        (IDC_NO, "no"),
        (IDC_WAIT, "wait"),
        (IDC_HELP, "help"),
    ];
    for &(idc, name) in stock {
        if let Ok(stock_handle) = unsafe { LoadCursorW(None, idc) } {
            if stock_handle == handle {
                return normalize_shape(name).to_string();
            }
        }
    }
    let id = handle.0 as usize;
    if id != 0 && id < 0x10000 {
        return shape_from_win_idc(id).to_string();
    }
    "arrow".into()
}

/// True when the process can open the input desktop. UAC / Ctrl+Alt+Del moves
/// input to Winlogon's secure desktop and this fails.
pub fn windows_capturable_state() -> CapturableState {
    unsafe {
        match OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, DESKTOP_READOBJECTS) {
            Ok(desk) => {
                let _ = CloseDesktop(desk);
                CapturableState::default()
            }
            Err(_) => CapturableState {
                capturable: false,
                reason: Some("secure desktop".into()),
            },
        }
    }
}

/// Heuristic: a frame that is almost entirely black often means the secure
/// desktop (or a blanked output) rather than a real dark wallpaper.
pub fn frame_looks_blank(frame: &Frame) -> bool {
    let pixels = frame.pixels();
    if pixels.len() < 16 {
        return true;
    }
    let step = ((pixels.len() / 4) / 4096).max(1) * 4;
    let mut checked = 0u32;
    let mut dark = 0u32;
    let mut i = 0;
    while i + 3 < pixels.len() {
        let b = pixels[i] as u32;
        let g = pixels[i + 1] as u32;
        let r = pixels[i + 2] as u32;
        checked += 1;
        if r | g | b < 8 {
            dark += 1;
        }
        i += step;
    }
    checked > 0 && dark * 100 / checked >= 98
}

pub fn open() -> Arc<Desktop> {
    let backend = Arc::new(WindowsDesktop::start());
    Arc::new(Desktop {
        capture: backend.clone(),
        hid: backend.clone(),
        a11y: backend,
    })
}

impl CaptureBackend for WindowsDesktop {
    fn backend_name(&self) -> &str {
        "windows"
    }

    fn list_monitors(&self) -> Result<Vec<MonitorInfo>> {
        self.worker.call(|state| state.monitors())
    }

    fn cursor(&self) -> Option<CursorSample> {
        let mut point = POINT::default();
        if unsafe { GetCursorPos(&mut point) }.is_err() {
            return None;
        }
        Some(CursorSample {
            x: point.x,
            y: point.y,
            shape: current_cursor_shape(),
        })
    }

    fn cursor_visible(&self) -> bool {
        current_cursor_visible()
    }

    fn capturable_state(&self) -> CapturableState {
        let input = windows_capturable_state();
        if !input.capturable {
            return input;
        }
        match self.worker.call(|state| {
            Ok(match state.last_frame.as_ref() {
                Some(frame) if frame_looks_blank(frame) => CapturableState {
                    capturable: false,
                    reason: Some("secure desktop".into()),
                },
                _ => CapturableState::default(),
            })
        }) {
            Ok(state) => state,
            Err(_) => CapturableState::default(),
        }
    }

    fn capture(&self, request: &CaptureRequest) -> Result<Frame> {
        let request = request.clone();
        self.worker.call(move |state| state.capture(&request))
    }

    fn open_session(&self, request: &CaptureRequest) -> Result<Box<dyn FrameSource>> {
        Ok(Box::new(WindowsSession {
            worker: self.worker.clone(),
            request: request.clone(),
            interval: stream_interval(request.max_fps),
            last: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
        }))
    }
}

impl HidBackend for WindowsDesktop {
    fn backend_name(&self) -> &str {
        "sendinput"
    }

    fn inject(&self, action: &InputAction) -> Result<()> {
        let action = action.clone();
        self.worker.call(move |state| perform(state, &action))
    }
}

impl A11yBackend for WindowsDesktop {
    fn backend_name(&self) -> &str {
        "uia"
    }

    fn tree(&self, max_depth: u32, max_nodes: u32) -> Result<UiNode> {
        self.worker
            .call(move |state| ui_tree(state, max_depth, max_nodes))
    }

    fn act(&self, id: &str, op: ElementOp, value: Option<&str>) -> Result<()> {
        let id = id.to_string();
        let value = value.map(str::to_string);
        self.worker
            .call(move |state| ui_act(state, &id, op, value.as_deref()))
    }
}

#[link(name = "user32")]
extern "system" {
    fn PrintWindow(hwnd: HWND, hdc: HDC, flags: u32) -> i32;
}
