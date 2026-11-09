//! macOS capture, input, and the accessibility tree.
//!
//! Capture uses CoreGraphics (`CGDisplayCreateImage`, `CGWindowListCreateImage`).
//! That is the synchronous screen API: a session calls it again at `max_fps`
//! and returns [`StreamMode::Surface`](crate::capture::StreamMode). ScreenCaptureKit's
//! `SCScreenshotManager` is a completion-handler API and is not called here;
//! a recorder should pull [`FrameSource`](crate::capture::FrameSource) frames
//! rather than opening a second capture stack.
//!
//! The process needs Screen Recording for images and Accessibility for
//! `CGEvent` plus the AX tree. macOS asks for those the first time this
//! process captures or posts events. Grant them to the terminal, app, or
//! parent that launches `agentlink node`, then restart the node.
//!
//! Pointer coordinates are pixels of the captured framebuffer (top-left of the
//! virtual desktop). They are converted to Quartz points with the display scale.

use std::ffi::c_void;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::a11y::{A11yBackend, ElementOp, UiNode};
use crate::capture::{
    frame_interval, scale_frame, stream_interval, wait_until_due, CaptureBackend, CaptureRequest,
    CaptureTarget, Frame, FrameSource, MonitorInfo, Rect as DeskRect, StreamMode,
};
use crate::error::{msg, Result};
use crate::input::{perform, HidBackend, InputAction, MouseButton, Pointer};
use crate::keys::key_info;
use crate::worker::Worker;
use crate::Desktop;

#[repr(C)]
#[derive(Clone, Copy)]
struct CgPoint {
    x: f64,
    y: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CgSize {
    width: f64,
    height: f64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct CgRect {
    origin: CgPoint,
    size: CgSize,
}

type DisplayId = u32;

#[link(name = "CoreFoundation", kind = "framework")]
#[link(name = "CoreGraphics", kind = "framework")]
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn CGMainDisplayID() -> DisplayId;
    fn CGGetActiveDisplayList(max: u32, displays: *mut DisplayId, count: *mut u32) -> i32;
    fn CGDisplayPixelsWide(display: DisplayId) -> usize;
    fn CGDisplayPixelsHigh(display: DisplayId) -> usize;
    fn CGDisplayBounds(display: DisplayId) -> CgRect;
    fn CGDisplayCreateImage(display: DisplayId) -> *mut c_void;
    fn CGWindowListCreateImage(
        bounds: CgRect,
        option: u32,
        window: u32,
        image_option: u32,
    ) -> *mut c_void;
    fn CGWindowListCopyWindowInfo(option: u32, relative: u32) -> *mut c_void;
    fn CGImageGetWidth(image: *mut c_void) -> usize;
    fn CGImageGetHeight(image: *mut c_void) -> usize;
    fn CGImageGetBytesPerRow(image: *mut c_void) -> usize;
    fn CGImageGetBitsPerPixel(image: *mut c_void) -> usize;
    fn CGImageGetBitmapInfo(image: *mut c_void) -> u32;
    fn CGImageGetDataProvider(image: *mut c_void) -> *mut c_void;
    fn CGImageRelease(image: *mut c_void);
    fn CGDataProviderCopyData(provider: *mut c_void) -> *mut c_void;

    fn CFDataGetBytePtr(data: *mut c_void) -> *const u8;
    fn CFDataGetLength(data: *mut c_void) -> isize;
    fn CFRelease(value: *mut c_void);
    fn CFRetain(value: *mut c_void) -> *mut c_void;
    fn CFStringCreateWithCString(alloc: *mut c_void, text: *const i8, encoding: u32)
        -> *mut c_void;
    fn CFStringGetCString(text: *mut c_void, buffer: *mut i8, size: isize, encoding: u32) -> bool;
    fn CFArrayGetCount(array: *mut c_void) -> isize;
    fn CFArrayGetValueAtIndex(array: *mut c_void, index: isize) -> *const c_void;
    fn CFGetTypeID(value: *const c_void) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFNumberGetTypeID() -> usize;
    fn CFArrayGetTypeID() -> usize;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFBooleanGetTypeID() -> usize;
    fn CFDictionaryGetValue(dict: *mut c_void, key: *const c_void) -> *const c_void;
    fn CFNumberGetValue(number: *const c_void, kind: isize, out: *mut c_void) -> bool;
    fn CFBooleanGetValue(value: *const c_void) -> bool;
    static kCFBooleanTrue: *const c_void;

    fn CGEventCreateMouseEvent(
        source: *mut c_void,
        kind: u32,
        point: CgPoint,
        button: u32,
    ) -> *mut c_void;
    fn CGEventCreateKeyboardEvent(source: *mut c_void, keycode: u16, down: bool) -> *mut c_void;
    fn CGEventKeyboardSetUnicodeString(event: *mut c_void, length: usize, text: *const u16);
    fn CGEventPost(tap: u32, event: *mut c_void);
    fn CGEventCreateScrollWheelEvent(
        source: *mut c_void,
        units: u32,
        wheel_count: u32,
        wheel1: i32,
        wheel2: i32,
    ) -> *mut c_void;

    fn AXIsProcessTrusted() -> bool;
    fn AXUIElementCreateSystemWide() -> *mut c_void;
    fn AXUIElementCopyAttributeValue(
        element: *mut c_void,
        attribute: *mut c_void,
        value: *mut *mut c_void,
    ) -> i32;
    fn AXUIElementSetAttributeValue(
        element: *mut c_void,
        attribute: *mut c_void,
        value: *const c_void,
    ) -> i32;
    fn AXUIElementPerformAction(element: *mut c_void, action: *mut c_void) -> i32;
    fn AXValueGetTypeID() -> usize;
    fn AXValueGetValue(value: *const c_void, kind: u32, out: *mut c_void) -> bool;
}

const UTF8: u32 = 0x0800_0100;
const WINDOW_ON_SCREEN: u32 = 1;
const WINDOW_INCLUDING: u32 = 8;
const WINDOW_EXCLUDE_DESKTOP: u32 = 16;
const IMAGE_BEST: u32 = 8;
const ALPHA_MASK: u32 = 0x1f;
const ORDER_MASK: u32 = 0x7000;
const ORDER_32_LITTLE: u32 = 2 << 12;

struct DisplayGeom {
    id: DisplayId,
    /// Pixel origin of this display in the virtual desktop.
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    /// Pixels per Quartz point.
    scale: f64,
    /// Quartz point origin (top-left of this display in global space).
    point_x: f64,
    point_y: f64,
    primary: bool,
    name: String,
}

struct MacState {
    displays: Vec<DisplayGeom>,
    ax: Vec<*mut c_void>,
    /// Last Quartz point posted by `mouse_move`. Button events reuse it so a
    /// click does not jump to the origin.
    cursor: CgPoint,
}

impl MacState {
    fn new() -> Self {
        Self {
            displays: Vec::new(),
            ax: Vec::new(),
            cursor: CgPoint { x: 0.0, y: 0.0 },
        }
    }

    fn refresh(&mut self) {
        self.displays = display_list();
    }

    fn capture(&mut self, request: &CaptureRequest) -> Result<Frame> {
        self.refresh();
        let frame = match &request.target {
            CaptureTarget::FullScreen => capture_full(&self.displays)?,
            CaptureTarget::Monitor(index) => capture_monitor(&self.displays, *index)?,
            CaptureTarget::Region(rect) => {
                let full = capture_full(&self.displays)?;
                crate::capture::crop_frame(&full, *rect)?
            }
            CaptureTarget::Window(query) => capture_window(query)?,
        };
        scale_frame(frame, request.scale)
    }
}

impl Drop for MacState {
    fn drop(&mut self) {
        release_ax(&mut self.ax);
    }
}

fn display_list() -> Vec<DisplayGeom> {
    let mut ids = [0u32; 32];
    let mut count = 0u32;
    let err = unsafe { CGGetActiveDisplayList(ids.len() as u32, ids.as_mut_ptr(), &mut count) };
    if err != 0 || count == 0 {
        let id = unsafe { CGMainDisplayID() };
        return vec![geom(id, 0, true)];
    }
    let main = unsafe { CGMainDisplayID() };
    let mut raw: Vec<DisplayGeom> = (0..count as usize)
        .map(|index| geom(ids[index], index as u32, ids[index] == main))
        .collect();
    let min_x = raw.iter().map(|item| item.x).min().unwrap_or(0);
    let min_y = raw.iter().map(|item| item.y).min().unwrap_or(0);
    for item in &mut raw {
        item.x -= min_x;
        item.y -= min_y;
    }
    raw
}

fn geom(id: DisplayId, index: u32, primary: bool) -> DisplayGeom {
    let bounds = unsafe { CGDisplayBounds(id) };
    let pixels_w = unsafe { CGDisplayPixelsWide(id) } as u32;
    let pixels_h = unsafe { CGDisplayPixelsHigh(id) } as u32;
    let scale = if bounds.size.width > 1.0 {
        pixels_w as f64 / bounds.size.width
    } else {
        1.0
    };
    let scale = if scale.is_finite() && scale > 0.0 {
        scale
    } else {
        1.0
    };
    DisplayGeom {
        id,
        x: (bounds.origin.x * scale).round() as i32,
        y: (bounds.origin.y * scale).round() as i32,
        width: pixels_w.max(1),
        height: pixels_h.max(1),
        scale,
        point_x: bounds.origin.x,
        point_y: bounds.origin.y,
        primary,
        name: if primary {
            format!("main-{index}")
        } else {
            format!("display-{index}")
        },
    }
}

fn capture_monitor(displays: &[DisplayGeom], index: u32) -> Result<Frame> {
    let display = displays
        .get(index as usize)
        .ok_or_else(|| msg(format!("no monitor {index}")))?;
    let image = unsafe { CGDisplayCreateImage(display.id) };
    image_frame(image, "coregraphics")
}

fn capture_full(displays: &[DisplayGeom]) -> Result<Frame> {
    if displays.is_empty() {
        return Err(msg("no displays"));
    }
    if displays.len() == 1 {
        return capture_monitor(displays, 0);
    }
    let width = displays
        .iter()
        .map(|item| item.x as i64 + item.width as i64)
        .max()
        .unwrap_or(1)
        .max(1) as u32;
    let height = displays
        .iter()
        .map(|item| item.y as i64 + item.height as i64)
        .max()
        .unwrap_or(1)
        .max(1) as u32;
    let mut canvas = vec![0u8; width as usize * height as usize * 4];
    for display in displays {
        let frame = capture_monitor(displays, display_index(displays, display.id))?;
        blit(&mut canvas, width, display.x, display.y, &frame);
    }
    Frame::from_bgra(width, height, width * 4, &canvas, "coregraphics")
}

fn display_index(displays: &[DisplayGeom], id: DisplayId) -> u32 {
    displays.iter().position(|item| item.id == id).unwrap_or(0) as u32
}

fn blit(canvas: &mut [u8], canvas_w: u32, x: i32, y: i32, frame: &Frame) {
    for row in 0..frame.height {
        let dst_y = y + row as i32;
        if dst_y < 0 || dst_y as u32 >= canvas.len() as u32 / (canvas_w as usize * 4) as u32 {
            continue;
        }
        let copy_w = frame.width.min(canvas_w.saturating_sub(x.max(0) as u32));
        if copy_w == 0 || x >= canvas_w as i32 {
            continue;
        }
        let src = (row as usize * frame.width as usize) * 4;
        let dst = (dst_y as usize * canvas_w as usize + x.max(0) as usize) * 4;
        let nbytes = copy_w as usize * 4;
        canvas[dst..dst + nbytes].copy_from_slice(&frame.pixels[src..src + nbytes]);
    }
}

fn capture_window(query: &str) -> Result<Frame> {
    let id = window_id(query)?;
    let bounds = CgRect {
        origin: CgPoint { x: 0.0, y: 0.0 },
        size: CgSize {
            width: 0.0,
            height: 0.0,
        },
    };
    let image = unsafe { CGWindowListCreateImage(bounds, WINDOW_INCLUDING, id, IMAGE_BEST) };
    image_frame(image, "coregraphics-window")
}

fn window_id(query: &str) -> Result<u32> {
    if let Ok(id) = query.parse::<u32>() {
        return Ok(id);
    }
    let list = unsafe { CGWindowListCopyWindowInfo(WINDOW_ON_SCREEN | WINDOW_EXCLUDE_DESKTOP, 0) };
    if list.is_null() {
        return Err(msg(
            "CGWindowListCopyWindowInfo failed. Grant Screen Recording to the process that launches the node.",
        ));
    }
    let query_l = query.to_ascii_lowercase();
    let count = unsafe { CFArrayGetCount(list) };
    let mut found = None;
    for index in 0..count {
        let item = unsafe { CFArrayGetValueAtIndex(list, index) } as *mut c_void;
        if item.is_null() {
            continue;
        }
        let name =
            dict_string(item, "kCGWindowName").or_else(|| dict_string(item, "kCGWindowOwnerName"));
        if name
            .map(|text| text.to_ascii_lowercase().contains(&query_l))
            .unwrap_or(false)
        {
            found = dict_u32(item, "kCGWindowNumber");
            if found.is_some() {
                break;
            }
        }
    }
    unsafe { CFRelease(list) };
    found.ok_or_else(|| msg(format!("no window title contains '{query}'")))
}

fn image_frame(image: *mut c_void, backend: &str) -> Result<Frame> {
    if image.is_null() {
        return Err(msg(
            "macOS returned no image. Grant Screen Recording to the terminal or app that launches the node, then restart it.",
        ));
    }
    let width = unsafe { CGImageGetWidth(image) } as u32;
    let height = unsafe { CGImageGetHeight(image) } as u32;
    let stride = unsafe { CGImageGetBytesPerRow(image) } as u32;
    let bpp = unsafe { CGImageGetBitsPerPixel(image) };
    let info = unsafe { CGImageGetBitmapInfo(image) };
    let provider = unsafe { CGImageGetDataProvider(image) };
    if provider.is_null() {
        unsafe { CGImageRelease(image) };
        return Err(msg("capture image has no data provider"));
    }
    let data = unsafe { CGDataProviderCopyData(provider) };
    if data.is_null() {
        unsafe { CGImageRelease(image) };
        return Err(msg("capture image has no pixel buffer"));
    }
    let len = unsafe { CFDataGetLength(data) }.max(0) as usize;
    let ptr = unsafe { CFDataGetBytePtr(data) };
    if ptr.is_null() {
        unsafe {
            CFRelease(data);
            CGImageRelease(image);
        }
        return Err(msg("capture image has an empty pixel buffer"));
    }
    let bytes = unsafe { std::slice::from_raw_parts(ptr, len) };
    let result = if bpp != 32 {
        Err(msg(format!(
            "capture image is {bpp} bits per pixel; only 32-bit frames are supported"
        )))
    } else {
        pack_bgra(bytes, width, height, stride, info, backend)
    };
    unsafe {
        CFRelease(data);
        CGImageRelease(image);
    }
    result
}

fn pack_bgra(
    bytes: &[u8],
    width: u32,
    height: u32,
    stride: u32,
    info: u32,
    backend: &str,
) -> Result<Frame> {
    let alpha = info & ALPHA_MASK;
    let order = info & ORDER_MASK;
    let little = order == ORDER_32_LITTLE || order == 0;
    // Little-endian + alpha-first / none-skip-first is BGRA, which is what CG display images usually are.
    let bgra = little && matches!(alpha, 2 | 4 | 6 | 0);
    if bgra {
        return Frame::from_bgra(width, height, stride, bytes, backend);
    }
    let row = width as usize * 4;
    let stride = stride as usize;
    let mut out = vec![0u8; row * height as usize];
    for y in 0..height as usize {
        let src_row = y * stride;
        for x in 0..width as usize {
            let src = src_row + x * 4;
            if src + 3 >= bytes.len() {
                break;
            }
            let (b, g, r, a) = if little {
                (bytes[src], bytes[src + 1], bytes[src + 2], bytes[src + 3])
            } else {
                (bytes[src + 3], bytes[src + 2], bytes[src + 1], bytes[src])
            };
            let dst = (y * width as usize + x) * 4;
            out[dst] = b;
            out[dst + 1] = g;
            out[dst + 2] = r;
            out[dst + 3] = a;
        }
    }
    Frame::from_bgra(width, height, width * 4, &out, backend)
}

impl Pointer for MacState {
    fn mouse_move(&mut self, x: i32, y: i32) -> Result<()> {
        if self.displays.is_empty() {
            self.refresh();
        }
        let point = self.to_point(x, y);
        self.cursor = point;
        post_mouse(5, point, 0)
    }

    fn mouse_button(&mut self, button: MouseButton, down: bool) -> Result<()> {
        let (kind, which) = match (button, down) {
            (MouseButton::Left, true) => (1, 0),
            (MouseButton::Left, false) => (2, 0),
            (MouseButton::Right, true) => (3, 1),
            (MouseButton::Right, false) => (4, 1),
            (MouseButton::Middle, true) => (25, 2),
            (MouseButton::Middle, false) => (26, 2),
        };
        post_mouse(kind, self.cursor, which)
    }

    fn scroll(&mut self, dx: i32, dy: i32) -> Result<()> {
        unsafe {
            let event = CGEventCreateScrollWheelEvent(std::ptr::null_mut(), 1, 2, dy, dx);
            if event.is_null() {
                return Err(msg(
                    "CGEventCreateScrollWheelEvent failed. Grant Accessibility to this process.",
                ));
            }
            CGEventPost(0, event);
            CFRelease(event);
        }
        Ok(())
    }

    fn key_down(&mut self, key: &str) -> Result<()> {
        post_key(key, true)
    }

    fn key_up(&mut self, key: &str) -> Result<()> {
        post_key(key, false)
    }

    fn type_text(&mut self, text: &str) -> Result<()> {
        for ch in text.chars() {
            if ch == '\r' {
                continue;
            }
            if ch == '\n' {
                post_key("enter", true)?;
                post_key("enter", false)?;
                continue;
            }
            post_unicode(ch, true)?;
            post_unicode(ch, false)?;
        }
        Ok(())
    }
}

impl MacState {
    fn to_point(&self, x: i32, y: i32) -> CgPoint {
        for display in &self.displays {
            let inside = x >= display.x
                && y >= display.y
                && (x as i64) < display.x as i64 + display.width as i64
                && (y as i64) < display.y as i64 + display.height as i64;
            if inside {
                let local_x = (x - display.x) as f64 / display.scale;
                let local_y = (y - display.y) as f64 / display.scale;
                return CgPoint {
                    x: display.point_x + local_x,
                    y: display.point_y + local_y,
                };
            }
        }
        let scale = self.displays.first().map(|item| item.scale).unwrap_or(1.0);
        CgPoint {
            x: x as f64 / scale,
            y: y as f64 / scale,
        }
    }
}

fn post_mouse(kind: u32, point: CgPoint, button: u32) -> Result<()> {
    unsafe {
        let event = CGEventCreateMouseEvent(std::ptr::null_mut(), kind, point, button);
        if event.is_null() {
            return Err(msg(
                "CGEventCreateMouseEvent failed. Grant Accessibility to the process that launches the node.",
            ));
        }
        CGEventPost(0, event);
        CFRelease(event);
    }
    Ok(())
}

fn post_key(name: &str, down: bool) -> Result<()> {
    let code = key_info(name)
        .map(|info| info.mac)
        .ok_or_else(|| msg(format!("unknown key '{name}'")))?;
    unsafe {
        let event = CGEventCreateKeyboardEvent(std::ptr::null_mut(), code, down);
        if event.is_null() {
            return Err(msg(
                "CGEventCreateKeyboardEvent failed. Grant Accessibility to this process.",
            ));
        }
        CGEventPost(0, event);
        CFRelease(event);
    }
    Ok(())
}

fn post_unicode(ch: char, down: bool) -> Result<()> {
    let mut units = [0u16; 2];
    let encoded = ch.encode_utf16(&mut units);
    let len = encoded.len();
    unsafe {
        let event = CGEventCreateKeyboardEvent(std::ptr::null_mut(), 0, down);
        if event.is_null() {
            return Err(msg("CGEventCreateKeyboardEvent failed"));
        }
        CGEventKeyboardSetUnicodeString(event, len, units.as_ptr());
        CGEventPost(0, event);
        CFRelease(event);
    }
    Ok(())
}

fn ui_tree(state: &mut MacState, max_depth: u32, max_nodes: u32) -> Result<UiNode> {
    if !unsafe { AXIsProcessTrusted() } {
        return Err(msg(
            "macOS Accessibility permission is off. Enable it for the terminal or app that launches the node, then restart the node.",
        ));
    }
    release_ax(&mut state.ax);
    let root = unsafe { AXUIElementCreateSystemWide() };
    if root.is_null() {
        return Err(msg("AXUIElementCreateSystemWide failed"));
    }
    let mut budget = max_nodes.max(1);
    let tree = walk_ax(state, root, max_depth.max(1), &mut budget)?;
    tree.ok_or_else(|| msg("accessibility tree is empty"))
}

fn walk_ax(
    state: &mut MacState,
    element: *mut c_void,
    depth: u32,
    budget: &mut u32,
) -> Result<Option<UiNode>> {
    if element.is_null() || *budget == 0 {
        if !element.is_null() {
            unsafe { CFRelease(element) };
        }
        return Ok(None);
    }
    *budget -= 1;
    state.ax.push(element);
    let index = state.ax.len() - 1;
    let role_raw = ax_string(element, "AXRole").unwrap_or_default();
    let name = ax_string(element, "AXTitle")
        .or_else(|| ax_string(element, "AXDescription"))
        .unwrap_or_default();
    let value = ax_string(element, "AXValue").unwrap_or_default();
    let focused = ax_bool(element, "AXFocused");
    let bounds = ax_bounds(element);
    let mut node = UiNode {
        id: format!("ax|{index}"),
        role: compact_role(&role_raw).to_string(),
        name,
        bounds,
        value,
        focused,
        children: Vec::new(),
    };
    if depth <= 1 {
        return Ok(Some(node));
    }
    let children = ax_children(element);
    for child in children.into_iter().take(64) {
        if *budget == 0 {
            unsafe { CFRelease(child) };
            continue;
        }
        if let Some(child) = walk_ax(state, child, depth - 1, budget)? {
            node.children.push(child);
        }
    }
    Ok(Some(node))
}

fn ui_act(state: &mut MacState, id: &str, op: ElementOp, value: Option<&str>) -> Result<()> {
    let index = id
        .strip_prefix("ax|")
        .and_then(|rest| rest.parse::<usize>().ok())
        .ok_or_else(|| msg(format!("element id '{id}' is not an accessibility id")))?;
    let element = *state.ax.get(index).ok_or_else(|| {
        msg(format!(
            "element '{id}' is not in the last tree. Call get_ui_tree again."
        ))
    })?;
    match op {
        ElementOp::Click => ax_action(element, "AXPress"),
        ElementOp::Focus => ax_set_bool(element, "AXFocused"),
        ElementOp::SetValue => ax_set_string(element, "AXValue", value.unwrap_or("")),
    }
}

fn ax_action(element: *mut c_void, name: &str) -> Result<()> {
    let attr = cf_string(name)?;
    let code = unsafe { AXUIElementPerformAction(element, attr) };
    unsafe { CFRelease(attr) };
    ax_result(code, "click")
}

fn ax_set_bool(element: *mut c_void, name: &str) -> Result<()> {
    let attr = cf_string(name)?;
    let code = unsafe { AXUIElementSetAttributeValue(element, attr, kCFBooleanTrue) };
    unsafe { CFRelease(attr) };
    ax_result(code, "focus")
}

fn ax_set_string(element: *mut c_void, name: &str, text: &str) -> Result<()> {
    let attr = cf_string(name)?;
    let value = cf_string(text)?;
    let code = unsafe { AXUIElementSetAttributeValue(element, attr, value) };
    unsafe {
        CFRelease(value);
        CFRelease(attr);
    }
    ax_result(code, "set_value")
}

fn ax_result(code: i32, what: &str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else if code == -25211 {
        Err(msg(
            "macOS Accessibility permission is off. Enable it for the process that launches the node, then restart the node.",
        ))
    } else {
        Err(msg(format!("accessibility {what} failed ({code})")))
    }
}

fn ax_string(element: *mut c_void, name: &str) -> Option<String> {
    let value = ax_copy(element, name)?;
    let text = cf_to_string(value);
    unsafe { CFRelease(value) };
    text
}

fn ax_bool(element: *mut c_void, name: &str) -> bool {
    let Some(value) = ax_copy(element, name) else {
        return false;
    };
    let flag = unsafe { CFGetTypeID(value) == CFBooleanGetTypeID() && CFBooleanGetValue(value) };
    unsafe { CFRelease(value) };
    flag
}

fn ax_bounds(element: *mut c_void) -> DeskRect {
    let Some(position) = ax_copy(element, "AXPosition") else {
        return DeskRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        };
    };
    let Some(size) = ax_copy(element, "AXSize") else {
        unsafe { CFRelease(position) };
        return DeskRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        };
    };
    let mut point = CgPoint { x: 0.0, y: 0.0 };
    let mut cg_size = CgSize {
        width: 0.0,
        height: 0.0,
    };
    unsafe {
        AXValueGetValue(position, 1, &mut point as *mut CgPoint as *mut c_void);
        AXValueGetValue(size, 2, &mut cg_size as *mut CgSize as *mut c_void);
        CFRelease(position);
        CFRelease(size);
    }
    DeskRect {
        x: point.x.round() as i32,
        y: point.y.round() as i32,
        width: cg_size.width.round().max(0.0) as u32,
        height: cg_size.height.round().max(0.0) as u32,
    }
}

fn ax_children(element: *mut c_void) -> Vec<*mut c_void> {
    let Some(value) = ax_copy(element, "AXChildren") else {
        return Vec::new();
    };
    if unsafe { CFGetTypeID(value) } != unsafe { CFArrayGetTypeID() } {
        unsafe { CFRelease(value) };
        return Vec::new();
    }
    let count = unsafe { CFArrayGetCount(value) }.clamp(0, 64);
    let mut out = Vec::with_capacity(count as usize);
    for index in 0..count {
        let child = unsafe { CFArrayGetValueAtIndex(value, index) } as *mut c_void;
        if !child.is_null() {
            out.push(unsafe { CFRetain(child) });
        }
    }
    unsafe { CFRelease(value) };
    out
}

fn ax_copy(element: *mut c_void, name: &str) -> Option<*mut c_void> {
    let Ok(attr) = cf_string(name) else {
        return None;
    };
    let mut value = std::ptr::null_mut();
    let code = unsafe { AXUIElementCopyAttributeValue(element, attr, &mut value) };
    unsafe { CFRelease(attr) };
    if code == 0 && !value.is_null() {
        Some(value)
    } else {
        None
    }
}

fn cf_string(text: &str) -> Result<*mut c_void> {
    let c = std::ffi::CString::new(text).map_err(|_| msg("string contains a nul"))?;
    let value = unsafe { CFStringCreateWithCString(std::ptr::null_mut(), c.as_ptr(), UTF8) };
    if value.is_null() {
        Err(msg("CFStringCreateWithCString failed"))
    } else {
        Ok(value)
    }
}

fn cf_to_string(value: *mut c_void) -> Option<String> {
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFStringGetTypeID() } {
        return None;
    }
    let mut buf = [0u8; 1024];
    let ok =
        unsafe { CFStringGetCString(value, buf.as_mut_ptr() as *mut i8, buf.len() as isize, UTF8) };
    if !ok {
        return None;
    }
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

fn dict_string(dict: *mut c_void, key: &str) -> Option<String> {
    let key = cf_string(key).ok()?;
    let value = unsafe { CFDictionaryGetValue(dict, key) } as *mut c_void;
    unsafe { CFRelease(key) };
    if value.is_null() {
        return None;
    }
    let text = cf_to_string(value);
    text
}

fn dict_u32(dict: *mut c_void, key: &str) -> Option<u32> {
    let key = cf_string(key).ok()?;
    let value = unsafe { CFDictionaryGetValue(dict, key) };
    unsafe { CFRelease(key) };
    if value.is_null() || unsafe { CFGetTypeID(value) } != unsafe { CFNumberGetTypeID() } {
        return None;
    }
    let mut number = 0i32;
    let ok = unsafe { CFNumberGetValue(value, 3, &mut number as *mut i32 as *mut c_void) };
    if ok {
        Some(number as u32)
    } else {
        None
    }
}

fn compact_role(role: &str) -> &str {
    match role {
        "AXButton" => "button",
        "AXTextField" | "AXTextArea" | "AXStaticText" => "text",
        "AXCheckBox" => "checkbox",
        "AXRadioButton" => "radio",
        "AXWindow" => "window",
        "AXMenuItem" => "menuitem",
        "AXLink" => "link",
        "AXList" => "list",
        "AXImage" => "image",
        "AXApplication" => "application",
        "AXGroup" => "group",
        "AXPopUpButton" => "combobox",
        other => other.strip_prefix("AX").unwrap_or(other),
    }
}

fn release_ax(elements: &mut Vec<*mut c_void>) {
    for element in elements.drain(..) {
        if !element.is_null() {
            unsafe { CFRelease(element) };
        }
    }
}

struct MacSession {
    worker: Worker<MacState>,
    request: CaptureRequest,
    interval: Duration,
    last: Instant,
}

impl FrameSource for MacSession {
    fn next_frame(&mut self, _timeout: Duration) -> Result<Option<Frame>> {
        wait_until_due(self.last, self.interval);
        let request = self.request.clone();
        let frame = self.worker.call(move |state| state.capture(&request))?;
        self.last = Instant::now();
        Ok(Some(frame))
    }

    fn mode(&self) -> StreamMode {
        StreamMode::Surface {
            backend: "coregraphics".into(),
        }
    }
}

#[derive(Clone)]
struct MacDesktop {
    worker: Worker<MacState>,
}

pub fn open() -> Arc<Desktop> {
    let backend = Arc::new(MacDesktop {
        worker: Worker::spawn(MacState::new),
    });
    Arc::new(Desktop {
        capture: backend.clone(),
        hid: backend.clone(),
        a11y: backend,
    })
}

impl CaptureBackend for MacDesktop {
    fn backend_name(&self) -> &str {
        "coregraphics"
    }

    fn list_monitors(&self) -> Result<Vec<MonitorInfo>> {
        self.worker.call(|state| {
            state.refresh();
            Ok(state
                .displays
                .iter()
                .enumerate()
                .map(|(index, display)| MonitorInfo {
                    index: index as u32,
                    name: display.name.clone(),
                    x: display.x,
                    y: display.y,
                    width: display.width,
                    height: display.height,
                    primary: display.primary,
                })
                .collect())
        })
    }

    fn capture(&self, request: &CaptureRequest) -> Result<Frame> {
        let request = request.clone();
        self.worker.call(move |state| state.capture(&request))
    }

    fn open_session(&self, request: &CaptureRequest) -> Result<Box<dyn FrameSource>> {
        match super::sck::SckSession::open(request) {
            Ok(session) => Ok(Box::new(session)),
            Err(err) => {
                tracing::info!(error = %err, "ScreenCaptureKit unavailable; streaming with CoreGraphics");
                Ok(Box::new(MacSession {
                    worker: self.worker.clone(),
                    request: request.clone(),
                    interval: stream_interval(request.max_fps),
                    last: Instant::now()
                        .checked_sub(Duration::from_secs(1))
                        .unwrap_or_else(Instant::now),
                }))
            }
        }
    }
}

impl HidBackend for MacDesktop {
    fn backend_name(&self) -> &str {
        "cgevent"
    }

    fn inject(&self, action: &InputAction) -> Result<()> {
        let action = action.clone();
        self.worker.call(move |state| perform(state, &action))
    }
}

impl A11yBackend for MacDesktop {
    fn backend_name(&self) -> &str {
        "ax"
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

#[allow(dead_code)]
fn _ax_type(value: *const c_void) -> usize {
    unsafe { AXValueGetTypeID() ^ (value as usize) }
}
