//! PipeWire ScreenCast consumer. Built only when libpipewire-0.3 headers
//! were found. The portal fd is passed in; this module does not open a portal.
//!
//! Optional capture-side downsample (`set_target_width` / env
//! `AGENTLINK_CAPTURE_MAX_WIDTH`) shrinks BGRA before it reaches Rust so the
//! full-resolution ScreenCast never enters the encode path. Cursor overlays
//! must use [`coord_scale`] (out/src) so stream-pixel positions map onto the
//! downsampled frame.

use std::os::fd::OwnedFd;
use std::os::raw::{c_int, c_void};
use std::os::unix::io::IntoRawFd;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::capture::Frame;
use crate::error::{msg, Result};

/// Last successful take: src/out widths for cursor mapping.
static LAST_SRC_W: AtomicU32 = AtomicU32::new(0);
static LAST_OUT_W: AtomicU32 = AtomicU32::new(0);

/// `(out, src)` width pair. Cursor stream-pixel coords → frame pixels: `x * out / src`.
/// When downsample is off both sides match and the factor is 1.
pub fn coord_scale() -> (u32, u32) {
    let src = LAST_SRC_W.load(Ordering::Relaxed);
    let out = LAST_OUT_W.load(Ordering::Relaxed);
    if src == 0 || out == 0 {
        return (1, 1);
    }
    (out, src)
}

fn remember_geometry(src_w: u32, out_w: u32) {
    if src_w > 0 {
        LAST_SRC_W.store(src_w, Ordering::Relaxed);
    }
    if out_w > 0 {
        LAST_OUT_W.store(out_w, Ordering::Relaxed);
    }
}

/// Resolve the capture-side max width for a one-shot request.
///
/// - `AGENTLINK_CAPTURE_DOWNSAMPLE=0` → off (full resolution)
/// - explicit `requested > 0` wins (stream encode size)
/// - `requested == 0` → full res unless `AGENTLINK_CAPTURE_MAX_WIDTH=N` forces a cap
///   (screenshots pass 0 so CLI behavior stays full-resolution by default)
pub fn resolve_target_width(requested: u32) -> u32 {
    if std::env::var("AGENTLINK_CAPTURE_DOWNSAMPLE")
        .ok()
        .as_deref()
        == Some("0")
    {
        return 0;
    }
    if requested > 0 {
        return requested;
    }
    match std::env::var("AGENTLINK_CAPTURE_MAX_WIDTH") {
        Ok(value) if value == "0" || value.is_empty() => 0,
        Ok(value) => value.parse::<u32>().unwrap_or(0),
        Err(_) => 0,
    }
}

/// Stream-path default max width when the session wants downsample on.
pub fn default_stream_max_width() -> u32 {
    if std::env::var("AGENTLINK_CAPTURE_DOWNSAMPLE")
        .ok()
        .as_deref()
        == Some("0")
    {
        return 0;
    }
    match std::env::var("AGENTLINK_CAPTURE_MAX_WIDTH") {
        Ok(value) if value == "0" => 0,
        Ok(value) => value.parse::<u32>().unwrap_or(1600),
        Err(_) => 1600,
    }
}

pub struct PwCapture {
    raw: *mut c_void,
}

unsafe impl Send for PwCapture {}

impl PwCapture {
    pub fn open(fd: OwnedFd, node_id: u32) -> Result<Self> {
        let raw = unsafe { al_pw_open(fd.into_raw_fd(), node_id) };
        if raw.is_null() {
            return Err(msg("PipeWire stream did not connect"));
        }
        Ok(Self { raw })
    }

    /// Connect to the user's default PipeWire daemon. Mutter's ScreenCast nodes
    /// are exported there; there is no portal fd to consume.
    pub fn open_default(node_id: u32) -> Result<Self> {
        let raw = unsafe { al_pw_open(-1, node_id) };
        if raw.is_null() {
            return Err(msg("PipeWire stream did not connect to the default daemon"));
        }
        Ok(Self { raw })
    }

    /// Cap output width (0 = full ScreenCast resolution).
    pub fn set_target_width(&mut self, target_width: u32) {
        unsafe { al_pw_set_target_width(self.raw, target_width as c_int) };
    }

    pub fn geometry(&self) -> (u32, u32, u32, u32) {
        let mut src_w = 0i32;
        let mut src_h = 0i32;
        let mut out_w = 0i32;
        let mut out_h = 0i32;
        unsafe {
            al_pw_geometry(
                self.raw,
                &mut src_w,
                &mut src_h,
                &mut out_w,
                &mut out_h,
            );
        }
        (
            src_w.max(0) as u32,
            src_h.max(0) as u32,
            out_w.max(0) as u32,
            out_h.max(0) as u32,
        )
    }

    /// VideoCrop on the last captured source buffer, in source pixels.
    /// `None` when the producer omitted crop metadata.
    pub fn videocrop(&self) -> Option<crate::capture::Rect> {
        let mut x = 0i32;
        let mut y = 0i32;
        let mut w = 0i32;
        let mut h = 0i32;
        let ok = unsafe { al_pw_videocrop(self.raw, &mut x, &mut y, &mut w, &mut h) };
        if ok != 0 && w > 0 && h > 0 && x >= 0 && y >= 0 {
            Some(crate::capture::Rect {
                x,
                y,
                width: w as u32,
                height: h as u32,
            })
        } else {
            None
        }
    }

    /// Latest `SPA_META_Cursor` without waiting on [`Self::take`].
    ///
    /// Independent of the encode loop so the cursor data channel can update
    /// while video is idle. `None` until the producer has attached cursor meta.
    pub fn cursor_sample(&self) -> Option<crate::capture::CursorSample> {
        let mut x = 0i32;
        let mut y = 0i32;
        let mut hx = 0i32;
        let mut hy = 0i32;
        let mut visible = 0i32;
        let mut bw = 0i32;
        let mut bh = 0i32;
        let mut has_bm = 0i32;
        let mut rgba = vec![0u8; (crate::MAX_CURSOR_BITMAP_EDGE as usize).pow(2) * 4];
        let rc = unsafe {
            al_pw_cursor(
                self.raw,
                &mut x,
                &mut y,
                &mut hx,
                &mut hy,
                &mut visible,
                &mut bw,
                &mut bh,
                &mut has_bm,
                rgba.as_mut_ptr(),
                rgba.len() as c_int,
            )
        };
        if rc != 1 {
            return None;
        }
        let _ = visible; // exposed via cursor_visible(); sample carries shape.
        let (bitmap_rgba, bitmap_w, bitmap_h, shape) = if has_bm != 0
            && bw > 0
            && bh > 0
            && crate::bitmap_within_bound(bw as u32, bh as u32)
        {
            let need = (bw as usize) * (bh as usize) * 4;
            rgba.truncate(need);
            (Some(rgba), bw as u32, bh as u32, "custom".to_string())
        } else {
            (None, 0, 0, "unknown".to_string())
        };
        Some(crate::capture::CursorSample {
            x,
            y,
            shape,
            hotspot_x: hx.max(0).min(u16::MAX as i32) as u16,
            hotspot_y: hy.max(0).min(u16::MAX as i32) as u16,
            bitmap_rgba,
            bitmap_w,
            bitmap_h,
        })
    }

    /// OS pointer visibility from the last cursor meta (`None` = no meta yet).
    pub fn cursor_visible(&self) -> Option<bool> {
        let mut x = 0i32;
        let mut y = 0i32;
        let mut hx = 0i32;
        let mut hy = 0i32;
        let mut visible = 0i32;
        let mut bw = 0i32;
        let mut bh = 0i32;
        let mut has_bm = 0i32;
        let rc = unsafe {
            al_pw_cursor(
                self.raw,
                &mut x,
                &mut y,
                &mut hx,
                &mut hy,
                &mut visible,
                &mut bw,
                &mut bh,
                &mut has_bm,
                std::ptr::null_mut(),
                0,
            )
        };
        if rc != 1 {
            return None;
        }
        Some(visible != 0)
    }

    pub fn take(&mut self, wait_ms: i32) -> Result<Option<(Frame, bool)>> {
        let mut width = 0i32;
        let mut height = 0i32;
        let mut stride = 0i32;
        let mut dma = 0i32;
        // Post-downsample frames are typically ≤1600×~1100 (~7 MB); grow on -2.
        let mut cap = 4 * 1024 * 1024;
        let mut dst = vec![0u8; cap];
        let rc = unsafe {
            al_pw_take(
                self.raw,
                dst.as_mut_ptr(),
                cap as c_int,
                &mut width,
                &mut height,
                &mut stride,
                &mut dma,
                wait_ms,
            )
        };
        if rc == -2 {
            let row = stride.max(width * 4).max(1) as usize;
            cap = row
                .checked_mul(height.max(1) as usize)
                .ok_or_else(|| msg("PipeWire frame dimensions overflow"))?;
            dst.resize(cap, 0);
            let rc = unsafe {
                al_pw_take(
                    self.raw,
                    dst.as_mut_ptr(),
                    dst.len() as c_int,
                    &mut width,
                    &mut height,
                    &mut stride,
                    &mut dma,
                    wait_ms,
                )
            };
            if rc == 1 {
                return finish_frame(self, width, height, stride, dma, dst);
            }
            if rc == 0 {
                return Ok(None);
            }
            return Err(msg(format!("PipeWire capture failed ({rc})")));
        }
        if rc == 0 {
            return Ok(None);
        }
        if rc < 0 {
            return Err(msg(format!("PipeWire capture failed ({rc})")));
        }
        finish_frame(self, width, height, stride, dma, dst)
    }
}

fn finish_frame(
    cap: &PwCapture,
    width: i32,
    height: i32,
    stride: i32,
    dma: i32,
    dst: Vec<u8>,
) -> Result<Option<(Frame, bool)>> {
    if width <= 0 || height <= 0 || stride <= 0 {
        return Ok(None);
    }
    let (src_w, _src_h, out_w, _out_h) = cap.geometry();
    remember_geometry(src_w, if out_w > 0 { out_w } else { width as u32 });
    // Take ownership of `dst` — no second full-frame copy into Frame.
    let frame = Frame::from_bgra_owned(width as u32, height as u32, stride as u32, dst, "pipewire")?;
    Ok(Some((frame, dma != 0)))
}

impl Drop for PwCapture {
    fn drop(&mut self) {
        unsafe { al_pw_close(self.raw) };
    }
}

extern "C" {
    fn al_pw_open(fd: c_int, node_id: u32) -> *mut c_void;
    fn al_pw_set_target_width(cap: *mut c_void, target_width: c_int);
    fn al_pw_videocrop(
        cap: *mut c_void,
        x: *mut c_int,
        y: *mut c_int,
        w: *mut c_int,
        h: *mut c_int,
    ) -> c_int;
    fn al_pw_cursor(
        cap: *mut c_void,
        x: *mut c_int,
        y: *mut c_int,
        hotspot_x: *mut c_int,
        hotspot_y: *mut c_int,
        visible: *mut c_int,
        width: *mut c_int,
        height: *mut c_int,
        has_bitmap: *mut c_int,
        rgba_out: *mut u8,
        rgba_cap: c_int,
    ) -> c_int;
    fn al_pw_geometry(
        cap: *mut c_void,
        src_width: *mut c_int,
        src_height: *mut c_int,
        out_width: *mut c_int,
        out_height: *mut c_int,
    );
    fn al_pw_take(
        cap: *mut c_void,
        dst: *mut u8,
        dst_cap: c_int,
        width: *mut c_int,
        height: *mut c_int,
        stride: *mut c_int,
        dma_buf: *mut c_int,
        wait_ms: c_int,
    ) -> c_int;
    fn al_pw_close(cap: *mut c_void);
}
