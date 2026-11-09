//! Screen capture types shared by one-shot screenshots and continuous sessions.
//!
//! # Audit recorders
//!
//! A `ScreenRecorder` in another crate should pull frames from a
//! [`FrameSource`] instead of opening its own platform handles. [`Frame`]
//! pixels are reference-counted: the backend copies out of the OS surface
//! once (DXGI staging texture, XShm, CoreGraphics, or a portal file) and
//! later consumers clone the [`Frame`] without copying pixels.
//!
//! ```ignore
//! let backend = agentlink_desktop::platform_capture()?;
//! let mut session = backend.open_session(&CaptureRequest {
//!     target: CaptureTarget::FullScreen,
//!     scale: 0.5,
//!     max_fps: 2.0,
//!     max_width: 0,
//! })?;
//! while let Some(frame) = session.next_frame(Duration::from_secs(2))? {
//!     recorder.on_frame(&frame);
//! }
//! ```
//!
//! `next_frame` may block, including for the whole frame interval, so call it
//! from a dedicated thread. `Ok(None)` means the session ended. A short
//! timeout does not end a low-fps session: pacing waits until the next frame
//! is due, and a static desktop repeats the last image when the OS has
//! nothing new.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{msg, Result};

/// Tightly packed 8-bit pixels. Capture normalizes to this before returning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PixelFormat {
    /// Byte order B, G, R, A. `stride == width * 4`.
    Bgra8,
}

/// One captured desktop image.
///
/// Cloning is cheap. [`Frame::pixels`] is an `Arc`.
#[derive(Debug, Clone)]
pub struct Frame {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: PixelFormat,
    pub pixels: Arc<[u8]>,
    pub captured_unix_ms: i64,
    /// Short backend id such as `x11-shm`, `dxgi`, `coregraphics`, `mock`.
    pub backend: String,
    /// Regions that differ from the previous frame. Empty when [`unchanged`](Self::unchanged).
    pub dirty: Vec<Rect>,
    /// The backend found no new pixels. [`pixels`](Self::pixels) may still be the last image.
    pub unchanged: bool,
}

impl Frame {
    pub fn pixels(&self) -> &[u8] {
        &self.pixels
    }

    /// Build a tightly packed BGRA frame, copying rows when `stride` is wider
    /// than `width * 4`.
    pub fn from_bgra(
        width: u32,
        height: u32,
        stride: u32,
        data: &[u8],
        backend: impl Into<String>,
    ) -> Result<Self> {
        if width == 0 || height == 0 {
            return Err(msg("capture is empty"));
        }
        let row = width as usize * 4;
        let stride = stride as usize;
        if stride < row {
            return Err(msg("capture stride is shorter than the row"));
        }
        let need = stride
            .checked_mul(height as usize)
            .ok_or_else(|| msg("capture dimensions overflow"))?;
        if data.len() < need {
            return Err(msg("capture buffer is shorter than width*height"));
        }
        let pixels = if stride == row {
            Arc::<[u8]>::from(data[..need].to_vec().into_boxed_slice())
        } else {
            let mut tight = vec![0u8; row * height as usize];
            for y in 0..height as usize {
                let src = y * stride;
                let dst = y * row;
                tight[dst..dst + row].copy_from_slice(&data[src..src + row]);
            }
            Arc::<[u8]>::from(tight.into_boxed_slice())
        };
        Ok(Self {
            width,
            height,
            stride: row as u32,
            format: PixelFormat::Bgra8,
            pixels,
            captured_unix_ms: unix_ms(),
            backend: backend.into(),
            dirty: vec![Rect {
                x: 0,
                y: 0,
                width,
                height,
            }],
            unchanged: false,
        })
    }

    /// Like [`from_bgra`], but takes ownership of `data` when `stride == width * 4`
    /// so the capture path does not pay a second full-frame copy.
    pub fn from_bgra_owned(
        width: u32,
        height: u32,
        stride: u32,
        mut data: Vec<u8>,
        backend: impl Into<String>,
    ) -> Result<Self> {
        if width == 0 || height == 0 {
            return Err(msg("capture is empty"));
        }
        let row = width as usize * 4;
        let stride_usize = stride as usize;
        if stride_usize < row {
            return Err(msg("capture stride is shorter than the row"));
        }
        let need = stride_usize
            .checked_mul(height as usize)
            .ok_or_else(|| msg("capture dimensions overflow"))?;
        if data.len() < need {
            return Err(msg("capture buffer is shorter than width*height"));
        }
        if stride_usize == row {
            data.truncate(need);
            let pixels: Arc<[u8]> = Arc::from(data);
            return Ok(Self {
                width,
                height,
                stride: row as u32,
                format: PixelFormat::Bgra8,
                pixels,
                captured_unix_ms: unix_ms(),
                backend: backend.into(),
                dirty: vec![Rect {
                    x: 0,
                    y: 0,
                    width,
                    height,
                }],
                unchanged: false,
            });
        }
        Self::from_bgra(width, height, stride, &data, backend)
    }

    pub fn mark_unchanged(&mut self) {
        self.unchanged = true;
        self.dirty.clear();
    }
}

/// Rectangle in desktop pixels. Origin is the top-left of the virtual screen
/// unless a backend documents a different space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// What to capture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureTarget {
    /// Every monitor, as one virtual desktop.
    FullScreen,
    /// Monitor index from [`CaptureBackend::list_monitors`].
    Monitor(u32),
    /// Sub-rectangle of the virtual desktop.
    Region(Rect),
    /// Window id or, when the backend supports it, a title substring.
    Window(String),
}

/// One-shot and session parameters.
///
/// `scale` is applied after the grab (`1.0` keeps the native size, `0.5`
/// halves each axis). Values above 1 are rejected by the handlers; the
/// capture API itself trusts the caller. `max_fps` paces [`FrameSource`]
/// only. `0.0` means "as fast as the backend can produce a frame".
///
/// `max_width` is a capture-side width cap for PipeWire/Mutter (0 = full
/// ScreenCast resolution). Streaming sets this to the encode width so ffmpeg
/// does not CPU-scale a 20 MB BGRA frame; screenshots leave it at 0.
#[derive(Debug, Clone)]
pub struct CaptureRequest {
    pub target: CaptureTarget,
    pub scale: f32,
    pub max_fps: f32,
    pub max_width: u32,
}

impl Default for CaptureRequest {
    fn default() -> Self {
        Self {
            target: CaptureTarget::FullScreen,
            scale: 1.0,
            max_fps: 2.0,
            max_width: 0,
        }
    }
}

/// A connected display.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MonitorInfo {
    pub index: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub primary: bool,
}

/// How a session produces frames. Recorders can read this and ignore it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamMode {
    /// One copy out of DXGI, XShm, or CoreGraphics.
    Surface { backend: String },
    /// Portal screenshot repeated at `max_fps`.
    ///
    /// `pipewire_node` is set when a ScreenCast session reported a PipeWire
    /// node and this build did not map that buffer. The frames are still
    /// real pixels; they are just not dma-buf imports.
    PortalSampled { pipewire_node: Option<u32> },
    /// PipeWire ScreenCast. `dma_buf` is true when the latest buffer was a dma-buf
    /// that PipeWire mapped for us. The encoder still receives a BGRA copy.
    PipeWire { node: u32, dma_buf: bool },
    /// macOS ScreenCaptureKit. One-shot screenshots stay on CoreGraphics.
    ScreenCaptureKit,
}

/// Pointer position for the cursor overlay channel. The video itself does not
/// burn the cursor in.
///
/// Wire shape is `{x,y,shape?,visible?}`. `visible` is attached by the stream
/// layer (see [`CaptureBackend::cursor_visible`]) so older backend constructors
/// that only fill `x`/`y`/`shape` keep compiling. Clients that do not know
/// `shape`/`visible` still work from coordinates alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorSample {
    pub x: i32,
    pub y: i32,
    pub shape: String,
}

/// Whether the desktop is currently capturable (for example not on a Windows
/// secure desktop). Missing on the wire means "assume yes" for old nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturableState {
    pub capturable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Default for CapturableState {
    fn default() -> Self {
        Self {
            capturable: true,
            reason: None,
        }
    }
}

/// Continuous capture. One session is not `Sync`; own it on the recorder thread.
///
/// `next_frame` waits until `max_fps` allows another frame, then copies one
/// image. That wait is not capped by `timeout`, so a 1 fps audit recorder
/// does not look closed when the caller passes a shorter timeout. `timeout`
/// bounds the platform grab after the frame is due. `Ok(None)` means the
/// session ended. `Err` means the grab failed.
pub trait FrameSource: Send {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>>;
    fn mode(&self) -> StreamMode;
}

/// Platform or mock capture.
///
/// Implementations copy out of the OS mapping once per frame and return a
/// [`Frame`]. They do not encode JPEG/PNG; the screenshot handler does that.
pub trait CaptureBackend: Send + Sync {
    fn backend_name(&self) -> &str;
    fn list_monitors(&self) -> Result<Vec<MonitorInfo>>;
    fn capture(&self, request: &CaptureRequest) -> Result<Frame>;
    fn open_session(&self, request: &CaptureRequest) -> Result<Box<dyn FrameSource>>;

    /// Current pointer, when the backend can read it without a grab.
    fn cursor(&self) -> Option<CursorSample> {
        None
    }

    /// Whether the OS cursor is currently drawn. Defaults to visible.
    fn cursor_visible(&self) -> bool {
        true
    }

    /// Whether the screen can be captured right now (secure desktop, etc.).
    fn capturable_state(&self) -> CapturableState {
        CapturableState::default()
    }
}

/// Pull frames until `stop` is set or the session ends.
///
/// The closure is the recorder hook. A `ScreenRecorder::on_frame` adapter is
/// a one-line wrapper around it. Returns how many frames were delivered.
pub fn drive_frames(
    source: &mut dyn FrameSource,
    stop: &AtomicBool,
    mut record: impl FnMut(&Frame) -> Result<()>,
) -> Result<u64> {
    let mut count = 0u64;
    while !stop.load(Ordering::Relaxed) {
        match source.next_frame(Duration::from_secs(2))? {
            Some(frame) => {
                record(&frame)?;
                count += 1;
            }
            None => break,
        }
    }
    Ok(count)
}

/// Sleep until the next paced frame is due. The capture timeout does not
/// shorten this wait: ending the session early would break a low-fps recorder.
pub(crate) fn wait_until_due(last: std::time::Instant, interval: Duration) {
    let due = interval.saturating_sub(last.elapsed());
    if !due.is_zero() {
        std::thread::sleep(due);
    }
}

pub fn frame_interval(max_fps: f32) -> Duration {
    paced_interval(max_fps, 30.0)
}

/// Stream pacing. Audit recorders keep [`frame_interval`]'s 30 fps cap.
/// A remote desktop session may run up to 60.
pub fn stream_interval(max_fps: f32) -> Duration {
    paced_interval(max_fps, 60.0)
}

fn paced_interval(max_fps: f32, cap: f32) -> Duration {
    if !max_fps.is_finite() || max_fps <= 0.0 {
        Duration::ZERO
    } else {
        let fps = max_fps.min(cap);
        Duration::from_secs_f32(1.0 / fps)
    }
}

pub fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Reject grabs that would allocate a multi-hundred-megabyte buffer.
pub fn check_pixels(width: u32, height: u32) -> Result<()> {
    let pixels = (width as u64).saturating_mul(height as u64);
    if width == 0 || height == 0 {
        return Err(msg("capture width and height must be non-zero"));
    }
    if pixels > 20_000_000 {
        return Err(msg(format!(
            "capture is {width}x{height} ({pixels} pixels); the limit is 20000000. Use a monitor, a region, or scale"
        )));
    }
    Ok(())
}

/// Last `scale_frame` wall time in microseconds (0 when scale was a no-op).
/// The stream pump reads this to split capture vs convert without platform edits.
pub(crate) fn last_scale_us() -> u64 {
    LAST_SCALE_US.load(Ordering::Relaxed)
}

static LAST_SCALE_US: AtomicU64 = AtomicU64::new(0);

pub(crate) fn scale_frame(frame: Frame, scale: f32) -> Result<Frame> {
    if !scale.is_finite() || scale <= 0.0 {
        return Err(msg("scale must be a positive finite number"));
    }
    if (scale - 1.0).abs() < 0.01 {
        LAST_SCALE_US.store(0, Ordering::Relaxed);
        return Ok(frame);
    }
    let width = ((frame.width as f32) * scale).round().max(1.0) as u32;
    let height = ((frame.height as f32) * scale).round().max(1.0) as u32;
    check_pixels(width, height)?;
    let started = Instant::now();
    // Direct BGRA box/nearest downscale. The old path did BGRA→RGBA→image
    // Triangle→RGBA→BGRA (~3 full-frame copies + expensive filter) and was the
    // dominant CPU cost on Retina panels even when VAAPI encode was cheap.
    let bgra = if scale <= 0.4 {
        scale_bgra_nearest(frame.pixels(), frame.width, frame.height, frame.stride, width, height)
    } else {
        scale_bgra_box(frame.pixels(), frame.width, frame.height, frame.stride, width, height)
    };
    LAST_SCALE_US.store(started.elapsed().as_micros() as u64, Ordering::Relaxed);
    Frame::from_bgra(width, height, width * 4, &bgra, frame.backend)
}

fn scale_bgra_nearest(
    src: &[u8],
    src_w: u32,
    src_h: u32,
    src_stride: u32,
    dst_w: u32,
    dst_h: u32,
) -> Vec<u8> {
    let mut out = vec![0u8; dst_w as usize * dst_h as usize * 4];
    let x_ratio = src_w as f32 / dst_w as f32;
    let y_ratio = src_h as f32 / dst_h as f32;
    let stride = src_stride as usize;
    for y in 0..dst_h as usize {
        let sy = ((y as f32 + 0.5) * y_ratio).floor() as usize;
        let sy = sy.min(src_h.saturating_sub(1) as usize);
        let src_row = sy * stride;
        let dst_row = y * dst_w as usize * 4;
        for x in 0..dst_w as usize {
            let sx = ((x as f32 + 0.5) * x_ratio).floor() as usize;
            let sx = sx.min(src_w.saturating_sub(1) as usize);
            let si = src_row + sx * 4;
            let di = dst_row + x * 4;
            if si + 4 <= src.len() {
                out[di..di + 4].copy_from_slice(&src[si..si + 4]);
            }
        }
    }
    out
}

/// Area-average (box) downscale in BGRA. Good enough for desktop encode and
/// much cheaper than Triangle through the `image` crate.
fn scale_bgra_box(
    src: &[u8],
    src_w: u32,
    src_h: u32,
    src_stride: u32,
    dst_w: u32,
    dst_h: u32,
) -> Vec<u8> {
    let mut out = vec![0u8; dst_w as usize * dst_h as usize * 4];
    let stride = src_stride as usize;
    for y in 0..dst_h {
        let y0 = (y as u64 * src_h as u64 / dst_h as u64) as u32;
        let y1 = (((y as u64 + 1) * src_h as u64 / dst_h as u64) as u32).max(y0 + 1);
        let y1 = y1.min(src_h);
        for x in 0..dst_w {
            let x0 = (x as u64 * src_w as u64 / dst_w as u64) as u32;
            let x1 = (((x as u64 + 1) * src_w as u64 / dst_w as u64) as u32).max(x0 + 1);
            let x1 = x1.min(src_w);
            let mut b = 0u32;
            let mut g = 0u32;
            let mut r = 0u32;
            let mut a = 0u32;
            let mut n = 0u32;
            for sy in y0..y1 {
                let row = sy as usize * stride;
                for sx in x0..x1 {
                    let i = row + sx as usize * 4;
                    if i + 4 > src.len() {
                        continue;
                    }
                    b += src[i] as u32;
                    g += src[i + 1] as u32;
                    r += src[i + 2] as u32;
                    a += src[i + 3] as u32;
                    n += 1;
                }
            }
            let di = (y as usize * dst_w as usize + x as usize) * 4;
            if n > 0 {
                out[di] = (b / n) as u8;
                out[di + 1] = (g / n) as u8;
                out[di + 2] = (r / n) as u8;
                out[di + 3] = (a / n) as u8;
            }
        }
    }
    out
}

/// Crop is used by the Wayland portal path and the macOS region path.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
pub(crate) fn crop_frame(frame: &Frame, rect: Rect) -> Result<Frame> {
    if rect.width == 0 || rect.height == 0 {
        return Err(msg("crop rectangle is empty"));
    }
    if rect.x < 0 || rect.y < 0 {
        return Err(msg("crop rectangle starts outside the frame"));
    }
    let x = rect.x as u32;
    let y = rect.y as u32;
    if x.saturating_add(rect.width) > frame.width || y.saturating_add(rect.height) > frame.height {
        return Err(msg(format!(
            "crop {}x{} at {},{} is outside {}x{}",
            rect.width, rect.height, rect.x, rect.y, frame.width, frame.height
        )));
    }
    let mut out = vec![0u8; rect.width as usize * rect.height as usize * 4];
    let src_stride = frame.stride as usize;
    let row = rect.width as usize * 4;
    for row_index in 0..rect.height as usize {
        let src = (y as usize + row_index) * src_stride + x as usize * 4;
        let dst = row_index * row;
        out[dst..dst + row].copy_from_slice(&frame.pixels[src..src + row]);
    }
    Frame::from_bgra(
        rect.width,
        rect.height,
        row as u32,
        &out,
        frame.backend.clone(),
    )
}

pub(crate) fn bgra_to_rgba(bgra: &[u8], width: u32, height: u32) -> Vec<u8> {
    let mut rgba = vec![0u8; width as usize * height as usize * 4];
    for (src, dst) in bgra.chunks_exact(4).zip(rgba.chunks_exact_mut(4)) {
        dst[0] = src[2];
        dst[1] = src[1];
        dst[2] = src[0];
        dst[3] = src[3];
    }
    rgba
}

pub(crate) fn rgba_to_bgra(rgba: &[u8]) -> Vec<u8> {
    let mut bgra = vec![0u8; rgba.len()];
    for (src, dst) in rgba.chunks_exact(4).zip(bgra.chunks_exact_mut(4)) {
        dst[0] = src[2];
        dst[1] = src[1];
        dst[2] = src[0];
        dst[3] = src[3];
    }
    bgra
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_halves_each_axis() {
        let mut raw = vec![0u8; 8 * 4 * 4];
        for (i, pixel) in raw.chunks_exact_mut(4).enumerate() {
            pixel[0] = i as u8;
            pixel[1] = 10;
            pixel[2] = 20;
            pixel[3] = 255;
        }
        let frame = Frame::from_bgra(8, 4, 32, &raw, "test").unwrap();
        let scaled = scale_frame(frame, 0.5).unwrap();
        assert_eq!((scaled.width, scaled.height), (4, 2));
        assert_eq!(scaled.stride, 16);
        assert_eq!(scaled.pixels.len(), 4 * 2 * 4);
    }

    #[test]
    fn coarse_preview_scale_uses_nearest_path() {
        // scale <= 0.4 takes the Nearest branch used by the viewer JPEG preview.
        let raw = vec![255u8; 8 * 4 * 4];
        let frame = Frame::from_bgra(8, 4, 32, &raw, "test").unwrap();
        let scaled = scale_frame(frame, 0.25).unwrap();
        assert_eq!((scaled.width, scaled.height), (2, 1));
        assert_eq!(scaled.stride, 8);
        assert_eq!(scaled.pixels.len(), 2 * 1 * 4);
    }

    #[test]
    fn drive_frames_stops_when_asked() {
        struct Src {
            left: u32,
        }
        impl FrameSource for Src {
            fn next_frame(&mut self, _: Duration) -> Result<Option<Frame>> {
                if self.left == 0 {
                    return Ok(None);
                }
                self.left -= 1;
                let raw = [1u8, 2, 3, 255];
                Ok(Some(Frame::from_bgra(1, 1, 4, &raw, "test")?))
            }
            fn mode(&self) -> StreamMode {
                StreamMode::Surface {
                    backend: "test".into(),
                }
            }
        }
        let stop = AtomicBool::new(false);
        let mut n = 0;
        let delivered = drive_frames(&mut Src { left: 10 }, &stop, |_| {
            n += 1;
            if n == 3 {
                stop.store(true, Ordering::Relaxed);
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(delivered, 3);
    }
}
