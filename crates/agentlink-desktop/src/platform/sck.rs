//! ScreenCaptureKit session. Frames arrive only when the display changes, so a
//! quiet desktop does not copy pixels. The OS cursor stays embedded until
//! macOS cursor metadata is wired end-to-end.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use screencapturekit::cm::CMSampleBufferExt;
use screencapturekit::cv::CVPixelBufferLockFlags;
use screencapturekit::prelude::*;

use crate::capture::{
    stream_interval, unix_ms, wait_until_due, CaptureRequest, CaptureTarget, Frame, FrameSource,
    StreamMode,
};
use crate::error::{msg, Result};

struct Slot {
    frame: Option<Frame>,
    seq: u64,
}

struct Handler {
    slot: Arc<(Mutex<Slot>, Condvar)>,
}

impl SCStreamOutputTrait for Handler {
    fn did_output_sample_buffer(&self, sample: CMSampleBuffer, output_type: SCStreamOutputType) {
        if !matches!(output_type, SCStreamOutputType::Screen) {
            return;
        }
        let Some(pixel) = sample.pixel_buffer() else {
            return;
        };
        let Ok(guard) = pixel.lock(CVPixelBufferLockFlags::READ_ONLY) else {
            return;
        };
        let Some(bytes) = (unsafe { guard.as_slice() }) else {
            return;
        };
        let width = guard.width() as u32;
        let height = guard.height() as u32;
        let stride = guard.bytes_per_row() as u32;
        let Ok(frame) = Frame::from_bgra(width, height, stride, bytes, "screencapturekit") else {
            return;
        };
        if let Ok(mut slot) = self.slot.0.lock() {
            slot.seq = slot.seq.wrapping_add(1);
            slot.frame = Some(frame);
            self.slot.1.notify_all();
        }
    }
}

pub struct SckSession {
    stream: SCStream,
    slot: Arc<(Mutex<Slot>, Condvar)>,
    seen: u64,
    interval: Duration,
    last: Instant,
}

impl SckSession {
    pub fn open(request: &CaptureRequest) -> Result<Self> {
        let content =
            SCShareableContent::get().map_err(|err| msg(format!("ScreenCaptureKit: {err}")))?;
        let displays = content.displays();
        let index = match request.target {
            CaptureTarget::Monitor(index) => index as usize,
            _ => 0,
        };
        let display = displays
            .get(index)
            .or_else(|| displays.first())
            .ok_or_else(|| msg("ScreenCaptureKit found no display"))?;
        let filter = SCContentFilter::create()
            .with_display(display)
            .with_excluding_windows(&[])
            .build()
            .map_err(|err| msg(format!("ScreenCaptureKit filter: {err}")))?;
        let width = display.width().max(2);
        let height = display.height().max(2);
        let fps = if request.max_fps <= 0.0 {
            30
        } else {
            request.max_fps.min(60.0) as u32
        };
        // Keep the OS cursor visible in SCK video frames until macOS cursor
        // metadata (position + shape + bitmap) is wired end-to-end.
        let config = SCStreamConfiguration::new()
            .with_width(width)
            .with_height(height)
            .with_pixel_format(PixelFormat::BGRA)
            .with_shows_cursor(true)
            .with_fps(fps.max(1));
        let slot = Arc::new((
            Mutex::new(Slot {
                frame: None,
                seq: 0,
            }),
            Condvar::new(),
        ));
        let handler = Handler { slot: slot.clone() };
        let mut stream = SCStream::new(&filter, &config)
            .map_err(|err| msg(format!("ScreenCaptureKit stream: {err}")))?;
        stream
            .add_output_handler(handler, SCStreamOutputType::Screen)
            .map_err(|err| msg(format!("ScreenCaptureKit output: {err}")))?;
        stream
            .start_capture()
            .map_err(|err| msg(format!("ScreenCaptureKit start: {err}")))?;
        Ok(Self {
            stream,
            slot,
            seen: 0,
            interval: stream_interval(request.max_fps),
            last: Instant::now()
                .checked_sub(Duration::from_secs(1))
                .unwrap_or_else(Instant::now),
        })
    }
}

impl FrameSource for SckSession {
    fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>> {
        wait_until_due(self.last, self.interval);
        let wait = timeout.max(Duration::from_millis(50));
        let deadline = Instant::now() + wait;
        let mut guard = self
            .slot
            .0
            .lock()
            .map_err(|_| msg("ScreenCaptureKit slot poisoned"))?;
        // Never emit a synthetic 2x2 placeholder frame before the first real SCK
        // callback arrives — wait up to `timeout` for a real frame instead.
        while guard.frame.is_none() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(msg("ScreenCaptureKit has not delivered a frame yet"));
            }
            let (next_guard, wait_res) = self
                .slot
                .1
                .wait_timeout(guard, remaining)
                .map_err(|_| msg("ScreenCaptureKit slot poisoned"))?;
            guard = next_guard;
            if wait_res.timed_out() && guard.frame.is_none() {
                return Err(msg("ScreenCaptureKit has not delivered a frame yet"));
            }
        }
        self.last = Instant::now();
        let frame = guard
            .frame
            .clone()
            .ok_or_else(|| msg("ScreenCaptureKit has not delivered a frame yet"))?;
        if guard.seq == self.seen {
            let mut quiet = frame;
            quiet.mark_unchanged();
            quiet.captured_unix_ms = unix_ms();
            return Ok(Some(quiet));
        }
        self.seen = guard.seq;
        Ok(Some(frame))
    }

    fn mode(&self) -> StreamMode {
        StreamMode::ScreenCaptureKit
    }
}

impl Drop for SckSession {
    fn drop(&mut self) {
        let _ = self.stream.stop_capture();
    }
}
