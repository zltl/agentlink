//! In-process Apple VideoToolbox encoder. No B-frames
//! (`kVTCompressionPropertyKey_AllowFrameReordering = false`).
//!
//! A session that cannot emit a packet is not an encoder. Callers then use
//! minih264 (H.264) or ffmpeg. That includes a hardware unit that opens and
//! then fails, which is what a Mac VM without the paravirtual scaler does.

use std::os::raw::{c_int, c_void};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::capture::{prepare_frame_for_encoder, Frame};

use super::encode::{
    annexb_keyframe, Codec, EncodedAccessUnit, EncoderInfo, EncoderRequest, VideoEncoder,
};

const VT_RETRY_COOLDOWN: Duration = Duration::from_secs(60);
static ENCODE_COOLDOWN_UNTIL: Mutex<Option<Instant>> = Mutex::new(None);

/// False while in cooldown after a session opened and produced no packet.
/// Unlike a permanent poison pill, retries after [`VT_RETRY_COOLDOWN`].
pub(super) fn device_can_encode() -> bool {
    let guard = ENCODE_COOLDOWN_UNTIL
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    !guard.is_some_and(|until| Instant::now() < until)
}

fn mark_encode_failed() {
    let mut guard = ENCODE_COOLDOWN_UNTIL
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    *guard = Some(Instant::now() + VT_RETRY_COOLDOWN);
}

pub fn try_open(request: &EncoderRequest) -> Option<Box<dyn VideoEncoder>> {
    if (request.codec != Codec::H264 && request.codec != Codec::H265) || !device_can_encode() {
        return None;
    }
    let mut encoder = VideoToolbox::open(request).ok()?;
    let pixels = vec![0u8; (encoder.width as usize) * (encoder.height as usize) * 4];
    let probe = Frame::from_bgra(
        encoder.width,
        encoder.height,
        encoder.width * 4,
        &pixels,
        "videotoolbox",
    )
    .ok()?;
    if let Err(err) = encoder.encode(&probe, true) {
        mark_encode_failed();
        tracing::debug!("VideoToolbox produced no packet ({err}); using another encoder");
        return None;
    }
    Some(Box::new(encoder))
}

struct VideoToolbox {
    raw: *mut c_void,
    width: u32,
    height: u32,
    codec: Codec,
    name: &'static str,
    out: Vec<u8>,
}

unsafe impl Send for VideoToolbox {}

impl VideoToolbox {
    fn open(request: &EncoderRequest) -> Result<Self, String> {
        let width = request.width.div_ceil(2) * 2;
        let height = request.height.div_ceil(2) * 2;
        let hevc = if request.codec == Codec::H265 { 1 } else { 0 };
        let mut raw = std::ptr::null_mut();
        let rc = unsafe {
            al_vt_open(
                width as c_int,
                height as c_int,
                request.fps.clamp(1, 60) as c_int,
                request.bitrate.max(100_000) as c_int,
                hevc,
                &mut raw,
            )
        };
        if rc != 0 || raw.is_null() {
            return Err(format!("VideoToolbox session failed ({rc})"));
        }
        let out_cap = (width as usize)
            .saturating_mul(height as usize)
            .clamp(64 * 1024, 16 * 1024 * 1024);
        Ok(Self {
            raw,
            width,
            height,
            codec: if hevc == 1 { Codec::H265 } else { Codec::H264 },
            name: if hevc == 1 {
                "videotoolbox-hevc"
            } else {
                "videotoolbox-h264"
            },
            out: vec![0u8; out_cap],
        })
    }
}

impl Drop for VideoToolbox {
    fn drop(&mut self) {
        unsafe { al_vt_close(self.raw) };
    }
}

impl VideoEncoder for VideoToolbox {
    fn info(&self) -> EncoderInfo {
        EncoderInfo {
            name: self.name.into(),
            codec: self.codec,
            hardware: true,
        }
    }

    fn encode(
        &mut self,
        frame: &Frame,
        force_keyframe: bool,
    ) -> crate::error::Result<EncodedAccessUnit> {
        let prepared = prepare_frame_for_encoder(frame, self.width, self.height)?;
        let src = prepared.as_ref();
        let src_w = src.width as usize;
        let src_h = src.height as usize;
        let src_stride = src.stride as usize;
        let min_bytes = src_h
            .saturating_sub(1)
            .saturating_mul(src_stride)
            .saturating_add(src_w.saturating_mul(4));
        if src_w == 0 || src_h == 0 || src_stride < src_w * 4 || src.pixels().len() < min_bytes {
            return Err(crate::error::msg("VideoToolbox input frame buffer too small"));
        }
        let mut key = 0i32;
        let mut written = unsafe {
            al_vt_encode(
                self.raw,
                src.pixels().as_ptr(),
                src.width as c_int,
                src.height as c_int,
                src.stride as c_int,
                if force_keyframe { 1 } else { 0 },
                self.out.as_mut_ptr(),
                self.out.len() as c_int,
                &mut key,
            )
        };
        if written == -4 && self.out.len() < 32 * 1024 * 1024 {
            self.out.resize(self.out.len().saturating_mul(2), 0);
            written = unsafe {
                al_vt_encode(
                    self.raw,
                    src.pixels().as_ptr(),
                    src.width as c_int,
                    src.height as c_int,
                    src.stride as c_int,
                    1,
                    self.out.as_mut_ptr(),
                    self.out.len() as c_int,
                    &mut key,
                )
            };
        }
        if written <= 0 {
            return Err(crate::error::msg(format!(
                "VideoToolbox encode failed ({written})"
            )));
        }
        let bytes = self.out[..written as usize].to_vec();
        Ok(EncodedAccessUnit {
            codec: self.codec,
            keyframe: key != 0 || annexb_keyframe(&bytes),
            bytes,
            width: self.width,
            height: self.height,
            captured_unix_ms: frame.captured_unix_ms,
        })
    }

    fn set_bitrate(&mut self, bitrate: u32) {
        unsafe { al_vt_set_bitrate(self.raw, bitrate.max(100_000) as c_int) };
    }
}

extern "C" {
    fn al_vt_open(
        width: c_int,
        height: c_int,
        fps: c_int,
        bitrate: c_int,
        hevc: c_int,
        out: *mut *mut c_void,
    ) -> c_int;
    fn al_vt_encode(
        enc: *mut c_void,
        bgra: *const u8,
        src_w: c_int,
        src_h: c_int,
        src_stride: c_int,
        force_key: c_int,
        dst: *mut u8,
        dst_cap: c_int,
        keyframe: *mut c_int,
    ) -> c_int;
    fn al_vt_set_bitrate(enc: *mut c_void, bitrate: c_int);
    fn al_vt_close(enc: *mut c_void);
}
