//! In-process Apple VideoToolbox encoder. No B-frames
//! (`kVTCompressionPropertyKey_AllowFrameReordering = false`).
//!
//! A session that cannot emit a packet is not an encoder. Callers then use
//! minih264 (H.264) or ffmpeg. That includes a hardware unit that opens and
//! then fails, which is what a Mac VM without the paravirtual scaler does.

use std::os::raw::{c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::capture::Frame;

use super::encode::{
    annexb_keyframe, Codec, EncodedAccessUnit, EncoderInfo, EncoderRequest, VideoEncoder,
};

static ENCODE_FAILED: AtomicBool = AtomicBool::new(false);

/// False after a session opened and then produced no packet. ffmpeg's
/// `h264_videotoolbox` uses the same device and would fail the same way.
pub(super) fn device_can_encode() -> bool {
    !ENCODE_FAILED.load(Ordering::Acquire)
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
        ENCODE_FAILED.store(true, Ordering::Release);
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
        let mut out = vec![0u8; (self.width as usize * self.height as usize).max(64 * 1024)];
        let mut key = 0i32;
        let written = unsafe {
            al_vt_encode(
                self.raw,
                frame.pixels().as_ptr(),
                frame.stride as c_int,
                if force_keyframe { 1 } else { 0 },
                out.as_mut_ptr(),
                out.len() as c_int,
                &mut key,
            )
        };
        if written <= 0 {
            return Err(crate::error::msg(format!(
                "VideoToolbox encode failed ({written})"
            )));
        }
        out.truncate(written as usize);
        Ok(EncodedAccessUnit {
            codec: self.codec,
            keyframe: key != 0 || annexb_keyframe(&out),
            bytes: out,
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
        stride: c_int,
        force_key: c_int,
        dst: *mut u8,
        dst_cap: c_int,
        keyframe: *mut c_int,
    ) -> c_int;
    fn al_vt_set_bitrate(enc: *mut c_void, bitrate: c_int);
    fn al_vt_close(enc: *mut c_void);
}
