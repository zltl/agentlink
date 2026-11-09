//! Video encoders. Hardware is preferred. The in-process fallback is minih264
//! (public domain, baseline, no B-frames, fastest speed). ffmpeg is used when
//! it is installed and advertises NVENC, QSV, AMF, VAAPI, VideoToolbox, x264,
//! or libvpx.

use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use crate::capture::Frame;
use crate::error::{msg, Result};

use super::ffmpeg::FfmpegEncoder;

/// After one hardware/ffmpeg encode failure, skip reopening it for later sessions.
static HARDWARE_ENCODER_UNUSABLE: AtomicBool = AtomicBool::new(false);

fn hardware_encoder_unusable() -> bool {
    HARDWARE_ENCODER_UNUSABLE.load(Ordering::Relaxed)
}

fn mark_hardware_encoder_unusable() {
    HARDWARE_ENCODER_UNUSABLE.store(true, Ordering::Relaxed);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Codec {
    H264,
    H265,
    Av1,
    Vp9,
}

impl Codec {
    pub fn parse(text: &str) -> Self {
        match text.trim().to_ascii_lowercase().as_str() {
            "h265" | "hevc" | "h.265" => Self::H265,
            "av1" => Self::Av1,
            "vp9" | "vp8" => Self::Vp9,
            _ => Self::H264,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::H265 => "h265",
            Self::Av1 => "av1",
            Self::Vp9 => "vp9",
        }
    }

    pub fn mime(self) -> &'static str {
        match self {
            Self::H264 => "video/H264",
            Self::H265 => "video/H265",
            Self::Av1 => "video/AV1",
            Self::Vp9 => "video/VP9",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncoderInfo {
    pub name: String,
    pub codec: Codec,
    pub hardware: bool,
}

pub struct EncodedAccessUnit {
    pub codec: Codec,
    pub bytes: Vec<u8>,
    pub keyframe: bool,
    pub width: u32,
    pub height: u32,
    pub captured_unix_ms: i64,
}

#[derive(Clone, Copy)]
pub struct EncoderRequest {
    pub codec: Codec,
    /// Encoded output size (after ffmpeg/minih264 scale).
    pub width: u32,
    pub height: u32,
    /// Capture/input size written to ffmpeg stdin. `0` means same as width/height
    /// (no scale filter). When set and larger than the encode size, ffmpeg scales.
    pub src_width: u32,
    pub src_height: u32,
    pub fps: u32,
    pub bitrate: u32,
}

pub trait VideoEncoder: Send {
    fn info(&self) -> EncoderInfo;
    fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> Result<EncodedAccessUnit>;
    fn set_bitrate(&mut self, bitrate: u32);
}

pub fn open_encoder(request: &EncoderRequest) -> Result<Box<dyn VideoEncoder>> {
    let request = align_request(*request);
    if request.codec == Codec::H264 {
        let primary = hardware_or_ffmpeg(&request);
        if primary.is_none() {
            return Ok(Box::new(MiniH264::open(&request)?));
        }
        // Hardware and ffmpeg can open and then never emit an access unit
        // (Media Foundation needs another input, ffmpeg `h264_mf` writes
        // nothing). Keep minih264 behind that failure so the session still
        // produces frames.
        return Ok(Box::new(FallbackEncoder::new(request, primary)));
    }
    if let Some(encoder) = hardware_or_ffmpeg(&request) {
        return Ok(encoder);
    }
    if let Some(encoder) = FfmpegEncoder::open(&request, false) {
        return Ok(Box::new(encoder));
    }
    if let Some(encoder) = FfmpegEncoder::open(
        &EncoderRequest {
            codec: Codec::H264,
            ..request
        },
        false,
    ) {
        return Ok(Box::new(encoder));
    }
    if let Ok(encoder) = MiniH264::open(&EncoderRequest {
        codec: Codec::H264,
        ..request
    }) {
        return Ok(Box::new(encoder));
    }
    Err(msg(format!(
        "no {} encoder is available on this machine",
        request.codec.as_str()
    )))
}

fn hardware_or_ffmpeg(request: &EncoderRequest) -> Option<Box<dyn VideoEncoder>> {
    if hardware_encoder_unusable() {
        return None;
    }
    if let Some(encoder) = super::hw::try_hardware(request) {
        return Some(encoder);
    }
    // Hardware ffmpeg is used only when the device node exists. A build that
    // merely lists h264_nvenc / h264_qsv / h264_vaapi is not usable.
    FfmpegEncoder::open(request, true).map(|encoder| Box::new(encoder) as Box<dyn VideoEncoder>)
}

/// Even macroblock size. minih264's SSE2/NEON build rejects a stride that is
/// not a multiple of 8, and chroma stride is width/2, so both axes must be a
/// multiple of 16. 1366x768 is a normal laptop panel and used to fail the
/// first encode, which ended the stream with frames=0.
pub(crate) fn align_mb(value: u32) -> u32 {
    value.div_ceil(16).saturating_mul(16).max(16)
}

pub(crate) fn align_request(mut request: EncoderRequest) -> EncoderRequest {
    request.width = align_mb(request.width);
    request.height = align_mb(request.height);
    if request.src_width == 0 {
        request.src_width = request.width;
    }
    if request.src_height == 0 {
        request.src_height = request.height;
    }
    // rawvideo -s wants even axes; keep capture dims close to the real frame.
    request.src_width = request.src_width.div_ceil(2).saturating_mul(2).max(2);
    request.src_height = request.src_height.div_ceil(2).saturating_mul(2).max(2);
    request
}

/// Media Foundation often returns length-prefixed NALs. The viewers expect Annex B.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
pub(crate) fn ensure_annexb(bytes: Vec<u8>) -> Vec<u8> {
    if bytes.is_empty() || has_start_code(&bytes) {
        return bytes;
    }
    avcc_to_annexb(&bytes).unwrap_or(bytes)
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn has_start_code(bytes: &[u8]) -> bool {
    bytes.windows(3).any(|w| w == [0, 0, 1])
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn avcc_to_annexb(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(bytes.len() + 16);
    let mut index = 0;
    let mut nals = 0;
    while index + 4 <= bytes.len() {
        let len = u32::from_be_bytes(bytes[index..index + 4].try_into().ok()?) as usize;
        index += 4;
        if len == 0 || index + len > bytes.len() {
            return None;
        }
        out.extend_from_slice(&[0, 0, 0, 1]);
        out.extend_from_slice(&bytes[index..index + len]);
        index += len;
        nals += 1;
    }
    if index != bytes.len() || nals == 0 {
        None
    } else {
        Some(out)
    }
}

/// Uses `primary` until it errors or stays empty, then encodes with minih264.
struct FallbackEncoder {
    request: EncoderRequest,
    primary: Option<Box<dyn VideoEncoder>>,
    fallback: Option<MiniH264>,
    misses: u32,
}

impl FallbackEncoder {
    fn new(request: EncoderRequest, primary: Option<Box<dyn VideoEncoder>>) -> Self {
        Self {
            request,
            primary,
            fallback: None,
            misses: 0,
        }
    }

    fn software(&mut self) -> Result<&mut MiniH264> {
        if self.fallback.is_none() {
            self.fallback = Some(MiniH264::open(&self.request)?);
        }
        self.fallback
            .as_mut()
            .ok_or_else(|| msg("software H.264 encoder did not open"))
    }
}

impl VideoEncoder for FallbackEncoder {
    fn info(&self) -> EncoderInfo {
        if let Some(fallback) = self.fallback.as_ref() {
            return fallback.info();
        }
        self.primary
            .as_ref()
            .map(|encoder| encoder.info())
            .unwrap_or_else(|| EncoderInfo {
                name: "minih264".into(),
                codec: Codec::H264,
                hardware: false,
            })
    }

    fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> Result<EncodedAccessUnit> {
        let mut give_up = self.primary.is_none();
        if let Some(primary) = self.primary.as_mut() {
            match primary.encode(frame, force_keyframe) {
                Ok(unit) if !unit.bytes.is_empty() => {
                    self.misses = 0;
                    return Ok(unit);
                }
                Ok(_) => {
                    self.misses += 1;
                    if self.misses < 4 {
                        return Ok(empty_unit(frame));
                    }
                    if !hardware_encoder_unusable() {
                        let why = super::ffmpeg::vaapi_probe_failure_reason()
                            .unwrap_or_else(|| "encoder opened but emitted empty packets".into());
                        tracing::warn!(
                            reason = %why,
                            "hardware encoder produced no frames; using minih264"
                        );
                    }
                    give_up = true;
                }
                Err(err) => {
                    if !hardware_encoder_unusable() {
                        tracing::warn!(
                            error = %err,
                            "hardware encoder failed; using minih264 (see ffmpeg stderr in error)"
                        );
                    }
                    give_up = true;
                }
            }
        }
        if give_up {
            self.primary = None;
            mark_hardware_encoder_unusable();
        }
        self.software()?.encode(frame, true)
    }

    fn set_bitrate(&mut self, bitrate: u32) {
        if let Some(primary) = self.primary.as_mut() {
            primary.set_bitrate(bitrate);
        }
        if let Some(fallback) = self.fallback.as_mut() {
            fallback.set_bitrate(bitrate);
        }
    }
}

fn empty_unit(frame: &Frame) -> EncodedAccessUnit {
    EncodedAccessUnit {
        codec: Codec::H264,
        bytes: Vec::new(),
        keyframe: false,
        width: frame.width,
        height: frame.height,
        captured_unix_ms: frame.captured_unix_ms,
    }
}

struct MiniH264 {
    raw: *mut MiniEncoder,
    width: i32,
    height: i32,
    y: Aligned,
    u: Aligned,
    v: Aligned,
    out: Vec<u8>,
    bitrate: Arc<AtomicU32>,
    fps: u32,
    codec_name: &'static str,
}

unsafe impl Send for MiniH264 {}

impl MiniH264 {
    fn open(request: &EncoderRequest) -> Result<Self> {
        let width = align_mb(request.width);
        let height = align_mb(request.height);
        let vbv = (request.bitrate / 8).clamp(8_000, 2_000_000) as i32;
        let gop = (request.fps.clamp(1, 60) * 2) as i32;
        let raw = unsafe { mini_open(width as i32, height as i32, gop, vbv) };
        if raw.is_null() {
            return Err(msg(format!(
                "minih264 rejected {width}x{height}. The software encoder needs a multiple of 16."
            )));
        }
        let out_cap = (width as usize)
            .saturating_mul(height as usize)
            .saturating_mul(2)
            .clamp(64 * 1024, 16 * 1024 * 1024);
        Ok(Self {
            raw,
            width: width as i32,
            height: height as i32,
            y: Aligned::new((width * height) as usize),
            u: Aligned::new((width / 2 * height / 2) as usize),
            v: Aligned::new((width / 2 * height / 2) as usize),
            out: vec![0u8; out_cap],
            bitrate: Arc::new(AtomicU32::new(request.bitrate.max(100_000))),
            fps: request.fps.clamp(1, 60),
            codec_name: "minih264",
        })
    }

    fn encode_into(&mut self, frame_type: i32, desired: i32) -> i32 {
        unsafe {
            mini_encode(
                self.raw,
                self.y.ptr,
                self.u.ptr,
                self.v.ptr,
                self.width,
                self.width / 2,
                self.width / 2,
                frame_type,
                desired,
                self.out.as_mut_ptr(),
                self.out.len() as i32,
            )
        }
    }
}

impl Drop for MiniH264 {
    fn drop(&mut self) {
        unsafe { mini_close(self.raw) };
    }
}

impl VideoEncoder for MiniH264 {
    fn info(&self) -> EncoderInfo {
        EncoderInfo {
            name: self.codec_name.into(),
            codec: Codec::H264,
            hardware: false,
        }
    }

    fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> Result<EncodedAccessUnit> {
        bgra_to_i420(
            frame,
            self.width as u32,
            self.height as u32,
            &mut self.y,
            &mut self.u,
            &mut self.v,
        );
        let bitrate = self.bitrate.load(Ordering::Relaxed).max(100_000);
        let desired = (bitrate / 8 / self.fps).clamp(250, 250_000) as i32;
        let frame_type = if force_keyframe { 6 } else { 0 };
        let mut written = self.encode_into(frame_type, desired);
        // -2 means the packet did not fit. One larger buffer covers a detailed IDR.
        if written == -2 && self.out.len() < 32 * 1024 * 1024 {
            self.out.resize(self.out.len().saturating_mul(2), 0);
            written = self.encode_into(frame_type, desired);
        }
        if written <= 0 {
            return Err(msg(format!("minih264 encode failed ({written})")));
        }
        let bytes = self.out[..written as usize].to_vec();
        let keyframe = annexb_keyframe(&bytes) || force_keyframe;
        Ok(EncodedAccessUnit {
            codec: Codec::H264,
            bytes,
            keyframe,
            width: self.width as u32,
            height: self.height as u32,
            captured_unix_ms: frame.captured_unix_ms,
        })
    }

    fn set_bitrate(&mut self, bitrate: u32) {
        self.bitrate.store(bitrate.max(100_000), Ordering::Relaxed);
    }
}

pub(crate) fn annexb_keyframe(bytes: &[u8]) -> bool {
    for nal in nal_payloads(bytes) {
        if nal.is_empty() {
            continue;
        }
        let kind = nal[0] & 0x1f;
        if kind == 5 {
            return true;
        }
    }
    false
}

fn nal_payloads(bytes: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if bytes[index] == 0 && bytes[index + 1] == 0 && bytes[index + 2] == 1 {
            starts.push(index + 3);
            index += 3;
            continue;
        }
        if index + 4 < bytes.len()
            && bytes[index] == 0
            && bytes[index + 1] == 0
            && bytes[index + 2] == 0
            && bytes[index + 3] == 1
        {
            starts.push(index + 4);
            index += 4;
            continue;
        }
        index += 1;
    }
    let mut nals = Vec::new();
    for (offset, start) in starts.iter().enumerate() {
        let end = starts.get(offset + 1).copied().unwrap_or(bytes.len());
        let mut stop = end;
        if stop >= 3 && bytes[stop - 1] == 1 && bytes[stop - 2] == 0 && bytes[stop - 3] == 0 {
            stop -= if stop >= 4 && bytes[stop - 4] == 0 {
                4
            } else {
                3
            };
        }
        if *start < stop {
            nals.push(&bytes[*start..stop]);
        }
    }
    nals
}

fn bgra_to_i420(
    frame: &Frame,
    width: u32,
    height: u32,
    y: &mut Aligned,
    u: &mut Aligned,
    v: &mut Aligned,
) {
    let src = frame.pixels();
    let src_w = frame.width.min(width) as usize;
    let src_h = frame.height.min(height) as usize;
    let stride = frame.stride as usize;
    let y_ptr = y.ptr;
    let u_ptr = u.ptr;
    let v_ptr = v.ptr;
    unsafe {
        std::ptr::write_bytes(y_ptr, 16, y.len);
        std::ptr::write_bytes(u_ptr, 128, u.len);
        std::ptr::write_bytes(v_ptr, 128, v.len);
        for row in 0..src_h {
            for col in 0..src_w {
                let pixel = row * stride + col * 4;
                if pixel + 2 >= src.len() {
                    break;
                }
                let b = src[pixel] as i32;
                let g = src[pixel + 1] as i32;
                let r = src[pixel + 2] as i32;
                let yy = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
                *y_ptr.add(row * width as usize + col) = yy.clamp(0, 255) as u8;
                if row % 2 == 0 && col % 2 == 0 {
                    let uu = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                    let vv = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
                    let chroma = (row / 2) * (width as usize / 2) + col / 2;
                    *u_ptr.add(chroma) = uu.clamp(0, 255) as u8;
                    *v_ptr.add(chroma) = vv.clamp(0, 255) as u8;
                }
            }
        }
    }
}

struct Aligned {
    ptr: *mut u8,
    layout: std::alloc::Layout,
    len: usize,
}

unsafe impl Send for Aligned {}

impl Aligned {
    fn new(len: usize) -> Self {
        let len = len.max(1);
        let layout = std::alloc::Layout::from_size_align(len, 32).expect("plane layout");
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        if ptr.is_null() {
            panic!("out of memory allocating a video plane");
        }
        Self { ptr, layout, len }
    }
}

impl Drop for Aligned {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ptr, self.layout) };
    }
}

#[repr(C)]
struct MiniEncoder {
    _private: [u8; 0],
}

extern "C" {
    fn mini_open(width: i32, height: i32, gop: i32, vbv_bytes: i32) -> *mut MiniEncoder;
    fn mini_encode(
        enc: *mut MiniEncoder,
        y: *mut u8,
        u: *mut u8,
        v: *mut u8,
        stride_y: i32,
        stride_u: i32,
        stride_v: i32,
        frame_type: i32,
        desired_bytes: i32,
        out: *mut u8,
        out_cap: i32,
    ) -> i32;
    fn mini_close(enc: *mut MiniEncoder);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn software_h264_is_annex_b_with_an_idr() {
        let width = 64u32;
        let height = 48u32;
        let mut raw = vec![0u8; (width * height * 4) as usize];
        for (index, pixel) in raw.chunks_exact_mut(4).enumerate() {
            pixel[0] = (index % 50) as u8;
            pixel[1] = 40;
            pixel[2] = 180;
            pixel[3] = 255;
        }
        let frame = Frame::from_bgra(width, height, width * 4, &raw, "test").unwrap();
        let mut encoder = MiniH264::open(&EncoderRequest {
            codec: Codec::H264,
            width,
            height,
            src_width: 0,
            src_height: 0,
            fps: 30,
            bitrate: 500_000,
        })
        .unwrap();
        let encoded = encoder.encode(&frame, true).unwrap();
        assert!(encoded.bytes.starts_with(&[0, 0, 0, 1]) || encoded.bytes.starts_with(&[0, 0, 1]));
        assert!(encoded.keyframe, "first forced frame is an IDR");
        assert_eq!(encoded.codec, Codec::H264);
        assert_eq!(encoded.width, width);
        assert_eq!(encoded.height, height);
        assert!(annexb_has_sps(&encoded.bytes));
        let second = encoder.encode(&frame, false).unwrap();
        assert!(!second.bytes.is_empty());
    }

    #[test]
    fn laptop_width_that_is_not_a_multiple_of_eight_still_encodes() {
        // 100 is not a multiple of 8. SSE2/NEON minih264 rejects that stride,
        // which is how a 1366-wide panel produced zero access units.
        let width = 100u32;
        let height = 50u32;
        let raw = vec![8u8; (width * height * 4) as usize];
        let frame = Frame::from_bgra(width, height, width * 4, &raw, "test").unwrap();
        let mut encoder = MiniH264::open(&EncoderRequest {
            codec: Codec::H264,
            width,
            height,
            src_width: 0,
            src_height: 0,
            fps: 10,
            bitrate: 400_000,
        })
        .unwrap();
        let encoded = encoder.encode(&frame, true).unwrap();
        assert!(!encoded.bytes.is_empty());
        assert!(encoded.keyframe);
        assert_eq!(encoded.width % 16, 0);
        assert_eq!(encoded.height % 16, 0);
        assert!(encoded.width >= width && encoded.height >= height);
    }

    #[test]
    fn primary_encode_error_falls_back_to_software() {
        struct Boom;
        impl VideoEncoder for Boom {
            fn info(&self) -> EncoderInfo {
                EncoderInfo {
                    name: "boom".into(),
                    codec: Codec::H264,
                    hardware: true,
                }
            }
            fn encode(&mut self, _: &Frame, _: bool) -> Result<EncodedAccessUnit> {
                Err(msg("media foundation produced no sample"))
            }
            fn set_bitrate(&mut self, _: u32) {}
        }
        let width = 64u32;
        let height = 48u32;
        let raw = vec![30u8; (width * height * 4) as usize];
        let frame = Frame::from_bgra(width, height, width * 4, &raw, "test").unwrap();
        let mut encoder = FallbackEncoder::new(
            EncoderRequest {
                codec: Codec::H264,
                width,
                height,
                src_width: 0,
                src_height: 0,
                fps: 15,
                bitrate: 400_000,
            },
            Some(Box::new(Boom)),
        );
        let encoded = encoder.encode(&frame, true).unwrap();
        assert!(
            !encoded.bytes.is_empty(),
            "fallback must emit an access unit"
        );
        assert!(annexb_keyframe(&encoded.bytes) || encoded.keyframe);
        assert!(encoder.primary.is_none());
    }

    #[test]
    fn length_prefixed_nals_become_annex_b() {
        let avcc = vec![0, 0, 0, 2, 0x65, 0x88];
        let annex = ensure_annexb(avcc);
        assert!(annex.starts_with(&[0, 0, 0, 1]));
        assert!(annexb_keyframe(&annex));
        let already = vec![0, 0, 0, 1, 0x67, 0x42];
        assert_eq!(ensure_annexb(already.clone()), already);
    }

    fn annexb_has_sps(bytes: &[u8]) -> bool {
        nal_payloads(bytes)
            .iter()
            .any(|nal| nal.first().map(|b| b & 0x1f) == Some(7))
    }
}
