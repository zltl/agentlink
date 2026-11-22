//! Windows Media Foundation hardware H.264 transform.
//!
//! A hardware MFT is how NVENC, Intel Quick Sync, and AMD AMF are exposed
//! without linking each vendor SDK. The transform is created on the encode
//! thread. Moving an MFT that was activated on the tokio thread produced
//! `CO_E_NOTINITIALIZED` or a permanent COM hang, and the pump treated that
//! as the end of the session (`frames=0`).
//!
//! `ProcessOutput` is given a buffer unless the MFT provides samples itself.
//! `MF_E_TRANSFORM_NEED_MORE_INPUT` is not a fatal error. A transform that
//! never emits a frame returns an error so the caller can use minih264.

use std::sync::atomic::{AtomicU32, Ordering};

use crate::capture::{prepare_frame_for_encoder, Frame};

use super::encode::{
    annexb_keyframe, ensure_annexb, Codec, EncodedAccessUnit, EncoderInfo, EncoderRequest,
    VideoEncoder,
};

/// RAII balance for per-thread COM (`CoInitializeEx`) and Media Foundation
/// (`MFStartup`). Kept as the LAST field of [`MfInner`] so the `IMFTransform`
/// COM interface is released before `MFShutdown` / `CoUninitialize`.
struct MfComGuard {
    com_init: bool,
    mf_started: bool,
}

impl MfComGuard {
    fn acquire() -> Result<Self, String> {
        use windows::Win32::Media::MediaFoundation::*;
        use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
        unsafe {
            // S_OK and S_FALSE both increment the thread COM refcount and must
            // be balanced with CoUninitialize; RPC_E_CHANGED_MODE does not.
            let com_hr = CoInitializeEx(None, COINIT_MULTITHREADED);
            let com_init = com_hr.is_ok();
            let mut guard = Self {
                com_init,
                mf_started: false,
            };
            MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET).map_err(|err| err.to_string())?;
            guard.mf_started = true;
            Ok(guard)
        }
    }
}

impl Drop for MfComGuard {
    fn drop(&mut self) {
        use windows::Win32::Media::MediaFoundation::MFShutdown;
        use windows::Win32::System::Com::CoUninitialize;
        unsafe {
            if self.mf_started {
                let _ = MFShutdown();
            }
            if self.com_init {
                CoUninitialize();
            }
        }
    }
}

pub fn try_open(request: &EncoderRequest) -> Option<Box<dyn VideoEncoder>> {
    if request.codec != Codec::H264 {
        return None;
    }
    match hardware_mft_count() {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(Box::new(MfEncoder::pending(*request))),
    }
}

struct MfEncoder {
    request: EncoderRequest,
    inner: Option<MfInner>,
    failed: bool,
    bitrate: AtomicU32,
    produced: u64,
    ticks: i64,
}

struct MfInner {
    transform: MfTransform,
    width: u32,
    height: u32,
    nv12: bool,
    input_stream: u32,
    output_stream: u32,
    /// Must remain the last field so `transform` drops before `MFShutdown`/`CoUninitialize`.
    _com_mf: MfComGuard,
}

/// `IMFTransform` is not `Send`. It is created and used only on the encode thread.
struct MfTransform(windows::Win32::Media::MediaFoundation::IMFTransform);

unsafe impl Send for MfTransform {}

impl MfEncoder {
    fn pending(request: EncoderRequest) -> Self {
        Self {
            bitrate: AtomicU32::new(request.bitrate.max(100_000)),
            request,
            inner: None,
            failed: false,
            produced: 0,
            ticks: 0,
        }
    }

    fn ensure(&mut self) -> Result<&mut MfInner, String> {
        if self.inner.is_none() {
            self.inner = Some(MfInner::open(&self.request)?);
        }
        self.inner
            .as_mut()
            .ok_or_else(|| "media foundation encoder was not opened".into())
    }
}

impl MfInner {
    fn open(request: &EncoderRequest) -> Result<Self, String> {
        let guard = MfComGuard::acquire()?;
        unsafe {
            let activates = enum_hardware_encoders()?;
            let mut last = "no hardware H.264 encoder accepted NV12 or RGB32".to_string();
            for activate in activates {
                let Some(activate) = activate else { continue };
                let transform = match activate.ActivateObject() {
                    Ok(transform) => transform,
                    Err(err) => {
                        last = err.to_string();
                        continue;
                    }
                };
                match configure(&transform, request) {
                    Ok(nv12) => {
                        return Ok(Self {
                            transform: MfTransform(transform),
                            width: request.width.div_ceil(2) * 2,
                            height: request.height.div_ceil(2) * 2,
                            nv12,
                            input_stream: 0,
                            output_stream: 0,
                            _com_mf: guard,
                        });
                    }
                    Err(err) => last = err,
                }
            }
            Err(last)
        }
    }
}

fn hardware_mft_count() -> Result<u32, String> {
    use windows::Win32::Media::MediaFoundation::*;
    let _guard = MfComGuard::acquire()?;
    unsafe {
        let mut activates = std::ptr::null_mut();
        let mut count = 0u32;
        let flags =
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER | MFT_ENUM_FLAG_TRANSCODE_ONLY;
        let output = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Video,
            guidSubtype: MFVideoFormat_H264,
        };
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            flags,
            None,
            Some(&raw const output),
            &mut activates,
            &mut count,
        )
        .map_err(|err| err.to_string())?;
        release_activates(activates, count);
        Ok(count)
    }
}

fn enum_hardware_encoders(
) -> Result<Vec<Option<windows::Win32::Media::MediaFoundation::IMFActivate>>, String> {
    use windows::Win32::Media::MediaFoundation::*;
    unsafe {
        let mut activates = std::ptr::null_mut();
        let mut count = 0u32;
        let flags =
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER | MFT_ENUM_FLAG_TRANSCODE_ONLY;
        let output = MFT_REGISTER_TYPE_INFO {
            guidMajorType: MFMediaType_Video,
            guidSubtype: MFVideoFormat_H264,
        };
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            flags,
            None,
            Some(&raw const output),
            &mut activates,
            &mut count,
        )
        .map_err(|err| err.to_string())?;
        if count == 0 || activates.is_null() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(count as usize);
        for index in 0..count {
            out.push((*activates.add(index as usize)).take());
        }
        windows::Win32::System::Com::CoTaskMemFree(Some(activates as *const _));
        Ok(out)
    }
}

fn release_activates(
    activates: *mut Option<windows::Win32::Media::MediaFoundation::IMFActivate>,
    count: u32,
) {
    if activates.is_null() || count == 0 {
        return;
    }
    unsafe {
        for index in 0..count {
            let _ = (*activates.add(index as usize)).take();
        }
        windows::Win32::System::Com::CoTaskMemFree(Some(activates as *const _));
    }
}

/// Returns whether the negotiated input is NV12.
fn configure(
    transform: &windows::Win32::Media::MediaFoundation::IMFTransform,
    request: &EncoderRequest,
) -> Result<bool, String> {
    use windows::Win32::Media::MediaFoundation::*;
    let width = request.width.div_ceil(2) * 2;
    let height = request.height.div_ceil(2) * 2;
    let fps = request.fps.max(1);
    unsafe {
        let output = MFCreateMediaType().map_err(|err| err.to_string())?;
        output
            .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
            .map_err(|err| err.to_string())?;
        output
            .SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_H264)
            .map_err(|err| err.to_string())?;
        output
            .SetUINT32(&MF_MT_AVG_BITRATE, request.bitrate.max(100_000))
            .map_err(|err| err.to_string())?;
        output
            .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
            .map_err(|err| err.to_string())?;
        set_packed(&output, &MF_MT_FRAME_SIZE, width, height)?;
        set_packed(&output, &MF_MT_FRAME_RATE, fps, 1)?;
        output.SetUINT32(&MF_LOW_LATENCY, 1).ok();
        transform
            .SetOutputType(0, &output, 0)
            .map_err(|err| err.to_string())?;
        let nv12 = set_input(transform, &MFVideoFormat_NV12, width, height, fps).is_ok();
        if !nv12 {
            set_input(transform, &MFVideoFormat_RGB32, width, height, fps)?;
        }
        let _ = transform.ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
        let _ = transform.ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
        Ok(nv12)
    }
}

fn set_input(
    transform: &windows::Win32::Media::MediaFoundation::IMFTransform,
    subtype: &windows::core::GUID,
    width: u32,
    height: u32,
    fps: u32,
) -> Result<(), String> {
    use windows::Win32::Media::MediaFoundation::*;
    unsafe {
        let input = MFCreateMediaType().map_err(|err| err.to_string())?;
        input
            .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
            .map_err(|err| err.to_string())?;
        input
            .SetGUID(&MF_MT_SUBTYPE, subtype)
            .map_err(|err| err.to_string())?;
        set_packed(&input, &MF_MT_FRAME_SIZE, width, height)?;
        set_packed(&input, &MF_MT_FRAME_RATE, fps, 1)?;
        let stride = if subtype == &MFVideoFormat_NV12 {
            width as u32
        } else {
            width.saturating_mul(4)
        };
        input.SetUINT32(&MF_MT_DEFAULT_STRIDE, stride).ok();
        transform
            .SetInputType(0, &input, 0)
            .map_err(|err| err.to_string())?;
        Ok(())
    }
}

impl VideoEncoder for MfEncoder {
    fn info(&self) -> EncoderInfo {
        EncoderInfo {
            name: "media-foundation".into(),
            codec: Codec::H264,
            hardware: true,
        }
    }

    fn encode(
        &mut self,
        frame: &Frame,
        force_keyframe: bool,
    ) -> crate::error::Result<EncodedAccessUnit> {
        if self.failed {
            return Err(crate::error::msg("media foundation encoder already failed"));
        }
        let fps = self.request.fps.max(1) as i64;
        let duration = 10_000_000 / fps.max(1);
        let produced = self.produced;
        let ticks = self.ticks;
        let bitrate = self.bitrate.load(Ordering::Relaxed);
        let result = (|| {
            let inner = self.ensure().map_err(crate::error::msg)?;
            inner
                .encode(
                    frame,
                    force_keyframe && produced > 0,
                    ticks,
                    duration,
                    bitrate,
                )
                .map_err(crate::error::msg)
        })();
        match result {
            Ok(Some(bytes)) => {
                self.ticks = self.ticks.saturating_add(duration);
                self.produced = self.produced.saturating_add(1);
                let keyframe = force_keyframe || annexb_keyframe(&bytes);
                Ok(EncodedAccessUnit {
                    codec: Codec::H264,
                    keyframe,
                    width: self.request.width.div_ceil(2) * 2,
                    height: self.request.height.div_ceil(2) * 2,
                    captured_unix_ms: frame.captured_unix_ms,
                    bytes,
                })
            }
            Ok(None) => Ok(EncodedAccessUnit {
                codec: Codec::H264,
                bytes: Vec::new(),
                keyframe: false,
                width: frame.width,
                height: frame.height,
                captured_unix_ms: frame.captured_unix_ms,
            }),
            Err(err) => {
                self.failed = true;
                self.inner = None;
                Err(err)
            }
        }
    }

    fn set_bitrate(&mut self, bitrate: u32) {
        self.bitrate.store(bitrate.max(100_000), Ordering::Relaxed);
    }
}

impl MfInner {
    /// `Ok(None)` means the transform needs another input frame.
    fn encode(
        &mut self,
        frame: &Frame,
        force_keyframe: bool,
        ticks: i64,
        duration: i64,
        _bitrate: u32,
    ) -> Result<Option<Vec<u8>>, String> {
        use windows::Win32::Media::MediaFoundation::*;
        unsafe {
            if force_keyframe {
                let _ = self
                    .transform
                    .0
                    .ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
                let _ = self
                    .transform
                    .0
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0);
                let _ = self
                    .transform
                    .0
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0);
            }
            let prepared = prepare_frame_for_encoder(frame, self.width, self.height)
                .map_err(|err| err.to_string())?;
            let sample = if self.nv12 {
                sample_from_nv12(prepared.as_ref(), self.width, self.height)?
            } else {
                sample_from_bgra(prepared.as_ref(), self.width, self.height)?
            };
            let _ = sample.SetSampleTime(ticks);
            let _ = sample.SetSampleDuration(duration);
            match self.transform.0.ProcessInput(self.input_stream, &sample, 0) {
                Ok(()) => {}
                Err(err) if err.code() == MF_E_NOTACCEPTING => {
                    if let Pull::Frame(bytes) = self.pull()? {
                        return Ok(Some(bytes));
                    }
                    self.transform
                        .0
                        .ProcessInput(self.input_stream, &sample, 0)
                        .map_err(|err| err.to_string())?;
                }
                Err(err) => return Err(err.to_string()),
            }
            for _ in 0..4 {
                match self.pull()? {
                    Pull::Frame(bytes) => return Ok(Some(bytes)),
                    Pull::NeedMore => return Ok(None),
                    Pull::StreamChange => self.retune()?,
                }
            }
            Ok(None)
        }
    }

    fn pull(&mut self) -> Result<Pull, String> {
        use windows::Win32::Media::MediaFoundation::*;
        unsafe {
            let info = self
                .transform
                .0
                .GetOutputStreamInfo(self.output_stream)
                .map_err(|err| err.to_string())?;
            let provides = info.dwFlags & (MFT_OUTPUT_STREAM_PROVIDES_SAMPLES.0 as u32) != 0;
            let size = if info.cbSize == 0 {
                self.width.saturating_mul(self.height).max(64 * 1024)
            } else {
                info.cbSize
            };
            let mut output = MFT_OUTPUT_DATA_BUFFER::default();
            output.dwStreamID = self.output_stream;
            if !provides {
                *output.pSample = Some(output_sample(size)?);
            }
            let mut status = 0u32;
            let produced =
                self.transform
                    .0
                    .ProcessOutput(0, std::slice::from_mut(&mut output), &mut status);
            // ManuallyDrop will not free these. Take them on every path.
            let _events = output.pEvents.take();
            let sample_back = output.pSample.take();
            match produced {
                Ok(()) => {
                    let sample =
                        sample_back.ok_or_else(|| "encoder returned no sample".to_string())?;
                    let bytes = ensure_annexb(sample_bytes(&sample)?);
                    if bytes.is_empty() {
                        Ok(Pull::NeedMore)
                    } else {
                        Ok(Pull::Frame(bytes))
                    }
                }
                Err(err) if err.code() == MF_E_TRANSFORM_NEED_MORE_INPUT => Ok(Pull::NeedMore),
                Err(err) if err.code() == MF_E_TRANSFORM_STREAM_CHANGE => Ok(Pull::StreamChange),
                Err(err) => Err(err.to_string()),
            }
        }
    }

    fn retune(&mut self) -> Result<(), String> {
        unsafe {
            let ty = self
                .transform
                .0
                .GetOutputAvailableType(self.output_stream, 0)
                .map_err(|err| err.to_string())?;
            self.transform
                .0
                .SetOutputType(self.output_stream, &ty, 0)
                .map_err(|err| err.to_string())?;
            Ok(())
        }
    }
}

enum Pull {
    Frame(Vec<u8>),
    NeedMore,
    StreamChange,
}

/// Width/height and numerator/denominator are packed the way `MFSetAttributeSize`
/// and `MFSetAttributeRatio` do. windows 0.61 does not export those helpers.
fn set_packed(
    attrs: &windows::Win32::Media::MediaFoundation::IMFMediaType,
    key: &windows::core::GUID,
    high: u32,
    low: u32,
) -> Result<(), String> {
    let packed = ((high as u64) << 32) | low as u64;
    unsafe { attrs.SetUINT64(key, packed).map_err(|err| err.to_string()) }
}

fn output_sample(size: u32) -> Result<windows::Win32::Media::MediaFoundation::IMFSample, String> {
    use windows::Win32::Media::MediaFoundation::*;
    unsafe {
        let buffer = MFCreateMemoryBuffer(size.max(1)).map_err(|err| err.to_string())?;
        let sample = MFCreateSample().map_err(|err| err.to_string())?;
        sample.AddBuffer(&buffer).map_err(|err| err.to_string())?;
        Ok(sample)
    }
}

fn sample_from_bgra(
    frame: &Frame,
    width: u32,
    height: u32,
) -> Result<windows::Win32::Media::MediaFoundation::IMFSample, String> {
    use windows::Win32::Media::MediaFoundation::*;
    unsafe {
        let row = width as usize * 4;
        let len = row * height as usize;
        let buffer = MFCreateMemoryBuffer(len as u32).map_err(|err| err.to_string())?;
        let mut data = std::ptr::null_mut();
        let mut max = 0u32;
        let mut current = 0u32;
        buffer
            .Lock(&mut data, Some(&raw mut max), Some(&raw mut current))
            .map_err(|err| err.to_string())?;
        let src = frame.pixels();
        let src_stride = frame.stride as usize;
        if !data.is_null() {
            // Zero-fill first so macroblock padding rows/columns never leak
            // uninitialized heap memory into encoded frames.
            std::ptr::write_bytes(data, 0, len);
            let copy = row
                .min(frame.width as usize * 4)
                .min(src_stride);
            let rows = (height as usize).min(frame.height as usize);
            for y in 0..rows {
                if y * src_stride + copy <= src.len() {
                    std::ptr::copy_nonoverlapping(
                        src.as_ptr().add(y * src_stride),
                        data.add(y * row),
                        copy,
                    );
                }
            }
        }
        buffer.Unlock().map_err(|err| err.to_string())?;
        buffer
            .SetCurrentLength(len as u32)
            .map_err(|err| err.to_string())?;
        let sample = MFCreateSample().map_err(|err| err.to_string())?;
        sample.AddBuffer(&buffer).map_err(|err| err.to_string())?;
        Ok(sample)
    }
}

fn sample_from_nv12(
    frame: &Frame,
    width: u32,
    height: u32,
) -> Result<windows::Win32::Media::MediaFoundation::IMFSample, String> {
    use windows::Win32::Media::MediaFoundation::*;
    unsafe {
        let y_size = width as usize * height as usize;
        let len = y_size + y_size / 2;
        let buffer = MFCreateMemoryBuffer(len as u32).map_err(|err| err.to_string())?;
        let mut data = std::ptr::null_mut();
        let mut max = 0u32;
        let mut current = 0u32;
        buffer
            .Lock(&mut data, Some(&raw mut max), Some(&raw mut current))
            .map_err(|err| err.to_string())?;
        if !data.is_null() {
            std::ptr::write_bytes(data, 16, y_size);
            std::ptr::write_bytes(data.add(y_size), 128, y_size / 2);
            blit_nv12(
                frame,
                width,
                height,
                std::slice::from_raw_parts_mut(data, len),
            );
        }
        buffer.Unlock().map_err(|err| err.to_string())?;
        buffer
            .SetCurrentLength(len as u32)
            .map_err(|err| err.to_string())?;
        let sample = MFCreateSample().map_err(|err| err.to_string())?;
        sample.AddBuffer(&buffer).map_err(|err| err.to_string())?;
        Ok(sample)
    }
}

fn blit_nv12(frame: &Frame, width: u32, height: u32, dst: &mut [u8]) {
    let src = frame.pixels();
    let src_w = frame.width.min(width) as usize;
    let src_h = frame.height.min(height) as usize;
    let stride = frame.stride as usize;
    let y_size = width as usize * height as usize;
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
            dst[row * width as usize + col] = yy.clamp(0, 255) as u8;
            if row % 2 == 0 && col % 2 == 0 {
                let uu = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
                let vv = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
                let chroma = y_size + (row / 2) * width as usize + col;
                if chroma + 1 < dst.len() {
                    dst[chroma] = uu.clamp(0, 255) as u8;
                    dst[chroma + 1] = vv.clamp(0, 255) as u8;
                }
            }
        }
    }
}

fn sample_bytes(
    sample: &windows::Win32::Media::MediaFoundation::IMFSample,
) -> Result<Vec<u8>, String> {
    unsafe {
        let buffer = sample
            .ConvertToContiguousBuffer()
            .map_err(|err| err.to_string())?;
        let mut data = std::ptr::null_mut();
        let mut max = 0u32;
        let mut current = 0u32;
        buffer
            .Lock(&mut data, Some(&raw mut max), Some(&raw mut current))
            .map_err(|err| err.to_string())?;
        let bytes = if data.is_null() || current == 0 {
            Vec::new()
        } else {
            std::slice::from_raw_parts(data, current as usize).to_vec()
        };
        buffer.Unlock().map_err(|err| err.to_string())?;
        if bytes.is_empty() {
            return Err("empty media foundation sample".into());
        }
        Ok(bytes)
    }
}
