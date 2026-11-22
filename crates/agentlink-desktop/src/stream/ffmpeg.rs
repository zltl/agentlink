//! ffmpeg child process for hardware encoders and for libx264 / libvpx when
//! they are installed. The in-process minih264 path does not need this.
//!
//! VAAPI note (Intel iHD / EncSliceLP, e.g. Kaby Lake): many iGPUs only expose
//! the low-power encode entrypoint and only CQP rate control. Passing `-b:v`
//! or omitting `-low_power 1` makes ffmpeg open the encoder and then emit no
//! packets. See [`vaapi_bitrate_to_qp`] and the probe cache below.

use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use agentlink_core::process;

use crate::capture::Frame;
use crate::error::{msg, Result};

use super::encode::{
    annexb_keyframe, Codec, EncodedAccessUnit, EncoderInfo, EncoderRequest, VideoEncoder,
};

/// How a successful VAAPI session was opened. Cached after the first probe so
/// later sessions do not re-trial failing flag combinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaapiMode {
    /// `-low_power 1 -rc_mode CQP -qp N` (Intel EncSliceLP).
    LowPowerCqp,
    /// Non-LP with `-b:v` (full EncSlice / drivers that accept bitrate).
    Bitrate,
}

#[derive(Debug, Clone)]
enum VaapiCache {
    Untested,
    Ok { mode: VaapiMode, render: String },
    Failed { reason: String },
}

fn vaapi_cache() -> &'static Mutex<VaapiCache> {
    static CACHE: OnceLock<Mutex<VaapiCache>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(VaapiCache::Untested))
}

/// Map a requested bitrate onto CQP `qp` in **18 (high rate) … 34 (low rate)**.
///
/// Formula (linear in log₂ bitrate):
/// ```text
/// t = clamp( (log2(bitrate) - log2(100_000)) / (log2(12_000_000) - log2(100_000)) , 0, 1 )
/// qp = round(34 - t * (34 - 18))
/// ```
///
/// Why log: doubling bitrate is a roughly constant quality step; a linear map
/// would crush the useful 0.5–4 Mbps band into a few qp values. Anchors match
/// the session bitrate clamp in `webrtc_session` (100 kbps … 12 Mbps).
pub fn vaapi_bitrate_to_qp(bitrate: u32) -> u32 {
    const LO: f64 = 100_000.0;
    const HI: f64 = 12_000_000.0;
    const QP_HI: f64 = 34.0; // low bitrate → coarser
    const QP_LO: f64 = 18.0; // high bitrate → finer
    let b = (bitrate as f64).clamp(LO, HI);
    let t = (b.log2() - LO.log2()) / (HI.log2() - LO.log2());
    let qp = QP_HI - t.clamp(0.0, 1.0) * (QP_HI - QP_LO);
    qp.round().clamp(QP_LO, QP_HI) as u32
}

/// First DRM render node that opens for read/write (`/dev/dri/renderD128`…).
pub fn find_render_node() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        for index in 128..144 {
            let path = format!("/dev/dri/renderD{index}");
            if std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .is_ok()
            {
                return Some(path);
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Process-wide VAAPI capability. Runs a 1-frame encode once; result is cached.
pub fn vaapi_probe_status() -> Option<(VaapiMode, String)> {
    ensure_vaapi_probed();
    let guard = vaapi_cache().lock().unwrap_or_else(|err| err.into_inner());
    match &*guard {
        VaapiCache::Ok { mode, render } => Some((*mode, render.clone())),
        _ => None,
    }
}

pub fn vaapi_probe_failure_reason() -> Option<String> {
    ensure_vaapi_probed();
    let guard = vaapi_cache().lock().unwrap_or_else(|err| err.into_inner());
    match &*guard {
        VaapiCache::Failed { reason } => Some(reason.clone()),
        _ => None,
    }
}

fn vaapi_probe_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn ensure_vaapi_probed() {
    {
        let guard = vaapi_cache().lock().unwrap_or_else(|err| err.into_inner());
        if !matches!(&*guard, VaapiCache::Untested) {
            return;
        }
    }
    // Never hold `vaapi_cache()` across blocking subprocess I/O so readers
    // inspecting the cache cannot deadlock if a VAAPI driver stalls.
    let _probe_guard = vaapi_probe_lock()
        .lock()
        .unwrap_or_else(|err| err.into_inner());
    {
        let guard = vaapi_cache().lock().unwrap_or_else(|err| err.into_inner());
        if !matches!(&*guard, VaapiCache::Untested) {
            return;
        }
    }
    let result = run_vaapi_probe();
    let mut guard = vaapi_cache().lock().unwrap_or_else(|err| err.into_inner());
    *guard = result;
}

fn run_vaapi_probe() -> VaapiCache {
    // Check render node FIRST so Windows/macOS/headless Linux skip spawning
    // `ffmpeg -encoders` entirely.
    let Some(render) = find_render_node() else {
        return VaapiCache::Failed {
            reason: "no openable /dev/dri/renderD* node".into(),
        };
    };
    let Some(binary) = which("ffmpeg") else {
        return VaapiCache::Failed {
            reason: "ffmpeg binary not found on PATH".into(),
        };
    };
    if !encoder_list(&binary).iter().any(|n| n == "h264_vaapi") {
        return VaapiCache::Failed {
            reason: "ffmpeg does not advertise h264_vaapi".into(),
        };
    }

    let deadline = Instant::now() + Duration::from_millis(900);

    // Prefer LP+CQP (Intel EncSliceLP). Fall back to non-LP bitrate.
    match probe_one_frame(&binary, &render, VaapiMode::LowPowerCqp, deadline) {
        Ok(()) => {
            tracing::info!(
                render = %render,
                mode = "low_power_cqp",
                "VAAPI h264 probe succeeded"
            );
            return VaapiCache::Ok {
                mode: VaapiMode::LowPowerCqp,
                render,
            };
        }
        Err(lp_err) => {
            tracing::warn!(
                render = %render,
                error = %lp_err,
                "VAAPI low_power+CQP probe failed; trying non-LP bitrate"
            );
            match probe_one_frame(&binary, &render, VaapiMode::Bitrate, deadline) {
                Ok(()) => {
                    tracing::info!(
                        render = %render,
                        mode = "bitrate",
                        "VAAPI h264 probe succeeded"
                    );
                    return VaapiCache::Ok {
                        mode: VaapiMode::Bitrate,
                        render,
                    };
                }
                Err(br_err) => {
                    let reason = format!(
                        "VAAPI probe failed (low_power+CQP: {lp_err}; bitrate: {br_err})"
                    );
                    tracing::warn!("{reason}");
                    return VaapiCache::Failed { reason };
                }
            }
        }
    }
}

fn probe_one_frame(
    binary: &str,
    render: &str,
    mode: VaapiMode,
    deadline: Instant,
) -> std::result::Result<(), String> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err("probe deadline exceeded".into());
    }
    let mut cmd = process::hidden(binary);
    cmd.arg("-hide_banner")
        .arg("-loglevel")
        .arg("error")
        .arg("-init_hw_device")
        .arg(format!("vaapi=va:{render}"))
        .arg("-filter_hw_device")
        .arg("va")
        .args([
            "-f",
            "lavfi",
            "-i",
            "color=c=black:s=64x64:r=30:d=0.1",
            "-an",
            "-vf",
            "format=nv12|vaapi,hwupload",
            "-c:v",
            "h264_vaapi",
        ]);
    match mode {
        VaapiMode::LowPowerCqp => {
            cmd.args(["-low_power", "1", "-rc_mode", "CQP", "-qp", "26"]);
        }
        VaapiMode::Bitrate => {
            cmd.args(["-b:v", "500000"]);
        }
    }
    cmd.args(["-bf", "0", "-g", "60", "-frames:v", "1", "-f", "h264", "pipe:1"]);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .map_err(|err| format!("spawn ffmpeg probe: {err}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| "ffmpeg probe stdout missing".to_string())?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| "ffmpeg probe stderr missing".to_string())?;

    let stderr_handle = std::thread::spawn(move || {
        let mut buf = Vec::new();
        let _ = stderr.read_to_end(&mut buf);
        String::from_utf8_lossy(&buf).into_owned()
    });

    let (stdout_tx, stdout_rx) = mpsc::channel::<std::io::Result<Vec<u8>>>();
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match stdout.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if stdout_tx.send(Ok(buf[..n].to_vec())).is_err() {
                        break;
                    }
                }
                Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(err) => {
                    let _ = stdout_tx.send(Err(err));
                    break;
                }
            }
        }
    });

    let mut out = Vec::new();
    let mut got = false;
    let mut timed_out = false;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            break;
        }
        match stdout_rx.recv_timeout(remaining) {
            Ok(Ok(chunk)) if !chunk.is_empty() => {
                out.extend_from_slice(&chunk);
                got = true;
                break;
            }
            Ok(Ok(_)) => continue,
            Ok(Err(err)) => {
                let _ = child.kill();
                let _ = child.wait();
                let err_text = truncate_stderr(&stderr_handle.join().unwrap_or_default());
                return Err(format!("read probe stdout: {err}; stderr={err_text}"));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                timed_out = true;
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    let err_text = truncate_stderr(&stderr_handle.join().unwrap_or_default());
    if got && !out.is_empty() {
        Ok(())
    } else if timed_out {
        if err_text.is_empty() {
            Err("probe watchdog deadline exceeded".into())
        } else {
            Err(format!(
                "probe watchdog deadline exceeded; stderr={err_text}"
            ))
        }
    } else if err_text.is_empty() {
        Err("probe produced no packet".into())
    } else {
        Err(format!("probe produced no packet; stderr={err_text}"))
    }
}

const STDERR_KEEP: usize = 4096;

/// Advance `idx` forward to the next UTF-8 character boundary (never panics).
fn ceil_char_boundary(s: &str, idx: usize) -> usize {
    let mut i = idx.min(s.len());
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

fn truncate_stderr(text: &str) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= STDERR_KEEP {
        return trimmed.to_string();
    }
    let start = ceil_char_boundary(trimmed, trimmed.len() - STDERR_KEEP);
    format!("…{}", &trimmed[start..])
}

struct StderrTail {
    buf: Mutex<String>,
}

impl StderrTail {
    fn new() -> std::sync::Arc<Self> {
        std::sync::Arc::new(Self {
            buf: Mutex::new(String::new()),
        })
    }

    fn push(&self, chunk: &str) {
        let Ok(mut guard) = self.buf.lock() else {
            return;
        };
        guard.push_str(chunk);
        if guard.len() > STDERR_KEEP * 2 {
            let drain = ceil_char_boundary(&guard, guard.len() - STDERR_KEEP);
            guard.drain(..drain);
        }
    }

    fn snapshot(&self) -> String {
        let guard = self.buf.lock().unwrap_or_else(|err| err.into_inner());
        truncate_stderr(&guard)
    }
}

const BITRATE_RESPAWN_COOLDOWN: Duration = Duration::from_secs(3);

pub struct FfmpegEncoder {
    child: Child,
    stdin: ChildStdin,
    chunks: Receiver<Vec<u8>>,
    stderr: std::sync::Arc<StderrTail>,
    request: EncoderRequest,
    spawned_bitrate: u32,
    name: String,
    hardware: bool,
    vaapi: Option<(VaapiMode, String)>,
    frames: u64,
    /// Last time a force-keyframe respawned the child (VAAPI throttling).
    last_idr_at: Instant,
    /// Last time a bitrate change respawned the child.
    last_bitrate_respawn: Instant,
    /// Leftover bytes read past an Annex-B AU boundary for the next frame.
    pending_out: Vec<u8>,
    /// Reusable tightly-packed BGRA stdin frame buffer (avoids 1080+ syscalls/frame).
    write_buf: Vec<u8>,
}

impl FfmpegEncoder {
    pub fn open(request: &EncoderRequest, hardware: bool) -> Option<Self> {
        let binary = which("ffmpeg")?;
        let encoders = encoder_list(&binary);
        for name in candidate_names(request.codec, hardware) {
            if !encoders.iter().any(|have| have == name) {
                continue;
            }
            if hardware && !hardware_device_present(name) {
                continue;
            }
            // Intel iGPUs with only EncSliceLP often advertise h264_qsv but
            // cannot open an MFX session. Prefer the VAAPI probe result and
            // skip QSV entirely when VAAPI already works.
            if name.contains("qsv") && vaapi_probe_status().is_some() {
                tracing::debug!(
                    encoder = name,
                    "skipping QSV because VAAPI probe already succeeded"
                );
                continue;
            }
            if name.contains("vaapi") {
                ensure_vaapi_probed();
                let cache = vaapi_cache().lock().unwrap_or_else(|err| err.into_inner());
                match &*cache {
                    VaapiCache::Failed { reason } => {
                        tracing::warn!(
                            encoder = name,
                            reason = %reason,
                            "skipping VAAPI; probe cached failure (will use software fallback)"
                        );
                        continue;
                    }
                    VaapiCache::Ok { mode, render } => {
                        let mode = *mode;
                        let render = render.clone();
                        drop(cache);
                        match Self::spawn(
                            &binary,
                            request,
                            name,
                            hardware,
                            Some((mode, render)),
                        ) {
                            Ok(encoder) => {
                                if hardware {
                                    match confirm_hardware_encoder(encoder) {
                                        Ok(ready) => return Some(ready),
                                        Err(err) => {
                                            tracing::warn!(
                                                encoder = name,
                                                error = %err,
                                                "VAAPI opened but first packet failed"
                                            );
                                            continue;
                                        }
                                    }
                                }
                                return Some(encoder);
                            }
                            Err(err) => {
                                tracing::warn!(
                                    encoder = name,
                                    error = %err,
                                    "VAAPI spawn failed after successful probe"
                                );
                                continue;
                            }
                        }
                    }
                    VaapiCache::Untested => {
                        drop(cache);
                        continue;
                    }
                }
            }
            if let Ok(encoder) = Self::spawn(&binary, request, name, hardware, None) {
                if hardware {
                    match confirm_hardware_encoder(encoder) {
                        Ok(ready) => return Some(ready),
                        Err(err) => {
                            tracing::warn!(
                                encoder = name,
                                error = %err,
                                "hardware ffmpeg candidate rejected after first-packet check"
                            );
                            continue;
                        }
                    }
                }
                return Some(encoder);
            }
        }
        None
    }

    fn spawn(
        binary: &str,
        request: &EncoderRequest,
        name: &str,
        hardware: bool,
        vaapi: Option<(VaapiMode, String)>,
    ) -> Result<Self> {
        let width = request.width.div_ceil(2) * 2;
        let height = request.height.div_ceil(2) * 2;
        let src_w = request.src_width.div_ceil(2).saturating_mul(2).max(2);
        let src_h = request.src_height.div_ceil(2).saturating_mul(2).max(2);
        let need_scale = src_w != width || src_h != height;
        let fps = request.fps.clamp(1, 60);
        let bitrate = format!("{}", request.bitrate.max(100_000));
        let mut cmd = process::hidden(binary);
        cmd.arg("-hide_banner").arg("-loglevel").arg("error");

        if let Some((_mode, render)) = vaapi.as_ref() {
            cmd.arg("-init_hw_device")
                .arg(format!("vaapi=va:{render}"))
                .arg("-filter_hw_device")
                .arg("va");
        }

        // stdin is native capture pixels; scale happens in -vf (GPU when VAAPI).
        cmd.arg("-f")
            .arg("rawvideo")
            .arg("-pix_fmt")
            .arg("bgra")
            .arg("-s")
            .arg(format!("{src_w}x{src_h}"))
            .arg("-r")
            .arg(fps.to_string())
            .arg("-i")
            .arg("pipe:0")
            .arg("-an");

        if vaapi.is_some() {
            // Intel EncSliceLP on this machine rejects scale_vaapi ("VAProfile
            // not supported"). Scale in ffmpeg (fast_bilinear) then hwupload —
            // still far cheaper than the old Rust image-crate path, and keeps
            // h264_vaapi on the encode side.
            let vf = if need_scale {
                format!(
                    "scale={width}:{height}:flags=fast_bilinear,format=nv12|vaapi,hwupload"
                )
            } else {
                "format=nv12|vaapi,hwupload".to_string()
            };
            cmd.arg("-vf").arg(vf);
        } else if need_scale {
            cmd.arg("-vf").arg(format!("scale={width}:{height}:flags=fast_bilinear"));
        }

        cmd.arg("-c:v").arg(name);
        match name {
            "libx264" => {
                // Force yuv420p + baseline so raw bgra stdin never produces
                // High 4:4:4 Predictive (undecodable by OpenH264 / browsers).
                // `aud=1` inserts explicit Annex-B Access Unit Delimiters.
                cmd.args(["-pix_fmt", "yuv420p", "-profile:v", "baseline"])
                    .args(["-preset", "ultrafast", "-tune", "zerolatency"])
                    .args(["-bf", "0", "-g", "60"])
                    .arg("-x264-params")
                    .arg("bframes=0:sync-lookahead=0:rc-lookahead=0:repeat-headers=1:annexb=1:aud=1");
            }
            "libvpx-vp9" => {
                cmd.args([
                    "-pix_fmt",
                    "yuv420p",
                    "-deadline",
                    "realtime",
                    "-cpu-used",
                    "8",
                    "-lag-in-frames",
                    "0",
                    "-g",
                    "60",
                ]);
            }
            _ => {
                cmd.args(["-bf", "0", "-g", "60"]);
            }
        }

        if let Some((mode, _)) = vaapi.as_ref() {
            match mode {
                VaapiMode::LowPowerCqp => {
                    let qp = vaapi_bitrate_to_qp(request.bitrate);
                    cmd.args([
                        "-low_power",
                        "1",
                        "-rc_mode",
                        "CQP",
                        "-qp",
                        &qp.to_string(),
                    ]);
                }
                VaapiMode::Bitrate => {
                    cmd.args(["-b:v", &bitrate]);
                }
            }
        } else {
            cmd.args(["-b:v", &bitrate]);
        }

        let container = match request.codec {
            Codec::H264 => "h264",
            Codec::H265 => "hevc",
            Codec::Av1 | Codec::Vp9 => "ivf",
        };
        // Push access units out as soon as the encoder produces them. Without
        // this, some mux paths buffer; with VAAPI we still need a priming
        // frame (see prime_vaapi) because the encoder itself has 1-frame delay.
        cmd.args(["-flush_packets", "1"]);
        cmd.args(["-f", container, "pipe:1"]);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn().map_err(|err| msg(format!("ffmpeg: {err}")))?;
        let stdin = child.stdin.take().ok_or_else(|| msg("ffmpeg stdin"))?;
        let mut stdout = child.stdout.take().ok_or_else(|| msg("ffmpeg stdout"))?;
        let mut stderr_pipe = child.stderr.take().ok_or_else(|| msg("ffmpeg stderr"))?;
        let stderr = StderrTail::new();
        let stderr_writer = stderr.clone();
        std::thread::Builder::new()
            .name("agentlink-ffmpeg-err".into())
            .spawn(move || {
                let mut buf = [0u8; 1024];
                loop {
                    match stderr_pipe.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let text = String::from_utf8_lossy(&buf[..n]);
                            stderr_writer.push(&text);
                        }
                    }
                }
            })
            .map_err(|err| msg(format!("ffmpeg stderr reader: {err}")))?;
        let (tx, chunks) = mpsc::channel();
        std::thread::Builder::new()
            .name("agentlink-ffmpeg".into())
            .spawn(move || {
                let mut buf = [0u8; 16 * 1024];
                loop {
                    match stdout.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if tx.send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
            })
            .map_err(|err| msg(format!("ffmpeg reader: {err}")))?;
        let now = Instant::now();
        let initial_bitrate = request.bitrate.max(100_000);
        Ok(Self {
            child,
            stdin,
            chunks,
            stderr,
            request: EncoderRequest {
                width,
                height,
                fps,
                bitrate: initial_bitrate,
                ..*request
            },
            spawned_bitrate: initial_bitrate,
            name: name.to_string(),
            hardware,
            vaapi,
            frames: 0,
            last_idr_at: now,
            last_bitrate_respawn: now,
            pending_out: Vec::new(),
            write_buf: Vec::with_capacity(src_w as usize * src_h as usize * 4),
        })
    }

    fn packet_error(&self, base: &str) -> crate::error::DesktopError {
        let tail = self.stderr.snapshot();
        if tail.is_empty() {
            msg(base.to_string())
        } else {
            msg(format!("{base}; ffmpeg stderr: {tail}"))
        }
    }
}

impl Drop for FfmpegEncoder {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl VideoEncoder for FfmpegEncoder {
    fn info(&self) -> EncoderInfo {
        EncoderInfo {
            name: format!("ffmpeg:{}", self.name),
            codec: self.request.codec,
            hardware: self.hardware,
        }
    }

    fn encode(&mut self, frame: &Frame, force_keyframe: bool) -> Result<EncodedAccessUnit> {
        if force_keyframe && self.frames > 0 {
            // VAAPI has no mid-stream IDR API on the rawvideo pipe path; respawn
            // re-inits the iGPU encoder (~50–150ms) and emits a fresh IDR.
            // Honour client keyframe asks within ~100ms — the old 2s throttle
            // made recovery after loss feel like a multi-second freeze.
            // 333ms ≈ one forced IDR per 10 frames at 30fps — fast enough for
            // recovery, slow enough that viewer keyframe spam cannot respawn
            // ffmpeg every tick.
            let min_gap = if self.vaapi.is_some() {
                Duration::from_millis(333)
            } else {
                Duration::ZERO
            };
            if self.last_idr_at.elapsed() >= min_gap {
                let request = self.request;
                let name = self.name.clone();
                let hardware = self.hardware;
                let vaapi = self.vaapi.clone();
                *self = Self::spawn("ffmpeg", &request, &name, hardware, vaapi)?;
                self.last_idr_at = Instant::now();
            }
        }
        let src_w = self.request.src_width.max(2);
        let src_h = self.request.src_height.max(2);
        write_bgra(&mut self.stdin, &mut self.write_buf, frame, src_w, src_h)?;
        self.stdin.flush().map_err(|err| msg(err.to_string()))?;
        // Intel h264_vaapi holds one frame before emitting. A black priming
        // frame used to make the first IDR a blank picture, which made the
        // viewer spam keyframe requests and restart ffmpeg every ~1.5s.
        // Double-writing the first real frame liberates a content IDR instead.
        if self.vaapi.is_some() && self.frames == 0 {
            write_bgra(&mut self.stdin, &mut self.write_buf, frame, src_w, src_h)?;
            self.stdin.flush().map_err(|err| msg(err.to_string()))?;
        }
        let bytes = match read_access_unit(
            &self.chunks,
            &mut self.pending_out,
            self.request.codec,
        ) {
            Ok(bytes) => bytes,
            Err(err) => {
                let text = err.to_string();
                return Err(self.packet_error(&text));
            }
        };
        self.frames += 1;
        let keyframe = match self.request.codec {
            Codec::H264 | Codec::H265 => {
                annexb_keyframe(&bytes) || force_keyframe || self.frames == 1
            }
            Codec::Av1 | Codec::Vp9 => true,
        };
        Ok(EncodedAccessUnit {
            codec: self.request.codec,
            bytes,
            keyframe,
            width: self.request.width,
            height: self.request.height,
            captured_unix_ms: frame.captured_unix_ms,
        })
    }

    fn set_bitrate(&mut self, bitrate: u32) {
        let next_bitrate = bitrate.max(100_000);
        self.request.bitrate = next_bitrate;
        let vaapi_mode = self.vaapi.as_ref().map(|(m, _)| *m);
        if should_respawn_for_bitrate(
            self.spawned_bitrate,
            next_bitrate,
            vaapi_mode,
            self.frames,
            self.last_bitrate_respawn.elapsed(),
        ) {
            let request = self.request;
            let name = self.name.clone();
            let hardware = self.hardware;
            let vaapi = self.vaapi.clone();
            if let Ok(next) = Self::spawn("ffmpeg", &request, &name, hardware, vaapi) {
                *self = next;
            }
        }
    }
}

/// Pure policy deciding whether an ffmpeg child must be respawned for a
/// bitrate change. Ignores minor idle QP jitter and enforces a cooldown so
/// AIMD/heartbeat updates cannot churn ffmpeg processes.
fn should_respawn_for_bitrate(
    spawned_bitrate: u32,
    new_bitrate: u32,
    vaapi_mode: Option<VaapiMode>,
    frames: u64,
    since_last_respawn: Duration,
) -> bool {
    if frames == 0 || since_last_respawn < BITRATE_RESPAWN_COOLDOWN {
        return false;
    }
    let previous = spawned_bitrate.max(1);
    if matches!(vaapi_mode, Some(VaapiMode::LowPowerCqp)) {
        let old_qp = vaapi_bitrate_to_qp(previous) as i32;
        let new_qp = vaapi_bitrate_to_qp(new_bitrate) as i32;
        (old_qp - new_qp).abs() >= 3
    } else {
        let ratio = new_bitrate as f32 / previous as f32;
        !(0.65..=1.5).contains(&ratio)
    }
}

fn write_bgra(
    stdin: &mut ChildStdin,
    buf: &mut Vec<u8>,
    frame: &Frame,
    width: u32,
    height: u32,
) -> Result<()> {
    let src_stride = frame.stride as usize;
    let row = width as usize * 4;
    let total = row * height as usize;
    let src = frame.pixels();
    // Fast path: tightly packed frame matches stdin dimensions exactly.
    if frame.width == width
        && frame.height == height
        && src_stride == row
        && src.len() >= total
    {
        return stdin
            .write_all(&src[..total])
            .map_err(|err| msg(err.to_string()));
    }
    buf.resize(total, 0);
    buf.fill(0);
    let rows = (height as usize).min(frame.height as usize);
    let copy_cols = row.min(frame.width as usize * 4);
    for y in 0..rows {
        let src_start = y * src_stride;
        let available = src.len().saturating_sub(src_start);
        let copy = copy_cols.min(available);
        let dst_start = y * row;
        if copy > 0 {
            buf[dst_start..dst_start + copy].copy_from_slice(&src[src_start..src_start + copy]);
        }
    }
    stdin.write_all(buf).map_err(|err| msg(err.to_string()))
}

/// Find the byte offset of the next Annex-B start code (`00 00 01` or
/// `00 00 00 01`) at or after `from`, returning `(start_code_pos, nal_header_pos)`.
fn find_start_code(bytes: &[u8], from: usize) -> Option<(usize, usize)> {
    let mut i = from;
    while i + 3 <= bytes.len() {
        if bytes[i] == 0 && bytes[i + 1] == 0 {
            if bytes[i + 2] == 1 {
                return Some((i, i + 3));
            }
            if i + 3 < bytes.len() && bytes[i + 2] == 0 && bytes[i + 3] == 1 {
                return Some((i, i + 4));
            }
        }
        i += 1;
    }
    None
}

fn is_vcl_nal(codec: Codec, nal_header: u8) -> bool {
    match codec {
        Codec::H264 => matches!(nal_header & 0x1f, 1..=5),
        Codec::H265 => matches!((nal_header >> 1) & 0x3f, 0..=21),
        _ => true,
    }
}

fn is_au_delimiter_after_vcl(codec: Codec, nal: &[u8]) -> bool {
    let Some(&hdr) = nal.first() else {
        return false;
    };
    match codec {
        Codec::H264 => {
            let ty = hdr & 0x1f;
            // AUD (9), SPS (7), PPS (8), SEI (6), or a new primary slice whose
            // first_mb_in_slice == 0 (Exp-Golomb 0 starts with MSB 1).
            matches!(ty, 6 | 7 | 8 | 9)
                || (matches!(ty, 1..=5) && nal.get(1).is_some_and(|b| (b & 0x80) != 0))
        }
        Codec::H265 => {
            let ty = (hdr >> 1) & 0x3f;
            // VPS (32), SPS (33), PPS (34), AUD (35), prefix SEI (39), or a new
            // slice with first_slice_segment_in_pic_flag == 1 (MSB of byte 2).
            matches!(ty, 32..=35 | 39)
                || (matches!(ty, 0..=21) && nal.get(2).is_some_and(|b| (b & 0x80) != 0))
        }
        _ => false,
    }
}

fn annexb_has_vcl(bytes: &[u8], codec: Codec) -> bool {
    let mut cursor = 0;
    while let Some((_, hdr_pos)) = find_start_code(bytes, cursor) {
        if let Some(&hdr) = bytes.get(hdr_pos) {
            if is_vcl_nal(codec, hdr) {
                return true;
            }
        }
        cursor = hdr_pos;
    }
    false
}

/// If `buf` contains at least one complete Access Unit followed by the start
/// of the next Access Unit (AUD, SPS/PPS, or next frame's first slice), split
/// off and return the first AU immediately, leaving the remainder in `buf`.
fn split_complete_annexb_au(buf: &mut Vec<u8>, codec: Codec) -> Option<Vec<u8>> {
    let mut saw_vcl = false;
    let mut cursor = 0;
    while let Some((sc_pos, hdr_pos)) = find_start_code(buf, cursor) {
        if hdr_pos >= buf.len() {
            break;
        }
        let slice = &buf[hdr_pos..];
        if saw_vcl && is_au_delimiter_after_vcl(codec, slice) {
            let tail = buf.split_off(sc_pos);
            let au = std::mem::replace(buf, tail);
            return Some(au);
        }
        if is_vcl_nal(codec, slice[0]) {
            saw_vcl = true;
        }
        cursor = hdr_pos;
    }
    None
}

fn read_access_unit(
    chunks: &Receiver<Vec<u8>>,
    pending: &mut Vec<u8>,
    codec: Codec,
) -> Result<Vec<u8>> {
    let annexb = matches!(codec, Codec::H264 | Codec::H265);
    if annexb {
        if let Some(au) = split_complete_annexb_au(pending, codec) {
            return Ok(au);
        }
    }
    let deadline = Instant::now() + Duration::from_millis(800);
    while pending.is_empty() || (annexb && !annexb_has_vcl(pending, codec)) {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(msg("ffmpeg produced no packet"));
        }
        let chunk = chunks
            .recv_timeout(remaining)
            .map_err(|_| msg("ffmpeg produced no packet"))?;
        pending.extend_from_slice(&chunk);
        if annexb {
            if let Some(au) = split_complete_annexb_au(pending, codec) {
                return Ok(au);
            }
        }
        if pending.len() > 8 * 1024 * 1024 {
            break;
        }
    }
    // Drain any chunks already buffered in the channel, then wait only a brief
    // 2ms tail window (not 20ms) for trailing bytes of a multi-chunk AU.
    while let Ok(more) = chunks.try_recv() {
        pending.extend_from_slice(&more);
        if annexb {
            if let Some(au) = split_complete_annexb_au(pending, codec) {
                return Ok(au);
            }
        }
        if pending.len() > 8 * 1024 * 1024 {
            break;
        }
    }
    let tail_wait = Duration::from_millis(2);
    loop {
        match chunks.recv_timeout(tail_wait) {
            Ok(more) => {
                pending.extend_from_slice(&more);
                if annexb {
                    if let Some(au) = split_complete_annexb_au(pending, codec) {
                        return Ok(au);
                    }
                }
            }
            Err(_) => break,
        }
        if pending.len() > 8 * 1024 * 1024 {
            break;
        }
    }
    let mut out = std::mem::take(pending);
    if matches!(out.get(0..4), Some(b"DKIF")) {
        out = strip_ivf(&out);
    }
    if out.is_empty() {
        return Err(msg("ffmpeg packet was empty"));
    }
    Ok(out)
}

fn strip_ivf(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() < 44 {
        return bytes.to_vec();
    }
    let size = u32::from_le_bytes(bytes[32..36].try_into().unwrap()) as usize;
    let start = 44.min(bytes.len());
    let end = start.saturating_add(size).min(bytes.len());
    bytes[start..end].to_vec()
}

fn which(name: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return Some(exe.to_string_lossy().into_owned());
            }
        }
    }
    None
}

fn encoder_list(binary: &str) -> Vec<String> {
    let Ok(output) = process::hidden(binary)
        .args(["-hide_banner", "-encoders"])
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&output.stdout);
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            let flags = parts.next()?;
            if !flags.contains('V') {
                return None;
            }
            parts.next().map(str::to_string)
        })
        .collect()
}

fn candidate_names(codec: Codec, hardware: bool) -> &'static [&'static str] {
    match (codec, hardware) {
        // VAAPI before QSV: many Intel iGPUs only expose EncSliceLP via VAAPI;
        // ffmpeg still lists h264_qsv and then fails at MFX open.
        (Codec::H264, true) => &[
            "h264_nvenc",
            "h264_vaapi",
            "h264_qsv",
            "h264_amf",
            "h264_videotoolbox",
            "h264_mf",
        ],
        (Codec::H264, false) => &["libx264"],
        (Codec::H265, true) => &[
            "hevc_nvenc",
            "hevc_vaapi",
            "hevc_qsv",
            "hevc_amf",
            "hevc_videotoolbox",
            "hevc_mf",
        ],
        (Codec::H265, false) => &["libx265"],
        (Codec::Av1, true) => &["av1_nvenc", "av1_vaapi", "av1_qsv", "av1_amf"],
        (Codec::Av1, false) => &["libsvtav1", "librav1e", "libaom-av1"],
        (Codec::Vp9, true) => &[],
        (Codec::Vp9, false) => &["libvpx-vp9"],
    }
}

/// Encode one solid frame. ffmpeg can spawn an "encoder" that never emits a
/// packet (h264_qsv without a working MFX session). Reject those before the
/// session falls through to minih264 and poisons the process-wide hardware flag.
fn confirm_hardware_encoder(mut encoder: FfmpegEncoder) -> Result<FfmpegEncoder> {
    let width = encoder.request.width.max(16);
    let height = encoder.request.height.max(16);
    let stride = width * 4;
    let pixels = vec![16u8; (stride * height) as usize];
    let frame = Frame::from_bgra(width, height, stride, &pixels, "ffmpeg-probe")
        .map_err(|err| msg(err.to_string()))?;
    match encoder.encode(&frame, true) {
        Ok(unit) if !unit.bytes.is_empty() => {
            // Re-open so the session's first access unit is a clean IDR and not
            // a leftover P-frame after this discarded probe.
            let request = encoder.request;
            let name = encoder.name.clone();
            let hardware = encoder.hardware;
            let vaapi = encoder.vaapi.clone();
            drop(encoder);
            FfmpegEncoder::spawn("ffmpeg", &request, &name, hardware, vaapi)
        }
        Ok(_) => Err(encoder.packet_error("ffmpeg produced empty probe packet")),
        Err(err) => Err(err),
    }
}

/// A compiled encoder name is not a device. NVENC needs an NVIDIA node,
/// VAAPI and QSV need a DRM render node, VideoToolbox is macOS, and the
/// Media Foundation / AMF names are the Windows ffmpeg builds.
fn hardware_device_present(name: &str) -> bool {
    if name.contains("videotoolbox") {
        return videotoolbox_device_present();
    }
    if name.contains("_mf") || name.ends_with("_amf") {
        return cfg!(target_os = "windows");
    }
    if name.contains("nvenc") {
        return nvidia_device_present();
    }
    if name.contains("qsv") || name.contains("vaapi") {
        return find_render_node().is_some();
    }
    false
}

fn videotoolbox_device_present() -> bool {
    #[cfg(target_os = "macos")]
    {
        super::videotoolbox::device_can_encode()
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

fn nvidia_device_present() -> bool {
    #[cfg(target_os = "linux")]
    {
        std::path::Path::new("/dev/nvidia0").exists()
            || std::path::Path::new("/dev/nvidiactl").exists()
    }
    #[cfg(target_os = "windows")]
    {
        // The in-process Media Foundation path is the Windows hardware
        // encoder. ffmpeg's NVENC wrapper is only used when the driver node
        // is visible to a later probe; this build does not guess.
        false
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qp_mapping_anchors_and_monotonic() {
        assert_eq!(vaapi_bitrate_to_qp(100_000), 34);
        assert_eq!(vaapi_bitrate_to_qp(12_000_000), 18);
        // Mid-band: 2 Mbps should land near the middle of 18..34.
        let mid = vaapi_bitrate_to_qp(2_000_000);
        assert!((22..=30).contains(&mid), "2 Mbps qp={mid}");
        assert!(vaapi_bitrate_to_qp(500_000) > vaapi_bitrate_to_qp(4_000_000));
        assert!(vaapi_bitrate_to_qp(50_000) == 34);
        assert!(vaapi_bitrate_to_qp(50_000_000) == 18);
    }

    #[test]
    fn stderr_tail_keeps_last_4kb() {
        let tail = StderrTail::new();
        let chunk = "x".repeat(3000);
        tail.push(&chunk);
        tail.push(&chunk);
        let snap = tail.snapshot();
        assert!(snap.len() <= STDERR_KEEP + 3); // leading ellipsis
        assert!(snap.ends_with('x'));
    }

    #[test]
    fn find_render_node_opens_or_none() {
        // On Linux CI without DRM this is None; on the developer box it finds one.
        let _ = find_render_node();
    }

    #[test]
    fn vaapi_probe_caches_result() {
        // First call may talk to ffmpeg; second must be instant from cache.
        let first = std::time::Instant::now();
        let _ = vaapi_probe_status();
        let _ = vaapi_probe_failure_reason();
        let first_ms = first.elapsed().as_millis();
        assert!(first_ms < 2_000, "probe took {first_ms} ms");

        let second = std::time::Instant::now();
        let again = vaapi_probe_status();
        let fail = vaapi_probe_failure_reason();
        assert!(second.elapsed().as_millis() < 50, "cached probe must be fast");
        assert!(again.is_some() || fail.is_some());
    }

    #[test]
    fn truncate_stderr_and_tail_are_utf8_safe() {
        // Multi-byte CJK chars (3 bytes each) repeated past STDERR_KEEP*2 so
        // raw byte slicing would land mid-character and panic.
        let chunk = "编码错误".repeat(800);
        let truncated = truncate_stderr(&chunk);
        assert!(truncated.len() <= STDERR_KEEP + 4);
        let tail = StderrTail::new();
        tail.push(&chunk);
        tail.push(&chunk);
        let snap = tail.snapshot();
        assert!(!snap.is_empty());
        assert!(snap.len() <= STDERR_KEEP + 4);
    }

    #[test]
    fn annexb_au_extractor_splits_back_to_back_access_units() {
        let au1 = [
            0, 0, 0, 1, 0x09, 0x10, // AUD
            0, 0, 0, 1, 0x67, 0x42, // SPS
            0, 0, 0, 1, 0x68, 0xce, // PPS
            0, 0, 0, 1, 0x65, 0x88, 0x01, // IDR (first_mb=0)
        ];
        let au2 = [
            0, 0, 0, 1, 0x09, 0x30, // AUD
            0, 0, 0, 1, 0x41, 0x9a, 0x02, // P-slice
        ];
        let mut buf = Vec::new();
        buf.extend_from_slice(&au1);
        buf.extend_from_slice(&au2);
        let extracted = split_complete_annexb_au(&mut buf, Codec::H264).expect("first AU");
        assert_eq!(extracted, au1);
        assert_eq!(buf, au2);
        assert!(split_complete_annexb_au(&mut buf, Codec::H264).is_none());
    }

    #[test]
    fn bitrate_respawn_policy_ignores_minor_qp_and_cooldown() {
        // Never respawn inside cooldown or on first frame.
        assert!(!should_respawn_for_bitrate(
            2_000_000,
            500_000,
            None,
            0,
            Duration::from_secs(10)
        ));
        assert!(!should_respawn_for_bitrate(
            2_000_000,
            500_000,
            None,
            10,
            Duration::from_secs(1)
        ));
        // Minor VAAPI QP shift (< 3) must not respawn ffmpeg.
        assert!(!should_respawn_for_bitrate(
            2_000_000,
            1_500_000,
            Some(VaapiMode::LowPowerCqp),
            10,
            Duration::from_secs(10)
        ));
        // Large VAAPI QP shift (>= 3) past cooldown does respawn.
        assert!(should_respawn_for_bitrate(
            4_000_000,
            500_000,
            Some(VaapiMode::LowPowerCqp),
            10,
            Duration::from_secs(10)
        ));
    }
}
