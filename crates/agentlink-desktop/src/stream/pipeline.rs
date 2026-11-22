//! Capture, drop unchanged frames, encode the rest.
//!
//! `next` blocks on the [`FrameSource`](crate::FrameSource) interval. Call it
//! from a dedicated thread. `Ok(None)` means the screen did not change, not
//! that the session ended.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::capture::{last_scale_us, FrameSource, Rect};
use crate::error::Result;

use super::damage::DamageTracker;
use super::encode::{EncodedAccessUnit, VideoEncoder};
use super::tap::{self, StreamTapEvent};

/// Still-desktop heartbeat so clients do not treat a quiet encode path as a stall.
///
/// Heartbeat still *encodes* a quiet frame; it must not force an IDR. On VAAPI,
/// `force_keyframe` respawns the ffmpeg child (rawvideo pipe has no mid-stream
/// IDR API). Initial IDR is `frames_sent == 0` / start `keyframe` flag; client
/// PLI/FIR/loss recovery sets `PumpControl::keyframe`.
const HEARTBEAT: Duration = Duration::from_secs(2);

/// Encode / IDR policy for one pump tick (pure; no I/O).
///
/// Returns `None` to skip the encode, or `Some(force_keyframe)`.
/// Idle heartbeat encodes without forcing IDR.
pub(crate) fn encode_force_policy(
    frame_unchanged: bool,
    dirty_empty: bool,
    client_keyframe: bool,
    need_heartbeat: bool,
    frames_sent: u64,
) -> Option<bool> {
    let force_keyframe = client_keyframe || frames_sent == 0;
    if !force_keyframe && !need_heartbeat && (frame_unchanged || dirty_empty) {
        return None;
    }
    Some(force_keyframe)
}

pub struct Pump {
    source: Box<dyn FrameSource>,
    encoder: Box<dyn VideoEncoder>,
    encoder_name: Arc<Mutex<String>>,
    damage: DamageTracker,
    bitrate: Arc<AtomicU32>,
    keyframe: Arc<AtomicBool>,
    session_id: String,
    pub frames_sent: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    /// Successful encodes (same as frames_sent when every encode is written).
    encoded_frames: Arc<AtomicU64>,
    /// Capture/encode attempts that did not produce a packet.
    dropped_frames: Arc<AtomicU64>,
    /// Exponential moving average of encode wall time, in microseconds.
    encode_us_ema: Arc<AtomicU64>,
    capture_us_ema: Arc<AtomicU64>,
    convert_us_ema: Arc<AtomicU64>,
    keyframes: Arc<AtomicU64>,
    capture_w: Arc<AtomicU32>,
    capture_h: Arc<AtomicU32>,
    encode_w: Arc<AtomicU32>,
    encode_h: Arc<AtomicU32>,
    last_error: Arc<Mutex<String>>,
    last_encoded_at: Instant,
    /// Last bitrate applied to `encoder` so we only call `set_bitrate` on real changes.
    last_bitrate: u32,
    /// Consecutive capture or encode errors for exponential backoff.
    error_streak: u32,
}

#[derive(Clone)]
pub struct PumpControl {
    pub bitrate: Arc<AtomicU32>,
    pub keyframe: Arc<AtomicBool>,
    pub frames_sent: Arc<AtomicU64>,
    pub bytes_sent: Arc<AtomicU64>,
    pub encoded_frames: Arc<AtomicU64>,
    pub dropped_frames: Arc<AtomicU64>,
    /// Sliding-average encode time in microseconds (divide by 1000 for ms).
    pub encode_us_ema: Arc<AtomicU64>,
    pub capture_us_ema: Arc<AtomicU64>,
    pub convert_us_ema: Arc<AtomicU64>,
    pub queue_us_ema: Arc<AtomicU64>,
    pub keyframes: Arc<AtomicU64>,
    pub capture_w: Arc<AtomicU32>,
    pub capture_h: Arc<AtomicU32>,
    pub encode_w: Arc<AtomicU32>,
    pub encode_h: Arc<AtomicU32>,
    /// Live encoder name (updates after hardware→software fallback).
    pub encoder_name: Arc<Mutex<String>>,
    /// Last capture or encode error. Empty when every attempted frame succeeded.
    pub last_error: Arc<Mutex<String>>,
}

impl Default for PumpControl {
    fn default() -> Self {
        Self {
            bitrate: Arc::new(AtomicU32::new(0)),
            keyframe: Arc::new(AtomicBool::new(false)),
            frames_sent: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            encoded_frames: Arc::new(AtomicU64::new(0)),
            dropped_frames: Arc::new(AtomicU64::new(0)),
            encode_us_ema: Arc::new(AtomicU64::new(0)),
            capture_us_ema: Arc::new(AtomicU64::new(0)),
            convert_us_ema: Arc::new(AtomicU64::new(0)),
            queue_us_ema: Arc::new(AtomicU64::new(0)),
            keyframes: Arc::new(AtomicU64::new(0)),
            capture_w: Arc::new(AtomicU32::new(0)),
            capture_h: Arc::new(AtomicU32::new(0)),
            encode_w: Arc::new(AtomicU32::new(0)),
            encode_h: Arc::new(AtomicU32::new(0)),
            encoder_name: Arc::new(Mutex::new(String::new())),
            last_error: Arc::new(Mutex::new(String::new())),
        }
    }
}

impl PumpControl {
    /// Sliding-average encode time in milliseconds.
    pub fn encode_ms(&self) -> f64 {
        self.encode_us_ema.load(Ordering::Relaxed) as f64 / 1000.0
    }

    pub fn capture_ms(&self) -> f64 {
        self.capture_us_ema.load(Ordering::Relaxed) as f64 / 1000.0
    }

    pub fn convert_ms(&self) -> f64 {
        self.convert_us_ema.load(Ordering::Relaxed) as f64 / 1000.0
    }

    pub fn queue_ms(&self) -> f64 {
        self.queue_us_ema.load(Ordering::Relaxed) as f64 / 1000.0
    }

    pub fn note_queue_wait(&self, wait: Duration) {
        update_encode_ema(&self.queue_us_ema, wait.as_micros() as u64);
    }

    pub fn encoder(&self) -> String {
        self.encoder_name
            .lock()
            .map(|name| name.clone())
            .unwrap_or_else(|err| err.into_inner().clone())
    }

    /// Snapshot for the meta `state` bus / close audit (no logging).
    pub fn perf_json(&self) -> serde_json::Value {
        serde_json::json!({
            "capture_ms": round2(self.capture_ms()),
            "convert_ms": round2(self.convert_ms()),
            "encode_ms": round2(self.encode_ms()),
            "queue_ms": round2(self.queue_ms()),
            "frames_sent": self.frames_sent.load(Ordering::Relaxed),
            "frames_dropped": self.dropped_frames.load(Ordering::Relaxed),
            "keyframes": self.keyframes.load(Ordering::Relaxed),
            "encoder": self.encoder(),
            "capture_w": self.capture_w.load(Ordering::Relaxed),
            "capture_h": self.capture_h.load(Ordering::Relaxed),
            "encode_w": self.encode_w.load(Ordering::Relaxed),
            "encode_h": self.encode_h.load(Ordering::Relaxed),
            "bitrate": self.bitrate.load(Ordering::Relaxed),
        })
    }
}

fn round2(v: f64) -> f64 {
    (v * 100.0).round() / 100.0
}

impl Pump {
    pub fn start(
        source: Box<dyn FrameSource>,
        encoder: Box<dyn VideoEncoder>,
        session_id: String,
        bitrate: u32,
    ) -> (Self, PumpControl) {
        let initial_bitrate = bitrate.max(100_000);
        let bitrate = Arc::new(AtomicU32::new(initial_bitrate));
        let keyframe = Arc::new(AtomicBool::new(true));
        let frames_sent = Arc::new(AtomicU64::new(0));
        let bytes_sent = Arc::new(AtomicU64::new(0));
        let encoded_frames = Arc::new(AtomicU64::new(0));
        let dropped_frames = Arc::new(AtomicU64::new(0));
        let encode_us_ema = Arc::new(AtomicU64::new(0));
        let capture_us_ema = Arc::new(AtomicU64::new(0));
        let convert_us_ema = Arc::new(AtomicU64::new(0));
        let queue_us_ema = Arc::new(AtomicU64::new(0));
        let keyframes = Arc::new(AtomicU64::new(0));
        let capture_w = Arc::new(AtomicU32::new(0));
        let capture_h = Arc::new(AtomicU32::new(0));
        let encode_w = Arc::new(AtomicU32::new(0));
        let encode_h = Arc::new(AtomicU32::new(0));
        let last_error = Arc::new(Mutex::new(String::new()));
        let encoder_name = Arc::new(Mutex::new(encoder.info().name.clone()));
        let pump = Self {
            source,
            encoder,
            encoder_name: encoder_name.clone(),
            damage: DamageTracker::new(),
            bitrate: bitrate.clone(),
            keyframe: keyframe.clone(),
            session_id,
            frames_sent: frames_sent.clone(),
            bytes_sent: bytes_sent.clone(),
            encoded_frames: encoded_frames.clone(),
            dropped_frames: dropped_frames.clone(),
            encode_us_ema: encode_us_ema.clone(),
            capture_us_ema: capture_us_ema.clone(),
            convert_us_ema: convert_us_ema.clone(),
            keyframes: keyframes.clone(),
            capture_w: capture_w.clone(),
            capture_h: capture_h.clone(),
            encode_w: encode_w.clone(),
            encode_h: encode_h.clone(),
            last_error: last_error.clone(),
            last_encoded_at: Instant::now() - HEARTBEAT,
            last_bitrate: initial_bitrate,
            error_streak: 0,
        };
        (
            pump,
            PumpControl {
                bitrate,
                keyframe,
                frames_sent,
                bytes_sent,
                encoded_frames,
                dropped_frames,
                encode_us_ema,
                capture_us_ema,
                convert_us_ema,
                queue_us_ema,
                keyframes,
                capture_w,
                capture_h,
                encode_w,
                encode_h,
                encoder_name,
                last_error,
            },
        )
    }

    pub fn next(&mut self, timeout: Duration) -> Result<Option<EncodedAccessUnit>> {
        let capture_started = Instant::now();
        let frame = match self.source.next_frame(timeout) {
            Ok(Some(frame)) => frame,
            Ok(None) => return Err(crate::error::msg("capture session ended")),
            Err(err) => {
                // One failed grab used to kill the encode thread. The client
                // then stopped the session at 8s with frames=0. Back off on
                // persistent capture errors so the pump thread does not hot-spin.
                self.dropped_frames.fetch_add(1, Ordering::Relaxed);
                self.note(&err);
                self.sleep_error_backoff(timeout);
                return Ok(None);
            }
        };
        let capture_total_us = capture_started.elapsed().as_micros() as u64;
        let scale_us = last_scale_us();
        let capture_us = capture_total_us.saturating_sub(scale_us);
        update_encode_ema(&self.capture_us_ema, capture_us);

        // Native size before scale is not available here; record post-scale
        // dimensions as both capture (what pump sees) and encode sizes.
        self.capture_w.store(frame.width, Ordering::Relaxed);
        self.capture_h.store(frame.height, Ordering::Relaxed);

        // Only forward real bitrate changes (e.g. from AIMD) — never oscillate
        // between base and a quiet/idle multiplier every tick.
        let target_bitrate = self.bitrate.load(Ordering::Relaxed).max(100_000);
        if target_bitrate != self.last_bitrate {
            self.encoder.set_bitrate(target_bitrate);
            self.last_bitrate = target_bitrate;
        }
        // Encoder name can change after hardware→minih264 fallback.
        let live_name = self.encoder.info().name;
        if let Ok(mut slot) = self.encoder_name.lock() {
            if *slot != live_name {
                *slot = live_name;
            }
        }
        let sent = self.frames_sent.load(Ordering::Relaxed);
        let client_force = self.keyframe.load(Ordering::Acquire);
        let need_heartbeat = self.last_encoded_at.elapsed() >= HEARTBEAT;
        // First picture / explicit ask force IDR; idle heartbeat does not.
        let force_idr = client_force || sent == 0;

        if frame.unchanged && !force_idr && !need_heartbeat {
            self.error_streak = 0;
            return Ok(None);
        }

        let convert_started = Instant::now();
        let dirty = if frame.unchanged {
            Vec::new()
        } else {
            self.damage.diff(&frame)
        };
        let convert_us = scale_us + convert_started.elapsed().as_micros() as u64;
        update_encode_ema(&self.convert_us_ema, convert_us);

        let Some(force) = encode_force_policy(
            frame.unchanged,
            dirty.is_empty(),
            client_force,
            need_heartbeat,
            sent,
        ) else {
            self.error_streak = 0;
            return Ok(None);
        };

        let encode_started = Instant::now();
        let packet = match self.encoder.encode(&frame, force) {
            Ok(packet) if !packet.bytes.is_empty() => packet,
            Ok(_) => {
                self.dropped_frames.fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }
            Err(err) => {
                self.dropped_frames.fetch_add(1, Ordering::Relaxed);
                self.note(&err);
                self.sleep_error_backoff(timeout);
                return Ok(None);
            }
        };
        self.error_streak = 0;
        let encode_us = encode_started.elapsed().as_micros() as u64;
        update_encode_ema(&self.encode_us_ema, encode_us);
        if force {
            let _ =
                self.keyframe
                    .compare_exchange(true, false, Ordering::Relaxed, Ordering::Relaxed);
        }
        let mut packet = packet;
        packet.captured_unix_ms = frame.captured_unix_ms;
        self.encode_w.store(packet.width, Ordering::Relaxed);
        self.encode_h.store(packet.height, Ordering::Relaxed);
        if packet.keyframe {
            self.keyframes.fetch_add(1, Ordering::Relaxed);
        }
        self.frames_sent.fetch_add(1, Ordering::Relaxed);
        self.encoded_frames.fetch_add(1, Ordering::Relaxed);
        self.bytes_sent
            .fetch_add(packet.bytes.len() as u64, Ordering::Relaxed);
        self.last_encoded_at = Instant::now();
        tap::emit(StreamTapEvent::Frame {
            session_id: self.session_id.clone(),
            frame,
            dirty,
        });
        Ok(Some(packet))
    }

    fn note(&self, err: &crate::error::DesktopError) {
        tracing::warn!(error = %err, "stream frame was not encoded");
        if let Ok(mut slot) = self.last_error.lock() {
            *slot = err.to_string();
        }
    }

    fn sleep_error_backoff(&mut self, timeout: Duration) {
        self.error_streak = self.error_streak.saturating_add(1);
        let delay = error_backoff(self.error_streak).min(timeout);
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
    }

    /// Test-only: pretend the last successful encode was `ago` in the past so
    /// the next quiet frame hits the heartbeat path without sleeping.
    #[cfg(test)]
    fn backdate_last_encoded_for_test(&mut self, ago: Duration) {
        self.last_encoded_at = Instant::now() - ago;
    }
}

/// Bounded exponential backoff on consecutive capture/encode errors
/// (15ms -> 30ms -> 60ms -> 120ms -> 240ms -> 480ms, capped at 500ms).
pub(crate) fn error_backoff(streak: u32) -> Duration {
    if streak == 0 {
        return Duration::ZERO;
    }
    let shift = streak.saturating_sub(1).min(6);
    Duration::from_millis((15u64 << shift).min(500))
}

/// EMA with α ≈ 1/8 so recent frames dominate without wild spikes.
fn update_encode_ema(slot: &AtomicU64, sample_us: u64) {
    let prev = slot.load(Ordering::Relaxed);
    let next = if prev == 0 {
        sample_us
    } else {
        prev - (prev >> 3) + (sample_us >> 3)
    };
    slot.store(next, Ordering::Relaxed);
}

/// Test helper: encode a sequence of frames with no platform capture.
pub fn encode_frames(
    frames: &[crate::capture::Frame],
    mut encoder: Box<dyn VideoEncoder>,
) -> Result<Vec<EncodedAccessUnit>> {
    let mut damage = DamageTracker::new();
    let mut out = Vec::new();
    for (index, frame) in frames.iter().enumerate() {
        let dirty = damage.diff(frame);
        if dirty.is_empty() {
            continue;
        }
        out.push(encoder.encode(frame, index == 0)?);
    }
    Ok(out)
}

pub fn full_rect(frame: &crate::capture::Frame) -> Rect {
    Rect {
        x: 0,
        y: 0,
        width: frame.width,
        height: frame.height,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Frame;
    use crate::stream::encode::{open_encoder, Codec, EncoderRequest};

    #[test]
    fn repeated_frame_is_not_encoded_again() {
        let raw = vec![20u8; 32 * 32 * 4];
        let frame = Frame::from_bgra(32, 32, 128, &raw, "pipeline").unwrap();
        let encoder = open_encoder(&EncoderRequest {
            codec: Codec::H264,
            width: 32,
            height: 32,
            src_width: 0,
            src_height: 0,
            fps: 10,
            bitrate: 200_000,
        })
        .unwrap();
        let packets = encode_frames(&[frame.clone(), frame.clone()], encoder).unwrap();
        assert_eq!(packets.len(), 1);
        assert_eq!(full_rect(&frame).width, 32);
        assert_eq!(full_rect(&frame).height, 32);
    }

    struct Seq {
        frames: Vec<Frame>,
    }

    impl FrameSource for Seq {
        fn next_frame(&mut self, _: Duration) -> Result<Option<Frame>> {
            if self.frames.is_empty() {
                return Ok(None);
            }
            Ok(Some(self.frames.remove(0)))
        }
        fn mode(&self) -> crate::capture::StreamMode {
            crate::capture::StreamMode::Surface {
                backend: "test".into(),
            }
        }
    }

    struct Flaky {
        fails_left: u32,
        saw_force: bool,
    }

    impl crate::stream::encode::VideoEncoder for Flaky {
        fn info(&self) -> crate::stream::encode::EncoderInfo {
            crate::stream::encode::EncoderInfo {
                name: "flaky".into(),
                codec: Codec::H264,
                hardware: false,
            }
        }
        fn encode(
            &mut self,
            frame: &Frame,
            force_keyframe: bool,
        ) -> Result<crate::stream::encode::EncodedAccessUnit> {
            if self.fails_left > 0 {
                self.fails_left -= 1;
                return Err(crate::error::msg("encode failed"));
            }
            self.saw_force = force_keyframe;
            Ok(crate::stream::encode::EncodedAccessUnit {
                codec: Codec::H264,
                bytes: vec![0, 0, 0, 1, 0x65],
                keyframe: force_keyframe,
                width: frame.width,
                height: frame.height,
                captured_unix_ms: frame.captured_unix_ms,
            })
        }
        fn set_bitrate(&mut self, _: u32) {}
    }

    fn solid() -> Frame {
        Frame::from_bgra(16, 16, 64, &vec![9u8; 16 * 16 * 4], "test").unwrap()
    }

    #[test]
    fn encode_error_keeps_the_session_and_the_keyframe() {
        let frame = solid();
        let mut unchanged = frame.clone();
        unchanged.mark_unchanged();
        let encoder = Flaky {
            fails_left: 1,
            saw_force: false,
        };
        let (mut pump, control) = Pump::start(
            Box::new(Seq {
                frames: vec![
                    frame.clone(),
                    unchanged.clone(),
                    unchanged.clone(),
                    unchanged,
                ],
            }),
            Box::new(encoder),
            "s".into(),
            200_000,
        );
        assert!(pump.next(Duration::from_millis(1)).unwrap().is_none());
        assert_eq!(control.frames_sent.load(Ordering::Relaxed), 0);
        assert!(control.keyframe.load(Ordering::Relaxed));
        assert!(control.last_error.lock().unwrap().contains("encode failed"));
        let packet = pump.next(Duration::from_millis(1)).unwrap().unwrap();
        assert!(!packet.bytes.is_empty());
        assert!(packet.keyframe);
        assert_eq!(control.frames_sent.load(Ordering::Relaxed), 1);
        assert!(!control.keyframe.load(Ordering::Relaxed));
        // A quiet desktop does not encode again until another keyframe is asked for.
        assert!(pump.next(Duration::from_millis(1)).unwrap().is_none());
        control.keyframe.store(true, Ordering::Relaxed);
        let again = pump.next(Duration::from_millis(1)).unwrap().unwrap();
        assert!(again.keyframe);
        assert_eq!(control.frames_sent.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn perf_json_exposes_timing_fields() {
        let encoder = Flaky {
            fails_left: 0,
            saw_force: false,
        };
        let (_pump, control) = Pump::start(
            Box::new(Seq {
                frames: vec![solid()],
            }),
            Box::new(encoder),
            "s".into(),
            200_000,
        );
        let snap = control.perf_json();
        assert!(snap.get("capture_ms").is_some());
        assert!(snap.get("convert_ms").is_some());
        assert!(snap.get("encode_ms").is_some());
        assert!(snap.get("queue_ms").is_some());
        assert!(snap.get("frames_sent").is_some());
    }

    /// Records every `force_keyframe` argument the pump passes into encode.
    struct Recording {
        forces: Arc<Mutex<Vec<bool>>>,
    }

    impl crate::stream::encode::VideoEncoder for Recording {
        fn info(&self) -> crate::stream::encode::EncoderInfo {
            crate::stream::encode::EncoderInfo {
                name: "recording".into(),
                codec: Codec::H264,
                hardware: false,
            }
        }
        fn encode(
            &mut self,
            frame: &Frame,
            force_keyframe: bool,
        ) -> Result<crate::stream::encode::EncodedAccessUnit> {
            self.forces.lock().unwrap().push(force_keyframe);
            Ok(crate::stream::encode::EncodedAccessUnit {
                codec: Codec::H264,
                bytes: vec![0, 0, 0, 1, if force_keyframe { 0x65 } else { 0x41 }],
                keyframe: force_keyframe,
                width: frame.width,
                height: frame.height,
                captured_unix_ms: frame.captured_unix_ms,
            })
        }
        fn set_bitrate(&mut self, _: u32) {}
    }

    fn solid_color(byte: u8) -> Frame {
        Frame::from_bgra(16, 16, 64, &vec![byte; 16 * 16 * 4], "test").unwrap()
    }

    #[test]
    fn encode_force_policy_idle_heartbeat_does_not_force_idr() {
        // Quiet desktop past HEARTBEAT: encode, but not as IDR.
        assert_eq!(
            encode_force_policy(true, true, false, true, 3),
            Some(false)
        );
        // Within HEARTBEAT and quiet: skip entirely.
        assert_eq!(encode_force_policy(true, true, false, false, 3), None);
        assert_eq!(encode_force_policy(false, true, false, false, 3), None);
    }

    #[test]
    fn encode_force_policy_first_frame_and_explicit_request_force_idr() {
        assert_eq!(
            encode_force_policy(false, false, false, false, 0),
            Some(true),
            "first frame forces IDR"
        );
        assert_eq!(
            encode_force_policy(true, true, true, false, 5),
            Some(true),
            "explicit client PLI/FIR/keyframe forces IDR even on unchanged"
        );
        assert_eq!(
            encode_force_policy(true, true, true, true, 5),
            Some(true),
            "explicit ask wins over idle heartbeat"
        );
    }

    #[test]
    fn encode_force_policy_dirty_frame_unchanged_idr_rules() {
        assert_eq!(
            encode_force_policy(false, false, false, false, 4),
            Some(false),
            "real dirty frame encodes without forced IDR"
        );
        assert_eq!(
            encode_force_policy(false, false, false, true, 4),
            Some(false),
            "dirty + heartbeat still does not force IDR"
        );
    }

    #[test]
    fn pump_idle_heartbeat_encodes_without_forcing_idr() {
        let forces = Arc::new(Mutex::new(Vec::new()));
        let mut quiet = solid();
        quiet.mark_unchanged();
        let (mut pump, control) = Pump::start(
            Box::new(Seq {
                frames: vec![solid(), quiet.clone(), quiet],
            }),
            Box::new(Recording {
                forces: forces.clone(),
            }),
            "s".into(),
            200_000,
        );
        let first = pump.next(Duration::from_millis(1)).unwrap().unwrap();
        assert!(first.keyframe, "first picture is an IDR");
        assert_eq!(forces.lock().unwrap().as_slice(), &[true]);
        assert!(!control.keyframe.load(Ordering::Relaxed));

        // Quiet tick inside HEARTBEAT: no encode.
        assert!(pump.next(Duration::from_millis(1)).unwrap().is_none());
        assert_eq!(forces.lock().unwrap().len(), 1);

        // Backdate past HEARTBEAT: encode a non-IDR keepalive.
        pump.backdate_last_encoded_for_test(HEARTBEAT + Duration::from_millis(1));
        let beat = pump.next(Duration::from_millis(1)).unwrap().unwrap();
        assert!(!beat.keyframe, "idle heartbeat must not force IDR");
        assert_eq!(forces.lock().unwrap().as_slice(), &[true, false]);
        assert_eq!(control.frames_sent.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn pump_explicit_keyframe_request_forces_idr_on_quiet_desktop() {
        let forces = Arc::new(Mutex::new(Vec::new()));
        let mut quiet = solid();
        quiet.mark_unchanged();
        let (mut pump, control) = Pump::start(
            Box::new(Seq {
                frames: vec![solid(), quiet.clone(), quiet],
            }),
            Box::new(Recording {
                forces: forces.clone(),
            }),
            "s".into(),
            200_000,
        );
        assert!(pump.next(Duration::from_millis(1)).unwrap().unwrap().keyframe);
        assert!(pump.next(Duration::from_millis(1)).unwrap().is_none());
        control.keyframe.store(true, Ordering::Relaxed);
        let again = pump.next(Duration::from_millis(1)).unwrap().unwrap();
        assert!(again.keyframe);
        assert_eq!(forces.lock().unwrap().as_slice(), &[true, true]);
    }

    #[test]
    fn pump_dirty_frame_encodes_without_forced_idr() {
        let forces = Arc::new(Mutex::new(Vec::new()));
        let (mut pump, _) = Pump::start(
            Box::new(Seq {
                frames: vec![solid_color(1), solid_color(200)],
            }),
            Box::new(Recording {
                forces: forces.clone(),
            }),
            "s".into(),
            200_000,
        );
        assert!(pump.next(Duration::from_millis(1)).unwrap().unwrap().keyframe);
        let dirty = pump.next(Duration::from_millis(1)).unwrap().unwrap();
        assert!(!dirty.keyframe, "content change is a delta, not a forced IDR");
        assert_eq!(forces.lock().unwrap().as_slice(), &[true, false]);
    }

    #[test]
    fn pump_does_not_oscillate_bitrate_on_quiet_heartbeat() {
        struct BitrateSpy {
            calls: Arc<Mutex<Vec<u32>>>,
        }
        impl crate::stream::encode::VideoEncoder for BitrateSpy {
            fn info(&self) -> crate::stream::encode::EncoderInfo {
                crate::stream::encode::EncoderInfo {
                    name: "spy".into(),
                    codec: Codec::H264,
                    hardware: false,
                }
            }
            fn encode(
                &mut self,
                frame: &Frame,
                force_keyframe: bool,
            ) -> Result<crate::stream::encode::EncodedAccessUnit> {
                Ok(crate::stream::encode::EncodedAccessUnit {
                    codec: Codec::H264,
                    bytes: vec![0, 0, 0, 1, if force_keyframe { 0x65 } else { 0x41 }],
                    keyframe: force_keyframe,
                    width: frame.width,
                    height: frame.height,
                    captured_unix_ms: frame.captured_unix_ms,
                })
            }
            fn set_bitrate(&mut self, bitrate: u32) {
                self.calls.lock().unwrap().push(bitrate);
            }
        }
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut quiet = solid();
        quiet.mark_unchanged();
        let (mut pump, control) = Pump::start(
            Box::new(Seq {
                frames: vec![solid(), quiet.clone(), quiet.clone(), solid_color(55)],
            }),
            Box::new(BitrateSpy {
                calls: calls.clone(),
            }),
            "s".into(),
            2_000_000,
        );
        let _ = pump.next(Duration::from_millis(1)).unwrap();
        let _ = pump.next(Duration::from_millis(1)).unwrap();
        pump.backdate_last_encoded_for_test(HEARTBEAT + Duration::from_millis(1));
        let _ = pump.next(Duration::from_millis(1)).unwrap();
        assert!(
            calls.lock().unwrap().is_empty(),
            "quiet/heartbeat frames must not oscillate set_bitrate: {:?}",
            calls.lock().unwrap()
        );
        // An explicit AIMD change is forwarded once.
        control.bitrate.store(1_200_000, Ordering::Relaxed);
        let _ = pump.next(Duration::from_millis(1)).unwrap();
        assert_eq!(calls.lock().unwrap().as_slice(), &[1_200_000]);
    }

    #[test]
    fn error_backoff_grows_and_caps() {
        assert_eq!(error_backoff(0), Duration::ZERO);
        assert_eq!(error_backoff(1), Duration::from_millis(15));
        assert!(error_backoff(3) > error_backoff(1));
        assert_eq!(error_backoff(10), Duration::from_millis(500));
    }
}
