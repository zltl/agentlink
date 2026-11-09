//! Synthetic capture/encode cost. CI runs the assertions. The numbers printed
//! here are what the README quotes for a static desktop, typing, and video.
//!
//! This is the encoder and the damage tracker, not a browser decode. WebRTC
//! loopback latency is measured separately when UDP works.

use std::time::Instant;

use crate::capture::Frame;

use super::damage::DamageTracker;
use super::encode::{open_encoder, Codec, EncoderRequest};

pub struct BenchRow {
    pub name: &'static str,
    pub frames: u32,
    pub encoded: u32,
    pub bytes: u64,
    pub cpu_ms: u128,
    pub wall_ms: u128,
    pub first_encode_ms: u128,
}

pub fn run() -> Vec<BenchRow> {
    let width = 640u32;
    let height = 360u32;
    let mut rows = Vec::new();
    rows.push(measure("static", width, height, 30, |index, pixels| {
        if index == 0 {
            fill(pixels, 40, 80, 120);
        }
    }));
    rows.push(measure("typing", width, height, 30, |index, pixels| {
        fill(pixels, 40, 80, 120);
        let offset = ((index as usize) % 200) * 4;
        if offset + 3 < pixels.len() {
            pixels[offset] = 255;
            pixels[offset + 1] = 255;
            pixels[offset + 2] = 255;
        }
    }));
    rows.push(measure("video", width, height, 20, |index, pixels| {
        for (byte, value) in pixels.iter_mut().enumerate() {
            *value = ((byte as u32).wrapping_mul(17).wrapping_add(index * 13)) as u8;
        }
    }));
    rows
}

fn measure(
    name: &'static str,
    width: u32,
    height: u32,
    frames: u32,
    paint: impl Fn(u32, &mut [u8]),
) -> BenchRow {
    let encoder = open_encoder(&EncoderRequest {
        codec: Codec::H264,
        width,
        height,
        src_width: 0,
        src_height: 0,
        fps: 30,
        bitrate: 2_000_000,
    })
    .expect("software encoder");
    let mut encoder = encoder;
    let mut damage = DamageTracker::new();
    let mut pixels = vec![0u8; (width * height * 4) as usize];
    let cpu_before = cpu_ms();
    let started = Instant::now();
    let mut encoded = 0u32;
    let mut bytes = 0u64;
    let mut first_encode_ms = 0u128;
    for index in 0..frames {
        paint(index, &mut pixels);
        let frame =
            Frame::from_bgra(width, height, width * 4, &pixels, "bench").expect("bench frame");
        let dirty = damage.diff(&frame);
        if dirty.is_empty() {
            continue;
        }
        let encode_started = Instant::now();
        let packet = encoder
            .encode(&frame, encoded == 0)
            .expect("encode bench frame");
        if encoded == 0 {
            first_encode_ms = encode_started.elapsed().as_millis();
        }
        encoded += 1;
        bytes += packet.bytes.len() as u64;
    }
    BenchRow {
        name,
        frames,
        encoded,
        bytes,
        cpu_ms: cpu_ms().saturating_sub(cpu_before),
        wall_ms: started.elapsed().as_millis(),
        first_encode_ms,
    }
}

fn fill(pixels: &mut [u8], b: u8, g: u8, r: u8) {
    for chunk in pixels.chunks_exact_mut(4) {
        chunk[0] = b;
        chunk[1] = g;
        chunk[2] = r;
        chunk[3] = 255;
    }
}

fn cpu_ms() -> u128 {
    #[cfg(target_os = "linux")]
    {
        let Ok(text) = std::fs::read_to_string("/proc/self/stat") else {
            return 0;
        };
        let rest = text.split_once(')').map(|(_, rest)| rest).unwrap_or("");
        let fields: Vec<&str> = rest.split_whitespace().collect();
        // After the comm field, utime is index 11 and stime is index 12 (0-based).
        let utime: u64 = fields.get(11).and_then(|v| v.parse().ok()).unwrap_or(0);
        let stime: u64 = fields.get(12).and_then(|v| v.parse().ok()).unwrap_or(0);
        let ticks = utime + stime;
        let hz = 100u128;
        return (ticks as u128) * 1000 / hz;
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_desktop_encodes_one_frame_and_then_nothing() {
        let rows = run();
        let static_row = rows.iter().find(|row| row.name == "static").unwrap();
        assert_eq!(static_row.encoded, 1, "static rows {rows:?}");
        let typing = rows.iter().find(|row| row.name == "typing").unwrap();
        assert!(typing.encoded > 1, "typing should encode the changed tiles");
        assert!(typing.bytes < rows.iter().find(|row| row.name == "video").unwrap().bytes);
        eprintln!("agentlink stream bench");
        for row in &rows {
            // Presentation bitrate over frames/30s, not the encoder's burst.
            let presented_ms = (row.frames as u128 * 1000 / 30).max(1);
            let kbps = row.bytes * 8 * 1000 / presented_ms as u64 / 1000;
            let cpu_pct = row.cpu_ms * 100 / presented_ms;
            eprintln!(
                "  {}: encoded {}/{} frames, {} bytes, ~{} kbps over {:.2}s, cpu {} ms ({}% of one core), wall {} ms, first encode {} ms",
                row.name,
                row.encoded,
                row.frames,
                row.bytes,
                kbps,
                presented_ms as f64 / 1000.0,
                row.cpu_ms,
                cpu_pct,
                row.wall_ms,
                row.first_encode_ms
            );
        }
    }
}

impl std::fmt::Debug for BenchRow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} encoded={}/{} bytes={} cpu_ms={} wall_ms={} first_encode_ms={}",
            self.name,
            self.encoded,
            self.frames,
            self.bytes,
            self.cpu_ms,
            self.wall_ms,
            self.first_encode_ms
        )
    }
}
