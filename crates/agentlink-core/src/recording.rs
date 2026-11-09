//! Screen recording contract for a later capture backend.
//!
//! Phase 2 owns pixels. This module owns the trait those handlers implement,
//! plus a keyframe-and-tile archive that does not need a system H.264 or AV1
//! encoder. When a `FrameSource` is registered the node samples it at the
//! configured rate. Without one, recording stays a logged gap instead of a
//! fake video.

use std::io::{Read, Write};

use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

pub const ARCHIVE_MAGIC: &[u8] = b"AGLKREC1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordMode {
    Off,
    /// While a GUI-control session (screenshot, input, accessibility) is active.
    Gui,
    /// While an agent is connected to this node.
    Always,
}

impl RecordMode {
    pub fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "gui" => Some(Self::Gui),
            "always" => Some(Self::Always),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// Implemented by the phase-2 screenshot handler, or by a test double.
///
/// A `NodeExtension` named `screenshot` can adapt to this by returning JSON
/// `{ "width": N, "height": N, "rgba_b64": "..." }`. The node wraps that
/// extension when it is registered and no other source is set.
pub trait FrameSource: Send + Sync {
    fn grab(&self) -> std::result::Result<CapturedFrame, String>;
}

/// One stored segment. Keyframes are deflate-compressed RGBA. Later frames
/// store only the 32×32 tiles that changed, also deflated. The audit log
/// points at the file with the same `session_id`.
#[derive(Debug, Clone)]
pub struct Segment {
    pub session_id: String,
    pub bytes: Vec<u8>,
    pub frames: u32,
}

pub fn encode_segment(session_id: &str, frames: &[CapturedFrame], quality: &str) -> Segment {
    let step = match quality {
        "high" => 1,
        "medium" => 2,
        _ => 4,
    };
    let mut out = ARCHIVE_MAGIC.to_vec();
    out.extend_from_slice(&(session_id.len() as u16).to_le_bytes());
    out.extend_from_slice(session_id.as_bytes());
    let mut prev: Option<CapturedFrame> = None;
    let mut kept = 0u32;
    for (index, frame) in frames.iter().enumerate() {
        let key = index % 10 == 0 || prev.is_none();
        if key {
            out.push(1);
            out.extend_from_slice(&frame.width.to_le_bytes());
            out.extend_from_slice(&frame.height.to_le_bytes());
            let payload = deflate(&downsample(&frame.rgba, frame.width, frame.height, step));
            out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
            out.extend_from_slice(&payload);
            prev = Some(frame.clone());
            kept += 1;
            continue;
        }
        let Some(prev_frame) = prev.as_ref() else {
            continue;
        };
        let tiles = delta_tiles(prev_frame, frame, step);
        out.push(2);
        out.extend_from_slice(&(tiles.len() as u32).to_le_bytes());
        out.extend_from_slice(&tiles);
        prev = Some(frame.clone());
        kept += 1;
    }
    Segment {
        session_id: session_id.to_string(),
        bytes: out,
        frames: kept,
    }
}

pub fn segment_session(bytes: &[u8]) -> Option<String> {
    if bytes.len() < ARCHIVE_MAGIC.len() + 2 || &bytes[..ARCHIVE_MAGIC.len()] != ARCHIVE_MAGIC {
        return None;
    }
    let len =
        u16::from_le_bytes([bytes[ARCHIVE_MAGIC.len()], bytes[ARCHIVE_MAGIC.len() + 1]]) as usize;
    let start = ARCHIVE_MAGIC.len() + 2;
    bytes
        .get(start..start + len)
        .and_then(|s| String::from_utf8(s.to_vec()).ok())
}

fn downsample(rgba: &[u8], width: u32, height: u32, step: usize) -> Vec<u8> {
    if step <= 1 {
        return rgba.to_vec();
    }
    let mut out = Vec::new();
    let step = step as u32;
    let mut y = 0;
    while y < height {
        let mut x = 0;
        while x < width {
            let i = ((y * width + x) * 4) as usize;
            if i + 4 <= rgba.len() {
                out.extend_from_slice(&rgba[i..i + 4]);
            }
            x += step;
        }
        y += step;
    }
    out
}

fn delta_tiles(prev: &CapturedFrame, next: &CapturedFrame, step: usize) -> Vec<u8> {
    let mut raw = Vec::new();
    if prev.width != next.width || prev.height != next.height {
        return deflate(&next.rgba);
    }
    let tile = 32u32;
    let mut ty = 0u32;
    let mut index = 0u32;
    while ty < next.height {
        let mut tx = 0u32;
        while tx < next.width {
            let mut changed = false;
            let y_end = (ty + tile).min(next.height);
            let x_end = (tx + tile).min(next.width);
            let mut y = ty;
            while y < y_end && !changed {
                let mut x = tx;
                while x < x_end {
                    let i = ((y * next.width + x) * 4) as usize;
                    if prev.rgba.get(i..i + 4) != next.rgba.get(i..i + 4) {
                        changed = true;
                        break;
                    }
                    x += step.max(1) as u32;
                }
                y += step.max(1) as u32;
            }
            if changed {
                raw.extend_from_slice(&index.to_le_bytes());
                let mut tile_bytes = Vec::new();
                let mut y = ty;
                while y < y_end {
                    let mut x = tx;
                    while x < x_end {
                        let i = ((y * next.width + x) * 4) as usize;
                        if i + 4 <= next.rgba.len() {
                            tile_bytes.extend_from_slice(&next.rgba[i..i + 4]);
                        }
                        x += step.max(1) as u32;
                    }
                    y += step.max(1) as u32;
                }
                let packed = deflate(&tile_bytes);
                raw.extend_from_slice(&(packed.len() as u32).to_le_bytes());
                raw.extend_from_slice(&packed);
            }
            index += 1;
            tx += tile;
        }
        ty += tile;
    }
    raw
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::fast());
    enc.write_all(data).ok();
    enc.finish().unwrap_or_default()
}

pub fn inflate(data: &[u8]) -> Vec<u8> {
    let mut dec = DeflateDecoder::new(data);
    let mut out = Vec::new();
    dec.read_to_end(&mut out).ok();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Stub;

    impl FrameSource for Stub {
        fn grab(&self) -> std::result::Result<CapturedFrame, String> {
            Ok(CapturedFrame {
                width: 16,
                height: 16,
                rgba: vec![9u8; 16 * 16 * 4],
            })
        }
    }

    #[test]
    fn keyframe_archive_round_trips_the_session_id() {
        let source = Stub;
        let first = source.grab().unwrap();
        let mut second = first.clone();
        second.rgba[0] = 1;
        let segment = encode_segment("sess-1", &[first, second], "low");
        assert!(segment.bytes.starts_with(ARCHIVE_MAGIC));
        assert_eq!(segment_session(&segment.bytes).as_deref(), Some("sess-1"));
        assert!(segment.frames >= 2);
        assert!(segment.bytes.len() < 16 * 16 * 4 * 2);
    }
}
