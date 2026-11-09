//! Tile hashes for dirty rectangles.
//!
//! A static desktop produces an empty list, and the stream sends nothing.
//! Platform damage (XDamage, DXGI timeout, ScreenCaptureKit, PipeWire) can
//! skip the copy entirely; this pass still runs when the backend always
//! returns pixels, including the mock desktop used in CI.

use crate::capture::{Frame, Rect};

const TILE: u32 = 64;

pub struct DamageTracker {
    prev: Vec<u64>,
    width: u32,
    height: u32,
    tiles_x: u32,
    tiles_y: u32,
}

impl DamageTracker {
    pub fn new() -> Self {
        Self {
            prev: Vec::new(),
            width: 0,
            height: 0,
            tiles_x: 0,
            tiles_y: 0,
        }
    }

    /// Rectangles that differ from the previous frame, in frame pixels.
    ///
    /// The first frame is fully dirty. An `unchanged` frame is empty and does
    /// not replace the stored hashes.
    pub fn diff(&mut self, frame: &Frame) -> Vec<Rect> {
        if frame.unchanged {
            return Vec::new();
        }
        let tiles_x = frame.width.div_ceil(TILE).max(1);
        let tiles_y = frame.height.div_ceil(TILE).max(1);
        let count = (tiles_x * tiles_y) as usize;
        if self.width != frame.width || self.height != frame.height || self.prev.len() != count {
            self.width = frame.width;
            self.height = frame.height;
            self.tiles_x = tiles_x;
            self.tiles_y = tiles_y;
            self.prev = hash_tiles(frame, tiles_x, tiles_y);
            return vec![Rect {
                x: 0,
                y: 0,
                width: frame.width,
                height: frame.height,
            }];
        }
        let next = hash_tiles(frame, tiles_x, tiles_y);
        let mut dirty = Vec::new();
        for index in 0..count {
            if next[index] == self.prev[index] {
                continue;
            }
            let tx = index as u32 % tiles_x;
            let ty = index as u32 / tiles_x;
            let x = tx * TILE;
            let y = ty * TILE;
            dirty.push(Rect {
                x: x as i32,
                y: y as i32,
                width: TILE.min(frame.width - x),
                height: TILE.min(frame.height - y),
            });
        }
        self.prev = next;
        dirty
    }
}

impl Default for DamageTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub fn dirty_rects(previous: Option<&Frame>, frame: &Frame) -> Vec<Rect> {
    let mut tracker = DamageTracker::new();
    if let Some(previous) = previous {
        let _ = tracker.diff(previous);
    }
    tracker.diff(frame)
}

fn hash_tiles(frame: &Frame, tiles_x: u32, tiles_y: u32) -> Vec<u64> {
    let mut hashes = vec![0u64; (tiles_x * tiles_y) as usize];
    let pixels = frame.pixels();
    let stride = frame.stride as usize;
    for ty in 0..tiles_y {
        for tx in 0..tiles_x {
            let x = tx * TILE;
            let y = ty * TILE;
            let tw = TILE.min(frame.width - x) as usize;
            let th = TILE.min(frame.height - y) as usize;
            let mut hash = 0xcbf29ce484222325u64;
            for row in 0..th {
                let start = (y as usize + row) * stride + x as usize * 4;
                let end = start + tw * 4;
                let row_bytes = &pixels[start..end];
                for chunk in row_bytes.chunks_exact(8) {
                    let value = u64::from_le_bytes(chunk.try_into().unwrap());
                    hash ^= value;
                    hash = hash.wrapping_mul(0x100000001b3);
                }
                let rest = row_bytes.len() % 8;
                if rest != 0 {
                    for byte in &row_bytes[row_bytes.len() - rest..] {
                        hash ^= *byte as u64;
                        hash = hash.wrapping_mul(0x100000001b3);
                    }
                }
            }
            hashes[(ty * tiles_x + tx) as usize] = hash;
        }
    }
    hashes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn solid(width: u32, height: u32, fill: u8) -> Frame {
        let mut raw = vec![fill; width as usize * height as usize * 4];
        for pixel in raw.chunks_exact_mut(4) {
            pixel[3] = 255;
        }
        Frame::from_bgra(width, height, width * 4, &raw, "test").unwrap()
    }

    #[test]
    fn static_frame_is_empty_and_one_pixel_is_one_tile() {
        let mut tracker = DamageTracker::new();
        let first = solid(128, 64, 10);
        let dirty = tracker.diff(&first);
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].width, 128);

        let again = solid(128, 64, 10);
        assert!(tracker.diff(&again).is_empty());

        let mut changed = solid(128, 64, 10);
        let mut pixels = ArcPixels::from_frame(&changed);
        pixels.set(70, 10, 200);
        changed = pixels.finish();
        let dirty = tracker.diff(&changed);
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].x, 64);
        assert_eq!(dirty[0].y, 0);
        let from_helper = dirty_rects(Some(&again), &changed);
        assert_eq!(from_helper.len(), 1);
        assert_eq!(from_helper[0].x, 64);
    }

    #[test]
    fn unchanged_flag_skips_the_hash() {
        let mut tracker = DamageTracker::new();
        let frame = solid(32, 32, 1);
        let _ = tracker.diff(&frame);
        let mut marked = frame.clone();
        marked.mark_unchanged();
        assert!(tracker.diff(&marked).is_empty());
    }

    struct ArcPixels {
        width: u32,
        height: u32,
        raw: Vec<u8>,
    }

    impl ArcPixels {
        fn from_frame(frame: &Frame) -> Self {
            Self {
                width: frame.width,
                height: frame.height,
                raw: frame.pixels().to_vec(),
            }
        }

        fn set(&mut self, x: u32, y: u32, value: u8) {
            let index = (y * self.width + x) as usize * 4;
            self.raw[index] = value;
        }

        fn finish(self) -> Frame {
            Frame::from_bgra(self.width, self.height, self.width * 4, &self.raw, "test").unwrap()
        }
    }
}
