//! JPEG fallback and H.264 Annex-B to RGBA for the controller window.
//!
//! The live path is the same WebRTC viewer the phone uses. OpenH264 is
//! compiled into this build and turns those access units into pixels. A
//! screenshot invoke is only used until the first decoded H.264 frame, or
//! when the node has no live video.

use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use openh264::nal_units;

pub fn decode_image(bytes: &[u8]) -> Option<(Vec<u8>, usize, usize)> {
    let image = image::load_from_memory(bytes).ok()?;
    let rgba = image.to_rgba8();
    let (width, height) = rgba.dimensions();
    if width == 0 || height == 0 {
        return None;
    }
    Some((rgba.into_raw(), width as usize, height as usize))
}

#[derive(Debug)]
pub enum DecodeOutcome {
    Frame {
        rgba: Vec<u8>,
        width: usize,
        height: usize,
    },
    Pending,
    Error,
}

pub struct H264Decoder {
    inner: Option<Decoder>,
    scratch: Vec<u8>,
}

impl H264Decoder {
    pub fn new() -> Self {
        Self {
            inner: Decoder::new().ok(),
            scratch: Vec::new(),
        }
    }

    pub fn available(&self) -> bool {
        self.inner.is_some()
    }

    /// Decode an Annex-B access unit into a fresh or recycled RGBA buffer,
    /// distinguishing decode errors so callers can request an IDR and wait
    /// for a keyframe instead of feeding orphaned P-frames.
    pub fn decode_into(&mut self, annex_b: &[u8], recycle: Option<Vec<u8>>) -> DecodeOutcome {
        let Some(decoder) = self.inner.as_mut() else {
            return DecodeOutcome::Error;
        };
        if let Some(buf) = recycle {
            if buf.capacity() > self.scratch.capacity() {
                self.scratch = buf;
            }
        }
        let mut last: Option<(usize, usize)> = None;
        let mut had_error = false;
        for nal in nal_units(annex_b) {
            match decoder.decode(nal) {
                Ok(Some(yuv)) => {
                    let (width, height) = yuv.dimensions();
                    if width == 0 || height == 0 {
                        continue;
                    }
                    let need = width * height * 4;
                    if self.scratch.len() != need {
                        self.scratch.resize(need, 0);
                    }
                    // openh264's write_rgba8 is a per-pixel f32 loop (~50–100ms
                    // at 1280×864). Integer BT.601 limited-range conversion
                    // stays well under the 25ms p95 budget and preserves dark
                    // themes (Y=16 -> RGB 0,0,0).
                    i420_to_rgba8(&yuv, &mut self.scratch);
                    last = Some((width, height));
                }
                Ok(None) => {}
                Err(_) => {
                    had_error = true;
                    break;
                }
            }
        }
        if let Some((width, height)) = last {
            let rgba = std::mem::take(&mut self.scratch);
            DecodeOutcome::Frame {
                rgba,
                width,
                height,
            }
        } else if had_error {
            DecodeOutcome::Error
        } else {
            DecodeOutcome::Pending
        }
    }

    pub fn decode(&mut self, annex_b: &[u8]) -> Option<(Vec<u8>, usize, usize)> {
        match self.decode_into(annex_b, None) {
            DecodeOutcome::Frame {
                rgba,
                width,
                height,
            } => Some((rgba, width, height)),
            DecodeOutcome::Pending | DecodeOutcome::Error => None,
        }
    }
}

/// BT.601 limited-range (studio swing: Y 16..235, U/V 16..240) I420 → RGBA8.
/// Faster than openh264's f32 `write_rgba8` and avoids washed-out dark themes.
fn i420_to_rgba8(yuv: &impl YUVSource, target: &mut [u8]) {
    let (width, height) = yuv.dimensions();
    let (sy, su, sv) = yuv.strides();
    let y_plane = yuv.y();
    let u_plane = yuv.u();
    let v_plane = yuv.v();
    debug_assert_eq!(target.len(), width * height * 4);

    for row in 0..height {
        let y_row = &y_plane[row * sy..row * sy + width];
        let u_row = &u_plane[(row / 2) * su..];
        let v_row = &v_plane[(row / 2) * sv..];
        let dst_row = &mut target[row * width * 4..(row + 1) * width * 4];
        let mut x = 0;
        while x + 1 < width {
            let d_u = u_row[x / 2] as i32 - 128;
            let d_v = v_row[x / 2] as i32 - 128;
            let r_off = 409 * d_v + 128;
            let g_off = -100 * d_u - 208 * d_v + 128;
            let b_off = 516 * d_u + 128;
            for dx in 0..2 {
                let c = (y_row[x + dx] as i32 - 16).max(0);
                let y_scaled = 298 * c;
                let r = ((y_scaled + r_off) >> 8).clamp(0, 255) as u8;
                let g = ((y_scaled + g_off) >> 8).clamp(0, 255) as u8;
                let b = ((y_scaled + b_off) >> 8).clamp(0, 255) as u8;
                let o = (x + dx) * 4;
                dst_row[o] = r;
                dst_row[o + 1] = g;
                dst_row[o + 2] = b;
                dst_row[o + 3] = 255;
            }
            x += 2;
        }
        if x < width {
            let d_u = u_row[x / 2] as i32 - 128;
            let d_v = v_row[x / 2] as i32 - 128;
            let c = (y_row[x] as i32 - 16).max(0);
            let y_scaled = 298 * c;
            let r = ((y_scaled + 409 * d_v + 128) >> 8).clamp(0, 255) as u8;
            let g = ((y_scaled - 100 * d_u - 208 * d_v + 128) >> 8).clamp(0, 255) as u8;
            let b = ((y_scaled + 516 * d_u + 128) >> 8).clamp(0, 255) as u8;
            let o = x * 4;
            dst_row[o] = r;
            dst_row[o + 1] = g;
            dst_row[o + 2] = b;
            dst_row[o + 3] = 255;
        }
    }
}

/// Check if an Annex-B H.264 access unit contains an IDR slice (NAL type 5).
pub fn annex_b_has_idr(annex_b: &[u8]) -> bool {
    for nal in nal_units(annex_b) {
        let body = if nal.starts_with(&[0, 0, 0, 1]) {
            &nal[4..]
        } else if nal.starts_with(&[0, 0, 1]) {
            &nal[3..]
        } else {
            nal
        };
        if let Some(&first) = body.first() {
            if (first & 0x1f) == 5 {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use openh264::encoder::Encoder;
    use openh264::formats::YUVBuffer;

    /// Encode a tiny solid frame, then run it through the controller decode path.
    /// Asserts dimensions > 0 (not pixel-perfect quality — no golden fixture in-tree).
    #[test]
    fn h264_decode_yields_positive_dimensions() {
        // Black 16x16 I420 is enough to force SPS/PPS/IDR; no in-repo golden bitstream.
        let yuv = YUVBuffer::new(16, 16);

        let mut encoder = Encoder::new().expect("openh264 encoder opens");
        let annex_b = encoder
            .encode(&yuv)
            .expect("encode 16x16 frame")
            .to_vec();
        assert!(
            !annex_b.is_empty(),
            "encoder must emit at least SPS/PPS/IDR"
        );

        let mut decoder = H264Decoder::new();
        assert!(
            decoder.available(),
            "openh264 decoder must open in this build"
        );
        let (rgba, out_w, out_h) = decoder
            .decode(&annex_b)
            .expect("decode path must yield a frame");
        assert!(out_w > 0, "decoded width must be > 0");
        assert!(out_h > 0, "decoded height must be > 0");
        assert_eq!(rgba.len(), out_w * out_h * 4);
        assert!(annex_b_has_idr(&annex_b));
    }

    #[test]
    fn i420_to_rgba8_uses_bt601_limited_range_without_washed_out_blacks() {
        struct ConstYuv {
            y: Vec<u8>,
            u: Vec<u8>,
            v: Vec<u8>,
            w: usize,
            h: usize,
        }
        impl YUVSource for ConstYuv {
            fn dimensions(&self) -> (usize, usize) {
                (self.w, self.h)
            }
            fn strides(&self) -> (usize, usize, usize) {
                (self.w, self.w / 2, self.w / 2)
            }
            fn y(&self) -> &[u8] {
                &self.y
            }
            fn u(&self) -> &[u8] {
                &self.u
            }
            fn v(&self) -> &[u8] {
                &self.v
            }
        }
        let black = ConstYuv {
            y: vec![16; 16],
            u: vec![128; 4],
            v: vec![128; 4],
            w: 4,
            h: 4,
        };
        let mut rgba = vec![0u8; 4 * 4 * 4];
        i420_to_rgba8(&black, &mut rgba);
        assert_eq!(&rgba[..4], &[0, 0, 0, 255], "Y=16 must map to pure black");

        let white = ConstYuv {
            y: vec![235; 16],
            u: vec![128; 4],
            v: vec![128; 4],
            w: 4,
            h: 4,
        };
        i420_to_rgba8(&white, &mut rgba);
        assert_eq!(
            &rgba[..4],
            &[255, 255, 255, 255],
            "Y=235 must map to pure white"
        );
    }

    #[test]
    fn annex_b_has_idr_distinguishes_idr_from_non_idr_slice() {
        let idr = [0, 0, 0, 1, 0x67, 0x42, 0, 0, 0, 1, 0x65, 0x88];
        let p_frame = [0, 0, 0, 1, 0x41, 0x9a];
        assert!(annex_b_has_idr(&idr));
        assert!(!annex_b_has_idr(&p_frame));
    }
}
