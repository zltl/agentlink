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

    pub fn decode(&mut self, annex_b: &[u8]) -> Option<(Vec<u8>, usize, usize)> {
        let decoder = self.inner.as_mut()?;
        let mut last = None;
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
                    // at 1280×864). Integer BT.601 conversion stays well under
                    // the 25ms p95 budget on the controller thread.
                    i420_to_rgba8(&yuv, &mut self.scratch);
                    let rgba = std::mem::take(&mut self.scratch);
                    self.scratch = Vec::with_capacity(need);
                    last = Some((rgba, width, height));
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
        last
    }
}

/// BT.601 limited-range I420 → RGBA8. Faster than openh264's f32 `write_rgba8`.
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
            let u = u_row[x / 2] as i32;
            let v = v_row[x / 2] as i32;
            let c_u = u - 128;
            let c_v = v - 128;
            // Fixed-point approx of the openh264 f32 coeffs.
            let r_off = (91881 * c_v) >> 16; // 1.402
            let g_off = (-22554 * c_u - 46802 * c_v) >> 16; // -0.344/-0.714
            let b_off = (116130 * c_u) >> 16; // 1.772
            for dx in 0..2 {
                let y = y_row[x + dx] as i32;
                let r = (y + r_off).clamp(0, 255) as u8;
                let g = (y + g_off).clamp(0, 255) as u8;
                let b = (y + b_off).clamp(0, 255) as u8;
                let o = (x + dx) * 4;
                dst_row[o] = r;
                dst_row[o + 1] = g;
                dst_row[o + 2] = b;
                dst_row[o + 3] = 255;
            }
            x += 2;
        }
        if x < width {
            let u = u_row[x / 2] as i32 - 128;
            let v = v_row[x / 2] as i32 - 128;
            let y = y_row[x] as i32;
            let r = (y + ((91881 * v) >> 16)).clamp(0, 255) as u8;
            let g = (y + ((-22554 * u - 46802 * v) >> 16)).clamp(0, 255) as u8;
            let b = (y + ((116130 * u) >> 16)).clamp(0, 255) as u8;
            let o = x * 4;
            dst_row[o] = r;
            dst_row[o + 1] = g;
            dst_row[o + 2] = b;
            dst_row[o + 3] = 255;
        }
    }
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
    }
}
