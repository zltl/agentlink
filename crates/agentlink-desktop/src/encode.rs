//! JPEG, WebP, and PNG encoding of a [`Frame`](crate::capture::Frame).

use std::io::Cursor;

use image::codecs::jpeg::JpegEncoder;
use image::codecs::png::PngEncoder;
use image::{ExtendedColorType, ImageEncoder};

use crate::capture::{bgra_to_rgba, Frame};
use crate::error::{msg, Result};

/// Largest encoded payload the node will put in one JSON result.
/// Base64 expands this by 4/3, and the WebSocket limit sits above that.
pub const MAX_ENCODED_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageFormat {
    Png,
    Jpeg,
    Webp,
}

impl ImageFormat {
    pub fn parse(text: &str) -> Result<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "png" => Ok(Self::Png),
            "jpeg" | "jpg" => Ok(Self::Jpeg),
            "webp" => Ok(Self::Webp),
            other => Err(msg(format!(
                "unknown image format '{other}' (expected png, jpeg, or webp)"
            ))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Png => "png",
            Self::Jpeg => "jpeg",
            Self::Webp => "webp",
        }
    }

    pub fn mime(self) -> &'static str {
        match self {
            Self::Png => "image/png",
            Self::Jpeg => "image/jpeg",
            Self::Webp => "image/webp",
        }
    }
}

pub struct EncodedImage {
    pub format: ImageFormat,
    pub mime: &'static str,
    pub bytes: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

pub fn encode_frame(frame: &Frame, format: ImageFormat, quality: u8) -> Result<EncodedImage> {
    let quality = quality.clamp(1, 100);
    let rgba = bgra_to_rgba(frame.pixels(), frame.width, frame.height);
    let bytes = match format {
        ImageFormat::Png => encode_png(&rgba, frame.width, frame.height)?,
        ImageFormat::Jpeg => encode_jpeg(&rgba, frame.width, frame.height, quality)?,
        ImageFormat::Webp => encode_webp(&rgba, frame.width, frame.height, quality)?,
    };
    if bytes.len() > MAX_ENCODED_BYTES {
        return Err(msg(format!(
            "encoded {} is {} bytes, over the {} byte limit; lower scale or quality",
            format.as_str(),
            bytes.len(),
            MAX_ENCODED_BYTES
        )));
    }
    Ok(EncodedImage {
        mime: format.mime(),
        format,
        bytes,
        width: frame.width,
        height: frame.height,
    })
}

fn encode_png(rgba: &[u8], width: u32, height: u32) -> Result<Vec<u8>> {
    let mut cursor = Cursor::new(Vec::new());
    PngEncoder::new(&mut cursor).write_image(rgba, width, height, ExtendedColorType::Rgba8)?;
    Ok(cursor.into_inner())
}

fn encode_jpeg(rgba: &[u8], width: u32, height: u32, quality: u8) -> Result<Vec<u8>> {
    let mut rgb = Vec::with_capacity(width as usize * height as usize * 3);
    for pixel in rgba.chunks_exact(4) {
        rgb.extend_from_slice(&pixel[..3]);
    }
    let mut cursor = Cursor::new(Vec::new());
    let mut encoder = JpegEncoder::new_with_quality(&mut cursor, quality);
    encoder.encode(&rgb, width, height, ExtendedColorType::Rgb8)?;
    Ok(cursor.into_inner())
}

fn encode_webp(rgba: &[u8], width: u32, height: u32, quality: u8) -> Result<Vec<u8>> {
    let encoder = webp::Encoder::from_rgba(rgba, width, height);
    let memory = encoder.encode(quality as f32);
    Ok(memory.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::Frame;

    fn sample() -> Frame {
        let mut raw = vec![0u8; 16 * 8 * 4];
        for (i, pixel) in raw.chunks_exact_mut(4).enumerate() {
            pixel[0] = (i * 3) as u8;
            pixel[1] = 40;
            pixel[2] = 200;
            pixel[3] = 255;
        }
        Frame::from_bgra(16, 8, 64, &raw, "test").unwrap()
    }

    #[test]
    fn png_jpeg_and_webp_decode() {
        let frame = sample();
        for format in [ImageFormat::Png, ImageFormat::Jpeg, ImageFormat::Webp] {
            let encoded = encode_frame(&frame, format, 80).unwrap();
            assert_eq!(encoded.mime, format.mime());
            let (width, height) = match format {
                ImageFormat::Webp => {
                    assert!(encoded.bytes.starts_with(b"RIFF"), "webp container");
                    let decoded = webp::Decoder::new(&encoded.bytes)
                        .decode()
                        .expect("webp bytes decode");
                    (decoded.width(), decoded.height())
                }
                ImageFormat::Png | ImageFormat::Jpeg => {
                    let image = image::load_from_memory(&encoded.bytes).unwrap();
                    (image.width(), image.height())
                }
            };
            assert_eq!((width, height), (16, 8));
        }
    }
}
