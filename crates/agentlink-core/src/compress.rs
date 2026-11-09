//! Optional per-chunk zstd. Already-compressed formats and chunks that do
//! not shrink are left alone so a JPEG or a random blob is not expanded.

use std::path::Path;

use crate::protocol::CompressPref;

const COMPRESSED_EXT: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "webp", "avif", "heic", "mp4", "m4v", "mov", "mkv", "webm", "avi",
    "zip", "gz", "tgz", "bz2", "xz", "zst", "7z", "rar", "br", "mp3", "aac", "ogg", "flac", "pdf",
    "jar", "war", "woff", "woff2", "lz4",
];

pub fn extension_is_compressed(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| {
            COMPRESSED_EXT
                .iter()
                .any(|known| ext.eq_ignore_ascii_case(known))
        })
        .unwrap_or(false)
}

pub fn allow_compression(pref: CompressPref, path: &Path) -> bool {
    match pref {
        CompressPref::Off => false,
        CompressPref::On => true,
        CompressPref::Auto => !extension_is_compressed(path),
    }
}

/// Compress `data` when the output is at least 3% smaller.
/// `None` means the caller should send the original bytes.
pub fn compress_if_smaller(data: &[u8]) -> Option<Vec<u8>> {
    if data.len() < 64 {
        return None;
    }
    let compressed = zstd::bulk::compress(data, 3).ok()?;
    if compressed.len() + 32 < data.len() && compressed.len() * 100 < data.len() * 97 {
        Some(compressed)
    } else {
        None
    }
}

pub fn decompress(data: &[u8], raw_len: usize) -> crate::error::Result<Vec<u8>> {
    zstd::bulk::decompress(data, raw_len.max(64))
        .map_err(|e| crate::error::Error::Message(format!("zstd: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_shrinks_and_random_does_not() {
        let text = vec![b'a'; 32_000];
        let compressed = compress_if_smaller(&text).expect("text should shrink");
        assert!(compressed.len() < text.len() / 10);
        let mut random = vec![0u8; 32_000];
        let mut state = 0x1234_5678_9abc_defu64;
        for byte in &mut random {
            state = state
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(0xBF58_476D_1CE4_E5B9);
            state ^= state >> 30;
            *byte = (state >> 33) as u8;
        }
        assert!(compress_if_smaller(&random).is_none());
    }

    #[test]
    fn archives_skip_auto_compression() {
        assert!(extension_is_compressed(Path::new("movie.MP4")));
        assert!(extension_is_compressed(Path::new("a/b/photos.zip")));
        assert!(!extension_is_compressed(Path::new("notes.txt")));
        assert!(!allow_compression(
            CompressPref::Auto,
            Path::new("clip.webm")
        ));
        assert!(allow_compression(CompressPref::On, Path::new("clip.webm")));
    }
}
