//! The Windows tray icon is a multi-size octopus sticker, crisp at 16 and 32.

use std::path::PathBuf;

fn ico() -> Vec<u8> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/agentlink.ico");
    std::fs::read(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
}

struct Frame {
    size: i32,
    pixels: Vec<[u8; 4]>,
}

fn frames(bytes: &[u8]) -> Vec<Frame> {
    assert!(bytes.len() > 6, "ico header");
    assert_eq!(u16::from_le_bytes([bytes[0], bytes[1]]), 0);
    assert_eq!(u16::from_le_bytes([bytes[2], bytes[3]]), 1, "icon type");
    let count = u16::from_le_bytes([bytes[4], bytes[5]]) as usize;
    let mut frames = Vec::new();
    for index in 0..count {
        let entry = 6 + index * 16;
        let mut size = bytes[entry] as i32;
        if size == 0 {
            size = 256;
        }
        let bytes_in =
            u32::from_le_bytes(bytes[entry + 8..entry + 12].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(bytes[entry + 12..entry + 16].try_into().unwrap()) as usize;
        let blob = &bytes[offset..offset + bytes_in];
        if blob.starts_with(b"\x89PNG") {
            assert!(
                size >= 128,
                "png frames are only for the large explorer sizes"
            );
            continue;
        }
        let bit_count = u16::from_le_bytes(blob[14..16].try_into().unwrap());
        assert_eq!(bit_count, 32, "{size}px frame should be 32-bit");
        let width = i32::from_le_bytes(blob[4..8].try_into().unwrap());
        let height = i32::from_le_bytes(blob[8..12].try_into().unwrap());
        assert_eq!(width, size);
        assert_eq!(height, size * 2, "ico dib height includes the mask");
        let mut pixels = Vec::with_capacity((size * size) as usize);
        for y in 0..size {
            let src = size - 1 - y;
            let base = 40 + (src * size * 4) as usize;
            for x in 0..size {
                let pixel = &blob[base + (x * 4) as usize..base + (x * 4) as usize + 4];
                pixels.push([pixel[2], pixel[1], pixel[0], pixel[3]]);
            }
        }
        frames.push(Frame { size, pixels });
    }
    frames
}

fn pixel(frame: &Frame, x: i32, y: i32) -> [u8; 4] {
    frame.pixels[(y * frame.size + x) as usize]
}

#[test]
fn tray_icon_has_crisp_16_and_32() {
    let frames = frames(&ico());
    let sizes: Vec<_> = frames.iter().map(|frame| frame.size).collect();
    for required in [16, 20, 24, 32, 40, 48, 64] {
        assert!(
            sizes.contains(&required),
            "missing {required}px frame in {sizes:?}"
        );
    }

    for size in [16, 32] {
        let frame = frames.iter().find(|frame| frame.size == size).unwrap();
        let corner = pixel(frame, 0, 0);
        assert_eq!(
            corner[3], 0,
            "{size}px corner should be transparent, got {corner:?}"
        );
        let center = pixel(frame, size / 2, size / 2);
        assert_eq!(center[3], 255, "{size}px center should be opaque");
        let teal = frame
            .pixels
            .iter()
            .filter(|pixel| pixel[3] == 255 && pixel[1] > 160 && pixel[2] > 150 && pixel[0] < 160)
            .count();
        let white = frame
            .pixels
            .iter()
            .filter(|pixel| pixel[3] == 255 && pixel[0] > 250 && pixel[1] > 250 && pixel[2] > 250)
            .count();
        let ink = frame
            .pixels
            .iter()
            .filter(|pixel| pixel[3] == 255 && pixel[0] < 50 && pixel[1] < 45 && pixel[2] < 40)
            .count();
        assert!(teal > 8, "{size}px should show the teal body, got {teal}");
        assert!(white > 4, "{size}px should keep the eyes, got {white}");
        assert!(ink > 16, "{size}px should keep the ink outline, got {ink}");
    }
}
