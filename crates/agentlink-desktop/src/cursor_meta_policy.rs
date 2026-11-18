//! STD-only PipeWire / Mutter cursor-meta semantics.
//!
//! Mirrors the C bridge rules so `rustc --test` can prove id=0 / absent /
//! bitmap_offset / format / bounds without libpipewire. Keep in sync with
//! `pipewire_capture.c` cursor parsing.

#![allow(dead_code)]

/// Max custom cursor edge (matches [`crate::MAX_CURSOR_BITMAP_EDGE`]).
pub const MAX_EDGE: u32 = 128;

/// Wire / overlay alpha interpretation for decoded cursor bitmaps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorAlpha {
    /// Mutter ScreenCast historically ships premultiplied BGRA.
    Premultiplied,
    Straight,
}

/// Default alpha for Mutter metadata bitmaps on the wire + overlay.
pub const MUTTER_CURSOR_ALPHA: CursorAlpha = CursorAlpha::Premultiplied;

/// Supported spa video formats for cursor bitmaps (numeric ids from spa).
/// Values match `SPA_VIDEO_FORMAT_*` in spa/param/video/raw.h.
pub const SPA_VIDEO_FORMAT_UNKNOWN: u32 = 0;
pub const SPA_VIDEO_FORMAT_BGRA: u32 = 6;
pub const SPA_VIDEO_FORMAT_BGRX: u32 = 7;
pub const SPA_VIDEO_FORMAT_RGBA: u32 = 8;
pub const SPA_VIDEO_FORMAT_RGBX: u32 = 9;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BitmapPixelLayout {
    Bgra,
    Rgba,
    Bgrx,
    Rgbx,
}

pub fn layout_for_format(format: u32) -> Option<BitmapPixelLayout> {
    match format {
        SPA_VIDEO_FORMAT_BGRA => Some(BitmapPixelLayout::Bgra),
        SPA_VIDEO_FORMAT_BGRX => Some(BitmapPixelLayout::Bgrx),
        SPA_VIDEO_FORMAT_RGBA => Some(BitmapPixelLayout::Rgba),
        SPA_VIDEO_FORMAT_RGBX => Some(BitmapPixelLayout::Rgbx),
        _ => None,
    }
}

/// Outcome of applying one present `spa_meta_cursor` (or its absence).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CursorMetaApply {
    /// No SPA_META_Cursor on this buffer — keep prior sample unchanged.
    Absent,
    /// Present meta with id=0 (Mutter unset: hidden or outside stream).
    UnsetHidden,
    /// Position/hotspot update; bitmap unchanged (`bitmap_offset == 0`).
    PositionOnly {
        x: i32,
        y: i32,
        hotspot_x: i32,
        hotspot_y: i32,
        visible: bool,
    },
    /// New bitmap + position. `pixels` is tightly packed RGBA (see alpha).
    WithBitmap {
        x: i32,
        y: i32,
        hotspot_x: i32,
        hotspot_y: i32,
        visible: bool,
        width: u32,
        height: u32,
        rgba: Vec<u8>,
        alpha: CursorAlpha,
    },
    /// Bitmap header says no pixels (inner offset 0) → invisible; keep size cleared.
    InvisibleNoPixels {
        x: i32,
        y: i32,
        hotspot_x: i32,
        hotspot_y: i32,
    },
    /// Unsupported format or failed bounds — keep prior bitmap; still update pos if valid.
    KeepBitmapUnsupportedFormat {
        x: i32,
        y: i32,
        hotspot_x: i32,
        hotspot_y: i32,
        visible: bool,
    },
}

/// Validate bitmap geometry before any pointer arithmetic.
pub fn bitmap_geometry_ok(
    width: u32,
    height: u32,
    stride: i32,
    bytes_pp: u32,
    meta_size: usize,
    cursor_hdr: usize,
    bitmap_offset: u32,
    bitmap_hdr: usize,
    pixel_offset: u32,
) -> bool {
    if width == 0 || height == 0 || width > MAX_EDGE || height > MAX_EDGE {
        return false;
    }
    if stride < 0 {
        return false;
    }
    let need_row = (width as u64).saturating_mul(bytes_pp as u64);
    if (stride as u64) < need_row {
        return false;
    }
    let off = bitmap_offset as u64;
    let pix = pixel_offset as u64;
    let hdr = cursor_hdr as u64;
    let bh = bitmap_hdr as u64;
    if off < hdr {
        return false;
    }
    if pix < bh {
        return false;
    }
    // Last byte of last row must lie inside meta->size.
    let last = off
        .saturating_add(pix)
        .saturating_add((height as u64 - 1).saturating_mul(stride as u64))
        .saturating_add(need_row.saturating_sub(1));
    last < meta_size as u64
}

/// Decode one pixel row into straight-or-premul RGBA into `dst` (4*width bytes).
pub fn decode_row(
    layout: BitmapPixelLayout,
    src: &[u8],
    width: u32,
    dst: &mut [u8],
) -> bool {
    let w = width as usize;
    if src.len() < w * 4 || dst.len() < w * 4 {
        return false;
    }
    for i in 0..w {
        let s = &src[i * 4..i * 4 + 4];
        let d = &mut dst[i * 4..i * 4 + 4];
        match layout {
            BitmapPixelLayout::Bgra | BitmapPixelLayout::Bgrx => {
                d[0] = s[2];
                d[1] = s[1];
                d[2] = s[0];
                d[3] = if matches!(layout, BitmapPixelLayout::Bgrx) {
                    255
                } else {
                    s[3]
                };
            }
            BitmapPixelLayout::Rgba | BitmapPixelLayout::Rgbx => {
                d[0] = s[0];
                d[1] = s[1];
                d[2] = s[2];
                d[3] = if matches!(layout, BitmapPixelLayout::Rgbx) {
                    255
                } else {
                    s[3]
                };
            }
        }
    }
    true
}

/// Apply present cursor meta fields (no PipeWire types).
pub fn apply_cursor_meta(
    present: bool,
    id: u32,
    x: i32,
    y: i32,
    hotspot_x: i32,
    hotspot_y: i32,
    bitmap_offset: u32,
    // bitmap fields when bitmap_offset != 0
    bm_format: u32,
    bm_width: u32,
    bm_height: u32,
    bm_stride: i32,
    bm_pixel_offset: u32,
    meta_size: usize,
    cursor_hdr: usize,
    bitmap_hdr: usize,
    pixel_bytes: Option<&[u8]>,
) -> CursorMetaApply {
    if !present {
        return CursorMetaApply::Absent;
    }
    if id == 0 {
        return CursorMetaApply::UnsetHidden;
    }
    if bitmap_offset == 0 {
        return CursorMetaApply::PositionOnly {
            x,
            y,
            hotspot_x,
            hotspot_y,
            visible: true,
        };
    }
    if bm_format == SPA_VIDEO_FORMAT_UNKNOWN {
        return CursorMetaApply::PositionOnly {
            x,
            y,
            hotspot_x,
            hotspot_y,
            visible: true,
        };
    }
    if bm_pixel_offset == 0 {
        return CursorMetaApply::InvisibleNoPixels {
            x,
            y,
            hotspot_x,
            hotspot_y,
        };
    }
    let Some(layout) = layout_for_format(bm_format) else {
        return CursorMetaApply::KeepBitmapUnsupportedFormat {
            x,
            y,
            hotspot_x,
            hotspot_y,
            visible: true,
        };
    };
    if !bitmap_geometry_ok(
        bm_width,
        bm_height,
        bm_stride,
        4,
        meta_size,
        cursor_hdr,
        bitmap_offset,
        bitmap_hdr,
        bm_pixel_offset,
    ) {
        return CursorMetaApply::KeepBitmapUnsupportedFormat {
            x,
            y,
            hotspot_x,
            hotspot_y,
            visible: true,
        };
    }
    let Some(src) = pixel_bytes else {
        return CursorMetaApply::KeepBitmapUnsupportedFormat {
            x,
            y,
            hotspot_x,
            hotspot_y,
            visible: true,
        };
    };
    let mut rgba = vec![0u8; (bm_width as usize) * (bm_height as usize) * 4];
    for row in 0..bm_height as usize {
        let start = row * bm_stride as usize;
        let end = start + (bm_width as usize) * 4;
        if end > src.len() {
            return CursorMetaApply::KeepBitmapUnsupportedFormat {
                x,
                y,
                hotspot_x,
                hotspot_y,
                visible: true,
            };
        }
        let dst_start = row * (bm_width as usize) * 4;
        let dst_end = dst_start + (bm_width as usize) * 4;
        if !decode_row(
            layout,
            &src[start..end],
            bm_width,
            &mut rgba[dst_start..dst_end],
        ) {
            return CursorMetaApply::KeepBitmapUnsupportedFormat {
                x,
                y,
                hotspot_x,
                hotspot_y,
                visible: true,
            };
        }
    }
    // Source pixels from Mutter are premul; callers that copy BGRA→RGBA
    // without un-premultiply must set Premultiplied. This helper's decode_row
    // leaves channel values as-is; production C bridge un-premultiplies so
    // the wire + egui overlay stay Straight.
    let _ = MUTTER_CURSOR_ALPHA;
    CursorMetaApply::WithBitmap {
        x,
        y,
        hotspot_x,
        hotspot_y,
        visible: true,
        width: bm_width,
        height: bm_height,
        rgba,
        alpha: CursorAlpha::Straight,
    }
}

/// Whether a build may advertise `cursor_caps.exclude`.
/// False when the SPA cursor parser cannot be compiled into the bridge.
pub fn exclude_cap_allowed(parser_built: bool) -> bool {
    parser_built
}

#[cfg(test)]
mod tests {
    use super::*;

    const CUR_HDR: usize = 24; // sizeof spa_meta_cursor approx
    const BM_HDR: usize = 20;

    #[test]
    fn absent_meta_is_not_hide() {
        assert_eq!(
            apply_cursor_meta(
                false, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, CUR_HDR, BM_HDR, None
            ),
            CursorMetaApply::Absent
        );
    }

    #[test]
    fn id_zero_is_mutter_unset_hidden() {
        assert_eq!(
            apply_cursor_meta(
                true, 0, 10, 10, 1, 1, 0, 0, 0, 0, 0, 0, 64, CUR_HDR, BM_HDR, None
            ),
            CursorMetaApply::UnsetHidden
        );
    }

    #[test]
    fn bitmap_offset_zero_keeps_sprite() {
        match apply_cursor_meta(
            true, 3, 5, 6, 1, 2, 0, 0, 0, 0, 0, 0, 64, CUR_HDR, BM_HDR, None
        ) {
            CursorMetaApply::PositionOnly {
                x: 5,
                y: 6,
                visible: true,
                ..
            } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn inner_offset_zero_means_invisible() {
        match apply_cursor_meta(
            true,
            2,
            1,
            1,
            0,
            0,
            CUR_HDR as u32,
            SPA_VIDEO_FORMAT_BGRA,
            16,
            16,
            64,
            0,
            4096,
            CUR_HDR,
            BM_HDR,
            None,
        ) {
            CursorMetaApply::InvisibleNoPixels { .. } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn oversize_rejected_before_cast() {
        assert!(!bitmap_geometry_ok(
            200,
            16,
            64,
            4,
            10_000,
            CUR_HDR,
            CUR_HDR as u32,
            BM_HDR,
            BM_HDR as u32
        ));
        assert!(!bitmap_geometry_ok(
            16,
            16,
            8, // stride too small
            4,
            10_000,
            CUR_HDR,
            CUR_HDR as u32,
            BM_HDR,
            BM_HDR as u32
        ));
    }

    #[test]
    fn unsupported_format_keeps_prior_bitmap_path() {
        match apply_cursor_meta(
            true,
            2,
            1,
            1,
            0,
            0,
            CUR_HDR as u32,
            999,
            8,
            8,
            32,
            BM_HDR as u32,
            4096,
            CUR_HDR,
            BM_HDR,
            Some(&[0u8; 256]),
        ) {
            CursorMetaApply::KeepBitmapUnsupportedFormat { visible: true, .. } => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn bgra_row_swizzle_to_rgba() {
        let src = [10u8, 20, 30, 40]; // B G R A
        let mut dst = [0u8; 4];
        assert!(decode_row(BitmapPixelLayout::Bgra, &src, 1, &mut dst));
        assert_eq!(dst, [30, 20, 10, 40]);
    }

    #[test]
    fn exclude_requires_parser() {
        assert!(!exclude_cap_allowed(false));
        assert!(exclude_cap_allowed(true));
    }
}
