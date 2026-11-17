//! STD-only vertical padding for fixed-height text fields.
//!
//! Centers Latin / CJK glyphs and password bullets inside a tall `TextEdit`
//! when egui margin vertical was previously 0 (glyphs stuck to the top).
//! No password values are read or logged — only geometry metrics.

#![allow(dead_code)]

/// Compute symmetric vertical margin (points) so a line of text is centered
/// in `field_height_pts`.
///
/// `ascent_pts` / `descent_pts` are font metrics in points (already divided by
/// `pixels_per_point` when sourced from pixel metrics). `line_extra_pts` covers
/// egui row leading beyond ascent+descent (often ~0 for single-line edits).
pub fn vertical_center_margin_pts(
    field_height_pts: f32,
    ascent_pts: f32,
    descent_pts: f32,
    line_extra_pts: f32,
) -> f32 {
    if !field_height_pts.is_finite() || field_height_pts <= 0.0 {
        return 0.0;
    }
    let glyph = (ascent_pts.max(0.0) + descent_pts.max(0.0) + line_extra_pts.max(0.0)).max(1.0);
    ((field_height_pts - glyph) * 0.5).max(0.0)
}

/// Estimate ascent/descent from a body font size when real metrics are unavailable.
///
/// Uses a conservative Latin+CJK friendly ratio (ascent ≈ 0.8·size, descent ≈
/// 0.2·size) so password bullets and CJK share the same vertical box.
pub fn estimate_ascent_descent(font_size_pts: f32) -> (f32, f32) {
    let size = font_size_pts.max(1.0);
    (size * 0.80, size * 0.20)
}

/// Convert pixel font metrics to points.
pub fn pixels_to_pts(pixels: f32, pixels_per_point: f32) -> f32 {
    let ppp = if pixels_per_point.is_finite() && pixels_per_point > 0.0 {
        pixels_per_point
    } else {
        1.0
    };
    pixels / ppp
}

/// Full helper: field height + font size + ppp → vertical margin in points.
pub fn text_edit_v_margin(
    field_height_pts: f32,
    font_size_pts: f32,
    pixels_per_point: f32,
) -> f32 {
    let (ascent_px_est, descent_px_est) = (
        font_size_pts * pixels_per_point * 0.80,
        font_size_pts * pixels_per_point * 0.20,
    );
    let ascent = pixels_to_pts(ascent_px_est, pixels_per_point);
    let descent = pixels_to_pts(descent_px_est, pixels_per_point);
    vertical_center_margin_pts(field_height_pts, ascent, descent, 0.0)
}

/// When real galley row height is known (preferred over size estimates).
pub fn text_edit_v_margin_from_row_height(field_height_pts: f32, row_height_pts: f32) -> f32 {
    if !field_height_pts.is_finite() || field_height_pts <= 0.0 {
        return 0.0;
    }
    let row = row_height_pts.max(1.0);
    ((field_height_pts - row) * 0.5).max(0.0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn centers_in_36px_field_at_100_percent() {
        let v = text_edit_v_margin(36.0, 14.0, 1.0);
        // glyph ≈ 14 → pad ≈ (36-14)/2 = 11
        assert!((v - 11.0).abs() < 0.5, "v={v}");
    }

    #[test]
    fn scales_with_pixels_per_point() {
        let a = text_edit_v_margin(36.0, 14.0, 1.0);
        let b = text_edit_v_margin(36.0, 14.0, 2.0);
        // Field height is in points; font size in points — ppp cancels for the
        // estimate path, so margins match across DPI for the same pt sizes.
        assert!((a - b).abs() < 1e-3, "a={a} b={b}");
    }

    #[test]
    fn row_height_path_centers() {
        let v = text_edit_v_margin_from_row_height(36.0, 18.0);
        assert!((v - 9.0).abs() < 1e-6);
    }

    #[test]
    fn never_negative() {
        assert_eq!(text_edit_v_margin_from_row_height(10.0, 20.0), 0.0);
        assert_eq!(vertical_center_margin_pts(8.0, 10.0, 5.0, 0.0), 0.0);
    }

    #[test]
    fn cjk_and_latin_share_estimate_box() {
        let (a, d) = estimate_ascent_descent(16.0);
        assert!((a + d - 16.0).abs() < 1e-6);
        let v = vertical_center_margin_pts(36.0, a, d, 0.0);
        assert!((v - 10.0).abs() < 1e-6);
    }
}
