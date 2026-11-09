//! Image viewport math for the remote desktop pane.
//!
//! The picture is shown with object-fit: contain (letterboxed), then zoom and
//! pan. Pointer fractions must use the content rectangle, not the full pane.

use eframe::egui::{Pos2, Rect, Vec2};

/// Size of `image` fitted inside `available` while keeping aspect ratio.
pub fn contain_size(image: Vec2, available: Vec2) -> Vec2 {
    if image.x <= 0.0 || image.y <= 0.0 || available.x <= 0.0 || available.y <= 0.0 {
        return Vec2::ZERO;
    }
    let scale = (available.x / image.x).min(available.y / image.y);
    image * scale
}

/// Content rectangle after contain-fit, zoom, and pan inside `available`.
///
/// `zoom == 1.0` is a pure contain fit centered in `available`. Values above
/// 1 enlarge the picture; `pan` shifts the content center in pane coordinates.
pub fn viewport_rect(image_size: Vec2, available: Rect, zoom: f32, pan: Vec2) -> Rect {
    let fitted = contain_size(image_size, available.size());
    if fitted == Vec2::ZERO {
        return Rect::from_min_size(available.min, Vec2::ZERO);
    }
    let size = fitted * zoom.max(0.05);
    let center = available.center() + pan;
    Rect::from_center_size(center, size)
}

/// Map a pane position onto 0..1 fractions of the content rectangle.
///
/// Positions outside the content still clamp to the nearest edge so letterbox
/// clicks do not invent a skewed coordinate system.
pub fn point_to_fraction(content: Rect, pos: Pos2) -> (f64, f64) {
    let width = content.width().max(1.0e-6);
    let height = content.height().max(1.0e-6);
    let x = ((pos.x - content.min.x) / width).clamp(0.0, 1.0) as f64;
    let y = ((pos.y - content.min.y) / height).clamp(0.0, 1.0) as f64;
    (x, y)
}

/// True when `pos` is inside the drawn content (not the letterbox).
pub fn hit_content(content: Rect, pos: Pos2) -> bool {
    content.width() > 0.0 && content.height() > 0.0 && content.contains(pos)
}

/// Zoom that shows the image at roughly 1 image pixel per egui point.
pub fn native_zoom(image_size: Vec2, available: Vec2) -> f32 {
    let fitted = contain_size(image_size, available);
    if fitted.x <= 0.0 {
        return 1.0;
    }
    (image_size.x / fitted.x).clamp(0.05, 8.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::egui::{pos2, vec2};

    fn approx(a: f64, b: f64) {
        assert!((a - b).abs() < 1.0e-6, "{a} != {b}");
    }

    #[test]
    fn contain_centers_wide_image_with_top_bottom_bars() {
        let image = vec2(200.0, 100.0);
        let available = Rect::from_min_size(pos2(0.0, 0.0), vec2(200.0, 200.0));
        let content = viewport_rect(image, available, 1.0, Vec2::ZERO);
        assert_eq!(content.width(), 200.0);
        assert_eq!(content.height(), 100.0);
        approx(content.center().x as f64, 100.0);
        approx(content.center().y as f64, 100.0);
    }

    #[test]
    fn contain_centers_tall_image_with_side_bars() {
        let image = vec2(100.0, 200.0);
        let available = Rect::from_min_size(pos2(10.0, 20.0), vec2(200.0, 200.0));
        let content = viewport_rect(image, available, 1.0, Vec2::ZERO);
        assert_eq!(content.width(), 100.0);
        assert_eq!(content.height(), 200.0);
        approx(content.center().x as f64, 110.0);
        approx(content.center().y as f64, 120.0);
    }

    #[test]
    fn letterbox_center_maps_to_half() {
        let image = vec2(200.0, 100.0);
        let available = Rect::from_min_size(pos2(0.0, 0.0), vec2(200.0, 200.0));
        let content = viewport_rect(image, available, 1.0, Vec2::ZERO);
        let (x, y) = point_to_fraction(content, content.center());
        approx(x, 0.5);
        approx(y, 0.5);
    }

    #[test]
    fn letterbox_corners_map_to_edges() {
        let image = vec2(200.0, 100.0);
        let available = Rect::from_min_size(pos2(0.0, 0.0), vec2(200.0, 200.0));
        let content = viewport_rect(image, available, 1.0, Vec2::ZERO);
        let (x0, y0) = point_to_fraction(content, content.min);
        let (x1, y1) = point_to_fraction(content, content.max);
        approx(x0, 0.0);
        approx(y0, 0.0);
        approx(x1, 1.0);
        approx(y1, 1.0);
        // Click in the top letterbox clamps to the top edge of the content.
        let (cx, cy) = point_to_fraction(content, pos2(100.0, 10.0));
        approx(cx, 0.5);
        approx(cy, 0.0);
    }

    #[test]
    fn zoom_two_and_half_preserve_center_fraction() {
        let image = vec2(400.0, 300.0);
        let available = Rect::from_min_size(pos2(0.0, 0.0), vec2(400.0, 300.0));
        for zoom in [1.0_f32, 2.0, 0.5] {
            let content = viewport_rect(image, available, zoom, Vec2::ZERO);
            let (x, y) = point_to_fraction(content, content.center());
            approx(x, 0.5);
            approx(y, 0.5);
            assert!((content.width() - 400.0 * zoom).abs() < 0.01);
        }
    }

    #[test]
    fn pan_shifts_content_and_fraction_follows() {
        let image = vec2(200.0, 100.0);
        let available = Rect::from_min_size(pos2(0.0, 0.0), vec2(200.0, 200.0));
        let content = viewport_rect(image, available, 1.0, vec2(30.0, -10.0));
        approx(content.center().x as f64, 130.0);
        approx(content.center().y as f64, 90.0);
        let (x, y) = point_to_fraction(content, content.min);
        approx(x, 0.0);
        approx(y, 0.0);
    }

    #[test]
    fn tiny_window_still_maps() {
        let image = vec2(1920.0, 1080.0);
        let available = Rect::from_min_size(pos2(0.0, 0.0), vec2(40.0, 30.0));
        let content = viewport_rect(image, available, 1.0, Vec2::ZERO);
        assert!(content.width() > 0.0 && content.height() > 0.0);
        assert!(content.width() <= 40.0 + 0.01);
        assert!(content.height() <= 30.0 + 0.01);
        let (x, y) = point_to_fraction(content, content.center());
        approx(x, 0.5);
        approx(y, 0.5);
    }

    #[test]
    fn native_zoom_is_one_when_pane_matches_image() {
        let zoom = native_zoom(vec2(800.0, 600.0), vec2(800.0, 600.0));
        assert!((zoom - 1.0).abs() < 0.01);
    }
}
