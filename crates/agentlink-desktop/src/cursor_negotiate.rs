//! Per-session cursor presentation negotiation (RDP-style).
//!
//! Official constraints (do not invent protocol claims):
//! - MS-RDPBCGR pointer updates carry position/shape/hotspot independent of
//!   the framebuffer; the client caches the sprite locally.
//! - XDG Portal ScreenCast cursor modes are Hidden=1, Embedded=2, Metadata=4;
//!   request only modes the backend advertises.
//! - Mutter's historical direct ScreenCast enum differs (hidden=0 embedded=1
//!   metadata=2). Never conflate portal bits with Mutter bits.
//! - PipeWire `spa_meta_cursor`: id=0 means no new cursor data; bitmap_offset=0
//!   means no new bitmap (not invisibility).
//!
//! Product rules from executor review:
//! 1. Default is [`CursorPresentation::Legacy`] — embedded/video cursor stays
//!    visible; never draw a second local arrow on top.
//! 2. [`CursorPresentation::Metadata`] only after both peers agree **and** the
//!    capture backend can exclude the embedded cursor for this session.
//! 3. Respect the remote `visible` flag; do not conflate capture exclusion with
//!    OS pointer hidden.
//! 4. Encode padding (macroblock align) must be applied when mapping hotspot /
//!    pointer into the letterboxed viewer content.

use serde::{Deserialize, Serialize};

/// How this session presents the remote pointer to the viewer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CursorPresentation {
    /// Embedded (or unknown) capture cursor. Viewer must not paint a second
    /// local sprite. Shape/hotspot may still be reported for diagnostics.
    #[default]
    Legacy,
    /// Capture excludes the OS cursor; viewer may show an immediate local
    /// sprite driven by the cursor data channel (shape/hotspot/visible).
    Metadata,
}

/// Capabilities advertised in the WebRTC answer (additive; old viewers ignore).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorCaps {
    /// Stock / named shapes can be reported (Windows IDC / X11 cursor name).
    pub shape: bool,
    /// OS pointer visibility is reported separately from capture exclusion.
    pub visible: bool,
    /// Hotspot coordinates accompany shape / bitmap updates.
    pub hotspot: bool,
    /// Backend can exclude the embedded cursor for *this* session when the
    /// viewer requests metadata mode. False ⇒ answer stays legacy.
    pub exclude: bool,
}

impl Default for CursorCaps {
    fn default() -> Self {
        Self {
            shape: true,
            visible: true,
            hotspot: true,
            // Safe default: do not claim exclusion without a negotiated backend.
            exclude: false,
        }
    }
}

/// Resolve the session presentation from viewer request + node caps.
///
/// Unknown / missing viewer preference ⇒ legacy. Metadata requires `exclude`.
pub fn negotiate_presentation(
    viewer_wants_metadata: bool,
    caps: &CursorCaps,
) -> CursorPresentation {
    if viewer_wants_metadata && caps.exclude {
        CursorPresentation::Metadata
    } else {
        CursorPresentation::Legacy
    }
}

/// Map a pointer from capture/stream pixels into content fractions, accounting
/// for macroblock encode padding below/right of the real picture.
///
/// `src_*` is the true content size fed to the encoder; `encode_*` is the
/// padded size (`align_mb`). Viewer letterboxing uses the content aspect; the
/// padded strip must not skew fractions (review point: 1280x853 → 1280x864).
///
/// Uses the **pixel-center** convention: the center of the middle row of an
/// odd height maps to 0.5 (`(y + 0.5) / src_h`). Coordinates that land in the
/// encode pad strip clamp to the last real content pixel before dividing.
pub fn content_fraction_with_pad(
    x: i32,
    y: i32,
    src_w: u32,
    src_h: u32,
    encode_w: u32,
    encode_h: u32,
) -> (f64, f64) {
    let _ = (encode_w, encode_h); // pad is outside content; fractions use src.
    let w = src_w.max(1);
    let h = src_h.max(1);
    let max_x = w.saturating_sub(1) as i32;
    let max_y = h.saturating_sub(1) as i32;
    let x = x.clamp(0, max_x);
    let y = y.clamp(0, max_y);
    let fx = ((x as f64) + 0.5) / (w as f64);
    let fy = ((y as f64) + 0.5) / (h as f64);
    (fx.clamp(0.0, 1.0), fy.clamp(0.0, 1.0))
}

/// Display size of the unpadded picture inside a letterboxed encode texture.
///
/// Encode pad (e.g. 11 rows under 853→864) must be cropped out of the viewer
/// content rectangle so pointer fractions and hit-tests stay on real pixels.
pub fn encode_pad_content_size(
    display_w: f32,
    display_h: f32,
    src_w: u32,
    src_h: u32,
    encode_w: u32,
    encode_h: u32,
) -> (f32, f32) {
    if encode_w == 0 || encode_h == 0 || src_w == 0 || src_h == 0 {
        return (display_w, display_h);
    }
    if src_w >= encode_w && src_h >= encode_h {
        return (display_w, display_h);
    }
    (
        display_w * (src_w as f32) / (encode_w as f32),
        display_h * (src_h as f32) / (encode_h as f32),
    )
}

/// Scale a hotspot from capture pixels into the encoded content space.
pub fn scale_hotspot(
    hotspot_x: u16,
    hotspot_y: u16,
    src_w: u32,
    src_h: u32,
    out_w: u32,
    out_h: u32,
) -> (u16, u16) {
    if src_w == 0 || src_h == 0 || out_w == 0 || out_h == 0 {
        return (hotspot_x, hotspot_y);
    }
    let x = (hotspot_x as u64) * (out_w as u64) / (src_w as u64);
    let y = (hotspot_y as u64) * (out_h as u64) / (src_h as u64);
    (
        x.min(u16::MAX as u64) as u16,
        y.min(u16::MAX as u64) as u16,
    )
}

/// Maximum custom cursor bitmap edge we will put on the wire (bytes bound).
pub const MAX_CURSOR_BITMAP_EDGE: u32 = 128;

/// True when a custom RGBA bitmap is small enough to send.
pub fn bitmap_within_bound(width: u32, height: u32) -> bool {
    width > 0
        && height > 0
        && width <= MAX_CURSOR_BITMAP_EDGE
        && height <= MAX_CURSOR_BITMAP_EDGE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_negotiation_is_legacy_without_exclude() {
        let caps = CursorCaps::default();
        assert_eq!(
            negotiate_presentation(true, &caps),
            CursorPresentation::Legacy
        );
        assert_eq!(
            negotiate_presentation(false, &caps),
            CursorPresentation::Legacy
        );
    }

    #[test]
    fn metadata_only_when_exclude_and_requested() {
        let caps = CursorCaps {
            exclude: true,
            ..CursorCaps::default()
        };
        assert_eq!(
            negotiate_presentation(true, &caps),
            CursorPresentation::Metadata
        );
        assert_eq!(
            negotiate_presentation(false, &caps),
            CursorPresentation::Legacy
        );
    }

    #[test]
    fn padded_853_to_864_fractions_use_src_height() {
        // 2736x1824 → 1280x853 content, encode pad to 1280x864 (11 rows).
        // Pixel-center: odd height row 426 → (426 + 0.5) / 853 == 0.5.
        // Even width has no integer column centered at 0.5; col 640 → 640.5/1280.
        let (x, y) = content_fraction_with_pad(640, 426, 1280, 853, 1280, 864);
        assert!((x - (640.5 / 1280.0)).abs() < 1e-12, "x={x}");
        assert!((y - 0.5).abs() < 1e-12, "y={y} expected 0.5");
        let (x2, y2) = content_fraction_with_pad(0, 852, 1280, 853, 1280, 864);
        assert!((x2 - (0.5 / 1280.0)).abs() < 1e-12);
        assert!(y2 > 0.998);
        // Pad-strip y must clamp into content, not skew above 1.0 via encode_h.
        let (x3, y3) = content_fraction_with_pad(640, 860, 1280, 853, 1280, 864);
        assert!((x3 - (640.5 / 1280.0)).abs() < 1e-12);
        assert!(y3 <= 1.0 + 1e-12);
        assert!(y3 > 0.998);
    }

    #[test]
    fn encode_pad_crops_display_height() {
        let (w, h) = encode_pad_content_size(1280.0, 864.0, 1280, 853, 1280, 864);
        assert!((w - 1280.0).abs() < 1e-6);
        assert!((h - 853.0).abs() < 1e-6);
        let (w2, h2) = encode_pad_content_size(640.0, 432.0, 1280, 853, 1280, 864);
        assert!((w2 - 640.0).abs() < 1e-6);
        assert!((h2 - 426.5).abs() < 1e-6);
    }

    #[test]
    fn bitmap_bound_rejects_huge_sprites() {
        assert!(bitmap_within_bound(32, 32));
        assert!(!bitmap_within_bound(256, 256));
        assert!(!bitmap_within_bound(0, 16));
    }
}
