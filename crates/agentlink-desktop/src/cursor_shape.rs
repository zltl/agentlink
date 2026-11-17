//! Cursor shape names for the remote overlay channel.
//!
//! The wire format is `{x,y,shape?,visible?,hotspot_x?,hotspot_y?}`. Stock
//! aliases map to canonical ids. Unrecognized names stay `"unknown"` via
//! [`classify_shape`] — do not pretend they are `"arrow"`. [`normalize_shape`]
//! keeps the older Windows stock fallback to `"arrow"` for IDC misses.

/// Canonical shape id when the name is a known stock alias; `"unknown"` otherwise.
pub fn classify_shape(name: &str) -> &'static str {
    match name.trim().to_ascii_lowercase().as_str() {
        "arrow" | "default" | "pointer" | "left_ptr" => "arrow",
        "ibeam" | "text" | "beam" | "xterm" => "ibeam",
        "hand" | "pointinghand" | "link" | "hand2" => "hand",
        "sizeall" | "move" | "all-scroll" | "grabbing" | "fleur" => "sizeall",
        "sizens" | "ns-resize" | "row-resize" | "n-resize" | "s-resize"
        | "sb_v_double_arrow" => "sizens",
        "sizewe" | "ew-resize" | "col-resize" | "e-resize" | "w-resize"
        | "sb_h_double_arrow" => "sizewe",
        "sizenwse" | "nwse-resize" | "bd_double_arrow" => "sizenwse",
        "sizenesw" | "nesw-resize" | "fd_double_arrow" => "sizenesw",
        "cross" | "crosshair" | "cross_reverse" => "cross",
        "wait" | "progress" | "busy" | "watch" | "left_ptr_watch" => "wait",
        "no" | "not-allowed" | "forbidden" | "crossed_circle" => "no",
        "help" | "question_arrow" => "help",
        "" => "unknown",
        _ => "unknown",
    }
}

/// Canonical shape id for Windows stock mapping. Unknown → `"arrow"`.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn normalize_shape(name: &str) -> &'static str {
    match classify_shape(name) {
        "unknown" => "arrow",
        other => other,
    }
}

/// Map a Windows system cursor resource id (IDC_*) ordinal to a shape name.
///
/// `LoadCursorW(NULL, IDC_*)` returns handles whose resource ids are these
/// well-known values. Comparing `CURSORINFO.hCursor` against freshly loaded
/// stock cursors is done on the Windows backend; this table is the pure half.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn shape_from_win_idc(idc: usize) -> &'static str {
    // From winuser.h: MAKEINTRESOURCE values for IDC_*.
    match idc {
        32512 => "arrow",     // IDC_ARROW
        32513 => "ibeam",     // IDC_IBEAM
        32514 => "wait",      // IDC_WAIT
        32515 => "cross",     // IDC_CROSS
        32516 => "arrow",     // IDC_UPARROW → treat as arrow
        32642 => "sizenwse",  // IDC_SIZENWSE
        32643 => "sizenesw",  // IDC_SIZENESW
        32644 => "sizewe",    // IDC_SIZEWE
        32645 => "sizens",    // IDC_SIZENS
        32646 => "sizeall",   // IDC_SIZEALL
        32648 => "no",        // IDC_NO
        32649 => "hand",      // IDC_HAND
        32650 => "wait",      // IDC_APPSTARTING
        32651 => "help",      // IDC_HELP
        _ => "arrow",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_aliases() {
        assert_eq!(normalize_shape("IBEAM"), "ibeam");
        assert_eq!(normalize_shape("pointingHand"), "hand");
        assert_eq!(normalize_shape("ns-resize"), "sizens");
        assert_eq!(normalize_shape("unknown-xyz"), "arrow");
        assert_eq!(classify_shape("xterm"), "ibeam");
        assert_eq!(classify_shape("unknown-xyz"), "unknown");
        assert_eq!(classify_shape("left_ptr"), "arrow");
    }

    #[test]
    fn win_idc_table() {
        assert_eq!(shape_from_win_idc(32512), "arrow");
        assert_eq!(shape_from_win_idc(32513), "ibeam");
        assert_eq!(shape_from_win_idc(32649), "hand");
        assert_eq!(shape_from_win_idc(32646), "sizeall");
        assert_eq!(shape_from_win_idc(32645), "sizens");
        assert_eq!(shape_from_win_idc(32644), "sizewe");
        assert_eq!(shape_from_win_idc(0), "arrow");
    }
}
