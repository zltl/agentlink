//! Cursor shape names for the remote overlay channel.
//!
//! The wire format is `{x,y,shape?,visible?}`. Unknown shapes fall back to
//! `"arrow"` on the node; old clients that only read `x`/`y` keep working.

/// Canonical shape id sent on the cursor data channel.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn normalize_shape(name: &str) -> &'static str {
    match name.trim().to_ascii_lowercase().as_str() {
        "arrow" | "default" | "pointer" => "arrow",
        "ibeam" | "text" | "beam" => "ibeam",
        "hand" | "pointinghand" | "link" => "hand",
        "sizeall" | "move" | "all-scroll" | "grabbing" => "sizeall",
        "sizens" | "ns-resize" | "row-resize" | "n-resize" | "s-resize" => "sizens",
        "sizewe" | "ew-resize" | "col-resize" | "e-resize" | "w-resize" => "sizewe",
        "sizenwse" | "nwse-resize" => "sizenwse",
        "sizenesw" | "nesw-resize" => "sizenesw",
        "cross" | "crosshair" => "cross",
        "wait" | "progress" | "busy" => "wait",
        "no" | "not-allowed" | "forbidden" => "no",
        "help" => "help",
        _ => "arrow",
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
