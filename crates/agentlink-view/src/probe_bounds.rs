//! Bounded env parsing for diagnostic probes (t449).
//!
//! Keeps long Windows LAN media runs from accepting unbounded
//! `AGENTLINK_PROBE_*` values while still allowing a ~30s sustained window.

/// Parse a positive integer env value and clamp into `[min, max]`.
/// Empty / missing / invalid / zero → `default` (also clamped).
pub fn parse_bounded_u64(raw: Option<&str>, default: u64, min: u64, max: u64) -> u64 {
    debug_assert!(min <= max);
    let fallback = default.clamp(min, max);
    let Some(raw) = raw else {
        return fallback;
    };
    match raw.trim().parse::<u64>() {
        Ok(n) if n > 0 => n.clamp(min, max),
        _ => fallback,
    }
}

/// `0` means "no early stop" (full probe window). Positive values clamp to `[1, max]`.
/// Missing / invalid → `default_zero_ok` (0 = unlimited).
pub fn parse_max_decoded(raw: Option<&str>, default_zero_ok: u32, max: u32) -> u32 {
    let fallback = if default_zero_ok == 0 {
        0
    } else {
        default_zero_ok.clamp(1, max)
    };
    let Some(raw) = raw else {
        return fallback;
    };
    match raw.trim().parse::<u32>() {
        Ok(0) => 0,
        Ok(n) => n.clamp(1, max),
        Err(_) => fallback,
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_bounded_u64, parse_max_decoded};

    #[test]
    fn probe_seconds_default_and_clamp() {
        assert_eq!(parse_bounded_u64(None, 15, 1, 120), 15);
        assert_eq!(parse_bounded_u64(Some(""), 15, 1, 120), 15);
        assert_eq!(parse_bounded_u64(Some("0"), 15, 1, 120), 15);
        assert_eq!(parse_bounded_u64(Some("abc"), 15, 1, 120), 15);
        assert_eq!(parse_bounded_u64(Some("30"), 15, 1, 120), 30);
        assert_eq!(parse_bounded_u64(Some("9999"), 15, 1, 120), 120);
        assert_eq!(parse_bounded_u64(Some(" 45 "), 15, 1, 120), 45);
    }

    #[test]
    fn max_decoded_zero_means_unlimited() {
        assert_eq!(parse_max_decoded(None, 0, 10_000), 0);
        assert_eq!(parse_max_decoded(Some("0"), 0, 10_000), 0);
        assert_eq!(parse_max_decoded(Some("8"), 0, 10_000), 8);
        assert_eq!(parse_max_decoded(Some("999999"), 0, 10_000), 10_000);
        assert_eq!(parse_max_decoded(Some("nope"), 0, 10_000), 0);
    }
}
