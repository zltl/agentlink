//! RTP H.264 (RFC 6184) to Annex-B access units.
//!
//! Packetization-mode 1 uses single NALs, STAP-A, and FU-A. The Android
//! decoder wants Annex-B (start code plus NAL), which is what the desktop
//! encoders already produce before the payloader splits them.

/// Inventory of candidate types found in an answer SDP.
///
/// This is **not** the media path. A typical ICE answer lists host, srflx,
/// and relay candidates together; host would always win here even when the
/// selected pair is TURN. The Controller HUD and `Viewer` path must use
/// [`classify_selected_path`] on the selected ICE pair (or `relay` for
/// JPEG stills over the WebSocket). `quic` is not an ICE type; callers
/// pass it through from a direct file/exec transfer.
pub fn classify_media_path(sdp: &str) -> &'static str {
    let mut host = false;
    let mut stun = false;
    let mut turn = false;
    let mut quic = false;
    for line in sdp.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("quic") && !lower.contains("typ ") {
            quic = true;
        }
        if lower.contains(" typ relay") {
            turn = true;
        } else if lower.contains(" typ srflx") || lower.contains(" typ prflx") {
            stun = true;
        } else if lower.contains(" typ host") {
            host = true;
        }
    }
    if quic && !host && !stun && !turn {
        "quic"
    } else if host {
        "host"
    } else if stun {
        "stun"
    } else if turn {
        "turn"
    } else {
        "relay"
    }
}

/// Path token for a *selected* ICE candidate pair (`host`, `stun`, `turn`,
/// `tailscale`, or `unknown`).
///
/// TURN (`typ relay`) always wins: media then goes through a TURN server,
/// not a direct peer path. STUN (`typ srflx`/`prflx`) is NAT-assisted
/// WebRTC, not a Tailscale tunnel. `typ host` addresses in 100.64.0.0/10
/// or `fd7a:115c:a1e0::/48` are labeled `tailscale` (Tailscale's CGNAT /
/// ULA ranges; see Tailscale KB 1015). That is an overlay, not public NAT
/// traversal, and is not unique to Tailscale for IPv4 CGNAT.
pub fn classify_selected_path(
    local_typ: &str,
    remote_typ: &str,
    local_ip: &str,
    remote_ip: &str,
) -> &'static str {
    let local_typ = typ_token(local_typ);
    let remote_typ = typ_token(remote_typ);
    if local_typ == "relay" || remote_typ == "relay" {
        return "turn";
    }
    if matches!(local_typ, "srflx" | "prflx") || matches!(remote_typ, "srflx" | "prflx") {
        return "stun";
    }
    if local_typ == "host" || remote_typ == "host" {
        if is_tailscale_range(local_ip) || is_tailscale_range(remote_ip) {
            return "tailscale";
        }
        return "host";
    }
    "unknown"
}

fn typ_token(raw: &str) -> &str {
    let lower = raw.trim().to_ascii_lowercase();
    if lower.contains("relay") {
        "relay"
    } else if lower.contains("srflx") {
        "srflx"
    } else if lower.contains("prflx") {
        "prflx"
    } else if lower.contains("host") {
        "host"
    } else {
        raw.trim()
    }
}

/// Address class for a selected-pair IP (no port).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AddrScope {
    Loopback,
    PrivateLan,
    /// 100.64.0.0/10 (RFC 6598) or Tailscale IPv6 ULA fd7a:115c:a1e0::/48.
    CgnatTailscale,
    Public,
    Other,
}

/// Classify a literal IP (IPv4 or IPv6). Ports and brackets are stripped.
pub fn addr_scope(ip: &str) -> AddrScope {
    let host = strip_host(ip);
    let Ok(addr) = host.parse::<std::net::IpAddr>() else {
        return AddrScope::Other;
    };
    match addr {
        std::net::IpAddr::V4(v4) => {
            if v4.is_loopback() {
                AddrScope::Loopback
            } else if is_cgnat(v4) {
                AddrScope::CgnatTailscale
            } else if v4.is_private() || v4.is_link_local() {
                AddrScope::PrivateLan
            } else if v4.is_unspecified() || v4.is_broadcast() || v4.is_multicast() {
                AddrScope::Other
            } else {
                AddrScope::Public
            }
        }
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() {
                AddrScope::Loopback
            } else if is_tailscale_ula(v6) {
                AddrScope::CgnatTailscale
            } else if v6.is_unique_local() || v6.is_unicast_link_local() {
                AddrScope::PrivateLan
            } else if v6.is_unspecified() || v6.is_multicast() {
                AddrScope::Other
            } else {
                AddrScope::Public
            }
        }
    }
}

pub fn is_tailscale_range(ip: &str) -> bool {
    addr_scope(ip) == AddrScope::CgnatTailscale
}

fn strip_host(raw: &str) -> &str {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    // IPv4 host:port (not IPv6)
    if raw.chars().filter(|c| *c == ':').count() == 1 {
        return raw.rsplit_once(':').map(|(h, _)| h).unwrap_or(raw);
    }
    raw
}

fn is_cgnat(addr: std::net::Ipv4Addr) -> bool {
    // RFC 6598 shared address space, also used by Tailscale (KB 1015).
    let o = addr.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

fn is_tailscale_ula(addr: std::net::Ipv6Addr) -> bool {
    // Tailscale IPv6 unique-local prefix fd7a:115c:a1e0::/48 (KB 1015 / 1033).
    let s = addr.segments();
    s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
}

/// Short explanation for the HUD. Distinguishes WebSocket JPEG, TURN, STUN,
/// LAN host, and a Tailscale/CGNAT host overlay.
pub fn media_path_hint(kind: &str, path: &str) -> &'static str {
    let kind = kind.trim().to_ascii_lowercase();
    let path = path.trim().to_ascii_lowercase();
    if kind == "jpeg" || (kind.is_empty() && path == "relay") {
        return "JPEG stills over the WebSocket relay — not WebRTC P2P";
    }
    match path.as_str() {
        "host" => {
            "WebRTC ICE typ host on a loopback or private address — same machine or LAN, not public NAT traversal"
        }
        "stun" => "WebRTC ICE typ srflx/prflx — STUN-assisted path, not a Tailscale tunnel",
        "turn" => "WebRTC media through a TURN relay — not a direct P2P path",
        "tailscale" => {
            "WebRTC typ host in 100.64.0.0/10 or fd7a:115c:a1e0::/48 (Tailscale/CGNAT range) — overlay, not public NAT traversal"
        }
        "relay" => "WebSocket relay — not WebRTC P2P",
        "quic" => "Direct QUIC used for file/exec, not the desktop video path",
        "connecting" => "WebRTC is still connecting; this is not a confirmed path",
        "unknown" => "H.264 arrived before a selected ICE pair was observed",
        _ => "Path is taken from the selected ICE pair, not from gathered SDP candidates",
    }
}

/// One decoded access unit, still compressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessUnit {
    pub bytes: Vec<u8>,
    pub keyframe: bool,
}

#[derive(Debug, Default)]
pub struct H264Depacketizer {
    nals: Vec<Vec<u8>>,
    fu: Vec<u8>,
    fu_open: bool,
}

impl H264Depacketizer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Push one RTP payload. `marker` ends the access unit.
    pub fn push(&mut self, payload: &[u8], marker: bool) -> Option<AccessUnit> {
        if !payload.is_empty() {
            let kind = payload[0] & 0x1f;
            if kind == 24 {
                self.stap_a(payload);
            } else if kind == 28 {
                self.fu_a(payload);
            } else if (1..24).contains(&kind) {
                self.nals.push(payload.to_vec());
            }
        }
        if marker { self.finish() } else { None }
    }

    fn stap_a(&mut self, payload: &[u8]) {
        let mut offset = 1;
        while offset + 2 <= payload.len() {
            let len = u16::from_be_bytes([payload[offset], payload[offset + 1]]) as usize;
            offset += 2;
            if len == 0 || offset + len > payload.len() {
                break;
            }
            self.nals.push(payload[offset..offset + len].to_vec());
            offset += len;
        }
    }

    fn fu_a(&mut self, payload: &[u8]) {
        if payload.len() < 2 {
            return;
        }
        let indicator = payload[0];
        let header = payload[1];
        let start = header & 0x80 != 0;
        let end = header & 0x40 != 0;
        if start {
            self.fu.clear();
            self.fu.push((indicator & 0xe0) | (header & 0x1f));
            self.fu_open = true;
        }
        if !self.fu_open {
            return;
        }
        self.fu.extend_from_slice(&payload[2..]);
        if end {
            self.fu_open = false;
            self.nals.push(std::mem::take(&mut self.fu));
        }
    }

    fn finish(&mut self) -> Option<AccessUnit> {
        self.fu_open = false;
        self.fu.clear();
        if self.nals.is_empty() {
            return None;
        }
        let nals = std::mem::take(&mut self.nals);
        let mut bytes = Vec::new();
        let mut keyframe = false;
        for nal in &nals {
            if nal.first().is_some_and(|byte| byte & 0x1f == 5) {
                keyframe = true;
            }
            bytes.extend_from_slice(&[0, 0, 0, 1]);
            bytes.extend_from_slice(nal);
        }
        Some(AccessUnit { bytes, keyframe })
    }
}

/// True when the Annex-B buffer contains an IDR NAL (type 5).
pub fn access_unit_is_idr(annex_b: &[u8]) -> bool {
    nal_bodies(annex_b)
        .iter()
        .any(|nal| nal.first().is_some_and(|byte| byte & 0x1f == 5))
}

fn nal_bodies(bytes: &[u8]) -> Vec<&[u8]> {
    let mut starts = Vec::new();
    let mut index = 0;
    while index + 3 < bytes.len() {
        if index + 4 <= bytes.len()
            && bytes[index] == 0
            && bytes[index + 1] == 0
            && bytes[index + 2] == 0
            && bytes[index + 3] == 1
        {
            starts.push(index + 4);
            index += 4;
            continue;
        }
        if bytes[index] == 0 && bytes[index + 1] == 0 && bytes[index + 2] == 1 {
            starts.push(index + 3);
            index += 3;
            continue;
        }
        index += 1;
    }
    let mut nals = Vec::new();
    for (nth, start) in starts.iter().copied().enumerate() {
        let mut end = starts.get(nth + 1).copied().unwrap_or(bytes.len());
        if nth + 1 < starts.len() {
            if end >= 4 && bytes.get(end - 4..end) == Some(&[0, 0, 0, 1][..]) {
                end -= 4;
            } else if end >= 3 && bytes.get(end - 3..end) == Some(&[0, 0, 1][..]) {
                end -= 3;
            }
        }
        if start < end && end <= bytes.len() {
            nals.push(&bytes[start..end]);
        }
    }
    nals
}

/// RTP sequence gaps this window, plus frames the viewer dropped locally.
#[derive(Debug, Default)]
pub struct LossWindow {
    next: Option<u16>,
    received: u64,
    lost: u64,
}

impl LossWindow {
    pub fn observe(&mut self, seq: u16) {
        match self.next {
            None => {
                self.received += 1;
                self.next = Some(seq.wrapping_add(1));
            }
            Some(expected) => {
                let gap = seq.wrapping_sub(expected);
                if gap == 0 {
                    self.received += 1;
                    self.next = Some(seq.wrapping_add(1));
                } else if gap < 0x8000 {
                    self.lost += u64::from(gap);
                    self.received += 1;
                    self.next = Some(seq.wrapping_add(1));
                } else {
                    self.received += 1;
                }
            }
        }
    }

    /// Loss ratio since the last take. `None` when no packet arrived, so a
    /// quiet desktop does not look like a perfect network.
    pub fn take_ratio(&mut self) -> Option<f64> {
        let total = self.received + self.lost;
        if total == 0 {
            return None;
        }
        let ratio = self.lost as f64 / total as f64;
        self.received = 0;
        self.lost = 0;
        Some(ratio)
    }
}

/// Combine RTP loss with access units the viewer had to drop. The node treats
/// this the same way the browser's `feedback` message does.
pub fn feedback_ratio(rtp_loss: f64, dropped: u64, shown: u64) -> f64 {
    let local = if shown + dropped == 0 {
        0.0
    } else {
        dropped as f64 / (shown + dropped) as f64
    };
    rtp_loss.max(local).clamp(0.0, 1.0)
}

/// Same clamps the node applies to an offer.
pub fn clamp_offer(max_fps: u32, bitrate: u32) -> (u32, u32) {
    (max_fps.clamp(1, 60), bitrate.clamp(100_000, 12_000_000))
}

pub fn is_screenshot_fallback(value: &serde_json::Value) -> bool {
    value.get("status").and_then(|item| item.as_str()) == Some("unavailable")
        && value.get("fallback").and_then(|item| item.as_str()) == Some("screenshot")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_nal_and_stap_a_become_annex_b() {
        let mut depay = H264Depacketizer::new();
        let sps = [0x67, 0x42, 0x00, 0x1f];
        let pps = [0x68, 0xce, 0x01];
        let mut stap = vec![0x18, 0x00, sps.len() as u8, 0, 0];
        // Rebuild with proper 2-byte lengths.
        stap = vec![0x18];
        stap.extend_from_slice(&(sps.len() as u16).to_be_bytes());
        stap.extend_from_slice(&sps);
        stap.extend_from_slice(&(pps.len() as u16).to_be_bytes());
        stap.extend_from_slice(&pps);
        assert!(depay.push(&stap, false).is_none());
        let idr = [0x65, 0x88, 0x84];
        let unit = depay.push(&idr, true).expect("access unit");
        assert!(unit.keyframe);
        assert!(access_unit_is_idr(&unit.bytes));
        assert!(unit.bytes.windows(4).any(|win| win == sps));
        assert!(unit.bytes.windows(4).any(|win| win == [0, 0, 0, 1]));
    }

    #[test]
    fn fu_a_reassembles_an_idr() {
        let mut depay = H264Depacketizer::new();
        let indicator = 0x7c;
        assert!(depay.push(&[indicator, 0x85, 0x88], false).is_none());
        let unit = depay.push(&[indicator, 0x45, 0x84], true).expect("idr");
        assert_eq!(unit.bytes, vec![0, 0, 0, 1, 0x65, 0x88, 0x84]);
        assert!(unit.keyframe);
    }

    #[test]
    fn sequence_gaps_and_reorder_do_not_invent_loss_twice() {
        let mut window = LossWindow::default();
        window.observe(1);
        window.observe(4);
        window.observe(2);
        let ratio = window.take_ratio().unwrap();
        assert!((ratio - 2.0 / 5.0).abs() < 0.001);
        assert!(window.take_ratio().is_none());
        assert!((feedback_ratio(0.0, 1, 3) - 0.25).abs() < 0.001);
        assert_eq!(feedback_ratio(0.5, 0, 0), 0.5);
        assert_eq!(clamp_offer(0, 1), (1, 100_000));
        assert_eq!(clamp_offer(90, 20_000_000), (60, 12_000_000));
    }

    #[test]
    fn media_path_prefers_a_direct_candidate() {
        assert_eq!(classify_media_path(""), "relay");
        assert_eq!(
            classify_media_path("a=candidate:1 1 UDP 1 10.0.0.2 9 typ host"),
            "host"
        );
        assert_eq!(
            classify_media_path("a=candidate:1 1 UDP 1 203.0.113.5 9 typ srflx"),
            "stun"
        );
        assert_eq!(
            classify_media_path("a=candidate:1 1 UDP 1 198.51.100.8 9 typ relay"),
            "turn"
        );
        assert_eq!(
            classify_media_path(
                "a=candidate:1 1 UDP 1 10.0.0.2 9 typ host\r\na=candidate:2 1 UDP 1 198.51.100.8 9 typ relay"
            ),
            "host"
        );
    }

    #[test]
    fn selected_pair_not_the_sdp_inventory() {
        // Inventory still prefers host when both typ host and typ relay
        // appear. The selected pair must not inherit that preference.
        let sdp = "a=candidate:1 1 UDP 1 10.0.0.2 9 typ host\r\na=candidate:2 1 UDP 1 198.51.100.8 9 typ relay";
        assert_eq!(classify_media_path(sdp), "host");
        assert_eq!(
            classify_selected_path("host", "relay", "10.0.0.2", "198.51.100.8"),
            "turn"
        );
        assert_eq!(
            classify_selected_path("typ host", "typ srflx", "10.0.0.2", "203.0.113.5"),
            "stun"
        );
        assert_eq!(
            classify_selected_path("host", "host", "127.0.0.1", "127.0.0.1"),
            "host"
        );
        assert_eq!(
            classify_selected_path("host", "host", "100.64.1.2", "100.64.1.3"),
            "tailscale"
        );
        assert_eq!(
            classify_selected_path("host", "host", "192.168.1.12", "100.65.0.4"),
            "tailscale"
        );
        assert_eq!(
            classify_selected_path("host", "host", "fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2"),
            "tailscale"
        );
        assert_eq!(addr_scope("127.0.0.1:9"), AddrScope::Loopback);
        assert_eq!(addr_scope("192.168.1.12"), AddrScope::PrivateLan);
        assert_eq!(addr_scope("10.0.0.2"), AddrScope::PrivateLan);
        assert_eq!(addr_scope("100.64.0.1"), AddrScope::CgnatTailscale);
        assert_eq!(addr_scope("203.0.113.5"), AddrScope::Public);
        assert_eq!(
            media_path_hint("jpeg", "relay"),
            "JPEG stills over the WebSocket relay — not WebRTC P2P"
        );
        assert!(
            !media_path_hint("h264", "host").contains("P2P")
                || media_path_hint("h264", "host").contains("LAN")
        );
        assert!(media_path_hint("h264", "turn").contains("not a direct P2P"));
    }

    #[test]
    fn screenshot_fallback_matches_the_phone_node() {
        let body = serde_json::json!({
            "status": "unavailable",
            "fallback": "screenshot"
        });
        assert!(is_screenshot_fallback(&body));
        assert!(!is_screenshot_fallback(
            &serde_json::json!({"status": "ok"})
        ));
    }
}
