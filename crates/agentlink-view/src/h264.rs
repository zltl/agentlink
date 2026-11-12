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

/// Count and label ICE candidates in an SDP (or loose candidate lines).
/// Used for diagnostics; this is not the selected-pair media path.
pub fn describe_ice_candidates(input: &str) -> String {
    let mut host = 0u32;
    let mut srflx = 0u32;
    let mut prflx = 0u32;
    let mut relay = 0u32;
    let mut other = 0u32;
    let mut items = Vec::new();
    for raw in input.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        let typ = if let Some(rest) = lower.split(" typ ").nth(1) {
            rest.split_whitespace().next().unwrap_or("unknown")
        } else if lower.contains("candidate:") {
            "unknown"
        } else {
            continue;
        };
        match typ {
            "host" => host += 1,
            "srflx" => srflx += 1,
            "prflx" => prflx += 1,
            "relay" => relay += 1,
            _ => other += 1,
        }
        let addr = candidate_addr(line).unwrap_or_else(|| "-".into());
        let scope = format!("{:?}", addr_scope(&addr)).to_ascii_lowercase();
        items.push(format!("{typ}:{scope}:{addr}"));
    }
    format!(
        "n={} host={} srflx={} prflx={} relay={} other={} [{}]",
        host + srflx + prflx + relay + other,
        host,
        srflx,
        prflx,
        relay,
        other,
        items.join(", ")
    )
}

fn candidate_addr(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let start = lower
        .find("candidate:")
        .map(|i| i + "candidate:".len())
        .unwrap_or(0);
    let tokens: Vec<&str> = line[start..].split_whitespace().collect();
    // foundation component transport priority address port typ ...
    if let Some(typ_at) = tokens.iter().position(|t| t.eq_ignore_ascii_case("typ")) {
        if typ_at >= 2 {
            return Some(tokens[typ_at - 2].to_string());
        }
    }
    tokens.get(4).map(|s| (*s).to_string())
}

/// Path token for a *selected* ICE candidate pair.
///
/// Tokens describe observable pair facts only:
/// `turn`, `stun`, `loopback`, `private`, `cgnat`, `tailscale`, `host`,
/// or `unknown`. `host` means typ host on a public or unparsed address.
/// It is not a claim of public NAT traversal success. `stun` is typ
/// srflx/prflx and is likewise not a NAT-success claim. `private` is typ
/// host on RFC1918/ULA/link-local and is not a claim of same-LAN (the
/// path may be a VPN or routed overlay). `cgnat` is typ host in
/// 100.64.0.0/10 (RFC 6598); that range is generic CGNAT and is not
/// itself a Tailscale confirmation. `tailscale` is used only when
/// [`detect_tailscale_reason`] finds a documented Tailscale identifier
/// (the `fd7a:115c:a1e0::/48` prefix, KB 1015) or a `tailscale*`
/// interface/route — never from 100.64/10 alone, and never by logging in.
pub fn classify_selected_path(
    local_typ: &str,
    remote_typ: &str,
    local_ip: &str,
    remote_ip: &str,
) -> &'static str {
    classify_selected_path_with(
        local_typ,
        remote_typ,
        local_ip,
        remote_ip,
        detect_tailscale_reason(local_ip, remote_ip).is_some(),
    )
}

/// Like [`classify_selected_path`], but the Tailscale confirmation is
/// supplied by the caller so tests do not depend on this host's routes.
pub fn classify_selected_path_with(
    local_typ: &str,
    remote_typ: &str,
    local_ip: &str,
    remote_ip: &str,
    tailscale_confirmed: bool,
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
        if tailscale_confirmed {
            return "tailscale";
        }
        let scopes = [addr_scope(local_ip), addr_scope(remote_ip)];
        if scopes.contains(&AddrScope::Cgnat) {
            return "cgnat";
        }
        if scopes.contains(&AddrScope::Loopback) {
            return "loopback";
        }
        if scopes.contains(&AddrScope::Public) {
            return "host";
        }
        if scopes.contains(&AddrScope::Private) {
            return "private";
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
    /// RFC1918, unique-local (except the Tailscale ULA), or link-local.
    Private,
    /// 100.64.0.0/10 (RFC 6598 shared space). Not a Tailscale identifier.
    Cgnat,
    /// Documented Tailscale IPv6 prefix fd7a:115c:a1e0::/48 (KB 1015).
    TailscaleUla,
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
                AddrScope::Cgnat
            } else if v4.is_private() || v4.is_link_local() {
                AddrScope::Private
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
                AddrScope::TailscaleUla
            } else if v6.is_unique_local() || v6.is_unicast_link_local() {
                AddrScope::Private
            } else if v6.is_unspecified() || v6.is_multicast() {
                AddrScope::Other
            } else {
                AddrScope::Public
            }
        }
    }
}

/// True when this address is in Tailscale's documented IPv6 prefix.
/// 100.64.0.0/10 is not included: that is generic RFC 6598 CGNAT.
pub fn is_tailscale_ula_prefix(ip: &str) -> bool {
    addr_scope(ip) == AddrScope::TailscaleUla
}

/// If this selected-pair address can be confirmed as Tailscale without a
/// Tailscale login, return a short reason. Confirmation is either the
/// documented IPv6 ULA prefix or a local `tailscale*` interface/route.
pub fn detect_tailscale_reason(local_ip: &str, remote_ip: &str) -> Option<String> {
    if is_tailscale_ula_prefix(local_ip) || is_tailscale_ula_prefix(remote_ip) {
        return Some(
            "address in fd7a:115c:a1e0::/48 (Tailscale documented IPv6 prefix, KB 1015)".into(),
        );
    }
    for ip in [local_ip, remote_ip] {
        if let Some(dev) = linux_route_device(ip) {
            if is_tailscale_iface(&dev) {
                return Some(format!(
                    "route to {ip} is via interface {dev} (name starts with tailscale)"
                ));
            }
        }
    }
    None
}

fn is_tailscale_iface(name: &str) -> bool {
    name.to_ascii_lowercase().starts_with("tailscale")
}

/// Best-effort Linux route lookup (`/proc/net/route`). Other OS: none.
fn linux_route_device(ip: &str) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        return linux_route_device_v4(strip_host(ip));
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = ip;
        None
    }
}

#[cfg(target_os = "linux")]
fn linux_route_device_v4(ip: &str) -> Option<String> {
    let addr: std::net::Ipv4Addr = ip.parse().ok()?;
    let bits = u32::from(addr);
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    let mut best: Option<(u32, String)> = None;
    for (i, line) in text.lines().enumerate() {
        if i == 0 {
            continue;
        }
        let mut cols = line.split_whitespace();
        let iface = cols.next()?;
        let dest = cols.next()?;
        let _gateway = cols.next()?;
        let _flags = cols.next()?;
        let _refcnt = cols.next()?;
        let _use = cols.next()?;
        let _metric = cols.next()?;
        let mask = cols.next()?;
        let dest_u = u32::from_str_radix(dest, 16).ok()?;
        let mask_u = u32::from_str_radix(mask, 16).ok()?;
        // /proc/net/route writes little-endian hex.
        let dest_ip = u32::from_le(dest_u);
        let mask_ip = u32::from_le(mask_u);
        if bits & mask_ip == dest_ip & mask_ip {
            let ones = mask_ip.count_ones();
            if best.as_ref().map(|(o, _)| ones > *o).unwrap_or(true) {
                best = Some((ones, iface.to_string()));
            }
        }
    }
    best.map(|(_, dev)| dev)
}

fn strip_host(raw: &str) -> &str {
    let raw = raw.trim();
    if let Some(rest) = raw.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    if raw.chars().filter(|c| *c == ':').count() == 1 {
        return raw.rsplit_once(':').map(|(h, _)| h).unwrap_or(raw);
    }
    raw
}

fn is_cgnat(addr: std::net::Ipv4Addr) -> bool {
    // RFC 6598 shared address space. Also used by Tailscale, but not unique.
    let o = addr.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

fn is_tailscale_ula(addr: std::net::Ipv6Addr) -> bool {
    // Tailscale IPv6 unique-local prefix fd7a:115c:a1e0::/48 (KB 1015).
    let s = addr.segments();
    s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0
}

/// Short explanation for the HUD. Claims only what the selected pair shows.
pub fn media_path_hint(kind: &str, path: &str) -> &'static str {
    let kind = kind.trim().to_ascii_lowercase();
    let path = path.trim().to_ascii_lowercase();
    if kind == "jpeg" || (kind.is_empty() && path == "relay") {
        return "JPEG stills over the WebSocket relay — not WebRTC P2P";
    }
    match path.as_str() {
        "loopback" => {
            "Selected ICE typ host on a loopback address (same host). Not cross-machine and not a public NAT traversal result"
        }
        "private" => {
            "Selected ICE typ host on a private address (RFC1918/ULA/link-local). May be LAN, VPN, or routed — not a same-LAN or public NAT claim"
        }
        "cgnat" => {
            "Selected ICE typ host in 100.64.0.0/10 (RFC 6598 CGNAT). That prefix alone does not identify Tailscale, and this is not a public NAT traversal result"
        }
        "host" => {
            "Selected ICE typ host on a public or unclassified address. This names the pair type only — it is not a public NAT traversal result"
        }
        "stun" => {
            "Selected ICE typ srflx/prflx (STUN-assisted). This is not a public NAT traversal result, and is not a Tailscale tunnel"
        }
        "turn" => "WebRTC media through a TURN relay — not a direct P2P path",
        "tailscale" => {
            "Selected typ host confirmed as Tailscale (documented IPv6 prefix or a tailscale* interface/route). Overlay, not public NAT traversal"
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
        if marker {
            self.finish()
        } else {
            None
        }
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
            classify_selected_path_with("host", "relay", "10.0.0.2", "198.51.100.8", false),
            "turn"
        );
        assert_eq!(
            classify_selected_path_with("typ host", "typ srflx", "10.0.0.2", "203.0.113.5", false),
            "stun"
        );
        assert_eq!(
            classify_selected_path_with("host", "host", "127.0.0.1", "127.0.0.1", false),
            "loopback"
        );
        assert_eq!(
            classify_selected_path_with("host", "host", "192.168.1.12", "10.0.0.2", false),
            "private"
        );
        // 100.64/10 alone is RFC 6598 CGNAT, not Tailscale.
        assert_eq!(
            classify_selected_path_with("host", "host", "100.64.1.2", "100.64.1.3", false),
            "cgnat"
        );
        assert_eq!(
            classify_selected_path_with("host", "host", "192.168.1.12", "100.65.0.4", false),
            "cgnat"
        );
        // Public typ host is possible and must not be called private or NAT success.
        assert_eq!(
            classify_selected_path_with("host", "host", "203.0.113.5", "198.51.100.8", false),
            "host"
        );
        // Mixed private + public typ host: do not invent "same LAN".
        assert_eq!(
            classify_selected_path_with("host", "host", "192.168.1.12", "203.0.113.5", false),
            "host"
        );
        // Tailscale only with extra confirmation, or the documented IPv6 prefix.
        assert_eq!(
            classify_selected_path_with("host", "host", "100.64.1.2", "100.64.1.3", true),
            "tailscale"
        );
        assert_eq!(
            classify_selected_path_with(
                "host",
                "host",
                "fd7a:115c:a1e0::1",
                "fd7a:115c:a1e0::2",
                detect_tailscale_reason("fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2").is_some()
            ),
            "tailscale"
        );
        assert!(detect_tailscale_reason("fd7a:115c:a1e0::1", "fd7a:115c:a1e0::2").is_some());
        assert!(detect_tailscale_reason("100.64.1.2", "100.64.1.3").is_none());
        assert_eq!(addr_scope("127.0.0.1:9"), AddrScope::Loopback);
        assert_eq!(addr_scope("192.168.1.12"), AddrScope::Private);
        assert_eq!(addr_scope("10.0.0.2"), AddrScope::Private);
        assert_eq!(addr_scope("100.64.0.1"), AddrScope::Cgnat);
        assert_eq!(addr_scope("203.0.113.5"), AddrScope::Public);
        assert_eq!(addr_scope("fd7a:115c:a1e0::1"), AddrScope::TailscaleUla);
        assert!(media_path_hint("jpeg", "relay").contains("not WebRTC P2P"));
        assert!(!media_path_hint("h264", "private")
            .to_ascii_lowercase()
            .contains("same lan"));
        assert!(!media_path_hint("h264", "host")
            .to_ascii_lowercase()
            .contains("success"));
        assert!(media_path_hint("h264", "cgnat").contains("RFC 6598"));
        assert!(!media_path_hint("h264", "cgnat").contains("confirmed as Tailscale"));
        assert!(media_path_hint("h264", "stun").contains("not a public NAT"));
        assert!(media_path_hint("h264", "turn").contains("not a direct P2P"));
        let inv = describe_ice_candidates(
            "a=candidate:1 1 UDP 2130706431 172.30.0.2 9 typ host\na=candidate:2 1 UDP 1694498815 203.0.113.5 9 typ srflx raddr 172.30.0.2 rport 9\n",
        );
        assert!(inv.contains("host=1"), "{inv}");
        assert!(inv.contains("srflx=1"), "{inv}");
        assert!(inv.contains("host:private:172.30.0.2"), "{inv}");
        assert!(inv.contains("srflx:public:203.0.113.5"), "{inv}");
    }

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
