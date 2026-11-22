//! Prefer on-link physical LAN host ICE candidates over VPN/overlay hosts.
//!
//! Pinned `webrtc`/`rtc-ice` 0.21.1 gathers every UDP host with the same
//! `DEFAULT_LOCAL_PREFERENCE` (65535) and nominates the first succeeded host
//! when `host_acceptance_min_wait` is 0. Same-LAN physical and Tailscale
//! `100.x` therefore race. This module scores **remote** host candidates at
//! ingest from **real local interface prefixes** (not assumed `/24` or
//! RFC1918-only) and rewrites the SDP priority field so pair priority prefers
//! physical on-link hosts while keeping overlay/VPN/srflx/relay candidates.
//!
//! `100.64.0.0/10` remains valid host P2P (mid preference). Never drop.
//!
//! Local gather still cannot set `CandidateConfig.priority` without patching
//! `webrtc` `stun_gatherer.rs` (SettingEngine interface filters are `/*todo*/`).
//! Remote rewrite + [`HOST_ACCEPTANCE_MIN_WAIT`] is the app-level half that
//! differentiates LAN↔LAN from overlay↔overlay when local prefs stay equal.
//!
//! Nondestructive fallbacks: empty local-prefix list, non-UDP transport,
//! non-host type, or component outside `1..=256` leave the candidate string
//! unchanged (no panic, no arbitrary downrank).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// ICE host type preference (RFC 8445 / rtc-ice 0.21.1).
pub const HOST_TYPE_PREFERENCE: u16 = 126;
/// rtc-ice default UDP local preference when no override is set.
pub const DEFAULT_LOCAL_PREFERENCE: u16 = 65535;
/// On-link via a non-tunnel local prefix.
pub const PHYSICAL_ON_LINK_PREF: u16 = 65535;
/// On-link only via CGNAT / Tailscale ULA / tunnel iface — still P2P.
pub const OVERLAY_ON_LINK_PREF: u16 = 49151;
/// Host address that is not on-link to any local prefix (e.g. other private NIC).
pub const OFF_LINK_HOST_PREF: u16 = 32767;
/// Virtual bridge (Docker/WSL/Hyper-V/libvirt/CNI/Podman) or link-local (`169.254/16`, `fe80::/10`).
/// Always ranked below physical LAN, overlay VPN, and off-link routable hosts, but still above srflx/relay.
pub const VIRTUAL_BRIDGE_HOST_PREF: u16 = 16383;
/// Short wait so multiple host pairs can succeed before nomination.
pub const HOST_ACCEPTANCE_MIN_WAIT: Duration = Duration::from_millis(250);

/// One local interface address with its OS prefix length.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IfacePrefix {
    pub addr: IpAddr,
    pub prefix_len: u8,
    pub name: String,
    /// Tunnel / CGNAT / Tailscale ULA — mid preference, never filtered out.
    pub overlay: bool,
}

/// True when `ip` lies in `prefix.addr/prefix_len` (same address family).
pub fn on_link(ip: IpAddr, prefix: &IfacePrefix) -> bool {
    match (ip, prefix.addr) {
        (IpAddr::V4(ip), IpAddr::V4(base)) => ipv4_prefix_contains(base, prefix.prefix_len, ip),
        (IpAddr::V6(ip), IpAddr::V6(base)) => ipv6_prefix_contains(base, prefix.prefix_len, ip),
        _ => false,
    }
}

/// Local preference for a remote host IP given real local prefixes.
///
/// Order: physical on-link > overlay/VPN on-link (incl. `100.64/10`, Wintun/Clash/Mihomo/WARP)
/// > off-link host > virtual bridge (Docker/WSL/Hyper-V/libvirt/CNI/Podman) and link-local
/// (`169.254/16`, `fe80::/10`).
///
/// Callers with an **empty** prefix list must not rewrite candidates: without
/// real iface data every host would look "off-link" and get hashed down. See
/// [`rewrite_candidate_line`].
pub fn host_local_pref(ip: IpAddr, prefixes: &[IfacePrefix]) -> u16 {
    if is_link_local_addr(ip) {
        return unique_in_band(VIRTUAL_BRIDGE_HOST_PREF, ip);
    }
    let mut saw_physical = false;
    let mut saw_overlay = false;
    let mut saw_virtual = false;
    for prefix in prefixes {
        if !on_link(ip, prefix) {
            continue;
        }
        if is_virtual_bridge_iface_name(&prefix.name) || is_link_local_addr(prefix.addr) {
            saw_virtual = true;
        } else if prefix.overlay
            || is_overlay_addr(prefix.addr)
            || is_overlay_iface_name(&prefix.name)
        {
            saw_overlay = true;
        } else {
            saw_physical = true;
        }
    }
    if saw_physical {
        unique_in_band(PHYSICAL_ON_LINK_PREF, ip)
    } else if saw_overlay {
        unique_in_band(OVERLAY_ON_LINK_PREF, ip)
    } else if saw_virtual {
        unique_in_band(VIRTUAL_BRIDGE_HOST_PREF, ip)
    } else {
        unique_in_band(OFF_LINK_HOST_PREF, ip)
    }
}

/// rtc-ice host priority formula for a **UDP** host candidate.
///
/// Returns [`None`] when `component` is not in `1..=256` (the `(256 − component)`
/// term). Never panics or wraps for any `u16` input.
pub fn host_priority(local_pref: u16, component: u16) -> Option<u32> {
    if !(1..=256).contains(&component) {
        return None;
    }
    Some(
        (1u32 << 24) * u32::from(HOST_TYPE_PREFERENCE)
            + (1u32 << 8) * u32::from(local_pref)
            + (256 - u32::from(component)),
    )
}

/// True for IPv4 link-local (`169.254.0.0/16`) or IPv6 link-local (`fe80::/10`).
pub fn is_link_local_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Interface-name heuristics for local container / VM / hypervisor virtual bridges
/// (Docker, libvirt, CNI, Podman, Windows Hyper-V / WSL `vEthernet`).
pub fn is_virtual_bridge_iface_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("docker")
        || n.starts_with("br-")
        || n.starts_with("virbr")
        || n.starts_with("cni")
        || n.starts_with("podman")
        || n.starts_with("veth")
        || n.starts_with("vboxnet")
        || n.starts_with("vmnet")
        || n.contains("vethernet")
}

/// Classify a local address as overlay/VPN (still valid P2P).
pub fn is_overlay_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_cgnat_v4(v4),
        IpAddr::V6(v6) => is_tailscale_ula_v6(v6),
    }
}

/// Interface-name heuristics for tunnels and VPN/proxy adapters (Tailscale,
/// WireGuard, utun, Wintun, Clash, Mihomo, Cloudflare WARP, etc.).
pub fn is_overlay_iface_name(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("tailscale")
        || n.starts_with("tun")
        || n.starts_with("tap")
        || n.starts_with("utun")
        || n.starts_with("wg")
        || n.starts_with("zt")
        || n.contains("wireguard")
        || n.contains("tailscale")
        || n.contains("wintun")
        || n.contains("clash")
        || n.contains("mihomo")
        || n.contains("warp")
}

/// Enumerate local unicast prefixes from the OS (real netmasks via `if-addrs`).
pub fn list_local_prefixes() -> Vec<IfacePrefix> {
    let Ok(ifaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(ifaces.len());
    for iface in ifaces {
        if iface.is_loopback() {
            continue;
        }
        let (addr, prefix_len) = match iface.addr {
            if_addrs::IfAddr::V4(v4) => {
                if v4.ip.is_unspecified() || v4.ip.is_multicast() {
                    continue;
                }
                (
                    IpAddr::V4(v4.ip),
                    prefix_len_from_netmask_v4(v4.netmask),
                )
            }
            if_addrs::IfAddr::V6(v6) => {
                if v6.ip.is_unspecified() || v6.ip.is_multicast() {
                    continue;
                }
                (
                    IpAddr::V6(v6.ip),
                    prefix_len_from_netmask_v6(v6.netmask),
                )
            }
        };
        out.push(IfacePrefix {
            overlay: is_overlay_addr(addr)
                || is_overlay_iface_name(&iface.name)
                || is_virtual_bridge_iface_name(&iface.name)
                || is_link_local_addr(addr),
            addr,
            prefix_len,
            name: iface.name,
        });
    }
    out
}

/// Rewrite the priority field of one ICE candidate attribute line.
///
/// Accepts `a=candidate:…`, `candidate:…`, or the bare attribute body.
/// Leaves the line unchanged when:
/// - prefixes are empty (no OS iface data → do not invent off-link ranks)
/// - transport is not UDP (TCP host uses a different local-pref formula)
/// - type is not `host`
/// - component is `0` or `> 256`, or fields are otherwise unparsable
///
/// Never panics. Never drops candidates.
pub fn rewrite_candidate_line(line: &str, prefixes: &[IfacePrefix]) -> String {
    if prefixes.is_empty() {
        return line.to_string();
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return line.to_string();
    }
    let (prefix, body) = split_candidate_prefix(trimmed);
    let mut parts: Vec<&str> = body.split_whitespace().collect();
    // foundation component transport priority address port typ host …
    if parts.len() < 8 || !parts[6].eq_ignore_ascii_case("typ") {
        return line.to_string();
    }
    if !parts[7].eq_ignore_ascii_case("host") {
        return line.to_string();
    }
    // Plan assumption / rtc-ice UDP default local_pref path — do not rewrite TCP.
    if !parts[2].eq_ignore_ascii_case("udp") {
        return line.to_string();
    }
    let Ok(component) = parts[1].parse::<u16>() else {
        return line.to_string();
    };
    let Ok(ip) = parse_candidate_ip(parts[4]) else {
        return line.to_string();
    };
    let Some(priority) = host_priority(host_local_pref(ip, prefixes), component) else {
        return line.to_string();
    };
    let priority_s = priority.to_string();
    parts[3] = priority_s.as_str();
    let rewritten = parts.join(" ");
    match prefix {
        CandidatePrefix::AEqual => format!("a=candidate:{rewritten}"),
        CandidatePrefix::Bare => format!("candidate:{rewritten}"),
        CandidatePrefix::None => rewritten,
    }
}

/// Rewrite every `a=candidate:` host line in an SDP body, preserving original
/// `\r\n` (RFC 4566) or `\n` line endings.
pub fn rewrite_sdp_remote_hosts(sdp: &str, prefixes: &[IfacePrefix]) -> String {
    if prefixes.is_empty() {
        return sdp.to_string();
    }
    let mut out = String::with_capacity(sdp.len() + 32);
    for segment in sdp.split_inclusive('\n') {
        let (line, eol) = if let Some(stripped) = segment.strip_suffix("\r\n") {
            (stripped, "\r\n")
        } else if let Some(stripped) = segment.strip_suffix('\n') {
            (stripped, "\n")
        } else {
            (segment, "")
        };
        if line
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("a=candidate:")
        {
            out.push_str(&rewrite_candidate_line(line, prefixes));
        } else {
            out.push_str(line);
        }
        out.push_str(eol);
    }
    out
}

/// List local prefixes and rewrite SDP host candidate priorities.
///
/// Empty enumeration → SDP returned unchanged.
pub fn prefer_on_link_hosts_in_sdp(sdp: &str) -> String {
    rewrite_sdp_remote_hosts(sdp, &list_local_prefixes())
}

/// List local prefixes and rewrite one candidate attribute string.
///
/// Empty enumeration → line returned unchanged.
pub fn prefer_on_link_hosts_in_candidate(line: &str) -> String {
    rewrite_candidate_line(line, &list_local_prefixes())
}

fn unique_in_band(base: u16, ip: IpAddr) -> u16 {
    let salt = match ip {
        IpAddr::V4(v4) => u16::from(v4.octets()[3]),
        IpAddr::V6(v6) => {
            let o = v6.octets();
            u16::from_be_bytes([o[14], o[15]])
        }
    };
    base.saturating_sub(salt % 256)
}

fn ipv4_prefix_contains(base: Ipv4Addr, prefix_len: u8, ip: Ipv4Addr) -> bool {
    let len = prefix_len.min(32);
    if len == 0 {
        return true;
    }
    let mask = if len == 32 {
        u32::MAX
    } else {
        !((1u32 << (32 - len)) - 1)
    };
    (u32::from(base) & mask) == (u32::from(ip) & mask)
}

fn ipv6_prefix_contains(base: Ipv6Addr, prefix_len: u8, ip: Ipv6Addr) -> bool {
    let len = prefix_len.min(128);
    if len == 0 {
        return true;
    }
    let base_u = u128::from(base);
    let ip_u = u128::from(ip);
    let mask = if len == 128 {
        u128::MAX
    } else {
        !((1u128 << (128 - len)) - 1)
    };
    (base_u & mask) == (ip_u & mask)
}

fn is_cgnat_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (o[1] & 0xc0) == 64
}

fn is_tailscale_ula_v6(ip: Ipv6Addr) -> bool {
    // fd7a:115c:a1e0::/48 — Tailscale documented IPv6 prefix (KB 1015).
    let o = ip.octets();
    o[0] == 0xfd
        && o[1] == 0x7a
        && o[2] == 0x11
        && o[3] == 0x5c
        && o[4] == 0xa1
        && o[5] == 0xe0
}

fn prefix_len_from_netmask_v4(mask: Ipv4Addr) -> u8 {
    u32::from(mask).count_ones() as u8
}

fn prefix_len_from_netmask_v6(mask: Ipv6Addr) -> u8 {
    u128::from(mask).count_ones() as u8
}

fn parse_candidate_ip(raw: &str) -> Result<IpAddr, ()> {
    let host = raw.trim().trim_start_matches('[').trim_end_matches(']');
    host.parse().map_err(|_| ())
}

#[derive(Clone, Copy)]
enum CandidatePrefix {
    AEqual,
    Bare,
    None,
}

fn split_candidate_prefix(line: &str) -> (CandidatePrefix, &str) {
    let lower = line.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("a=candidate:") {
        let body = &line[line.len() - rest.len()..];
        (CandidatePrefix::AEqual, body)
    } else if let Some(rest) = lower.strip_prefix("candidate:") {
        let body = &line[line.len() - rest.len()..];
        (CandidatePrefix::Bare, body)
    } else {
        (CandidatePrefix::None, line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn pref(addr: IpAddr, prefix_len: u8, name: &str, overlay: bool) -> IfacePrefix {
        IfacePrefix {
            addr,
            prefix_len,
            name: name.into(),
            overlay,
        }
    }

    /// Exact formula from pinned `rtc-ice-0.21.1` `CandidatePair::priority`.
    ///
    /// RFC 5245 §5.7.2 writes `2^32 * MIN(G,D) + …`. rtc-ice uses `(2^32 − 1) *
    /// MIN` so `1<<32` never overflows `u32` intermediates and `u32::MAX` pairs
    /// stay inside `u64`. Ordering is identical for our LAN-vs-overlay case
    /// (equal MIN, higher MAX wins).
    fn rtc_ice_pair_priority(controlling: u32, controlled: u32) -> u64 {
        let (g, d) = (controlling, controlled);
        ((1u64 << 32) - 1) * u64::from(std::cmp::min(g, d))
            + 2 * u64::from(std::cmp::max(g, d))
            + u64::from(g > d)
    }

    #[test]
    fn on_link_respects_real_prefix_not_assumed_24() {
        let lan24 = pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)), 24, "eth0", false);
        assert!(on_link(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12)), &lan24));
        assert!(!on_link(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 12)), &lan24));

        let lan16 = pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)), 16, "eth0", false);
        assert!(on_link(IpAddr::V4(Ipv4Addr::new(192, 168, 200, 9)), &lan16));

        let only24 = pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)), 24, "eth0", false);
        assert!(!on_link(IpAddr::V4(Ipv4Addr::new(192, 168, 200, 9)), &only24));

        let ten = pref(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 8, "eth0", false);
        assert!(on_link(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), &ten));
        assert!(on_link(IpAddr::V4(Ipv4Addr::new(10, 255, 1, 2)), &ten));
        assert!(!on_link(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 5)), &ten));
    }

    #[test]
    fn on_link_ipv6_and_non24_v4() {
        let ula = pref(
            IpAddr::V6("fd12:3456:789a::1".parse::<Ipv6Addr>().unwrap()),
            64,
            "eth0",
            false,
        );
        assert!(on_link(
            IpAddr::V6("fd12:3456:789a::99".parse().unwrap()),
            &ula
        ));
        assert!(!on_link(
            IpAddr::V6("fd12:3456:789b::99".parse().unwrap()),
            &ula
        ));

        let slash25 = pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 25, "eth0", false);
        assert!(on_link(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            &slash25
        ));
        assert!(!on_link(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 200)),
            &slash25
        ));
    }

    #[test]
    fn scoring_physical_over_cgnat_over_off_link_hyperv() {
        let prefixes = vec![
            pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)), 24, "eth0", false),
            pref(
                IpAddr::V4(Ipv4Addr::new(100, 109, 112, 34)),
                10,
                "tailscale0",
                true,
            ),
            pref(
                IpAddr::V4(Ipv4Addr::new(192, 168, 140, 1)),
                24,
                "vEthernet",
                false,
            ),
        ];

        let physical = host_local_pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12)), &prefixes);
        let cgnat = host_local_pref(IpAddr::V4(Ipv4Addr::new(100, 91, 104, 2)), &prefixes);
        let hyperv_remote =
            host_local_pref(IpAddr::V4(Ipv4Addr::new(192, 168, 190, 1)), &prefixes);

        assert!(physical > cgnat, "{physical} > {cgnat}");
        assert!(cgnat > hyperv_remote, "{cgnat} > {hyperv_remote}");
        // 100.x stays a host preference band — not "not P2P".
        assert!(cgnat > 40000);
        assert!(host_priority(physical, 1).unwrap() > host_priority(cgnat, 1).unwrap());
        assert!(host_priority(cgnat, 1).unwrap() > host_priority(hyperv_remote, 1).unwrap());
    }

    #[test]
    fn host_still_outranks_srflx_and_relay_type_prefs() {
        let host = host_priority(OFF_LINK_HOST_PREF, 1).unwrap();
        let srflx = (1u32 << 24) * 100 + (1u32 << 8) * u32::from(DEFAULT_LOCAL_PREFERENCE) + 255;
        let relay = (1u32 << 8) * u32::from(DEFAULT_LOCAL_PREFERENCE) + 255;
        assert!(host > srflx);
        assert!(srflx > relay);
    }

    #[test]
    fn rtc_ice_pair_priority_prefers_boosted_remote_lan_when_locals_equal() {
        let local = host_priority(DEFAULT_LOCAL_PREFERENCE, 1).unwrap();
        let remote_lan = host_priority(PHYSICAL_ON_LINK_PREF, 1).unwrap();
        let remote_ts = host_priority(OVERLAY_ON_LINK_PREF, 1).unwrap();
        let lan_pair = rtc_ice_pair_priority(local, remote_lan);
        let ts_pair = rtc_ice_pair_priority(local, remote_ts);
        assert!(lan_pair > ts_pair, "{lan_pair} > {ts_pair}");
        // Same ordering under literal RFC 2^32*MIN (proof the (2^32-1) pin is fine here).
        let rfc = |g: u32, d: u32| {
            (1u64 << 32) * u64::from(std::cmp::min(g, d))
                + 2 * u64::from(std::cmp::max(g, d))
                + u64::from(g > d)
        };
        assert!(rfc(local, remote_lan) > rfc(local, remote_ts));
    }

    #[test]
    fn host_priority_rejects_invalid_components_without_panic() {
        assert!(host_priority(DEFAULT_LOCAL_PREFERENCE, 1).is_some());
        assert!(host_priority(DEFAULT_LOCAL_PREFERENCE, 2).is_some());
        assert!(host_priority(DEFAULT_LOCAL_PREFERENCE, 256).is_some());
        assert_eq!(host_priority(DEFAULT_LOCAL_PREFERENCE, 0), None);
        assert_eq!(host_priority(DEFAULT_LOCAL_PREFERENCE, 257), None);
        assert_eq!(host_priority(DEFAULT_LOCAL_PREFERENCE, 65535), None);
    }

    #[test]
    fn rewrite_leaves_malformed_components_unchanged() {
        let prefixes = vec![pref(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
            24,
            "eth0",
            false,
        )];
        for component in ["0", "257", "65535"] {
            let line = format!(
                "candidate:1 {component} udp 2130706431 192.168.1.12 54444 typ host"
            );
            assert_eq!(
                rewrite_candidate_line(&line, &prefixes),
                line,
                "component={component}"
            );
        }
        let unparsed = "candidate:1 not-a-number udp 2130706431 192.168.1.12 54444 typ host";
        assert_eq!(rewrite_candidate_line(unparsed, &prefixes), unparsed);
    }

    #[test]
    fn rewrite_leaves_tcp_host_unchanged() {
        let prefixes = vec![pref(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
            24,
            "eth0",
            false,
        )];
        let tcp = "candidate:1 1 tcp 2130706431 192.168.1.12 54444 typ host tcptype passive";
        assert_eq!(rewrite_candidate_line(tcp, &prefixes), tcp);
    }

    #[test]
    fn empty_prefixes_keep_original_priority() {
        let host = "candidate:1 1 udp 2130706431 192.168.1.12 54444 typ host";
        assert_eq!(rewrite_candidate_line(host, &[]), host);
        let sdp = "v=0\na=candidate:1 1 udp 2130706431 192.168.1.12 1 typ host\n";
        assert_eq!(rewrite_sdp_remote_hosts(sdp, &[]), sdp);
    }

    #[test]
    fn rewrite_changes_host_priority_field_leaves_srflx() {
        let prefixes = vec![
            pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)), 24, "eth0", false),
            pref(
                IpAddr::V4(Ipv4Addr::new(100, 64, 1, 1)),
                10,
                "tailscale0",
                true,
            ),
        ];
        let host = "candidate:1 1 udp 2130706431 192.168.1.12 54444 typ host";
        let out = rewrite_candidate_line(host, &prefixes);
        let parts: Vec<_> = out.split_whitespace().collect();
        assert_eq!(parts[0], "candidate:1");
        let p: u32 = parts[3].parse().unwrap();
        assert_ne!(p, 2130706431);
        assert_eq!(
            p,
            host_priority(
                host_local_pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 12)), &prefixes),
                1
            )
            .unwrap()
        );
        assert_ne!(p, 0);

        let srflx = "a=candidate:2 1 udp 1694498815 203.0.113.5 54444 typ srflx raddr 192.168.1.12 rport 54444";
        assert_eq!(rewrite_candidate_line(srflx, &prefixes), srflx);
    }

    #[test]
    fn rewrite_sdp_only_touches_host_lines() {
        let prefixes = vec![pref(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            8,
            "eth0",
            false,
        )];
        let sdp = "v=0\na=candidate:1 1 udp 2130706431 10.0.0.5 1 typ host\na=candidate:2 1 udp 100 203.0.113.1 1 typ srflx\n";
        let out = rewrite_sdp_remote_hosts(sdp, &prefixes);
        assert!(out.contains("typ srflx"));
        let host_line = out.lines().find(|l| l.contains("typ host")).unwrap();
        assert!(!host_line.contains("2130706431"));
    }

    #[test]
    fn cgnat_100_is_overlay_not_excluded() {
        assert!(is_overlay_addr(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_overlay_addr(IpAddr::V4(Ipv4Addr::new(100, 127, 1, 1))));
        assert!(!is_overlay_addr(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
        assert!(is_overlay_iface_name("tailscale0"));
        assert!(is_overlay_iface_name("utun3"));
        assert!(!is_overlay_iface_name("eth0"));
    }

    #[test]
    fn host_acceptance_wait_is_nonzero_vs_rtc_ice_default() {
        assert!(HOST_ACCEPTANCE_MIN_WAIT > Duration::from_secs(0));
        assert!(HOST_ACCEPTANCE_MIN_WAIT <= Duration::from_millis(500));
    }

    #[test]
    fn desk24_virtual_bridges_vpn_adapters_and_link_local_are_downranked() {
        for bridge in [
            "docker0",
            "br-1a2b3c4d",
            "virbr0",
            "cni0",
            "podman0",
            "vEthernet (WSL)",
            "vEthernet (Default Switch)",
        ] {
            assert!(is_virtual_bridge_iface_name(bridge), "expected virtual bridge: {bridge}");
        }
        for vpn in ["wintun", "Clash", "MihomoMeta", "CloudflareWARP"] {
            assert!(is_overlay_iface_name(vpn), "expected overlay/VPN: {vpn}");
        }
        assert!(is_link_local_addr(IpAddr::V4(Ipv4Addr::new(169, 254, 10, 5))));
        assert!(is_link_local_addr(IpAddr::V6(
            "fe80::1".parse::<Ipv6Addr>().unwrap()
        )));
        assert!(!is_link_local_addr(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 5))));

        let prefixes = vec![
            pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)), 24, "eth0", false),
            pref(IpAddr::V4(Ipv4Addr::new(172, 17, 0, 1)), 16, "docker0", false),
            pref(IpAddr::V4(Ipv4Addr::new(192, 168, 122, 1)), 24, "virbr0", false),
            pref(IpAddr::V4(Ipv4Addr::new(172, 24, 0, 1)), 20, "vEthernet (WSL)", false),
            pref(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 24, "wintun", false),
            pref(
                IpAddr::V6("fe80::1".parse::<Ipv6Addr>().unwrap()),
                64,
                "eth0",
                false,
            ),
        ];

        let lan = host_local_pref(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50)), &prefixes);
        let wintun = host_local_pref(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)), &prefixes);
        let docker = host_local_pref(IpAddr::V4(Ipv4Addr::new(172, 17, 0, 2)), &prefixes);
        let wsl = host_local_pref(IpAddr::V4(Ipv4Addr::new(172, 24, 0, 5)), &prefixes);
        let apipa = host_local_pref(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 2)), &prefixes);
        let ll6 = host_local_pref(IpAddr::V6("fe80::2".parse::<Ipv6Addr>().unwrap()), &prefixes);

        assert!(lan > wintun, "{lan} > {wintun}");
        assert!(wintun > docker, "{wintun} > {docker}");
        assert!(wintun > wsl, "{wintun} > {wsl}");
        assert!(wintun > apipa, "{wintun} > {apipa}");
        assert!(wintun > ll6, "{wintun} > {ll6}");
        // Virtual bridge / link-local still stay valid host candidates above srflx.
        let srflx = (1u32 << 24) * 100 + (1u32 << 8) * u32::from(DEFAULT_LOCAL_PREFERENCE) + 255;
        assert!(host_priority(docker, 1).unwrap() > srflx);
    }

    #[test]
    fn strm03_rewrite_sdp_preserves_crlf_line_endings() {
        let prefixes = vec![pref(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 8)),
            24,
            "eth0",
            false,
        )];
        let sdp = "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\na=candidate:1 1 udp 2130706431 192.168.1.12 54444 typ host\r\na=candidate:2 1 udp 100 203.0.113.1 1 typ srflx\r\n";
        let out = rewrite_sdp_remote_hosts(sdp, &prefixes);
        assert!(out.ends_with("\r\n"), "must preserve trailing CRLF");
        for seg in out.split_inclusive('\n') {
            assert!(seg.ends_with("\r\n"), "lost CRLF in segment: {seg:?}");
        }
        assert!(out.contains("192.168.1.12"));
        assert!(!out.contains("2130706431"));
    }
}
