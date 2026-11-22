//! STUN servers advertised to desktop viewers.
//!
//! `AGENTLINK_STUN_URLS` is a comma-separated list. When that variable is
//! unset, viewers get [`DEFAULT_STUN_URLS`]: public STUN, no credentials, and
//! no media relay. An empty value turns STUN off (host candidates only).
//! TURN stays opt-in via `AGENTLINK_TURN_URLS`. Short-lived REST credentials
//! (`AGENTLINK_TURN_SECRET`) are minted on an authenticated request. A public
//! ICE document lists TURN URLs and never includes a username or credential.
//! `AGENTLINK_TURN_USERNAME` and `AGENTLINK_TURN_PASSWORD` are obsolete;
//! treat any password that was published in `/view/config.json` as compromised.
//!
//! [`stun_urls_ready_for_ice`] may rewrite *built-in* [`DEFAULT_STUN_URLS`]
//! when system DNS is unusable (empty or only RFC 2544 `198.18.0.0/15`).
//! That rewrite uses DoH (`https://cloudflare-dns.com/dns-query`,
//! `https://dns.google/resolve`) and substitutes literal IPs so WebRTC does
//! not re-resolve via a poisoned resolver. This is a Controller-side
//! compatibility path for this class of proxy/resolver, not a general DNS
//! override.
//!
//! Operator-supplied `AGENTLINK_STUN_URLS` are never sent to third-party
//! DoH and are never silently rewritten to literals (private or split-horizon
//! names stay as the operator wrote them). Literal `198.18.0.0/15`
//! destinations are still skipped. Set `AGENTLINK_STUN_REWRITE=off` to
//! disable default-url rewrite and DoH entirely. Unset or
//! `defaults`/`on` keeps the default-only policy. If a default URL cannot
//! be rewritten, it is omitted and logged; the offer continues with any
//! remaining STUN URLs (host-only if none remain).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Public STUN servers used when `AGENTLINK_STUN_URLS` is unset.
/// These reveal a reflexive address. They do not relay media through symmetric NAT.
pub const DEFAULT_STUN_URLS: &[&str] = &[
    "stun:stun.l.google.com:19302",
    "stun:stun1.l.google.com:19302",
    "stun:stun.cloudflare.com:3478",
];

/// Resolve STUN URLs from an optional environment value.
///
/// `None` means the variable is unset, so the public defaults apply.
/// `Some("")` or a list of only commas means the operator disabled STUN.
pub fn stun_urls(configured: Option<&str>) -> Vec<String> {
    let Some(configured) = configured else {
        return DEFAULT_STUN_URLS
            .iter()
            .map(|url| (*url).to_string())
            .collect();
    };
    configured
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(str::to_string)
        .collect()
}

/// `AGENTLINK_STUN_URLS` for this process. Unset uses [`DEFAULT_STUN_URLS`].
pub fn stun_urls_from_env() -> Vec<String> {
    match std::env::var("AGENTLINK_STUN_URLS") {
        Ok(value) => stun_urls(Some(&value)),
        Err(_) => stun_urls(None),
    }
}

/// One ICE attempt the viewer runs, in order, until a peer connection connects.
///
/// Auto walks host, then each STUN server, then each TURN UDP URL, then TURN
/// TCP. A dead server is abandoned after [`IceAttempt::gather_ms`] plus
/// [`IceAttempt::connect_ms`] instead of waiting out a full STUN retransmit
/// schedule. Addresses in `198.18.0.0/15` are skipped: that range is not a
/// reachable STUN or TURN server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IceAttempt {
    pub id: &'static str,
    pub banner: &'static str,
    pub policy: &'static str,
    pub gather_ms: u64,
    pub connect_ms: u64,
    pub urls: Vec<String>,
    pub username: String,
    pub credential: String,
}

impl IceAttempt {
    pub fn to_json(&self) -> serde_json::Value {
        let mut server = serde_json::json!({ "urls": self.urls });
        if !self.username.is_empty() {
            server["username"] = serde_json::json!(self.username);
        }
        if !self.credential.is_empty() {
            server["credential"] = serde_json::json!(self.credential);
        }
        let ice_servers = if self.urls.is_empty() {
            Vec::<serde_json::Value>::new()
        } else {
            vec![server]
        };
        serde_json::json!({
            "id": self.id,
            "banner": self.banner,
            "ice_transport_policy": self.policy,
            "gather_ms": self.gather_ms,
            "connect_ms": self.connect_ms,
            "ice_servers": ice_servers,
        })
    }
}

/// Host, then one attempt per STUN URL, then TURN UDP, then TURN TCP.
///
/// A UDP `turn:` URL also produces a TCP attempt (`transport=tcp`) so relay
/// TCP is tried even when the operator only listed UDP. `turns:` is TCP only.
pub fn ice_attempts(
    stun: &[String],
    turn_urls: &[String],
    username: &str,
    credential: &str,
) -> Vec<IceAttempt> {
    let mut out = vec![IceAttempt {
        id: "host",
        banner: "via host",
        policy: "all",
        gather_ms: 800,
        connect_ms: 3_000,
        urls: Vec::new(),
        username: String::new(),
        credential: String::new(),
    }];
    for url in stun {
        if !usable_ice_url(url) || !url.to_ascii_lowercase().starts_with("stun:") {
            continue;
        }
        out.push(IceAttempt {
            id: "srflx",
            banner: "via STUN",
            policy: "all",
            gather_ms: 2_500,
            connect_ms: 4_000,
            urls: vec![url.clone()],
            username: String::new(),
            credential: String::new(),
        });
    }
    let mut udp = Vec::new();
    let mut listed_tcp = Vec::new();
    for url in turn_urls {
        if !usable_ice_url(url) {
            continue;
        }
        match turn_class(url) {
            Some(TurnClass::Udp) => udp.push(url.clone()),
            Some(TurnClass::Tcp) => listed_tcp.push(url.clone()),
            None => {}
        }
    }
    let mut tcp = Vec::new();
    for url in &udp {
        let variant = tcp_variant(url);
        if !tcp.iter().any(|item| item == &variant)
            && !listed_tcp.iter().any(|item| item == &variant)
        {
            tcp.push(variant);
        }
    }
    for url in listed_tcp {
        if !tcp.iter().any(|item| item == &url) {
            tcp.push(url);
        }
    }
    for url in udp {
        out.push(relay_attempt(
            "relay-udp",
            "via TURN udp",
            5_000,
            6_000,
            url,
            username,
            credential,
        ));
    }
    for url in tcp {
        out.push(relay_attempt(
            "relay-tcp",
            "via TURN tcp",
            6_000,
            6_000,
            url,
            username,
            credential,
        ));
    }
    out
}

fn relay_attempt(
    id: &'static str,
    banner: &'static str,
    gather_ms: u64,
    connect_ms: u64,
    url: String,
    username: &str,
    credential: &str,
) -> IceAttempt {
    IceAttempt {
        id,
        banner,
        policy: "relay",
        gather_ms,
        connect_ms,
        urls: vec![url],
        username: username.to_string(),
        credential: credential.to_string(),
    }
}

#[derive(Clone, Copy)]
enum TurnClass {
    Udp,
    Tcp,
}

fn turn_class(url: &str) -> Option<TurnClass> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("turns:") || lower.contains("transport=tcp") {
        return Some(TurnClass::Tcp);
    }
    if lower.starts_with("turn:") {
        return Some(TurnClass::Udp);
    }
    None
}

fn tcp_variant(url: &str) -> String {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("turns:") || lower.contains("transport=tcp") {
        return url.to_string();
    }
    if let Some(idx) = lower.find("transport=udp") {
        let mut out = url.to_string();
        out.replace_range(idx..idx + "transport=udp".len(), "transport=tcp");
        return out;
    }
    if url.contains('?') {
        format!("{url}&transport=tcp")
    } else {
        format!("{url}?transport=tcp")
    }
}

fn usable_ice_url(url: &str) -> bool {
    let Some(host) = ice_url_host(url) else {
        return !url.trim().is_empty();
    };
    !is_benchmarking_v4(&host)
}

fn ice_url_host(url: &str) -> Option<String> {
    let rest = url.split_once(':')?.1;
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    if let Some(rest) = rest.strip_prefix('[') {
        return Some(rest.split(']').next()?.to_string());
    }
    let host = match rest.rsplit_once(':') {
        Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => host,
        _ => rest,
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// `198.18.0.0/15` is the RFC 2544 benchmarking range. It shows up when a
/// resolver hands back a non-routable address, and a STUN client will
/// retransmit at it until the transaction dies.
fn is_benchmarking_v4(host: &str) -> bool {
    let Ok(ip) = host.parse::<std::net::Ipv4Addr>() else {
        return false;
    };
    let octets = ip.octets();
    octets[0] == 198 && (octets[1] == 18 || octets[1] == 19)
}

/// Rewrite ICE URLs so the WebRTC stack does not target RFC 2544
/// `198.18.0.0/15` addresses. Some resolvers return that range for public
/// STUN hostnames; a STUN transaction to them never completes, so typ srflx
/// never appears. When system DNS only yields that range, [`resolve`] may
/// return usable addresses from another lookup (DoH). Hostnames that cannot
/// be rewritten are omitted rather than left to resolve to 198.18/15.
pub fn rewrite_ice_urls<F>(urls: &[String], mut resolve: F) -> Vec<String>
where
    F: FnMut(&str) -> Vec<IpAddr>,
{
    let mut out = Vec::new();
    for url in urls {
        let Some((scheme, host, suffix)) = split_ice_url_parts(url) else {
            out.push(url.clone());
            continue;
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_benchmarking_ip(ip) {
                eprintln!(
                    "agentlink live-webrtc: skipping ICE URL in RFC 2544 198.18.0.0/15 ({url})"
                );
                continue;
            }
            out.push(url.clone());
            continue;
        }
        let usable: Vec<IpAddr> = resolve(&host)
            .into_iter()
            .filter(|ip| !is_benchmarking_ip(*ip))
            .collect();
        if usable.is_empty() {
            eprintln!(
                "agentlink live-webrtc: no usable address for ICE host {host} (system DNS may have returned 198.18.0.0/15); skipping"
            );
            continue;
        }
        for ip in usable {
            let rewritten = format_ice_url(scheme, ip, suffix);
            if rewritten != *url {
                eprintln!(
                    "agentlink live-webrtc: ICE URL {url} rewritten to {rewritten} so the peer connection does not re-resolve via poisoned DNS"
                );
            }
            out.push(rewritten);
        }
    }
    out
}

/// Policy for [`stun_urls_ready_for_ice`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StunRewriteMode {
    /// Never DoH, never rewrite hostnames to literals. Literal RFC 2544
    /// destinations are still skipped.
    Off,
    /// Rewrite only [`DEFAULT_STUN_URLS`], and only when system DNS is
    /// unusable for that host. Operator `AGENTLINK_STUN_URLS` are unchanged
    /// (aside from skipping literal 198.18/15).
    DefaultsOnly,
}

/// Parse `AGENTLINK_STUN_REWRITE`. `None` (unset), empty, `defaults`, or
/// `on` → [`StunRewriteMode::DefaultsOnly`]. `off`/`0`/`false` →
/// [`StunRewriteMode::Off`]. Unknown values log and use defaults-only.
pub fn stun_rewrite_mode_from_value(value: Option<&str>) -> StunRewriteMode {
    let Some(value) = value else {
        return StunRewriteMode::DefaultsOnly;
    };
    let value = value.trim().to_ascii_lowercase();
    if value.is_empty()
        || matches!(
            value.as_str(),
            "1" | "on" | "true" | "yes" | "defaults" | "default"
        )
    {
        StunRewriteMode::DefaultsOnly
    } else if matches!(
        value.as_str(),
        "0" | "off" | "false" | "no" | "disable" | "disabled"
    ) {
        StunRewriteMode::Off
    } else {
        eprintln!(
            "agentlink live-webrtc: unknown AGENTLINK_STUN_REWRITE={value}; using defaults-only"
        );
        StunRewriteMode::DefaultsOnly
    }
}

/// Read `AGENTLINK_STUN_REWRITE` for [`stun_urls_ready_for_ice`].
pub fn stun_rewrite_mode_from_env() -> StunRewriteMode {
    stun_rewrite_mode_from_value(std::env::var("AGENTLINK_STUN_REWRITE").ok().as_deref())
}

/// True when `url` is one of the built-in public STUN servers (scheme, host,
/// and port), so a DoH fallback is in scope.
pub fn is_default_stun_url(url: &str) -> bool {
    let Some(key) = stun_url_key(url) else {
        return false;
    };
    DEFAULT_STUN_URLS
        .iter()
        .any(|item| stun_url_key(item) == Some(key.clone()))
}

fn stun_url_key(url: &str) -> Option<(String, String, String)> {
    let (scheme, host, suffix) = split_ice_url_parts(url)?;
    Some((
        scheme.to_ascii_lowercase(),
        host.to_ascii_lowercase(),
        suffix.to_ascii_lowercase(),
    ))
}

/// Apply [`StunRewriteMode`] to a STUN URL list.
///
/// `system_lookup` is ordinary DNS. `doh_lookup` is only consulted for
/// built-in default hosts, and only when system DNS is empty or only RFC 2544.
pub fn prepare_stun_urls<F, G>(
    urls: &[String],
    mode: StunRewriteMode,
    mut system_lookup: F,
    mut doh_lookup: G,
) -> Vec<String>
where
    F: FnMut(&str) -> Vec<IpAddr>,
    G: FnMut(&str) -> Vec<IpAddr>,
{
    let mut out = Vec::new();
    for url in urls {
        let Some((scheme, host, suffix)) = split_ice_url_parts(url) else {
            out.push(url.clone());
            continue;
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_benchmarking_ip(ip) {
                eprintln!(
                    "agentlink live-webrtc: skipping ICE URL in RFC 2544 198.18.0.0/15 ({url})"
                );
                continue;
            }
            out.push(url.clone());
            continue;
        }
        let default = is_default_stun_url(url);
        if mode == StunRewriteMode::Off || !default {
            out.push(url.clone());
            continue;
        }
        let system = system_lookup(&host);
        let usable_system: Vec<IpAddr> = system
            .iter()
            .copied()
            .filter(|ip| !is_benchmarking_ip(*ip))
            .collect();
        if !usable_system.is_empty() {
            // Healthy system DNS: leave the hostname so WebRTC uses the
            // operator/system resolver. No silent literal rewrite.
            out.push(url.clone());
            continue;
        }
        if system.iter().any(|ip| is_benchmarking_ip(*ip)) {
            eprintln!(
                "agentlink live-webrtc: default STUN host {host} resolved to RFC 2544 198.18.0.0/15 via system DNS; trying DoH (AGENTLINK_STUN_REWRITE=defaults)"
            );
        } else {
            eprintln!(
                "agentlink live-webrtc: default STUN host {host} had no system DNS address; trying DoH (AGENTLINK_STUN_REWRITE=defaults)"
            );
        }
        let usable_doh: Vec<IpAddr> = doh_lookup(&host)
            .into_iter()
            .filter(|ip| !is_benchmarking_ip(*ip))
            .collect();
        if usable_doh.is_empty() {
            eprintln!(
                "agentlink live-webrtc: no usable DoH address for default STUN host {host}; omitting rather than leaving a poisoned hostname"
            );
            continue;
        }
        for ip in usable_doh {
            let rewritten = format_ice_url(scheme, ip, suffix);
            eprintln!(
                "agentlink live-webrtc: ICE URL {url} rewritten to {rewritten} so the peer connection does not re-resolve via poisoned DNS"
            );
            out.push(rewritten);
        }
    }
    out
}

/// TTL for cached prepared STUN URL results so repeated connects do not repeat
/// DNS/DoH round-trips or stall callers.
pub const STUN_CACHE_TTL: Duration = Duration::from_secs(300);

type StunCacheKey = (Vec<String>, StunRewriteMode);
type StunCacheEntry = (Instant, Vec<String>);

fn stun_cache() -> &'static Mutex<HashMap<StunCacheKey, StunCacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<StunCacheKey, StunCacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn stun_cache_get(urls: &[String], mode: StunRewriteMode) -> Option<Vec<String>> {
    let guard = stun_cache().lock().ok()?;
    let key = (urls.to_vec(), mode);
    let (at, cached) = guard.get(&key)?;
    if at.elapsed() <= STUN_CACHE_TTL {
        Some(cached.clone())
    } else {
        None
    }
}

fn stun_cache_put(urls: &[String], mode: StunRewriteMode, resolved: &[String]) {
    if let Ok(mut guard) = stun_cache().lock() {
        guard.retain(|_, (at, _)| at.elapsed() <= STUN_CACHE_TTL);
        if guard.len() >= 32 {
            guard.clear();
        }
        guard.insert((urls.to_vec(), mode), (Instant::now(), resolved.to_vec()));
    }
}

#[cfg(test)]
fn clear_stun_cache() {
    if let Ok(mut guard) = stun_cache().lock() {
        guard.clear();
    }
}

/// Async version of [`prepare_stun_urls`] using `tokio::net::lookup_host` and
/// async DoH (`A` + `AAAA` with literal bootstrap IPs) so Tokio worker threads
/// are never blocked by `thread::join()` or `reqwest::blocking`.
pub async fn prepare_stun_urls_async(urls: &[String], mode: StunRewriteMode) -> Vec<String> {
    if let Some(cached) = stun_cache_get(urls, mode) {
        return cached;
    }
    let mut out = Vec::new();
    for url in urls {
        let Some((scheme, host, suffix)) = split_ice_url_parts(url) else {
            out.push(url.clone());
            continue;
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            if is_benchmarking_ip(ip) {
                eprintln!(
                    "agentlink live-webrtc: skipping ICE URL in RFC 2544 198.18.0.0/15 ({url})"
                );
                continue;
            }
            out.push(url.clone());
            continue;
        }
        let default = is_default_stun_url(url);
        if mode == StunRewriteMode::Off || !default {
            out.push(url.clone());
            continue;
        }
        let system = lookup_host_system_async(&host).await;
        let usable_system: Vec<IpAddr> = system
            .iter()
            .copied()
            .filter(|ip| !is_benchmarking_ip(*ip))
            .collect();
        if !usable_system.is_empty() {
            out.push(url.clone());
            continue;
        }
        if system.iter().any(|ip| is_benchmarking_ip(*ip)) {
            eprintln!(
                "agentlink live-webrtc: default STUN host {host} resolved to RFC 2544 198.18.0.0/15 via system DNS; trying DoH (AGENTLINK_STUN_REWRITE=defaults)"
            );
        } else {
            eprintln!(
                "agentlink live-webrtc: default STUN host {host} had no system DNS address; trying DoH (AGENTLINK_STUN_REWRITE=defaults)"
            );
        }
        let usable_doh: Vec<IpAddr> = doh_lookup_async(&host)
            .await
            .into_iter()
            .filter(|ip| !is_benchmarking_ip(*ip))
            .collect();
        if usable_doh.is_empty() {
            eprintln!(
                "agentlink live-webrtc: no usable DoH address for default STUN host {host}; omitting rather than leaving a poisoned hostname"
            );
            continue;
        }
        for ip in usable_doh {
            let rewritten = format_ice_url(scheme, ip, suffix);
            eprintln!(
                "agentlink live-webrtc: ICE URL {url} rewritten to {rewritten} so the peer connection does not re-resolve via poisoned DNS"
            );
            out.push(rewritten);
        }
    }
    stun_cache_put(urls, mode, &out);
    out
}

/// Async, TTL-cached preparation of STUN URLs from the environment for WebRTC.
///
/// Prefer this over [`stun_urls_ready_for_ice`] inside async tasks so Tokio
/// worker threads are never blocked.
pub async fn stun_urls_ready_for_ice_async() -> Vec<String> {
    let urls = stun_urls_from_env();
    let mode = stun_rewrite_mode_from_env();
    prepare_stun_urls_async(&urls, mode).await
}

/// Default or env STUN URLs, prepared for the WebRTC stack under
/// [`stun_rewrite_mode_from_env`]. Uses the shared [`STUN_CACHE_TTL`] cache.
pub fn stun_urls_ready_for_ice() -> Vec<String> {
    let urls = stun_urls_from_env();
    let mode = stun_rewrite_mode_from_env();
    if let Some(cached) = stun_cache_get(&urls, mode) {
        return cached;
    }
    let urls_for_thread = urls.clone();
    let resolved = match std::thread::Builder::new()
        .name("agentlink-ice-resolve".into())
        .spawn(move || {
            prepare_stun_urls(
                &urls_for_thread,
                mode,
                lookup_host_system,
                doh_lookup_sync,
            )
        }) {
        Ok(handle) => handle.join().unwrap_or_else(|_| {
            eprintln!(
                "agentlink live-webrtc: ICE URL resolve thread panicked; STUN hostnames left unresolved"
            );
            Vec::new()
        }),
        Err(err) => {
            eprintln!("agentlink live-webrtc: cannot spawn ICE URL resolve thread: {err}");
            Vec::new()
        }
    };
    stun_cache_put(&urls, mode, &resolved);
    resolved
}

async fn lookup_host_system_async(host: &str) -> Vec<IpAddr> {
    let query = if host.contains(':') && !host.contains('.') {
        format!("[{host}]:0")
    } else {
        format!("{host}:0")
    };
    let Ok(Ok(iter)) =
        tokio::time::timeout(Duration::from_secs(2), tokio::net::lookup_host(query)).await
    else {
        return Vec::new();
    };
    let mut ips = Vec::new();
    for addr in iter {
        if !ips.contains(&addr.ip()) {
            ips.push(addr.ip());
        }
    }
    ips
}

fn lookup_host_system(host: &str) -> Vec<IpAddr> {
    let query = if host.contains(':') && !host.contains('.') {
        format!("[{host}]:0")
    } else {
        format!("{host}:0")
    };
    query
        .to_socket_addrs()
        .map(|iter| {
            let mut ips = Vec::new();
            for addr in iter {
                if !ips.contains(&addr.ip()) {
                    ips.push(addr.ip());
                }
            }
            ips
        })
        .unwrap_or_default()
}

/// Literal DoH bootstrap resolvers so poisoned system DNS cannot blackhole DoH
/// itself while TLS SNI and WebPKI certificate validation still verify the
/// DoH server hostname.
const DOH_PROVIDERS: &[(&str, &str, &[[u8; 4]])] = &[
    (
        "cloudflare-dns.com",
        "https://cloudflare-dns.com/dns-query",
        &[[1, 1, 1, 1], [1, 0, 0, 1]],
    ),
    (
        "dns.google",
        "https://dns.google/resolve",
        &[[8, 8, 8, 8], [8, 8, 4, 4]],
    ),
];

fn parse_doh_answer_ips(text: &str) -> Vec<IpAddr> {
    let Ok(body) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut ips = Vec::new();
    if let Some(answers) = body.get("Answer").and_then(|value| value.as_array()) {
        for item in answers {
            let rtype = item.get("type").and_then(|value| value.as_u64());
            // Type 1 = A (IPv4), Type 28 = AAAA (IPv6).
            if rtype != Some(1) && rtype != Some(28) {
                continue;
            }
            if let Some(data) = item.get("data").and_then(|value| value.as_str()) {
                if let Ok(ip) = data.trim().parse::<IpAddr>() {
                    if !is_benchmarking_ip(ip) && !ips.contains(&ip) {
                        ips.push(ip);
                    }
                }
            }
        }
    }
    ips
}

async fn doh_lookup_async(host: &str) -> Vec<IpAddr> {
    for (domain, base_url, bootstrap_v4s) in DOH_PROVIDERS {
        let addrs: Vec<SocketAddr> = bootstrap_v4s
            .iter()
            .map(|octets| SocketAddr::from((Ipv4Addr::from(*octets), 443)))
            .collect();
        let Ok(client) = reqwest::Client::builder()
            .timeout(Duration::from_secs(2))
            .resolve_to_addrs(domain, &addrs)
            .build()
        else {
            continue;
        };
        let mut ips = Vec::new();
        for qtype in ["A", "AAAA"] {
            let url = format!("{base_url}?name={host}&type={qtype}");
            let Ok(resp) = client
                .get(&url)
                .header("accept", "application/dns-json")
                .send()
                .await
            else {
                continue;
            };
            let Ok(text) = resp.text().await else {
                continue;
            };
            for ip in parse_doh_answer_ips(&text) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        if !ips.is_empty() {
            return ips;
        }
    }
    Vec::new()
}

fn doh_lookup_sync(host: &str) -> Vec<IpAddr> {
    for (domain, base_url, bootstrap_v4s) in DOH_PROVIDERS {
        let addrs: Vec<SocketAddr> = bootstrap_v4s
            .iter()
            .map(|octets| SocketAddr::from((Ipv4Addr::from(*octets), 443)))
            .collect();
        let Ok(client) = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .resolve_to_addrs(domain, &addrs)
            .build()
        else {
            continue;
        };
        let mut ips = Vec::new();
        for qtype in ["A", "AAAA"] {
            let url = format!("{base_url}?name={host}&type={qtype}");
            let Ok(resp) = client
                .get(&url)
                .header("accept", "application/dns-json")
                .send()
            else {
                continue;
            };
            let Ok(text) = resp.text() else {
                continue;
            };
            for ip in parse_doh_answer_ips(&text) {
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
        if !ips.is_empty() {
            return ips;
        }
    }
    Vec::new()
}

/// One WebRTC ICE server entry (STUN or TURN with optional REST credentials).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IceServerConfig {
    pub urls: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential: Option<String>,
}

impl IceServerConfig {
    pub fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::json!({ "urls": self.urls });
        if let Some(u) = self.username.as_deref().filter(|s| !s.is_empty()) {
            obj["username"] = serde_json::json!(u);
        }
        if let Some(c) = self.credential.as_deref().filter(|s| !s.is_empty()) {
            obj["credential"] = serde_json::json!(c);
        }
        obj
    }
}

/// ICE server list fetched from relay `POST /api/ice` or env override (`DESK-03`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RelayIceConfig {
    pub ice_servers: Vec<IceServerConfig>,
    pub ttl_secs: u64,
}

impl RelayIceConfig {
    pub fn to_json_servers(&self) -> Vec<serde_json::Value> {
        self.ice_servers.iter().map(IceServerConfig::to_json).collect()
    }
}

/// Parse explicit TURN servers from `AGENTLINK_TURN_URLS` plus optional
/// `AGENTLINK_TURN_USERNAME` (`AGENTLINK_TURN_USER`) and
/// `AGENTLINK_TURN_PASSWORD` (`AGENTLINK_TURN_PASS` / `AGENTLINK_TURN_CREDENTIAL`).
pub fn turn_servers_from_env() -> Vec<IceServerConfig> {
    let raw = match std::env::var("AGENTLINK_TURN_URLS") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => return Vec::new(),
    };
    let username = std::env::var("AGENTLINK_TURN_USERNAME")
        .or_else(|_| std::env::var("AGENTLINK_TURN_USER"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let credential = std::env::var("AGENTLINK_TURN_PASSWORD")
        .or_else(|_| std::env::var("AGENTLINK_TURN_PASS"))
        .or_else(|_| std::env::var("AGENTLINK_TURN_CREDENTIAL"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    turn_servers_from_values(&raw, username, credential)
}

fn turn_servers_from_values(
    raw_urls: &str,
    username: Option<String>,
    credential: Option<String>,
) -> Vec<IceServerConfig> {
    let urls: Vec<String> = raw_urls
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty() && usable_ice_url(s))
        .map(str::to_string)
        .collect();
    if urls.is_empty() {
        return Vec::new();
    }
    vec![IceServerConfig {
        urls,
        username,
        credential,
    }]
}

/// Build the HTTP(S) `/api/ice` endpoint URL from a relay URL (`ws://`, `wss://`,
/// `http://`, or `https://`).
pub fn relay_ice_endpoint(relay_url: &str) -> Result<String> {
    let trimmed = relay_url.trim();
    let mut parsed = url::Url::parse(trimmed)
        .map_err(|e| Error::Message(format!("invalid relay url '{trimmed}': {e}")))?;
    match parsed.scheme() {
        "wss" => {
            parsed
                .set_scheme("https")
                .map_err(|_| Error::Message("could not convert wss:// relay url to https://".into()))?;
        }
        "ws" => {
            parsed
                .set_scheme("http")
                .map_err(|_| Error::Message("could not convert ws:// relay url to http://".into()))?;
        }
        "https" | "http" => {}
        other => {
            return Err(Error::Message(format!(
                "unsupported relay url scheme '{other}'"
            )));
        }
    }
    parsed.set_query(None);
    parsed.set_fragment(None);
    parsed.set_path("/api/ice");
    Ok(parsed.to_string())
}

fn parse_ice_server_entry(item: &serde_json::Value) -> Option<IceServerConfig> {
    let urls: Vec<String> = match item.get("urls") {
        Some(serde_json::Value::String(s)) => vec![s.trim().to_string()],
        Some(serde_json::Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .collect(),
        _ => return None,
    }
    .into_iter()
    .filter(|u| !u.is_empty() && usable_ice_url(u))
    .collect();
    if urls.is_empty() {
        return None;
    }
    let username = item
        .get("username")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let credential = item
        .get("credential")
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    Some(IceServerConfig {
        urls,
        username,
        credential,
    })
}

/// Parse relay `/api/ice` JSON responses (supporting both `{ "ice_servers": [...] }`
/// and legacy `{ "stun": [...], "turn": [...] }` shapes).
pub fn parse_relay_ice_response(body: &serde_json::Value) -> RelayIceConfig {
    let ttl_secs = body
        .get("ttl_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);
    let mut servers = Vec::new();
    if let Some(arr) = body.get("ice_servers").and_then(|v| v.as_array()) {
        for item in arr {
            if let Some(cfg) = parse_ice_server_entry(item) {
                servers.push(cfg);
            }
        }
    }
    if servers.is_empty() {
        if let Some(stun_arr) = body.get("stun").and_then(|v| v.as_array()) {
            let stun_urls: Vec<String> = stun_arr
                .iter()
                .filter_map(|v| v.as_str())
                .map(|s| s.trim().to_string())
                .filter(|u| !u.is_empty() && usable_ice_url(u))
                .collect();
            if !stun_urls.is_empty() {
                servers.push(IceServerConfig {
                    urls: stun_urls,
                    username: None,
                    credential: None,
                });
            }
        }
        if let Some(turn_arr) = body.get("turn").and_then(|v| v.as_array()) {
            for item in turn_arr {
                if let Some(cfg) = parse_ice_server_entry(item) {
                    servers.push(cfg);
                }
            }
        }
    }
    RelayIceConfig {
        ice_servers: servers,
        ttl_secs,
    }
}

/// Fetch fresh STUN + short-lived TURN ICE servers for WebRTC (`DESK-03`).
///
/// Honors explicit `AGENTLINK_TURN_URLS` (plus `AGENTLINK_TURN_USERNAME` /
/// `AGENTLINK_TURN_PASSWORD`) env override first; otherwise POSTs to the
/// relay's `/api/ice` endpoint with `Authorization: Bearer <access_token>`
/// authenticated against the pinned [`crate::tls::RelayTrust`].
pub async fn fetch_relay_ice_servers(
    relay_url: &str,
    trust: &crate::tls::RelayTrust,
    access_token: &str,
) -> Result<RelayIceConfig> {
    let env_turn = turn_servers_from_env();
    if !env_turn.is_empty() {
        let mut servers = Vec::new();
        let stuns = stun_urls_ready_for_ice_async().await;
        if !stuns.is_empty() {
            servers.push(IceServerConfig {
                urls: stuns,
                username: None,
                credential: None,
            });
        }
        servers.extend(env_turn);
        return Ok(RelayIceConfig {
            ice_servers: servers,
            ttl_secs: STUN_CACHE_TTL.as_secs(),
        });
    }

    let endpoint = relay_ice_endpoint(relay_url)?;
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());
    if endpoint.starts_with("https://") {
        let tls_cfg = crate::tls::client_config_for(trust)?;
        builder = builder.use_preconfigured_tls((*tls_cfg).clone());
    }
    let client = builder
        .build()
        .map_err(|e| Error::Message(format!("build relay ice client: {e}")))?;

    let mut req = client
        .post(&endpoint)
        .header("content-type", "application/json")
        .body("{}");
    let token = access_token.trim();
    if !token.is_empty() {
        req = req.header("authorization", format!("Bearer {token}"));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| Error::Message(format!("fetch relay /api/ice: {e}")))?;
    if !resp.status().is_success() {
        return Err(Error::Message(format!(
            "relay /api/ice returned HTTP {}",
            resp.status()
        )));
    }
    let text = resp
        .text()
        .await
        .map_err(|e| Error::Message(format!("read relay /api/ice body: {e}")))?;
    let json: serde_json::Value = serde_json::from_str(&text)
        .map_err(|e| Error::Message(format!("parse relay /api/ice json: {e}")))?;
    Ok(parse_relay_ice_response(&json))
}

fn split_ice_url_parts(url: &str) -> Option<(&str, String, &str)> {
    let (scheme, rest) = url.split_once(':')?;
    let rest = rest.split(['?', '#']).next().unwrap_or(rest);
    let suffix_start = scheme.len() + 1 + rest.len();
    let suffix = if suffix_start < url.len() {
        &url[suffix_start..]
    } else {
        ""
    };
    let (host, port_suffix) = if let Some(rest) = rest.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        (host.to_string(), after)
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) if !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit()) => {
                (host.to_string(), &url[scheme.len() + 1 + host.len()..])
            }
            _ => (rest.to_string(), suffix),
        }
    };
    // port_suffix for bracket form:
    let port_suffix = if url.contains('[') {
        let after = url.split_once(']')?.1;
        after
    } else {
        port_suffix
    };
    if host.is_empty() {
        None
    } else {
        Some((scheme, host, port_suffix))
    }
}

fn format_ice_url(scheme: &str, ip: IpAddr, suffix: &str) -> String {
    match ip {
        IpAddr::V6(v6) => format!("{scheme}:[{v6}]{suffix}"),
        IpAddr::V4(v4) => format!("{scheme}:{v4}{suffix}"),
    }
}

fn is_benchmarking_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 198 && (o[1] == 18 || o[1] == 19)
        }
        IpAddr::V6(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unset_uses_public_stun() {
        let urls = stun_urls(None);
        assert_eq!(
            urls,
            DEFAULT_STUN_URLS
                .iter()
                .map(|url| (*url).to_string())
                .collect::<Vec<_>>()
        );
        assert!(urls.len() >= 2);
        assert!(urls.iter().all(|url| url.starts_with("stun:")));
    }

    #[test]
    fn explicit_list_replaces_defaults() {
        let urls = stun_urls(Some(" stun:turn.example:3478, stun:stun.example:19302 "));
        assert_eq!(
            urls,
            vec![
                "stun:turn.example:3478".to_string(),
                "stun:stun.example:19302".to_string(),
            ]
        );
    }

    #[test]
    fn empty_value_disables_stun() {
        assert!(stun_urls(Some("")).is_empty());
        assert!(stun_urls(Some(" , ")).is_empty());
    }

    #[test]
    fn auto_order_is_host_then_each_stun_then_turn_udp_then_tcp() {
        let attempts = ice_attempts(
            &[
                "stun:198.18.0.1:19302".into(),
                "stun:stun.l.google.com:19302".into(),
            ],
            &[
                "turn:192.0.2.10:3478".into(),
                "turns:turn.example:5349".into(),
            ],
            "agentlink",
            "replace-me",
        );
        let ids: Vec<_> = attempts.iter().map(|item| item.id).collect();
        assert_eq!(
            ids,
            vec!["host", "srflx", "relay-udp", "relay-tcp", "relay-tcp"]
        );
        assert!(attempts
            .iter()
            .all(|item| item.urls.iter().all(|url| !url.contains("198.18.0.1"))));
        assert_eq!(attempts[0].banner, "via host");
        assert_eq!(attempts[0].gather_ms, 800);
        assert_eq!(attempts[1].banner, "via STUN");
        assert_eq!(attempts[1].gather_ms, 2_500);
        assert_eq!(attempts[1].urls, vec!["stun:stun.l.google.com:19302"]);
        assert_eq!(attempts[2].banner, "via TURN udp");
        assert_eq!(attempts[2].policy, "relay");
        assert_eq!(attempts[2].urls, vec!["turn:192.0.2.10:3478"]);
        assert_eq!(attempts[3].urls, vec!["turn:192.0.2.10:3478?transport=tcp"]);
        assert_eq!(attempts[4].banner, "via TURN tcp");
        assert_eq!(attempts[4].urls, vec!["turns:turn.example:5349"]);
        assert_eq!(attempts[2].username, "agentlink");
        let json = attempts[2].to_json();
        assert_eq!(json["ice_transport_policy"], "relay");
        assert_eq!(json["ice_servers"][0]["credential"], "replace-me");
    }

    #[test]
    fn rewrite_skips_rfc2544_literals_and_rewrites_poisoned_hosts() {
        use std::net::IpAddr;
        let urls = vec![
            "stun:198.18.0.1:19302".into(),
            "stun:stun.l.google.com:19302".into(),
            "stun:stun.cloudflare.com:3478".into(),
        ];
        let rewritten = rewrite_ice_urls(&urls, |host| match host {
            "stun.l.google.com" => vec![
                "198.18.0.1".parse().unwrap(),
                "74.125.250.129".parse().unwrap(),
            ],
            "stun.cloudflare.com" => vec!["162.159.207.0".parse().unwrap()],
            _ => Vec::new(),
        });
        assert!(!rewritten.iter().any(|u| u.contains("198.18")));
        assert_eq!(
            rewritten,
            vec![
                "stun:74.125.250.129:19302".to_string(),
                "stun:162.159.207.0:3478".to_string(),
            ]
        );
        // A host that only resolves to 198.18/15 and whose resolver returns
        // nothing usable is dropped, not left as a hostname.
        let dropped = rewrite_ice_urls(&["stun:poison.example:19302".into()], |_| {
            vec!["198.18.0.1".parse::<IpAddr>().unwrap()]
        });
        assert!(dropped.is_empty());
        // Already-good literals are kept.
        let kept = rewrite_ice_urls(&["stun:74.125.250.129:19302".into()], |_| Vec::new());
        assert_eq!(kept, vec!["stun:74.125.250.129:19302".to_string()]);
    }

    #[test]
    fn prepare_rewrites_only_poisoned_default_stun_hosts() {
        use std::net::IpAddr;
        let defaults: Vec<String> = DEFAULT_STUN_URLS.iter().map(|u| (*u).to_string()).collect();
        let system = |host: &str| match host {
            "stun.l.google.com" | "stun1.l.google.com" | "stun.cloudflare.com" => {
                vec!["198.18.0.1".parse::<IpAddr>().unwrap()]
            }
            _ => Vec::new(),
        };
        let doh = |host: &str| match host {
            "stun.l.google.com" | "stun1.l.google.com" => {
                vec!["74.125.250.129".parse::<IpAddr>().unwrap()]
            }
            "stun.cloudflare.com" => vec!["162.159.207.0".parse::<IpAddr>().unwrap()],
            "stun.internal.example" => vec!["8.8.8.8".parse::<IpAddr>().unwrap()],
            _ => Vec::new(),
        };
        let rewritten = prepare_stun_urls(&defaults, StunRewriteMode::DefaultsOnly, system, doh);
        assert!(
            rewritten.iter().all(|u| !u.contains("198.18")),
            "{rewritten:?}"
        );
        assert!(
            rewritten.iter().any(|u| u.contains("74.125.250.129")),
            "{rewritten:?}"
        );
        assert!(
            rewritten.iter().any(|u| u.contains("162.159.207.0")),
            "{rewritten:?}"
        );

        // Healthy system DNS: keep hostnames, no literal rewrite, no DoH.
        let healthy = |host: &str| match host {
            "stun.l.google.com" | "stun1.l.google.com" => {
                vec!["74.125.250.129".parse::<IpAddr>().unwrap()]
            }
            "stun.cloudflare.com" => vec!["162.159.207.0".parse::<IpAddr>().unwrap()],
            _ => Vec::new(),
        };
        let doh_healthy = std::cell::Cell::new(0u32);
        let kept = prepare_stun_urls(&defaults, StunRewriteMode::DefaultsOnly, healthy, |host| {
            doh_healthy.set(doh_healthy.get() + 1);
            doh(host)
        });
        assert_eq!(kept, defaults);
        assert_eq!(doh_healthy.get(), 0, "healthy system DNS must not use DoH");

        // Empty system DNS (not only RFC 2544) still DoH-rewrites defaults.
        let doh_empty = std::cell::Cell::new(0u32);
        let from_empty = prepare_stun_urls(
            &defaults,
            StunRewriteMode::DefaultsOnly,
            |_| Vec::new(),
            |host| {
                doh_empty.set(doh_empty.get() + 1);
                doh(host)
            },
        );
        assert!(doh_empty.get() >= 1, "empty system DNS must try DoH");
        assert!(
            from_empty.iter().any(|u| u.contains("74.125.250.129")),
            "{from_empty:?}"
        );

        // Operator URL, even if system DNS is poisoned and DoH knows a public
        // address: do not force third-party DoH or rewrite a split-horizon name.
        let operator = vec!["stun:stun.internal.example:3478".into()];
        let poisoned = |_: &str| vec!["198.18.0.1".parse::<IpAddr>().unwrap()];
        let doh_operator = std::cell::Cell::new(0u32);
        let left = prepare_stun_urls(&operator, StunRewriteMode::DefaultsOnly, poisoned, |host| {
            doh_operator.set(doh_operator.get() + 1);
            doh(host)
        });
        assert_eq!(left, operator);
        assert_eq!(
            doh_operator.get(),
            0,
            "operator STUN URLs must never be sent to DoH"
        );

        // Off: default hostnames stay even when system DNS is poisoned; no DoH.
        let doh_off = std::cell::Cell::new(0u32);
        let off = prepare_stun_urls(&defaults, StunRewriteMode::Off, system, |host| {
            doh_off.set(doh_off.get() + 1);
            doh(host)
        });
        assert_eq!(off, defaults);
        assert_eq!(doh_off.get(), 0, "REWRITE=off must not call DoH");

        assert!(is_default_stun_url("stun:stun.l.google.com:19302"));
        assert!(!is_default_stun_url("stun:stun.internal.example:3478"));
        assert!(!is_default_stun_url("stun:stun.l.google.com:3478"));
    }

    #[test]
    fn stun_rewrite_mode_parses_off_and_defaults() {
        assert_eq!(stun_rewrite_mode_from_value(None), StunRewriteMode::DefaultsOnly);
        assert_eq!(stun_rewrite_mode_from_value(Some("")), StunRewriteMode::DefaultsOnly);
        assert_eq!(
            stun_rewrite_mode_from_value(Some(" defaults ")),
            StunRewriteMode::DefaultsOnly
        );
        assert_eq!(stun_rewrite_mode_from_value(Some("on")), StunRewriteMode::DefaultsOnly);
        assert_eq!(stun_rewrite_mode_from_value(Some("off")), StunRewriteMode::Off);
        assert_eq!(stun_rewrite_mode_from_value(Some("0")), StunRewriteMode::Off);
        assert_eq!(stun_rewrite_mode_from_value(Some("false")), StunRewriteMode::Off);
        assert_eq!(
            stun_rewrite_mode_from_value(Some("mystery")),
            StunRewriteMode::DefaultsOnly
        );
    }

    #[test]
    fn strm02_parse_doh_answer_supports_a_and_aaaa_and_skips_rfc2544() {
        let json = r#"{
            "Answer": [
                {"type": 5, "data": "alias.example."},
                {"type": 1, "data": "198.18.0.1"},
                {"type": 1, "data": "74.125.250.129"},
                {"type": 28, "data": "2001:4860:4864:5::81"}
            ]
        }"#;
        let ips = parse_doh_answer_ips(json);
        assert_eq!(
            ips,
            vec![
                "74.125.250.129".parse::<IpAddr>().unwrap(),
                "2001:4860:4864:5::81".parse::<IpAddr>().unwrap(),
            ]
        );
        assert_eq!(
            format_ice_url("stun", ips[1], ":19302"),
            "stun:[2001:4860:4864:5::81]:19302"
        );
    }

    #[tokio::test]
    async fn strm02_prepare_stun_urls_async_caches_and_filters_rfc2544() {
        clear_stun_cache();
        let urls = vec![
            "stun:198.18.0.1:19302".into(),
            "stun:74.125.250.129:19302".into(),
            "stun:[2001:4860:4864:5::81]:19302".into(),
        ];
        let first = prepare_stun_urls_async(&urls, StunRewriteMode::DefaultsOnly).await;
        assert_eq!(
            first,
            vec![
                "stun:74.125.250.129:19302".to_string(),
                "stun:[2001:4860:4864:5::81]:19302".to_string(),
            ]
        );
        // Second call returns cached entry immediately.
        assert_eq!(
            stun_cache_get(&urls, StunRewriteMode::DefaultsOnly),
            Some(first)
        );
    }

    #[test]
    fn desk03_parse_relay_ice_response_supports_new_and_legacy_shapes_and_turn_env() {
        assert_eq!(
            relay_ice_endpoint("wss://relay.example:7443/ws").unwrap(),
            "https://relay.example:7443/api/ice"
        );
        assert_eq!(
            relay_ice_endpoint("ws://127.0.0.1:8080/ws").unwrap(),
            "http://127.0.0.1:8080/api/ice"
        );

        let new_shape = serde_json::json!({
            "ttl_secs": 600,
            "ice_servers": [
                { "urls": "stun:stun.l.google.com:19302" },
                {
                    "urls": ["turn:198.18.0.1:3478", "turn:192.0.2.5:3478", "turns:turn.example:5349"],
                    "username": "1700000600:alice",
                    "credential": "hmac-pass"
                }
            ]
        });
        let parsed = parse_relay_ice_response(&new_shape);
        assert_eq!(parsed.ttl_secs, 600);
        assert_eq!(parsed.ice_servers.len(), 2);
        assert_eq!(
            parsed.ice_servers[1].urls,
            vec![
                "turn:192.0.2.5:3478".to_string(),
                "turns:turn.example:5349".to_string()
            ]
        );
        assert_eq!(
            parsed.ice_servers[1].username.as_deref(),
            Some("1700000600:alice")
        );

        let legacy_shape = serde_json::json!({
            "stun": ["stun:stun.cloudflare.com:3478"],
            "turn": [
                {
                    "urls": ["turn:192.0.2.9:3478"],
                    "username": "u",
                    "credential": "p"
                }
            ]
        });
        let legacy = parse_relay_ice_response(&legacy_shape);
        assert_eq!(legacy.ice_servers.len(), 2);
        assert_eq!(legacy.ice_servers[0].urls, vec!["stun:stun.cloudflare.com:3478"]);
        assert_eq!(legacy.ice_servers[1].credential.as_deref(), Some("p"));

        let from_env = turn_servers_from_values(
            "turn:198.18.0.1:3478, turn:192.0.2.10:3478, turns:turn.example:5349",
            Some("user".into()),
            Some("pass".into()),
        );
        assert_eq!(from_env.len(), 1);
        assert_eq!(
            from_env[0].urls,
            vec![
                "turn:192.0.2.10:3478".to_string(),
                "turns:turn.example:5349".to_string()
            ]
        );
        assert_eq!(from_env[0].username.as_deref(), Some("user"));
        assert_eq!(from_env[0].credential.as_deref(), Some("pass"));
    }

    #[tokio::test]
    async fn desk03_fetch_relay_ice_servers_posts_bearer_token_and_parses_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 4096];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(req.starts_with("POST /api/ice HTTP/1.1"), "{req}");
            assert!(
                req.to_ascii_lowercase()
                    .contains("authorization: bearer test-ice-token"),
                "{req}"
            );
            let body = r#"{"ttl_secs":420,"ice_servers":[{"urls":["turn:192.0.2.1:3478"],"username":"u1","credential":"c1"}]}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let trust = crate::tls::RelayTrust::parse("", Some("webpki")).unwrap();
        let cfg = fetch_relay_ice_servers(&format!("ws://{addr}/ws"), &trust, "test-ice-token")
            .await
            .unwrap();
        server.await.unwrap();
        assert_eq!(cfg.ttl_secs, 420);
        assert_eq!(cfg.ice_servers.len(), 1);
        assert_eq!(cfg.ice_servers[0].urls, vec!["turn:192.0.2.1:3478"]);
        assert_eq!(cfg.ice_servers[0].username.as_deref(), Some("u1"));
        assert_eq!(cfg.ice_servers[0].credential.as_deref(), Some("c1"));
    }
}
