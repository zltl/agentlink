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
}
