//! Relay URL parsing shared by the CLI, node, MCP server, and QUIC rendezvous.
//!
//! `Url::port()` is `None` both when the port is omitted and when it is the
//! scheme default, so `wss://host` and `wss://host:443` must not fall through
//! to [`crate::protocol::DEFAULT_PORT`]. [`Url::port_or_known_default`] keeps
//! the scheme default (443 for `wss`/`https`, 80 for `ws`/`http`) and still
//! returns an explicit non-default port.
//!
//! A bare host with no scheme is the only form that defaults to 7443. Callers,
//! including a foreign binding such as an Android FFI wrapper, should use
//! [`parse_relay_url`] instead of reading the port themselves.

use url::Url;

use crate::error::{Error, Result};
use crate::protocol::{DEFAULT_PORT, WS_PATH};

/// Host, port, and WebSocket path of a relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
    /// `wss` after `https` is normalized. Bare hosts are `wss`.
    pub scheme: String,
}

impl RelayUrl {
    /// `host:port`, with IPv6 addresses in brackets.
    pub fn dial_label(&self) -> String {
        format!("{}:{}", self.bracket_host(), self.port)
    }

    pub fn bracket_host(&self) -> String {
        if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        }
    }
}

/// Parse a relay URL into the socket the client dials.
///
/// * `wss://host` and `wss://host:443` are port 443.
/// * `wss://host:7443` stays 7443.
/// * `https://` is accepted as an alias of `wss://`.
/// * `host`, `host:7443`, and `[::1]` have no scheme and default to 7443
///   unless a port is written.
pub fn parse_relay_url(input: &str) -> Result<RelayUrl> {
    let input = input.trim();
    if input.is_empty() {
        return Err(Error::Message("relay url is empty".into()));
    }
    if has_scheme(input) {
        parse_schemed(input)
    } else {
        parse_bare(input)
    }
}

/// Browser page for `agentlink view`. The port follows [`parse_relay_url`]:
/// 443 is omitted, and a bare host keeps 7443.
pub fn viewer_url(relay: &str, ticket: &str, node: &str, monitor: Option<u32>) -> Result<String> {
    let endpoint = parse_relay_url(relay)?;
    let origin = page_origin(&endpoint);
    let mut url = format!(
        "{origin}/view/#ticket={}&node={}",
        encode_fragment(ticket),
        encode_fragment(node)
    );
    if let Some(monitor) = monitor {
        url.push_str(&format!("&monitor={monitor}"));
    }
    Ok(url)
}

/// HTTP(S) origin for browser pages served by the relay. Default ports are
/// omitted; a bare host keeps 7443.
pub(crate) fn page_origin(endpoint: &RelayUrl) -> String {
    let https = endpoint.scheme == "wss";
    let scheme = if https { "https" } else { "http" };
    let default_port = if https { 443 } else { 80 };
    if endpoint.port == default_port {
        format!("{scheme}://{}", endpoint.bracket_host())
    } else {
        format!("{scheme}://{}:{}", endpoint.bracket_host(), endpoint.port)
    }
}

fn parse_schemed(input: &str) -> Result<RelayUrl> {
    let url = Url::parse(input).map_err(|e| Error::Message(format!("relay url: {e}")))?;
    let scheme = match url.scheme() {
        "wss" | "https" => "wss",
        "ws" | "http" => {
            return Err(Error::Message(
                "relay url must use wss:// (TLS is required)".into(),
            ))
        }
        other => {
            return Err(Error::Message(format!(
                "relay url scheme `{other}` is not supported; use wss://"
            )))
        }
    };
    relay_from_url(&url, scheme, false)
}

fn parse_bare(input: &str) -> Result<RelayUrl> {
    // A non-special scheme has no default port, so an explicit :443 is not
    // stripped the way `wss://host:443` is. `port_or_known_default` then
    // returns that port, and a missing port falls through to 7443.
    let dummy = format!("agentlink://{input}");
    let url = Url::parse(&dummy).map_err(|e| Error::Message(format!("relay url: {e}")))?;
    if url.scheme() != "agentlink" {
        return Err(Error::Message(format!(
            "relay url `{input}` is not a host or a wss:// URL"
        )));
    }
    relay_from_url(&url, "wss", true)
}

fn relay_from_url(url: &Url, scheme: &str, bare: bool) -> Result<RelayUrl> {
    let host = url
        .host_str()
        .ok_or_else(|| Error::Message("relay url is missing a host".into()))?
        .trim_matches(['[', ']'])
        .to_string();
    if host.is_empty() {
        return Err(Error::Message("relay url is missing a host".into()));
    }
    let port = if bare {
        url.port_or_known_default().unwrap_or(DEFAULT_PORT)
    } else {
        url.port_or_known_default().ok_or_else(|| {
            Error::Message(format!(
                "relay url scheme `{}` has no default port; write one explicitly",
                url.scheme()
            ))
        })?
    };
    if port == 0 {
        return Err(Error::Message("relay port must not be 0".into()));
    }
    Ok(RelayUrl {
        host,
        port,
        path: normalize_path(url.path()),
        scheme: scheme.to_string(),
    })
}

fn normalize_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        WS_PATH.to_string()
    } else if let Some(stripped) = path.strip_prefix('/') {
        format!("/{stripped}")
    } else {
        format!("/{path}")
    }
}

fn has_scheme(input: &str) -> bool {
    let Some((scheme, _)) = input.split_once("://") else {
        return false;
    };
    let mut chars = scheme.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {
            chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
        }
        _ => false,
    }
}

fn encode_fragment(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char);
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(input: &str) -> RelayUrl {
        parse_relay_url(input).unwrap_or_else(|err| panic!("{input}: {err}"))
    }

    #[test]
    fn scheme_default_and_explicit_ports() {
        let cases = [
            (
                "wss://relay.example.com",
                "relay.example.com",
                443,
                "/v1/connect",
            ),
            (
                "wss://relay.example.com:443",
                "relay.example.com",
                443,
                "/v1/connect",
            ),
            (
                "wss://relay.example.com:443/",
                "relay.example.com",
                443,
                "/v1/connect",
            ),
            (
                "WSS://Relay.Example.com",
                "relay.example.com",
                443,
                "/v1/connect",
            ),
            (
                "wss://relay.example.com:7443",
                "relay.example.com",
                7443,
                "/v1/connect",
            ),
            (
                "wss://relay.example.com:8443/v1/connect",
                "relay.example.com",
                8443,
                "/v1/connect",
            ),
            (
                "https://relay.example.com",
                "relay.example.com",
                443,
                "/v1/connect",
            ),
            (
                "https://relay.example.com:8443/custom",
                "relay.example.com",
                8443,
                "/custom",
            ),
            ("wss://127.0.0.1", "127.0.0.1", 443, "/v1/connect"),
            ("wss://127.0.0.1:443", "127.0.0.1", 443, "/v1/connect"),
            ("wss://127.0.0.1:7443", "127.0.0.1", 7443, "/v1/connect"),
            ("wss://[::1]", "::1", 443, "/v1/connect"),
            ("wss://[::1]:443", "::1", 443, "/v1/connect"),
            ("wss://[::1]:7443/v1/webrtc", "::1", 7443, "/v1/webrtc"),
            (
                "  wss://relay.example.com  ",
                "relay.example.com",
                443,
                "/v1/connect",
            ),
        ];
        for (input, host, port, path) in cases {
            let got = parsed(input);
            assert_eq!(got.host, host, "{input}");
            assert_eq!(got.port, port, "{input}");
            assert_eq!(got.path, path, "{input}");
            assert_eq!(got.scheme, "wss", "{input}");
        }
    }

    #[test]
    fn bare_host_defaults_to_7443_and_honors_an_explicit_port() {
        let cases = [
            (
                "relay.example.com",
                "relay.example.com",
                7443,
                "/v1/connect",
            ),
            (
                "relay.example.com:7443",
                "relay.example.com",
                7443,
                "/v1/connect",
            ),
            (
                "relay.example.com:443",
                "relay.example.com",
                443,
                "/v1/connect",
            ),
            (
                "relay.example.com:8443/v1/webrtc",
                "relay.example.com",
                8443,
                "/v1/webrtc",
            ),
            ("127.0.0.1", "127.0.0.1", 7443, "/v1/connect"),
            ("127.0.0.1:9000", "127.0.0.1", 9000, "/v1/connect"),
            ("127.0.0.1:443", "127.0.0.1", 443, "/v1/connect"),
            ("[::1]", "::1", 7443, "/v1/connect"),
            ("[::1]:7443", "::1", 7443, "/v1/connect"),
            ("[::1]:443", "::1", 443, "/v1/connect"),
        ];
        for (input, host, port, path) in cases {
            let got = parsed(input);
            assert_eq!(got.host, host, "{input}");
            assert_eq!(got.port, port, "{input}");
            assert_eq!(got.path, path, "{input}");
        }
    }

    #[test]
    fn cleartext_and_empty_urls_are_rejected() {
        for input in [
            "",
            "   ",
            "ws://relay.example.com",
            "http://relay.example.com",
            "wss://",
        ] {
            assert!(parse_relay_url(input).is_err(), "{input}");
        }
    }

    #[test]
    fn viewer_url_uses_the_same_port_rules() {
        let page = viewer_url("wss://relay.example.com", "tok en", "node", None).unwrap();
        assert_eq!(
            page,
            "https://relay.example.com/view/#ticket=tok%20en&node=node"
        );
        let explicit =
            viewer_url("wss://relay.example.com:443/v1/connect", "a", "b", Some(1)).unwrap();
        assert_eq!(
            explicit,
            "https://relay.example.com/view/#ticket=a&node=b&monitor=1"
        );
        let direct = viewer_url("wss://relay.example.com:7443", "a", "b", None).unwrap();
        assert_eq!(
            direct,
            "https://relay.example.com:7443/view/#ticket=a&node=b"
        );
        let bare = viewer_url("relay.example.com", "a", "b", None).unwrap();
        assert_eq!(bare, "https://relay.example.com:7443/view/#ticket=a&node=b");
        let v6 = viewer_url("wss://[::1]", "a", "b", None).unwrap();
        assert_eq!(v6, "https://[::1]/view/#ticket=a&node=b");
    }
}
