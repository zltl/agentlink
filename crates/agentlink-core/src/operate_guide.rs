//! Shareable, documentation-only operating guide for one node.
//!
//! The fragment is `v1.<base64url(json)>` and never reaches the server as an
//! authorization credential. It carries display metadata and the relay URL so
//! a person or an AI can copy the right commands. It is not a grant, ticket,
//! pairing token, or session cookie, and the relay page does not mint any of
//! those. Owner-signed [`crate::grant::SignedGrant`] is still the only node
//! authorization.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::relay_url::{page_origin, parse_relay_url};

const PREFIX: &str = "v1.";
const VERSION: u8 = 1;

/// The only fields a guide may carry. Anything else is refused at encode time
/// so a future field cannot silently smuggle a secret into a shareable URL.
pub const OPERATE_GUIDE_KEYS: &[&str] = &[
    "v",
    "relay",
    "node_id",
    "name",
    "os",
    "arch",
    "version",
    "online",
    "has_display",
    "access",
    "effective",
    "notes",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperateGuide {
    /// Payload version. Only `1` is accepted.
    pub v: u8,
    /// Relay URL the CLI dials (for example `wss://relay.example.com`).
    pub relay: String,
    /// Hex node id.
    pub node_id: String,
    pub name: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub version: String,
    /// Omitted when the caller cannot know presence (for example `guide --local`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// `None` means the node has not reported whether it has a desktop.
    #[serde(default)]
    pub has_display: Option<bool>,
    /// Caller access preset, informational only.
    #[serde(default)]
    pub access: String,
    /// Effective policy preset, informational only.
    #[serde(default)]
    pub effective: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub notes: String,
}

/// Browser page for a node's operating guide. The origin follows the same
/// port rules as [`crate::relay_url::viewer_url`].
pub fn operate_guide_url(relay: &str, guide: &OperateGuide) -> Result<String> {
    let endpoint = parse_relay_url(relay)?;
    Ok(format!(
        "{}/operate/#{}",
        page_origin(&endpoint),
        encode_operate_guide(guide)?
    ))
}

/// Encode `v1.<base64url(json)>` for the URL fragment.
pub fn encode_operate_guide(guide: &OperateGuide) -> Result<String> {
    validate(guide)?;
    let value = serde_json::to_value(guide)?;
    let object = value
        .as_object()
        .ok_or_else(|| Error::Message("operate guide is not an object".into()))?;
    for key in object.keys() {
        if !OPERATE_GUIDE_KEYS.contains(&key.as_str()) {
            return Err(Error::Message(format!(
                "operate guide field `{key}` is not allowed"
            )));
        }
    }
    let json = serde_json::to_vec(guide)?;
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
}

/// Decode a raw fragment (a leading `#` is allowed) or the payload after it.
pub fn decode_operate_guide(fragment: &str) -> Result<OperateGuide> {
    let fragment = fragment.trim().trim_start_matches('#');
    let (version, payload) = fragment
        .split_once('.')
        .ok_or_else(|| Error::Message("operate guide is missing a version prefix".into()))?;
    if version != "v1" {
        return Err(Error::Message(format!(
            "unsupported operate guide version `{version}` (expected v1)"
        )));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| Error::Message(format!("operate guide: {e}")))?;
    let guide: OperateGuide = serde_json::from_slice(&bytes)?;
    if guide.v != VERSION {
        return Err(Error::Message(format!(
            "unsupported operate guide version {} (expected {VERSION})",
            guide.v
        )));
    }
    validate(&guide)?;
    Ok(guide)
}

fn validate(guide: &OperateGuide) -> Result<()> {
    if guide.v != VERSION {
        return Err(Error::Message(format!(
            "unsupported operate guide version {} (expected {VERSION})",
            guide.v
        )));
    }
    if guide.relay.trim().is_empty() {
        return Err(Error::Message("operate guide needs a relay URL".into()));
    }
    if guide.relay.contains('@') {
        return Err(Error::Message(
            "operate guide relay must not carry credentials".into(),
        ));
    }
    parse_relay_url(&guide.relay)?;
    if guide.node_id.trim().is_empty() {
        return Err(Error::Message("operate guide needs a node id".into()));
    }
    if guide.name.chars().any(char::is_control)
        || guide.node_id.chars().any(char::is_control)
        || guide.os.chars().any(char::is_control)
        || guide.arch.chars().any(char::is_control)
        || guide.version.chars().any(char::is_control)
        || guide.access.chars().any(char::is_control)
        || guide.effective.chars().any(char::is_control)
        || guide.notes.chars().any(char::is_control)
    {
        return Err(Error::Message(
            "operate guide fields must not contain control characters".into(),
        ));
    }
    if guide.notes.chars().count() > 500 {
        return Err(Error::Message(
            "operate guide notes are longer than 500 characters".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn guide() -> OperateGuide {
        OperateGuide {
            v: 1,
            relay: "wss://relay.example.com".into(),
            node_id: "ab".repeat(32),
            name: "lab-box".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: "1.2.3".into(),
            online: Some(true),
            has_display: Some(true),
            access: "exec".into(),
            effective: "exec".into(),
            notes: String::new(),
        }
    }

    #[test]
    fn operate_guide_url_uses_the_same_port_rules_as_viewer() {
        let payload = encode_operate_guide(&guide()).unwrap();
        let cases = [
            ("wss://relay.example.com", "https://relay.example.com"),
            ("wss://relay.example.com:443", "https://relay.example.com"),
            (
                "https://relay.example.com:443/v1/connect",
                "https://relay.example.com",
            ),
            (
                "wss://relay.example.com:7443",
                "https://relay.example.com:7443",
            ),
            ("relay.example.com", "https://relay.example.com:7443"),
            ("wss://[::1]", "https://[::1]"),
            ("[::1]:7443", "https://[::1]:7443"),
        ];
        for (relay, origin) in cases {
            let url = operate_guide_url(relay, &guide()).unwrap();
            assert_eq!(url, format!("{origin}/operate/#{payload}"), "{relay}");
        }
    }

    #[test]
    fn operate_guide_round_trips_through_the_fragment() {
        let encoded = encode_operate_guide(&guide()).unwrap();
        assert!(encoded.starts_with("v1."));
        assert_eq!(decode_operate_guide(&encoded).unwrap(), guide());
        assert_eq!(
            decode_operate_guide(&format!("#{encoded}")).unwrap(),
            guide()
        );
        let url = operate_guide_url("wss://relay.example.com", &guide()).unwrap();
        let fragment = url.split('#').nth(1).unwrap();
        assert_eq!(decode_operate_guide(fragment).unwrap(), guide());
    }

    #[test]
    fn operate_guide_omits_unknown_presence_and_empty_notes() {
        let mut guide = guide();
        guide.online = None;
        guide.notes = String::new();
        let encoded = encode_operate_guide(&guide).unwrap();
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.trim_start_matches("v1."))
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(value.get("online").is_none());
        assert!(value.get("notes").is_none());
        assert!(value["has_display"].is_boolean());
    }

    #[test]
    fn encoded_payload_keys_are_only_the_allowlist() {
        let mut guide = guide();
        guide.notes = "short note".into();
        let encoded = encode_operate_guide(&guide).unwrap();
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded.trim_start_matches("v1."))
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let object = value.as_object().unwrap();
        for key in object.keys() {
            assert!(
                OPERATE_GUIDE_KEYS.contains(&key.as_str()),
                "unexpected field `{key}`"
            );
        }
        assert_eq!(object.len(), OPERATE_GUIDE_KEYS.len());
        for secret in ["token", "ticket", "cookie", "refresh", "secret", "key"] {
            assert!(!object.contains_key(secret), "{secret}");
        }
    }

    #[test]
    fn unknown_versions_are_rejected() {
        let encoded = encode_operate_guide(&guide()).unwrap();
        let payload = encoded.trim_start_matches("v1.");
        assert!(decode_operate_guide(&format!("v2.{payload}")).is_err());
        assert!(decode_operate_guide("nope").is_err());
        assert!(decode_operate_guide("v1.").is_err());

        let mut future = guide();
        future.v = 2;
        assert!(encode_operate_guide(&future).is_err());

        let bytes = serde_json::to_vec(&future).unwrap();
        let fragment = format!("v1.{}", URL_SAFE_NO_PAD.encode(bytes));
        assert!(decode_operate_guide(&fragment).is_err());
    }

    #[test]
    fn credentials_in_the_relay_are_refused() {
        let mut guide = guide();
        guide.relay = "wss://user:pass@relay.example.com".into();
        assert!(encode_operate_guide(&guide).is_err());
    }

    #[test]
    fn a_missing_relay_or_node_id_is_refused() {
        let mut missing_relay = guide();
        missing_relay.relay.clear();
        assert!(encode_operate_guide(&missing_relay).is_err());

        let mut missing_node = guide();
        missing_node.node_id.clear();
        assert!(encode_operate_guide(&missing_node).is_err());
    }
}
