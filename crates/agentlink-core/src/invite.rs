//! Pairing invite strings.
//!
//! `agentlink pair` prints `agentlink-invite:v1:<base64url>` so a node can
//! enroll with the relay URL, certificate trust, and one-time token together.
//! The relay still stores only the random token. The trust mode travels in
//! the invite, not inside the token the relay checks.
//!
//! A parsed invite is not a grant and it does not skip the end-to-end
//! handshake. The node still requires its own signed grant before it runs a
//! command, file, or desktop session.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::relay_url::parse_relay_url;
use crate::tls::RelayTrust;

const PREFIX: &str = "agentlink-invite:v1:";

/// Shown when the field is not an invite and is shorter than a pairing token.
pub const JOIN_TOO_SHORT: &str = "that text is too short to be an invite or a pairing token. Paste the invite from agentlink pair. Nothing was paired.";

/// Everything a new node needs, apart from its own key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Invite {
    pub relay: String,
    #[serde(default)]
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    pub token: String,
    #[serde(default)]
    pub name: String,
}

/// What the phone or tray may do with the Invite field.
///
/// [`JoinText::Absent`] is an empty field: an already-enrolled node may start
/// without a new token. It is not acceptance of an empty invite string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinText {
    Absent,
    /// One-time relay enrollment token. Not a grant.
    Token(String),
    Invite(Invite),
}

pub fn encode_invite(invite: &Invite) -> Result<String> {
    validate_invite(invite)?;
    let json = serde_json::to_vec(invite)?;
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
}

pub fn decode_invite(text: &str) -> Result<Invite> {
    let text = text.trim();
    if text.is_empty() {
        return Err(Error::Message("invite is empty".into()));
    }
    let payload = text.strip_prefix(PREFIX).ok_or_else(|| {
        Error::Message(format!(
            "invite must start with {PREFIX} (print one with `agentlink pair`)"
        ))
    })?;
    if payload.is_empty() {
        return Err(Error::Message(
            "invite is damaged (not valid base64)".into(),
        ));
    }
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| Error::Message("invite is damaged (not valid base64)".into()))?;
    let invite: Invite = serde_json::from_slice(&bytes)
        .map_err(|_| Error::Message("invite is damaged (not valid JSON)".into()))?;
    validate_invite(&invite)?;
    let trust = normalized_trust(invite.trust.as_deref());
    Ok(Invite {
        relay: invite.relay.trim().to_string(),
        fingerprint: invite.fingerprint.trim().to_string(),
        trust,
        token: invite.token.trim().to_ascii_lowercase(),
        name: invite.name.trim().to_string(),
    })
}

/// Classify the Invite field. Never panics.
///
/// Empty text is [`JoinText::Absent`]. `123`, a damaged `agentlink-invite:v1:`
/// string, and any other non-token are errors. A 64-hex pairing token is
/// accepted as enrollment material only.
pub fn parse_join_text(text: &str) -> Result<JoinText> {
    let text = text.trim();
    if text.is_empty() {
        return Ok(JoinText::Absent);
    }
    if text.to_ascii_lowercase().starts_with("agentlink-invite") {
        return Ok(JoinText::Invite(decode_invite(text)?));
    }
    if text.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(Error::Message(
            "that text is not an invite or a pairing token".into(),
        ));
    }
    if text.len() < 64 {
        return Err(Error::Message(JOIN_TOO_SHORT.into()));
    }
    if !is_pairing_token(text) {
        return Err(Error::Message(
            "that text is not an invite or a pairing token".into(),
        ));
    }
    Ok(JoinText::Token(text.to_ascii_lowercase()))
}

/// Relay enrollment tokens are 32 bytes of hex (`random_token`).
pub fn is_pairing_token(text: &str) -> bool {
    let text = text.trim();
    text.len() == 64 && text.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn normalized_trust(trust: Option<&str>) -> Option<String> {
    trust
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn validate_invite(invite: &Invite) -> Result<()> {
    let relay = invite.relay.trim();
    let token = invite.token.trim();
    if relay.is_empty() || token.is_empty() {
        return Err(Error::Message("invite is missing a relay or token".into()));
    }
    let relay_lower = relay.to_ascii_lowercase();
    if !(relay_lower.starts_with("wss://") || relay_lower.starts_with("https://")) {
        return Err(Error::Message(
            "invite relay URL must start with wss://".into(),
        ));
    }
    parse_relay_url(relay)?;
    if !is_pairing_token(token) {
        return Err(Error::Message(
            "invite pairing token is not a one-time token".into(),
        ));
    }
    let trust = normalized_trust(invite.trust.as_deref());
    if invite.fingerprint.trim().is_empty() && trust.is_none() {
        return Err(Error::Message("invite is missing certificate trust".into()));
    }
    RelayTrust::parse(invite.fingerprint.trim(), trust.as_deref()).map_err(|err| {
        Error::Message(format!(
            "invite certificate trust is not valid ({})",
            clip_err(&err.to_string())
        ))
    })?;
    Ok(())
}

fn clip_err(text: &str) -> String {
    let mut chars = text.chars();
    let clipped: String = chars.by_ref().take(160).collect();
    if chars.next().is_some() {
        format!("{clipped}…")
    } else {
        clipped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pin() -> String {
        format!("sha256:{}", "ab".repeat(32))
    }

    fn token() -> String {
        "cd".repeat(32)
    }

    fn sample() -> Invite {
        Invite {
            relay: "wss://relay.example.com".into(),
            fingerprint: pin(),
            trust: Some("webpki".into()),
            token: token(),
            name: "laptop".into(),
        }
    }

    #[test]
    fn invite_round_trip_carries_webpki_trust() {
        let invite = sample();
        let text = encode_invite(&invite).unwrap();
        assert!(text.starts_with(PREFIX), "{text}");
        assert!(
            !text.contains(&invite.token),
            "token should be inside the payload"
        );
        assert_eq!(decode_invite(&text).unwrap(), invite);
        match parse_join_text(&text).unwrap() {
            JoinText::Invite(got) => assert_eq!(got, invite),
            other => panic!("expected invite, got {other:?}"),
        }
    }

    #[test]
    fn short_empty_and_malformed_invites_are_refused() {
        let empty = decode_invite("").unwrap_err().to_string();
        assert!(empty.contains("empty"), "{empty}");
        let blank = decode_invite("   ").unwrap_err().to_string();
        assert!(blank.contains("empty"), "{blank}");
        assert!(matches!(parse_join_text("").unwrap(), JoinText::Absent));
        assert!(matches!(parse_join_text("   ").unwrap(), JoinText::Absent));

        let short = parse_join_text("123").unwrap_err().to_string();
        assert!(short.contains("too short"), "{short}");
        assert!(decode_invite("123").is_err());
        assert!(parse_join_text("123").is_err());

        for damaged in [
            "agentlink-invite:v1:",
            "agentlink-invite:v1:%%%",
            "agentlink-invite:v1:123",
            "agentlink-invite:v2:aaaa",
        ] {
            let err = parse_join_text(damaged).unwrap_err().to_string();
            assert!(
                err.contains("damaged") || err.contains("must start with"),
                "{damaged} -> {err}"
            );
            assert!(decode_invite(damaged).is_err(), "{damaged}");
        }
    }

    #[test]
    fn short_token_inside_an_envelope_is_not_usable() {
        let json = format!(
            r#"{{"relay":"wss://relay.example.com","fingerprint":"{}","token":"123","name":"phone"}}"#,
            pin()
        );
        let text = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
        let err = decode_invite(&text).unwrap_err().to_string();
        assert!(err.contains("not a one-time token"), "{err}");
        assert!(parse_join_text(&text).is_err());
    }

    #[test]
    fn weak_pin_inside_an_envelope_is_not_usable() {
        let json = format!(
            r#"{{"relay":"wss://relay.example.com","fingerprint":"sha256:ab","token":"{}","name":"phone"}}"#,
            token()
        );
        let text = format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json.as_bytes()));
        let err = decode_invite(&text).unwrap_err().to_string();
        assert!(err.contains("certificate trust"), "{err}");
    }

    #[test]
    fn raw_pairing_token_is_not_a_grant() {
        let raw = token();
        match parse_join_text(&raw).unwrap() {
            JoinText::Token(got) => assert_eq!(got, raw),
            other => panic!("expected token, got {other:?}"),
        }
        let noisy = "zz".repeat(32);
        assert!(parse_join_text(&noisy).is_err());
    }
}
