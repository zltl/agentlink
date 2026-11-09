//! Pairing invite strings.
//!
//! `agentlink pair` prints `agentlink-invite:v1:<base64url>` so a node can
//! enroll with the relay URL, certificate trust, and one-time token together.
//! The relay still stores only the random token. The trust mode travels in
//! the invite, not inside the token the relay checks.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

const PREFIX: &str = "agentlink-invite:v1:";

/// Everything a new node needs, apart from its own key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

pub fn encode_invite(invite: &Invite) -> Result<String> {
    if invite.relay.trim().is_empty() || invite.token.trim().is_empty() {
        return Err(Error::Message(
            "invite needs a relay URL and a pairing token".into(),
        ));
    }
    let json = serde_json::to_vec(invite)?;
    Ok(format!("{PREFIX}{}", URL_SAFE_NO_PAD.encode(json)))
}

pub fn decode_invite(text: &str) -> Result<Invite> {
    let text = text.trim();
    let payload = text.strip_prefix(PREFIX).ok_or_else(|| {
        Error::Message(format!(
            "invite must start with {PREFIX} (print one with `agentlink pair`)"
        ))
    })?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| Error::Message(format!("invite: {e}")))?;
    let invite: Invite = serde_json::from_slice(&bytes)?;
    if invite.relay.trim().is_empty() || invite.token.trim().is_empty() {
        return Err(Error::Message("invite is missing a relay or token".into()));
    }
    if invite.fingerprint.trim().is_empty()
        && invite.trust.as_deref().unwrap_or("").trim().is_empty()
    {
        return Err(Error::Message("invite is missing certificate trust".into()));
    }
    Ok(invite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_round_trip_carries_webpki_trust() {
        let invite = Invite {
            relay: "wss://relay.example.com".into(),
            fingerprint: "sha256:ab".into(),
            trust: Some("webpki".into()),
            token: "pair-token".into(),
            name: "laptop".into(),
        };
        let text = encode_invite(&invite).unwrap();
        assert!(text.starts_with(PREFIX), "{text}");
        assert!(
            !text.contains("pair-token"),
            "token should be inside the payload"
        );
        assert_eq!(decode_invite(&text).unwrap(), invite);
        assert!(decode_invite("nope").is_err());
    }
}
