//! Time-limited TURN credentials (REST / coturn `use-auth-secret`).
//!
//! `username` is `<expiry unix>:<user id>`. `credential` is the standard
//! base64 of HMAC-SHA1(shared secret, username). Coturn checks that with
//! `use-auth-secret` and `static-auth-secret`. The secret never goes in a
//! public JSON document. Callers mint a credential only after a view ticket
//! or a logged-in session has been checked.
//!
//! TTL is clamped to 5–15 minutes. The default is 10 minutes.

use base64::Engine;
use hmac::{Hmac, Mac};
use sha1::Sha1;

use crate::error::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

pub const MIN_TURN_TTL_SECS: i64 = 5 * 60;
pub const MAX_TURN_TTL_SECS: i64 = 15 * 60;
pub const DEFAULT_TURN_TTL_SECS: i64 = 10 * 60;

/// Clamp a requested lifetime into the 5–15 minute window.
pub fn clamp_ttl(ttl_secs: i64) -> i64 {
    ttl_secs.clamp(MIN_TURN_TTL_SECS, MAX_TURN_TTL_SECS)
}

/// `expiry:userid`. The user id is trimmed and limited so it stays a single token.
pub fn rest_username(expiry_unix: i64, user_id: &str) -> String {
    format!("{expiry_unix}:{}", sanitize_user(user_id))
}

fn sanitize_user(user_id: &str) -> String {
    let mut out = String::new();
    for ch in user_id.chars() {
        if out.len() >= 64 {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '@' | '-' | ':') {
            out.push(ch);
        }
    }
    if out.is_empty() {
        "viewer".into()
    } else {
        out
    }
}

/// Base64(HMAC-SHA1(secret, username)). This is the coturn REST password.
pub fn rest_credential(secret: &str, username: &str) -> Result<String> {
    if secret.is_empty() {
        return Err(Error::Message(
            "AGENTLINK_TURN_SECRET is empty; refusing to mint a TURN credential".into(),
        ));
    }
    let mut mac = HmacSha1::new_from_slice(secret.as_bytes())
        .map_err(|_| Error::Message("TURN secret was rejected by HMAC-SHA1".into()))?;
    mac.update(username.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

/// Mint `(username, credential, expiry_unix)`.
pub fn mint(
    secret: &str,
    user_id: &str,
    now_unix: i64,
    ttl_secs: i64,
) -> Result<(String, String, i64)> {
    let expiry = now_unix.saturating_add(clamp_ttl(ttl_secs));
    let username = rest_username(expiry, user_id);
    let credential = rest_credential(secret, &username)?;
    Ok((username, credential, expiry))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha1_matches_an_independent_mac_and_the_rest_shape() {
        let secret = "test-turn-secret";
        let (username, credential, expiry) = mint(secret, "web:alice", 1_700_000_000, 600).unwrap();
        assert_eq!(username, "1700000600:web:alice");
        assert_eq!(expiry, 1_700_000_600);

        let mut mac = HmacSha1::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(username.as_bytes());
        let expect = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert_eq!(credential, expect);
        assert!(!credential.contains(secret));
        assert!(rest_credential("", &username).is_err());
    }

    #[test]
    fn ttl_stays_inside_five_to_fifteen_minutes() {
        assert_eq!(clamp_ttl(1), MIN_TURN_TTL_SECS);
        assert_eq!(clamp_ttl(10 * 60), DEFAULT_TURN_TTL_SECS);
        assert_eq!(clamp_ttl(24 * 60 * 60), MAX_TURN_TTL_SECS);
        let (_, _, expiry) = mint("s", "u", 100, 1).unwrap();
        assert_eq!(expiry, 100 + MIN_TURN_TTL_SECS);
    }

    #[test]
    fn user_id_drops_spaces_and_is_capped() {
        assert_eq!(rest_username(10, "bad id"), "10:badid");
        let long = "a".repeat(80);
        assert_eq!(rest_username(10, &long).len(), "10:".len() + 64);
    }
}
