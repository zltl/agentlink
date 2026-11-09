//! Local account primitives: argon2id passwords, lockout, TOTP, token hashes.
//!
//! Password verification always runs one argon2id check so a missing user does
//! not return faster than a wrong password. Lockout state is pure so it can be
//! tested without a database.

use std::sync::OnceLock;

use argon2::{PasswordHasher, PasswordVerifier};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

const MAX_PASSWORD_BYTES: usize = 1024;
pub const LOCK_AFTER: u32 = 5;
pub const LOCK_SECS: i64 = 15 * 60;
/// Short-lived API credential. Clients refresh it; they do not ask for a password.
pub const ACCESS_TTL_SECS: i64 = 15 * 60;
/// Accept an access token this long after its stated expiry.
///
/// Phones and the relay are not the same clock. The client refreshes a minute
/// early; this covers the relay being a few minutes ahead so that skew does
/// not look like a logged-out session.
pub const ACCESS_SKEW_SECS: i64 = 5 * 60;
/// A device that has not refreshed for this long can still refresh without a password.
pub const REFRESH_IDLE_SECS: i64 = 30 * 24 * 3600;
/// Slack so clock skew does not expire a token that has been idle for [`REFRESH_IDLE_SECS`].
pub const REFRESH_GRACE_SECS: i64 = 2 * 24 * 3600;
/// Written on login and again on every refresh, so the window slides with use.
pub const REFRESH_TTL_SECS: i64 = REFRESH_IDLE_SECS + REFRESH_GRACE_SECS;
pub const WEB_TTL_SECS: i64 = 12 * 3600;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lockout {
    pub failed: u32,
    pub locked_until: i64,
}

impl Lockout {
    pub fn fresh() -> Self {
        Self {
            failed: 0,
            locked_until: 0,
        }
    }

    pub fn is_locked(self, now: i64) -> bool {
        self.locked_until > now
    }

    /// Count a failure. The fifth failure in a row locks the account.
    pub fn on_failure(self, now: i64) -> Self {
        if self.is_locked(now) {
            return self;
        }
        let failed = self.failed.saturating_add(1);
        if failed >= LOCK_AFTER {
            Self {
                failed,
                locked_until: now.saturating_add(LOCK_SECS),
            }
        } else {
            Self {
                failed,
                locked_until: 0,
            }
        }
    }

    pub fn on_success(self) -> Self {
        Self::fresh()
    }
}

pub fn hash_password(password: &str) -> Result<String> {
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(Error::Message("password is too long".into()));
    }
    if password.is_empty() {
        return Err(Error::Message("password is required".into()));
    }
    let salt =
        argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
    let argon = argon2_id();
    let hash = argon
        .hash_password(password.as_bytes(), &salt)
        .map_err(|err| Error::Message(format!("password hash: {err}")))?;
    Ok(hash.to_string())
}

/// One argon2id verification. Invalid stored hashes are checked against the
/// dummy hash so the work factor stays the same.
pub fn verify_password(password: &str, encoded: &str) -> bool {
    let usable = !password.is_empty()
        && password.len() <= MAX_PASSWORD_BYTES
        && argon2::password_hash::PasswordHash::new(encoded).is_ok();
    let target = if usable { encoded } else { dummy_hash() };
    let ok = verify_encoded(password, target);
    ok && usable
}

pub fn token_hash(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

pub fn valid_username(name: &str) -> bool {
    let bytes = name.as_bytes();
    (1..=32).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-' || *c == b'_')
}

pub fn valid_role(role: &str) -> bool {
    role == "admin" || role == "user"
}

/// Random base32 TOTP secret (160 bits).
pub fn totp_secret() -> String {
    let mut raw = [0u8; 20];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut raw);
    base32_encode(&raw)
}

pub fn totp_verify(secret: &str, code: &str, now: i64) -> bool {
    let provided = code.trim();
    let mut ok = false;
    for delta in [-1_i64, 0, 1] {
        let expect = totp_at(secret, now.saturating_add(delta * 30)).unwrap_or_default();
        ok |= crate::util::ct_eq(provided, &expect);
    }
    ok && provided.len() == 6
}

pub fn totp_at(secret: &str, unix: i64) -> Result<String> {
    let key = base32_decode(secret).map_err(Error::Message)?;
    let counter = (unix.max(0) as u64) / 30;
    let mut mac =
        HmacSha1::new_from_slice(&key).map_err(|_| Error::Message("totp key rejected".into()))?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([
        digest[offset],
        digest[offset + 1],
        digest[offset + 2],
        digest[offset + 3],
    ]) & 0x7fff_ffff;
    Ok(format!("{:06}", bin % 1_000_000))
}

pub fn otpauth_url(secret: &str, username: &str, issuer: &str) -> String {
    format!(
        "otpauth://totp/{issuer}:{username}?secret={secret}&issuer={issuer}&algorithm=SHA1&digits=6&period=30",
        issuer = urlencoding_min(issuer),
        username = urlencoding_min(username),
        secret = secret,
    )
}

fn verify_encoded(password: &str, encoded: &str) -> bool {
    let Ok(parsed) = argon2::password_hash::PasswordHash::new(encoded) else {
        return false;
    };
    argon2_id()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn dummy_hash() -> &'static str {
    static DUMMY: OnceLock<String> = OnceLock::new();
    DUMMY.get_or_init(|| hash_password("agentlink-dummy-password").expect("dummy hash"))
}

fn argon2_id() -> argon2::Argon2<'static> {
    let params = argon2::Params::new(19_456, 2, 1, None).expect("argon2id params");
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
}

fn base32_encode(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let mut buffer = 0u32;
    let mut bits = 0;
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let index = ((buffer >> bits) & 0x1f) as usize;
            out.push(ALPHA[index] as char);
        }
    }
    if bits > 0 {
        let index = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(ALPHA[index] as char);
    }
    out
}

fn base32_decode(text: &str) -> std::result::Result<Vec<u8>, String> {
    let mut buffer = 0u32;
    let mut bits = 0;
    let mut out = Vec::new();
    for ch in text.chars() {
        if ch == '=' || ch.is_whitespace() {
            continue;
        }
        let val = match ch.to_ascii_uppercase() {
            'A'..='Z' => ch.to_ascii_uppercase() as u32 - 'A' as u32,
            '2'..='7' => ch as u32 - '2' as u32 + 26,
            _ => return Err("totp secret is not base32".into()),
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    if out.is_empty() {
        return Err("totp secret is empty".into());
    }
    Ok(out)
}

fn urlencoding_min(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_hash_verifies_and_rejects() {
        let hash = hash_password("correct horse").unwrap();
        assert!(verify_password("correct horse", &hash));
        assert!(!verify_password("wrong horse", &hash));
        assert!(!verify_password("correct horse", "not-a-hash"));
        assert!(!verify_password("", &hash));
    }

    #[test]
    fn lockout_trips_on_the_fifth_failure_and_resets() {
        let mut state = Lockout::fresh();
        let now = 1_000_000;
        for _ in 0..4 {
            state = state.on_failure(now);
            assert!(!state.is_locked(now));
        }
        state = state.on_failure(now);
        assert!(state.is_locked(now));
        assert!(state.is_locked(now + LOCK_SECS - 1));
        assert!(!state.is_locked(now + LOCK_SECS));
        let during = state.on_failure(now + 10);
        assert_eq!(during.locked_until, state.locked_until);
        assert_eq!(state.on_success(), Lockout::fresh());
    }

    #[test]
    fn totp_matches_rfc6238_sha1_vector() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp_at(secret, 59).unwrap(), "287082");
        assert!(totp_verify(secret, "287082", 59));
        assert!(totp_verify(secret, "287082", 59 + 30));
        assert!(!totp_verify(secret, "000000", 59));
        assert!(!totp_verify(secret, "28708", 59));
    }

    #[test]
    fn token_hash_is_stable_and_not_the_token() {
        let token = "atk.example";
        let hash = token_hash(token);
        assert_eq!(hash, token_hash(token));
        assert_ne!(hash, token);
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn refresh_token_outlives_a_month_idle() {
        assert_eq!(ACCESS_TTL_SECS, 15 * 60);
        assert!(ACCESS_SKEW_SECS > 60 && ACCESS_SKEW_SECS < ACCESS_TTL_SECS);
        assert_eq!(REFRESH_IDLE_SECS, 30 * 24 * 3600);
        assert!(REFRESH_GRACE_SECS > 0);
        assert_eq!(REFRESH_TTL_SECS, REFRESH_IDLE_SECS + REFRESH_GRACE_SECS);
        assert!(
            REFRESH_TTL_SECS > REFRESH_IDLE_SECS,
            "a device idle for 30 days must still be inside the refresh window"
        );
    }

    #[test]
    fn usernames_are_lowercase_identifiers() {
        assert!(valid_username("ada"));
        assert!(valid_username("a"));
        assert!(!valid_username("Ada"));
        assert!(!valid_username("1ada"));
        assert!(!valid_username(""));
        assert!(valid_role("admin"));
        assert!(valid_role("user"));
        assert!(!valid_role("root"));
    }
}
