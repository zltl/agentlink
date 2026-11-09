//! Error type shared by the client, relay, and node.

use std::io;

/// Recoverable agentlink failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Message(String),
    #[error("permission denied: {0}")]
    PermissionDenied(String),
    #[error("not found: {0}")]
    NotFound(String),
    #[error("node offline: {0}")]
    Offline(String),
    #[error("ambiguous node name '{0}'")]
    Ambiguous(String),
    #[error("authentication failed: {0}")]
    Auth(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("cancelled")]
    Cancelled,
    #[error("timed out")]
    Timeout,
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("tls: {0}")]
    Tls(String),
    #[error("websocket: {0}")]
    Ws(String),
}

impl Error {
    /// Fatal authentication errors should stop the node instead of retrying.
    pub fn is_fatal(&self) -> bool {
        matches!(self, Error::Auth(_))
    }

    /// A dropped relay socket or a node that has not redialed yet.
    pub fn is_retryable(&self) -> bool {
        match self {
            Error::Ws(_) | Error::Timeout | Error::Io(_) => true,
            Error::Offline(_) => true,
            Error::Tls(message) => is_transient_tls(message),
            Error::Message(message) => crate::resume::is_transient_message(message),
            _ => false,
        }
    }
}

/// A relay that dropped the TLS handshake, not a trust failure.
///
/// Fingerprint, certificate, and hostname mismatches must not be retried;
/// they will fail the same way on every dial.
pub fn is_transient_tls(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("handshake eof")
        || lower.contains("unexpected eof")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
}

/// Appended to a transient relay TLS flap, already prefixed for display.
pub const TRANSIENT_TLS_TIP: &str =
    "tip: transient relay TLS flap — wait a second and retry; the CLI already retried the dial briefly";

const TRANSIENT_TLS_MARKER: &str = "transient relay TLS flap";

/// Append [`TRANSIENT_TLS_TIP`] to a display string that looks like a
/// transient TLS flap. Idempotent, so an error already carrying the tip is
/// returned unchanged.
pub fn decorate_transient_tls(message: &str) -> String {
    if message.contains(TRANSIENT_TLS_MARKER) {
        return message.to_string();
    }
    if is_transient_tls(message) {
        format!("{message}; {TRANSIENT_TLS_TIP}")
    } else {
        message.to_string()
    }
}

/// User-facing hint for a transient TLS connect failure, if `err` is one.
pub fn transient_tls_tip(err: &Error) -> Option<String> {
    match err {
        Error::Tls(message) if is_transient_tls(message) => {
            Some(format!("{err}; {TRANSIENT_TLS_TIP}"))
        }
        _ => None,
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transient_tls_handshake_failures_are_retryable() {
        assert!(Error::Tls("tls handshake eof".into()).is_retryable());
        assert!(Error::Tls("unexpected eof".into()).is_retryable());
        assert!(Error::Tls("connection reset by peer".into()).is_retryable());
        assert!(Error::Tls("broken pipe".into()).is_retryable());
        assert!(Error::Tls("TLS HANDSHAKE EOF".into()).is_retryable());
    }

    #[test]
    fn tls_trust_failures_are_not_retryable() {
        assert!(!Error::Tls("certificate fingerprint mismatch".into()).is_retryable());
        assert!(!Error::Tls("invalid server name".into()).is_retryable());
        assert!(!Error::Tls("certificate has expired".into()).is_retryable());
        assert!(!Error::Auth("bad token".into()).is_retryable());
    }

    #[test]
    fn tip_marks_only_transient_tls_failures() {
        let tip = transient_tls_tip(&Error::Tls("tls handshake eof".into())).unwrap();
        assert_eq!(
            tip,
            "tls: tls handshake eof; tip: transient relay TLS flap — wait a second and retry; the CLI already retried the dial briefly"
        );
        assert!(transient_tls_tip(&Error::Tls("invalid server name".into())).is_none());
        assert!(transient_tls_tip(&Error::Message("tls handshake eof".into())).is_none());
    }

    #[test]
    fn decorate_appends_the_tip_once() {
        assert_eq!(
            decorate_transient_tls("tls: tls handshake eof"),
            "tls: tls handshake eof; tip: transient relay TLS flap — wait a second and retry; the CLI already retried the dial briefly"
        );
        assert_eq!(
            decorate_transient_tls("download SHA256SUMS from https://relay.example/dl: unexpected eof"),
            "download SHA256SUMS from https://relay.example/dl: unexpected eof; tip: transient relay TLS flap — wait a second and retry; the CLI already retried the dial briefly"
        );
        let once = decorate_transient_tls("tls: tls handshake eof");
        assert_eq!(decorate_transient_tls(&once), once);
        assert_eq!(
            decorate_transient_tls("checksum mismatch for agentlink.tar.gz"),
            "checksum mismatch for agentlink.tar.gz"
        );
        assert_eq!(
            decorate_transient_tls("tls: certificate fingerprint mismatch"),
            "tls: certificate fingerprint mismatch"
        );
    }
}
