//! Callbacks implemented by the Android app.
//!
//! Every method returns a JSON object:
//! `{"ok":true,"body":...}` or `{"ok":false,"error":"..."}`.
//! Session polls use `body.event` of `pending`, `chunk`, or `exit`.
//! The methods run on a Rust worker thread and must not call back into a
//! blocking agentlink call.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Mutex};

use agentlink_core::{Error, Result};
use serde_json::Value;
use uuid::Uuid;

#[uniffi::export(with_foreign)]
pub trait NodeHost: Send + Sync {
    fn unary(&self, kind: String, payload_json: String) -> String;
    fn open_session(&self, kind: String, payload_json: String) -> String;
    /// Public session poll. `caller` must be the authenticated E2E peer
    /// recorded at open; an empty caller is rejected.
    fn poll_session(&self, session_id: String, caller: String) -> String;
    fn session_input(&self, session_id: String, data_b64: String, caller: String) -> String;
    fn close_session(&self, session_id: String, caller: String) -> String;
    /// In-process cleanup for the task that opened the session. `release` is
    /// a capability minted at open and is not sent to the remote client.
    fn release_session(&self, session_id: String, release: String) -> String;
    fn prepare_path(&self, guest: String, write: bool) -> String;
    fn publish_path(&self, guest: String, real_path: String) -> String;
    fn on_status(&self, status_json: String);
}

struct HostSession {
    owner_peer: String,
    release: String,
    grant_jti: String,
    grant_exp_unix: Option<i64>,
}

/// Rust-side owner/release gate. The registered owner is the sealed E2E
/// peer from the opening invoke, not a client-supplied string.
#[derive(Default)]
pub struct HostSessionRegistry {
    inner: Mutex<HashMap<String, HostSession>>,
}

impl HostSessionRegistry {
    pub fn mint_release() -> String {
        Uuid::new_v4().to_string()
    }

    pub fn register(&self, session_id: &str, owner_peer: &str, release: &str) -> Result<()> {
        self.register_with_grant(session_id, owner_peer, release, "", None)
    }

    pub fn register_with_grant(
        &self,
        session_id: &str,
        owner_peer: &str,
        release: &str,
        grant_jti: &str,
        grant_exp_unix: Option<i64>,
    ) -> Result<()> {
        let owner = owner_peer.trim();
        if owner.is_empty() || release.trim().is_empty() || session_id.trim().is_empty() {
            return Err(Error::Auth("session owner is required".into()));
        }
        let mut map = self
            .inner
            .lock()
            .map_err(|_| Error::Message("host session map poisoned".into()))?;
        map.insert(
            session_id.to_string(),
            HostSession {
                owner_peer: owner.to_string(),
                release: release.to_string(),
                grant_jti: grant_jti.trim().to_string(),
                grant_exp_unix,
            },
        );
        Ok(())
    }

    /// Remove and return `(session_id, release)` for sessions whose grant
    /// expired, is revoked, or when the deny-list could not be read (`fail_closed`).
    pub fn take_inactive(
        &self,
        revoked: &BTreeSet<String>,
        now_unix: i64,
        fail_closed: bool,
    ) -> Vec<(String, String)> {
        let Ok(mut map) = self.inner.lock() else {
            return Vec::new();
        };
        let ids: Vec<String> = map
            .iter()
            .filter(|(_, session)| {
                if session.grant_exp_unix.is_some_and(|exp| now_unix >= exp) {
                    return true;
                }
                let jti = session.grant_jti.trim();
                if fail_closed {
                    return true;
                }
                !jti.is_empty()
                    && revoked
                        .iter()
                        .any(|item| item.trim().eq_ignore_ascii_case(jti))
            })
            .map(|(id, _)| id.clone())
            .collect();
        ids.into_iter()
            .filter_map(|id| map.remove(&id).map(|session| (id, session.release)))
            .collect()
    }

    /// Remove and return every tracked `(session_id, release)` for teardown.
    pub fn take_all(&self) -> Vec<(String, String)> {
        let Ok(mut map) = self.inner.lock() else {
            return Vec::new();
        };
        map.drain()
            .map(|(id, session)| (id, session.release))
            .collect()
    }

    pub fn authorize_caller(&self, session_id: &str, caller: &str) -> Result<()> {
        let caller = caller.trim();
        if caller.is_empty() {
            return Err(Error::Auth("session access requires a caller owner".into()));
        }
        let map = self
            .inner
            .lock()
            .map_err(|_| Error::Message("host session map poisoned".into()))?;
        let Some(session) = map.get(session_id) else {
            return Err(Error::NotFound("session not found for this peer".into()));
        };
        if session.owner_peer != caller {
            return Err(Error::NotFound("session not found for this peer".into()));
        }
        Ok(())
    }

    pub fn authorize_release(&self, session_id: &str, release: &str) -> Result<()> {
        if release.trim().is_empty() {
            return Err(Error::Auth("session release is required".into()));
        }
        let map = self
            .inner
            .lock()
            .map_err(|_| Error::Message("host session map poisoned".into()))?;
        let Some(session) = map.get(session_id) else {
            return Err(Error::NotFound("session not found for this peer".into()));
        };
        if session.release != release {
            return Err(Error::NotFound("session not found for this peer".into()));
        }
        Ok(())
    }

    pub fn take_release(&self, session_id: &str, release: &str) -> Result<()> {
        self.authorize_release(session_id, release)?;
        let mut map = self
            .inner
            .lock()
            .map_err(|_| Error::Message("host session map poisoned".into()))?;
        map.remove(session_id);
        Ok(())
    }
}

pub fn poll_for_peer(
    registry: &HostSessionRegistry,
    host: &Arc<dyn NodeHost>,
    session_id: &str,
    caller: &str,
) -> Result<Value> {
    registry.authorize_caller(session_id, caller)?;
    let host = host.clone();
    let sid = session_id.to_string();
    let caller = caller.to_string();
    // Caller is the sealed peer already checked against the registry.
    parse_host(&host.poll_session(sid, caller))
}

pub fn close_for_peer(
    registry: &HostSessionRegistry,
    host: &Arc<dyn NodeHost>,
    session_id: &str,
    caller: &str,
) -> Result<Value> {
    registry.authorize_caller(session_id, caller)?;
    parse_host(&host.close_session(session_id.to_string(), caller.to_string()))
}

pub fn release_owned(
    registry: &HostSessionRegistry,
    host: &Arc<dyn NodeHost>,
    session_id: &str,
    release: &str,
) -> Result<()> {
    registry.take_release(session_id, release)?;
    let _ = parse_host(&host.release_session(session_id.to_string(), release.to_string()));
    Ok(())
}

pub fn parse_host(raw: &str) -> Result<Value> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|e| Error::Message(format!("host returned invalid json: {e}")))?;
    if value.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        Ok(value.get("body").cloned().unwrap_or(Value::Null))
    } else {
        let message = value
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("host error");
        Err(Error::Message(message.to_string()))
    }
}

pub async fn call_unary(host: &Arc<dyn NodeHost>, kind: &str, payload: Value) -> Result<Value> {
    let kind = kind.to_string();
    let payload = payload.to_string();
    let host = host.clone();
    let raw = tokio::task::spawn_blocking(move || host.unary(kind, payload))
        .await
        .map_err(|e| Error::Message(format!("host task: {e}")))?;
    parse_host(&raw)
}

pub fn host_ok(body: Value) -> String {
    serde_json::json!({"ok": true, "body": body}).to_string()
}

pub fn host_err(message: impl Into<String>) -> String {
    serde_json::json!({"ok": false, "error": message.into()}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Mutex;

    struct RecordingHost {
        polls: Mutex<Vec<(String, String)>>,
        closes: Mutex<Vec<(String, String)>>,
        releases: Mutex<Vec<(String, String)>>,
        output: String,
    }

    impl RecordingHost {
        fn new(output: &str) -> Self {
            Self {
                polls: Mutex::new(Vec::new()),
                closes: Mutex::new(Vec::new()),
                releases: Mutex::new(Vec::new()),
                output: output.to_string(),
            }
        }
    }

    impl NodeHost for RecordingHost {
        fn unary(&self, _kind: String, _payload_json: String) -> String {
            host_err("unused")
        }
        fn open_session(&self, _kind: String, _payload_json: String) -> String {
            host_err("unused")
        }
        fn poll_session(&self, session_id: String, caller: String) -> String {
            self.polls.lock().unwrap().push((session_id, caller));
            host_ok(json!({"event": "chunk", "stream": "stdout", "data_b64": self.output}))
        }
        fn session_input(&self, _session_id: String, _data_b64: String, _caller: String) -> String {
            host_err("unused")
        }
        fn close_session(&self, session_id: String, caller: String) -> String {
            self.closes.lock().unwrap().push((session_id.clone(), caller));
            host_ok(json!({"closed": session_id}))
        }
        fn release_session(&self, session_id: String, release: String) -> String {
            self.releases.lock().unwrap().push((session_id.clone(), release));
            host_ok(json!({"closed": session_id}))
        }
        fn prepare_path(&self, _guest: String, _write: bool) -> String {
            host_err("unused")
        }
        fn publish_path(&self, _guest: String, _real_path: String) -> String {
            host_ok(json!({}))
        }
        fn on_status(&self, _status_json: String) {}
    }

    #[test]
    fn alice_cannot_poll_or_close_bobs_host_session() {
        let registry = HostSessionRegistry::default();
        let host = Arc::new(RecordingHost::new("Ym9iLW91dA==")); // not used if denied
        let release = HostSessionRegistry::mint_release();
        registry.register("sid-bob", "bob", &release).unwrap();

        let err = poll_for_peer(&registry, &(host.clone() as Arc<dyn NodeHost>), "sid-bob", "alice")
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
        assert!(host.polls.lock().unwrap().is_empty(), "alice must not read Bob output");

        let err = poll_for_peer(&registry, &(host.clone() as Arc<dyn NodeHost>), "sid-bob", "")
            .unwrap_err();
        assert!(err.to_string().contains("requires a caller"), "{err}");
        assert!(host.polls.lock().unwrap().is_empty());

        let err = close_for_peer(&registry, &(host.clone() as Arc<dyn NodeHost>), "sid-bob", "alice")
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
        assert!(host.closes.lock().unwrap().is_empty());

        // Forged owner string is not enough without the registered sealed peer.
        let err = close_for_peer(&registry, &(host.clone() as Arc<dyn NodeHost>), "sid-bob", "bob-forged")
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");

        let body = poll_for_peer(&registry, &(host.clone() as Arc<dyn NodeHost>), "sid-bob", "bob").unwrap();
        assert_eq!(body["event"], "chunk");
        assert_eq!(host.polls.lock().unwrap().as_slice(), &[("sid-bob".into(), "bob".into())]);

        let err = release_owned(&registry, &(host.clone() as Arc<dyn NodeHost>), "sid-bob", "wrong-release")
            .unwrap_err();
        assert!(err.to_string().contains("not found"), "{err}");
        assert!(host.releases.lock().unwrap().is_empty());

        release_owned(&registry, &(host.clone() as Arc<dyn NodeHost>), "sid-bob", &release).unwrap();
        assert_eq!(host.releases.lock().unwrap().len(), 1);
        // After trusted release, even Bob cannot poll.
        assert!(poll_for_peer(&registry, &(host.clone() as Arc<dyn NodeHost>), "sid-bob", "bob").is_err());
    }
}
