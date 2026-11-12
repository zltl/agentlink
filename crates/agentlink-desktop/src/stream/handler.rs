//! `webrtc_signal` extension. Signaling is request/response JSON. The media
//! plane is the WebRTC peer connection owned by [`super::webrtc_session`].

use std::any::Any;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use agentlink_core::{NodeExtension, NodePolicy, PHASE3_WEBRTC_SIGNAL};
use serde_json::Value;

use crate::Desktop;

use super::consent::ConsentMode;
use super::webrtc_session::{self, SessionManager};

/// One stream or remote-control event. The node forwards this to
/// `audit::submit`. Callers must not put SDP or full typed text in `detail`.
#[derive(Clone, Debug)]
pub struct StreamAudit {
    pub action: String,
    pub client_id: String,
    pub detail: String,
    pub args: Value,
    pub ok: bool,
    pub error: Option<String>,
    pub duration: Duration,
}

pub type StreamAuditHook = Arc<dyn Fn(&StreamAudit) + Send + Sync>;

/// Returns true when this grant jti is still active for `peer`.
pub type GrantActiveHook = Arc<dyn Fn(&str, &str) -> bool + Send + Sync>;

pub struct StreamSettings {
    pub policy: NodePolicy,
    pub audit_path: PathBuf,
    pub consent: ConsentMode,
    /// When set, stream start, stop, and remote-control input go through this
    /// hook instead of the desktop JSONL writer.
    pub on_audit: Option<StreamAuditHook>,
    /// When set, live sessions re-check this hook (revoked jti) on later
    /// signaling and input. Missing hook means "no deny-list check"; expiry
    /// is still enforced when `_grant_exp` was stamped.
    pub grant_active: Option<GrantActiveHook>,
}

pub(crate) struct StreamShared {
    pub policy: Arc<RwLock<NodePolicy>>,
    pub audit_path: RwLock<PathBuf>,
    pub consent: RwLock<ConsentMode>,
    pub on_audit: RwLock<Option<StreamAuditHook>>,
    pub grant_active: RwLock<Option<GrantActiveHook>>,
}

pub struct StreamHandler {
    desktop: Arc<Desktop>,
    shared: Arc<StreamShared>,
    engine: Mutex<Option<Engine>>,
}

struct Engine {
    runtime: Option<tokio::runtime::Runtime>,
    sessions: Arc<SessionManager>,
}

impl Drop for Engine {
    fn drop(&mut self) {
        let Some(runtime) = self.runtime.take() else {
            return;
        };
        // `Runtime`'s own drop blocks, and it panics when that happens on the
        // node runtime ("Cannot drop a runtime in a context where blocking is
        // not allowed"). SIGTERM unwinds the daemon on that runtime, which is
        // where this engine lives. Shut the worker runtime down on a plain thread.
        let _ = std::thread::Builder::new()
            .name("agentlink-rtc-shutdown".into())
            .spawn(move || drop(runtime));
    }
}

impl StreamHandler {
    pub fn new(desktop: Arc<Desktop>) -> Self {
        Self {
            desktop,
            shared: Arc::new(StreamShared {
                policy: Arc::new(RwLock::new(NodePolicy::none())),
                audit_path: RwLock::new(PathBuf::new()),
                consent: RwLock::new(ConsentMode::Deny),
                on_audit: RwLock::new(None),
                grant_active: RwLock::new(None),
            }),
            engine: Mutex::new(None),
        }
    }

    pub fn configure(&self, settings: StreamSettings) {
        if let Ok(mut policy) = self.shared.policy.write() {
            *policy = settings.policy;
        }
        if let Ok(mut path) = self.shared.audit_path.write() {
            *path = settings.audit_path;
        }
        if let Ok(mut consent) = self.shared.consent.write() {
            *consent = settings.consent;
        }
        if let Ok(mut hook) = self.shared.on_audit.write() {
            *hook = settings.on_audit;
        }
        if let Ok(mut hook) = self.shared.grant_active.write() {
            *hook = settings.grant_active;
        }
    }

    pub fn set_grant_active(&self, hook: Option<GrantActiveHook>) {
        if let Ok(mut slot) = self.shared.grant_active.write() {
            *slot = hook;
        }
    }

    pub fn close_sessions_for_jti(&self, jti: &str) -> usize {
        let Ok(sessions) = self.sessions() else {
            return 0;
        };
        let Ok(handle) = self.runtime_handle() else {
            return 0;
        };
        let jti = jti.to_string();
        std::thread::spawn(move || handle.block_on(sessions.close_sessions_for_jti(&jti)))
            .join()
            .unwrap_or(0)
    }

    pub fn close_expired_sessions(&self) -> usize {
        let Ok(sessions) = self.sessions() else {
            return 0;
        };
        let Ok(handle) = self.runtime_handle() else {
            return 0;
        };
        std::thread::spawn(move || handle.block_on(sessions.close_expired_sessions()))
            .join()
            .unwrap_or(0)
    }

    pub fn close_inactive_sessions(&self) -> usize {
        let Ok(sessions) = self.sessions() else {
            return 0;
        };
        let Ok(handle) = self.runtime_handle() else {
            return 0;
        };
        std::thread::spawn(move || handle.block_on(sessions.close_inactive_sessions()))
            .join()
            .unwrap_or(0)
    }

    pub fn close_all_sessions(&self) -> usize {
        let Ok(sessions) = self.sessions() else {
            return 0;
        };
        let Ok(handle) = self.runtime_handle() else {
            return 0;
        };
        std::thread::spawn(move || handle.block_on(sessions.close_all_sessions()))
            .join()
            .unwrap_or(0)
    }

    pub fn set_policy(&self, policy: NodePolicy) {
        if let Ok(mut slot) = self.shared.policy.write() {
            *slot = policy;
        }
    }

    /// Candidates gathered for a live session, including any that arrived
    /// after the answer was returned. typ/proto JSON only; no ufrag.
    pub fn gathered_candidates(&self, session_id: &str) -> Option<Vec<Value>> {
        self.sessions()
            .ok()
            .and_then(|sessions| sessions.gathered_candidates(session_id))
    }

    /// Fixture / tests only: append a candidate gathered after the answer.
    pub fn inject_gathered_candidate(
        &self,
        session_id: &str,
        candidate: Value,
    ) -> std::result::Result<(), String> {
        self.sessions()?
            .inject_gathered_candidate(session_id, candidate)
    }

    pub fn insert_test_grant_session(
        &self,
        id: &str,
        peer: &str,
        jti: &str,
        exp: Option<i64>,
    ) -> std::result::Result<(), String> {
        let sessions = self.sessions()?;
        let _ = self.runtime_handle()?;
        sessions.insert_test_grant_session(id, peer, jti, exp);
        Ok(())
    }

    pub fn test_session_is_live(&self, id: &str) -> bool {
        self.sessions()
            .ok()
            .is_some_and(|sessions| sessions.test_session_is_live(id))
    }

    fn sessions(&self) -> std::result::Result<Arc<SessionManager>, String> {
        let mut guard = self.engine.lock().unwrap_or_else(|err| err.into_inner());
        if guard.is_none() {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name("agentlink-rtc")
                .build()
                .map_err(|err| err.to_string())?;
            *guard = Some(Engine {
                runtime: Some(runtime),
                sessions: Arc::new(webrtc_session::manager(
                    self.desktop.clone(),
                    self.shared.clone(),
                )),
            });
        }
        Ok(guard.as_ref().unwrap().sessions.clone())
    }

    fn runtime_handle(&self) -> std::result::Result<tokio::runtime::Handle, String> {
        let guard = self.engine.lock().unwrap_or_else(|err| err.into_inner());
        guard
            .as_ref()
            .and_then(|engine| {
                engine
                    .runtime
                    .as_ref()
                    .map(|runtime| runtime.handle().clone())
            })
            .ok_or_else(|| "stream engine is not running".into())
    }
}

impl NodeExtension for StreamHandler {
    fn name(&self) -> &'static str {
        PHASE3_WEBRTC_SIGNAL
    }

    fn handle(&self, payload: &Value) -> std::result::Result<Value, String> {
        self.handle_peer(payload, "")
    }

    fn handle_peer(&self, payload: &Value, peer: &str) -> std::result::Result<Value, String> {
        let sessions = self.sessions()?;
        let handle = self.runtime_handle()?;
        let payload = payload.clone();
        let peer = peer.to_string();
        std::thread::spawn(move || {
            handle.block_on(async move { sessions.handle(&peer, &payload).await })
        })
        .join()
        .map_err(|_| "stream thread panicked".to_string())?
    }

    fn as_any(&self) -> Option<&dyn Any> {
        Some(self)
    }
}

pub fn configure_stream(extensions: &[Arc<dyn NodeExtension>], settings: StreamSettings) {
    if let Some(handler) = find(extensions) {
        handler.configure(settings);
    }
}

pub fn update_stream_policy(extensions: &[Arc<dyn NodeExtension>], policy: NodePolicy) {
    if let Some(handler) = find(extensions) {
        handler.set_policy(policy);
    }
}

pub fn close_streams_for_jti(extensions: &[Arc<dyn NodeExtension>], jti: &str) -> usize {
    find(extensions)
        .map(|handler| handler.close_sessions_for_jti(jti))
        .unwrap_or(0)
}

pub fn close_expired_streams(extensions: &[Arc<dyn NodeExtension>]) -> usize {
    find(extensions)
        .map(|handler| handler.close_expired_sessions())
        .unwrap_or(0)
}

/// Close live media sessions whose stored grant metadata is revoked or expired.
pub fn close_inactive_streams(extensions: &[Arc<dyn NodeExtension>]) -> usize {
    find(extensions)
        .map(|handler| handler.close_inactive_sessions())
        .unwrap_or(0)
}

/// Close every live media session (relay disconnect / node shutdown).
pub fn close_all_streams(extensions: &[Arc<dyn NodeExtension>]) -> usize {
    find(extensions)
        .map(|handler| handler.close_all_sessions())
        .unwrap_or(0)
}

fn find(extensions: &[Arc<dyn NodeExtension>]) -> Option<&StreamHandler> {
    extensions.iter().find_map(|ext| {
        ext.as_any()
            .and_then(|any| any.downcast_ref::<StreamHandler>())
    })
}
