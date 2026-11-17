//! Sticky first-cause transport status for a [`crate::client::Client`] session.
//!
//! Downstream callers often only see `connection closed`. This module records the
//! **first** supervise / auth / WebSocket end reason with whitelist categories and
//! an optional WS close code — never tokens, credential files, SDP, or raw
//! server error strings.
//!
//! An optional [`ClosureSink`] fires only after **all** observer locks are
//! released (status + sink slot), so a callback may safely [`TransportObserver::snapshot`]
//! / [`TransportObserver::set_sink`] without deadlock.

use std::fmt;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

/// Whitelisted closure categories suitable for persistent sanitized logs.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ClosureCategory {
    /// No terminal transport event recorded yet.
    #[default]
    None,
    /// Local shutdown / CancellationToken cancelled.
    Shutdown,
    /// Peer sent a WebSocket Close frame (see [`TransportStatus::ws_close_code`]).
    WsClose,
    /// WebSocket stream ended without a Close frame (`None` from the socket).
    WsStreamEnd,
    /// WebSocket stream returned a transport error (category only; no raw string).
    WsStreamError,
    /// Relay rejected credentials / HelloErr (auth path; no raw message logged).
    AuthRejected,
    /// Post-connect reconnect budget exhausted.
    DialGiveUp,
    /// First dial never became ready within the initial budget.
    InitialDialGiveUp,
    /// Ready oneshot dropped before a Hello outcome.
    ReadyDropped,
    /// Soft relay GoingAway observed (reconnect expected; not a hard fail alone).
    GoingAway,
}

impl ClosureCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Shutdown => "shutdown",
            Self::WsClose => "ws_close",
            Self::WsStreamEnd => "ws_stream_end",
            Self::WsStreamError => "ws_stream_error",
            Self::AuthRejected => "auth_rejected",
            Self::DialGiveUp => "dial_give_up",
            Self::InitialDialGiveUp => "initial_dial_give_up",
            Self::ReadyDropped => "ready_dropped",
            Self::GoingAway => "going_away",
        }
    }

    pub fn parse_whitelist(raw: &str) -> Option<Self> {
        match raw.trim() {
            "none" => Some(Self::None),
            "shutdown" => Some(Self::Shutdown),
            "ws_close" => Some(Self::WsClose),
            "ws_stream_end" => Some(Self::WsStreamEnd),
            "ws_stream_error" => Some(Self::WsStreamError),
            "auth_rejected" => Some(Self::AuthRejected),
            "dial_give_up" => Some(Self::DialGiveUp),
            "initial_dial_give_up" => Some(Self::InitialDialGiveUp),
            "ready_dropped" => Some(Self::ReadyDropped),
            "going_away" => Some(Self::GoingAway),
            _ => None,
        }
    }

    /// Categories that explain why waiters later see `connection closed`.
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::None | Self::GoingAway)
    }
}

/// Snapshot of the first recorded transport end for one Client supervise loop.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TransportStatus {
    pub category: ClosureCategory,
    pub ws_close_code: Option<u16>,
    /// Dial / reconnect attempt count when the first cause was recorded.
    pub attempt: u32,
}

impl TransportStatus {
    pub fn is_empty(&self) -> bool {
        self.category == ClosureCategory::None
    }
}

/// Invoked when a new first-cause (or GoingAway→terminal upgrade) is recorded.
/// May call back into the observer (`snapshot` / `set_sink`); must not assume
/// the sink mutex is held.
pub type ClosureSink = Arc<dyn Fn(TransportStatus) + Send + Sync>;

/// Process-local observer: sticky first cause only.
///
/// Manual [`Debug`]: `ClosureSink` is `dyn Fn` and is not `Debug`. Representation
/// exposes only status / attempt / whether a sink is installed — never the
/// closure (required so `ClientInner` can derive Debug).
#[derive(Default)]
pub struct TransportObserver {
    status: Mutex<TransportStatus>,
    attempts: AtomicU32,
    sink: Mutex<Option<ClosureSink>>,
}

impl fmt::Debug for TransportObserver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sink_set = self.sink.lock().map(|slot| slot.is_some()).unwrap_or(false);
        f.debug_struct("TransportObserver")
            .field("status", &self.snapshot())
            .field("attempts", &self.attempt())
            .field("sink_set", &sink_set)
            .finish()
    }
}

impl TransportObserver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_sink(&self, sink: Option<ClosureSink>) {
        if let Ok(mut slot) = self.sink.lock() {
            *slot = sink;
        }
    }

    pub fn bump_attempt(&self) -> u32 {
        self.attempts
            .fetch_add(1, Ordering::SeqCst)
            .saturating_add(1)
    }

    pub fn attempt(&self) -> u32 {
        self.attempts.load(Ordering::SeqCst)
    }

    pub fn snapshot(&self) -> TransportStatus {
        self.status
            .lock()
            .map(|guard| guard.clone())
            .unwrap_or_default()
    }

    /// Record the first cause. Later calls are ignored unless the slot is empty
    /// or a soft [`ClosureCategory::GoingAway`] upgrades to a terminal cause.
    /// Returns `true` when the stored status changed. The optional sink runs
    /// only after **all** observer locks are released.
    pub fn note_first(&self, category: ClosureCategory, ws_close_code: Option<u16>) -> bool {
        if category == ClosureCategory::None {
            return false;
        }
        let attempt = self.attempt();
        let recorded = {
            let Ok(mut guard) = self.status.lock() else {
                return false;
            };
            let upgrade_going_away =
                guard.category == ClosureCategory::GoingAway && category.is_terminal();
            if guard.category == ClosureCategory::None || upgrade_going_away {
                *guard = TransportStatus {
                    category,
                    ws_close_code,
                    attempt,
                };
                true
            } else {
                false
            }
        };
        if recorded {
            let snap = self.snapshot();
            let sink = self.sink.lock().ok().and_then(|slot| slot.clone());
            if let Some(sink) = sink {
                sink(snap);
            }
        }
        recorded
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn first_cause_is_sticky_and_whitelist_parses() {
        let obs = TransportObserver::new();
        assert_eq!(obs.bump_attempt(), 1);
        assert!(obs.note_first(ClosureCategory::WsClose, Some(1000)));
        assert!(!obs.note_first(ClosureCategory::AuthRejected, None));
        let snap = obs.snapshot();
        assert_eq!(snap.category, ClosureCategory::WsClose);
        assert_eq!(snap.ws_close_code, Some(1000));
        assert_eq!(snap.attempt, 1);
        assert_eq!(
            ClosureCategory::parse_whitelist("auth_rejected"),
            Some(ClosureCategory::AuthRejected)
        );
        assert!(ClosureCategory::parse_whitelist("token leaked").is_none());
    }

    #[test]
    fn going_away_upgrades_to_terminal() {
        let obs = TransportObserver::new();
        let _ = obs.bump_attempt();
        assert!(obs.note_first(ClosureCategory::GoingAway, None));
        assert!(obs.note_first(ClosureCategory::DialGiveUp, None));
        assert_eq!(obs.snapshot().category, ClosureCategory::DialGiveUp);
    }

    #[test]
    fn sink_fires_outside_first_note_and_only_on_change() {
        let obs = Arc::new(TransportObserver::new());
        let _ = obs.bump_attempt();
        let fired = Arc::new(AtomicBool::new(false));
        let seen = Arc::new(Mutex::new(None));
        let fired_flag = Arc::clone(&fired);
        let seen_slot = Arc::clone(&seen);
        obs.set_sink(Some(Arc::new(move |status| {
            fired_flag.store(true, Ordering::SeqCst);
            *seen_slot.lock().expect("seen") = Some(status);
        })));
        assert!(obs.note_first(ClosureCategory::AuthRejected, None));
        assert!(fired.load(Ordering::SeqCst));
        assert_eq!(
            seen.lock().expect("seen").as_ref().map(|s| s.category),
            Some(ClosureCategory::AuthRejected)
        );
        fired.store(false, Ordering::SeqCst);
        assert!(!obs.note_first(ClosureCategory::WsClose, Some(1001)));
        assert!(!fired.load(Ordering::SeqCst));
    }

    #[test]
    fn observer_debug_omits_closure_and_compiles_with_sink_installed() {
        let obs = TransportObserver::new();
        obs.set_sink(Some(Arc::new(|_| {})));
        let text = format!("{obs:?}");
        assert!(text.contains("TransportObserver"));
        assert!(text.contains("sink_set: true"));
        assert!(!text.contains("Fn("));
    }

    #[test]
    fn sink_callback_may_reenter_snapshot_and_set_sink() {
        let obs = Arc::new(TransportObserver::new());
        let _ = obs.bump_attempt();
        let reentered = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&reentered);
        let weak = Arc::clone(&obs);
        obs.set_sink(Some(Arc::new(move |_status| {
            let snap = weak.snapshot();
            assert_eq!(snap.category, ClosureCategory::WsClose);
            weak.set_sink(None);
            flag.store(true, Ordering::SeqCst);
        })));
        assert!(obs.note_first(ClosureCategory::WsClose, Some(1000)));
        assert!(reentered.load(Ordering::SeqCst));
        assert!(obs.sink.lock().expect("sink").is_none());
    }
}
