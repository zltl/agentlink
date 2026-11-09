//! Callbacks implemented by the Android app.
//!
//! Every method returns a JSON object:
//! `{"ok":true,"body":...}` or `{"ok":false,"error":"..."}`.
//! Session polls use `body.event` of `pending`, `chunk`, or `exit`.
//! The methods run on a Rust worker thread and must not call back into a
//! blocking agentlink call.

use std::sync::Arc;

use agentlink_core::{Error, Result};
use serde_json::Value;

#[uniffi::export(with_foreign)]
pub trait NodeHost: Send + Sync {
    fn unary(&self, kind: String, payload_json: String) -> String;
    fn open_session(&self, kind: String, payload_json: String) -> String;
    fn poll_session(&self, session_id: String) -> String;
    fn session_input(&self, session_id: String, data_b64: String) -> String;
    fn close_session(&self, session_id: String) -> String;
    fn prepare_path(&self, guest: String, write: bool) -> String;
    fn publish_path(&self, guest: String, real_path: String) -> String;
    fn on_status(&self, status_json: String);
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
