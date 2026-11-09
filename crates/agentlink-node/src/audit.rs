//! Audit API for node handlers.
//!
//! Handlers build an [`AuditEvent`] and call [`submit`]. The installed
//! [`crate::pipeline::AuditService`] applies the audit policy: category
//! toggles, detail level, redaction, hash chain, and sinks. A failed write
//! does not fail the operation.
//!
//! [`EditAudit`] and [`ProcessAudit`] are the structured results search, edit,
//! and process handlers already produce. [`submit`] is what stores them.

use std::path::PathBuf;
use std::time::Duration;

use agentlink_core::audit::category_for_action;
use agentlink_core::protocol::Op;
use serde::Serialize;
use serde_json::{json, Value};

pub use agentlink_core::audit::AuditEvent;

/// Unified diffs stored on an edit record are cut here when a handler builds
/// its own preview. The policy cap is what the pipeline stores.
pub const DIFF_CAP: usize = 16 * 1024;
/// Command and PTY output a handler may attach to one event.
pub const OUTPUT_CAP: usize = 8 * 1024;

/// Who is being audited. Copied onto background tasks that outlive the request.
#[derive(Clone, Debug)]
pub struct Origin {
    pub path: PathBuf,
    pub node: String,
    pub node_id: String,
}

/// Before/after text for one edited file. The pipeline hashes and diffs these
/// under the edit policy.
#[derive(Clone, Debug, Serialize)]
pub struct EditAudit {
    pub files: Vec<FileEdit>,
}

#[derive(Clone, Debug, Serialize)]
pub struct FileEdit {
    pub path: String,
    pub before: String,
    pub after: String,
}

/// Command line, working directory, and exit. Output bytes travel on the event.
#[derive(Clone, Debug, Serialize)]
pub struct ProcessAudit {
    pub command: String,
    pub cwd: Option<String>,
    pub exit_code: Option<i32>,
}

/// What a handler returns so the dispatcher can record the outcome.
#[derive(Clone, Debug)]
pub struct Outcome {
    pub ok: bool,
    pub error: Option<String>,
    pub result: Value,
    pub edit: Option<EditAudit>,
    pub process: Option<ProcessAudit>,
    pub stdout: Option<Vec<u8>>,
    pub stderr: Option<Vec<u8>>,
}

impl Outcome {
    pub fn ok(result: Value) -> Self {
        Self {
            ok: true,
            error: None,
            result,
            edit: None,
            process: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn fail(error: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(error.into()),
            result: Value::Null,
            edit: None,
            process: None,
            stdout: None,
            stderr: None,
        }
    }

    pub fn with_edit(mut self, edit: EditAudit) -> Self {
        self.edit = Some(edit);
        self
    }

    pub fn with_process(mut self, process: ProcessAudit) -> Self {
        self.process = Some(process);
        self
    }
}

impl EditAudit {
    pub fn from_texts(files: Vec<(String, &str, &str)>) -> Self {
        Self {
            files: files
                .into_iter()
                .map(|(path, before, after)| FileEdit {
                    path,
                    before: before.to_string(),
                    after: after.to_string(),
                })
                .collect(),
        }
    }
}

impl ProcessAudit {
    pub fn new(
        command: impl Into<String>,
        cwd: Option<String>,
        exit_code: Option<i32>,
        _output: &str,
    ) -> Self {
        Self {
            command: command.into(),
            cwd,
            exit_code,
        }
    }
}

/// Record one operation. The policy decides whether it is stored.
pub fn submit(event: AuditEvent) {
    crate::pipeline::submit(event);
}

pub fn blake3_hex(bytes: &[u8]) -> String {
    blake3::hash(bytes).to_hex().to_string()
}

pub fn cap_text(text: &str, max: usize) -> (String, bool) {
    if text.len() <= max {
        return (text.to_string(), false);
    }
    let mut end = max.min(text.len());
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (format!("{}\n...[truncated]", &text[..end]), true)
}

pub fn combine_output(stdout: &[u8], stderr: &[u8]) -> String {
    let mut out = String::new();
    if !stdout.is_empty() {
        out.push_str(&String::from_utf8_lossy(stdout));
    }
    if !stderr.is_empty() {
        if !out.is_empty() {
            out.push('\n');
        }
        out.push_str("[stderr]\n");
        out.push_str(&String::from_utf8_lossy(stderr));
    }
    out
}

pub fn category_of(op: &Op) -> &'static str {
    match op {
        Op::Extension { name, payload } if name == "screenshot" => "gui_screenshot",
        Op::Extension { name, payload } if name == "inject_input" => {
            match payload.get("action").and_then(Value::as_str) {
                Some("ui_tree" | "act" | "find" | "click_element") => "a11y",
                _ => "gui_input",
            }
        }
        Op::Extension { name, .. } if name == "webrtc_signal" => "desktop_stream",
        other => category_for_action(&other.kind()),
    }
}

pub fn args_from_op(op: &Op) -> Value {
    match op {
        Op::WriteFile {
            path,
            offset,
            data_b64,
            truncate,
        } => json!({
            "path": path,
            "offset": offset,
            "bytes": (data_b64.len() / 4) * 3,
            "truncate": truncate,
        }),
        Op::PtyInput {
            session_id,
            data_b64,
        } => json!({
            "session_id": session_id,
            "bytes": (data_b64.len() / 4) * 3,
        }),
        Op::Exec {
            program,
            args,
            cwd,
            env,
            timeout_ms,
            shell,
            ..
        } => command_args(program, args, cwd, env, *shell, *timeout_ms),
        Op::BgStart {
            program,
            args,
            cwd,
            env,
            shell,
            ..
        } => command_args(program, args, cwd, env, *shell, None),
        Op::Replace {
            path,
            old,
            new,
            replace_all,
        } => json!({
            "path": path,
            "old_len": old.len(),
            "new_len": new.len(),
            "old_preview": preview(old, 200),
            "new_preview": preview(new, 200),
            "replace_all": replace_all,
        }),
        Op::EditLines {
            path,
            start_line,
            end_line,
            content,
        } => json!({
            "path": path,
            "start_line": start_line,
            "end_line": end_line,
            "content_len": content.len(),
            "content_preview": preview(content, 200),
        }),
        Op::ApplyPatch { root, patch } => json!({
            "root": root,
            "patch_bytes": patch.len(),
            "patch_preview": preview(patch, 500),
        }),
        Op::Extension { name, .. } => json!({"name": name}),
        other => serde_json::to_value(other).unwrap_or(Value::Null),
    }
}

fn command_args(
    program: &str,
    args: &[String],
    cwd: &Option<String>,
    env: &[(String, String)],
    shell: bool,
    timeout_ms: Option<u64>,
) -> Value {
    json!({
        "program": program,
        "args": args,
        "cwd": cwd,
        "shell": shell,
        "timeout_ms": timeout_ms,
        "env_keys": env.iter().map(|(key, _)| key).collect::<Vec<_>>(),
    })
}

fn preview(text: &str, max: usize) -> String {
    cap_text(text, max).0
}

/// Build the event a handler submits. `client_id` is the agent's ed25519
/// public key, never the labels `cli` or `mcp`.
pub fn event_for(
    category: &str,
    action: &str,
    client_id: &str,
    detail: &str,
    args: Value,
    ok: bool,
    error: Option<String>,
    duration: Duration,
) -> AuditEvent {
    let mut args = if args.is_object() { args } else { json!({}) };
    if let Some(obj) = args.as_object_mut() {
        obj.entry("detail").or_insert(json!(detail));
    }
    AuditEvent {
        category: category.to_string(),
        action: action.to_string(),
        client_id: client_id.to_string(),
        duration,
        args,
        ok,
        error,
        paths: paths_in(detail),
        ..AuditEvent::default()
    }
}

fn paths_in(detail: &str) -> Vec<String> {
    if detail.is_empty() || detail == "info" || detail == "pty" {
        Vec::new()
    } else if detail.contains('/') || detail.contains('\\') {
        vec![detail.to_string()]
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn edit_keeps_before_and_after_text() {
        let edit = EditAudit::from_texts(vec![("note.txt".into(), "old\n", "new\n")]);
        assert_eq!(edit.files[0].before, "old\n");
        assert_eq!(edit.files[0].after, "new\n");
        assert_eq!(blake3_hex(b"old\n").len(), 64);
    }

    #[test]
    fn args_omit_file_bytes_and_env_values() {
        let op = Op::Exec {
            program: "sh".into(),
            args: vec!["-c".into(), "echo".into()],
            cwd: Some("/tmp".into()),
            env: vec![("TOKEN".into(), "secret-value".into())],
            timeout_ms: Some(5),
            shell: false,
                stdin_b64: None,
        };
        let args = args_from_op(&op);
        let text = args.to_string();
        assert!(!text.contains("secret-value"));
        assert_eq!(args["env_keys"][0], "TOKEN");
        let write = Op::WriteFile {
            path: "/tmp/a".into(),
            offset: 0,
            data_b64: "aGVsbG8=".into(),
            truncate: true,
        };
        assert!(args_from_op(&write).get("data_b64").is_none());
    }

    #[test]
    fn extension_category_splits_input_and_accessibility() {
        let shot = Op::Extension {
            name: "screenshot".into(),
            payload: json!({"target": "region"}),
        };
        assert_eq!(category_of(&shot), "gui_screenshot");
        let typed = Op::Extension {
            name: "inject_input".into(),
            payload: json!({"action": "type", "text": "hello desktop"}),
        };
        assert_eq!(category_of(&typed), "gui_input");
        let tree = Op::Extension {
            name: "inject_input".into(),
            payload: json!({"action": "ui_tree"}),
        };
        assert_eq!(category_of(&tree), "a11y");
    }
}
