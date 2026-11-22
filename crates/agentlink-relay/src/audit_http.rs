//! HTTP `/audit` helpers: streamed JSONL pages, auth-chain appends, isolated
//! node-audit storage, bounded log rotation, `0600` file permissions, and the
//! read-only HTML viewer.
//!
//! Kept separate from the relay connection/state machine so audit IO policy
//! (pagination, filter-before-page, chain tips, rotation) stays reviewable in
//! one place.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use agentlink_core::audit::AuditRecord;

use crate::models::WebSession;

/// Default / hard ceiling for HTTP `GET /audit/records` and WS `QueryAudit` pages.
pub(crate) const AUDIT_RECORDS_DEFAULT_LIMIT: usize = 200;
pub(crate) const AUDIT_RECORDS_MAX_LIMIT: usize = 1_000;
/// Hard ceiling for `offset` so the streamed ring (`limit + offset`) stays bounded.
pub(crate) const AUDIT_RECORDS_MAX_OFFSET: usize = 10_000;

/// Maximum size of a single relay audit JSONL file before rotation (16 MiB).
pub(crate) const AUDIT_ROTATE_MAX_BYTES: u64 = 16 * 1024 * 1024;
/// Number of rotated archives (`.1` .. `.3`) retained on disk.
pub(crate) const AUDIT_ROTATE_KEEP: usize = 3;
/// Isolated filename for node-uploaded `AuditBatch` records (sibling of `audit.jsonl`).
pub(crate) const NODE_AUDIT_FILE: &str = "node-audit.jsonl";

static AUDIT_LOCK: Mutex<()> = Mutex::new(());
static NODE_AUDIT_LOCK: Mutex<()> = Mutex::new(());

pub(crate) fn node_audit_path(audit_path: &Path) -> PathBuf {
    audit_path.with_file_name(NODE_AUDIT_FILE)
}

pub(crate) fn audit_records_json(path: &Path, query: &str) -> String {
    let (limit, offset) = audit_page_bounds(query);
    let records = read_audit_values_page(path, limit, offset, None);
    serde_json::to_string(&records).unwrap_or_else(|_| "[]".into())
}

pub(crate) fn audit_records_json_for_session(
    path: &Path,
    query: &str,
    session: &WebSession,
) -> String {
    let (limit, offset) = audit_page_bounds(query);
    // Non-admin sessions filter by user *while* streaming so a sparse user
    // still receives a full page and memory stays O(limit+offset).
    let user_filter = if session.role == "admin" {
        None
    } else {
        Some(session.user.as_str())
    };
    let records = read_audit_values_page(path, limit, offset, user_filter);
    serde_json::to_string(&records).unwrap_or_else(|_| "[]".into())
}

/// Parse `limit` / `offset` query params for `/audit/records`. Unknown keys
/// (including the removed `token=`) are ignored. Limit is clamped to
/// `[1, AUDIT_RECORDS_MAX_LIMIT]` with default `AUDIT_RECORDS_DEFAULT_LIMIT`.
/// Offset is clamped to `[0, AUDIT_RECORDS_MAX_OFFSET]`.
pub(crate) fn audit_page_bounds(query: &str) -> (usize, usize) {
    let mut limit = AUDIT_RECORDS_DEFAULT_LIMIT;
    let mut offset = 0usize;
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "limit" => {
                if let Ok(parsed) = value.parse::<usize>() {
                    limit = parsed.clamp(1, AUDIT_RECORDS_MAX_LIMIT);
                }
            }
            "offset" => {
                if let Ok(parsed) = value.parse::<usize>() {
                    offset = parsed.min(AUDIT_RECORDS_MAX_OFFSET);
                }
            }
            _ => {}
        }
    }
    (limit, offset)
}

/// Stream newest-last records from both the relay audit log and the isolated
/// node-uploaded audit log, applying `keep` while streaming so memory stays
/// `O(limit + offset)`.
pub(crate) fn read_audit_records_merged(
    audit_path: &Path,
    limit: usize,
    offset: usize,
    mut keep: impl FnMut(&AuditRecord) -> bool,
) -> Vec<AuditRecord> {
    if limit == 0 {
        return Vec::new();
    }
    let cap = limit.saturating_add(offset);
    let mut relay = agentlink_core::audit::page_from_jsonl(audit_path, cap, 0, &mut keep);
    let node_path = node_audit_path(audit_path);
    let mut nodes = if node_path.is_file() {
        agentlink_core::audit::page_from_jsonl(&node_path, cap, 0, &mut keep)
    } else {
        Vec::new()
    };
    let mut combined = if nodes.is_empty() {
        relay
    } else if relay.is_empty() {
        nodes
    } else {
        relay.append(&mut nodes);
        relay.sort_by(|a, b| compare_audit_ts(&a.ts, &b.ts));
        relay
    };
    if offset >= combined.len() {
        return Vec::new();
    }
    let end = combined.len() - offset;
    let start = end.saturating_sub(limit);
    combined.drain(start..end).collect()
}

fn compare_audit_ts(a: &str, b: &str) -> std::cmp::Ordering {
    match (a.parse::<i64>(), b.parse::<i64>()) {
        (Ok(left), Ok(right)) => left.cmp(&right),
        _ => a.cmp(b),
    }
}

/// Newest-last page of audit JSON values. `offset` skips the newest records
/// (so `offset=0` is the latest page); older pages use larger offsets.
/// When `user` is `Some`, only that user's rows enter the page ring.
pub(crate) fn read_audit_values_page(
    path: &Path,
    limit: usize,
    offset: usize,
    user: Option<&str>,
) -> Vec<serde_json::Value> {
    read_audit_records_merged(path, limit, offset, |record| match user {
        None => true,
        Some(name) => record.user.as_deref() == Some(name),
    })
    .into_iter()
    .filter_map(|record| serde_json::to_value(record).ok())
    .collect()
}

/// Open an append-only log file with owner-only permissions (`0600` on Unix,
/// private user/service ACL on Windows) and an owner-only parent directory
/// (`0700` when newly created).
pub(crate) fn open_private_append(path: &Path) -> std::io::Result<std::fs::File> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let _ = agentlink_core::util::ensure_secret_parent(parent);
        }
    }
    #[cfg(not(unix))]
    let existed = path.exists();
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    #[cfg(unix)]
    {
        let _ = agentlink_core::util::restrict_existing_file(path);
    }
    #[cfg(not(unix))]
    {
        if !existed {
            let _ = agentlink_core::util::restrict_existing_file(path);
        }
    }
    Ok(file)
}

pub(crate) fn rotate_if_needed(path: &Path, incoming_bytes: u64, max_bytes: u64, keep: usize) {
    if max_bytes == 0 {
        return;
    }
    let current = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if current == 0 || current.saturating_add(incoming_bytes) <= max_bytes {
        return;
    }
    rotate_log(path, keep);
}

fn rotated_path(path: &Path, index: usize) -> PathBuf {
    let mut os = path.as_os_str().to_os_string();
    os.push(format!(".{index}"));
    PathBuf::from(os)
}

fn rotate_log(path: &Path, keep: usize) {
    if keep == 0 {
        let _ = std::fs::remove_file(path);
        return;
    }
    let oldest = rotated_path(path, keep);
    let _ = std::fs::remove_file(&oldest);
    for idx in (1..keep).rev() {
        let src = rotated_path(path, idx);
        if src.exists() {
            let dst = rotated_path(path, idx + 1);
            let _ = agentlink_core::util::replace_file(&src, &dst);
        }
    }
    let first = rotated_path(path, 1);
    if path.exists() {
        let _ = agentlink_core::util::replace_file(path, &first);
        #[cfg(unix)]
        let _ = agentlink_core::util::restrict_existing_file(&first);
    }
}

fn append_serialized_locked(
    path: &Path,
    records: &[serde_json::Value],
    max_bytes: u64,
    keep: usize,
) {
    if records.is_empty() {
        return;
    }
    let mut buf = Vec::new();
    for record in records {
        buf.extend_from_slice(record.to_string().as_bytes());
        buf.push(b'\n');
    }
    rotate_if_needed(path, buf.len() as u64, max_bytes, keep);
    let Ok(mut file) = open_private_append(path) else {
        return;
    };
    let _ = file.write_all(&buf);
}

pub(crate) fn append_chained_auth(
    path: &Path,
    op: &str,
    user: &str,
    device: &str,
    ok: bool,
    error: &str,
) {
    append_chained_auth_with_limit(
        path,
        op,
        user,
        device,
        ok,
        error,
        AUDIT_ROTATE_MAX_BYTES,
        AUDIT_ROTATE_KEEP,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn append_chained_auth_with_limit(
    path: &Path,
    op: &str,
    user: &str,
    device: &str,
    ok: bool,
    error: &str,
    max_bytes: u64,
    keep: usize,
) {
    use agentlink_core::audit::assign_chain;
    let Ok(_guard) = AUDIT_LOCK.lock() else {
        return;
    };
    // Rotate BEFORE reading the chain tip so each rotated segment and the new
    // active file each carry an intact, self-contained hash chain.
    rotate_if_needed(path, 512, max_bytes, keep);
    let (seq, prev) = agentlink_core::audit::chain_tip_from_jsonl(path);
    let mut record = AuditRecord {
        seq: 0,
        ts: chrono_now(),
        node_id: "relay".into(),
        node_name: "relay".into(),
        client_id: device.into(),
        client_name: None,
        session_id: None,
        category: "auth".into(),
        op: op.into(),
        args: serde_json::json!({"user": user}),
        result: if ok { "ok" } else { "error" }.into(),
        error: if error.is_empty() {
            None
        } else {
            Some(error.into())
        },
        duration_ms: 0,
        transfer: None,
        before_hash: None,
        after_hash: None,
        diff_ref: None,
        output_ref: None,
        exit_code: None,
        prev_hash: String::new(),
        hash: String::new(),
        user: Some(user.into()),
        device_id: Some(device.into()),
    };
    assign_chain(&mut record, seq.saturating_add(1), &prev, true);
    if let Ok(value) = serde_json::to_value(&record) {
        append_serialized_locked(path, &[value], max_bytes, keep);
    }
}

pub(crate) fn append_audit(path: &Path, records: &[serde_json::Value]) {
    append_audit_with_limit(path, records, AUDIT_ROTATE_MAX_BYTES, AUDIT_ROTATE_KEEP);
}

pub(crate) fn append_audit_with_limit(
    path: &Path,
    records: &[serde_json::Value],
    max_bytes: u64,
    keep: usize,
) {
    let Ok(_guard) = AUDIT_LOCK.lock() else {
        return;
    };
    append_serialized_locked(path, records, max_bytes, keep);
}

/// Append node-uploaded audit records to the isolated `node-audit.jsonl` file
/// so untrusted node records can never corrupt the relay's auth hash chain or
/// force premature rotation of relay auth logs.
pub(crate) fn append_node_audit(path: &Path, records: &[serde_json::Value]) {
    let Ok(_guard) = NODE_AUDIT_LOCK.lock() else {
        return;
    };
    append_serialized_locked(path, records, AUDIT_ROTATE_MAX_BYTES, AUDIT_ROTATE_KEEP);
}

pub(crate) fn audit_page() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>agentlink audit</title>
<style>
body { font: 14px/1.4 ui-sans-serif, sans-serif; margin: 24px; color: #1c1917; background: #fafaf9; }
h1 { font-size: 20px; }
label { margin-right: 12px; }
input { margin-right: 8px; }
table { border-collapse: collapse; width: 100%; background: white; }
th, td { border: 1px solid #e7e5e4; padding: 6px 8px; text-align: left; vertical-align: top; }
th { background: #f5f5f4; }
code { font-size: 12px; }
</style>
</head>
<body>
<h1>agentlink audit</h1>
<p>Read-only view of records the nodes uploaded to this relay. End-to-end payloads are not on this page. Sign in on the dashboard to use your HttpOnly session cookie, or enter a Bearer token (kept in memory only).</p>
<form id="filters">
<label>token <input id="token" type="password" autocomplete="off" placeholder="optional if signed in"></label>
<label>node <input id="node"></label>
<label>agent <input id="agent"></label>
<label>op <input id="op"></label>
<label>text <input id="text"></label>
<button type="submit">load</button>
</form>
<p id="status"></p>
<table>
<thead><tr><th>time</th><th>node</th><th>agent</th><th>op</th><th>result</th><th>hash</th></tr></thead>
<tbody id="rows"></tbody>
</table>
<script>
const tokenBox = document.getElementById("token");
document.getElementById("filters").addEventListener("submit", async (event) => {
  event.preventDefault();
  const status = document.getElementById("status");
  status.textContent = "loading";
  const token = tokenBox.value.trim();
  const headers = token ? { "Authorization": "Bearer " + token } : {};
  const response = await fetch("/audit/records?limit=200", {
    credentials: "same-origin",
    headers
  });
  if (!response.ok) { status.textContent = "rejected (" + response.status + ")"; return; }
  const records = await response.json();
  const node = document.getElementById("node").value.trim();
  const agent = document.getElementById("agent").value.trim();
  const op = document.getElementById("op").value.trim();
  const text = document.getElementById("text").value.trim().toLowerCase();
  const rows = document.getElementById("rows");
  rows.innerHTML = "";
  let shown = 0;
  for (const record of records) {
    const blob = JSON.stringify(record).toLowerCase();
    if (node && record.node_id !== node && record.node_name !== node) continue;
    if (agent && record.client_id !== agent && record.client_name !== agent) continue;
    if (op && record.op !== op && record.category !== op) continue;
    if (text && !blob.includes(text)) continue;
    const tr = document.createElement("tr");
    for (const value of [record.ts, record.node_name || record.node_id, record.client_id, record.op, record.result, (record.hash || "").slice(0, 12)]) {
      const td = document.createElement("td");
      td.textContent = value || "";
      tr.appendChild(td);
    }
    rows.appendChild(tr);
    shown += 1;
  }
  status.textContent = shown + " records";
});
</script>
</body>
</html>
"#
    .to_string()
}

pub(crate) fn note_legacy_use(path: &Path, ok: bool, error: &str) {
    append_chained_auth(path, "legacy.admin", "admin", "token", ok, error);
}

pub(crate) fn audit_auth(
    path: &Path,
    op: &str,
    user: &str,
    device: &str,
    ok: bool,
    error: &str,
) {
    let record = serde_json::json!({
        "seq": 0,
        "ts": chrono_now(),
        "node_id": "relay",
        "node_name": "relay",
        "client_id": device,
        "category": "auth",
        "op": op,
        "args": {"user": user},
        "result": if ok { "ok" } else { "error" },
        "error": if error.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(error.into()) },
        "duration_ms": 0,
        "prev_hash": "off",
        "hash": "off",
        "user": user,
        "device_id": device,
    });
    append_audit(path, &[record]);
}

pub(crate) fn chrono_now() -> String {
    agentlink_core::util::unix_now().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_page_bounds_clamps_limit_and_ignores_token() {
        assert_eq!(
            audit_page_bounds(""),
            (AUDIT_RECORDS_DEFAULT_LIMIT, 0)
        );
        assert_eq!(audit_page_bounds("limit=50&offset=10"), (50, 10));
        assert_eq!(
            audit_page_bounds("limit=99999&token=secret"),
            (AUDIT_RECORDS_MAX_LIMIT, 0)
        );
        assert_eq!(audit_page_bounds("limit=0"), (1, 0));
        assert_eq!(audit_page_bounds("offset=abc&limit=25"), (25, 0));
        assert_eq!(
            audit_page_bounds(&format!("offset={}", AUDIT_RECORDS_MAX_OFFSET + 99)),
            (AUDIT_RECORDS_DEFAULT_LIMIT, AUDIT_RECORDS_MAX_OFFSET)
        );
    }

    #[test]
    fn audit_records_page_returns_newest_slice() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut body = String::new();
        for i in 0..10 {
            body.push_str(&format!(
                "{{\"seq\":{i},\"ts\":\"t{i}\",\"node_id\":\"n\",\"node_name\":\"n\",\"client_id\":\"c\",\"category\":\"op\",\"op\":\"op{i}\",\"result\":\"ok\",\"duration_ms\":0,\"prev_hash\":\"0\",\"hash\":\"{i}\"}}\n"
            ));
        }
        std::fs::write(&path, body).unwrap();
        let page = read_audit_values_page(&path, 3, 0, None);
        assert_eq!(page.len(), 3);
        assert_eq!(page[0]["op"], "op7");
        assert_eq!(page[2]["op"], "op9");
        let older = read_audit_values_page(&path, 3, 3, None);
        assert_eq!(older[0]["op"], "op4");
        assert_eq!(older[2]["op"], "op6");
    }

    #[test]
    fn audit_records_filter_user_before_paging() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut body = String::new();
        for i in 0..20 {
            let user = if i % 2 == 0 { "alice" } else { "bob" };
            body.push_str(&format!(
                "{{\"seq\":{i},\"ts\":\"t{i}\",\"node_id\":\"n\",\"node_name\":\"n\",\"client_id\":\"c\",\"category\":\"op\",\"op\":\"op{i}\",\"result\":\"ok\",\"duration_ms\":0,\"prev_hash\":\"0\",\"hash\":\"{i}\",\"user\":\"{user}\"}}\n"
            ));
        }
        std::fs::write(&path, body).unwrap();
        let page = read_audit_values_page(&path, 3, 0, Some("alice"));
        assert_eq!(page.len(), 3);
        assert_eq!(page[0]["op"], "op14");
        assert_eq!(page[1]["op"], "op16");
        assert_eq!(page[2]["op"], "op18");
        assert!(page.iter().all(|row| row["user"] == "alice"));
    }

    #[test]
    fn audit_page_does_not_persist_tokens_in_web_storage() {
        let html = audit_page();
        assert!(!html.contains("sessionStorage"), "{html}");
        assert!(!html.contains("localStorage"), "{html}");
        assert!(html.contains("credentials: \"same-origin\""), "{html}");
    }

    #[test]
    fn audit_rotation_caps_file_size_and_archive_count_with_private_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        for i in 0..25 {
            append_chained_auth_with_limit(
                &path,
                &format!("op.{i}"),
                "alice",
                "dev",
                true,
                "",
                700,
                2,
            );
        }
        assert!(path.is_file());
        assert!(rotated_path(&path, 1).is_file());
        assert!(rotated_path(&path, 2).is_file());
        assert!(
            !rotated_path(&path, 3).exists(),
            "archives beyond keep=2 must be pruned"
        );
        // Active file and rotated segment must each hold a valid hash chain.
        let active = agentlink_core::audit::page_from_jsonl(&path, 100, 0, |_| true);
        assert!(!active.is_empty());
        agentlink_core::audit::verify_chain(&active).unwrap();
        let prev = agentlink_core::audit::page_from_jsonl(&rotated_path(&path, 1), 100, 0, |_| true);
        assert!(!prev.is_empty());
        agentlink_core::audit::verify_chain(&prev).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for p in [&path, &rotated_path(&path, 1), &rotated_path(&path, 2)] {
                let mode = std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{} mode was {mode:o}", p.display());
            }
        }
    }
}
