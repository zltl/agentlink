//! HTTP `/audit` helpers: streamed JSONL pages, auth-chain appends, and the
//! read-only HTML viewer.
//!
//! Kept separate from the relay connection/state machine so audit IO policy
//! (pagination, filter-before-page, chain tips) stays reviewable in one place.

use std::sync::Mutex;

use crate::models::WebSession;

/// Default / hard ceiling for HTTP `GET /audit/records` pages.
pub(crate) const AUDIT_RECORDS_DEFAULT_LIMIT: usize = 200;
pub(crate) const AUDIT_RECORDS_MAX_LIMIT: usize = 1_000;
/// Hard ceiling for `offset` so the streamed ring (`limit + offset`) stays bounded.
pub(crate) const AUDIT_RECORDS_MAX_OFFSET: usize = 10_000;

pub(crate) fn audit_records_json(path: &std::path::Path, query: &str) -> String {
    let (limit, offset) = audit_page_bounds(query);
    let records = read_audit_values_page(path, limit, offset, None);
    serde_json::to_string(&records).unwrap_or_else(|_| "[]".into())
}

pub(crate) fn audit_records_json_for_session(
    path: &std::path::Path,
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

/// Newest-last page of audit JSON values. `offset` skips the newest records
/// (so `offset=0` is the latest page); older pages use larger offsets.
/// When `user` is `Some`, only that user's rows enter the page ring.
pub(crate) fn read_audit_values_page(
    path: &std::path::Path,
    limit: usize,
    offset: usize,
    user: Option<&str>,
) -> Vec<serde_json::Value> {
    agentlink_core::audit::page_from_jsonl(path, limit, offset, |record| match user {
        None => true,
        Some(name) => record.user.as_deref() == Some(name),
    })
    .into_iter()
    .filter_map(|record| serde_json::to_value(record).ok())
    .collect()
}

pub(crate) fn append_chained_auth(
    path: &std::path::Path,
    op: &str,
    user: &str,
    device: &str,
    ok: bool,
    error: &str,
) {
    use agentlink_core::audit::{assign_chain, AuditRecord};
    static CHAIN: Mutex<()> = Mutex::new(());
    let Ok(_guard) = CHAIN.lock() else {
        return;
    };
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
        append_audit(path, &[value]);
    }
}

pub(crate) fn append_audit(path: &std::path::Path, records: &[serde_json::Value]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    for record in records {
        let _ = std::io::Write::write_all(&mut file, record.to_string().as_bytes());
        let _ = std::io::Write::write_all(&mut file, b"\n");
    }
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
<p>Read-only view of records the nodes uploaded to this relay. End-to-end payloads are not on this page.</p>
<form id="filters">
<label>token <input id="token" type="password" autocomplete="current-password"></label>
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
tokenBox.value = sessionStorage.getItem("agentlink-audit-token") || "";
document.getElementById("filters").addEventListener("submit", async (event) => {
  event.preventDefault();
  sessionStorage.setItem("agentlink-audit-token", tokenBox.value);
  const status = document.getElementById("status");
  status.textContent = "loading";
  const response = await fetch("/audit/records?limit=200", {
    headers: { "Authorization": "Bearer " + tokenBox.value }
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


pub(crate) fn note_legacy_use(path: &std::path::Path, ok: bool, error: &str) {
    append_chained_auth(path, "legacy.admin", "admin", "token", ok, error);
}

pub(crate) fn audit_auth(
    path: &std::path::Path,
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
}
