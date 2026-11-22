//! Phone audit log.
//!
//! Handlers call [`submit`]. The policy builds a hash-chained record, writes
//! the local JSONL sink, forwards a batch to the relay, and can put the same
//! bytes in S3. `app:/audit.log` still receives the legacy line the phone UI
//! reads.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

use agentlink_core::audit::{
    self, assign_chain, prepare, AuditEvent, AuditPolicy, AuditRecord, SinkSpec,
};
use agentlink_core::protocol::Envelope;
use agentlink_core::s3::{self, S3Client, S3Config};
use agentlink_core::ws::Outbound;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::Serialize;
use serde_json::json;
use tokio::sync::mpsc;

#[derive(Serialize)]
struct AuditEntry<'a> {
    ts: String,
    op: &'a str,
    detail: &'a str,
    ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer: Option<&'a str>,
}

pub fn record(
    path: &Path,
    op: &str,
    detail: &str,
    ok: bool,
    error: Option<&str>,
    peer: Option<&str>,
) {
    let entry = AuditEntry {
        ts: chrono::Utc::now().to_rfc3339(),
        op,
        detail,
        ok,
        error,
        peer,
    };
    let Ok(line) = serde_json::to_string(&entry) else {
        return;
    };
    let _guard = lock().lock().unwrap_or_else(|e| e.into_inner());
    if let Err(err) = append(path, &line) {
        tracing::error!(error = %err, "audit log write failed");
    }
}

pub fn tail(path: &Path, limit: usize) -> String {
    let _guard = lock().lock().unwrap_or_else(|e| e.into_inner());
    // Bounded per-line and O(limit) ring — never `BufRead::lines().collect()` of
    // the whole file (hostile multi-MiB lines or huge logs must not force RAM).
    agentlink_core::audit::tail_bounded_lines(path, limit).join("\n")
}

fn append(path: &Path, line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    Ok(())
}

fn lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

struct ChainState {
    seq: u64,
    prev: String,
}

struct S3Job {
    config: S3Config,
    key: String,
    body: Vec<u8>,
}

const S3_QUEUE_CAP: usize = 256;

/// Hash chain and sinks for one phone node. Survives a relay reconnect.
pub struct AuditHub {
    node_id: String,
    node_name: String,
    root: PathBuf,
    policy: RwLock<AuditPolicy>,
    chain: Mutex<ChainState>,
    tx: Mutex<Option<mpsc::Sender<Outbound>>>,
    s3_tx: Mutex<Option<std::sync::mpsc::SyncSender<S3Job>>>,
}

impl AuditHub {
    pub fn open(data_dir: &Path, node_id: &str, node_name: &str) -> Self {
        let root = data_dir.join("audit");
        let _ = fs::create_dir_all(root.join("logs"));
        let _ = fs::create_dir_all(root.join("blobs"));
        let policy = load_policy(data_dir);
        let chain = load_chain(&root);
        let (s3_tx, s3_rx) = std::sync::mpsc::sync_channel::<S3Job>(S3_QUEUE_CAP);
        let worker_tx = match std::thread::Builder::new()
            .name("agentlink-audit-s3".into())
            .spawn(move || {
                while let Ok(job) = s3_rx.recv() {
                    if let Ok(client) = S3Client::new(job.config) {
                        let _ = client.put(&job.key, &job.body, "application/gzip");
                    }
                }
            }) {
            Ok(_) => Some(s3_tx),
            Err(_) => None,
        };
        Self {
            node_id: node_id.to_string(),
            node_name: node_name.to_string(),
            root,
            policy: RwLock::new(policy),
            chain: Mutex::new(chain),
            tx: Mutex::new(None),
            s3_tx: Mutex::new(worker_tx),
        }
    }

    pub fn legacy_path(&self) -> PathBuf {
        self.root.parent().unwrap_or(&self.root).join("audit.log")
    }

    pub fn set_tx(&self, tx: Option<mpsc::Sender<Outbound>>) {
        if let Ok(mut guard) = self.tx.lock() {
            *guard = tx;
        }
    }

    pub fn replace_policy(&self, policy: AuditPolicy) {
        if let Ok(mut guard) = self.policy.write() {
            *guard = policy;
        }
    }

    pub fn policy(&self) -> AuditPolicy {
        self.policy
            .read()
            .map(|policy| policy.clone())
            .unwrap_or_else(|_| AuditPolicy::preset("standard").expect("standard preset"))
    }

    /// Record one operation. A failed sink does not fail the operation.
    pub fn submit(&self, event: AuditEvent) {
        let policy = self.policy();
        let Some(mut draft) = prepare(&policy, &self.node_id, &self.node_name, &event) else {
            self.append_legacy(&event);
            return;
        };
        let (seq, prev, chain_on) = {
            let Ok(mut chain) = self.chain.lock() else {
                return;
            };
            chain.seq += 1;
            (chain.seq, chain.prev.clone(), policy.forward.chain)
        };
        if let Some(diff) = &draft.diff {
            let name = format!("diff-{seq:016}.txt");
            let _ = fs::write(self.root.join("blobs").join(&name), diff);
            draft.record.diff_ref = Some(format!("blobs/{name}"));
        }
        if let Some(output) = &draft.output {
            let name = format!("output-{seq:016}.txt");
            let _ = fs::write(self.root.join("blobs").join(&name), output);
            draft.record.output_ref = Some(format!("blobs/{name}"));
        }
        assign_chain(&mut draft.record, seq, &prev, chain_on);
        if chain_on {
            if let Ok(mut chain) = self.chain.lock() {
                chain.prev = draft.record.hash.clone();
                save_chain(&self.root, &chain);
            }
        }
        self.write_local(&policy, &draft.record);
        self.append_legacy(&event);
        self.forward(&policy, &draft.record);
    }

    fn append_legacy(&self, event: &AuditEvent) {
        let detail = event
            .args
            .get("detail")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        record(
            &self.legacy_path(),
            &event.action,
            detail,
            event.ok,
            event.error.as_deref(),
            Some(&event.client_id),
        );
    }

    fn write_local(&self, policy: &AuditPolicy, record: &AuditRecord) {
        let sinks: Vec<&SinkSpec> = policy
            .sinks
            .iter()
            .filter(|sink| sink.kind == "local" && sink.accepts("logs"))
            .collect();
        if sinks.is_empty() {
            return;
        }
        let day = chrono::Utc::now().format("%Y-%m-%d");
        let path = self.root.join("logs").join(format!("{day}.jsonl"));
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let Ok(line) = serde_json::to_string(record) else {
            return;
        };
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{line}");
        }
    }

    fn forward(&self, policy: &AuditPolicy, record: &AuditRecord) {
        let Ok(value) = serde_json::to_value(record) else {
            return;
        };
        for sink in &policy.sinks {
            if sink.kind == "relay" && sink.accepts("logs") {
                let env = Envelope::AuditBatch {
                    node_id: self.node_id.clone(),
                    records: vec![value.clone()],
                };
                let Ok(text) = serde_json::to_string(&env) else {
                    continue;
                };
                let tx = self.tx.lock().ok().and_then(|guard| guard.clone());
                if let Some(tx) = tx {
                    let _ = tx.try_send(Outbound::Text(text));
                }
            }
            if sink.kind == "s3" && sink.accepts("logs") {
                if let Some(config) = sink.s3.clone() {
                    let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
                    let name = format!("{:016}.jsonl.gz", record.seq);
                    let key = s3::object_key(&self.node_id, &day, "logs", &name);
                    let Some(body) = gzip_line(record) else {
                        continue;
                    };
                    if let Ok(guard) = self.s3_tx.lock() {
                        if let Some(tx) = guard.as_ref() {
                            let _ = tx.try_send(S3Job { config, key, body });
                        }
                    }
                }
            }
        }
    }
}

pub fn event_for(
    category: &str,
    action: &str,
    client_id: &str,
    detail: &str,
    ok: bool,
    error: Option<String>,
) -> AuditEvent {
    let paths = if detail.contains('/') || detail.contains('\\') {
        vec![detail.to_string()]
    } else {
        Vec::new()
    };
    AuditEvent {
        category: category.to_string(),
        action: action.to_string(),
        client_id: client_id.to_string(),
        args: json!({"detail": detail}),
        ok,
        error,
        paths,
        ..AuditEvent::default()
    }
}

pub async fn submit_op(
    hub: &Arc<AuditHub>,
    action: &str,
    client_id: &str,
    detail: &str,
    ok: bool,
    error: Option<String>,
) {
    let category = audit::category_for_action(action);
    let event = event_for(category, action, client_id, detail, ok, error);
    let hub = Arc::clone(hub);
    let _ = tokio::task::spawn_blocking(move || hub.submit(event)).await;
}

fn load_policy(data_dir: &Path) -> AuditPolicy {
    let path = data_dir.join("audit.toml");
    if let Ok(text) = fs::read_to_string(path) {
        if let Ok(policy) = AuditPolicy::parse(&text) {
            return policy;
        }
    }
    AuditPolicy::preset("standard").expect("standard preset")
}

fn load_chain(root: &Path) -> ChainState {
    let path = root.join("chain.state");
    if let Ok(text) = fs::read_to_string(path) {
        let mut parts = text.split_whitespace();
        let seq = parts.next().and_then(|part| part.parse().ok()).unwrap_or(0);
        let prev = parts.next().unwrap_or("").to_string();
        let prev = if seq == 0 && prev.is_empty() {
            "0".repeat(64)
        } else {
            prev
        };
        return ChainState { seq, prev };
    }
    ChainState {
        seq: 0,
        prev: "0".repeat(64),
    }
}

fn save_chain(root: &Path, chain: &ChainState) {
    let _ = fs::write(
        root.join("chain.state"),
        format!("{} {}\n", chain.seq, chain.prev),
    );
}

fn gzip_line(record: &AuditRecord) -> Option<Vec<u8>> {
    let line = serde_json::to_string(record).ok()?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(line.as_bytes()).ok()?;
    encoder.write_all(b"\n").ok()?;
    encoder.finish().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_has_the_desktop_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        record(
            &path,
            "write",
            "app:/files/a",
            false,
            Some("denied"),
            Some("c1"),
        );
        let text = tail(&path, 10);
        let value: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(value["op"], "write");
        assert_eq!(value["detail"], "app:/files/a");
        assert_eq!(value["ok"], false);
        assert_eq!(value["error"], "denied");
        assert_eq!(value["peer"], "c1");
        assert!(value["ts"].as_str().unwrap().contains('T'));
    }

    #[test]
    fn tail_skips_oversized_line_and_keeps_ring_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let mut body = vec![b'x'; agentlink_core::audit::MAX_AUDIT_LINE_BYTES + 4_096];
        body.push(b'\n');
        body.extend_from_slice(br#"{"op":"keep","ok":true}"#);
        body.push(b'\n');
        for i in 0..8 {
            body.extend_from_slice(format!(r#"{{"op":"n{i}"}}"#).as_bytes());
            body.push(b'\n');
        }
        std::fs::write(&path, &body).unwrap();
        let text = tail(&path, 3);
        assert!(!text.contains("xxxxx"), "oversized line must not be retained");
        assert!(text.contains(r#""op":"n5""#) || text.contains(r#""op":"n6""#));
        assert!(text.contains(r#""op":"n7""#));
        assert!(!text.contains(r#""op":"n0""#), "ring must keep only last N");
    }

    #[test]
    fn submit_writes_a_hash_chain_and_the_legacy_line() {
        let dir = tempfile::tempdir().unwrap();
        let hub = AuditHub::open(dir.path(), "node-key", "phone");
        hub.submit(event_for(
            "exec",
            "exec",
            "client-key",
            "echo hi",
            true,
            None,
        ));
        let legacy = std::fs::read_to_string(hub.legacy_path()).unwrap();
        assert!(legacy.contains("\"op\":\"exec\""), "{legacy}");
        assert!(legacy.contains("\"peer\":\"client-key\""), "{legacy}");
        let day = chrono::Utc::now().format("%Y-%m-%d");
        let chain =
            std::fs::read_to_string(dir.path().join("audit/logs").join(format!("{day}.jsonl")))
                .unwrap();
        let first_line = chain.lines().next().unwrap();
        let record: serde_json::Value = serde_json::from_str(first_line).unwrap();
        assert_eq!(record["seq"], 1);
        assert_eq!(record["op"], "exec");
        assert!(record["hash"].as_str().unwrap().len() > 8, "{record}");
        let parsed: AuditRecord = serde_json::from_str(first_line).unwrap();
        agentlink_core::audit::verify_chain(&[parsed]).unwrap();
        let state = std::fs::read_to_string(dir.path().join("audit/chain.state")).unwrap();
        assert!(state.starts_with("1 "), "{state}");
    }
}
