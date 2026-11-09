//! Audit pipeline: policy, hash chain, fan-out sinks, retention, recording.
//!
//! `submit` is the API search, edit, watch, and background handlers should
//! call. A full disk or a dead remote sink does not fail the operation.

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use agentlink_core::audit::{
    self, alert_matches, assign_chain, select, AuditDraft, AuditEvent, AuditFilter, AuditPolicy,
    AuditRecord, SinkSpec,
};
use agentlink_core::protocol::Envelope;
use agentlink_core::recording::{self, CapturedFrame, RecordMode};
use agentlink_core::s3::{self, S3Client};
use agentlink_core::ws::Outbound;
use agentlink_core::Result;
use agentlink_desktop::{CaptureRequest, CaptureTarget, ScreenCapture};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use tokio::sync::mpsc;

static SERVICE: OnceLock<Arc<AuditService>> = OnceLock::new();

pub struct AuditExtra {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub transcript: Vec<u8>,
    pub before: Option<Vec<u8>>,
    pub after: Option<Vec<u8>>,
    pub exit_code: Option<i32>,
    pub command: Option<String>,
    pub cwd: Option<String>,
    pub env: Vec<(String, String)>,
    pub paths: Vec<String>,
}

impl Default for AuditExtra {
    fn default() -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            transcript: Vec::new(),
            before: None,
            after: None,
            exit_code: None,
            command: None,
            cwd: None,
            env: Vec::new(),
            paths: Vec::new(),
        }
    }
}

impl AuditExtra {
    pub fn push_stream(&mut self, stream: &str, data: &[u8]) {
        let cap: usize = 64 * 1024;
        let buf = match stream {
            "stderr" => &mut self.stderr,
            "pty" => &mut self.transcript,
            _ => &mut self.stdout,
        };
        let room = cap.saturating_sub(buf.len());
        if room == 0 {
            return;
        }
        buf.extend_from_slice(&data[..room.min(data.len())]);
    }
}

struct ChainState {
    seq: u64,
    prev: String,
}

pub struct AuditService {
    node_id: String,
    node_name: String,
    root: PathBuf,
    policy: RwLock<AuditPolicy>,
    chain: Mutex<ChainState>,
    tx: Mutex<Option<mpsc::Sender<Outbound>>>,
    batch: Mutex<Vec<AuditRecord>>,
    activity: AtomicI64,
    gui_until: AtomicI64,
}

impl AuditService {
    pub fn install(service: Arc<Self>) {
        let _ = SERVICE.set(service);
    }

    pub fn get() -> Option<Arc<Self>> {
        SERVICE.get().cloned()
    }

    pub fn open(data_dir: &Path, node_id: &str, node_name: &str) -> Arc<Self> {
        let root = data_dir.join("audit");
        let _ = fs::create_dir_all(root.join("logs"));
        let _ = fs::create_dir_all(root.join("blobs"));
        let _ = fs::create_dir_all(root.join("recordings"));
        let _ = fs::create_dir_all(root.join("spool"));
        let policy = load_policy(data_dir);
        let chain = load_chain(&root);
        let service = Arc::new(Self {
            node_id: node_id.to_string(),
            node_name: node_name.to_string(),
            root,
            policy: RwLock::new(policy),
            chain: Mutex::new(chain),
            tx: Mutex::new(None),
            batch: Mutex::new(Vec::new()),
            activity: AtomicI64::new(0),
            gui_until: AtomicI64::new(0),
        });
        Self::install(service.clone());
        let background = service.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                background.flush();
            }
        });
        service
    }

    pub fn set_tx(&self, tx: Option<mpsc::Sender<Outbound>>) {
        if let Ok(mut guard) = self.tx.lock() {
            *guard = tx;
        }
    }

    pub fn touch(&self) {
        self.activity.store(now_secs(), Ordering::Relaxed);
    }

    pub fn touch_gui(&self) {
        let idle = self
            .policy
            .read()
            .map(|policy| policy.recording.idle_secs)
            .unwrap_or(30);
        self.gui_until
            .store(now_secs() + idle as i64, Ordering::Relaxed);
        self.touch();
    }

    pub fn policy(&self) -> AuditPolicy {
        self.policy
            .read()
            .map(|policy| policy.clone())
            .unwrap_or_else(|_| AuditPolicy::preset("standard").expect("standard preset"))
    }

    pub fn replace_policy(&self, policy: AuditPolicy, audit_change: bool) {
        if let Ok(mut guard) = self.policy.write() {
            *guard = policy;
        }
        if audit_change {
            self.submit(AuditEvent {
                category: "permission".into(),
                action: "audit_config".into(),
                client_id: "local".into(),
                ok: true,
                args: serde_json::json!({"changed": true}),
                ..AuditEvent::default()
            });
        }
    }

    pub fn submit(&self, event: AuditEvent) {
        let policy = self.policy();
        let Some(mut draft) = audit::prepare(&policy, &self.node_id, &self.node_name, &event)
        else {
            return;
        };
        let (seq, prev, chain_on) = {
            let Ok(mut chain) = self.chain.lock() else {
                return;
            };
            chain.seq += 1;
            let seq = chain.seq;
            let prev = chain.prev.clone();
            (seq, prev, policy.forward.chain)
        };
        if let Some(diff) = &draft.diff {
            let name = format!("diff-{:016}.txt", seq);
            let _ = fs::write(self.root.join("blobs").join(&name), diff);
            draft.record.diff_ref = Some(format!("blobs/{name}"));
        }
        if let Some(output) = &draft.output {
            let name = format!("output-{:016}.txt", seq);
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
        self.write_local(&draft);
        self.append_legacy(&event);
        if let Ok(mut batch) = self.batch.lock() {
            batch.push(draft.record.clone());
        }
        for rule in &policy.alerts {
            if alert_matches(rule, &draft.record) {
                if let Ok(payload) = serde_json::to_value(&draft.record) {
                    audit::fire_webhook(&rule.webhook, &payload);
                }
            }
        }
    }

    fn append_legacy(&self, event: &AuditEvent) {
        let Some(parent) = self.root.parent() else {
            return;
        };
        let detail = event
            .args
            .get("detail")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let Ok(line) = serde_json::to_string(&serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "op": event.action,
            "detail": detail,
            "ok": event.ok,
            "client_id": event.client_id,
            "node": self.node_name,
        })) else {
            return;
        };
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(parent.join("audit.log"))
        {
            let _ = writeln!(file, "{line}");
        }
    }

    fn write_local(&self, draft: &AuditDraft) {
        let policy = self.policy();
        let sinks: Vec<SinkSpec> = policy
            .sinks
            .iter()
            .filter(|sink| sink.kind == "local" && sink.accepts("logs"))
            .cloned()
            .collect();
        if sinks.is_empty() {
            return;
        }
        let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = self.root.join("logs").join(format!("{day}.jsonl"));
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let Ok(line) = serde_json::to_string(&draft.record) else {
            return;
        };
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
            let _ = writeln!(file, "{line}");
        }
    }

    pub fn flush(&self) {
        let records = match self.batch.lock() {
            Ok(mut batch) => std::mem::take(&mut *batch),
            Err(_) => return,
        };
        self.retry_spool();
        if records.is_empty() {
            self.prune();
            return;
        }
        let policy = self.policy();
        for sink in &policy.sinks {
            if sink.kind == "local" || !sink.accepts("logs") {
                continue;
            }
            let body = match gzip_jsonl(&records) {
                Some(body) => body,
                None => continue,
            };
            if sink.kind == "relay" {
                if self.send_relay(&records) {
                    continue;
                }
            }
            if sink.kind == "s3" {
                if let Some(config) = sink.s3.clone() {
                    let key = s3::object_key(
                        &self.node_id,
                        &chrono::Utc::now().format("%Y-%m-%d").to_string(),
                        "logs",
                        &format!(
                            "{}/{:016}.jsonl.gz",
                            records
                                .first()
                                .and_then(|record| record.session_id.clone())
                                .unwrap_or_else(|| "session".into()),
                            records.first().map(|record| record.seq).unwrap_or(0)
                        ),
                    );
                    if let Ok(client) = S3Client::new(config) {
                        if client.put(&key, &body, "application/gzip").is_ok() {
                            continue;
                        }
                    }
                }
            }
            self.spool(&sink.name, &body);
        }
        self.prune();
    }

    fn send_relay(&self, records: &[AuditRecord]) -> bool {
        let Ok(values) = records
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()
        else {
            return false;
        };
        let env = Envelope::AuditBatch {
            node_id: self.node_id.clone(),
            records: values,
        };
        let Ok(text) = serde_json::to_string(&env) else {
            return false;
        };
        let tx = self.tx.lock().ok().and_then(|guard| guard.clone());
        let Some(tx) = tx else {
            return false;
        };
        tx.try_send(Outbound::Text(text)).is_ok()
    }

    fn spool(&self, sink: &str, body: &[u8]) {
        let dir = self.root.join("spool").join(sink);
        let _ = fs::create_dir_all(&dir);
        let name = format!("{}-0.jsonl.gz", now_secs());
        let _ = fs::write(dir.join(name), body);
    }

    fn retry_spool(&self) {
        let spool = self.root.join("spool");
        let Ok(sinks) = fs::read_dir(&spool) else {
            return;
        };
        let policy = self.policy();
        for entry in sinks.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(spec) = policy.sinks.iter().find(|sink| sink.name == name) else {
                continue;
            };
            let Ok(files) = fs::read_dir(entry.path()) else {
                continue;
            };
            for file in files.flatten() {
                let path = file.path();
                let Ok(modified) = file.metadata().and_then(|meta| meta.modified()) else {
                    continue;
                };
                let age = modified.elapsed().unwrap_or_default().as_secs();
                if age < 2 {
                    continue;
                }
                let Ok(body) = fs::read(&path) else {
                    continue;
                };
                let ok = if spec.kind == "s3" {
                    spec.s3
                        .clone()
                        .and_then(|config| S3Client::new(config).ok())
                        .and_then(|client| {
                            let key = s3::object_key(
                                &self.node_id,
                                &chrono::Utc::now().format("%Y-%m-%d").to_string(),
                                "logs",
                                &format!("retry/{}.jsonl.gz", now_secs()),
                            );
                            client.put(&key, &body, "application/gzip").ok()
                        })
                        .is_some()
                } else if spec.kind == "relay" {
                    gunzip(&body)
                        .and_then(|plain| {
                            let records: Vec<AuditRecord> = String::from_utf8(plain)
                                .ok()?
                                .lines()
                                .filter_map(|line| serde_json::from_str(line).ok())
                                .collect();
                            Some(self.send_relay(&records))
                        })
                        .unwrap_or(false)
                } else {
                    false
                };
                if ok {
                    let _ = fs::remove_file(path);
                }
            }
        }
    }

    fn prune(&self) {
        let policy = self.policy();
        prune_dir(
            &self.root.join("logs"),
            policy.retention.log_days,
            policy.retention.max_log_bytes,
        );
        prune_dir(
            &self.root.join("blobs"),
            policy.retention.diff_days,
            policy.retention.max_diff_bytes,
        );
        prune_dir(
            &self.root.join("recordings"),
            policy.retention.recording_days,
            policy.retention.max_recording_bytes,
        );
        for sink in &policy.sinks {
            if sink.kind != "s3" {
                continue;
            }
            let Some(days) = sink.retention_days.or(Some(policy.retention.log_days)) else {
                continue;
            };
            let Some(config) = sink.s3.clone() else {
                continue;
            };
            let Ok(client) = S3Client::new(config.clone()) else {
                continue;
            };
            let Ok(keys) = client.list(&format!("{}/", self.node_id)) else {
                continue;
            };
            let cutoff = chrono::Utc::now() - chrono::Duration::days(days as i64);
            for key in keys {
                if let Some(day) = key_day(&key) {
                    if day < cutoff.format("%Y-%m-%d").to_string() {
                        let _ = client.delete(&relative_key(&config, &key));
                    }
                }
            }
        }
    }

    pub fn recording_active(&self) -> bool {
        let policy = self.policy();
        match RecordMode::parse(&policy.recording.mode) {
            Some(RecordMode::Off) | None => false,
            Some(RecordMode::Always) => {
                let idle = policy.recording.idle_secs as i64;
                now_secs() - self.activity.load(Ordering::Relaxed) < idle.max(1)
            }
            Some(RecordMode::Gui) => now_secs() < self.gui_until.load(Ordering::Relaxed),
        }
    }

    pub fn store_segment(&self, session_id: &str, frames: &[CapturedFrame]) {
        if frames.is_empty() {
            return;
        }
        let quality = self
            .policy
            .read()
            .map(|policy| policy.recording.quality.clone())
            .unwrap_or_else(|_| "low".into());
        let segment = recording::encode_segment(session_id, frames, &quality);
        let day = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let path = self
            .root
            .join("recordings")
            .join(day)
            .join(format!("{session_id}-{}.bin", now_secs()));
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, &segment.bytes);
        let policy = self.policy();
        for sink in &policy.sinks {
            if sink.kind == "s3" && sink.accepts("recordings") {
                if let Some(config) = sink.s3.clone() {
                    if let Ok(client) = S3Client::new(config) {
                        let key = s3::object_key(
                            &self.node_id,
                            &chrono::Utc::now().format("%Y-%m-%d").to_string(),
                            "recordings",
                            &format!("{session_id}/{}.bin", now_secs()),
                        );
                        let _ = client.put(&key, &segment.bytes, "application/octet-stream");
                    }
                }
            }
        }
    }
}

pub fn submit(event: AuditEvent) {
    if let Some(service) = AuditService::get() {
        service.submit(event);
    }
}

/// Record a local audit-config change into this data directory's hash chain.
///
/// Used by `agentlink audit config` and `agentlink audit sink` when they edit
/// `audit.toml` on disk. A running node picks up the same file on its next
/// start, or immediately when the change is pushed with `--push`.
pub fn record_local_change(data_dir: &Path, detail: &str) {
    let service = AuditService::open(data_dir, "local", "local");
    service.submit(AuditEvent {
        category: "permission".into(),
        action: "audit_config".into(),
        client_id: "local".into(),
        ok: true,
        args: serde_json::json!({"detail": detail}),
        ..AuditEvent::default()
    });
}

pub fn query_local(data_dir: &Path, filter: &AuditFilter) -> Vec<AuditRecord> {
    let logs = data_dir.join("audit").join("logs");
    let mut records = Vec::new();
    if let Ok(entries) = fs::read_dir(logs) {
        let mut paths: Vec<_> = entries
            .filter_map(|entry| entry.ok())
            .map(|e| e.path())
            .collect();
        paths.sort();
        for path in paths {
            let Ok(text) = fs::read_to_string(path) else {
                continue;
            };
            for line in text.lines() {
                if let Ok(record) = serde_json::from_str::<AuditRecord>(line) {
                    records.push(record);
                }
            }
        }
    }
    select(&records, filter)
}

pub fn query_s3(
    config: agentlink_core::s3::S3Config,
    filter: &AuditFilter,
) -> Result<Vec<AuditRecord>> {
    let client = S3Client::new(config.clone())?;
    let prefix = filter.node.clone().unwrap_or_default();
    let keys = client.list(&prefix)?;
    let mut records = Vec::new();
    for key in keys {
        if !key.contains("/logs/") {
            continue;
        }
        let bytes = client.get(&relative_key(&config, &key))?;
        let plain = gunzip(&bytes).unwrap_or(bytes);
        let Ok(text) = String::from_utf8(plain) else {
            continue;
        };
        for line in text.lines() {
            if let Ok(record) = serde_json::from_str::<AuditRecord>(line) {
                records.push(record);
            }
        }
    }
    Ok(select(&records, filter))
}

pub fn load_policy(data_dir: &Path) -> AuditPolicy {
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
        let seq = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let prev = parts.next().unwrap_or("").to_string();
        return ChainState { seq, prev };
    }
    ChainState {
        seq: 0,
        prev: String::new(),
    }
}

fn save_chain(root: &Path, chain: &ChainState) {
    let _ = fs::write(
        root.join("chain.state"),
        format!("{} {}\n", chain.seq, chain.prev),
    );
}

fn gzip_jsonl(records: &[AuditRecord]) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    for record in records {
        let line = serde_json::to_string(record).ok()?;
        raw.extend_from_slice(line.as_bytes());
        raw.push(b'\n');
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&raw).ok()?;
    encoder.finish().ok()
}

fn gunzip(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut decoder = GzDecoder::new(bytes);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out).ok()?;
    Some(out)
}

fn prune_dir(dir: &Path, days: u64, max_bytes: u64) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let cutoff = SystemTime::now()
        .checked_sub(Duration::from_secs(days.saturating_mul(86400)))
        .unwrap_or(SystemTime::UNIX_EPOCH);
    let mut files = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            prune_dir(&path, days, max_bytes);
            continue;
        }
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.modified().ok().filter(|time| *time < cutoff).is_some() {
            let _ = fs::remove_file(&path);
            continue;
        }
        files.push((path, meta.len(), meta.modified().ok()));
    }
    let mut total: u64 = files.iter().map(|(_, len, _)| *len).sum();
    if max_bytes > 0 && total > max_bytes {
        files.sort_by_key(|(_, _, modified)| *modified);
        for (path, len, _) in files {
            if total <= max_bytes {
                break;
            }
            if fs::remove_file(path).is_ok() {
                total = total.saturating_sub(len);
            }
        }
    }
}

fn relative_key(config: &agentlink_core::s3::S3Config, key: &str) -> String {
    let prefix = config.prefix.trim_matches('/');
    if prefix.is_empty() {
        return key.to_string();
    }
    key.strip_prefix(&format!("{prefix}/"))
        .unwrap_or(key)
        .to_string()
}

fn key_day(key: &str) -> Option<String> {
    let parts: Vec<_> = key.split('/').collect();
    for window in parts.windows(3) {
        if window[0].len() == 4 && window[1].len() == 2 && window[2].len() == 2 {
            return Some(format!("{}-{}-{}", window[0], window[1], window[2]));
        }
    }
    None
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Open `CaptureBackend::open_session` while the recording policy says to,
/// and pull [`agentlink_desktop::FrameSource::next_frame`].
pub fn spawn_recorder(service: Arc<AuditService>, backend: Option<Arc<dyn ScreenCapture>>) {
    let Some(backend) = backend else {
        return;
    };
    std::thread::spawn(move || {
        let mut session: Option<Box<dyn agentlink_desktop::FrameSource>> = None;
        let mut frames = Vec::new();
        let mut session_id = String::new();
        loop {
            let policy = service.policy();
            let fps = policy.recording.fps.clamp(1, 30) as f32;
            if !service.recording_active() {
                if !frames.is_empty() {
                    service.store_segment(&session_id, &frames);
                    frames.clear();
                }
                session = None;
                std::thread::sleep(Duration::from_millis(250));
                continue;
            }
            if session.is_none() {
                session_id = format!("rec-{}", now_secs());
                let request = CaptureRequest {
                    target: CaptureTarget::FullScreen,
                    scale: 1.0,
                    max_fps: fps,
                    max_width: 0,
                };
                match backend.open_session(&request) {
                    Ok(opened) => session = Some(opened),
                    Err(err) => {
                        tracing::debug!(error = %err, "screen session failed");
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                }
            }
            let Some(source) = session.as_mut() else {
                continue;
            };
            match source.next_frame(Duration::from_secs(2)) {
                Ok(Some(frame)) => {
                    frames.push(captured_from_desktop(&frame));
                    if frames.len() >= 20 {
                        service.store_segment(&session_id, &frames);
                        frames.clear();
                    }
                }
                Ok(None) => session = None,
                Err(err) => {
                    tracing::debug!(error = %err, "frame grab failed");
                    session = None;
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }
    });
}

/// Copy one desktop frame into the recorder's RGBA buffer.
pub fn captured_from_desktop(frame: &agentlink_desktop::Frame) -> CapturedFrame {
    let pixels = frame.pixels();
    let row = frame.width as usize * 4;
    let stride = frame.stride as usize;
    let mut rgba = Vec::with_capacity(frame.height as usize * row);
    for y in 0..frame.height as usize {
        let start = y.saturating_mul(stride);
        let end = start.saturating_add(row).min(pixels.len());
        if start >= pixels.len() || end < start + row {
            break;
        }
        for px in pixels[start..end].chunks_exact(4) {
            rgba.extend_from_slice(&[px[2], px[1], px[0], px[3]]);
        }
    }
    CapturedFrame {
        width: frame.width,
        height: frame.height,
        rgba,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentlink_desktop::{CaptureRequest, CaptureTarget};
    use std::time::Duration;

    #[test]
    fn recorder_reads_a_desktop_session() {
        let backend = agentlink_desktop::mock_capture();
        let mut session = backend
            .open_session(&CaptureRequest {
                target: CaptureTarget::FullScreen,
                scale: 1.0,
                max_fps: 8.0,
                max_width: 0,
            })
            .expect("open_session");
        let frame = session
            .next_frame(Duration::from_secs(2))
            .expect("next_frame")
            .expect("frame");
        let captured = captured_from_desktop(&frame);
        assert!(captured.width > 0 && captured.height > 0);
        assert_eq!(
            captured.rgba.len(),
            captured.width as usize * captured.height as usize * 4
        );
    }
}
