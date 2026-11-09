//! Directory watches.
//!
//! The node keeps a `notify` watcher and a bounded event buffer. The CLI
//! polls in a loop so events appear as a stream. MCP calls the same poll.

use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use agentlink_core::util;
use agentlink_core::{Error, Result};
use notify::{EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use serde_json::{json, Value};
use tokio::sync::Notify;

const MAX_WATCHES: usize = 32;
const MAX_EVENTS: usize = 1000;
const MAX_TIMEOUT_MS: u64 = 30_000;
const MAX_LIMIT: u32 = 200;
const STALE_AFTER: Duration = Duration::from_secs(30 * 60);

struct Stored {
    seq: u64,
    kind: String,
    paths: Vec<String>,
    unix_ms: i64,
}

struct EventBuf {
    events: Vec<Stored>,
    next_seq: u64,
}

impl Default for EventBuf {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            next_seq: 1,
        }
    }
}

impl EventBuf {
    fn push(&mut self, kind: String, paths: Vec<String>) {
        let seq = self.next_seq;
        self.next_seq += 1;
        self.events.push(Stored {
            seq,
            kind,
            paths,
            unix_ms: now_ms(),
        });
        if self.events.len() > MAX_EVENTS {
            let extra = self.events.len() - MAX_EVENTS;
            self.events.drain(..extra);
        }
    }

    fn oldest_seq(&self) -> u64 {
        self.events
            .first()
            .map(|event| event.seq)
            .unwrap_or(self.next_seq)
    }
}

struct Watch {
    events: Arc<Mutex<EventBuf>>,
    notify: Arc<Notify>,
    last_used: Instant,
    _watcher: RecommendedWatcher,
}

#[derive(Clone, Default)]
pub struct WatchManager {
    inner: Arc<Mutex<Vec<(String, Watch)>>>,
}

impl WatchManager {
    pub fn start(&self, path: &Path, recursive: bool) -> Result<Value> {
        self.reap();
        {
            let guard = self.lock()?;
            if guard.len() >= MAX_WATCHES {
                return Err(Error::Message(format!(
                    "this node already has {MAX_WATCHES} watches"
                )));
            }
        }
        let id = util::random_hex(4);
        // macOS reports FSEvents under the canonical path. A tempfile lives in
        // `/var/folders`, which is a symlink to `/private/var/folders`, so a
        // prefix check against the path the caller passed drops every event.
        let root = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let events = Arc::new(Mutex::new(EventBuf::default()));
        let notify = Arc::new(Notify::new());
        let events_cb = events.clone();
        let notify_cb = notify.clone();
        let root_cb = root.clone();
        let mut watcher = notify::recommended_watcher(
            move |result: std::result::Result<notify::Event, notify::Error>| {
                let Ok(event) = result else { return };
                let kind = kind_name(&event.kind);
                if kind == "access" {
                    return;
                }
                let paths: Vec<String> = event
                    .paths
                    .iter()
                    .filter(|candidate| allowed(&root_cb, candidate, recursive))
                    .map(|candidate| candidate.to_string_lossy().to_string())
                    .collect();
                if paths.is_empty() {
                    return;
                }
                if let Ok(mut buf) = events_cb.lock() {
                    buf.push(kind.to_string(), paths);
                }
                notify_cb.notify_one();
            },
        )
        .map_err(|err| Error::Message(format!("watch: {err}")))?;
        let mut skipped: Vec<String> = Vec::new();
        if recursive {
            match watcher.watch(&root, RecursiveMode::Recursive) {
                Ok(()) => {}
                Err(err) if is_permission_denied(&err) => {
                    // Common on /tmp and similar: one unreadable child makes a
                    // single recursive inotify walk fail. Watch what we can.
                    skipped = watch_tree_skipping_denied(&mut watcher, &root)?;
                }
                Err(err) => {
                    return Err(Error::Message(format!(
                        "watch {}: {err}",
                        root.display()
                    )));
                }
            }
        } else {
            watcher
                .watch(&root, RecursiveMode::NonRecursive)
                .map_err(|err| Error::Message(format!("watch {}: {err}", root.display())))?;
        }
        self.lock()?.push((
            id.clone(),
            Watch {
                events,
                notify,
                last_used: Instant::now(),
                _watcher: watcher,
            },
        ));
        Ok(json!({
            "watch_id": id,
            "path": root.display().to_string(),
            "recursive": recursive,
            "skipped": skipped,
        }))
    }

    pub async fn poll(&self, id: &str, cursor: u64, timeout_ms: u64, limit: u32) -> Result<Value> {
        let timeout_ms = timeout_ms.min(MAX_TIMEOUT_MS);
        let limit = if limit == 0 { 50 } else { limit.min(MAX_LIMIT) };
        let notify = self.notify_of(id)?;
        let deadline = Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            if let Some(batch) = self.drain(id, cursor, limit, false)? {
                return Ok(batch);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return self
                    .drain(id, cursor, limit, true)?
                    .ok_or_else(|| Error::NotFound(format!("watch {id}")));
            }
            tokio::select! {
                _ = tokio::time::sleep(left) => {
                    return self.drain(id, cursor, limit, true)?.ok_or_else(|| {
                        Error::NotFound(format!("watch {id}"))
                    });
                }
                _ = notify.notified() => continue,
            }
        }
    }

    pub fn stop(&self, id: &str) -> Result<Value> {
        let mut guard = self.lock()?;
        let before = guard.len();
        guard.retain(|(watch_id, _)| watch_id != id);
        if guard.len() == before {
            return Err(Error::NotFound(format!("watch {id}")));
        }
        Ok(json!({"watch_id": id, "stopped": true}))
    }

    fn drain(&self, id: &str, cursor: u64, limit: u32, allow_empty: bool) -> Result<Option<Value>> {
        let mut guard = self.lock()?;
        let Some(watch) = guard.iter_mut().find(|(watch_id, _)| watch_id == id) else {
            return Err(Error::NotFound(format!("watch {id}")));
        };
        watch.1.last_used = Instant::now();
        let buf = watch
            .1
            .events
            .lock()
            .map_err(|_| Error::Message("watch buffer poisoned".into()))?;
        let oldest = buf.oldest_seq();
        let gap = cursor + 1 < oldest && oldest > 1;
        let events: Vec<_> = buf
            .events
            .iter()
            .filter(|event| event.seq > cursor)
            .take(limit as usize)
            .map(|event| {
                json!({
                    "seq": event.seq,
                    "kind": event.kind,
                    "paths": event.paths,
                    "unix_ms": event.unix_ms,
                })
            })
            .collect();
        if events.is_empty() && !allow_empty {
            return Ok(None);
        }
        let next = events
            .last()
            .and_then(|event| event["seq"].as_u64())
            .unwrap_or(cursor);
        Ok(Some(json!({
            "watch_id": id,
            "events": events,
            "cursor": next,
            "gap": gap,
        })))
    }

    fn notify_of(&self, id: &str) -> Result<Arc<Notify>> {
        let guard = self.lock()?;
        guard
            .iter()
            .find(|(watch_id, _)| watch_id == id)
            .map(|(_, watch)| watch.notify.clone())
            .ok_or_else(|| Error::NotFound(format!("watch {id}")))
    }

    fn reap(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.retain(|(_, watch)| watch.last_used.elapsed() < STALE_AFTER);
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, Vec<(String, Watch)>>> {
        self.inner
            .lock()
            .map_err(|_| Error::Message("watch map poisoned".into()))
    }
}

fn kind_name(kind: &EventKind) -> &'static str {
    match kind {
        EventKind::Create(_) => "create",
        EventKind::Modify(_) => "modify",
        EventKind::Remove(_) => "remove",
        EventKind::Access(_) => "access",
        EventKind::Any => "any",
        EventKind::Other => "other",
    }
}


fn is_permission_denied(err: &notify::Error) -> bool {
    match &err.kind {
        notify::ErrorKind::Io(io) => io.kind() == std::io::ErrorKind::PermissionDenied,
        _ => {
            let text = err.to_string().to_ascii_lowercase();
            text.contains("permission denied") || text.contains("(os error 13)")
        }
    }
}

/// Best-effort recursive watch when a full-tree register hits EACCES.
///
/// Watches `root` non-recursively, then each accessible immediate child
/// directory recursively (so notify still auto-tracks nested creates under
/// those children). Unreadable children are listed in the returned `skipped`.
fn watch_tree_skipping_denied(
    watcher: &mut RecommendedWatcher,
    root: &Path,
) -> Result<Vec<String>> {
    let mut skipped = Vec::new();
    watcher
        .watch(root, RecursiveMode::NonRecursive)
        .map_err(|err| Error::Message(format!("watch {}: {err}", root.display())))?;
    let entries = std::fs::read_dir(root)
        .map_err(|err| Error::Message(format!("watch {}: {err}", root.display())))?;
    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };
        let path = entry.path();
        let file_type = match entry.file_type() {
            Ok(kind) => kind,
            Err(_) => continue,
        };
        if !file_type.is_dir() {
            continue;
        }
        match watcher.watch(&path, RecursiveMode::Recursive) {
            Ok(()) => {}
            Err(err) if is_permission_denied(&err) => {
                skipped.push(path.display().to_string());
            }
            Err(err) if matches!(err.kind, notify::ErrorKind::MaxFilesWatch) => {
                return Err(Error::Message(format!(
                    "watch {}: inotify watch limit reached",
                    path.display()
                )));
            }
            Err(err) => {
                // One bad child should not abort the whole tree.
                skipped.push(format!("{} ({err})", path.display()));
            }
        }
    }
    Ok(skipped)
}

fn lexical_clean(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn allowed(root: &Path, path: &Path, recursive: bool) -> bool {
    let root_c = std::fs::canonicalize(root).unwrap_or_else(|_| lexical_clean(root));
    let candidate = std::fs::canonicalize(path).unwrap_or_else(|_| lexical_clean(path));
    // A raw `starts_with` treats `root/../outside` as inside `root`. That shows
    // up for deleted paths, which can no longer be canonicalized. Reject any
    // path that still contains `..` before trusting the raw prefix.
    let escaped = path
        .components()
        .any(|component| matches!(component, Component::ParentDir));
    let inside = candidate == root_c
        || candidate.starts_with(&root_c)
        || (!escaped && (path.starts_with(root) || path.starts_with(&root_c)));
    if !inside {
        return false;
    }
    if recursive {
        return true;
    }
    path == root
        || candidate == root_c
        || path.parent() == Some(root)
        || candidate.parent() == Some(root_c.as_path())
}

fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn watch_sees_a_created_file() {
        let dir = tempfile::tempdir().unwrap();
        let watches = WatchManager::default();
        let started = watches.start(dir.path(), true).unwrap();
        let id = started["watch_id"].as_str().unwrap().to_string();
        // FSEvents registers the stream after `watch` returns. A create in
        // that window is dropped, so wait until the stream is live.
        tokio::time::sleep(Duration::from_millis(400)).await;
        let file = dir.path().join("created.txt");
        std::fs::write(&file, "hi").unwrap();
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut saw = false;
        let mut cursor = 0u64;
        while Instant::now() < deadline {
            let batch = watches.poll(&id, cursor, 500, 20).await.unwrap();
            cursor = batch["cursor"].as_u64().unwrap_or(cursor);
            let events = batch["events"].as_array().unwrap();
            if events.iter().any(|event| {
                event["paths"].as_array().is_some_and(|paths| {
                    paths
                        .iter()
                        .any(|path| path.as_str().unwrap_or("").contains("created.txt"))
                })
            }) {
                saw = true;
                break;
            }
        }
        assert!(saw, "no create/modify event for created.txt");
        watches.stop(&id).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn recursive_watch_skips_permission_denied_children() {
        let dir = tempfile::tempdir().unwrap();
        let open = dir.path().join("open");
        let denied = dir.path().join("denied");
        std::fs::create_dir(&open).unwrap();
        std::fs::create_dir(&denied).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o000)).unwrap();
        let watches = WatchManager::default();
        let started = match watches.start(dir.path(), true) {
            Ok(value) => value,
            Err(err) => {
                let _ = std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o755));
                panic!("watch should start despite denied child: {err}");
            }
        };
        let _ = std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o755));
        let skipped = started["skipped"].as_array().cloned().unwrap_or_default();
        // Either notify walked past it (skipped empty) or our fallback listed it.
        // The important contract: start succeeded.
        assert!(started["watch_id"].as_str().is_some());
        if !skipped.is_empty() {
            assert!(
                skipped.iter().any(|value| {
                    value
                        .as_str()
                        .unwrap_or("")
                        .contains("denied")
                }),
                "skipped={skipped:?}"
            );
        }
        watches.stop(started["watch_id"].as_str().unwrap()).unwrap();
    }

    #[test]
    fn parent_escape_is_not_an_allowed_watch_path() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let gone = root.join("..").join("gone");
        assert!(
            !allowed(&root, &gone, true),
            "deleted parent escape was treated as inside the watch"
        );
        assert!(allowed(&root, &root.join("inside.txt"), true));
    }
}
