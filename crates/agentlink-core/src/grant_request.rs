//! Pending access *requests* stored on the node host.
//!
//! A request is not a grant. Network delivery of a request must not authorize
//! anything. Only a local allow action on the node, using the node issuer key
//! that never leaves this data directory, signs a [`crate::grant::SignedGrant`].

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::grant::{self, SignedGrant};
use crate::identity::Identity;
use crate::permissions::{parse_access, NodePolicy};
use crate::util;

pub const REQUESTS_DIR: &str = "grant-requests";
pub const MAX_PENDING_PER_GRANTEE: usize = 3;
pub const MAX_PENDING_TOTAL: usize = 32;
pub const DEFAULT_REQUEST_TTL_SECS: u64 = 10 * 60;
pub const MIN_REQUEST_TTL_SECS: u64 = 30;
pub const MAX_REQUEST_TTL_SECS: u64 = 24 * 60 * 60;
pub const MAX_GRANT_TTL_SECS: u64 = crate::grant::PERMANENT_GRANT_TTL_SECS;
const USED_NONCES_FILE: &str = "used-nonces.json";
const MAX_NONCE_LEN: usize = 80;
const NONCE_RETAIN_SECS: i64 = 8 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestStatus {
    Pending,
    Approved,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessRequest {
    pub request_id: String,
    pub grantee_id: String,
    pub node_id: String,
    pub policy: NodePolicy,
    pub ttl_secs: u64,
    pub created_unix: i64,
    pub exp_unix: i64,
    pub nonce: String,
    #[serde(default)]
    pub status: RequestStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_unix: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_jti: Option<String>,
}

impl Default for RequestStatus {
    fn default() -> Self {
        Self::Pending
    }
}

impl AccessRequest {
    pub fn is_pending(&self, now_unix: i64) -> bool {
        self.status == RequestStatus::Pending && now_unix <= self.exp_unix
    }
}

pub fn requests_dir(data_dir: &Path) -> PathBuf {
    data_dir.join(REQUESTS_DIR)
}

fn request_path(data_dir: &Path, request_id: &str) -> PathBuf {
    requests_dir(data_dir).join(format!("{}.json", request_id.trim()))
}

fn is_request_id(id: &str) -> bool {
    let id = id.trim();
    !id.is_empty()
        && id.len() <= 80
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn is_key_hex(id: &str) -> bool {
    let id = id.trim();
    id.len() == 64 && id.chars().all(|c| c.is_ascii_hexdigit())
}

/// Build a new pending request. Does not write it.
pub fn draft_request(
    grantee_id: &str,
    node_id: &str,
    policy: NodePolicy,
    ttl_secs: u64,
    now_unix: i64,
    request_ttl_secs: u64,
) -> Result<AccessRequest> {
    let grantee_id = grantee_id.trim().to_ascii_lowercase();
    let node_id = node_id.trim().to_ascii_lowercase();
    if !is_key_hex(&grantee_id) {
        return Err(Error::Message(
            "grantee must be a 32-byte ed25519 public key hex".into(),
        ));
    }
    if !is_key_hex(&node_id) {
        return Err(Error::Message(
            "node id must be a 32-byte ed25519 public key hex".into(),
        ));
    }
    if ttl_secs == 0 || ttl_secs > MAX_GRANT_TTL_SECS {
        return Err(Error::Message(format!(
            "grant ttl must be between 1s and {MAX_GRANT_TTL_SECS}s"
        )));
    }
    let request_ttl = request_ttl_secs.clamp(MIN_REQUEST_TTL_SECS, MAX_REQUEST_TTL_SECS);
    Ok(AccessRequest {
        request_id: uuid::Uuid::new_v4().to_string(),
        grantee_id,
        node_id,
        policy,
        ttl_secs,
        created_unix: now_unix,
        exp_unix: now_unix.saturating_add(request_ttl as i64),
        nonce: uuid::Uuid::new_v4().to_string(),
        status: RequestStatus::Pending,
        decided_unix: None,
        grant_jti: None,
    })
}

fn list_raw(data_dir: &Path) -> Result<Vec<(PathBuf, AccessRequest)>> {
    let dir = requests_dir(data_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if path.file_name().and_then(|n| n.to_str()) == Some(USED_NONCES_FILE) {
            continue;
        }
        let text = match fs::read_to_string(&path) {
            Ok(text) => text,
            Err(_) => continue,
        };
        match serde_json::from_str::<AccessRequest>(&text) {
            Ok(req) => out.push((path, req)),
            Err(err) => {
                return Err(Error::Message(format!(
                    "grant request {}: {err}",
                    path.display()
                )))
            }
        }
    }
    out.sort_by_key(|(_, req)| req.created_unix);
    Ok(out)
}

pub fn list_requests(data_dir: &Path) -> Result<Vec<AccessRequest>> {
    Ok(list_raw(data_dir)?.into_iter().map(|(_, r)| r).collect())
}

pub fn load_request(data_dir: &Path, request_id: &str) -> Result<Option<AccessRequest>> {
    if !is_request_id(request_id) {
        return Err(Error::Message("invalid request id".into()));
    }
    let path = request_path(data_dir, request_id);
    if !path.exists() {
        return Ok(None);
    }
    let text = fs::read_to_string(&path)?;
    let req = serde_json::from_str(&text)
        .map_err(|err| Error::Message(format!("grant request {}: {err}", path.display())))?;
    Ok(Some(req))
}

fn save_request(data_dir: &Path, req: &AccessRequest) -> Result<PathBuf> {
    if !is_request_id(&req.request_id) {
        return Err(Error::Message("invalid request id".into()));
    }
    let dir = requests_dir(data_dir);
    util::ensure_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let path = request_path(data_dir, &req.request_id);
    util::write_secret(&path, serde_json::to_string_pretty(req)?.as_bytes())?;
    Ok(path)
}

fn used_nonces_path(data_dir: &Path) -> PathBuf {
    requests_dir(data_dir).join(USED_NONCES_FILE)
}

fn load_used_nonces_map(data_dir: &Path) -> Result<std::collections::BTreeMap<String, i64>> {
    let path = used_nonces_path(data_dir);
    if !path.is_file() {
        return Ok(std::collections::BTreeMap::new());
    }
    let text = fs::read_to_string(&path)?;
    serde_json::from_str(&text)
        .map_err(|err| Error::Message(format!("used-nonces {}: {err}", path.display())))
}

fn remember_nonce(data_dir: &Path, nonce: &str, now_unix: i64) -> Result<()> {
    let nonce = nonce.trim();
    if nonce.is_empty() || nonce.len() > MAX_NONCE_LEN {
        return Err(Error::Message("invalid request nonce".into()));
    }
    let dir = requests_dir(data_dir);
    util::ensure_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let mut map = load_used_nonces_map(data_dir)?;
    if map.contains_key(nonce) {
        return Err(Error::Message(
            "request nonce was already used (replay)".into(),
        ));
    }
    map.retain(|_, ts| now_unix.saturating_sub(*ts) <= NONCE_RETAIN_SECS);
    map.insert(nonce.to_string(), now_unix);
    let path = used_nonces_path(data_dir);
    util::write_secret(&path, serde_json::to_string_pretty(&map)?.as_bytes())?;
    Ok(())
}

/// Narrow a requested grant. The target may shrink policy or ttl, never enlarge.
pub fn resolve_allow_scope(
    requested: NodePolicy,
    requested_ttl: u64,
    policy: Option<NodePolicy>,
    ttl_secs: Option<u64>,
) -> Result<(NodePolicy, u64)> {
    let policy = match policy {
        Some(p) if p.is_subset_of(requested) => p,
        Some(_) => {
            return Err(Error::Message(
                "the target node may narrow permissions, but cannot widen them (for example, changing read-only to desktop/exec)".into(),
            ))
        }
        None => requested,
    };
    let ttl = match ttl_secs {
        Some(t) if t > 0 && t <= requested_ttl => t,
        Some(_) => {
            return Err(Error::Message(
                "the target node may shorten the grant lifetime, but cannot extend the requested ttl".into(),
            ))
        }
        None => requested_ttl,
    };
    Ok((policy, ttl))
}

/// Store a pending request after rate-limit, expiry, replay, and node-id checks.
pub fn submit_request(
    data_dir: &Path,
    expected_node_id: &str,
    req: AccessRequest,
    now_unix: i64,
) -> Result<AccessRequest> {
    let expected = expected_node_id.trim().to_ascii_lowercase();
    if req.node_id != expected {
        return Err(Error::Message(format!(
            "request node_id {} does not match this node's identity {expected}",
            req.node_id
        )));
    }
    if now_unix > req.exp_unix {
        return Err(Error::Message("request has already expired".into()));
    }
    let existing = list_raw(data_dir)?;
    if existing.iter().any(|(_, r)| r.nonce == req.nonce) {
        return Err(Error::Message(
            "request nonce was already used (replay)".into(),
        ));
    }
    // Durable nonce log survives request-file deletion and process restart.
    remember_nonce(data_dir, &req.nonce, now_unix)?;
    if existing.iter().any(|(_, r)| r.request_id == req.request_id) {
        return Err(Error::Message("request id already exists (replay)".into()));
    }
    let pending: Vec<_> = existing
        .iter()
        .filter(|(_, r)| r.is_pending(now_unix))
        .collect();
    if pending.len() >= MAX_PENDING_TOTAL {
        return Err(Error::Message(
            "too many pending grant requests on this node".into(),
        ));
    }
    let per = pending
        .iter()
        .filter(|(_, r)| r.grantee_id == req.grantee_id)
        .count();
    if per >= MAX_PENDING_PER_GRANTEE {
        return Err(Error::Message(
            "too many pending grant requests from this controller".into(),
        ));
    }
    let mut req = req;
    req.status = RequestStatus::Pending;
    req.decided_unix = None;
    req.grant_jti = None;
    save_request(data_dir, &req)?;
    Ok(req)
}

pub fn deny_request(data_dir: &Path, request_id: &str, now_unix: i64) -> Result<AccessRequest> {
    let mut req = load_request(data_dir, request_id)?
        .ok_or_else(|| Error::Message(format!("no grant request {request_id}")))?;
    if req.status != RequestStatus::Pending {
        return Err(Error::Message(format!(
            "request {request_id} is already {:?}",
            req.status
        )));
    }
    req.status = RequestStatus::Denied;
    req.decided_unix = Some(now_unix);
    save_request(data_dir, &req)?;
    Ok(req)
}

/// Sign a grant locally with the node issuer. Never called from a remote RPC.
pub fn allow_request(
    data_dir: &Path,
    request_id: &str,
    issuer: &Identity,
    expected_node_id: &str,
    now_unix: i64,
    policy: Option<NodePolicy>,
    ttl_secs: Option<u64>,
) -> Result<(AccessRequest, SignedGrant)> {
    let mut req = load_request(data_dir, request_id)?
        .ok_or_else(|| Error::Message(format!("no grant request {request_id}")))?;
    if req.status != RequestStatus::Pending {
        return Err(Error::Message(format!(
            "request {request_id} is already {:?}",
            req.status
        )));
    }
    if now_unix > req.exp_unix {
        return Err(Error::Message("request has expired".into()));
    }
    let expected = expected_node_id.trim().to_ascii_lowercase();
    if req.node_id != expected {
        return Err(Error::Message(format!(
            "request node_id {} does not match this node's identity {expected}",
            req.node_id
        )));
    }
    let (policy, ttl_secs) = resolve_allow_scope(req.policy, req.ttl_secs, policy, ttl_secs)?;
    let exp = grant::exp_unix_for_ttl(now_unix, ttl_secs as i64)?;
    let grant = SignedGrant::sign(
        issuer,
        &req.grantee_id,
        &req.node_id,
        policy,
        now_unix.saturating_sub(30),
        exp,
        uuid::Uuid::new_v4().to_string(),
    )?;
    req.status = RequestStatus::Approved;
    req.decided_unix = Some(now_unix);
    req.grant_jti = Some(grant.jti.clone());
    save_request(data_dir, &req)?;
    Ok((req, grant))
}

/// Prune expired pending requests so the queue cannot grow forever.
pub fn expire_pending(data_dir: &Path, now_unix: i64) -> Result<usize> {
    let mut n = 0;
    for (_, mut req) in list_raw(data_dir)? {
        if req.status == RequestStatus::Pending && now_unix > req.exp_unix {
            req.status = RequestStatus::Denied;
            req.decided_unix = Some(now_unix);
            save_request(data_dir, &req)?;
            n += 1;
        }
    }
    Ok(n)
}

/// Read this node's public id from identity.json.
pub fn node_public_hex(data_dir: &Path) -> Result<String> {
    let path = data_dir.join("identity.json");
    if !path.is_file() {
        return Err(Error::Message(format!(
            "no identity.json in {}",
            data_dir.display()
        )));
    }
    let ident = Identity::load_or_create(&path)?;
    Ok(ident.public_hex().to_string())
}

/// Sign a pending request using the issuer key that already lives in `data_dir`.
pub fn allow_request_in_dir(
    data_dir: &Path,
    request_id: &str,
    now_unix: i64,
    policy: Option<NodePolicy>,
    ttl_secs: Option<u64>,
) -> Result<(AccessRequest, SignedGrant)> {
    let node_id = node_public_hex(data_dir)?;
    let issuer = grant::load_issuer(data_dir)?
        .ok_or_else(|| Error::Message(format!("no grant-issuer.json in {}", data_dir.display())))?;
    allow_request(
        data_dir, request_id, &issuer, &node_id, now_unix, policy, ttl_secs,
    )
}

/// Store a signed grant under `<data_dir>/issued-grants/` (mode 600, dir 700).
pub fn save_issued_grant(data_dir: &Path, grant: &SignedGrant) -> Result<PathBuf> {
    let dir = data_dir.join("issued-grants");
    util::ensure_dir(&dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }
    let jti = grant.jti.trim();
    if jti.is_empty()
        || jti.len() > 80
        || !jti
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(Error::Message("invalid grant jti".into()));
    }
    let path = dir.join(format!("{jti}.json"));
    util::write_secret(&path, serde_json::to_string_pretty(grant)?.as_bytes())?;
    Ok(path)
}

/// Default node data directory when this process is running on the node host.
pub fn default_node_data_dir() -> Option<PathBuf> {
    let dir = crate::config::default_data_dir("node").ok()?;
    dir.join("identity.json").is_file().then_some(dir)
}

pub fn parse_policy(name: &str) -> Result<NodePolicy> {
    parse_access(name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;

    fn ids() -> (Identity, String, String) {
        let issuer = Identity::generate();
        let grantee = Identity::generate().public_hex().to_string();
        let node = Identity::generate().public_hex().to_string();
        (issuer, grantee, node)
    }

    #[test]
    fn submit_allow_signs_locally_and_replay_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (issuer, grantee, node) = ids();
        let now = 1_700_000_000;
        let req = draft_request(&grantee, &node, NodePolicy::desktop(), 3600, now, 600).unwrap();
        let stored = submit_request(dir.path(), &node, req.clone(), now).unwrap();
        assert_eq!(stored.status, RequestStatus::Pending);
        let pending = list_requests(dir.path()).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0]
            .policy
            .capability_summary()
            .contains("exec/shell"));

        let (decided, grant) = allow_request(
            dir.path(),
            &stored.request_id,
            &issuer,
            &node,
            now,
            None,
            None,
        )
        .unwrap();
        assert_eq!(decided.status, RequestStatus::Approved);
        assert_eq!(grant.grantee_id, grantee);
        assert_eq!(grant.node_id, node);
        assert_eq!(grant.policy, NodePolicy::desktop());
        assert_eq!(grant.issuer_id, issuer.public_hex());
        assert!(!grant.sig_hex.is_empty());

        let err = allow_request(
            dir.path(),
            &stored.request_id,
            &issuer,
            &node,
            now,
            None,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("already"), "{err}");

        let replay = submit_request(dir.path(), &node, req, now)
            .unwrap_err()
            .to_string();
        assert!(
            replay.contains("replay") || replay.contains("already"),
            "{replay}"
        );
    }

    #[test]
    fn mismatch_node_id_and_expired_and_rate_limit_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (_issuer, grantee, node) = ids();
        let other = Identity::generate().public_hex().to_string();
        let now = 1_700_000_000;
        let req = draft_request(&grantee, &other, NodePolicy::exec(), 60, now, 600).unwrap();
        let err = submit_request(dir.path(), &node, req, now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("does not match"), "{err}");

        let expired =
            draft_request(&grantee, &node, NodePolicy::exec(), 60, now - 10_000, 30).unwrap();
        let err = submit_request(dir.path(), &node, expired, now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expired"), "{err}");

        for _ in 0..MAX_PENDING_PER_GRANTEE {
            let req =
                draft_request(&grantee, &node, NodePolicy::read_only(), 60, now, 600).unwrap();
            submit_request(dir.path(), &node, req, now).unwrap();
        }
        let extra = draft_request(&grantee, &node, NodePolicy::read_only(), 60, now, 600).unwrap();
        let err = submit_request(dir.path(), &node, extra, now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("too many"), "{err}");
    }

    #[test]
    fn deny_and_expire_pending() {
        let dir = tempfile::tempdir().unwrap();
        let (_issuer, grantee, node) = ids();
        let now = 1_700_000_000;
        let req = draft_request(&grantee, &node, NodePolicy::exec(), 60, now, 600).unwrap();
        let stored = submit_request(dir.path(), &node, req, now).unwrap();
        let denied = deny_request(dir.path(), &stored.request_id, now).unwrap();
        assert_eq!(denied.status, RequestStatus::Denied);

        let req = draft_request(&grantee, &node, NodePolicy::exec(), 60, now, 60).unwrap();
        let stored = submit_request(dir.path(), &node, req, now).unwrap();
        assert_eq!(expire_pending(dir.path(), now + 120).unwrap(), 1);
        let loaded = load_request(dir.path(), &stored.request_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded.status, RequestStatus::Denied);
    }

    #[test]
    fn parse_policy_names() {
        assert_eq!(parse_policy("desktop").unwrap(), NodePolicy::desktop());
        assert!(parse_policy("not-a-policy").is_err());
    }

    #[test]
    fn narrow_allow_cannot_enlarge_and_can_shrink() {
        let req = NodePolicy::desktop();
        let (p, t) = resolve_allow_scope(req, 3600, Some(NodePolicy::exec()), Some(600)).unwrap();
        assert_eq!(p, NodePolicy::exec());
        assert_eq!(t, 600);
        let err = resolve_allow_scope(NodePolicy::exec(), 600, Some(NodePolicy::desktop()), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot widen"), "{err}");
        let err = resolve_allow_scope(req, 600, None, Some(3600))
            .unwrap_err()
            .to_string();
        assert!(err.contains("cannot extend"), "{err}");
    }

    #[test]
    fn sec20_load_request_rejects_path_traversal_ids() {
        let dir = tempfile::tempdir().unwrap();
        for bad in ["../node", "..\\node", "a/b", "a\\b", "", "req.json"] {
            let err = load_request(dir.path(), bad).unwrap_err().to_string();
            assert!(err.contains("invalid request id"), "bad={bad}: {err}");
        }
    }

    #[test]
    fn nonce_log_survives_deleting_the_request_file() {
        let dir = tempfile::tempdir().unwrap();
        let (_issuer, grantee, node) = ids();
        let now = 1_700_000_000;
        let req = draft_request(&grantee, &node, NodePolicy::exec(), 60, now, 600).unwrap();
        let stored = submit_request(dir.path(), &node, req.clone(), now).unwrap();
        let path = requests_dir(dir.path()).join(format!("{}.json", stored.request_id));
        std::fs::remove_file(&path).unwrap();
        let err = submit_request(dir.path(), &node, req, now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("replay"), "{err}");
    }

    #[test]
    fn permanent_request_allows_permanent_or_shrinks_and_never_enlarges_finite() {
        let dir = tempfile::tempdir().unwrap();
        let (issuer, grantee, node) = ids();
        let now = 1_700_000_000;

        assert!(draft_request(&grantee, &node, NodePolicy::exec(), 0, now, 600).is_err());

        let req = draft_request(
            &grantee,
            &node,
            NodePolicy::full(),
            grant::PERMANENT_GRANT_TTL_SECS,
            now,
            600,
        )
        .unwrap();
        let stored = submit_request(dir.path(), &node, req, now).unwrap();
        let (_decided, perm_grant) = allow_request(
            dir.path(),
            &stored.request_id,
            &issuer,
            &node,
            now,
            None,
            None,
        )
        .unwrap();
        assert!(perm_grant.is_permanent());
        assert_eq!(perm_grant.exp_unix, grant::PERMANENT_GRANT_EXP_UNIX);

        // Permanent request can still be shrunk by the target to 3600s.
        let req2 = draft_request(
            &grantee,
            &node,
            NodePolicy::full(),
            grant::PERMANENT_GRANT_TTL_SECS,
            now,
            600,
        )
        .unwrap();
        let stored2 = submit_request(dir.path(), &node, req2, now).unwrap();
        let (_decided2, shrunk_grant) = allow_request(
            dir.path(),
            &stored2.request_id,
            &issuer,
            &node,
            now,
            None,
            Some(3600),
        )
        .unwrap();
        assert!(!shrunk_grant.is_permanent());
        assert_eq!(shrunk_grant.exp_unix, now + 3600);

        // A finite request cannot be widened to permanent.
        let finite_req = draft_request(&grantee, &node, NodePolicy::full(), 3600, now, 600).unwrap();
        let finite_stored = submit_request(dir.path(), &node, finite_req, now).unwrap();
        let err = allow_request(
            dir.path(),
            &finite_stored.request_id,
            &issuer,
            &node,
            now,
            None,
            Some(grant::PERMANENT_GRANT_TTL_SECS),
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("cannot extend"), "{err}");
    }
}
