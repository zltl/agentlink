//! Owner-signed capability grants for end-to-end authorization.
//!
//! The relay may stamp `relay_grant` / `relay_admin` on the outer E2E envelope.
//! Those fields are cleartext and must not be the node's source of truth once
//! owner issuer keys are configured. A [`SignedGrant`] is signed by an owner
//! device key, carried inside the sealed invoke body, and verified against
//! `owner-keys.json` on the node. See `docs/e2e-auth.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::{self, Identity};
use crate::permissions::NodePolicy;
use crate::util;

pub const GRANT_VERSION: &str = "agentlink-grant-v1";
/// Version string for issuer-signed remote revoke statements.
pub const REVOKE_VERSION: &str = "agentlink-revoke-v1";
pub const OWNER_KEYS_FILE: &str = "owner-keys.json";
/// Node-local deny-list of revoked grant jtis.
pub const REVOKED_GRANTS_FILE: &str = "revoked-grants.json";
/// Persistent issuer used when a node bootstraps signed-grant mode itself.
pub const GRANT_ISSUER_FILE: &str = "grant-issuer.json";
/// Per-node grant files under the client config directory.
pub const GRANTS_DIR: &str = "grants";
/// Explicit grant file for one invocation.
pub const GRANT_FILE_ENV: &str = "AGENTLINK_GRANT_FILE";
/// Raw grant JSON for one invocation.
pub const GRANT_JSON_ENV: &str = "AGENTLINK_GRANT_JSON";
/// Opt out of signed-grant bootstrap and keep legacy relay grants.
pub const LEGACY_RELAY_AUTH_ENV: &str = "AGENTLINK_LEGACY_RELAY_AUTH";
/// Opt out of client-side automatic grant ensure/mint (`0`/`false`/`no`/`off`).
pub const AUTO_GRANT_ENV: &str = "AGENTLINK_AUTO_GRANT";
/// Lifetime in seconds for automatically issued grants (default 3600).
pub const AUTO_GRANT_TTL_ENV: &str = "AGENTLINK_AUTO_GRANT_TTL";
/// Default automatic grant lifetime.
pub const DEFAULT_AUTO_GRANT_TTL_SECS: i64 = 3600;
/// Policy for automatically issued grants (default `exec`).
pub const AUTO_GRANT_POLICY_ENV: &str = "AGENTLINK_AUTO_GRANT_POLICY";

/// What [`ensure_grant`] did with the stored grant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureGrantAction {
    Reused,
    Refreshed,
    Issued,
}

impl EnsureGrantAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Reused => "reused",
            Self::Refreshed => "refreshed",
            Self::Issued => "issued",
        }
    }
}

/// Capability bound to one grantee, one node, and a policy window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedGrant {
    pub grantee_id: String,
    pub node_id: String,
    pub policy: NodePolicy,
    pub nbf_unix: i64,
    pub exp_unix: i64,
    pub jti: String,
    /// Hex ed25519 public key of the issuer.
    pub issuer_id: String,
    pub sig_hex: String,
}

/// Issuer-signed request to add one grant jti to a node's deny-list.
///
/// Carried inside a sealed E2E invoke as [`crate::protocol::Op::RevokeGrant`].
/// The relay never sees or validates it; only the node checks the issuer
/// against `owner-keys.json`. The deny-list still lives on the node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRevoke {
    pub node_id: String,
    pub jti: String,
    pub nbf_unix: i64,
    pub exp_unix: i64,
    /// Hex ed25519 public key of the issuer.
    pub issuer_id: String,
    pub sig_hex: String,
    /// When the revoked grant would have expired. Advisory prune metadata
    /// only: not part of the signed canonical bytes, so older nodes can still
    /// verify the revoke. `None` means unknown (keep the jti forever).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_exp_unix: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct OwnerKeysFile {
    #[serde(default)]
    issuers: BTreeSet<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RevokedGrantEntry {
    #[serde(default)]
    jti: String,
    /// When the underlying grant would have expired. `None` = unknown / keep
    /// (legacy bare jtis). Prune only when `Some(exp)` and `now > exp`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exp_unix: Option<i64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RevokedGrantsFile {
    /// Legacy bare list. Still read; migrated into entries on save.
    #[serde(default)]
    jtis: BTreeSet<String>,
    #[serde(default)]
    entries: Vec<RevokedGrantEntry>,
}

/// Canonical bytes the issuer signs. Field order is fixed; do not change it
/// without bumping [`GRANT_VERSION`].
pub fn canonical_bytes(
    grantee_id: &str,
    node_id: &str,
    policy: &NodePolicy,
    nbf_unix: i64,
    exp_unix: i64,
    jti: &str,
) -> Result<Vec<u8>> {
    let policy_json = serde_json::to_string(policy)
        .map_err(|err| Error::Message(format!("grant policy: {err}")))?;
    let text = format!(
        "{GRANT_VERSION}\ngrantee:{}\nnode:{}\npolicy:{policy_json}\nnbf:{nbf_unix}\nexp:{exp_unix}\njti:{jti}\n",
        grantee_id.trim().to_ascii_lowercase(),
        node_id.trim().to_ascii_lowercase(),
    );
    Ok(text.into_bytes())
}

/// Canonical bytes an issuer signs for a remote revoke. Field order is fixed
/// and deliberately distinct from [`canonical_bytes`] so a grant signature can
/// never be replayed as a revoke.
pub fn canonical_revoke_bytes(node_id: &str, jti: &str, nbf_unix: i64, exp_unix: i64) -> Vec<u8> {
    format!(
        "{REVOKE_VERSION}\nnode:{}\njti:{}\nnbf:{nbf_unix}\nexp:{exp_unix}\n",
        node_id.trim().to_ascii_lowercase(),
        jti.trim().to_ascii_lowercase(),
    )
    .into_bytes()
}

impl SignedRevoke {
    pub fn sign(
        issuer: &Identity,
        node_id: &str,
        jti: &str,
        nbf_unix: i64,
        exp_unix: i64,
    ) -> Result<Self> {
        let node_id = node_id.trim().to_ascii_lowercase();
        let jti = jti.trim().to_ascii_lowercase();
        if node_id.is_empty() || jti.is_empty() {
            return Err(Error::Message("revoke needs a node and jti".into()));
        }
        if exp_unix < nbf_unix {
            return Err(Error::Message("revoke exp is before nbf".into()));
        }
        let message = canonical_revoke_bytes(&node_id, &jti, nbf_unix, exp_unix);
        Ok(Self {
            node_id,
            jti,
            nbf_unix,
            exp_unix,
            issuer_id: issuer.public_hex().to_ascii_lowercase(),
            sig_hex: issuer.sign_message(&message),
            grant_exp_unix: None,
        })
    }

    /// Check signature and binding. Does not consult the clock or owner keys.
    pub fn verify_signature(&self) -> Result<()> {
        let message =
            canonical_revoke_bytes(&self.node_id, &self.jti, self.nbf_unix, self.exp_unix);
        identity::verify_message(&self.issuer_id, &message, &self.sig_hex)
    }

    /// Node-side check: trusted issuer, signature, node binding, time window,
    /// and a non-empty jti.
    pub fn authorize(
        &self,
        trusted_issuers: &BTreeSet<String>,
        expected_node_id: &str,
        now_unix: i64,
    ) -> Result<()> {
        let issuer = self.issuer_id.trim().to_ascii_lowercase();
        if issuer.is_empty() {
            return Err(Error::Auth(
                "revoke has no issuer id; sign it with a key enrolled in the node's \
                 owner-keys.json (see `agentlink grant trust-owner`)"
                    .into(),
            ));
        }
        if !trusted_issuers
            .iter()
            .any(|key| key.eq_ignore_ascii_case(&issuer))
        {
            return Err(Error::Auth(format!(
                "revoke issuer {issuer} is not trusted; on the node host run \
                 `agentlink grant trust-owner {issuer} --data-dir <node-data-dir>`"
            )));
        }
        self.verify_signature()?;
        if !self.node_id.eq_ignore_ascii_case(expected_node_id.trim()) {
            return Err(Error::Auth("revoke is for a different node".into()));
        }
        if now_unix < self.nbf_unix {
            return Err(Error::Auth("revoke is not valid yet".into()));
        }
        if now_unix > self.exp_unix {
            return Err(Error::Auth("revoke has expired".into()));
        }
        if self.jti.trim().is_empty() {
            return Err(Error::Auth("revoke has an empty jti".into()));
        }
        Ok(())
    }
}

impl SignedGrant {
    pub fn sign(
        issuer: &Identity,
        grantee_id: &str,
        node_id: &str,
        policy: NodePolicy,
        nbf_unix: i64,
        exp_unix: i64,
        jti: impl Into<String>,
    ) -> Result<Self> {
        let grantee_id = grantee_id.trim().to_ascii_lowercase();
        let node_id = node_id.trim().to_ascii_lowercase();
        let jti = jti.into();
        if grantee_id.is_empty() || node_id.is_empty() || jti.trim().is_empty() {
            return Err(Error::Message("grant needs grantee, node, and jti".into()));
        }
        if exp_unix < nbf_unix {
            return Err(Error::Message("grant exp is before nbf".into()));
        }
        let message = canonical_bytes(&grantee_id, &node_id, &policy, nbf_unix, exp_unix, &jti)?;
        let sig_hex = issuer.sign_message(&message);
        Ok(Self {
            grantee_id,
            node_id,
            policy,
            nbf_unix,
            exp_unix,
            jti,
            issuer_id: issuer.public_hex().to_ascii_lowercase(),
            sig_hex,
        })
    }

    /// Check signature and binding. Does not consult the clock or owner-key store.
    pub fn verify_signature(&self) -> Result<()> {
        let message = canonical_bytes(
            &self.grantee_id,
            &self.node_id,
            &self.policy,
            self.nbf_unix,
            self.exp_unix,
            &self.jti,
        )?;
        identity::verify_message(&self.issuer_id, &message, &self.sig_hex)
    }

    /// Full node-side check: trusted issuer, signature, node, grantee, time,
    /// and the node-local revoked-jti deny-list.
    pub fn authorize(
        &self,
        trusted_issuers: &BTreeSet<String>,
        revoked_jtis: &BTreeSet<String>,
        expected_node_id: &str,
        expected_grantee_id: &str,
        now_unix: i64,
    ) -> Result<NodePolicy> {
        let issuer = self.issuer_id.trim().to_ascii_lowercase();
        if issuer.is_empty() {
            return Err(Error::Auth(
                "grant has no issuer id; on the node host run `agentlink grant trust-owner \
                 <issuer_hex> --data-dir <node-data-dir>` (picked up on the next request), or \
                 issue with `agentlink grant issue --node <id> --issuer-data-dir <node-data-dir>`"
                    .into(),
            ));
        }
        if !trusted_issuers
            .iter()
            .any(|k| k.eq_ignore_ascii_case(&issuer))
        {
            return Err(Error::Auth(format!(
                "grant issuer {issuer} is not trusted; if the CLI auto-issued this grant, its \
                 operator key is not in owner-keys.json yet. On the node host run \
                 `agentlink grant trust-owner {issuer} --data-dir <node-data-dir>` (picked up on \
                 the next request, no restart), or issue with \
                 `agentlink grant issue --node <id> --issuer-data-dir <node-data-dir>`"
            )));
        }
        self.verify_signature()?;
        if !self.node_id.eq_ignore_ascii_case(expected_node_id.trim()) {
            return Err(Error::Auth("grant is for a different node".into()));
        }
        if !self
            .grantee_id
            .eq_ignore_ascii_case(expected_grantee_id.trim())
        {
            return Err(Error::Auth("grant is for a different peer".into()));
        }
        if now_unix < self.nbf_unix {
            return Err(Error::Auth("grant is not valid yet".into()));
        }
        if now_unix > self.exp_unix {
            return Err(Error::Auth("grant has expired".into()));
        }
        let jti = self.jti.trim();
        if revoked_jtis
            .iter()
            .any(|revoked| revoked.trim().eq_ignore_ascii_case(jti))
        {
            return Err(Error::Auth(format!(
                "grant was revoked (jti {})",
                jti.to_ascii_lowercase()
            )));
        }
        Ok(self.policy)
    }
}

/// Re-sign an existing grant for the same grantee, node, and policy with a
/// fresh validity window and jti.
pub fn refresh_grant(
    issuer: &Identity,
    grant: &SignedGrant,
    nbf_unix: i64,
    exp_unix: i64,
    jti: impl Into<String>,
) -> Result<SignedGrant> {
    SignedGrant::sign(
        issuer,
        &grant.grantee_id,
        &grant.node_id,
        grant.policy,
        nbf_unix,
        exp_unix,
        jti,
    )
}

/// Ensure a usable local grant for `(node_id, grantee_id)`.
///
/// - Valid stored grant (same node and grantee, not expired) → [`Reused`],
///   unchanged.
/// - Stored grant with the same bindings but expired → [`refresh_grant`] with
///   a fresh window and jti, saved → [`Refreshed`]. The stored policy is kept.
/// - No usable stored grant → [`SignedGrant::sign`] with `policy`, saved →
///   [`Issued`].
///
/// The window is `nbf = now - 60`, `exp = now + ttl_secs`. Only writes when the
/// stored grant is missing, expired, or bound to another grantee.
///
/// [`Reused`]: EnsureGrantAction::Reused
/// [`Refreshed`]: EnsureGrantAction::Refreshed
/// [`Issued`]: EnsureGrantAction::Issued
pub fn ensure_grant(
    config_dir: &Path,
    issuer: &Identity,
    node_id: &str,
    grantee_id: &str,
    policy: NodePolicy,
    ttl_secs: i64,
) -> Result<(SignedGrant, EnsureGrantAction)> {
    if ttl_secs <= 0 {
        return Err(Error::Message("grant ttl must be positive".into()));
    }
    let now = util::unix_now();
    let nbf = now.saturating_sub(60);
    let exp = now.saturating_add(ttl_secs);
    let stored = load_grant(config_dir, node_id)?;
    match stored {
        Some(grant)
            if grant.node_id.eq_ignore_ascii_case(node_id.trim())
                && grant.grantee_id.eq_ignore_ascii_case(grantee_id.trim())
                && now <= grant.exp_unix =>
        {
            Ok((grant, EnsureGrantAction::Reused))
        }
        Some(grant)
            if grant.node_id.eq_ignore_ascii_case(node_id.trim())
                && grant.grantee_id.eq_ignore_ascii_case(grantee_id.trim()) =>
        {
            let refreshed =
                refresh_grant(issuer, &grant, nbf, exp, uuid::Uuid::new_v4().to_string())?;
            save_grant(config_dir, &refreshed)?;
            Ok((refreshed, EnsureGrantAction::Refreshed))
        }
        _ => {
            let issued = SignedGrant::sign(
                issuer,
                grantee_id,
                node_id,
                policy,
                nbf,
                exp,
                uuid::Uuid::new_v4().to_string(),
            )?;
            save_grant(config_dir, &issued)?;
            Ok((issued, EnsureGrantAction::Issued))
        }
    }
}

/// True unless `AGENTLINK_AUTO_GRANT` is `0`/`false`/`no`/`off`.
pub fn auto_grant_enabled() -> bool {
    match std::env::var(AUTO_GRANT_ENV) {
        Ok(raw) => !matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "0" | "false" | "no" | "off"
        ),
        Err(_) => true,
    }
}

/// `AGENTLINK_AUTO_GRANT_TTL` in raw seconds; invalid or non-positive values
/// fall back to [`DEFAULT_AUTO_GRANT_TTL_SECS`].
pub fn auto_grant_ttl_secs() -> i64 {
    std::env::var(AUTO_GRANT_TTL_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<i64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_AUTO_GRANT_TTL_SECS)
}

/// Policy for auto-issued grants, from [`AUTO_GRANT_POLICY_ENV`].
///
/// Unset or empty → [`NodePolicy::full`]. Invalid names fall back to `full`
/// as well: a connected owner is not clipped to a narrower preset.
pub fn auto_grant_policy() -> NodePolicy {
    let raw = std::env::var(AUTO_GRANT_POLICY_ENV).unwrap_or_default();
    let raw = raw.trim();
    if raw.is_empty() {
        return NodePolicy::full();
    }
    crate::permissions::parse_access(raw).unwrap_or_else(|err| {
        tracing::warn!(
            value = raw,
            error = %err,
            "invalid {AUTO_GRANT_POLICY_ENV}; auto-issued grants use full"
        );
        NodePolicy::full()
    })
}

/// Load trusted issuer public keys from `dir/owner-keys.json`.
///
/// Missing file → empty set (legacy relay_grant mode).
pub fn load_owner_keys(dir: &Path) -> Result<BTreeSet<String>> {
    let path = dir.join(OWNER_KEYS_FILE);
    if !path.exists() {
        return Ok(BTreeSet::new());
    }
    let text = std::fs::read_to_string(&path)?;
    let file: OwnerKeysFile = serde_json::from_str(&text)
        .map_err(|err| Error::Message(format!("owner-keys.json: {err}")))?;
    Ok(file
        .issuers
        .into_iter()
        .map(|k| k.trim().to_ascii_lowercase())
        .filter(|k| !k.is_empty())
        .collect())
}

/// Reload trusted issuers from `dir/owner-keys.json`, keeping `cached` when the
/// file cannot be read or parsed.
///
/// Nodes call this before each authz decision so `grant trust-owner` takes
/// effect on the next request without a restart. Missing file still returns an
/// empty set (legacy relay-grant mode).
pub fn refresh_owner_keys(dir: &Path, cached: &BTreeSet<String>) -> BTreeSet<String> {
    match load_owner_keys(dir) {
        Ok(keys) => keys,
        Err(err) => {
            tracing::warn!(
                error = %err,
                dir = %dir.display(),
                "could not reload owner-keys.json; keeping the last known issuers"
            );
            cached.clone()
        }
    }
}

/// Replace the issuer set. Empty set deletes the file so legacy mode returns.
pub fn save_owner_keys(dir: &Path, issuers: &BTreeSet<String>) -> Result<()> {
    let path = dir.join(OWNER_KEYS_FILE);
    if issuers.is_empty() {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        util::ensure_dir(parent)?;
    }
    let normalized: BTreeSet<String> = issuers
        .iter()
        .map(|k| k.trim().to_ascii_lowercase())
        .filter(|k| !k.is_empty())
        .collect();
    let file = OwnerKeysFile {
        issuers: normalized,
    };
    util::write_secret(
        path.as_path(),
        serde_json::to_string_pretty(&file)?.as_bytes(),
    )?;
    Ok(())
}

fn normalize_jti(jti: &str) -> String {
    jti.trim().to_ascii_lowercase()
}

/// Prefer a known expiry; when both sides know one keep the later value so a
/// stale shorter expiry can never prune a still-live grant early.
fn merge_expiry(current: Option<i64>, incoming: Option<i64>) -> Option<i64> {
    match (current, incoming) {
        (Some(a), Some(b)) => Some(a.max(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Merge the legacy `jtis` list and `entries` into one jti → expiry map.
fn load_revoked_map(dir: &Path) -> Result<BTreeMap<String, Option<i64>>> {
    let path = dir.join(REVOKED_GRANTS_FILE);
    if !path.exists() {
        return Ok(BTreeMap::new());
    }
    let text = std::fs::read_to_string(&path)?;
    let file: RevokedGrantsFile = serde_json::from_str(&text)
        .map_err(|err| Error::Message(format!("revoked-grants.json: {err}")))?;
    let mut map: BTreeMap<String, Option<i64>> = BTreeMap::new();
    for jti in file.jtis {
        let jti = normalize_jti(&jti);
        if !jti.is_empty() {
            map.insert(jti, None);
        }
    }
    for entry in file.entries {
        let jti = normalize_jti(&entry.jti);
        if jti.is_empty() {
            continue;
        }
        let expiry = merge_expiry(map.get(&jti).copied().flatten(), entry.exp_unix);
        map.insert(jti, expiry);
    }
    Ok(map)
}

fn persist_revoked_map(dir: &Path, map: &BTreeMap<String, Option<i64>>) -> Result<()> {
    let path = dir.join(REVOKED_GRANTS_FILE);
    if map.is_empty() {
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        util::ensure_dir(parent)?;
    }
    let file = RevokedGrantsFile {
        jtis: map.keys().cloned().collect(),
        entries: map
            .iter()
            .map(|(jti, exp_unix)| RevokedGrantEntry {
                jti: jti.clone(),
                exp_unix: *exp_unix,
            })
            .collect(),
    };
    util::write_secret(
        path.as_path(),
        serde_json::to_string_pretty(&file)?.as_bytes(),
    )?;
    Ok(())
}

/// Drop entries whose grant expiry is strictly before `now`. Returns whether
/// anything was removed.
fn prune_revoked_map(map: &mut BTreeMap<String, Option<i64>>, now_unix: i64) -> bool {
    let before = map.len();
    map.retain(|_, exp| !matches!(exp, Some(exp) if now_unix > *exp));
    map.len() != before
}

/// Load the deny-list, dropping and persisting entries whose grant already
/// expired at `now_unix`.
pub fn prune_expired_revoked_jtis(dir: &Path, now_unix: i64) -> Result<BTreeSet<String>> {
    let mut map = load_revoked_map(dir)?;
    if prune_revoked_map(&mut map, now_unix) {
        persist_revoked_map(dir, &map)?;
    }
    Ok(map.into_keys().collect())
}

/// Load active revoked grant jtis from `dir/revoked-grants.json`.
///
/// Missing file → empty set. Expired entries are pruned and the pruned file is
/// written back so the deny-list does not grow forever.
pub fn load_revoked_jtis(dir: &Path) -> Result<BTreeSet<String>> {
    prune_expired_revoked_jtis(dir, util::unix_now())
}

/// Reload revoked jtis from `dir/revoked-grants.json`, keeping `cached` when
/// the file cannot be read or parsed.
///
/// Nodes call this before each authz decision so `grant revoke --data-dir`
/// takes effect on the next request without a restart. Missing file still
/// returns an empty set.
pub fn refresh_revoked_jtis(dir: &Path, cached: &BTreeSet<String>) -> BTreeSet<String> {
    match load_revoked_jtis(dir) {
        Ok(jtis) => jtis,
        Err(err) => {
            tracing::warn!(
                error = %err,
                dir = %dir.display(),
                "could not reload revoked-grants.json; keeping the last known jtis"
            );
            cached.clone()
        }
    }
}

/// Replace the revoked-jti set. Empty set deletes the file.
///
/// Writes both the legacy `jtis` list (all active keys, for older node
/// binaries) and `entries` with any known expiry, so `exp` metadata is
/// preserved across a plain replace.
pub fn save_revoked_jtis(dir: &Path, jtis: &BTreeSet<String>) -> Result<()> {
    let existing = load_revoked_map(dir)?;
    let mut map: BTreeMap<String, Option<i64>> = BTreeMap::new();
    for jti in jtis {
        let jti = normalize_jti(jti);
        if !jti.is_empty() {
            let expiry = existing.get(&jti).copied().flatten();
            map.insert(jti, expiry);
        }
    }
    persist_revoked_map(dir, &map)
}

/// Add one jti to the deny-list without dropping the others.
pub fn add_revoked_jti(dir: &Path, jti: &str) -> Result<BTreeSet<String>> {
    add_revoked_jti_until(dir, jti, None)
}

/// Add one jti with its grant expiry (when known), pruning expired entries
/// first. Returns the remaining active jti set.
pub fn add_revoked_jti_until(
    dir: &Path,
    jti: &str,
    exp_unix: Option<i64>,
) -> Result<BTreeSet<String>> {
    let jti = normalize_jti(jti);
    if jti.is_empty() {
        return Err(Error::Message("grant jti is empty".into()));
    }
    let mut map = load_revoked_map(dir)?;
    prune_revoked_map(&mut map, util::unix_now());
    let expiry = merge_expiry(map.get(&jti).copied().flatten(), exp_unix);
    map.insert(jti, expiry);
    persist_revoked_map(dir, &map)?;
    Ok(map.into_keys().collect())
}

/// True when the operator asked for the pre-grant relay behavior.
pub fn legacy_relay_auth_enabled() -> bool {
    matches!(
        std::env::var(LEGACY_RELAY_AUTH_ENV)
            .unwrap_or_default()
            .trim()
            .to_ascii_lowercase()
            .as_str(),
        "1" | "true" | "yes" | "on"
    )
}

/// Load the persistent grant issuer, if the node has one.
pub fn load_issuer(data_dir: &Path) -> Result<Option<Identity>> {
    let path = data_dir.join(GRANT_ISSUER_FILE);
    if path.exists() {
        return Ok(Some(Identity::load_or_create(&path)?));
    }
    Ok(None)
}

/// Create `<data_dir>/grant-issuer.json` and enroll it in `owner-keys.json`
/// when the node has no trusted issuers yet.
///
/// `legacy_relay_auth` skips bootstrap and leaves owner keys empty, which keeps
/// the old relay-stamped behavior. The caller passes the env decision explicitly
/// so tests do not race on process-global environment variables.
pub fn bootstrap_issuer_with_mode(
    data_dir: &Path,
    legacy_relay_auth: bool,
) -> Result<Option<Identity>> {
    if legacy_relay_auth {
        return Ok(None);
    }
    if !load_owner_keys(data_dir)?.is_empty() {
        return Ok(None);
    }
    let issuer = Identity::load_or_create(&data_dir.join(GRANT_ISSUER_FILE))?;
    add_owner_key(data_dir, issuer.public_hex())?;
    Ok(Some(issuer))
}

/// Read `AGENTLINK_LEGACY_RELAY_AUTH` and bootstrap if signed grants are on.
pub fn bootstrap_issuer(data_dir: &Path) -> Result<Option<Identity>> {
    bootstrap_issuer_with_mode(data_dir, legacy_relay_auth_enabled())
}

/// Add one issuer without dropping the others.
pub fn add_owner_key(dir: &Path, issuer_hex: &str) -> Result<BTreeSet<String>> {
    let mut keys = load_owner_keys(dir)?;
    let key = issuer_hex.trim().to_ascii_lowercase();
    if key.is_empty() {
        return Err(Error::Message("owner key is empty".into()));
    }
    // Reject obviously wrong lengths early.
    let bytes = hex::decode(&key).map_err(|err| Error::Message(format!("owner key: {err}")))?;
    if bytes.len() != 32 {
        return Err(Error::Message("owner key must be 32 bytes".into()));
    }
    keys.insert(key);
    save_owner_keys(dir, &keys)?;
    Ok(keys)
}

/// The relay already authenticated this caller for the node.
///
/// Admins set `relay_admin`. Owners, sharees, and same-owner peers set a
/// grant other than [`NodePolicy::none`]. Account membership lives on the
/// relay. Operation payloads stay in the sealed body, which the relay cannot
/// read. `NodePolicy::none()` is an explicit deny, not a narrow preset.
pub fn relay_account_connected(relay_admin: bool, relay_grant: Option<NodePolicy>) -> bool {
    if relay_admin {
        return true;
    }
    match relay_grant {
        Some(policy) => policy != NodePolicy::none(),
        None => false,
    }
}

fn connected_capability(invoke_grant: Option<NodePolicy>) -> NodePolicy {
    let mut policy = NodePolicy::full();
    if let Some(extra) = invoke_grant {
        // A per-call cap (a view ticket) can only narrow, never raise.
        policy = policy.intersect(extra);
    }
    policy
}

/// Effective capability for one invoke or transfer.
///
/// A relay-authenticated owner, admin, share, or same-owner peer is **full**.
/// A signed grant is not required for that session, and a stored preset or
/// node ceiling does not clip it. A per-call `invoke_grant` can still narrow
/// one call (view tickets).
///
/// When owner keys are configured and this is not an account session, a valid
/// signed grant still authorizes full use. A missing or rejected grant is an
/// error. With no owner keys and no account session, the result is empty
/// unless a per-call grant narrows the ceiling.
pub fn resolve_e2e_policy(
    trusted_issuers: &BTreeSet<String>,
    revoked_jtis: &BTreeSet<String>,
    authz: Option<&SignedGrant>,
    expected_node_id: &str,
    expected_grantee_id: &str,
    now_unix: i64,
    ceiling: NodePolicy,
    relay_admin: bool,
    relay_grant: Option<NodePolicy>,
    invoke_grant: Option<NodePolicy>,
) -> Result<NodePolicy> {
    if relay_account_connected(relay_admin, relay_grant) {
        return Ok(connected_capability(invoke_grant));
    }

    if !trusted_issuers.is_empty() {
        let Some(grant) = authz else {
            return Err(Error::Auth(format!(
                "signed grant required (owner keys configured); this connection is not signed in as the owner or an admin of node {expected_node_id}; the controller public key is {expected_grantee_id}"
            )));
        };
        // The signature, peer, expiry, and revoke list still bind the key.
        // The grant's preset does not clip; a valid grant is full use.
        grant.authorize(
            trusted_issuers,
            revoked_jtis,
            expected_node_id,
            expected_grantee_id,
            now_unix,
        )?;
        return Ok(connected_capability(invoke_grant));
    }

    let mut policy = NodePolicy::none();
    if let Some(extra) = invoke_grant {
        policy = ceiling.intersect(extra);
    }
    Ok(policy)
}

/// One grant file on disk.
#[derive(Debug, Clone)]
pub struct StoredGrant {
    pub path: PathBuf,
    pub grant: SignedGrant,
}

pub fn grants_dir(config_dir: &Path) -> PathBuf {
    config_dir.join(GRANTS_DIR)
}

pub fn grant_path(config_dir: &Path, node_id: &str) -> PathBuf {
    grants_dir(config_dir).join(format!("{}.json", node_id.trim().to_ascii_lowercase()))
}

pub fn save_grant(config_dir: &Path, grant: &SignedGrant) -> Result<PathBuf> {
    let path = grant_path(config_dir, &grant.node_id);
    util::write_secret(&path, serde_json::to_string_pretty(grant)?.as_bytes())?;
    Ok(path)
}

pub fn load_grant_file(path: &Path) -> Result<SignedGrant> {
    let text = std::fs::read_to_string(path)?;
    serde_json::from_str(&text)
        .map_err(|err| Error::Message(format!("grant {}: {err}", path.display())))
}

pub fn load_grant(config_dir: &Path, node_id: &str) -> Result<Option<SignedGrant>> {
    let path = grant_path(config_dir, node_id);
    if !path.exists() {
        return Ok(None);
    }
    load_grant_file(&path).map(Some)
}

/// Every readable grant file, newest expiry first.
pub fn list_stored_grants(config_dir: &Path) -> Result<Vec<StoredGrant>> {
    let dir = grants_dir(config_dir);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        match load_grant_file(&path) {
            Ok(grant) => out.push(StoredGrant { path, grant }),
            Err(err) => return Err(Error::Message(format!("grant {}: {err}", path.display()))),
        }
    }
    out.sort_by(|a, b| {
        b.grant
            .exp_unix
            .cmp(&a.grant.exp_unix)
            .then_with(|| a.grant.node_id.cmp(&b.grant.node_id))
    });
    Ok(out)
}

/// Delete one local grant file. Returns whether a file was removed.
pub fn delete_grant(config_dir: &Path, node_id: &str) -> Result<bool> {
    let path = grant_path(config_dir, node_id);
    if !path.exists() {
        return Ok(false);
    }
    std::fs::remove_file(path)?;
    Ok(true)
}

/// Reject a grant that is bound to another node/grantee or outside its window.
pub fn validate_grant_for(
    grant: &SignedGrant,
    node_id: &str,
    grantee_id: &str,
    now_unix: i64,
) -> Result<()> {
    if !grant.node_id.eq_ignore_ascii_case(node_id.trim()) {
        return Err(Error::Message(format!(
            "grant is for node {}, not {node_id}; run `agentlink grant issue --node {node_id}`",
            grant.node_id
        )));
    }
    if !grant.grantee_id.eq_ignore_ascii_case(grantee_id.trim()) {
        return Err(Error::Message(format!(
            "grant is bound to grantee {}, but this client identity is {grantee_id}; run `agentlink grant issue --node {node_id} --grantee {grantee_id}`",
            grant.grantee_id
        )));
    }
    if now_unix > grant.exp_unix {
        return Err(Error::Message(format!(
            "grant expired at unix {}; run `agentlink grant refresh --node {node_id}` (or \
             `agentlink grant issue --node {node_id}` to change policy)",
            grant.exp_unix
        )));
    }
    if now_unix < grant.nbf_unix {
        return Err(Error::Message(format!(
            "grant is not valid until unix {}; check the clock or re-issue with `agentlink grant issue --node {node_id}`",
            grant.nbf_unix
        )));
    }
    Ok(())
}

/// Load the grant a client should attach for `node_id`.
///
/// Precedence: `AGENTLINK_GRANT_JSON`, `AGENTLINK_GRANT_FILE`, then
/// `<config_dir>/grants/<node_id>.json`. Missing grants return `None` so legacy
/// nodes keep working; present but unusable grants are errors with a next step.
pub fn load_grant_for(
    config_dir: Option<&Path>,
    node_id: &str,
    grantee_id: &str,
) -> Result<Option<SignedGrant>> {
    let now = util::unix_now();
    if let Ok(raw) = std::env::var(GRANT_JSON_ENV) {
        if !raw.trim().is_empty() {
            let grant: SignedGrant = serde_json::from_str(raw.trim())
                .map_err(|err| Error::Message(format!("{GRANT_JSON_ENV}: {err}")))?;
            validate_grant_for(&grant, node_id, grantee_id, now)?;
            return Ok(Some(grant));
        }
    }
    if let Ok(path) = std::env::var(GRANT_FILE_ENV) {
        if !path.trim().is_empty() {
            let grant = load_grant_file(Path::new(path.trim()))?;
            validate_grant_for(&grant, node_id, grantee_id, now)?;
            return Ok(Some(grant));
        }
    }
    let Some(dir) = config_dir else {
        return Ok(None);
    };
    let Some(grant) = load_grant(dir, node_id)? else {
        return Ok(None);
    };
    validate_grant_for(&grant, node_id, grantee_id, now)?;
    Ok(Some(grant))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util;

    fn ids() -> (Identity, Identity, Identity) {
        (
            Identity::generate(),
            Identity::generate(),
            Identity::generate(),
        )
    }

    #[test]
    fn signed_grant_round_trips_and_binds_peer() {
        let (owner, grantee, other) = ids();
        let node = Identity::generate();
        let now = util::unix_now();
        let grant = SignedGrant::sign(
            &owner,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 10,
            now + 3600,
            "jti-1",
        )
        .unwrap();
        grant.verify_signature().unwrap();

        let mut trusted = BTreeSet::new();
        trusted.insert(owner.public_hex().to_string());
        assert_eq!(
            grant
                .authorize(
                    &trusted,
                    &BTreeSet::new(),
                    node.public_hex(),
                    grantee.public_hex(),
                    now,
                )
                .unwrap(),
            NodePolicy::exec()
        );
        assert!(grant
            .authorize(
                &trusted,
                &BTreeSet::new(),
                node.public_hex(),
                other.public_hex(),
                now
            )
            .is_err());
        assert!(grant
            .authorize(
                &trusted,
                &BTreeSet::new(),
                other.public_hex(),
                grantee.public_hex(),
                now
            )
            .is_err());
    }

    #[test]
    fn account_session_is_full_without_a_grant_file() {
        let trusted = BTreeSet::from(["ab".repeat(32)]);
        let node = "cd".repeat(32);
        let owner = resolve_e2e_policy(
            &trusted,
            &BTreeSet::new(),
            None,
            &node,
            &"ef".repeat(32),
            1,
            NodePolicy::exec(),
            false,
            Some(NodePolicy::exec()),
            None,
        )
        .unwrap();
        assert_eq!(owner, NodePolicy::full());
        assert!(owner.allow_desktop && owner.allows_remote_control());

        let admin = resolve_e2e_policy(
            &trusted,
            &BTreeSet::new(),
            None,
            &node,
            &"ef".repeat(32),
            1,
            NodePolicy::read_only(),
            true,
            None,
            None,
        )
        .unwrap();
        assert_eq!(admin, NodePolicy::full());

        // A view ticket can still narrow this one call.
        let watch = resolve_e2e_policy(
            &trusted,
            &BTreeSet::new(),
            None,
            &node,
            &"ef".repeat(32),
            1,
            NodePolicy::full(),
            true,
            None,
            Some(NodePolicy::remote_view()),
        )
        .unwrap();
        assert!(watch.allows_remote_view());
        assert!(!watch.allows_remote_control());
        assert!(!watch.allow_exec);
    }

    #[test]
    fn missing_authz_fails_when_there_is_no_account_session() {
        let trusted = BTreeSet::from(["ab".repeat(32)]);
        let err = resolve_e2e_policy(
            &trusted,
            &BTreeSet::new(),
            None,
            &"cd".repeat(32),
            &"ef".repeat(32),
            1,
            NodePolicy::full(),
            false,
            Some(NodePolicy::none()),
            None,
        )
        .unwrap_err();
        let err = err.to_string();
        assert!(err.contains("signed grant required"), "{err}");
        assert!(err.contains("not signed in"), "{err}");
        assert!(err.contains(&format!("node {}", "cd".repeat(32))), "{err}");
        assert!(
            err.contains(&format!("controller public key is {}", "ef".repeat(32))),
            "{err}"
        );
    }

    #[test]
    fn connected_session_is_full_and_an_anonymous_one_is_empty() {
        let empty = BTreeSet::new();
        let policy = resolve_e2e_policy(
            &empty,
            &BTreeSet::new(),
            None,
            "node",
            "peer",
            1,
            NodePolicy::read_only(),
            false,
            Some(NodePolicy::exec()),
            None,
        )
        .unwrap();
        assert_eq!(policy, NodePolicy::full());

        let denied = resolve_e2e_policy(
            &empty,
            &BTreeSet::new(),
            None,
            "node",
            "peer",
            1,
            NodePolicy::full(),
            false,
            None,
            None,
        )
        .unwrap();
        assert_eq!(denied, NodePolicy::none());
    }

    #[test]
    fn untrusted_issuer_is_rejected() {
        let (owner, stranger, grantee) = ids();
        let node = Identity::generate();
        let now = util::unix_now();
        let grant = SignedGrant::sign(
            &stranger,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::full(),
            now - 1,
            now + 60,
            "evil",
        )
        .unwrap();
        let mut trusted = BTreeSet::new();
        trusted.insert(owner.public_hex().to_string());
        let err = grant
            .authorize(
                &trusted,
                &BTreeSet::new(),
                node.public_hex(),
                grantee.public_hex(),
                now,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not trusted"), "{err}");
        assert!(
            err.contains(&stranger.public_hex().to_ascii_lowercase()),
            "{err}"
        );
        assert!(err.contains("agentlink grant trust-owner"), "{err}");
        assert!(err.contains("--issuer-data-dir"), "{err}");
        assert!(err.contains("no restart"), "{err}");
    }

    #[test]
    fn refresh_owner_keys_picks_up_changes_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (owner, next, grantee) = ids();
        let node = Identity::generate();
        let now = util::unix_now();
        add_owner_key(dir.path(), owner.public_hex()).unwrap();
        let cached = refresh_owner_keys(dir.path(), &BTreeSet::new());
        assert!(cached.contains(&owner.public_hex().to_ascii_lowercase()));

        let grant = SignedGrant::sign(
            &next,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::full(),
            now - 1,
            now + 60,
            "hot-reload",
        )
        .unwrap();
        assert!(grant
            .authorize(
                &cached,
                &BTreeSet::new(),
                node.public_hex(),
                grantee.public_hex(),
                now
            )
            .is_err());

        add_owner_key(dir.path(), next.public_hex()).unwrap();
        let reloaded = refresh_owner_keys(dir.path(), &cached);
        assert_eq!(
            grant
                .authorize(
                    &reloaded,
                    &BTreeSet::new(),
                    node.public_hex(),
                    grantee.public_hex(),
                    now,
                )
                .unwrap(),
            NodePolicy::full()
        );

        // A corrupt file must not drop the last good set.
        std::fs::write(dir.path().join(OWNER_KEYS_FILE), b"not json").unwrap();
        assert_eq!(refresh_owner_keys(dir.path(), &reloaded), reloaded);
    }

    #[test]
    fn owner_keys_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let id = Identity::generate();
        let keys = add_owner_key(dir.path(), id.public_hex()).unwrap();
        assert!(keys.contains(&id.public_hex().to_ascii_lowercase()));
        let loaded = load_owner_keys(dir.path()).unwrap();
        assert_eq!(loaded, keys);
        save_owner_keys(dir.path(), &BTreeSet::new()).unwrap();
        assert!(load_owner_keys(dir.path()).unwrap().is_empty());
        assert!(!dir.path().join(OWNER_KEYS_FILE).exists());
    }

    #[test]
    fn expired_grant_is_rejected() {
        let (owner, grantee, _) = ids();
        let node = Identity::generate();
        let now = util::unix_now();
        let grant = SignedGrant::sign(
            &owner,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 100,
            now - 1,
            "old",
        )
        .unwrap();
        let mut trusted = BTreeSet::new();
        trusted.insert(owner.public_hex().to_string());
        assert!(grant
            .authorize(
                &trusted,
                &BTreeSet::new(),
                node.public_hex(),
                grantee.public_hex(),
                now
            )
            .is_err());
    }

    #[test]
    fn refresh_grant_reuses_binding_and_extends_window() {
        let (owner, grantee, _) = ids();
        let node = Identity::generate();
        let now = util::unix_now();
        let old = SignedGrant::sign(
            &owner,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 100,
            now - 10,
            "old-jti",
        )
        .unwrap();

        let refreshed = refresh_grant(&owner, &old, now, now + 3600, "new-jti").unwrap();
        assert_eq!(refreshed.grantee_id, old.grantee_id);
        assert_eq!(refreshed.node_id, old.node_id);
        assert_eq!(refreshed.policy, old.policy);
        assert_eq!(refreshed.issuer_id, old.issuer_id);
        assert_eq!(refreshed.jti, "new-jti");
        assert_eq!(refreshed.nbf_unix, now);
        assert!(refreshed.exp_unix > old.exp_unix);
        refreshed.verify_signature().unwrap();
        validate_grant_for(&refreshed, node.public_hex(), grantee.public_hex(), now).unwrap();
    }

    #[test]
    fn ensure_grant_issues_when_missing_and_authorizes() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let grantee = Identity::generate();
        let node = Identity::generate();
        let now = util::unix_now();

        let (grant, action) = ensure_grant(
            dir.path(),
            &issuer,
            node.public_hex(),
            grantee.public_hex(),
            NodePolicy::exec(),
            600,
        )
        .unwrap();
        assert_eq!(action, EnsureGrantAction::Issued);
        assert!(dir
            .path()
            .join(GRANTS_DIR)
            .join(format!("{}.json", node.public_hex()))
            .exists());
        assert!(grant.nbf_unix == now - 60 || grant.nbf_unix == now - 59);
        assert!(grant.exp_unix == now + 600 || grant.exp_unix == now + 601);

        let trusted = BTreeSet::from([issuer.public_hex().to_ascii_lowercase()]);
        assert_eq!(
            grant
                .authorize(
                    &trusted,
                    &BTreeSet::new(),
                    node.public_hex(),
                    grantee.public_hex(),
                    now,
                )
                .unwrap(),
            NodePolicy::exec()
        );
        assert_eq!(
            load_grant(dir.path(), node.public_hex()).unwrap(),
            Some(grant)
        );
    }

    #[test]
    fn ensure_grant_reuses_valid_grant_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let grantee = Identity::generate();
        let node = Identity::generate();
        let now = util::unix_now();
        let stored = SignedGrant::sign(
            &issuer,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 60,
            now + 600,
            "stable-jti",
        )
        .unwrap();
        save_grant(dir.path(), &stored).unwrap();

        // A different policy must not rewrite a valid grant.
        let (grant, action) = ensure_grant(
            dir.path(),
            &issuer,
            node.public_hex(),
            grantee.public_hex(),
            NodePolicy::full(),
            900,
        )
        .unwrap();
        assert_eq!(action, EnsureGrantAction::Reused);
        assert_eq!(grant.jti, "stable-jti");
        assert_eq!(grant.exp_unix, stored.exp_unix);
        assert_eq!(grant.policy, NodePolicy::exec());
        assert_eq!(
            load_grant(dir.path(), node.public_hex()).unwrap(),
            Some(stored)
        );
    }

    #[test]
    fn ensure_grant_refreshes_expired_grant_with_new_window_and_jti() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let grantee = Identity::generate();
        let node = Identity::generate();
        let now = util::unix_now();
        let stored = SignedGrant::sign(
            &issuer,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 120,
            now - 10,
            "old-jti",
        )
        .unwrap();
        save_grant(dir.path(), &stored).unwrap();

        // The stored policy is kept even though a wider one is requested.
        let (grant, action) = ensure_grant(
            dir.path(),
            &issuer,
            node.public_hex(),
            grantee.public_hex(),
            NodePolicy::full(),
            600,
        )
        .unwrap();
        assert_eq!(action, EnsureGrantAction::Refreshed);
        assert_ne!(grant.jti, stored.jti);
        assert_eq!(grant.policy, NodePolicy::exec());
        assert!(grant.nbf_unix == now - 60 || grant.nbf_unix == now - 59);
        assert!(grant.exp_unix == now + 600 || grant.exp_unix == now + 601);
        assert!(grant.exp_unix > stored.exp_unix);
        grant.verify_signature().unwrap();
        assert_eq!(
            load_grant(dir.path(), node.public_hex()).unwrap(),
            Some(grant)
        );
    }

    #[test]
    fn ensure_grant_rejects_non_positive_ttl() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = Identity::generate();
        let grantee = Identity::generate();
        for ttl in [0, -1] {
            let err = ensure_grant(
                dir.path(),
                &issuer,
                "node",
                grantee.public_hex(),
                NodePolicy::exec(),
                ttl,
            )
            .unwrap_err()
            .to_string();
            assert!(err.contains("ttl must be positive"), "{err}");
        }
        assert!(load_grant(dir.path(), "node").unwrap().is_none());
    }

    #[test]
    fn auto_grant_policy_defaults_to_exec_and_reads_env() {
        // One test covers all cases so the process-global env var is not
        // mutated concurrently by parallel tests.
        std::env::remove_var(AUTO_GRANT_POLICY_ENV);
        assert_eq!(auto_grant_policy(), NodePolicy::full());

        std::env::set_var(AUTO_GRANT_POLICY_ENV, "");
        assert_eq!(auto_grant_policy(), NodePolicy::full());

        std::env::set_var(AUTO_GRANT_POLICY_ENV, "full");
        assert_eq!(auto_grant_policy(), NodePolicy::full());

        std::env::set_var(AUTO_GRANT_POLICY_ENV, "exec");
        assert_eq!(auto_grant_policy(), NodePolicy::exec());

        std::env::set_var(AUTO_GRANT_POLICY_ENV, "definitely-not-a-policy");
        assert_eq!(auto_grant_policy(), NodePolicy::full());

        std::env::remove_var(AUTO_GRANT_POLICY_ENV);
    }

    #[test]
    fn bootstrap_creates_a_persistent_issuer_and_owner_key() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = bootstrap_issuer_with_mode(dir.path(), false)
            .unwrap()
            .expect("issuer created");
        let keys = load_owner_keys(dir.path()).unwrap();
        assert_eq!(keys.len(), 1);
        assert!(keys.contains(&issuer.public_hex().to_ascii_lowercase()));
        assert!(dir.path().join(GRANT_ISSUER_FILE).exists());

        // The same secret is reused, and an enrolled owner key is not touched.
        let again = load_issuer(dir.path()).unwrap().expect("issuer exists");
        assert_eq!(again.public_hex(), issuer.public_hex());
        assert!(bootstrap_issuer_with_mode(dir.path(), false)
            .unwrap()
            .is_none());
    }

    #[test]
    fn legacy_bootstrap_skips_issuer_and_owner_keys() {
        let dir = tempfile::tempdir().unwrap();
        assert!(bootstrap_issuer_with_mode(dir.path(), true)
            .unwrap()
            .is_none());
        assert!(!dir.path().join(GRANT_ISSUER_FILE).exists());
        assert!(!dir.path().join(OWNER_KEYS_FILE).exists());
        assert!(load_owner_keys(dir.path()).unwrap().is_empty());
    }

    #[test]
    fn grant_files_round_trip_and_expire_into_an_actionable_error() {
        let config = tempfile::tempdir().unwrap();
        let node = Identity::generate();
        let grantee = Identity::generate();
        let issuer = Identity::generate();
        let now = util::unix_now();
        let grant = SignedGrant::sign(
            &issuer,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 5,
            now + 600,
            "roundtrip",
        )
        .unwrap();
        let path = save_grant(config.path(), &grant).unwrap();
        assert!(path.ends_with(format!("{}.json", node.public_hex())));
        let loaded = load_grant(config.path(), node.public_hex())
            .unwrap()
            .expect("stored");
        assert_eq!(loaded, grant);
        let listed = list_stored_grants(config.path()).unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].grant, grant);
        validate_grant_for(&loaded, node.public_hex(), grantee.public_hex(), now).unwrap();

        let err = validate_grant_for(&loaded, node.public_hex(), grantee.public_hex(), now + 601)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expired"), "{err}");
        assert!(err.contains("agentlink grant refresh"), "{err}");
        assert!(err.contains("agentlink grant issue"), "{err}");
        assert!(err.contains(&node.public_hex()), "{err}");

        assert!(delete_grant(config.path(), node.public_hex()).unwrap());
        assert!(!delete_grant(config.path(), node.public_hex()).unwrap());
        assert!(load_grant(config.path(), node.public_hex())
            .unwrap()
            .is_none());
    }

    #[test]
    fn grant_for_another_peer_is_rejected() {
        let node = Identity::generate();
        let grantee = Identity::generate();
        let other = Identity::generate();
        let now = util::unix_now();
        let grant = SignedGrant::sign(
            &Identity::generate(),
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::read_only(),
            now - 1,
            now + 60,
            "peer",
        )
        .unwrap();
        let err = validate_grant_for(&grant, node.public_hex(), other.public_hex(), now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("grantee"), "{err}");
    }

    #[test]
    fn revoked_jtis_round_trip_and_reject_empty() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_revoked_jtis(dir.path()).unwrap().is_empty());

        let jtis = add_revoked_jti(dir.path(), "  JTI-One  ").unwrap();
        assert_eq!(jtis, BTreeSet::from(["jti-one".to_string()]));
        let jtis = add_revoked_jti(dir.path(), "jti-two").unwrap();
        assert_eq!(load_revoked_jtis(dir.path()).unwrap(), jtis);
        assert!(jtis.contains("jti-one") && jtis.contains("jti-two"));
        assert!(dir.path().join(REVOKED_GRANTS_FILE).exists());

        assert!(add_revoked_jti(dir.path(), "   ").is_err());

        save_revoked_jtis(dir.path(), &BTreeSet::new()).unwrap();
        assert!(load_revoked_jtis(dir.path()).unwrap().is_empty());
        assert!(!dir.path().join(REVOKED_GRANTS_FILE).exists());
    }

    fn read_revoked_file(dir: &Path) -> RevokedGrantsFile {
        let text = std::fs::read_to_string(dir.join(REVOKED_GRANTS_FILE)).unwrap();
        serde_json::from_str(&text).unwrap()
    }

    fn entry_exp(dir: &Path, jti: &str) -> Option<i64> {
        read_revoked_file(dir)
            .entries
            .iter()
            .find(|entry| entry.jti == jti)
            .and_then(|entry| entry.exp_unix)
    }

    #[test]
    fn legacy_revoked_jtis_load_and_migrate_to_entries_on_save() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join(REVOKED_GRANTS_FILE),
            br#"{"jtis":["  JTI-A  ","","jti-b"]}"#,
        )
        .unwrap();

        let loaded = load_revoked_jtis(dir.path()).unwrap();
        assert_eq!(
            loaded,
            BTreeSet::from(["jti-a".to_string(), "jti-b".to_string()])
        );
        // Nothing expired, so the legacy file is left untouched.
        assert!(read_revoked_file(dir.path()).entries.is_empty());

        let now = util::unix_now();
        add_revoked_jti_until(dir.path(), "jti-c", Some(now + 600)).unwrap();
        let file = read_revoked_file(dir.path());
        assert_eq!(
            file.jtis,
            BTreeSet::from([
                "jti-a".to_string(),
                "jti-b".to_string(),
                "jti-c".to_string()
            ])
        );
        assert!(file
            .entries
            .iter()
            .any(|entry| entry.jti == "jti-c" && entry.exp_unix == Some(now + 600)));
        assert!(file
            .entries
            .iter()
            .any(|entry| entry.jti == "jti-a" && entry.exp_unix.is_none()));
    }

    #[test]
    fn expired_revoked_entries_are_pruned_and_written_back() {
        let dir = tempfile::tempdir().unwrap();
        let now = util::unix_now();
        std::fs::write(
            dir.path().join(REVOKED_GRANTS_FILE),
            serde_json::to_vec(&serde_json::json!({
                "jtis": ["legacy-unknown"],
                "entries": [
                    {"jti": "past", "exp_unix": now - 10},
                    {"jti": "future", "exp_unix": now + 600},
                    {"jti": "unknown"}
                ]
            }))
            .unwrap(),
        )
        .unwrap();

        let loaded = load_revoked_jtis(dir.path()).unwrap();
        assert!(!loaded.contains("past"));
        assert!(loaded.contains("future"));
        assert!(loaded.contains("unknown"));
        assert!(loaded.contains("legacy-unknown"));

        let text = std::fs::read_to_string(dir.path().join(REVOKED_GRANTS_FILE)).unwrap();
        assert!(!text.contains("past"), "{text}");
        assert!(text.contains("future"), "{text}");
        assert!(text.contains("legacy-unknown"), "{text}");

        // A future expiry still revokes the grant.
        let (owner, grantee, _) = ids();
        let node = Identity::generate();
        let grant = SignedGrant::sign(
            &owner,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 1,
            now + 600,
            "future",
        )
        .unwrap();
        let trusted = BTreeSet::from([owner.public_hex().to_ascii_lowercase()]);
        assert!(grant
            .authorize(
                &trusted,
                &loaded,
                node.public_hex(),
                grantee.public_hex(),
                now
            )
            .is_err());

        // Adding a jti prunes stale entries too.
        add_revoked_jti_until(dir.path(), "another", None).unwrap();
        let text = std::fs::read_to_string(dir.path().join(REVOKED_GRANTS_FILE)).unwrap();
        assert!(!text.contains("past"), "{text}");
    }

    #[test]
    fn unknown_expiry_is_never_pruned() {
        let dir = tempfile::tempdir().unwrap();
        add_revoked_jti(dir.path(), "no-exp").unwrap();
        let pruned = prune_expired_revoked_jtis(dir.path(), i64::MAX).unwrap();
        assert!(pruned.contains("no-exp"));
        assert_eq!(load_revoked_jtis(dir.path()).unwrap(), pruned);
    }

    #[test]
    fn add_revoked_jti_until_upgrades_and_keeps_later_expiry() {
        let dir = tempfile::tempdir().unwrap();
        let now = util::unix_now();

        add_revoked_jti(dir.path(), "jti").unwrap();
        assert_eq!(entry_exp(dir.path(), "jti"), None);

        add_revoked_jti_until(dir.path(), "jti", Some(now + 100)).unwrap();
        assert_eq!(entry_exp(dir.path(), "jti"), Some(now + 100));

        // A shorter expiry must not overwrite the later one.
        add_revoked_jti_until(dir.path(), "jti", Some(now + 50)).unwrap();
        assert_eq!(entry_exp(dir.path(), "jti"), Some(now + 100));

        // Unknown expiry keeps the known one.
        add_revoked_jti_until(dir.path(), "jti", None).unwrap();
        assert_eq!(entry_exp(dir.path(), "jti"), Some(now + 100));

        add_revoked_jti_until(dir.path(), "jti", Some(now + 200)).unwrap();
        assert_eq!(entry_exp(dir.path(), "jti"), Some(now + 200));
    }

    #[test]
    fn signed_revoke_grant_exp_is_advisory_and_unsigned() {
        let owner = Identity::generate();
        let node = Identity::generate();
        let now = util::unix_now();
        let mut revoke =
            SignedRevoke::sign(&owner, node.public_hex(), "jti", now, now + 60).unwrap();
        assert_eq!(revoke.grant_exp_unix, None);
        revoke.grant_exp_unix = Some(now + 1234);
        revoke.verify_signature().unwrap();

        let text = serde_json::to_string(&revoke).unwrap();
        assert!(text.contains("grant_exp_unix"), "{text}");
        let back: SignedRevoke = serde_json::from_str(&text).unwrap();
        assert_eq!(back, revoke);

        // 0.1.106 payloads without the field still parse and verify.
        let legacy: SignedRevoke = serde_json::from_value(serde_json::json!({
            "node_id": revoke.node_id,
            "jti": revoke.jti,
            "nbf_unix": revoke.nbf_unix,
            "exp_unix": revoke.exp_unix,
            "issuer_id": revoke.issuer_id,
            "sig_hex": revoke.sig_hex,
        }))
        .unwrap();
        assert_eq!(legacy.grant_exp_unix, None);
        legacy.verify_signature().unwrap();
    }

    #[test]
    fn authorize_rejects_a_revoked_jti() {
        let (owner, grantee, _) = ids();
        let node = Identity::generate();
        let now = util::unix_now();
        let grant = SignedGrant::sign(
            &owner,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::full(),
            now - 1,
            now + 600,
            "Revoked-Jti",
        )
        .unwrap();
        let trusted = BTreeSet::from([owner.public_hex().to_ascii_lowercase()]);

        assert_eq!(
            grant
                .authorize(
                    &trusted,
                    &BTreeSet::new(),
                    node.public_hex(),
                    grantee.public_hex(),
                    now
                )
                .unwrap(),
            NodePolicy::full()
        );

        // Case/whitespace-insensitive match against the set.
        let revoked = BTreeSet::from(["  REVOKED-JTI  ".to_string()]);
        let err = grant
            .authorize(
                &trusted,
                &revoked,
                node.public_hex(),
                grantee.public_hex(),
                now,
            )
            .unwrap_err()
            .to_string();
        assert!(err.contains("revoked"), "{err}");
        assert!(err.contains("revoked-jti"), "{err}");

        // A different jti stays valid.
        let other_revoked = BTreeSet::from(["some-other-jti".to_string()]);
        assert!(grant
            .authorize(
                &trusted,
                &other_revoked,
                node.public_hex(),
                grantee.public_hex(),
                now
            )
            .is_ok());
    }

    #[test]
    fn resolve_e2e_policy_rejects_revoked_authz() {
        let (owner, grantee, _) = ids();
        let node = Identity::generate();
        let now = util::unix_now();
        let grant = SignedGrant::sign(
            &owner,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 1,
            now + 600,
            "resolve-revoked",
        )
        .unwrap();
        let trusted = BTreeSet::from([owner.public_hex().to_ascii_lowercase()]);
        let revoked = BTreeSet::from(["resolve-revoked".to_string()]);

        let err = resolve_e2e_policy(
            &trusted,
            &revoked,
            Some(&grant),
            node.public_hex(),
            grantee.public_hex(),
            now,
            NodePolicy::full(),
            false,
            None,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("revoked"), "{err}");

        assert_eq!(
            resolve_e2e_policy(
                &trusted,
                &BTreeSet::new(),
                Some(&grant),
                node.public_hex(),
                grantee.public_hex(),
                now,
                NodePolicy::read_only(),
                false,
                None,
                None,
            )
            .unwrap(),
            NodePolicy::full()
        );
    }

    #[test]
    fn refresh_revoked_jtis_picks_up_changes_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (owner, grantee, _) = ids();
        let node = Identity::generate();
        let now = util::unix_now();
        let grant = SignedGrant::sign(
            &owner,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::full(),
            now - 1,
            now + 60,
            "hot-reload-jti",
        )
        .unwrap();
        let trusted = BTreeSet::from([owner.public_hex().to_ascii_lowercase()]);

        let cached = refresh_revoked_jtis(dir.path(), &BTreeSet::new());
        assert!(cached.is_empty());
        grant
            .authorize(
                &trusted,
                &cached,
                node.public_hex(),
                grantee.public_hex(),
                now,
            )
            .unwrap();

        add_revoked_jti(dir.path(), "hot-reload-jti").unwrap();
        let reloaded = refresh_revoked_jtis(dir.path(), &cached);
        assert!(grant
            .authorize(
                &trusted,
                &reloaded,
                node.public_hex(),
                grantee.public_hex(),
                now
            )
            .is_err());

        // A corrupt file must not drop the last good set.
        std::fs::write(dir.path().join(REVOKED_GRANTS_FILE), b"not json").unwrap();
        assert_eq!(refresh_revoked_jtis(dir.path(), &reloaded), reloaded);
    }

    #[test]
    fn signed_revoke_round_trips_and_authorizes() {
        let owner = Identity::generate();
        let node = Identity::generate();
        let now = util::unix_now();
        let revoke = SignedRevoke::sign(
            &owner,
            node.public_hex(),
            "  JTI-Revoke  ",
            now - 10,
            now + 300,
        )
        .unwrap();
        assert_eq!(revoke.jti, "jti-revoke");
        assert_eq!(revoke.node_id, node.public_hex().to_ascii_lowercase());
        revoke.verify_signature().unwrap();

        let trusted = BTreeSet::from([owner.public_hex().to_ascii_lowercase()]);
        revoke.authorize(&trusted, node.public_hex(), now).unwrap();

        // Field order is fixed and revoke bytes never equal grant bytes.
        let message = canonical_revoke_bytes(&revoke.node_id, &revoke.jti, now - 10, now + 300);
        assert!(String::from_utf8_lossy(&message).starts_with(REVOKE_VERSION));
    }

    #[test]
    fn signed_revoke_rejects_wrong_node_untrusted_expired_and_bad_sig() {
        let owner = Identity::generate();
        let other = Identity::generate();
        let node = Identity::generate();
        let stranger = Identity::generate();
        let now = util::unix_now();
        let revoke =
            SignedRevoke::sign(&owner, node.public_hex(), "jti-x", now - 10, now + 300).unwrap();
        let trusted = BTreeSet::from([owner.public_hex().to_ascii_lowercase()]);

        // Wrong node.
        let err = revoke
            .authorize(&trusted, other.public_hex(), now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("different node"), "{err}");

        // Untrusted issuer keeps the signature valid but fails trust.
        let untrusted =
            SignedRevoke::sign(&stranger, node.public_hex(), "jti-x", now - 10, now + 300).unwrap();
        let err = untrusted
            .authorize(&trusted, node.public_hex(), now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("is not trusted"), "{err}");

        // Expired window.
        let expired =
            SignedRevoke::sign(&owner, node.public_hex(), "jti-x", now - 100, now - 1).unwrap();
        let err = expired
            .authorize(&trusted, node.public_hex(), now)
            .unwrap_err()
            .to_string();
        assert!(err.contains("expired"), "{err}");

        // Bad signature.
        let mut forged = revoke.clone();
        forged.sig_hex = "00".repeat(64);
        assert!(forged.verify_signature().is_err());
        assert!(forged.authorize(&trusted, node.public_hex(), now).is_err());

        // Empty jti cannot be signed in the first place.
        assert!(SignedRevoke::sign(&owner, node.public_hex(), "   ", now, now + 1).is_err());
    }
}
