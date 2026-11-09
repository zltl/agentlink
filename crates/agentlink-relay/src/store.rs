//! Persistent enrollment and pairing tokens.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use agentlink_core::{Error, NodePolicy, Result};
use serde::{Deserialize, Serialize};

use agentlink_core::util::{self, unix_now};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrolledNode {
    pub id: String,
    pub name: String,
    pub public_key_hex: String,
    pub policy: NodePolicy,
    #[serde(default = "default_ceiling")]
    pub ceiling: NodePolicy,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub os: String,
    #[serde(default)]
    pub arch: String,
    #[serde(default)]
    pub version: String,
    pub enrolled_unix: i64,
    #[serde(default)]
    pub last_seen_unix: Option<i64>,
    #[serde(default)]
    pub owner: String,
}

fn default_ceiling() -> NodePolicy {
    NodePolicy::phase1_ceiling()
}

impl EnrolledNode {
    /// Connected use is full. Stored presets and ceilings are not a cap.
    pub fn effective(&self) -> NodePolicy {
        NodePolicy::full()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PairingRecord {
    token: String,
    name: String,
    policy: NodePolicy,
    expires_unix: i64,
    used: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRecord {
    pub id: String,
    pub name: String,
    pub role: String,
    pub revoked: bool,
    #[serde(default)]
    pub grants: HashMap<String, NodePolicy>,
}

#[derive(Debug, Serialize, Deserialize)]
struct StoreData {
    admin_token: String,
    #[serde(default)]
    nodes: HashMap<String, EnrolledNode>,
    #[serde(default)]
    pairing: Vec<PairingRecord>,
    #[serde(default)]
    clients: HashMap<String, ClientRecord>,
    /// Pushed to the node on its next connection.
    #[serde(default)]
    audit_policies: HashMap<String, String>,
}

pub struct Store {
    path: PathBuf,
    data: StoreData,
    /// True when this process created `store.json`.
    created: bool,
}

#[derive(Debug, Clone)]
pub struct NodeMeta {
    pub name: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub ceiling: NodePolicy,
}

#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub token: String,
    pub name: String,
    pub expires_unix: i64,
    pub policy: NodePolicy,
}

impl Store {
    pub fn load(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            util::ensure_dir(parent)?;
        }
        if path.exists() {
            let text = std::fs::read_to_string(path)?;
            let data: StoreData = serde_json::from_str(&text)?;
            let store = Self {
                path: path.to_path_buf(),
                data,
                created: false,
            };
            store.write_admin_file()?;
            return Ok(store);
        }
        let data = StoreData {
            admin_token: util::random_token(),
            nodes: HashMap::new(),
            pairing: Vec::new(),
            clients: HashMap::new(),
            audit_policies: HashMap::new(),
        };
        let store = Self {
            path: path.to_path_buf(),
            data,
            created: true,
        };
        store.save()?;
        store.write_admin_file()?;
        Ok(store)
    }

    pub fn admin_token(&self) -> &str {
        &self.data.admin_token
    }

    /// The admin token was generated during this `load`, not read from disk.
    pub fn created(&self) -> bool {
        self.created
    }

    pub fn create_pairing(
        &mut self,
        name: &str,
        policy: NodePolicy,
        ttl_secs: u64,
    ) -> Result<IssuedToken> {
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Message("pairing name is required".into()));
        }
        if !(60..=7 * 24 * 3600).contains(&ttl_secs) {
            return Err(Error::Message(
                "pairing ttl must be between 60 seconds and 7 days".into(),
            ));
        }
        self.data
            .pairing
            .retain(|p| !p.used && p.expires_unix > unix_now());
        let token = util::random_token();
        let expires_unix = unix_now() + ttl_secs as i64;
        self.data.pairing.push(PairingRecord {
            token: token.clone(),
            name: name.to_string(),
            policy,
            expires_unix,
            used: false,
        });
        self.save()?;
        Ok(IssuedToken {
            token,
            name: name.to_string(),
            expires_unix,
            policy,
        })
    }

    /// Enroll a new node, or refresh an existing one.
    ///
    /// An already-enrolled key reconnects without a token. A still-valid token
    /// updates that node's policy (re-pair). An unknown key needs a live token.
    pub fn enroll(
        &mut self,
        pairing_token: Option<&str>,
        public_hex: &str,
        meta: NodeMeta,
    ) -> Result<EnrolledNode> {
        let id = public_hex.trim().to_ascii_lowercase();
        if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Auth(
                "node public key is not a valid ed25519 key".into(),
            ));
        }
        let now = unix_now();
        if let Some(existing) = self.data.nodes.get(&id).cloned() {
            let mut node = existing;
            if let Some(token) = pairing_token.filter(|t| !t.is_empty()) {
                if let Some(rec) = self.take_valid_token(token, now) {
                    node.policy = rec.policy;
                    if !rec.name.is_empty() && meta.name.is_empty() {
                        node.name = rec.name;
                    }
                }
            }
            if !meta.name.is_empty() {
                node.name = meta.name;
            }
            node.hostname = meta.hostname;
            node.os = meta.os;
            node.arch = meta.arch;
            node.version = meta.version;
            node.ceiling = meta.ceiling;
            node.last_seen_unix = Some(now);
            self.data.nodes.insert(id, node.clone());
            self.save()?;
            return Ok(node);
        }

        let token = pairing_token
            .filter(|t| !t.is_empty())
            .ok_or_else(|| Error::Auth("node is not paired; pass a pairing token".into()))?;
        let pairing_before = self.data.pairing.clone();
        let rec = self.take_valid_token(token, now).ok_or_else(|| {
            Error::Auth("pairing token is invalid, expired, or already used".into())
        })?;
        let name = if meta.name.is_empty() {
            rec.name
        } else {
            meta.name
        };
        let node = EnrolledNode {
            id: id.clone(),
            name,
            public_key_hex: id.clone(),
            policy: rec.policy,
            ceiling: meta.ceiling,
            hostname: meta.hostname,
            os: meta.os,
            arch: meta.arch,
            version: meta.version,
            enrolled_unix: now,
            last_seen_unix: Some(now),
            owner: String::new(),
        };
        self.data.nodes.insert(id.clone(), node.clone());
        if let Err(err) = self.save() {
            self.data.nodes.remove(&id);
            self.data.pairing = pairing_before;
            return Err(err);
        }
        Ok(node)
    }

    pub fn touch(&mut self, id: &str) {
        if let Some(node) = self.data.nodes.get_mut(id) {
            node.last_seen_unix = Some(unix_now());
        }
    }

    pub fn set_policy(&mut self, query: &str, policy: NodePolicy) -> Result<EnrolledNode> {
        let id = self.resolve(query)?.id.clone();
        let node = self
            .data
            .nodes
            .get_mut(&id)
            .ok_or_else(|| Error::NotFound(format!("node '{query}'")))?;
        node.policy = policy;
        let cloned = node.clone();
        self.save()?;
        Ok(cloned)
    }

    pub fn resolve(&self, query: &str) -> Result<EnrolledNode> {
        if let Some(node) = self.data.nodes.get(query) {
            return Ok(node.clone());
        }
        let lower = query.to_ascii_lowercase();
        if let Some(node) = self.data.nodes.get(&lower) {
            return Ok(node.clone());
        }
        let matches: Vec<_> = self
            .data
            .nodes
            .values()
            .filter(|n| n.name == query)
            .cloned()
            .collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().expect("len checked")),
            0 => Err(Error::NotFound(format!("node '{query}'"))),
            _ => Err(Error::Ambiguous(query.to_string())),
        }
    }

    pub fn register_client(&mut self, name: &str, public_key: &str) -> Result<ClientRecord> {
        let id = public_key.trim().to_ascii_lowercase();
        if id.len() != 64 || !id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::Message(
                "client public key must be 64 hex characters".into(),
            ));
        }
        let name = name.trim();
        if name.is_empty() {
            return Err(Error::Message("client name is required".into()));
        }
        let record = if let Some(existing) = self.data.clients.get(&id) {
            let mut record = existing.clone();
            record.name = name.to_string();
            record.revoked = false;
            record
        } else {
            ClientRecord {
                id: id.clone(),
                name: name.to_string(),
                role: "agent".into(),
                revoked: false,
                grants: HashMap::new(),
            }
        };
        self.data.clients.insert(id, record.clone());
        self.save()?;
        Ok(record)
    }

    pub fn set_grant(
        &mut self,
        client_id: &str,
        node_id: &str,
        policy: NodePolicy,
    ) -> Result<ClientRecord> {
        let client_id = self.resolve_client(client_id)?.id.clone();
        let node = self.resolve(node_id)?;
        let record = self
            .data
            .clients
            .get_mut(&client_id)
            .ok_or_else(|| Error::NotFound(format!("client '{client_id}'")))?;
        if record.revoked {
            return Err(Error::Auth("client is revoked".into()));
        }
        record.grants.insert(node.id, policy);
        let cloned = record.clone();
        self.save()?;
        Ok(cloned)
    }

    pub fn revoke_client(&mut self, client_id: &str) -> Result<ClientRecord> {
        let client_id = self.resolve_client(client_id)?.id.clone();
        let record = self
            .data
            .clients
            .get_mut(&client_id)
            .ok_or_else(|| Error::NotFound(format!("client '{client_id}'")))?;
        record.revoked = true;
        record.grants.clear();
        let cloned = record.clone();
        self.save()?;
        Ok(cloned)
    }

    pub fn client(&self, client_id: &str) -> Result<ClientRecord> {
        self.resolve_client(client_id)
    }

    pub fn list_clients(&self) -> Vec<ClientRecord> {
        let mut clients: Vec<_> = self.data.clients.values().cloned().collect();
        clients.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        clients
    }

    pub fn set_audit_policy(&mut self, node_id: &str, toml: &str) -> Result<()> {
        let node = self.resolve(node_id)?;
        self.data.audit_policies.insert(node.id, toml.to_string());
        self.save()?;
        Ok(())
    }

    pub fn audit_policy(&self, node_id: &str) -> Option<String> {
        self.data.audit_policies.get(node_id).cloned()
    }

    fn resolve_client(&self, query: &str) -> Result<ClientRecord> {
        let lower = query.trim().to_ascii_lowercase();
        if let Some(client) = self.data.clients.get(&lower) {
            return Ok(client.clone());
        }
        let matches: Vec<_> = self
            .data
            .clients
            .values()
            .filter(|client| client.name == query || client.id == query)
            .cloned()
            .collect();
        match matches.len() {
            1 => Ok(matches.into_iter().next().expect("len checked")),
            0 => Err(Error::NotFound(format!("client '{query}'"))),
            _ => Err(Error::Ambiguous(query.to_string())),
        }
    }

    pub fn list(&self) -> Vec<EnrolledNode> {
        let mut nodes: Vec<_> = self.data.nodes.values().cloned().collect();
        nodes.sort_by(|a, b| a.name.cmp(&b.name).then(a.id.cmp(&b.id)));
        nodes
    }

    fn take_valid_token(&mut self, token: &str, now: i64) -> Option<PairingRecord> {
        let pos = self
            .data
            .pairing
            .iter()
            .position(|p| util::ct_eq(&p.token, token) && !p.used && p.expires_unix > now)?;
        let mut rec = self.data.pairing.remove(pos);
        rec.used = true;
        // Keep the used record so the same token cannot be inserted again by
        // a replay. `create_pairing` drops used records, which is fine: the
        // token string itself is not reusable once removed and marked.
        self.data.pairing.push(rec.clone());
        Some(rec)
    }

    fn save(&self) -> Result<()> {
        let text = serde_json::to_string_pretty(&self.data)?;
        util::write_secret(&self.path, text.as_bytes())?;
        self.write_admin_file()?;
        Ok(())
    }

    fn write_admin_file(&self) -> Result<()> {
        let Some(parent) = self.path.parent() else {
            return Ok(());
        };
        util::write_secret(
            &parent.join("admin.token"),
            self.data.admin_token.as_bytes(),
        )?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(name: &str) -> NodeMeta {
        NodeMeta {
            name: name.into(),
            hostname: "host".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: "0.1.0".into(),
            ceiling: NodePolicy::phase1_ceiling(),
        }
    }

    #[test]
    fn pairing_is_single_use_and_policy_updates() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::load(&dir.path().join("store.json")).unwrap();
        let issued = store
            .create_pairing("box", NodePolicy::read_only(), 600)
            .unwrap();
        let key = "ab".repeat(32);
        let node = store
            .enroll(Some(&issued.token), &key, meta("box"))
            .unwrap();
        assert_eq!(node.policy, NodePolicy::read_only());
        let err = store
            .enroll(Some(&issued.token), &"cd".repeat(32), meta("other"))
            .unwrap_err();
        assert!(err.to_string().contains("pairing"), "{err}");

        // Existing node reconnects with no token.
        let again = store.enroll(None, &key, meta("box")).unwrap();
        assert_eq!(again.id, node.id);

        let updated = store.set_policy("box", NodePolicy::exec()).unwrap();
        assert_eq!(updated.policy, NodePolicy::exec());
        // Stored preset is kept for the row. Connected use is full.
        assert_eq!(updated.effective(), NodePolicy::full());
    }
}
