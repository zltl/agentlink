//! Rows the relay keeps in SQLite or PostgreSQL.

use std::collections::HashMap;

use agentlink_core::NodePolicy;
use serde::{Deserialize, Serialize};

use agentlink_core::protocol::{ClientGrant, ClientInfo, NodeInfo};

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
    /// `Some(true)` when the node last reported a graphical session.
    /// `Some(false)` is headless. `None` means it has not reported.
    #[serde(default)]
    pub has_display: Option<bool>,
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

#[derive(Debug, Clone)]
pub struct NodeMeta {
    pub name: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub ceiling: NodePolicy,
    /// `None` leaves a stored report unchanged.
    pub has_display: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRecord {
    pub id: String,
    pub name: String,
    pub role: String,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub grants: HashMap<String, NodePolicy>,
    #[serde(default)]
    pub owner: String,
}

impl ClientRecord {
    pub fn info(self) -> ClientInfo {
        ClientInfo {
            id: self.id,
            name: self.name,
            role: self.role,
            revoked: self.revoked,
            grants: self
                .grants
                .into_iter()
                .map(|(node_id, policy)| ClientGrant { node_id, policy })
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IssuedToken {
    pub id: String,
    pub token: String,
    pub name: String,
    pub expires_unix: i64,
    pub policy: NodePolicy,
    pub uses: u32,
    pub owner: String,
}

#[derive(Debug, Clone)]
pub struct TokenView {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub policy: NodePolicy,
    pub created_unix: i64,
    pub expires_unix: i64,
    pub max_uses: u32,
    pub uses_remaining: u32,
    pub revoked: bool,
}

impl TokenView {
    pub fn state(&self, now: i64) -> &'static str {
        if self.revoked {
            "revoked"
        } else if self.expires_unix <= now {
            "expired"
        } else if self.uses_remaining == 0 {
            "used"
        } else {
            "pending"
        }
    }
}

#[derive(Debug, Clone)]
pub struct UserAccount {
    pub username: String,
    pub role: String,
    pub disabled: bool,
    pub created_unix: i64,
    pub totp_enabled: bool,
    pub failed_attempts: u32,
    pub locked_until_unix: i64,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub id: String,
    pub user: String,
    pub name: String,
    pub created_unix: i64,
    pub last_seen_unix: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone)]
pub struct IssuedSession {
    pub user: String,
    pub role: String,
    pub device_id: String,
    pub access_token: String,
    pub access_expires_unix: i64,
    pub refresh_token: String,
    pub refresh_expires_unix: i64,
}

#[derive(Debug, Clone)]
pub struct AccessSession {
    pub user: String,
    pub role: String,
    pub device_id: String,
    pub token_hash: String,
    pub expires_unix: i64,
}

#[derive(Debug, Clone)]
pub struct WebSession {
    pub user: String,
    pub role: String,
    pub csrf: String,
    pub expires_unix: i64,
}

#[derive(Debug, Clone)]
pub struct Caller {
    pub user: String,
    pub admin: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    Owner,
    Shared,
    Admin,
}

impl Relation {
    pub fn as_str(self) -> &'static str {
        match self {
            Relation::Owner => "owner",
            Relation::Shared => "shared",
            Relation::Admin => "admin",
        }
    }
}

#[derive(Debug, Clone)]
pub struct VisibleNode {
    pub node: EnrolledNode,
    pub access: NodePolicy,
    pub relation: Relation,
}

impl VisibleNode {
    pub fn info(&self, online: bool) -> NodeInfo {
        NodeInfo {
            id: self.node.id.clone(),
            name: self.node.name.clone(),
            hostname: self.node.hostname.clone(),
            os: self.node.os.clone(),
            arch: self.node.arch.clone(),
            version: self.node.version.clone(),
            online,
            policy: self.node.policy,
            effective: self.access,
            owner: self.node.owner.clone(),
            relation: self.relation.as_str().to_string(),
            access: self.access.preset_name().to_string(),
            has_display: self.node.has_display,
        }
    }
}
