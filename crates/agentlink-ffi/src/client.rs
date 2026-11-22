//! Admin client used by the phone UI.
//!
//! Bulk copies call [`agentlink_core::Client::copy_upload`] and
//! `copy_download`, which are the fast path: binary frames, a sliding window,
//! BLAKE3, zstd, and a direct QUIC attempt that falls back to the relay.

use std::collections::BTreeMap;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use agentlink_core::engine::XferOpts;
use agentlink_core::grant::SignedGrant;
use agentlink_core::protocol::Op;
use agentlink_core::{
    Client, ClientSettings, ExecRequest, Identity, NodePolicy, PtySession, PHASE2_INJECT_INPUT,
    PHASE2_SCREENSHOT, PHASE3_WEBRTC_SIGNAL,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::mpsc;

use crate::pty_pump::{pump_session, EventQueue, PtyCmd, WRITE_CMD_CAP};
use crate::LinkError;

#[derive(uniffi::Record, Clone)]
pub struct FfiPolicy {
    pub allow_read: bool,
    pub allow_write: bool,
    pub allow_exec: bool,
    pub allow_desktop: bool,
    pub allow_desktop_stream: bool,
    pub allow_remote_view: bool,
    pub allow_remote_control: bool,
}

impl From<NodePolicy> for FfiPolicy {
    fn from(policy: NodePolicy) -> Self {
        Self {
            allow_read: policy.allow_read,
            allow_write: policy.allow_write,
            allow_exec: policy.allow_exec,
            allow_desktop: policy.allow_desktop,
            allow_desktop_stream: policy.allow_desktop_stream,
            allow_remote_view: policy.allow_remote_view,
            allow_remote_control: policy.allow_remote_control,
        }
    }
}

impl From<FfiPolicy> for NodePolicy {
    fn from(policy: FfiPolicy) -> Self {
        Self {
            allow_read: policy.allow_read,
            allow_write: policy.allow_write,
            allow_exec: policy.allow_exec,
            allow_desktop: policy.allow_desktop,
            allow_desktop_stream: policy.allow_desktop_stream,
            allow_remote_view: policy.allow_remote_view,
            allow_remote_control: policy.allow_remote_control,
        }
    }
}

#[derive(uniffi::Record)]
pub struct MachineInfo {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub online: bool,
    pub preset: String,
    pub policy: FfiPolicy,
    pub owner: String,
    pub relation: String,
    pub access: String,
}

#[derive(uniffi::Record)]
pub struct FfiStat {
    pub path: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified_unix_ms: i64,
    pub readonly: bool,
}

#[derive(uniffi::Record)]
pub struct FfiEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified_unix_ms: i64,
}

#[derive(uniffi::Record)]
pub struct FfiStats {
    pub logical_bytes: u64,
    pub payload_bytes: u64,
    pub skipped: bool,
    pub files: u32,
    pub transport: String,
    pub resumed_bytes: u64,
}

#[derive(uniffi::Record)]
pub struct ExecDone {
    pub exit_code: i32,
    pub truncated: bool,
}

#[derive(uniffi::Record)]
pub struct FfiPairing {
    pub token: String,
    pub name: String,
    pub expires_unix: i64,
    pub policy: FfiPolicy,
}

#[uniffi::export(with_foreign)]
pub trait ProgressSink: Send + Sync {
    fn on_progress(&self, transferred: u64, total: u64);
}

#[uniffi::export(with_foreign)]
pub trait OutputSink: Send + Sync {
    /// Return false to cancel the remote command.
    fn on_output(&self, stream: String, data: Vec<u8>) -> bool;
}

/// Ed25519 device key. The phone wraps the seed with an Android Keystore AES
/// key and only returns a hex signature.
#[uniffi::export(with_foreign)]
pub trait KeySigner: Send + Sync {
    fn public_hex(&self) -> String;
    fn sign(&self, message: Vec<u8>) -> String;
}

#[derive(uniffi::Record)]
pub struct FfiLogin {
    pub user: String,
    pub role: String,
    pub device_id: String,
    pub access_token: String,
    pub access_expires_unix: i64,
    pub refresh_token: String,
    pub refresh_expires_unix: i64,
}

#[derive(uniffi::Record)]
pub struct FfiDevice {
    pub id: String,
    pub user: String,
    pub name: String,
    pub created_unix: i64,
    pub last_seen_unix: i64,
    pub revoked: bool,
}

#[derive(uniffi::Record)]
pub struct FfiNodePin {
    pub name: String,
    pub node_id: String,
}

#[derive(uniffi::Record)]
pub struct FfiGrant {
    pub node_id: String,
    pub grantee_id: String,
    pub issuer_id: String,
    pub jti: String,
    pub nbf_unix: i64,
    pub exp_unix: i64,
    pub preset: String,
    pub policy: FfiPolicy,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PinFile {
    #[serde(default)]
    nodes: BTreeMap<String, String>,
}

#[derive(uniffi::Object)]
pub struct MobileClient {
    handle: tokio::runtime::Handle,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
    settings: Arc<RwLock<ClientSettings>>,
    identity: ClientIdentity,
    client: Mutex<Option<Arc<Client>>>,
    connect_lock: Mutex<()>,
    pins: Option<PathBuf>,
    ice_servers: Mutex<Option<Vec<Value>>>,
}

enum ClientIdentity {
    File(PathBuf),
    External(Identity),
}

impl MobileClient {
    fn open(
        relay: String,
        token: String,
        fingerprint: String,
        data_dir: String,
    ) -> Result<Self, LinkError> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("agentlink-client")
            .build()
            .map_err(|e| LinkError::Fail {
                detail: format!("runtime: {e}"),
            })?;
        let handle = runtime.handle().clone();
        let identity_path = PathBuf::from(&data_dir).join("client-identity.json");
        if let Some(parent) = identity_path.parent() {
            std::fs::create_dir_all(parent).map_err(|err| LinkError::Fail {
                detail: format!("identity dir: {err}"),
            })?;
        }
        let pins = identity_path.parent().map(Path::to_path_buf);
        Self::open_with(
            runtime,
            handle,
            relay,
            token,
            fingerprint,
            ClientIdentity::File(identity_path),
            pins,
        )
    }

    fn open_with(
        runtime: tokio::runtime::Runtime,
        handle: tokio::runtime::Handle,
        relay: String,
        token: String,
        fingerprint: String,
        identity: ClientIdentity,
        pins: Option<PathBuf>,
    ) -> Result<Self, LinkError> {
        let mut relay = relay;
        let mut trust = None;
        crate::apply_mobile_relay_defaults(&mut relay, &fingerprint, &mut trust);
        Ok(Self {
            handle,
            runtime: Mutex::new(Some(runtime)),
            settings: Arc::new(RwLock::new(ClientSettings {
                relay,
                token,
                fingerprint,
                trust,
            })),
            identity,
            client: Mutex::new(None),
            connect_lock: Mutex::new(()),
            pins,
            ice_servers: Mutex::new(None),
        })
    }

    fn current_settings(&self) -> Result<ClientSettings, LinkError> {
        self.settings
            .read()
            .map(|guard| guard.clone())
            .map_err(|_| LinkError::Fail {
                detail: "client settings lock poisoned".into(),
            })
    }

    fn require_store_dir(&self) -> Result<PathBuf, LinkError> {
        self.pin_dir().ok_or_else(|| LinkError::Fail {
            detail: "client data directory is not configured".into(),
        })
    }

    fn pin_dir(&self) -> Option<PathBuf> {
        self.pins.clone()
    }

    fn open_external(
        relay: String,
        fingerprint: String,
        access_token: String,
        identity: Identity,
        data_dir: String,
    ) -> Result<Arc<Self>, LinkError> {
        if !data_dir.is_empty() {
            std::fs::create_dir_all(&data_dir).map_err(|err| LinkError::Fail {
                detail: format!("identity dir: {err}"),
            })?;
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("agentlink-client")
            .build()
            .map_err(|e| LinkError::Fail {
                detail: format!("runtime: {e}"),
            })?;
        let handle = runtime.handle().clone();
        let pins = if data_dir.is_empty() {
            None
        } else {
            Some(PathBuf::from(data_dir))
        };
        Ok(Arc::new(Self::open_with(
            runtime,
            handle,
            relay,
            access_token,
            fingerprint,
            ClientIdentity::External(identity),
            pins,
        )?))
    }

    fn load_identity(&self) -> Result<Identity, LinkError> {
        match &self.identity {
            ClientIdentity::File(path) => {
                Identity::load_or_create(path).map_err(|err| LinkError::Fail {
                    detail: err.to_string(),
                })
            }
            ClientIdentity::External(identity) => Ok(identity.clone()),
        }
    }

    fn session(&self) -> Result<Arc<Client>, LinkError> {
        {
            let guard = self.client.lock().map_err(|_| LinkError::Fail {
                detail: "client lock poisoned".into(),
            })?;
            if let Some(client) = guard.as_ref() {
                if client.is_alive() {
                    return Ok(client.clone());
                }
            }
        }
        // Serialize reconnects so concurrent callers do not open duplicate sockets.
        let _connecting = self.connect_lock.lock().map_err(|_| LinkError::Fail {
            detail: "client connect lock poisoned".into(),
        })?;
        {
            let guard = self.client.lock().map_err(|_| LinkError::Fail {
                detail: "client lock poisoned".into(),
            })?;
            if let Some(client) = guard.as_ref() {
                if client.is_alive() {
                    return Ok(client.clone());
                }
            }
        }
        let settings = self.current_settings()?;
        let identity = self.load_identity()?;
        let client = drive(&self.handle, async move {
            let use_token = !settings.token.is_empty();
            Client::connect_identity(&settings, identity, use_token).await
        })?;
        if let Some(dir) = self.pin_dir() {
            client.remember_node_pins(dir.clone());
            client.remember_grants(dir);
        }
        let client = Arc::new(client);
        let mut guard = self.client.lock().map_err(|_| LinkError::Fail {
            detail: "client lock poisoned".into(),
        })?;
        *guard = Some(client.clone());
        Ok(client)
    }
}

#[uniffi::export]
impl MobileClient {
    #[uniffi::constructor]
    pub fn connect(
        relay: String,
        token: String,
        fingerprint: String,
        data_dir: String,
    ) -> Result<Arc<Self>, LinkError> {
        Ok(Arc::new(Self::open(relay, token, fingerprint, data_dir)?))
    }

    /// Open a session that signs with the Keystore device key.
    #[uniffi::constructor]
    pub fn connect_user(
        relay: String,
        fingerprint: String,
        access_token: String,
        signer: Arc<dyn KeySigner>,
        data_dir: String,
    ) -> Result<Arc<Self>, LinkError> {
        let identity = identity_from_signer(signer);
        Self::open_external(relay, fingerprint, access_token, identity, data_dir)
    }

    pub fn list_machines(&self) -> Result<Vec<MachineInfo>, LinkError> {
        let client = self.session()?;
        let nodes = drive(&self.handle, async move { client.list_nodes().await })?;
        Ok(nodes
            .into_iter()
            .map(|node| MachineInfo {
                id: node.id,
                name: node.name,
                hostname: node.hostname,
                os: node.os,
                arch: node.arch,
                version: node.version,
                online: node.online,
                preset: node.effective.preset_name().to_string(),
                policy: node.effective.into(),
                owner: node.owner,
                relation: node.relation,
                access: node.access,
            })
            .collect())
    }

    pub fn stat_path(&self, node: String, path: String) -> Result<FfiStat, LinkError> {
        let client = self.session()?;
        let stat = drive(&self.handle, async move { client.stat(&node, &path).await })?;
        Ok(FfiStat {
            path: stat.path,
            is_dir: stat.is_dir,
            is_file: stat.is_file,
            is_symlink: stat.is_symlink,
            size: stat.size,
            modified_unix_ms: stat.modified_unix_ms.unwrap_or(0),
            readonly: stat.readonly,
        })
    }

    pub fn list_dir(&self, node: String, path: String) -> Result<Vec<FfiEntry>, LinkError> {
        let client = self.session()?;
        let entries = drive(
            &self.handle,
            async move { client.list_dir(&node, &path).await },
        )?;
        Ok(entries
            .into_iter()
            .map(|entry| FfiEntry {
                name: entry.name,
                is_dir: entry.is_dir,
                is_file: entry.is_file,
                is_symlink: entry.is_symlink,
                size: entry.size,
                modified_unix_ms: entry.modified_unix_ms.unwrap_or(0),
            })
            .collect())
    }

    pub fn read_bytes(
        &self,
        node: String,
        path: String,
        offset: u64,
        max_bytes: u64,
    ) -> Result<Vec<u8>, LinkError> {
        let max_bytes = max_bytes.clamp(1, 8 * 1024 * 1024);
        let client = self.session()?;
        drive(&self.handle, async move {
            let mut buf = Vec::new();
            client
                .stream_download(
                    &node,
                    &path,
                    offset,
                    Some(max_bytes),
                    &mut buf,
                    &xfer_opts(true),
                )
                .await?;
            Ok(buf)
        })
    }

    pub fn write_bytes(&self, node: String, path: String, data: Vec<u8>) -> Result<(), LinkError> {
        let client = self.session()?;
        drive(&self.handle, async move {
            let mut cursor = Cursor::new(data);
            client
                .stream_upload(&node, &path, &mut cursor, &xfer_opts(true))
                .await?;
            Ok(())
        })
    }

    pub fn mkdir(&self, node: String, path: String, recursive: bool) -> Result<(), LinkError> {
        let client = self.session()?;
        drive(&self.handle, async move {
            client.mkdir(&node, &path, recursive).await?;
            Ok(())
        })
    }

    pub fn remove(&self, node: String, path: String, recursive: bool) -> Result<(), LinkError> {
        let client = self.session()?;
        drive(&self.handle, async move {
            client.remove(&node, &path, recursive).await?;
            Ok(())
        })
    }

    pub fn rename(&self, node: String, from: String, to: String) -> Result<(), LinkError> {
        let client = self.session()?;
        drive(&self.handle, async move {
            let _ = client.rename(&node, &from, &to).await?;
            Ok(())
        })
    }

    pub fn exec(
        &self,
        node: String,
        program: String,
        args: Vec<String>,
        cwd: Option<String>,
        env: Vec<String>,
        shell: bool,
        timeout_ms: u64,
        sink: Arc<dyn OutputSink>,
    ) -> Result<ExecDone, LinkError> {
        let client = self.session()?;
        let truncated = Arc::new(AtomicBool::new(false));
        let flag = truncated.clone();
        let env = parse_env(env)?;
        let timeout = if timeout_ms == 0 {
            None
        } else {
            Some(Duration::from_millis(timeout_ms))
        };
        let code = drive(&self.handle, async move {
            client
                .exec_streaming(
                    &node,
                    ExecRequest {
                        program,
                        args,
                        cwd,
                        env,
                        timeout,
                        shell,
                        stdin: None,
                    },
                    move |stream, data| {
                        let keep = sink.on_output(stream.to_string(), data.to_vec());
                        if !keep {
                            flag.store(true, Ordering::Relaxed);
                        }
                        keep
                    },
                )
                .await
        })?;
        Ok(ExecDone {
            exit_code: code.unwrap_or(-1),
            truncated: truncated.load(Ordering::Relaxed),
        })
    }

    pub fn transfer_up(
        &self,
        node: String,
        remote: String,
        local: String,
        prefer_direct: bool,
        sink: Arc<dyn ProgressSink>,
    ) -> Result<FfiStats, LinkError> {
        let client = self.session()?;
        let stats = drive(&self.handle, async move {
            let progress: Option<Arc<dyn Fn(u64, u64) + Send + Sync>> =
                Some(Arc::new(move |done, total| sink.on_progress(done, total)));
            client
                .copy_upload(
                    &node,
                    &remote,
                    Path::new(&local),
                    &xfer_opts(prefer_direct),
                    progress,
                )
                .await
        })?;
        Ok(stats_of(stats))
    }

    pub fn transfer_down(
        &self,
        node: String,
        remote: String,
        local: String,
        prefer_direct: bool,
        sink: Arc<dyn ProgressSink>,
    ) -> Result<FfiStats, LinkError> {
        let client = self.session()?;
        let stats = drive(&self.handle, async move {
            let progress: Option<Arc<dyn Fn(u64, u64) + Send + Sync>> =
                Some(Arc::new(move |done, total| sink.on_progress(done, total)));
            client
                .copy_download(
                    &node,
                    &remote,
                    Path::new(&local),
                    &xfer_opts(prefer_direct),
                    progress,
                )
                .await
        })?;
        Ok(stats_of(stats))
    }

    pub fn extension(
        &self,
        node: String,
        name: String,
        payload_json: String,
    ) -> Result<String, LinkError> {
        let payload: Value = serde_json::from_str(&payload_json).map_err(|err| LinkError::Fail {
            detail: format!("invalid extension payload json: {err}"),
        })?;
        let client = self.session()?;
        let body = drive(&self.handle, async move {
            client.call_op(&node, Op::Extension { name, payload }).await
        })?;
        Ok(body.to_string())
    }

    pub fn set_policy(&self, node: String, policy: FfiPolicy) -> Result<FfiPolicy, LinkError> {
        let client = self.session()?;
        let updated = drive(&self.handle, async move {
            client.set_policy(&node, policy.into()).await
        })?;
        Ok(updated.into())
    }

    pub fn create_pairing(
        &self,
        name: String,
        policy: FfiPolicy,
        ttl_secs: u64,
    ) -> Result<FfiPairing, LinkError> {
        let client = self.session()?;
        let issued = drive(&self.handle, async move {
            client
                .create_pairing_token(&name, policy.into(), ttl_secs.max(60))
                .await
        })?;
        Ok(FfiPairing {
            token: issued.token,
            name: issued.name,
            expires_unix: issued.expires_unix,
            policy: issued.policy.into(),
        })
    }

    pub fn pty_open(
        &self,
        node: String,
        command: Option<String>,
        rows: u16,
        cols: u16,
    ) -> Result<Arc<PtyHandle>, LinkError> {
        let client = self.session()?;
        let handle = self.handle.clone();
        let session = drive(&self.handle, async move {
            client
                .open_pty(&node, command, None, rows.max(1), cols.max(1))
                .await
        })?;
        Ok(PtyHandle::spawn(handle, session))
    }

    pub fn logout(&self, refresh_token: String) -> Result<(), LinkError> {
        let client = self.session()?;
        let refresh = if refresh_token.is_empty() {
            None
        } else {
            Some(refresh_token)
        };
        drive(
            &self.handle,
            async move { client.logout_session(refresh).await },
        )?;
        Ok(())
    }

    pub fn list_devices(&self) -> Result<Vec<FfiDevice>, LinkError> {
        let client = self.session()?;
        let devices = drive(&self.handle, async move { client.list_devices().await })?;
        Ok(devices
            .into_iter()
            .map(|device| FfiDevice {
                id: device.id,
                user: device.user,
                name: device.name,
                created_unix: device.created_unix,
                last_seen_unix: device.last_seen_unix,
                revoked: device.revoked,
            })
            .collect())
    }

    /// Enroll the phone's node key under the logged-in user. No pairing token.
    pub fn enroll_self(&self, name: String, node_data_dir: String) -> Result<(), LinkError> {
        let client = self.session()?;
        let identity =
            Identity::load_or_create(&PathBuf::from(&node_data_dir).join("identity.json"))
                .map_err(|err| LinkError::Fail {
                    detail: err.to_string(),
                })?;
        drive(&self.handle, async move {
            client.enroll_self(&name, &identity, None).await.map(|_| ())
        })?;
        Ok(())
    }

    /// Update the access token used on future reconnects and relay API calls
    /// without interrupting active PTY, live desktop, or file transfer sessions.
    pub fn update_access_token(&self, token: String) -> Result<(), LinkError> {
        let mut guard = self.settings.write().map_err(|_| LinkError::Fail {
            detail: "client settings lock poisoned".into(),
        })?;
        guard.token = token;
        Ok(())
    }

    pub fn revoke_device(&self, device_id: String) -> Result<(), LinkError> {
        let client = self.session()?;
        drive(&self.handle, async move {
            client.revoke_device(&device_id).await
        })?;
        Ok(())
    }

    pub fn list_node_pins(&self) -> Result<Vec<FfiNodePin>, LinkError> {
        let dir = self.require_store_dir()?;
        let path = agentlink_core::node_pin::pin_path(&dir);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = std::fs::read_to_string(&path).map_err(|err| LinkError::Fail {
            detail: format!("node-pins.json: {err}"),
        })?;
        let file = serde_json::from_str::<PinFile>(&text).map_err(|err| LinkError::Fail {
            detail: format!("node-pins.json: {err}"),
        })?;
        Ok(file
            .nodes
            .into_iter()
            .map(|(name, node_id)| FfiNodePin { name, node_id })
            .collect())
    }

    pub fn clear_node_pin(&self, name: String) -> Result<bool, LinkError> {
        let target = name.trim();
        if target.is_empty() {
            return Ok(false);
        }
        let dir = self.require_store_dir()?;
        let path = agentlink_core::node_pin::pin_path(&dir);
        if !path.exists() {
            return Ok(false);
        }
        let text = std::fs::read_to_string(&path).map_err(|err| LinkError::Fail {
            detail: format!("node-pins.json: {err}"),
        })?;
        let mut file = serde_json::from_str::<PinFile>(&text).map_err(|err| LinkError::Fail {
            detail: format!("node-pins.json: {err}"),
        })?;
        let removed = if file.nodes.remove(target).is_some() {
            true
        } else if let Some(found) = file
            .nodes
            .keys()
            .find(|key| key.eq_ignore_ascii_case(target))
            .cloned()
        {
            file.nodes.remove(&found).is_some()
        } else {
            false
        };
        if removed {
            let encoded = serde_json::to_string_pretty(&file).map_err(|err| LinkError::Fail {
                detail: format!("encode node-pins.json: {err}"),
            })?;
            agentlink_core::util::write_secret(&path, encoded.as_bytes()).map_err(|err| {
                LinkError::Fail {
                    detail: format!("write node-pins.json: {err}"),
                }
            })?;
        }
        Ok(removed)
    }

    pub fn node_pin_warnings(&self) -> Vec<String> {
        self.client
            .lock()
            .ok()
            .and_then(|guard| guard.as_ref().map(|c| c.node_pin_warnings()))
            .unwrap_or_default()
    }

    pub fn list_grants(&self) -> Result<Vec<FfiGrant>, LinkError> {
        let dir = self.require_store_dir()?;
        let stored = agentlink_core::grant::list_stored_grants(&dir).map_err(|err| {
            LinkError::Fail {
                detail: err.to_string(),
            }
        })?;
        Ok(stored
            .into_iter()
            .map(|item| ffi_grant_of(&item.grant))
            .collect())
    }

    pub fn import_grant(&self, grant_json: String) -> Result<FfiGrant, LinkError> {
        let dir = self.require_store_dir()?;
        let grant: SignedGrant =
            serde_json::from_str(grant_json.trim()).map_err(|err| LinkError::Fail {
                detail: format!("invalid grant json: {err}"),
            })?;
        if grant.node_id.trim().is_empty()
            || grant.grantee_id.trim().is_empty()
            || grant.issuer_id.trim().is_empty()
            || grant.jti.trim().is_empty()
            || grant.sig_hex.trim().is_empty()
        {
            return Err(LinkError::Fail {
                detail: "grant is missing required fields".into(),
            });
        }
        let identity = self.load_identity()?;
        agentlink_core::grant::validate_grant_for(
            &grant,
            &grant.node_id,
            identity.public_hex(),
            agentlink_core::util::unix_now(),
        )
        .map_err(|err| LinkError::Fail {
            detail: err.to_string(),
        })?;
        agentlink_core::grant::save_grant(&dir, &grant).map_err(|err| LinkError::Fail {
            detail: err.to_string(),
        })?;
        Ok(ffi_grant_of(&grant))
    }

    pub fn delete_grant(&self, node_id: String) -> Result<bool, LinkError> {
        let dir = self.require_store_dir()?;
        agentlink_core::grant::delete_grant(&dir, &node_id).map_err(|err| LinkError::Fail {
            detail: err.to_string(),
        })
    }

    pub fn find_files(
        &self,
        node: String,
        path: String,
        pattern: String,
        regex: bool,
        include_hidden: bool,
        case_insensitive: bool,
        limit: u32,
    ) -> Result<String, LinkError> {
        let client = self.session()?;
        let value = drive(&self.handle, async move {
            client
                .find(
                    &node,
                    &path,
                    &pattern,
                    regex,
                    true,
                    include_hidden,
                    case_insensitive,
                    0,
                    limit,
                )
                .await
        })?;
        Ok(value.to_string())
    }

    pub fn search_content(
        &self,
        node: String,
        path: String,
        pattern: String,
        literal: bool,
        include_hidden: bool,
        case_insensitive: bool,
        limit: u32,
    ) -> Result<String, LinkError> {
        let client = self.session()?;
        let value = drive(&self.handle, async move {
            client
                .search(
                    &node,
                    &path,
                    &pattern,
                    literal,
                    Vec::new(),
                    Vec::new(),
                    true,
                    include_hidden,
                    case_insensitive,
                    0,
                    0,
                    0,
                    limit,
                )
                .await
        })?;
        Ok(value.to_string())
    }

    pub fn query_audit(&self, node_id: String, limit: u32) -> Result<String, LinkError> {
        let client = self.session()?;
        let filter = json!({
            "node_id": node_id,
            "limit": limit.clamp(1, 500),
        });
        let records = drive(&self.handle, async move { client.query_audit(filter).await })?;
        Ok(Value::Array(records).to_string())
    }

    pub fn sys_info(&self, node: String) -> Result<String, LinkError> {
        let client = self.session()?;
        let value = drive(&self.handle, async move { client.sysinfo(&node).await })?;
        Ok(value.to_string())
    }

    /// Override or clear (`""`) the ICE/TURN servers used by [`Self::open_live`].
    pub fn set_ice_servers(&self, ice_servers_json: String) -> Result<(), LinkError> {
        let trimmed = ice_servers_json.trim();
        let next = if trimmed.is_empty() {
            None
        } else {
            let parsed: Value = serde_json::from_str(trimmed).map_err(|err| LinkError::Fail {
                detail: format!("invalid ice_servers json: {err}"),
            })?;
            Some(crate::live::parse_ice_document(&parsed))
        };
        let mut guard = self.ice_servers.lock().map_err(|_| LinkError::Fail {
            detail: "ice_servers lock poisoned".into(),
        })?;
        *guard = next;
        Ok(())
    }

    /// Fetch fresh ICE/TURN servers from the relay (`/api/ice` with fallback to
    /// `/view/config.json`) using the current relay settings and access token.
    pub fn refresh_ice_servers(&self) -> Result<String, LinkError> {
        let settings = self.current_settings()?;
        let fetched = drive(&self.handle, async move {
            Ok(crate::live::fetch_ice_servers(&settings).await)
        })?;
        let encoded = Value::Array(fetched.clone()).to_string();
        if let Ok(mut guard) = self.ice_servers.lock() {
            *guard = Some(fetched);
        }
        Ok(encoded)
    }

    /// Open the phase-3 desktop stream. The returned object depacketizes
    /// RTP H.264 to Annex-B. Screenshot polling stays in the UI and runs
    /// only when this returns an error.
    pub fn open_live(
        &self,
        node: String,
        max_fps: u32,
        bitrate: u32,
        monitor: u32,
    ) -> Result<Arc<crate::live::DesktopLive>, LinkError> {
        let client = self.session()?;
        let cached = self
            .ice_servers
            .lock()
            .ok()
            .and_then(|guard| guard.clone());
        let settings = self.current_settings()?;
        let ice_servers = match cached {
            Some(servers) => servers,
            None => {
                let initial_settings = settings.clone();
                drive(&self.handle, async move {
                    Ok(crate::live::fetch_ice_servers(&initial_settings).await)
                })
                .unwrap_or_default()
            }
        };
        let refresh_handle = self.handle.clone();
        let refresh_settings = Arc::clone(&self.settings);
        let ice_refresh: Arc<dyn Fn() -> Vec<Value> + Send + Sync> = Arc::new(move || {
            let Ok(settings) = refresh_settings.read().map(|guard| guard.clone()) else {
                return Vec::new();
            };
            let (tx, rx) = std::sync::mpsc::sync_channel(1);
            refresh_handle.spawn(async move {
                let servers = crate::live::fetch_ice_servers(&settings).await;
                let _ = tx.send(servers);
            });
            rx.recv_timeout(Duration::from_secs(5)).unwrap_or_default()
        });
        crate::live::open(
            client,
            self.handle.clone(),
            node,
            max_fps,
            bitrate,
            monitor,
            ice_servers,
            Some(ice_refresh),
        )
    }
}

fn ffi_grant_of(grant: &SignedGrant) -> FfiGrant {
    FfiGrant {
        node_id: grant.node_id.clone(),
        grantee_id: grant.grantee_id.clone(),
        issuer_id: grant.issuer_id.clone(),
        jti: grant.jti.clone(),
        nbf_unix: grant.nbf_unix,
        exp_unix: grant.exp_unix,
        preset: grant.policy.preset_name().to_string(),
        policy: grant.policy.into(),
    }
}

#[uniffi::export]
pub fn login_account(
    relay: String,
    fingerprint: String,
    username: String,
    password: String,
    totp: String,
    device_name: String,
    signer: Arc<dyn KeySigner>,
) -> Result<FfiLogin, LinkError> {
    let identity = identity_from_signer(signer);
    let totp = totp.trim().to_string();
    let (relay, fingerprint, trust) = relay_defaults(relay, fingerprint);
    let session = block_on(async move {
        agentlink_core::client::login_user(
            &relay,
            &fingerprint,
            trust.as_deref(),
            &identity,
            &username,
            &password,
            if totp.is_empty() {
                None
            } else {
                Some(totp.as_str())
            },
            &device_name,
        )
        .await
    })?;
    Ok(login_record(session))
}

#[uniffi::export]
pub fn refresh_account(
    relay: String,
    fingerprint: String,
    refresh_token: String,
    signer: Arc<dyn KeySigner>,
) -> Result<FfiLogin, LinkError> {
    let identity = identity_from_signer(signer);
    let (relay, fingerprint, trust) = relay_defaults(relay, fingerprint);
    let session = block_on(async move {
        agentlink_core::client::refresh_user(
            &relay,
            &fingerprint,
            trust.as_deref(),
            &identity,
            &refresh_token,
        )
        .await
    })?;
    Ok(login_record(session))
}

fn relay_defaults(relay: String, fingerprint: String) -> (String, String, Option<String>) {
    let mut relay = relay;
    let mut trust = None;
    crate::apply_mobile_relay_defaults(&mut relay, &fingerprint, &mut trust);
    (relay, fingerprint, trust)
}

fn login_record(session: agentlink_core::client::UserSession) -> FfiLogin {
    FfiLogin {
        user: session.user,
        role: session.role,
        device_id: session.device_id,
        access_token: session.access_token,
        access_expires_unix: session.access_expires_unix,
        refresh_token: session.refresh_token,
        refresh_expires_unix: session.refresh_expires_unix,
    }
}

fn identity_from_signer(signer: Arc<dyn KeySigner>) -> Identity {
    let public_hex = signer.public_hex();
    Identity::from_external(
        public_hex,
        Arc::new(move |message: &[u8]| signer.sign(message.to_vec())),
    )
}

fn block_on<T: Send + 'static>(
    fut: impl std::future::Future<Output = agentlink_core::Result<T>> + Send + 'static,
) -> Result<T, LinkError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| LinkError::Fail {
            detail: format!("runtime: {err}"),
        })?;
    runtime.block_on(fut).map_err(|err| LinkError::Fail {
        detail: err.to_string(),
    })
}

impl Drop for MobileClient {
    fn drop(&mut self) {
        self.client.lock().ok().map(|mut g| g.take());
        if let Some(runtime) = self.runtime.lock().ok().and_then(|mut g| g.take()) {
            runtime.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

#[derive(uniffi::Object)]
pub struct PtyHandle {
    cmd: mpsc::Sender<PtyCmd>,
    events: Arc<EventQueue>,
}

impl PtyHandle {
    fn spawn(handle: tokio::runtime::Handle, session: PtySession) -> Arc<Self> {
        let (cmd, cmd_rx) = mpsc::channel(WRITE_CMD_CAP);
        let events = Arc::new(EventQueue::new());
        let queue = events.clone();
        let writer = session.writer();
        handle.spawn(async move {
            // Input-first, pinned recv, bounded lossless queue (see docs and pty_pump.rs).
            pump_session(cmd_rx, session, writer, queue).await;
        });
        Arc::new(Self { cmd, events })
    }
}

fn send_cmd(cmd: &mpsc::Sender<PtyCmd>, value: PtyCmd) -> Result<(), LinkError> {
    cmd.try_send(value).map_err(|err| match err {
        mpsc::error::TrySendError::Full(_) => LinkError::Fail {
            detail: "shell input queue is full".into(),
        },
        mpsc::error::TrySendError::Closed(_) => LinkError::Fail {
            detail: "shell session closed".into(),
        },
    })
}

#[uniffi::export]
impl PtyHandle {
    pub fn poll(&self) -> String {
        self.events
            .pop()
            .unwrap_or_else(|| json!({"event":"pending"}).to_string())
    }

    pub fn write(&self, data: Vec<u8>) -> Result<(), LinkError> {
        send_cmd(&self.cmd, PtyCmd::Write(data))
    }

    pub fn resize(&self, rows: u16, cols: u16) -> Result<(), LinkError> {
        send_cmd(&self.cmd, PtyCmd::Resize(rows, cols))
    }

    pub fn shutdown(&self) {
        let _ = self.cmd.try_send(PtyCmd::Close);
        self.events.close();
    }
}

fn stats_of(stats: agentlink_core::protocol::TransferStats) -> FfiStats {
    FfiStats {
        logical_bytes: stats.logical_bytes,
        payload_bytes: stats.payload_bytes,
        skipped: stats.skipped,
        files: stats.files,
        transport: stats.transport,
        resumed_bytes: stats.resumed_bytes,
    }
}

fn xfer_opts(prefer_direct: bool) -> XferOpts {
    XferOpts {
        transport: if prefer_direct {
            "relay".into()
        } else {
            "relay-only".into()
        },
        ..XferOpts::default()
    }
}

fn parse_env(pairs: Vec<String>) -> Result<Vec<(String, String)>, LinkError> {
    let mut out = Vec::new();
    for pair in pairs {
        let Some((key, value)) = pair.split_once('=') else {
            return Err(LinkError::Fail {
                detail: format!("env entry '{pair}' must be KEY=VALUE"),
            });
        };
        if key.is_empty() {
            return Err(LinkError::Fail {
                detail: "env key is empty".into(),
            });
        }
        out.push((key.to_string(), value.to_string()));
    }
    Ok(out)
}

pub fn known_extensions() -> Vec<String> {
    vec![
        PHASE2_SCREENSHOT.to_string(),
        PHASE2_INJECT_INPUT.to_string(),
        PHASE3_WEBRTC_SIGNAL.to_string(),
    ]
}

fn drive<T: Send + 'static>(
    handle: &tokio::runtime::Handle,
    fut: impl std::future::Future<Output = agentlink_core::Result<T>> + Send + 'static,
) -> Result<T, LinkError> {
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    handle.spawn(async move {
        let _ = tx.send(fut.await);
    });
    match rx.recv() {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(err)) => Err(LinkError::Fail {
            detail: err.to_string(),
        }),
        Err(_) => Err(LinkError::Fail {
            detail: "client runtime stopped".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mobile_client_pins_grants_token_update_and_json_validation() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().display().to_string();
        let client = MobileClient::connect(
            "wss://127.0.0.1:7443".into(),
            "old-token".into(),
            "system".into(),
            data_dir,
        )
        .unwrap();

        // 1. update_access_token updates settings in-place without dropping state.
        client.update_access_token("new-token".into()).unwrap();
        assert_eq!(client.current_settings().unwrap().token, "new-token");

        // 2. extension() rejects invalid JSON before touching the network.
        let err = client
            .extension("node-1".into(), "screenshot".into(), "{bad json".into())
            .unwrap_err();
        assert!(err.to_string().contains("invalid extension payload json"), "{err}");

        // 3. set_ice_servers rejects invalid JSON and accepts valid ICE documents.
        assert!(client.set_ice_servers("{not-json".into()).is_err());
        client
            .set_ice_servers(r#"[{"urls":["stun:stun.example:3478"]}]"#.into())
            .unwrap();
        assert_eq!(
            client.ice_servers.lock().unwrap().as_ref().map(Vec::len),
            Some(1)
        );
        client.set_ice_servers(String::new()).unwrap();
        assert!(client.ice_servers.lock().unwrap().is_none());

        // 4. list_node_pins / clear_node_pin roundtrip on node-pins.json.
        let node_id = "ab".repeat(32);
        agentlink_core::node_pin::observe(dir.path(), "laptop", &node_id).unwrap();
        let pins = client.list_node_pins().unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].name, "laptop");
        assert_eq!(pins[0].node_id, node_id);
        assert!(client.clear_node_pin("LAPTOP".into()).unwrap());
        assert!(!client.clear_node_pin("laptop".into()).unwrap());
        assert!(client.list_node_pins().unwrap().is_empty());

        // 5. import_grant / list_grants / delete_grant roundtrip.
        let issuer = Identity::generate();
        let grantee = client.load_identity().unwrap().public_hex().to_string();
        let now = agentlink_core::util::unix_now();
        let signed = SignedGrant::sign(
            &issuer,
            &grantee,
            &node_id,
            NodePolicy::read_only(),
            now - 10,
            now + 3600,
            "jti-ffi-test",
        )
        .unwrap();
        let grant_json = serde_json::to_string(&signed).unwrap();
        let imported = client.import_grant(grant_json).unwrap();
        assert_eq!(imported.node_id, node_id);
        assert_eq!(imported.jti, "jti-ffi-test");
        let listed = client.list_grants().unwrap();
        assert_eq!(listed.len(), 1);
        assert!(client.delete_grant(node_id.clone()).unwrap());
        assert!(client.list_grants().unwrap().is_empty());
    }

    #[test]
    fn empty_fingerprint_defaults_to_system_webpki_for_mobile_client_and_login() {
        let (relay, fp, trust) = relay_defaults(" wss://relay.example.com ".into(), String::new());
        assert_eq!(relay, "wss://relay.example.com");
        assert_eq!(fp, "");
        assert_eq!(trust.as_deref(), Some(agentlink_core::DEFAULT_RELAY_TRUST));
        assert!(agentlink_core::RelayTrust::parse(&fp, trust.as_deref()).is_ok());

        let leaf = format!("sha256:{}", "ab".repeat(32));
        let (_relay2, fp2, trust2) =
            relay_defaults("wss://relay.example.com".into(), leaf.clone());
        assert_eq!(fp2, leaf);
        assert!(trust2.is_none());

        let dir = tempfile::tempdir().unwrap();
        let client = MobileClient::connect(
            "wss://relay.example.com".into(),
            "tok".into(),
            String::new(),
            dir.path().display().to_string(),
        )
        .unwrap();
        let settings = client.current_settings().unwrap();
        assert_eq!(settings.fingerprint, "");
        assert_eq!(
            settings.trust.as_deref(),
            Some(agentlink_core::DEFAULT_RELAY_TRUST)
        );
    }
}
