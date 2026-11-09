//! Android bindings for agentlink.
//!
//! The phone runs the same protocol as the desktop node and client. Bulk file
//! copies use the fast-transfer engine in `agentlink-core` (binary frames,
//! sliding window, BLAKE3, zstd, QUIC with relay fallback). Screen capture,
//! accessibility input, SAF folders, and the app-sandbox shell are supplied
//! by the Kotlin host.

mod audit;
mod client;
mod files;
mod host;
mod live;
mod node;
mod paths;
mod pty;
mod resume;
mod tools;
mod transfer;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentlink_core::{apply_relay_defaults, Identity, NodePolicy, PROTOCOL_VERSION};
use tokio_util::sync::CancellationToken;

pub use client::{
    ExecDone, FfiEntry, FfiPairing, FfiPolicy, FfiStat, FfiStats, MachineInfo, MobileClient,
    OutputSink, ProgressSink, PtyHandle,
};
pub use host::{host_err, host_ok, NodeHost};
pub use node::{serve_node, NodeIo, ServeConfig};

uniffi::setup_scaffolding!();

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum LinkError {
    #[error("{detail}")]
    Fail { detail: String },
}

#[derive(uniffi::Record)]
pub struct NodeOptions {
    pub relay_url: String,
    pub fingerprint: String,
    pub data_dir: String,
    pub files_dir: String,
    pub cache_dir: String,
    /// Empty when all-files access is not granted.
    pub storage_dir: String,
    pub name: String,
    pub pairing_token: String,
    pub hostname: String,
    pub arch: String,
    pub version: String,
    pub allow_read: bool,
    pub allow_write: bool,
    pub allow_exec: bool,
    pub allow_desktop: bool,
    pub allow_desktop_stream: bool,
    /// Watch the screen. Set with the live-stream consent choice.
    pub allow_remote_view: bool,
    /// Pointer, keyboard, and clipboard on a stream. Implies view.
    pub allow_remote_control: bool,
}

#[derive(uniffi::Object)]
pub struct MobileNode {
    shutdown: CancellationToken,
    io: NodeIo,
    audit_path: PathBuf,
    runtime: Mutex<Option<tokio::runtime::Runtime>>,
}

#[uniffi::export]
impl MobileNode {
    #[uniffi::constructor]
    pub fn start(opts: NodeOptions, host: Arc<dyn NodeHost>) -> Result<Arc<Self>, LinkError> {
        init_log();
        let ceiling = NodePolicy {
            allow_read: opts.allow_read,
            allow_write: opts.allow_write,
            allow_exec: opts.allow_exec,
            allow_desktop: opts.allow_desktop,
            allow_desktop_stream: opts.allow_desktop_stream,
            allow_remote_view: opts.allow_remote_view,
            allow_remote_control: opts.allow_remote_control,
        };
        let mut relay_url = opts.relay_url;
        let mut trust = None;
        apply_relay_defaults(&mut relay_url, &opts.fingerprint, &mut trust);
        let config = ServeConfig {
            relay_url,
            fingerprint: opts.fingerprint,
            trust,
            data_dir: PathBuf::from(&opts.data_dir),
            files_dir: PathBuf::from(&opts.files_dir),
            cache_dir: PathBuf::from(&opts.cache_dir),
            storage_dir: if opts.storage_dir.is_empty() {
                None
            } else {
                Some(PathBuf::from(opts.storage_dir))
            },
            name: opts.name,
            pairing_token: if opts.pairing_token.is_empty() {
                None
            } else {
                Some(opts.pairing_token)
            },
            hostname: opts.hostname,
            os: "android".into(),
            arch: opts.arch,
            version: opts.version,
            ceiling,
        };
        let audit_path = config.data_dir.join("audit.log");
        let io = NodeIo {
            status: Arc::new(Mutex::new(String::new())),
            node_id: Arc::new(Mutex::new(String::new())),
        };
        let shutdown = CancellationToken::new();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .thread_name("agentlink-node")
            .build()
            .map_err(|e| LinkError::Fail {
                detail: format!("runtime: {e}"),
            })?;
        let task_shutdown = shutdown.clone();
        let task_io = NodeIo {
            status: io.status.clone(),
            node_id: io.node_id.clone(),
        };
        runtime.spawn(async move {
            if let Err(err) = serve_node(config, host, task_shutdown, task_io).await {
                tracing::error!(error = %err, "node stopped");
            }
        });
        Ok(Arc::new(Self {
            shutdown,
            io,
            audit_path,
            runtime: Mutex::new(Some(runtime)),
        }))
    }

    pub fn stop(&self) {
        self.shutdown.cancel();
    }

    pub fn status(&self) -> String {
        self.io.status.lock().map(|g| g.clone()).unwrap_or_default()
    }

    pub fn node_id(&self) -> String {
        self.io
            .node_id
            .lock()
            .map(|g| g.clone())
            .unwrap_or_default()
    }

    pub fn audit_tail(&self, limit: u32) -> String {
        audit::tail(&self.audit_path, limit.max(1) as usize)
    }
}

impl Drop for MobileNode {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(runtime) = self.runtime.lock().ok().and_then(|mut g| g.take()) {
            runtime.shutdown_timeout(Duration::from_secs(2));
        }
    }
}

#[uniffi::export]
pub fn protocol_version() -> u32 {
    PROTOCOL_VERSION
}

/// Sign with a raw ed25519 seed. Android Keystore does not reliably provide
/// Ed25519, so the seed is wrapped by a Keystore AES key and unwrapped only
/// for this call.
#[uniffi::export]
pub fn sign_ed25519(seed: Vec<u8>, message: Vec<u8>) -> Result<String, LinkError> {
    let identity = Identity::from_seed(&seed).map_err(|err| LinkError::Fail {
        detail: err.to_string(),
    })?;
    Ok(identity.sign_message(&message))
}

#[uniffi::export]
pub fn public_hex_ed25519(seed: Vec<u8>) -> Result<String, LinkError> {
    let identity = Identity::from_seed(&seed).map_err(|err| LinkError::Fail {
        detail: err.to_string(),
    })?;
    Ok(identity.public_hex().to_string())
}

#[uniffi::export]
pub fn extension_names() -> Vec<String> {
    client::known_extensions()
}

fn init_log() {
    #[cfg(target_os = "android")]
    {
        android_logger::init_once(
            android_logger::Config::default()
                .with_max_level(log::LevelFilter::Info)
                .with_tag("agentlink"),
        );
    }
}
