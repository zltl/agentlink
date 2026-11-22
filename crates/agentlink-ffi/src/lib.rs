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
mod pty_pump;
mod resume;
mod tools;
mod transfer;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use agentlink_core::{
    apply_relay_defaults, parse_join_text, Identity, JoinText, NodePolicy, DEFAULT_RELAY_TRUST,
    PROTOCOL_VERSION,
};
use futures_util::FutureExt;
use tokio_util::sync::CancellationToken;

pub use client::{
    ExecDone, FfiEntry, FfiGrant, FfiNodePin, FfiPairing, FfiPolicy, FfiStat, FfiStats,
    MachineInfo, MobileClient, OutputSink, ProgressSink, PtyHandle,
};
pub use host::{host_err, host_ok, NodeHost};
pub use live::LiveClipboard;
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
        let config = prepare_serve_config(&opts)?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            start_with_config(config, host)
        })) {
            Ok(result) => result,
            Err(_) => Err(LinkError::Fail {
                detail: "node start failed. The phone is still open; check the invite, relay, and certificate pin.".into(),
            }),
        }
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

pub(crate) fn apply_mobile_relay_defaults(
    relay: &mut String,
    fingerprint: &str,
    trust: &mut Option<String>,
) {
    apply_relay_defaults(relay, fingerprint, trust);
    let trust_empty = trust.as_deref().map(str::trim).unwrap_or("").is_empty();
    if fingerprint.trim().is_empty() && trust_empty {
        *trust = Some(DEFAULT_RELAY_TRUST.to_string());
    }
}

fn prepare_serve_config(opts: &NodeOptions) -> Result<ServeConfig, LinkError> {
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
    let joined = parse_join_text(&opts.pairing_token).map_err(|err| LinkError::Fail {
        detail: err.to_string(),
    })?;
    let mut relay_url = opts.relay_url.clone();
    let mut fingerprint = opts.fingerprint.clone();
    let mut trust = None;
    let mut name = opts.name.clone();
    // A parsed invite only fills enrollment fields. It does not grant
    // control and it does not skip the end-to-end handshake.
    let pairing_token = match joined {
        JoinText::Absent => None,
        JoinText::Token(token) => Some(token),
        JoinText::Invite(invite) => {
            relay_url = invite.relay;
            fingerprint = invite.fingerprint;
            trust = invite.trust;
            if name.trim().is_empty() {
                name = invite.name;
            }
            Some(invite.token)
        }
    };
    apply_mobile_relay_defaults(&mut relay_url, &fingerprint, &mut trust);
    Ok(ServeConfig {
        relay_url,
        fingerprint,
        trust,
        data_dir: PathBuf::from(&opts.data_dir),
        files_dir: PathBuf::from(&opts.files_dir),
        cache_dir: PathBuf::from(&opts.cache_dir),
        storage_dir: if opts.storage_dir.is_empty() {
            None
        } else {
            Some(PathBuf::from(&opts.storage_dir))
        },
        name,
        pairing_token,
        hostname: opts.hostname.clone(),
        os: "android".into(),
        arch: opts.arch.clone(),
        version: opts.version.clone(),
        ceiling,
    })
}

fn start_with_config(
    config: ServeConfig,
    host: Arc<dyn NodeHost>,
) -> Result<Arc<MobileNode>, LinkError> {
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
        let task = std::panic::AssertUnwindSafe(serve_node(config, host, task_shutdown, task_io));
        match task.catch_unwind().await {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(error = %err, "node stopped"),
            Err(_) => tracing::error!("node task panicked; the phone stays open"),
        }
    });
    Ok(Arc::new(MobileNode {
        shutdown,
        io,
        audit_path,
        runtime: Mutex::new(Some(runtime)),
    }))
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

struct ZeroizeBytes(Vec<u8>);

impl Drop for ZeroizeBytes {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

/// Sign with a raw ed25519 seed. Android Keystore does not reliably provide
/// Ed25519, so the seed is wrapped by a Keystore AES key and unwrapped only
/// for this call.
#[uniffi::export]
pub fn sign_ed25519(seed: Vec<u8>, message: Vec<u8>) -> Result<String, LinkError> {
    let seed = ZeroizeBytes(seed);
    let identity = Identity::from_seed(&seed.0).map_err(|err| LinkError::Fail {
        detail: err.to_string(),
    })?;
    Ok(identity.sign_message(&message))
}

#[uniffi::export]
pub fn public_hex_ed25519(seed: Vec<u8>) -> Result<String, LinkError> {
    let seed = ZeroizeBytes(seed);
    let identity = Identity::from_seed(&seed.0).map_err(|err| LinkError::Fail {
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

#[cfg(test)]
mod tests {
    use super::*;
    use agentlink_core::{encode_invite, Invite};

    fn opts(token: &str) -> NodeOptions {
        NodeOptions {
            relay_url: "wss://relay.example:7443".into(),
            fingerprint: "system".into(),
            data_dir: "/tmp/agentlink-node".into(),
            files_dir: "/tmp/agentlink-files".into(),
            cache_dir: "/tmp/agentlink-cache".into(),
            storage_dir: String::new(),
            name: String::new(),
            pairing_token: token.into(),
            hostname: "phone".into(),
            arch: "arm64".into(),
            version: "0.1.0".into(),
            allow_read: true,
            allow_write: false,
            allow_exec: false,
            allow_desktop: false,
            allow_desktop_stream: false,
            allow_remote_view: false,
            allow_remote_control: false,
        }
    }

    fn valid_invite() -> String {
        encode_invite(&Invite {
            relay: "wss://relay.example.com".into(),
            fingerprint: format!("sha256:{}", "ab".repeat(32)),
            trust: Some("webpki".into()),
            token: "cd".repeat(32),
            name: "from-invite".into(),
        })
        .unwrap()
    }

    #[test]
    fn short_empty_malformed_and_valid_invites_do_not_grant_access() {
        let short = match prepare_serve_config(&opts("123")) {
            Err(err) => err.to_string(),
            Ok(_) => panic!("123 was accepted"),
        };
        assert!(short.contains("too short"), "{short}");
        assert!(prepare_serve_config(&opts("agentlink-invite:v1:%%%")).is_err());

        let empty = match prepare_serve_config(&opts("")) {
            Ok(config) => config,
            Err(err) => panic!("empty invite field was refused: {err}"),
        };
        assert!(empty.pairing_token.is_none());
        assert!(!empty.ceiling.allow_exec);
        assert!(!empty.ceiling.allow_remote_control);

        let prepared = match prepare_serve_config(&opts(&valid_invite())) {
            Ok(config) => config,
            Err(err) => panic!("valid invite was refused: {err}"),
        };
        assert_eq!(prepared.relay_url, "wss://relay.example.com");
        assert_eq!(
            prepared.pairing_token.as_deref(),
            Some("cd".repeat(32).as_str())
        );
        assert_eq!(prepared.name, "from-invite");
        assert_eq!(prepared.trust.as_deref(), Some("webpki"));
        assert!(!prepared.ceiling.allow_exec);
        assert!(!prepared.ceiling.allow_write);
        assert!(!prepared.ceiling.allow_desktop);
        assert!(!prepared.ceiling.allow_remote_control);
    }

    #[test]
    fn mobile_defaults_trust_to_system_webpki_only_when_pin_is_empty() {
        let mut empty_pin = opts("");
        empty_pin.fingerprint = String::new();
        let prepared = prepare_serve_config(&empty_pin).unwrap();
        assert_eq!(prepared.trust.as_deref(), Some(DEFAULT_RELAY_TRUST));
        assert!(agentlink_core::RelayTrust::parse(
            &prepared.fingerprint,
            prepared.trust.as_deref()
        )
        .is_ok());

        let mut explicit_pin = opts("");
        explicit_pin.fingerprint = format!("sha256:{}", "ab".repeat(32));
        let prepared_pinned = prepare_serve_config(&explicit_pin).unwrap();
        assert!(prepared_pinned.trust.is_none());
        assert!(agentlink_core::RelayTrust::parse(
            &prepared_pinned.fingerprint,
            prepared_pinned.trust.as_deref()
        )
        .is_ok());
    }
}
