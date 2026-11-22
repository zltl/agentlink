//! JSON envelopes carried on a WebSocket.
//!
//! Text frames are UTF-8 JSON. File bytes travel in binary frames (see
//! [`crate::frame`]); the relay routes them by the request id in the frame
//! header and does not inspect the payload. Search, edit, watch, process,
//! system, and PTY operations are first-class variants. Phase 3 picture bytes
//! are WebRTC RTP between the viewer and the node, not these frames. Phase 2
//! and phase 3 still use [`Op::Extension`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::permissions::NodePolicy;

/// Bumped only when envelopes change in a breaking way.
/// Version 2 adds binary file frames and transfer control messages.
/// Extension operations do not require a bump.
pub const PROTOCOL_VERSION: u32 = 2;

/// WebSocket path for phase-1 control messages.
pub const WS_PATH: &str = "/v1/connect";

/// Browser viewer WebSocket. Same JSON envelopes as [`WS_PATH`]. Media is P2P.
pub const WS_WEBRTC_PATH: &str = "/v1/webrtc";

/// Browser dashboard socket for files and a terminal.
///
/// The upgrade carries the dashboard session cookie. It is not a device key
/// and it cannot enroll, change policy, or signal a desktop stream.
pub const WS_WEB_PATH: &str = "/v1/web";

pub const DEFAULT_PORT: u16 = 7443;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Client,
    Node,
}

fn default_true() -> bool {
    true
}

fn default_uses() -> u32 {
    1
}

/// A file or directory as reported by the node.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileStat {
    pub path: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified_unix_ms: Option<i64>,
    pub readonly: bool,
    pub mode: Option<u32>,
}

/// One directory entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirEntry {
    pub name: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub modified_unix_ms: Option<i64>,
    pub mode: Option<u32>,
}

/// A paired machine, online or not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeInfo {
    pub id: String,
    pub name: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub version: String,
    pub online: bool,
    /// Admin policy stored on the relay.
    pub policy: NodePolicy,
    /// Intersection of the relay policy and the node's local ceiling.
    pub effective: NodePolicy,
    /// Account that owns the node. Empty on relays that have not migrated.
    #[serde(default)]
    pub owner: String,
    /// `owner`, `shared`, or `admin` for the caller that listed the node.
    #[serde(default)]
    pub relation: String,
    /// Preset name of the access this caller may use.
    #[serde(default)]
    pub access: String,
    /// Graphical session reported by the node.
    ///
    /// `None` means the node has not reported (an older binary). `Some(false)`
    /// is headless. `Some(true)` is a real desktop session.
    #[serde(default)]
    pub has_display: Option<bool>,
}

/// Operations a node can perform.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Op {
    Stat {
        path: String,
    },
    ListDir {
        path: String,
    },
    /// Legacy 64 KiB base64 read. `cat` and MCP `read_file` use `PullStream`.
    ReadFile {
        path: String,
        offset: u64,
        max_bytes: u32,
    },
    /// Legacy 64 KiB base64 write. `write` and MCP `write_file` use `PushStream`.
    WriteFile {
        path: String,
        offset: u64,
        data_b64: String,
        truncate: bool,
    },
    Mkdir {
        path: String,
        recursive: bool,
    },
    Remove {
        path: String,
        recursive: bool,
    },
    Rename {
        from: String,
        to: String,
    },
    Exec {
        program: String,
        args: Vec<String>,
        cwd: Option<String>,
        env: Vec<(String, String)>,
        timeout_ms: Option<u64>,
        shell: bool,
        /// Optional stdin payload (base64). Omitted/null means `/dev/null`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin_b64: Option<String>,
    },
    PtyOpen {
        command: Option<String>,
        #[serde(default)]
        cwd: Option<String>,
        rows: u16,
        cols: u16,
    },
    PtyInput {
        session_id: String,
        data_b64: String,
    },
    PtyResize {
        session_id: String,
        rows: u16,
        cols: u16,
    },
    PtyClose {
        session_id: String,
    },
    Search {
        path: String,
        pattern: String,
        #[serde(default)]
        literal: bool,
        #[serde(default)]
        include: Vec<String>,
        #[serde(default)]
        exclude: Vec<String>,
        #[serde(default = "default_true")]
        gitignore: bool,
        #[serde(default)]
        include_hidden: bool,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(default)]
        before: u32,
        #[serde(default)]
        after: u32,
        #[serde(default)]
        offset: u32,
        #[serde(default)]
        limit: u32,
    },
    Find {
        path: String,
        pattern: String,
        #[serde(default)]
        regex: bool,
        #[serde(default = "default_true")]
        gitignore: bool,
        #[serde(default)]
        include_hidden: bool,
        #[serde(default)]
        case_insensitive: bool,
        #[serde(default)]
        offset: u32,
        #[serde(default)]
        limit: u32,
    },
    Replace {
        path: String,
        old: String,
        new: String,
        #[serde(default)]
        replace_all: bool,
    },
    EditLines {
        path: String,
        start_line: u32,
        end_line: u32,
        content: String,
    },
    ApplyPatch {
        root: String,
        patch: String,
    },
    WatchStart {
        path: String,
        #[serde(default = "default_true")]
        recursive: bool,
    },
    WatchPoll {
        watch_id: String,
        #[serde(default)]
        cursor: u64,
        #[serde(default)]
        timeout_ms: u64,
        #[serde(default)]
        limit: u32,
    },
    WatchStop {
        watch_id: String,
    },
    BgStart {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        env: Vec<(String, String)>,
        #[serde(default)]
        shell: bool,
        /// Optional stdin payload (base64). Omitted/null means `/dev/null`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        stdin_b64: Option<String>,
    },
    BgList,
    BgOutput {
        id: String,
        #[serde(default)]
        stdout_cursor: u64,
        #[serde(default)]
        stderr_cursor: u64,
        #[serde(default)]
        max_bytes: u32,
    },
    BgStatus {
        id: String,
    },
    BgKill {
        id: String,
    },
    SysInfo,
    /// Issuer-signed grant revocation. Only accepted inside a sealed E2E
    /// invoke; the node verifies the issuer against `owner-keys.json` and
    /// appends the jti to its local deny-list.
    RevokeGrant {
        revoke: crate::grant::SignedRevoke,
    },
    /// Phase 2/3 hook. See [`crate::extensions`].
    Extension {
        name: String,
        payload: Value,
    },
}

impl Op {
    pub fn kind(&self) -> String {
        match self {
            Op::Stat { .. } => "stat".into(),
            Op::ListDir { .. } => "list_dir".into(),
            Op::ReadFile { .. } => "read".into(),
            Op::WriteFile { .. } => "write".into(),
            Op::Mkdir { .. } => "mkdir".into(),
            Op::Remove { .. } => "remove".into(),
            Op::Rename { .. } => "rename".into(),
            Op::Exec { .. } => "exec".into(),
            Op::PtyOpen { .. } => "pty_open".into(),
            Op::PtyInput { .. } => "pty_input".into(),
            Op::PtyResize { .. } => "pty_resize".into(),
            Op::PtyClose { .. } => "pty_close".into(),
            Op::Search { .. } => "search".into(),
            Op::Find { .. } => "find".into(),
            Op::Replace { .. } => "replace".into(),
            Op::EditLines { .. } => "edit_lines".into(),
            Op::ApplyPatch { .. } => "apply_patch".into(),
            Op::WatchStart { .. } => "watch_start".into(),
            Op::WatchPoll { .. } => "watch_poll".into(),
            Op::WatchStop { .. } => "watch_stop".into(),
            Op::BgStart { .. } => "bg_start".into(),
            Op::BgList => "bg_list".into(),
            Op::BgOutput { .. } => "bg_output".into(),
            Op::BgStatus { .. } => "bg_status".into(),
            Op::BgKill { .. } => "bg_kill".into(),
            Op::SysInfo => "sys_info".into(),
            Op::RevokeGrant { .. } => "revoke_grant".into(),
            Op::Extension { name, .. } => format!("ext:{name}"),
        }
    }

    pub fn audit_detail(&self) -> String {
        match self {
            Op::Stat { path }
            | Op::ListDir { path }
            | Op::ReadFile { path, .. }
            | Op::Mkdir { path, .. }
            | Op::Remove { path, .. } => path.clone(),
            Op::WriteFile { path, offset, .. } => format!("{path} @{offset}"),
            Op::Rename { from, to } => format!("{from} -> {to}"),
            Op::Exec {
                program,
                args,
                shell,
                ..
            } => {
                if *shell {
                    program.clone()
                } else if args.is_empty() {
                    program.clone()
                } else {
                    format!("{program} {}", args.join(" "))
                }
            }
            Op::PtyOpen { command, .. } => command.clone().unwrap_or_else(|| "shell".into()),
            Op::PtyInput { session_id, .. }
            | Op::PtyResize { session_id, .. }
            | Op::PtyClose { session_id } => format!("session {session_id}"),
            Op::Search { path, pattern, .. } | Op::Find { path, pattern, .. } => {
                format!("{path}: {pattern}")
            }
            Op::Replace { path, .. } | Op::EditLines { path, .. } | Op::WatchStart { path, .. } => {
                path.clone()
            }
            Op::ApplyPatch { root, .. } => root.clone(),
            Op::WatchPoll { watch_id, .. } | Op::WatchStop { watch_id } => watch_id.clone(),
            Op::BgStart {
                program,
                args,
                shell,
                ..
            } => {
                if *shell || args.is_empty() {
                    program.clone()
                } else {
                    format!("{program} {}", args.join(" "))
                }
            }
            Op::BgList | Op::SysInfo => "info".into(),
            Op::BgOutput { id, .. } | Op::BgStatus { id } | Op::BgKill { id } => id.clone(),
            Op::RevokeGrant { revoke } => revoke.jti.clone(),
            Op::Extension { name, payload } => extension_audit(name, payload),
        }
    }
}

/// Short audit line for an extension payload. Image bytes and long typed
/// strings stay out of the log. A type or set-value action records a character
/// count and at most 12 characters of preview.
fn extension_audit(name: &str, payload: &Value) -> String {
    let mut parts = vec![name.to_string()];
    if let Some(action) = payload.get("action").and_then(Value::as_str) {
        if action != name {
            parts.push(action.to_string());
        }
    }
    if let Some(target) = payload.get("target").and_then(Value::as_str) {
        parts.push(target.to_string());
    }
    if let Some(image_format) = payload.get("format").and_then(Value::as_str) {
        parts.push(image_format.to_string());
    }
    if let Some(window) = payload
        .get("window_id")
        .or_else(|| payload.get("window"))
        .and_then(Value::as_str)
    {
        parts.push(format!("window={window}"));
    }
    if let Some(monitor) = payload.get("monitor").and_then(Value::as_u64) {
        parts.push(format!("monitor={monitor}"));
    }
    if payload.get("x").is_some() || payload.get("y").is_some() {
        let x = payload.get("x").and_then(Value::as_i64).unwrap_or(0);
        let y = payload.get("y").and_then(Value::as_i64).unwrap_or(0);
        parts.push(format!("@{x},{y}"));
    }
    if let Some(to_x) = payload.get("to_x").and_then(Value::as_i64) {
        let to_y = payload.get("to_y").and_then(Value::as_i64).unwrap_or(0);
        parts.push(format!("->{to_x},{to_y}"));
    }
    if let Some(dx) = payload.get("dx").and_then(Value::as_i64) {
        let dy = payload.get("dy").and_then(Value::as_i64).unwrap_or(0);
        if dx != 0 || dy != 0 {
            parts.push(format!("scroll={dx},{dy}"));
        }
    }
    if let Some(keys) = payload.get("keys").and_then(Value::as_str) {
        parts.push(keys.to_string());
    } else if let Some(keys) = payload.get("keys").and_then(Value::as_array) {
        let text = keys
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("+");
        if !text.is_empty() {
            parts.push(text);
        }
    }
    if let Some(id) = payload.get("id").and_then(Value::as_str) {
        parts.push(id.to_string());
    }
    if let Some(op) = payload.get("op").and_then(Value::as_str) {
        parts.push(op.to_string());
    }
    if let Some(text) = payload
        .get("text")
        .or_else(|| payload.get("value"))
        .and_then(Value::as_str)
    {
        let count = text.chars().count();
        let mut preview: String = text.chars().take(12).collect();
        preview = preview.replace(['\n', '\r'], " ");
        if count > preview.chars().count() {
            parts.push(format!("{count} chars \"{preview}…\""));
        } else {
            parts.push(format!("{count} chars \"{preview}\""));
        }
    }
    let mut detail: String = parts.join(" ");
    if detail.chars().count() > 180 {
        detail = detail.chars().take(180).collect();
    }
    detail
}

/// Inclusive-exclusive byte range.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CompressPref {
    Auto,
    On,
    Off,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockSig {
    pub off: u64,
    pub len: u32,
    pub weak: u32,
    /// First 16 bytes of BLAKE3, hex.
    pub strong: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SigTable {
    pub block: u32,
    pub sigs: Vec<BlockSig>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum PlanOp {
    Copy { old: u64, new: u64, len: u64 },
    Lit { new: u64, len: u64 },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub rel: String,
    pub size: u64,
    pub hash: String,
    pub dir: bool,
    /// When set, this entry is a symlink whose target is the string (not followed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symlink: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum AcceptMode {
    Skip,
    Full { missing: Vec<ByteRange> },
    Files { needed: Vec<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferStats {
    pub logical_bytes: u64,
    pub payload_bytes: u64,
    pub skipped: bool,
    pub files: u32,
    pub files_skipped: u32,
    pub compressed: bool,
    pub transport: String,
    pub delta_copy_bytes: u64,
    pub resumed_bytes: u64,
}

fn default_window() -> usize {
    8
}

fn default_parallel() -> usize {
    4
}

/// Control messages for a bulk transfer. Bytes follow as binary frames.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum TransferMsg {
    Push {
        path: String,
        size: u64,
        hash: String,
        chunk_size: u32,
        compress: CompressPref,
        resume: bool,
        /// Unix mode bits when the source could read them.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mode: Option<u32>,
        /// Source mtime as seconds since Unix epoch.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mtime_unix: Option<u64>,
    },
    Pull {
        path: String,
        have_hash: Option<String>,
        have_ranges: Vec<ByteRange>,
        chunk_size: u32,
        compress: CompressPref,
        sigs: Option<SigTable>,
    },
    PushDir {
        dest: String,
        manifest_hash: String,
        entries: Vec<ManifestEntry>,
        chunk_size: u32,
        compress: CompressPref,
    },
    PullDir {
        path: String,
        have: Vec<ManifestEntry>,
        chunk_size: u32,
        compress: CompressPref,
    },
    /// Source node copies one of its paths to another node.
    PeerCopy {
        dst_node: String,
        src_path: String,
        dst_path: String,
        chunk_size: u32,
        #[serde(default = "default_window")]
        window: usize,
        #[serde(default = "default_parallel")]
        parallel: usize,
        compress: CompressPref,
        direct: bool,
    },
    Accept {
        mode: AcceptMode,
    },
    Sigs {
        table: SigTable,
    },
    Plan {
        out_size: u64,
        out_hash: String,
        ops: Vec<PlanOp>,
    },
    PreferFull,
    /// A tar or file blob the peer should write next.
    Blob {
        size: u64,
        hash: String,
        tar: bool,
    },
    Ack {
        ranges: Vec<ByteRange>,
    },
    Finish,
    /// Upload whose length is known only when the reader hits EOF.
    PushStream {
        path: String,
        chunk_size: u32,
        #[serde(default = "default_window")]
        window: usize,
        compress: CompressPref,
    },
    /// Download `[offset, offset+max_bytes)`, or the whole file when `max_bytes` is absent.
    PullStream {
        path: String,
        offset: u64,
        #[serde(default)]
        max_bytes: Option<u64>,
        chunk_size: u32,
        #[serde(default = "default_window")]
        window: usize,
        compress: CompressPref,
    },
    /// The byte range a `PullStream` will cover. `file_size` is the whole remote file.
    StreamReady {
        start: u64,
        end: u64,
        file_size: u64,
    },
    /// End of a streamed body. `hash` is BLAKE3 of the uncompressed bytes.
    Commit {
        size: u64,
        hash: String,
    },
    /// Client asks the node to dial `host:port` (forward data path).
    TunnelDial {
        host: String,
        port: u16,
    },
    /// Client asks the node to listen on 127.0.0.1:`port` (reverse control).
    TunnelBind {
        port: u16,
    },
    /// Reverse listener is up; `port` is the bound port.
    TunnelBound {
        port: u16,
    },
    /// Reverse listener accepted a TCP connection; claim with TunnelAccept.
    TunnelIncoming {
        token: String,
    },
    /// Claim a TunnelIncoming on a new transfer request.
    TunnelAccept {
        token: String,
    },
    /// Dial or accepted socket is ready; byte frames follow.
    TunnelReady,
    /// Half-close: this side hit EOF on its TCP socket.
    TunnelClose,
    Done {
        stats: TransferStats,
    },
    Failed {
        message: String,
    },
}

impl TransferMsg {
    pub fn is_terminal(&self) -> bool {
        matches!(self, TransferMsg::Done { .. } | TransferMsg::Failed { .. })
    }

    pub fn needs_write(&self) -> bool {
        matches!(
            self,
            TransferMsg::Push { .. }
                | TransferMsg::PushDir { .. }
                | TransferMsg::PushStream { .. }
                | TransferMsg::PeerCopy { .. }
        )
    }

    pub fn needs_read(&self) -> bool {
        matches!(
            self,
            TransferMsg::Pull { .. } | TransferMsg::PullDir { .. } | TransferMsg::PullStream { .. }
        )
    }
}

/// One control message.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Envelope {
    Hello {
        role: Role,
        protocol: u32,
        #[serde(default)]
        token: Option<String>,
        #[serde(default)]
        node_id: Option<String>,
        #[serde(default)]
        public_key: Option<String>,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        pairing_token: Option<String>,
        #[serde(default)]
        hostname: Option<String>,
        #[serde(default)]
        os: Option<String>,
        #[serde(default)]
        arch: Option<String>,
        #[serde(default)]
        version: Option<String>,
        #[serde(default)]
        ceiling: Option<NodePolicy>,
        /// Set by a node. Clients and older nodes omit it.
        #[serde(default)]
        has_display: Option<bool>,
    },
    Challenge {
        nonce: String,
    },
    Authenticate {
        signature: String,
    },
    HelloOk {
        #[serde(default)]
        node_id: Option<String>,
        #[serde(default)]
        policy: Option<NodePolicy>,
        protocol: u32,
        heartbeat_secs: u64,
        /// Set the first time a view ticket is redeemed. Later sockets present
        /// `view.<ticket>.<session>`. Absent for every other role.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        view_session: Option<String>,
    },
    HelloErr {
        message: String,
        #[serde(default)]
        fatal: bool,
    },
    Ping,
    Pong,
    CreatePairingToken {
        request_id: String,
        name: String,
        policy: NodePolicy,
        ttl_secs: u64,
        /// Missing or 0 means one use. The relay rejects values above 1000.
        #[serde(default = "default_uses")]
        uses: u32,
    },
    PairingToken {
        request_id: String,
        token: String,
        name: String,
        expires_unix: i64,
        policy: NodePolicy,
        #[serde(default)]
        id: String,
        #[serde(default = "default_uses")]
        uses: u32,
    },
    SetPolicy {
        request_id: String,
        node_id: String,
        policy: NodePolicy,
    },
    ListNodes {
        request_id: String,
    },
    NodeList {
        request_id: String,
        nodes: Vec<NodeInfo>,
    },
    Invoke {
        request_id: String,
        node_id: String,
        client_id: String,
        op: Op,
        /// Set by the relay for a view-ticket session. The node intersects
        /// this with its own ceiling. Clients cannot raise their own grant:
        /// the relay overwrites the field before forwarding.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        grant: Option<NodePolicy>,
        /// Owner-signed capability. Travels inside the sealed E2E body so the
        /// relay cannot forge it. See `crate::grant` and `docs/e2e-auth.md`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authz: Option<crate::grant::SignedGrant>,
        /// Account that invoked the operation. Stamped by the relay.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        /// Device that invoked the operation. Stamped by the relay.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
    },
    Cancel {
        request_id: String,
        node_id: String,
    },
    Result {
        request_id: String,
        ok: bool,
        #[serde(default)]
        error: Option<String>,
        #[serde(default)]
        body: Option<Value>,
        /// When true, the request is finished. A PTY open acks with `false`
        /// so later output chunks still have a route.
        #[serde(default = "default_true")]
        terminal: bool,
        /// Per-request sequence, starting at 1. Zero means the sender did not
        /// sequence this frame (relay errors, older peers).
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        seq: u64,
    },
    Chunk {
        request_id: String,
        stream: String,
        data_b64: String,
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        seq: u64,
    },
    End {
        request_id: String,
        #[serde(default)]
        exit_code: Option<i32>,
        #[serde(default)]
        error: Option<String>,
        #[serde(default, skip_serializing_if = "is_zero_u64")]
        seq: u64,
    },
    /// Pushed to a live node when an admin changes its policy.
    PolicyUpdate {
        policy: NodePolicy,
    },
    /// Bulk transfer control. File bytes are binary frames with the same request id.
    Transfer {
        request_id: String,
        node_id: String,
        #[serde(default)]
        client_id: String,
        msg: TransferMsg,
        /// When true, the relay drops the route after forwarding.
        #[serde(default)]
        terminal: bool,
        /// Owner-signed capability for the transfer. Travels inside the sealed
        /// E2E body, so the relay cannot forge it.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authz: Option<crate::grant::SignedGrant>,
    },
    /// Ask the relay to introduce a direct QUIC path to `node_id`.
    DirectOffer {
        request_id: String,
        node_id: String,
        public_key: String,
        cert_fp: String,
        cert_sig: String,
        local_addrs: Vec<String>,
        #[serde(default)]
        reflexive: Option<String>,
    },
    DirectAnswer {
        request_id: String,
        public_key: String,
        cert_fp: String,
        cert_sig: String,
        local_addrs: Vec<String>,
        #[serde(default)]
        reflexive: Option<String>,
    },
    /// First handshake message. The body is an opaque X25519 + ed25519 transcript.
    E2eHello {
        request_id: String,
        node_id: String,
        message_b64: String,
    },
    /// Second handshake message, node to client.
    E2eWelcome {
        request_id: String,
        node_id: String,
        message_b64: String,
    },
    /// Ciphertext of an [`Envelope`] the relay must not read. `class` is the
    /// only operation detail in the clear: `read`, `write`, `exec`, `desktop`,
    /// or `meta`.
    E2e {
        request_id: String,
        node_id: String,
        client_id: String,
        class: String,
        #[serde(default)]
        terminal: bool,
        body_b64: String,
        /// Account that invoked the operation. Stamped by the relay.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
        /// Device that invoked the operation. Stamped by the relay.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device_id: Option<String>,
        /// Filled by the relay from the authenticated principal. Clients send false.
        #[serde(default)]
        relay_admin: bool,
        /// Filled by the relay. Intersected with the node ceiling.
        #[serde(default)]
        relay_grant: Option<NodePolicy>,
    },
    RegisterClient {
        request_id: String,
        name: String,
        public_key: String,
    },
    SetClientGrant {
        request_id: String,
        client_id: String,
        node_id: String,
        policy: NodePolicy,
    },
    RevokeClient {
        request_id: String,
        client_id: String,
    },
    ListClients {
        request_id: String,
    },
    ClientList {
        request_id: String,
        clients: Vec<ClientInfo>,
    },
    ApprovalRequest {
        /// Invoke request that is held; empty on older nodes.
        #[serde(default)]
        request_id: String,
        approval_id: String,
        node_id: String,
        client_id: String,
        category: String,
        summary: String,
        expires_unix: i64,
    },
    ListApprovals {
        request_id: String,
    },
    ApprovalList {
        request_id: String,
        items: Vec<ApprovalInfo>,
    },
    ResolveApproval {
        request_id: String,
        approval_id: String,
        node_id: String,
        allow: bool,
    },
    ApprovalDecision {
        approval_id: String,
        allow: bool,
    },
    AuditBatch {
        node_id: String,
        records: Vec<serde_json::Value>,
    },
    QueryAudit {
        request_id: String,
        filter: serde_json::Value,
    },
    AuditPage {
        request_id: String,
        records: Vec<serde_json::Value>,
    },
    SetAuditPolicy {
        request_id: String,
        node_id: String,
        #[serde(default)]
        agent_id: Option<String>,
        toml: String,
        /// When set, store a per-user audit policy instead of a node policy.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
    /// Pushed to a node. Ignored when the node set `lock_local`.
    AuditPolicyPush {
        toml: String,
    },
    /// A registered agent asks for a short-lived browser viewer credential.
    /// The ticket is not an admin token. It can signal `webrtc_signal` or
    /// request `screenshot` on one node, under that agent's grant.
    IssueViewTicket {
        request_id: String,
        node_id: String,
        /// When false (the default), the ticket is view-only even if the
        /// account grant includes remote control. Input requires this flag
        /// and the underlying grant.
        #[serde(default)]
        control: bool,
    },
    ViewTicket {
        request_id: String,
        ticket: String,
        node_id: String,
        expires_unix: i64,
    },
    Login {
        request_id: String,
        username: String,
        password: String,
        #[serde(default)]
        totp: Option<String>,
        public_key: String,
        #[serde(default)]
        device_name: Option<String>,
    },
    LoginOk {
        request_id: String,
        user: String,
        role: String,
        device_id: String,
        access_token: String,
        access_expires_unix: i64,
        refresh_token: String,
        refresh_expires_unix: i64,
    },
    LoginErr {
        request_id: String,
        message: String,
    },
    RefreshSession {
        request_id: String,
        refresh_token: String,
        public_key: String,
    },
    Signup {
        request_id: String,
        username: String,
        password: String,
        public_key: String,
        #[serde(default)]
        device_name: Option<String>,
    },
    Logout {
        request_id: String,
        #[serde(default)]
        refresh_token: Option<String>,
    },
    ListDevices {
        request_id: String,
    },
    DeviceList {
        request_id: String,
        devices: Vec<DeviceInfo>,
    },
    RevokeDevice {
        request_id: String,
        device_id: String,
    },
    UserAdd {
        request_id: String,
        username: String,
        password: String,
        #[serde(default)]
        role: String,
        #[serde(default)]
        admin: bool,
    },
    UserList {
        request_id: String,
    },
    UserListed {
        request_id: String,
        users: Vec<UserInfo>,
    },
    UserPasswd {
        request_id: String,
        username: String,
        password: String,
    },
    UserSetDisabled {
        request_id: String,
        username: String,
        disabled: bool,
    },
    UserRemove {
        request_id: String,
        username: String,
    },
    UserSetRole {
        request_id: String,
        username: String,
        role: String,
    },
    TotpBegin {
        request_id: String,
    },
    TotpPending {
        request_id: String,
        secret: String,
        url: String,
    },
    TotpConfirm {
        request_id: String,
        code: String,
    },
    TotpDisable {
        request_id: String,
    },
    ShareNode {
        request_id: String,
        node_id: String,
        username: String,
        policy: NodePolicy,
    },
    UnshareNode {
        request_id: String,
        node_id: String,
        username: String,
    },
    ListEnrollmentTokens {
        request_id: String,
    },
    EnrollmentTokenList {
        request_id: String,
        tokens: Vec<TokenInfo>,
    },
    RevokeEnrollmentToken {
        request_id: String,
        id: String,
    },
    /// Enroll this device as a node owned by the logged-in user.
    /// `signature` is over `agentlink-enroll-v1:{request_id}:{public_key}`.
    EnrollSelf {
        request_id: String,
        name: String,
        public_key: String,
        signature: String,
        #[serde(default)]
        policy: Option<NodePolicy>,
        #[serde(default)]
        hostname: Option<String>,
        #[serde(default)]
        os: Option<String>,
        #[serde(default)]
        arch: Option<String>,
        #[serde(default)]
        version: Option<String>,
    },
    SetUserAudit {
        request_id: String,
        #[serde(default)]
        username: Option<String>,
        toml: String,
    },
    /// The relay is restarting. Peers should reconnect immediately.
    GoingAway {
        retry_after_ms: u64,
    },
    /// Reattach a logical client session after the socket drops.
    ///
    /// `cursors` are the highest sequence numbers the client has applied,
    /// per request. The node replays anything newer from its ring buffer.
    Session {
        session_id: String,
        #[serde(default)]
        node_id: String,
        #[serde(default)]
        cursors: Vec<SessionCursor>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceInfo {
    pub id: String,
    pub user: String,
    pub name: String,
    pub created_unix: i64,
    pub last_seen_unix: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserInfo {
    pub username: String,
    pub role: String,
    pub disabled: bool,
    pub created_unix: i64,
    pub totp_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    pub owner: String,
    pub policy: NodePolicy,
    pub created_unix: i64,
    pub expires_unix: i64,
    pub max_uses: u32,
    pub uses_remaining: u32,
    pub revoked: bool,
    pub state: String,
}

fn is_zero_u64(value: &u64) -> bool {
    *value == 0
}

/// One request's applied sequence, carried in [`Envelope::Session`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionCursor {
    pub request_id: String,
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientInfo {
    pub id: String,
    pub name: String,
    pub role: String,
    pub revoked: bool,
    pub grants: Vec<ClientGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientGrant {
    pub node_id: String,
    pub policy: NodePolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApprovalInfo {
    pub approval_id: String,
    pub node_id: String,
    pub client_id: String,
    pub category: String,
    pub summary: String,
    pub expires_unix: i64,
}

impl Envelope {
    pub fn request_id(&self) -> Option<&str> {
        match self {
            Envelope::CreatePairingToken { request_id, .. }
            | Envelope::PairingToken { request_id, .. }
            | Envelope::SetPolicy { request_id, .. }
            | Envelope::ListNodes { request_id }
            | Envelope::NodeList { request_id, .. }
            | Envelope::Invoke { request_id, .. }
            | Envelope::Cancel { request_id, .. }
            | Envelope::Result { request_id, .. }
            | Envelope::Chunk { request_id, .. }
            | Envelope::End { request_id, .. }
            | Envelope::Transfer { request_id, .. }
            | Envelope::DirectOffer { request_id, .. }
            | Envelope::DirectAnswer { request_id, .. }
            | Envelope::E2eHello { request_id, .. }
            | Envelope::E2eWelcome { request_id, .. }
            | Envelope::E2e { request_id, .. }
            | Envelope::RegisterClient { request_id, .. }
            | Envelope::SetClientGrant { request_id, .. }
            | Envelope::RevokeClient { request_id, .. }
            | Envelope::ListClients { request_id }
            | Envelope::ClientList { request_id, .. }
            | Envelope::ListApprovals { request_id }
            | Envelope::ApprovalList { request_id, .. }
            | Envelope::ResolveApproval { request_id, .. }
            | Envelope::QueryAudit { request_id, .. }
            | Envelope::AuditPage { request_id, .. }
            | Envelope::SetAuditPolicy { request_id, .. }
            | Envelope::IssueViewTicket { request_id, .. }
            | Envelope::ViewTicket { request_id, .. }
            // Account replies are not `Result`. `dispatch` drops an envelope
            // whose request id is missing, so `devices` (and user / token /
            // totp list) would wait until the client timeout.
            | Envelope::Login { request_id, .. }
            | Envelope::LoginOk { request_id, .. }
            | Envelope::LoginErr { request_id, .. }
            | Envelope::RefreshSession { request_id, .. }
            | Envelope::Signup { request_id, .. }
            | Envelope::Logout { request_id, .. }
            | Envelope::ListDevices { request_id }
            | Envelope::DeviceList { request_id, .. }
            | Envelope::RevokeDevice { request_id, .. }
            | Envelope::UserAdd { request_id, .. }
            | Envelope::UserList { request_id }
            | Envelope::UserListed { request_id, .. }
            | Envelope::UserPasswd { request_id, .. }
            | Envelope::UserSetDisabled { request_id, .. }
            | Envelope::UserRemove { request_id, .. }
            | Envelope::UserSetRole { request_id, .. }
            | Envelope::TotpBegin { request_id }
            | Envelope::TotpPending { request_id, .. }
            | Envelope::TotpConfirm { request_id, .. }
            | Envelope::TotpDisable { request_id }
            | Envelope::ShareNode { request_id, .. }
            | Envelope::UnshareNode { request_id, .. }
            | Envelope::ListEnrollmentTokens { request_id }
            | Envelope::EnrollmentTokenList { request_id, .. }
            | Envelope::RevokeEnrollmentToken { request_id, .. }
            | Envelope::EnrollSelf { request_id, .. }
            | Envelope::SetUserAudit { request_id, .. } => Some(request_id),
            Envelope::ApprovalRequest { request_id, .. } if !request_id.is_empty() => {
                Some(request_id)
            }
            _ => None,
        }
    }

    pub fn result_ok(request_id: String, body: Value) -> Self {
        Envelope::Result {
            request_id,
            ok: true,
            error: None,
            body: Some(body),
            terminal: true,
            seq: 0,
        }
    }

    pub fn result_err(request_id: String, error: impl Into<String>) -> Self {
        Envelope::Result {
            request_id,
            ok: false,
            error: Some(error.into()),
            body: None,
            terminal: true,
            seq: 0,
        }
    }

    pub fn result_ack(request_id: String, body: Value) -> Self {
        Envelope::Result {
            request_id,
            ok: true,
            error: None,
            body: Some(body),
            terminal: false,
            seq: 0,
        }
    }

    pub fn seq(&self) -> u64 {
        match self {
            Envelope::Result { seq, .. }
            | Envelope::Chunk { seq, .. }
            | Envelope::End { seq, .. } => *seq,
            _ => 0,
        }
    }

    pub fn set_seq(&mut self, seq: u64) {
        match self {
            Envelope::Result { seq: slot, .. }
            | Envelope::Chunk { seq: slot, .. }
            | Envelope::End { seq: slot, .. } => *slot = seq,
            _ => {}
        }
    }

    pub fn is_terminal_frame(&self) -> bool {
        match self {
            Envelope::Result { terminal, .. } => *terminal,
            Envelope::End { .. } => true,
            _ => false,
        }
    }
}

/// True when `query` looks like a filesystem path or glob rather than a
/// machine name. Used to improve "node not found" errors when arguments are
/// swapped (`agentlink find '*.rs' example`).
pub fn looks_like_path_or_glob(query: &str) -> bool {
    if query.is_empty() {
        return false;
    }
    query.contains('/')
        || query.contains('\\')
        || query.contains('*')
        || query.contains('?')
        || query.contains('[')
        || query.starts_with('.')
        || query.starts_with('~')
}

/// Resolve a user-supplied name, full id, or unique >=8-char hex id prefix
/// against a node list.
///
/// Precedence:
/// 1. Exact node id (then case-insensitive exact id).
/// 2. Exact case-sensitive node name.
/// 3. Case-insensitive node name.
/// 4. Unique case-insensitive hex id prefix of at least 8 hex characters.
pub fn resolve_node<'a>(nodes: &'a [NodeInfo], query: &str) -> crate::error::Result<&'a NodeInfo> {
    if let Some(node) = nodes.iter().find(|n| n.id == query) {
        return Ok(node);
    }
    let trimmed = query.trim();
    if !trimmed.is_empty() {
        let id_ci: Vec<_> = nodes
            .iter()
            .filter(|n| n.id.eq_ignore_ascii_case(trimmed))
            .collect();
        match id_ci.len() {
            1 => return Ok(id_ci[0]),
            n if n > 1 => return Err(crate::error::Error::Ambiguous(query.to_string())),
            _ => {}
        }
    }
    let exact_name: Vec<_> = nodes.iter().filter(|n| n.name == query).collect();
    match exact_name.len() {
        1 => return Ok(exact_name[0]),
        n if n > 1 => return Err(crate::error::Error::Ambiguous(query.to_string())),
        _ => {}
    }
    let ci_name: Vec<_> = nodes
        .iter()
        .filter(|n| n.name.eq_ignore_ascii_case(query))
        .collect();
    match ci_name.len() {
        1 => return Ok(ci_name[0]),
        n if n > 1 => return Err(crate::error::Error::Ambiguous(query.to_string())),
        _ => {}
    }
    if trimmed.len() >= 8 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        let prefix = trimmed.to_ascii_lowercase();
        let prefix_matches: Vec<_> = nodes
            .iter()
            .filter(|n| n.id.to_ascii_lowercase().starts_with(&prefix))
            .collect();
        match prefix_matches.len() {
            1 => return Ok(prefix_matches[0]),
            n if n > 1 => return Err(crate::error::Error::Ambiguous(query.to_string())),
            _ => {}
        }
    }
    let hint = if looks_like_path_or_glob(query) {
        " (looks like a path or glob; put the machine name first — see `agentlink nodes`)"
    } else {
        ""
    };
    Err(crate::error::Error::NotFound(format!("node '{query}'{hint}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_or_glob_queries_are_detected() {
        assert!(looks_like_path_or_glob("*.rs"));
        assert!(looks_like_path_or_glob("/tmp"));
        assert!(looks_like_path_or_glob("C:\\Users"));
        assert!(looks_like_path_or_glob("./src"));
        assert!(looks_like_path_or_glob("~/notes"));
        assert!(looks_like_path_or_glob("src/**/*.rs"));
        assert!(!looks_like_path_or_glob("example"));
        assert!(!looks_like_path_or_glob("tun1000-box"));
        assert!(!looks_like_path_or_glob("probe"));
    }

    #[test]
    fn resolve_node_hints_when_query_looks_like_a_path() {
        let err = resolve_node(&[], "*.rs").expect_err("missing");
        let msg = err.to_string();
        assert!(msg.contains("*.rs"), "{msg}");
        assert!(msg.contains("path or glob"), "{msg}");
        assert!(msg.contains("machine name"), "{msg}");

        let plain = resolve_node(&[], "no-such-box").expect_err("missing");
        let plain_msg = plain.to_string();
        assert!(plain_msg.contains("no-such-box"), "{plain_msg}");
        assert!(!plain_msg.contains("path or glob"), "{plain_msg}");
    }

    #[test]
    fn ux06_resolve_node_supports_case_insensitive_name_and_unique_hex_prefix() {
        let node = |id: &str, name: &str| NodeInfo {
            id: id.into(),
            name: name.into(),
            hostname: name.into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: "0.1.0".into(),
            online: true,
            policy: NodePolicy::exec(),
            effective: NodePolicy::exec(),
            owner: String::new(),
            relation: String::new(),
            access: String::new(),
            has_display: None,
        };
        let a_id = "abcdef0111111111111111111111111111111111111111111111111111111111";
        let b_id = "abcdef0122222222222222222222222222222222222222222222222222222222";
        let c_id = "99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff";
        let nodes = vec![
            node(a_id, "AlphaBox"),
            node(b_id, "beta-box"),
            node(c_id, "Gamma"),
        ];

        // Exact ID wins.
        assert_eq!(resolve_node(&nodes, a_id).unwrap().name, "AlphaBox");
        // Case-insensitive exact ID works.
        assert_eq!(
            resolve_node(&nodes, &c_id.to_ascii_uppercase()).unwrap().name,
            "Gamma"
        );
        // Case-insensitive name works.
        assert_eq!(resolve_node(&nodes, "alphabox").unwrap().id, a_id);
        assert_eq!(resolve_node(&nodes, "BETA-BOX").unwrap().id, b_id);
        // Unique >=8-char hex prefix works (case-insensitive).
        assert_eq!(resolve_node(&nodes, "99887766").unwrap().id, c_id);
        assert_eq!(resolve_node(&nodes, "ABCDEF011").unwrap().id, a_id);
        // Ambiguous >=8-char hex prefix returns Ambiguous.
        assert!(matches!(
            resolve_node(&nodes, "abcdef01"),
            Err(crate::error::Error::Ambiguous(_))
        ));
        // Prefix shorter than 8 chars does NOT match.
        assert!(matches!(
            resolve_node(&nodes, "9988776"),
            Err(crate::error::Error::NotFound(_))
        ));
        // Exact case-sensitive name wins over case-insensitive collision.
        let dup_case = vec![node(a_id, "Box"), node(b_id, "box")];
        assert_eq!(resolve_node(&dup_case, "Box").unwrap().id, a_id);
        assert_eq!(resolve_node(&dup_case, "box").unwrap().id, b_id);
        assert!(matches!(
            resolve_node(&dup_case, "BOX"),
            Err(crate::error::Error::Ambiguous(_))
        ));
    }

    #[test]
    fn account_replies_keep_the_request_id_the_client_is_waiting_on() {
        let devices = Envelope::DeviceList {
            request_id: "dev-1".into(),
            devices: vec![],
        };
        assert_eq!(devices.request_id(), Some("dev-1"));
        let users = Envelope::UserListed {
            request_id: "usr-1".into(),
            users: vec![],
        };
        assert_eq!(users.request_id(), Some("usr-1"));
        let tokens = Envelope::EnrollmentTokenList {
            request_id: "tok-1".into(),
            tokens: vec![],
        };
        assert_eq!(tokens.request_id(), Some("tok-1"));
        let totp = Envelope::TotpPending {
            request_id: "otp-1".into(),
            secret: "s".into(),
            url: "u".into(),
        };
        assert_eq!(totp.request_id(), Some("otp-1"));
        assert_eq!(Envelope::Ping.request_id(), None);
        assert_eq!(Envelope::Pong.request_id(), None);
    }

    #[test]
    fn envelope_roundtrip() {
        let env = Envelope::Invoke {
            request_id: "r1".into(),
            node_id: "n1".into(),
            client_id: "c1".into(),
            op: Op::ReadFile {
                path: "/tmp/a".into(),
                offset: 0,
                max_bytes: 10,
            },
            grant: None,
            authz: None,
            user: None,
            device_id: None,
        };
        let text = serde_json::to_string(&env).unwrap();
        let back: Envelope = serde_json::from_str(&text).unwrap();
        assert_eq!(back.request_id(), Some("r1"));
        match back {
            Envelope::Invoke { op, .. } => match op {
                Op::ReadFile { path, .. } => assert_eq!(path, "/tmp/a"),
                _ => panic!("op"),
            },
            _ => panic!("variant"),
        }
    }

    #[test]
    fn revoke_grant_roundtrips_and_reports_kind() {
        let issuer = crate::Identity::generate();
        let revoke =
            crate::grant::SignedRevoke::sign(&issuer, "n1", "jti-1", 10, 20).unwrap();
        let op = Op::RevokeGrant {
            revoke: revoke.clone(),
        };
        assert_eq!(op.kind(), "revoke_grant");
        assert_eq!(op.audit_detail(), "jti-1");
        let text = serde_json::to_string(&op).unwrap();
        assert!(text.contains("\"op\":\"revoke_grant\""), "{text}");
        let back: Op = serde_json::from_str(&text).unwrap();
        match back {
            Op::RevokeGrant { revoke: back } => assert_eq!(back, revoke),
            other => panic!("expected revoke_grant, got {other:?}"),
        }
    }

    #[test]
    fn transfer_authz_round_trips_and_is_omitted_when_absent() {
        let plain = Envelope::Transfer {
            request_id: "t1".into(),
            node_id: "n1".into(),
            client_id: "c1".into(),
            msg: TransferMsg::Commit {
                size: 1,
                hash: "h".into(),
            },
            terminal: false,
            authz: None,
        };
        let text = serde_json::to_string(&plain).unwrap();
        assert!(!text.contains("authz"), "{text}");

        let issuer = crate::Identity::generate();
        let grant = crate::grant::SignedGrant::sign(
            &issuer,
            "c1",
            "n1",
            crate::NodePolicy::exec(),
            1,
            2,
            "jti-1",
        )
        .unwrap();
        let sealed = Envelope::Transfer {
            request_id: "t1".into(),
            node_id: "n1".into(),
            client_id: "c1".into(),
            msg: TransferMsg::Commit {
                size: 1,
                hash: "h".into(),
            },
            terminal: false,
            authz: Some(grant.clone()),
        };
        let text = serde_json::to_string(&sealed).unwrap();
        let back: Envelope = serde_json::from_str(&text).unwrap();
        match back {
            Envelope::Transfer { authz: Some(back), msg, .. } => {
                assert_eq!(back, grant);
                assert!(matches!(msg, TransferMsg::Commit { size: 1, .. }));
            }
            other => panic!("expected transfer with authz, got {other:?}"),
        }
    }

    #[test]
    fn search_defaults_and_roundtrip() {
        let raw = r#"{"op":"search","path":".","pattern":"fn "}"#;
        let op: Op = serde_json::from_str(raw).unwrap();
        match op {
            Op::Search {
                gitignore,
                literal,
                limit,
                pattern,
                ..
            } => {
                assert!(gitignore);
                assert!(!literal);
                assert_eq!(limit, 0);
                assert_eq!(pattern, "fn ");
            }
            _ => panic!("variant"),
        }
        let pty = Op::PtyOpen {
            command: None,
            cwd: Some("/tmp".into()),
            rows: 24,
            cols: 80,
        };
        let text = serde_json::to_string(&pty).unwrap();
        let back: Op = serde_json::from_str(&text).unwrap();
        assert_eq!(back.kind(), "pty_open");
    }

    #[test]
    fn result_defaults_to_terminal() {
        let raw = r#"{"type":"result","request_id":"r","ok":true}"#;
        let env: Envelope = serde_json::from_str(raw).unwrap();
        match env {
            Envelope::Result { terminal, .. } => assert!(terminal),
            _ => panic!("variant"),
        }
    }

    #[test]
    fn extension_audit_skips_image_bytes_and_long_text() {
        let shot = Op::Extension {
            name: "screenshot".into(),
            payload: serde_json::json!({
                "target": "region",
                "x": 1,
                "y": 2,
                "format": "png",
                "data_b64": "AAAA-image-bytes",
            }),
        };
        let detail = shot.audit_detail();
        assert!(detail.contains("screenshot"));
        assert!(detail.contains("region"));
        assert!(detail.contains("@1,2"));
        assert!(!detail.contains("AAAA-image-bytes"));

        let typed = Op::Extension {
            name: "inject_input".into(),
            payload: serde_json::json!({
                "action": "type",
                "text": "super-secret-password",
            }),
        };
        let detail = typed.audit_detail();
        assert!(detail.contains("inject_input"));
        assert!(detail.contains("type"));
        assert!(detail.contains("21 chars"));
        assert!(!detail.contains("super-secret-password"));
        assert!(detail.contains("super-secret"));
    }
}
