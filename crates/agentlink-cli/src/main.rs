//! `agentlink` binary: relay, node, CLI, and MCP server.
#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

mod account;
mod audit_cmd;
mod bench_cmd;
mod endpoint;
mod fetch;
mod mcp;
mod mcp_http;
mod node_cfg;
#[cfg(test)]
mod reconnect_test;
mod service;
#[cfg(windows)]
mod service_win;
mod signature;
mod terminal;
mod tray;
#[cfg(windows)]
mod tray_win;
mod controller;
mod grant_local;
mod identity_cmd;
mod status_cmd;
mod update;
mod version;

use std::io::{IsTerminal, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use agentlink_core::engine::XferOpts;
use agentlink_core::protocol::{CompressPref, NodeInfo, TransferStats};
use agentlink_core::{
    encode_invite, load_settings, operate_guide_url, parse_access, save_settings,
    Client, ClientSettings, ExecRequest, Identity, Invite, NodePolicy, Op, OperateGuide,
    PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT,
};
use agentlink_relay::{serve, RelayConfig};
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use clap::parser::ValueSource;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use endpoint::{parse_endpoint, Endpoint};
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

/// A pointer coordinate: absolute pixels when whole, otherwise a 0–1
/// fraction of the primary monitor (same as Android and web JPEG clicks).
#[derive(Debug, Clone, Copy, PartialEq)]
struct Coord(f64);

impl Coord {
    /// Emit an integer JSON number when whole so `1920` stays a pixel and
    /// `0.5` stays a fraction.
    fn as_json(self) -> Value {
        if self.0.fract() == 0.0 && self.0.abs() <= i64::MAX as f64 {
            json!(self.0 as i64)
        } else {
            json!(self.0)
        }
    }
}

impl std::str::FromStr for Coord {
    type Err = String;

    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        let value: f64 = text
            .trim()
            .parse()
            .map_err(|_| format!("`{text}` is not a number"))?;
        if !value.is_finite() {
            return Err(format!("`{text}` must be finite"));
        }
        Ok(Self(value))
    }
}

impl std::fmt::Display for Coord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.0.fract() == 0.0 && self.0.abs() <= i64::MAX as f64 {
            write!(f, "{}", self.0 as i64)
        } else {
            write!(f, "{}", self.0)
        }
    }
}

impl Default for Coord {
    fn default() -> Self {
        Self(0.0)
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "agentlink",
    version = version::current(),
    about = "Access your Linux, Windows, and macOS machines from agents and the terminal",
    arg_required_else_help = true
)]
struct Cli {
    /// Print JSON to stdout.
    #[arg(long, global = true)]
    json: bool,

    /// Relay URL. Required unless `AGENTLINK_RELAY` or a saved config sets one.
    /// There is no built-in relay. `wss://host` dials 443. An explicit port is
    /// kept. A bare host with no scheme defaults to port 7443.
    #[arg(long, global = true, env = "AGENTLINK_RELAY")]
    relay: Option<String>,

    /// Relay admin token.
    #[arg(long, global = true, env = "AGENTLINK_TOKEN")]
    token: Option<String>,

    /// Relay certificate check. `sha256:<hex>` pins the leaf. `spki:sha256:<hex>`
    /// pins the leaf public key (stable when the key is reused).
    /// `intermediate:sha256:<hex>` pins the issuing intermediate and checks the
    /// hostname. `system` uses the OS trust store. `webpki` uses Mozilla roots.
    #[arg(long, global = true, env = "AGENTLINK_FINGERPRINT")]
    fingerprint: Option<String>,

    /// Verify the relay with public roots: `system` or `webpki`.
    /// When a pin is also set, both checks must succeed. `--ca` is an alias.
    #[arg(long, visible_alias = "ca", global = true, env = "AGENTLINK_TRUST")]
    trust: Option<String>,

    /// Directory containing client config.json.
    #[arg(long, global = true, env = "AGENTLINK_CONFIG_DIR")]
    config_dir: Option<PathBuf>,

    /// Stable ed25519 identity. With a token this is the admin key. Without a
    /// token the relay treats the process as a registered agent.
    #[arg(long, global = true, env = "AGENTLINK_IDENTITY")]
    identity: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum BgCommand {
    Start {
        #[arg(long)]
        cwd: Option<String>,
        /// Environment variable `KEY=VALUE`. Repeatable.
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        #[arg(long)]
        shell: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    List,
    Output {
        id: String,
        #[arg(long, default_value_t = 0)]
        stdout_cursor: u64,
        #[arg(long, default_value_t = 0)]
        stderr_cursor: u64,
        #[arg(long, default_value_t = 65536)]
        max_bytes: u32,
    },
    Status {
        id: String,
    },
    Kill {
        id: String,
    },
}

/// When `cp` prints a transfer progress line on stderr.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
enum CpProgressMode {
    /// While stderr is a terminal.
    Auto,
    /// Always, including pipes and `--json`.
    On,
    /// Never.
    Off,
}

#[derive(Args, Debug)]
struct RelayArgs {
    /// Listen address.
    #[arg(long, default_value = "0.0.0.0:7443")]
    bind: String,
    /// Certificate, admin token, and enrollment live here.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Postgres URL. Empty uses SQLite at `<data-dir>/relay.db`.
    #[arg(long, env = "AGENTLINK_DATABASE_URL")]
    database_url: Option<String>,
    /// Accept `Signup` from the network. Off unless set.
    #[arg(long)]
    allow_signup: bool,
    /// Print the admin token even when the store already exists.
    /// Leave this off in a service unit so the token stays out of the journal.
    #[arg(long)]
    print_admin_token: bool,
    /// Trust X-Forwarded-For and X-Real-IP when the TCP peer is in this CIDR.
    /// Repeat for more than one proxy. A bare IP means a single host.
    /// Example: `--trust-proxy 127.0.0.1/32`.
    #[arg(long = "trust-proxy")]
    trust_proxy: Vec<String>,
    #[command(subcommand)]
    action: Option<account::RelayAction>,
}

#[derive(Args, Debug)]
struct NodeArgs {
    /// Display name. Defaults to the hostname.
    #[arg(long)]
    name: Option<String>,
    /// One-time token from `agentlink pair`.
    #[arg(long)]
    pairing_token: Option<String>,
    /// Invite string from `agentlink pair` (`agentlink-invite:v1:...`).
    /// It carries the relay URL, trust mode, and pairing token.
    #[arg(long)]
    invite: Option<String>,
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Confine file paths, and the exec working directory, to this directory.
    #[arg(long)]
    root: Option<PathBuf>,
    /// Local permission ceiling: read-only, read-write, exec, desktop, remote-view, remote-control, or full.
    #[arg(long)]
    max_access: Option<String>,
    /// Consent before a viewer attaches: auto, notify, prompt, or deny.
    #[arg(long, default_value = "notify")]
    stream_consent: String,
    /// Command allow glob. Repeatable. Written to limits.json.
    #[arg(long = "allow-cmd")]
    allow_cmd: Vec<String>,
    /// Command deny glob. Deny wins. Written to limits.json.
    #[arg(long = "deny-cmd")]
    deny_cmd: Vec<String>,
    /// Seconds to wait for `agentlink approve` before a held op is denied.
    #[arg(long)]
    confirm_timeout: Option<u64>,
    /// Audit preset written to audit.toml before the node starts: minimal, standard, full, paranoid.
    #[arg(long)]
    audit_preset: Option<String>,
}

#[derive(Args, Debug)]
struct CpArgs {
    src: String,
    dst: String,
    /// Chunk size, for example `1MiB` or `256KiB`.
    #[arg(long, default_value = "1MiB")]
    chunk_size: String,
    /// Chunks kept in flight.
    #[arg(long, default_value_t = 8)]
    window: usize,
    /// Workers that pull different ranges at once.
    #[arg(long, default_value_t = 4)]
    parallel: usize,
    /// `auto`, `on`, or `off`. Auto skips formats that are already compressed.
    #[arg(long, default_value = "auto")]
    compress: String,
    /// Stay on the relay instead of trying a direct QUIC path.
    #[arg(long = "no-direct", action = clap::ArgAction::SetTrue)]
    no_direct: bool,
    /// Progress on stderr: `auto`, `on`, or `off`.
    ///
    /// `auto` (default) prints while stderr is a terminal. `on` always
    /// prints. `off` stays quiet. `--progress` with no value means `on`.
    ///
    /// A terminal gets one updating line (bytes done / total, percent,
    /// throughput, and ETA). Forced progress on a pipe prints a new line
    /// about twice a second. Directory copies show overall progress of the
    /// archive stream. With `--json`, the line stays on stderr and stdout
    /// is only the final JSON object.
    #[arg(
        long,
        value_enum,
        default_value = "auto",
        num_args = 0..=1,
        default_missing_value = "on",
        require_equals = true,
        value_name = "WHEN"
    )]
    progress: CpProgressMode,
}

#[derive(Args, Debug)]
struct SearchArgs {
    node: String,
    pattern: String,
    /// Directory or file. Defaults to `.`.
    path: Option<String>,
    #[arg(long)]
    literal: bool,
    #[arg(long)]
    include: Vec<String>,
    #[arg(long)]
    exclude: Vec<String>,
    #[arg(long)]
    include_hidden: bool,
    #[arg(long)]
    ignore_case: bool,
    #[arg(long)]
    no_gitignore: bool,
    #[arg(long, default_value_t = 0)]
    before: u32,
    #[arg(long, default_value_t = 0)]
    after: u32,
    #[arg(long, default_value_t = 0)]
    offset: u32,
    #[arg(long, default_value_t = 100)]
    limit: u32,
}

#[derive(Args, Debug)]
struct FindArgs {
    node: String,
    pattern: String,
    path: Option<String>,
    #[arg(long)]
    regex: bool,
    #[arg(long)]
    include_hidden: bool,
    #[arg(long)]
    ignore_case: bool,
    #[arg(long)]
    no_gitignore: bool,
    #[arg(long, default_value_t = 0)]
    offset: u32,
    #[arg(long, default_value_t = 200)]
    limit: u32,
}

#[derive(Args, Debug)]
struct ScreenshotArgs {
    node: String,
    /// Optional output path (same as `--out`). Lets `screenshot NODE path.jpg` work.
    #[arg(value_name = "OUT")]
    out_path: Option<PathBuf>,
    /// screen, monitor, region, window, or monitors.
    #[arg(long, default_value = "screen")]
    target: String,
    #[arg(long)]
    monitor: Option<u32>,
    /// Window id or a title substring.
    #[arg(long)]
    window_id: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    x: Option<i64>,
    #[arg(long, allow_hyphen_values = true)]
    y: Option<i64>,
    #[arg(long)]
    width: Option<u64>,
    #[arg(long)]
    height: Option<u64>,
    /// png, jpeg, webp, or auto (from `--out` / OUT extension; jpeg if unknown).
    #[arg(long = "format", default_value = "auto")]
    image_format: String,
    #[arg(long, default_value_t = 80)]
    quality: u8,
    /// Scale factor from 0.05 to 1.
    #[arg(long, default_value_t = 1.0)]
    scale: f32,
    /// Image path. Same as the optional positional `OUT`. Without `--json`, a
    /// file is written even when both are omitted (auto-named in cwd).
    #[arg(long)]
    out: Option<PathBuf>,
}

#[derive(Args, Debug)]
struct ClickArgs {
    node: String,
    /// X pixel, or 0–1 fraction of the primary monitor.
    x: Coord,
    /// Y pixel, or 0–1 fraction of the primary monitor.
    y: Coord,
    #[arg(long, default_value = "left")]
    button: String,
    #[arg(long, default_value_t = 1)]
    count: u32,
    /// Drag target X pixel, or 0–1 fraction of the primary monitor.
    #[arg(long, allow_hyphen_values = true)]
    to_x: Option<Coord>,
    /// Drag target Y pixel, or 0–1 fraction of the primary monitor.
    #[arg(long, allow_hyphen_values = true)]
    to_y: Option<Coord>,
    /// Move the pointer and do not click.
    #[arg(long)]
    move_only: bool,
}

#[derive(Args, Debug)]
struct ControllerArgs {
    /// Node data directory shown for this computer. Defaults to the per-user directory.
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// Hide the window until the status icon is opened. The window stays
    /// visible when this session has no icon.
    #[arg(long)]
    background: bool,
    /// Print whether this build includes the window, then exit.
    #[arg(long)]
    check: bool,
    /// Listen for JSON-line debug commands on this Unix socket.
    #[arg(long, value_name = "PATH")]
    debug_socket: Option<PathBuf>,
    /// Drive the UI with mock desktop frames (no relay).
    #[arg(long)]
    mock: bool,
    /// Run without a real window (logical egui loop). Pair with `--debug-socket`.
    #[arg(long)]
    headless: bool,
    /// Mock only: fail the session connect so the UI lands in the error state.
    #[arg(long)]
    fail_connect: bool,
    /// Seconds to wait for the first frame before marking the session failed.
    #[arg(long, default_value_t = 12)]
    connect_timeout_secs: u64,
    /// Capture/encode fps cap sent in the live offer (default 30).
    #[arg(long, default_value_t = 30)]
    max_fps: u32,
    /// Append client perf CSV every 2s (fps, decode/present ms, stalls…).
    #[arg(long, value_name = "PATH")]
    perf_log: Option<PathBuf>,
    /// Open this node's desktop as soon as the machine list loads.
    ///
    /// Skips the machines page, which makes headless screenshotting and
    /// smoke tests possible without synthesising clicks.
    #[arg(long, value_name = "NODE")]
    open_desktop: Option<String>,
    /// Isolated layout fixture. Temporary directories, labeled sample
    /// machines, no live account, and no production auto-start.
    #[arg(long)]
    preview_ui: bool,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run the relay. Nodes and clients connect out to it.
    Relay(Box<RelayArgs>),
    /// Run a node daemon. It dials the relay and reconnects on its own.
    Node(Box<NodeArgs>),
    /// Mint a one-time pairing token.
    Pair {
        #[arg(long)]
        name: String,
        /// Kept for older scripts. Connected use is full; this value is not a cap.
        #[arg(long, default_value = "full")]
        access: String,
        /// Lifetime in minutes.
        #[arg(long, default_value_t = 15)]
        ttl_minutes: u64,
    },
    /// List paired machines.
    Nodes,
    /// List machines, or list a directory when a node is given.
    Ls {
        /// Node name or id. Omit to list machines.
        node: Option<String>,
        /// Directory on the node. Defaults to the node process working directory.
        path: Option<String>,
    },
    /// Print a remote file. Bytes stream to stdout. `--json` stops at 1 MiB.
    Cat { node: String, path: String },
    /// Write a remote file from `--content` or stdin, without buffering the stream.
    /// Path `-` is rejected (that would create a literal file named `-`); pipe stdin to a real path.
    Write {
        node: String,
        path: String,
        #[arg(long)]
        content: Option<String>,
    },
    /// Copy a file or directory. Endpoints are local paths or `node://name/path`. A file copied onto an existing directory lands inside it (Unix `cp`).
    Cp(Box<CpArgs>),
    /// Create a directory on a node.
    Mkdir {
        node: String,
        path: String,
        /// Create intermediate directories (Unix `mkdir -p`).
        #[arg(short = 'p', long)]
        parents: bool,
    },
    /// Remove a file or directory on a node.
    #[command(visible_aliases = ["delete", "remove"])]
    Rm {
        node: String,
        path: String,
        /// Remove directories and their contents (Unix `rm -r` / `rm -R`).
        #[arg(short = 'r', long, short_aliases = ['R'])]
        recursive: bool,
    },
    /// Rename or move a path on a node. An existing directory destination receives the source basename (Unix `mv`).
    #[command(visible_aliases = ["move", "rename"])]
    Mv {
        node: String,
        from: String,
        to: String,
    },
    /// Run a command on a node. Non-terminal stdin is forwarded (max 16 MiB).
    Exec {
        node: String,
        /// Working directory on the node.
        #[arg(long)]
        cwd: Option<String>,
        /// Environment variable `KEY=VALUE`. Repeatable. Prefer this over
        /// shell `set`/`export` — Windows `cmd` expands `%VAR%` at parse time.
        #[arg(long = "env", value_name = "KEY=VALUE")]
        env: Vec<String>,
        /// Timeout in seconds. 0 waits without a timeout.
        #[arg(long, default_value_t = 60)]
        timeout_secs: u64,
        /// Join the arguments into one command line and run them in the platform shell.
        #[arg(long)]
        shell: bool,
        /// Program and arguments.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        cmd: Vec<String>,
    },
    /// Search file contents. Respects `.gitignore` unless `--no-gitignore`.
    ///
    /// Order is `search <NODE> <PATTERN> [PATH]`. Putting a path before the
    /// pattern (`search example /tmp needle`) is rejected with a did-you-mean.
    #[command(visible_alias = "grep")]
    Search(Box<SearchArgs>),
    /// Search file names by glob, or by regex with `--regex`.
    ///
    /// Machine name comes first (`agentlink find example '*.rs'`). Swapping
    /// node and pattern yields a clear error instead of `not found: node '*.rs'`.
    /// Putting PATH before PATTERN (`find example /tmp '*.rs'`) is also rejected
    /// with a did-you-mean pointing at `find NODE PATTERN PATH`. Unix `-name`/
    /// `-iname` predicates are rejected with a did-you-mean too.
    Find(Box<FindArgs>),
    /// Replace an exact string. Fails when the match is not unique unless `--all`.
    ///
    /// `edit` is a visible alias (agents and muscle memory often reach for it).
    #[command(visible_alias = "edit")]
    Replace {
        node: String,
        path: String,
        old: String,
        new: String,
        #[arg(long)]
        all: bool,
    },
    /// Replace a 1-based inclusive line range. `end` equal to one past the last line appends.
    EditLines {
        node: String,
        path: String,
        start: u32,
        end: u32,
        content: String,
    },
    /// Apply a unified diff. Read the patch from `--file`, `--file -`, or stdin.
    Patch {
        node: String,
        /// Directory the patch paths are relative to.
        root: String,
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Stream filesystem events until Ctrl-C or `--timeout-secs`.
    Watch {
        node: String,
        path: String,
        #[arg(long)]
        no_recursive: bool,
        /// 0 waits until Ctrl-C.
        #[arg(long, default_value_t = 0)]
        timeout_secs: u64,
    },
    /// Background processes: start, list, output, status, kill.
    Bg {
        node: String,
        #[command(subcommand)]
        action: BgCommand,
    },
    /// Operating system, CPU, memory, disks, filtered environment, and key tools.
    #[command(visible_alias = "sys")]
    Sysinfo { node: String },
    /// Open a shell. Raw mode with resize, unless `--line` or stdin is not a terminal.
    /// With `--command` and a non-terminal stdin, runs like `exec --shell` so the
    /// remote process gets a real EOF (max 16 MiB).
    Shell {
        node: String,
        #[arg(long)]
        command: Option<String>,
        #[arg(long)]
        cwd: Option<String>,
        #[arg(long)]
        line: bool,
    },
    /// Capture the screen, a monitor, a region, or a window.
    Screenshot(Box<ScreenshotArgs>),
    /// Move, click, or drag. Coordinates are pixels, or 0–1 fractions of the
    /// primary monitor (same as Android / web JPEG).
    Click(Box<ClickArgs>),
    /// Type Unicode text.
    Type { node: String, text: String },
    /// Press a key combo, for example ctrl+shift+a.
    Key { node: String, keys: String },
    /// Scroll. Positive dy moves up. `--x`/`--y` are pixels or 0–1 fractions of the primary monitor.
    /// Omit both to scroll at the current pointer without moving it.
    Scroll {
        node: String,
        /// Allow `--x -10` (clap otherwise treats `-10` as a flag).
        #[arg(long, allow_hyphen_values = true)]
        x: Option<Coord>,
        #[arg(long, allow_hyphen_values = true)]
        y: Option<Coord>,
        #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
        dx: i32,
        /// Positive moves up. `--dy -3` must parse (not only `--dy=-3`).
        #[arg(long, default_value_t = 0, allow_hyphen_values = true)]
        dy: i32,
    },
    /// Print the accessibility tree.
    UiTree {
        node: String,
        #[arg(long, default_value_t = 6)]
        max_depth: u32,
        #[arg(long, default_value_t = 400)]
        max_nodes: u32,
    },
    /// Click, focus, or set the value of one accessibility element.
    UiAct {
        node: String,
        id: String,
        /// click, focus, or set_value.
        #[arg(long, default_value = "click")]
        op: String,
        #[arg(long)]
        value: Option<String>,
    },
    /// Removed. Browser desktop control is not a sealed channel.
    ///
    /// The command fails. Control the node from a sealed client after the
    /// node operator has issued a grant for that client's key.
    #[command(visible_alias = "desktop")]
    View {
        node: String,
        /// Print the URL without launching a browser.
        #[arg(long)]
        no_open: bool,
        /// Monitor index on the node.
        #[arg(long)]
        monitor: Option<u32>,
        /// Ask for a ticket that can inject input. Off by default.
        #[arg(long)]
        control: bool,
    },
    /// Print or open a documentation-only how-to link for a node.
    ///
    /// The URL carries display metadata in its fragment and no secrets. It is
    /// not a grant or a ticket; the relay page only explains how to operate the
    /// node. Use `--local` on the node host to build it without listing nodes.
    Guide {
        /// Node name or id. Required unless `--local` is set.
        node: Option<String>,
        /// Build the guide for this machine from its node data directory.
        #[arg(long)]
        local: bool,
        /// Node data directory for `--local`. Defaults to the per-user node dir.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Print the URL without launching a browser.
        #[arg(long)]
        no_open: bool,
        /// Print the URL without launching a browser (alias of `--no-open`).
        #[arg(long)]
        print_only: bool,
    },
    /// Replace a node's relay permission preset.
    Perm {
        node: String,
        /// read-only, read-write, exec, desktop, remote-view, remote-control, or full.
        access: String,
    },
    /// MCP server on stdio, or streamable HTTP when `--http` is set.
    Mcp {
        /// Listen address, for example `127.0.0.1:7337`. Omit to use stdio.
        #[arg(long)]
        http: Option<String>,
        /// Bearer token required by the HTTP transport.
        #[arg(long, env = "AGENTLINK_MCP_TOKEN")]
        mcp_token: Option<String>,
    },
    /// Register, list, grant, or revoke an agent identity.
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },
    /// List or resolve operations held for human confirmation.
    Approve {
        #[command(subcommand)]
        action: ApproveAction,
    },
    /// Query the audit log, or edit its policy and sinks.
    Audit {
        #[command(subcommand)]
        action: audit_cmd::AuditAction,
    },
    /// Save the relay URL, token, and fingerprint for later commands.
    ///
    /// `--user` exchanges a password for a device session, the same flow the
    /// Android app uses.
    Login {
        /// Account name. Omit this to save a legacy admin token from `--token`.
        #[arg(long)]
        user: Option<String>,
        /// Read the password from stdin instead of hiding a terminal prompt.
        #[arg(long)]
        password_stdin: bool,
        /// TOTP code, when the account has authenticator enabled.
        #[arg(long)]
        totp: Option<String>,
        /// Name recorded for this device key.
        #[arg(long, default_value = "cli")]
        device_name: String,
    },
    /// Share one of your nodes with another account.
    Share {
        node: String,
        #[arg(long)]
        with: String,
        /// Kept for older scripts. A share is full use of the machine.
        #[arg(long, default_value = "full")]
        access: String,
    },
    /// Remove a share.
    Unshare {
        node: String,
        #[arg(long)]
        with: String,
    },
    /// Create, list, or revoke an enrollment token.
    Token {
        #[command(subcommand)]
        action: account::TokenAction,
    },
    /// Manage accounts on the relay you are logged into.
    User {
        #[command(subcommand)]
        action: account::UserAction,
    },
    /// Forget the saved session and revoke its refresh token.
    Logout,
    /// List devices, or revoke one with `--revoke`.
    Devices {
        /// Device id (the device public key) to revoke.
        #[arg(long)]
        revoke: Option<String>,
    },
    /// Sign in and open machines, a shell, files, and remote desktop.
    ///
    /// The window ships in the Windows, macOS, and glibc Linux builds. A musl
    /// binary prints how to build the glibc controller instead.
    Controller(Box<ControllerArgs>),
    /// Notification-area icon and status window.
    ///
    /// On Windows this is the user-scope node. With no subcommand it opens
    /// the window. Start-on-login uses HKCU and does not need an administrator.
    Tray {
        /// Node data directory. Defaults to the per-user agentlink data directory.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Stay in the notification area until the icon is clicked.
        #[arg(long)]
        background: bool,
        /// Node display name used when signing in or applying an invite.
        #[arg(long)]
        name: Option<String>,
        #[command(subcommand)]
        action: Option<TrayCommand>,
    },
    /// Install or control the node background service.
    Service {
        #[command(subcommand)]
        action: service::Action,
    },
    /// Check GitHub Releases, verify the archive, and replace this binary.
    Update(update::UpdateArgs),
    /// Loopback throughput and latency. Prints a markdown table.
    Bench {
        /// Skip the 100 MiB file, the sparse 1 GiB file, and the larger file set.
        #[arg(long)]
        quick: bool,
        /// Also write the markdown table to this path.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Release signing helper.
    #[command(hide = true)]
    Internal {
        #[command(subcommand)]
        action: signature::InternalAction,
    },
    /// Offline diagnosis of identity, relay transport, and local grants.
    ///
    /// Does not contact the relay. Exit 0 when the command itself succeeds.
    /// A relay session is not a grant. Never prints private keys or tokens.
    Status,
    /// Offline local identity. Not a grant and not a relay login.
    ///
    /// `grant offer` remains the way to produce a controller card.
    Identity {
        #[command(subcommand)]
        action: IdentityAction,
    },
    /// Owner-signed grants for end-to-end operations on a node.
    Grant {
        #[command(subcommand)]
        action: GrantCommand,
    },
    /// TCP port forwarding through a node. Both listeners bind loopback.
    Port {
        #[command(subcommand)]
        action: PortCommand,
    },
}

#[derive(Subcommand, Debug)]
enum IdentityAction {
    /// Print the public id and fingerprint. Errors if the file is missing.
    Show,
    /// Create the identity file only when missing; otherwise re-read it.
    Create,
    /// Same as `create`: reuse a present file, never rotate, fail if corrupt.
    Ensure,
}

#[derive(Subcommand, Debug)]
enum PortCommand {
    /// Listen on 127.0.0.1:LOCAL_PORT and forward to REMOTE_HOST:PORT on the node.
    Forward {
        node: String,
        local_port: u16,
        /// host:port on the node (IPv6 as [addr]:port).
        remote: String,
    },
    /// Ask the node to listen on 127.0.0.1:REMOTE_PORT and forward to [LOCAL_HOST:]LOCAL_PORT here.
    Reverse {
        node: String,
        remote_port: u16,
        /// Local target: PORT or HOST:PORT (default host 127.0.0.1).
        local: String,
    },
    /// Show active port maps. Maps live in the forward/reverse processes only.
    #[command(visible_alias = "list")]
    Status,
}

#[derive(Subcommand, Debug)]
enum GrantCommand {
    /// Sign a time-limited grant and store it for a node.
    Issue {
        /// Node name or public id.
        #[arg(long)]
        node: String,
        /// Lifetime: seconds (`900`) or units (`15m`, `1h`, `7d`, `1h30m`).
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Access preset: `read-only`, `read-write`, `exec`, `desktop`, `remote-view`, `remote-control`, or `full`.
        #[arg(long, default_value = "full")]
        policy: String,
        /// Grantee public key hex. Defaults to this CLI's identity.
        #[arg(long)]
        grantee: Option<String>,
        /// Node data directory holding grant-issuer.json and owner-keys.json.
        /// Defaults to AGENTLINK_ISSUER_DATA_DIR, then the default node data dir
        /// (~/.local/share/agentlink/node) when it already has issuer artifacts;
        /// otherwise signs with this CLI's operator identity.
        /// Local issue uses this directory and does not require a relay admin token
        /// when the node name is pinned or matches this node's identity.
        #[arg(long)]
        issuer_data_dir: Option<PathBuf>,
        /// Write the raw grant JSON here (`-` prints it) instead of stdout summary.
        #[arg(long)]
        out: Option<String>,
    },
    /// Re-sign the stored grant for a node with the same grantee and policy.
    Refresh {
        /// Node name or public id.
        #[arg(long)]
        node: String,
        /// Lifetime: seconds (`900`) or units (`15m`, `1h`, `7d`, `1h30m`).
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Node data directory holding grant-issuer.json and owner-keys.json.
        /// Defaults to AGENTLINK_ISSUER_DATA_DIR, then the default node data dir
        /// (~/.local/share/agentlink/node) when it already has issuer artifacts;
        /// otherwise signs with this CLI's operator identity.
        #[arg(long)]
        issuer_data_dir: Option<PathBuf>,
        /// Write the raw grant JSON here (`-` prints it) instead of stdout summary.
        #[arg(long)]
        out: Option<String>,
    },
    /// Ensure a usable local grant: reuse a valid one, refresh an expired one,
    /// or issue a new one. Prints the action taken.
    Ensure {
        /// Node name or public id.
        #[arg(long)]
        node: String,
        /// Lifetime: seconds (`900`) or units (`15m`, `1h`, `7d`, `1h30m`).
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Access preset used only when a new grant is issued; refresh keeps the stored policy.
        /// `read-only`, `read-write`, `exec`, `desktop`, `remote-view`, `remote-control`, or `full`.
        #[arg(long, default_value = "full")]
        policy: String,
        /// Grantee public key hex. Defaults to this CLI's identity.
        #[arg(long)]
        grantee: Option<String>,
        /// Node data directory holding grant-issuer.json and owner-keys.json.
        /// Defaults to AGENTLINK_ISSUER_DATA_DIR, then the default node data dir
        /// (~/.local/share/agentlink/node) when it already has issuer artifacts;
        /// otherwise signs with this CLI's operator identity.
        #[arg(long)]
        issuer_data_dir: Option<PathBuf>,
    },
    /// Print the stored grant for a node.
    Show {
        #[arg(long)]
        node: String,
    },
    /// List stored grants.
    List,
    /// Delete the local grant file for a node (alias: `clear`).
    /// Local only: the node still accepts the grant until it expires unless
    /// `grant revoke` added its jti to the node deny-list.
    #[command(visible_alias = "clear")]
    RevokeLocal {
        #[arg(long)]
        node: String,
    },
    /// Revoke a grant on this machine's node data directory.
    ///
    /// Writes `<data-dir>/revoked-grants.json`. The node reads that file. A
    /// remote revoke is not sent and is not accepted. A command that already
    /// started is not killed; the next request and any recorded terminal are
    /// denied.
    Revoke {
        /// Node name or public id. Used to find the local grant file.
        #[arg(long)]
        node: String,
        /// Node data directory on this machine. Defaults to
        /// ~/.local/share/agentlink/node when that directory already holds a
        /// node identity. The jti is appended to revoked-grants.json there.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Grant jti to revoke. Defaults to the stored local grant for this node.
        #[arg(long)]
        jti: Option<String>,
        /// Ignored. Revoke does not sign or send a remote request.
        #[arg(long, hide = true)]
        issuer_data_dir: Option<PathBuf>,
    },
    /// List grant *requests* stored on this node. A request is not a grant.
    /// Local only: does not contact the relay.
    Pending {
        /// Node data directory holding grant-requests/. Defaults to the local node dir.
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Approve a pending request by signing a grant with this node's issuer.
    ///
    /// Local only. This is not `approve allow` (held destructive ops) and it
    /// is not a remote RPC.
    Allow {
        /// Pending request id.
        request_id: String,
        /// Node data directory on this machine.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Write the signed grant JSON here (`-` prints it) in addition to storing it.
        #[arg(long)]
        out: Option<String>,
        /// Optional narrower policy than the request (target may shrink, never enlarge).
        #[arg(long)]
        policy: Option<String>,
        /// Optional shorter ttl than the request (target may shrink, never extend).
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Deny a pending grant request on this node. Local only.
    Deny {
        request_id: String,
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Show a local Allow / Deny prompt for a pending request on this node.
    ///
    /// Uses a desktop dialog when DISPLAY is set, otherwise a tty prompt.
    /// This is not `approve allow` and cannot be invoked as a remote grant.
    Prompt {
        /// Pending request id. Defaults to the oldest still-pending request.
        request_id: Option<String>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Optional narrower policy than the request (target may shrink, never enlarge).
        #[arg(long)]
        policy: Option<String>,
        /// Optional shorter ttl than the request (target may shrink, never extend).
        #[arg(long)]
        ttl: Option<String>,
    },
    /// 控制端（远程）：生成一张身份码，复制到【目标机】本地粘贴。
    ///
    /// 公开身份不是凭证，身份码不是 grant，relay 不能据此授权。
    /// 此命令只使用本机身份文件，不需要 relay 登录。
    Offer {
        /// 请求的权限预设。`desktop` 含 exec 与文件读写，会写在码里并在目标机展示。
        #[arg(long, default_value = "desktop")]
        policy: String,
        /// 若目标机同意，grant 的有效期。
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// 可选：绑定目标机 64 位公钥，防止跨目标粘贴。
        #[arg(long)]
        node: Option<String>,
        /// 身份码本身过期时间（默认 10m），过期后目标机必须要求控制端重发。
        #[arg(long, default_value = "10m")]
        offer_ttl: String,
        /// 可选：绑定 relay 证书指纹（不同命名空间拒绝）。
        #[arg(long)]
        relay_fp: Option<String>,
        /// 把身份码写到文件（`-` 打印到 stdout）。默认打印到终端。
        #[arg(long)]
        out: Option<String>,
    },
    /// 目标机（本地）：粘贴控制端身份码或完整 64 位公钥，形成待批请求。
    ///
    /// 不会签发 grant。核对指纹与实际权限后，再 `grant allow` 或 `--prompt`。
    /// 目标机图形入口：弹出粘贴框，核对指纹后再批准。不只 CLI。
    PasteUi {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        policy: Option<String>,
        #[arg(long)]
        ttl: Option<String>,
    },
    Paste {
        /// `grant offer` 的整行，或 64 位控制端公钥。省略则打开本机图形/终端粘贴框。
        card: Option<String>,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// 仅当粘贴裸公钥时需要（身份码已自带策略）。
        #[arg(long)]
        policy: Option<String>,
        /// 仅当粘贴裸公钥时需要。
        #[arg(long)]
        ttl: Option<String>,
        /// 粘贴校验通过后，在本机弹出 Allow/Deny（不是 `approve allow`）。
        #[arg(long)]
        prompt: bool,
    },
    /// Record a pending request on this node without signing a grant.
    ///
    /// The request cannot be used for control until `grant allow` is run
    /// locally as the node user.
    Request {
        /// Grantee (controller) public key hex.
        #[arg(long)]
        grantee: String,
        /// Access preset. See the printed capability list; `desktop` includes exec.
        #[arg(long, default_value = "desktop")]
        policy: String,
        /// Lifetime of the grant if later allowed (`15m`, `1h`, `7d`).
        #[arg(long, default_value = "1h")]
        ttl: String,
        /// Node data directory. Defaults to the local node dir.
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
    /// Trust an additional owner issuer key in a node data directory.
    TrustOwner {
        /// Issuer public key hex.
        key: String,
        /// Node data directory. Defaults to the node's default data directory.
        #[arg(long)]
        data_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
enum TrayCommand {
    /// Register start-on-login for the current user. Does not need an administrator.
    Install {
        /// Print the HKCU Run command and write nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove start-on-login.
    Uninstall,
    /// Print relay connection, pairing, and account status.
    Status,
}

#[derive(Subcommand, Debug)]
enum ClientAction {
    /// Create a key file and register it with the relay. Prints the public id.
    Create {
        name: String,
        /// Where to write the secret key. Defaults to `./<name>.identity.json`.
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// List registered agents.
    List,
    /// Tell the relay this agent may be routed to a node.
    ///
    /// This does not authorize the machine. The node still requires a signed
    /// grant for the agent's key, clipped by --max-access.
    Grant {
        client: String,
        node: String,
        /// read-only, read-write, exec, desktop, remote-view, remote-control, or full.
        access: String,
    },
    /// Revoke an agent. Existing sockets are not killed until they reconnect.
    Revoke { client: String },
}

#[derive(Subcommand, Debug)]
enum ApproveAction {
    /// List operations waiting for a decision.
    List,
    /// Allow one held operation.
    Allow { approval_id: String, node: String },
    /// Deny one held operation.
    Deny { approval_id: String, node: String },
}

fn main() {
    #[cfg(windows)]
    prepare_stdio();
    let argv = normalize_cli_argv(std::env::args_os());
    if let Some(hint) = find_unix_predicate_hint(&argv) {
        eprintln!("error: {hint}");
        std::process::exit(2);
    }
    if let Some(hint) = port_swapped_arg_hint(&argv) {
        eprintln!("error: {hint}");
        std::process::exit(2);
    }
    let (cli, matches) = parse_cli_from(argv);
    if let Command::Service {
        action: service::Action::Run { data_dir },
    } = &cli.command
    {
        std::process::exit(service::run_windows_service(data_dir.clone()));
    }
    // The window owns the main thread. Starting it inside the CLI runtime makes
    // the Linux accessibility bus look for a Tokio reactor that is not there.
    if let Command::Controller(args) = &cli.command {
        if !args.check && args.preview_ui {
            if let Some(err) = preview_incompatible_flags(&matches) {
                eprintln!("error: {err}");
                std::process::exit(2);
            }
            std::process::exit(controller::enter_preview());
        }
        if !args.check {
            let config_dir = match config_dir(&cli) {
                Ok(dir) => dir,
                Err(err) => {
                    eprintln!("error: {err:#}");
                    std::process::exit(1);
                }
            };
            std::process::exit(controller::enter_args(controller::EnterArgs {
                config_dir,
                data_dir: args.data_dir.clone(),
                tray: true,
                background: args.background,
                check: false,
                debug_socket: args.debug_socket.clone(),
                mock: args.mock,
                headless: args.headless,
                fail_connect: args.fail_connect,
                connect_timeout_secs: args.connect_timeout_secs,
                max_fps: args.max_fps,
                perf_log: args.perf_log.clone(),
                open_desktop: args.open_desktop.clone(),
                preview_ui: args.preview_ui,
            }));
        }
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async_main(cli));
}

async fn async_main(cli: Cli) {
    if tray_ui(&cli.command) {
        if let Some(dir) = tray_log_dir(&cli) {
            tray::init_tray_log(&dir);
        }
    }
    let default_filter = match &cli.command {
        Command::Relay(_) | Command::Node(_) => "info",
        _ => "warn",
    };
    init_tracing(default_filter);
    match dispatch(&cli).await {
        Ok(code) => std::process::exit(code),
        Err(err) => {
            let raw = err.to_string();
            let message = decorate_bg_process_limit(&decorate_bg_process_not_found(&decorate_patch_hunk_mismatch(
                &decorate_patch_parse(&decorate_ambiguous_node(&decorate_missing_parent(&decorate_ls_missing(
                    &decorate_path_not_found(&decorate_search_glob(&decorate_search_regex(
                        &decorate_exec_program_path_miss(&decorate_exec_path_miss(
                            &decorate_edit_mismatch(&decorate_node_not_found(
                                &decorate_session_auth(&decorate_grant_capability(
                                    &decorate_node_offline(
                                        &agentlink_core::error::decorate_transient_tls(&raw),
                                    ),
                                )),
                            )),
                        )),
                    ))),
                ))),
            ))));
            let message = decorate_mv_rm_missing(&message);
            let message = decorate_exec_enoexec(&message);
            let message = decorate_env_var_rejected(&message);
            let message = decorate_scroll_coord_pair(&message);
            let message = decorate_mkdir_target_not_dir(&message);
            let message = decorate_path_component_not_dir(&message);
            let message = decorate_patch_root_not_dir(&message);
            let message = decorate_atspi_bus_failure(&decorate_screenshot_monitor_missing(
                &decorate_screenshot_window_not_found(&decorate_no_click_action(
                    &decorate_pty_session_not_found(&decorate_watch_target_missing(&decorate_watch_inotify_limit(&decorate_watch_limit(&decorate_watch_not_found(
                        &decorate_ui_element_stale(&decorate_edit_lines_outside(
                            &decorate_edit_lines_end_before_start(&decorate_edit_lines_zero_based(
                                &decorate_patch_path(&decorate_sandbox_denial(
                                    &decorate_sandbox_path_escape(
                                        &decorate_patch_missing_headers(
                                            &decorate_patch_too_large(
                                                &decorate_replacement_text_too_large(
                                                    &decorate_edit_text_not_utf8(
                                                        &decorate_edit_file_too_large(
                                                            &decorate_replace_empty_old(&message),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                )),
                            )),
                        )),
                    ))))),
                )),
            ));
            let message = decorate_windows_input_capture(&message);
            let message = decorate_write_target_is_directory(&decorate_exec_cwd_missing(
                &decorate_mv_cross_device(&decorate_approval_unresolved(&message)),
            ));
            let message = decorate_symlink_dir_read(&message);
            let message = decorate_ambiguous_replace(&message);
            let message = decorate_edit_atomic_write(&message);
            let message = decorate_exec_cwd_permission(&message);
            let tip = untrusted_grant_issuer_hex(&raw)
                .map(|issuer| tip_untrusted_grant_issuer(&issuer));
            if cli.json {
                let mut out = json!({"ok": false, "error": message});
                if let Some(tip) = &tip {
                    out["tip"] = json!(tip);
                }
                println!("{out}");
            } else {
                let chain = decorate_bg_process_limit(&decorate_bg_process_not_found(&decorate_patch_hunk_mismatch(
                    &decorate_patch_parse(&decorate_ambiguous_node(&decorate_missing_parent(&decorate_ls_missing(
                        &decorate_path_not_found(&decorate_search_glob(&decorate_search_regex(
                            &decorate_exec_program_path_miss(&decorate_exec_path_miss(
                                &decorate_edit_mismatch(&decorate_node_not_found(
                                    &decorate_session_auth(&decorate_grant_capability(
                                        &decorate_node_offline(
                                            &agentlink_core::error::decorate_transient_tls(&format!(
                                                "{err:#}"
                                            )),
                                        ),
                                    )),
                                )),
                            )),
                        ))),
                    ))),
                ))));
                let chain = decorate_mv_rm_missing(&chain);
                let chain = decorate_patch_root_not_dir(&chain);
                let chain = decorate_atspi_bus_failure(&decorate_screenshot_monitor_missing(
                    &decorate_screenshot_window_not_found(&decorate_no_click_action(
                        &decorate_pty_session_not_found(&decorate_watch_target_missing(&decorate_watch_inotify_limit(&decorate_watch_limit(&decorate_watch_not_found(
                            &decorate_ui_element_stale(&decorate_edit_lines_outside(
                                &decorate_edit_lines_end_before_start(
                                    &decorate_edit_lines_zero_based(&decorate_patch_path(
                                        &decorate_sandbox_denial(&decorate_sandbox_path_escape(
                                            &decorate_patch_missing_headers(
                                                &decorate_patch_too_large(
                                                    &decorate_replacement_text_too_large(
                                                        &decorate_edit_text_not_utf8(
                                                            &decorate_edit_file_too_large(
                                                                &decorate_replace_empty_old(&chain),
                                                            ),
                                                        ),
                                                    ),
                                                ),
                                            ),
                                        )),
                                    )),
                                ),
                            )),
                        ))))),
                    )),
                ));
                let chain = decorate_windows_input_capture(&chain);
                let chain = decorate_write_target_is_directory(&decorate_exec_cwd_missing(
                    &decorate_mv_cross_device(&decorate_approval_unresolved(&chain)),
                ));
                let chain = decorate_symlink_dir_read(&chain);
                let chain = decorate_ambiguous_replace(&chain);
                let chain = decorate_exec_enoexec(&chain);
                let chain = decorate_env_var_rejected(&chain);
                let chain = decorate_scroll_coord_pair(&chain);
                let chain = decorate_mkdir_target_not_dir(&chain);
                let chain = decorate_path_component_not_dir(&chain);
                let chain = decorate_edit_atomic_write(&chain);
                let chain = decorate_exec_cwd_permission(&chain);
                eprintln!("error: {chain}");
                if let Some(tip) = &tip {
                    eprintln!("{tip}");
                }
            }
            std::process::exit(1);
        }
    }
}

fn init_tracing(default_filter: &str) {
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();
}

async fn dispatch(cli: &Cli) -> Result<i32> {
    match &cli.command {
        Command::Relay(args) => {
            let RelayArgs {
                bind,
                data_dir,
                database_url,
                allow_signup,
                action,
                print_admin_token,
                trust_proxy,
            } = &**args;
            let data_dir = match data_dir {
                Some(dir) => dir.clone(),
                None => agentlink_core::config::default_data_dir("relay")?,
            };
            let database_url = database_url.clone().filter(|url| !url.trim().is_empty());
            if let Some(account::RelayAction::User { cmd }) = action {
                return account::relay_user(&data_dir, database_url.as_deref(), cmd, cli.json)
                    .await;
            }
            let bind: SocketAddr = bind.parse().context("invalid --bind address")?;
            serve(RelayConfig {
                bind,
                data_dir,
                capture: None,
                database_url,
                allow_signup: *allow_signup,
                bootstrap_admin: true,
                db_schema: None,
                trust_proxy: trust_proxy.clone(),
                print_admin_token: *print_admin_token,
                legacy_admin_override: None,
            })
            .await?;
            Ok(0)
        }
        Command::Node(args) => {
            let NodeArgs {
                name,
                pairing_token,
                invite,
                data_dir,
                root,
                max_access,
                stream_consent,
                allow_cmd,
                deny_cmd,
                confirm_timeout,
                audit_preset,
            } = &**args;
            let config = node_cfg::load(node_cfg::NodeArgs {
                relay: cli.relay.clone(),
                fingerprint: cli.fingerprint.clone(),
                trust: cli.trust.clone(),
                invite: invite.clone(),
                name: name.clone(),
                pairing_token: pairing_token.clone(),
                data_dir: data_dir.clone(),
                root: root.clone(),
                max_access: max_access.clone(),
                stream_consent: Some(stream_consent.clone()),
            })?;
            write_node_policy_files(
                &config.data_dir,
                allow_cmd,
                deny_cmd,
                *confirm_timeout,
                audit_preset.as_deref(),
            )?;
            if let Some(reason) = tray::standalone_node_block_reason(&config.data_dir) {
                eprintln!("{reason}");
                return Ok(0);
            }
            let shutdown = CancellationToken::new();
            spawn_shutdown(shutdown.clone());
            agentlink_node::run(config, shutdown).await?;
            Ok(0)
        }
        Command::Service { action } => {
            service::dispatch(
                &service::Env {
                    json: cli.json,
                    relay: cli.relay.clone(),
                    token: cli.token.clone(),
                    fingerprint: cli.fingerprint.clone(),
                    trust: cli.trust.clone(),
                    config_dir: cli.config_dir.clone(),
                },
                action,
            )
            .await
        }
        Command::Controller(args) if args.preview_ui && !args.check => {
            Ok(controller::enter_preview())
        }
        Command::Controller(args) => Ok(controller::enter_args(controller::EnterArgs {
            config_dir: config_dir(cli)?,
            data_dir: args.data_dir.clone(),
            tray: true,
            background: args.background,
            check: args.check,
            debug_socket: args.debug_socket.clone(),
            mock: args.mock,
            headless: args.headless,
            fail_connect: args.fail_connect,
            connect_timeout_secs: args.connect_timeout_secs,
            max_fps: args.max_fps,
            perf_log: args.perf_log.clone(),
            open_desktop: args.open_desktop.clone(),
            preview_ui: args.preview_ui,
        })),
        Command::Tray {
            data_dir,
            background,
            name,
            action,
        } => {
            let action = match action {
                None => tray::TrayAction::Run,
                Some(TrayCommand::Install { dry_run }) => {
                    tray::TrayAction::Install { dry_run: *dry_run }
                }
                Some(TrayCommand::Uninstall) => tray::TrayAction::Uninstall,
                Some(TrayCommand::Status) => tray::TrayAction::Status,
            };
            tray::dispatch(&tray::TrayContext {
                json: cli.json,
                relay: cli.relay.clone(),
                fingerprint: cli.fingerprint.clone(),
                trust: cli.trust.clone(),
                config_dir: config_dir(cli)?,
                data_dir: data_dir.clone(),
                name: name.clone(),
                background: *background,
                action,
            })
        }
        Command::Update(args) => update::run(cli.json, cli.config_dir.clone(), args).await,
        Command::Internal { action } => {
            signature::dispatch(action)?;
            Ok(0)
        }
        Command::Bench { quick, out } => bench_cmd::run(*quick, out.as_deref()).await,
        Command::Mcp { http, mcp_token } => {
            let settings = settings(cli)?;
            let identity_path = operator_identity_path(cli)?;
            if let Some(http) = http {
                let token = mcp_token
                    .clone()
                    .filter(|token| !token.is_empty())
                    .ok_or_else(|| {
                        anyhow!("--mcp-token or AGENTLINK_MCP_TOKEN is required with --http")
                    })?;
                let bind: SocketAddr = http.parse().context("invalid --http address")?;
                mcp_http::serve(settings, bind, token, identity_path).await?;
            } else {
                mcp::serve(settings, identity_path).await?;
            }
            Ok(0)
        }
        Command::Audit { action } => {
            let needs_relay = matches!(
                action,
                audit_cmd::AuditAction::Query { sink, .. } if sink == "relay"
            ) || matches!(
                action,
                audit_cmd::AuditAction::Config {
                    action: audit_cmd::ConfigAction::Set { push: Some(_), .. }
                } | audit_cmd::AuditAction::Config {
                    action: audit_cmd::ConfigAction::Preset { push: Some(_), .. }
                } | audit_cmd::AuditAction::Sink {
                    action: audit_cmd::SinkAction::Add { push: Some(_), .. }
                } | audit_cmd::AuditAction::Sink {
                    action: audit_cmd::SinkAction::Rm { push: Some(_), .. }
                }
            );
            let client;
            let client_ref = if needs_relay {
                client = connect_client(cli, "audit").await?;
                Some(&client)
            } else {
                None
            };
            return audit_cmd::run(action, cli.json, client_ref).await;
        }
        Command::Client { .. } | Command::Approve { .. } => {
            let client = connect_client(cli, "admin").await?;
            match &cli.command {
                Command::Client { action } => client_cmd(&client, action, cli.json).await,
                Command::Approve { action } => approve_cmd(&client, action, cli.json).await,
                _ => unreachable!(),
            }
        }
        Command::Login {
            user,
            password_stdin,
            totp,
            device_name,
        } => {
            let dir = config_dir(cli)?;
            let saved = agentlink_core::config::load_file(&dir).unwrap_or_default();
            let mut relay = cli
                .relay
                .clone()
                .filter(|value| !value.trim().is_empty())
                .or(saved.relay.clone())
                .unwrap_or_default();
            let fingerprint = cli
                .fingerprint
                .clone()
                .filter(|value| !value.trim().is_empty())
                .or(saved.fingerprint.clone())
                .unwrap_or_default();
            let mut trust = cli
                .trust
                .clone()
                .filter(|value| !value.trim().is_empty())
                .or(saved.trust.clone());
            agentlink_core::apply_relay_defaults(&mut relay, &fingerprint, &mut trust);
            if fingerprint.trim().is_empty() && trust.is_none() {
                return Err(anyhow!(
                    "--fingerprint or --trust is required (sha256:<hex>, system, or webpki)"
                ));
            }
            let parsed = agentlink_core::RelayTrust::parse(&fingerprint, trust.as_deref())
                .map_err(|err| anyhow!(err.to_string()))?;
            if let Some(user) = user {
                let password = if *password_stdin {
                    let mut line = String::new();
                    std::io::stdin().read_line(&mut line)?;
                    line.trim().to_string()
                } else {
                    account::prompt_secret("password: ")?
                };
                let identity = Identity::load_or_create(&operator_identity_path(cli)?)
                    .map_err(|err| anyhow!(err.to_string()))?;
                let session = agentlink_core::client::login_user(
                    &relay,
                    &parsed.fingerprint_value(),
                    parsed.trust_value().as_deref(),
                    &identity,
                    user,
                    &password,
                    totp.as_deref(),
                    device_name,
                )
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
                let settings = ClientSettings {
                    relay: relay.clone(),
                    token: session.access_token.clone(),
                    fingerprint: parsed.fingerprint_value(),
                    trust: parsed.trust_value(),
                };
                agentlink_core::config::save_session(
                    &dir,
                    &settings,
                    &session.user,
                    &session.refresh_token,
                    session.access_expires_unix,
                )?;
                emit(
                    cli.json,
                    json!({"ok": true, "user": session.user, "device_id": session.device_id, "config_dir": dir}),
                    || {
                        eprintln!("logged in as {}", session.user);
                        eprintln!("saved client config in {}", dir.display());
                    },
                );
                return Ok(0);
            }
            let settings = ClientSettings {
                relay,
                token: cli
                    .token
                    .clone()
                    .ok_or_else(|| anyhow!("--token is required"))?,
                fingerprint: parsed.fingerprint_value(),
                trust: parsed.trust_value(),
            };
            save_settings(&dir, &settings)?;
            emit(cli.json, json!({"ok": true, "config_dir": dir}), || {
                eprintln!("saved client config in {}", dir.display());
            });
            Ok(0)
        }
        Command::Logout => {
            let dir = config_dir(cli)?;
            let file = agentlink_core::config::load_file(&dir).unwrap_or_default();
            if file.refresh_token.is_some() {
                if let Ok(client) = connect_client(cli, "logout").await {
                    let _ = client.logout_session(file.refresh_token.clone()).await;
                }
            }
            let cleared = ClientSettings {
                relay: file.relay.clone().unwrap_or_default(),
                token: String::new(),
                fingerprint: file.fingerprint.clone().unwrap_or_default(),
                trust: file.trust.clone(),
            };
            if !cleared.relay.is_empty() {
                save_settings(&dir, &cleared)?;
            }
            emit(cli.json, json!({"ok": true}), || eprintln!("logged out"));
            Ok(0)
        }
        Command::Share { node, with, access } => {
            let client = connect_client(cli, "share").await?;
            account::share_cmd(&client, node, with, access, cli.json).await
        }
        Command::Unshare { node, with } => {
            let client = connect_client(cli, "unshare").await?;
            account::unshare_cmd(&client, node, with, cli.json).await
        }
        Command::Token { action } => {
            let client = connect_client(cli, "token").await?;
            account::token_cmd(&client, action, cli.json).await
        }
        Command::User { action } => {
            let client = connect_client(cli, "user").await?;
            account::user_cmd(&client, action, cli.json).await
        }
        Command::Devices { revoke } => {
            let client = connect_client(cli, "devices").await?;
            if let Some(id) = revoke {
                client
                    .revoke_device(id)
                    .await
                    .map_err(|err| anyhow!(err.to_string()))?;
                emit(cli.json, json!({"ok": true, "revoked": id}), || {
                    eprintln!("revoked {id}");
                });
                return Ok(0);
            }
            let devices = client
                .list_devices()
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(cli.json, json!({"devices": devices}), || {
                for device in &devices {
                    eprintln!(
                        "{} {} {} revoked={}",
                        device.id, device.user, device.name, device.revoked
                    );
                }
            });
            Ok(0)
        }
        Command::View {
            node,
            no_open,
            monitor,
            control,
        } => {
            let _ = (node, no_open, monitor, control);
            return Err(anyhow!(
                "browser view is not available; use a sealed client with a node-local grant"
            ));
        }
        Command::Guide {
            node,
            local,
            data_dir,
            no_open,
            print_only,
        } => {
            guide_cmd(
                cli,
                node.as_deref(),
                *local,
                data_dir.as_deref(),
                *no_open || *print_only,
            )
            .await
        }
        Command::Status => {
            let dir = config_dir(cli)?;
            let id_path = operator_identity_path(cli)?;
            return status_cmd::run(&dir, &id_path, cli.json);
        }
        Command::Identity { action } => {
            let path = operator_identity_path(cli)?;
            return match action {
                IdentityAction::Show => identity_cmd::show(&path, cli.json),
                IdentityAction::Create => identity_cmd::create_or_ensure(&path, cli.json, "create"),
                IdentityAction::Ensure => identity_cmd::create_or_ensure(&path, cli.json, "ensure"),
            };
        }
        Command::Grant { action } => grant_cmd(cli, action).await,
        Command::Port { action } => port_cmd(cli, action).await,
        other => {
            let client = connect_client(cli, "").await?;
            match other {
                Command::Pair {
                    name,
                    access,
                    ttl_minutes,
                } => {
                    let policy = parse_access(access)?;
                    let info = client
                        .create_pairing_token(name, policy, ttl_minutes * 60)
                        .await?;
                    let saved = settings(cli)?;
                    let invite = encode_invite(&Invite {
                        relay: saved.relay.clone(),
                        fingerprint: saved.fingerprint.clone(),
                        trust: saved.trust.clone(),
                        token: info.token.clone(),
                        name: info.name.clone(),
                    })
                    .map_err(|err| anyhow!(err.to_string()))?;
                    let enroll = enroll_command(&saved, &info.token, &info.name);
                    emit(
                        cli.json,
                        json!({
                            "pairing_token": info.token,
                            "name": info.name,
                            "access": info.policy.preset_name(),
                            "expires_unix": info.expires_unix,
                            "invite": invite,
                            "trust": saved.trust,
                        }),
                        || {
                            eprintln!(
                                "pairing token for '{}' ({}, expires unix {})",
                                info.name,
                                info.policy.preset_name(),
                                info.expires_unix
                            );
                            eprintln!("on the machine, run:");
                            eprintln!("  agentlink node --invite {invite}");
                            eprintln!("  {enroll}");
                            println!("{}", info.token);
                        },
                    );
                    Ok(0)
                }
                Command::Nodes => {
                    print_nodes(&client, cli.json).await?;
                    Ok(0)
                }
                Command::Grant { .. } => unreachable!("grant is handled before connecting"),
                Command::Status | Command::Identity { .. } => {
                    unreachable!("status/identity are handled before connecting")
                }
                Command::Port { .. } => unreachable!("port is handled before connecting"),
                Command::Ls { node, path } => {
                    if let Some(node) = node {
                        let path = path.clone().unwrap_or_else(|| ".".into());
                        let entries = client
                            .list_dir(node, &path)
                            .await
                            .map_err(|err| hint_list_dir_permission(err, node, &path))?;
                        emit(cli.json, json!(entries), || {
                            for entry in &entries {
                                println!(
                                    "{} {:>10} {}",
                                    dir_entry_kind(entry),
                                    entry.size,
                                    entry.name
                                );
                            }
                        });
                    } else {
                        print_nodes(&client, cli.json).await?;
                    }
                    Ok(0)
                }
                Command::Cat { node, path } => {
                    reject_dash_remote_path("cat", path)?;
                    let opts = XferOpts::default();
                    if cli.json {
                        let mut data = Vec::new();
                        let body = client
                            .stream_download(node, path, 0, Some(1024 * 1024), &mut data, &opts)
                            .await
                            .map_err(|err| hint_fs_error(err, FsHint::Cat))?;
                        let truncated = body.end < body.file_size;
                        println!("{}", encode_payload(path, &data, truncated));
                    } else {
                        let stdout = std::io::stdout();
                        let mut stdout = stdout.lock();
                        client
                            .stream_download(node, path, 0, None, &mut stdout, &opts)
                            .await
                            .map_err(|err| hint_fs_error(err, FsHint::Cat))?;
                        stdout.flush().ok();
                    }
                    Ok(0)
                }
                Command::Write {
                    node,
                    path,
                    content,
                } => {
                    validate_write_path(path)?;
                    let opts = XferOpts::default();
                    let stats = match content {
                        Some(text) => {
                            let mut cursor = std::io::Cursor::new(text.as_bytes());
                            match client.stream_upload(node, path, &mut cursor, &opts).await {
                                Ok(stats) => stats,
                                Err(err) => {
                                    let err = hint_if_node_args_swapped(
                                        &client,
                                        err,
                                        node,
                                        Some(path),
                                        &format!(
                                            "agentlink write {} {}",
                                            shell_quote_arg(path),
                                            shell_quote_arg(node)
                                        ),
                                    )
                                    .await;
                                    return Err(hint_fs_error(err, FsHint::Write));
                                }
                            }
                        }
                        None => {
                            if std::io::stdin().is_terminal() {
                                return Err(anyhow!(
                                    "pass --content TEXT or pipe data on stdin (stdin is a terminal); use --content '' to write an empty file"
                                ));
                            }
                            // Peek one byte before uploading. An empty pipe used to
                            // truncate the remote file and then error — destroy then
                            // fail. Reject EOF up front; intentional empties use
                            // `--content ''`.
                            let stdin = std::io::stdin();
                            let mut stdin = stdin.lock();
                            let mut first = [0u8; 1];
                            let n = stdin.read(&mut first).map_err(|err| anyhow!(err))?;
                            if n == 0 {
                                return Err(anyhow!(
                                    "wrote 0 bytes from stdin; pass --content TEXT or pipe data (use --content '' to create an empty file)"
                                ));
                            }
                            let mut reader = std::io::Cursor::new(first[..n].to_vec()).chain(stdin);
                            match client.stream_upload(node, path, &mut reader, &opts).await {
                                Ok(stats) => stats,
                                Err(err) => {
                                    let err = hint_if_node_args_swapped(
                                        &client,
                                        err,
                                        node,
                                        Some(path),
                                        &format!(
                                            "agentlink write {} {}",
                                            shell_quote_arg(path),
                                            shell_quote_arg(node)
                                        ),
                                    )
                                    .await;
                                    return Err(hint_fs_error(err, FsHint::Write));
                                }
                            }
                        }
                    };
                    emit(
                        cli.json,
                        json!({"ok": true, "path": path, "bytes": stats.logical_bytes}),
                        || eprintln!("wrote {} bytes to {path}", stats.logical_bytes),
                    );
                    Ok(0)
                }
                Command::Cp(args) => {
                    let CpArgs {
                        src,
                        dst,
                        chunk_size,
                        window,
                        parallel,
                        compress,
                        no_direct,
                        progress,
                    } = &**args;
                    copy_path(
                        &client,
                        src,
                        dst,
                        cli.json,
                        chunk_size,
                        *window,
                        *parallel,
                        compress,
                        !*no_direct,
                        *progress,
                    )
                    .await?;
                    Ok(0)
                }
                Command::Mkdir {
                    node,
                    path,
                    parents,
                } => {
                    reject_dash_remote_path("mkdir", path)?;
                    match client.mkdir(node, path, *parents).await {
                        Ok(()) => {
                            emit(cli.json, json!({"ok": true, "path": path}), || {
                                eprintln!("created {path}");
                            });
                            Ok(0)
                        }
                        Err(err) => {
                            let msg = err.to_string();
                            if let Some(hint) = mkdir_error_hint(&msg, node, path, *parents) {
                                return Err(anyhow!(hint));
                            }
                            let err = hint_if_node_args_swapped(
                                &client,
                                err,
                                node,
                                Some(path),
                                &format!(
                                    "agentlink mkdir {} {}",
                                    shell_quote_arg(path),
                                    shell_quote_arg(node)
                                ),
                            )
                            .await;
                            let msg = err.to_string();
                            let decorated =
                                decorate_mkdir_dest_permission(&msg, node, path, *parents);
                            if decorated != msg {
                                return Err(anyhow!(decorated));
                            }
                            Err(anyhow!("{msg}"))
                        }
                    }
                }
                Command::Rm {
                    node,
                    path,
                    recursive,
                } => {
                    reject_dash_remote_path("rm", path)?;
                    match client.remove(node, path, *recursive).await {
                        Ok(()) => {
                            emit(cli.json, json!({"ok": true, "path": path}), || {
                                eprintln!("removed {path}");
                            });
                            Ok(0)
                        }
                        Err(err) => {
                            let msg = err.to_string();
                            let decorated =
                                decorate_remove_dest_permission(&msg, node, path, *recursive);
                            if decorated != msg {
                                return Err(anyhow!(decorated));
                            }
                            let missing = decorate_mv_rm_missing(&msg);
                            if missing != msg {
                                return Err(anyhow!(missing));
                            }
                            if !*recursive && is_remove_not_empty_error(&msg) {
                                Err(anyhow!(decorate_remove_not_empty(&msg)))
                            } else {
                                Err(hint_if_node_args_swapped(
                                    &client,
                                    err,
                                    node,
                                    Some(path),
                                    &format!(
                                        "agentlink rm {} {}",
                                        shell_quote_arg(path),
                                        shell_quote_arg(node)
                                    ),
                                )
                                .await)
                            }
                        }
                    }
                }
                Command::Mv { node, from, to } => {
                    reject_dash_remote_path("mv from", from)?;
                    reject_dash_remote_path("mv to", to)?;
                    let result = match client.rename(node, from, to).await {
                        Ok(body) => body,
                        Err(err) => {
                            // `mv /tmp/a /tmp/b example` parses as node=/tmp/a, to=example.
                            let err = hint_if_node_args_swapped(
                                &client,
                                err,
                                node,
                                Some(to),
                                &format!(
                                    "agentlink mv {} {} {}",
                                    shell_quote_arg(to),
                                    shell_quote_arg(node),
                                    shell_quote_arg(from)
                                ),
                            )
                            .await;
                            let msg = err.to_string();
                            let decorated = decorate_mv_dest_permission(&msg, node, from, to);
                            if decorated != msg {
                                return Err(anyhow!(decorated));
                            }
                            let missing = decorate_mv_rm_missing(&msg);
                            if missing != msg {
                                return Err(anyhow!(missing));
                            }
                            return Err(anyhow!(
                                "{}",
                                decorate_mv_target_not_empty(&msg, from, to)
                            ));
                        }
                    };
                    // Prefer server-resolved paths so into-directory moves report
                    // the final file path, not the destination directory alone.
                    let from_out = result
                        .get("from")
                        .and_then(|v| v.as_str())
                        .unwrap_or(from);
                    let to_out = result.get("to").and_then(|v| v.as_str()).unwrap_or(to);
                    emit(
                        cli.json,
                        json!({"ok": true, "from": from_out, "to": to_out}),
                        || eprintln!("moved {from_out} -> {to_out}"),
                    );
                    Ok(0)
                }
                Command::Exec {
                    node,
                    cwd,
                    env,
                    timeout_secs,
                    shell,
                    cmd,
                } => {
                    if !*shell {
                        reject_flag_like_program("exec", cmd)?;
                    }
                    let timeout = (*timeout_secs > 0).then(|| Duration::from_secs(*timeout_secs));
                    let env_pairs = parse_env_pairs(env)?;
                    let stdin = read_exec_stdin()?;
                    let req = if *shell {
                        let mut req = ExecRequest::shell(cmd.join(" "), timeout);
                        req.cwd = cwd.clone();
                        req.env = env_pairs;
                        req.stdin = stdin;
                        req
                    } else {
                        ExecRequest {
                            program: cmd[0].clone(),
                            args: cmd[1..].to_vec(),
                            cwd: cwd.clone(),
                            env: env_pairs,
                            timeout,
                            shell: false,
                            stdin,
                        }
                    };
                    if cli.json {
                        match client.exec_collect(node, req, None).await {
                            Ok(output) => {
                                println!(
                                    "{}",
                                    json!({
                                        "exit_code": output.exit_code,
                                        "stdout": String::from_utf8_lossy(&output.stdout),
                                        "stderr": String::from_utf8_lossy(&output.stderr),
                                        "truncated": output.truncated,
                                    })
                                );
                                Ok(output.exit_code.unwrap_or(1))
                            }
                            Err(err) => Err(hint_exec_eacces(
                                hint_exec_timeout(
                                    hint_exec_cwd_missing(err, cwd.as_deref()),
                                    *timeout_secs,
                                ),
                                cwd.as_deref(),
                            )),
                        }
                    } else {
                        match client
                            .exec_streaming(node, req, |stream, data| {
                                if stream == "stderr" {
                                    let mut err = std::io::stderr();
                                    err.write_all(data).ok();
                                    err.flush().ok();
                                } else {
                                    let mut out = std::io::stdout();
                                    out.write_all(data).ok();
                                    out.flush().ok();
                                }
                                true
                            })
                            .await
                        {
                            Ok(code) => Ok(code.unwrap_or(1)),
                            Err(err) => Err(hint_exec_eacces(
                                hint_exec_timeout(
                                    hint_exec_cwd_missing(err, cwd.as_deref()),
                                    *timeout_secs,
                                ),
                                cwd.as_deref(),
                            )),
                        }
                    }
                }
                Command::Search(args) => {
                    let SearchArgs {
                        node,
                        pattern,
                        path,
                        literal,
                        include,
                        exclude,
                        include_hidden,
                        ignore_case,
                        no_gitignore,
                        before,
                        after,
                        offset,
                        limit,
                    } = &**args;
                    if let Some(root) = path.as_deref() {
                        reject_dash_remote_path("search", root)?;
                    }
                    if let Some(hint) = search_path_before_pattern_hint(pattern, path.as_deref()) {
                        return Err(anyhow!("{hint}"));
                    }
                    let value = match client
                        .search(
                            node,
                            path.as_deref().unwrap_or("."),
                            pattern,
                            *literal,
                            include.clone(),
                            exclude.clone(),
                            !no_gitignore,
                            *include_hidden,
                            *ignore_case,
                            *before,
                            *after,
                            *offset,
                            *limit,
                        )
                        .await
                    {
                        Ok(value) => value,
                        Err(err) => {
                            let example = match path.as_deref() {
                                Some(p) => format!(
                                    "agentlink search {} {} {}",
                                    shell_quote_arg(pattern),
                                    shell_quote_arg(node),
                                    shell_quote_arg(p)
                                ),
                                None => format!(
                                    "agentlink search {} {}",
                                    shell_quote_arg(pattern),
                                    shell_quote_arg(node)
                                ),
                            };
                            let err = match err {
                                agentlink_core::Error::Message(message)
                                    if is_search_permission_error(&message) =>
                                {
                                    agentlink_core::Error::Message(decorate_search_permission(
                                        &message,
                                        node,
                                        path.as_deref().unwrap_or("."),
                                    ))
                                }
                                other => other,
                            };
                            return Err(hint_if_node_args_swapped(
                                &client,
                                err,
                                node,
                                Some(pattern),
                                &example,
                            )
                            .await);
                        }
                    };
                    if cli.json {
                        println!("{value}");
                    } else if let Some(matches) = value["matches"].as_array() {
                        if matches.is_empty() {
                            eprintln!("(no matches)");
                        }
                        for hit in matches {
                            println!(
                                "{}:{}:{}",
                                hit["path"].as_str().unwrap_or(""),
                                hit["line"].as_u64().unwrap_or(0),
                                hit["text"].as_str().unwrap_or("").trim_end()
                            );
                        }
                        if let Some(skipped) = value["skipped_files"].as_u64() {
                            if skipped > 0 {
                                eprintln!(
                                    "warning: skipped {skipped} inaccessible file(s) while searching"
                                );
                            }
                        }
                    }
                    Ok(0)
                }
                Command::Find(args) => {
                    let FindArgs {
                        node,
                        pattern,
                        path,
                        regex,
                        include_hidden,
                        ignore_case,
                        no_gitignore,
                        offset,
                        limit,
                    } = &**args;
                    if let Some(root) = path.as_deref() {
                        reject_dash_remote_path("find", root)?;
                    }
                    if let Some(hint) = find_path_before_pattern_hint(pattern, path.as_deref()) {
                        return Err(anyhow!("{hint}"));
                    }
                    let value = match client
                        .find(
                            node,
                            path.as_deref().unwrap_or("."),
                            pattern,
                            *regex,
                            !no_gitignore,
                            *include_hidden,
                            *ignore_case,
                            *offset,
                            *limit,
                        )
                        .await
                    {
                        Ok(value) => value,
                        Err(err) => {
                            // Args may be swapped: first held the glob, pattern the machine.
                            let example = match path.as_deref() {
                                Some(p) => format!(
                                    "agentlink find {} {} {}",
                                    shell_quote_arg(pattern),
                                    shell_quote_arg(node),
                                    shell_quote_arg(p)
                                ),
                                None => format!(
                                    "agentlink find {} {}",
                                    shell_quote_arg(pattern),
                                    shell_quote_arg(node)
                                ),
                            };
                            return Err(hint_if_node_args_swapped(
                                &client,
                                err,
                                node,
                                Some(pattern),
                                &example,
                            )
                            .await);
                        }
                    };
                    if cli.json {
                        println!("{value}");
                    } else if let Some(matches) = value["matches"].as_array() {
                        if matches.is_empty() {
                            eprintln!("(no matches)");
                        }
                        for hit in matches {
                            println!("{}", hit["path"].as_str().unwrap_or(""));
                        }
                    }
                    Ok(0)
                }
                Command::Replace {
                    node,
                    path,
                    old,
                    new,
                    all,
                } => {
                    reject_dash_remote_path("replace", path)?;
                    let value = match client.replace(node, path, old, new, *all).await {
                        Ok(value) => value,
                        Err(err) => {
                            // `replace /tmp/x foo bar example` → machine was last.
                            let err = hint_if_node_args_swapped(
                                &client,
                                err,
                                node,
                                Some(new),
                                &format!(
                                    "agentlink replace {} {} {} {}",
                                    shell_quote_arg(new),
                                    shell_quote_arg(node),
                                    shell_quote_arg(path),
                                    shell_quote_arg(old)
                                ),
                            )
                            .await;
                            return Err(anyhow!(
                                "{}",
                                decorate_replace_missing_file(&err.to_string(), path)
                            ));
                        }
                    };
                    emit(cli.json, value, || eprintln!("replaced {path}"));
                    Ok(0)
                }
                Command::EditLines {
                    node,
                    path,
                    start,
                    end,
                    content,
                } => {
                    reject_dash_remote_path("edit-lines", path)?;
                    let value = client.edit_lines(node, path, *start, *end, content).await?;
                    emit(cli.json, value, || eprintln!("edited {path}"));
                    Ok(0)
                }
                Command::Patch { node, root, file } => {
                    reject_dash_remote_path("patch root", root)?;
                    // `--file -` is the Unix stdin convention (agents/scripts pass it often).
                    let patch = match file {
                        Some(path) if !path_is_stdin(&path) => std::fs::read_to_string(&path)
                            .with_context(|| format!("read {}", path.display()))?,
                        Some(_) | None => {
                            let mut text = String::new();
                            std::io::stdin().read_to_string(&mut text)?;
                            text
                        }
                    };
                    let value = client.apply_patch(node, root, &patch).await?;
                    emit(cli.json, value, || eprintln!("applied patch under {root}"));
                    Ok(0)
                }
                Command::Watch {
                    node,
                    path,
                    no_recursive,
                    timeout_secs,
                } => {
                    reject_dash_remote_path("watch", path)?;
                    match watch_follow(cli, &client, node, path, !no_recursive, *timeout_secs)
                        .await
                    {
                        Ok(code) => Ok(code),
                        Err(err) => {
                            use agentlink_core::protocol::{looks_like_path_or_glob, resolve_node};
                            let msg = err.to_string();
                            if looks_like_path_or_glob(node) {
                                if let Ok(nodes) = client.list_nodes().await {
                                    if resolve_node(&nodes, path).is_ok() {
                                        return Err(anyhow!(
                                            "{msg}. Did you mean `agentlink watch {} {}` (machine name first)?",
                                            shell_quote_arg(path),
                                            shell_quote_arg(node)
                                        ));
                                    }
                                }
                            }
                            Err(err)
                        }
                    }
                }
                Command::Bg { node, action } => bg_command(cli, &client, node, action).await,
                Command::Sysinfo { node } => {
                    let value = client.sysinfo(node).await?;
                    emit(cli.json, value.clone(), || print_sysinfo(&value));
                    Ok(0)
                }
                Command::Shell {
                    node,
                    command,
                    cwd,
                    line,
                } => {
                    reject_empty_shell_command(command.as_deref())?;
                    // `--command` + piped/redirected stdin needs pipe EOF. A PTY
                    // never delivers that; interact_lines used to forward bytes
                    // then hang forever in cat/python/etc. Route through exec.
                    if command.is_some() && !std::io::stdin().is_terminal() {
                        let cmd = command.as_ref().expect("checked is_some");
                        let stdin = read_exec_stdin()?;
                        let mut req = ExecRequest::shell(cmd.clone(), None);
                        req.cwd = cwd.clone();
                        req.stdin = stdin;
                        if cli.json {
                            match client.exec_collect(node, req, None).await {
                                Ok(output) => {
                                    println!(
                                        "{}",
                                        json!({
                                            "exit_code": output.exit_code,
                                            "stdout": String::from_utf8_lossy(&output.stdout),
                                            "stderr": String::from_utf8_lossy(&output.stderr),
                                            "truncated": output.truncated,
                                        })
                                    );
                                    Ok(output.exit_code.unwrap_or(1))
                                }
                                Err(err) => Err(hint_exec_cwd_missing(err, cwd.as_deref())),
                            }
                        } else {
                            match client
                                .exec_streaming(node, req, |stream, data| {
                                    if stream == "stderr" {
                                        let mut err = std::io::stderr();
                                        err.write_all(data).ok();
                                        err.flush().ok();
                                    } else {
                                        let mut out = std::io::stdout();
                                        out.write_all(data).ok();
                                        out.flush().ok();
                                    }
                                    true
                                })
                                .await
                            {
                                Ok(code) => Ok(code.unwrap_or(1)),
                                Err(err) => Err(hint_exec_cwd_missing(err, cwd.as_deref())),
                            }
                        }
                    } else {
                        let (rows, cols) = if *line {
                            (24, 80)
                        } else {
                            terminal::terminal_size()
                        };
                        let mut pty = client
                            .open_pty(node, command.clone(), cwd.clone(), rows, cols)
                            .await?;
                        let code = terminal::interact(&mut pty, *line).await?;
                        if cli.json {
                            println!("{}", json!({"exit_code": code}));
                        }
                        Ok(code)
                    }
                }
                Command::Screenshot(args) => {
                    let ScreenshotArgs {
                        node,
                        out_path,
                        target,
                        monitor,
                        window_id,
                        x,
                        y,
                        width,
                        height,
                        image_format,
                        quality,
                        scale,
                        out,
                    } = &**args;
                    let out = match (out.as_ref(), out_path.as_ref()) {
                        (Some(flag), Some(pos)) if flag != pos => {
                            return Err(anyhow!(
                                "pass only one output path (`--out` or a positional path), not both"
                            ));
                        }
                        (Some(flag), _) => Some(flag.clone()),
                        (None, Some(pos)) => Some(pos.clone()),
                        (None, None) => None,
                    };
                    let image_format = resolve_screenshot_format(&image_format, out.as_deref())?;
                    let mut payload = json!({
                        "target": target,
                        "format": image_format,
                        "quality": quality,
                        "scale": scale,
                    });
                    if let Some(monitor) = monitor {
                        payload["monitor"] = json!(monitor);
                    }
                    if let Some(window_id) = window_id {
                        payload["window_id"] = json!(window_id);
                    }
                    if let Some(x) = x {
                        payload["x"] = json!(x);
                    }
                    if let Some(y) = y {
                        payload["y"] = json!(y);
                    }
                    if let Some(width) = width {
                        payload["width"] = json!(width);
                    }
                    if let Some(height) = height {
                        payload["height"] = json!(height);
                    }
                    let value = desktop_call(&client, node, PHASE2_SCREENSHOT, payload).await?;
                    if target != "monitors" {
                        let written = if let Some(path) = out.as_ref() {
                            write_image(&value, path)?;
                            Some(path.clone())
                        } else if !cli.json {
                            let ext = match image_format.as_str() {
                                "png" => "png",
                                "webp" => "webp",
                                _ => "jpg",
                            };
                            let stamp = value["captured_unix_ms"].as_i64().unwrap_or(0);
                            let path = PathBuf::from(format!("agentlink-screenshot-{stamp}.{ext}"));
                            write_image(&value, &path)?;
                            Some(path)
                        } else {
                            None
                        };
                        if let Some(path) = written {
                            if !cli.json {
                                eprintln!(
                                    "wrote {} ({}x{})",
                                    path.display(),
                                    value["width"],
                                    value["height"]
                                );
                            }
                        }
                    }
                    if cli.json || target == "monitors" {
                        if cli.json {
                            println!("{value}");
                        } else {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&value)
                                    .unwrap_or_else(|_| value.to_string())
                            );
                        }
                    }
                    Ok(0)
                }
                Command::Click(args) => {
                    let ClickArgs {
                        node,
                        x,
                        y,
                        button,
                        count,
                        to_x,
                        to_y,
                        move_only,
                    } = &**args;
                    let (action, mut payload) = if *move_only {
                        ("move", json!({"x": x.as_json(), "y": y.as_json()}))
                    } else if let (Some(to_x), Some(to_y)) = (to_x, to_y) {
                        (
                            "drag",
                            json!({
                                "x": x.as_json(),
                                "y": y.as_json(),
                                "to_x": to_x.as_json(),
                                "to_y": to_y.as_json(),
                                "button": button,
                            }),
                        )
                    } else {
                        (
                            "click",
                            json!({
                                "x": x.as_json(),
                                "y": y.as_json(),
                                "button": button,
                                "count": count,
                            }),
                        )
                    };
                    payload["action"] = json!(action);
                    let value = desktop_call(&client, node, PHASE2_INJECT_INPUT, payload).await?;
                    emit(cli.json, value, || eprintln!("{action} at {x},{y}"));
                    Ok(0)
                }
                Command::Type { node, text } => {
                    let value = desktop_call(
                        &client,
                        node,
                        PHASE2_INJECT_INPUT,
                        json!({"action": "type", "text": text}),
                    )
                    .await?;
                    emit(cli.json, value, || {
                        eprintln!("typed {} characters", text.chars().count())
                    });
                    Ok(0)
                }
                Command::Key { node, keys } => {
                    let value = desktop_call(
                        &client,
                        node,
                        PHASE2_INJECT_INPUT,
                        json!({"action": "key", "keys": keys}),
                    )
                    .await?;
                    emit(cli.json, value, || eprintln!("pressed {keys}"));
                    Ok(0)
                }
                Command::Scroll { node, x, y, dx, dy } => {
                    if x.is_some() != y.is_some() {
                        anyhow::bail!("scroll needs both --x and --y, or neither");
                    }
                    let mut payload = json!({
                        "action": "scroll",
                        "dx": dx,
                        "dy": dy,
                    });
                    if let (Some(x), Some(y)) = (x, y) {
                        payload["x"] = x.as_json();
                        payload["y"] = y.as_json();
                    }
                    let value = desktop_call(
                        &client,
                        node,
                        PHASE2_INJECT_INPUT,
                        payload,
                    )
                    .await?;
                    emit(cli.json, value, || eprintln!("scrolled {dx},{dy}"));
                    Ok(0)
                }
                Command::UiTree {
                    node,
                    max_depth,
                    max_nodes,
                } => {
                    let value = desktop_call(
                        &client,
                        node,
                        PHASE2_INJECT_INPUT,
                        json!({"action": "ui_tree", "max_depth": max_depth, "max_nodes": max_nodes}),
                    )
                    .await?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
                    );
                    Ok(0)
                }
                Command::UiAct {
                    node,
                    id,
                    op,
                    value,
                } => {
                    let mut payload = json!({"action": "act", "id": id, "op": op});
                    if let Some(value) = value {
                        payload["value"] = json!(value);
                    }
                    let result = desktop_call(&client, node, PHASE2_INJECT_INPUT, payload).await?;
                    emit(cli.json, result, || eprintln!("{op} {id}"));
                    Ok(0)
                }
                Command::Perm { node, access } => {
                    let policy = parse_access(access)?;
                    let saved = client.set_policy(node, policy).await?;
                    emit(
                        cli.json,
                        json!({"node": node, "access": saved.preset_name(), "policy": saved}),
                        || eprintln!("{node} access is now {}", saved.preset_name()),
                    );
                    Ok(0)
                }
                Command::Relay(_)
                | Command::Node(_)
                | Command::Mcp { .. }
                | Command::Login { .. }
                | Command::Logout
                | Command::Devices { .. }
                | Command::Share { .. }
                | Command::Unshare { .. }
                | Command::Token { .. }
                | Command::User { .. }
                | Command::Client { .. }
                | Command::Approve { .. }
                | Command::Audit { .. }
                | Command::Service { .. }
                | Command::Controller(_)
                | Command::Tray { .. }
                | Command::Update(_)
                | Command::View { .. }
                | Command::Guide { .. }
                | Command::Internal { .. }
                | Command::Bench { .. } => unreachable!(),
            }
        }
    }
}

async fn watch_follow(
    cli: &Cli,
    client: &Client,
    node: &str,
    path: &str,
    recursive: bool,
    timeout_secs: u64,
) -> Result<i32> {
    let started = client.watch_start(node, path, recursive).await?;
    let id = started["watch_id"]
        .as_str()
        .ok_or_else(|| anyhow!("watch did not return an id"))?
        .to_string();
    if !cli.json {
        if let Some(skipped) = started["skipped"].as_array() {
            if !skipped.is_empty() {
                eprintln!(
                    "warning: skipped {} inaccessible path(s) under the watch",
                    skipped.len()
                );
                for path in skipped.iter().take(8) {
                    if let Some(path) = path.as_str() {
                        eprintln!("  {path}");
                    }
                }
                if skipped.len() > 8 {
                    eprintln!("  …");
                }
            }
        }
    }
    let mut cursor = 0u64;
    let mut events = Vec::new();
    let deadline =
        (timeout_secs > 0).then(|| std::time::Instant::now() + Duration::from_secs(timeout_secs));
    let mut interrupted = false;
    loop {
        let now = std::time::Instant::now();
        if deadline.is_some_and(|deadline| now >= deadline) {
            break;
        }
        // Cap each poll to the remaining budget so we return promptly at
        // `--timeout-secs` instead of overshooting by a full 1s wait.
        let wait_ms = match deadline {
            Some(deadline) => deadline
                .saturating_duration_since(now)
                .as_millis()
                .min(1000) as u64,
            None => 1000,
        };
        let poll = tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                interrupted = true;
                break;
            }
            value = client.watch_poll(node, &id, cursor, wait_ms.max(1), 100) => value?,
        };
        if let Some(batch) = poll["events"].as_array() {
            for event in batch {
                if !cli.json {
                    println!(
                        "{} {}",
                        event["kind"].as_str().unwrap_or("event"),
                        event["paths"]
                    );
                }
                events.push(event.clone());
            }
        }
        cursor = poll["cursor"].as_u64().unwrap_or(cursor);
    }
    // Drain once more before stop. Leaving on deadline/ctrl-c without this
    // drop events that arrived after the last poll returned empty (live:
    // `watch --timeout-secs` often reported 0 events for files written near
    // the end of the window).
    if let Ok(poll) = client.watch_poll(node, &id, cursor, 0, 100).await {
        if let Some(batch) = poll["events"].as_array() {
            for event in batch {
                if !cli.json {
                    println!(
                        "{} {}",
                        event["kind"].as_str().unwrap_or("event"),
                        event["paths"]
                    );
                }
                events.push(event.clone());
            }
        }
    }
    let _ = client.watch_stop(node, &id).await;
    if cli.json {
        println!(
            "{}",
            json!({"watch_id": id, "events": events, "interrupted": interrupted})
        );
    } else if events.is_empty() && !interrupted {
        println!("(no events)");
    }
    Ok(0)
}

async fn bg_command(cli: &Cli, client: &Client, node: &str, action: &BgCommand) -> Result<i32> {
    let value = match action {
        BgCommand::Start { cwd, env, shell, cmd } => {
            if !*shell {
                reject_flag_like_program("bg start", cmd)?;
            }
            let env_pairs = parse_env_pairs(env)?;
            let stdin = read_exec_stdin()?;
            let program = if *shell {
                cmd.join(" ")
            } else {
                cmd[0].clone()
            };
            let started = if *shell {
                client
                    .bg_start(
                        node,
                        &program,
                        Vec::new(),
                        cwd.clone(),
                        env_pairs,
                        true,
                        stdin,
                    )
                    .await
            } else {
                client
                    .bg_start(
                        node,
                        &program,
                        cmd[1..].to_vec(),
                        cwd.clone(),
                        env_pairs,
                        false,
                        stdin,
                    )
                    .await
            };
            match started {
                Ok(value) => value,
                Err(err) => {
                    return Err(hint_bg_start_exec_denied(
                        hint_exec_cwd_missing(err, cwd.as_deref()),
                        node,
                        &program,
                        cwd.as_deref(),
                    ))
                }
            }
        }
        BgCommand::List => client.bg_list(node).await?,
        BgCommand::Output {
            id,
            stdout_cursor,
            stderr_cursor,
            max_bytes,
        } => {
            client
                .bg_output(node, id, *stdout_cursor, *stderr_cursor, *max_bytes)
                .await?
        }
        BgCommand::Status { id } => client.bg_status(node, id).await?,
        BgCommand::Kill { id } => client.bg_kill(node, id).await?,
    };
    emit(cli.json, value.clone(), || print_bg(action, &value));
    Ok(0)
}

fn print_bg(action: &BgCommand, value: &Value) {
    match action {
        BgCommand::List => {
            let procs = value
                .get("processes")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();
            if procs.is_empty() {
                println!("(no background processes)");
                return;
            }
            println!("ID        PID      STATUS   COMMAND");
            for proc in procs {
                let id = proc.get("id").and_then(|v| v.as_str()).unwrap_or("");
                let pid = proc
                    .get("pid")
                    .and_then(|v| v.as_u64())
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into());
                let status = if proc.get("running").and_then(|v| v.as_bool()) == Some(true) {
                    "running".to_string()
                } else if let Some(code) = proc.get("exit_code").and_then(|v| v.as_i64()) {
                    format!("exit {code}")
                } else {
                    "done".into()
                };
                let cmd = proc.get("command").and_then(|v| v.as_str()).unwrap_or("");
                println!("{id:<8}  {pid:<7}  {status:<8} {cmd}");
            }
        }
        BgCommand::Start { .. } => {
            let id = value.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let pid = value
                .get("pid")
                .and_then(|v| v.as_u64())
                .map(|p| p.to_string())
                .unwrap_or_else(|| "?".into());
            let cmd = value.get("command").and_then(|v| v.as_str()).unwrap_or("");
            println!("started {id} pid {pid}: {cmd}");
        }
        BgCommand::Status { .. } | BgCommand::Kill { .. } => {
            let id = value.get("id").and_then(|v| v.as_str()).unwrap_or("");
            let running = value.get("running").and_then(|v| v.as_bool());
            let exit = value.get("exit_code").and_then(|v| v.as_i64());
            match (running, exit) {
                (Some(true), _) => println!("{id} running"),
                (_, Some(code)) => println!("{id} exit {code}"),
                _ => println!("{value}"),
            }
        }
        BgCommand::Output { .. } => {
            // Node returns { encoding, text } (or base64) per stream.
            for (key, to_stderr) in [("stdout", false), ("stderr", true)] {
                let chunk = value.get(key);
                let text = chunk
                    .and_then(|v| v.get("text"))
                    .and_then(|v| v.as_str())
                    .or_else(|| chunk.and_then(|v| v.as_str()))
                    .unwrap_or("");
                if text.is_empty() {
                    continue;
                }
                if to_stderr {
                    eprint!("{text}");
                } else {
                    print!("{text}");
                }
            }
        }
    }
}

fn print_sysinfo(value: &Value) {
    println!(
        "{} {} ({})",
        value["os_name"]
            .as_str()
            .unwrap_or(value["os"].as_str().unwrap_or("")),
        value["os_version"].as_str().unwrap_or(""),
        value["arch"].as_str().unwrap_or("")
    );
    println!("host {}", value["hostname"].as_str().unwrap_or(""));
    println!(
        "cpu {} x {}",
        value["cpu"]["count"].as_u64().unwrap_or(0),
        value["cpu"]["brand"].as_str().unwrap_or("")
    );
    println!(
        "memory {} / {} bytes free",
        value["memory"]["available_bytes"].as_u64().unwrap_or(0),
        value["memory"]["total_bytes"].as_u64().unwrap_or(0)
    );
    println!(
        "user {} shell {}",
        value["user"].as_str().unwrap_or(""),
        value["shell"].as_str().unwrap_or("")
    );
}

fn shell_quote_arg(s: &str) -> String {
    if s.is_empty() {
        return "''".into();
    }
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':' ))
        && !s.contains('*')
        && !s.contains('?')
        && !s.contains('[')
    {
        return s.to_string();
    }
    format!("'{s}'")
}

/// When the first positional fails as a machine name but a later arg is a
/// known machine, suggest swapping (path/glob or bare token before NODE).
async fn hint_if_node_args_swapped(
    client: &Client,
    err: agentlink_core::Error,
    first: &str,
    second: Option<&str>,
    example: &str,
) -> anyhow::Error {
    use agentlink_core::protocol::resolve_node;
    if let Some(second) = second {
        if let Ok(nodes) = client.list_nodes().await {
            if resolve_node(&nodes, first).is_err() && resolve_node(&nodes, second).is_ok() {
                return anyhow!(
                    "{err}. Did you mean `{example}` (machine name first)?"
                );
            }
        }
    }
    anyhow!(err.to_string())
}

const NODES_EMPTY_TIP: &str =
    "tip: pair a machine with `agentlink pair --name <name>`, then run `agentlink nodes` again";
const NODES_FOOTER_TIP: &str =
    "tip: `agentlink exec <name> hostname`; `agentlink grant list`; `agentlink guide <name>`";

/// `ONLINE` / `OFFLINE`, matching the upper-case labels of `grant list`.
fn nodes_status_label(online: bool) -> &'static str {
    if online {
        "ONLINE"
    } else {
        "OFFLINE"
    }
}

/// Desktop-session label; `?` means an older node that has not reported.
fn nodes_display_label(has_display: Option<bool>) -> &'static str {
    match has_display {
        Some(true) => "desktop",
        Some(false) => "headless",
        None => "?",
    }
}

/// Leading semver token of `version`, dropping build metadata such as
/// ` (9c1180d…)`. Unknown or empty versions show `?`.
fn nodes_version_short(version: &str) -> String {
    let token = version
        .trim()
        .split(|ch: char| ch.is_whitespace() || ch == '(')
        .next()
        .unwrap_or("");
    if token.is_empty() {
        "?".to_string()
    } else {
        token.to_string()
    }
}

/// One human line per paired machine: name, status, display, os/arch, access,
/// short id, and version.
fn format_nodes_line(node: &NodeInfo) -> String {
    let id: String = node.id.chars().take(12).collect();
    format!(
        "{:<16} {:<8} {:<8} {:<16} {:<14} {:<12} {id}",
        node.name,
        nodes_status_label(node.online),
        nodes_display_label(node.has_display),
        format!("{}/{}", node.os, node.arch),
        node.effective.preset_name(),
        nodes_version_short(&node.version),
    )
    .trim_end()
    .to_string()
}

/// Cap a list of names at three, appending `and N more` when longer.
fn nodes_cap_names(names: &[&str]) -> String {
    let shown = names.iter().take(3).copied().collect::<Vec<_>>().join(", ");
    match names.len().saturating_sub(3) {
        0 => shown,
        extra => format!("{shown} and {extra} more"),
    }
}

/// Guidance for an offline node, shared by `nodes` tips and error decoration.
fn tip_node_offline(name: &str) -> String {
    format!(
        "tip: offline: {name} — wake the machine or check the agentlink-node service; then agentlink nodes"
    )
}

const NODE_OFFLINE_TIP_MARKER: &str = "wake the machine or check the agentlink-node service";

/// Extract `<name>` from a `node offline: <name>` message, including one
/// wrapped in an anyhow context chain.
fn node_offline_name(message: &str) -> Option<&str> {
    let (_, rest) = message.rsplit_once("node offline: ")?;
    let name = rest.lines().next()?.trim();
    (!name.is_empty()).then_some(name)
}

/// Append [`tip_node_offline`] to a `node offline: <name>` error. Idempotent,
/// so an error already carrying the tip is returned unchanged.
fn decorate_node_offline(message: &str) -> String {
    if message.contains(NODE_OFFLINE_TIP_MARKER) {
        return message.to_string();
    }
    match node_offline_name(message) {
        Some(name) => format!("{message}. {}", tip_node_offline(name)),
        None => message.to_string(),
    }
}

const CONNECTION_CLOSED_TIP_MARKER: &str = "the relay connection closed during the operation";

/// MCP `retry` returns this exact fallback after both relay attempts close.
/// Wrapped and more specific transport errors stay raw so they retain their
/// own context.
fn is_connection_closed_error(message: &str) -> bool {
    message.trim() == "connection closed"
}

/// Explain reconnect behavior without claiming that the node rejected or never
/// received the operation. The request may have taken effect before the relay
/// connection dropped, so blind retries of side-effecting calls are unsafe.
fn decorate_connection_closed(message: &str) -> String {
    if message.contains(CONNECTION_CLOSED_TIP_MARKER) || !is_connection_closed_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {CONNECTION_CLOSED_TIP_MARKER} — MCP dropped the closed client, cleared \
         its cached terminal sessions, reconnected, and retried once, but both attempts ended \
         with `connection closed`. The operation's outcome is unknown: the request may have \
         reached the node before the disconnect, so do not assume nothing ran. Before repeating \
         side-effecting `run_command` / `process_start`, file writes, copies, moves, or removes, \
         inspect the relevant files or processes to avoid duplicating effects; read-only list / \
         stat / read calls can be retried after connectivity returns. Run `agentlink nodes` to \
         check whether the target is ONLINE, then retry the MCP call to establish a fresh \
         connection. Cached terminal ids were cleared: call `terminal_open` again and use the new \
         `session_id` rather than reusing an old one. This is a transport failure, not proof of \
         invalid input, a permission denial, or an offline node. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod connection_closed_tip_tests {
    use super::*;

    #[test]
    fn connection_closed_gets_the_tip_once() {
        for raw in ["connection closed", "  connection closed\n"] {
            let out = decorate_connection_closed(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(out.matches(CONNECTION_CLOSED_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "cleared its cached terminal sessions",
                "reconnected, and retried once",
                "both attempts",
                "outcome is unknown",
                "do not assume nothing ran",
                "`run_command` / `process_start`",
                "inspect the relevant files or processes",
                "read-only list / stat / read",
                "`agentlink nodes`",
                "ONLINE",
                "`terminal_open`",
                "new `session_id`",
                "transport failure",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_connection_closed(&out), out);
        }
    }

    #[test]
    fn connection_closed_leaves_siblings_alone() {
        for raw in [
            "exec hostname: connection closed",
            "connection closed by peer",
            "node offline: box",
            "relay session expired or was revoked",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_connection_closed(raw), raw, "{raw}");
        }
    }
}

const RELAY_URL_TLS_TIP_MARKER: &str = "relay URLs must use wss://";

/// Shared relay URL parsing rejects insecure `ws://` and `http://` with this
/// exact message. Other unsupported schemes include their own scheme name and
/// are a separate error.
fn is_relay_url_tls_error(message: &str) -> bool {
    message.trim() == "relay url must use wss:// (TLS is required)"
}

/// Give a valid replacement URL and port defaults, and distinguish this
/// pre-connect validation from later TLS certificate or connection failures.
fn decorate_relay_url_tls(message: &str) -> String {
    if message.contains(RELAY_URL_TLS_TIP_MARKER) || !is_relay_url_tls_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {RELAY_URL_TLS_TIP_MARKER} — replace `ws://` or `http://` with `wss://` \
         explicitly; insecure schemes are rejected, not upgraded silently. For example, use \
         `--relay wss://relay.example.com` (or set `AGENTLINK_RELAY=wss://relay.example.com`). \
         `https://` is accepted as an alias for `wss://`. A `wss://host` URL dials port 443 and an \
         explicit port is preserved, as in `wss://host:7443`; a bare `host` or `host:port` remains \
         valid and defaults to port 7443 when no port is written. This URL validation happens \
         before any relay connection or node operation, so retrying the same insecure URL fails \
         identically. Certificate, hostname, authentication, and connection-refused errors happen \
         later and are different failures. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod relay_url_tls_tip_tests {
    use super::*;

    #[test]
    fn insecure_relay_url_gets_the_tip_once() {
        for raw in [
            "relay url must use wss:// (TLS is required)",
            "  relay url must use wss:// (TLS is required)\n",
        ] {
            let out = decorate_relay_url_tls(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(out.matches(RELAY_URL_TLS_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "`ws://` or `http://`",
                "not upgraded silently",
                "`--relay wss://relay.example.com`",
                "`AGENTLINK_RELAY=wss://relay.example.com`",
                "`https://` is accepted as an alias",
                "port 443",
                "`wss://host:7443`",
                "bare `host` or `host:port`",
                "defaults to port 7443",
                "before any relay connection or node operation",
                "Certificate, hostname, authentication, and connection-refused",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_relay_url_tls(&out), out);
        }
    }

    #[test]
    fn insecure_relay_url_leaves_siblings_alone() {
        for raw in [
            "connect: relay url must use wss:// (TLS is required)",
            "relay url scheme `ftp` is not supported; use wss://",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "tls: tls handshake eof",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_relay_url_tls(raw), raw, "{raw}");
        }
    }
}

const UNSUPPORTED_RELAY_SCHEME_TIP_MARKER: &str = "supported relay URL forms";

/// Match the separate shared-parser error for schemes other than ws, http,
/// wss, and https. URL schemes are ASCII and cannot contain wrapping text or
/// newlines; validating that shape keeps unrelated wrapped errors raw.
fn is_unsupported_relay_scheme_error(message: &str) -> bool {
    let scheme = message
        .trim()
        .strip_prefix("relay url scheme `")
        .and_then(|rest| rest.strip_suffix("` is not supported; use wss://"))
        .unwrap_or_default();
    let mut bytes = scheme.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_alphabetic())
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
}

/// Show every accepted URL form without conflating this error with the
/// insecure ws/http error or with failures after a valid URL starts connecting.
fn decorate_unsupported_relay_scheme(message: &str) -> String {
    if message.contains(UNSUPPORTED_RELAY_SCHEME_TIP_MARKER)
        || !is_unsupported_relay_scheme_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {UNSUPPORTED_RELAY_SCHEME_TIP_MARKER} — use \
         `--relay wss://relay.example.com` (or set \
         `AGENTLINK_RELAY=wss://relay.example.com`). `wss://` is the normal secure scheme; \
         `https://` is accepted as an alias and normalized to `wss`. Valid forms are \
         `wss://host[:port]` (port 443 by default), `https://host[:port]`, or `host[:port]` \
         (port 7443 by default); an explicit port is preserved. This validation happens before \
         any relay connection or node operation. `ws://` and `http://` are insecure and have a \
         separate TLS-required error; certificate, hostname, authentication, and \
         connection-refused errors happen later. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod unsupported_relay_scheme_tip_tests {
    use super::*;

    #[test]
    fn unsupported_relay_scheme_gets_the_tip_once() {
        for raw in [
            "relay url scheme `ftp` is not supported; use wss://",
            "  relay url scheme `quic+control` is not supported; use wss://\n",
        ] {
            let out = decorate_unsupported_relay_scheme(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(
                out.matches(UNSUPPORTED_RELAY_SCHEME_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "`--relay wss://relay.example.com`",
                "`AGENTLINK_RELAY=wss://relay.example.com`",
                "`https://` is accepted as an alias",
                "`wss://host[:port]`",
                "port 443 by default",
                "`host[:port]`",
                "port 7443 by default",
                "explicit port is preserved",
                "before any relay connection or node operation",
                "separate TLS-required error",
                "certificate, hostname, authentication, and",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_unsupported_relay_scheme(&out), out);
        }
    }

    #[test]
    fn unsupported_relay_scheme_leaves_siblings_alone() {
        for raw in [
            "connect: relay url scheme `ftp` is not supported; use wss://",
            "relay url scheme `` is not supported; use wss://",
            "relay url scheme `ftp` is not supported; use wss:// extra",
            "relay url must use wss:// (TLS is required)",
            "relay url: relative URL without a base",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_unsupported_relay_scheme(raw), raw, "{raw}");
        }
    }
}

const RELAY_PORT_ZERO_TIP_MARKER: &str = "relay port must be between 1 and 65535";

fn is_relay_port_zero_error(message: &str) -> bool {
    message.trim() == "relay port must not be 0"
}

/// Explain how to recover from an explicitly zero port without swallowing the
/// URL parser's distinct error for ports above 65535.
fn decorate_relay_port_zero(message: &str) -> String {
    if message.contains(RELAY_PORT_ZERO_TIP_MARKER) || !is_relay_port_zero_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {RELAY_PORT_ZERO_TIP_MARKER} — port 0 cannot identify a remote relay \
         listener. Omit `:0` to use the default: `--relay wss://relay.example.com` dials port 443, \
         while bare `relay.example.com` defaults to port 7443 (`https://` remains an accepted \
         `wss://` alias). Or write an explicit port such as \
         `--relay wss://relay.example.com:7443`. Valid explicit ports are 1 through 65535; larger \
         values fail URL parsing separately as `relay url: invalid port number`. This validation \
         happens before any relay connection or node operation. Scheme, certificate, hostname, \
         authentication, and connection-refused errors are separate failures. See \
         `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod relay_port_zero_tip_tests {
    use super::*;

    #[test]
    fn relay_port_zero_gets_the_tip_once() {
        for raw in ["relay port must not be 0", "  relay port must not be 0\n"] {
            let out = decorate_relay_port_zero(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(out.matches(RELAY_PORT_ZERO_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "port 0 cannot identify a remote relay listener",
                "Omit `:0`",
                "`--relay wss://relay.example.com`",
                "port 443",
                "bare `relay.example.com` defaults to port 7443",
                "`https://` remains an accepted",
                "`--relay wss://relay.example.com:7443`",
                "1 through 65535",
                "`relay url: invalid port number`",
                "before any relay connection or node operation",
                "Scheme, certificate, hostname, authentication, and",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_relay_port_zero(&out), out);
        }
    }

    #[test]
    fn relay_port_zero_leaves_siblings_alone() {
        for raw in [
            "connect: relay port must not be 0",
            "relay port must not be 0 extra",
            "relay url: invalid port number",
            "relay url is missing a host",
            "relay url must use wss:// (TLS is required)",
            "relay url scheme `ftp` is not supported; use wss://",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_relay_port_zero(raw), raw, "{raw}");
        }
    }
}

const RELAY_INVALID_PORT_TIP_MARKER: &str = "relay URL port is invalid";

fn is_relay_invalid_port_error(message: &str) -> bool {
    message.trim() == "relay url: invalid port number"
}

/// Cover both nonnumeric and oversized ports rejected by `url::Url`. Port
/// zero parses successfully and is handled by its own later validation tip.
fn decorate_relay_invalid_port(message: &str) -> String {
    if message.contains(RELAY_INVALID_PORT_TIP_MARKER) || !is_relay_invalid_port_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {RELAY_INVALID_PORT_TIP_MARKER} — write the port as decimal digits from \
         1 through 65535; words such as `:abc` and oversized values such as `:65536` fail during \
         URL parsing. Remove the invalid `:port` to use the default, as in \
         `--relay wss://relay.example.com` (port 443), or write a valid explicit port, as in \
         `--relay wss://relay.example.com:7443`. A bare `relay.example.com` defaults to port 7443, \
         and `https://` is an accepted `wss://` alias. Port 0 parses but is rejected separately as \
         `relay port must not be 0`. This URL validation happens before any relay connection or \
         node operation. Scheme, certificate, hostname, authentication, and connection-refused \
         errors are separate failures. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod relay_invalid_port_tip_tests {
    use super::*;

    #[test]
    fn relay_invalid_port_gets_the_tip_once() {
        for raw in [
            "relay url: invalid port number",
            "  relay url: invalid port number\n",
        ] {
            let out = decorate_relay_invalid_port(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(
                out.matches(RELAY_INVALID_PORT_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "decimal digits from 1 through 65535",
                "`:abc`",
                "`:65536`",
                "Remove the invalid `:port`",
                "`--relay wss://relay.example.com`",
                "port 443",
                "`--relay wss://relay.example.com:7443`",
                "bare `relay.example.com` defaults to port 7443",
                "`https://` is an accepted",
                "`relay port must not be 0`",
                "before any relay connection or node operation",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_relay_invalid_port(&out), out);
        }
    }

    #[test]
    fn relay_invalid_port_leaves_siblings_alone() {
        for raw in [
            "connect: relay url: invalid port number",
            "relay url: invalid port number extra",
            "relay port must not be 0",
            "relay url: relative URL without a base",
            "relay url must use wss:// (TLS is required)",
            "relay url scheme `ftp` is not supported; use wss://",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_relay_invalid_port(raw), raw, "{raw}");
        }
    }
}

const RELAY_EMPTY_HOST_TIP_MARKER: &str = "relay URL needs a host";

fn is_relay_empty_host_error(message: &str) -> bool {
    message.trim() == "relay url: empty host"
}

/// A scheme-only special URL fails inside `url::Url`, before the parser's own
/// missing-host check. Keep those two RAW forms distinct.
fn decorate_relay_empty_host(message: &str) -> String {
    if message.contains(RELAY_EMPTY_HOST_TIP_MARKER) || !is_relay_empty_host_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {RELAY_EMPTY_HOST_TIP_MARKER} — write a DNS name or IP address after \
         `wss://`; a scheme, port, or path alone is not enough. For example, use \
         `--relay wss://relay.example.com` (or set `AGENTLINK_RELAY=wss://relay.example.com`), \
         which dials port 443. An explicit port is preserved, as in \
         `--relay wss://relay.example.com:7443`. `https://` is an accepted `wss://` alias, and a \
         bare `relay.example.com` defaults to port 7443. This URL validation happens before any \
         relay connection or node operation. Empty URLs, missing-host validation, scheme/port \
         errors, certificate/hostname/authentication failures, and connection refusal are separate \
         failures. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod relay_empty_host_tip_tests {
    use super::*;

    #[test]
    fn relay_empty_host_gets_the_tip_once() {
        for raw in ["relay url: empty host", "  relay url: empty host\n"] {
            let out = decorate_relay_empty_host(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(out.matches(RELAY_EMPTY_HOST_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "write a DNS name or IP address after `wss://`",
                "scheme, port, or path alone is not enough",
                "`--relay wss://relay.example.com`",
                "`AGENTLINK_RELAY=wss://relay.example.com`",
                "port 443",
                "`--relay wss://relay.example.com:7443`",
                "`https://` is an accepted",
                "bare `relay.example.com` defaults to port 7443",
                "before any relay connection or node operation",
                "Empty URLs, missing-host validation, scheme/port",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_relay_empty_host(&out), out);
        }
    }

    #[test]
    fn relay_empty_host_leaves_siblings_alone() {
        for raw in [
            "connect: relay url: empty host",
            "relay url: empty host extra",
            "relay url is empty",
            "relay url is missing a host",
            "relay url: invalid port number",
            "relay port must not be 0",
            "relay url must use wss:// (TLS is required)",
            "relay url scheme `ftp` is not supported; use wss://",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_relay_empty_host(raw), raw, "{raw}");
        }
    }
}

const RELAY_MISSING_HOST_TIP_MARKER: &str = "relay URL is missing a host";

fn is_relay_missing_host_error(message: &str) -> bool {
    message.trim() == "relay url is missing a host"
}

/// A bare path parses as a URL but has no relay host. Keep this distinct from
/// the special-URL parser's `relay url: empty host` error.
fn decorate_relay_missing_host(message: &str) -> String {
    if message.contains(RELAY_MISSING_HOST_TIP_MARKER) || !is_relay_missing_host_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {RELAY_MISSING_HOST_TIP_MARKER} — a value such as `/` supplies a path \
         but no DNS name or IP address. Use `--relay wss://relay.example.com` (or set \
         `AGENTLINK_RELAY=wss://relay.example.com`), which dials port 443. An explicit port is \
         preserved, as in `--relay wss://relay.example.com:7443`. `https://` is an accepted \
         `wss://` alias, and a bare `relay.example.com` defaults to port 7443. This URL validation \
         happens before any relay connection or node operation. The separate `relay url: empty \
         host` parse error, empty URLs, scheme/port errors, certificate/hostname/authentication \
         failures, and connection refusal are distinct failures. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod relay_missing_host_tip_tests {
    use super::*;

    #[test]
    fn relay_missing_host_gets_the_tip_once() {
        for raw in ["relay url is missing a host", "  relay url is missing a host\n"] {
            let out = decorate_relay_missing_host(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(out.matches(RELAY_MISSING_HOST_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "a value such as `/` supplies a path",
                "no DNS name or IP address",
                "`--relay wss://relay.example.com`",
                "`AGENTLINK_RELAY=wss://relay.example.com`",
                "port 443",
                "`--relay wss://relay.example.com:7443`",
                "`https://` is an accepted",
                "bare `relay.example.com` defaults to port 7443",
                "before any relay connection or node operation",
                "`relay url: empty host` parse error",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_relay_missing_host(&out), out);
        }
    }

    #[test]
    fn relay_missing_host_leaves_siblings_alone() {
        for raw in [
            "connect: relay url is missing a host",
            "relay url is missing a host extra",
            "relay url: empty host",
            "relay url is empty",
            "relay url: invalid port number",
            "relay port must not be 0",
            "relay url must use wss:// (TLS is required)",
            "relay url scheme `ftp` is not supported; use wss://",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_relay_missing_host(raw), raw, "{raw}");
        }
    }
}

const RELAY_FINGERPRINT_TIP_MARKER: &str = "relay certificate fingerprint is invalid";

fn is_relay_fingerprint_error(message: &str) -> bool {
    message.trim() == "tls: fingerprint: Odd number of digits"
}

/// An unknown trust token falls through to legacy leaf-fingerprint parsing, so
/// an odd-length token and an odd-length explicit pin share this parser error.
fn decorate_relay_fingerprint(message: &str) -> String {
    if message.contains(RELAY_FINGERPRINT_TIP_MARKER) || !is_relay_fingerprint_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {RELAY_FINGERPRINT_TIP_MARKER} — a SHA-256 fingerprint is 64 \
         hexadecimal digits (32 bytes), not an arbitrary name or odd-length string. Use \
         `--fingerprint sha256:<64 hex digits>`, or use public roots with `--fingerprint system` \
         or `--trust webpki` (`web-pki` is an alias). An unrecognized `--trust` value is treated \
         as a legacy leaf fingerprint and can produce this same parser error; valid root modes are \
         `system` and `webpki` (combine them as `system+webpki`). This validation happens before \
         any relay connection or node operation. Certificate mismatch, hostname failure, and \
         connection refusal are separate failures. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod relay_fingerprint_tip_tests {
    use super::*;

    #[test]
    fn relay_fingerprint_gets_the_tip_once() {
        for raw in [
            "tls: fingerprint: Odd number of digits",
            "  tls: fingerprint: Odd number of digits\n",
        ] {
            let out = decorate_relay_fingerprint(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(out.matches(RELAY_FINGERPRINT_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "64 hexadecimal digits (32 bytes)",
                "not an arbitrary name or odd-length string",
                "`--fingerprint sha256:<64 hex digits>`",
                "`--fingerprint system`",
                "`--trust webpki`",
                "`web-pki` is an alias",
                "unrecognized `--trust` value",
                "valid root modes are `system` and `webpki`",
                "`system+webpki`",
                "before any relay connection or node operation",
                "Certificate mismatch, hostname failure, and connection refusal",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_relay_fingerprint(&out), out);
        }
    }

    #[test]
    fn relay_fingerprint_leaves_siblings_alone() {
        for raw in [
            "connect: tls: fingerprint: Odd number of digits",
            "tls: fingerprint: Odd number of digits extra",
            "tls: fingerprint: odd number of digits",
            "tls: fingerprint: Invalid character 'x' at position 0",
            "tls: fingerprint must be 32 bytes (sha256 hex)",
            "tls: certificate fingerprint mismatch",
            "tls: invalid server name",
            "relay url: empty host",
            "relay url is missing a host",
            "connect 127.0.0.1:9: Connection refused (os error 111)",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_relay_fingerprint(raw), raw, "{raw}");
        }
    }
}

const GRANT_CAPABILITY_TIP_MARKER: &str = "tip: capability denied";
const GRANT_EXPIRED_TIP_MARKER: &str = "tip: the signed grant has expired";
const GRANT_REVOKED_TIP_MARKER: &str = "tip: the signed grant was revoked";
const GRANT_LIST_TIP_MARKER: &str = "grant list";

/// The policy kind in an `exec is not allowed on this node (…)` message, used
/// to suggest the narrowest `grant ensure --policy` that would allow it.
fn denied_capability_kind(message: &str) -> Option<&str> {
    const NEEDLE: &str = " is not allowed on this node";
    let idx = message.find(NEEDLE)?;
    let head = &message[..idx];
    let kind = head
        .rsplit(|ch: char| ch.is_whitespace() || ch == ':')
        .next()?
        .trim();
    (!kind.is_empty()).then_some(kind)
}

/// Actionable tips for capability and signed-grant failures: a node policy
/// that is too narrow, an expired grant, or a revoked grant. Filesystem
/// `Permission denied (os error 13)` errors are left alone — those already get
/// [`hint_fs_error`].
fn decorate_grant_capability(message: &str) -> String {
    if message.contains(GRANT_CAPABILITY_TIP_MARKER)
        || message.contains(GRANT_EXPIRED_TIP_MARKER)
        || message.contains(GRANT_REVOKED_TIP_MARKER)
    {
        return message.to_string();
    }
    if let Some(kind) = denied_capability_kind(message) {
        let policy = match kind {
            "read" | "write" | "exec" => kind,
            _ => "exec",
        };
        return format!(
            "{message}; {GRANT_CAPABILITY_TIP_MARKER} — check `agentlink grant list`; widen with \
             `agentlink grant ensure --node <name> --policy {policy}` (or full); see \
             `agentlink guide <name>`"
        );
    }
    if message.contains("grant has expired") || message.contains("grant expired at unix") {
        return format!(
            "{message}; {GRANT_EXPIRED_TIP_MARKER} — refresh with `agentlink grant refresh --node \
             <name>` (or `agentlink grant ensure --node <name>`); check `agentlink grant list`; \
             see `agentlink guide <name>`"
        );
    }
    if message.contains("grant was revoked") {
        return format!(
            "{message}; {GRANT_REVOKED_TIP_MARKER} — check `agentlink grant list`; issue a fresh \
             grant with `agentlink grant ensure --node <name>` (or `agentlink grant issue --node \
             <name>`); see `agentlink guide <name>`"
        );
    }
    if message.contains("signed grant required") && !message.contains(GRANT_LIST_TIP_MARKER) {
        return format!("{message}; tip: also `agentlink grant list` / `agentlink guide <name>`");
    }
    message.to_string()
}

#[cfg(test)]
mod grant_capability_tip_tests {
    use super::*;

    #[test]
    fn policy_deny_gets_grant_and_guide_tips() {
        let out = decorate_grant_capability(
            "exec hostname: exec is not allowed on this node (read-only)",
        );
        assert!(out.contains("tip: capability denied"), "{out}");
        assert!(out.contains("agentlink grant list"), "{out}");
        assert!(
            out.contains("agentlink grant ensure --node <name> --policy exec"),
            "{out}"
        );
        assert!(out.contains("agentlink guide <name>"), "{out}");
    }

    #[test]
    fn wrapped_write_deny_suggests_write_policy() {
        let out = decorate_grant_capability("permission denied: write is not allowed on this node");
        assert!(out.contains("tip: capability denied"), "{out}");
        assert!(out.contains("--policy write"), "{out}");
        assert!(out.contains("agentlink guide <name>"), "{out}");
    }

    #[test]
    fn expired_grant_gets_refresh_and_list_tips() {
        let out = decorate_grant_capability("authentication failed: grant has expired");
        assert!(out.contains("tip: the signed grant has expired"), "{out}");
        assert!(
            out.contains("agentlink grant refresh --node <name>"),
            "{out}"
        );
        assert!(
            out.contains("agentlink grant ensure --node <name>"),
            "{out}"
        );
        assert!(out.contains("agentlink grant list"), "{out}");
        assert!(out.contains("agentlink guide <name>"), "{out}");
    }

    #[test]
    fn expired_grant_at_unix_gets_refresh_and_list_tips() {
        let raw = "grant expired at unix 1793780563; run `agentlink grant refresh --node 762e3a20` (or `agentlink grant issue --node 762e3a20` to change policy)";
        let out = decorate_grant_capability(raw);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(out.matches(GRANT_EXPIRED_TIP_MARKER).count(), 1, "{out}");
        assert!(
            out.contains("agentlink grant refresh --node <name>"),
            "{out}"
        );
        assert!(
            out.contains("agentlink grant ensure --node <name>"),
            "{out}"
        );
        assert!(out.contains("agentlink grant list"), "{out}");
        assert!(out.contains("agentlink guide <name>"), "{out}");
        assert_eq!(out.matches("; tip:").count(), 1, "{out}");
        assert_eq!(decorate_grant_capability(&out), out);
    }

    #[test]
    fn revoked_grant_gets_ensure_and_list_tips() {
        let out = decorate_grant_capability(
            "authentication failed: grant was revoked (jti 3f2a1b4c-0000-0000-0000-000000000000)",
        );
        assert!(out.contains("tip: the signed grant was revoked"), "{out}");
        assert!(out.contains("agentlink grant list"), "{out}");
        assert!(
            out.contains("agentlink grant ensure --node <name>"),
            "{out}"
        );
        assert!(out.contains("agentlink grant issue --node <name>"), "{out}");
    }

    #[test]
    fn decorate_is_idempotent() {
        for raw in [
            "exec is not allowed on this node (read-only)",
            "authentication failed: grant has expired",
            "grant expired at unix 1793780563; run `agentlink grant refresh --node 762e3a20` (or `agentlink grant issue --node 762e3a20` to change policy)",
            "authentication failed: grant was revoked (jti abc)",
            "signed grant required (owner keys configured); run `agentlink grant issue --node deadbeef`",
        ] {
            let once = decorate_grant_capability(raw);
            assert_eq!(decorate_grant_capability(&once), once, "{raw}");
        }
    }

    #[test]
    fn filesystem_permission_denied_is_left_to_hint_fs_error() {
        for raw in [
            "Permission denied (os error 13)",
            "cp /tmp/a: Permission denied",
            "permission denied: exec",
            "io: Permission denied (os error 13)",
        ] {
            assert_eq!(decorate_grant_capability(raw), raw);
        }
    }

    #[test]
    fn signed_grant_required_adds_list_and_guide_once() {
        let raw = "signed grant required (owner keys configured); run `agentlink grant issue --node deadbeef` (or `agentlink grant refresh --node deadbeef` if a grant file still exists; revoke: `agentlink grant revoke --node deadbeef` to update the node deny-list over E2E, or `agentlink grant revoke-local --node deadbeef` for the local file only)";
        let out = decorate_grant_capability(raw);
        assert!(out.starts_with(raw), "{out}");
        assert!(out.contains("`agentlink grant list`"), "{out}");
        assert!(out.contains("`agentlink guide <name>`"), "{out}");
        assert_eq!(decorate_grant_capability(&out), out);
    }
}

const SESSION_AUTH_TIP_MARKER: &str = "tip: relay session expired or was revoked";

/// Append an actionable tip to relay session/refresh failures: sign in again
/// (with TOTP when enabled) or inspect/revoke devices if this one was revoked.
/// Idempotent; signed-grant failures are left to [`decorate_grant_capability`].
fn decorate_session_auth(message: &str) -> String {
    if message.contains(SESSION_AUTH_TIP_MARKER) {
        return message.to_string();
    }
    let session_failure = [
        "session expired or revoked",
        "session expired",
        "session revoked",
        "refresh token is invalid or revoked",
        "client is revoked",
    ]
    .iter()
    .any(|needle| message.contains(needle));
    if !session_failure {
        return message.to_string();
    }
    format!(
        "{message}; {SESSION_AUTH_TIP_MARKER} — sign in again with `agentlink login --user <name>` \
         (add `--totp <code>` if enabled); check `agentlink devices` if this device was revoked"
    )
}

#[cfg(test)]
mod session_auth_tip_tests {
    use super::*;

    #[test]
    fn session_failures_get_login_and_devices_tip_once() {
        for raw in [
            "authentication failed: session expired or revoked",
            "authentication failed: session expired",
            "authentication failed: session revoked",
            "authentication failed: refresh token is invalid or revoked",
            "authentication failed: client is revoked",
        ] {
            let out = decorate_session_auth(raw);
            assert!(out.starts_with(raw), "{raw}: {out}");
            assert_eq!(out.matches(SESSION_AUTH_TIP_MARKER).count(), 1, "{out}");
            assert!(out.contains("agentlink login --user <name>"), "{out}");
            assert!(out.contains("--totp <code>"), "{out}");
            assert!(out.contains("agentlink devices"), "{out}");
            assert_eq!(decorate_session_auth(&out), out, "{raw}");
        }
    }

    #[test]
    fn grant_failures_are_left_to_grant_decorator() {
        for raw in [
            "authentication failed: grant has expired",
            "authentication failed: grant was revoked (jti abc)",
        ] {
            assert_eq!(decorate_session_auth(raw), raw);
        }
    }

    #[test]
    fn unrelated_errors_are_unchanged() {
        for raw in [
            "node offline: probe",
            "Permission denied (os error 13)",
            "connection reset by peer",
        ] {
            assert_eq!(decorate_session_auth(raw), raw);
        }
    }
}

const NODE_NOT_FOUND_TIP_MARKER: &str = "tip: no node named";

/// Extract `<name>` from a `not found: node '<name>'` message, including one
/// wrapped in an anyhow context chain.
fn node_not_found_name(message: &str) -> Option<&str> {
    const NEEDLE: &str = "not found: node '";
    let start = message.rfind(NEEDLE)? + NEEDLE.len();
    let rest = &message[start..];
    let end = rest.find('\'')?;
    let name = &rest[..end];
    (!name.is_empty()).then_some(name)
}

/// Append an actionable tip when a node name or id does not resolve: list the
/// paired machines and copy the exact name (or id when names collide).
/// Idempotent. Offline nodes, grant/session failures, filesystem errors, and
/// errors already carrying `resolve_node`'s path/glob hint are left alone.
fn decorate_node_not_found(message: &str) -> String {
    if message.contains(NODE_NOT_FOUND_TIP_MARKER) {
        return message.to_string();
    }
    if message.contains("path or glob") {
        return message.to_string();
    }
    match node_not_found_name(message) {
        Some(name) => format!(
            "{message}. {NODE_NOT_FOUND_TIP_MARKER} '{name}' — list paired machines with \
             `agentlink nodes`; copy the exact id/name (use the id when names collide)"
        ),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod node_not_found_tip_tests {
    use super::*;

    #[test]
    fn not_found_node_gets_nodes_tip_once() {
        let out = decorate_node_not_found("not found: node 'foo'");
        assert_eq!(
            out,
            "not found: node 'foo'. tip: no node named 'foo' — list paired machines with \
             `agentlink nodes`; copy the exact id/name (use the id when names collide)"
        );
        assert_eq!(decorate_node_not_found(&out), out);
    }

    #[test]
    fn wrapped_not_found_node_uses_the_quoted_name() {
        let out = decorate_node_not_found("exec hostname: not found: node 'example-stale'");
        assert!(out.contains("tip: no node named 'example-stale'"), "{out}");
        assert_eq!(out.matches(NODE_NOT_FOUND_TIP_MARKER).count(), 1, "{out}");
    }

    #[test]
    fn path_or_glob_hint_is_left_alone() {
        for raw in [
            "not found: node '*.rs' (looks like a path or glob; put the machine name first — see `agentlink nodes`)",
            "not found: node 'new-node' (looks like a path or glob; put the machine name first — see `agentlink nodes`)",
        ] {
            assert_eq!(decorate_node_not_found(raw), raw);
        }
    }

    #[test]
    fn offline_grant_session_and_fs_errors_are_unchanged() {
        for raw in [
            "node offline: probe",
            "exec hostname: node offline: probe",
            "authentication failed: grant has expired",
            "authentication failed: session expired or revoked",
            "exec is not allowed on this node (read-only)",
            "Permission denied (os error 13)",
            "cp /tmp/a: No such file or directory",
            "not found: node ''",
            "not found: user 'foo'",
        ] {
            assert_eq!(decorate_node_not_found(raw), raw, "{raw}");
        }
    }
}

const AMBIGUOUS_NODE_TIP_MARKER: &str = "more than one paired machine is named";

/// Extract `<name>` from an `ambiguous node name '<name>'` message, including
/// one wrapped in an anyhow context chain (`ls: ambiguous node name 'devbox'`).
fn ambiguous_node_name(message: &str) -> Option<&str> {
    const NEEDLE: &str = "ambiguous node name '";
    let start = message.rfind(NEEDLE)? + NEEDLE.len();
    let rest = &message[start..];
    let end = rest.find('\'')?;
    let name = &rest[..end];
    (!name.is_empty()).then_some(name)
}

/// Append an actionable tip when a node name matches more than one paired
/// machine: fetch full ids with `agentlink nodes --json` and pass the id.
/// Idempotent. Messages that already point at `nodes --json` and unrelated
/// errors are left alone.
fn decorate_ambiguous_node(message: &str) -> String {
    if message.contains(AMBIGUOUS_NODE_TIP_MARKER) || message.contains("nodes --json") {
        return message.to_string();
    }
    match ambiguous_node_name(message) {
        Some(name) => format!(
            "{message}. tip: {AMBIGUOUS_NODE_TIP_MARKER} '{name}' — run `agentlink nodes \
             --json` and pass that machine's full `id` as <node> (the ID column in table \
             output is truncated), e.g. `agentlink ls <full-id> <dir>`; names must be unique \
             to use them directly"
        ),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod ambiguous_node_tip_tests {
    use super::*;

    #[test]
    fn ambiguous_node_gets_the_json_tip_once() {
        let out = decorate_ambiguous_node("ambiguous node name 'devbox'");
        assert_eq!(
            out,
            "ambiguous node name 'devbox'. tip: more than one paired machine is named 'devbox' \
             — run `agentlink nodes --json` and pass that machine's full `id` as <node> (the \
             ID column in table output is truncated), e.g. `agentlink ls <full-id> <dir>`; \
             names must be unique to use them directly"
        );
        assert_eq!(decorate_ambiguous_node(&out), out);
        assert_eq!(out.matches(AMBIGUOUS_NODE_TIP_MARKER).count(), 1, "{out}");
    }

    #[test]
    fn wrapped_ambiguous_uses_the_quoted_name() {
        for raw in [
            "ls: ambiguous node name 'devbox'",
            "exec hostname: ambiguous node name 'devbox'",
            "error: ls /srv: ambiguous node name 'devbox'",
        ] {
            let out = decorate_ambiguous_node(raw);
            assert!(
                out.contains("more than one paired machine is named 'devbox'"),
                "{raw} => {out}"
            );
            assert_eq!(decorate_ambiguous_node(&out), out, "{raw}");
        }
    }

    #[test]
    fn messages_already_pointing_at_nodes_json_are_left_alone() {
        let raw = "ambiguous node name 'devbox' (see `agentlink nodes --json` for full ids)";
        assert_eq!(decorate_ambiguous_node(raw), raw);
    }

    #[test]
    fn unrelated_and_empty_errors_are_unchanged() {
        for raw in [
            "not found: node 'foo'",
            "node offline: probe",
            "not found: /srv/app/src",
            "parent directory does not exist: /srv/app",
            "ls: path `/srv/app/src.txt` does not exist",
            "ambiguous node name ''",
            "ambiguous node name 'devbox",
            "authentication failed: grant has expired",
            "Permission denied (os error 13)",
        ] {
            assert_eq!(decorate_ambiguous_node(raw), raw, "{raw}");
        }
    }
}

const PATH_NOT_FOUND_TIP_MARKER: &str = "is a path on the node";

/// Extract the payload of the last `not found: ` message when it is a remote
/// filesystem path (absolute, `~/`, or a Windows drive). Quoted ids such as
/// `node 'foo'` and prose payloads such as `parent directory does not exist: …`
/// are not paths and yield `None`.
fn path_not_found_payload(message: &str) -> Option<&str> {
    const NEEDLE: &str = "not found: ";
    let start = message.rfind(NEEDLE)? + NEEDLE.len();
    let payload = message[start..].trim_end();
    if is_remote_path(payload) {
        Some(payload)
    } else {
        None
    }
}

fn is_remote_path(payload: &str) -> bool {
    if payload.starts_with('/') || payload.starts_with("~/") {
        return true;
    }
    let bytes = payload.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

/// Append an actionable tip when a remote filesystem path does not exist:
/// `agentlink ls` its parent, and remember PATH is a directory on the node,
/// not a machine name. Idempotent. Quoted ids, offline/grant/session errors,
/// PATH misses, edit mismatches, EACCES, search-regex failures, and prose
/// payloads such as `parent directory does not exist: …` are left alone.
fn decorate_path_not_found(message: &str) -> String {
    if message.contains(PATH_NOT_FOUND_TIP_MARKER) {
        return message.to_string();
    }
    match path_not_found_payload(message) {
        Some(path) => format!(
            "{message}. tip: '{path}' {PATH_NOT_FOUND_TIP_MARKER}, not a machine name — \
             list its parent with `agentlink ls <node> <dir>`; omit PATH to search the node's cwd"
        ),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod path_not_found_tip_tests {
    use super::*;

    #[test]
    fn absolute_path_gets_the_ls_tip_once() {
        let out = decorate_path_not_found("not found: /srv/app/src");
        assert_eq!(
            out,
            "not found: /srv/app/src. tip: '/srv/app/src' is a path on the node, not a machine \
             name — list its parent with `agentlink ls <node> <dir>`; omit PATH to search the \
             node's cwd"
        );
        assert_eq!(decorate_path_not_found(&out), out);
    }

    #[test]
    fn wrapped_search_root_uses_the_path() {
        let out = decorate_path_not_found("search /srv: not found: /srv/app/src");
        assert!(out.contains("tip: '/srv/app/src' is a path on the node"), "{out}");
        assert_eq!(out.matches(PATH_NOT_FOUND_TIP_MARKER).count(), 1, "{out}");
    }

    #[test]
    fn home_and_windows_drive_paths_get_the_tip() {
        for raw in ["not found: ~/app/src", "not found: C:\\Users\\me\\app"] {
            let out = decorate_path_not_found(raw);
            assert!(out.contains(PATH_NOT_FOUND_TIP_MARKER), "{raw} => {out}");
            assert_eq!(decorate_path_not_found(&out), out, "{raw}");
        }
    }

    #[test]
    fn quoted_ids_and_prose_payloads_are_unchanged() {
        for raw in [
            "not found: node 'foo'",
            "not found: user 'foo'",
            "not found: client 'abc'",
            "not found: parent directory does not exist: /srv/app",
            "not found: no existing ancestor for /srv/app",
            "not found: background process 7",
            "not found: watch 7",
        ] {
            assert_eq!(decorate_path_not_found(raw), raw, "{raw}");
        }
    }

    #[test]
    fn offline_grant_session_path_miss_edit_and_fs_errors_are_unchanged() {
        for raw in [
            "node offline: probe",
            "exec hostname: node offline: probe",
            "authentication failed: grant has expired",
            "exec is not allowed on this node (read-only)",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "old string was not found in /tmp/x",
            "Permission denied (os error 13)",
            "exec x: spawn: Permission denied (os error 13)",
            "regex parse error: unclosed group",
            "cp /tmp/a: No such file or directory",
        ] {
            assert_eq!(decorate_path_not_found(raw), raw, "{raw}");
        }
    }
}

const BG_PROCESS_NOT_FOUND_TIP_MARKER: &str = "no live background process has that id";

/// Extract `<id>` from a `not found: background process <id>` message, including
/// one wrapped in an anyhow context chain (`bg output box: not found: background
/// process d5c86dab`). Empty or non-hex tokens are rejected.
fn bg_process_not_found_id(message: &str) -> Option<&str> {
    const NEEDLE: &str = "not found: background process ";
    let start = message.rfind(NEEDLE)? + NEEDLE.len();
    let rest = &message[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(rest.len());
    let id = &rest[..end];
    looks_like_bg_process_id(id).then_some(id)
}

/// Append an actionable tip when a background process id is unknown: list the
/// node's processes and use the short ID (the `pid` from `bg start` is the OS
/// pid). Idempotent. Messages already pointing at `bg list`/`bg <node> list`
/// and unrelated not-found forms are left alone.
fn decorate_bg_process_not_found(message: &str) -> String {
    if message.contains(BG_PROCESS_NOT_FOUND_TIP_MARKER)
        || message.contains("bg <node> list")
        || message.contains("agentlink bg")
    {
        return message.to_string();
    }
    match bg_process_not_found_id(message) {
        Some(_) => format!(
            "{message}. tip: {BG_PROCESS_NOT_FOUND_TIP_MARKER} — run `agentlink bg <node> list` \
             (MCP `process_list`) and use the short ID column (the `pid` printed by `bg start` / \
             returned by `process_start` is the OS pid, not the id); ids are in-memory and \
             disappear when the node service restarts or after the ~30 min retention window"
        ),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod bg_process_not_found_tip_tests {
    use super::*;

    #[test]
    fn numeric_id_gets_the_bg_list_tip_once() {
        let out = decorate_bg_process_not_found("not found: background process 7");
        assert_eq!(
            out,
            "not found: background process 7. tip: no live background process has that id — run \
             `agentlink bg <node> list` (MCP `process_list`) and use the short ID column (the \
             `pid` printed by `bg start` / returned by `process_start` is the OS pid, not the \
             id); ids are in-memory and disappear when the node service restarts or after the \
             ~30 min retention window"
        );
        assert!(out.contains("process_list"), "{out}");
        assert!(out.contains("process_start"), "{out}");
        assert_eq!(decorate_bg_process_not_found(&out), out);
    }

    #[test]
    fn wrapped_hex_id_gets_the_tip_once() {
        let out =
            decorate_bg_process_not_found("bg output box: not found: background process d5c86dab");
        assert!(
            out.starts_with("bg output box: not found: background process d5c86dab. tip:"),
            "{out}"
        );
        assert!(out.contains(BG_PROCESS_NOT_FOUND_TIP_MARKER), "{out}");
        assert_eq!(
            out.matches(BG_PROCESS_NOT_FOUND_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_bg_process_not_found(&out), out);
    }

    #[test]
    fn other_not_found_forms_and_path_payloads_are_unchanged() {
        for raw in [
            "not found: watch 7",
            "not found: /srv/app/src",
            "not found: node 'foo'",
            "not found: user 'foo'",
            "not found: client 'abc'",
            "not found: background process ",
            "not found: background process  ",
            "not found: background process nothex",
            "not found: background process d5c86dab already says no live background process has that id",
            "not found: background process 7. tip: already mentions `bg <node> list`",
            "not found: background process 7 (see `agentlink bg`)",
        ] {
            assert_eq!(decorate_bg_process_not_found(raw), raw, "{raw}");
        }
    }

    #[test]
    fn ambiguous_missing_parent_ls_and_node_tips_are_not_disturbed() {
        for raw in [
            "ambiguous node name 'devbox'",
            "parent directory does not exist: /srv/app",
            "ls: path `/srv/app/src.txt` does not exist",
            "not found: node 'foo'",
        ] {
            assert_eq!(decorate_bg_process_not_found(raw), raw, "{raw}");
        }
    }
}

const BG_LIMIT_TIP_MARKER: &str = "background process slots are full";

/// Append an actionable tip when the node refuses a new background process
/// because its running-process cap (32) is reached. Idempotent and narrowly
/// matched so the watch cap and unrelated errors are left alone.
fn decorate_bg_process_limit(message: &str) -> String {
    if message.contains(BG_LIMIT_TIP_MARKER)
        || !(message.contains("already has") && message.contains("background process"))
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {BG_LIMIT_TIP_MARKER} — the node caps running background processes (32); \
         list them with `agentlink bg <node> list` (or MCP `process_list`), then stop ones you no \
         longer need with `agentlink bg <node> kill <id>` (or MCP `process_kill`); finished \
         processes are reaped on the next start, and for one-shot work prefer `agentlink exec \
         <node> …` (MCP `run_command`) over leaving a server running; see `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod bg_process_limit_tip_tests {
    use super::*;

    #[test]
    fn raw_limit_error_gets_the_tip_once() {
        let raw = "this node already has 32 background processes";
        let out = decorate_bg_process_limit(raw);
        assert_eq!(
            out,
            "this node already has 32 background processes. tip: background process slots are \
             full — the node caps running background processes (32); list them with `agentlink bg \
             <node> list` (or MCP `process_list`), then stop ones you no longer need with \
             `agentlink bg <node> kill <id>` (or MCP `process_kill`); finished processes are \
             reaped on the next start, and for one-shot work prefer `agentlink exec <node> …` \
             (MCP `run_command`) over leaving a server running; see `agentlink guide <node>`."
        );
        assert_eq!(decorate_bg_process_limit(&out), out);
    }

    #[test]
    fn wrapped_limit_error_gets_the_tip_once() {
        let out =
            decorate_bg_process_limit("bg start: this node already has 32 background processes");
        assert!(
            out.starts_with("bg start: this node already has 32 background processes. tip: "),
            "{out}"
        );
        assert!(out.contains(BG_LIMIT_TIP_MARKER), "{out}");
        assert_eq!(out.matches(BG_LIMIT_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_bg_process_limit(&out), out);
    }

    #[test]
    fn already_tipped_message_is_unchanged() {
        let tipped = decorate_bg_process_limit("this node already has 32 background processes");
        assert_eq!(decorate_bg_process_limit(&tipped), tipped);
    }

    #[test]
    fn not_found_and_unrelated_are_unchanged() {
        for raw in [
            "not found: background process 7",
            "node offline",
            "request timed out",
            "permission denied",
        ] {
            assert_eq!(decorate_bg_process_limit(raw), raw, "{raw}");
        }
    }
}

const BG_START_EXEC_DENIED_TIP_MARKER: &str =
    "the background program was denied execute permission on the node";

const BG_START_EXEC_DENIED_FORMS: &[&str] = &[
    "spawn: Permission denied (os error 13)",
    "spawn: Access is denied. (os error 5)",
];

/// Whole-message equality only: `spawn:` is also produced by `exec` (which has
/// its own EACCES tip) and `pty spawn:` (node-chosen shell), and wrapped forms
/// carry context this tip cannot attribute to the caller's program.
fn is_bg_start_exec_denied_error(message: &str) -> bool {
    BG_START_EXEC_DENIED_FORMS.contains(&message.trim_end())
}

/// Append an actionable tip when CLI `bg start` / MCP `process_start` fails to
/// spawn the caller's program with EACCES. The raw line names neither the
/// program nor a path, so the caller's `node`/`program` are interpolated here.
/// Wired only at those two bg sites: `decorate_exec_eacces` matches the same
/// raw line and must not stack on top, and the flat `tool_err` chain must keep
/// it raw for `exec`/`pty spawn:`. When the caller passed `cwd`, the same line
/// is also indistinguishable from an unenterable working directory, so a
/// directory-first differential is inserted; without `cwd` the text is
/// unchanged. Idempotent.
fn decorate_bg_start_exec_denied(
    message: &str,
    node: &str,
    program: &str,
    cwd: Option<&str>,
) -> String {
    if message.contains(BG_START_EXEC_DENIED_TIP_MARKER) || !is_bg_start_exec_denied_error(message)
    {
        return message.to_string();
    }
    let cwd_clause = cwd
        .filter(|dir| !dir.is_empty())
        .map(|dir| {
            format!(
                "If you passed a `cwd` (`{dir}`), this same line also appears when `{dir}` exists \
                 but cannot be entered — missing search (`x`) on the directory itself, or (on \
                 Windows) an ACL denying traverse — because the node only stats `{dir}` before \
                 spawning and the kernel then refuses the chdir; `{program}`'s mode is not \
                 necessarily at fault. Check the directory first: MCP `stat_path` (its `mode` needs \
                 `x`) or `run_command stat -c '%A %n' {dir}`; if it lacks search, add it on the \
                 directory (`chmod a+x {dir}`, or a `setfacl` entry). `--shell sh <path>` cannot \
                 bypass this, because the shell spawn needs the same directory. "
            )
        })
        .unwrap_or_default();
    format!(
        "{message}. tip: {BG_START_EXEC_DENIED_TIP_MARKER} — `bg start` (CLI) / MCP \
         `process_start` asked `{node}` to execute `{program}`, and the spawn was refused before \
         any process existed. The raw line names neither the program nor a path: `{program}` is \
         the value you passed (a bare name is resolved like any command, a relative path against \
         the node cwd or `--root` jail, and `~` is not expanded without a shell). The usual cause \
         is a missing execute bit: `write`/`write_file` creates `0644` and `cp` preserves the \
         source mode, so a script that was just written or copied is not executable. Check it \
         with MCP `stat_path` (decimal `mode`) or `run_command stat -c '%A %n' <path>` (`ls -l` \
         also works), then add the bit with `chmod a+x <path>` through `run_command` / \
         `agentlink exec <node> -- …` and retry. Second, `{program}` may point at a directory \
         rather than a file — a directory is not executable, so pick the file inside it. Third, \
         the filesystem may be mounted `noexec`: the mode can be `-rwxr-xr-x` and the spawn still \
         fails. Check `findmnt -T <path> -o TARGET,OPTIONS` (or `mount`) for `noexec`; either \
         copy the program to an executable filesystem or run it through an interpreter, which \
         needs only read access: `agentlink bg start <node> --shell sh <path>` / MCP \
         `process_start` with `argv: [\"sh\", \"<path>\"]` (or `command: \"sh <path>\"`). A chmod \
         cannot fix a `noexec` mount. For a script, the kernel also execs the `#!` interpreter, \
         so a non-executable or `noexec` interpreter gives this same line even when the script \
         itself is `0755`: check the interpreter path from its first line too. On Windows there \
         is no execute bit, so `Access is denied.` usually means an ACL denying execute, \
         AppLocker/AV/SmartScreen, or a blocked location: inspect with `icacls <path>`; move it \
         to a trusted directory or ask the operator. {cwd_clause}In all cases nothing was \
         started, no background id was allocated, and `bg list` (CLI) / `process_list` (MCP) \
         shows no new entry; retrying unchanged fails identically. This is not a missing program \
         (the not-found form quotes the program and has its own tip), not a bad executable format \
         (its own tip covers that), not a missing `cwd`, not the command-policy refusal, not a \
         rejected env var, not the background-slot cap, and not a \
         grant/sandbox/approval/node-offline failure. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod bg_start_exec_denied_tip_tests {
    use super::*;

    const UNIX: &str = "spawn: Permission denied (os error 13)";
    const WINDOWS: &str = "spawn: Access is denied. (os error 5)";

    #[test]
    fn unix_eacces_gets_the_tip_once() {
        let out = decorate_bg_start_exec_denied(UNIX, "box", "/tmp/run.sh", None);
        assert!(
            out.starts_with(&format!(
                "{UNIX}. tip: {BG_START_EXEC_DENIED_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(BG_START_EXEC_DENIED_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "box",
            "/tmp/run.sh",
            "execute bit",
            "noexec",
            "findmnt",
            "interpreter",
            "directory",
            "nothing was started",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        for literal in ["{node}", "{program}"] {
            assert!(!out.contains(literal), "{literal} literal left: {out}");
        }
        assert_eq!(
            decorate_bg_start_exec_denied(&out, "box", "/tmp/run.sh", None),
            out
        );
    }

    #[test]
    fn windows_form_gets_the_tip() {
        let out = decorate_bg_start_exec_denied(WINDOWS, "box", "C:\\tools\\run.exe", None);
        assert!(out.contains(BG_START_EXEC_DENIED_TIP_MARKER), "{out}");
        assert_eq!(
            out.matches(BG_START_EXEC_DENIED_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("icacls"), "{out}");
        assert_eq!(
            decorate_bg_start_exec_denied(&out, "box", "C:\\tools\\run.exe", None),
            out
        );
    }

    #[test]
    fn exact_whole_message_only() {
        for raw in [
            "spawn: Permission denied (os error 13) extra",
            "exec x: spawn: Permission denied (os error 13)",
            "pty spawn: Permission denied (os error 13)",
            "io: Permission denied (os error 13)",
            "Permission denied (os error 13)",
            "spawn: Operation not permitted (os error 1)",
            "spawn: Input/output error (os error 5)",
            "spawn: No such file or directory (os error 2)",
            "program '/tmp/x' not found (No such file or directory (os error 2))",
            "spawn: Exec format error (os error 8)",
            "this node already has 32 background processes",
            "rejected env var 'X'",
            "the node's command policy denied this",
            "",
        ] {
            assert_eq!(
                decorate_bg_start_exec_denied(raw, "box", "/tmp/run.sh", None),
                raw,
                "{raw}"
            );
            assert_eq!(
                decorate_bg_start_exec_denied(raw, "box", "/tmp/run.sh", Some("/srv/work")),
                raw,
                "{raw}"
            );
        }
        // A transport-added trailing newline still matches via `trim_end`.
        let out = decorate_bg_start_exec_denied(&format!("{UNIX}\n"), "box", "/tmp/run.sh", None);
        assert!(out.contains(BG_START_EXEC_DENIED_TIP_MARKER), "{out}");
    }

    #[test]
    fn already_tipped_and_siblings_are_noops() {
        let tipped = decorate_bg_start_exec_denied(UNIX, "box", "/tmp/run.sh", None);
        assert_eq!(decorate_exec_enoexec(&tipped), tipped);
        assert_eq!(decorate_exec_cwd_missing(&tipped), tipped);
        assert_eq!(decorate_bg_process_limit(&tipped), tipped);
        assert_eq!(decorate_bg_process_not_found(&tipped), tipped);
        assert_eq!(
            decorate_mkdir_dest_permission(&tipped, "box", "/tmp", false),
            tipped
        );
        assert_eq!(
            decorate_remove_dest_permission(&tipped, "box", "/tmp", false),
            tipped
        );
        assert_eq!(
            decorate_write_dest_permission(&tipped, "box", "/tmp"),
            tipped
        );
        assert_eq!(
            decorate_mv_dest_permission(&tipped, "box", "/tmp/a", "/tmp/b"),
            tipped
        );
    }

    #[test]
    fn hint_bg_start_exec_denied_adds_the_tip() {
        let out =
            hint_bg_start_exec_denied(UNIX, "box", "/tmp/run.sh", Some("/srv/work")).to_string();
        assert!(out.starts_with(UNIX), "{out}");
        assert_eq!(
            out.matches(BG_START_EXEC_DENIED_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("/srv/work"), "{out}");

        let cwd = "cwd /tmp/missing: No such file or directory (os error 2)";
        let out = hint_bg_start_exec_denied(cwd, "box", "/tmp/run.sh", None).to_string();
        assert!(!out.contains(BG_START_EXEC_DENIED_TIP_MARKER), "{out}");
    }

    #[test]
    fn cwd_hedge_names_the_directory() {
        let out = decorate_bg_start_exec_denied(UNIX, "box", "/tmp/run.sh", Some("/srv/work"));
        for needle in ["/srv/work", "stat_path", "search", "cannot be entered"] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        assert_eq!(
            out.matches(BG_START_EXEC_DENIED_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for literal in ["{dir}", "{cwd}"] {
            assert!(!out.contains(literal), "{literal} literal left: {out}");
        }
        assert_eq!(
            decorate_bg_start_exec_denied(&out, "box", "/tmp/run.sh", Some("/srv/work")),
            out
        );
        assert_eq!(
            decorate_bg_start_exec_denied(&out, "box", "/tmp/run.sh", None),
            out
        );

        let win =
            decorate_bg_start_exec_denied(WINDOWS, "box", "C:\\tools\\run.exe", Some(r"C:\work"));
        assert!(win.contains("icacls"), "{win}");
        assert!(win.contains(r"C:\work"), "{win}");
    }

    #[test]
    fn cwd_hedge_stays_out_of_cwd_frames() {
        let out = decorate_bg_start_exec_denied(UNIX, "box", "/tmp/run.sh", Some("/srv/work"));
        assert_eq!(decorate_exec_cwd_permission(&out), out);
        assert_eq!(decorate_exec_cwd_missing(&out), out);
        assert_eq!(decorate_missing_parent(&out), out);
        assert_eq!(decorate_exec_eacces(&out, Some("/srv/work")), out);
    }
}

const WATCH_LIMIT_TIP_MARKER: &str = "watch slots are full";

/// Append an actionable tip when the node refuses a new watch because its
/// live-watch cap (32) is reached. Idempotent and narrowly matched so the
/// background-process cap and unrelated errors are left alone.
fn decorate_watch_limit(message: &str) -> String {
    if message.contains(WATCH_LIMIT_TIP_MARKER)
        || !(message.contains("already has") && message.contains("watches"))
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {WATCH_LIMIT_TIP_MARKER} — the node caps live watches at 32; stop ones \
         you no longer need with MCP `watch_stop` (CLI `agentlink watch` releases its slot when it \
         exits), reuse a single watch instead of opening one per path, and idle watches are reaped \
         after ~30 min on the next `watch_start`; see `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod watch_limit_tip_tests {
    use super::*;

    #[test]
    fn raw_limit_error_gets_the_tip_once() {
        let raw = "this node already has 32 watches";
        let out = decorate_watch_limit(raw);
        assert_eq!(
            out,
            "this node already has 32 watches. tip: watch slots are full — the node caps live \
             watches at 32; stop ones you no longer need with MCP `watch_stop` (CLI `agentlink \
             watch` releases its slot when it exits), reuse a single watch instead of opening one \
             per path, and idle watches are reaped after ~30 min on the next `watch_start`; see \
             `agentlink guide <node>`."
        );
        assert_eq!(decorate_watch_limit(&out), out);
        assert_eq!(decorate_bg_process_limit(raw), raw);
    }

    #[test]
    fn wrapped_limit_error_gets_the_tip_once() {
        let out = decorate_watch_limit("watch_start: this node already has 32 watches");
        assert!(
            out.starts_with("watch_start: this node already has 32 watches. tip: "),
            "{out}"
        );
        assert!(out.contains(WATCH_LIMIT_TIP_MARKER), "{out}");
        assert_eq!(out.matches(WATCH_LIMIT_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_watch_limit(&out), out);
    }

    #[test]
    fn already_tipped_message_is_unchanged() {
        let tipped = decorate_watch_limit("this node already has 32 watches");
        assert_eq!(decorate_watch_limit(&tipped), tipped);
    }

    #[test]
    fn bg_limit_not_found_and_unrelated_are_unchanged() {
        for raw in [
            "this node already has 32 background processes",
            "not found: watch 7a3f0c2e",
            "node offline",
            "request timed out",
            "permission denied",
        ] {
            assert_eq!(decorate_watch_limit(raw), raw, "{raw}");
        }
    }
}

const WATCH_NOT_FOUND_TIP_MARKER: &str = "no live watch has that id";

/// Extract `<id>` from a `not found: watch <id>` message, including one wrapped
/// in an anyhow context chain. Watch ids are 8 hex chars (`util::random_hex(4)`);
/// short numeric forms are accepted too, mirroring the bg-process extractor.
fn watch_not_found_id(message: &str) -> Option<&str> {
    const NEEDLE: &str = "not found: watch ";
    let start = message.rfind(NEEDLE)? + NEEDLE.len();
    let rest = &message[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(rest.len());
    let id = &rest[..end];
    (!id.is_empty() && id.len() <= 16).then_some(id)
}

/// Append an actionable tip when a watch id is unknown: open a new watch and
/// keep the id it returns. Idempotent. Messages already carrying the marker or
/// pointing at `watch_start` are left alone.
fn decorate_watch_not_found(message: &str) -> String {
    if message.contains(WATCH_NOT_FOUND_TIP_MARKER) || message.contains("watch_start") {
        return message.to_string();
    }
    match watch_not_found_id(message) {
        Some(_) => format!(
            "{message}. tip: {WATCH_NOT_FOUND_TIP_MARKER} — run `agentlink watch <node> <path>` \
             (or MCP `watch_start`) to open a new watch and keep the 8-char hex `watch_id` it \
             returns; ids are per-node and in-memory, and disappear after `watch_stop`, a node \
             service restart, or ~30 min idle"
        ),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod watch_not_found_tip_tests {
    use super::*;

    #[test]
    fn hex_id_gets_the_tip_once() {
        let out = decorate_watch_not_found("not found: watch 7a3f0c2e");
        assert_eq!(
            out,
            "not found: watch 7a3f0c2e. tip: no live watch has that id — run `agentlink watch \
             <node> <path>` (or MCP `watch_start`) to open a new watch and keep the 8-char hex \
             `watch_id` it returns; ids are per-node and in-memory, and disappear after \
             `watch_stop`, a node service restart, or ~30 min idle"
        );
        assert_eq!(decorate_watch_not_found(&out), out);
    }

    #[test]
    fn short_numeric_id_and_wrapped_message_get_the_tip_once() {
        let out = decorate_watch_not_found("watch poll: not found: watch 7");
        assert!(
            out.starts_with("watch poll: not found: watch 7. tip:"),
            "{out}"
        );
        assert!(out.contains("`agentlink watch <node> <path>`"), "{out}");
        assert_eq!(out.matches(WATCH_NOT_FOUND_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_watch_not_found(&out), out);
    }

    #[test]
    fn other_not_found_forms_and_path_payloads_are_unchanged() {
        for raw in [
            "not found: background process 7",
            "not found: /srv/app/src",
            "not found: node 'foo'",
            "not found: user 'foo'",
            "not found: client 'abc'",
            "not found: watch ",
            "not found: watch /srv/app",
            "not found: watch 7a3f0c2e already says no live watch has that id",
            "not found: watch 7. tip: use `watch_start` to open a new watch",
        ] {
            assert_eq!(decorate_watch_not_found(raw), raw, "{raw}");
        }
    }

    #[test]
    fn unrelated_tips_are_not_disturbed() {
        for raw in [
            "ambiguous node name 'devbox'",
            "parent directory does not exist: /srv/app",
            "ls: path `/srv/app/src.txt` does not exist",
            "not found: background process d5c86dab",
        ] {
            assert_eq!(decorate_watch_not_found(raw), raw, "{raw}");
        }
    }
}

const WATCH_INOTIFY_LIMIT_TIP_MARKER: &str = "the OS inotify watch limit was hit";

/// Append an actionable tip when the kernel's inotify watch budget is
/// exhausted. Matches both `watch <path>: inotify watch limit reached` and the
/// generic `watch <root>: OS file watch limit reached.` form (case-insensitive),
/// so wrappers match too. Idempotent, and narrowly matched so the node's
/// per-node watch cap, unknown watch ids, and unrelated errors are left alone.
fn decorate_watch_inotify_limit(message: &str) -> String {
    if message.contains(WATCH_INOTIFY_LIMIT_TIP_MARKER)
        || !message.to_ascii_lowercase().contains("watch limit reached")
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {WATCH_INOTIFY_LIMIT_TIP_MARKER} — the kernel's \
         fs.inotify.max_user_watches is exhausted on that machine; watch a narrower subtree \
         (exclude node_modules, target, .git) or raise the limit (sudo sysctl \
         fs.inotify.max_user_watches=524288); see `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod watch_inotify_limit_tip_tests {
    use super::*;

    #[test]
    fn inotify_needle_gets_the_tip_once() {
        let raw = "watch /srv/app: inotify watch limit reached";
        let out = decorate_watch_inotify_limit(raw);
        assert_eq!(
            out,
            "watch /srv/app: inotify watch limit reached. tip: the OS inotify watch limit was hit \
             — the kernel's fs.inotify.max_user_watches is exhausted on that machine; watch a \
             narrower subtree (exclude node_modules, target, .git) or raise the limit (sudo \
             sysctl fs.inotify.max_user_watches=524288); see `agentlink guide <node>`."
        );
        assert_eq!(decorate_watch_inotify_limit(&out), out);
    }

    #[test]
    fn os_file_needle_gets_the_tip_once() {
        let out = decorate_watch_inotify_limit("watch /srv/app: OS file watch limit reached.");
        assert!(out.contains(WATCH_INOTIFY_LIMIT_TIP_MARKER), "{out}");
        assert_eq!(
            out.matches(WATCH_INOTIFY_LIMIT_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_watch_inotify_limit(&out), out);
    }

    #[test]
    fn wrapped_inotify_message_gets_the_tip_once() {
        let out = decorate_watch_inotify_limit(
            "watch_start: watch /srv/app: inotify watch limit reached",
        );
        assert!(
            out.starts_with("watch_start: watch /srv/app: inotify watch limit reached. tip: "),
            "{out}"
        );
        assert!(out.contains(WATCH_INOTIFY_LIMIT_TIP_MARKER), "{out}");
        assert!(
            out.contains("sudo sysctl fs.inotify.max_user_watches=524288"),
            "{out}"
        );
        assert!(out.contains("agentlink guide <node>"), "{out}");
        assert_eq!(
            out.matches(WATCH_INOTIFY_LIMIT_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_watch_inotify_limit(&out), out);
    }

    #[test]
    fn case_insensitive_match_and_already_tipped_is_unchanged() {
        let out = decorate_watch_inotify_limit("watch /srv/app: OS FILE WATCH LIMIT REACHED");
        assert!(out.contains(WATCH_INOTIFY_LIMIT_TIP_MARKER), "{out}");
        assert_eq!(decorate_watch_inotify_limit(&out), out);
    }

    #[test]
    fn other_limits_not_found_and_unrelated_are_unchanged() {
        for raw in [
            "this node already has 32 watches",
            "not found: watch 7",
            "not found: watch 7a3f0c2e",
            "this node already has 32 background processes",
            "node offline",
            "request timed out",
            "permission denied",
        ] {
            assert_eq!(decorate_watch_inotify_limit(raw), raw, "{raw}");
        }
    }
}

const WATCH_TARGET_MISSING_TIP_MARKER: &str = "the watch target does not exist on the node";

/// Tail after the last `<...>watch <path>: ` frame. Occurrences of `watch `
/// that are not followed by a `: ` separator are skipped, so rust's
/// "You attempted to watch a single file, ..." wording still finds the real
/// frame.
fn watch_target_missing_tail(message: &str) -> Option<&str> {
    let mut end = message.len();
    loop {
        let idx = message[..end].rfind("watch ")?;
        let rest = &message[idx + "watch ".len()..];
        if let Some(sep) = rest.find(": ") {
            return Some(&rest[sep + 2..]);
        }
        end = idx;
        if end == 0 {
            return None;
        }
    }
}

/// Append an actionable tip when a watch fails because the target path is not
/// present on the node. Covers Linux ENOENT, macOS/Windows `No path was
/// found`, and the Windows single-file form where the parent directory cannot
/// be opened. Idempotent, and narrowly matched so limit, permission,
/// unknown-id, and PATH-miss errors are left alone.
fn decorate_watch_target_missing(message: &str) -> String {
    if message.contains(WATCH_TARGET_MISSING_TIP_MARKER) {
        return message.to_string();
    }
    let Some(tail) = watch_target_missing_tail(message) else {
        return message.to_string();
    };
    if !(looks_like_enoent_message(tail)
        || tail.contains("No path was found")
        || tail.contains("parent directory could not be opened"))
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {WATCH_TARGET_MISSING_TIP_MARKER} — watch_start only reports changes \
         after it registers, so it cannot create or follow a path that is not there yet; create it \
         first (`agentlink mkdir -p <node> <dir>` / MCP `mkdir`, or `write_file` for a file) or \
         watch the nearest existing parent (a parent watch still reports child \
         create/modify/remove); relative paths resolve against the node's cwd, and `~` is not \
         expanded."
    )
}

#[cfg(test)]
mod watch_target_missing_tip_tests {
    use super::*;

    #[test]
    fn linux_enoent_gets_the_tip_once() {
        let raw = "watch /srv/app: No such file or directory (os error 2)";
        let out = decorate_watch_target_missing(raw);
        assert_eq!(
            out,
            "watch /srv/app: No such file or directory (os error 2). tip: the watch target does \
             not exist on the node — watch_start only reports changes after it registers, so it \
             cannot create or follow a path that is not there yet; create it first (`agentlink \
             mkdir -p <node> <dir>` / MCP `mkdir`, or `write_file` for a file) or watch the \
             nearest existing parent (a parent watch still reports child create/modify/remove); \
             relative paths resolve against the node's cwd, and `~` is not expanded."
        );
        assert_eq!(decorate_watch_target_missing(&out), out);
    }

    #[test]
    fn macos_and_windows_no_path_was_found_get_the_tip_once() {
        for raw in [
            r#"watch /srv/app: No path was found. about ["/srv/app"]"#,
            r#"watch C:\Users\me\app: No path was found. about ["C:\\Users\\me\\app"]"#,
        ] {
            let out = decorate_watch_target_missing(raw);
            assert!(out.starts_with(raw), "{out}");
            assert!(out.contains(WATCH_TARGET_MISSING_TIP_MARKER), "{out}");
            assert_eq!(
                out.matches(WATCH_TARGET_MISSING_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(decorate_watch_target_missing(&out), out);
        }
    }

    #[test]
    fn windows_single_file_parent_form_gets_the_tip_once() {
        let raw = r#"watch C:\Users\me\out.log: You attempted to watch a single file, but parent directory could not be opened. about ["C:\\Users\\me\\out.log"]"#;
        let out = decorate_watch_target_missing(raw);
        assert!(out.starts_with(raw), "{out}");
        assert!(out.contains(WATCH_TARGET_MISSING_TIP_MARKER), "{out}");
        assert!(out.contains("`~` is not expanded"), "{out}");
        assert_eq!(
            out.matches(WATCH_TARGET_MISSING_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_watch_target_missing(&out), out);
    }

    #[test]
    fn wrapped_message_gets_the_tip_once() {
        let out = decorate_watch_target_missing(
            "watch_start: watch /srv/app: No such file or directory (os error 2)",
        );
        assert!(
            out.starts_with(
                "watch_start: watch /srv/app: No such file or directory (os error 2). tip: "
            ),
            "{out}"
        );
        assert!(out.contains("agentlink mkdir -p <node> <dir>"), "{out}");
        assert!(out.contains("nearest existing parent"), "{out}");
        assert_eq!(decorate_watch_target_missing(&out), out);
    }

    #[test]
    fn already_tipped_message_is_unchanged() {
        let tipped = decorate_watch_target_missing(
            "watch /srv/app: No such file or directory (os error 2)",
        );
        assert_eq!(decorate_watch_target_missing(&tipped), tipped);
    }

    #[test]
    fn limits_unknown_ids_permissions_and_path_misses_are_unchanged() {
        for raw in [
            "watch /srv/app: inotify watch limit reached",
            "watch /srv/app: OS file watch limit reached",
            "this node already has 32 watches",
            "not found: watch 7a3f0c2e",
            "watch /srv/app: Permission denied (os error 13)",
            "program 'watch' not found on PATH (No such file or directory (os error 2))",
        ] {
            assert_eq!(decorate_watch_target_missing(raw), raw, "{raw}");
        }
    }
}

const PTY_SESSION_NOT_FOUND_TIP_MARKER: &str = "no live terminal has that session id";

/// Extract `<id>` from a `not found: pty session <id>` or `unknown terminal <id>`
/// message, including one wrapped in an anyhow context chain. Session ids are
/// hyphenated UUIDs; malformed and non-UUID ids deliberately stay raw.
fn pty_session_not_found_id(message: &str) -> Option<&str> {
    const NEEDLES: [&str; 2] = ["not found: pty session ", "unknown terminal "];
    for needle in NEEDLES {
        let Some(pos) = message.rfind(needle) else {
            continue;
        };
        let rest = &message[pos + needle.len()..];
        let end = rest
            .find(|c: char| !(c.is_ascii_hexdigit() || c == '-'))
            .unwrap_or(rest.len());
        let id = &rest[..end];
        if id.len() == 36 && uuid::Uuid::parse_str(id).is_ok() {
            return Some(id);
        }
    }
    None
}

/// Append an actionable tip when a terminal/pty session id is unknown: open a
/// fresh session and keep the id it returns. Idempotent. Messages already
/// carrying the marker or pointing at `terminal_open` / `agentlink shell` are
/// left alone.
fn decorate_pty_session_not_found(message: &str) -> String {
    if message.contains(PTY_SESSION_NOT_FOUND_TIP_MARKER)
        || message.contains("terminal_open")
        || message.contains("agentlink shell")
    {
        return message.to_string();
    }
    match pty_session_not_found_id(message) {
        Some(_) => format!(
            "{message}. tip: {PTY_SESSION_NOT_FOUND_TIP_MARKER} — open a fresh session with MCP \
             `terminal_open` (or CLI `agentlink shell <node>`) and use the `session_id` it returns; \
             ids are per-node and in-memory, and disappear when the child process exits, the node \
             service restarts, or the MCP client reconnects"
        ),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod pty_session_not_found_tip_tests {
    use super::*;

    #[test]
    fn uuid_id_gets_the_tip_once() {
        let out = decorate_pty_session_not_found(
            "not found: pty session 3f2a9d1c-8b47-4e6a-9f10-52c7d8e0b1a3",
        );
        assert_eq!(
            out,
            "not found: pty session 3f2a9d1c-8b47-4e6a-9f10-52c7d8e0b1a3. tip: no live terminal \
             has that session id — open a fresh session with MCP `terminal_open` (or CLI \
             `agentlink shell <node>`) and use the `session_id` it returns; ids are per-node and \
             in-memory, and disappear when the child process exits, the node service restarts, or \
             the MCP client reconnects"
        );
        assert_eq!(decorate_pty_session_not_found(&out), out);
    }

    #[test]
    fn unknown_terminal_form_gets_the_tip_once() {
        let out = decorate_pty_session_not_found("unknown terminal 0f9e8d7c-6b5a-4c3b-2a19-87654321abcd");
        assert!(
            out.starts_with("unknown terminal 0f9e8d7c-6b5a-4c3b-2a19-87654321abcd. tip:"),
            "{out}"
        );
        assert!(out.contains("`terminal_open`"), "{out}");
        assert!(out.contains("`agentlink shell <node>`"), "{out}");
        assert_eq!(
            out.matches(PTY_SESSION_NOT_FOUND_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_pty_session_not_found(&out), out);
    }

    #[test]
    fn wrapped_message_gets_the_tip_once() {
        let out = decorate_pty_session_not_found(
            "terminal resize: not found: pty session 3f2a9d1c-8b47-4e6a-9f10-52c7d8e0b1a3",
        );
        assert!(
            out.starts_with(
                "terminal resize: not found: pty session \
                 3f2a9d1c-8b47-4e6a-9f10-52c7d8e0b1a3. tip:"
            ),
            "{out}"
        );
        assert!(out.contains(PTY_SESSION_NOT_FOUND_TIP_MARKER), "{out}");
        assert_eq!(
            out.matches(PTY_SESSION_NOT_FOUND_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_pty_session_not_found(&out), out);
    }

    #[test]
    fn messages_pointing_at_the_fix_are_left_alone() {
        for raw in [
            "unknown terminal 0f9e8d7c-6b5a-4c3b-2a19-87654321abcd. tip: use terminal_open",
            "not found: pty session 3f2a9d1c-8b47-4e6a-9f10-52c7d8e0b1a3 already says no live \
             terminal has that session id",
            "not found: pty session 3f2a9d1c-8b47-4e6a-9f10-52c7d8e0b1a3 (run `agentlink shell \
             <node>`)",
        ] {
            assert_eq!(decorate_pty_session_not_found(raw), raw, "{raw}");
        }
    }

    #[test]
    fn other_not_found_forms_and_unrelated_tips_are_unchanged() {
        for raw in [
            "not found: watch 7a3f0c2e",
            "not found: background process d5c86dab",
            "not found: pty session ",
            "not found: pty session /dev/pts/3",
            "not found: pty session ------------------------------------",
            "unknown terminal",
            "unknown terminal ",
            "unknown terminal abc",
            "unknown terminal deadbeef",
            "unknown terminal 0f9e8d7c6b5a4c3b2a1987654321abcd",
            "unknown terminal 0f9e8d7c-6b5a-4c3b-2a19-87654321abcg",
            "unknown terminal /dev/pts/3",
            "ambiguous node name 'devbox'",
            "not found: node 'foo'",
            "ls: path `/srv/app/src.txt` does not exist",
        ] {
            assert_eq!(decorate_pty_session_not_found(raw), raw, "{raw}");
        }
    }
}

const TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER: &str =
    "terminal_write needs UTF-8 data or data_base64";

const TERMINAL_WRITE_NEEDS_DATA_RAW: &str = "terminal_write needs `data` or `data_base64`";

/// MCP `terminal_write` emits this exact message when neither input field is
/// a JSON string. Match the whole trimmed message so wrapped errors, invalid
/// base64, and terminal lookup failures stay distinct.
fn is_terminal_write_needs_data_error(message: &str) -> bool {
    message.trim() == TERMINAL_WRITE_NEEDS_DATA_RAW
}

/// Explain the two input encodings and that validation happened before the
/// terminal lookup or write. Empty strings are valid and do not produce this
/// error. Idempotent; unrelated errors are left alone.
fn decorate_terminal_write_needs_data(message: &str) -> String {
    if message.contains(TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER)
        || !is_terminal_write_needs_data_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER} — MCP `terminal_write` accepts \
         input in one of two JSON string fields: `data` for UTF-8 text (for example `\"data\": \
         \"ls\\n\"`), or `data_base64` for standard base64 of arbitrary bytes (for example \
         `\"data_base64\": \"bHMK\"`, which also decodes to `ls\\n`). If both are strings, \
         `data` takes precedence. An empty string is valid and writes zero bytes; it is not \
         this error. This form means neither field was a string: both may be absent, and numbers, \
         booleans, arrays, objects, or `null` are not accepted. Validation and decoding happen \
         before the terminal lookup or write, so no bytes were written and retrying unchanged \
         fails identically. This is input validation, not a permission, node-offline, or timeout \
         failure. A malformed string in `data_base64` instead reports `data_base64: ...`; valid \
         input with an expired or unknown id reports `unknown terminal ...`. Check the tool's \
         inputSchema via `tools/list`. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod terminal_write_needs_data_tip_tests {
    use super::*;

    #[test]
    fn terminal_write_needs_data_gets_the_tip_once() {
        for raw in [
            TERMINAL_WRITE_NEEDS_DATA_RAW,
            "  terminal_write needs `data` or `data_base64`\n",
        ] {
            let out = decorate_terminal_write_needs_data(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(
                out.matches(TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "`data`",
                "`data_base64`",
                "UTF-8",
                "standard base64",
                "`\"data\": \"ls\\n\"`",
                "`\"data_base64\": \"bHMK\"`",
                "takes precedence",
                "empty string is valid",
                "writes zero bytes",
                "`null`",
                "before the terminal lookup or write",
                "no bytes were written",
                "data_base64: ...",
                "unknown terminal ...",
                "inputSchema",
                "tools/list",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_terminal_write_needs_data(&out), out);
        }
    }

    #[test]
    fn terminal_write_needs_data_leaves_siblings_alone() {
        for raw in [
            "terminal_write: terminal_write needs `data` or `data_base64`",
            "write_file needs `content` or `content_base64`",
            "data_base64: Invalid symbol 33, offset 0.",
            "content_base64: Invalid symbol 33, offset 0.",
            "unknown terminal abc",
            "not found: pty session 3f2a9d1c-8b47-4e6a-9f10-52c7d8e0b1a3",
            "stat_path: No such file or directory (os error 2)",
            "missing `session_id`",
        ] {
            assert_eq!(decorate_terminal_write_needs_data(raw), raw, "{raw}");
        }
    }
}

const DATA_BASE64_TIP_MARKER: &str = "`data_base64` must be standard base64";

/// MCP `terminal_write` prefixes the base64 crate's complaint with the field
/// name. Match only that unwrapped prefix and require an actual complaint;
/// `content_base64` and the missing-input error are separate cases.
fn is_data_base64_error(message: &str) -> bool {
    message
        .trim_start()
        .strip_prefix("data_base64:")
        .is_some_and(|error| !error.trim().is_empty())
}

/// Explain the exact encoding accepted by `terminal_write`, including required
/// padding and outer-whitespace handling. Decoding fails before terminal
/// lookup, so no bytes can have been written. Idempotent.
fn decorate_data_base64(message: &str) -> String {
    if message.contains(DATA_BASE64_TIP_MARKER) || !is_data_base64_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {DATA_BASE64_TIP_MARKER} — MCP `terminal_write` expected a JSON string \
         containing standard Base64 (the RFC 4648 alphabet `A-Z`, `a-z`, `0-9`, `+`, `/`), with \
         `=` padding where required: for example `\"data_base64\": \"YQ==\"` sends `a`, while \
         `\"YQ\"` fails with `Invalid padding`. Pass the encoded text only, not raw binary bytes \
         or a `data:` URL. Surrounding whitespace is trimmed, but whitespace inside the encoding \
         is invalid; the URL-safe alphabet (`-` and `_`) is not accepted, so transcode it first. \
         For UTF-8 text, use `data` instead (for example `\"data\": \"ls\\n\"`); if both fields \
         are strings, `data` takes precedence. Decoding happens before the terminal lookup or \
         write, so no bytes were written and retrying the same encoding fails identically. \
         Missing or non-string input is the separate `terminal_write needs data or data_base64` \
         error; valid input with an expired id instead reports `unknown terminal ...`. Check the \
         tool's inputSchema via `tools/list`. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod data_base64_tip_tests {
    use super::*;

    #[test]
    fn invalid_data_base64_gets_the_tip_once() {
        for raw in [
            "data_base64: Invalid symbol 33, offset 0.",
            "data_base64: Invalid padding",
            "data_base64: Invalid last symbol 66, offset 3.",
            "  data_base64: Invalid symbol 33, offset 0.\n",
        ] {
            let out = decorate_data_base64(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(out.matches(DATA_BASE64_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "`terminal_write`",
                "standard Base64",
                "RFC 4648",
                "`=` padding where required",
                "`\"data_base64\": \"YQ==\"`",
                "`\"YQ\"` fails with `Invalid padding`",
                "raw binary",
                "`data:` URL",
                "Surrounding whitespace is trimmed",
                "URL-safe",
                "`data` takes precedence",
                "before the terminal lookup or write",
                "no bytes were written",
                "inputSchema",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert!(!out.contains(TERMINAL_WRITE_NEEDS_DATA_TIP_MARKER), "{out}");
            assert_eq!(decorate_data_base64(&out), out);
        }
    }

    #[test]
    fn invalid_data_base64_leaves_siblings_alone() {
        for raw in [
            "data_base64:",
            "data_base64:   ",
            "terminal_write: data_base64: Invalid padding",
            "content_base64: Invalid symbol 33, offset 0.",
            TERMINAL_WRITE_NEEDS_DATA_RAW,
            "unknown terminal abc",
            "stat_path: No such file or directory (os error 2)",
        ] {
            assert_eq!(decorate_data_base64(raw), raw, "{raw}");
        }
    }
}

const LS_MISSING_TIP_MARKER: &str = "locate the file by name";

/// Extract `<path>` from the node's `ls: path \`<path>\` does not exist` error,
/// including one wrapped in an anyhow context chain. The bare (unquoted) form
/// is accepted too for older nodes.
fn ls_missing_path(message: &str) -> Option<&str> {
    const NEEDLE: &str = "ls: path ";
    let start = message.rfind(NEEDLE)? + NEEDLE.len();
    let rest = &message[start..];
    let (path, tail) = match rest.strip_prefix('`') {
        Some(quoted) => {
            let end = quoted.find('`')?;
            (&quoted[..end], &quoted[end + 1..])
        }
        None => {
            let end = rest.find(" does not exist")?;
            (&rest[..end], &rest[end..])
        }
    };
    (!path.is_empty() && tail.starts_with(" does not exist")).then_some(path)
}

/// Append an actionable tip when `ls` reports that the remote path is missing:
/// locate it by name with `find`, or list its parent. Idempotent. Node
/// not-found, `not found:` path tips, offline/grant/session, PATH misses, edit
/// mismatches, EACCES, search-regex failures, and EISDIR are left alone.
fn decorate_ls_missing(message: &str) -> String {
    if message.contains(LS_MISSING_TIP_MARKER) || message.contains("agentlink find") {
        return message.to_string();
    }
    match ls_missing_path(message) {
        Some(path) => format!(
            "{message}. tip: '{path}' is on the node, not a machine name — \
             {LS_MISSING_TIP_MARKER} with `agentlink find <node> <basename>`, or list the \
             parent with `agentlink ls <node> <parent>`; paths are absolute or home-relative \
             unless the node's cwd applies"
        ),
        None => message.to_string(),
    }
}

const MV_RM_MISSING_TIP_MARKER: &str =
    "the mv source or rm path is missing on the node";

/// Extract `<path>` from the node's `mv source \`<path>\` does not exist` or
/// `rm: path \`<path>\` does not exist` error, including one wrapped in an
/// anyhow context chain. Both node messages always backtick the path, and
/// requiring the backtick keeps prose mentions such as ``not a missing path
/// (`rm: path ... does not exist`)`` in other tips from matching. The
/// `ls: path …` sibling deliberately has a different needle.
fn mv_rm_missing_path(message: &str) -> Option<&str> {
    const NEEDLES: &[&str] = &["mv source `", "rm: path `"];
    let (start, needle_len) = NEEDLES
        .iter()
        .filter_map(|needle| message.rfind(needle).map(|at| (at, needle.len())))
        .max_by_key(|(at, _)| *at)?;
    let quoted = &message[start + needle_len..];
    let end = quoted.find('`')?;
    let path = &quoted[..end];
    let tail = &quoted[end + 1..];
    (!path.is_empty() && tail.starts_with(" does not exist")).then_some(path)
}

/// Append an actionable tip when `mv` reports that its source is missing or
/// `rm` reports that its path is missing: locate the entry by name, or list
/// its parent. Idempotent. The `ls: path …` sibling keeps its own tip, and
/// node-not-found, offline/grant/session, PATH misses, and the bare
/// `io: No such file…` line are left alone.
fn decorate_mv_rm_missing(message: &str) -> String {
    if message.contains(MV_RM_MISSING_TIP_MARKER) {
        return message.to_string();
    }
    match mv_rm_missing_path(message) {
        Some(path) => format!(
            "{message}. tip: {MV_RM_MISSING_TIP_MARKER} ('{path}') — locate it by name with \
             `agentlink find <node> <basename>` (MCP `search_files`), or list the parent with \
             `agentlink ls <node> <parent>` (MCP `list_dir`); check the path for typos before \
             retrying"
        ),
        None => message.to_string(),
    }
}

const LIST_DIR_PERMISSION_TIP_MARKER: &str =
    "directory listing was denied by the node's permissions";

const LIST_DIR_PERMISSION_FORMS: &[&str] = &[
    "io: Permission denied (os error 13)",
    "io: Access is denied. (os error 5)",
];

/// Whole-message equality only: the pathless `io:` line is shared by every node
/// op (`cat`/`read_file`, `write`, `mkdir`, `remove`, `mv`), each with its own
/// permission tip, and wrapped forms carry context this tip cannot attribute to
/// the caller's directory. Keep the Windows sentence whole so Linux EIO
/// (`Input/output error (os error 5)`) stays raw.
fn is_list_dir_permission_error(message: &str) -> bool {
    LIST_DIR_PERMISSION_FORMS.contains(&message.trim_end())
}

/// Append an actionable tip when CLI `ls` / MCP `list_dir` is refused with the
/// pathless OS permission line. `list_dir_entries` opens the directory with
/// `read_dir`, and the failure names neither node nor path, so the caller's
/// labels are interpolated here. Wired only at those two listing sites: the
/// identical `io:` line is produced by every other node op, each with its own
/// tip, so the flat `tool_err` chain and the CLI global chain must keep it raw.
/// Idempotent.
fn decorate_list_dir_permission(message: &str, node: &str, path: &str) -> String {
    if message.contains(LIST_DIR_PERMISSION_TIP_MARKER) || !is_list_dir_permission_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {LIST_DIR_PERMISSION_TIP_MARKER} — MCP `list_dir` (CLI `agentlink ls`) \
         asked the node `{node}` to list `{path}`, and the node's process user was refused. The \
         raw line names neither the node nor the path; `{path}` is the value you passed (omitted, \
         and the node used its working directory; a relative path is joined to the node working \
         directory or the `--root` jail; `~` is not expanded). Enumeration needs read (`r`) on \
         the directory, and traversal needs execute/search (`x`) on the directory and every \
         parent; failing either gate gives this same line. A `stat_path` call can still succeed \
         with only `x` (it reads the entry's own metadata, not the name list), so a successful \
         stat does not mean the contents are listable. Common causes are another user's `0700` \
         home such as `/root`, a `0700`/`0710` service directory, a directory whose mode is \
         `0111` or `0644`, or a target under a parent that lacks `x`; on a node running as a \
         service account this is routine. Diagnose with MCP `stat_path` (decimal `mode`, e.g. \
         `16832` is `0o40700`) and the same for each parent, and with `run_command` / \
         `agentlink exec <node> -- stat -c '%A %U:%G %n' <path>` (or `ls -ld <parent>`). Fix by \
         granting the node user read+search on the directory and any parent that lacks `x` \
         (`chmod o+rx <dir>`, or `u+rx` when the node user owns it), by `sudo chown <node-user> \
         <dir>`, or by running the listing as a user with access through `run_command` / \
         `agentlink exec` with `sudo` when the node policy allows. Or avoid the listing: reading \
         a known child needs only that child's own read bit plus `x` on the parents. If the node \
         runs as a service user, ask the operator to grant access or move the files. On Windows \
         there is no mode bit: `os error 5` means an ACL, AppLocker, or protected location \
         denies List Folder or traverse on the directory or a parent; inspect with `icacls \
         <dir>` and grant the node user `(RX)`, or use an allowed folder. Nothing was listed and \
         no entries were returned; retrying unchanged fails identically. This is not a missing \
         path (the node's `ls: path` + `does not exist` line has its own tip), not a wrong-type \
         path (a file, or a non-directory component), not a `--root` sandbox escape (its own \
         message, with no `io:` prefix), not a signed-grant/capability denial, and not \
         node-offline. See `agentlink guide <node>`."
    )
}

const LIST_DIR_IO_MISSING_TIP_MARKER: &str = "the list_dir path is missing on the node";

/// Pathless ENOENT `io:` forms: Unix errno 2, plus the Windows
/// `ERROR_FILE_NOT_FOUND` (2) and `ERROR_PATH_NOT_FOUND` (3) sentences in
/// English and Chinese. Linux nodes remap a missing listing to `ls: path …`
/// (already tipped by `decorate_ls_missing`); these bare forms come from
/// Windows and bare-OS nodes.
const LIST_DIR_IO_MISSING_FORMS: &[&str] = &[
    "io: No such file or directory (os error 2)",
    "io: The system cannot find the file specified. (os error 2)",
    "io: The system cannot find the path specified. (os error 3)",
    "io: 系统找不到指定的文件。 (os error 2)",
    "io: 系统找不到指定的路径。 (os error 3)",
];

/// Whole-message equality only: the pathless `io:` line is shared by every
/// node op, each with its own missing-path handling (`stat_path` deliberately
/// stays raw), and wrapped forms carry context this tip cannot attribute to
/// the caller's directory.
fn is_list_dir_io_missing_error(message: &str) -> bool {
    LIST_DIR_IO_MISSING_FORMS.contains(&message.trim_end())
}

/// Append an actionable tip when CLI `ls` / MCP `list_dir` gets the pathless
/// ENOENT `io:` line. The failure names neither node nor path, so the caller's
/// labels are interpolated here. Wired only at those two listing sites: the
/// identical `io:` line is produced by every other node op, so the flat
/// `tool_err` chain and the CLI global chain must keep it raw. Idempotent.
fn decorate_list_dir_io_missing(message: &str, node: &str, path: &str) -> String {
    if message.contains(LIST_DIR_IO_MISSING_TIP_MARKER) || !is_list_dir_io_missing_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {LIST_DIR_IO_MISSING_TIP_MARKER} — MCP `list_dir` (CLI `agentlink ls`) \
         asked the node `{node}` to list `{path}`, but the node's OS reports that path (or one of \
         its parents) does not exist. The raw line names neither the node nor the path. Locate \
         the entry by name with `agentlink find <node> <basename>` (MCP `search_files`), or list \
         the parent with `agentlink ls <node> <parent>` (MCP `list_dir`); check `{path}` for \
         typos, and remember a relative path is resolved against the node working directory or \
         the `--root` jail. Nothing was listed and no entries were returned; retrying unchanged \
         fails identically."
    )
}

#[cfg(test)]
mod list_dir_io_missing_tip_tests {
    use super::*;

    const UNIX: &str = "io: No such file or directory (os error 2)";
    const WINDOWS_EN_FILE: &str = "io: The system cannot find the file specified. (os error 2)";
    const WINDOWS_EN_PATH: &str = "io: The system cannot find the path specified. (os error 3)";
    const WINDOWS_CN_FILE: &str = "io: 系统找不到指定的文件。 (os error 2)";
    const WINDOWS_CN_PATH: &str = "io: 系统找不到指定的路径。 (os error 3)";

    #[test]
    fn list_dir_io_missing_tips_each_form_once_with_node_and_path() {
        for raw in [
            UNIX,
            WINDOWS_EN_FILE,
            WINDOWS_EN_PATH,
            WINDOWS_CN_FILE,
            WINDOWS_CN_PATH,
        ] {
            let out = decorate_list_dir_io_missing(raw, "probe", "C:\\nope-ls-237");
            assert!(
                out.starts_with(&format!("{raw}. tip: {LIST_DIR_IO_MISSING_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(
                out.matches(LIST_DIR_IO_MISSING_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "probe",
                "C:\\nope-ls-237",
                "`agentlink find <node> <basename>`",
                "`agentlink ls <node> <parent>`",
                "MCP `search_files`",
                "MCP `list_dir`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            for literal in ["{node}", "{path}", "{message}"] {
                assert!(!out.contains(literal), "{literal} literal left: {out}");
            }
            assert_eq!(
                decorate_list_dir_io_missing(&out, "probe", "C:\\nope-ls-237"),
                out,
                "second call must be byte-identical"
            );
        }
    }

    #[test]
    fn list_dir_io_missing_leaves_siblings_and_wrapped_forms_alone() {
        for raw in [
            "ls: path `/srv/app` does not exist",
            "io: Permission denied (os error 13)",
            "io: Access is denied. (os error 5)",
            "io: Not a directory (os error 20)",
            "io: No such file or directory (os error 2) extra",
            "exec x: io: No such file or directory (os error 2)",
            "node offline: probe",
            "authentication failed: grant has expired",
            "program 'ls' not found on PATH (No such file or directory (os error 2))",
            "stat_path: io: No such file or directory (os error 2)",
            "",
        ] {
            assert_eq!(
                decorate_list_dir_io_missing(raw, "probe", "/tmp/nope"),
                raw,
                "{raw}"
            );
        }

        let trailing = format!("{UNIX}\n");
        let out = decorate_list_dir_io_missing(&trailing, "probe", "/tmp/nope");
        assert_eq!(
            out.matches(LIST_DIR_IO_MISSING_TIP_MARKER).count(),
            1,
            "{out}"
        );

        let permission =
            decorate_list_dir_permission("io: Permission denied (os error 13)", "probe", "/root");
        assert_eq!(
            decorate_list_dir_io_missing(&permission, "probe", "/root"),
            permission
        );
    }
}

#[cfg(test)]
mod ls_missing_tip_tests {
    use super::*;

    #[test]
    fn missing_ls_path_gets_the_tip_once() {
        let out = decorate_ls_missing("ls: path `/srv/app/src.txt` does not exist");
        assert_eq!(
            out,
            "ls: path `/srv/app/src.txt` does not exist. tip: '/srv/app/src.txt' is on the node, \
             not a machine name — locate the file by name with `agentlink find <node> <basename>`, \
             or list the parent with `agentlink ls <node> <parent>`; paths are absolute or \
             home-relative unless the node's cwd applies"
        );
        assert_eq!(decorate_ls_missing(&out), out);
    }

    #[test]
    fn wrapped_missing_ls_path_uses_the_backticked_path() {
        let out = decorate_ls_missing("ls /srv: ls: path `/srv/app/src.txt` does not exist");
        assert!(out.contains("tip: '/srv/app/src.txt' is on the node"), "{out}");
        assert_eq!(out.matches(LS_MISSING_TIP_MARKER).count(), 1, "{out}");
    }

    #[test]
    fn bare_missing_ls_path_uses_the_path() {
        let out = decorate_ls_missing("ls: path /srv/app/src.txt does not exist");
        assert!(out.contains("tip: '/srv/app/src.txt' is on the node"), "{out}");
        assert_eq!(decorate_ls_missing(&out), out);
    }

    #[test]
    fn other_path_and_node_tips_are_left_alone() {
        for raw in [
            "not found: node 'foo'",
            "not found: /srv/app/src",
            "not found: ~/app/src",
            "find /srv: not found: /srv/app/src",
            "ls: path `/srv/app/src` does not exist. tip: already mentions `agentlink find <node>`",
        ] {
            assert_eq!(decorate_ls_missing(raw), raw, "{raw}");
        }
    }

    #[test]
    fn offline_grant_session_path_miss_edit_eacces_regex_eisdir_are_unchanged() {
        for raw in [
            "node offline: probe",
            "authentication failed: grant has expired",
            "authentication failed: session expired or revoked",
            "program 'ls' not found on PATH (No such file or directory (os error 2))",
            "old string was not found in /tmp/x",
            "Permission denied (os error 13)",
            "regex parse error: unclosed group",
            "cat: path `/tmp` is a directory",
        ] {
            assert_eq!(decorate_ls_missing(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod mv_rm_missing_tip_tests {
    use super::*;

    #[test]
    fn missing_mv_source_gets_the_tip_once() {
        let raw = "mv source `/tmp/nope-src` does not exist";
        let out = decorate_mv_rm_missing(raw);
        assert_eq!(
            out,
            "mv source `/tmp/nope-src` does not exist. tip: the mv source or rm path is missing \
             on the node ('/tmp/nope-src') — locate it by name with `agentlink find <node> \
             <basename>` (MCP `search_files`), or list the parent with `agentlink ls <node> \
             <parent>` (MCP `list_dir`); check the path for typos before retrying"
        );
        assert_eq!(decorate_mv_rm_missing(&out), out);
    }

    #[test]
    fn missing_rm_path_gets_the_tip_once() {
        let out = decorate_mv_rm_missing("rm: path `/tmp/nope-rm` does not exist");
        assert!(out.contains(MV_RM_MISSING_TIP_MARKER), "{out}");
        assert!(out.contains("('/tmp/nope-rm')"), "{out}");
        assert!(out.contains("`agentlink find <node> <basename>`"), "{out}");
        assert!(out.contains("`agentlink ls <node> <parent>`"), "{out}");
        assert!(out.contains("MCP `search_files`"), "{out}");
        assert!(out.contains("MCP `list_dir`"), "{out}");
        assert_eq!(out.matches(MV_RM_MISSING_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_mv_rm_missing(&out), out);
    }

    #[test]
    fn wrapped_form_uses_the_path() {
        let wrapped = decorate_mv_rm_missing("mv /srv: mv source `/srv/app/a` does not exist");
        assert!(wrapped.contains("('/srv/app/a')"), "{wrapped}");
        assert_eq!(decorate_mv_rm_missing(&wrapped), wrapped);
    }

    #[test]
    fn sibling_errors_are_left_alone() {
        for raw in [
            "ls: path `/tmp/nope` does not exist",
            "io: No such file or directory (os error 2)",
            "node offline: probe",
            "authentication failed: grant has expired",
            "not found: node 'foo'",
            "mv source  does not exist",
            "rm: path  does not exist",
            "not a missing path (`rm: path ... does not exist`)",
            "rm: path /srv/app/a does not exist",
        ] {
            assert_eq!(decorate_mv_rm_missing(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod list_dir_permission_tip_tests {
    use super::*;

    const UNIX: &str = "io: Permission denied (os error 13)";
    const WINDOWS: &str = "io: Access is denied. (os error 5)";

    #[test]
    fn unix_eacces_gets_the_tip_once() {
        let out = decorate_list_dir_permission(UNIX, "box", "/root");
        assert!(
            out.starts_with(&format!("{UNIX}. tip: {LIST_DIR_PERMISSION_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(
            out.matches(LIST_DIR_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "box",
            "/root",
            "read",
            "execute/search",
            "stat",
            "chmod o+rx",
            "icacls",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        for literal in ["{node}", "{path}", "{message}"] {
            assert!(!out.contains(literal), "{literal} literal left: {out}");
        }
        assert_eq!(decorate_list_dir_permission(UNIX, "box", "/root"), out);
        assert_eq!(
            decorate_list_dir_permission(&out, "box", "/root"),
            out,
            "second call must be byte-identical"
        );
    }

    #[test]
    fn windows_form_gets_the_tip() {
        let out = decorate_list_dir_permission(WINDOWS, "box", "/root");
        assert!(
            out.starts_with(&format!(
                "{WINDOWS}. tip: {LIST_DIR_PERMISSION_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(LIST_DIR_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("icacls"), "{out}");
        assert_eq!(decorate_list_dir_permission(&out, "box", "/root"), out);
    }

    #[test]
    fn exact_whole_message_only() {
        for raw in [
            "io: Permission denied (os error 13) extra",
            "exec x: io: Permission denied (os error 13)",
            "cat /etc/shadow: io: Permission denied (os error 13)",
            "Permission denied (os error 13)",
            "io: Input/output error (os error 5)",
            "io: No such file or directory (os error 2)",
            "io: Not a directory (os error 20)",
            "ls: path `/srv/app` does not exist",
            "watch /root: Permission denied (os error 13) about [\"/root\"]",
            "node offline: probe",
            "",
        ] {
            assert_eq!(
                decorate_list_dir_permission(raw, "box", "/root"),
                raw,
                "{raw}"
            );
        }

        let trailing = format!("{UNIX}\n");
        let out = decorate_list_dir_permission(&trailing, "box", "/root");
        assert_eq!(
            out.matches(LIST_DIR_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn already_tipped_and_siblings_are_noops() {
        let out = decorate_list_dir_permission(UNIX, "box", "/root");
        assert_eq!(decorate_ls_missing(&out), out);
        assert_eq!(decorate_path_not_found(&out), out);
        assert_eq!(decorate_missing_parent(&out), out);
        assert_eq!(decorate_write_target_is_directory(&out), out);
        assert_eq!(decorate_symlink_dir_read(&out), out);
        assert_eq!(decorate_read_target_is_directory(&out), out);
        assert_eq!(decorate_write_dest_permission(&out, "box", "/root"), out);
        assert_eq!(
            decorate_mkdir_dest_permission(&out, "box", "/root", false),
            out
        );
        assert_eq!(
            decorate_remove_dest_permission(&out, "box", "/root", false),
            out
        );
        assert_eq!(
            decorate_mv_dest_permission(&out, "box", "/srv/a", "/root"),
            out
        );
        assert_eq!(decorate_sandbox_path_escape(&out), out);
    }

    #[test]
    fn hint_list_dir_permission_wraps_the_tip() {
        let out = hint_list_dir_permission(UNIX, "box", "/root").to_string();
        assert!(out.starts_with(UNIX), "{out}");
        assert_eq!(
            out.matches(LIST_DIR_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );

        let missing = "ls: path `/srv/app` does not exist";
        assert_eq!(
            hint_list_dir_permission(missing, "box", "/srv/app").to_string(),
            missing
        );
    }

    #[test]
    fn hint_list_dir_permission_wraps_list_dir_io_missing_tip() {
        let out = hint_list_dir_permission(
            "io: No such file or directory (os error 2)",
            "probe",
            "/tmp/nope",
        )
        .to_string();
        assert!(
            out.starts_with("io: No such file or directory (os error 2). tip: "),
            "{out}"
        );
        assert_eq!(
            out.matches(LIST_DIR_IO_MISSING_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("probe") && out.contains("/tmp/nope"), "{out}");
        assert_eq!(
            out.matches(LIST_DIR_PERMISSION_TIP_MARKER).count(),
            0,
            "{out}"
        );

        let missing = "ls: path `/srv/app` does not exist";
        assert_eq!(
            hint_list_dir_permission(missing, "box", "/srv/app").to_string(),
            missing
        );
    }
}

const STAT_PATH_PERMISSION_TIP_MARKER: &str =
    "`stat_path` was denied metadata access on the node";

const STAT_PATH_PERMISSION_FORMS: &[&str] = &[
    "io: Permission denied (os error 13)",
    "io: Access is denied. (os error 5)",
];

/// Whole-message equality only: the pathless `io:` line is shared by every node
/// op (`stat_path`, `copy_path` peer preflight, `read_file`, `write_file`,
/// `mkdir`, `remove_path`, `move_path`, `list_dir`, the edit family), each with
/// its own permission treatment, and wrapped forms carry context this tip
/// cannot attribute to the caller's metadata probe. Keep the Windows sentence
/// whole so Linux EIO (`Input/output error (os error 5)`) stays raw.
fn is_stat_path_permission_error(message: &str) -> bool {
    STAT_PATH_PERMISSION_FORMS.contains(&message.trim_end())
}

/// Append an actionable tip when MCP `stat_path` is refused with the pathless
/// OS permission line. The node's `symlink_metadata` names neither node nor
/// path, so the caller's labels are interpolated here. Wired only at the
/// `stat_path` arm: the identical `io:` line is produced by every other node op
/// (notably the `copy_path` peer preflight, which shares `Op::Stat`), each with
/// its own tip, so the flat `tool_err` chain must keep it raw. There is no CLI
/// `stat` surface. Idempotent.
fn decorate_stat_path_permission(message: &str, node: &str, path: &str) -> String {
    if message.contains(STAT_PATH_PERMISSION_TIP_MARKER) || !is_stat_path_permission_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {STAT_PATH_PERMISSION_TIP_MARKER} — MCP `stat_path` asked the node \
         `{node}` for metadata on `{path}`, and the node's process user was refused by the OS. \
         The raw line names neither the node nor the path; `{path}` is exactly the value passed \
         (a relative path is joined to the node working directory or the `--root` jail; `~` is \
         not expanded). `stat` / `symlink_metadata` needs execute/search (`x`) on every \
         ancestor, but not read (`r`) on the target and no permission on a final symlink's \
         referent; failing an ancestor `x` gate gives this line. A directory with mode `000` \
         still stats successfully, while an entry under another user's `0700` home does not. \
         Contrast with `read_file`: `stat_path /etc/shadow` usually succeeds (dogfood: `mode` \
         `33184`, i.e. `0o100640`, on `box`) while `read_file` is refused — a successful stat \
         does not mean the file is readable. Conversely, a denied `stat_path` is the stronger \
         signal: it points at a parent (or an ACL/LSM rule), not at the file's own mode. \
         Dogfood: `stat_path /root` succeeds (`mode` `16832`, i.e. `0o40700`) while `stat_path \
         /root/.bashrc` and `stat_path /etc/ssl/private/ssl-cert-snakeoil.key` return this line \
         because `/root` is `0700` and `/etc/ssl/private` is `0710 root:ssl-cert`. Common cases \
         are another user's `0700` home (e.g. `/root/...`), a `0700`/`0710` service directory, a \
         relative path whose working-directory ancestor is not searchable, or an ACL/LSM rule; \
         on a node running as a service account this is routine. Because `stat_path` is itself \
         the failing call, inspect from the node with `run_command` / `agentlink exec <node> -- \
         namei -l <path>` (or `stat -c '%A %U:%G %n' <path> <parent>` and `ls -ld <parent>`) \
         plus `id -un`; use `getfacl` / `lsattr` for ACLs and immutable flags; on Windows use \
         `icacls <path>` and `icacls <parent>`. `list_dir` on the parent needs `r+x` and can \
         fail the same way; if the node user cannot traverse, only an operator/root can inspect \
         it. Fixes: add `x` to the blocking ancestor for the node user (`chmod o+x <dir>`, or \
         `u+x`/`g+x` when appropriate); `chown` it to the node user; add the node user to the \
         owning group; or correct the ACL. LSM policy needs an operator. If the ancestor must \
         stay protected, run the work as a user with access through `run_command` / `agentlink \
         exec` with `sudo` when the node policy allows, or ask the operator. On Windows there is \
         no mode bit: `os error 5` means an ACL, AppLocker, AV, or protected location denies \
         traverse/metadata; inspect with `icacls`. No metadata was returned; nothing on the node \
         was modified; retrying unchanged fails identically. This is not a missing path (ENOENT \
         — keep raw here; peer-copy has its own tip), not a sandbox jail denial (no `io:` \
         prefix), not a signed-grant/capability refusal, not a `read_file`/`list_dir`/write/\
         mkdir/remove/mv permission tip (those are other arms), and not node-offline. See \
         `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod stat_path_permission_tip_tests {
    use super::*;

    const UNIX: &str = "io: Permission denied (os error 13)";
    const WINDOWS: &str = "io: Access is denied. (os error 5)";

    #[test]
    fn unix_eacces_gets_the_tip_once() {
        let out = decorate_stat_path_permission(UNIX, "box", "/root/.bashrc");
        assert!(
            out.starts_with(&format!(
                "{UNIX}. tip: {STAT_PATH_PERMISSION_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(STAT_PATH_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "box",
            "/root/.bashrc",
            "execute/search",
            "ancestor",
            "namei",
            "stat -c",
            "icacls",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        for literal in ["{node}", "{path}", "{message}"] {
            assert!(!out.contains(literal), "{literal} literal left: {out}");
        }
        assert_eq!(decorate_stat_path_permission(UNIX, "box", "/root/.bashrc"), out);
        assert_eq!(
            decorate_stat_path_permission(&out, "box", "/root/.bashrc"),
            out,
            "second call must be byte-identical"
        );
    }

    #[test]
    fn windows_form_gets_the_tip() {
        let out = decorate_stat_path_permission(WINDOWS, "box", "/root/.bashrc");
        assert!(
            out.starts_with(&format!(
                "{WINDOWS}. tip: {STAT_PATH_PERMISSION_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(STAT_PATH_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("icacls"), "{out}");
        assert_eq!(decorate_stat_path_permission(&out, "box", "/root/.bashrc"), out);
    }

    #[test]
    fn exact_whole_message_only() {
        for raw in [
            "io: Permission denied (os error 13) extra",
            "exec x: io: Permission denied (os error 13)",
            "stat /root/.bashrc: io: Permission denied (os error 13)",
            "/root/.bashrc: Permission denied (os error 13)",
            "Permission denied (os error 13)",
            "io: Input/output error (os error 5)",
            "io: Operation not permitted (os error 1)",
            "io: No such file or directory (os error 2)",
            "watch /root: Permission denied (os error 13) about [\"/root\"]",
            "permission denied: command denied by sandbox pattern 'sudo **'",
            "capability denied",
            "node offline: probe",
            "",
        ] {
            assert_eq!(
                decorate_stat_path_permission(raw, "box", "/root/.bashrc"),
                raw,
                "{raw}"
            );
        }

        let trailing = format!("{UNIX}\n");
        let out = decorate_stat_path_permission(&trailing, "box", "/root/.bashrc");
        assert_eq!(
            out.matches(STAT_PATH_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn already_tipped_and_siblings_are_noops() {
        let out = decorate_stat_path_permission(UNIX, "box", "/root/.bashrc");
        assert_eq!(decorate_read_file_permission(&out, "box", "/root/.bashrc"), out);
        assert_eq!(decorate_list_dir_permission(&out, "box", "/root/.bashrc"), out);
        assert_eq!(decorate_write_dest_permission(&out, "box", "/root/.bashrc"), out);
        assert_eq!(
            decorate_mkdir_dest_permission(&out, "box", "/root/.bashrc", false),
            out
        );
        assert_eq!(
            decorate_remove_dest_permission(&out, "box", "/root/.bashrc", false),
            out
        );
        assert_eq!(
            decorate_mv_dest_permission(&out, "box", "/srv/a", "/root/.bashrc"),
            out
        );
        assert_eq!(decorate_sandbox_path_escape(&out), out);
    }

    #[test]
    fn read_file_decorator_still_owns_its_arm() {
        let read = decorate_read_file_permission(UNIX, "box", "/etc/shadow");
        assert!(
            read.contains(READ_FILE_PERMISSION_TIP_MARKER),
            "{read}"
        );
        assert_eq!(decorate_stat_path_permission(&read, "box", "/etc/shadow"), read);
    }
}

const MISSING_PARENT_TIP_MARKER: &str = "do not create parent";

/// Extract `<dir>` from a `parent directory does not exist: <dir>` message,
/// including one wrapped in an anyhow context chain
/// (`write /srv/app/notes.txt: …`).
fn missing_parent_dir(message: &str) -> Option<&str> {
    const NEEDLE: &str = "parent directory does not exist: ";
    let start = message.rfind(NEEDLE)? + NEEDLE.len();
    let dir = message[start..].trim_end();
    (!dir.is_empty()).then_some(dir)
}

/// Append an actionable tip when write/cp fail because the destination's
/// parent directory is missing: create it with `agentlink mkdir -p`. Idempotent.
/// Messages that already mention `mkdir -p` (such as the node's `mv`
/// destination tip) and unrelated errors are left alone.
fn decorate_missing_parent(message: &str) -> String {
    if message.contains(MISSING_PARENT_TIP_MARKER) || message.contains("mkdir -p") {
        return message.to_string();
    }
    match missing_parent_dir(message) {
        Some(dir) => format!(
            "{message}. tip: '{dir}' does not exist on the node — create it first with \
             `agentlink mkdir -p <node> {dir}` (write/cp do not create parent dirs), or target \
             an existing directory"
        ),
        None => message.to_string(),
    }
}

const MV_CROSS_DEVICE_TIP_MARKER: &str = "rename(2) cannot cross filesystems on the node";

/// `rename(2)` reports EXDEV (errno 18 on Linux/macOS/BSD); Windows maps the
/// same failure to ERROR_NOT_SAME_DEVICE (17). Never match a bare
/// `(os error 18)` alone: 18 is ERROR_NO_MORE_FILES on Windows, and this
/// decorator sees every CLI/MCP error string.
fn is_mv_cross_device_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("cross-device link")
        || lower.contains("cross device link")
        || lower.contains("different disk drive")
}

/// Append an actionable tip when `mv` / MCP `move_path` fails with EXDEV:
/// rename cannot move across filesystems, but copy-then-delete can.
/// Idempotent; unrelated errors are left alone.
fn decorate_mv_cross_device(message: &str) -> String {
    if message.contains(MV_CROSS_DEVICE_TIP_MARKER) || !is_mv_cross_device_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {MV_CROSS_DEVICE_TIP_MARKER} — `mv` (MCP `move_path`) is a single \
         rename(2) on the node, and rename cannot move between filesystems: `/tmp` (tmpfs) vs \
         the disk, a container's overlay `/` vs a bind-mounted volume, NFS/SMB shares, or \
         separate partitions/drives (Windows C: vs D:) all return EXDEV. This is an OS limit, \
         not a grant, sandbox, or permission problem — retrying, `-f`, or sudo cannot succeed. \
         Copy across, then delete the source: `agentlink cp node://<name>/<src> \
         node://<name>/<dst>` then `agentlink rm <node> <src>` (`-r` for a directory; MCP \
         `copy_path` with direction `peer` on the same node, then `remove_path`). Or let the \
         node's own `mv` do the copy+unlink: `agentlink exec <node> --shell 'mv <src> <dst>'` \
         (MCP `run_command`). Check the mounts with `agentlink exec <node> --shell 'df <src> \
         <dst>'`; see `agentlink guide <node>`."
    )
}

const REMOVE_NOT_EMPTY_TIP_MARKER: &str = "a non-recursive remove only deletes an empty directory";

/// ENOTEMPTY: `39` on Linux/BSD, `66` on macOS, `145` (ERROR_DIR_NOT_EMPTY) on
/// Windows. Only match this at the remove call sites: `fs::rename` produces the
/// same literal when the destination is a non-empty directory, and `mv` /
/// MCP `move_path` need a different remedy.
fn is_remove_not_empty_error(message: &str) -> bool {
    message.contains("Directory not empty")
        || message.contains("directory is not empty")
        || message.contains("ENOTEMPTY")
        || message.contains("os error 39")
        || message.contains("os error 66")
        || message.contains("os error 145")
}

/// Append an actionable tip when a non-recursive `rm` / MCP `remove_path`
/// hits a non-empty directory. Idempotent; unrelated errors are left alone.
fn decorate_remove_not_empty(message: &str) -> String {
    if message.contains(REMOVE_NOT_EMPTY_TIP_MARKER) || !is_remove_not_empty_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {REMOVE_NOT_EMPTY_TIP_MARKER} — `remove_path` defaults to \
         non-recursive, which maps to `rmdir(2)` and fails as soon as the directory has any \
         entry; nothing was removed. Check what is inside first with `agentlink ls <node> \
         <path>` / MCP `list_dir`, then either delete the children and retry, or repeat the \
         call with `recursive: true` (MCP) / `agentlink rm <node> <path> -r` (CLI). Recursive \
         removal is permanent and deletes everything under the path (a symlink is unlinked, \
         never followed). If you already passed `recursive`/`-r` and still see this, a child \
         could not be deleted (permissions, or a file open on Windows): list the directory and \
         remove the remainder individually, or use `agentlink exec <node> --shell '<platform rm \
         -rf equivalent>'` / MCP `run_command`. See `agentlink guide <node>`."
    )
}

const REMOVE_DEST_PERMISSION_TIP_MARKER: &str =
    "`remove_path` was denied permission to delete the destination `path`";

/// Exact, pathless `io:` forms the node returns when the filesystem refuses to
/// unlink the entry at `path` or remove the directory there. These strings are
/// shared by every node op, so this predicate may only run at the CLI `rm`
/// branch and the MCP `remove_path` arm, which know the operation and path.
/// Match the whole trimmed message: Linux errno 5 is EIO (`Input/output error
/// (os error 5)`) and errno 32 is EPIPE (`Broken pipe (os error 32)`), so the
/// Windows forms must match their full sentences, never the bare errno.
const REMOVE_DEST_PERMISSION_FORMS: &[&str] = &[
    "io: Permission denied (os error 13)",
    "io: Operation not permitted (os error 1)",
    "io: Access is denied. (os error 5)",
    "io: Read-only file system (os error 30)",
    "io: The process cannot access the file because it is being used by another process. (os error 32)",
];

fn is_remove_dest_permission_error(message: &str) -> bool {
    let m = message.trim_end();
    REMOVE_DEST_PERMISSION_FORMS.iter().any(|s| m == *s)
}

/// Append an actionable tip when `rm` / MCP `remove_path` is refused by the
/// node's filesystem with a pathless permission, lock, or read-only error.
/// The node reports only the bare `io:` line, so name the node and path here,
/// explain the Unix parent-directory and sticky rules, and point at the
/// inspection/repair commands. Idempotent; unrelated errors are left alone.
fn decorate_remove_dest_permission(
    message: &str,
    node: &str,
    path: &str,
    recursive: bool,
) -> String {
    if message.contains(REMOVE_DEST_PERMISSION_TIP_MARKER)
        || !is_remove_dest_permission_error(message)
    {
        return message.to_string();
    }
    let outcome = if recursive {
        format!(
            "Because `recursive: true` (CLI `-r`) deletes as it walks, a refusal part-way through \
             can leave the tree partially deleted with some entries already gone: re-list `{path}` \
             and its parent before retrying."
        )
    } else {
        format!("Nothing was removed: `{path}` and everything under it are unchanged.")
    };
    format!(
        "{message}. tip: {REMOVE_DEST_PERMISSION_TIP_MARKER} — `remove_path` (CLI `agentlink \
         rm`) deletes exactly `{path}` on `{node}`, and the node's filesystem refused it. On \
         Unix, unlinking a file or removing an empty directory needs write and execute \
         permission on the containing directory, not on the entry itself: a `0444` file in a \
         writable directory is deletable, while a `0777` file in a `0555` directory is not. \
         Execute/search permission is also needed on every ancestor, so a grandparent missing \
         `+x` gives the same refusal. In a sticky world-writable directory such as `/tmp` (mode \
         `1777`) only the entry's owner or root may delete it, so another user's entry is \
         refused with `io: Operation not permitted (os error 1)` even though the directory looks \
         writable — changing the entry's mode cannot fix that; ownership or root is required. \
         Other causes: the immutable or append-only attribute also gives that refusal and only \
         root can clear it with `chattr -i`; the Windows `Access is denied.` form is usually the \
         read-only attribute (`attrib -r`) or a locked/running executable; the sharing-violation \
         sentence means another process holds the file open; `Read-only file system` means the \
         mount is read-only and no mode change helps. `remove_path` unlinks a symlink itself and \
         never follows it, so the link's parent must permit the delete while the target and its \
         directory are untouched. {outcome} Retrying unchanged fails identically. This is not the \
         non-empty-directory case (separate tip), not a missing path (`rm: path ... does not \
         exist`), not the ENOTDIR path-component failure, not a `--root` jail denial (those carry \
         a `permission denied:` prefix and no `io:`), not a signed-grant failure (`capability \
         denied`), not node-offline, and not `Device or resource busy (os error 16)` (a mount \
         point or busy resource, different remedy). Inspect before fixing: MCP `stat_path` on \
         `{path}` and on its parent — the parent's `mode` is what matters, and if stat on the \
         parent also fails an ancestor lacks execute/search — plus `list_dir` on the parent for \
         ownership, or `run_command` `ls -ld <parent>` / `stat -c '%A %U:%G %n' <path> <parent>`; \
         on Windows `icacls <parent>` / `attrib <path>`. Fixes: `chmod u+w` (or `g+w`/`o+w`) on \
         the parent directory, or `chown` it to the node user; for a sticky `/tmp` ask the entry's \
         owner or the node operator; immutable/append-only needs root `chattr -i`; Windows \
         read-only is `attrib -r` and an in-use file needs the holder closed (`process_list` / \
         `process_kill`); a read-only mount must be remounted read-write or the copy deleted \
         elsewhere. If the parent must stay unwritable for the node user, that user cannot delete \
         the entry — ask the operator. Note the raw message is pathless: `{path}` is the \
         caller's path, a relative path is joined to the node cwd (or the `--root` jail), and \
         `~` is not expanded. See `agentlink guide <node>`."
    )
}

const WRITE_TARGET_IS_DIRECTORY_TIP_MARKER: &str =
    "`write`/`write_file` replace a single file, not a directory";

/// The node's `serve_push_stream` guard is the sole producer of
/// `format!("{} is a directory", dest.display())`. Case-sensitive suffix only:
/// the read path appends `, not a file; use \`ls\` to list it`, OS EISDIR is
/// `"Is a directory"`/`"(os error 21)"`, `mv` says "is not a directory", and
/// mkdir says "already exists as a directory".
fn is_write_target_directory_error(message: &str) -> bool {
    message.trim_end().ends_with(" is a directory")
}

/// Append an actionable tip when `write` / MCP `write_file` targets an existing
/// directory (the node rejects before accepting bytes). Idempotent; unrelated
/// errors are left alone.
fn decorate_write_target_is_directory(message: &str) -> String {
    if message.contains(WRITE_TARGET_IS_DIRECTORY_TIP_MARKER)
        || !is_write_target_directory_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {WRITE_TARGET_IS_DIRECTORY_TIP_MARKER} — `write` (MCP `write_file`) \
         streams a single file to the exact path given, and the node refuses before accepting any \
         bytes when that path already exists as a directory (including a symlink/Windows junction \
         that resolves to one); nothing was written and no partial file was created. Pass a file \
         path inside it (append a name, e.g. `agentlink write <node> <path>/<file>` / MCP \
         `write_file` with the file name in `path`) — inspect first with `agentlink ls <node> \
         <path>` / MCP `list_dir` or `stat_path`. If you meant to create a directory, use \
         `agentlink mkdir <node> <path>` / MCP `mkdir`. If you meant to replace the directory \
         with a file, remove or move it first: `agentlink rm <node> <path> -r` / MCP \
         `remove_path` with `recursive: true` (permanent — deletes everything under it), or \
         `agentlink mv` / `move_path` to move it aside. If you meant to upload a whole tree, \
         `write` cannot: use `agentlink cp <local-dir> node://<node>/<path>` / MCP `copy_path` \
         with direction `upload`. A trailing slash is rejected earlier with a different message; \
         retrying unchanged will loop. Note the path above is the node-resolved target (`~` and \
         the `--root` jail applied). See `agentlink guide <node>`."
    )
}

const WRITE_FILE_NEEDS_CONTENT_TIP_MARKER: &str =
    "write_file needs UTF-8 content or content_base64";

const WRITE_FILE_NEEDS_CONTENT_RAW: &str = "write_file needs `content` or `content_base64`";

/// `decode_content` is the sole producer of the raw message: MCP `write_file`
/// has no `content` string and no `content_base64` string (absent, or a
/// non-string JSON value for both). Match the whole trimmed message so wrapped
/// or partially different errors stay raw.
fn is_write_file_needs_content_error(message: &str) -> bool {
    message.trim() == WRITE_FILE_NEEDS_CONTENT_RAW
}

/// Append an actionable tip when MCP `write_file` receives neither a string
/// `content` nor a string `content_base64`. The raw message names both fields
/// but not the accepted types or the fact that nothing was written. Idempotent;
/// unrelated errors are left alone.
fn decorate_write_file_needs_content(message: &str) -> String {
    if message.contains(WRITE_FILE_NEEDS_CONTENT_TIP_MARKER)
        || !is_write_file_needs_content_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {WRITE_FILE_NEEDS_CONTENT_TIP_MARKER} — MCP `write_file` streams \
         in-memory bytes, so pass one of the content fields: `content` as a JSON string of \
         UTF-8 text (for example `\"content\": \"hello\\n\"`), or `content_base64` as a JSON \
         string of standard base64 for binary data (for example `\"content_base64\": \
         \"AAEC\"`). `content` must be a string: a number, boolean, array, object, or `null` \
         is not accepted, and omitting both fields also produces this form (an empty string is \
         valid and writes an empty file). Nothing was written and no file was created or \
         changed. This is input validation, not a node, permission, disk, or timeout failure, \
         not the directory case (`... is a directory`, separate tip), and not a base64 decode \
         failure (`content_base64: ...`). Check the tool's inputSchema via `tools/list` and \
         send the bytes as a JSON string; stringify a number only if you meant its text. See \
         `agentlink guide <node>`."
    )
}

const CONTENT_BASE64_TIP_MARKER: &str =
    "`content_base64` must be standard base64";

/// `decode_content` is the sole producer of these messages: MCP `write_file`
/// receives a string `content_base64` and the base64 crate rejects it, so the
/// error is prefixed with the field name (`content_base64: Invalid symbol 33,
/// offset 0.`). Match the trimmed prefix so wrapped errors stay raw; the
/// missing-both-fields form is a different error and does not match.
fn is_content_base64_error(message: &str) -> bool {
    message.trim_start().starts_with("content_base64:")
}

/// Append an actionable tip when MCP `write_file` receives a `content_base64`
/// string that fails to decode. The raw message names the field and the decoder
/// complaint but not the accepted encoding or the `content` alternative.
/// Idempotent; unrelated errors are left alone.
fn decorate_content_base64(message: &str) -> String {
    if message.contains(CONTENT_BASE64_TIP_MARKER) || !is_content_base64_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {CONTENT_BASE64_TIP_MARKER} — MCP `write_file` decodes the \
         `content_base64` field itself, and the decoder rejected the string. It must be a JSON \
         string containing standard Base64 (the RFC 4648 alphabet `A-Z`, `a-z`, `0-9`, `+`, \
         `/`), with optional `=` padding; pass the encoded text only, not raw binary bytes, a \
         `data:` URL, or a value with whitespace inside it. The URL-safe alphabet (`-` and `_`) \
         is not accepted because this field uses the standard alphabet; if that is what you \
         have, transcode it first. If you meant UTF-8 text, pass it as `content` instead of \
         encoding it yourself. Nothing was written and no file was created or changed, and \
         retrying the same string fails identically. Omitting both content fields is a \
         different error (`write_file needs content or content_base64`, separate tip), and a \
         non-string `content_base64` value is not a decode error. Check the tool's inputSchema \
         via `tools/list` and re-encode the bytes with a standard Base64 encoder. See \
         `agentlink guide <node>`."
    )
}

const WRITE_DEST_PERMISSION_TIP_MARKER: &str =
    "`write_file` was denied write/install at the destination `path`";

/// Exact, pathless `io:` forms produced when the node cannot create the hidden
/// partial beside `path` or install/replace the existing target there. The
/// strings are shared with every other node op, so this predicate may only run
/// at the MCP `write_file` call site, where the payload is in-memory content and
/// the only filesystem IO is the node destination. Match the whole trimmed
/// message: Linux errno 5 is EIO (`Input/output error (os error 5)`) and errno
/// 32 is EPIPE (`Broken pipe (os error 32)`), so the Windows forms must match
/// their full sentences, not the bare errno.
const WRITE_DEST_PERMISSION_FORMS: &[&str] = &[
    "io: Permission denied (os error 13)",
    "io: Access is denied. (os error 5)",
    "io: Read-only file system (os error 30)",
    "io: The process cannot access the file because it is being used by another process. (os error 32)",
];

fn is_write_dest_permission_error(message: &str) -> bool {
    let m = message.trim_end();
    WRITE_DEST_PERMISSION_FORMS.iter().any(|s| m == *s)
}

/// Append an actionable tip when MCP `write_file` is denied at the destination
/// by the OS (permissions, read-only filesystem, Windows sharing violation).
/// The node accepts the stream and the error arrives pathless, so name the node
/// and path here. Idempotent; unrelated errors are left alone.
fn decorate_write_dest_permission(message: &str, node: &str, path: &str) -> String {
    if message.contains(WRITE_DEST_PERMISSION_TIP_MARKER)
        || !is_write_dest_permission_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {WRITE_DEST_PERMISSION_TIP_MARKER} — `write_file` streams one in-memory \
         file to exactly `{path}` on `{node}`, and the node could not create or replace it there \
         (this is a node-side write, not a local source read). The node first creates a hidden \
         `.{{name}}.agentlink-partial` beside the target — that fails if the parent directory is \
         not writable or the filesystem is read-only (`io: Read-only file system (os error 30)`) \
         — then installs it by opening an existing target for write and removing/renaming into \
         place; a `0444`/root-owned file or a read-only mount is refused at that gate, and a \
         Windows sharing violation (`os error 32`, \"being used by another process\") means \
         another process holds the file open. The existing file at `{path}` is left intact with \
         its original contents, mode, owner, and inode (unchanged); the temporary partial is \
         discarded and the journal removed, and if the target did not exist nothing was created. \
         No silent truncation occurred. Retrying unchanged fails identically because the node \
         user's permissions have not changed. This is not the directory case (`... is a \
         directory`, separate tip), not a `--root` sandbox jail denial (those say \"path \
         escapes sandbox\" with no `io:` prefix; `sudo`/`chmod` will not help there), not a \
         signed-grant/capability denial \
         (`capability denied` / `permission denied: write is not allowed on this node`), not a \
         missing parent (`parent directory does not exist` / `io: No such file or directory (os \
         error 2)`, separate), and not the ENOTDIR path-component case (`path component ... \
         exists but is not a directory; cannot create parent directories for write/cp`). Inspect \
         with MCP `stat_path` (`node: \"{node}\", path: \"{path}\"`) for `mode` (e.g. \
         `0o444`/`0o555`) and `readonly` (the Windows read-only attribute; on Unix inspect \
         `mode`), and `list_dir` on the parent for its mode/owner and any same-named entry; \
         `run_command` with `ls -ld <parent>` / `stat -c '%A %U:%G %n' <path>` (needs exec \
         permission) confirms. Fixes: `chmod u+w {path}` (or `sudo chown <node-user> {path}`) \
         for the target; `chmod u+w <parent>` for the directory; `remove_path` the read-only \
         file then `write_file` again (removal itself needs write permission on the parent); \
         write to a different path on a writable filesystem and `move_path` if allowed; for `os \
         error 32` find and close the process holding the file (`process_list`, `lsof`, \
         `handle.exe`). If the node runs as a service user, ask the operator to grant write or \
         start it as an appropriate user. Note the path named above is the caller's `path`: a \
         relative `path` is joined to the node cwd (or the `--root` jail), `~` is not expanded, \
         and the node-resolved absolute path may differ under `--root`. See `agentlink guide \
         <node>`."
    )
}

const EDIT_ATOMIC_WRITE_TIP_MARKER: &str = "the edit could not install its new file contents";

/// Exact OS tails from `edit::atomic_write`'s `tempfile::NamedTempFile::persist`
/// failure. The raw line is `atomic write <resolved-path>: <tail>`, so the path
/// is already present and no caller context is needed. Match only these four
/// permission tails: temp-creation failures surface earlier as a bare
/// `io: ...` line and must stay raw.
const EDIT_ATOMIC_WRITE_OS_FORMS: &[&str] = &[
    "Permission denied (os error 13)",
    "Operation not permitted (os error 1)",
    "Access is denied. (os error 5)",
    "The process cannot access the file because it is being used by another process. (os error 32)",
];

/// Extract the resolved path from `atomic write <path>: <tail>` when the tail
/// is one of the four permission forms and the path is non-empty. `rsplit_once`
/// splits on the last `": "`, so a Windows drive colon is not mistaken for it.
fn edit_atomic_write_path(message: &str) -> Option<&str> {
    let m = message.trim_end();
    let rest = m.strip_prefix("atomic write ")?;
    let (path, tail) = rest.rsplit_once(": ")?;
    if path.is_empty() || !EDIT_ATOMIC_WRITE_OS_FORMS.iter().any(|s| tail == *s) {
        return None;
    }
    Some(path)
}

/// Append an actionable tip when an edit family op is refused at the final
/// rename that installs the rebuilt file. The raw line already names the
/// node-resolved path, so this decorator is text-only. Idempotent; earlier
/// temp-creation failures and unrelated errors are left alone.
fn decorate_edit_atomic_write(message: &str) -> String {
    if message.contains(EDIT_ATOMIC_WRITE_TIP_MARKER) {
        return message.to_string();
    }
    let Some(path) = edit_atomic_write_path(message) else {
        return message.to_string();
    };
    format!(
        "{message}. tip: {EDIT_ATOMIC_WRITE_TIP_MARKER} — `replace` (MCP `replace_text`), \
         `edit-lines` (MCP `edit_lines`), and `patch` (MCP `apply_patch`) build the entire new \
         file in memory, write it to a hidden `.agentlink-*` temporary file beside `{path}`, then \
         rename it over the target to make the change atomic. The content was accepted and the \
         temporary file was written, but that final rename was refused, so `{path}` still has its \
         original contents, mode, owner, and inode; the hidden temporary file is removed when the \
         call fails and no partial content was written. On Unix the rename needs write and \
         execute permission on the containing directory, not on the target file: a read-only \
         `0444` target in a writable directory is replaced successfully, while a `0555` or \
         ACL-restricted parent refuses. In a sticky directory such as `/tmp` (mode `1777`), \
         replacing another user's file is refused with `Operation not permitted (os error 1)` — \
         the target's own mode cannot help; ownership or root is required. The immutable or \
         append-only attribute also refuses with that error and only root can clear it (`chattr \
         -i` / `chattr -a`; macOS `chflags nouchg` / `nouappnd`); inspect with `lsattr <path>` \
         or `ls -lO`. Windows `Access is denied.` is usually the read-only attribute (`attrib -r \
         <path>`) or a parent ACL; `os error 32` (\"being used by another process\") means the \
         target is open or running — close the holder first. If the parent itself is not \
         writable, the failure happens earlier while creating the temporary file and appears as \
         a bare `io: Permission denied (os error 13)` (a different line; not this tip), and a \
         read-only mount likewise fails earlier with `io: Read-only file system (os error 30)`. \
         Retrying unchanged fails identically. `patch` applies planned files in order: a rename \
         failure on one file can leave earlier files in the same patch already updated (and \
         missing parent directories created), while this file and later ones are unchanged — \
         re-read or `stat_path` the files before retrying, because re-applying the same diff to \
         an already updated file fails the hunk match. Inspect with MCP `stat_path` on `{path}` \
         and its parent (mode, owner, `readonly` on Windows), `list_dir` on the parent, and \
         `run_command` `ls -ld <parent>` / `stat -c '%A %U:%G %n' <path>` plus \
         `lsattr`/`getfacl`/`ls -lZ` (Linux) or `attrib`/`icacls` (Windows). Fixes: `chmod u+w \
         <parent>` (and `+x` on every ancestor) or `chown` the parent to the node user; for a \
         sticky directory edit a file you own (or ask its owner/operator); clear \
         immutable/append-only as root; on Windows `attrib -r` and close the locking process \
         (`process_list` / `process_kill`). If the parent must stay unwritable, that user cannot \
         atomically replace an entry there: write elsewhere and use `move_path` only if both \
         parents are writable, otherwise ask the operator. This is not the plain read/write \
         denial before the temporary file is created, not a missing path or a parent that is a \
         file (`is not a directory`), not the 8 MiB edit cap, non-UTF-8 text, empty/ambiguous \
         `old`, or a patch hunk mismatch (separate tips), not the `--root` jail refusal, not a \
         signed-grant refusal, and not a connectivity failure. Note `{path}` is the node-resolved \
         absolute path embedded in the raw line (cwd / `--root` applied). See `agentlink guide \
         <node>`."
    )
}

#[cfg(test)]
mod edit_atomic_write_tip_tests {
    use super::*;

    const TAILS: &[&str] = &[
        "Permission denied (os error 13)",
        "Operation not permitted (os error 1)",
        "Access is denied. (os error 5)",
        "The process cannot access the file because it is being used by another process. (os error 32)",
    ];

    #[test]
    fn permission_forms_get_the_tip_once() {
        for tail in TAILS {
            let raw = format!("atomic write /srv/app/config.toml: {tail}");
            let out = decorate_edit_atomic_write(&raw);
            assert!(
                out.starts_with(&format!("{raw}. tip: {EDIT_ATOMIC_WRITE_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(
                out.matches(EDIT_ATOMIC_WRITE_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(out.matches(". tip:").count(), 1, "{out}");
            for needle in [
                "config.toml",
                "replace_text",
                "edit_lines",
                "apply_patch",
                ".agentlink-",
                "rename",
                "parent",
                "0444",
                "sticky",
                "chattr",
                "attrib",
                "process_kill",
                "stat_path",
                "agentlink guide <node>",
            ] {
                assert!(out.contains(needle), "{needle}: {out}");
            }
            assert_eq!(decorate_edit_atomic_write(&out), out);
        }
    }

    #[test]
    fn path_with_spaces_and_windows_drive_are_captured() {
        let spaced = decorate_edit_atomic_write(
            "atomic write /srv/my app/notes.txt: Permission denied (os error 13)",
        );
        assert!(spaced.contains("/srv/my app/notes.txt"), "{spaced}");

        let windows = decorate_edit_atomic_write(
            r"atomic write C:\Users\me\notes.txt: Permission denied (os error 13)",
        );
        assert!(windows.contains(r"C:\Users\me\notes.txt"), "{windows}");
        assert_eq!(
            windows.matches(EDIT_ATOMIC_WRITE_TIP_MARKER).count(),
            1,
            "{windows}"
        );
    }

    #[test]
    fn earlier_and_unrelated_lines_are_unchanged() {
        for raw in [
            "io: Permission denied (os error 13)",
            "io: Read-only file system (os error 30)",
            "atomic write /tmp/x: No such file or directory (os error 2)",
            "atomic write /tmp/x: Is a directory (os error 21)",
            "atomic write : Permission denied (os error 13)",
            "atomic writeX /tmp/x: Permission denied (os error 13)",
            "atomic write /tmp/x: Input/output error (os error 5)",
            "old string was not found in /tmp/x",
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4)",
            "",
        ] {
            assert_eq!(decorate_edit_atomic_write(raw), raw, "{raw}");
        }
    }

    #[test]
    fn already_tipped_is_unchanged() {
        let raw = "atomic write /srv/app/config.toml: Permission denied (os error 13)";
        let out = decorate_edit_atomic_write(raw);
        assert_ne!(out, raw);
        assert_eq!(decorate_edit_atomic_write(&out), out);
    }
}

#[cfg(test)]
mod write_dest_permission_tip_tests {
    use super::*;

    #[test]
    fn write_permission_gets_the_tip_once() {
        let raw = "io: Permission denied (os error 13)";
        let out = decorate_write_dest_permission(raw, "builder", "/etc/app/config.toml");
        assert!(
            out.starts_with(&format!("{raw}. tip: {WRITE_DEST_PERMISSION_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(
            out.matches(WRITE_DEST_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "builder",
            "/etc/app/config.toml",
            "stat_path",
            "list_dir",
            "0444",
            "readonly",
            "chmod",
            "partial",
            "intact",
            "unchanged",
            "capability denied",
            "os error 32",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        // The sandbox disambiguation must not embed the exact escape needle,
        // or `tool_err`'s `decorate_sandbox_path_escape` re-matches this tip.
        assert!(out.contains("sandbox"), "{out}");
        assert!(out.contains("`--root` sandbox jail denial"), "{out}");
        assert!(out.contains("`io:` prefix"), "{out}");
        assert!(!out.contains(SANDBOX_PATH_ESCAPE_NEEDLE), "{out}");
        assert!(!out.contains(SANDBOX_PATH_ESCAPE_TIP_MARKER), "{out}");
        assert_eq!(decorate_write_dest_permission(&out, "builder", "/etc/app/config.toml"), out);
    }

    #[test]
    fn decorated_tip_does_not_retrigger_sandbox_escape_tip() {
        let raw = "io: Permission denied (os error 13)";
        let out = decorate_write_dest_permission(raw, "builder", "/etc/app/config.toml");
        assert_eq!(decorate_sandbox_path_escape(&out), out);
    }

    #[test]
    fn windows_readonly_and_lock_forms() {
        for raw in [
            "io: Access is denied. (os error 5)",
            "io: Read-only file system (os error 30)",
            "io: The process cannot access the file because it is being used by another process. (os error 32)",
        ] {
            let out = decorate_write_dest_permission(raw, "builder", "/srv/app/config.toml");
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert_eq!(
                out.matches(WRITE_DEST_PERMISSION_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(
                decorate_write_dest_permission(&out, "builder", "/srv/app/config.toml"),
                out,
                "{raw}"
            );
        }
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "io: Input/output error (os error 5)",
            "io: Broken pipe (os error 32)",
            "io: Is a directory (os error 21)",
            "/srv/app is a directory",
            "permission denied: path escapes sandbox: /tmp/x",
            "permission denied: write is not allowed on this node",
            "capability denied: write",
            "io: No such file or directory (os error 2)",
            "path component `/srv/app` exists but is not a directory; cannot create parent directories for write/cp",
            "",
        ] {
            assert_eq!(
                decorate_write_dest_permission(raw, "builder", "/srv/app"),
                raw,
                "{raw}"
            );
        }
    }

    #[test]
    fn write_dir_and_permission_are_disjoint() {
        let raw = "io: Permission denied (os error 13)";
        assert_eq!(decorate_write_target_is_directory(raw), raw);
        let dir = "/srv/app is a directory";
        assert_eq!(decorate_write_dest_permission(dir, "builder", "/srv/app"), dir);
    }
}

#[cfg(test)]
mod missing_parent_tip_tests {
    use super::*;

    #[test]
    fn missing_parent_gets_the_mkdir_tip_once() {
        let out = decorate_missing_parent("parent directory does not exist: /srv/app");
        assert_eq!(
            out,
            "parent directory does not exist: /srv/app. tip: '/srv/app' does not exist on the \
             node — create it first with `agentlink mkdir -p <node> /srv/app` (write/cp do not \
             create parent dirs), or target an existing directory"
        );
        assert_eq!(decorate_missing_parent(&out), out);
        assert_eq!(out.matches(MISSING_PARENT_TIP_MARKER).count(), 1, "{out}");
    }

    #[test]
    fn wrapped_write_and_not_found_forms_use_the_dir() {
        for raw in [
            "write /srv/app/notes.txt: parent directory does not exist: /srv/app",
            "not found: parent directory does not exist: /srv/app",
            "cp /tmp/a: write /srv/app/notes.txt: parent directory does not exist: /srv/app",
        ] {
            let out = decorate_missing_parent(raw);
            assert!(
                out.contains("tip: '/srv/app' does not exist on the node"),
                "{raw} => {out}"
            );
            assert!(
                out.contains("`agentlink mkdir -p <node> /srv/app`"),
                "{out}"
            );
            assert_eq!(decorate_missing_parent(&out), out, "{raw}");
        }
    }

    #[test]
    fn existing_mkdir_p_tip_is_left_alone() {
        let raw = "mv destination parent `/srv/app` does not exist; create it with mkdir -p first \
                   (unlike write/cp, mv does not create parents)";
        assert_eq!(decorate_missing_parent(raw), raw);
    }

    #[test]
    fn other_errors_and_empty_dirs_are_unchanged() {
        for raw in [
            "ls: path `/srv/app` does not exist",
            "not found: /srv/app/src",
            "not found: node 'foo'",
            "node offline: probe",
            "authentication failed: grant has expired",
            "exec is not allowed on this node (read-only)",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "old string was not found in /tmp/x",
            "Permission denied (os error 13)",
            "regex parse error: unclosed group",
            "cat: path `/tmp` is a directory",
            "parent directory does not exist: ",
            "parent directory does not exist:",
        ] {
            assert_eq!(decorate_missing_parent(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod mv_cross_device_tip_tests {
    use super::*;

    #[test]
    fn linux_macos_windows_and_wrapped_errors_tip_once() {
        for raw in [
            "io: Invalid cross-device link (os error 18)",
            "Cross-device link (os error 18)",
            "The system cannot move the file to a different disk drive. (os error 17)",
            "mv: io: Invalid cross-device link (os error 18)",
        ] {
            let out = decorate_mv_cross_device(raw);
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert!(
                out.contains(&format!("tip: {MV_CROSS_DEVICE_TIP_MARKER}")),
                "{raw} => {out}"
            );
            assert!(out.contains("`agentlink cp node://<name>/<src>"), "{out}");
            assert!(out.contains("`agentlink rm <node> <src>`"), "{out}");
            assert!(
                out.contains("`agentlink exec <node> --shell 'mv <src> <dst>'`"),
                "{out}"
            );
            assert!(out.contains("`agentlink guide <node>`"), "{out}");
            assert_eq!(out.matches(MV_CROSS_DEVICE_TIP_MARKER).count(), 1, "{out}");
            assert_eq!(decorate_mv_cross_device(&out), out, "{raw}");
        }
    }

    #[test]
    fn other_errors_are_unchanged() {
        for raw in [
            "mv source `/tmp/a` does not exist",
            "mv destination parent `/srv/app` does not exist; create it with mkdir -p first \
             (unlike write/cp, mv does not create parents)",
            "cannot move directory `/srv/app` into itself",
            "io: Directory not empty (os error 39)",
            "io: Permission denied (os error 13)",
            "path escapes sandbox: /tmp/out.txt",
            "not found: node 'foo'",
            "io: No space left on device (os error 28)",
            "io: Invalid argument (os error 18)",
            "replacement text is too large",
        ] {
            assert_eq!(decorate_mv_cross_device(raw), raw, "{raw}");
        }
    }
}

const MV_TARGET_NOT_EMPTY_TIP_MARKER: &str = "mv cannot replace an existing non-empty directory";

/// ENOTEMPTY at the `mv` / MCP `move_path` sites: `39` on Linux/BSD, `66` on
/// macOS, `145` (ERROR_DIR_NOT_EMPTY) on Windows. Kept separate from
/// `is_remove_not_empty_error` so the two sites can evolve independently. The
/// errno alternatives cover localized nodes whose `strerror` text is translated.
fn is_mv_target_not_empty_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("directory not empty")
        || lower.contains("directory is not empty")
        || lower.contains("enotempty")
        || message.contains("os error 39")
        || message.contains("os error 66")
        || message.contains("os error 145")
}

/// Append an actionable tip when `mv` / MCP `move_path` hits ENOTEMPTY: the
/// node joined the destination with the source basename and found a non-empty
/// directory there, which `rename(2)` cannot replace. Idempotent; unrelated
/// errors are left alone.
fn decorate_mv_target_not_empty(message: &str, from: &str, to: &str) -> String {
    if message.contains(MV_TARGET_NOT_EMPTY_TIP_MARKER)
        || message.contains(REMOVE_NOT_EMPTY_TIP_MARKER)
        || !is_mv_target_not_empty_error(message)
    {
        return message.to_string();
    }
    let name = Path::new(from)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<source-name>");
    let joined = Path::new(to).join(name).display().to_string();
    format!(
        "{message}. tip: {MV_TARGET_NOT_EMPTY_TIP_MARKER} — `mv` (MCP `move_path`) is a single \
         rename(2) on the node, and rename can replace a directory only when the target \
         directory is empty. Because `{to}` is an existing directory, the node first resolved \
         the destination to `{joined}` (Unix into-directory semantics), and that path already \
         exists as a non-empty directory; the rename was refused before changing anything, so \
         `{from}` is untouched and `{joined}` still has its old contents. This is not a \
         permission, grant, or sandbox problem, and retrying the same `mv` fails the same way. \
         Pick a destination that does not collide: `agentlink mv <node> {from} {to}/<new-name>` \
         / MCP `move_path` with a fresh `to`. Or move the existing target aside first — \
         `agentlink mv <node> {joined} {joined}.bak` / MCP `move_path` — and retry the original \
         move (rename still works because `{joined}.bak` does not exist). To merge instead of \
         replace, copy over it: `agentlink cp node://<name>/{from} node://<name>/{joined}` / MCP \
         `copy_path` with direction `peer` and `dst_path` set to `{joined}` (it overwrites \
         colliding files and leaves extra entries), then, after verifying with `agentlink ls \
         <node> {joined}` / MCP `list_dir`, remove the source: `agentlink rm <node> {from} -r` / \
         MCP `remove_path` with `recursive: true` (permanent — deletes everything under it; a \
         symlink is unlinked, never followed). Inspect the collision first with `agentlink ls \
         <node> {joined}` / MCP `list_dir` or `stat_path`. Note `mv <src> <existing-dir>` always \
         moves *inside* that directory, so the effective target is `{joined}`, not `{to}` itself; \
         to replace the directory, move it aside first. On Windows the same refusal usually \
         reads `The directory is not empty. (os error 145)`. See `agentlink guide <node>`."
    )
}

const MV_DEST_PERMISSION_TIP_MARKER: &str =
    "`mv`/`move_path` was denied rename permission on the node";

/// Exact, pathless `io:` forms the node returns when the filesystem refuses a
/// rename at `from`/`to`. These strings are shared by every node op, so this
/// predicate may only run at the CLI `mv` branch and the MCP `move_path` arm,
/// which know the operation and both paths. Match the whole trimmed message:
/// Linux errno 5 is EIO (`Input/output error (os error 5)`) and errno 32 is
/// EPIPE (`Broken pipe (os error 32)`), so the Windows forms must match their
/// full sentences, never the bare errno.
const MV_DEST_PERMISSION_FORMS: &[&str] = &[
    "io: Permission denied (os error 13)",
    "io: Operation not permitted (os error 1)",
    "io: Access is denied. (os error 5)",
    "io: Read-only file system (os error 30)",
    "io: The process cannot access the file because it is being used by another process. (os error 32)",
];

fn is_mv_dest_permission_error(message: &str) -> bool {
    MV_DEST_PERMISSION_FORMS.contains(&message.trim_end())
}

/// Append an actionable tip when `mv` / MCP `move_path` is refused by the
/// node's filesystem with a pathless permission, lock, or read-only error.
/// The node reports only the bare `io:` line, so name the node and both paths
/// here, explain the Unix parent-directory, sticky, immutable, and Windows
/// rules, and point at the inspection/repair commands. Idempotent; unrelated
/// errors are left alone.
fn decorate_mv_dest_permission(message: &str, node: &str, from: &str, to: &str) -> String {
    if message.contains(MV_DEST_PERMISSION_TIP_MARKER)
        || !is_mv_dest_permission_error(message)
    {
        return message.to_string();
    }
    let name = Path::new(from)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("<source-name>");
    let joined = Path::new(to).join(name).display().to_string();
    format!(
        "{message}. tip: {MV_DEST_PERMISSION_TIP_MARKER} — `mv` (CLI) / MCP `move_path` is a \
         single rename(2) on `{node}` from `{from}` to `{to}`, and the node's filesystem refused \
         it. A failed rename changes neither name, so `{from}` is still in place; moving a \
         directory is likewise all-or-nothing (the whole subtree stays at `{from}`), not a \
         partial move. Unix rule: rename(2) needs write and execute permission on the directory \
         that contains the source and on the directory that will contain the destination; the \
         entry's own mode and owner are irrelevant (a `0444` file in a writable directory moves \
         fine, while a `0777` file in a `0555` directory does not). Execute/search permission \
         is also needed on every ancestor, so a grandparent missing `+x` gives the same EACCES. \
         Moving out of an unwritable or root-owned tree fails on the source parent just as \
         moving into an unwritable directory fails on the destination parent; changing only one \
         side is not enough. Into-directory semantics: when `{to}` is an existing directory, the \
         node resolves the effective destination to `{joined}` (the rename(2) move-inside \
         form), so `{to}` itself is the destination parent that must allow writes, not `{to}`'s \
         parent. Sticky rule: in a sticky world-writable directory such as `/tmp` (mode `1777`) \
         only the entry's owner or root may rename it out, so another user's entry gives \
         `Operation not permitted` even though the directory looks writable; chmod on the entry \
         cannot fix it — ownership or root is required. Immutable or append-only: Linux `chattr \
         +i`/`+a` (macOS `chflags uchg`/`schg`) also gives `Operation not permitted`, and only \
         root can clear the flag. Windows: `Access is denied.` usually means an ACL denies \
         write on a parent directory, the destination name is already taken by a directory, or \
         the source or destination is a read-only or in-use file; the sharing-violation \
         sentence means another process holds the file open (close the holder, or move under a \
         different name). Read-only filesystem: the mount itself is read-only; no chmod helps — \
         remount read-write or move to a writable filesystem. Nothing was moved, and retrying \
         unchanged fails identically. Inspect with MCP `stat_path` on `{from}`, `{to}`, and both \
         parent directories (the parents' mode decides), `list_dir` on both parents for owner \
         and mode, and `run_command` `ls -ld <parent>` / `stat -c '%A %U:%G %n' <path>` (needs \
         execute permission), or `findmnt`/`df` to spot a read-only mount; on Windows `icacls \
         <parent>` / `attrib <path>`. Fix by making the blocking parent writable (`chmod u+w`, \
         or `g+w`/`o+w`), `chown`ing it to the node user, clearing immutable flags as root, \
         closing the Windows holder or clearing the read-only attribute, or remounting \
         read-write. If the source parent must stay unwritable to the node user, that user \
         cannot move the entry out — ask the operator; `agentlink cp` / MCP `copy_path` can \
         duplicate it to a writable target, but deleting the original needs the same \
         source-parent write permission. `sudo mv` only works through `run_command` if the node \
         user has passwordless sudo. Symlinks: rename moves the link itself and never follows \
         it, so only the link's parent must permit the rename; the target tree is untouched. \
         This is not the cross-filesystem case (separate tip), not a destination directory that \
         already holds entries (separate tip), not a missing destination parent (separate tip), \
         not a directory moved into itself, not a path component that is not a directory, not \
         the `--root` jail refusal (those carry a `permission denied:` prefix and no `io:`), \
         not a capability or grant refusal, and not node-offline. `Device or resource busy` is \
         a different condition (mount point or busy resource) and is left raw. Note `{from}` \
         and `{to}` are the caller's paths: a relative path is joined to the node cwd (or the \
         `--root` jail), `~` is not expanded, and the node-resolved paths may differ under \
         `--root` or into-directory resolution. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod mv_target_not_empty_tip_tests {
    use super::*;

    #[test]
    fn mv_target_not_empty_gets_the_tip_once() {
        let raw = "io: Directory not empty (os error 39)";
        let out = decorate_mv_target_not_empty(raw, "/srv/app/build", "/srv/releases/current");
        assert!(
            out.starts_with(&format!("{raw}. tip: {MV_TARGET_NOT_EMPTY_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(MV_TARGET_NOT_EMPTY_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`/srv/releases/current/build`",
            "`/srv/app/build`",
            "`move_path`",
            "`agentlink mv <node> ",
            "`copy_path`",
            "`dst_path`",
            "`remove_path`",
            "`recursive: true`",
            "`stat_path`",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle} missing from {out}");
        }
        assert_eq!(
            decorate_mv_target_not_empty(&out, "/srv/app/build", "/srv/releases/current"),
            out
        );
    }

    #[test]
    fn platform_and_prefixed_forms_tip_once() {
        for raw in [
            "Directory not empty (os error 66)",
            "The directory is not empty. (os error 145)",
            "ENOTEMPTY",
            "rename: io: Directory not empty (os error 39)",
        ] {
            let out = decorate_mv_target_not_empty(raw, "/srv/app/build", "/srv/releases/current");
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert_eq!(out.matches(MV_TARGET_NOT_EMPTY_TIP_MARKER).count(), 1, "{out}");
            assert_eq!(
                decorate_mv_target_not_empty(&out, "/srv/app/build", "/srv/releases/current"),
                out,
                "{raw}"
            );
        }
    }

    #[test]
    fn remove_not_empty_tip_is_not_double_decorated() {
        let remove = decorate_remove_not_empty("io: Directory not empty (os error 39)");
        assert_eq!(
            decorate_mv_target_not_empty(&remove, "/srv/app/build", "/srv/releases/current"),
            remove
        );
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "io: Permission denied (os error 13)",
            "io: Invalid cross-device link (os error 18)",
            "io: Is a directory (os error 21)",
            "io: No space left on device (os error 28)",
            "mv source `/tmp/a` does not exist",
            "mv destination parent `/srv/app` does not exist; create it with mkdir -p first \
             (unlike write/cp, mv does not create parents)",
            "mv destination `/srv/app/dst` exists but is not a directory; cannot move directory \
             `/srv/app/src` onto a file",
            "cannot move directory `/srv/app` into itself (`/srv/app/sub` is inside it)",
        ] {
            assert_eq!(
                decorate_mv_target_not_empty(raw, "/srv/app/src", "/srv/app/dst"),
                raw,
                "{raw}"
            );
        }
    }
}

#[cfg(test)]
mod mv_dest_permission_tip_tests {
    use super::*;

    const FROM: &str = "/srv/app/build";
    const TO: &str = "/srv/releases/current";

    #[test]
    fn unix_forms_get_the_tip_once() {
        for raw in [
            "io: Permission denied (os error 13)",
            "io: Operation not permitted (os error 1)",
        ] {
            let out = decorate_mv_dest_permission(raw, "builder", FROM, TO);
            assert!(
                out.starts_with(&format!(
                    "{raw}. tip: {MV_DEST_PERMISSION_TIP_MARKER} — "
                )),
                "{out}"
            );
            assert_eq!(
                out.matches(MV_DEST_PERMISSION_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "builder",
                FROM,
                TO,
                "parent",
                "chmod",
                "sticky",
                "/tmp",
                "chattr",
                "changes neither name",
                "still in place",
                "agentlink guide <node>",
            ] {
                assert!(out.contains(needle), "{needle} missing from {out}");
            }
            assert_eq!(decorate_mv_dest_permission(raw, "builder", FROM, TO), out);
            for literal in ["{from}", "{to}", "{node}"] {
                assert!(
                    !out.contains(literal),
                    "literal {literal} left in {out}"
                );
            }
        }
    }

    #[test]
    fn windows_and_readonly_forms_get_the_tip() {
        for raw in [
            "io: Access is denied. (os error 5)",
            "io: Read-only file system (os error 30)",
            "io: The process cannot access the file because it is being used by another process. (os error 32)",
        ] {
            let out = decorate_mv_dest_permission(raw, "builder", FROM, TO);
            assert!(out.starts_with(&format!("{raw}. tip: ")), "{out}");
            assert_eq!(
                out.matches(MV_DEST_PERMISSION_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(decorate_mv_dest_permission(&out, "builder", FROM, TO), out);
        }
    }

    #[test]
    fn into_directory_explains_effective_parent() {
        let out = decorate_mv_dest_permission(
            "io: Permission denied (os error 13)",
            "builder",
            FROM,
            "/srv/releases/current",
        );
        assert!(out.contains("`/srv/releases/current/build`"), "{out}");
        assert!(out.contains("destination parent"), "{out}");
        assert!(out.contains("existing directory"), "{out}");
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "io: Invalid cross-device link (os error 18)",
            "io: Directory not empty (os error 39)",
            "io: Device or resource busy (os error 16)",
            "io: Broken pipe (os error 32)",
            "io: Input/output error (os error 5)",
            "io: No such file or directory (os error 2)",
            "io: Is a directory (os error 21)",
            "mv source `/srv/app/x` does not exist",
            "mv destination parent `/srv/app` does not exist; create it with mkdir -p first \
             (unlike write/cp, mv does not create parents)",
            "mkdir `/srv/app` already exists as a directory",
            "path component `/srv/app/file` exists but is not a directory",
            "permission denied: path escapes sandbox: /tmp/x",
            "capability denied: write",
            "node offline: probe",
            "",
        ] {
            assert_eq!(
                decorate_mv_dest_permission(raw, "builder", FROM, TO),
                raw,
                "{raw}"
            );
        }
    }

    #[test]
    fn exact_match_only() {
        let already = decorate_mv_dest_permission(
            "io: Permission denied (os error 13)",
            "builder",
            FROM,
            TO,
        );
        for raw in ["/srv/app/x: Permission denied (os error 13)", already.as_str()] {
            assert_eq!(
                decorate_mv_dest_permission(raw, "builder", FROM, TO),
                raw,
                "{raw}"
            );
        }
    }

    #[test]
    fn does_not_retrigger_mv_siblings() {
        let decorated =
            decorate_mv_dest_permission("io: Permission denied (os error 13)", "builder", FROM, TO);
        assert_eq!(decorate_mv_target_not_empty(&decorated, FROM, TO), decorated);
        assert_eq!(decorate_mv_cross_device(&decorated), decorated);

        let not_empty = decorate_mv_target_not_empty(
            "io: Directory not empty (os error 39)",
            FROM,
            TO,
        );
        assert_eq!(
            decorate_mv_dest_permission(&not_empty, "builder", FROM, TO),
            not_empty
        );
        let cross = decorate_mv_cross_device("io: Invalid cross-device link (os error 18)");
        assert_eq!(
            decorate_mv_dest_permission(&cross, "builder", FROM, TO),
            cross
        );
    }
}

#[cfg(test)]
mod remove_not_empty_tip_tests {
    use super::*;

    #[test]
    fn bare_error_gets_the_tip_once() {
        let raw = "io: Directory not empty (os error 39)";
        let out = decorate_remove_not_empty(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {REMOVE_NOT_EMPTY_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(REMOVE_NOT_EMPTY_TIP_MARKER).count(), 1, "{out}");
        assert!(out.contains("recursive: true"), "{out}");
        assert!(out.contains("`agentlink rm <node> <path> -r`"), "{out}");
        assert!(out.contains("list_dir"), "{out}");
        assert!(out.contains("run_command"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_remove_not_empty(&out), out);
    }

    #[test]
    fn macos_and_windows_forms_get_the_tip() {
        for raw in [
            "io: Directory not empty (os error 66)",
            "io: The directory is not empty. (os error 145)",
        ] {
            let out = decorate_remove_not_empty(raw);
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert_eq!(out.matches(REMOVE_NOT_EMPTY_TIP_MARKER).count(), 1, "{out}");
        }
    }

    #[test]
    fn decorated_output_is_idempotent() {
        let once = decorate_remove_not_empty("Directory not empty (os error 39)");
        assert_eq!(once.matches(REMOVE_NOT_EMPTY_TIP_MARKER).count(), 1, "{once}");
        assert_eq!(decorate_remove_not_empty(&once), once);
    }

    #[test]
    fn unrelated_errors_are_unchanged() {
        for raw in [
            "io: Is a directory (os error 21)",
            "io: Permission denied (os error 13)",
            "io: No space left on device (os error 28)",
            "io: Invalid argument (os error 18)",
            "mv destination parent `/srv/app` does not exist; create it with mkdir -p first \
             (unlike write/cp, mv does not create parents)",
            "cannot move directory `/srv/app` into itself",
            "patch exceeds 1 MiB",
            "replacement text exceeds 1 MiB",
            "old string was not found in /tmp/x",
            "rm: path `/srv/app/src` does not exist",
        ] {
            assert_eq!(decorate_remove_not_empty(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod remove_dest_permission_tip_tests {
    use super::*;

    #[test]
    fn unix_forms_get_the_tip_once() {
        for raw in [
            "io: Permission denied (os error 13)",
            "io: Operation not permitted (os error 1)",
        ] {
            let out = decorate_remove_dest_permission(raw, "builder", "/srv/app/run.pid", false);
            assert!(
                out.starts_with(&format!(
                    "{raw}. tip: {REMOVE_DEST_PERMISSION_TIP_MARKER} — "
                )),
                "{out}"
            );
            assert_eq!(
                out.matches(REMOVE_DEST_PERMISSION_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "builder",
                "/srv/app/run.pid",
                "parent",
                "chmod",
                "sticky",
                "/tmp",
                "chattr",
                "Nothing was removed",
                "agentlink guide <node>",
            ] {
                assert!(out.contains(needle), "{needle} missing from {out}");
            }
            assert!(
                out.contains(
                    "Nothing was removed: `/srv/app/run.pid` and everything under it are unchanged."
                ),
                "{out}"
            );
            for literal in ["{path}", "{node}", "{message}", "{outcome}"] {
                assert!(!out.contains(literal), "{literal} literal left: {out}");
            }
            assert_eq!(
                decorate_remove_dest_permission(raw, "builder", "/srv/app/run.pid", false),
                out
            );
        }
    }

    #[test]
    fn windows_and_readonly_forms_get_the_tip() {
        for raw in [
            "io: Access is denied. (os error 5)",
            "io: Read-only file system (os error 30)",
            "io: The process cannot access the file because it is being used by another process. (os error 32)",
        ] {
            let out = decorate_remove_dest_permission(raw, "builder", "/srv/app/run.pid", false);
            assert!(out.starts_with(&format!("{raw}. tip: ")), "{out}");
            assert_eq!(
                out.matches(REMOVE_DEST_PERMISSION_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(
                decorate_remove_dest_permission(&out, "builder", "/srv/app/run.pid", false),
                out
            );
        }
    }

    #[test]
    fn recursive_wording_reports_partial_delete() {
        let raw = "io: Permission denied (os error 13)";
        let recursive = decorate_remove_dest_permission(raw, "builder", "/srv/app/run.pid", true);
        assert!(recursive.contains("partially deleted"), "{recursive}");
        assert!(!recursive.contains("Nothing was removed"), "{recursive}");
        assert!(
            recursive
                .contains("re-list `/srv/app/run.pid` and its parent before retrying."),
            "{recursive}"
        );
        for literal in ["{path}", "{node}", "{message}", "{outcome}"] {
            assert!(
                !recursive.contains(literal),
                "{literal} literal left: {recursive}"
            );
        }
        let flat = decorate_remove_dest_permission(raw, "builder", "/srv/app/run.pid", false);
        assert!(flat.contains("Nothing was removed"), "{flat}");
        assert!(!flat.contains("partially deleted"), "{flat}");
    }

    #[test]
    fn outcome_clause_uses_the_caller_path() {
        let raw = "io: Permission denied (os error 13)";
        let path = "/srv/app/cache dir/run.pid";
        let flat = decorate_remove_dest_permission(raw, "builder", path, false);
        assert!(
            flat.contains(&format!(
                "Nothing was removed: `{path}` and everything under it are unchanged."
            )),
            "{flat}"
        );
        let recursive = decorate_remove_dest_permission(raw, "builder", path, true);
        assert!(
            recursive.contains(&format!(
                "re-list `{path}` and its parent before retrying."
            )),
            "{recursive}"
        );
        for out in [&flat, &recursive] {
            for literal in ["{path}", "{node}", "{message}", "{outcome}"] {
                assert!(!out.contains(literal), "{literal} literal left: {out}");
            }
        }
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "io: Directory not empty (os error 39)",
            "io: No such file or directory (os error 2)",
            "rm: path `/srv/app/x` does not exist",
            "path component `/srv/app/file` exists but is not a directory",
            "io: Is a directory (os error 21)",
            "io: Too many levels of symbolic links (os error 40)",
            "io: Device or resource busy (os error 16)",
            "io: Broken pipe (os error 32)",
            "io: Input/output error (os error 5)",
            "permission denied: path escapes sandbox: /tmp/x",
            "capability denied: write",
            "node offline: probe",
            "",
        ] {
            assert_eq!(
                decorate_remove_dest_permission(raw, "builder", "/srv/app/run.pid", false),
                raw,
                "{raw}"
            );
        }
    }

    #[test]
    fn exact_match_only() {
        let already = decorate_remove_dest_permission(
            "io: Permission denied (os error 13)",
            "builder",
            "/srv/app/run.pid",
            false,
        );
        for raw in [
            "/srv/app/x: Permission denied (os error 13)",
            already.as_str(),
        ] {
            assert_eq!(
                decorate_remove_dest_permission(raw, "builder", "/srv/app/run.pid", false),
                raw,
                "{raw}"
            );
        }
    }

    #[test]
    fn does_not_retrigger_remove_not_empty() {
        let decorated_perm = decorate_remove_dest_permission(
            "io: Permission denied (os error 13)",
            "builder",
            "/srv/app/run.pid",
            false,
        );
        assert_eq!(decorate_remove_not_empty(&decorated_perm), decorated_perm);

        let decorated_not_empty =
            decorate_remove_not_empty("io: Directory not empty (os error 39)");
        assert_eq!(
            decorate_remove_dest_permission(
                &decorated_not_empty,
                "builder",
                "/srv/app/run.pid",
                false,
            ),
            decorated_not_empty
        );
    }
}

#[cfg(test)]
mod write_target_directory_tip_tests {
    use super::*;

    #[test]
    fn bare_error_gets_the_tip_once() {
        let raw = "/srv/app/reports is a directory";
        let out = decorate_write_target_is_directory(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {WRITE_TARGET_IS_DIRECTORY_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(WRITE_TARGET_IS_DIRECTORY_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`agentlink ls <node> <path>`",
            "list_dir",
            "stat_path",
            "recursive: true",
            "`agentlink rm <node> <path> -r`",
            "`agentlink mkdir <node> <path>`",
            "copy_path",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(decorate_write_target_is_directory(&out), out);
    }

    #[test]
    fn resolved_paths_get_the_tip() {
        for raw in [
            "/home/dev/project/build is a directory",
            "C:\\Users\\dev\\AppData\\out is a directory",
            "/srv/app/current is a directory",
        ] {
            let out = decorate_write_target_is_directory(raw);
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert_eq!(out.matches(WRITE_TARGET_IS_DIRECTORY_TIP_MARKER).count(), 1, "{out}");
        }
    }

    #[test]
    fn decorated_output_is_idempotent() {
        let once = decorate_write_target_is_directory("/srv/app/reports is a directory");
        assert_eq!(once.matches(WRITE_TARGET_IS_DIRECTORY_TIP_MARKER).count(), 1, "{once}");
        assert_eq!(decorate_write_target_is_directory(&once), once);
    }

    #[test]
    fn unrelated_errors_are_unchanged() {
        for raw in [
            "/srv/app/reports is a directory, not a file; use `ls` to list it",
            "io: Is a directory (os error 21)",
            "Is a directory",
            "EISDIR",
            "mv destination `/srv/app/reports` exists but is not a directory",
            "mv destination parent `/srv/app` exists but is not a directory",
            "mkdir `/srv/app` already exists as a directory",
            "path component `/srv/app/notes.txt` exists but is not a directory",
            "write destination `/srv/app/reports/` ends with a slash; pass a file path (use mkdir \
             if you need a directory)",
            "ls: path `/srv/app/src` does not exist",
            "patch exceeds 1 MiB",
            "replacement text exceeds 1 MiB",
        ] {
            assert_eq!(decorate_write_target_is_directory(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod write_file_needs_content_tip_tests {
    use super::*;

    #[test]
    fn write_file_needs_content_gets_the_tip_once() {
        let raw = "write_file needs `content` or `content_base64`";
        let out = decorate_write_file_needs_content(raw);
        assert!(
            out.starts_with(&format!(
                "{raw}. tip: {WRITE_FILE_NEEDS_CONTENT_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(WRITE_FILE_NEEDS_CONTENT_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "`content`",
            "`content_base64`",
            "UTF-8",
            "JSON string",
            "base64",
            "number",
            "object",
            "`null`",
            "Nothing was written",
            "inputSchema",
            "tools/list",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        assert_eq!(decorate_write_file_needs_content(&out), out);
    }

    #[test]
    fn write_file_needs_content_whitespace_is_still_the_whole_message() {
        let out =
            decorate_write_file_needs_content("  write_file needs `content` or `content_base64`\n");
        assert!(
            out.starts_with("  write_file needs `content` or `content_base64`\n"),
            "{out}"
        );
        assert_eq!(
            out.matches(WRITE_FILE_NEEDS_CONTENT_TIP_MARKER).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn write_file_needs_content_leaves_siblings_alone() {
        for raw in [
            "missing `path`",
            "missing `node`",
            "/srv/app/reports is a directory",
            "content_base64: Invalid symbol 33, offset 0",
            "stat_path: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
            "unknown terminal abc",
            "write_file needs content",
            "write_file: write_file needs `content` or `content_base64`",
        ] {
            assert_eq!(decorate_write_file_needs_content(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod content_base64_tip_tests {
    use super::*;

    #[test]
    fn content_base64_decode_errors_get_the_tip_once() {
        for raw in [
            "content_base64: Invalid symbol 33, offset 0.",
            "content_base64: Invalid symbol 33, offset 0",
            "content_base64: Invalid padding",
            "content_base64: Invalid last symbol 66, offset 3.",
        ] {
            let out = decorate_content_base64(raw);
            assert!(
                out.starts_with(&format!("{raw}. tip: {CONTENT_BASE64_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(out.matches(CONTENT_BASE64_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "standard Base64",
                "RFC 4648",
                "JSON string",
                "padding",
                "URL-safe",
                "raw binary",
                "`content`",
                "Nothing was written",
                "write_file needs content or content_base64",
                "tools/list",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_content_base64(&out), out, "{out}");
        }
    }

    #[test]
    fn content_base64_leading_whitespace_is_still_the_prefix() {
        let out = decorate_content_base64("  content_base64: Invalid padding\n");
        assert!(
            out.starts_with("  content_base64: Invalid padding\n"),
            "{out}"
        );
        assert_eq!(out.matches(CONTENT_BASE64_TIP_MARKER).count(), 1, "{out}");
    }

    #[test]
    fn content_base64_leaves_siblings_alone() {
        for raw in [
            "write_file needs `content` or `content_base64`",
            "write_file needs content",
            "missing `path`",
            "missing `node`",
            "/srv/app/reports is a directory",
            "stat_path: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
            "unknown terminal abc",
            "write_file: content_base64: Invalid symbol 33, offset 0",
            "content: Invalid symbol 33, offset 0",
        ] {
            assert_eq!(decorate_content_base64(raw), raw, "{raw}");
        }
    }
}

const SYMLINK_DIR_READ_TIP_MARKER: &str =
    "a symlink to a directory is a directory, not a file";

/// The node's `ensure_pullable_file` guard is the sole producer of
/// `<path> is a symlink to a directory, not a file; use directory copy`.
/// Strict suffix including `; use directory copy`: the plain-directory form
/// ends `, not a file; use \`ls\` to list it`, and the fifo/device form says
/// `is not a regular file (refusing fifo/socket/device)`.
fn is_symlink_dir_read_error(message: &str) -> bool {
    message
        .trim_end()
        .ends_with(" is a symlink to a directory, not a file; use directory copy")
}

/// Append an actionable tip when `cat` (CLI) / MCP `read_file` is pointed at a
/// symlink whose target is a directory (the node refuses before opening it).
/// Idempotent; the plain-directory and fifo/device read errors are left alone.
fn decorate_symlink_dir_read(message: &str) -> String {
    if message.contains(SYMLINK_DIR_READ_TIP_MARKER) || !is_symlink_dir_read_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {SYMLINK_DIR_READ_TIP_MARKER} — the node refused the source before \
         opening it: `cat` (CLI) / `read_file` (MCP) read regular files, and this path is a \
         symbolic link whose target is a directory (a Windows junction that resolves to a \
         directory behaves the same), so there is no file to stream. Nothing was transferred. If \
         you meant the directory, list it with `agentlink ls <node> <path>` / MCP `list_dir` (it \
         follows a directory symlink) or `stat_path` (it reports `is_symlink: true` with \
         `is_dir: true`). If you meant a file inside it, append the name: `agentlink cat <node> \
         <path>/<file>` / MCP `read_file` with `path` set to `<path>/<file>`. To fetch the whole \
         tree, use a directory copy: `agentlink cp node://<node>/<path> <local-dir>` / MCP \
         `copy_path` with `direction: \"download\"` (a plain `cat` never follows a symlink into a \
         directory, and the src of that cp is classified by the link target). If the link is \
         stale, remove only the link with `agentlink rm <node> <path>` / MCP `remove_path` (a \
         symlink is unlinked, never followed) and point it at the file/directory you meant. Note \
         the path above is the node-resolved source (`~` is not expanded); on a node started \
         with `--root` the leaf is canonicalized, so the same mistake may instead appear as \
         `<path> is a directory, not a file; use `ls` to list it` (same fix) or as a sandbox \
         escape if the link targets something outside the jail. Retrying the same \
         `cat`/`read_file` fails the same way. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod symlink_dir_read_tip_tests {
    use super::*;

    #[test]
    fn symlink_dir_read_gets_the_tip_once() {
        let raw =
            "/srv/app/current is a symlink to a directory, not a file; use directory copy";
        let out = decorate_symlink_dir_read(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {SYMLINK_DIR_READ_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(SYMLINK_DIR_READ_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`agentlink ls <node> <path>`",
            "`list_dir`",
            "`stat_path`",
            "`is_symlink: true`",
            "`is_dir: true`",
            "agentlink cat <node> <path>/<file>",
            "agentlink cp node://<node>/<path> <local-dir>",
            "`copy_path`",
            "direction: \"download\"",
            "`agentlink rm <node> <path>`",
            "--root",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(decorate_symlink_dir_read(&out), out);
    }

    #[test]
    fn prefixed_forms_get_the_tip_once() {
        for raw in [
            "transfer: /srv/app/current is a symlink to a directory, not a file; use directory \
             copy",
            "pull_stream: /srv/app/current is a symlink to a directory, not a file; use directory \
             copy",
        ] {
            let out = decorate_symlink_dir_read(raw);
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert_eq!(
                out.matches(SYMLINK_DIR_READ_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert_eq!(decorate_symlink_dir_read(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_read_errors_are_unchanged() {
        for raw in [
            "/srv/app/reports is a directory, not a file; use `ls` to list it",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
            "io: Is a directory (os error 21)",
            "Is a directory",
            "EISDIR",
            "/srv/app/current is a symlink to a directory",
            "/srv/app/link: No such file or directory (os error 2)",
            "permission denied: path escapes sandbox: /srv/app/current",
            "write destination `/srv/app/reports/` ends with a slash; pass a file path (use mkdir \
             if you need a directory)",
            "/srv/app/src.rs is not a directory",
        ] {
            assert_eq!(decorate_symlink_dir_read(raw), raw, "{raw}");
        }
    }
}

const READ_TARGET_IS_DIRECTORY_TIP_MARKER: &str =
    "`read_file`/`cat` stream a single regular file, not a directory";
const READ_TARGET_IS_DIRECTORY_SUFFIX: &str =
    " is a directory, not a file; use `ls` to list it";

/// The node's `ensure_pullable_file` / `open_pullable_file` guards emit this
/// exact suffix for a real (non-symlink) directory before anything is opened
/// or streamed. Strict suffix: the symlink-to-directory form ends `; use
/// directory copy`, the fifo/device form says `is not a regular file`, and the
/// OS EISDIR form is `Is a directory (os error 21)`.
fn is_read_target_directory_error(message: &str) -> bool {
    message
        .trim_end()
        .ends_with(READ_TARGET_IS_DIRECTORY_SUFFIX)
}

/// Append an actionable tip when MCP `read_file` / CLI `cat` is pointed at a
/// directory (the node refuses before opening or streaming it). Idempotent;
/// the symlink-to-directory, fifo/device, and OS EISDIR read errors are left
/// alone by their sibling decorators.
fn decorate_read_target_is_directory(message: &str) -> String {
    if message.contains(READ_TARGET_IS_DIRECTORY_TIP_MARKER)
        || !is_read_target_directory_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {READ_TARGET_IS_DIRECTORY_TIP_MARKER} — the node checked the source \
         before opening or streaming it: MCP `read_file` (CLI `agentlink cat`) returns one \
         regular file, and the path above is a directory, so there is no file payload to stream. \
         Nothing was read and no bytes were transferred; the directory was not modified. This is \
         a type mismatch, not a permission, grant, sandbox, node-offline, or missing-path \
         failure, and retrying the same call unchanged fails identically — note that the `ls` \
         named in the message is a CLI command, not an MCP tool. The path is node-resolved (the \
         `--root` jail applied; `~` is not expanded). List the directory with MCP `list_dir` \
         (CLI `agentlink ls <node> <path>`) and confirm its type with MCP `stat_path` (`is_dir: \
         true`, `is_file: false`). If you meant the whole tree, use a directory copy: MCP \
         `copy_path` with `direction: \"download\"` / CLI `agentlink cp node://<node>/<path> \
         <local-dir>` (a read returns a file body, never a tree). If you meant one entry, name \
         it: MCP `read_file` with `path` set to `<path>/<file>` (CLI `agentlink cat <node> \
         <path>/<file>`); list first if you do not know the name. A symlink that resolves to a \
         directory is usually reported as the separate `is a symlink to a directory, not a file; \
         use directory copy` message (with its own tip); with `--root` canonicalization it can \
         surface as this message instead, and the same fixes apply. The OS `io: Is a directory \
         (os error 21)` that `write`/`write_file` can produce is a different case. See \
         `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod read_target_is_directory_tip_tests {
    use super::*;

    #[test]
    fn directory_read_gets_the_tip_once() {
        let raw = "/srv/app/reports is a directory, not a file; use `ls` to list it";
        let out = decorate_read_target_is_directory(raw);
        assert!(
            out.starts_with(&format!(
                "{raw}. tip: {READ_TARGET_IS_DIRECTORY_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(READ_TARGET_IS_DIRECTORY_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "read_file",
            "list_dir",
            "stat_path",
            "is_dir: true",
            "copy_path",
            "direction: \"download\"",
            "agentlink cp node://",
            "agentlink cat <node> <path>/<file>",
            "not a permission",
            "Nothing was read",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(decorate_read_target_is_directory(&out), out);
    }

    #[test]
    fn prefixed_forms_are_idempotent() {
        for raw in [
            "pull_stream: /srv/app/reports is a directory, not a file; use `ls` to list it",
            "/srv/app/reports is a directory, not a file; use `ls` to list it ",
        ] {
            let out = decorate_read_target_is_directory(raw);
            assert!(
                out.starts_with(raw.trim_end()),
                "{raw} => {out}"
            );
            assert_eq!(
                out.matches(READ_TARGET_IS_DIRECTORY_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert_eq!(decorate_read_target_is_directory(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_read_and_type_errors_are_unchanged() {
        for raw in [
            "/srv/app/current is a symlink to a directory, not a file; use directory copy",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
            "io: Is a directory (os error 21)",
            "Is a directory",
            "EISDIR",
            "/srv/app/reports is a directory",
            "/srv/app/src.rs is not a directory",
            "mkdir `/srv/app` already exists as a directory",
            "mkdir `/srv/app` exists but is not a directory",
            "mv destination parent `/srv/app` exists but is not a directory",
            "cannot create directory `/srv/app/x`: path exists but is not a directory (refusing \
             to copy a directory onto a file)",
            "/srv/app/notes.txt is a file, not a directory; use `cat` to print it",
            "/srv/app/current is a broken symbolic link",
            "write destination `/srv/app/reports/` ends with a slash; pass a file path (use mkdir \
             if you need a directory)",
        ] {
            assert_eq!(decorate_read_target_is_directory(raw), raw, "{raw}");
        }
    }
}

const READ_MISSING_FILE_TIP_MARKER: &str =
    "`read_file`/`copy_path` download can only stream an existing node path";
const READ_MISSING_FILE_SUFFIX: &str = ": No such file or directory";

/// The node's `ensure_pullable_file` emits this exact custom form (resolved
/// path plus the bare OS phrase) before opening or streaming anything — no
/// `io:` prefix and no `(os error N)` suffix. Reject the `io:` form (`stat_path`
/// and raw `fs` errors), any `io::Error` display including the dangling-symlink
/// variant, and the node startup `sandbox root:` failure.
fn read_missing_file_path(message: &str) -> Option<&str> {
    let msg = message.trim_end();
    let path = msg.strip_suffix(READ_MISSING_FILE_SUFFIX)?;
    if path.is_empty()
        || path.contains('\n')
        || msg.contains("io: ")
        || msg.contains("(os error")
        || msg.contains("sandbox root:")
    {
        return None;
    }
    Some(path)
}

fn is_read_missing_file_error(message: &str) -> bool {
    read_missing_file_path(message).is_some()
}

/// Append an actionable tip when MCP `read_file` or `copy_path` with
/// `direction: "download"` names a path that does not exist on the node. Both
/// call sites know the path is a node source, so the tip's claims hold; it is
/// deliberately not part of the flat `tool_err` chain because the same literal
/// also arises for a missing local upload source.
fn decorate_read_missing_file(message: &str) -> String {
    let Some(path) = read_missing_file_path(message) else {
        return message.to_string();
    };
    if message.contains(READ_MISSING_FILE_TIP_MARKER) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {READ_MISSING_FILE_TIP_MARKER} — the node resolved `{path}` and checked \
         it with `symlink_metadata` before opening or streaming anything, so there is no such \
         entry on the node: the leaf is missing, or one of its parent directories is missing. \
         Retrying the same call unchanged fails identically; nothing was read, transferred, \
         written, or created. This is a missing-path failure, not a permission, grant, sandbox, \
         node-offline, or wrong-machine failure. The path is resolved on the node, not on this \
         machine: a relative `path` is joined to the node's working directory (or the node's \
         `--root` jail), `.` is not your local project, and `~` is not expanded — `~/notes.txt` \
         literally means `<node-cwd>/~/notes.txt`, so pass the absolute path (for example \
         `/home/<user>/notes.txt`) or a path relative to the node cwd. Check the parent with MCP \
         `list_dir` (CLI `agentlink ls <node> <dir>`) or the type with MCP `stat_path`; if you \
         only know the file name, locate it with MCP `search_files` (CLI `agentlink find <node> \
         <name>`). If you meant to create it, MCP `write_file` creates missing parent directories \
         (CLI `agentlink write <node> <path> --content <text>`), as does MCP `edit_lines` with \
         `start_line: 1` / CLI `agentlink edit-lines <node> <path> 1 1 <text>`; then retry. If you \
         meant a directory, list it instead — an existing directory returns the separate `is a \
         directory, not a file; use `ls` to list it` message. For `copy_path`, `path` is the node \
         source in `direction: \"download\"`; `direction: \"upload\"` instead checks `local` on \
         this machine, and `direction: \"peer\"` calls `stat_path` first, so a missing peer source \
         surfaces as a bare `io: No such file or directory (os error 2)` (different shape, left \
         alone). The same words with an `(os error 2)` suffix (dangling symlink target) or an \
         `io:` prefix (bare OS error) are different failures and are not matched. See `agentlink \
         guide <node>`."
    )
}

#[cfg(test)]
mod read_missing_file_tip_tests {
    use super::*;

    #[test]
    fn missing_read_gets_the_tip_once() {
        let raw = "/srv/app/notes.txt: No such file or directory";
        let out = decorate_read_missing_file(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {READ_MISSING_FILE_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(
            out.matches(READ_MISSING_FILE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "nothing was read",
            "`~` is not expanded",
            "list_dir",
            "stat_path",
            "search_files",
            "write_file",
            "start_line: 1",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(decorate_read_missing_file(&out), out);
    }

    #[test]
    fn resolved_relative_and_windows_paths_are_named() {
        for raw in [
            "/home/me/~/notes.txt: No such file or directory",
            "C:\\Users\\me\\notes.txt: No such file or directory",
        ] {
            let out = decorate_read_missing_file(raw);
            assert!(is_read_missing_file_error(raw), "{raw}");
            assert_eq!(
                out.matches(READ_MISSING_FILE_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            let path = raw.strip_suffix(READ_MISSING_FILE_SUFFIX).unwrap();
            assert!(out.contains(&format!("`{path}`")), "{raw}: {out}");
            assert_eq!(decorate_read_missing_file(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_enoent_and_type_errors_are_unchanged() {
        for raw in [
            "io: No such file or directory (os error 2)",
            "/srv/app/link: No such file or directory (os error 2)",
            "sandbox root: No such file or directory",
            "/srv/app/reports is a directory, not a file; use `ls` to list it",
            "/srv/app/current is a symlink to a directory, not a file; use directory copy",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
            "ls: path `/srv/app/x` does not exist",
            "not found: /srv/app/x",
            "program 'x' not found (No such file or directory (os error 2))",
            "cwd /tmp/missing: No such file or directory (os error 2)",
        ] {
            assert_eq!(decorate_read_missing_file(raw), raw, "{raw}");
        }
    }
}

const READ_DANGLING_SYMLINK_TIP_MARKER: &str =
    "`read_file`/`copy_path` download followed a dangling symlink on the node";
const READ_DANGLING_SYMLINK_SUFFIX: &str = ": No such file or directory (os error 2)";
const READ_DANGLING_SYMLINK_WINDOWS_SUFFIX: &str =
    ": The system cannot find the file specified. (os error 2)";

/// The node's `ensure_pullable_file` emits `<resolved path>: <io::Error>` when
/// the leaf exists as a symlink (`symlink_metadata` succeeds) but the target
/// does not resolve (`fs::metadata` fails ENOENT). Match only that full
/// `(os error 2)` suffix and reject the pathless `io:` form, the node startup
/// `sandbox root:` failure, and the `cwd `/`program ` exec forms.
fn read_dangling_symlink_path(message: &str) -> Option<&str> {
    let msg = message.trim_end();
    let path = msg
        .strip_suffix(READ_DANGLING_SYMLINK_SUFFIX)
        .or_else(|| msg.strip_suffix(READ_DANGLING_SYMLINK_WINDOWS_SUFFIX))?;
    if path.is_empty()
        || path.contains('\n')
        || msg.contains("io: ")
        || msg.contains("sandbox root:")
        || path.starts_with("cwd ")
        || path.starts_with("program ")
    {
        return None;
    }
    Some(path)
}

/// Append an actionable tip when MCP `read_file` or `copy_path` with
/// `direction: "download"` follows a dangling symlink on the node. Both call
/// sites know the path is a node source, so the tip's claims hold; it is
/// deliberately not part of the flat `tool_err` chain because the same literal
/// is also produced for a dangling local symlink in the upload arm.
fn decorate_read_dangling_symlink(message: &str) -> String {
    if message.contains(READ_DANGLING_SYMLINK_TIP_MARKER) {
        return message.to_string();
    }
    if read_dangling_symlink_path(message).is_none() {
        return message.to_string();
    }
    format!(
        "{message}. tip: {READ_DANGLING_SYMLINK_TIP_MARKER} — the node's \
         `ensure_pullable_file` used `symlink_metadata` on the resolved path, \
         which succeeded because the leaf itself is a symbolic link, then \
         followed it with `fs::metadata` and got ENOENT: the entry exists on \
         the node but the path it points to does not resolve — the target was \
         deleted, never deployed, or lives on a volume/mount that is not \
         present. Nothing was opened, read, transferred, written, or created, \
         and retrying the same call unchanged fails identically. This is a \
         node-side broken link, not a missing leaf, permission, grant, \
         sandbox, node-offline, or wrong-machine failure; do not confuse it \
         with the sibling `<path>: No such file or directory` message \
         (without `(os error 2)`), which means the node path itself does not \
         exist. Inspect it with MCP `stat_path`: a dangling link reports \
         `is_symlink: true` with `is_file: false` and `is_dir: false` (the \
         stat result does not include the link target), while MCP `list_dir` \
         (CLI `agentlink ls <node> <parent>`) shows the same entry with \
         `is_symlink: true`. To see what it points to, run `readlink <path>` \
         or `ls -l <path>` on the node via MCP `run_command` / CLI `agentlink \
         exec <node> --shell 'readlink <path>'` (needs exec permission), or \
         check the deployment. Fix the link — repoint it at an existing file, \
         or recreate its target — or read/list the real target path instead. \
         If the link is stale, `remove_path` (CLI `agentlink rm <node> \
         <path>`) unlinks only the symlink, never its target. If you meant to \
         create the missing target file, `write_file` on the link path follows \
         the link and creates the target when the target's parent directory \
         exists; create that parent first if it does not. Then retry. The path \
         above is node-resolved: a relative `path` is joined to the node cwd \
         (or the `--root` jail), `~` is not expanded, and a relative symlink \
         target is resolved against the link's directory on the node, not your \
         local project. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod read_dangling_symlink_tip_tests {
    use super::*;

    #[test]
    fn dangling_symlink_gets_the_tip_once() {
        let raw = "/srv/app/current: No such file or directory (os error 2)";
        let out = decorate_read_dangling_symlink(raw);
        assert!(
            out.starts_with(&format!(
                "{raw}. tip: {READ_DANGLING_SYMLINK_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(READ_DANGLING_SYMLINK_TIP_MARKER).count(),
            1,
            "{out}"
        );
        let lower = out.to_ascii_lowercase();
        for needle in [
            "symlink",
            "target",
            "nothing was opened",
            "stat_path",
            "is_symlink: true",
            "list_dir",
            "readlink",
            "remove_path",
            "write_file",
            "`~` is not expanded",
            "agentlink guide <node>",
        ] {
            assert!(lower.contains(needle), "{needle}: {out}");
        }
        assert_eq!(decorate_read_dangling_symlink(&out), out);
    }

    #[test]
    fn windows_and_relative_paths_are_named() {
        for raw in [
            "C:\\Users\\me\\AppData\\Local\\current: The system cannot find the file specified. \
             (os error 2)",
            "build/current: No such file or directory (os error 2)",
        ] {
            let out = decorate_read_dangling_symlink(raw);
            assert_eq!(
                out.matches(READ_DANGLING_SYMLINK_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert!(out.contains(raw), "{raw}: {out}");
            assert_eq!(decorate_read_dangling_symlink(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_forms_are_unchanged() {
        for raw in [
            "io: No such file or directory (os error 2)",
            "sandbox root: No such file or directory (os error 2)",
            "cwd /tmp/missing: No such file or directory (os error 2)",
            "program 'x' not found (No such file or directory (os error 2))",
            "/srv/app/notes.txt: No such file or directory",
            "/srv/app/link: Too many levels of symbolic links (os error 40)",
            "/srv/app/link: Permission denied (os error 13)",
            "/srv/app/current is a symlink to a directory, not a file; use directory copy",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
        ] {
            assert_eq!(decorate_read_dangling_symlink(raw), raw, "{raw}");
        }
    }
}

const READ_FILE_PERMISSION_TIP_MARKER: &str =
    "`read_file` was denied read access to the node file";

const READ_FILE_PERMISSION_FORMS: &[&str] = &[
    "io: Permission denied (os error 13)",
    "io: Access is denied. (os error 5)",
];

/// Whole-message equality only: the pathless `io:` line is shared by every node
/// op (`stat_path`, `copy_path`, `write_file`, `mkdir`, `remove_path`,
/// `move_path`, `list_dir`, the edit family), each with its own permission
/// treatment, and wrapped forms carry context this tip cannot attribute to the
/// caller's read. Keep the Windows sentence whole so Linux EIO
/// (`Input/output error (os error 5)`) stays raw.
fn is_read_file_permission_error(message: &str) -> bool {
    READ_FILE_PERMISSION_FORMS.contains(&message.trim_end())
}

/// Append an actionable tip when MCP `read_file` is refused with the pathless OS
/// permission line. The node-side pull-stream opens the caller's `path` for
/// reading, and the failure names neither node nor path, so the caller's labels
/// are interpolated here. Wired only at the `read_file` arm: the identical
/// `io:` line is produced by every other node op, each with its own tip, so the
/// flat `tool_err` chain and the CLI global chain must keep it raw. CLI `cat`
/// already tips via `hint_fs_error`. Idempotent.
fn decorate_read_file_permission(message: &str, node: &str, path: &str) -> String {
    if message.contains(READ_FILE_PERMISSION_TIP_MARKER) || !is_read_file_permission_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {READ_FILE_PERMISSION_TIP_MARKER} — MCP `read_file` (CLI `agentlink \
         cat`) asked the node `{node}` to stream the file `{path}`, and the node's process user \
         was refused by the OS. The raw line names neither the node nor the path; `{path}` is \
         the value you passed (a relative path is joined to the node working directory or the \
         `--root` jail; `~` is not expanded). Read access needs two independent gates: read \
         (`r`) on the file itself, and execute/search (`x`) on the file's directory and every \
         parent; failing either gate gives this same line. A `stat_path` call can still succeed \
         with only `x` on the parents because it reads the file's own metadata without opening \
         its contents, so a successful stat does not mean the file is readable (dogfood: on \
         `box`, `stat_path /etc/shadow` returned `mode` `33184`, i.e. `0o100640`, while \
         `read_file` was refused). Conversely, if `stat_path` on the file also returns this \
         line, suspect a parent directory that lacks `x`, or an LSM/ACL. Common cases are a \
         `0640 root:shadow` file such as `/etc/shadow`, a `0600` key such as \
         `~/.ssh/id_ed25519`, another user's `0700` home, a `0700`/`0710` service directory, \
         or any target under `/root`; on a node running as a service account this is routine, \
         and the same absolute path can be readable on one node and refused on another because \
         the node process user differs (dogfood: `box` denied `/etc/shadow`, `example` \
         returned it). Diagnose with MCP `stat_path` (decimal `mode`, e.g. `33184` is \
         `0o100640`) on the file and each parent, and with `run_command` / `agentlink exec \
         <node> -- stat -c '%A %U:%G %n' <path>` plus `id -un` (or `ls -ld <parent>`) to show \
         mode, owner, and the node user. Fix by granting the node user read on the file \
         (`chmod o+r <file>`, or `g+r` plus adding the node user to the owning group, e.g. \
         `sudo usermod -aG shadow <node-user>`), by `sudo chown <node-user> <file>`, or by \
         adding `x` to any parent that lacks it. If the node runs as a read-only service user, \
         ask the operator to grant access or copy the file to a readable location; \
         alternatively read it as a user with access through `run_command` / `agentlink exec` \
         with `sudo` when the node policy allows. On Windows there is no mode bit: `os error \
         5` means an ACL, AppLocker, AV, or protected location denies read on the file or \
         traverse on a parent; inspect with `icacls <path>` and grant the node user `(R)`. \
         Nothing was streamed and no file bytes were returned; the file was not modified, and \
         retrying unchanged fails identically. This is not a missing file (`…: No such file \
         or directory`, own tip), not a dangling symlink (`(os error 2)` suffix, own tip), \
         not a directory or directory-symlink read (own tips), not a fifo/socket/device \
         refusal, not a `--root` sandbox jail denial (its own message, with no `io:` prefix), \
         not a signed-grant/capability refusal, and not node-offline. See `agentlink guide \
         <node>`."
    )
}

#[cfg(test)]
mod read_file_permission_tip_tests {
    use super::*;

    const UNIX: &str = "io: Permission denied (os error 13)";
    const WINDOWS: &str = "io: Access is denied. (os error 5)";

    #[test]
    fn unix_eacces_gets_the_tip_once() {
        let out = decorate_read_file_permission(UNIX, "box", "/etc/shadow");
        assert!(
            out.starts_with(&format!(
                "{UNIX}. tip: {READ_FILE_PERMISSION_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(READ_FILE_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "box",
            "/etc/shadow",
            "read",
            "execute/search",
            "stat_path",
            "33184",
            "0o100640",
            "chmod",
            "icacls",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        for literal in ["{node}", "{path}", "{message}"] {
            assert!(!out.contains(literal), "{literal} literal left: {out}");
        }
        assert_eq!(decorate_read_file_permission(UNIX, "box", "/etc/shadow"), out);
        assert_eq!(
            decorate_read_file_permission(&out, "box", "/etc/shadow"),
            out,
            "second call must be byte-identical"
        );
    }

    #[test]
    fn windows_form_gets_the_tip() {
        let out = decorate_read_file_permission(WINDOWS, "box", "/etc/shadow");
        assert!(
            out.starts_with(&format!(
                "{WINDOWS}. tip: {READ_FILE_PERMISSION_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(READ_FILE_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("icacls"), "{out}");
        assert_eq!(decorate_read_file_permission(&out, "box", "/etc/shadow"), out);
    }

    #[test]
    fn exact_whole_message_only() {
        for raw in [
            "io: Permission denied (os error 13) extra",
            "exec x: io: Permission denied (os error 13)",
            "cat /etc/shadow: io: Permission denied (os error 13)",
            "/srv/app/link: Permission denied (os error 13)",
            "Permission denied (os error 13)",
            "io: Input/output error (os error 5)",
            "io: Operation not permitted (os error 1)",
            "io: No such file or directory (os error 2)",
            "/srv/app/notes.txt: No such file or directory",
            "/srv/app/link: No such file or directory (os error 2)",
            "/srv/app/reports is a directory, not a file; use `ls` to list it",
            "/srv/app/current is a symlink to a directory, not a file; use directory copy",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
            "io: Is a directory (os error 21)",
            "watch /root: Permission denied (os error 13) about [\"/root\"]",
            "permission denied: command denied by sandbox pattern 'sudo **'",
            "capability denied",
            "node offline: probe",
            "",
        ] {
            assert_eq!(
                decorate_read_file_permission(raw, "box", "/etc/shadow"),
                raw,
                "{raw}"
            );
        }

        let trailing = format!("{UNIX}\n");
        let out = decorate_read_file_permission(&trailing, "box", "/etc/shadow");
        assert_eq!(
            out.matches(READ_FILE_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn already_tipped_and_siblings_are_noops() {
        let out = decorate_read_file_permission(UNIX, "box", "/etc/shadow");
        assert_eq!(decorate_read_missing_file(&out), out);
        assert_eq!(decorate_read_dangling_symlink(&out), out);
        assert_eq!(decorate_read_target_is_directory(&out), out);
        assert_eq!(decorate_symlink_dir_read(&out), out);
        assert_eq!(
            decorate_list_dir_permission(&out, "box", "/etc/shadow"),
            out
        );
        assert_eq!(
            decorate_write_dest_permission(&out, "box", "/etc/shadow"),
            out
        );
        assert_eq!(
            decorate_mkdir_dest_permission(&out, "box", "/etc/shadow", false),
            out
        );
        assert_eq!(
            decorate_remove_dest_permission(&out, "box", "/etc/shadow", false),
            out
        );
        assert_eq!(
            decorate_mv_dest_permission(&out, "box", "/srv/a", "/etc/shadow"),
            out
        );
        assert_eq!(decorate_sandbox_path_escape(&out), out);
    }

    #[test]
    fn missing_and_dangling_decorators_still_run_first() {
        assert_eq!(decorate_read_missing_file(UNIX), UNIX);
        assert_eq!(decorate_read_dangling_symlink(UNIX), UNIX);
        assert_eq!(
            decorate_read_file_permission(
                &decorate_read_missing_file(UNIX),
                "box",
                "/etc/shadow"
            ),
            decorate_read_file_permission(UNIX, "box", "/etc/shadow")
        );
    }
}

const COPY_SPECIAL_FILE_TIP_MARKER: &str =
    "read_file and copy_path stream regular files only, not fifos, sockets, or devices";
const COPY_SPECIAL_FILE_SUFFIX: &str =
    " is not a regular file (refusing fifo/socket/device)";

/// The node/client guards (`ensure_pullable_file`, `copy_download`,
/// `copy_node_to_node`) all emit this exact suffix. It is shared by `copy_path`
/// upload/download/peer and MCP `read_file`; match the full suffix so the CLI
/// EISDIR text and the directory/symlink-to-directory messages stay untouched.
fn is_copy_special_file_error(message: &str) -> bool {
    message.contains(COPY_SPECIAL_FILE_SUFFIX)
}

/// Append an actionable tip when MCP `read_file` / `copy_path` hits a FIFO,
/// Unix socket, or device. The raw message names only the source and the
/// refusal category; this says nothing was transferred, retrying is pointless,
/// and how to inspect or bounded-read the path. Idempotent, and leaves the CLI
/// fs-hint outputs alone (their call sites already append a shorter tip).
fn decorate_copy_special_file(message: &str) -> String {
    if message.contains(COPY_SPECIAL_FILE_TIP_MARKER)
        || message.contains("not devices, fifos, or sockets")
        || !is_copy_special_file_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {COPY_SPECIAL_FILE_TIP_MARKER} — the source was refused before any \
         bytes were read, so nothing was streamed and the destination was not updated. A \
         FIFO/pipe, Unix socket, or character/block device is not a finite regular file: a FIFO \
         or socket with no peer can block open/read indefinitely, and devices such as /dev/zero \
         or /dev/random never reach EOF (or have side effects). Retrying `read_file`/`copy_path` \
         unchanged fails identically, and this is not a permission, grant, sandbox, \
         node-offline, or missing-path error. The path above is the source (a local path for \
         `copy_path` upload; a node path for `read_file`, download, and peer). Check its type \
         with MCP `stat_path` — a special file reports `is_file: false` and `is_dir: false` \
         (`is_symlink: false` when the path itself is the fifo/socket/device; `is_symlink: true` \
         with the same false pair when it points at one) — or inspect the parent with \
         `list_dir`. If the path is a symlink to a regular file, pass the resolved target \
         instead (a symlink to a regular file is accepted). Otherwise there is no finite payload \
         to copy: use `run_command` on the node with a bounded read (for example `head -c 65536 \
         <path> > /tmp/capture.bin`, or `dd if=<path> of=/tmp/capture.bin bs=4096 count=16`) \
         and then `read_file`/`copy_path` that regular output file; for a socket or FIFO, use \
         the service/protocol that owns it rather than reading the node. A directory source is \
         different: `copy_path` copies its regular files, subdirectories, and symlinks and \
         silently omits special entries, so this error only appears when the \
         fifo/socket/device is the explicit source. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod copy_special_file_tip_tests {
    use super::*;

    #[test]
    fn socket_fifo_and_device_forms_get_the_tip_once() {
        for raw in [
            "/srv/app/run/app.sock is not a regular file (refusing fifo/socket/device)",
            "/tmp/capture.pipe is not a regular file (refusing fifo/socket/device)",
            "/dev/zero is not a regular file (refusing fifo/socket/device)",
            "/srv/app/current is not a regular file (refusing fifo/socket/device)",
        ] {
            let out = decorate_copy_special_file(raw);
            assert!(
                out.starts_with(&format!("{raw}. tip: {COPY_SPECIAL_FILE_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(
                out.matches(COPY_SPECIAL_FILE_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "read_file",
                "copy_path",
                "stat_path",
                "list_dir",
                "run_command",
                "head -c",
                "dd if=",
                "not a permission",
                "silently omits",
                "agentlink guide <node>",
            ] {
                assert!(out.contains(needle), "{needle}: {out}");
            }
            assert_eq!(decorate_copy_special_file(&out), out);
        }
    }

    #[test]
    fn prefixed_and_suffixed_forms_are_idempotent() {
        for raw in [
            "read_file: /srv/app/x is not a regular file (refusing fifo/socket/device)",
            "/srv/app/x is not a regular file (refusing fifo/socket/device) Did you mean ...?",
        ] {
            let out = decorate_copy_special_file(raw);
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert_eq!(
                out.matches(COPY_SPECIAL_FILE_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(decorate_copy_special_file(&out), out, "{raw}");
        }
    }

    #[test]
    fn cli_hint_and_siblings_are_unchanged() {
        let raw = "/srv/app/run/app.sock is not a regular file (refusing fifo/socket/device)";
        for kind in [FsHint::Cp, FsHint::Cat, FsHint::Write] {
            let already = hint_fs_error(raw, kind).to_string();
            assert_eq!(decorate_copy_special_file(&already), already, "{already}");
        }
        for raw in [
            "/srv/app/reports is a directory, not a file; use `ls` to list it",
            "/srv/app/link is a symlink to a directory, not a file; use directory copy",
            "/srv/app/missing: No such file or directory (os error 2)",
            "path component `/srv/app/file` exists but is not a directory",
            "max_bytes 67108865 exceeds the 67108864 byte limit",
            "patch exceeds 1 MiB",
        ] {
            assert_eq!(decorate_copy_special_file(raw), raw, "{raw}");
        }
    }
}

const COPY_UPLOAD_LOCAL_MISSING_TIP_MARKER: &str =
    "`copy_path` upload reads `local` on the machine running the CLI/MCP server, not on the node";
const COPY_UPLOAD_LOCAL_MISSING_SUFFIX: &str = ": No such file or directory";

/// `copy_upload` runs `ensure_pullable_file(local)` before it dials the node,
/// and that custom form has no `io:` prefix and no `(os error N)` suffix.
/// Reject the `io:` form, every `io::Error` display including the
/// dangling-symlink variant, and the node startup `sandbox root:` failure.
/// The node-side bare form is textually identical, so this must only be wired
/// at the upload call site, never in the flat `tool_err` chain.
fn copy_upload_missing_local_path(message: &str) -> Option<&str> {
    let msg = message.trim_end();
    let path = msg.strip_suffix(COPY_UPLOAD_LOCAL_MISSING_SUFFIX)?;
    if path.is_empty()
        || path.contains('\n')
        || msg.contains("io: ")
        || msg.contains("(os error")
        || msg.contains("sandbox root:")
    {
        return None;
    }
    Some(path)
}

/// Append an actionable tip when MCP `copy_path` with `direction: "upload"`
/// names a missing local source. The upload arm is the only client call site
/// where `ensure_pullable_file(local)` is guaranteed to have run on `local`
/// before any node contact, so a bare ENOENT here is always the local file.
fn decorate_copy_upload_missing_local(message: &str) -> String {
    if copy_upload_missing_local_path(message).is_none() {
        return message.to_string();
    }
    if message.contains(COPY_UPLOAD_LOCAL_MISSING_TIP_MARKER) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {COPY_UPLOAD_LOCAL_MISSING_TIP_MARKER} — `local` names a path on this \
         machine (the process running the agentlink CLI/MCP server), while `path` names the \
         destination on the node. The client checked the local source with `symlink_metadata` \
         and found no such entry — the leaf is missing, or one of its parent directories is \
         missing — and it refused before dialing the node or starting the transfer: nothing was \
         read, sent, written, or created, and retrying the same call unchanged fails identically. \
         This is not a node-side missing path, permission, grant, sandbox, or node-offline \
         failure; do not go list, stat, search, or create anything on the node. A relative \
         `local` is resolved against the MCP server's (or CLI's) current working directory, not \
         the node and not your editor/project workspace, and `~` is not expanded — pass the \
         absolute local path (for example `/home/<user>/app.tgz`). Check the file in your own \
         shell / `ls`, or upload a directory that actually exists (the same message appears when \
         the missing `local` is a directory). If you meant to fetch a node file, use \
         `direction: \"download\"` (`path` is then the node source and `local` is the local save \
         path). If you have the content in hand, MCP `write_file` writes it directly to the node \
         (creating missing parents) and needs no local source. A local FIFO/socket/device or \
         symlink-to-directory returns a different message; the `(os error 2)` form (`<local>: \
         No such file or directory (os error 2)`) is a dangling local symlink and gets the \
         separate local dangling-symlink tip at the upload call site. \
         See `agentlink guide <node>`."
    )
}

const COPY_UPLOAD_DANGLING_LOCAL_TIP_MARKER: &str =
    "`copy_path` upload `local` is a dangling symlink on this machine, not the node";
const COPY_UPLOAD_DANGLING_LOCAL_SUFFIX: &str = ": No such file or directory (os error 2)";
const COPY_UPLOAD_DANGLING_LOCAL_WINDOWS_SUFFIX: &str =
    ": The system cannot find the file specified. (os error 2)";
const COPY_UPLOAD_DANGLING_LOCAL_WINDOWS_PATH_SUFFIX: &str =
    ": The system cannot find the path specified. (os error 3)";

/// `ensure_pullable_file(local)` follows a symlink leaf with `fs::metadata` and
/// returns `<local>: <io::Error>` (ENOENT) when the target does not resolve.
/// This is the *local* mirror of `read_dangling_symlink_path`: the literal is
/// identical, so this must only be wired at the upload call site, never in the
/// flat `tool_err` chain. Reject the pathless `io:` form, the node startup
/// `sandbox root:` failure, and the `cwd `/`program ` exec forms.
fn copy_upload_dangling_local_path(message: &str) -> Option<&str> {
    let msg = message.trim_end();
    let path = msg
        .strip_suffix(COPY_UPLOAD_DANGLING_LOCAL_SUFFIX)
        .or_else(|| msg.strip_suffix(COPY_UPLOAD_DANGLING_LOCAL_WINDOWS_SUFFIX))
        .or_else(|| msg.strip_suffix(COPY_UPLOAD_DANGLING_LOCAL_WINDOWS_PATH_SUFFIX))?;
    if path.is_empty()
        || path.contains('\n')
        || msg.contains("io: ")
        || msg.contains("sandbox root:")
        || path.starts_with("cwd ")
        || path.starts_with("program ")
    {
        return None;
    }
    Some(path)
}

/// Append an actionable tip when MCP `copy_path` with `direction: "upload"`
/// names a `local` path that is a dangling symlink on this machine. The upload
/// arm is the only client call site where the `ensure_pullable_file(local)`
/// guard is guaranteed to have run on `local` before any node contact, so the
/// `(os error 2)` form here is always the local source, not a node path.
fn decorate_copy_upload_dangling_local(message: &str) -> String {
    if message.contains(COPY_UPLOAD_DANGLING_LOCAL_TIP_MARKER) || message.contains("Did you mean") {
        return message.to_string();
    }
    let Some(path) = copy_upload_dangling_local_path(message) else {
        return message.to_string();
    };
    format!(
        "{message}. tip: {COPY_UPLOAD_DANGLING_LOCAL_TIP_MARKER} — `local` is a path on this \
         machine (the process running the agentlink CLI/MCP server), not on the node. The \
         client's local `ensure_pullable_file` guard used `symlink_metadata` on {path}, which \
         succeeded because the leaf itself is a symbolic link, then followed it with \
         `fs::metadata` and got ENOENT: the link exists locally but the path it points to does \
         not resolve, so there is no file content to stream to the node. The guard runs before \
         the transfer starts: no node operation was sent for this copy, nothing was read, \
         hashed, compressed, or uploaded, and `path` on the node was not created or modified. \
         Retrying the same call unchanged fails identically, and this is not a node-side \
         missing path, permission, grant, sandbox, node-offline, or wrong-machine failure — do \
         not stat, list, search, or create anything on the node for it. Inspect the link in \
         your own shell: `ls -l {path}` shows the entry and its target, and `readlink {path}` \
         (or `readlink -f {path}` / `realpath {path}`) prints the target that does not exist. \
         Then either repair the target (build/copy it to the expected location) or repoint the \
         link with `ln -sfn <existing-file> {path}`, or pass the resolved target path as \
         `local` (an existing regular file or link-to-regular-file uploads normally). If the \
         content lives at another local path, upload that path instead. `copy_path` streams a \
         regular file's bytes; it does not transfer the link itself — to create a symlink on \
         the node, use `run_command` with `ln -s <target> <path>` (needs exec permission), or \
         `write_file` the content to the node path. The sibling message `{path}: No such file \
         or directory` (without ` (os error 2)`) means the local leaf or one of its parent \
         directories does not exist at all; a node-side dangling symlink for `direction: \
         \"download\"`/`read_file` produces the same `(os error 2)` wording but refers to a \
         node path (already tipped separately) — for `direction: \"upload\"`, `local` is always \
         evaluated on this machine. A symlink loop (`Too many levels of symbolic links (os \
         error 40)`) or an unreadable target (`Permission denied (os error 13)`) is a different \
         failure and is not matched. A relative `local` is resolved against the MCP server's \
         (or CLI's) current working directory, not the node and not your editor workspace, and \
         `~` is not expanded. See `agentlink guide <node>`."
    )
}

const COPY_PEER_SOURCE_MISSING_TIP_MARKER: &str =
    "`copy_path` direction \"peer\" could not stat the source `path` on `node`, so nothing was copied";
const COPY_PEER_SOURCE_MISSING_LINUX: &str = "io: No such file or directory (os error 2)";
const COPY_PEER_SOURCE_MISSING_WINDOWS_FILE: &str =
    "io: The system cannot find the file specified. (os error 2)";
const COPY_PEER_SOURCE_MISSING_WINDOWS_PATH: &str =
    "io: The system cannot find the path specified. (os error 3)";

/// The pathless `Error::Io` display carries no path at all. This literal is
/// shared by many MCP ops (`stat_path`, `remove_path`, `replace_text`, …) and
/// pinned raw by `tool_err_leaves_bare_io_enoent_alone`, so the match must be
/// exact and the decorator may only run at the `copy_path` "peer" call site,
/// where `copy_node_to_node` is known to stat the source before any transfer.
fn is_copy_peer_source_missing(message: &str) -> bool {
    let msg = message.trim_end();
    msg == COPY_PEER_SOURCE_MISSING_LINUX
        || msg == COPY_PEER_SOURCE_MISSING_WINDOWS_FILE
        || msg == COPY_PEER_SOURCE_MISSING_WINDOWS_PATH
}

/// Append an actionable tip when MCP `copy_path` with `direction: "peer"`
/// cannot stat the source during its preflight. The raw `io::Error` has no
/// path, so the four call arguments are the only way to name what failed.
fn decorate_copy_peer_source_missing(
    message: &str,
    src_node: &str,
    src_path: &str,
    dst_node: &str,
    dst_path: &str,
) -> String {
    if message.contains(COPY_PEER_SOURCE_MISSING_TIP_MARKER)
        || !is_copy_peer_source_missing(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {COPY_PEER_SOURCE_MISSING_TIP_MARKER} — for `direction: \"peer\"`, `node` \
         and `path` are the source and `dst_node`/`dst_path` are the destination. The client \
         resolves both nodes, then stats the source with `Op::Stat` before it opens any data \
         link; that stat returned ENOENT, and an `io::Error`'s display carries no path, which is \
         why the message names none of the four arguments. The copy stopped at that preflight \
         check: no bytes were read from {src_node}:{src_path}, no bridge temp file was created, \
         and nothing was written to {dst_node}:{dst_path}. Retrying unchanged fails identically; \
         this is not a permission, grant, sandbox, node-offline, ambiguous-name, or \
         destination-missing failure — a bad `dst_node` fails earlier as a missing/offline node, \
         and the receiver creates missing destination directories during the transfer, so this \
         is not about `dst_path`. Check the source first: MCP `stat_path` with `node: \
         \"{src_node}\", path: \"{src_path}\"` (or `list_dir` on its parent) shows whether it \
         exists and what it is. Common causes: the path is relative and resolves against the \
         node daemon's working directory (or the sandbox root), not `/` and not your editor \
         workspace; `~` is not expanded, so pass an absolute path; `node` and `dst_node` are \
         swapped; the path lives on the other node or on this machine; or it was renamed, \
         cleaned, or built under a different directory. If the content is local, use `direction: \
         \"upload\"`; if it should exist on the source, build it there with `run_command` first. \
         A named `{src_path}: No such file or directory (os error 2)` is a dangling symlink on \
         the source (the stat succeeds and the stream later fails), and `not found: parent \
         directory does not exist: <dir>` means the source's parent is missing inside the node's \
         sandbox root — neither is this pathless form. See `agentlink guide <node>`."
    )
}

const COPY_PEER_DANGLING_SOURCE_TIP_MARKER: &str =
    "`copy_path` direction \"peer\" followed a dangling symlink on the source `node`";

/// The named `(os error 2)` literal is shared with the read/download and
/// upload-local arms, so this decorator may only run at the `copy_path` "peer"
/// call site, where `ensure_pullable_file` is known to have followed a source
/// symlink whose target does not resolve.
fn decorate_copy_peer_dangling_source(
    message: &str,
    src_node: &str,
    src_path: &str,
    dst_node: &str,
    dst_path: &str,
) -> String {
    if message.contains(COPY_PEER_DANGLING_SOURCE_TIP_MARKER)
        || message.contains(READ_DANGLING_SYMLINK_TIP_MARKER)
    {
        return message.to_string();
    }
    // `read_dangling_symlink_path` covers the Linux and Windows-file suffixes;
    // the upload-local parser is the same literal plus Windows `(os error 3)`.
    let Some(resolved) =
        read_dangling_symlink_path(message).or_else(|| copy_upload_dangling_local_path(message))
    else {
        return message.to_string();
    };
    format!(
        "{message}. tip: {COPY_PEER_DANGLING_SOURCE_TIP_MARKER} — for `direction: \"peer\"`, \
         `node` and `path` are the source and `dst_node`/`dst_path` are the destination. The \
         preflight `Op::Stat` used `symlink_metadata` on the source path, which succeeded \
         because the leaf itself is a symbolic link: it reported `is_symlink: true` with \
         `is_file: false` and `is_dir: false`, so the missing-leaf guard did not fire. The \
         source node's `ensure_pullable_file` then followed the link with `fs::metadata` and \
         got ENOENT, returning `{resolved}: ... (os error 2)`; `{resolved}` is the \
         node-resolved absolute path and can differ from `path` under a `--root` sandbox. The \
         guard runs before the source opens or hashes anything: no bytes were read from \
         {src_node}:{src_path}, nothing was written to {dst_node}:{dst_path}, and the local \
         bridge fallback stopped at the same guard before uploading. Retrying the same call \
         unchanged fails identically. This is not the pathless `io: ... (os error 2)` form (the \
         preflight stat saw no leaf or parent; already tipped), not the plain `{src_path}: No \
         such file or directory` without `(os error 2)` (the leaf or a parent never existed, or \
         vanished mid-copy), and not a permission, grant, sandbox-escape, node-offline, \
         ambiguous-name, or wrong-machine failure — both nodes resolved and the preflight stat \
         succeeded. Inspect it with MCP `stat_path` (`node: \"{src_node}\", path: \
         \"{src_path}\"`): a dangling link reports `is_symlink: true`, `is_file: false`, \
         `is_dir: false`, and `list_dir` on the parent shows the same entry. To see the missing \
         target, run `readlink {src_path}` or `ls -l {src_path}` on the node via MCP \
         `run_command` (needs exec permission). Repair or recreate the target, repoint the \
         link, or pass the resolved target path as `path`. `remove_path` unlinks only the link, \
         never its target. `write_file` on the link path follows it and creates the target when \
         the target's parent directory exists (create that parent first otherwise). `copy_path` \
         copies file bytes, not the link; to recreate a link on the node use `run_command` with \
         `ln -s <target> <path>`. If the content is local, use `direction: \"upload\"`. A \
         relative `path` is joined to the node cwd (or the `--root` jail), `~` is not expanded, \
         and a relative symlink target resolves against the link's directory on the node. See \
         `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod copy_upload_missing_local_tip_tests {
    use super::*;

    #[test]
    fn upload_missing_local_gets_the_tip_once() {
        let raw = "/home/me/app.tgz: No such file or directory";
        let out = decorate_copy_upload_missing_local(raw);
        assert!(
            out.starts_with(&format!(
                "{raw}. tip: {COPY_UPLOAD_LOCAL_MISSING_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(COPY_UPLOAD_LOCAL_MISSING_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "local",
            "path",
            "direction: \"download\"",
            "`~` is not expanded",
            "absolute local path",
            "write_file",
            "before dialing the node",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(decorate_copy_upload_missing_local(&out), out);
    }

    #[test]
    fn relative_windows_and_directory_forms_are_named() {
        for raw in [
            "build/app.tgz: No such file or directory",
            "C:\\Users\\me\\app.tgz: No such file or directory",
            "/srv/app/reports: No such file or directory",
        ] {
            let out = decorate_copy_upload_missing_local(raw);
            assert!(
                out.starts_with(&format!(
                    "{raw}. tip: {COPY_UPLOAD_LOCAL_MISSING_TIP_MARKER} — "
                )),
                "{out}"
            );
            assert_eq!(
                out.matches(COPY_UPLOAD_LOCAL_MISSING_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert_eq!(decorate_copy_upload_missing_local(&out), out, "{raw}");
        }
    }

    #[test]
    fn io_os_error_and_sandbox_forms_are_unchanged() {
        // The node-side bare form (`"/srv/app/notes.txt: No such file or
        // directory"`) matches this function by design; correctness comes from
        // wiring it only at the upload call site, not from a function-level
        // negative test.
        for raw in [
            "io: No such file or directory (os error 2)",
            "/srv/app/link: No such file or directory (os error 2)",
            "sandbox root: No such file or directory",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
            "path component `/srv/app/file` exists but is not a directory",
            "parent directory does not exist: /srv/app",
        ] {
            assert_eq!(decorate_copy_upload_missing_local(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod copy_upload_dangling_local_tip_tests {
    use super::*;

    #[test]
    fn dangling_local_upload_gets_the_tip_once() {
        let raw = "/home/me/current: No such file or directory (os error 2)";
        let out = decorate_copy_upload_dangling_local(raw);
        assert!(
            out.starts_with(&format!(
                "{raw}. tip: {COPY_UPLOAD_DANGLING_LOCAL_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(COPY_UPLOAD_DANGLING_LOCAL_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "this machine",
            "symlink",
            "target",
            "no node operation was sent",
            "nothing was read",
            "do not stat, list, search, or create anything on the node",
            "ls -l",
            "readlink",
            "ln -sfn",
            "direction: \"download\"",
            "`~` is not expanded",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(decorate_copy_upload_dangling_local(&out), out);
    }

    #[test]
    fn windows_relative_and_path_not_found_forms_are_named() {
        for raw in [
            "build/current: No such file or directory (os error 2)",
            "C:\\Users\\me\\current: The system cannot find the file specified. (os error 2)",
            "C:\\Users\\me\\current: The system cannot find the path specified. (os error 3)",
        ] {
            let out = decorate_copy_upload_dangling_local(raw);
            assert!(
                out.starts_with(&format!(
                    "{raw}. tip: {COPY_UPLOAD_DANGLING_LOCAL_TIP_MARKER} — "
                )),
                "{raw}: {out}"
            );
            assert_eq!(
                out.matches(COPY_UPLOAD_DANGLING_LOCAL_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert_eq!(decorate_copy_upload_dangling_local(&out), out, "{raw}");
        }
    }

    #[test]
    fn siblings_and_already_tipped_forms_are_unchanged() {
        for raw in [
            "/home/me/app.tgz: No such file or directory",
            "io: No such file or directory (os error 2)",
            "sandbox root: No such file or directory (os error 2)",
            "cwd /tmp/missing: No such file or directory (os error 2)",
            "program 'x' not found (No such file or directory (os error 2))",
            "/srv/app/link: Too many levels of symbolic links (os error 40)",
            "/srv/app/link: Permission denied (os error 13)",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
            "/srv/app/link is a symlink to a directory, not a file; use directory copy",
        ] {
            assert_eq!(decorate_copy_upload_dangling_local(raw), raw, "{raw}");
        }
        // The two call-site decorators are disjoint: each leaves the other's
        // positive fixture untouched.
        let raw_dangling = "/home/me/current: No such file or directory (os error 2)";
        let raw_missing_leaf = "/home/me/app.tgz: No such file or directory";
        assert_eq!(
            decorate_copy_upload_missing_local(raw_dangling),
            raw_dangling
        );
        assert_eq!(
            decorate_copy_upload_dangling_local(raw_missing_leaf),
            raw_missing_leaf
        );
    }
}

#[cfg(test)]
mod copy_peer_source_missing_tip_tests {
    use super::*;

    #[test]
    fn peer_source_missing_gets_the_tip_once() {
        let raw = "io: No such file or directory (os error 2)";
        let out = decorate_copy_peer_source_missing(
            raw,
            "builder",
            "/srv/app/dist",
            "prod",
            "/srv/www/releases",
        );
        assert!(
            out.starts_with(&format!(
                "{raw}. tip: {COPY_PEER_SOURCE_MISSING_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(COPY_PEER_SOURCE_MISSING_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "builder",
            "/srv/app/dist",
            "prod",
            "/srv/www/releases",
            "source",
            "stat_path",
            "list_dir",
            "no bytes were read",
            "nothing was written",
            "`~` is not expanded",
            "direction: \"upload\"",
            "run_command",
            "sandbox root",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(
            decorate_copy_peer_source_missing(
                &out,
                "builder",
                "/srv/app/dist",
                "prod",
                "/srv/www/releases"
            ),
            out
        );
    }

    #[test]
    fn windows_forms_are_named() {
        for raw in [
            "io: The system cannot find the file specified. (os error 2)",
            "io: The system cannot find the path specified. (os error 3)",
        ] {
            let out = decorate_copy_peer_source_missing(
                raw,
                "builder",
                "/srv/app/dist",
                "prod",
                "/srv/www",
            );
            assert!(
                out.starts_with(&format!(
                    "{raw}. tip: {COPY_PEER_SOURCE_MISSING_TIP_MARKER} — "
                )),
                "{raw}: {out}"
            );
            assert_eq!(
                out.matches(COPY_PEER_SOURCE_MISSING_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert_eq!(
                decorate_copy_peer_source_missing(
                    &out,
                    "builder",
                    "/srv/app/dist",
                    "prod",
                    "/srv/www"
                ),
                out,
                "{raw}"
            );
        }
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "/srv/app/current: No such file or directory (os error 2)",
            "not found: parent directory does not exist: /srv/app",
            "io: No such file or directory",
            "sandbox root: No such file or directory (os error 2)",
            "io: Not a directory (os error 20)",
            "io: Permission denied (os error 13)",
            "io: Too many levels of symbolic links (os error 40)",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
            "node offline: builder",
            "ambiguous node name 'web'",
        ] {
            assert_eq!(
                decorate_copy_peer_source_missing(
                    raw,
                    "builder",
                    "/srv/app/dist",
                    "prod",
                    "/srv/www"
                ),
                raw,
                "{raw}"
            );
        }
    }
}

#[cfg(test)]
mod copy_peer_dangling_source_tip_tests {
    use super::*;

    #[test]
    fn peer_dangling_source_gets_the_tip_once() {
        let raw = "/srv/app/current: No such file or directory (os error 2)";
        let out = decorate_copy_peer_dangling_source(
            raw,
            "builder",
            "/srv/app/current",
            "prod",
            "/srv/www/releases",
        );
        assert!(
            out.starts_with(&format!(
                "{raw}. tip: {COPY_PEER_DANGLING_SOURCE_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(COPY_PEER_DANGLING_SOURCE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "builder",
            "/srv/app/current",
            "prod",
            "/srv/www/releases",
            "source",
            "is_symlink: true",
            "stat_path",
            "readlink",
            "remove_path",
            "write_file",
            "direction: \"upload\"",
            "no bytes were read",
            "nothing was written",
            "bridge",
            "sandbox",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(
            decorate_copy_peer_dangling_source(
                &out,
                "builder",
                "/srv/app/current",
                "prod",
                "/srv/www/releases"
            ),
            out
        );
    }

    #[test]
    fn windows_forms_are_named() {
        for raw in [
            "/srv/app/current: The system cannot find the file specified. (os error 2)",
            "/srv/app/current: The system cannot find the path specified. (os error 3)",
        ] {
            let out = decorate_copy_peer_dangling_source(
                raw,
                "builder",
                "/srv/app/current",
                "prod",
                "/srv/www",
            );
            assert!(
                out.starts_with(&format!(
                    "{raw}. tip: {COPY_PEER_DANGLING_SOURCE_TIP_MARKER} — "
                )),
                "{raw}: {out}"
            );
            assert_eq!(
                out.matches(COPY_PEER_DANGLING_SOURCE_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert_eq!(
                decorate_copy_peer_dangling_source(
                    &out,
                    "builder",
                    "/srv/app/current",
                    "prod",
                    "/srv/www"
                ),
                out,
                "{raw}"
            );
        }
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "io: No such file or directory (os error 2)",
            "/srv/app/current: No such file or directory",
            "not found: parent directory does not exist: /srv/app",
            "sandbox root: No such file or directory (os error 2)",
            "/srv/app: Permission denied (os error 13)",
            "/srv/app/loop: Too many levels of symbolic links (os error 40)",
            "/srv/app/current is a symlink to a directory, not a file; use directory copy",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
            "node offline: builder",
            "ambiguous node name 'web'",
        ] {
            assert_eq!(
                decorate_copy_peer_dangling_source(
                    raw,
                    "builder",
                    "/srv/app/current",
                    "prod",
                    "/srv/www"
                ),
                raw,
                "{raw}"
            );
        }
    }

    #[test]
    fn peer_decorators_are_disjoint() {
        let named = "/srv/app/current: No such file or directory (os error 2)";
        assert_eq!(
            decorate_copy_peer_source_missing(
                named,
                "builder",
                "/srv/app/current",
                "prod",
                "/srv/www"
            ),
            named
        );
        let pathless = "io: No such file or directory (os error 2)";
        assert_eq!(
            decorate_copy_peer_dangling_source(
                pathless,
                "builder",
                "/srv/app/current",
                "prod",
                "/srv/www"
            ),
            pathless
        );
    }
}

const COPY_DIRECTION_TIP_MARKER: &str = "copy_path direction must be upload, download, or peer";

/// True for MCP `copy_path`'s rejection of an unknown `direction`. The raw
/// message is `direction must be upload, download, or peer, got <value>`; the
/// prefix is matched exactly and the trailing value must be non-empty so a
/// truncated `… got ` on its own does not match.
fn is_copy_direction_error(message: &str) -> bool {
    message
        .strip_prefix("direction must be upload, download, or peer, got ")
        .is_some_and(|got| !got.is_empty())
}

/// Append an actionable tip when MCP `copy_path` receives a value outside
/// `upload` / `download` / `peer`. The raw message names no valid mapping and
/// never says nothing was transferred. Operation-general because the raw
/// message names no path or node. Idempotent.
fn decorate_copy_direction(message: &str) -> String {
    if message.contains(COPY_DIRECTION_TIP_MARKER) || !is_copy_direction_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {COPY_DIRECTION_TIP_MARKER} — `direction` is a required string on MCP \
         `copy_path`, and only three values are accepted, each naming a source and a \
         destination: `upload` copies local → node (`path` is the remote destination and \
         `local` is the local source), `download` copies node → local (`path` is the remote \
         source and `local` is the local destination), and `peer` copies node → node (`path` on \
         `node` is the source, plus `dst_node` / `dst_path`). Invented verbs (for example \
         `sideways`, `sync`, `pull`, `push`) fail the same way, and the value is \
         case-sensitive. `direction` is validated before any transfer starts, so nothing was \
         copied in either direction and retrying the same value fails identically. This is \
         input validation, not a permission, grant, sandbox, node-offline, or timeout failure. \
         See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod copy_direction_tip_tests {
    use super::*;

    #[test]
    fn copy_direction_gets_the_tip_once() {
        for raw in [
            "direction must be upload, download, or peer, got sideways",
            "direction must be upload, download, or peer, got sync",
            "direction must be upload, download, or peer, got pull",
            "direction must be upload, download, or peer, got push",
        ] {
            let out = decorate_copy_direction(raw);
            assert!(
                out.starts_with(&format!("{raw}. tip: {COPY_DIRECTION_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(
                out.matches(COPY_DIRECTION_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "`upload`",
                "local → node",
                "`download`",
                "node → local",
                "`peer`",
                "node → node",
                "`dst_node`",
                "`dst_path`",
                "sideways",
                "sync",
                "case-sensitive",
                "before any transfer starts",
                "not a permission, grant, sandbox, node-offline, or timeout failure",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_copy_direction(&out), out);
        }
    }

    #[test]
    fn copy_direction_leaves_siblings_alone() {
        for raw in [
            "env.PORT must be a string",
            "missing `path`",
            "stat_path: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
            "unknown terminal abc",
            "direction must be upload, download, or peer, got ",
            "Direction must be upload, download, or peer, got sideways",
        ] {
            assert_eq!(decorate_copy_direction(raw), raw, "{raw}");
        }
    }
}

const COMPRESS_VALUE_TIP_MARKER: &str = "compress must be exactly auto, on, or off";

/// MCP `copy_path` includes the rejected string after `got`; the CLI uses a
/// shorter message without it. Require one non-empty, single-line value so the
/// CLI form, wrapped errors, and multiline lookalikes stay raw.
fn is_compress_value_error(message: &str) -> bool {
    message
        .trim()
        .strip_prefix("compress must be auto, on, or off, got ")
        .is_some_and(|got| {
            !got.is_empty() && !got.bytes().any(|byte| matches!(byte, b'\r' | b'\n'))
        })
}

/// Explain the accepted compression policy and that an invalid value stopped
/// the copy before direction dispatch or any source read. Idempotent.
fn decorate_compress_value(message: &str) -> String {
    if message.contains(COMPRESS_VALUE_TIP_MARKER) || !is_compress_value_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {COMPRESS_VALUE_TIP_MARKER} — MCP `copy_path` accepts only the \
         lowercase JSON strings `\"auto\"`, `\"on\"`, and `\"off\"`; values such as `\"yes\"`, \
         `\"true\"`, `\"ON\"`, or `\"gzip\"` are not aliases. Omit `compress` for `auto`, which \
         lets the transport choose and skips formats that are already compressed; use `\"on\"` \
         to force compression or `\"off\"` to disable it. Use the string `\"on\"`, not boolean \
         `true`: a non-string `compress` is treated as omitted and selects `auto`, rather than \
         forcing compression. The value is validated before direction dispatch, so no source \
         was read, nothing was transferred, and retrying unchanged fails identically. This is \
         input validation, not a permission, grant, sandbox, node-offline, disk, or timeout \
         failure. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod compress_value_tip_tests {
    use super::*;

    #[test]
    fn invalid_compress_gets_the_tip_once() {
        for raw in [
            "compress must be auto, on, or off, got yes",
            "compress must be auto, on, or off, got ON",
            "compress must be auto, on, or off, got gzip",
            "compress must be auto, on, or off, got auto ",
            "  compress must be auto, on, or off, got true\n",
        ] {
            let out = decorate_compress_value(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(out.matches(COMPRESS_VALUE_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "`copy_path`",
                "lowercase JSON strings",
                "`\"auto\"`",
                "`\"on\"`",
                "`\"off\"`",
                "already compressed",
                "force compression",
                "not boolean `true`",
                "non-string `compress`",
                "before direction dispatch",
                "no source was read",
                "nothing was transferred",
                "retrying unchanged fails identically",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_compress_value(&out), out);
        }
    }

    #[test]
    fn invalid_compress_leaves_siblings_alone() {
        for raw in [
            "compress must be auto, on, or off",
            "compress must be auto, on, or off, got ",
            "copy_path: compress must be auto, on, or off, got yes",
            "compress must be auto, on, or off, got yes\nother error",
            "direction must be upload, download, or peer, got sideways",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_compress_value(raw), raw, "{raw}");
        }
    }
}

const SCROLL_COORD_PAIR_TIP_MARKER: &str = "scroll x and y must both be set or both omitted";

/// True for `scroll`'s half-pair rejection. MCP `scroll` reports
/// `scroll needs both x and y, or neither` when exactly one of `x` / `y` is a
/// JSON number; the CLI reports `scroll needs both --x and --y, or neither`
/// when exactly one flag is present. Both raw forms are matched exactly so
/// wrapped or truncated variants stay raw.
fn is_scroll_coord_pair_error(message: &str) -> bool {
    matches!(
        message.trim(),
        "scroll needs both x and y, or neither" | "scroll needs both --x and --y, or neither"
    )
}

/// Append an actionable tip when `scroll` receives only one of its optional
/// coordinate pair. The raw message names neither the omit-both case, the
/// number-only rule, nor the separate `dx` / `dy` deltas. Operation-general
/// because the raw message names no node. Idempotent.
fn decorate_scroll_coord_pair(message: &str) -> String {
    if message.contains(SCROLL_COORD_PAIR_TIP_MARKER) || !is_scroll_coord_pair_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {SCROLL_COORD_PAIR_TIP_MARKER} — `x` and `y` are the optional screen \
         point to move the pointer to before scrolling, so supply them as a pair or omit both. \
         Omitting both scrolls at the current pointer without moving it, which is the common \
         case. MCP `scroll` accepts them only as JSON numbers (pixels, or a 0–1 fraction of the \
         primary monitor) — `\"x\": 640, \"y\": 480` — and a string such as `\"640\"` does not \
         count as supplied, so pairing `\"x\": 640` with `\"y\": \"480\"` produces this error. \
         The CLI equivalent is `agentlink scroll <node> --x 640 --y 480`. The scroll amount is \
         separate and optional: `dx` / `dy` (CLI `--dx` / `--dy`) are integer wheel deltas and \
         default to 0, so coordinates are never required — if no pointer move is intended, drop \
         `x` / `y` entirely instead of setting one. Validation happens before the desktop \
         action is sent, so the pointer did not move and nothing scrolled, and retrying \
         unchanged fails identically. This is input validation, not a permission, grant, \
         sandbox, node-offline, or timeout failure. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod scroll_coord_pair_tip_tests {
    use super::*;

    #[test]
    fn scroll_coord_pair_gets_the_tip_once() {
        for raw in [
            "scroll needs both x and y, or neither",
            "scroll needs both --x and --y, or neither",
            "  scroll needs both x and y, or neither  ",
        ] {
            let out = decorate_scroll_coord_pair(raw);
            assert!(
                out.contains(&format!("tip: {SCROLL_COORD_PAIR_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(
                out.matches(SCROLL_COORD_PAIR_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "omit both",
                "current pointer",
                "JSON numbers",
                "0–1 fraction",
                "`\"x\": 640, \"y\": 480`",
                "`\"640\"`",
                "`agentlink scroll <node> --x 640 --y 480`",
                "`dx`",
                "`dy`",
                "pointer did not move",
                "nothing scrolled",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_scroll_coord_pair(&out), out);
        }
    }

    #[test]
    fn scroll_coord_pair_leaves_siblings_alone() {
        for raw in [
            "scroll needs both x and y",
            "scroll needs both --x and --y",
            "Scroll needs both x and y, or neither",
            "`x` must be a finite number",
            "missing `node`",
            "scroll: timeout",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_scroll_coord_pair(raw), raw, "{raw}");
        }
    }
}

const EDIT_MISMATCH_TIP_MARKER: &str = "tip: read the current text";

/// Append an actionable tip when `replace`/`edit` cannot find the old string:
/// read the remote text, match it byte-for-byte, and use `--all` for repeats.
/// Idempotent. Empty-old, ambiguous-match, patch, and unrelated errors are
/// left alone.
fn decorate_edit_mismatch(message: &str) -> String {
    const NEEDLE: &str = "old string was not found in ";
    if message.contains(EDIT_MISMATCH_TIP_MARKER) || !message.contains(NEEDLE) {
        return message.to_string();
    }
    format!(
        "{message}. {EDIT_MISMATCH_TIP_MARKER} with `agentlink cat <node> <path>` (or pin it with \
         `agentlink search <node> <pattern> <path>`) and match it byte-for-byte — indentation, \
         quotes, and CRLF included — then re-run the edit; for repeated text use `agentlink \
         replace --all`, or switch to `agentlink edit-lines`; see `agentlink guide <node>`"
    )
}

#[cfg(test)]
mod edit_mismatch_tip_tests {
    use super::*;

    #[test]
    fn missing_old_string_gets_edit_tip_once() {
        let out = decorate_edit_mismatch("old string was not found in /home/me/notes.txt");
        assert_eq!(
            out,
            "old string was not found in /home/me/notes.txt. tip: read the current text with \
             `agentlink cat <node> <path>` (or pin it with `agentlink search <node> <pattern> \
             <path>`) and match it byte-for-byte — indentation, quotes, and CRLF included — then \
             re-run the edit; for repeated text use `agentlink replace --all`, or switch to \
             `agentlink edit-lines`; see `agentlink guide <node>`"
        );
        assert_eq!(decorate_edit_mismatch(&out), out);
    }

    #[test]
    fn wrapped_missing_old_string_gets_the_tip_once() {
        let out = decorate_edit_mismatch(
            "replace /tmp/x: old string was not found in /tmp/x (no such text)",
        );
        assert_eq!(out.matches(EDIT_MISMATCH_TIP_MARKER).count(), 1, "{out}");
        assert!(out.contains("`agentlink cat <node> <path>`"), "{out}");
        assert!(out.contains("`agentlink replace --all`"), "{out}");
        assert!(out.contains("`agentlink edit-lines`"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
    }

    #[test]
    fn other_edit_and_unrelated_errors_are_unchanged() {
        for raw in [
            "old string is empty",
            "found 2 matches of the old string in /tmp/x; pass --all (CLI) or replace_all (MCP/API) to replace every match",
            "patch /tmp/x: hunk 1 does not apply",
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4)",
            "replacement text exceeds 1 MiB",
            "node offline: probe",
            "not found: node 'foo'",
            "authentication failed: session expired or revoked",
            "Permission denied (os error 13)",
            "exec hostname: connection reset by peer",
        ] {
            assert_eq!(decorate_edit_mismatch(raw), raw, "{raw}");
        }
    }
}

const AMBIGUOUS_REPLACE_TIP_MARKER: &str =
    "`replace_text` refuses a non-unique `old` unless `replace_all` is true";

const AMBIGUOUS_REPLACE_SUFFIX: &str =
    "pass --all (CLI) or replace_all (MCP/API) to replace every match";

fn is_ambiguous_replace_error(message: &str) -> bool {
    message.contains(" matches of the old string in ")
        && message.contains(AMBIGUOUS_REPLACE_SUFFIX)
}

/// Append an actionable tip when `replace`/`replace_text` finds more than one
/// occurrence of a non-unique `old`: the file is untouched, the count is exact,
/// and there are three ways forward (unique anchor, `edit-lines`, or `--all`).
/// Idempotent. Not-found, empty-old, patch, and unrelated errors are left alone.
fn decorate_ambiguous_replace(message: &str) -> String {
    if message.contains(AMBIGUOUS_REPLACE_TIP_MARKER) || !is_ambiguous_replace_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {AMBIGUOUS_REPLACE_TIP_MARKER} — the node read the file and counted the \
         occurrences of `old`, then stopped before writing: nothing on the node changed and no \
         partial or backup edit was made, so the file is exactly as it was. The count is a \
         case-sensitive, byte-exact, non-overlapping substring count over the whole file (not per \
         line), so indentation, quotes, and CRLF must match exactly and an anchor copied from one \
         repeated line matches every copy. Retrying the same call unchanged fails identically; \
         this is not a permission, grant, sandbox, node-offline, or missing-path failure. Three \
         ways forward: (1) make `old` unique by including surrounding lines or indentation (read \
         them with MCP `read_file` / CLI `agentlink cat <node> <path>`), then retry without \
         `replace_all`; (2) change one known location by line range with MCP `edit_lines` / CLI \
         `agentlink edit-lines <node> <path> <start> <end> <text>` (1-based, inclusive); or (3) \
         set MCP `replace_text` `\"replace_all\": true` / CLI `agentlink replace --all` only when \
         you intend to rewrite all occurrences — the successful response reports the number in \
         `replacements`. Do not set `replace_all` merely to silence this error: on a repeated line \
         it rewrites every copy, including unrelated code. The path is node-resolved (the `--root` \
         jail applied; `~` is not expanded). See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod ambiguous_replace_tip_tests {
    use super::*;

    const RAW: &str = "found 2 matches of the old string in /srv/app/src/main.rs; pass --all \
                       (CLI) or replace_all (MCP/API) to replace every match";

    #[test]
    fn ambiguous_replace_gets_the_tip_once() {
        let out = decorate_ambiguous_replace(RAW);
        assert!(
            out.starts_with(&format!(
                "{RAW}. tip: {AMBIGUOUS_REPLACE_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(AMBIGUOUS_REPLACE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "nothing on the node changed",
            "replace_all",
            "edit_lines",
            "replacements",
            "read_file",
            "agentlink cat <node> <path>",
            "1-based",
            "not a permission",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(decorate_ambiguous_replace(&out), out);
    }

    #[test]
    fn prefixed_forms_are_idempotent() {
        for raw in [
            "replace /srv/app/src.rs: found 4 matches of the old string in /srv/app/src.rs; pass \
             --all (CLI) or replace_all (MCP/API) to replace every match",
            "replace /srv/app/src.rs: found 4 matches of the old string in /srv/app/src.rs; pass \
             --all (CLI) or replace_all (MCP/API) to replace every match ",
        ] {
            let out = decorate_ambiguous_replace(raw);
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert_eq!(
                out.matches(AMBIGUOUS_REPLACE_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(decorate_ambiguous_replace(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_replace_and_edit_errors_are_unchanged() {
        for raw in [
            "old string was not found in /tmp/x",
            "old string is empty",
            "replacement text exceeds 1 MiB",
            "line numbers are 1-based",
            "end line 2 is before start line 5",
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4)",
            "patch exceeds 1 MiB",
            "found 2 matches of the old string in /tmp/x",
            "found 2 matches of the pattern in /tmp/x",
            "found 2 matches of the old string in /tmp/x. tip: `replace_text` refuses a \
             non-unique `old` unless `replace_all` is true",
            "old string was not found in /tmp/x. tip: read the current text with `agentlink cat \
             <node> <path>`",
            "old string is empty. tip: `replace` needs a non-empty, unique anchor",
        ] {
            assert_eq!(decorate_ambiguous_replace(raw), raw, "{raw}");
        }
    }
}

const EDIT_LINES_ZERO_BASED_TIP_MARKER: &str = "1-based and inclusive";

/// Append an actionable tip when `edit-lines` gets a 0-based line number
/// (`start` or `end` is 0): the range is 1-based and inclusive, appending uses
/// `end = <line count> + 1`, and `search`/`replace` help locate the span.
/// Idempotent. `end before start`, out-of-range, patch, and unrelated errors
/// are left alone.
fn decorate_edit_lines_zero_based(message: &str) -> String {
    const NEEDLE: &str = "line numbers are 1-based";
    if message.contains(EDIT_LINES_ZERO_BASED_TIP_MARKER) || !message.contains(NEEDLE) {
        return message.to_string();
    }
    format!(
        "{message}. tip: `agentlink edit-lines <node> <path> <start> <end> <text>` is 1-based and \
         inclusive — line 1 is the first line, and `end = <line count> + 1` appends. Find the \
         number by searching nearby text with `agentlink search <node> '<text>' <path>` (hits \
         print `path:line:text`); for a unique text anchor prefer `agentlink replace <node> \
         <path> <old> <new>`."
    )
}

#[cfg(test)]
mod edit_lines_zero_based_tip_tests {
    use super::*;

    #[test]
    fn zero_based_line_number_gets_the_tip_once() {
        let out = decorate_edit_lines_zero_based("line numbers are 1-based");
        assert_eq!(
            out,
            "line numbers are 1-based. tip: `agentlink edit-lines <node> <path> <start> <end> \
             <text>` is 1-based and inclusive — line 1 is the first line, and `end = <line count> \
             + 1` appends. Find the number by searching nearby text with `agentlink search <node> \
             '<text>' <path>` (hits print `path:line:text`); for a unique text anchor prefer \
             `agentlink replace <node> <path> <old> <new>`."
        );
        assert_eq!(
            out.matches(EDIT_LINES_ZERO_BASED_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_edit_lines_zero_based(&out), out);
    }

    #[test]
    fn wrapped_zero_based_line_number_gets_the_tip_once() {
        let out = decorate_edit_lines_zero_based(
            "edit-lines /home/me/notes.txt 0 2 hello: line numbers are 1-based",
        );
        assert_eq!(
            out.matches(EDIT_LINES_ZERO_BASED_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("`agentlink search <node> '<text>' <path>`"), "{out}");
        assert!(out.contains("`agentlink replace <node> <path> <old> <new>`"), "{out}");
        assert!(out.contains("`end = <line count> + 1`"), "{out}");
        assert_eq!(decorate_edit_lines_zero_based(&out), out);
    }

    #[test]
    fn end_before_start_and_other_errors_are_unchanged() {
        for raw in [
            "end line 2 is before start line 5",
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4)",
            "old string is empty",
            "old string was not found in /tmp/x",
            "patch /tmp/x: hunk 1 does not apply",
            "replacement text exceeds 1 MiB",
            "node offline: probe",
            "not found: node 'foo'",
            "exec hostname: connection reset by peer",
            "Permission denied (os error 13)",
        ] {
            assert_eq!(decorate_edit_lines_zero_based(raw), raw, "{raw}");
        }
    }
}

const EDIT_LINES_OUTSIDE_TIP_MARKER: &str =
    "edit-lines `end` is inclusive and must not pass the last line";

/// True when `message` carries the edit-lines out-of-range error, matching
/// `line range <digits>-<digits> is outside ` and `(file has <digits> lines`
/// independently so wrapped or context-prefixed forms still match. The append
/// clause is not required because the FFI error omits it.
fn is_edit_lines_outside_error(message: &str) -> bool {
    contains_digits_between(message, "line range ", " is outside ", Some('-'))
        && contains_digits_between(message, "(file has ", " lines", None)
}

fn contains_digits_between(message: &str, head: &str, tail: &str, sep: Option<char>) -> bool {
    let mut rest = message;
    while let Some(pos) = rest.find(head) {
        let after = &rest[pos + head.len()..];
        if let Some(tail_pos) = after.find(tail) {
            let value = &after[..tail_pos];
            let digit_parts: Vec<&str> = match sep {
                Some(sep) => value.split(sep).collect(),
                None => vec![value],
            };
            if digit_parts.len() == sep.map_or(1, |_| 2)
                && digit_parts
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
            {
                return true;
            }
        }
        rest = &after;
    }
    false
}

/// Append an actionable tip when `edit-lines` fails because the requested line
/// range is past EOF: `end` is inclusive, `end=<n>` replaces through the last
/// line, and only `start=end=<n+1>` appends. Idempotent; the zero-based,
/// end-before-start, patch, and unrelated errors are left alone.
fn decorate_edit_lines_outside(message: &str) -> String {
    if message.contains(EDIT_LINES_OUTSIDE_TIP_MARKER) || !is_edit_lines_outside_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: edit-lines `end` is inclusive and must not pass the last line — both \
         bounds must be ≤ the file's line count; use `end=<n>` to replace through the last \
         line, and only `start=end=<n+1>` appends. Read the current text and line count first \
         with `agentlink cat <node> <path>` (or MCP `read_file`), locate the span with \
         `agentlink search <node> '<text>' <path>`, then retry; for a unique text anchor prefer \
         `agentlink replace <node> <path> <old> <new>`; see `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod edit_lines_outside_tip_tests {
    use super::*;

    #[test]
    fn outside_line_range_gets_the_tip_once() {
        let out = decorate_edit_lines_outside(
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4)",
        );
        assert_eq!(
            out,
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4). tip: \
             edit-lines `end` is inclusive and must not pass the last line — both bounds must be ≤ \
             the file's line count; use `end=<n>` to replace through the last line, and only \
             `start=end=<n+1>` appends. Read the current text and line count first with \
             `agentlink cat <node> <path>` (or MCP `read_file`), locate the span with \
             `agentlink search <node> '<text>' <path>`, then retry; for a unique text anchor \
             prefer `agentlink replace <node> <path> <old> <new>`; see `agentlink guide <node>`."
        );
        assert_eq!(
            out.matches(EDIT_LINES_OUTSIDE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_edit_lines_outside(&out), out);
    }

    #[test]
    fn wrapped_outside_line_range_gets_the_tip_once() {
        let out = decorate_edit_lines_outside(
            "edit-lines /home/me/notes.txt 9 10 hi: line range 9-10 is outside \
             /home/me/notes.txt (file has 3 lines)",
        );
        assert_eq!(
            out.matches(EDIT_LINES_OUTSIDE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("`end=<n>`"), "{out}");
        assert!(out.contains("`start=end=<n+1>`"), "{out}");
        assert!(out.contains("`agentlink cat <node> <path>`"), "{out}");
        assert!(out.contains("`agentlink search <node> '<text>' <path>`"), "{out}");
        assert!(out.contains("`agentlink replace <node> <path> <old> <new>`"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_edit_lines_outside(&out), out);
    }

    #[test]
    fn zero_based_end_before_start_and_unrelated_errors_are_unchanged() {
        for raw in [
            "line numbers are 1-based",
            "end line 2 is before start line 5",
            "old string was not found in /tmp/x",
            "patch /tmp/x: hunk 1 does not apply",
            "replacement text exceeds 1 MiB",
            "line range 9-10 is outside /tmp/x",
            "file has 3 lines",
            "node offline: probe",
            "not found: node 'foo'",
            "exec hostname: connection reset by peer",
            "Permission denied (os error 13)",
        ] {
            assert_eq!(decorate_edit_lines_outside(raw), raw, "{raw}");
        }
    }
}

const EDIT_LINES_END_BEFORE_START_TIP_MARKER: &str =
    "edit-lines `end` must be ≥ `start`";

/// True when `message` carries the edit-lines reversed-bounds error, matching
/// `end line <digits> is before start line <digits>` so wrapped or
/// context-prefixed forms still match. Requires digits on both sides so
/// unrelated prose containing the words does not trigger the tip.
fn is_edit_lines_end_before_start_error(message: &str) -> bool {
    const HEAD: &str = "end line ";
    const TAIL: &str = " is before start line ";
    let mut rest = message;
    while let Some(pos) = rest.find(HEAD) {
        let after = &rest[pos + HEAD.len()..];
        if let Some(tail_pos) = after.find(TAIL) {
            let start_val = &after[..tail_pos];
            let end_val = &after[tail_pos + TAIL.len()..];
            let end_digits: String = end_val
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            if !start_val.is_empty()
                && start_val.bytes().all(|b| b.is_ascii_digit())
                && !end_digits.is_empty()
            {
                return true;
            }
        }
        rest = after;
    }
    false
}

/// Append an actionable tip when `edit-lines` fails because `end < start`: the
/// arguments are ordered `<start> <end>` and replace that inclusive span. The
/// bounds were probably swapped or the range copied backwards; re-read the file
/// to confirm line numbers or use a text anchor. Idempotent; the zero-based,
/// out-of-range, patch, and unrelated errors are left alone.
fn decorate_edit_lines_end_before_start(message: &str) -> String {
    if message.contains(EDIT_LINES_END_BEFORE_START_TIP_MARKER)
        || !is_edit_lines_end_before_start_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: edit-lines `end` must be ≥ `start` — the arguments are ordered `<start> \
         <end>` and replace that inclusive span; you likely swapped them or copied a range \
         backwards. Re-read the file with `agentlink cat <node> <path>` (or MCP `read_file`) to \
         confirm line numbers, or use a text anchor with `agentlink replace <node> <path> <old> \
         <new>`; see `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod edit_lines_end_before_start_tip_tests {
    use super::*;

    #[test]
    fn end_before_start_gets_the_tip_once() {
        let out = decorate_edit_lines_end_before_start("end line 2 is before start line 5");
        assert_eq!(
            out,
            "end line 2 is before start line 5. tip: edit-lines `end` must be ≥ `start` — the \
             arguments are ordered `<start> <end>` and replace that inclusive span; you likely \
             swapped them or copied a range backwards. Re-read the file with `agentlink cat \
             <node> <path>` (or MCP `read_file`) to confirm line numbers, or use a text anchor \
             with `agentlink replace <node> <path> <old> <new>`; see `agentlink guide <node>`."
        );
        assert_eq!(
            out.matches(EDIT_LINES_END_BEFORE_START_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_edit_lines_end_before_start(&out), out);
    }

    #[test]
    fn wrapped_end_before_start_gets_the_tip_once() {
        let out = decorate_edit_lines_end_before_start(
            "edit-lines /home/me/notes.txt 5 2 hi: end line 2 is before start line 5",
        );
        assert_eq!(
            out.matches(EDIT_LINES_END_BEFORE_START_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("`<start> <end>`"), "{out}");
        assert!(out.contains("`agentlink cat <node> <path>`"), "{out}");
        assert!(out.contains("`read_file`"), "{out}");
        assert!(out.contains("`agentlink replace <node> <path> <old> <new>`"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_edit_lines_end_before_start(&out), out);
    }

    #[test]
    fn zero_based_outside_and_unrelated_errors_are_unchanged() {
        for raw in [
            "line numbers are 1-based",
            "line range 9-10 is outside /tmp/x (file has 3 lines; append with start=end=4)",
            "old string was not found in /tmp/x",
            "patch /tmp/x: hunk 1 does not apply",
            "replacement text exceeds 1 MiB",
            "end line is before start line",
            "node offline: probe",
            "not found: node 'foo'",
            "exec hostname: connection reset by peer",
            "Permission denied (os error 13)",
        ] {
            assert_eq!(decorate_edit_lines_end_before_start(raw), raw, "{raw}");
        }
    }
}

const UI_ELEMENT_STALE_TIP_MARKER: &str = "snapshot-scoped";

/// Append an actionable tip when `ui-act` rejects an element id as missing,
/// stale, or malformed (including Windows UIA ids that are not UI Automation
/// ids): ids are snapshot-scoped from the latest `ui-tree`, so re-run it and
/// pass a current id. Idempotent; action-missing errors and unrelated messages
/// are left alone.
fn decorate_ui_element_stale(message: &str) -> String {
    const NEEDLES: [&str; 5] = [
        "call get_ui_tree before acting on a Windows element",
        "is not in the last tree",
        "is not an accessibility id",
        "is not an AT-SPI id",
        "is not a UI Automation id",
    ];
    if message.contains(UI_ELEMENT_STALE_TIP_MARKER)
        || !NEEDLES.iter().any(|needle| message.contains(needle))
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: element ids are snapshot-scoped — they come only from the latest \
         `agentlink ui-tree <node>` and go stale after any UI change (new focus, dialog, \
         re-render, or reconnect). Re-run `agentlink ui-tree <node>` (raise `--max-depth`/\
         `--max-nodes`, max 12/2000, if the element was beyond the truncated tree), then pass a \
         current id to `agentlink ui-act <node> <id> --op click`. `get_ui_tree` is the node \
         extension op; the CLI command is `agentlink ui-tree`."
    )
}

#[cfg(test)]
mod ui_element_stale_tip_tests {
    use super::*;

    const EXPECTED_TIP: &str = "tip: element ids are snapshot-scoped — they come only from the \
         latest `agentlink ui-tree <node>` and go stale after any UI change (new focus, dialog, \
         re-render, or reconnect). Re-run `agentlink ui-tree <node>` (raise `--max-depth`/\
         `--max-nodes`, max 12/2000, if the element was beyond the truncated tree), then pass a \
         current id to `agentlink ui-act <node> <id> --op click`. `get_ui_tree` is the node \
         extension op; the CLI command is `agentlink ui-tree`.";

    #[test]
    fn each_backend_stale_id_message_gets_the_tip_once() {
        for raw in [
            "call get_ui_tree before acting on a Windows element",
            "element 'win|123' is not in the last tree",
            "element 'ax|7' is not in the last tree. Call get_ui_tree again.",
            "element id 'ax|nope' is not an accessibility id",
            "element id 'nope' is not an AT-SPI id. Call get_ui_tree again.",
            "element id 'stale|99' is not a UI Automation id",
        ] {
            let out = decorate_ui_element_stale(raw);
            assert!(out.starts_with(raw), "{out}");
            assert!(out.ends_with(EXPECTED_TIP), "{out}");
            assert_eq!(out.matches(UI_ELEMENT_STALE_TIP_MARKER).count(), 1, "{out}");
            assert!(
                out.contains("`agentlink ui-act <node> <id> --op click`"),
                "{out}"
            );
            assert!(out.contains("max 12/2000"), "{out}");
            assert!(out.contains("CLI command is `agentlink ui-tree`"), "{out}");
            assert_eq!(decorate_ui_element_stale(&out), out);
        }
    }

    #[test]
    fn wrapped_stale_id_message_gets_the_tip_once() {
        let out = decorate_ui_element_stale(
            "ui-act laptop ax|7 --op click: element 'ax|7' is not in the last tree. Call \
             get_ui_tree again.",
        );
        assert_eq!(out.matches(UI_ELEMENT_STALE_TIP_MARKER).count(), 1, "{out}");
        assert!(out.contains("Re-run `agentlink ui-tree <node>`"), "{out}");
        assert_eq!(decorate_ui_element_stale(&out), out);
    }

    #[test]
    fn action_missing_and_other_errors_are_unchanged() {
        for raw in [
            "AT-SPI element 42 has no click action",
            "element 'win|1' has no value pattern",
            "Wayland portal screenshot is unavailable",
            "patch /tmp/x: hunk 1 does not apply",
            "line numbers are 1-based",
            "old string is empty",
            "node offline: probe",
            "Permission denied (os error 13)",
            "exec hostname: connection reset by peer",
            "ambiguous node prefix 'foo'",
        ] {
            let out = decorate_ui_element_stale(raw);
            assert_eq!(out, raw, "{raw}");
            assert!(!out.contains(UI_ELEMENT_STALE_TIP_MARKER), "{out}");
        }
    }
}

const NO_CLICK_ACTION_TIP_MARKER: &str = "only Action-bearing widgets expose a click action";

/// Append an actionable tip when `ui-act --op click` finds the AT-SPI element
/// has no click action: only Action-bearing widgets expose one, so the target
/// is usually a container/label and the real control is a descendant.
/// Idempotent. Stale-element and AT-SPI/accessibility-id errors (snapshot-scoped
/// tip) and unrelated messages are left alone.
fn decorate_no_click_action(message: &str) -> String {
    const NEEDLE: &str = "no click action";
    if message.contains(NO_CLICK_ACTION_TIP_MARKER) || !message.contains(NEEDLE) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {NO_CLICK_ACTION_TIP_MARKER} — this element is a container/label; \
         the clickable control is usually a descendant. Re-run `agentlink ui-tree <node>` \
         (raise `--max-depth`/`--max-nodes` if the button is nested) and click the child with \
         a control role instead: `agentlink ui-act <node> <child-id> --op click`. Last resort: \
         `agentlink screenshot <node>` then `agentlink click <node> <x> <y>`; see `agentlink \
         guide <node>`"
    )
}

#[cfg(test)]
mod no_click_action_tip_tests {
    use super::*;

    const EXPECTED_TIP: &str = "tip: only Action-bearing widgets expose a click action — this \
         element is a container/label; the clickable control is usually a descendant. Re-run \
         `agentlink ui-tree <node>` (raise `--max-depth`/`--max-nodes` if the button is nested) \
         and click the child with a control role instead: `agentlink ui-act <node> <child-id> \
         --op click`. Last resort: `agentlink screenshot <node>` then `agentlink click <node> \
         <x> <y>`; see `agentlink guide <node>`";

    #[test]
    fn no_click_action_message_gets_the_tip_once() {
        let out = decorate_no_click_action("AT-SPI element 42 has no click action");
        assert_eq!(
            out,
            "AT-SPI element 42 has no click action. tip: only Action-bearing widgets expose a \
             click action — this element is a container/label; the clickable control is usually \
             a descendant. Re-run `agentlink ui-tree <node>` (raise `--max-depth`/`--max-nodes` \
             if the button is nested) and click the child with a control role instead: \
             `agentlink ui-act <node> <child-id> --op click`. Last resort: `agentlink \
             screenshot <node>` then `agentlink click <node> <x> <y>`; see `agentlink guide \
             <node>`"
        );
        assert_eq!(out.matches(NO_CLICK_ACTION_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_no_click_action(&out), out);
    }

    #[test]
    fn wrapped_no_click_action_message_gets_the_tip_once() {
        let out = decorate_no_click_action(
            "ui-act laptop 42 --op click: AT-SPI element 42 has no click action",
        );
        assert!(
            out.starts_with("ui-act laptop 42 --op click: AT-SPI element 42 has no click \
                             action. tip:"),
            "{out}"
        );
        assert_eq!(out.matches(NO_CLICK_ACTION_TIP_MARKER).count(), 1, "{out}");
        assert!(out.ends_with(EXPECTED_TIP), "{out}");
        assert_eq!(decorate_no_click_action(&out), out);
    }

    #[test]
    fn already_tipped_messages_are_left_alone() {
        let tipped = decorate_no_click_action("AT-SPI element 42 has no click action");
        assert_eq!(decorate_no_click_action(&tipped), tipped);
    }

    #[test]
    fn stale_id_and_unrelated_errors_are_unchanged() {
        for raw in [
            "element 'ax|7' is not in the last tree. Call get_ui_tree again.",
            "element id 'nope' is not an AT-SPI id. Call get_ui_tree again.",
            "element id 'ax|nope' is not an accessibility id",
            "Wayland portal screenshot is unavailable",
            "patch /tmp/x: hunk 1 does not apply",
            "node offline: probe",
            "Permission denied (os error 13)",
            "ambiguous node prefix 'foo'",
        ] {
            let out = decorate_no_click_action(raw);
            assert_eq!(out, raw, "{raw}");
            assert!(!out.contains(NO_CLICK_ACTION_TIP_MARKER), "{out}");
        }
    }
}

const ATSPI_BUS_TIP_MARKER: &str = "the node's accessibility bus is unreachable";

/// Append an actionable tip when `ui-tree` (or related desktop ops) fail because
/// the node's AT-SPI/accessibility bus is unreachable or exposes no AT-SPI
/// nodes (typical on headless/SSH/systemd nodes). The `AT-SPI bus launcher:`
/// error already self-documents (`at-spi2-core` guard) and stale-element /
/// no-click errors carry their own tips, so those are left alone. Idempotent.
fn decorate_atspi_bus_failure(message: &str) -> String {
    const NEEDLES: [&str; 7] = [
        "AT-SPI GetDesktop: ",
        "AT-SPI registry: ",
        "AT-SPI bus: ",
        "AT-SPI GetAddress: ",
        "session bus: ",
        "AT-SPI desktop tree is empty",
        "AT-SPI capability missing:",
    ];
    if message.contains(ATSPI_BUS_TIP_MARKER)
        || message.contains("at-spi2-core")
        || !NEEDLES.iter().any(|needle| message.contains(needle))
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {ATSPI_BUS_TIP_MARKER} or apps expose no AT-SPI nodes — typical on \
         headless/SSH/systemd nodes. Fix on the node: install at-spi2-core, launch the node \
         from the desktop session (or export DBUS_SESSION_BUS_ADDRESS), enable toolkit \
         accessibility (`gsettings set org.gnome.desktop.interface toolkit-accessibility true`, \
         then re-login; `QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1` for Qt). Retry \
         `agentlink ui-tree <node>`. Fallback: `agentlink screenshot <node>` then \
         `agentlink click <node> <x> <y>`; see `agentlink guide <node>`"
    )
}

#[cfg(test)]
mod atspi_bus_tip_tests {
    use super::*;

    const EXPECTED_TAIL: &str = "tip: the node's accessibility bus is unreachable or apps \
         expose no AT-SPI nodes — typical on headless/SSH/systemd nodes. Fix on the node: \
         install at-spi2-core, launch the node from the desktop session (or export \
         DBUS_SESSION_BUS_ADDRESS), enable toolkit accessibility (`gsettings set \
         org.gnome.desktop.interface toolkit-accessibility true`, then re-login; \
         `QT_LINUX_ACCESSIBILITY_ALWAYS_ON=1` for Qt). Retry `agentlink ui-tree <node>`. \
         Fallback: `agentlink screenshot <node>` then `agentlink click <node> <x> <y>`; see \
         `agentlink guide <node>`";

    #[test]
    fn each_bus_error_gets_the_tip_once() {
        for raw in [
            "AT-SPI GetDesktop: ServiceUnknown",
            "AT-SPI registry: ServiceUnknown",
            "AT-SPI bus: address is not set",
            "AT-SPI GetAddress: ServiceUnknown",
            "session bus: NotSupported",
            "AT-SPI desktop tree is empty",
            "AT-SPI capability missing: desktop root unreachable",
        ] {
            let out = decorate_atspi_bus_failure(raw);
            assert!(out.starts_with(&format!("{raw}. tip:")), "{out}");
            assert!(out.ends_with(EXPECTED_TAIL), "{out}");
            assert_eq!(out.matches(ATSPI_BUS_TIP_MARKER).count(), 1, "{out}");
            assert_eq!(decorate_atspi_bus_failure(&out), out, "{raw}");
        }
    }

    #[test]
    fn wrapped_bus_error_gets_the_tip_once() {
        let out = decorate_atspi_bus_failure("ui-tree laptop: AT-SPI desktop tree is empty");
        assert!(
            out.starts_with("ui-tree laptop: AT-SPI desktop tree is empty. tip:"),
            "{out}"
        );
        assert_eq!(out.matches(ATSPI_BUS_TIP_MARKER).count(), 1, "{out}");
        assert!(out.ends_with(EXPECTED_TAIL), "{out}");
        assert_eq!(decorate_atspi_bus_failure(&out), out);
    }

    #[test]
    fn already_tipped_messages_are_left_alone() {
        let tipped = decorate_atspi_bus_failure("AT-SPI desktop tree is empty");
        assert_eq!(decorate_atspi_bus_failure(&tipped), tipped);
    }

    #[test]
    fn launcher_no_click_stale_and_unrelated_errors_are_unchanged() {
        for raw in [
            "AT-SPI bus launcher: ServiceUnknown. Install at-spi2-core and start the session \
             accessibility bus.",
            "AT-SPI element 42 has no click action",
            "element 'ax|7' is not in the last tree. Call get_ui_tree again.",
            "element id 'nope' is not an AT-SPI id. Call get_ui_tree again.",
            "AT-SPI focus: ServiceUnknown",
            "AT-SPI click: ServiceUnknown",
            "Wayland portal screenshot is unavailable",
            "node offline: probe",
            "Permission denied (os error 13)",
            "ambiguous node prefix 'foo'",
        ] {
            let out = decorate_atspi_bus_failure(raw);
            assert_eq!(out, raw, "{raw}");
            assert!(!out.contains(ATSPI_BUS_TIP_MARKER), "{out}");
        }
    }
}

const SCREENSHOT_WINDOW_TIP_MARKER: &str = "window capture did not match any visible window";

/// Append an actionable tip when window-targeted capture fails because no
/// visible top-level window matched the `--window-id` query. Window capture
/// matches a case-insensitive title substring (or numeric id), so a guessed
/// title commonly misses; point at `ui-tree` to discover names and at the
/// full-screen/monitor fallbacks. Idempotent, and leaves unrelated desktop
/// errors alone.
fn decorate_screenshot_window_not_found(message: &str) -> String {
    const NEEDLES: [&str; 7] = [
        "no X11 window matches '",
        "no window title contains '",
        "mock window '",
        "window capture capability missing:",
        "Mutter RecordWindow failed",
        "portal-authorized window does not match",
        "portal ScreenCast returned a MONITOR stream",
    ];
    if message.contains(SCREENSHOT_WINDOW_TIP_MARKER)
        || message.contains("ui-tree")
        || !NEEDLES.iter().any(|needle| message.contains(needle))
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {SCREENSHOT_WINDOW_TIP_MARKER} — window capture matches a \
         case-insensitive title substring (or a numeric window id) against visible top-level \
         windows, so a guessed title often misses. Discover names with `agentlink ui-tree \
         <node>`, then re-run `agentlink screenshot <node> --target window --window-id \
         '<title substring>'`. To capture without a window, use `agentlink screenshot <node>` \
         (full screen) or `--target monitor --monitor <n>`; MCP `screenshot`: omit `window_id` \
         or set `target: \"screen\"`."
    )
}

#[cfg(test)]
mod screenshot_window_tip_tests {
    use super::*;

    const EXPECTED_TAIL: &str = "tip: window capture did not match any visible window — window \
         capture matches a case-insensitive title substring (or a numeric window id) against \
         visible top-level windows, so a guessed title often misses. Discover names with \
         `agentlink ui-tree <node>`, then re-run `agentlink screenshot <node> --target window \
         --window-id '<title substring>'`. To capture without a window, use `agentlink screenshot \
         <node>` (full screen) or `--target monitor --monitor <n>`; MCP `screenshot`: omit \
         `window_id` or set `target: \"screen\"`.";

    #[test]
    fn x11_window_miss_gets_the_tip_once() {
        let raw = "no X11 window matches 'Terminal'";
        let out = decorate_screenshot_window_not_found(raw);
        assert!(out.starts_with(&format!("{raw}. tip:")), "{out}");
        assert!(out.ends_with(EXPECTED_TAIL), "{out}");
        assert_eq!(
            out.matches(SCREENSHOT_WINDOW_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_screenshot_window_not_found(&out), out);
    }

    #[test]
    fn macos_windows_window_miss_gets_the_tip_once() {
        for raw in [
            "no window title contains 'Terminal'",
            "screenshot laptop: no window title contains 'Terminal'",
        ] {
            let out = decorate_screenshot_window_not_found(raw);
            assert!(out.starts_with(&format!("{raw}. tip:")), "{out}");
            assert!(out.ends_with(EXPECTED_TAIL), "{out}");
            assert_eq!(
                out.matches(SCREENSHOT_WINDOW_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(decorate_screenshot_window_not_found(&out), out, "{raw}");
        }
    }

    #[test]
    fn mock_window_miss_gets_the_tip_once() {
        let raw = "mock window 'demo' was not found";
        let out = decorate_screenshot_window_not_found(raw);
        assert!(out.starts_with(&format!("{raw}. tip:")), "{out}");
        assert!(out.ends_with(EXPECTED_TAIL), "{out}");
        assert_eq!(
            out.matches(SCREENSHOT_WINDOW_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_screenshot_window_not_found(&out), out);
    }

    #[test]
    fn wrapped_window_miss_gets_the_tip_once() {
        let out = decorate_screenshot_window_not_found(
            "screenshot desktop: no X11 window matches 'ghost'",
        );
        assert!(
            out.starts_with("screenshot desktop: no X11 window matches 'ghost'. tip:"),
            "{out}"
        );
        assert_eq!(
            out.matches(SCREENSHOT_WINDOW_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_screenshot_window_not_found(&out), out);
    }

    #[test]
    fn already_tipped_messages_are_left_alone() {
        let tipped = decorate_screenshot_window_not_found("no X11 window matches 'ghost'");
        assert_eq!(decorate_screenshot_window_not_found(&tipped), tipped);
    }

    #[test]
    fn unrelated_desktop_errors_are_unchanged() {
        for raw in [
            "AT-SPI bus: address is not set",
            "AT-SPI element 42 has no click action",
            "element 'ax|7' is not in the last tree. Call get_ui_tree again.",
            "Wayland portal screenshot is unavailable",
            "Screen Recording permission is required",
            "no monitors found",
            "no X11 window matches 'ghost'. tip: discover names with `agentlink ui-tree n`",
            "Permission denied (os error 13)",
        ] {
            let out = decorate_screenshot_window_not_found(raw);
            assert_eq!(out, raw, "{raw}");
            assert!(!out.contains(SCREENSHOT_WINDOW_TIP_MARKER), "{out}");
        }
    }
}

const SCREENSHOT_MONITOR_TIP_MARKER: &str =
    "monitor indexes are 0-based, node-local, and only cover active displays";

/// True when `message` contains `needle` followed by a decimal monitor index
/// and then `tail`. An empty `tail` accepts end-of-message or trailing
/// punctuation, which covers the unwrapped-and-prefixed `no monitor <n>` forms.
fn monitor_index_after(message: &str, needle: &str, tail: &str) -> bool {
    let mut rest = message;
    while let Some(pos) = rest.find(needle) {
        let after = &rest[pos + needle.len()..];
        let digits = after.bytes().take_while(u8::is_ascii_digit).count();
        if digits > 0 {
            let remaining = &after[digits..];
            let matched = if tail.is_empty() {
                remaining.is_empty()
                    || matches!(remaining.chars().next(), Some('.' | ':' | ',' | ')'))
            } else {
                remaining.starts_with(tail)
            };
            if matched {
                return true;
            }
        }
        rest = &rest[pos + needle.len()..];
    }
    false
}

fn screenshot_monitor_missing(message: &str) -> bool {
    [
        ("monitor ", " does not exist"),
        ("no monitor ", ""),
        ("no DXGI output for monitor ", ""),
    ]
    .into_iter()
    .any(|(needle, tail)| monitor_index_after(message, needle, tail))
}

/// Append an actionable tip when `--target monitor --monitor <n>` fails because
/// the index does not exist: indexes are 0-based, node-local, and cover only
/// active displays, so list them and reuse one of the reported indexes.
/// Idempotent, and leaves window/AT-SPI/portal/other errors alone.
fn decorate_screenshot_monitor_missing(message: &str) -> String {
    if message.contains(SCREENSHOT_MONITOR_TIP_MARKER)
        || message.contains("--target monitors")
        || message.contains("target: \"monitors\"")
        || !screenshot_monitor_missing(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {SCREENSHOT_MONITOR_TIP_MARKER} — list them with `agentlink \
         screenshot <node> --target monitors` (each entry has `index`/`name`/`width`/`height`/\
         `primary`), then re-run `agentlink screenshot <node> --target monitor --monitor \
         <index>`; omit `--monitor` or use `--target screen` for the whole desktop. MCP \
         `screenshot`: set `target: \"monitors\"` to list, then `target: \"monitor\"` with \
         `monitor: <index>`."
    )
}

#[cfg(test)]
mod screenshot_monitor_tip_tests {
    use super::*;

    const EXPECTED_TAIL: &str = "tip: monitor indexes are 0-based, node-local, and only cover \
         active displays — list them with `agentlink screenshot <node> --target monitors` (each \
         entry has `index`/`name`/`width`/`height`/`primary`), then re-run `agentlink screenshot \
         <node> --target monitor --monitor <index>`; omit `--monitor` or use `--target screen` \
         for the whole desktop. MCP `screenshot`: set `target: \"monitors\"` to list, then \
         `target: \"monitor\"` with `monitor: <index>`.";

    fn assert_tipped_once(raw: &str) {
        let out = decorate_screenshot_monitor_missing(raw);
        assert!(out.starts_with(&format!("{raw}. tip:")), "{out}");
        assert!(out.ends_with(EXPECTED_TAIL), "{out}");
        assert_eq!(
            out.matches(SCREENSHOT_MONITOR_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_screenshot_monitor_missing(&out), out);
    }

    #[test]
    fn x11_monitor_miss_gets_the_tip_once() {
        assert_tipped_once("monitor 7 does not exist");
    }

    #[test]
    fn macos_windows_monitor_miss_gets_the_tip_once() {
        assert_tipped_once("no monitor 3");
        assert_tipped_once("screenshot laptop: no monitor 3");
    }

    #[test]
    fn mock_monitor_miss_gets_the_tip_once() {
        assert_tipped_once("mock monitor 4 does not exist");
    }

    #[test]
    fn dxgi_monitor_miss_gets_the_tip_once() {
        assert_tipped_once("no DXGI output for monitor 2");
    }

    #[test]
    fn wrapped_monitor_miss_gets_the_tip_once() {
        let out =
            decorate_screenshot_monitor_missing("screenshot desktop: monitor 9 does not exist");
        assert!(
            out.starts_with("screenshot desktop: monitor 9 does not exist. tip:"),
            "{out}"
        );
        assert_eq!(
            out.matches(SCREENSHOT_MONITOR_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_screenshot_monitor_missing(&out), out);
    }

    #[test]
    fn already_tipped_messages_are_left_alone() {
        let tipped = decorate_screenshot_monitor_missing("no monitor 3");
        assert_eq!(decorate_screenshot_monitor_missing(&tipped), tipped);
    }

    #[test]
    fn messages_already_pointing_at_monitor_listing_are_left_alone() {
        for raw in [
            "no monitor 3; list them with --target monitors",
            "no monitor 3; MCP target: \"monitors\"",
        ] {
            assert_eq!(decorate_screenshot_monitor_missing(raw), raw, "{raw}");
        }
    }

    #[test]
    fn unrelated_errors_are_unchanged() {
        for raw in [
            "no X11 window matches 'Terminal'",
            "no window title contains 'Terminal'",
            "mock window 'demo' was not found",
            "no monitors found",
            "no monitors to map coordinates onto",
            "monitor 3 capture failed",
            "AT-SPI bus: address is not set",
            "AT-SPI element 42 has no click action",
            "element 'ax|7' is not in the last tree. Call get_ui_tree again.",
            "Wayland portal screenshot is unavailable",
            "Screen Recording permission is required",
            "Permission denied (os error 13)",
        ] {
            let out = decorate_screenshot_monitor_missing(raw);
            assert_eq!(out, raw, "{raw}");
            assert!(!out.contains(SCREENSHOT_MONITOR_TIP_MARKER), "{out}");
        }
    }
}

const WINDOWS_INPUT_CAPTURE_TIP_MARKER: &str =
    "Windows desktop input/capture needs an interactive session";

fn windows_input_capture_failure(message: &str) -> bool {
    const NEEDLES: [&str; 4] = [
        "SendInput mouse failed",
        "SendInput key failed",
        "SendInput unicode failed",
        "GDI capture failed",
    ];
    NEEDLES.iter().any(|needle| message.contains(needle))
}

/// Append an actionable tip when a Windows desktop op fails in `SendInput`
/// (mouse/key/unicode) or `GDI` capture. Both only reach the interactive
/// desktop of the logged-in user, so a locked, non-interactive (service /
/// session 0), UAC-elevation-mismatched, or disconnected-RDP session makes
/// them fail. Idempotent, and leaves unrelated desktop errors alone.
fn decorate_windows_input_capture(message: &str) -> String {
    if message.contains(WINDOWS_INPUT_CAPTURE_TIP_MARKER) || !windows_input_capture_failure(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {WINDOWS_INPUT_CAPTURE_TIP_MARKER} — SendInput and GDI only reach the \
         interactive desktop of the node's logged-in user, so the Windows session is likely \
         locked, running non-interactively (service / session 0), mismatched by UAC elevation, \
         or a remote desktop session was disconnected. Unlock the console and run the node in \
         that interactive desktop session (with matching elevation), confirm the \
         remote-control/desktop grant allows input and capture, then retry the MCP tools \
         `click`/`type`/`key`/`scroll`/`screenshot` (CLI `agentlink click`, `agentlink type`, \
         `agentlink key`, `agentlink scroll`, `agentlink screenshot`)."
    )
}

#[cfg(test)]
mod windows_input_capture_tip_tests {
    use super::*;

    const EXPECTED_TAIL: &str = "tip: Windows desktop input/capture needs an interactive \
         session — SendInput and GDI only reach the interactive desktop of the node's logged-in \
         user, so the Windows session is likely locked, running non-interactively (service / \
         session 0), mismatched by UAC elevation, or a remote desktop session was disconnected. \
         Unlock the console and run the node in that interactive desktop session (with matching \
         elevation), confirm the remote-control/desktop grant allows input and capture, then \
         retry the MCP tools `click`/`type`/`key`/`scroll`/`screenshot` (CLI `agentlink click`, \
         `agentlink type`, `agentlink key`, `agentlink scroll`, `agentlink screenshot`).";

    #[test]
    fn each_sendinput_and_gdi_form_gets_the_tip_once() {
        for raw in [
            "SendInput mouse failed",
            "SendInput mouse failed (5)",
            "SendInput key failed",
            "SendInput key failed (5)",
            "SendInput unicode failed",
            "SendInput unicode failed (5)",
            "GDI capture failed",
            "GDI capture failed (6)",
            "click laptop 10 20: SendInput mouse failed (5)",
            "screenshot probe: GDI capture failed (6)",
        ] {
            let out = decorate_windows_input_capture(raw);
            assert!(out.starts_with(&format!("{raw}. tip:")), "{out}");
            assert!(out.ends_with(EXPECTED_TAIL), "{out}");
            assert_eq!(
                out.matches(WINDOWS_INPUT_CAPTURE_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert!(
                out.contains("`click`/`type`/`key`/`scroll`/`screenshot`"),
                "{out}"
            );
            assert!(out.contains("`agentlink screenshot`"), "{out}");
            assert_eq!(decorate_windows_input_capture(&out), out, "{raw}");
        }
    }

    #[test]
    fn already_tipped_messages_are_left_alone() {
        let tipped = decorate_windows_input_capture("SendInput mouse failed (5)");
        assert_eq!(decorate_windows_input_capture(&tipped), tipped);
    }

    #[test]
    fn unrelated_desktop_and_io_errors_are_unchanged() {
        for raw in [
            "element 'ax|7' is not in the last tree. Call get_ui_tree again.",
            "element id 'nope' is not an AT-SPI id. Call get_ui_tree again.",
            "AT-SPI bus: address is not set",
            "no X11 window matches 'Terminal'",
            "no monitor 3",
            "Wayland portal screenshot is unavailable",
            "Permission denied (os error 13)",
            "stat_path probe /tmp/x: No such file or directory (os error 2)",
            "missing `/tmp/x`",
            "SendInput mouse",
            "GDI capture",
        ] {
            let out = decorate_windows_input_capture(raw);
            assert_eq!(out, raw, "{raw}");
            assert!(!out.contains(WINDOWS_INPUT_CAPTURE_TIP_MARKER), "{out}");
        }
    }
}

const APPROVAL_UNRESOLVED_TIP_MARKER: &str = "this op was held for human approval";

const APPROVAL_UNRESOLVED_TIP_NEEDLE: &str = "approval denied or timed out";

/// Append an actionable tip when the node's confirm policy paused an op for
/// human approval and the request was denied or timed out. Idempotent, and
/// leaves unrelated timeout/approval notices alone.
fn decorate_approval_unresolved(message: &str) -> String {
    if message.contains(APPROVAL_UNRESOLVED_TIP_MARKER)
        || message.contains("agentlink approve")
        || !message.contains(APPROVAL_UNRESOLVED_TIP_NEEDLE)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {APPROVAL_UNRESOLVED_TIP_MARKER} — the node's confirm policy pauses \
         destructive ops (e.g. `rm -rf`) until a person decides, and the default 60s timeout \
         denies the call. List pending requests with `agentlink approve list` (operator/admin \
         login), then allow with `agentlink approve allow <approval_id> <node>` or deny with \
         `agentlink approve deny <approval_id> <node>` while the request is still pending; if it \
         already timed out, re-run the original call after allowing. Approving is a human CLI \
         action — MCP exposes no approve tool."
    )
}

#[cfg(test)]
mod approval_unresolved_tip_tests {
    use super::*;

    const EXPECTED_TAIL: &str = "tip: this op was held for human approval — the node's confirm \
         policy pauses destructive ops (e.g. `rm -rf`) until a person decides, and the default 60s \
         timeout denies the call. List pending requests with `agentlink approve list` \
         (operator/admin login), then allow with `agentlink approve allow <approval_id> <node>` or \
         deny with `agentlink approve deny <approval_id> <node>` while the request is still \
         pending; if it already timed out, re-run the original call after allowing. Approving is a \
         human CLI action — MCP exposes no approve tool.";

    fn assert_tipped_once(raw: &str) {
        let out = decorate_approval_unresolved(raw);
        assert!(out.starts_with(&format!("{raw}. tip:")), "{out}");
        assert!(out.ends_with(EXPECTED_TAIL), "{out}");
        assert_eq!(
            out.matches(APPROVAL_UNRESOLVED_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_approval_unresolved(&out), out);
    }

    #[test]
    fn raw_needle_gets_the_tip_once() {
        assert_tipped_once("approval denied or timed out");
    }

    #[test]
    fn wrapped_needle_gets_the_tip_once() {
        assert_tipped_once("exec rm -rf /tmp/x: approval denied or timed out");
    }

    #[test]
    fn already_tipped_messages_are_left_alone() {
        let tipped = decorate_approval_unresolved("approval denied or timed out");
        assert_eq!(decorate_approval_unresolved(&tipped), tipped);
    }

    #[test]
    fn messages_already_pointing_at_agentlink_approve_are_left_alone() {
        let raw = "approval denied or timed out; see agentlink approve list";
        assert_eq!(decorate_approval_unresolved(raw), raw);
    }

    #[test]
    fn unrelated_errors_are_unchanged() {
        for raw in [
            "timed out after 30s",
            "exec timed out after 60s",
            "request timed out",
            "waiting for approval on node n1 (approval ab12)",
            "approval request denied",
            "grant denied: capability shell.exec",
            "node offline",
            "sandbox denied write",
            "no X11 window matches 'Terminal'",
            "no monitor 3",
        ] {
            let out = decorate_approval_unresolved(raw);
            assert_eq!(out, raw, "{raw}");
            assert!(!out.contains(APPROVAL_UNRESOLVED_TIP_MARKER), "{out}");
        }
    }
}

const REPLACE_EMPTY_OLD_TIP_MARKER: &str = "needs a non-empty";

/// Append an actionable tip when `replace` is given an empty anchor: replace
/// needs a non-empty, unique anchor, so point at `agentlink write` for whole
/// files and `agentlink edit-lines` for positional edits. Idempotent. The
/// already-handled not-found case and unrelated errors are left alone.
fn decorate_replace_empty_old(message: &str) -> String {
    const NEEDLE: &str = "old string is empty";
    if message.contains(REPLACE_EMPTY_OLD_TIP_MARKER) || !message.contains(NEEDLE) {
        return message.to_string();
    }
    format!(
        "{message}. tip: `replace` needs a non-empty, unique anchor. To create or overwrite a \
         whole file use `agentlink write <node> <path> --content <text>`; to change lines by \
         position use `agentlink edit-lines <node> <path> <start> <end> <text>` (1-based; append \
         with start=end=<line count + 1>). If the anchor came from a shell/interpolation \
         variable, quote it and confirm it expanded; see `agentlink guide <node>`"
    )
}

#[cfg(test)]
mod replace_empty_old_tip_tests {
    use super::*;

    #[test]
    fn empty_old_string_gets_the_tip_once() {
        let out = decorate_replace_empty_old("old string is empty");
        assert_eq!(
            out,
            "old string is empty. tip: `replace` needs a non-empty, unique anchor. To create or \
             overwrite a whole file use `agentlink write <node> <path> --content <text>`; to \
             change lines by position use `agentlink edit-lines <node> <path> <start> <end> \
             <text>` (1-based; append with start=end=<line count + 1>). If the anchor came from a \
             shell/interpolation variable, quote it and confirm it expanded; see `agentlink \
             guide <node>`"
        );
        assert_eq!(decorate_replace_empty_old(&out), out);
        assert_eq!(
            out.matches(REPLACE_EMPTY_OLD_TIP_MARKER).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn wrapped_empty_old_string_gets_the_tip_once() {
        for raw in [
            "replace /srv/app/src.rs: old string is empty",
            "edit /home/me/notes.txt: old string is empty (anchor)",
        ] {
            let out = decorate_replace_empty_old(raw);
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert_eq!(
                out.matches(REPLACE_EMPTY_OLD_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert!(
                out.contains("`agentlink write <node> <path> --content <text>`"),
                "{out}"
            );
            assert!(
                out.contains("`agentlink edit-lines <node> <path> <start> <end> <text>`"),
                "{out}"
            );
            assert!(out.contains("`agentlink guide <node>`"), "{out}");
            assert_eq!(decorate_replace_empty_old(&out), out, "{raw}");
        }
    }

    #[test]
    fn already_tipped_and_related_errors_are_unchanged() {
        for raw in [
            "old string is empty. tip: `replace` needs a non-empty, unique anchor",
            "old string was not found in /tmp/x",
            "replace /tmp/x: old string was not found in /tmp/x (no such text)",
            "found 2 matches of the old string in /tmp/x; pass --all (CLI) or replace_all \
             (MCP/API) to replace every match",
            "patch /tmp/x: hunk 1 does not apply",
            "node offline: probe",
            "not found: node 'foo'",
            "authentication failed: session expired or revoked",
            "Permission denied (os error 13)",
            "exec hostname: connection reset by peer",
        ] {
            assert_eq!(decorate_replace_empty_old(raw), raw, "{raw}");
        }
    }
}

const REPLACE_MISSING_FILE_TIP_MARKER: &str =
    "`replace` edits an existing file and never creates one";

fn is_replace_missing_file_error(message: &str) -> bool {
    let msg = message.trim_start();
    msg.starts_with("io: ") && looks_like_enoent_message(msg)
}

/// Append an actionable tip when `replace`/MCP `replace_text` fails because the
/// target file does not exist. The node returns a bare `io:` ENOENT that names
/// neither the operation nor the path, so the tip restores the caller's raw
/// path and the remedies. Idempotent; the node-args-swapped hint wins.
fn decorate_replace_missing_file(message: &str, path: &str) -> String {
    if !is_replace_missing_file_error(message)
        || message.contains(REPLACE_MISSING_FILE_TIP_MARKER)
        || message.contains("Did you mean")
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {REPLACE_MISSING_FILE_TIP_MARKER} — `replace` (MCP `replace_text`) \
         reads `{path}` in full before matching, and the node could not open it: the file does \
         not exist (or one of its parent directories does). Nothing was written. The path is \
         resolved on the node, not locally: a relative path uses the node's working directory \
         (`.` is not your local project) and `~` is not expanded. Confirm it with `agentlink ls \
         <node> <dir>` / MCP `list_dir` or `stat_path`, or locate the name with `agentlink find \
         <node> <name>`; then create it with `agentlink write <node> <path> --content <text>` / \
         MCP `write_file` (both create missing parent directories) and retry — or create and \
         edit in one step with `agentlink edit-lines <node> <path> 1 1 <text>` / MCP \
         `edit_lines` with `start_line: 1` (a missing path is created when `start_line` is 1). \
         If the file is on another machine, the path exists only there. `old string was not \
         found` is a different failure and means the file does exist. Retrying this call \
         unchanged fails the same way. See `agentlink guide <node>`"
    )
}

#[cfg(test)]
mod replace_missing_file_tip_tests {
    use super::*;

    #[test]
    fn missing_file_gets_the_tip_once() {
        let raw = "io: No such file or directory (os error 2)";
        let out = decorate_replace_missing_file(raw, "/srv/app/notes.txt");
        assert!(
            out.starts_with(&format!(
                "{raw}. tip: {REPLACE_MISSING_FILE_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(REPLACE_MISSING_FILE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "`/srv/app/notes.txt`",
            "`agentlink write <node> <path> --content <text>`",
            "write_file",
            "`agentlink edit-lines <node> <path> 1 1 <text>`",
            "edit_lines",
            "`agentlink ls <node> <dir>`",
            "list_dir",
            "stat_path",
            "agentlink find",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
        assert_eq!(
            decorate_replace_missing_file(&out, "/srv/app/notes.txt"),
            out
        );
    }

    #[test]
    fn windows_missing_file_gets_the_tip_once() {
        let raw = "io: The system cannot find the file specified. (os error 2)";
        let out = decorate_replace_missing_file(raw, "notes.txt");
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(
            out.matches(REPLACE_MISSING_FILE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("`notes.txt`"), "{out}");
        assert_eq!(decorate_replace_missing_file(&out, "notes.txt"), out);
    }

    #[test]
    fn swap_hint_wins() {
        let raw = "io: No such file or directory (os error 2). Did you mean `agentlink replace x \
                   y z` (machine name first)?";
        assert_eq!(decorate_replace_missing_file(raw, "x"), raw);
    }

    #[test]
    fn unrelated_errors_are_unchanged() {
        for raw in [
            "io: Is a directory (os error 21)",
            "io: Permission denied (os error 13)",
            "io: Not a directory (os error 20)",
            "io: No space left on device (os error 28)",
            "sandbox root: No such file or directory (os error 2)",
            "not found: parent directory does not exist: /srv/app",
            "not found: /srv/app/notes.txt",
            "old string was not found in /srv/app/notes.txt",
            "old string is empty",
            "replacement text exceeds 1 MiB",
            "node offline: probe",
        ] {
            assert_eq!(
                decorate_replace_missing_file(raw, "/srv/app/notes.txt"),
                raw,
                "{raw}"
            );
        }
    }
}

const EDIT_FILE_TOO_LARGE_TIP_MARKER: &str = "the node's text edit cap is 8 MiB";
// The byte count is the literal from `MAX_FILE` (8 * 1024 * 1024) in
// crates/agentlink-node/src/edit.rs; a future cap change must update both.
const EDIT_FILE_TOO_LARGE_NEEDLE: &str = " is larger than 8388608 bytes";

/// Append an actionable tip when `replace`/`edit-lines`/`patch` refuse a target
/// over the node's whole-file edit cap: these ops read the whole file, so edit
/// in place over `exec`, or stream out with `cat` and write back. Idempotent;
/// the per-op text/chunk caps and unrelated errors are left alone.
fn decorate_edit_file_too_large(message: &str) -> String {
    if message.contains(EDIT_FILE_TOO_LARGE_TIP_MARKER)
        || !message.contains(EDIT_FILE_TOO_LARGE_NEEDLE)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {EDIT_FILE_TOO_LARGE_TIP_MARKER} — `replace` (MCP `replace_text`), \
         `edit-lines` (MCP `edit_lines`), and `patch` (MCP `apply_patch`) read the whole \
         target file, so even a one-line change is refused when it exceeds 8388608 bytes. Edit \
         it in place on the node with `agentlink exec <node> --shell \"sed -i 's/<old>/<new>/' \
         <path>\"` (MCP `run_command`, or perl/python), or stream it out (`agentlink cat <node> \
         <path>` / MCP `read_file` with `offset`/`max_bytes`), edit locally, and replace it with \
         `agentlink write <node> <path>` (MCP `write_file`) — cat/write stream bytes and have no \
         8 MiB text cap. Check the size first with `agentlink ls <node> <dir>` / MCP \
         `stat_path`; retrying another text op hits the same guard. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod edit_file_too_large_tip_tests {
    use super::*;

    #[test]
    fn bare_path_gets_the_tip_once() {
        let out = decorate_edit_file_too_large("/var/log/app.log is larger than 8388608 bytes");
        assert_eq!(
            out,
            "/var/log/app.log is larger than 8388608 bytes. tip: the node's text edit cap is 8 \
             MiB — `replace` (MCP `replace_text`), `edit-lines` (MCP `edit_lines`), and `patch` \
             (MCP `apply_patch`) read the whole target file, so even a one-line change is refused \
             when it exceeds 8388608 bytes. Edit it in place on the node with `agentlink exec \
             <node> --shell \"sed -i 's/<old>/<new>/' <path>\"` (MCP `run_command`, or \
             perl/python), or stream it out (`agentlink cat <node> <path>` / MCP `read_file` with \
             `offset`/`max_bytes`), edit locally, and replace it with `agentlink write <node> \
             <path>` (MCP `write_file`) — cat/write stream bytes and have no 8 MiB text cap. \
             Check the size first with `agentlink ls <node> <dir>` / MCP `stat_path`; retrying \
             another text op hits the same guard. See `agentlink guide <node>`."
        );
        assert_eq!(decorate_edit_file_too_large(&out), out);
        assert_eq!(
            out.matches(EDIT_FILE_TOO_LARGE_TIP_MARKER).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn deep_path_with_spaces_gets_the_tip_once() {
        let raw = "/srv/My App/data/archive 2026/notes v2.txt is larger than 8388608 bytes";
        let out = decorate_edit_file_too_large(raw);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(
            out.matches(EDIT_FILE_TOO_LARGE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("`agentlink exec <node> --shell"), "{out}");
        assert!(out.contains("`agentlink cat <node> <path>`"), "{out}");
        assert!(out.contains("`agentlink write <node> <path>`"), "{out}");
        assert!(out.contains("`agentlink ls <node> <dir>`"), "{out}");
        assert!(out.contains("`stat_path`"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_edit_file_too_large(&out), out);
    }

    #[test]
    fn patched_target_gets_the_tip_once() {
        let raw = "patch /srv/app/src/main.rs: /srv/app/src/main.rs is larger than 8388608 bytes";
        let out = decorate_edit_file_too_large(raw);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(
            out.matches(EDIT_FILE_TOO_LARGE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("`apply_patch`"), "{out}");
        assert!(out.contains("`replace_text`"), "{out}");
        assert!(out.contains("`edit_lines`"), "{out}");
        assert_eq!(decorate_edit_file_too_large(&out), out);
    }

    #[test]
    fn related_and_unrelated_errors_are_unchanged() {
        for raw in [
            "replacement text exceeds 1 MiB",
            "patch exceeds 1 MiB",
            "write chunk is larger than 1 MiB",
            "read is larger than 8 MiB",
            "response is larger than 134217728 bytes",
            "is not UTF-8 text",
            "old string was not found in /tmp/x",
            "not found: /srv/app/src",
            "old string is empty",
        ] {
            assert_eq!(decorate_edit_file_too_large(raw), raw, "{raw}");
        }
    }
}

const EDIT_TEXT_NOT_UTF8_TIP_MARKER: &str =
    "the node's edit tools decode the whole target file as UTF-8";

/// Case-sensitive on purpose: the local patch-file read error (`stream did not
/// contain valid UTF-8`) and the FFI lowercase `is not utf-8` must not match.
fn is_edit_text_not_utf8_error(message: &str) -> bool {
    message.contains("is not UTF-8 text")
}

/// Append an actionable tip when `replace`/`edit-lines`/`patch` reject a target
/// that is not valid UTF-8: those ops read and strictly decode the whole file,
/// so inspect the bytes, convert the encoding, or round-trip bytes via base64.
/// Idempotent; sibling size/cap and unrelated errors are left alone.
fn decorate_edit_text_not_utf8(message: &str) -> String {
    if message.contains(EDIT_TEXT_NOT_UTF8_TIP_MARKER) || !is_edit_text_not_utf8_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {EDIT_TEXT_NOT_UTF8_TIP_MARKER} — `replace` (MCP `replace_text`), \
         `edit-lines` (MCP `edit_lines`), and `patch` (MCP `apply_patch`) read each target file \
         in full and decode it strictly as UTF-8 before matching or applying, so one non-UTF-8 \
         byte anywhere fails the operation even when the text you are changing is plain ASCII, \
         and nothing was written; `patch` plans every section before writing, so a non-UTF-8 \
         file aborts the whole patch (a delete-only section still reads the file). Confirm the \
         bytes and encoding first: `agentlink cat <node> <path> | xxd | head` (MCP `read_file` \
         returns `\"encoding\": \"base64\"` plus `content_base64` for non-UTF-8 data, page with \
         `offset`/`next_offset`), and `agentlink exec <node> --shell \"file -bi <path>\"` / MCP \
         `run_command`. If it is text in another encoding (UTF-16LE/BE with an `FF FE` / `FE FF` \
         BOM, Latin-1/CP1252, ...), keep a copy (`agentlink cp` / MCP `copy_path`) and convert \
         it on the node, for example `agentlink exec <node> --shell \"iconv -f UTF-16 -t UTF-8 \
         <path> > <path>.tmp && mv <path>.tmp <path>\"` (use the charset `file -bi` reported; on \
         Windows use PowerShell `[IO.File]::ReadAllText` / `WriteAllText` with \
         `UTF8Encoding($false)`), then retry the edit. To change bytes without altering the \
         encoding, round-trip them: MCP `read_file` (base64) → edit → `write_file` with \
         `content_base64`; CLI `agentlink cat <node> <path> > local`, edit locally, then pipe \
         back with `agentlink write <node> <path>`. If the target is actually binary, do not use \
         text tools — copy or move it and use a byte-level tool over `exec`/`run_command`. See \
         `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod edit_text_not_utf8_tip_tests {
    use super::*;

    #[test]
    fn bare_error_gets_the_tip_once() {
        let raw = "/srv/app/config.ini is not UTF-8 text";
        let out = decorate_edit_text_not_utf8(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {EDIT_TEXT_NOT_UTF8_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(
            out.matches(EDIT_TEXT_NOT_UTF8_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "`replace_text`",
            "`edit_lines`",
            "`apply_patch`",
            "`read_file`",
            "`content_base64`",
            "`write_file`",
            "`run_command`",
            "`copy_path`",
            "`agentlink cat <node> <path> | xxd | head`",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle}: {out}");
        }
    }

    #[test]
    fn prefixed_error_gets_the_tip_once() {
        let raw = "replace_text: /srv/app/config.ini is not UTF-8 text";
        let out = decorate_edit_text_not_utf8(raw);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(
            out.matches(EDIT_TEXT_NOT_UTF8_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_edit_text_not_utf8(&out), out);
    }

    #[test]
    fn decorated_output_is_idempotent() {
        let out = decorate_edit_text_not_utf8("/srv/app/config.ini is not UTF-8 text");
        assert_eq!(decorate_edit_text_not_utf8(&out), out);
    }

    #[test]
    fn related_and_unrelated_errors_are_unchanged() {
        for raw in [
            "/srv/app/archive.bin is larger than 8388608 bytes",
            "replacement text exceeds 1 MiB",
            "patch exceeds 1 MiB",
            "old string was not found in /srv/app/config.ini",
            "old string is empty",
            "line numbers are 1-based",
            "stream did not contain valid UTF-8",
            "/srv/app/config.ini is not utf-8",
            "/srv/app/fifo is not a regular file (refusing fifo/socket/device)",
            "io: Directory not empty (os error 39)",
        ] {
            assert_eq!(decorate_edit_text_not_utf8(raw), raw, "{raw}");
        }
    }
}

const REPLACEMENT_TEXT_TOO_LARGE_TIP_MARKER: &str =
    "the node's text edit arguments are capped at 1 MiB";
// The phrase is the literal from `MAX_TEXT` (1024 * 1024) in
// crates/agentlink-node/src/edit.rs (shared by `replace_blocking` for `old`/`new`
// and `edit_lines_blocking` for `content`); a future cap change must update both.
// It deliberately does not collide with `patch exceeds 1 MiB`, `write chunk is
// larger than 1 MiB`, or `read is larger than 8 MiB`.
const REPLACEMENT_TEXT_TOO_LARGE_NEEDLE: &str = "replacement text exceeds 1 MiB";

/// Append an actionable tip when `replace`/`edit-lines` reject a text argument
/// over the node's per-argument cap: rewrite the whole file with `write`, split
/// the `edit-lines` insertion, or edit in place over `exec`. Idempotent; the
/// sibling per-file/per-chunk/patch caps and unrelated errors are left alone.
fn decorate_replacement_text_too_large(message: &str) -> String {
    if message.contains(REPLACEMENT_TEXT_TOO_LARGE_TIP_MARKER)
        || !message.contains(REPLACEMENT_TEXT_TOO_LARGE_NEEDLE)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {REPLACEMENT_TEXT_TOO_LARGE_TIP_MARKER} — `replace` checks the `old` \
         anchor and the `new` text independently (MCP `replace_text`), and `edit-lines` checks \
         its whole replacement `content` (MCP `edit_lines`); this caps each argument, not the \
         target file, which has a separate 8 MiB whole-file limit. To rewrite a whole file, \
         stream it with `agentlink write <node> <path>` from stdin (MCP `write_file`) — write and \
         MCP upload send 64 KiB chunks and have no 1 MiB text-argument cap. To change a region \
         whose text is over 1 MiB, split the insertion into several `agentlink edit-lines <node> \
         <path> <start> <end> <text>` calls (1-based; append with start=end=<line count + 1>), or \
         do it on the node with `agentlink exec <node> --shell \"perl -0pi -e 's/<old>/<new>/' \
         <path>\"` / MCP `run_command`. If the `old` anchor itself is over the cap it is a \
         whole-file rewrite — use `write`, not `replace`. `apply_patch` has its own separate 1 \
         MiB diff cap. Retrying the same call hits the same guard; see `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod replacement_text_too_large_tip_tests {
    use super::*;

    #[test]
    fn bare_error_gets_the_tip_once() {
        let out = decorate_replacement_text_too_large("replacement text exceeds 1 MiB");
        assert!(
            out.starts_with("replacement text exceeds 1 MiB. tip: "),
            "{out}"
        );
        assert_eq!(
            out.matches(REPLACEMENT_TEXT_TOO_LARGE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("`replace_text`"), "{out}");
        assert!(out.contains("`edit_lines`"), "{out}");
        assert!(out.contains("`write_file`"), "{out}");
        assert!(out.contains("`run_command`"), "{out}");
        assert!(out.contains("`apply_patch`"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_replacement_text_too_large(&out), out);
    }

    #[test]
    fn wrapped_error_gets_the_tip_once() {
        let raw = "replace_text: replacement text exceeds 1 MiB";
        let out = decorate_replacement_text_too_large(raw);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(
            out.matches(REPLACEMENT_TEXT_TOO_LARGE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_replacement_text_too_large(&out), out);
    }

    #[test]
    fn sibling_limits_and_unrelated_errors_are_unchanged() {
        for raw in [
            "patch exceeds 1 MiB",
            "write chunk is larger than 1 MiB",
            "/var/log/app.log is larger than 8388608 bytes",
            "read is larger than 8 MiB",
            "is not UTF-8 text",
            "old string is empty",
            "old string was not found in /tmp/x",
            "not found: /srv/app/src",
        ] {
            assert_eq!(decorate_replacement_text_too_large(raw), raw, "{raw}");
        }
    }
}

const PATCH_TOO_LARGE_TIP_MARKER: &str = "the whole patch is capped at 1 MiB, not the target file";
// Literal from the `MAX_PATCH` guard (1024 * 1024) in
// crates/agentlink-node/src/edit.rs, matched exactly so the sibling caps
// (`replacement text exceeds 1 MiB`, `write chunk is larger than 1 MiB`) stay
// untouched.
const PATCH_TOO_LARGE_NEEDLE: &str = "patch exceeds 1 MiB";

fn is_patch_too_large_error(message: &str) -> bool {
    message.contains(PATCH_TOO_LARGE_NEEDLE)
}

/// Append an actionable tip when `patch` / MCP `apply_patch` rejects the whole
/// unified diff over the node's 1 MiB cap: split the diff, stream a rewrite
/// through `write`, or upload and `git apply` it. Idempotent; the sibling
/// size caps and unrelated errors are left alone.
fn decorate_patch_too_large(message: &str) -> String {
    if message.contains(PATCH_TOO_LARGE_TIP_MARKER) || !is_patch_too_large_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {PATCH_TOO_LARGE_TIP_MARKER} — `patch` (MCP `apply_patch`) measures the \
         raw unified diff before parsing and rejects the whole request over 1024 * 1024 bytes, \
         so nothing from the diff was applied. The cap is on the diff text, not the file (a text \
         edit target may be up to 8 MiB). Split the diff into several `agentlink patch <node> \
         <root> --file <part>` / MCP `apply_patch` calls, each under 1 MiB; calls apply in order \
         and each is atomic, so a later failure leaves earlier sections applied. For a \
         whole-file rewrite, stream the result into `agentlink write <node> <path>` from stdin \
         (MCP `write_file`) — it sends 64 KiB chunks and has no 1 MiB diff cap. Or upload the \
         diff with `agentlink cp <local.patch> node://<node>/<remote.patch>` (MCP `copy_path`) \
         and apply it on the node with `agentlink exec <node> --shell 'git apply <remote.patch>'` \
         (or `patch -p1 < <remote.patch>` when GNU patch is installed; MCP `run_command`). \
         Shrink the diff first (fewer context lines, `diff -U1`, exclude generated/lock files). \
         Retrying the same oversized call hits the same guard; see `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod patch_too_large_tip_tests {
    use super::*;

    #[test]
    fn bare_error_gets_the_tip_once() {
        let out = decorate_patch_too_large("patch exceeds 1 MiB");
        assert!(out.starts_with("patch exceeds 1 MiB. tip: "), "{out}");
        assert_eq!(out.matches(PATCH_TOO_LARGE_TIP_MARKER).count(), 1, "{out}");
        assert!(out.contains("`apply_patch`"), "{out}");
        assert!(out.contains("`write_file`"), "{out}");
        assert!(out.contains("`copy_path`"), "{out}");
        assert!(out.contains("`run_command`"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_patch_too_large(&out), out);
    }

    #[test]
    fn wrapped_error_gets_the_tip_once() {
        let raw = "patch task: patch exceeds 1 MiB";
        let out = decorate_patch_too_large(raw);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(out.matches(PATCH_TOO_LARGE_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_patch_too_large(&out), out);
    }

    #[test]
    fn sibling_limits_and_unrelated_errors_are_unchanged() {
        for raw in [
            "replacement text exceeds 1 MiB",
            "write chunk is larger than 1 MiB",
            "read is larger than 8 MiB",
            "patch is empty",
            "patch section has no path",
            "patch has no unified diff headers (--- / +++)",
            "is not UTF-8 text",
            "io: Directory not empty (os error 39)",
            "io: No space left on device (os error 28)",
        ] {
            assert_eq!(decorate_patch_too_large(raw), raw, "{raw}");
        }
    }
}

const PATCH_MISSING_HEADERS_TIP_MARKER: &str =
    "a unified diff needs adjacent `--- ` and `+++ ` header lines";
// Literal from `split_patch` in crates/agentlink-node/src/edit.rs, which scans
// for an adjacent `--- `/`+++ ` pair before parsing any hunk. Unique to
// `apply_patch`, so a substring match is safe.
const PATCH_MISSING_HEADERS_NEEDLE: &str = "patch has no unified diff headers (--- / +++)";

fn is_patch_missing_headers_error(message: &str) -> bool {
    message.contains(PATCH_MISSING_HEADERS_NEEDLE)
}

/// Append an actionable tip when `patch` / MCP `apply_patch` is given text that
/// is not a unified diff. The node rejects it before touching any file; the tip
/// shows the accepted shape and the per-file alternatives. Idempotent; the
/// diffy parse errors and sibling patch tips are left alone.
fn decorate_patch_missing_headers(message: &str) -> String {
    if message.contains(PATCH_MISSING_HEADERS_TIP_MARKER) || !is_patch_missing_headers_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {PATCH_MISSING_HEADERS_TIP_MARKER} — the node parses the patch text \
         before touching any file, and for each file it requires a `--- ` line immediately \
         followed by a `+++ ` line, then a hunk header `@@ -<old>[,<count>] +<new>[,<count>] @@` \
         whose body lines start with a space (context), `-` (removed), or `+` (added). A minimal \
         accepted diff is five consecutive lines: `--- a/src/main.rs`, `+++ b/src/main.rs`, \
         `@@ -1,2 +1,2 @@`, `-old`, `+new`. The space after `---`/`+++` is required; `a/` and \
         `b/` prefixes and tab-separated timestamps are stripped; both paths are relative to the \
         patch root (MCP `root` defaults to `.`, the node's working directory). `*** Begin \
         Patch` / `*** Update File:` (the other common agent patch dialect), a bare `@@ … @@` \
         hunk with no file headers, and `diff`-like text pasted without the `---`/`+++` pair are \
         all rejected with this same message. Nothing was written — the patch is parsed and \
         applied atomically after validation. Send real unified diff text (`git diff --no-color \
         -- <paths>`, or `diff -u <old> <new>`), or for a one-off change use `agentlink replace \
         <node> <path> <old> <new>` (MCP `replace_text`) / `agentlink edit-lines <node> <path> \
         <start> <end> <text>` (MCP `edit_lines`); for a whole-file rewrite use `agentlink write \
         <node> <path>` (MCP `write_file`). CLI: `agentlink patch <node> <root> --file <diff>` \
         (or pipe the diff; `--file -` reads stdin). MCP: `apply_patch` with `root` (directory \
         the header paths are relative to) and `patch`. Retrying the same text unchanged fails \
         the same way. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod patch_missing_headers_tip_tests {
    use super::*;

    #[test]
    fn bare_error_gets_the_tip_once() {
        let raw = "patch has no unified diff headers (--- / +++)";
        let out = decorate_patch_missing_headers(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {PATCH_MISSING_HEADERS_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(
            out.matches(PATCH_MISSING_HEADERS_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("--- a/src/main.rs"), "{out}");
        assert!(out.contains("+++ b/src/main.rs"), "{out}");
        assert!(out.contains("@@ -1,2 +1,2 @@"), "{out}");
        assert!(out.contains("*** Begin Patch"), "{out}");
        assert!(out.contains("`replace_text`"), "{out}");
        assert!(out.contains("`edit_lines`"), "{out}");
        assert!(out.contains("`write_file`"), "{out}");
        assert!(
            out.contains("`agentlink patch <node> <root> --file <diff>`"),
            "{out}"
        );
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_patch_missing_headers(&out), out);
    }

    #[test]
    fn wrapped_error_gets_the_tip_once() {
        for raw in [
            "apply_patch: patch has no unified diff headers (--- / +++)",
            "patch task: patch has no unified diff headers (--- / +++)",
        ] {
            let out = decorate_patch_missing_headers(raw);
            assert!(out.starts_with(raw), "{out}");
            assert_eq!(
                out.matches(PATCH_MISSING_HEADERS_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(decorate_patch_missing_headers(&out), out);
        }
    }

    #[test]
    fn sibling_and_unrelated_errors_are_unchanged() {
        for raw in [
            "patch is empty",
            "patch exceeds 1 MiB",
            "patch section has no path",
            "invalid patch path '../etc/passwd'",
            "patch path escapes the root: ../../etc/passwd",
            "patch /srv/app/src.rs: error applying hunk #1",
            "patch /srv/app/src.rs: Hunk header does not match hunk",
            "could not apply new-file patch for /srv/app/new.rs: error applying hunk #1",
            "old string was not found in /srv/app/x",
            "io: No such file or directory (os error 2)",
            "node offline: probe",
        ] {
            assert_eq!(decorate_patch_missing_headers(raw), raw, "{raw}");
        }
    }
}

const SANDBOX_DENIAL_TIP_MARKER: &str = "the node's command policy denied this";
const SANDBOX_DENY_PATTERN_NEEDLE: &str = "command denied by sandbox pattern '";
const SANDBOX_ALLOW_LIST_NEEDLE: &str = "command is not on the sandbox allow list";

/// The deny glob quoted in a `command denied by sandbox pattern '<pattern>'`
/// message, if present.
fn sandbox_denied_pattern(message: &str) -> Option<&str> {
    let start = message.find(SANDBOX_DENY_PATTERN_NEEDLE)? + SANDBOX_DENY_PATTERN_NEEDLE.len();
    let rest = &message[start..];
    let end = rest.find('\'')?;
    Some(&rest[..end])
}

/// Append an actionable tip when the node's command sandbox/policy denies a
/// command (`limits.json`, `--allow-cmd`/`--deny-cmd`) — distinct from a
/// signed-grant capability denial or an OS EACCES. Idempotent; unrelated
/// failures are left alone.
fn decorate_sandbox_denial(message: &str) -> String {
    if message.contains(SANDBOX_DENIAL_TIP_MARKER) {
        return message.to_string();
    }
    let clause = if let Some(pattern) = sandbox_denied_pattern(message) {
        format!("pattern `{pattern}` matched a `--deny-cmd` rule")
    } else if message.contains(SANDBOX_ALLOW_LIST_NEEDLE) {
        "the command is outside the node's `--allow-cmd` allow list".to_string()
    } else {
        return message.to_string();
    };
    format!(
        "{message}. tip: the node's command policy denied this (`limits.json`), not your signed \
         grant — {clause}. Don't retry the same line unchanged; use an allowed alternative, or ask \
         the operator to allow it by editing the node's `limits.json` or (re)starting the node with \
         `agentlink node --allow-cmd '<glob>'` (deny wins over allow). See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod sandbox_denial_tip_tests {
    use super::*;

    #[test]
    fn deny_pattern_gets_the_tip_once() {
        let raw = "exec build: permission denied: command denied by sandbox pattern 'rm -rf *'";
        let out = decorate_sandbox_denial(raw);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(out.matches(SANDBOX_DENIAL_TIP_MARKER).count(), 1, "{out}");
        assert!(
            out.contains("pattern `rm -rf *` matched a `--deny-cmd` rule"),
            "{out}"
        );
        assert!(out.contains("not your signed grant"), "{out}");
        assert!(
            out.contains("`agentlink node --allow-cmd '<glob>'`"),
            "{out}"
        );
        assert!(out.contains("(deny wins over allow)"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_sandbox_denial(&out), out);
    }

    #[test]
    fn allow_list_gets_the_tip_once() {
        let raw =
            "bg start cargo watch: permission denied: command is not on the sandbox allow list";
        let out = decorate_sandbox_denial(raw);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(out.matches(SANDBOX_DENIAL_TIP_MARKER).count(), 1, "{out}");
        assert!(
            out.contains("outside the node's `--allow-cmd` allow list"),
            "{out}"
        );
        assert!(!out.contains("`--deny-cmd` rule"), "{out}");
        assert_eq!(decorate_sandbox_denial(&out), out);
    }

    #[test]
    fn wrapped_and_bare_forms_are_decorated() {
        for raw in [
            "permission denied: command denied by sandbox pattern 'sudo **'",
            "exec deploy: permission denied: command denied by sandbox pattern 'curl *'",
            "permission denied: command is not on the sandbox allow list",
            "bg start make -j8: permission denied: command is not on the sandbox allow list",
        ] {
            let out = decorate_sandbox_denial(raw);
            assert!(out.starts_with(raw), "{raw} => {out}");
            assert_eq!(
                out.matches(SANDBOX_DENIAL_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert_eq!(decorate_sandbox_denial(&out), out, "{raw}");
        }
    }

    #[test]
    fn unrelated_and_already_decorated_errors_are_unchanged() {
        for raw in [
            "permission denied: exec is not allowed on this node (read-only)",
            "exec hostname: exec is not allowed on this node",
            "Permission denied (os error 13)",
            "exec hostname: spawn: Permission denied (os error 13)",
            "spawn: Permission denied (os error 13). tip: the target may exist but is not \
             executable — set the bit with `chmod +x`",
            "old string is empty",
            "patch /tmp/x: hunk 1 does not apply",
            "not found: background process 7",
            "not found: node 'foo'",
            "node offline: probe",
            "authentication failed: session expired or revoked",
            "permission denied: command denied by sandbox pattern 'x'. tip: the node's command \
             policy denied this (`limits.json`)",
        ] {
            assert_eq!(decorate_sandbox_denial(raw), raw, "{raw}");
        }
    }
}

const SANDBOX_PATH_ESCAPE_TIP_MARKER: &str = "outside the node's filesystem root";
const SANDBOX_PATH_ESCAPE_NEEDLE: &str = "path escapes sandbox: ";

/// Append an actionable tip when a file/path op resolves outside a node's
/// `--root` filesystem jail (`permission denied: path escapes sandbox: <path>`),
/// distinct from an OS permission bit or the command allow/deny policy.
/// Idempotent; unrelated and sibling sandbox errors are left alone.
fn decorate_sandbox_path_escape(message: &str) -> String {
    if message.contains(SANDBOX_PATH_ESCAPE_TIP_MARKER)
        || !message.contains(SANDBOX_PATH_ESCAPE_NEEDLE)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {SANDBOX_PATH_ESCAPE_TIP_MARKER} — the node was started with `--root` and \
         rejects paths that resolve outside it; this is not an OS permission bit, so \
         `sudo`/`chmod` will not help. Run `agentlink ls <node>` (no PATH; MCP `list_dir` with no \
         `path`) to see the root, then use a path under it — a relative path is joined to the \
         root, and `~` is not expanded. Symlinks are canonicalized, so a link that points outside \
         the root is denied too. The same jail covers cat/write/cp/edit/search/find/watch/patch \
         and `exec --cwd`; ask the operator to widen or remove `--root` if the path must be \
         reachable. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod sandbox_path_escape_tip_tests {
    use super::*;

    fn assert_tipped_once(raw: &str) -> String {
        let out = decorate_sandbox_path_escape(raw);
        assert!(out.starts_with(raw), "{raw} => {out}");
        assert_eq!(
            out.matches(SANDBOX_PATH_ESCAPE_TIP_MARKER).count(),
            1,
            "{raw}: {out}"
        );
        assert!(out.contains("`sudo`/`chmod` will not help"), "{out}");
        assert!(
            out.contains("Run `agentlink ls <node>` (no PATH; MCP `list_dir` with no `path`)"),
            "{out}"
        );
        assert!(out.contains("a relative path is joined to the root"), "{out}");
        assert!(out.contains("`~` is not expanded"), "{out}");
        assert!(out.contains("Symlinks are canonicalized"), "{out}");
        assert!(
            out.contains("cat/write/cp/edit/search/find/watch/patch"),
            "{out}"
        );
        assert!(out.contains("`exec --cwd`"), "{out}");
        assert!(out.contains("widen or remove `--root`"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_sandbox_path_escape(&out), out, "{raw}");
        out
    }

    #[test]
    fn linux_absolute_path_gets_the_tip_once() {
        assert_tipped_once("permission denied: path escapes sandbox: /tmp/out.txt");
    }

    #[test]
    fn tilde_and_windows_drive_forms_get_the_tip_once() {
        assert_tipped_once("permission denied: path escapes sandbox: ~/app");
        assert_tipped_once("permission denied: path escapes sandbox: C:\\tmp\\out.txt");
        assert_tipped_once("permission denied: path escapes sandbox: D:/data/x");
    }

    #[test]
    fn wrapped_cat_path_gets_the_tip_once() {
        assert_tipped_once(
            "cat /etc/passwd: permission denied: path escapes sandbox: /etc/passwd",
        );
    }

    #[test]
    fn already_tipped_and_unrelated_errors_are_unchanged() {
        for raw in [
            "path escapes sandbox: /tmp/out.txt. tip: outside the node's filesystem root",
            "patch path escapes the root: ../../etc/passwd",
            "path escapes directory: ../x",
            "permission denied: command denied by sandbox pattern 'rm -rf *'",
            "permission denied: command is not on the sandbox allow list",
            "permission denied: exec is not allowed on this node (read-only)",
            "Permission denied (os error 13)",
            "exec hostname: spawn: Permission denied (os error 13)",
            "sandbox root: No such file or directory (os error 2)",
            "not found: /srv/app/src",
            "no existing ancestor for /x",
        ] {
            assert_eq!(decorate_sandbox_path_escape(raw), raw, "{raw}");
        }
    }
}

const PATCH_HUNK_MISMATCH_TIP_MARKER: &str = "nothing was written (patch is atomic)";

/// Append an actionable tip when a unified-diff hunk does not apply because the
/// file no longer matches the diff (stale context, indentation, or CRLF).
/// Idempotent. Empty/oversized/no-header patches, new-file patch fallbacks,
/// path errors, and unrelated failures are left alone.
fn decorate_patch_hunk_mismatch(message: &str) -> String {
    const NEEDLE: &str = ": error applying hunk #";
    if message.contains(PATCH_HUNK_MISMATCH_TIP_MARKER)
        || message.contains("could not apply new-file patch")
        || !message.contains(NEEDLE)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: the file no longer matches this diff — it changed since the diff was \
         made, or context/indentation/CRLF differs — and nothing was written (patch is atomic). \
         Re-read it with `agentlink cat <node> <path>`, regenerate the diff against the current \
         text, or make a surgical edit with `agentlink replace <node> <path> <old> <new>` (unique \
         anchor) / `agentlink edit-lines <node> <path> <start> <end>`; see `agentlink guide <node>`"
    )
}

#[cfg(test)]
mod patch_hunk_mismatch_tip_tests {
    use super::*;

    #[test]
    fn applying_hunk_failure_gets_the_tip_once() {
        let out = decorate_patch_hunk_mismatch("patch /srv/app/src.rs: error applying hunk #1");
        assert_eq!(
            out,
            "patch /srv/app/src.rs: error applying hunk #1. tip: the file no longer matches this \
             diff — it changed since the diff was made, or context/indentation/CRLF differs — and \
             nothing was written (patch is atomic). Re-read it with `agentlink cat <node> \
             <path>`, regenerate the diff against the current text, or make a surgical edit with \
             `agentlink replace <node> <path> <old> <new>` (unique anchor) / `agentlink \
             edit-lines <node> <path> <start> <end>`; see `agentlink guide <node>`"
        );
        assert_eq!(decorate_patch_hunk_mismatch(&out), out);
    }

    #[test]
    fn wrapped_hunk_failure_gets_the_tip_once() {
        for raw in [
            "apply patch: patch /srv/app/src.rs: error applying hunk #2",
            "patch /home/me/notes.txt: error applying hunk #12 (context mismatch)",
        ] {
            let out = decorate_patch_hunk_mismatch(raw);
            assert!(out.starts_with(raw), "{out}");
            assert_eq!(
                out.matches(PATCH_HUNK_MISMATCH_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert!(out.contains("`agentlink cat <node> <path>`"), "{out}");
            assert!(
                out.contains("`agentlink replace <node> <path> <old> <new>`"),
                "{out}"
            );
            assert!(
                out.contains("`agentlink edit-lines <node> <path> <start> <end>`"),
                "{out}"
            );
            assert!(out.contains("`agentlink guide <node>`"), "{out}");
            assert_eq!(decorate_patch_hunk_mismatch(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_patch_errors_are_unchanged() {
        for raw in [
            "could not apply new-file patch for /srv/app/new.rs: error applying hunk #1",
            "patch is empty",
            "patch exceeds 1 MiB",
            "patch has no unified diff headers (--- / +++)",
            "invalid patch path '../etc/passwd'",
            "patch path escapes the root: ../../etc/passwd",
            "patch section has no path",
        ] {
            assert_eq!(decorate_patch_hunk_mismatch(raw), raw, "{raw}");
        }
    }

    #[test]
    fn already_tipped_and_unrelated_errors_are_unchanged() {
        for raw in [
            "patch /srv/app/src.rs: error applying hunk #1. tip: the file no longer matches this \
             diff and nothing was written (patch is atomic)",
            "old string was not found in /tmp/x. tip: read the current text with `agentlink cat \
             <node> <path>`",
            "not found: node 'foo'",
            "node offline: probe",
            "exec hostname: connection reset by peer",
            "patch /tmp/x: hunk 1 does not apply",
        ] {
            assert_eq!(decorate_patch_hunk_mismatch(raw), raw, "{raw}");
        }
    }
}

const PATCH_PARSE_TIP_MARKER: &str = "the diff text is malformed, not a stale file";
// diffy's `ParsePatchError` Display starts with this exact prefix (diffy 0.4.2,
// reached only from `edit.rs::apply_diff`). The trailing space keeps it clear
// of the stale-file needle `": error applying hunk #"`; a substring match is
// safe on both the CLI and MCP chains.
const PATCH_PARSE_NEEDLE: &str = "error parsing patch: ";

fn is_patch_parse_error(message: &str) -> bool {
    message.contains(PATCH_PARSE_NEEDLE)
}

/// Append an actionable tip when the node rejects a unified diff at parse time
/// (`diffy` `ParsePatchError`): the hunk header counts/order/grammar are wrong,
/// so the target file is fine and nothing was written. Idempotent; the separate
/// `error applying hunk #` stale-file case and sibling patch tips are left
/// alone.
fn decorate_patch_parse(message: &str) -> String {
    if message.contains(PATCH_PARSE_TIP_MARKER) || !is_patch_parse_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {PATCH_PARSE_TIP_MARKER} — the node parsed this diff before touching any \
         file and rejected it: diffy's `error parsing patch: …` means the patch text itself is \
         inconsistent, so re-reading the target will not help (that is the separate `error \
         applying hunk #N` case). The usual causes are that the hunk header's old/new line counts \
         do not equal the body's lines (`Hunk header does not match hunk`), that hunks are out of \
         order or overlap (`Hunks not in order or overlap`), or that a header is not exactly `@@ \
         -<old_start>[,<old_count>] +<new_start>[,<new_count>] @@` (`unable to parse hunk header`, \
         `hunk header unterminated`, `can't parse range`). How to count: each body line with a \
         leading space (context) counts once toward BOTH sides, `-` counts only toward old, `+` \
         only toward new, an omitted count means 1, a new file uses `-0,0`, and an empty file uses \
         `+0,0`. For `@@ -1,3 +1,3 @@` followed by ` context`, `-old`, `+new`, the correct header \
         is `@@ -1,2 +1,2 @@`. Sort hunks by ascending old start and never let their ranges \
         overlap; nothing was written — the whole patch is parsed and applied atomically. \
         Regenerate the diff with `git diff -U3 --no-color -- <paths>` or `diff -u <old> <new>`, \
         or make the change surgically with `agentlink replace <node> <path> <old> <new>` (MCP \
         `replace_text`) / `agentlink edit-lines <node> <path> <start> <end> <text>` (MCP \
         `edit_lines`), or rewrite the file with `agentlink write <node> <path>` (MCP \
         `write_file`). CLI: `agentlink patch <node> <root> --file <diff>` (or pipe the diff; \
         `--file -` reads stdin). MCP: `apply_patch` with `root` and `patch`. Retrying the same \
         text unchanged fails the same way. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod patch_parse_tip_tests {
    use super::*;

    #[test]
    fn hunk_count_mismatch_gets_the_tip_once() {
        let raw = "patch /srv/app/src.rs: error parsing patch: Hunk header does not match hunk";
        let out = decorate_patch_parse(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {PATCH_PARSE_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(PATCH_PARSE_TIP_MARKER).count(), 1, "{out}");
        assert!(
            out.contains("@@ -<old_start>[,<old_count>] +<new_start>[,<new_count>] @@"),
            "{out}"
        );
        assert!(out.contains("`@@ -1,2 +1,2 @@`"), "{out}");
        assert!(out.contains("counts once toward BOTH sides"), "{out}");
        assert!(out.contains("Hunks not in order or overlap"), "{out}");
        assert!(out.contains("unable to parse hunk header"), "{out}");
        assert!(out.contains("hunk header unterminated"), "{out}");
        assert!(out.contains("`can't parse range`"), "{out}");
        assert!(out.contains("not a stale file"), "{out}");
        assert!(out.contains("nothing was written"), "{out}");
        assert!(out.contains("`replace_text`"), "{out}");
        assert!(out.contains("`edit_lines`"), "{out}");
        assert!(out.contains("`write_file`"), "{out}");
        assert!(
            out.contains("`agentlink patch <node> <root> --file <diff>`"),
            "{out}"
        );
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        assert_eq!(decorate_patch_parse(&out), out);
    }

    #[test]
    fn every_parse_detail_gets_the_tip_once() {
        for detail in [
            "Hunk header does not match hunk",
            "Hunks not in order or overlap",
            "unable to parse hunk header",
            "hunk header unterminated",
            "can't parse range",
        ] {
            for raw in [
                format!("patch /srv/app/src.rs: error parsing patch: {detail}"),
                format!("apply_patch: patch /srv/app/src.rs: error parsing patch: {detail}"),
                format!("patch task: patch /srv/app/src.rs: error parsing patch: {detail}"),
            ] {
                let out = decorate_patch_parse(&raw);
                assert!(out.starts_with(raw.as_str()), "{out}");
                assert_eq!(
                    out.matches(PATCH_PARSE_TIP_MARKER).count(),
                    1,
                    "{raw}: {out}"
                );
                assert_eq!(decorate_patch_parse(&out), out, "{raw}");
            }
        }
    }

    #[test]
    fn new_file_fallback_form_gets_the_tip_once() {
        let raw = "could not apply new-file patch for /srv/app/new.rs: error parsing patch: Hunk \
                   header does not match hunk";
        let out = decorate_patch_parse(raw);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(out.matches(PATCH_PARSE_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_patch_parse(&out), out);
    }

    #[test]
    fn sibling_and_unrelated_errors_are_unchanged() {
        for raw in [
            "patch is empty",
            "patch exceeds 1 MiB",
            "patch has no unified diff headers (--- / +++)",
            "patch section has no path",
            "invalid patch path '../etc/passwd'",
            "patch path escapes the root: ../../etc/passwd",
            "patch /srv/app/src.rs: error applying hunk #1",
            "could not apply new-file patch for /srv/app/new.rs: error applying hunk #1",
            "patch /srv/app/src.rs: Hunk header does not match hunk",
            "old string was not found in /srv/app/x",
            "io: No such file or directory (os error 2)",
            "node offline: probe",
        ] {
            assert_eq!(decorate_patch_parse(raw), raw, "{raw}");
        }
    }
}

const PATCH_ROOT_NOT_DIR_TIP_MARKER: &str =
    "the patch root must be an existing directory, not the file to patch";

/// True for the node's bare `<absolute path> is not a directory` from the
/// `apply_patch` root guard (`base.is_dir()`). The suffix match tolerates an
/// optional `patch task: ` panic prefix or tool prefix; the two exclusions
/// carve out mkdir/util/mv/rename sibling messages that must stay untouched.
fn is_patch_root_not_dir_error(message: &str) -> bool {
    let message = message.trim_end();
    message.ends_with(" is not a directory")
        && !message.contains("exists but is not a directory")
        && !message.ends_with("ends with a slash but is not a directory")
}

/// Append an actionable tip when `patch` (CLI) / `apply_patch` (MCP) is given a
/// `root` that resolves to a non-directory (or does not exist): the node's bare
/// `<path> is not a directory` names neither the argument nor the operation.
/// Idempotent; sibling `exists but` / `ends with a slash` forms are unchanged.
fn decorate_patch_root_not_dir(message: &str) -> String {
    if message.contains(PATCH_ROOT_NOT_DIR_TIP_MARKER) || !is_patch_root_not_dir_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {PATCH_ROOT_NOT_DIR_TIP_MARKER} — the node checked the directory argument \
         before touching any file and found it is not a directory. In `patch` (CLI) / \
         `apply_patch` (MCP) that argument is `root`: every `---`/`+++` path in the diff is joined \
         to it, so it must be an existing directory that contains the files you are patching — \
         pass the parent directory, not the file itself (e.g. `agentlink patch <node> /srv/app \
         --file change.diff` / MCP `apply_patch` with `\"root\": \"/srv/app\"`, where the headers \
         are `a/src.rs` / `b/src.rs`). This one message covers two different faults because the \
         guard is `is_dir()`: the path is a regular file (or a symlink resolving to one), **or it \
         does not exist at all** — a missing root whose parent exists is reported this way rather \
         than as `does not exist` (a missing *parent* gives the separate `parent directory does \
         not exist` error). Check the parent with `agentlink ls <node> <parent>` / MCP `list_dir` \
         or `stat_path`; if the directory is genuinely missing, create it first with `agentlink \
         mkdir <node> <path> -p` / MCP `mkdir`, or omit `root` to apply relative to the node's \
         current directory (MCP default `.`). Nothing was written: the root check runs before the \
         diff is parsed or any hunk is applied, so this is not the `error parsing patch` / `error \
         applying hunk #` family. If you meant to change one already-known file rather than apply \
         a whole diff, use `agentlink replace <node> <path> <old> <new>` (MCP `replace_text`) or \
         `agentlink edit-lines <node> <path> <start> <end> <text>` (MCP `edit_lines`). The path \
         above is the node-resolved root (`~` is not expanded; the node's `--root` jail applies). \
         Retrying the same arguments fails the same way. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod patch_root_not_dir_tip_tests {
    use super::*;

    #[test]
    fn file_root_gets_the_tip_once() {
        let raw = "/srv/app/src.rs is not a directory";
        let out = decorate_patch_root_not_dir(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {PATCH_ROOT_NOT_DIR_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(
            out.matches(PATCH_ROOT_NOT_DIR_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(
            out.contains("pass the parent directory, not the file itself"),
            "{out}"
        );
        assert!(out.contains("/srv/app --file change.diff"), "{out}");
        assert!(out.contains("\"root\": \"/srv/app\""), "{out}");
        assert!(out.contains("is_dir()"), "{out}");
        assert!(out.contains("does not exist at all"), "{out}");
        assert!(out.contains("`agentlink mkdir <node> <path> -p`"), "{out}");
        assert!(out.contains("`replace_text`"), "{out}");
        assert!(out.contains("`edit_lines`"), "{out}");
        assert!(out.contains("`error parsing patch`"), "{out}");
        assert!(out.contains("Nothing was written"), "{out}");
        assert!(out.contains("`agentlink guide <node>`"), "{out}");
        let again = decorate_patch_root_not_dir(&out);
        assert_eq!(again, out);
    }

    #[test]
    fn missing_and_symlink_forms_get_the_tip_once() {
        for raw in [
            "/srv/app/missing is not a directory",
            "/srv/app/link-to-file is not a directory",
            "patch task: /srv/app/src.rs is not a directory",
            "apply_patch: /srv/app/src.rs is not a directory",
        ] {
            let out = decorate_patch_root_not_dir(raw);
            assert!(out.starts_with(raw), "{out}");
            assert_eq!(
                out.matches(PATCH_ROOT_NOT_DIR_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert_eq!(decorate_patch_root_not_dir(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_not_a_directory_errors_are_unchanged() {
        for raw in [
            "mkdir `/srv/app` exists but is not a directory",
            "path component `/srv/app/x` exists but is not a directory",
            "path component `/srv/app/x` exists but is not a directory; cannot create parent \
             directories for write/cp",
            "mv destination parent `/srv/app` exists but is not a directory",
            "destination `/srv/app/x` ends with a slash but is not a directory",
            "rename: /srv/app/x ends with a slash but is not a directory",
            "cwd /srv/file: Not a directory",
            "io: Not a directory (os error 20)",
            "/srv/app/reports is a directory",
            "patch is empty",
            "patch exceeds 1 MiB",
            "patch has no unified diff headers (--- / +++)",
            "patch /srv/app/src.rs: error parsing patch: Hunk header does not match hunk",
            "patch /srv/app/src.rs: error applying hunk #1",
            "parent directory does not exist: /srv/app",
        ] {
            assert_eq!(decorate_patch_root_not_dir(raw), raw, "{raw}");
        }
    }
}

const PATCH_PATH_TIP_MARKER: &str = "patch headers must be relative to the patch root";

/// True for the three `safe_relative` header rejections: invalid
/// (empty/NUL/`:`), absolute, or escaping with `..`/non-normal components.
fn is_patch_path_error(message: &str) -> bool {
    message.contains("invalid patch path '")
        || message.contains("patch path must stay inside the root: ")
        || message.contains("patch path escapes the root: ")
}

/// Append an actionable tip when a diff header path is rejected because it is
/// absolute, escapes with `..`, or is invalid (empty/NUL/`:`). Idempotent.
/// Hunk mismatches, empty/oversized/no-header patches, new-file fallbacks,
/// pathless sections, and unrelated failures are left alone.
fn decorate_patch_path(message: &str) -> String {
    if message.contains(PATCH_PATH_TIP_MARKER) || !is_patch_path_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: patch headers must be relative to the patch root (`agentlink patch \
         <node> <root> --file <diff>`): rewrite `---`/`+++` as `a/<path>` / `b/<path>`, strip a \
         leading `/` or drive letter (`:` is rejected), and don't climb out with `..`; the root \
         does not make absolute headers legal. Regenerate the diff, or edit per file with \
         `agentlink replace` / `agentlink edit-lines`; see `agentlink guide <node>`"
    )
}

#[cfg(test)]
mod patch_path_tip_tests {
    use super::*;

    const TIP: &str = "tip: patch headers must be relative to the patch root (`agentlink patch \
         <node> <root> --file <diff>`): rewrite `---`/`+++` as `a/<path>` / `b/<path>`, strip a \
         leading `/` or drive letter (`:` is rejected), and don't climb out with `..`; the root \
         does not make absolute headers legal. Regenerate the diff, or edit per file with \
         `agentlink replace` / `agentlink edit-lines`; see `agentlink guide <node>`";

    #[test]
    fn path_rejections_get_the_tip_once() {
        for raw in [
            "invalid patch path '../etc/passwd'",
            "invalid patch path ''",
            "invalid patch path 'C:\\tmp\\x'",
            "patch path must stay inside the root: /etc/passwd",
            "patch path escapes the root: ../../etc/passwd",
            "patch path escapes the root: ./a/../b",
        ] {
            let out = decorate_patch_path(raw);
            assert_eq!(out, format!("{raw}. {TIP}"), "{raw}");
            assert_eq!(
                out.matches(PATCH_PATH_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert_eq!(decorate_patch_path(&out), out, "{raw}");
        }
    }

    #[test]
    fn wrapped_path_rejections_get_the_tip_once() {
        for raw in [
            "apply patch: invalid patch path '/etc/passwd'",
            "patch /srv/app: patch path must stay inside the root: /etc/passwd",
            "apply patch: patch path escapes the root: ../outside.rs",
        ] {
            let out = decorate_patch_path(raw);
            assert!(out.starts_with(raw), "{out}");
            assert_eq!(
                out.matches(PATCH_PATH_TIP_MARKER).count(),
                1,
                "{raw}: {out}"
            );
            assert!(out.contains("`agentlink replace`"), "{out}");
            assert!(out.contains("`agentlink edit-lines`"), "{out}");
            assert!(out.contains("`agentlink guide <node>`"), "{out}");
            assert_eq!(decorate_patch_path(&out), out, "{raw}");
        }
    }

    #[test]
    fn hunk_decorator_leaves_path_errors_for_this_tip() {
        let raw = "patch path escapes the root: ../../etc/passwd";
        assert_eq!(decorate_patch_hunk_mismatch(raw), raw);
        let out = decorate_patch_path(&decorate_patch_hunk_mismatch(raw));
        assert_eq!(out, decorate_patch_path(raw));
    }

    #[test]
    fn sibling_patch_and_unrelated_errors_are_unchanged() {
        for raw in [
            "patch /srv/app/src.rs: error applying hunk #1",
            "could not apply new-file patch for /srv/app/new.rs: error applying hunk #1",
            "patch is empty",
            "patch exceeds 1 MiB",
            "patch has no unified diff headers (--- / +++)",
            "patch section has no path",
            "permission denied: command denied by sandbox pattern 'x'",
            "old string is empty",
            "not found: node 'foo'",
            "node offline: probe",
            "exec hostname: connection reset by peer",
        ] {
            assert_eq!(decorate_patch_path(raw), raw, "{raw}");
        }
    }

    #[test]
    fn already_tipped_messages_are_unchanged() {
        let already = format!("invalid patch path '../x'. {TIP}");
        assert_eq!(decorate_patch_path(&already), already);
    }
}

const EXEC_PATH_MISS_TIP_MARKER: &str = "shell builtins/aliases/pipelines need a shell";

/// Extract `<prog>` from `program '<prog>' not found on PATH (...)`, including
/// one wrapped in an anyhow context chain.
fn exec_path_miss_program(message: &str) -> Option<&str> {
    const NEEDLE: &str = "program '";
    const SUFFIX: &str = "' not found on PATH (";
    let start = message.rfind(NEEDLE)? + NEEDLE.len();
    let rest = &message[start..];
    let end = rest.find(SUFFIX)?;
    let program = &rest[..end];
    (!program.is_empty()).then_some(program)
}

/// Append an actionable tip when a bare `exec` argv names a program that is not
/// on the node's PATH — shell builtins, aliases, pipelines, and `cd`/`export`
/// need a shell, not a bare argv. Idempotent. Path-like programs, generic
/// filesystem errors, and messages already mentioning `--shell` are left alone.
fn decorate_exec_path_miss(message: &str) -> String {
    if message.contains(EXEC_PATH_MISS_TIP_MARKER) || message.contains("--shell") {
        return message.to_string();
    }
    match exec_path_miss_program(message) {
        Some(program) => format!(
            "{message}. tip: '{program}' is not on the node's PATH — \
             {EXEC_PATH_MISS_TIP_MARKER}, not a bare argv: \
             `agentlink exec <node> --shell '<cmd>'`"
        ),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod exec_path_miss_tip_tests {
    use super::*;

    #[test]
    fn missing_program_gets_the_shell_tip_once() {
        let out = decorate_exec_path_miss(
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
        );
        assert_eq!(
            out,
            "program 'cd' not found on PATH (No such file or directory (os error 2)). tip: 'cd' \
             is not on the node's PATH — shell builtins/aliases/pipelines need a shell, not a \
             bare argv: `agentlink exec <node> --shell '<cmd>'`"
        );
        assert_eq!(decorate_exec_path_miss(&out), out);
    }

    #[test]
    fn wrapped_missing_program_uses_the_quoted_name() {
        let out = decorate_exec_path_miss(
            "exec box: program 'grep' not found on PATH (No such file or directory (os error 2))",
        );
        assert!(
            out.contains("tip: 'grep' is not on the node's PATH"),
            "{out}"
        );
        assert_eq!(out.matches(EXEC_PATH_MISS_TIP_MARKER).count(), 1, "{out}");
        assert!(
            out.contains("`agentlink exec <node> --shell '<cmd>'`"),
            "{out}"
        );
    }

    #[test]
    fn path_like_and_unrelated_errors_are_unchanged() {
        for raw in [
            "program '/opt/missing/tool' not found (No such file or directory (os error 2))",
            "cp /tmp/a: No such file or directory",
            "Permission denied (os error 13)",
            "node offline: probe",
            "not found: node 'foo'",
            "authentication failed: grant has expired",
            "old string was not found in /tmp/x",
            "exec bash --shell 'cd /tmp'",
        ] {
            assert_eq!(decorate_exec_path_miss(raw), raw, "{raw}");
        }
    }
}

const EXEC_PROGRAM_PATH_MISS_TIP_MARKER: &str = "that program path is missing on the node";

/// Extract `<prog>` from the path-like form `program '<prog>' not found (...)`
/// (not `not found on PATH`), including one wrapped in an anyhow context chain.
fn exec_program_path_miss_program(message: &str) -> Option<&str> {
    const NEEDLE: &str = "program '";
    const SUFFIX: &str = "' not found (";
    let start = message.rfind(NEEDLE)? + NEEDLE.len();
    let rest = &message[start..];
    let end = rest.find(SUFFIX)?;
    let program = &rest[..end];
    (!program.is_empty() && (program.contains('/') || program.contains('\\'))).then_some(program)
}

/// Append an actionable tip when a path-like `exec` argv (`./gradlew`,
/// `/opt/tool`, `~/bin/tool`) does not exist on the node. Bare names are left to
/// [`decorate_exec_path_miss`]; messages already mentioning `--shell` or the PATH
/// form are untouched. Idempotent.
fn decorate_exec_program_path_miss(message: &str) -> String {
    if message.contains(EXEC_PROGRAM_PATH_MISS_TIP_MARKER)
        || message.contains("--shell")
        || message.contains("not found on PATH")
    {
        return message.to_string();
    }
    match exec_program_path_miss_program(message) {
        Some(_) => format!(
            "{message}. tip: {EXEC_PROGRAM_PATH_MISS_TIP_MARKER} — relative paths resolve \
             against the node's cwd, not your shell (pass `--cwd <dir>` / MCP `cwd`, or an \
             absolute path); `~` is not expanded without a shell (`agentlink exec <node> \
             --shell '<cmd>'`); check with `agentlink ls <node> <dir>`; if the file exists, its \
             `#!` interpreter may be absent (posix_spawn reports ENOENT for that too)."
        ),
        None => message.to_string(),
    }
}

#[cfg(test)]
mod exec_program_path_miss_tip_tests {
    use super::*;

    #[test]
    fn relative_path_gets_the_node_tip_once() {
        let out = decorate_exec_program_path_miss(
            "program './gradlew' not found (No such file or directory (os error 2))",
        );
        assert_eq!(
            out,
            "program './gradlew' not found (No such file or directory (os error 2)). tip: that \
             program path is missing on the node — relative paths resolve against the node's \
             cwd, not your shell (pass `--cwd <dir>` / MCP `cwd`, or an absolute path); `~` is \
             not expanded without a shell (`agentlink exec <node> --shell '<cmd>'`); check with \
             `agentlink ls <node> <dir>`; if the file exists, its `#!` interpreter may be absent \
             (posix_spawn reports ENOENT for that too)."
        );
        assert_eq!(decorate_exec_program_path_miss(&out), out);
    }

    #[test]
    fn absolute_path_and_home_path_are_tipped() {
        for raw in [
            "program '/opt/missing/tool' not found (No such file or directory (os error 2))",
            "program '~/bin/tool' not found (No such file or directory (os error 2))",
        ] {
            let out = decorate_exec_program_path_miss(raw);
            assert!(
                out.contains(EXEC_PROGRAM_PATH_MISS_TIP_MARKER),
                "{raw} -> {out}"
            );
            assert_eq!(
                out.matches(EXEC_PROGRAM_PATH_MISS_TIP_MARKER).count(),
                1,
                "{out}"
            );
        }
    }

    #[test]
    fn wrapped_missing_program_is_tipped() {
        let out = decorate_exec_program_path_miss(
            "exec box: program '/srv/app/tool' not found (No such file or directory (os error 2))",
        );
        assert!(out.contains(EXEC_PROGRAM_PATH_MISS_TIP_MARKER), "{out}");
        assert!(out.contains("`agentlink ls <node> <dir>`"), "{out}");
        assert!(out.contains("`--cwd <dir>`"), "{out}");
        assert_eq!(
            out.matches(EXEC_PROGRAM_PATH_MISS_TIP_MARKER).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn already_tipped_messages_are_unchanged() {
        let already = format!(
            "program './gradlew' not found (No such file or directory (os error 2)). tip: {EXEC_PROGRAM_PATH_MISS_TIP_MARKER} — ..."
        );
        assert_eq!(decorate_exec_program_path_miss(&already), already);
    }

    #[test]
    fn path_form_no_slash_and_unrelated_errors_are_unchanged() {
        for raw in [
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "program 'grep' not found (No such file or directory (os error 2))",
            "exec bash --shell 'cd /tmp'",
            "spawn: No such file or directory (os error 2)",
            "node offline: probe",
            "not found: node 'foo'",
            "Permission denied (os error 13)",
            "cp /tmp/a: No such file or directory",
        ] {
            assert_eq!(decorate_exec_program_path_miss(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod exec_cwd_miss_tip_tests {
    use super::*;

    #[test]
    fn enoent_raw_gets_the_tip_once() {
        let out =
            decorate_exec_cwd_missing("cwd /tmp/missing: No such file or directory (os error 2)");
        assert_eq!(
            out,
            "cwd /tmp/missing: No such file or directory (os error 2). tip: the target directory \
             does not exist on the node — create it first (`agentlink mkdir <node> <dir> -p` / MCP \
             `mkdir`), pass an absolute path, or omit `cwd` and `cd`/`--shell` instead; relative \
             paths resolve against the node's cwd and `~` is not expanded."
        );
        assert_eq!(out.matches(EXEC_CWD_MISS_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_exec_cwd_missing(&out), out);
    }

    #[test]
    fn enotdir_raw_gets_the_tip_once() {
        let out = decorate_exec_cwd_missing("cwd /tmp/file: Not a directory");
        assert!(out.contains(EXEC_CWD_MISS_TIP_MARKER), "{out}");
        assert!(
            out.contains("`/tmp/file` exists but is not a directory"),
            "{out}"
        );
        assert!(out.contains("`agentlink mkdir <node> <dir> -p`"), "{out}");
        assert!(out.contains("MCP `mkdir`"), "{out}");
        assert!(out.contains("`~` is not expanded"), "{out}");
        assert_eq!(out.matches(EXEC_CWD_MISS_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_exec_cwd_missing(&out), out);
    }

    #[test]
    fn enotdir_os_error_20_is_not_treated_as_enoent() {
        let out = decorate_exec_cwd_missing("cwd /tmp/file: Not a directory (os error 20)");
        assert!(
            out.contains("`/tmp/file` exists but is not a directory"),
            "{out}"
        );
        assert!(!out.contains("create it first"), "{out}");
    }

    #[test]
    fn wrapped_message_gets_the_tip_once() {
        let out = decorate_exec_cwd_missing(
            "exec box: cwd /tmp/missing: No such file or directory (os error 2)",
        );
        assert!(out.contains(EXEC_CWD_MISS_TIP_MARKER), "{out}");
        assert_eq!(out.matches(EXEC_CWD_MISS_TIP_MARKER).count(), 1, "{out}");
        assert!(out.contains("`cd`/`--shell`"), "{out}");
        assert_eq!(decorate_exec_cwd_missing(&out), out);
    }

    #[test]
    fn already_tipped_messages_are_unchanged() {
        let already = format!(
            "cwd /tmp/missing: No such file or directory (os error 2). tip: {EXEC_CWD_MISS_TIP_MARKER} — ..."
        );
        assert_eq!(decorate_exec_cwd_missing(&already), already);
    }

    #[test]
    fn existing_cli_hints_are_not_double_tipped() {
        for hinted in [
            "cwd /tmp/missing: No such file or directory (os error 2). Check `--cwd /tmp/missing` \
             exists on the node (create it with `mkdir -p`/`--parents` if needed).",
            "cwd /tmp/file: Not a directory. `/tmp/file` exists but is not a directory; pass a \
             directory path to `--cwd`.",
        ] {
            assert_eq!(decorate_exec_cwd_missing(hinted), hinted, "{hinted}");
        }
    }

    #[test]
    fn unrelated_errors_are_unchanged() {
        for raw in [
            "not found: /tmp/missing",
            "list /tmp/missing: No such file or directory (os error 2)",
            "program './gradlew' not found (No such file or directory (os error 2))",
            "exec /tmp/missing: No such file or directory (os error 2)",
            "cwd /tmp/x: Permission denied (os error 13)",
            "cwd /tmp/x",
            "node offline: probe",
            "approval denied or timed out",
            "Not a directory",
        ] {
            assert_eq!(decorate_exec_cwd_missing(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod exec_cwd_permission_tip_tests {
    use super::*;

    #[test]
    fn unix_and_windows_forms_get_the_tip_once() {
        let unix = "cwd /home/alice/repo: Permission denied (os error 13)";
        let windows = r"cwd C:\Users\Alice\repo: Access is denied. (os error 5)";
        for (raw, path) in [(unix, "/home/alice/repo"), (windows, r"C:\Users\Alice\repo")] {
            let out = decorate_exec_cwd_permission(raw);
            assert!(
                out.starts_with(&format!("{raw}. tip: {EXEC_CWD_PERMISSION_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(
                out.matches(EXEC_CWD_PERMISSION_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(out.matches(". tip:").count(), 1, "{out}");
            assert!(out.contains(path), "{path}: {out}");
            for needle in [
                "run_command",
                "process_start",
                "bg start",
                "stat_path",
                "getfacl",
                "icacls",
                "agentlink guide <node>",
                "working directory",
            ] {
                assert!(out.contains(needle), "{needle}: {out}");
            }
            assert_eq!(decorate_exec_cwd_permission(&out), out);
        }
    }

    #[test]
    fn wrapped_prefix_spaces_and_colons_are_captured() {
        let out = decorate_exec_cwd_permission(
            "exec box: cwd /srv/my app: Permission denied (os error 13)",
        );
        assert!(out.contains("`/srv/my app`"), "{out}");
        assert_eq!(
            out.matches(EXEC_CWD_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );

        let out = decorate_exec_cwd_permission(
            "cwd /srv/a: b/repo: Permission denied (os error 13)",
        );
        assert!(out.contains("`/srv/a: b/repo`"), "{out}");

        let out = decorate_exec_cwd_permission(
            r"cwd C:\Users\Alice\repo: Access is denied. (os error 5)",
        );
        assert!(out.contains(r"`C:\Users\Alice\repo`"), "{out}");
    }

    #[test]
    fn node_named_cwd_and_prefix_words_do_not_capture() {
        for raw in [
            "exec cwd x: spawn: Permission denied (os error 13)",
            "cwdX /tmp/x: Permission denied (os error 13)",
            "cwd : Permission denied (os error 13)",
        ] {
            assert_eq!(decorate_exec_cwd_permission(raw), raw, "{raw}");
        }
    }

    #[test]
    fn unrelated_and_sibling_errors_are_unchanged() {
        for raw in [
            "Permission denied (os error 13)",
            "io: Permission denied (os error 13)",
            "spawn: Permission denied (os error 13)",
            "pty spawn: Permission denied (os error 13)",
            "exec box: spawn: Permission denied (os error 13)",
            "cwd /tmp/missing: No such file or directory (os error 2)",
            "cwd /tmp/file: Not a directory",
            "cwd /tmp/x: Operation not permitted (os error 1)",
            "cwd /tmp/x: Read-only file system (os error 30)",
            "cwd /tmp/x: Too many levels of symbolic links (os error 40)",
            "not found: parent directory does not exist: /home/alice/repo",
            "",
        ] {
            assert_eq!(decorate_exec_cwd_permission(raw), raw, "{raw}");
        }
    }

    #[test]
    fn already_tipped_is_unchanged() {
        let already = format!(
            "cwd /home/alice/repo: Permission denied (os error 13). tip: \
             {EXEC_CWD_PERMISSION_TIP_MARKER} — ..."
        );
        assert_eq!(decorate_exec_cwd_permission(&already), already);
    }

    #[test]
    fn does_not_retrigger_siblings() {
        let raw = "cwd /home/alice/repo: Permission denied (os error 13)";
        let decorated = decorate_exec_cwd_permission(raw);
        assert_ne!(decorated, raw);
        assert_eq!(decorate_exec_cwd_missing(&decorated), decorated);
        assert_eq!(decorate_exec_eacces(&decorated, None), decorated);
        assert_eq!(decorate_exec_enoexec(&decorated), decorated);
        assert_eq!(decorate_missing_parent(&decorated), decorated);
        assert_eq!(decorate_exec_program_path_miss(&decorated), decorated);
    }
}

const EXEC_NOT_EXECUTABLE_TIP_MARKER: &str = "chmod +x";

/// Append an actionable tip when `exec` spawn fails with EACCES ("Permission
/// denied (os error 13)") — the target usually exists but lacks the execute
/// bit. Only the `spawn:` wrapper from `diagnose_spawn` qualifies, so
/// filesystem Permission denied from `cp`/`cat`/`write` (which goes through
/// [`hint_fs_error`]) is left alone. When the caller passed `cwd`, the same
/// line is also indistinguishable from an unenterable working directory, so
/// a directory-first differential is appended; without `cwd` the text is
/// unchanged. Idempotent.
fn decorate_exec_eacces(message: &str, cwd: Option<&str>) -> String {
    if message.contains(EXEC_NOT_EXECUTABLE_TIP_MARKER) || message.contains("--shell") {
        return message.to_string();
    }
    if !message.contains("spawn:")
        || !(message.contains("Permission denied") || message_mentions_os_error(message, 13))
    {
        return message.to_string();
    }
    let cwd_clause = cwd
        .filter(|dir| !dir.is_empty())
        .map(|dir| {
            format!(
                ". Because you passed `--cwd` (`{dir}`), this same line also appears when `{dir}` \
                 exists but cannot be entered — missing search (`x`) on the directory itself, or an \
                 ACL/SELinux rule — because the node only stats `{dir}` before spawning and the \
                 kernel refuses the chdir at spawn, so nothing is learned about the program's mode. \
                 Check `{dir}` first: MCP `stat_path` (its `mode` needs `x` for the account the \
                 node runs as) or `run_command test -x {dir} && echo ok` (without `--cwd`); if \
                 `{dir}` lacks search, add it on `{dir}` itself (`chmod u+x {dir}`, or a `setfacl` \
                 entry). `--shell 'sh …'` cannot bypass this, because the shell spawn needs the \
                 same directory. If `{dir}` is enterable, the program's execute bit is the cause."
            )
        })
        .unwrap_or_default();
    format!(
        "{message}. tip: the target may exist but is not executable — set the bit on the node \
         with `agentlink exec <node> -- chmod +x <path>`, or run it through a shell: \
         `agentlink exec <node> --shell 'sh <path>'`; check `agentlink ls <node> <dir>` for mode bits{cwd_clause}"
    )
}

#[cfg(test)]
mod exec_eacces_tip_tests {
    use super::*;

    const SPAWN_EACCES: &str = "spawn: Permission denied (os error 13)";

    #[test]
    fn spawn_eacces_gets_the_chmod_tip_once() {
        let out = decorate_exec_eacces(SPAWN_EACCES, None);
        assert_eq!(
            out,
            "spawn: Permission denied (os error 13). tip: the target may exist but is not \
             executable — set the bit on the node with `agentlink exec <node> -- chmod +x \
             <path>`, or run it through a shell: `agentlink exec <node> --shell 'sh <path>'`; \
             check `agentlink ls <node> <dir>` for mode bits"
        );
        assert_eq!(
            out.matches(EXEC_NOT_EXECUTABLE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_exec_eacces(&out, None), out);
    }

    #[test]
    fn wrapped_spawn_eacces_gets_the_tip() {
        let out = decorate_exec_eacces(
            "exec hostname: spawn: Permission denied (os error 13)",
            None,
        );
        assert!(out.contains("not executable"), "{out}");
        assert!(out.contains("-- chmod +x <path>"), "{out}");
        assert_eq!(
            out.matches(EXEC_NOT_EXECUTABLE_TIP_MARKER).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn filesystem_permission_denied_is_unchanged() {
        for raw in [
            "Permission denied (os error 13)",
            "io: Permission denied (os error 13)",
            "cp /tmp/a /tmp/b: Permission denied (os error 13)",
            "permission denied: write is not allowed on this node",
            "permission denied: exec is not allowed on this node (read-only)",
        ] {
            assert_eq!(decorate_exec_eacces(raw, None), raw, "{raw}");
            assert_eq!(decorate_exec_eacces(raw, Some("/srv/work")), raw, "{raw}");
        }
    }

    #[test]
    fn path_miss_grant_offline_and_enoent_are_unchanged() {
        for raw in [
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "program '/opt/missing/tool' not found (No such file or directory (os error 2))",
            "spawn: No such file or directory (os error 2)",
            "exec hostname: node offline: probe",
            "authentication failed: grant has expired",
            "not found: node 'foo'",
        ] {
            assert_eq!(decorate_exec_eacces(raw, None), raw, "{raw}");
        }
    }

    #[test]
    fn cwd_hedge_names_the_directory() {
        let out = decorate_exec_eacces(SPAWN_EACCES, Some("/srv/work"));
        assert!(out.starts_with(SPAWN_EACCES), "{out}");
        for needle in ["/srv/work", "stat_path", "test -x", "search"] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        assert_eq!(
            out.matches(EXEC_NOT_EXECUTABLE_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for literal in ["{dir}", "{cwd}"] {
            assert!(!out.contains(literal), "{literal} literal left: {out}");
        }
        assert_eq!(decorate_exec_eacces(&out, Some("/srv/work")), out);
        assert_eq!(decorate_exec_eacces(&out, None), out);
    }

    #[test]
    fn cwd_hedge_only_when_cwd_passed() {
        let none = decorate_exec_eacces(SPAWN_EACCES, None);
        assert!(!none.contains("cannot be entered"), "{none}");
        let some = decorate_exec_eacces(SPAWN_EACCES, Some("/srv/work dir"));
        assert!(some.contains("cannot be entered"), "{some}");
        assert!(some.contains("/srv/work dir"), "{some}");
        assert!(!some.contains("{dir}"), "{some}");
    }

    #[test]
    fn cwd_hedged_exec_is_not_a_cwd_frame() {
        let out = decorate_exec_eacces(SPAWN_EACCES, Some("/srv/work"));
        assert_eq!(decorate_exec_cwd_permission(&out), out);
        assert_eq!(decorate_exec_cwd_missing(&out), out);
        assert_eq!(decorate_exec_enoexec(&out), out);
        assert_eq!(decorate_exec_program_path_miss(&out), out);
        assert_eq!(decorate_missing_parent(&out), out);
    }
}

const EXEC_ENOEXEC_TIP_MARKER: &str = "the kernel cannot execute that program's file format";

/// True for the `diagnose_spawn` wrapper when `execve` rejected the program's
/// file format (ENOEXEC = 8 / Windows `ERROR_BAD_EXE_FORMAT` = 193). `spawn:` is
/// required and `pty spawn:` is excluded: the PTY shell is node-chosen, so
/// shebang/interpreter advice would be wrong there.
fn is_exec_enoexec_error(message: &str) -> bool {
    if !message.contains("spawn:") || message.contains("pty spawn:") {
        return false;
    }
    message.to_ascii_lowercase().contains("exec format error")
        || message.contains("not a valid Win32 application")
        || message.contains("ERROR_BAD_EXE_FORMAT")
        || message_mentions_os_error(message, 8)
        || message_mentions_os_error(message, 193)
}

/// Append an actionable tip when a direct-argv `exec`/`bg start` spawn fails
/// with ENOEXEC: the file exists and is executable, but its contents are not a
/// format the kernel can run. Operation-general because the raw message names
/// no program. Idempotent.
fn decorate_exec_enoexec(message: &str) -> String {
    if message.contains(EXEC_ENOEXEC_TIP_MARKER) || !is_exec_enoexec_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {EXEC_ENOEXEC_TIP_MARKER} — the node spawned the program directly (an \
         argv, not a shell) and the kernel refused the file itself, so nothing ran: there is no \
         exit code, stdout, or stderr, and retrying the same argv fails identically. This is not \
         a permission problem (a mode problem is `EACCES`/`Permission denied (os error 13)` with \
         the `chmod +x` tip), not a missing path (that form quotes `program '<path>' not found \
         …`), and not a sandbox, grant, node-offline, or timeout failure. The file exists and at \
         least the exec bit is set (otherwise the error would differ), but its contents are not \
         an executable format: on Unix the typical case is a **text script with no `#!` \
         interpreter line** — often written with `write`/`write_file` or `cp` and then `chmod \
         +x`-ed — or a `#!` line that is not literally the first bytes (leading blank line, \
         UTF-8 BOM, overlong line, or CRLF after the interpreter, though that last one usually \
         reports the interpreter as `not found` instead). The other case is a **binary for \
         another OS/architecture** (an x86_64 or glibc build executed on an arm64 or musl node, \
         a macOS build on Linux) or a truncated/interrupted upload. Fix a script without editing \
         it: run it through an interpreter — `agentlink exec <node> -- bash <path>` (or `sh \
         <path>`, `python3 <path>`; this needs only read access, not the exec bit) / MCP \
         `run_command` or `process_start` with `\"argv\": [\"bash\", \"<path>\"]` — or add \
         `#!/bin/sh` as the very first line, ensure it is executable (`chmod +x`), then \
         `agentlink exec <node> -- <path>` again. Fix a binary: check the node's OS/arch with \
         `agentlink sysinfo <node>` / MCP `system_info`, fetch the matching build, and verify \
         the transfer size/type with `agentlink ls <node> <dir>` / MCP `stat_path` before \
         retrying (a partial upload has the same ENOEXEC shape). If you used `--shell` / MCP \
         `command`, the shell executes the target itself and reports its own exit 126/127 plus \
         stderr, so this spawn error means you used the direct argv form. The raw message quotes \
         no program, so it is the `program`/`argv[0]` you passed. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod exec_enoexec_tip_tests {
    use super::*;

    #[test]
    fn spawn_enoexec_gets_the_tip_once() {
        let raw = "spawn: Exec format error (os error 8)";
        let out = decorate_exec_enoexec(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {EXEC_ENOEXEC_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(EXEC_ENOEXEC_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`#!/bin/sh`",
            "`agentlink exec <node> -- bash <path>`",
            "python3",
            "`system_info`",
            "`stat_path`",
            "`agentlink ls <node> <dir>`",
            "exit 126/127",
            "nothing ran",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        assert_eq!(decorate_exec_enoexec(&out), out);
    }

    #[test]
    fn prefixed_and_windows_forms_get_the_tip() {
        for raw in [
            "exec deploy: spawn: Exec format error (os error 8)",
            "spawn: %1 is not a valid Win32 application. (os error 193)",
            "spawn: ERROR_BAD_EXE_FORMAT",
            "spawn: os error 8",
        ] {
            let out = decorate_exec_enoexec(raw);
            assert!(
                out.starts_with(&format!("{raw}. tip: {EXEC_ENOEXEC_TIP_MARKER} — ")),
                "{raw} -> {out}"
            );
            assert_eq!(
                out.matches(EXEC_ENOEXEC_TIP_MARKER).count(),
                1,
                "{raw} -> {out}"
            );
            assert_eq!(decorate_exec_enoexec(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_spawn_and_exec_errors_are_unchanged() {
        let eacces = decorate_exec_eacces("spawn: Permission denied (os error 13)", None);
        for raw in [
            "spawn: No such file or directory (os error 2)",
            "spawn: Permission denied (os error 13)",
            "spawn: Invalid argument (os error 22)",
            "program './gradlew' not found (No such file or directory (os error 2))",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "cwd /tmp/missing: No such file or directory (os error 2)",
            "cwd /tmp/file: Not a directory",
            "timed out",
            "pty spawn: Exec format error (os error 8)",
            "io: Exec format error (os error 8)",
            "node offline: probe",
            "authentication failed: grant has expired",
            "old string was not found in /tmp/x",
            eacces.as_str(),
        ] {
            assert_eq!(decorate_exec_enoexec(raw), raw, "{raw}");
        }
    }
}

const ENV_VAR_REJECTED_TIP_MARKER: &str =
    "env names must be non-empty and contain no '='; NUL is never valid in an env entry";

/// True for an `env` entry rejected by the CLI/MCP parse step or the node's
/// `validate_env`. Quote-agnostic: the CLI-local form uses backticks, the node
/// and MCP forms use single quotes.
fn is_env_var_rejected_error(message: &str) -> bool {
    message.contains("rejected env var ")
}

/// Append an actionable tip when `env` validation rejects an entry. The raw
/// message names only the offending name, never the rule that broke, and never
/// says nothing was spawned. Operation-general because the raw message names no
/// command or path. Idempotent.
fn decorate_env_var_rejected(message: &str) -> String {
    if message.contains(ENV_VAR_REJECTED_TIP_MARKER) || !is_env_var_rejected_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {ENV_VAR_REJECTED_TIP_MARKER} — `env` is validated before anything is \
         spawned (by the CLI/MCP client and again by the node), so no process started: there is \
         no pid, exit code, stdout, or stderr, and retrying the same `env` fails identically. \
         This is input validation, not a permission, grant, sandbox, node-offline, or timeout \
         failure. An environment entry is a name and a value; the quoted text is the rejected \
         **name**. If the name is empty (`rejected env var ''`), the entry had nothing before \
         `=`: `--env '=x'` → `--env FOO=x`. If it shows a whole `KEY=VALUE` pair (for example \
         `rejected env var 'FOO=bar'`), the pair was put in the name slot — the common MCP \
         shape mistake is a pair-keyed object (`\"env\": {{\"FOO=bar\": \"\"}}`), not a map of \
         bare names to values (an array of strings fails one step earlier with `env must be an \
         object of string values`); pass a JSON object mapping bare names to values instead: \
         `\"env\": {{\"FOO\": \"bar\"}}` (MCP `run_command` / `process_start`). If the name \
         looks valid, the *value* contains a NUL byte (often an escaped `\\u0000` in generated \
         JSON) — remove it; an OS environment cannot represent NUL at all. A value may contain \
         `=` freely: `--env 'FOO=a=b'` (the CLI splits at the first `=`) and `{{\"FOO\": \
         \"a=b\"}}` are both valid; only the name is restricted. To set a variable inside a \
         shell command instead, use the platform syntax with `--shell` / MCP `command` \
         (`FOO=bar <cmd>` on Unix; `set FOO=bar && <cmd>` on Windows). See `agentlink guide \
         <node>`."
    )
}

#[cfg(test)]
mod env_var_rejected_tip_tests {
    use super::*;

    #[test]
    fn rejected_pair_key_gets_the_tip_once() {
        let raw = "rejected env var 'FOO=bar'";
        let out = decorate_env_var_rejected(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {ENV_VAR_REJECTED_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(ENV_VAR_REJECTED_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "no process started",
            "`\"env\": {\"FOO\": \"bar\"}`",
            "run_command",
            "process_start",
            "`--env FOO=x`",
            "first `=`",
            "`\\u0000`",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        assert_eq!(decorate_env_var_rejected(&out), out);
    }

    #[test]
    fn cli_backtick_empty_name_and_prefixed_forms_get_the_tip() {
        for raw in [
            "rejected env var ``",
            "exec deploy: rejected env var 'FOO=bar'",
            "bg start box1: rejected env var 'FOO'",
        ] {
            let out = decorate_env_var_rejected(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(
                out.matches(ENV_VAR_REJECTED_TIP_MARKER).count(),
                1,
                "{raw} -> {out}"
            );
            assert_eq!(decorate_env_var_rejected(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_env_and_exec_errors_are_unchanged() {
        for raw in [
            "env must be an object of string values",
            "env.FOO must be a string",
            "--env expects KEY=VALUE, got `NOEQUALS` (example: --env FOO=bar)",
            "command is empty",
            "spawn: Exec format error (os error 8)",
            "cwd /tmp/missing: No such file or directory (os error 2)",
        ] {
            assert_eq!(decorate_env_var_rejected(raw), raw, "{raw}");
        }
    }
}

const ENV_VALUE_NOT_STRING_TIP_MARKER: &str = "env values must be JSON strings";

/// True for `parse_env_arg`'s per-value rejection: `env.<key> must be a
/// string`. The key is restricted to the characters an environment name can
/// actually contain so unrelated `... must be a string` errors (for example
/// `stdin must be a string`) do not match.
fn is_env_value_not_string_error(message: &str) -> bool {
    let Some(pos) = message.find("env.") else {
        return false;
    };
    let rest = &message[pos + "env.".len()..];
    let Some(end) = rest.find(" must be a string") else {
        return false;
    };
    let key = &rest[..end];
    !key.is_empty()
        && key
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Append an actionable tip when MCP `env` carries a non-string value. The raw
/// message names the offending key but not the rule that every value must be a
/// JSON string, and never says nothing was spawned. Operation-general because
/// the raw message names no command or path. Idempotent.
fn decorate_env_value_not_string(message: &str) -> String {
    if message.contains(ENV_VALUE_NOT_STRING_TIP_MARKER) || !is_env_value_not_string_error(message)
    {
        return message.to_string();
    }
    format!(
        "{message}. tip: {ENV_VALUE_NOT_STRING_TIP_MARKER} — the `env` argument is a JSON \
         object mapping variable names to values, and every **value** must be a JSON string, \
         not a number, boolean, null, array, or object: send `\"env\": {{\"PORT\": \"8080\", \
         \"DEBUG\": \"true\"}}`, not `{{\"PORT\": 8080, \"DEBUG\": true}}`. Stringify a number \
         or boolean you meant as text (`\"1\"`, not `1`); the child process receives the \
         characters either way. Key validation is a separate step: invalid names (empty, \
         containing `=` or NUL) fail with `rejected env var '…'` (separate tip), so a \
         suspicious key name is a different error. The `env` map is parsed before anything is \
         spawned, so no process started: there is no pid, exit code, stdout, or stderr, and \
         retrying the same `env` fails identically. This is input validation, not a \
         permission, grant, sandbox, node-offline, or timeout failure. Applies to MCP \
         `run_command` / `process_start`. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod env_value_not_string_tip_tests {
    use super::*;

    #[test]
    fn env_value_not_string_gets_the_tip_once() {
        for raw in [
            "env.PORT must be a string",
            "env.my-key_1 must be a string",
            "run_command: env.FOO must be a string",
        ] {
            let out = decorate_env_value_not_string(raw);
            assert!(
                out.starts_with(&format!("{raw}. tip: {ENV_VALUE_NOT_STRING_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(
                out.matches(ENV_VALUE_NOT_STRING_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "JSON string",
                "`\"env\": {\"PORT\": \"8080\", \"DEBUG\": \"true\"}`",
                "`rejected env var '…'`",
                "no process started",
                "run_command",
                "process_start",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_env_value_not_string(&out), out);
        }
    }

    #[test]
    fn env_value_not_string_leaves_siblings_alone() {
        for raw in [
            "env must be an object of string values",
            "rejected env var 'FOO=bar'",
            "argv is empty",
            "argv values must be strings",
            "missing `command`",
            "stdin must be a string",
            "stat_path: No such file or directory (os error 2)",
        ] {
            assert_eq!(decorate_env_value_not_string(raw), raw, "{raw}");
        }
    }
}

const STDIN_NOT_STRING_TIP_MARKER: &str = "stdin must be a JSON string";

/// True for `parse_stdin_arg`'s type rejection, which is exactly
/// `stdin must be a string`. Only an exact (trimmed) match qualifies: the
/// sibling size rejection (`stdin is N bytes; max is …`), `env.<key> must be a
/// string`, `argv values must be strings`, and other `... must be a string`
/// messages stay raw.
fn is_stdin_not_string_error(message: &str) -> bool {
    message.trim() == "stdin must be a string"
}

/// Append an actionable tip when MCP `run_command` / `process_start` receive a
/// non-string `stdin`. The raw message names no accepted form, never says
/// nothing was spawned, and does not distinguish the sibling size rejection.
/// Operation-general because the raw message names no program. Idempotent.
fn decorate_stdin_not_string(message: &str) -> String {
    if message.contains(STDIN_NOT_STRING_TIP_MARKER) || !is_stdin_not_string_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {STDIN_NOT_STRING_TIP_MARKER} — `stdin` must be a JSON string of the \
         bytes to feed the child as standard input, interpreted as UTF-8 text, for example \
         `\"stdin\": \"hello\\n\"` for the line `hello`. Numbers, booleans, objects, and arrays \
         are rejected; stringify text you meant to send (`\"42\"`, not `42`) and serialize \
         structured input yourself. `null` or an absent `stdin` means no stdin at all and is not \
         an error. Oversized input fails separately as `stdin is N bytes; max is …` (separate \
         error), so a payload over the size limit is not this failure. `stdin` is parsed before \
         anything is spawned, so nothing was spawned: there is no pid, exit code, stdout, or \
         stderr, and retrying the same `stdin` fails identically. This is input validation, not \
         a permission, grant, sandbox, node-offline, or timeout failure. Applies to MCP \
         `run_command` / `process_start`. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod stdin_not_string_tip_tests {
    use super::*;

    #[test]
    fn stdin_not_string_gets_the_tip_once() {
        for raw in ["stdin must be a string", "  stdin must be a string  "] {
            let out = decorate_stdin_not_string(raw);
            assert!(
                out.contains(&format!("tip: {STDIN_NOT_STRING_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(out.matches(STDIN_NOT_STRING_TIP_MARKER).count(), 1, "{out}");
            assert!(out.starts_with(raw), "{out}");
            for needle in [
                "JSON string",
                "UTF-8 text",
                "`\"stdin\": \"hello\\n\"`",
                "Numbers, booleans, objects, and arrays",
                "`null`",
                "no stdin at all",
                "`stdin is N bytes; max is …`",
                "nothing was spawned",
                "run_command",
                "process_start",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_stdin_not_string(&out), out);
        }
    }

    #[test]
    fn stdin_not_string_leaves_siblings_alone() {
        for raw in [
            "stdin is 16777217 bytes; max is 16777216",
            "env.PORT must be a string",
            "env must be an object of string values",
            "argv values must be strings",
            "argv is empty",
            "missing `command`",
            "stat_path: No such file or directory (os error 2)",
            "io: No such file or directory (os error 2)",
            "unknown terminal abc",
            "stdin must be a string (got number)",
        ] {
            assert_eq!(decorate_stdin_not_string(raw), raw, "{raw}");
        }
    }
}

const STDIN_TOO_LARGE_TIP_MARKER: &str = "stdin exceeds the inline byte limit";

/// Parse MCP `parse_stdin_arg`'s no-suffix size rejection. The CLI and node
/// produce the same prefix but already append file-based guidance; those forms
/// deliberately do not match. A valid rejection has decimal sizes and an
/// actual size strictly greater than the limit.
fn stdin_too_large_sizes(message: &str) -> Option<(u64, u64)> {
    let rest = message.trim().strip_prefix("stdin is ")?;
    let (bytes, max) = rest.split_once(" bytes; max is ")?;
    if bytes.is_empty()
        || max.is_empty()
        || !bytes.bytes().all(|byte| byte.is_ascii_digit())
        || !max.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    let bytes = bytes.parse::<u64>().ok()?;
    let max = max.parse::<u64>().ok()?;
    (bytes > max).then_some((bytes, max))
}

/// Append an actionable tip when MCP inline stdin exceeds its byte limit.
/// The raw error has sizes but no recovery path and never says that validation
/// happened before spawn. Operation-general because it names no program.
/// Idempotent, and distinct from the non-string stdin decorator.
fn decorate_stdin_too_large(message: &str) -> String {
    if message.contains(STDIN_TOO_LARGE_TIP_MARKER) {
        return message.to_string();
    }
    let Some((bytes, max)) = stdin_too_large_sizes(message) else {
        return message.to_string();
    };
    format!(
        "{message}. tip: {STDIN_TOO_LARGE_TIP_MARKER} — this MCP `stdin` payload is {bytes} \
         UTF-8 bytes, over the {max}-byte inline limit. The limit counts bytes, not characters: \
         multibyte text can exceed it with fewer than {max} characters. Retry with at most \
         {max} bytes only if the child can use shortened input; otherwise put the complete \
         payload in a remote file with `copy_path` upload or `write_file`, then have the command \
         read that file. For shell-form `run_command`, use `command`: `prog < /tmp/input`; \
         programs that accept a path can use `argv` with that path instead. Remove the temporary \
         file with `remove_path` when done. This applies to MCP `run_command` / `process_start`; \
         validation happens before anything is spawned, so nothing was spawned: there is no pid, \
         exit code, stdout, or stderr, and retrying unchanged fails identically. This is input \
         validation, not a permission, grant, sandbox, node-offline, or timeout failure. See \
         `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod stdin_too_large_tip_tests {
    use super::*;

    #[test]
    fn stdin_too_large_gets_the_tip_once() {
        for raw in [
            "stdin is 16777217 bytes; max is 16777216",
            "stdin is 20000000 bytes; max is 16777216",
            "  stdin is 16777217 bytes; max is 16777216  ",
        ] {
            let out = decorate_stdin_too_large(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(out.matches(STDIN_TOO_LARGE_TIP_MARKER).count(), 1, "{out}");
            for needle in [
                "UTF-8 bytes",
                "bytes, not characters",
                "16777216-byte inline limit",
                "copy_path",
                "write_file",
                "`prog < /tmp/input`",
                "`argv`",
                "remove_path",
                "run_command",
                "process_start",
                "nothing was spawned",
                "retrying unchanged fails identically",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert!(!out.contains(STDIN_NOT_STRING_TIP_MARKER), "{out}");
            assert_eq!(decorate_stdin_too_large(&out), out);
        }
    }

    #[test]
    fn stdin_too_large_leaves_siblings_alone() {
        for raw in [
            "stdin must be a string",
            "stdin is 16777216 bytes; max is 16777216",
            "stdin is 10 bytes; max is 16777216",
            "stdin is N bytes; max is 16777216",
            "stdin is 16777217 bytes; max is ",
            "stdin is 16777217 bytes; max is 16777216.",
            "stdin is 16777217 bytes; max is 16777216. Write a file and exec that path instead.",
            "stdin is 16777217 bytes; max is 16777216. Write a remote file and exec that path instead.",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
        ] {
            assert_eq!(decorate_stdin_too_large(raw), raw, "{raw}");
        }
    }
}

const ARGV_EMPTY_TIP_MARKER: &str = "argv must list a program";

/// True for the MCP argv parser's empty-array rejection. The CLI's clap parser
/// rejects an empty command before this code runs, so this is MCP-only.
fn is_argv_empty_error(message: &str) -> bool {
    message.contains("argv is empty")
}

/// Append an actionable tip when MCP `run_command` / `process_start` receive an
/// empty `argv` array. The raw message names no command, never says nothing was
/// spawned, and does not distinguish an omitted `command`. Operation-general
/// because the raw message names no program. Idempotent.
fn decorate_argv_empty(message: &str) -> String {
    if message.contains(ARGV_EMPTY_TIP_MARKER) || !is_argv_empty_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {ARGV_EMPTY_TIP_MARKER} — `argv` is a JSON array whose first \
         element is the program and whose remaining elements are its arguments, and the \
         array was empty (`\"argv\": []`), so nothing was spawned: there is no pid, exit \
         code, stdout, or stderr, and retrying the same `argv` fails identically. This is \
         input validation, not a permission, grant, sandbox, node-offline, or timeout \
         failure, and not a missing program (that form quotes `program '<path>' not found \
         …`). Pass at least one string with the program name first — `\"argv\": [\"ls\", \
         \"-la\", \"/tmp\"]` (MCP `run_command` / `process_start`) — or, for a shell line, \
         omit `argv` and use `\"command\": \"cd /tmp && ls -la\"` (the CLI equivalent is \
         `agentlink exec <node> --shell '<cmd>'`). Every argv value must be a string: \
         `\"argv\": [\"ls\", 2]` fails with a different error. See `agentlink guide <node>`."
    )
}

const ARGV_NOT_STRINGS_TIP_MARKER: &str = "argv entries must be JSON strings";

/// True for the MCP argv parser's type rejection when an element of `argv` is
/// not a JSON string. Both `run_command` and the `process_start` /
/// `command_argv` parser emit this exact message. The CLI's clap parser rejects
/// non-string values before this code runs, so this is MCP-only.
fn is_argv_not_strings_error(message: &str) -> bool {
    message.contains("argv values must be strings")
}

/// Append an actionable tip when MCP `run_command` / `process_start` receive an
/// `argv` array with a non-string element. The raw message names no index or
/// value, never says nothing was spawned, and does not distinguish the program
/// element from an argument. Operation-general because the raw message names no
/// program. Idempotent.
fn decorate_argv_not_strings(message: &str) -> String {
    if message.contains(ARGV_NOT_STRINGS_TIP_MARKER) || !is_argv_not_strings_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {ARGV_NOT_STRINGS_TIP_MARKER} — `argv` is a JSON array whose first \
         element is the program and whose remaining elements are its arguments, and at least \
         one element was not a string (a number, boolean, null, object, or array), so nothing \
         was spawned: there is no pid, exit code, stdout, or stderr, and retrying the same \
         `argv` fails identically. This is input validation, not a permission, grant, sandbox, \
         node-offline, or timeout failure, not an empty array (`argv is empty`), and not a \
         missing program. Quote every element as a JSON string — `\"argv\": [\"ls\", \"-la\", \
         \"/tmp\"]` — and stringify numbers you meant as arguments, e.g. `\"argv\": [\"sleep\", \
         \"2\"]` instead of `\"argv\": [\"sleep\", 2]` (MCP `run_command` / `process_start`). \
         For a shell line, omit `argv` and use `\"command\": \"cd /tmp && ls -la\"` (the CLI \
         equivalent is `agentlink exec <node> --shell '<cmd>'`). See `agentlink guide <node>`."
    )
}

const MISSING_COMMAND_TIP_MARKER: &str = "pass argv (string array) or command (shell line)";

/// True for the MCP command parser's `required_str` fallback when neither a
/// non-empty `argv` array nor a non-empty `command` string was supplied.
/// Matches the exact needle so other `missing `<key>`` errors keep their raw
/// form. The CLI's clap parser rejects this before the code runs, so this is
/// MCP-only.
fn is_missing_command_error(message: &str) -> bool {
    message.contains("missing `command`")
}

/// Append an actionable tip when MCP `run_command` / `process_start` receive
/// neither `argv` nor `command`. The raw message does not say which field to
/// pass, never says nothing was spawned, and does not distinguish the sibling
/// argv validation errors. Operation-general because the raw message names no
/// program. Idempotent.
fn decorate_missing_command(message: &str) -> String {
    if message.contains(MISSING_COMMAND_TIP_MARKER) || !is_missing_command_error(message) {
        return message.to_string();
    }
    format!(
        "{message}. tip: {MISSING_COMMAND_TIP_MARKER} — MCP `run_command` / `process_start` \
         received neither a non-empty `argv` array nor a `command` string, so nothing was \
         spawned: there is no pid, exit code, stdout, or stderr, and retrying without one of \
         them fails identically. This is input validation, not a permission, grant, sandbox, \
         node-offline, or timeout failure, not an empty array (`argv is empty`), and not \
         non-string elements (`argv values must be strings`). Pass either `\"argv\"`, a JSON \
         array of strings with the program first — `\"argv\": [\"ls\", \"-la\", \"/tmp\"]` — or \
         `\"command\"`, a shell line — `\"command\": \"cd /tmp && ls -la\"` (the CLI equivalent \
         is `agentlink exec <node> --shell '<cmd>'`). See `agentlink guide <node>`."
    )
}

const MISSING_ARG_TIP_MARKER: &str = "required MCP argument is missing or empty";

/// Pre-v0.1.250 marker. Still recognized so already-tipped messages are not
/// tipped a second time.
const LEGACY_MISSING_ARG_TIP_MARKER: &str = "required MCP string argument is missing or empty";

/// Keys whose schema type is a finite JSON number rather than a string.
const COORD_ARG_KEYS: [&str; 4] = ["x", "y", "to_x", "to_y"];

/// Extract the key from an exact whole-message `missing `<ident>`` error,
/// where `<ident>` matches `[a-z_][a-z0-9_]*`. Paths and other keys with
/// punctuation do not match. `command` is excluded because
/// `decorate_missing_command` owns that richer needle.
fn missing_arg_key(message: &str) -> Option<&str> {
    let key = message.trim().strip_prefix("missing `")?.strip_suffix('`')?;
    if key.is_empty() || key == "command" {
        return None;
    }
    let mut chars = key.chars();
    let first = chars.next()?;
    if !(first.is_ascii_lowercase() || first == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return None;
    }
    Some(key)
}

/// Append an actionable tip when an MCP tool rejects a required argument
/// supplied as absent, empty, or of the wrong JSON type. The raw message names
/// the key but not the type rule, the accepted form, or where to find the
/// schema. Coordinate keys (`x`, `y`, `to_x`, `to_y`) get number-aware prose;
/// other keys get string prose. Idempotent.
fn decorate_missing_arg(message: &str) -> String {
    if message.contains(MISSING_ARG_TIP_MARKER)
        || message.contains(LEGACY_MISSING_ARG_TIP_MARKER)
    {
        return message.to_string();
    }
    let Some(key) = missing_arg_key(message) else {
        return message.to_string();
    };
    if COORD_ARG_KEYS.contains(&key) {
        return format!(
            "{message}. tip: {MISSING_ARG_TIP_MARKER} — `{key}` is a required MCP argument and \
             must be a finite JSON number. An absent key surfaces as this form; a present value \
             that is not a finite number surfaces as `{key}` must be a finite number. Check the \
             tool's inputSchema via `tools/list` and pass an integer pixel coordinate (for \
             example `\"{key}\": 320`) or a 0–1 fraction (for example `\"{key}\": 0.5`) as a \
             JSON number, not `\"0.5\"`. See `agentlink guide <node>`."
        );
    }
    format!(
        "{message}. tip: {MISSING_ARG_TIP_MARKER} — `{key}` is a required MCP argument and must \
         be a non-empty JSON string. An absent key, an empty string, or a non-string value \
         (`null`, a number, boolean, array, or object) all surface as this form. Check the \
         tool's inputSchema via `tools/list` and pass `\"{key}\": \"...\"` as a JSON string; \
         stringify values the tool parses from text. See `agentlink guide <node>`."
    )
}

const FINITE_NUMBER_TIP_MARKER: &str = "must be a JSON number (pixel or 0–1 fraction)";

/// Extract the key from an exact whole-message `` `<ident>` must be a finite
/// number `` error, where `<ident>` matches `[a-z_][a-z0-9_]*`. Wrapped forms
/// and keys with punctuation do not match.
fn finite_number_key(message: &str) -> Option<&str> {
    let key = message
        .trim()
        .strip_suffix(" must be a finite number")?
        .strip_prefix('`')?
        .strip_suffix('`')?;
    let mut chars = key.chars();
    let first = chars.next()?;
    if !(first.is_ascii_lowercase() || first == '_') {
        return None;
    }
    if !chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        return None;
    }
    Some(key)
}

/// Append an actionable tip when an MCP tool rejects a coordinate-like argument
/// that is present but not a finite JSON number. The raw message names the key
/// but not the accepted numeric forms or where to find the schema. Idempotent.
fn decorate_finite_number(message: &str) -> String {
    if message.contains(FINITE_NUMBER_TIP_MARKER) {
        return message.to_string();
    }
    let Some(key) = finite_number_key(message) else {
        return message.to_string();
    };
    format!(
        "{message}. tip: {FINITE_NUMBER_TIP_MARKER} — `{key}` must be a finite JSON number, not \
         a string or other non-number value. Pass an integer pixel coordinate (for example \
         `\"{key}\": 320`) or a 0–1 fraction (for example `\"{key}\": 0.5`); `NaN` and \
         `Infinity` are rejected. Check the tool's inputSchema via `tools/list` and send a JSON \
         number instead of `\"0.5\"`. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod argv_empty_tip_tests {
    use super::*;

    #[test]
    fn empty_argv_gets_the_tip_once() {
        let raw = "argv is empty";
        let out = decorate_argv_empty(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {ARGV_EMPTY_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(ARGV_EMPTY_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`\"argv\": []`",
            "program name first",
            "run_command",
            "process_start",
            "`\"command\": \"",
            "nothing was spawned",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        assert_eq!(decorate_argv_empty(&out), out);
    }

    #[test]
    fn wrapped_forms_get_the_tip_once() {
        for raw in [
            "process_start: argv is empty",
            "run_command box: argv is empty",
        ] {
            let out = decorate_argv_empty(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(
                out.matches(ARGV_EMPTY_TIP_MARKER).count(),
                1,
                "{raw} -> {out}"
            );
            assert_eq!(decorate_argv_empty(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_argv_and_exec_errors_are_unchanged() {
        for raw in [
            "missing `command`",
            "missing `node`",
            "command is empty",
            "argv values must be strings",
            "program './gradlew' not found (No such file or directory (os error 2))",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "spawn: Permission denied (os error 13)",
            "spawn: Exec format error (os error 8)",
            "rejected env var 'FOO=bar'",
            "node offline: probe",
            "authentication failed: grant has expired",
            "cwd /tmp/missing: No such file or directory (os error 2)",
        ] {
            assert_eq!(decorate_argv_empty(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod argv_not_strings_tip_tests {
    use super::*;

    #[test]
    fn non_string_argv_gets_the_tip_once() {
        let raw = "argv values must be strings";
        let out = decorate_argv_not_strings(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {ARGV_NOT_STRINGS_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(ARGV_NOT_STRINGS_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`\"argv\": [\"ls\", \"-la\", \"/tmp\"]`",
            "`\"argv\": [\"sleep\", \"2\"]`",
            "run_command",
            "process_start",
            "`\"command\": \"",
            "nothing was spawned",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        assert_eq!(decorate_argv_not_strings(&out), out);
    }

    #[test]
    fn wrapped_forms_get_the_tip_once() {
        for raw in [
            "process_start: argv values must be strings",
            "run_command box: argv values must be strings",
        ] {
            let out = decorate_argv_not_strings(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(
                out.matches(ARGV_NOT_STRINGS_TIP_MARKER).count(),
                1,
                "{raw} -> {out}"
            );
            assert_eq!(decorate_argv_not_strings(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_argv_and_exec_errors_are_unchanged() {
        for raw in [
            "argv is empty",
            "missing `command`",
            "missing `node`",
            "command is empty",
            "program './gradlew' not found (No such file or directory (os error 2))",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "spawn: Permission denied (os error 13)",
            "spawn: Exec format error (os error 8)",
            "rejected env var 'FOO=bar'",
            "node offline: probe",
            "authentication failed: grant has expired",
            "cwd /tmp/missing: No such file or directory (os error 2)",
            "No such file or directory (os error 2)",
        ] {
            assert_eq!(decorate_argv_not_strings(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod missing_command_tip_tests {
    use super::*;

    #[test]
    fn missing_command_gets_the_tip_once() {
        let raw = "missing `command`";
        let out = decorate_missing_command(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {MISSING_COMMAND_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(MISSING_COMMAND_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "run_command",
            "process_start",
            "`\"argv\": [\"ls\", \"-la\", \"/tmp\"]`",
            "`\"command\": \"",
            "`argv is empty`",
            "`argv values must be strings`",
            "nothing was spawned",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        assert_eq!(decorate_missing_command(&out), out);
    }

    #[test]
    fn wrapped_forms_get_the_tip_once() {
        for raw in [
            "process_start: missing `command`",
            "run_command box: missing `command`",
        ] {
            let out = decorate_missing_command(raw);
            assert!(out.starts_with(raw), "{raw} -> {out}");
            assert_eq!(
                out.matches(MISSING_COMMAND_TIP_MARKER).count(),
                1,
                "{raw} -> {out}"
            );
            assert_eq!(decorate_missing_command(&out), out, "{raw}");
        }
    }

    #[test]
    fn sibling_missing_keys_and_argv_errors_are_unchanged() {
        for raw in [
            "missing `node`",
            "missing `keys`",
            "missing `cwd`",
            "missing `action`",
            "missing `old`",
            "argv is empty",
            "argv values must be strings",
            "command is empty",
            "program './gradlew' not found (No such file or directory (os error 2))",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "spawn: Permission denied (os error 13)",
            "spawn: Exec format error (os error 8)",
            "rejected env var 'FOO=bar'",
            "node offline: probe",
            "authentication failed: grant has expired",
            "cwd /tmp/missing: No such file or directory (os error 2)",
        ] {
            assert_eq!(decorate_missing_command(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod missing_arg_tip_tests {
    use super::*;

    #[test]
    fn missing_string_arg_gets_the_tip_once() {
        for key in ["keys", "text", "path", "node"] {
            let raw = format!("missing `{key}`");
            let out = decorate_missing_arg(&raw);
            assert!(
                out.starts_with(&format!("{raw}. tip: {MISSING_ARG_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(out.matches(MISSING_ARG_TIP_MARKER).count(), 1, "{out}");
            assert!(out.contains(&format!("`{key}`")), "{out}");
            for needle in [
                "non-empty JSON string",
                "tools/list",
                "inputSchema",
                "empty string",
                "array",
                "`null`",
                "agentlink guide <node>",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert!(!out.contains("finite JSON number"), "{out}");
            assert_eq!(decorate_missing_arg(&out), out, "{out}");
        }
    }

    #[test]
    fn missing_coord_arg_gets_number_prose_once() {
        for key in ["x", "y", "to_x", "to_y"] {
            let raw = format!("missing `{key}`");
            let out = decorate_missing_arg(&raw);
            assert!(
                out.starts_with(&format!("{raw}. tip: {MISSING_ARG_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(out.matches(MISSING_ARG_TIP_MARKER).count(), 1, "{out}");
            assert!(out.contains(&format!("`{key}`")), "{out}");
            for needle in [
                "required MCP argument",
                "finite JSON number",
                "pixel",
                "0–1 fraction",
                "tools/list",
                "inputSchema",
                "not `\"0.5\"`",
                "agentlink guide <node>",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert!(
                out.contains(&format!("`{key}` must be a finite number")),
                "{out}"
            );
            assert!(!out.contains("non-empty JSON string"), "{out}");
            assert_eq!(decorate_missing_arg(&out), out, "{out}");
        }
    }

    #[test]
    fn legacy_marker_is_idempotent() {
        let raw = format!("missing `x`. tip: {LEGACY_MISSING_ARG_TIP_MARKER} — old prose");
        assert_eq!(decorate_missing_arg(&raw), raw);
    }

    #[test]
    fn leading_and_trailing_whitespace_is_still_the_whole_message() {
        let out = decorate_missing_arg("  missing `keys`\n");
        assert!(out.starts_with("  missing `keys`\n"), "{out}");
        assert_eq!(out.matches(MISSING_ARG_TIP_MARKER).count(), 1, "{out}");
    }

    #[test]
    fn sibling_missing_keys_and_argv_errors_are_unchanged() {
        for raw in [
            "missing `command`",
            "missing `/tmp/x`",
            "missing `Makefile`",
            "missing `a-b`",
            "missing ``",
            "process_start: missing `keys`",
            "missing `keys` and `text`",
            "argv is empty",
            "argv values must be strings",
            "command is empty",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "spawn: Permission denied (os error 13)",
            "node offline: probe",
            "io: No such file or directory (os error 2)",
            "stat_path: No such file or directory (os error 2)",
        ] {
            assert_eq!(decorate_missing_arg(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod finite_number_tip_tests {
    use super::*;

    #[test]
    fn finite_number_gets_the_tip_once() {
        for key in ["x", "y", "to_x", "to_y", "scale"] {
            let raw = format!("`{key}` must be a finite number");
            let out = decorate_finite_number(&raw);
            assert!(
                out.starts_with(&format!(
                    "{raw}. tip: {FINITE_NUMBER_TIP_MARKER} — "
                )),
                "{out}"
            );
            assert_eq!(out.matches(FINITE_NUMBER_TIP_MARKER).count(), 1, "{out}");
            assert!(out.contains(&format!("`{key}`")), "{out}");
            for needle in [
                "finite JSON number",
                "not a string",
                "pixel",
                "0–1 fraction",
                "`NaN`",
                "`Infinity`",
                "tools/list",
                "inputSchema",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing: {out}");
            }
            assert_eq!(decorate_finite_number(&out), out, "{out}");
        }
    }

    #[test]
    fn leading_and_trailing_whitespace_is_still_the_whole_message() {
        let out = decorate_finite_number("  `x` must be a finite number\n");
        assert!(out.starts_with("  `x` must be a finite number\n"), "{out}");
        assert_eq!(out.matches(FINITE_NUMBER_TIP_MARKER).count(), 1, "{out}");
    }

    #[test]
    fn sibling_missing_keys_and_number_errors_are_unchanged() {
        for raw in [
            "missing `x`",
            "missing `y`",
            "`x` must be a number",
            "`x` must be a string",
            "`x` must be a finite number and positive",
            "process_start: `x` must be a finite number",
            "`a-b` must be a finite number",
            "`X` must be a finite number",
            "`` must be a finite number",
            "must be a finite number",
            "argv is empty",
            "argv values must be strings",
            "command is empty",
            "stat_path: No such file or directory (os error 2)",
            "unknown terminal abc",
            "spawn: Permission denied (os error 13)",
            "node offline: probe",
        ] {
            assert_eq!(decorate_finite_number(raw), raw, "{raw}");
        }
    }
}

const SEARCH_REGEX_TIP_MARKER: &str = "is treated as a regex";

/// Extract the offending pattern from a `regex parse error:` block:
/// `pattern: regex parse error:\n    <pattern>\n    ^\nerror: ...`.
/// Multi-line patterns use a `~` divider instead of the indented note, so they
/// fall back to the generic `<pattern>` placeholder.
fn search_regex_pattern(message: &str) -> Option<&str> {
    const HEADER: &str = "regex parse error:\n";
    let start = message.rfind(HEADER)? + HEADER.len();
    let line = message[start..].lines().next()?;
    let pattern = line.strip_prefix("    ").unwrap_or(line).trim();
    if pattern.is_empty() || pattern.chars().all(|c| c == '~') {
        return None;
    }
    // `agentlink search` builds a grep matcher, which wraps the user pattern
    // in `(?:...)`; `find --regex` uses the bare pattern.
    Some(
        pattern
            .strip_prefix("(?:")
            .and_then(|rest| rest.strip_suffix(')'))
            .unwrap_or(pattern),
    )
}

/// Append an actionable tip when `search` (or `find --regex`) fails because the
/// pattern was treated as a regex: escape metacharacters or search the exact
/// string with `--literal`. Idempotent. Glob, empty/NUL, and unrelated errors
/// are left alone.
fn decorate_search_regex(message: &str) -> String {
    const DIAGNOSTICS: [&str; 4] = [
        "regex parse error",
        "unclosed group",
        "unclosed character class",
        "repetition operator missing expression",
    ];
    if message.contains(SEARCH_REGEX_TIP_MARKER)
        || message.contains("--literal")
        || !message.contains("pattern: ")
        || !DIAGNOSTICS.iter().any(|needle| message.contains(needle))
    {
        return message.to_string();
    }
    let pattern = search_regex_pattern(message).unwrap_or("<pattern>");
    format!(
        "{message}. tip: '{pattern}' {SEARCH_REGEX_TIP_MARKER} — escape metacharacters \
         (e.g. \\( \\[ \\*) or search the exact string with `agentlink search <node> \
         --literal '{pattern}' <path>`"
    )
}

#[cfg(test)]
mod search_regex_tip_tests {
    use super::*;

    const UNCLOSED_GROUP: &str =
        "pattern: regex parse error:\n    (?:()\n    ^\nerror: unclosed group";

    #[test]
    fn parse_error_gets_the_literal_tip_once() {
        let out = decorate_search_regex(UNCLOSED_GROUP);
        assert_eq!(
            out,
            "pattern: regex parse error:\n    (?:()\n    ^\nerror: unclosed group. tip: '(' is \
             treated as a regex — escape metacharacters (e.g. \\( \\[ \\*) or search the exact \
             string with `agentlink search <node> --literal '(' <path>`"
        );
        assert_eq!(decorate_search_regex(&out), out);
    }

    #[test]
    fn find_regex_error_uses_the_bare_pattern() {
        let out = decorate_search_regex(
            "pattern: regex parse error:\n    (\n    ^\nerror: unclosed group",
        );
        assert!(out.contains("tip: '(' is treated as a regex"), "{out}");
        assert_eq!(decorate_search_regex(&out), out);
    }

    #[test]
    fn wrapped_parse_error_uses_the_extracted_pattern() {
        let out = decorate_search_regex(
            "search .: pattern: regex parse error:\n    (?:[abc)\n       ^\nerror: unclosed character class",
        );
        assert_eq!(out.matches(SEARCH_REGEX_TIP_MARKER).count(), 1, "{out}");
        assert!(out.contains("'[abc'"), "{out}");
        assert!(
            out.contains("`agentlink search <node> --literal '[abc' <path>`"),
            "{out}"
        );
    }

    #[test]
    fn repetition_and_generic_parse_errors_get_the_tip() {
        for raw in [
            "pattern: regex parse error:\n    (?:*)\n       ^\nerror: repetition operator missing expression",
            "pattern: regex parse error:\n    (?:a{2,1})\n        ^^^^^\nerror: invalid repetition count range, the start must be <= the end",
        ] {
            let out = decorate_search_regex(raw);
            assert!(out.contains(SEARCH_REGEX_TIP_MARKER), "{raw} -> {out}");
            assert_eq!(decorate_search_regex(&out), out, "{raw}");
        }
    }

    #[test]
    fn multi_line_pattern_falls_back_to_the_placeholder() {
        let raw = "pattern: regex parse error:\n~~~\n1: (\n2: [\n~~~\nerror: unclosed group";
        let out = decorate_search_regex(raw);
        assert!(out.contains("'<pattern>' is treated as a regex"), "{out}");
    }

    #[test]
    fn literal_mention_or_glob_and_unrelated_errors_are_unchanged() {
        for raw in [
            "pattern is empty",
            "pattern contains NUL",
            "pattern is longer than 4096 bytes",
            "glob: invalid glob '['",
            "include glob '[a': unclosed character class",
            "pattern: compiled regex exceeds size limit of 1048576",
            "pattern: regex parse error:\n    (\n    ^\nerror: unclosed group — try --literal",
            "pattern: regex parse error:\n    (\n    ^\nerror: unclosed group. tip: '(' is treated as a regex",
            "node offline: probe",
            "not found: node 'foo'",
            "old string was not found in /tmp/x",
            "program 'cd' not found on PATH (No such file or directory (os error 2))",
            "Permission denied (os error 13)",
        ] {
            assert_eq!(decorate_search_regex(raw), raw, "{raw}");
        }
    }
}

const SEARCH_GLOB_TIP_MARKER: &str = "search and find glob patterns use glob syntax, not regex";

/// True only for the four glob-error shapes produced by the node's search
/// paths (`include glob`, `exclude glob`, `invalid glob`, and `find`'s bare
/// `glob: error parsing glob`). A bare `error parsing glob` without one of
/// those prefixes is left alone.
fn is_search_glob_error(message: &str) -> bool {
    message.contains("include glob '")
        || message.contains("exclude glob '")
        || message.contains("invalid glob '")
        || message.contains("glob: error parsing glob '")
}

/// Extract the rejected glob: text between the prefix's opening quote and the
/// next `'`. `invalid glob` has no following `': ` reason, and the include /
/// exclude forms nest globset's own `error parsing glob '<glob>'` inside them,
/// so the first opening quote is the right one.
fn search_glob_pattern(message: &str) -> Option<&str> {
    const PREFIXES: [&str; 4] = [
        "include glob '",
        "exclude glob '",
        "invalid glob '",
        "error parsing glob '",
    ];
    let rest = PREFIXES
        .iter()
        .find_map(|prefix| message.find(*prefix).map(|at| &message[at + prefix.len()..]))?;
    let end = rest.find('\'')?;
    Some(&rest[..end])
}

/// The glob parser's reason from a trailing `'<glob>': <reason>` clause.
/// `invalid glob` has none.
fn search_glob_reason(message: &str) -> Option<&str> {
    message.rsplit_once("': ").map(|(_, reason)| reason.trim())
}

/// Append an actionable tip when `search`/`grep` `--include`/`--exclude`,
/// `find` without `--regex`, or the MCP search tools reject a malformed glob.
/// Idempotent. Regex errors and unrelated failures are left alone.
fn decorate_search_glob(message: &str) -> String {
    if message.contains(SEARCH_GLOB_TIP_MARKER) || !is_search_glob_error(message) {
        return message.to_string();
    }
    let glob = match search_glob_pattern(message) {
        Some("") => "(empty)".to_string(),
        Some(glob) => {
            let mut chars = glob.chars();
            let head: String = chars.by_ref().take(120).collect();
            if chars.next().is_some() {
                format!("{head}…")
            } else {
                head
            }
        }
        None => "<glob>".to_string(),
    };
    let reason_clause = search_glob_reason(message)
        .map(|reason| format!(" — the glob parser's reason is `{reason}`"))
        .unwrap_or_default();
    format!(
        "{message}. tip: {SEARCH_GLOB_TIP_MARKER} — `search` (CLI alias `grep`) \
         `--include`/`--exclude` and `find` without `--regex` (MCP `search_content` \
         `include`/`exclude`, `search_files` without `\"regex\": true`) match file paths with \
         gitignore-style globs (`globset`/`ignore`), not regular expressions. The node rejected \
         the pattern before walking or opening any file, so no results were produced and nothing \
         changed on the node. Retrying the same pattern unchanged fails identically; this is not \
         a permission, grant, sandbox, node-offline, or missing-path failure. The rejected \
         pattern is `{glob}`{reason_clause}. Fix the glob: `[` opens a character class and must \
         be closed (`[abc]`, `[a-z]`; negation is `[!abc]` — do not assume regex `[^abc]`), so a \
         literal bracket must be escaped: a Next.js-style `[slug].tsx` is `\\[slug\\].tsx` in the \
         pattern. A trailing lone `\\` is a dangling escape (double it or drop it); `[z-a]` is an \
         invalid range because the endpoints are reversed; and `**` is valid only as a whole path \
         component (`**/target/**`). Regex/shell forms such as `\\.rs$`, `(a|b)`, and `[^x]` are \
         not globs (some parse silently and then match the wrong names). Use `/` as the separator \
         even on Windows, and quote the pattern for your shell (an unquoted `*.rs` is expanded \
         locally before the CLI sees it). `--include`/`--exclude` filter file paths relative to \
         the search root; a slashless `*.rs` matches at any depth. Pass `--exclude '*.log'` \
         (plain glob, no `!`): the node adds the exclusion marker for you. `find` has no \
         `--include`/`--exclude`, and its non-regex `*`/`?` can also match `/` (it is tested \
         against the root-relative path, the basename, and the absolute path). If you meant a \
         regex, use `agentlink find <node> <regex> <path> --regex` / MCP `search_files` with \
         `\"regex\": true`; if you meant literal content, use `agentlink search <node> --literal \
         <text> <path>` / MCP `search_content` with `\"literal\": true`. An empty, \
         over-4096-byte, or NUL-containing glob is rejected as `invalid glob` — pass a real, \
         shorter pattern or drop the flag. List names first with `agentlink ls <node> <path>` / \
         MCP `list_dir`. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod search_glob_tip_tests {
    use super::*;

    const INCLUDE_UNCLOSED: &str =
        "include glob '[a': error parsing glob '[a': unclosed character class";
    const EXCLUDE_RANGE: &str =
        "exclude glob '[z-a]': error parsing glob '[z-a]': invalid range";
    const FIND_UNCLOSED: &str =
        "glob: error parsing glob '[slug].tsx': unclosed character class";

    #[test]
    fn include_glob_error_gets_the_tip_once() {
        let raw = INCLUDE_UNCLOSED;
        let out = decorate_search_glob(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {SEARCH_GLOB_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(SEARCH_GLOB_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`[a`",
            "unclosed character class",
            "`--include`",
            "`--exclude`",
            "find <node> <regex> <path> --regex",
            "`search_files`",
            "`\"regex\": true`",
            "--literal",
            "`agentlink ls <node> <path>`",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "missing {needle:?}: {out}");
        }
        assert_eq!(decorate_search_glob(&out), out);
    }

    #[test]
    fn exclude_and_find_forms_tip_once() {
        for (raw, needle) in [
            (EXCLUDE_RANGE, "[z-a]"),
            (EXCLUDE_RANGE, "invalid range"),
            (FIND_UNCLOSED, "[slug].tsx"),
            (FIND_UNCLOSED, "unclosed character class"),
        ] {
            let out = decorate_search_glob(raw);
            assert!(out.starts_with(raw), "{out}");
            assert_eq!(out.matches(SEARCH_GLOB_TIP_MARKER).count(), 1, "{out}");
            assert!(out.contains(needle), "missing {needle:?}: {out}");
            assert_eq!(decorate_search_glob(&out), out, "{raw}");
        }
    }

    #[test]
    fn invalid_glob_forms_tip_once() {
        let out = decorate_search_glob("invalid glob ''");
        assert!(out.contains("(empty)"), "{out}");
        assert_eq!(out.matches(SEARCH_GLOB_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_search_glob(&out), out);

        let huge = "a".repeat(5000);
        let raw = format!("invalid glob '{huge}'");
        let out = decorate_search_glob(&raw);
        assert!(out.contains('…'), "over-long glob must be elided: {}", out.len());
        assert!(out.contains(&format!("`{}…`", "a".repeat(120))), "{out}");
        assert_eq!(out.matches(SEARCH_GLOB_TIP_MARKER).count(), 1, "{}", out.len());
        assert_eq!(decorate_search_glob(&out), out);

        let out = decorate_search_glob("invalid glob '\0x'");
        assert_eq!(out.matches(SEARCH_GLOB_TIP_MARKER).count(), 1, "{out}");
        assert_eq!(decorate_search_glob(&out), out);
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "pattern: regex parse error:\n    (\n    ^\nerror: unclosed group",
            "pattern is empty",
            "pattern contains NUL",
            "pattern is longer than 4096 bytes",
            "not found: node 'foo'",
            "io: No such file or directory (os error 2)",
            "error parsing glob '[a': unclosed character class",
        ] {
            assert_eq!(decorate_search_glob(raw), raw, "{raw}");
        }
        // The regex decorator still leaves its sibling glob forms alone.
        assert_eq!(
            decorate_search_regex("include glob '[a': unclosed character class"),
            "include glob '[a': unclosed character class"
        );
    }
}

const SEARCH_PERMISSION_TIP_MARKER: &str = "content search could not read a file on the node";

const SEARCH_PERMISSION_SUFFIXES: &[&str] = &[
    ": Permission denied (os error 13)",
    ": Access is denied. (os error 5)",
];

/// Extract the resolved path from a direct-file content-search refusal. Prefix
/// and exact suffix only: the bare permission sentence is shared by every node
/// op, and only the `search <resolved>: ` wrapper identifies content search.
/// The `task` guard keeps the spawn/join wrapper raw, and the full Windows
/// sentence keeps Linux EIO (`Input/output error (os error 5)`) raw.
fn search_permission_path(message: &str) -> Option<&str> {
    let message = message.trim_end();
    let rest = message.strip_prefix("search ")?;
    for suffix in SEARCH_PERMISSION_SUFFIXES {
        if let Some(path) = rest.strip_suffix(suffix) {
            if !path.is_empty() && path != "task" && !path.starts_with("task: ") {
                return Some(path);
            }
        }
    }
    None
}

fn is_search_permission_error(message: &str) -> bool {
    search_permission_path(message).is_some()
}

/// Append an actionable tip when a direct single-file content search is refused
/// opening the target. The node already names the resolved path but not the
/// operation family; the caller's node and path are interpolated here. Wired
/// only at the CLI `search`/`grep` arm and the MCP `search_content` arm: the
/// same bare permission sentence belongs to every other node op, and directory
/// walks swallow it into `skipped_files`, so the flat `tool_err` chain must
/// keep it raw. Idempotent.
fn decorate_search_permission(message: &str, node: &str, path: &str) -> String {
    if message.contains(SEARCH_PERMISSION_TIP_MARKER) {
        return message.to_string();
    }
    let resolved = match search_permission_path(message) {
        Some(resolved) => resolved,
        None => return message.to_string(),
    };
    format!(
        "{message}. tip: {SEARCH_PERMISSION_TIP_MARKER} — MCP `search_content` (CLI `search`, \
         alias `grep`) asked the node `{node}` to search `{path}` for content, and the node's \
         process user was refused opening the file `{resolved}`. The raw line already names \
         `{resolved}` but not the operation or the node; `{path}` is exactly the caller's value \
         (a relative path is joined to the node's working directory or the `--root` jail; `~` \
         is not expanded), and it resolved to `{resolved}` on the node. Content search must \
         open and read each candidate file, so it needs read (`r`) on the target file plus \
         execute/search (`x`) on every ancestor; this line is the target file's own read gate \
         (or an ACL/LSM rule), not a directory listing gate. A direct single-file search fails \
         loudly with this line. A directory walk instead skips per-file `PermissionDenied` and \
         `NotFound` and counts them in `skipped_files` (the CLI prints `warning: skipped N \
         inaccessible file(s) while searching`), so zero matches with `skipped_files` above \
         zero is that warning, not this error; a search root directory that cannot be \
         traversed currently yields zero matches without an error, so check the root with \
         `stat_path` / `list_dir` rather than expecting this line. Contrast on the same file \
         (dogfood on `box`): `stat_path` on `/etc/shadow` succeeds with `mode` `33184` (i.e. \
         `0o100640`) because metadata needs `x` on ancestors but not `r` on the file, while \
         `read_file` on the same path is refused with its own tip — a successful `stat_path` \
         does not mean search can read the content. Common cases: `/etc/shadow` / `/etc/gshadow` \
         (`0640 root:shadow`), another user's `0600` file, private keys (`~/.ssh/id_*`), cloud \
         credential files, and service secrets; on a node running as a service account this is \
         routine. Diagnose from the node with `run_command` / `agentlink exec <node> -- stat -c \
         '%A %a %U:%G %n' <resolved>` plus `id -un`, `namei -l <resolved>` for the ancestors, and \
         `getfacl` / `lsattr` for ACLs and immutable flags; on Windows use `icacls <resolved>`. \
         `stat_path` / `list_dir` on the parent help when the blocker is an ancestor. Fix by \
         granting the node user read on the file (`chmod o+r <file>`, or `g+r` / `u+r` as \
         appropriate), `chown`ing it to the node user, adding the node user to the owning group, \
         or correcting the ACL; LSM policy needs an operator. If the file must stay protected, \
         search as a user with access through `run_command` / `agentlink exec` with `sudo` when \
         the node policy allows, or ask the operator. Retrying unchanged fails identically, and \
         `--include` / `--exclude` cannot unblock a direct single-file search; to keep scanning, \
         search the parent directory so the unreadable file is counted in `skipped_files`. On \
         Windows there is no mode bit: `os error 5` means an ACL, AppLocker, AV, or protected \
         location denies the open/read; inspect with `icacls`. No content from `{resolved}` was \
         read and no matches were returned for it; nothing on the node was modified. This is not \
         a missing file (ENOENT stays raw here), not a malformed pattern or include/exclude glob \
         (glob tip owns those), not a sandbox jail denial (no `search ` prefix), not a \
         capability/grant or session refusal, not a `read_file` / `stat_path` / `list_dir` / \
         write / mkdir / remove / mv permission (those are other arms and markers), not \
         node-offline, and not the walk-time skip warning. See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod search_permission_tip_tests {
    use super::*;

    const UNIX: &str = "search /etc/shadow: Permission denied (os error 13)";
    const WINDOWS: &str = "search C:\\ProgramData\\secrets\\app.txt: Access is denied. (os error 5)";

    #[test]
    fn unix_eacces_gets_the_tip_once() {
        let out = decorate_search_permission(UNIX, "box", "/etc/shadow");
        assert!(
            out.starts_with(&format!(
                "{UNIX}. tip: {SEARCH_PERMISSION_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(SEARCH_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        for needle in [
            "box",
            "/etc/shadow",
            "skipped_files",
            "stat_path",
            "namei",
            "stat -c",
            "icacls",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle} missing: {out}");
        }
        for literal in ["{node}", "{path}", "{resolved}", "{message}"] {
            assert!(!out.contains(literal), "{literal} literal left: {out}");
        }
        assert_eq!(
            decorate_search_permission(UNIX, "box", "/etc/shadow"),
            out
        );
        assert_eq!(
            decorate_search_permission(&out, "box", "/etc/shadow"),
            out,
            "second call must be byte-identical"
        );
    }

    #[test]
    fn relative_caller_path_names_both() {
        let raw = "search /srv/app/secret.env: Permission denied (os error 13)";
        let out = decorate_search_permission(raw, "box", "secret.env");
        assert!(out.contains("secret.env"), "{out}");
        assert!(out.contains("/srv/app/secret.env"), "{out}");
        assert_eq!(
            out.matches(SEARCH_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
    }

    #[test]
    fn windows_form_gets_the_tip() {
        let out = decorate_search_permission(WINDOWS, "box", "/srv/app.txt");
        assert!(
            out.starts_with(&format!(
                "{WINDOWS}. tip: {SEARCH_PERMISSION_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(SEARCH_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("icacls"), "{out}");
        assert_eq!(decorate_search_permission(&out, "box", "/srv/app.txt"), out);

        let eio = "search /x: Input/output error (os error 5)";
        assert_eq!(decorate_search_permission(eio, "box", "/x"), eio);
    }

    #[test]
    fn exact_wrapper_and_suffix_only() {
        for raw in [
            "search /etc/shadow: Permission denied (os error 13) extra",
            "search task: Permission denied (os error 13)",
            "io: Permission denied (os error 13)",
            "Permission denied (os error 13)",
            "search /x: Operation not permitted (os error 1)",
            "search /x: No such file or directory (os error 2)",
            "search /x: Input/output error (os error 5)",
            "find /x: Permission denied (os error 13)",
            "skipped 28 inaccessible file(s) while searching",
            "search foo: invalid glob 'foo'",
            "node offline: probe",
            "permission denied: command denied by sandbox pattern 'sudo **'",
            "",
        ] {
            assert_eq!(
                decorate_search_permission(raw, "box", "/etc/shadow"),
                raw,
                "{raw}"
            );
        }

        let trailing = format!("{UNIX}\n");
        let out = decorate_search_permission(&trailing, "box", "/etc/shadow");
        assert_eq!(
            out.matches(SEARCH_PERMISSION_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert_eq!(decorate_search_permission(&out, "box", "/etc/shadow"), out);
    }

    #[test]
    fn already_tipped_and_siblings_are_noops() {
        let out = decorate_search_permission(UNIX, "box", "/etc/shadow");
        assert_eq!(
            decorate_read_file_permission(&out, "box", "/etc/shadow"),
            out
        );
        assert_eq!(
            decorate_stat_path_permission(&out, "box", "/etc/shadow"),
            out
        );
        assert_eq!(
            decorate_list_dir_permission(&out, "box", "/etc/shadow"),
            out
        );
        assert_eq!(
            decorate_write_dest_permission(&out, "box", "/etc/shadow"),
            out
        );
        assert_eq!(
            decorate_mkdir_dest_permission(&out, "box", "/etc/shadow", false),
            out
        );
        assert_eq!(
            decorate_remove_dest_permission(&out, "box", "/etc/shadow", false),
            out
        );
        assert_eq!(
            decorate_mv_dest_permission(&out, "box", "/srv/a", "/etc/shadow"),
            out
        );
        assert_eq!(decorate_sandbox_path_escape(&out), out);
        assert_eq!(decorate_search_glob(&out), out);
    }

    #[test]
    fn bare_io_stays_with_read_file() {
        let read = decorate_read_file_permission(
            "io: Permission denied (os error 13)",
            "box",
            "/etc/shadow",
        );
        assert!(read.contains(READ_FILE_PERMISSION_TIP_MARKER), "{read}");
        assert_eq!(
            decorate_search_permission(&read, "box", "/etc/shadow"),
            read
        );
    }
}

/// Actionable tips for offline and stale-VERSION nodes. Offline nodes get one
/// tip naming them; online nodes whose version is older than `cli` get a tip
/// naming both versions. Current/equal versions produce no tip.
fn nodes_tips(nodes: &[NodeInfo], cli: &str) -> Vec<String> {
    let mut tips = Vec::new();
    let offline = nodes
        .iter()
        .filter(|node| !node.online)
        .map(|node| node.name.as_str())
        .collect::<Vec<_>>();
    if !offline.is_empty() {
        tips.push(tip_node_offline(&nodes_cap_names(&offline)));
    }
    let mut stale = nodes
        .iter()
        .filter(|node| node.online)
        .filter_map(|node| {
            let version = nodes_version_short(&node.version);
            if version == "?" {
                return None;
            }
            (update::compare_versions(&version, cli) == std::cmp::Ordering::Less)
                .then(|| (node.name.as_str(), version))
        })
        .collect::<Vec<_>>();
    let extra = stale.len().saturating_sub(3);
    stale.truncate(3);
    for (name, version) in stale {
        tips.push(format!(
            "tip: {name} is on {version}; this CLI is {cli} — on that host run agentlink update (or install from https://relay.example.com/dl)"
        ));
    }
    if extra > 0 {
        tips.push(format!(
            "tip: and {extra} more nodes are behind this CLI — run agentlink update on those hosts"
        ));
    }
    tips
}

async fn print_nodes(client: &Client, json_mode: bool) -> Result<()> {
    let nodes = client.list_nodes().await?;
    let tips = if nodes.is_empty() {
        Vec::new()
    } else {
        nodes_tips(&nodes, version::semver())
    };
    for warning in client.node_pin_warnings() {
        eprintln!("{warning}");
    }
    emit(
        json_mode,
        json!({
            "nodes": nodes,
            "pin_warnings": client.node_pin_warnings(),
            "tips": tips,
        }),
        || {
            if nodes.is_empty() {
                eprintln!("no paired machines");
                eprintln!("{NODES_EMPTY_TIP}");
                return;
            }
            println!(
                "{:<16} {:<8} {:<8} {:<16} {:<14} {:<12} {}",
                "NAME", "STATUS", "DISPLAY", "OS/ARCH", "ACCESS", "VERSION", "ID"
            );
            for node in &nodes {
                println!("{}", format_nodes_line(node));
            }
            for tip in &tips {
                eprintln!("{tip}");
            }
            eprintln!("{NODES_FOOTER_TIP}");
        },
    );
    Ok(())
}

#[cfg(test)]
mod nodes_list_tests {
    use super::*;

    fn node(online: bool, has_display: Option<bool>, version: &str) -> NodeInfo {
        NodeInfo {
            id: "907af48d6786d69a05776a83b94aabbe784f9fa5452c0ac0e469bad4b1243043".into(),
            name: "box".into(),
            hostname: "box".into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: version.into(),
            online,
            policy: NodePolicy::full(),
            effective: NodePolicy::full(),
            owner: String::new(),
            relation: "owner".into(),
            access: "full".into(),
            has_display,
        }
    }

    #[test]
    fn nodes_status_labels_are_upper_case() {
        assert_eq!(nodes_status_label(true), "ONLINE");
        assert_eq!(nodes_status_label(false), "OFFLINE");
    }

    #[test]
    fn nodes_display_labels_distinguish_desktop_headless_and_unknown() {
        assert_eq!(nodes_display_label(Some(true)), "desktop");
        assert_eq!(nodes_display_label(Some(false)), "headless");
        assert_eq!(nodes_display_label(None), "?");
    }

    #[test]
    fn nodes_version_short_strips_build_metadata() {
        assert_eq!(nodes_version_short("0.1.124 (9c1180d…)"), "0.1.124");
        assert_eq!(nodes_version_short("0.1.124(9c1180d)"), "0.1.124");
        assert_eq!(nodes_version_short(" 0.1.44 "), "0.1.44");
        assert_eq!(nodes_version_short(""), "?");
    }

    #[test]
    fn format_nodes_line_shows_name_status_short_id_and_version() {
        let line = format_nodes_line(&node(true, Some(true), "0.1.124 (9c1180d…)"));
        assert!(line.contains("box"), "{line}");
        assert!(line.contains("ONLINE"), "{line}");
        assert!(line.contains("desktop"), "{line}");
        assert!(line.contains("linux/x86_64"), "{line}");
        assert!(line.contains("907af48d6786"), "{line}");
        assert!(line.contains("0.1.124"), "{line}");
        assert!(!line.contains("9c1180d"), "{line}");
    }

    #[test]
    fn format_nodes_line_marks_offline_headless_old_node() {
        let headless = format_nodes_line(&node(true, Some(false), "0.1.44"));
        assert!(headless.contains("headless"), "{headless}");
        let unknown = format_nodes_line(&node(false, None, ""));
        assert!(unknown.contains("OFFLINE"), "{unknown}");
        assert!(unknown.contains("?"), "{unknown}");
        assert!(!unknown.ends_with(' '), "{unknown}");
    }

    #[test]
    fn nodes_empty_and_footer_tips_are_actionable() {
        assert!(NODES_EMPTY_TIP.contains("agentlink pair"));
        assert!(NODES_EMPTY_TIP.contains("agentlink nodes"));
        assert!(NODES_FOOTER_TIP.contains("agentlink exec"));
        assert!(NODES_FOOTER_TIP.contains("agentlink grant list"));
        assert!(NODES_FOOTER_TIP.contains("agentlink guide"));
    }

    #[test]
    fn nodes_tips_name_offline_nodes() {
        let tips = nodes_tips(&[node(false, None, "")], "0.1.141");
        assert_eq!(tips.len(), 1, "{tips:?}");
        assert!(tips[0].contains("offline: box"), "{tips:?}");
        assert!(tips[0].contains("agentlink nodes"), "{tips:?}");
    }

    #[test]
    fn nodes_tips_name_both_versions_when_a_node_is_stale() {
        let tips = nodes_tips(&[node(true, Some(true), "0.1.44 (9c1180d…)")], "0.1.141");
        assert_eq!(tips.len(), 1, "{tips:?}");
        assert!(tips[0].contains("box"), "{tips:?}");
        assert!(tips[0].contains("0.1.44"), "{tips:?}");
        assert!(tips[0].contains("0.1.141"), "{tips:?}");
        assert!(tips[0].contains("agentlink update"), "{tips:?}");
    }

    #[test]
    fn nodes_tips_are_silent_when_online_and_current_or_newer() {
        assert!(nodes_tips(&[node(true, Some(true), "0.1.141")], "0.1.141").is_empty());
        assert!(nodes_tips(&[node(true, Some(true), "0.1.150")], "0.1.141").is_empty());
        assert!(nodes_tips(&[node(true, Some(true), "")], "0.1.141").is_empty());
    }

    #[test]
    fn nodes_tips_prefer_offline_over_stale_for_the_same_node() {
        let mut probe = node(false, None, "0.1.44");
        probe.name = "probe".into();
        let tips = nodes_tips(&[probe], "0.1.141");
        assert_eq!(tips.len(), 1, "{tips:?}");
        assert!(tips[0].contains("offline: probe"), "{tips:?}");
    }

    #[test]
    fn tip_node_offline_names_the_node_and_the_fix() {
        assert_eq!(
            tip_node_offline("probe"),
            "tip: offline: probe — wake the machine or check the agentlink-node service; then agentlink nodes"
        );
        assert!(tip_node_offline("probe").contains("wake the machine"));
        assert!(tip_node_offline("probe").contains("agentlink-node service"));
        assert!(tip_node_offline("probe").contains("agentlink nodes"));
    }

    #[test]
    fn decorate_node_offline_appends_the_tip_once() {
        let decorated = decorate_node_offline("node offline: probe");
        assert_eq!(
            decorated,
            "node offline: probe. tip: offline: probe — wake the machine or check the agentlink-node service; then agentlink nodes"
        );
        assert_eq!(decorate_node_offline(&decorated), decorated);
        assert_eq!(
            decorate_node_offline("exec hostname: node offline: probe"),
            "exec hostname: node offline: probe. tip: offline: probe — wake the machine or check the agentlink-node service; then agentlink nodes"
        );
    }

    #[test]
    fn decorate_node_offline_leaves_unrelated_errors_unchanged() {
        assert_eq!(
            decorate_node_offline("permission denied: exec"),
            "permission denied: exec"
        );
        assert_eq!(decorate_node_offline("node offline: "), "node offline: ");
    }

    #[test]
    fn nodes_cap_names_shortens_long_lists() {
        assert_eq!(nodes_cap_names(&["a", "b"]), "a, b");
        assert_eq!(
            nodes_cap_names(&["a", "b", "c", "d", "e"]),
            "a, b, c and 2 more"
        );
    }
}

/// When `dst` is an existing directory (or ends with `/`), append `file_name`
/// like Unix `cp`. Otherwise return `dst` unchanged (trim trailing slash noise).
async fn resolve_remote_cp_dest(
    client: &Client,
    node: &str,
    dst: &str,
    file_name: &str,
) -> Result<String> {
    let trailing_sep = dst.ends_with('/') || dst.ends_with('\\');
    let trimmed = dst.trim_end_matches(['/', '\\']);
    let trimmed = if trimmed.is_empty() { "/" } else { trimmed };
    let is_dir = match client.stat(node, trimmed).await {
        Ok(stat) => stat.is_dir,
        Err(_) if trailing_sep => {
            return Err(anyhow!(
                "destination `{dst}` ends with a slash but is not a directory on {node}"
            ));
        }
        Err(_) => false,
    };
    if is_dir || trailing_sep {
        Ok(join_remote_path(trimmed, file_name))
    } else {
        Ok(trimmed.to_string())
    }
}

fn resolve_local_cp_dest(local: &std::path::Path, remote_src: &str) -> Result<std::path::PathBuf> {
    if local.is_dir() {
        Ok(local.join(file_name_hint_str(remote_src)?))
    } else {
        Ok(local.to_path_buf())
    }
}

fn join_remote_path(dir: &str, file_name: &str) -> String {
    if dir == "/" {
        format!("/{file_name}")
    } else {
        format!("{dir}/{file_name}")
    }
}

fn file_name_hint(path: &std::path::Path) -> Result<&str> {
    path.file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow!("source path has no file name"))
}

fn file_name_hint_str(path: &str) -> Result<&str> {
    file_name_hint(std::path::Path::new(path))
}

async fn copy_path(
    client: &Client,
    src: &str,
    dst: &str,
    json_mode: bool,
    chunk_size: &str,
    window: usize,
    parallel: usize,
    compress: &str,
    direct: bool,
    progress: CpProgressMode,
) -> Result<()> {
    let opts = XferOpts {
        chunk_size: parse_size(chunk_size)?,
        window,
        parallel,
        compress: parse_compress(compress)?,
        resume: true,
        transport: if direct {
            "relay".into()
        } else {
            "relay-only".into()
        },
    };
    // Progress follows the flag and whether stderr is a terminal. `--json`
    // does not change that: the line is always stderr, and stdout stays the
    // final object below.
    let style = cp_progress_style(progress, std::io::stderr().is_terminal());
    let printer = CpProgress::start(style);
    let hook = printer.hook();
    let stats = match (parse_endpoint(src), parse_endpoint(dst)) {
        (Endpoint::Local(local), Endpoint::Remote { node, path }) => {
            let path = resolve_remote_cp_dest(client, &node, &path, file_name_hint(&local)?).await?;
            client
                .copy_upload(&node, &path, &local, &opts, hook)
                .await
                .map_err(|err| hint_cp_failure(&printer, err))?
        }
        (Endpoint::Remote { node, path }, Endpoint::Local(local)) => {
            let local = resolve_local_cp_dest(&local, &path)?;
            if let Some(parent) = local.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent).ok();
                }
            }
            client
                .copy_download(&node, &path, &local, &opts, hook)
                .await
                .map_err(|err| hint_cp_failure(&printer, err))?
        }
        (
            Endpoint::Remote {
                node: src_node,
                path: src_path,
            },
            Endpoint::Remote {
                node: dst_node,
                path: dst_path,
            },
        ) => {
            let dst_path =
                resolve_remote_cp_dest(client, &dst_node, &dst_path, file_name_hint_str(&src_path)?)
                    .await?;
            client
                .copy_node_to_node(
                    &src_node,
                    &src_path,
                    &dst_node,
                    &dst_path,
                    &opts,
                    direct,
                    hook,
                )
                .await
                .map_err(|err| hint_cp_failure(&printer, err))?
        }
        _ => {
            return Err(anyhow!(
                "cp copies a local path to node://name/path, the reverse, or node://a/path to node://b/path"
            ))
        }
    };
    printer.finish();
    let done_line = format_cp_done(&stats);
    emit(json_mode, cp_done_value(&stats), || {
        eprintln!("{done_line}");
    });
    Ok(())
}

fn human_bytes(bytes: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    let n = bytes as f64;
    if n >= GIB {
        format!("{:.1} GiB", n / GIB)
    } else if n >= MIB {
        format!("{:.1} MiB", n / MIB)
    } else if n >= KIB {
        format!("{:.1} KiB", n / KIB)
    } else {
        format!("{bytes} B")
    }
}

/// How a progress sample is written. Quiet writes nothing. A terminal uses one
/// carriage-return line. A forced non-terminal uses periodic newlines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CpProgressStyle {
    Quiet,
    CarriageReturn,
    Newline,
}

/// Newline-style updates, when progress is forced and stderr is not a terminal.
const CP_PROGRESS_NEWLINE_INTERVAL: Duration = Duration::from_millis(500);

fn cp_progress_style(mode: CpProgressMode, stderr_is_tty: bool) -> CpProgressStyle {
    match mode {
        CpProgressMode::Off => CpProgressStyle::Quiet,
        CpProgressMode::On if stderr_is_tty => CpProgressStyle::CarriageReturn,
        CpProgressMode::On => CpProgressStyle::Newline,
        CpProgressMode::Auto if stderr_is_tty => CpProgressStyle::CarriageReturn,
        CpProgressMode::Auto => CpProgressStyle::Quiet,
    }
}

/// Final `--json` document for `cp`. Progress is not part of this value.
fn cp_done_value(stats: &TransferStats) -> Value {
    json!({"event": "done", "stats": stats})
}

fn format_cp_progress(sent: u64, total: u64, rate_mib: f64, eta: Option<u64>) -> String {
    let rate = format!("{rate_mib:.1} MiB/s");
    if total == 0 {
        return format!("{}  {rate}", human_bytes(sent));
    }
    let percent = sent.min(total).saturating_mul(100) / total;
    let eta_txt = match eta {
        Some(secs) => format_eta_secs(secs),
        None if sent >= total => "0s".to_string(),
        None => "--".to_string(),
    };
    format!(
        "{} / {}  {rate}  {percent}%  eta {eta_txt}",
        human_bytes(sent),
        human_bytes(total)
    )
}

fn format_eta_secs(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{}h{:02}m", secs / 3600, (secs % 3600) / 60)
    }
}

/// Throughput from bytes received after the first sample, so a resumed
/// baseline is not counted as just transferred.
fn cp_rate_mib(origin_sent: u64, sent: u64, elapsed_secs: f64) -> f64 {
    if elapsed_secs <= 0.0 {
        return 0.0;
    }
    (sent.saturating_sub(origin_sent) as f64 / elapsed_secs) / (1024.0 * 1024.0)
}

fn cp_eta_secs(origin_sent: u64, sent: u64, total: u64, elapsed_secs: f64) -> Option<u64> {
    if total == 0 || sent >= total || elapsed_secs < 0.2 {
        return None;
    }
    let delta = sent.saturating_sub(origin_sent);
    if delta == 0 {
        return None;
    }
    let rate = delta as f64 / elapsed_secs;
    let remain = total.saturating_sub(sent) as f64 / rate;
    if !remain.is_finite() || remain < 0.0 {
        return None;
    }
    Some(remain.round() as u64)
}

fn cp_newline_due(last: Option<Instant>, now: Instant, sent: u64, total: u64) -> bool {
    let Some(last) = last else {
        return true;
    };
    if total > 0 && sent >= total {
        return true;
    }
    now.saturating_duration_since(last) >= CP_PROGRESS_NEWLINE_INTERVAL
}

/// Stderr text for one sample. Empty when progress is off. Never stdout.
fn render_cp_progress_update(style: CpProgressStyle, line: &str) -> String {
    match style {
        CpProgressStyle::Quiet => String::new(),
        CpProgressStyle::CarriageReturn => format!("\r{line}"),
        CpProgressStyle::Newline => format!("{line}\n"),
    }
}

struct CpProgressState {
    origin_sent: Option<u64>,
    origin_at: Option<Instant>,
    last_newline: Option<Instant>,
    last_emitted: Option<u64>,
    high: u64,
}

struct CpProgress {
    style: CpProgressStyle,
    printed: AtomicBool,
    width: AtomicUsize,
    state: Mutex<CpProgressState>,
}

impl CpProgress {
    fn start(style: CpProgressStyle) -> Arc<Self> {
        Arc::new(Self {
            style,
            printed: AtomicBool::new(false),
            width: AtomicUsize::new(0),
            state: Mutex::new(CpProgressState {
                origin_sent: None,
                origin_at: None,
                last_newline: None,
                last_emitted: None,
                high: 0,
            }),
        })
    }

    fn hook(self: &Arc<Self>) -> Option<Arc<dyn Fn(u64, u64) + Send + Sync>> {
        if self.style == CpProgressStyle::Quiet {
            return None;
        }
        let this = Arc::clone(self);
        Some(Arc::new(move |sent, total| this.on_sample(sent, total)))
    }

    fn on_sample(&self, sent: u64, total: u64) {
        if sent == 0 && total == 0 {
            return;
        }
        let now = Instant::now();
        let mut state = self.state.lock().unwrap_or_else(|err| err.into_inner());
        // Parallel chunks can report a lower cumulative value late. Keep the
        // line from moving backward. A bridge's second hop starts above the
        // first, so the high-water mark still climbs.
        let shown = state.high.max(sent);
        state.high = shown;
        let complete = total > 0 && shown >= total;
        // The last chunks of a parallel transfer all report `total`. Print 100%
        // once; later duplicates would be extra newline-mode lines.
        if complete && state.last_emitted == Some(shown) {
            return;
        }
        if self.style == CpProgressStyle::Newline
            && !cp_newline_due(state.last_newline, now, shown, total)
        {
            return;
        }
        if state.origin_at.is_none() {
            state.origin_sent = Some(shown);
            state.origin_at = Some(now);
        }
        let origin_sent = state.origin_sent.unwrap_or(shown);
        let origin_at = state.origin_at.unwrap_or(now);
        let elapsed = now.saturating_duration_since(origin_at).as_secs_f64();
        let rate = cp_rate_mib(origin_sent, shown, elapsed);
        let eta = cp_eta_secs(origin_sent, shown, total, elapsed);
        let mut line = format_cp_progress(shown, total, rate, eta);
        if self.style == CpProgressStyle::CarriageReturn {
            let cols = line.chars().count();
            let width = self.width.fetch_max(cols, Ordering::AcqRel).max(cols);
            if cols < width {
                line.push_str(&" ".repeat(width - cols));
            }
            self.printed.store(true, Ordering::Release);
        } else {
            state.last_newline = Some(now);
        }
        state.last_emitted = Some(shown);
        let text = render_cp_progress_update(self.style, &line);
        // Hold the lock across the write so two chunks cannot tear one line.
        eprint!("{text}");
        let _ = std::io::stderr().flush();
    }

    fn finish(&self) {
        if self.style == CpProgressStyle::CarriageReturn
            && self.printed.swap(false, Ordering::AcqRel)
        {
            eprintln!();
            let _ = std::io::stderr().flush();
        }
    }

    fn clear(&self) {
        if self.style != CpProgressStyle::CarriageReturn || !self.printed.load(Ordering::Acquire) {
            return;
        }
        let width = self.width.load(Ordering::Acquire);
        eprint!("{}", cp_progress_clear_seq(width));
        let _ = std::io::stderr().flush();
        self.printed.store(false, Ordering::Release);
    }
}

/// Erase sequence for a human cp progress line: carriage return, blank out
/// `width` columns, carriage return, then a newline so anything printed next
/// (e.g. `error:`) starts on a fresh line.
fn cp_progress_clear_seq(width: usize) -> String {
    format!("\r{}\r\n", " ".repeat(width.max(1)))
}

fn hint_cp_failure(printer: &CpProgress, err: impl std::fmt::Display) -> anyhow::Error {
    printer.clear();
    hint_cp_error(err)
}

/// Apply the listing tips at the CLI `ls` call site: permission first, then
/// the pathless ENOENT `io:` line. The node's `io:` line carries neither
/// label, so the caller's `node` and `path` are supplied here.
fn hint_list_dir_permission(
    err: impl std::fmt::Display,
    node: &str,
    path: &str,
) -> anyhow::Error {
    let message = decorate_list_dir_permission(&err.to_string(), node, path);
    anyhow!("{}", decorate_list_dir_io_missing(&message, node, path))
}

#[derive(Clone, Copy)]
enum FsHint {
    Cp,
    Cat,
    Write,
}

/// Extra guidance for the common filesystem failures of `cp`, `cat`, and
/// `write`. Applied at the CLI layer so the core error strings (and the JSON
/// `error` payload) stay unchanged.
fn hint_fs_error(err: impl std::fmt::Display, kind: FsHint) -> anyhow::Error {
    let msg = dedupe_fs_error(&err.to_string());
    if msg.contains("exists but is not a directory") || looks_like_enotdir_message(&msg) {
        let tip = match kind {
            FsHint::Cp => "a path component is a file (or other non-dir); pick a different destination path or remove/rename the blocking file — creating parents cannot fix that",
            FsHint::Cat => "a path component is a file (or other non-dir); check the path for a file where a directory is expected",
            FsHint::Write => "a path component is a file (or other non-dir); pick a different path or remove/rename the blocking file — creating parents cannot fix that",
        };
        anyhow!("{msg}. tip: {tip}")
    } else if looks_like_eisdir_message(&msg) {
        if msg.contains(EISDIR_TIP_MARKER) {
            return anyhow!("{msg}");
        }
        let tip = match kind {
            FsHint::Cp => "that source is a directory, not a regular file — list it with `agentlink ls <node> <path>`, or copy the tree with `agentlink cp node://<name>/<path> <local-dir>`",
            FsHint::Cat => "that path is a directory, not a file — list it with `agentlink ls <node> <path>` (or `agentlink cp` to fetch the tree); `agentlink cat` prints regular files only",
            FsHint::Write => "that path is a directory, not a file — pick a file path inside it; list it with `agentlink ls <node> <path>`",
        };
        anyhow!("{msg}. tip: {tip}")
    } else if msg.contains("No such file or directory") {
        let tip = match kind {
            FsHint::Cp => {
                "check the source path exists; remote sources use node://<name>/abs/or/home-relative"
            }
            FsHint::Cat => "check the remote path exists on the node (absolute or home-relative)",
            FsHint::Write => {
                "check the remote path's parent directory exists on the node (absolute or home-relative)"
            }
        };
        anyhow!("{msg}. tip: {tip}")
    } else if msg.contains("Permission denied") || msg.contains("os error 13") {
        let tip = match kind {
            FsHint::Cp => {
                "need write access to the destination (and its parent); on a node, the agentlink-node user must be allowed"
            }
            FsHint::Cat => "the agentlink-node user needs read access to that path",
            FsHint::Write => {
                "the agentlink-node user needs write access to that path (and its parent)"
            }
        };
        anyhow!("{msg}. tip: {tip}")
    } else if msg.contains("not a regular file") || msg.contains("refusing fifo/socket/device") {
        let tip = match kind {
            FsHint::Cp => {
                "cp copies regular files (and directories via dir mode); not devices, fifos, or sockets"
            }
            FsHint::Cat => "cat reads regular files; not devices, fifos, or sockets",
            FsHint::Write => "write targets regular files; not devices, fifos, or sockets",
        };
        anyhow!("{msg}. tip: {tip}")
    } else {
        anyhow!("{msg}")
    }
}

fn hint_cp_error(err: impl std::fmt::Display) -> anyhow::Error {
    hint_fs_error(err, FsHint::Cp)
}

fn dedupe_fs_error(msg: &str) -> String {
    if let Some(idx) = msg.rfind(": ") {
        let (head, tail) = msg.split_at(idx);
        let tail = &tail[2..];
        if !tail.is_empty() && head.ends_with(tail) {
            return head.to_string();
        }
    }
    msg.to_string()
}

/// Byte sizes in `cp` summaries: human units at or above 1 KiB, plain bytes
/// below so small files stay exact.
fn format_cp_size(bytes: u64) -> String {
    if bytes >= 1024 {
        human_bytes(bytes)
    } else {
        format!("{bytes} bytes")
    }
}

fn format_cp_done(stats: &TransferStats) -> String {
    let skipped = stats.skipped || (stats.files_skipped == stats.files && stats.payload_bytes == 0);
    let logical = format_cp_size(stats.logical_bytes);
    if skipped {
        if stats.files > 1 {
            format!(
                "already up to date; skipped {}/{} files, {logical} (transport {})",
                stats.files_skipped, stats.files, stats.transport
            )
        } else {
            format!(
                "already up to date; skipped {logical} (transport {})",
                stats.transport
            )
        }
    } else {
        format!(
            "copied {logical} (payload {}, transport {})",
            format_cp_size(stats.payload_bytes),
            stats.transport
        )
    }
}

fn parse_size(input: &str) -> Result<usize> {
    let lower = input.trim().to_ascii_lowercase();
    let (num, mul) = if let Some(n) = lower.strip_suffix("mib") {
        (n, 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("kib") {
        (n, 1024)
    } else if let Some(n) = lower.strip_suffix("gib") {
        (n, 1024 * 1024 * 1024)
    } else if let Some(n) = lower.strip_suffix("mb") {
        (n, 1000 * 1000)
    } else if let Some(n) = lower.strip_suffix("kb") {
        (n, 1000)
    } else {
        (lower.as_str(), 1usize)
    };
    let n: u64 = num.trim().parse().map_err(|_| {
        anyhow!("chunk size `{input}` is not a number with an optional KiB/MiB/GiB suffix")
    })?;
    Ok(n.saturating_mul(mul as u64) as usize)
}

fn parse_compress(input: &str) -> Result<CompressPref> {
    match input.trim().to_ascii_lowercase().as_str() {
        "auto" => Ok(CompressPref::Auto),
        "on" => Ok(CompressPref::On),
        "off" => Ok(CompressPref::Off),
        _ => Err(anyhow!("compress must be auto, on, or off")),
    }
}

fn enroll_command(settings: &ClientSettings, token: &str, name: &str) -> String {
    let mut cmd = format!("agentlink node --relay {}", settings.relay);
    if !settings.fingerprint.trim().is_empty() {
        cmd.push_str(&format!(" --fingerprint {}", settings.fingerprint));
    }
    if let Some(trust) = settings.trust.as_deref().filter(|value| !value.is_empty()) {
        cmd.push_str(&format!(" --trust {trust}"));
    }
    cmd.push_str(&format!(" --pairing-token {token} --name {name}"));
    cmd
}

fn open_browser(url: &str) {
    let result = if cfg!(target_os = "macos") {
        agentlink_core::process::hidden("open").arg(url).spawn()
    } else if cfg!(target_os = "windows") {
        agentlink_core::process::hidden("cmd")
            .args(["/C", "start", "", url])
            .spawn()
    } else {
        agentlink_core::process::hidden("xdg-open").arg(url).spawn()
    };
    if result.is_err() {
        eprintln!("could not launch a browser; open the URL above");
    }
}

fn settings(cli: &Cli) -> Result<ClientSettings> {
    let dir = config_dir(cli)?;
    load_settings(
        &dir,
        cli.relay.clone(),
        cli.token.clone(),
        cli.fingerprint.clone(),
        cli.trust.clone(),
    )
    .map_err(|err| anyhow!(err))
}

fn tray_ui(command: &Command) -> bool {
    matches!(command, Command::Tray { action: None, .. })
}

/// Rewrite `bg <verb> <node> …` into the clap shape `bg <node> <verb> …`.
///
/// Agents and humans often put the subcommand first (`bg list example`), matching
/// git/docker muscle memory. Clap's `bg <NODE> <COMMAND>` rejects that; normalize
/// before parse so both orders work. Canonical help still shows NODE first.
fn normalize_cli_argv<I, T>(raw: I) -> Vec<std::ffi::OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<std::ffi::OsString>,
{
    let mut args: Vec<std::ffi::OsString> = raw.into_iter().map(Into::into).collect();
    normalize_bg_verb_before_node(&mut args);
    args
}

fn normalize_bg_verb_before_node(args: &mut Vec<std::ffi::OsString>) {
    const VERBS: &[&str] = &["list", "start", "output", "status", "kill", "help"];
    let Some(bg_idx) = find_top_level_command(args) else {
        return;
    };
    if args.get(bg_idx).and_then(|s| s.to_str()) != Some("bg") {
        return;
    }
    let Some(verb) = args.get(bg_idx + 1).and_then(|s| s.to_str()) else {
        return;
    };
    if !VERBS.contains(&verb) {
        return; // already `bg <node> …`, or unknown
    }
    match verb {
        "list" | "help" => {
            // `bg list NODE` → `bg NODE list`
            if args.len() > bg_idx + 2 {
                let node = args.remove(bg_idx + 2);
                if looks_like_cli_flag(&node) {
                    args.insert(bg_idx + 2, node);
                    return;
                }
                args.insert(bg_idx + 1, node);
            }
        }
        "status" | "kill" | "output" => {
            // Canonical is `bg NODE status ID`. Verb-first keeps the remaining
            // args in that same order: `bg status NODE ID` → `bg NODE status ID`.
            // Also accept the older `bg status ID NODE` when the first token looks
            // like a process id and the second looks like a node name.
            // Incomplete `bg status NODE` → `bg NODE status`.
            if args.len() > bg_idx + 3 {
                let a = args[bg_idx + 2].to_str().unwrap_or("");
                let b = args[bg_idx + 3].to_str().unwrap_or("");
                let node_at = if looks_like_bg_process_id(a) && looks_like_node_name(b) {
                    bg_idx + 3
                } else {
                    bg_idx + 2
                };
                let node = args.remove(node_at);
                if looks_like_cli_flag(&node) {
                    args.insert(node_at, node);
                    return;
                }
                args.insert(bg_idx + 1, node);
            } else if args.len() == bg_idx + 3 {
                let node = args.remove(bg_idx + 2);
                if looks_like_cli_flag(&node) {
                    args.insert(bg_idx + 2, node);
                    return;
                }
                args.insert(bg_idx + 1, node);
            }
        }
        "start" => {
            // `bg start [--cwd DIR] [--shell] NODE [--] cmd…` → `bg NODE start …`
            let mut i = bg_idx + 2;
            while i < args.len() {
                let s = args[i].to_str().unwrap_or("");
                if s == "--" {
                    break;
                }
                if s == "--cwd" {
                    i += 2;
                    continue;
                }
                if let Some(rest) = s.strip_prefix("--cwd=") {
                    let _ = rest;
                    i += 1;
                    continue;
                }
                if s == "--env" {
                    i += 2;
                    continue;
                }
                if let Some(rest) = s.strip_prefix("--env=") {
                    let _ = rest;
                    i += 1;
                    continue;
                }
                if s == "--shell" {
                    i += 1;
                    continue;
                }
                if s.starts_with('-') {
                    i += 1;
                    continue;
                }
                let node = args.remove(i);
                args.insert(bg_idx + 1, node);
                break;
            }
        }
        _ => {}
    }
}


/// Parse repeatable `--env KEY=VALUE` flags into pairs for Exec/BgStart.

/// When stdin is not a terminal, forward its bytes to the remote process (max 16 MiB).
/// A terminal stdin stays `/dev/null` on the node so interactive agents do not hang.
fn read_exec_stdin() -> Result<Option<Vec<u8>>> {
    use std::io::Read;
    const MAX_STDIN: usize = 16 * 1024 * 1024;
    if std::io::stdin().is_terminal() {
        return Ok(None);
    }
    let mut buf = Vec::new();
    std::io::stdin()
        .lock()
        .read_to_end(&mut buf)
        .map_err(|err| anyhow!("read stdin: {err}"))?;
    if buf.is_empty() {
        return Ok(None);
    }
    if buf.len() > MAX_STDIN {
        return Err(anyhow!(
            "stdin is {} bytes; max is {MAX_STDIN}. Write a remote file and exec that path instead.",
            buf.len()
        ));
    }
    Ok(Some(buf))
}

fn parse_env_pairs(items: &[String]) -> Result<Vec<(String, String)>> {
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let Some((key, value)) = item.split_once('=') else {
            return Err(anyhow!(
                "--env expects KEY=VALUE, got `{item}` (example: --env FOO=bar)"
            ));
        };
        if key.is_empty() || key.contains('\0') || value.contains('\0') {
            return Err(anyhow!("rejected env var `{key}`"));
        }
        out.push((key.to_string(), value.to_string()));
    }
    Ok(out)
}

fn dir_entry_kind(entry: &agentlink_core::protocol::DirEntry) -> &'static str {
    if entry.is_symlink {
        "l"
    } else if entry.is_dir {
        "d"
    } else {
        "-"
    }
}

fn looks_like_cli_flag(arg: &std::ffi::OsString) -> bool {
    arg.to_str().is_some_and(|s| s.starts_with('-'))
}

/// Glob metacharacters that belong in `find`'s PATTERN, not PATH.
fn looks_like_glob_pattern(s: &str) -> bool {
    s.contains('*') || s.contains('?') || s.contains('[')
}

/// Absolute/home/relative roots that belong in `find`'s PATH, not PATTERN.
fn looks_like_find_search_root(s: &str) -> bool {
    if s.is_empty() || looks_like_glob_pattern(s) {
        return false;
    }
    s.starts_with('/')
        || s.starts_with('~')
        || s.starts_with('.')
        || s.contains('/')
        || s.contains('\\')
}

/// `find NODE /tmp '*.rs'` puts PATH where PATTERN belongs.
fn find_path_before_pattern_hint(pattern: &str, path: Option<&str>) -> Option<String> {
    let path = path?;
    if looks_like_find_search_root(pattern) && looks_like_glob_pattern(path) {
        Some(format!(
            "argument order is `find <NODE> <PATTERN> [PATH]`; `{pattern}` looks like a search root and `{path}` looks like a pattern. Did you mean `agentlink find <NODE> {} {}`?",
            shell_quote_arg(path),
            shell_quote_arg(pattern)
        ))
    } else {
        None
    }
}

/// `find NODE /tmp -name '*.txt'` uses unix `find` predicates that clap rejects
/// before `find_path_before_pattern_hint` can run. Detect them in argv and point
/// at the agentlink order (`find <NODE> <PATTERN> [PATH]`) instead.
fn find_unix_predicate_hint(args: &[std::ffi::OsString]) -> Option<String> {
    let find_idx = find_top_level_command(args)?;
    if args.get(find_idx).and_then(|s| s.to_str()) != Some("find") {
        return None;
    }

    let mut predicate: Option<&str> = None;
    let mut ignore_case = false;
    let mut name_value: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut type_seen = false;

    let mut i = find_idx + 1;
    while i < args.len() {
        let s = args[i].to_str().unwrap_or("");
        if s == "--" {
            break;
        }
        match s {
            "-name" | "--name" => {
                if let Some(value) = args.get(i + 1).and_then(|a| a.to_str()) {
                    predicate = Some("-name");
                    name_value = Some(value.to_string());
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            "-iname" | "--iname" => {
                if let Some(value) = args.get(i + 1).and_then(|a| a.to_str()) {
                    predicate = Some("-iname");
                    ignore_case = true;
                    name_value = Some(value.to_string());
                    i += 2;
                    continue;
                }
                i += 1;
                continue;
            }
            "-type" => {
                type_seen = true;
                i += if args.get(i + 1).is_some() { 2 } else { 1 };
                continue;
            }
            "--ignore-case" => {
                ignore_case = true;
                i += 1;
                continue;
            }
            "--offset" | "--limit" => {
                i += 2;
                continue;
            }
            _ => {}
        }
        if s.starts_with("--offset=") || s.starts_with("--limit=") {
            i += 1;
            continue;
        }
        if s.starts_with('-') && s != "-" {
            i += 1;
            continue;
        }
        positionals.push(s.to_string());
        i += 1;
    }

    let predicate = predicate?;
    let pattern = name_value?;
    let node = positionals.first()?;
    let path = positionals.get(1);

    let mut hint = String::from(
        "agentlink `find` does not take unix `find -name`; put the glob after the node: `find <NODE> <PATTERN> [PATH]`.",
    );
    if predicate == "-iname" {
        hint.push_str(" For case-insensitive matches use `--ignore-case`.");
    }
    if type_seen {
        hint.push_str(" `-type` is also not supported.");
    }

    let mut suggestion = format!("agentlink find {}", shell_quote_arg(node));
    if ignore_case {
        suggestion.push_str(" --ignore-case");
    }
    suggestion.push(' ');
    suggestion.push_str(&shell_quote_arg(&pattern));
    if let Some(path) = path {
        suggestion.push(' ');
        suggestion.push_str(&shell_quote_arg(path));
    }
    hint.push_str(&format!(" Did you mean `{suggestion}`?"));
    Some(hint)
}

/// `port forward 18080 box 127.0.0.1:80` swaps NODE and LOCAL_PORT, which
/// clap rejects as `invalid value 'box' for '<LOCAL_PORT>'` before port_cmd
/// can run. Detect the swap in argv so the user gets the real argument order.
fn port_swapped_arg_hint(args: &[std::ffi::OsString]) -> Option<String> {
    let port_idx = find_top_level_command(args)?;
    if args.get(port_idx).and_then(|s| s.to_str()) != Some("port") {
        return None;
    }
    let action_idx = port_idx + 1;
    let action = args.get(action_idx)?.to_str()?;
    let usage = match action {
        "forward" => "port forward <NODE> <LOCAL_PORT> <REMOTE>",
        "reverse" => "port reverse <NODE> <REMOTE_PORT> <LOCAL>",
        _ => return None,
    };

    let mut positionals: Vec<&str> = Vec::new();
    for arg in args.iter().skip(action_idx + 1) {
        let s = arg.to_str().unwrap_or("");
        if s == "--" {
            break;
        }
        if s.starts_with('-') && s != "-" {
            continue;
        }
        positionals.push(s);
        if positionals.len() == 3 {
            break;
        }
    }

    let port = positionals.first()?;
    let node = positionals.get(1)?;
    if !looks_like_bare_port(port) || !looks_like_node_token(node) {
        return None;
    }

    let mut suggestion = format!(
        "agentlink port {action} {} {}",
        shell_quote_arg(node),
        shell_quote_arg(port)
    );
    if let Some(remote) = positionals.get(2) {
        suggestion.push(' ');
        suggestion.push_str(&shell_quote_arg(remote));
    }
    Some(format!(
        "argument order is `{usage}`; Did you mean `{suggestion}`?"
    ))
}

fn looks_like_bare_port(s: &str) -> bool {
    !s.is_empty() && s.parse::<u16>().is_ok()
}

/// Node-name-ish token for the swap check: not a flag, not a pure number, and
/// not a `host:port` target (which belongs in the REMOTE/LOCAL slot).
fn looks_like_node_token(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.chars().all(|c| c.is_ascii_digit())
        && !s.contains(':')
}

/// `search NODE /tmp needle` puts PATH where PATTERN belongs.
///
/// Unlike `find`, the trailing arg is a content needle (not a glob), so the
/// swap signal is: PATTERN looks like a search root and PATH looks like a
/// bare word rather than another path.
fn search_path_before_pattern_hint(pattern: &str, path: Option<&str>) -> Option<String> {
    let path = path?;
    if looks_like_find_search_root(pattern)
        && !looks_like_find_search_root(path)
        && !looks_like_glob_pattern(path)
    {
        Some(format!(
            "argument order is `search <NODE> <PATTERN> [PATH]`; `{pattern}` looks like a search root and `{path}` looks like a content pattern. Did you mean `agentlink search <NODE> {} {}`?",
            shell_quote_arg(path),
            shell_quote_arg(pattern)
        ))
    } else {
        None
    }
}

fn hint_exec_cwd_missing(err: impl std::fmt::Display, cwd: Option<&str>) -> anyhow::Error {
    let msg = err.to_string();
    if let Some(cwd) = cwd {
        if let Some(hint) = exec_cwd_error_hint(&msg, cwd) {
            return anyhow!(hint);
        }
    }
    anyhow!("{msg}")
}

/// Extra guidance when `exec` spawn fails with EACCES. Scoped to the exec error
/// path so `cp`/`cat`/`write` Permission denied keeps its `hint_fs_error` tip.
fn hint_exec_eacces(err: impl std::fmt::Display, cwd: Option<&str>) -> anyhow::Error {
    anyhow!("{}", decorate_exec_eacces(&err.to_string(), cwd))
}

/// Extra guidance when `bg start` fails to spawn the caller's program with
/// EACCES. Scoped to the bg start arm; the exec branch keeps `hint_exec_eacces`.
fn hint_bg_start_exec_denied(
    err: impl std::fmt::Display,
    node: &str,
    program: &str,
    cwd: Option<&str>,
) -> anyhow::Error {
    anyhow!(
        "{}",
        decorate_bg_start_exec_denied(&err.to_string(), node, program, cwd)
    )
}

/// Extra guidance when `exec` hits the core `Error::Timeout` (bare `timed out`).
/// Applied after the cwd hint so a missing-`--cwd` diagnosis is not replaced.
fn hint_exec_timeout(err: impl std::fmt::Display, timeout_secs: u64) -> anyhow::Error {
    let msg = err.to_string();
    if !looks_like_exec_timeout(&msg) {
        return anyhow!("{msg}");
    }
    if timeout_secs > 0 {
        anyhow!(
            "{msg}. tip: timed out after {timeout_secs}s — raise with `agentlink exec … --timeout-secs N` (0 waits forever)"
        )
    } else {
        anyhow!(
            "{msg}. tip: no CLI timeout was set (--timeout-secs 0); the timeout came from the relay/node path — check the node is reachable and retry"
        )
    }
}

fn looks_like_exec_timeout(msg: &str) -> bool {
    let msg = msg.trim();
    msg == "timed out" || msg.ends_with(": timed out")
}

const EXEC_CWD_MISS_TIP_MARKER: &str = "the target directory does not exist on the node";

/// Locate a node `cwd <path>: <err>` frame whose error is ENOENT or ENOTDIR.
/// Returns the cwd and whether the failure was ENOTDIR. Requiring the `cwd `
/// prefix keeps unrelated `not found: /path` and program-miss tips untouched.
fn exec_cwd_miss_cause(message: &str) -> Option<(&str, bool)> {
    const HEAD: &str = "cwd ";
    let mut rest = message;
    while let Some(pos) = rest.find(HEAD) {
        let after = &rest[pos + HEAD.len()..];
        if let Some(colon) = after.find(": ") {
            let cwd = &after[..colon];
            let err = &after[colon + 2..];
            let enotdir = looks_like_enotdir_message(err);
            if !cwd.is_empty() && (enotdir || looks_like_enoent_message(err)) {
                return Some((cwd, enotdir));
            }
        }
        rest = after;
    }
    None
}

/// Append an actionable tip when exec / bg / pty / MCP `run_command` fails
/// because the requested cwd is missing or is not a directory. Idempotent;
/// skips messages already carrying the CLI hint (`Check `--cwd …`` or the
/// not-a-directory wording) so CLI and MCP never double-tip.
fn decorate_exec_cwd_missing(message: &str) -> String {
    if message.contains(EXEC_CWD_MISS_TIP_MARKER)
        || message.contains("Check `--cwd")
        || message.contains("exists but is not a directory")
    {
        return message.to_string();
    }
    let Some((cwd, enotdir)) = exec_cwd_miss_cause(message) else {
        return message.to_string();
    };
    if enotdir {
        format!(
            "{message}. tip: {EXEC_CWD_MISS_TIP_MARKER} — `{cwd}` exists but is not a directory, \
             so use a directory path (create one with `agentlink mkdir <node> <dir> -p` / MCP \
             `mkdir`), pass an absolute path, or omit `cwd` and `cd`/`--shell` instead; relative \
             paths resolve against the node's cwd and `~` is not expanded."
        )
    } else {
        format!(
            "{message}. tip: {EXEC_CWD_MISS_TIP_MARKER} — create it first (`agentlink mkdir \
             <node> <dir> -p` / MCP `mkdir`), pass an absolute path, or omit `cwd` and \
             `cd`/`--shell` instead; relative paths resolve against the node's cwd and `~` is not \
             expanded."
        )
    }
}

const EXEC_CWD_PERMISSION_TIP_MARKER: &str =
    "the node user cannot enter the requested working directory";

/// Exact OS tails from `finish_command`'s pre-spawn `metadata(cwd)` failure.
/// The raw line is `cwd <resolved-path>: <tail>`, so the path is already
/// present and no caller context is needed. Only these two permission tails
/// qualify: ENOENT/ENOTDIR belong to `decorate_exec_cwd_missing`, and the
/// `spawn:`/`io:` forms to other decorators.
const EXEC_CWD_PERMISSION_TAILS: &[&str] = &[
    "Permission denied (os error 13)",
    "Access is denied. (os error 5)",
];

/// Extract the resolved path from a `cwd <path>: <tail>` frame whose tail is
/// one of the two permission forms. A frame must begin at the start of the
/// message or immediately after a `": "` context separator, so a node name such
/// as `exec cwd x: …` cannot masquerade as one. `rsplit_once` splits on the last
/// `": "`, so spaces, embedded `": "`, and a Windows drive colon stay in the path.
fn exec_cwd_permission_cause(message: &str) -> Option<&str> {
    const HEAD: &str = "cwd ";
    let m = message.trim_end();
    let mut from = 0;
    while let Some(rel) = m[from..].find(HEAD) {
        let pos = from + rel;
        let frame_start = pos == 0 || m[..pos].ends_with(": ");
        if frame_start {
            let rest = &m[pos + HEAD.len()..];
            if let Some((path, tail)) = rest.rsplit_once(": ") {
                if !path.is_empty() && EXEC_CWD_PERMISSION_TAILS.iter().any(|s| tail == *s) {
                    return Some(path);
                }
            }
        }
        from = pos + HEAD.len();
    }
    None
}

/// Append an actionable tip when the node's pre-spawn working-directory check
/// is denied because the node user cannot traverse to the requested directory.
/// The raw line already names the operation and the node-resolved path, so this
/// decorator is text-only. Idempotent; missing/not-a-directory, `spawn:`, and
/// bare `io:` permission lines are left alone.
fn decorate_exec_cwd_permission(message: &str) -> String {
    if message.contains(EXEC_CWD_PERMISSION_TIP_MARKER) {
        return message.to_string();
    }
    let Some(path) = exec_cwd_permission_cause(message) else {
        return message.to_string();
    };
    format!(
        "{message}. tip: {EXEC_CWD_PERMISSION_TIP_MARKER} — `exec` (CLI and MCP `run_command`, \
         including the CLI's non-interactive terminal fallback) and `bg start` (MCP \
         `process_start`) apply the requested working directory on the node, and the node's user \
         cannot enter `{path}`. The node checks it before spawning, so nothing ran: there is no pid, \
         exit code, stdout, or stderr, and no command side effects; retrying unchanged fails \
         identically. This is a traversal (search) denial, not a read or write permission on the \
         directory's contents. On Unix, entering a directory needs execute/search (`+x`) on every \
         component from `/` down to `{path}`; read and write bits are irrelevant. The blocked \
         component is usually an ancestor owned by someone else — `/root` (mode `0700`), another \
         user's home (`/home/<user>` is `0700` on most systems), a `0750` group directory you are \
         not in — or an ACL/SELinux/AppArmor rule; a symlink component is resolved, so its target's \
         ancestors must be traversable too. Because the kernel checks traversal first, `{path}` may \
         not exist at all: a typo below an inaccessible parent reports the same denial. Windows \
         reports the ACL refusal as `Access is denied.`. Fix the working directory, not the program: \
         omit `cwd` to use the node's default directory, point `--cwd` at a directory the node user \
         can enter (for example `/tmp`, `/var/tmp`, or a shared workspace), or ask the operator to \
         grant traversal on the blocking ancestor — narrowly with `setfacl -m u:<node-user>:x \
         <ancestor>` or a group `+x`, broadly with `chmod o+x` — and grant it on the ancestor, not \
         only on `{path}`. Copying the tree into an accessible workspace is the alternative when the \
         owner should not loosen permissions. Inspect from the top down: MCP `stat_path` on `{path}` \
         and each ancestor — if stat on `{path}` fails with a bare `io:` permission-denied line, the \
         blocker is above it — plus `stat_path` on the nearest traversable parent for mode and owner, \
         and `run_command` `namei -l {path}` / `stat -c '%A %U:%G %n' <ancestor>`; on Linux also \
         `getfacl` or `ls -lZ` for ACL/SELinux labels, on Windows `icacls`. This is not the \
         missing-directory case (the path is absent), not the not-a-directory case (a file sits at \
         `{path}`), not the `--root` confinement refusal (rejected before the working directory is \
         examined), not a signed-grant, approval, or node-offline failure, and not a read/write \
         denial on `{path}`'s contents. Do not confuse it with the spawn-time permission denial you \
         get when the working directory itself — rather than an ancestor — is unenterable: that line \
         looks like a program permission error but has the same cause, so verify the directory before \
         changing any execute bit. See `agentlink guide <node>`."
    )
}

/// Extra guidance when `--cwd` is missing or is not a directory.
fn exec_cwd_error_hint(msg: &str, cwd: &str) -> Option<String> {
    if looks_like_enotdir_message(msg) {
        return Some(format!(
            "{msg}. `{cwd}` exists but is not a directory; pass a directory path to `--cwd`."
        ));
    }
    if looks_like_enoent_message(msg) {
        return Some(format!(
            "{msg}. Check `--cwd {cwd}` exists on the node (create it with `mkdir -p`/`--parents` if needed)."
        ));
    }
    None
}

/// True when `msg` mentions a specific `os error N` without matching a longer code
/// (`os error 2` must not match `os error 20`).
fn message_mentions_os_error(msg: &str, code: i32) -> bool {
    let needle = format!("os error {code}");
    msg.match_indices(&needle).any(|(idx, _)| {
        !msg.as_bytes()
            .get(idx + needle.len())
            .is_some_and(u8::is_ascii_digit)
    })
}

fn looks_like_enoent_message(msg: &str) -> bool {
    msg.contains("No such file or directory")
        || msg.contains("ENOENT")
        || msg.contains("The system cannot find")
        || message_mentions_os_error(msg, 2)
}

fn looks_like_enotdir_message(msg: &str) -> bool {
    msg.contains("Not a directory")
        || msg.contains("ENOTDIR")
        || message_mentions_os_error(msg, 20)
}

const EISDIR_TIP_MARKER: &str = "list it with";

fn looks_like_eisdir_message(msg: &str) -> bool {
    msg.contains("Is a directory") || msg.contains("EISDIR") || message_mentions_os_error(msg, 21)
}

const MKDIR_ALREADY_EXISTS_TIP_MARKER: &str =
    "a non-recursive mkdir fails when the directory already exists";

fn is_mkdir_already_exists_error(message: &str) -> bool {
    message.contains("already exists as a directory")
}

/// Node-resolved path from ``mkdir `<path>` already exists as a directory``;
/// the caller's path is used only as a fallback label.
fn mkdir_already_exists_path(message: &str) -> Option<&str> {
    let (_, rest) = message.split_once("mkdir `")?;
    let (path, _) = rest.split_once('`')?;
    (!path.is_empty()).then_some(path)
}

/// Append an actionable tip when non-recursive `mkdir` hits EEXIST on a
/// directory. Idempotent; the sibling file-blocker diagnostics are left alone.
fn decorate_mkdir_already_exists(message: &str, path: &str) -> String {
    if message.contains(MKDIR_ALREADY_EXISTS_TIP_MARKER)
        || message.contains("exists but is not a directory")
        || message.contains("cannot replace a file with a directory")
        || message.contains("path component ")
        || !is_mkdir_already_exists_error(message)
    {
        return message.to_string();
    }
    let dir = mkdir_already_exists_path(message).unwrap_or(path);
    format!(
        "{message}. tip: {MKDIR_ALREADY_EXISTS_TIP_MARKER} — `mkdir` (CLI) / MCP `mkdir` with \
         `parents: false` maps to mkdir(2), which refuses any existing path even when it is \
         already the directory you wanted; nothing was created and `{dir}` and its contents are \
         untouched. Because `{dir}` already is a directory, the desired end state holds — you can \
         continue using it; this is not a permission, grant, sandbox, or node-offline failure. To \
         make creation idempotent, pass `-p`/`--parents`: `agentlink mkdir <node> {dir} -p` / MCP \
         `mkdir` with `parents: true` (the MCP default). With `-p`, an existing directory is \
         success and intermediate directories are created; the CLI still prints `created {dir}` \
         even when the directory already existed, so do not read that line as proof it was new. \
         If you expected a fresh or empty directory, this one may hold stale files: inspect it \
         with `agentlink ls <node> {dir}` / MCP `list_dir` or `stat_path`, then remove and \
         recreate it with `agentlink rm <node> {dir} -r` / MCP `remove_path` with `recursive: \
         true` (permanent — deletes everything under it; a symlink is unlinked, never followed), \
         or pick a different name. If the path exists as a file or a symlink to a file you \
         instead get `exists but is not a directory`; that needs the blocking file removed or \
         renamed, and `-p` cannot fix it. Retrying this non-recursive call unchanged fails \
         identically. See `agentlink guide <node>`."
    )
}

const MKDIR_TARGET_NOT_DIR_TIP_MARKER: &str =
    "mkdir needs an unused name and cannot replace an existing file";

/// Require the `mkdir \`` producer prefix so the shared `exists but is not a
/// directory` phrase from `mv`, copy-parent, and `path component` diagnostics
/// is left alone.
fn is_mkdir_target_not_dir_error(message: &str) -> bool {
    message.contains("mkdir `") && message.contains("exists but is not a directory")
}

/// Node-resolved path from ``mkdir `<path>` exists but is not a directory...``.
fn mkdir_target_not_dir_path(message: &str) -> Option<&str> {
    let (_, rest) = message.split_once("mkdir `")?;
    let (path, _) = rest.split_once('`')?;
    (!path.is_empty()).then_some(path)
}

/// Append an actionable tip when `mkdir` hits a non-directory leaf. The path
/// comes from the message, so this is safe in the global CLI chains and in MCP
/// `tool_err`; idempotent and disjoint from the already-exists-as-directory tip.
fn decorate_mkdir_target_not_dir(message: &str) -> String {
    if message.contains(MKDIR_TARGET_NOT_DIR_TIP_MARKER)
        || !is_mkdir_target_not_dir_error(message)
    {
        return message.to_string();
    }
    let Some(dir) = mkdir_target_not_dir_path(message) else {
        return message.to_string();
    };
    format!(
        "{message}. tip: {MKDIR_TARGET_NOT_DIR_TIP_MARKER} — the node called mkdir(2) on `{dir}` \
         (`create_dir_all` for the `-p`/`parents: true` form) and the path already exists as \
         something that is not a directory: a regular file, a symlink to a file, a dangling \
         symlink, or another special file. The leaf is the blocker, its parent directory is fine, \
         nothing was created, and the existing object was not modified. This is a name collision, \
         not a permission, grant, sandbox, node-offline, or missing-parent failure. \
         `-p`/`--parents` cannot fix it: parents only help create missing intermediate \
         directories (the recursive form already appends `cannot replace a file with a \
         directory`). Retrying the same call unchanged fails identically. Inspect the blocker \
         with `agentlink ls <node> <parent>` / MCP `list_dir` and MCP `stat_path` (`is_dir: \
         false` with `is_file: true`, or `is_symlink: true` whose target is not a directory). \
         Then either remove the file (it is a file, so no `-r` is needed) with `agentlink rm \
         <node> {dir}` / MCP `remove_path` (a symlink is unlinked and its target is untouched), \
         or move it aside with `agentlink mv <node> {dir} {dir}.bak` / MCP `move_path`, and rerun \
         the mkdir; if the file is needed, create the directory under a different name and use \
         that for subsequent writes/runs. If you expected an existing directory, that is the \
         separate `already exists as a directory` message (also tipped) — this one means \
         the leaf is not a directory. If an intermediate component is the blocker you get `path \
         component … exists but is not a directory`, which already names the remedy. The path \
         above is what the node resolved (`~` and the sandbox root applied). See `agentlink guide \
         <node>`."
    )
}

const MKDIR_MISSING_PARENT_TIP_MARKER: &str =
    "`mkdir` with `parents: false` does not create missing parent directories";

/// Only the `mkdir` arm knows the operation and its `parents` flag: the bare
/// `io:` ENOENT and the `not found: parent directory does not exist:` prefix
/// are shared by many ops, so this must never go in the flat `tool_err` chain.
fn is_mkdir_missing_parent_error(message: &str, parents: bool) -> bool {
    if parents {
        return false;
    }
    let msg = message.trim_start();
    (msg.starts_with("io: ") && looks_like_enoent_message(msg))
        || msg.starts_with("not found: parent directory does not exist: ")
}

/// Append an actionable tip when `mkdir` with `parents: false` hits a missing
/// intermediate. The `--root` form names the unresolvable directory; the
/// pathless `io:` ENOENT does not. Idempotent; `parents: true` is left alone
/// (there the same literal means a dangling-symlink component).
fn decorate_mkdir_missing_parent(message: &str, path: &str, parents: bool) -> String {
    if message.contains(MKDIR_MISSING_PARENT_TIP_MARKER)
        || message.contains("Did you mean")
        || !is_mkdir_missing_parent_error(message, parents)
    {
        return message.to_string();
    }
    let msg = message.trim_start();
    let named = msg
        .strip_prefix("not found: parent directory does not exist: ")
        .map(|dir| format!("The node named the unresolvable directory as `{}`. ", dir.trim_end()))
        .unwrap_or_default();
    format!(
        "{message}. tip: {MKDIR_MISSING_PARENT_TIP_MARKER} — MCP `mkdir` with `parents: false` \
         (CLI `agentlink mkdir` without `-p`) calls mkdir(2)/`create_dir`, which creates only the \
         final component, so every intermediate directory of `{path}` must already exist. \
         {named}The node returns ENOENT because an intermediate component is absent — usually \
         the parent directory; without a sandbox `--root` the message is the pathless `io: No \
         such file or directory (os error 2)`, while with `--root` the pre-check returns `not \
         found: parent directory does not exist: …`. Nothing was created and the existing tree \
         was not modified. This is not `already exists as a directory` (EEXIST from `parents: \
         false` on an existing directory), not `exists but is not a directory` (a file or \
         dangling-symlink leaf; `-p` cannot fix it), not `Not a directory (os error 20)` (a \
         component is a file), not `Permission denied (os error 13)`, and not a sandbox-escape, \
         grant, or node-offline failure. Fix it by creating the parents: rerun the same call with \
         `parents: true` (the MCP default) / `-p`, which creates all missing intermediates and \
         then the leaf, or create them first with `agentlink mkdir <node> <path> -p` / MCP \
         `mkdir` with `parents: true`. Confirm what exists with `agentlink ls <node> <parent>` / \
         MCP `list_dir` or `stat_path`, or locate the name with `agentlink find <node> <name>`. \
         If the blocker is a dangling symlink rather than an absent directory, `parents: true` \
         still fails: `stat_path` reports `is_symlink: true` with `is_dir: false`, and `readlink \
         <path>` via MCP `run_command` / `agentlink exec` shows the target — repoint or remove \
         the link, then retry. The path is resolved on the node, not locally: a relative path is \
         joined to the node cwd (or the `--root` jail) and `~` is not expanded. Retrying this \
         call unchanged fails identically. See `agentlink guide <node>`."
    )
}

const MKDIR_DEST_PERMISSION_TIP_MARKER: &str =
    "`mkdir` was denied permission to create the directory on the node";

/// Exact, pathless `io:` forms the node returns when the filesystem refuses to
/// create the directory. These strings are shared by every node op, so this
/// predicate may only run at the CLI `mkdir` branch and the MCP `mkdir` arm,
/// which know the operation, the path, and the `parents` flag. Match the whole
/// trimmed message: Linux errno 5 is EIO (`Input/output error (os error 5)`)
/// and errno 32 is EPIPE (`Broken pipe (os error 32)`), so the Windows form
/// must match its full sentence, never the bare errno. A Windows sharing
/// violation is deliberately left raw.
const MKDIR_DEST_PERMISSION_FORMS: &[&str] = &[
    "io: Permission denied (os error 13)",
    "io: Operation not permitted (os error 1)",
    "io: Access is denied. (os error 5)",
    "io: Read-only file system (os error 30)",
];

fn is_mkdir_dest_permission_error(message: &str) -> bool {
    MKDIR_DEST_PERMISSION_FORMS.contains(&message.trim_end())
}

/// Append an actionable tip when `mkdir` / MCP `mkdir` is refused by the
/// node's filesystem with a pathless permission, immutable, or read-only
/// error. Creating a directory needs write + execute on its parent, so name
/// the node, the caller's path, and the `parents` flag, explain the Unix,
/// sticky, immutable, Windows, and read-only rules, and point at the
/// inspection/repair commands. Idempotent; unrelated errors are left alone.
fn decorate_mkdir_dest_permission(message: &str, node: &str, path: &str, parents: bool) -> String {
    if message.contains(MKDIR_DEST_PERMISSION_TIP_MARKER)
        || !is_mkdir_dest_permission_error(message)
    {
        return message.to_string();
    }
    let outcome = if parents {
        format!(
            "With `parents: true` (the MCP default / CLI `-p`) the node calls `create_dir_all`, \
             which creates components as it walks, so a refusal part-way through can leave newly \
             created empty parent directories behind: re-list `{path}` and its parent before \
             retrying. No file was created at the leaf."
        )
    } else {
        format!(
            "With `parents: false` (CLI `agentlink mkdir` without `-p`) the node made a single \
             mkdir(2) / `create_dir` call for the leaf only, so that call failed and nothing was \
             created."
        )
    };
    format!(
        "{message}. tip: {MKDIR_DEST_PERMISSION_TIP_MARKER} — `mkdir` (CLI `agentlink mkdir`) / \
         MCP `mkdir` creates exactly `{path}` on `{node}`, and the node's filesystem refused it. \
         The raw line is pathless; the path above is the caller's path. {outcome} Unix rule: \
         creating a directory needs write and execute permission on the parent directory, not on \
         the new leaf (which does not exist yet); execute/search is also needed on every \
         ancestor, so a grandparent missing `+x` gives the same refusal and also makes `stat` on \
         the parent fail. Sticky directories: `/tmp` (mode `1777`) does not refuse a new name — \
         the sticky rule only prevents deleting or renaming another user's existing entry, so it \
         is not a cause here. Immutable or append-only: Linux `chattr +i`/`+a` (macOS `chflags \
         uchg`/`schg`) on the parent gives `Operation not permitted`, and only root can clear the \
         flag. Read-only filesystem: the mount itself is read-only; no mode change helps — \
         remount read-write or create the directory on a writable filesystem. Windows: `Access \
         is denied.` usually means an ACL denies creating a child in the parent; inspect with \
         `icacls <parent>` and grant the node user write (`icacls <parent> /grant <user>:(W)`). A \
         parent that is a regular file gives `Not a directory`, which is a separate case. \
         Retrying unchanged fails identically. Inspect MCP `stat_path` on `{path}` and its parent \
         — the parent's `mode` decides, and a stat failure on the parent points at an ancestor \
         lacking execute/search — plus `list_dir` on the parent for owner and mode. `run_command` \
         `ls -ld <parent>` / `stat -c '%A %U:%G %n' <parent>` confirms, and `findmnt`/`df` spots \
         a read-only mount; on Windows `icacls <parent>`. Repair: make the blocking parent \
         writable (`chmod u+w <parent>`, or `g+w`/`o+w`) or `chown` it to the node user; choose a \
         writable location such as the node cwd, home, or `/tmp`; remount read-write; clear \
         immutable or append-only as root. `mkdir` has no mode flag, so set the new directory's \
         mode afterward with `run_command chmod …` if needed. If the parent must stay unwritable \
         for the node user, that user cannot create the directory — ask the operator; `sudo` \
         only works through `run_command` when the node user has passwordless sudo. This is not \
         an existing-directory case (non-recursive call on a directory, separate tip), not a \
         leaf that is a file (separate case), not a missing intermediate with `parents: false` \
         (separate tip), not the `--root` jail refusal (it has no `io:` prefix), not a \
         signed-grant refusal, not node-offline, not an approval hold, and not a full or \
         over-quota filesystem, an over-long name, or a sharing violation (those stay raw). Note \
         `{path}` is the caller's path; a relative path is joined to the node cwd (or the `--root` \
         jail), `~` is not expanded, and the node-resolved absolute path may differ. See \
         `agentlink guide <node>`."
    )
}

/// Extra guidance for mkdir failures when `-p` was not requested.
fn mkdir_error_hint(msg: &str, node: &str, path: &str, parents: bool) -> Option<String> {
    // Node-side diagnose_mkdir_io already names the blocker; do not double-tip.
    if msg.contains("exists but is not a directory") {
        return None;
    }
    if !parents && is_mkdir_already_exists_error(msg) {
        return Some(decorate_mkdir_already_exists(msg, path));
    }
    if looks_like_enoent_message(msg) {
        if parents {
            return None;
        }
        return Some(format!(
            "{msg}. Pass `-p`/`--parents` to create intermediate directories (e.g. `agentlink mkdir {node} {path} -p`)."
        ));
    }
    if looks_like_enotdir_message(msg) {
        return Some(format!(
            "{msg}. A path component of `{path}` exists but is not a directory; `-p`/`--parents` cannot fix that — pick a different path or remove the blocking file."
        ));
    }
    None
}

#[cfg(test)]
mod mkdir_already_exists_tip_tests {
    use super::*;

    #[test]
    fn already_exists_gets_the_tip_once() {
        let raw = "mkdir `/srv/app/releases` already exists as a directory";
        let out = decorate_mkdir_already_exists(raw, "/srv/app/releases");
        assert!(
            out.starts_with(&format!("{raw}. tip: {MKDIR_ALREADY_EXISTS_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(MKDIR_ALREADY_EXISTS_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`/srv/app/releases`",
            "`-p`/`--parents`",
            "`parents: true`",
            "`agentlink ls <node> ",
            "`list_dir`",
            "`stat_path`",
            "`recursive: true`",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle} missing from {out}");
        }
        assert_eq!(
            decorate_mkdir_already_exists(&out, "/srv/app/releases"),
            out,
            "second pass must be byte-identical"
        );
    }

    #[test]
    fn mkdir_error_hint_adds_the_tip_only_without_parents() {
        let msg = "mkdir `/srv/app/releases` already exists as a directory";
        let hint = mkdir_error_hint(msg, "tun1000-box", "/srv/app/releases", false).unwrap();
        assert_eq!(hint.matches(MKDIR_ALREADY_EXISTS_TIP_MARKER).count(), 1, "{hint}");
        // `-p` cannot produce this literal; stay defensive.
        assert!(mkdir_error_hint(msg, "tun1000-box", "/srv/app/releases", true).is_none());
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "mkdir `/srv/app` exists but is not a directory",
            "mkdir `/srv/app` exists but is not a directory; `-p`/`--parents` cannot replace a \
             file with a directory",
            "path component `/etc/hostname` exists but is not a directory; `-p`/`--parents` \
             cannot fix that — pick a different path or remove the blocking file",
            "io: File exists (os error 17)",
        ] {
            assert_eq!(decorate_mkdir_already_exists(raw, "/srv/app"), raw, "{raw}");
        }
        assert_eq!(
            decorate_write_target_is_directory("mkdir `/srv/app` already exists as a directory"),
            "mkdir `/srv/app` already exists as a directory"
        );
    }
}

#[cfg(test)]
mod mkdir_target_not_dir_tip_tests {
    use super::*;

    #[test]
    fn bare_target_file_gets_the_tip_once() {
        let raw = "mkdir `/srv/app/releases` exists but is not a directory";
        let out = decorate_mkdir_target_not_dir(raw);
        assert!(
            out.starts_with(&format!("{raw}. tip: {MKDIR_TARGET_NOT_DIR_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(MKDIR_TARGET_NOT_DIR_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`/srv/app/releases`",
            "nothing was created",
            "not modified",
            "`-p`/`--parents` cannot fix it",
            "`already exists as a directory`",
            "`agentlink ls <node> <parent>`",
            "`list_dir`",
            "`stat_path`",
            "`agentlink rm <node> /srv/app/releases`",
            "`remove_path`",
            "`agentlink mv <node> ",
            "`move_path`",
            "`agentlink guide <node>`",
        ] {
            assert!(out.contains(needle), "{needle} missing from {out}");
        }
        assert_eq!(
            decorate_mkdir_target_not_dir(&out),
            out,
            "second pass must be byte-identical"
        );
    }

    #[test]
    fn recursive_and_prefixed_forms_get_the_tip_once() {
        for raw in [
            "mkdir `/srv/app/releases` exists but is not a directory; `-p`/`--parents` cannot \
             replace a file with a directory",
            "mkdir task: mkdir `/srv/app/releases` exists but is not a directory",
            "mkdir `C:\\Users\\me\\out` exists but is not a directory",
            "mkdir `/srv/app/releases` exists but is not a directory Did you mean `mkdir \
             /srv/app/release`?",
        ] {
            let out = decorate_mkdir_target_not_dir(raw);
            assert!(out.starts_with(raw), "{out}");
            assert_eq!(out.matches(MKDIR_TARGET_NOT_DIR_TIP_MARKER).count(), 1, "{out}");
            assert_eq!(decorate_mkdir_target_not_dir(&out), out, "{raw}");
        }
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "mkdir `/srv/app/releases` already exists as a directory",
            "path component `/srv/app/x` exists but is not a directory",
            "path component `/srv/app/x` exists but is not a directory; `-p`/`--parents` cannot \
             fix that — pick a different path or remove the blocking file",
            "cannot create directory `/srv/app/x`: path exists but is not a directory (refusing \
             to copy a directory onto a file)",
            "mv destination `/srv/app/x` exists but is not a directory; cannot move directory \
             `/srv/app/y` onto a file",
            "mv destination parent `/srv/app` exists but is not a directory",
            "destination `/srv/app/x` ends with a slash but is not a directory",
            "io: File exists (os error 17)",
            "io: Not a directory (os error 20)",
        ] {
            assert_eq!(decorate_mkdir_target_not_dir(raw), raw, "{raw}");
        }
    }
}

const PATH_COMPONENT_NOT_DIR_TIP_MARKER: &str = "a path component is a file (or other non-dir)";

/// Backticked path from the two node diagnostics this decorator owns:
/// `path component \`…\` exists but is not a directory` (write/cp parent
/// creation, with the optional `; cannot create parent directories for
/// write/cp` suffix) and `mv destination parent \`…\` exists but is not a
/// directory`.
///
/// `mkdir`'s leaf form (`mkdir \`…\` exists but is not a directory`) belongs to
/// [`decorate_mkdir_target_not_dir`], its self-explaining intermediate form
/// (`path component …; \`-p\`/`--parents` cannot fix that`) and `mv
/// destination … cannot move directory … onto a file` already name their
/// remedy, and the `… does not exist` mv parent form is a different failure.
/// Prefixes such as `write /path: ` are tolerated by searching for the phrase.
fn path_component_not_dir_blocker(message: &str) -> Option<&str> {
    const COMPONENT: &str = "path component `";
    const NOT_DIR: &str = " exists but is not a directory";
    const WRITE_CP_TAIL: &str = "; cannot create parent directories for write/cp";
    if let Some(rest) = message
        .find(COMPONENT)
        .map(|at| &message[at + COMPONENT.len()..])
    {
        let (path, after) = rest.split_once('`')?;
        let after = after.strip_prefix(NOT_DIR)?.trim();
        return (!path.is_empty() && (after.is_empty() || after.starts_with(WRITE_CP_TAIL)))
            .then_some(path);
    }
    const MV_PARENT: &str = "mv destination parent `";
    let rest = message
        .find(MV_PARENT)
        .map(|at| &message[at + MV_PARENT.len()..])?;
    let (path, after) = rest.split_once('`')?;
    (after.trim() == "exists but is not a directory" && !path.is_empty()).then_some(path)
}

/// Append an actionable tip when write/cp or mv fails because a component of
/// the requested path exists as a non-directory. The marker deliberately
/// matches the CLI `write`/`cp` hint from `hint_fs_error`, so a path that
/// already carries that tip is left byte-identical. Idempotent; mkdir's leaf
/// and intermediate forms, patch-root, bare ENOENT, and offline errors are
/// left alone.
fn decorate_path_component_not_dir(message: &str) -> String {
    if message.contains(PATH_COMPONENT_NOT_DIR_TIP_MARKER) {
        return message.to_string();
    }
    let Some(blocker) = path_component_not_dir_blocker(message) else {
        return message.to_string();
    };
    format!(
        "{message}. tip: {PATH_COMPONENT_NOT_DIR_TIP_MARKER} — one component of the requested \
         path, `{blocker}`, is a regular file (or a symlink to one, a dangling symlink, or another \
         special file), so it cannot contain the child you named; the node stops at the first such \
         component and reports it as the backticked path. `write`/`write_file` and `cp`/\
         `copy_path` create missing parent directories but cannot replace an existing file with a \
         directory, and `mv`/`move_path` never creates parents. `-p`/`--parents` and mkdir cannot \
         fix this, and retrying the same call unchanged fails identically; nothing was written and \
         nothing was moved. This is not a missing parent (`No such file or directory`), not the \
         mkdir leaf collision (`mkdir … exists but is not a directory`, where the destination \
         itself is the blocker), and not a permission, sandbox, grant, or node-offline failure. \
         Inspect it and its parent with `agentlink ls <node> <parent>` / MCP `list_dir` and MCP \
         `stat_path` (`is_dir: false`), then remove it with `agentlink rm <node> {blocker}` / MCP \
         `remove_path` (a file needs no `-r`; a symlink is unlinked and its target untouched), \
         rename it aside with `agentlink mv <node> {blocker} {blocker}.bak` / MCP `move_path`, or \
         pick a different destination path altogether. If you need this exact path, remove/rename \
         the blocker and, when using mv (which does not create parents), create the parent first \
         with `agentlink mkdir <node> <parent> -p` / MCP `mkdir`, then retry. The path above is \
         what the node resolved (`~` and the sandbox root applied). See `agentlink guide <node>`."
    )
}

#[cfg(test)]
mod path_component_not_dir_tip_tests {
    use super::*;

    #[test]
    fn write_and_cp_component_gets_the_tip_once() {
        for raw in [
            "path component `/tmp/file` exists but is not a directory",
            "path component `/tmp/file` exists but is not a directory; cannot create parent \
             directories for write/cp",
            "write /tmp/file/nested: path component `/tmp/file` exists but is not a directory; \
             cannot create parent directories for write/cp",
        ] {
            let out = decorate_path_component_not_dir(raw);
            assert!(
                out.starts_with(&format!(
                    "{raw}. tip: {PATH_COMPONENT_NOT_DIR_TIP_MARKER} — "
                )),
                "{out}"
            );
            assert_eq!(
                out.matches(PATH_COMPONENT_NOT_DIR_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "`/tmp/file`",
                "`write_file`",
                "`copy_path`",
                "`-p`/`--parents`",
                "`No such file or directory`",
                "`mkdir … exists but is not a directory`",
                "`stat_path`",
                "`remove_path`",
                "`move_path`",
                "`agentlink mkdir <node> <parent> -p`",
                "`agentlink guide <node>`",
            ] {
                assert!(out.contains(needle), "{needle} missing from {out}");
            }
            assert_eq!(
                decorate_path_component_not_dir(&out),
                out,
                "second pass must be byte-identical"
            );
        }
    }

    #[test]
    fn mv_destination_parent_gets_the_tip_once() {
        let raw = "mv destination parent `/srv/app` exists but is not a directory";
        let out = decorate_path_component_not_dir(raw);
        assert!(
            out.starts_with(&format!(
                "{raw}. tip: {PATH_COMPONENT_NOT_DIR_TIP_MARKER} — "
            )),
            "{out}"
        );
        assert_eq!(
            out.matches(PATH_COMPONENT_NOT_DIR_TIP_MARKER).count(),
            1,
            "{out}"
        );
        assert!(out.contains("`/srv/app`"), "{out}");
        assert!(out.contains("`move_path`"), "{out}");
        assert_eq!(decorate_path_component_not_dir(&out), out);
    }

    #[test]
    fn existing_hint_fs_error_write_tip_is_left_alone() {
        let raw = "path component `/tmp/file` exists but is not a directory; cannot create parent \
                   directories for write/cp";
        let hinted = hint_fs_error(raw, FsHint::Write).to_string();
        assert!(
            hinted.contains(PATH_COMPONENT_NOT_DIR_TIP_MARKER),
            "{hinted}"
        );
        assert_eq!(decorate_path_component_not_dir(&hinted), hinted);
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "ls: path `/srv/app/src` does not exist",
            "mkdir `/srv/app` exists but is not a directory",
            "mkdir `/srv/app` exists but is not a directory; `-p`/`--parents` cannot replace a \
             file with a directory",
            "path component `/etc/hostname` exists but is not a directory; `-p`/`--parents` \
             cannot fix that — pick a different path or remove the blocking file",
            "/srv/app/src.rs is not a directory",
            "mv destination `/srv/app/x` exists but is not a directory; cannot move directory \
             `/srv/app/y` onto a file",
            "mv destination parent `/srv/app` does not exist; create it with mkdir -p first \
             (unlike write/cp, mv does not create parents)",
            "io: No such file or directory (os error 2)",
            "io: Not a directory (os error 20)",
            "node 'builder' is offline",
        ] {
            assert_eq!(decorate_path_component_not_dir(raw), raw, "{raw}");
        }
    }
}

#[cfg(test)]
mod mkdir_missing_parent_tip_tests {
    use super::*;

    #[test]
    fn bare_io_enoent_gets_the_tip_once() {
        let raw = "io: No such file or directory (os error 2)";
        let out = decorate_mkdir_missing_parent(raw, "/srv/app/releases", false);
        assert!(
            out.starts_with(&format!("{raw}. tip: {MKDIR_MISSING_PARENT_TIP_MARKER} — ")),
            "{out}"
        );
        assert_eq!(out.matches(MKDIR_MISSING_PARENT_TIP_MARKER).count(), 1, "{out}");
        for needle in [
            "`/srv/app/releases`",
            "`parents: false`",
            "`parents: true`",
            "`create_dir`",
            "stat_path",
            "list_dir",
            "agentlink find",
            "`--root`",
            "`~` is not expanded",
            "agentlink guide <node>",
        ] {
            assert!(out.contains(needle), "{needle} missing from {out}");
        }
        assert!(
            out.to_lowercase().contains("nothing was created"),
            "{out}"
        );
        assert_eq!(
            decorate_mkdir_missing_parent(&out, "/srv/app/releases", false),
            out,
            "second pass must be byte-identical"
        );
    }

    #[test]
    fn sandbox_parent_not_found_gets_the_tip_and_names_the_parent() {
        let raw = "not found: parent directory does not exist: /srv/app";
        let out = decorate_mkdir_missing_parent(raw, "/srv/app/releases", false);
        assert!(out.starts_with(raw), "{out}");
        assert_eq!(out.matches(MKDIR_MISSING_PARENT_TIP_MARKER).count(), 1, "{out}");
        assert!(out.contains("`/srv/app`"), "{out}");
        assert!(out.contains("`/srv/app/releases`"), "{out}");
        assert_eq!(
            decorate_mkdir_missing_parent(&out, "/srv/app/releases", false),
            out,
            "second pass must be byte-identical"
        );

        for raw in [
            "io: The system cannot find the file specified. (os error 2)",
            "io: The system cannot find the path specified. (os error 3)",
        ] {
            let out = decorate_mkdir_missing_parent(raw, "/srv/app/releases", false);
            assert_eq!(out.matches(MKDIR_MISSING_PARENT_TIP_MARKER).count(), 1, "{out}");
        }
    }

    #[test]
    fn parents_true_and_siblings_are_unchanged() {
        for raw in [
            "io: No such file or directory (os error 2)",
            "not found: parent directory does not exist: /srv/app",
        ] {
            assert_eq!(decorate_mkdir_missing_parent(raw, "/srv/app/releases", true), raw);
        }

        for raw in [
            "mkdir `/srv/app` already exists as a directory",
            "mkdir `/srv/app` exists but is not a directory",
            "path component `/etc/hostname` exists but is not a directory; `-p`/`--parents` \
             cannot fix that — pick a different path or remove the blocking file",
            "io: Not a directory (os error 20)",
            "io: Permission denied (os error 13)",
            "io: File exists (os error 17)",
            "sandbox root: No such file or directory (os error 2)",
            "not found: no existing ancestor for /srv/app/x",
            "io: No such file or directory (os error 2) Did you mean `mkdir /srv/app/release`?",
        ] {
            assert_eq!(
                decorate_mkdir_missing_parent(raw, "/srv/app/releases", false),
                raw,
                "{raw}"
            );
        }
    }
}

#[cfg(test)]
mod mkdir_dest_permission_tip_tests {
    use super::*;

    const NODE: &str = "builder";
    const PATH: &str = "/srv/app/releases/v2";

    #[test]
    fn unix_forms_get_the_tip_once() {
        for raw in [
            "io: Permission denied (os error 13)",
            "io: Operation not permitted (os error 1)",
        ] {
            let out = decorate_mkdir_dest_permission(raw, NODE, PATH, false);
            assert!(
                out.starts_with(&format!("{raw}. tip: {MKDIR_DEST_PERMISSION_TIP_MARKER} — ")),
                "{out}"
            );
            assert_eq!(
                out.matches(MKDIR_DEST_PERMISSION_TIP_MARKER).count(),
                1,
                "{out}"
            );
            for needle in [
                "builder",
                "/srv/app/releases/v2",
                "parent",
                "chmod",
                "execute",
                "chattr",
                "Read-only",
                "nothing was created",
                "agentlink guide <node>",
            ] {
                assert!(out.contains(needle), "{needle} missing from {out}");
            }
            for literal in ["{path}", "{node}", "{parents}"] {
                assert!(!out.contains(literal), "{literal} leaked into {out}");
            }
            for needle in [
                "already exists as a directory",
                "exists but is not a directory",
                "mkdir `",
                "path component ",
                "parent directory does not exist: ",
                "mkdir -p",
                "is a path on the node",
                "ls: path ",
                "old string",
                "matches of the old string",
                "pass --all (CLI) or replace_all (MCP/API)",
                "replacement text exceeds 1 MiB",
                " is larger than 8388608 bytes",
                "path escapes sandbox: ",
                "outside the node's filesystem root",
                " is not allowed on this node",
                "capability denied",
                "signed grant required",
                "grant has expired",
                "grant was revoked",
                "grant list",
                "node offline: ",
                "approval denied or timed out",
                "chmod +x",
                "list it with",
                "Directory not empty",
                "directory is not empty",
                "ENOTEMPTY",
                "os error 39",
                "os error 66",
                "os error 145",
                "cross-device link",
                "cross device link",
                "different disk drive",
                "the node's command policy denied this",
                "command denied by sandbox pattern '",
                "command is not on the sandbox allow list",
                "rejected env var '",
                "the target directory does not exist on the node",
                "spawn:",
                "Exec format error",
                " is not a regular file (refusing fifo/socket/device)",
                " is a directory, not a file; use `ls` to list it",
                " is a symlink to a directory, not a file; use directory copy",
                "inotify",
                "watch slots",
                "background process",
                "no node named",
                "more than one paired machine",
                "wake the machine or check the agentlink-node service",
                "transient relay TLS flap",
            ] {
                assert!(!out.contains(needle), "{needle} leaked into {out}");
            }
            assert!(!out.ends_with(" is a directory"), "{out}");
            assert_eq!(
                decorate_mkdir_dest_permission(&out, NODE, PATH, false),
                out,
                "second pass must be byte-identical"
            );
        }
    }

    #[test]
    fn windows_and_readonly_forms_get_the_tip() {
        for raw in [
            "io: Access is denied. (os error 5)",
            "io: Read-only file system (os error 30)",
        ] {
            let out = decorate_mkdir_dest_permission(raw, NODE, PATH, true);
            assert!(out.starts_with(raw), "{out}");
            assert_eq!(
                out.matches(MKDIR_DEST_PERMISSION_TIP_MARKER).count(),
                1,
                "{out}"
            );
            assert_eq!(
                decorate_mkdir_dest_permission(&out, NODE, PATH, true),
                out,
                "{raw}"
            );
        }
        let windows = decorate_mkdir_dest_permission(
            "io: Access is denied. (os error 5)",
            NODE,
            PATH,
            false,
        );
        assert!(windows.contains("icacls"), "{windows}");
    }

    #[test]
    fn parents_conditional_outcome() {
        let recursive =
            decorate_mkdir_dest_permission("io: Permission denied (os error 13)", NODE, PATH, true);
        assert!(recursive.contains("create_dir_all"), "{recursive}");
        assert!(recursive.contains("re-list"), "{recursive}");
        assert!(
            recursive.contains("newly created empty parent directories"),
            "{recursive}"
        );

        let flat =
            decorate_mkdir_dest_permission("io: Permission denied (os error 13)", NODE, PATH, false);
        assert!(flat.contains("single mkdir(2)"), "{flat}");
        assert!(flat.contains("nothing was created"), "{flat}");
        assert!(!flat.contains("create_dir_all"), "{flat}");

        for out in [&recursive, &flat] {
            assert!(
                out.contains("write and execute permission on the parent directory"),
                "{out}"
            );
            assert!(out.contains("not on the new leaf"), "{out}");
        }
    }

    #[test]
    fn siblings_are_unchanged() {
        for raw in [
            "io: Input/output error (os error 5)",
            "io: Broken pipe (os error 32)",
            "io: The process cannot access the file because it is being used by another process. (os error 32)",
            "io: File exists (os error 17)",
            "io: No such file or directory (os error 2)",
            "io: Not a directory (os error 20)",
            "io: File name too long (os error 36)",
            "io: No space left on device (os error 28)",
            "io: Disk quota exceeded (os error 122)",
            "mkdir `/srv/app` already exists as a directory",
            "mkdir `/srv/app` exists but is not a directory",
            "path component `/srv/app/file` exists but is not a directory",
            "parent directory does not exist: /srv/app",
            "io: Permission denied (os error 13) at /srv/app",
            "permission denied: path escapes sandbox: /tmp/x",
            "capability denied: write",
            "exec x is not allowed on this node",
            "",
        ] {
            assert_eq!(
                decorate_mkdir_dest_permission(raw, NODE, PATH, false),
                raw,
                "{raw}"
            );
        }
    }

    #[test]
    fn exact_match_only() {
        for raw in [
            "/srv/app/releases: Permission denied (os error 13)",
            "prefix io: Permission denied (os error 13)",
        ] {
            assert_eq!(
                decorate_mkdir_dest_permission(raw, NODE, PATH, false),
                raw,
                "{raw}"
            );
        }
        let tipped = decorate_mkdir_dest_permission(
            "io: Permission denied (os error 13)",
            NODE,
            PATH,
            false,
        );
        assert_eq!(
            decorate_mkdir_dest_permission(&tipped, NODE, PATH, false),
            tipped
        );
    }

    #[test]
    fn does_not_retrigger_mkdir_siblings() {
        let out = decorate_mkdir_dest_permission(
            "io: Permission denied (os error 13)",
            NODE,
            PATH,
            true,
        );
        assert_eq!(decorate_mkdir_already_exists(&out, PATH), out);
        assert_eq!(decorate_mkdir_target_not_dir(&out), out);
        assert_eq!(decorate_mkdir_missing_parent(&out, PATH, false), out);
        assert_eq!(decorate_mkdir_missing_parent(&out, PATH, true), out);
        assert_eq!(decorate_exec_cwd_missing(&out), out);
        assert_eq!(decorate_sandbox_path_escape(&out), out);
        assert_eq!(decorate_grant_capability(&out), out);
        assert_eq!(decorate_missing_parent(&out), out);
    }
}

/// `exec`/`bg start` use `trailing_var_arg` + `allow_hyphen_values`, so an unknown
/// flag after `<NODE>` becomes `cmd[0]` and the node reports a cryptic spawn ENOENT.
/// Refuse those before dialing; tip the common `--timeout-ms` mix-up.
/// `--command` with only whitespace used to open a brief PTY and exit 0.
/// Match `exec`/`bg start`: refuse blank commands before dialing.
fn reject_empty_shell_command(command: Option<&str>) -> Result<()> {
    match command {
        Some(cmd) if cmd.trim().is_empty() => {
            Err(anyhow!("shell: --command is empty"))
        }
        _ => Ok(()),
    }
}

fn reject_flag_like_program(kind: &str, cmd: &[String]) -> Result<()> {
    let Some(program) = cmd.first() else {
        return Err(anyhow!("{kind}: command is empty"));
    };
    // Whitespace-only argv0 used to dial the node and fail as spawn ENOENT.
    if program.trim().is_empty() {
        return Err(anyhow!("{kind}: command is empty"));
    }
    if !program.starts_with('-') || program == "-" {
        return Ok(());
    }
    let tip = if program == "--timeout-ms" || program.starts_with("--timeout-ms=") {
        " Did you mean `--timeout-secs`? Put known flags before the program (e.g. `agentlink exec <NODE> --timeout-secs 5 -- /bin/echo hi`)."
    } else {
        " Put known flags (e.g. `--timeout-secs`, `--cwd`, `--env`) before the program; unknown `--flags` after `<NODE>` are treated as the executable."
    };
    Err(anyhow!(
        "{kind}: `{program}` looks like a CLI flag, not a program.{tip}"
    ))
}

/// Short hex / numeric tokens used as background process ids (`d5c86dab`, `42`).
fn looks_like_bg_process_id(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Node names tend to include a letter outside `a-f`, or a hyphen (`example`, `tun1000-box`).
fn looks_like_node_name(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && (s.contains('-')
            || s.chars()
                .any(|c| c.is_ascii_alphabetic() && !c.is_ascii_hexdigit()))
}

/// Index of the top-level subcommand (`bg`, `ls`, …), skipping global flags.
fn find_top_level_command(args: &[std::ffi::OsString]) -> Option<usize> {
    let mut i = 1; // argv0
    while i < args.len() {
        let s = args[i].to_str().unwrap_or("");
        if s == "--" {
            return None;
        }
        if let Some(rest) = s.strip_prefix("--") {
            let (name, has_eq) = match rest.split_once('=') {
                Some((name, _)) => (name, true),
                None => (rest, false),
            };
            let takes_value = matches!(
                name,
                "relay" | "token" | "fingerprint" | "trust" | "ca" | "config-dir" | "identity"
            );
            i += if takes_value && !has_eq { 2 } else { 1 };
            continue;
        }
        if s.starts_with('-') {
            i += 1;
            continue;
        }
        return Some(i);
    }
    None
}

fn tray_log_dir(cli: &Cli) -> Option<PathBuf> {
    let Command::Tray { data_dir, .. } = &cli.command else {
        return None;
    };
    tray::resolve_data_dir(data_dir.as_deref()).ok()
}

#[cfg(windows)]
fn prepare_stdio() {
    use windows::Win32::System::Console::{
        AttachConsole, GetStdHandle, ATTACH_PARENT_PROCESS, STD_OUTPUT_HANDLE,
    };
    let args: Vec<String> = std::env::args().skip(1).take(6).collect();
    let tray_ui = args.first().map(String::as_str) == Some("tray")
        && !args.iter().any(|arg| {
            matches!(
                arg.as_str(),
                "status" | "install" | "uninstall" | "--help" | "-h" | "help"
            )
        });
    let controller_window = args.first().map(String::as_str) == Some("controller")
        && !args.iter().any(|arg| matches!(arg.as_str(), "--check" | "--help" | "-h" | "help"));
    if tray_ui || controller_window {
        return;
    }
    unsafe {
        let stdout = GetStdHandle(STD_OUTPUT_HANDLE).unwrap_or_default();
        let missing = stdout.is_invalid() || stdout.0.is_null();
        if missing {
            let _ = AttachConsole(ATTACH_PARENT_PROCESS);
        }
    }
}

fn parse_cli_from(
    argv: impl IntoIterator<Item = impl Into<std::ffi::OsString> + Clone>,
) -> (Cli, clap::ArgMatches) {
    let matches = match Cli::command().try_get_matches_from(argv) {
        Ok(matches) => matches,
        Err(err) => err.exit(),
    };
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(err) => err.exit(),
    };
    (cli, matches)
}

fn is_user_supplied(matches: &clap::ArgMatches, id: &str) -> bool {
    matches!(
        matches.value_source(id),
        Some(ValueSource::CommandLine | ValueSource::EnvVariable)
    )
}

/// Reject explicit live flags combined with `--preview-ui`.
///
/// Uses clap `ValueSource` so defaulted values (for example `--max-fps`
/// / `--connect-timeout-secs`) are not treated as user-supplied.
fn preview_incompatible_flags(matches: &clap::ArgMatches) -> Option<String> {
    let Some(("controller", sub)) = matches.subcommand() else {
        return None;
    };
    if sub.value_source("preview_ui") != Some(ValueSource::CommandLine) {
        return None;
    }
    let mut flags = Vec::new();
    if is_user_supplied(sub, "data_dir") {
        flags.push("--data-dir");
    }
    if is_user_supplied(matches, "config_dir") {
        flags.push("--config-dir");
    }
    if is_user_supplied(sub, "debug_socket") {
        flags.push("--debug-socket");
    }
    if is_user_supplied(sub, "headless") {
        flags.push("--headless");
    }
    if is_user_supplied(sub, "open_desktop") {
        flags.push("--open-desktop");
    }
    if is_user_supplied(sub, "background") {
        flags.push("--background");
    }
    if flags.is_empty() {
        return None;
    }
    Some(format!(
        "--preview-ui cannot be combined with {}. Isolated preview uses its own temporary directories and does not start a live session.",
        flags.join(", ")
    ))
}

fn config_dir(cli: &Cli) -> Result<PathBuf> {
    if let Some(dir) = &cli.config_dir {
        return Ok(dir.clone());
    }
    agentlink_core::config::default_config_dir().map_err(|err| anyhow!(err))
}

fn operator_identity_path(cli: &Cli) -> Result<PathBuf> {
    if let Some(path) = &cli.identity {
        return Ok(path.clone());
    }
    Ok(config_dir(cli)?.join("identity.json"))
}

async fn connect_client(cli: &Cli, _label: &str) -> Result<Client> {
    let mut settings = settings(cli)?;
    let identity = Identity::load_or_create(&operator_identity_path(cli)?)
        .map_err(|err| anyhow!(err.to_string()))?;
    if cli.token.is_none() {
        if let Some(fresh) = agentlink_core::client::maintain_session(&config_dir(cli)?, &identity)
            .await
            .map_err(|err| anyhow!(err.to_string()))?
        {
            settings.token = fresh.token;
        }
    }
    let use_token = !settings.token.is_empty();
    let client = Client::connect_identity(&settings, identity.clone(), use_token)
        .await
        .map_err(|err| {
            let message = agentlink_core::error::transient_tls_tip(&err)
                .unwrap_or_else(|| err.to_string());
            anyhow!(message)
        })?;
    if let Ok(dir) = config_dir(cli) {
        client.remember_node_pins(dir.clone());
        client.remember_grants(dir);
    }
    warn_ca_only(&settings);
    Ok(client)
}

fn is_public_key_hex(text: &str) -> bool {
    let text = text.trim();
    text.len() == 64 && text.chars().all(|ch| ch.is_ascii_hexdigit())
}

/// One stored grant selected for local clear/revoke.
struct LocalGrantMatch {
    node_id: String,
    path: PathBuf,
}

/// Whether a successful revoke should delete the local grant file.
///
/// An explicit `--jti` may target a different grant than the stored one (for
/// example an old or test jti), so only remove the file when the jtis match.
/// Without `--jti` the stored grant is the revoke target, and with no stored
/// grant there is nothing to keep.
fn should_remove_local_grant(explicit_jti: Option<&str>, stored_jti: Option<&str>) -> bool {
    match (explicit_jti, stored_jti) {
        (Some(explicit), Some(stored)) => explicit.trim().eq_ignore_ascii_case(stored.trim()),
        _ => true,
    }
}

/// Stored grants whose node id or file stem starts with `token`
/// (case-insensitive). Empty tokens match nothing.
fn matching_local_grants(config_dir: &Path, token: &str) -> Result<Vec<LocalGrantMatch>> {
    let token = token.trim().to_ascii_lowercase();
    if token.is_empty() {
        return Ok(Vec::new());
    }
    let mut matches: Vec<LocalGrantMatch> = Vec::new();
    for stored in agentlink_core::grant::list_stored_grants(config_dir)
        .map_err(|err| anyhow!(err.to_string()))?
    {
        let node_id = stored.grant.node_id.to_ascii_lowercase();
        let stem = stored
            .path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if node_id.starts_with(&token) || stem.starts_with(&token) {
            if !matches.iter().any(|found| found.path == stored.path) {
                matches.push(LocalGrantMatch {
                    node_id,
                    path: stored.path,
                });
            }
        }
    }
    Ok(matches)
}

fn ambiguous_local_grant_error(node: &str, matches: &[LocalGrantMatch]) -> anyhow::Error {
    let ids: Vec<_> = matches.iter().map(|found| found.node_id.as_str()).collect();
    anyhow!(
        "`{node}` matches {} stored grants ({}); pass a longer node id",
        matches.len(),
        ids.join(", ")
    )
}

fn missing_local_grant_error(node: &str) -> anyhow::Error {
    anyhow!(
        "no local grant matching `{node}`; run `agentlink grant list` or pass the full node id"
    )
}

/// Resolve a node for local clear/revoke without requiring the relay.
///
/// A full hex id is used directly. Otherwise a unique local id/prefix or file
/// stem wins before any relay lookup, so `grant clear --node abc9bac5` works
/// offline. Friendly names still fall back to `resolve_grant_node`.
async fn resolve_local_grant_node(
    cli: &Cli,
    config_dir: &Path,
    node: &str,
) -> Result<LocalGrantMatch> {
    let node = node.trim();
    if is_public_key_hex(node) {
        let node_id = node.to_ascii_lowercase();
        return Ok(LocalGrantMatch {
            path: agentlink_core::grant::grant_path(config_dir, &node_id),
            node_id,
        });
    }
    let mut matches = matching_local_grants(config_dir, node)?;
    if matches.len() == 1 {
        return Ok(matches.remove(0));
    }
    if matches.len() > 1 {
        return Err(ambiguous_local_grant_error(node, &matches));
    }
    match resolve_grant_node(cli, node).await {
        Ok(node_id) => Ok(LocalGrantMatch {
            path: agentlink_core::grant::grant_path(config_dir, &node_id),
            node_id,
        }),
        Err(_) => Err(missing_local_grant_error(node)),
    }
}

async fn resolve_grant_node(cli: &Cli, node: &str) -> Result<String> {
    resolve_grant_node_local_or_relay(cli, node, None).await
}

/// Resolve a node name to its public id without requiring a relay token when
/// the name is already pinned locally or matches `--issuer-data-dir`'s node.
async fn resolve_grant_node_local_or_relay(
    cli: &Cli,
    node: &str,
    issuer_data_dir: Option<&std::path::Path>,
) -> Result<String> {
    let node = node.trim();
    if is_public_key_hex(node) {
        return Ok(node.to_ascii_lowercase());
    }
    let dir = config_dir(cli)?;
    if let Some(id) = agentlink_core::node_pin::id_for_name(&dir, node)
        .map_err(|err| anyhow!(err.to_string()))?
    {
        return Ok(id);
    }
    let issuer_dir = issuer_data_dir
        .map(|path| path.to_path_buf())
        .or_else(|| resolve_issuer_data_dir(None));
    if let Some(issuer_dir) = issuer_dir {
        if let Some(id) = local_issuer_node_id(&issuer_dir, node) {
            return Ok(id);
        }
    }
    match connect_client(cli, "grant").await {
        Ok(client) => {
            let nodes = client
                .list_nodes()
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            let mut matches = nodes
                .iter()
                .filter(|info| info.name == node || info.id.eq_ignore_ascii_case(node));
            let Some(first) = matches.next() else {
                return Err(anyhow!(
                    "no node named `{node}`; run `agentlink nodes` or pass the node id"
                ));
            };
            let id = first.id.clone();
            if matches.next().is_some() {
                return Err(anyhow!(
                    "more than one node matches `{node}`; pass the node id"
                ));
            }
            Ok(id)
        }
        Err(err) => Err(anyhow!(
            "no local pin or issuer identity for node `{node}`, and the relay is unavailable ({err}).              On the node host pass --issuer-data-dir <node-data-dir>, or pass the 64-hex node id"
        )),
    }
}

/// Read the node public id from an issuer/node data dir when `name` matches
/// `node.json`. Never creates identity files.
fn local_issuer_node_id(issuer_dir: &std::path::Path, name: &str) -> Option<String> {
    let ident_path = issuer_dir.join("identity.json");
    if !ident_path.is_file() {
        return None;
    }
    let ident: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(ident_path).ok()?).ok()?;
    let id = ident.get("public_hex")?.as_str()?.trim().to_ascii_lowercase();
    if !is_public_key_hex(&id) {
        return None;
    }
    let node_cfg = issuer_dir.join("node.json");
    if !node_cfg.is_file() {
        return None;
    }
    let cfg: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(node_cfg).ok()?).ok()?;
    let stored = cfg.get("name")?.as_str()?.trim();
    (stored == name).then_some(id)
}

/// Where [`resolve_issuer_data_dir`] found the issuer data directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IssuerDirSource {
    Explicit,
    Env,
    LocalNode,
}

/// Resolve the issuer data dir for `grant issue|refresh|ensure`.
///
/// Priority: `--issuer-data-dir`, `AGENTLINK_ISSUER_DATA_DIR`, then the default
/// node data dir when it already contains `grant-issuer.json` or non-empty
/// `owner-keys.json`. Discovery never creates files; `None` keeps the operator
/// identity.
fn resolve_issuer_data_dir(explicit: Option<&Path>) -> Option<PathBuf> {
    let env = std::env::var_os("AGENTLINK_ISSUER_DATA_DIR");
    let node_dir = agentlink_core::config::default_data_dir("node").ok();
    let resolved = resolve_issuer_data_dir_with(explicit, env.as_deref(), node_dir.as_deref());
    if let Some((dir, IssuerDirSource::LocalNode)) = &resolved {
        eprintln!(
            "using issuer data-dir {} (local node dir; override with --issuer-data-dir or AGENTLINK_ISSUER_DATA_DIR)",
            dir.display()
        );
    }
    resolved.map(|(dir, _)| dir)
}

fn resolve_issuer_data_dir_with(
    explicit: Option<&Path>,
    env: Option<&std::ffi::OsStr>,
    node_dir: Option<&Path>,
) -> Option<(PathBuf, IssuerDirSource)> {
    if let Some(path) = explicit {
        return Some((path.to_path_buf(), IssuerDirSource::Explicit));
    }
    if let Some(value) = env {
        if !value.to_string_lossy().trim().is_empty() {
            return Some((PathBuf::from(value), IssuerDirSource::Env));
        }
    }
    let dir = node_dir?;
    if !dir.is_dir() {
        return None;
    }
    let has_issuer = dir
        .join(agentlink_core::grant::GRANT_ISSUER_FILE)
        .is_file();
    let has_owner_keys = agentlink_core::grant::load_owner_keys(dir)
        .map(|keys| !keys.is_empty())
        .unwrap_or(false);
    (has_issuer || has_owner_keys).then(|| (dir.to_path_buf(), IssuerDirSource::LocalNode))
}

fn auto_grant_issuer_data_dir_with(
    env: Option<&std::ffi::OsStr>,
    node_dir: Option<&Path>,
) -> Option<PathBuf> {
    resolve_issuer_data_dir_with(None, env, node_dir).map(|(dir, _)| dir)
}

fn grant_issuer(issuer_data_dir: Option<&std::path::Path>, operator: &Identity) -> Result<Identity> {
    let Some(dir) = issuer_data_dir else {
        return Ok(operator.clone());
    };
    let owner_keys = agentlink_core::grant::load_owner_keys(dir)
        .map_err(|err| anyhow!(err.to_string()))?;
    if owner_keys.is_empty() {
        return agentlink_core::grant::bootstrap_issuer_with_mode(dir)
            .map_err(|err| anyhow!(err.to_string()))?
            .ok_or_else(|| anyhow!("could not create an issuer in {}", dir.display()));
    }
    if owner_keys
        .iter()
        .any(|key| key.eq_ignore_ascii_case(operator.public_hex()))
    {
        return Ok(operator.clone());
    }
    if let Some(issuer) =
        agentlink_core::grant::load_issuer(dir).map_err(|err| anyhow!(err.to_string()))?
    {
        return Ok(issuer);
    }
    Err(anyhow!(
        "no trusted issuer in {}; run `agentlink grant trust-owner {} --data-dir {}` first",
        dir.display(),
        operator.public_hex(),
        dir.display()
    ))
}

/// Load `<dir>/grant-issuer.json` when its key is the grant's issuer.
fn issuer_matching_grant(
    dir: &std::path::Path,
    grant: &agentlink_core::grant::SignedGrant,
) -> Option<Identity> {
    let issuer_id = grant.issuer_id.trim();
    if issuer_id.is_empty() {
        return None;
    }
    let issuer = agentlink_core::grant::load_issuer(dir).ok()??;
    issuer
        .public_hex()
        .eq_ignore_ascii_case(issuer_id)
        .then_some(issuer)
}

/// Pick the issuer for a revoke.
///
/// `--issuer-data-dir` keeps the existing rules. Without it, a stored grant
/// issued by a key other than the operator falls back to the default node data
/// dir when that directory's issuer matches the grant.
fn grant_issuer_for_revoke(
    issuer_data_dir: Option<&std::path::Path>,
    operator: &Identity,
    stored_grant: Option<&agentlink_core::grant::SignedGrant>,
) -> Result<Identity> {
    if issuer_data_dir.is_some() {
        return grant_issuer(issuer_data_dir, operator);
    }
    if let Some(grant) = stored_grant {
        let matches_operator = grant
            .issuer_id
            .trim()
            .eq_ignore_ascii_case(operator.public_hex());
        if !grant.issuer_id.trim().is_empty() && !matches_operator {
            if let Ok(dir) = agentlink_core::config::default_data_dir("node") {
                if let Some(issuer) = issuer_matching_grant(&dir, grant) {
                    eprintln!(
                        "using issuer from {} (matches grant issuer_id)",
                        dir.display()
                    );
                    return Ok(issuer);
                }
            }
        }
    }
    Ok(operator.clone())
}

fn trust_owner_report(dir: &std::path::Path, keys: &std::collections::BTreeSet<String>) -> String {
    format!(
        "trusted {} issuers in {}\n\
         a running node reloads owner-keys.json on the next request; no restart needed \
         (restart older node binaries to apply)",
        keys.len(),
        dir.display()
    )
}

/// Parse `900`, `15m`, `1h`, `7d`, `1h30m`, and mixes of those units.
fn parse_ttl(text: &str) -> Result<i64> {
    let text = text.trim();
    if text.is_empty() {
        return Err(anyhow!("--ttl is empty"));
    }
    if let Ok(secs) = text.parse::<i64>() {
        if secs > 0 {
            return Ok(secs);
        }
        return Err(anyhow!("--ttl must be positive"));
    }
    let mut total = 0i64;
    let mut digits = String::new();
    for ch in text.chars() {
        if ch.is_ascii_digit() {
            digits.push(ch);
            continue;
        }
        if digits.is_empty() {
            return Err(anyhow!("--ttl `{text}`: expected a number before `{ch}`"));
        }
        let value: i64 = digits
            .parse()
            .map_err(|_| anyhow!("--ttl `{text}`: number is too large"))?;
        let mult = match ch.to_ascii_lowercase() {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 604_800,
            _ => return Err(anyhow!("--ttl `{text}`: unknown unit `{ch}`")),
        };
        total = total.saturating_add(value.saturating_mul(mult));
        digits.clear();
    }
    if !digits.is_empty() {
        return Err(anyhow!("--ttl `{text}`: missing unit after `{digits}`"));
    }
    if total <= 0 {
        return Err(anyhow!("--ttl must be positive"));
    }
    Ok(total)
}

/// `1d 2h`, `3h 4m`, `5m`, `6s` for a positive elapsed/remaining span.
fn grant_duration_text(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    let seconds = secs % 60;
    if days > 0 {
        if hours > 0 {
            format!("{days}d {hours}h")
        } else {
            format!("{days}d")
        }
    } else if hours > 0 {
        if minutes > 0 {
            format!("{hours}h {minutes}m")
        } else {
            format!("{hours}h")
        }
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

/// `EXPIRED` or `in 1h 30m` for a grant expiry relative to `now_unix`.
fn grant_expiry_status(now_unix: i64, exp_unix: i64) -> String {
    let remaining = exp_unix - now_unix;
    if remaining < 0 {
        return "EXPIRED".to_string();
    }
    if remaining == 0 {
        return "expires now".to_string();
    }
    format!("in {}", grant_duration_text(remaining as u64))
}

/// Past-oriented counterpart to [`grant_expiry_status`]: `just now`, `3d ago`,
/// or `in 2h` when the grant is not valid yet.
fn grant_issued_status(now_unix: i64, nbf_unix: i64) -> String {
    let elapsed = now_unix - nbf_unix;
    if elapsed < 0 {
        return format!("in {}", grant_duration_text(elapsed.unsigned_abs()));
    }
    if elapsed == 0 {
        return "just now".to_string();
    }
    format!("{} ago", grant_duration_text(elapsed as u64))
}

/// `ACTIVE` through the expiry instant (inclusive), otherwise `EXPIRED`.
fn grant_status_label(now_unix: i64, exp_unix: i64) -> &'static str {
    if now_unix <= exp_unix {
        "ACTIVE"
    } else {
        "EXPIRED"
    }
}

/// First 12 lowercase hex chars, as shown by `nodes`.
fn grant_short_id(node_id: &str) -> String {
    node_id
        .trim()
        .to_ascii_lowercase()
        .chars()
        .take(12)
        .collect()
}

/// Short display form of a grant jti (UUIDs keep their first group).
fn grant_jti_short(jti: &str) -> String {
    jti.chars().take_while(|ch| *ch != '-').take(8).collect()
}

const GRANT_LIST_EMPTY_TIP: &str =
    "tip: agentlink grant ensure --node <name>   # or: grant issue / grant refresh";
const GRANT_LIST_FOOTER_TIP: &str = "tip: refresh with `agentlink grant refresh --node <name-or-id>`; revoke with `agentlink grant revoke --node …` (deny-list) or `grant revoke-local` (file only)";

/// Pull the 64-hex issuer out of a node "grant issuer … is not trusted"
/// error. A leading `authentication failed: ` wrapper is harmless.
fn untrusted_grant_issuer_hex(message: &str) -> Option<String> {
    if !message.contains("is not trusted") {
        return None;
    }
    const NEEDLE: &str = "grant issuer ";
    let start = message.find(NEEDLE)? + NEEDLE.len();
    let rest = &message[start..];
    let hex: String = rest.chars().take(64).collect();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    if matches!(rest.chars().nth(64), Some(ch) if ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(hex.to_ascii_lowercase())
}

/// Conventional node data dir in copy-paste tips; the tilde form is fine here.
const NODE_DATA_DIR_TIP: &str = "~/.local/share/agentlink/node";

/// One line, ready to paste on the node host.
fn trust_owner_paste_cmd(issuer: &str) -> String {
    format!("agentlink grant trust-owner {issuer} --data-dir {NODE_DATA_DIR_TIP}")
}

/// Short tip after a grant is signed by the operator (no issuer data dir).
fn grant_issuer_trust_tip(issuer: &str) -> String {
    format!(
        "tip: if the node rejects this issuer, on the node host paste:\n  {}",
        trust_owner_paste_cmd(issuer)
    )
}

/// Whether a stored grant was signed by this CLI's operator identity.
fn grant_issuer_is_operator(
    grant: &agentlink_core::grant::SignedGrant,
    operator: &Identity,
) -> bool {
    grant
        .issuer_id
        .trim()
        .eq_ignore_ascii_case(operator.public_hex())
}

/// Pasteable `trust-owner` command only for operator-signed grants, i.e. when
/// no issuer data dir was resolved (a node's own issuer is already trusted).
fn operator_trust_owner_cmd(
    issuer: &Identity,
    issuer_data_dir: Option<&std::path::Path>,
) -> Option<String> {
    issuer_data_dir
        .is_none()
        .then(|| trust_owner_paste_cmd(&issuer.public_hex()))
}

/// Concrete next step when the node rejects a client-signed grant issuer.
fn tip_untrusted_grant_issuer(issuer: &str) -> String {
    format!(
        "tip: this grant's issuer is not trusted by the node yet.\n  on the node host, paste:\n    {cmd}\n    (hot-reloads on the next request)\n  or mint with the node issuer, then retry:\n    agentlink grant ensure --node <name> --issuer-data-dir {dir}\n  or set AGENTLINK_ISSUER_DATA_DIR=…",
        cmd = trust_owner_paste_cmd(issuer),
        dir = NODE_DATA_DIR_TIP,
    )
}

/// One human line per stored grant, without the redundant absolute path.
fn grant_list_line(
    name: Option<&str>,
    node_id: &str,
    access: &str,
    now_unix: i64,
    exp_unix: i64,
    jti: &str,
) -> String {
    let short = grant_short_id(node_id);
    let status = grant_status_label(now_unix, exp_unix);
    let expires = if status == "ACTIVE" {
        grant_expiry_status(now_unix, exp_unix)
    } else {
        String::new()
    };
    let jti = grant_jti_short(jti);
    let line = match name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => {
            format!("{name:<16} {short:<12} {status:<7} {access:<6} {expires:<14} jti {jti}")
        }
        None => format!("{short:<12} {status:<7} {access:<6} {expires:<14} jti {jti}"),
    };
    line.trim_end().to_string()
}

/// One `grant list --json` item. `trust_owner_cmd` appears only when the
/// issuer is this CLI's operator identity, mirroring `grant ensure` JSON.
fn grant_list_json_item(
    grant: &agentlink_core::grant::SignedGrant,
    path: &std::path::Path,
    name: Option<&str>,
    now_unix: i64,
    operator: Option<&Identity>,
) -> Value {
    let mut item = json!({
        "path": path,
        "grant": grant,
        "expired": now_unix > grant.exp_unix,
        "status": grant_status_label(now_unix, grant.exp_unix),
        "node_short": grant_short_id(&grant.node_id),
        "name": name,
        "expires_in": grant_expiry_status(now_unix, grant.exp_unix),
    });
    if operator.is_some_and(|operator| grant_issuer_is_operator(grant, operator)) {
        item["trust_owner_cmd"] = json!(trust_owner_paste_cmd(&grant.issuer_id));
    }
    item
}

/// Multi-line `grant show` summary: labeled, list-style, without the raw
/// policy bool map or signature hex.
fn format_grant_show(
    name: Option<&str>,
    grant: &agentlink_core::grant::SignedGrant,
    now_unix: i64,
    path: &std::path::Path,
) -> String {
    let short = grant_short_id(&grant.node_id);
    let node = match name.map(str::trim).filter(|name| !name.is_empty()) {
        Some(name) => format!("{name} ({short})"),
        None => short,
    };
    let expires = if now_unix > grant.exp_unix {
        format!(
            "EXPIRED ({} ago)",
            grant_duration_text((now_unix - grant.exp_unix) as u64)
        )
    } else {
        grant_expiry_status(now_unix, grant.exp_unix)
    };
    let lines = [
        format!("{:<10}{node}", "node:"),
        format!(
            "{:<10}{}",
            "status:",
            grant_status_label(now_unix, grant.exp_unix)
        ),
        format!("{:<10}{}", "access:", grant.policy.capability_summary()),
        format!(
            "{:<10}{} (unix {})",
            "issued:",
            grant_issued_status(now_unix, grant.nbf_unix),
            grant.nbf_unix
        ),
        format!("{:<10}{expires} (unix {})", "expires:", grant.exp_unix),
        format!("{:<10}{}", "jti:", grant.jti),
        format!("{:<10}{}", "issuer:", grant_short_id(&grant.issuer_id)),
        format!("{:<10}{}", "path:", path.display()),
    ];
    lines.join("\n")
}

#[cfg(test)]
mod grant_ttl_tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn ttl_accepts_seconds_and_units() {
        assert_eq!(parse_ttl("900").unwrap(), 900);
        assert_eq!(parse_ttl("15m").unwrap(), 900);
        assert_eq!(parse_ttl("1h30m").unwrap(), 5400);
        assert_eq!(parse_ttl("7d").unwrap(), 604_800);
        assert!(parse_ttl("0").is_err());
        assert!(parse_ttl("5x").is_err());
        assert!(parse_ttl("10").is_ok());
        assert!(parse_ttl("1h30").is_err());
    }

    #[test]
    fn guide_subcommand_parses() {
        let cli = Cli::try_parse_from(["agentlink", "guide", "lab-box", "--no-open"]).unwrap();
        match cli.command {
            Command::Guide {
                node,
                local,
                data_dir,
                no_open,
                print_only,
            } => {
                assert_eq!(node.as_deref(), Some("lab-box"));
                assert!(!local);
                assert!(data_dir.is_none());
                assert!(no_open);
                assert!(!print_only);
            }
            other => panic!("expected guide, got {other:?}"),
        }

        let local = Cli::try_parse_from([
            "agentlink",
            "guide",
            "--local",
            "--data-dir",
            "/tmp/agentlink-node",
            "--print-only",
        ])
        .unwrap();
        match local.command {
            Command::Guide {
                node,
                local,
                data_dir,
                no_open,
                print_only,
            } => {
                assert!(node.is_none());
                assert!(local);
                assert_eq!(
                    data_dir.as_deref(),
                    Some(std::path::Path::new("/tmp/agentlink-node"))
                );
                assert!(!no_open);
                assert!(print_only);
            }
            other => panic!("expected local guide, got {other:?}"),
        }
    }

    fn test_guide(name: &str) -> OperateGuide {
        OperateGuide {
            v: 1,
            relay: "wss://relay.example.test".into(),
            node_id: "abc123".into(),
            name: name.into(),
            os: "linux".into(),
            arch: "x86_64".into(),
            version: "0.1.127".into(),
            online: Some(true),
            has_display: None,
            access: "exec".into(),
            effective: "exec".into(),
            notes: String::new(),
        }
    }

    #[test]
    fn guide_tips_cover_docs_only_expiry_and_trust_owner() {
        let tips = guide_tips(&test_guide("lab-box"));
        assert_eq!(tips.len(), 2);
        assert!(tips[0].contains("no grant, ticket, or issuer secrets"));
        assert!(tips[1].contains("full access"));
        assert!(tips[1].contains("do not paste a grant"));
        assert!(tips[1].contains("agentlink grant issue --node lab-box --ttl 1h"));
        assert!(tips[1].contains("agentlink grant show"));
    }

    #[test]
    fn guide_tips_fall_back_to_node_id_without_name() {
        let tips = guide_tips(&test_guide("  "));
        assert!(tips[1].contains("agentlink grant issue --node abc123 --ttl 1h"));
    }

    #[test]
    fn guide_human_output_puts_url_first_then_tips() {
        let tips = guide_tips(&test_guide("lab-box"));
        let out = guide_human_output("https://relay.example.test/operate/#v1.abc", &tips);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("https://relay.example.test/operate/#v1."));
        assert!(lines[1].starts_with("tip: docs-only"));
        assert!(lines[2].contains("--ttl 1h"));
    }

    #[test]
    fn grant_subcommands_parse() {
        let cli = Cli::try_parse_from([
            "agentlink",
            "grant",
            "issue",
            "--node",
            "box",
            "--ttl",
            "15m",
        ])
        .unwrap();
        match cli.command {
            Command::Grant {
                action: GrantCommand::Issue { ttl, policy, .. },
            } => {
                assert_eq!(ttl, "15m");
                assert_eq!(policy, "full");
            }
            other => panic!("expected grant issue, got {other:?}"),
        }
    }

    #[test]
    fn grant_refresh_parses() {
        let cli =
            Cli::try_parse_from(["agentlink", "grant", "refresh", "--node", "x"]).unwrap();
        match cli.command {
            Command::Grant {
                action: GrantCommand::Refresh { node, ttl, .. },
            } => {
                assert_eq!(node, "x");
                assert_eq!(ttl, "1h");
            }
            other => panic!("expected grant refresh, got {other:?}"),
        }
    }

    #[test]
    fn grant_ensure_parses() {
        let grantee = "ab".repeat(32);
        let cli = Cli::try_parse_from([
            "agentlink",
            "grant",
            "ensure",
            "--node",
            "box",
            "--ttl",
            "30m",
            "--policy",
            "full",
            "--grantee",
            &grantee,
            "--issuer-data-dir",
            "/tmp/issuer",
        ])
        .unwrap();
        match cli.command {
            Command::Grant {
                action:
                    GrantCommand::Ensure {
                        node,
                        ttl,
                        policy,
                        grantee: parsed_grantee,
                        issuer_data_dir,
                    },
            } => {
                assert_eq!(node, "box");
                assert_eq!(ttl, "30m");
                assert_eq!(policy, "full");
                assert_eq!(parsed_grantee.as_deref(), Some(grantee.as_str()));
                assert_eq!(issuer_data_dir, Some(PathBuf::from("/tmp/issuer")));
            }
            other => panic!("expected grant ensure, got {other:?}"),
        }
    }

    #[test]
    fn grant_revoke_parses_as_node_revoke() {
        let cli = Cli::try_parse_from([
            "agentlink",
            "grant",
            "revoke",
            "--node",
            "x",
            "--data-dir",
            "/tmp/node",
            "--issuer-data-dir",
            "/tmp/issuer",
            "--jti",
            "abc",
        ])
        .unwrap();
        match cli.command {
            Command::Grant {
                action:
                    GrantCommand::Revoke {
                        node,
                        data_dir,
                        jti,
                        issuer_data_dir,
                    },
            } => {
                assert_eq!(node, "x");
                assert_eq!(data_dir, Some(PathBuf::from("/tmp/node")));
                assert_eq!(issuer_data_dir, Some(PathBuf::from("/tmp/issuer")));
                assert_eq!(jti.as_deref(), Some("abc"));
            }
            other => panic!("expected grant revoke as node revoke, got {other:?}"),
        }
    }

    #[test]
    fn should_remove_local_grant_only_when_jtis_match() {
        // No explicit jti: the stored grant is the revoke target.
        assert!(should_remove_local_grant(None, Some("abc")));
        // Explicit jti matching the stored grant, trimmed and case-insensitive.
        assert!(should_remove_local_grant(Some(" ABC "), Some("abc")));
        // Explicit jti for another grant: keep the stored file.
        assert!(!should_remove_local_grant(Some("other"), Some("abc")));
        // Nothing stored: no local grant to keep.
        assert!(should_remove_local_grant(Some("other"), None));
        assert!(should_remove_local_grant(None, None));
    }

    #[test]
    fn grant_clear_and_revoke_local_parse_as_revoke_local() {
        for verb in ["clear", "revoke-local"] {
            let cli = Cli::try_parse_from(["agentlink", "grant", verb, "--node", "x"]).unwrap();
            match cli.command {
                Command::Grant {
                    action: GrantCommand::RevokeLocal { node },
                } => assert_eq!(node, "x"),
                other => panic!("expected grant {verb} as revoke-local, got {other:?}"),
            }
        }
    }

    #[test]
    fn grant_pending_allow_deny_prompt_parse_and_are_not_approve() {
        let pending = Cli::try_parse_from(["agentlink", "grant", "pending", "--data-dir", "/tmp/node"]).unwrap();
        match pending.command {
            Command::Grant {
                action: GrantCommand::Pending { data_dir },
            } => assert_eq!(data_dir, Some(PathBuf::from("/tmp/node"))),
            other => panic!("expected grant pending, got {other:?}"),
        }
        let allow = Cli::try_parse_from(["agentlink", "grant", "allow", "req-1", "--data-dir", "/tmp/node"]).unwrap();
        match allow.command {
            Command::Grant {
                action: GrantCommand::Allow { request_id, data_dir, out, policy, ttl },
            } => {
                assert_eq!(request_id, "req-1");
                assert_eq!(data_dir, Some(PathBuf::from("/tmp/node")));
                assert!(out.is_none());
                assert!(policy.is_none());
                assert!(ttl.is_none());
            }
            other => panic!("expected grant allow, got {other:?}"),
        }
        let deny = Cli::try_parse_from(["agentlink", "grant", "deny", "req-1"]).unwrap();
        match deny.command {
            Command::Grant {
                action: GrantCommand::Deny { request_id, .. },
            } => assert_eq!(request_id, "req-1"),
            other => panic!("expected grant deny, got {other:?}"),
        }
        let prompt = Cli::try_parse_from(["agentlink", "grant", "prompt"]).unwrap();
        match prompt.command {
            Command::Grant {
                action: GrantCommand::Prompt { request_id, data_dir, policy, ttl },
            } => {
                assert!(request_id.is_none());
                assert!(data_dir.is_none());
                assert!(policy.is_none());
                assert!(ttl.is_none());
            }
            other => panic!("expected grant prompt, got {other:?}"),
        }
        let offer = Cli::try_parse_from([
            "agentlink",
            "grant",
            "offer",
            "--policy",
            "desktop",
            "--ttl",
            "4h",
        ])
        .unwrap();
        match offer.command {
            Command::Grant {
                action: GrantCommand::Offer { policy, ttl, .. },
            } => {
                assert_eq!(policy, "desktop");
                assert_eq!(ttl, "4h");
            }
            other => panic!("expected grant offer, got {other:?}"),
        }
        let paste = Cli::try_parse_from([
            "agentlink",
            "grant",
            "paste",
            "agentlink-offer:v1:x",
            "--data-dir",
            "/tmp/node",
        ])
        .unwrap();
        match paste.command {
            Command::Grant {
                action: GrantCommand::Paste { card, prompt, .. },
            } => {
                assert!(card.as_deref().unwrap().starts_with("agentlink-offer:v1:"));
                assert!(!prompt);
            }
            other => panic!("expected grant paste, got {other:?}"),
        }
        let shrink = Cli::try_parse_from([
            "agentlink",
            "grant",
            "allow",
            "req-1",
            "--policy",
            "exec",
            "--ttl",
            "10m",
        ])
        .unwrap();
        match shrink.command {
            Command::Grant {
                action: GrantCommand::Allow { policy, ttl, .. },
            } => {
                assert_eq!(policy.as_deref(), Some("exec"));
                assert_eq!(ttl.as_deref(), Some("10m"));
            }
            other => panic!("expected shrink allow, got {other:?}"),
        }
        let paste_ui = Cli::try_parse_from(["agentlink", "grant", "paste-ui", "--data-dir", "/tmp/node"]).unwrap();
        match paste_ui.command {
            Command::Grant {
                action: GrantCommand::PasteUi { data_dir, .. },
            } => assert_eq!(data_dir, Some(PathBuf::from("/tmp/node"))),
            other => panic!("expected grant paste-ui, got {other:?}"),
        }

        // Held destructive-ops verbs stay on `approve`, not `grant`.
        let approve = Cli::try_parse_from([
            "agentlink",
            "approve",
            "allow",
            "hold-1",
            "sufa",
        ]);
        assert!(approve.is_ok(), "{approve:?}");
        match approve.unwrap().command {
            Command::Approve { .. } => {}
            other => panic!("approve allow must stay on Approve, got {other:?}"),
        }
    }

    #[test]
    fn local_issuer_node_id_matches_name_and_rejects_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let id = "aa".repeat(32);
        std::fs::write(
            dir.path().join("identity.json"),
            serde_json::json!({"public_hex": id}).to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("node.json"),
            serde_json::json!({"name": "sufa-iso"}).to_string(),
        )
        .unwrap();
        assert_eq!(
            local_issuer_node_id(dir.path(), "sufa-iso").as_deref(),
            Some(id.as_str())
        );
        assert!(local_issuer_node_id(dir.path(), "other-node").is_none());
        assert!(local_issuer_node_id(dir.path(), id.as_str()).is_none());
        let empty = tempfile::tempdir().unwrap();
        assert!(local_issuer_node_id(empty.path(), "sufa-iso").is_none());
    }

    fn store_grant(dir: &Path, node_id: &str) {
        let issuer = Identity::generate();
        let grantee = Identity::generate();
        let now = agentlink_core::util::unix_now();
        let grant = agentlink_core::grant::SignedGrant::sign(
            &issuer,
            grantee.public_hex(),
            node_id,
            NodePolicy::exec(),
            now - 1,
            now + 600,
            format!("jti-{node_id}"),
        )
        .unwrap();
        agentlink_core::grant::save_grant(dir, &grant).unwrap();
    }

    #[test]
    fn local_grant_prefix_match_clears_only_the_right_file() {
        let dir = tempfile::tempdir().unwrap();
        let first = format!("abc9{}", "0".repeat(60));
        let second = format!("cdef{}", "0".repeat(60));
        store_grant(dir.path(), &first);
        store_grant(dir.path(), &second);

        let mut matches = matching_local_grants(dir.path(), &first[..8]).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].node_id, first);
        std::fs::remove_file(&matches.remove(0).path).unwrap();
        assert!(agentlink_core::grant::load_grant(dir.path(), &first)
            .unwrap()
            .is_none());
        assert!(agentlink_core::grant::load_grant(dir.path(), &second)
            .unwrap()
            .is_some());
    }

    #[test]
    fn ambiguous_local_grant_prefix_asks_for_a_longer_id() {
        let dir = tempfile::tempdir().unwrap();
        store_grant(dir.path(), &format!("abc1{}", "0".repeat(60)));
        store_grant(dir.path(), &format!("abc2{}", "0".repeat(60)));
        let matches = matching_local_grants(dir.path(), "abc").unwrap();
        assert_eq!(matches.len(), 2);
        let err = ambiguous_local_grant_error("abc", &matches).to_string();
        assert!(err.contains("matches 2 stored grants"), "{err}");
        assert!(err.contains("pass a longer node id"), "{err}");
    }

    #[test]
    fn missing_local_grant_tips_grant_list() {
        let err = missing_local_grant_error("nope").to_string();
        assert!(err.contains("no local grant matching `nope`"), "{err}");
        assert!(err.contains("agentlink grant list"), "{err}");
        assert!(err.contains("full node id"), "{err}");
    }

    #[test]
    fn grant_expiry_status_marks_expired_and_remaining() {
        assert_eq!(grant_expiry_status(100, 99), "EXPIRED");
        assert_eq!(grant_expiry_status(100, 100), "expires now");
        assert_eq!(grant_expiry_status(100, 100 + 7200), "in 2h");
        assert_eq!(grant_expiry_status(100, 100 + 5400), "in 1h 30m");
        assert_eq!(grant_expiry_status(100, 100 + 90), "in 1m");
        assert_eq!(grant_expiry_status(100, 100 + 30), "in 30s");
    }

    #[test]
    fn grant_status_is_active_through_the_expiry_instant() {
        assert_eq!(grant_status_label(100, 101), "ACTIVE");
        assert_eq!(grant_status_label(100, 100), "ACTIVE");
        assert_eq!(grant_status_label(101, 100), "EXPIRED");
    }

    #[test]
    fn grant_short_id_and_jti_stay_compact() {
        assert_eq!(
            grant_short_id("907AF48D6786D69A05776A83B94AABBE784F9FA5452C0AC0E469BAD4B1243043"),
            "907af48d6786"
        );
        assert_eq!(grant_short_id("abc"), "abc");
        assert_eq!(
            grant_jti_short("0e31d8db-5496-43eb-8138-e05a35bfb7dc"),
            "0e31d8db"
        );
        assert_eq!(grant_jti_short("1234567890"), "12345678");
    }

    #[test]
    fn grant_list_line_shows_name_status_access_and_no_paths() {
        let node = "907AF48D6786D69A05776A83B94AABBE784F9FA5452C0AC0E469BAD4B1243043";
        let now = 1_000_000;
        let line = grant_list_line(
            Some("box"),
            node,
            "full",
            now,
            now + 29 * 86_400 + 15 * 3_600,
            "0e31d8db-5496-43eb-8138-e05a35bfb7dc",
        );
        assert!(line.starts_with("box"), "{line}");
        assert!(line.contains("907af48d6786"), "{line}");
        assert!(!line.contains("907af48d6786d69a"), "{line}");
        assert!(line.contains("ACTIVE"), "{line}");
        assert!(line.contains("full"), "{line}");
        assert!(line.contains("in 29d 15h"), "{line}");
        assert!(line.contains("jti 0e31d8db"), "{line}");
        assert!(!line.contains("0e31d8db-5496"), "{line}");
        assert!(!line.contains("expires "), "{line}");
        assert!(!line.contains(&now.to_string()), "{line}");
    }

    #[test]
    fn grant_list_line_expired_drops_remaining_detail() {
        let line = grant_list_line(
            Some("box"),
            &"ab".repeat(32),
            "exec",
            1_000,
            999,
            "abcdef01-2345",
        );
        assert!(line.contains("EXPIRED"), "{line}");
        assert!(!line.contains("in "), "{line}");
        assert!(!line.contains("999"), "{line}");
    }

    #[test]
    fn grant_list_line_without_pin_names_only_the_short_id() {
        let line = grant_list_line(None, "907af48d6786d69a", "full", 100, 200, "0e31d8db-rest");
        assert!(line.starts_with("907af48d6786 "), "{line}");
        assert!(!line.contains("unknown"), "{line}");
    }

    fn fixture_grant(
        policy: NodePolicy,
        nbf_unix: i64,
        exp_unix: i64,
    ) -> agentlink_core::grant::SignedGrant {
        agentlink_core::grant::SignedGrant {
            grantee_id: "ab".repeat(32),
            node_id: "907AF48D6786D69A05776A83B94AABBE784F9FA5452C0AC0E469BAD4B1243043"
                .to_string(),
            policy,
            nbf_unix,
            exp_unix,
            jti: "0e31d8db-5496-43eb-8138-e05a35bfb7dc".to_string(),
            issuer_id: "327DB37D61FEAABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233"
                .to_string(),
            sig_hex: "deadbeef".repeat(16),
        }
    }

    #[test]
    fn grant_show_summary_labels_active_named_node() {
        let now = 1_000_000;
        let grant = fixture_grant(
            NodePolicy::full(),
            now - 3 * 86_400,
            now + 29 * 86_400 + 15 * 3_600,
        );
        let path = std::path::PathBuf::from("/cfg/grants/907af48d6786.json");
        let out = format_grant_show(Some("box"), &grant, now, &path);
        assert!(out.contains("node:     box (907af48d6786)"), "{out}");
        assert!(out.contains("status:   ACTIVE"), "{out}");
        assert!(out.contains("access:   full"), "{out}");
        assert!(out.contains("issued:   3d ago (unix 740800)"), "{out}");
        assert!(out.contains("expires:  in 29d 15h (unix 3559600)"), "{out}");
        assert!(
            out.contains("jti:      0e31d8db-5496-43eb-8138-e05a35bfb7dc"),
            "{out}"
        );
        assert!(out.contains("issuer:   327db37d61fe"), "{out}");
        assert!(
            out.contains("path:     /cfg/grants/907af48d6786.json"),
            "{out}"
        );
        assert!(!out.contains("sig"), "{out}");
        assert!(!out.contains("deadbeef"), "{out}");
        assert!(!out.contains("allow_"), "{out}");
    }

    #[test]
    fn grant_show_summary_expired_unnamed_pin() {
        let now = 1_000;
        let grant = fixture_grant(NodePolicy::exec(), 900, 999);
        let path = std::path::PathBuf::from("/cfg/grants/x.json");
        let out = format_grant_show(None, &grant, now, &path);
        assert!(out.contains("node:     907af48d6786\n"), "{out}");
        assert!(!out.contains("node:     907af48d6786 ("), "{out}");
        assert!(out.contains("status:   EXPIRED"), "{out}");
        assert!(out.contains("access:   exec"), "{out}");
        assert!(out.contains("issued:   1m ago (unix 900)"), "{out}");
        assert!(out.contains("expires:  EXPIRED (1s ago) (unix 999)"), "{out}");
    }

    #[test]
    fn grant_issued_status_past_future_and_zero() {
        assert_eq!(grant_issued_status(1_000, 1_000), "just now");
        assert_eq!(grant_issued_status(1_000, 1_000 - 3 * 86_400), "3d ago");
        assert_eq!(grant_issued_status(1_000, 1_000 - 7_200), "2h ago");
        assert_eq!(grant_issued_status(1_000, 1_000 - 30), "30s ago");
        assert_eq!(grant_issued_status(1_000, 1_000 + 7_200), "in 2h");
        assert_eq!(grant_issued_status(1_000, 1_000 + 90), "in 1m");
    }

    #[test]
    fn pin_name_reverse_lookup_matches_ids_case_insensitively() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            agentlink_core::node_pin::pin_path(dir.path()),
            r#"{"nodes":{"box":"907AF48D6786D69A","zeta":"907af48d6786d69a","example":"abc9bac5ec27"}}"#,
        )
        .unwrap();
        assert_eq!(
            agentlink_core::node_pin::name_for_id(dir.path(), "907af48d6786d69a")
                .unwrap()
                .as_deref(),
            Some("box"),
            "first by name order wins for a shared id"
        );
        assert_eq!(
            agentlink_core::node_pin::name_for_id(dir.path(), "ABC9BAC5EC27")
                .unwrap()
                .as_deref(),
            Some("example")
        );
        assert_eq!(
            agentlink_core::node_pin::name_for_id(dir.path(), "ffffffffffff").unwrap(),
            None
        );
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            agentlink_core::node_pin::name_for_id(empty.path(), "907af48d6786d69a").unwrap(),
            None
        );
    }

    #[test]
    fn grant_list_empty_and_footer_tips_are_actionable() {
        assert!(GRANT_LIST_EMPTY_TIP.contains("grant ensure"));
        assert!(GRANT_LIST_EMPTY_TIP.contains("grant issue"));
        assert!(GRANT_LIST_EMPTY_TIP.contains("grant refresh"));
        assert!(GRANT_LIST_FOOTER_TIP.contains("grant refresh"));
        assert!(GRANT_LIST_FOOTER_TIP.contains("grant revoke"));
        assert!(GRANT_LIST_FOOTER_TIP.contains("revoke-local"));
    }

    #[test]
    fn untrusted_grant_issuer_extracts_from_auth_error() {
        let issuer = "ab".repeat(32);
        let message = format!(
            "authentication failed: grant issuer {issuer} is not trusted; on the node host run \
             `agentlink grant trust-owner {issuer} --data-dir <node-data-dir>`"
        );
        assert_eq!(
            untrusted_grant_issuer_hex(&message).as_deref(),
            Some(issuer.as_str())
        );
    }

    #[test]
    fn untrusted_grant_tip_names_trust_owner_and_env() {
        let issuer = "cd".repeat(32);
        let tip = tip_untrusted_grant_issuer(&issuer);
        assert!(tip.contains(&format!("trust-owner {issuer}")), "{tip}");
        assert!(tip.contains("grant ensure"), "{tip}");
        assert!(!tip.contains("AGENTLINK_AUTO_GRANT"), "{tip}");
        assert!(tip.contains("~/.local/share/agentlink/node"), "{tip}");
        let paste = trust_owner_paste_cmd(&issuer);
        assert!(tip.contains(&format!("    {paste}")), "{tip}");
        assert!(!tip.contains("<node-data-dir>"), "{tip}");
    }

    #[test]
    fn trust_owner_paste_cmd_is_ready_to_paste() {
        let issuer = "ef".repeat(32);
        let cmd = trust_owner_paste_cmd(&issuer);
        assert!(cmd.contains(&issuer), "{cmd}");
        assert!(cmd.contains("agentlink grant trust-owner"), "{cmd}");
        assert!(cmd.contains("~/.local/share/agentlink/node"), "{cmd}");
        assert!(!cmd.contains('<'), "{cmd}");
    }

    #[test]
    fn operator_signed_grants_carry_trust_owner_tip() {
        let operator = Identity::generate();
        let issuer = operator.public_hex();
        let cmd = operator_trust_owner_cmd(&operator, None).expect("operator path has tip");
        assert_eq!(cmd, trust_owner_paste_cmd(&issuer));

        let dir = tempfile::tempdir().unwrap();
        assert!(operator_trust_owner_cmd(&operator, Some(dir.path())).is_none());

        let tip = grant_issuer_trust_tip(&issuer);
        assert!(tip.contains(&cmd), "{tip}");

        let node = Identity::generate();
        let now = agentlink_core::util::unix_now();
        let grant = agentlink_core::grant::SignedGrant::sign(
            &operator,
            operator.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 1,
            now + 60,
            "jti",
        )
        .unwrap();
        let path = Path::new("/tmp/grant.json");

        let with_tip = grant_result_json(&grant, path, &operator, Some(&cmd));
        assert_eq!(with_tip["issuer"], json!(issuer));
        assert_eq!(with_tip["trust_owner_cmd"], json!(cmd));

        let without_tip = grant_result_json(&grant, path, &operator, None);
        assert!(without_tip.get("trust_owner_cmd").is_none());
        assert_eq!(without_tip["issuer"], json!(issuer));
    }

    #[test]
    fn grant_issuer_is_operator_matches_hex_case_insensitively() {
        let operator = Identity::generate();
        let node = Identity::generate();
        let now = agentlink_core::util::unix_now();
        let mut grant = agentlink_core::grant::SignedGrant::sign(
            &operator,
            operator.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 1,
            now + 60,
            "jti",
        )
        .unwrap();
        assert!(grant_issuer_is_operator(&grant, &operator));
        assert!(!grant_issuer_is_operator(&grant, &Identity::generate()));

        grant.issuer_id = grant.issuer_id.to_ascii_uppercase();
        assert!(grant_issuer_is_operator(&grant, &operator));

        grant.issuer_id = format!("  {}  ", grant.issuer_id);
        assert!(grant_issuer_is_operator(&grant, &operator));
    }

    #[test]
    fn operator_issuer_tip_keeps_full_issuer_and_node_data_dir() {
        let operator = Identity::generate();
        let node = Identity::generate();
        let now = agentlink_core::util::unix_now();
        let grant = agentlink_core::grant::SignedGrant::sign(
            &operator,
            operator.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 1,
            now + 60,
            "jti",
        )
        .unwrap();
        assert!(grant_issuer_is_operator(&grant, &operator));

        let tip = grant_issuer_trust_tip(&grant.issuer_id);
        assert!(tip.contains(&grant.issuer_id), "{tip}");
        assert!(tip.contains("agentlink grant trust-owner"), "{tip}");
        assert!(tip.contains("~/.local/share/agentlink/node"), "{tip}");
    }

    #[test]
    fn grant_list_json_item_adds_trust_owner_cmd_only_for_operator_issuer() {
        let operator = Identity::generate();
        let node = Identity::generate();
        let now = agentlink_core::util::unix_now();
        let grant = agentlink_core::grant::SignedGrant::sign(
            &operator,
            operator.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 1,
            now + 60,
            "jti",
        )
        .unwrap();
        let path = Path::new("/tmp/grant.json");

        let item = grant_list_json_item(&grant, path, Some("n1"), now, Some(&operator));
        assert_eq!(
            item["trust_owner_cmd"],
            json!(trust_owner_paste_cmd(&grant.issuer_id))
        );
        assert_eq!(item["name"], json!("n1"));
        assert_eq!(item["grant"]["issuer_id"], json!(operator.public_hex()));

        let other = Identity::generate();
        let item = grant_list_json_item(&grant, path, None, now, Some(&other));
        assert!(item.get("trust_owner_cmd").is_none());
        assert_eq!(item["grant"]["issuer_id"], json!(operator.public_hex()));

        let item = grant_list_json_item(&grant, path, None, now, None);
        assert!(item.get("trust_owner_cmd").is_none());
    }

    #[test]
    fn untrusted_grant_detection_ignores_other_errors() {
        assert_eq!(
            untrusted_grant_issuer_hex("authentication failed: bad token"),
            None
        );
        assert_eq!(
            untrusted_grant_issuer_hex("grant is for a different node"),
            None
        );
        assert_eq!(
            untrusted_grant_issuer_hex("grant issuer abc is not trusted"),
            None
        );
    }

    #[test]
    fn issuer_matching_grant_reads_persistent_issuer() {
        let dir = tempfile::tempdir().unwrap();
        let issuer = Identity::load_or_create(
            &dir.path().join(agentlink_core::grant::GRANT_ISSUER_FILE),
        )
        .unwrap();
        let node = Identity::generate();
        let grantee = Identity::generate();
        let now = agentlink_core::util::unix_now();
        let grant = agentlink_core::grant::SignedGrant::sign(
            &issuer,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 1,
            now + 60,
            "jti",
        )
        .unwrap();
        let found = issuer_matching_grant(dir.path(), &grant).expect("issuer matches");
        assert_eq!(found.public_hex(), issuer.public_hex());

        let other_issuer = Identity::generate();
        let other = agentlink_core::grant::SignedGrant::sign(
            &other_issuer,
            grantee.public_hex(),
            node.public_hex(),
            NodePolicy::exec(),
            now - 1,
            now + 60,
            "jti",
        )
        .unwrap();
        assert!(issuer_matching_grant(dir.path(), &other).is_none());
        let empty = tempfile::tempdir().unwrap();
        assert!(issuer_matching_grant(empty.path(), &grant).is_none());
    }

    #[test]
    fn issuer_resolver_explicit_wins_over_env_and_discovery() {
        use std::ffi::OsStr;
        let node = tempfile::tempdir().unwrap();
        std::fs::write(
            node.path().join(agentlink_core::grant::GRANT_ISSUER_FILE),
            b"{}",
        )
        .unwrap();
        let explicit = Path::new("/tmp/explicit");
        let env = OsStr::new("/tmp/env");
        let (dir, source) =
            resolve_issuer_data_dir_with(Some(explicit), Some(env), Some(node.path())).unwrap();
        assert_eq!(dir, explicit);
        assert_eq!(source, IssuerDirSource::Explicit);
    }

    #[test]
    fn issuer_resolver_uses_env_when_flag_absent() {
        use std::ffi::OsStr;
        let (dir, source) =
            resolve_issuer_data_dir_with(None, Some(OsStr::new("/tmp/env")), None).unwrap();
        assert_eq!(dir, PathBuf::from("/tmp/env"));
        assert_eq!(source, IssuerDirSource::Env);
    }

    #[test]
    fn issuer_resolver_empty_env_falls_through() {
        use std::ffi::OsStr;
        let node = tempfile::tempdir().unwrap();
        std::fs::write(
            node.path().join(agentlink_core::grant::GRANT_ISSUER_FILE),
            b"{}",
        )
        .unwrap();
        let (dir, source) =
            resolve_issuer_data_dir_with(None, Some(OsStr::new("  ")), Some(node.path())).unwrap();
        assert_eq!(dir, node.path());
        assert_eq!(source, IssuerDirSource::LocalNode);
    }

    #[test]
    fn issuer_resolver_missing_node_dir_is_none() {
        let node = tempfile::tempdir().unwrap();
        let missing = node.path().join("does-not-exist");
        assert!(resolve_issuer_data_dir_with(None, None, Some(&missing)).is_none());
        assert!(resolve_issuer_data_dir_with(None, None, None).is_none());
    }

    #[test]
    fn issuer_resolver_empty_node_dir_is_none() {
        let node = tempfile::tempdir().unwrap();
        assert!(resolve_issuer_data_dir_with(None, None, Some(node.path())).is_none());

        std::fs::write(
            node.path().join(agentlink_core::grant::OWNER_KEYS_FILE),
            br#"{"issuers":[]}"#,
        )
        .unwrap();
        assert!(resolve_issuer_data_dir_with(None, None, Some(node.path())).is_none());

        std::fs::write(
            node.path().join(agentlink_core::grant::OWNER_KEYS_FILE),
            b"",
        )
        .unwrap();
        assert!(resolve_issuer_data_dir_with(None, None, Some(node.path())).is_none());
    }

    #[test]
    fn issuer_resolver_discovers_issuer_artifacts() {
        let with_issuer = tempfile::tempdir().unwrap();
        std::fs::write(
            with_issuer
                .path()
                .join(agentlink_core::grant::GRANT_ISSUER_FILE),
            b"{}",
        )
        .unwrap();
        let (dir, source) =
            resolve_issuer_data_dir_with(None, None, Some(with_issuer.path())).unwrap();
        assert_eq!(dir, with_issuer.path());
        assert_eq!(source, IssuerDirSource::LocalNode);

        let with_owner_keys = tempfile::tempdir().unwrap();
        std::fs::write(
            with_owner_keys
                .path()
                .join(agentlink_core::grant::OWNER_KEYS_FILE),
            format!(r#"{{"issuers":["{}"]}}"#, "ab".repeat(32)),
        )
        .unwrap();
        let (dir, source) =
            resolve_issuer_data_dir_with(None, None, Some(with_owner_keys.path())).unwrap();
        assert_eq!(dir, with_owner_keys.path());
        assert_eq!(source, IssuerDirSource::LocalNode);
    }

    #[test]
    fn auto_grant_reuses_ensure_discovery() {
        use std::ffi::OsStr;
        // Env wins over a local node dir with issuer artifacts.
        let node = tempfile::tempdir().unwrap();
        std::fs::write(
            node.path().join(agentlink_core::grant::GRANT_ISSUER_FILE),
            b"{}",
        )
        .unwrap();
        assert_eq!(
            auto_grant_issuer_data_dir_with(Some(OsStr::new("/tmp/env")), Some(node.path())),
            Some(PathBuf::from("/tmp/env"))
        );

        // Local node with issuer artifacts is discovered.
        assert_eq!(
            auto_grant_issuer_data_dir_with(None, Some(node.path())),
            Some(node.path().to_path_buf())
        );

        let with_owner_keys = tempfile::tempdir().unwrap();
        std::fs::write(
            with_owner_keys
                .path()
                .join(agentlink_core::grant::OWNER_KEYS_FILE),
            format!(r#"{{"issuers":["{}"]}}"#, "ab".repeat(32)),
        )
        .unwrap();
        assert_eq!(
            auto_grant_issuer_data_dir_with(None, Some(with_owner_keys.path())),
            Some(with_owner_keys.path().to_path_buf())
        );

        // Empty or missing node dir keeps the operator identity.
        let empty = tempfile::tempdir().unwrap();
        assert!(auto_grant_issuer_data_dir_with(None, Some(empty.path())).is_none());
        assert!(auto_grant_issuer_data_dir_with(None, None).is_none());
        assert!(
            auto_grant_issuer_data_dir_with(None, Some(&empty.path().join("does-not-exist")))
                .is_none()
        );
    }

    #[test]
    fn trust_owner_reports_hot_reload_without_restart() {
        let dir = tempfile::tempdir().unwrap();
        let keys = std::collections::BTreeSet::from(["ab".repeat(32)]);
        let text = trust_owner_report(dir.path(), &keys);
        assert!(text.contains("trusted 1 issuers"), "{text}");
        assert!(text.contains("next request"), "{text}");
        assert!(text.contains("no restart"), "{text}");
    }

    #[test]
    fn port_error_keeps_auth_tip_and_adds_bind_hint() {
        let auth = port_error("grant issuer abc is not trusted", "unused hint");
        assert_eq!(auth.to_string(), "grant issuer abc is not trusted");
        let bind = port_error(
            "listen 127.0.0.1:8080: Address already in use (os error 98)",
            "pass a different LOCAL_PORT",
        );
        assert!(bind.to_string().contains("Address already in use"));
        assert!(bind.to_string().contains("pass a different LOCAL_PORT"));
    }
}


async fn guide_cmd(
    cli: &Cli,
    node: Option<&str>,
    local: bool,
    data_dir: Option<&std::path::Path>,
    no_open: bool,
) -> Result<i32> {
    let guide = if local {
        if node.map(|value| !value.trim().is_empty()).unwrap_or(false) {
            return Err(anyhow!("pass a node name or --local, not both"));
        }
        local_operate_guide(data_dir)?
    } else {
        let node = node
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| anyhow!("node name or id required (or use --local on the node host)"))?;
        let saved = settings(cli)?;
        let client = connect_client(cli, "guide").await?;
        let nodes = client
            .list_nodes()
            .await
            .map_err(|err| anyhow!(err.to_string()))?;
        let info = agentlink_core::protocol::resolve_node(&nodes, node)
            .map_err(|err| anyhow!(err.to_string()))?;
        OperateGuide {
            v: 1,
            relay: saved.relay.clone(),
            node_id: info.id.clone(),
            name: info.name.clone(),
            os: info.os.clone(),
            arch: info.arch.clone(),
            version: info.version.clone(),
            online: Some(info.online),
            has_display: info.has_display,
            access: info.access.clone(),
            effective: info.effective.preset_name().to_string(),
            notes: String::new(),
        }
    };
    let url = operate_guide_url(&guide.relay, &guide).map_err(|err| anyhow!(err.to_string()))?;
    let tips = guide_tips(&guide);
    emit(
        cli.json,
        json!({"url": &url, "guide": &guide, "tips": &tips}),
        || println!("{}", guide_human_output(&url, &tips)),
    );
    if !no_open {
        open_browser(&url);
    }
    Ok(0)
}

/// Human tips after the guide URL. The link is documentation only; grants are
/// still required, expire, and must be signed by an issuer the node trusts.
fn guide_tips(guide: &OperateGuide) -> Vec<String> {
    let name = guide.name.trim();
    let node = if name.is_empty() {
        guide.node_id.as_str()
    } else {
        name
    };
    vec![
        "tip: docs-only link — no grant, ticket, or issuer secrets.".to_string(),
        format!(
            "tip: sign in as the owner or an admin for full access; do not paste a grant. \
             A key that is not an account session still uses `agentlink grant issue --node {node} --ttl 1h` \
             and `agentlink grant show`."
        ),
    ]
}

fn guide_human_output(url: &str, tips: &[String]) -> String {
    let mut out = url.to_string();
    for tip in tips {
        out.push('\n');
        out.push_str(tip);
    }
    out
}

/// Build a guide from this host's `node.json` and node identity. Presence and
/// display are unknown here, so they stay omitted until the relay lists the
/// node.
fn local_operate_guide(data_dir: Option<&std::path::Path>) -> Result<OperateGuide> {
    let dir = match data_dir {
        Some(dir) => dir.to_path_buf(),
        None => agentlink_core::config::default_data_dir("node").map_err(|err| anyhow!(err))?,
    };
    let config_path = dir.join("node.json");
    let text = std::fs::read_to_string(&config_path)
        .with_context(|| format!("read {}", config_path.display()))?;
    let value: Value = serde_json::from_str(&text)
        .with_context(|| format!("parse {}", config_path.display()))?;
    let identity_path = dir.join("identity.json");
    let identity_text = std::fs::read_to_string(&identity_path).with_context(|| {
        format!(
            "read {}; start `agentlink node` once to create this node identity",
            identity_path.display()
        )
    })?;
    let identity: Value = serde_json::from_str(&identity_text)
        .with_context(|| format!("parse {}", identity_path.display()))?;
    let node_id = identity["public_hex"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("{} has no public_hex", identity_path.display()))?
        .to_ascii_lowercase();
    let relay = value["relay_url"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| anyhow!("{} has no relay_url", config_path.display()))?;
    let name = value["name"]
        .as_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(node_cfg::machine_name);
    let max_policy = value
        .get("max_policy")
        .and_then(|policy| serde_json::from_value::<NodePolicy>(policy.clone()).ok())
        .unwrap_or_else(NodePolicy::exec);
    Ok(OperateGuide {
        v: 1,
        relay: relay.to_string(),
        node_id,
        name,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        version: version::current().to_string(),
        online: None,
        has_display: None,
        access: String::new(),
        effective: max_policy.preset_name().to_string(),
        notes: String::new(),
    })
}

async fn port_cmd(cli: &Cli, action: &PortCommand) -> Result<i32> {
    // Parse the target before connecting so a bad target reports its own tip
    // instead of an unrelated tls handshake error when the relay flaps.
    match action {
        PortCommand::Forward {
            node,
            local_port,
            remote,
        } => {
            let (host, port) = port_forward_remote(remote)?;
            let client = connect_client(cli, "port").await?;
            client
                .port_forward(node, *local_port, &host, port)
                .await
                .map_err(|err| {
                    port_error(
                        err,
                        &format!(
                            "127.0.0.1:{local_port} is already in use; pass a different \
                             LOCAL_PORT or stop the other listener"
                        ),
                    )
                })?;
        }
        PortCommand::Reverse {
            node,
            remote_port,
            local,
        } => {
            let (host, port) = port_reverse_local(local)?;
            let client = connect_client(cli, "port").await?;
            client
                .port_reverse(node, *remote_port, &host, port)
                .await
                .map_err(|err| {
                    port_error(
                        err,
                        &format!(
                            "the node could not listen on port {remote_port}; pass a different \
                             REMOTE_PORT or stop the other listener"
                        ),
                    )
                })?;
        }
        PortCommand::Status => port_status(cli.json),
    }
    Ok(0)
}

const PORT_STATUS_TIP: &str = "port maps are the running `agentlink port forward` / \
    `agentlink port reverse` processes; there is no durable registry";
const PORT_STATUS_EXAMPLE: &str = "tip: start one with `agentlink port forward <NODE> \
    <LOCAL_PORT> <REMOTE>` or `agentlink port reverse <NODE> <REMOTE_PORT> <LOCAL>`; \
    see `agentlink guide <node>`";

fn port_status_value() -> Value {
    json!({
        "maps": [],
        "tip": PORT_STATUS_TIP,
        "example": PORT_STATUS_EXAMPLE,
    })
}

/// `port status` never dials the relay: maps are scoped to the running
/// forward/reverse processes, so there is nothing durable to query.
fn port_status(json_mode: bool) {
    emit(json_mode, port_status_value(), || {
        println!("active port maps: 0");
        println!("{PORT_STATUS_TIP}");
        println!("{PORT_STATUS_EXAMPLE}");
    });
}

fn port_forward_remote(remote: &str) -> Result<(String, u16)> {
    agentlink_core::tunnel::parse_target(remote).map_err(|err| {
        match agentlink_core::tunnel::forward_bare_port_hint(remote) {
            Some(tip) => anyhow!("{err}; {tip}"),
            None => anyhow!(err.to_string()),
        }
    })
}

fn port_reverse_local(local: &str) -> Result<(String, u16)> {
    agentlink_core::tunnel::parse_local_target(local).map_err(|err| anyhow!(err.to_string()))
}

/// Keep authz/grant messages intact; append a hint only for bind conflicts.
fn port_error(err: impl std::fmt::Display, in_use_hint: &str) -> anyhow::Error {
    let message = err.to_string();
    if agentlink_core::tunnel::is_addr_in_use(&message) {
        return anyhow!("{message}. {in_use_hint}");
    }
    anyhow!("{message}")
}

/// JSON for issue/refresh/ensure. `trust_owner_cmd` is present only on the
/// operator-signed path so existing parsers keep their fields.
fn grant_result_json(
    grant: &agentlink_core::grant::SignedGrant,
    path: &std::path::Path,
    issuer: &Identity,
    trust_owner_cmd: Option<&str>,
) -> Value {
    let mut out = json!({
        "grant": grant,
        "path": path,
        "issuer": issuer.public_hex(),
    });
    if let Some(cmd) = trust_owner_cmd {
        out["trust_owner_cmd"] = json!(cmd);
    }
    out
}

/// Shared `grant issue` / `grant refresh` output.
fn write_grant_result(
    cli: &Cli,
    out: Option<&str>,
    grant: &agentlink_core::grant::SignedGrant,
    path: &std::path::Path,
    issuer: &Identity,
    trust_owner_cmd: Option<&str>,
) -> Result<()> {
    if let Some(out) = out {
        let text = serde_json::to_string_pretty(grant)?;
        if out == "-" {
            println!("{text}");
        } else {
            agentlink_core::util::write_secret(std::path::Path::new(out), text.as_bytes())
                .map_err(|err| anyhow!(err.to_string()))?;
            eprintln!("wrote {out}");
        }
        return Ok(());
    }
    emit(
        cli.json,
        grant_result_json(grant, path, issuer, trust_owner_cmd),
        || {
            eprintln!(
                "grant {} on node {} expires unix {}",
                grant.grantee_id,
                grant.node_id,
                grant.exp_unix
            );
            eprintln!("access: {}", grant.policy.capability_summary());
            eprintln!("issuer: {}", issuer.public_hex());
            eprintln!("jti: {}", grant.jti);
            eprintln!("stored: {}", path.display());
            if let Some(cmd) = trust_owner_cmd {
                eprintln!("tip: if the node rejects this issuer, on the node host paste:");
                eprintln!("  {cmd}");
            }
        },
    );
    Ok(())
}

fn revoke_data_dir(explicit: Option<&std::path::Path>) -> Result<std::path::PathBuf> {
    if let Some(dir) = explicit {
        if !dir.is_dir() {
            return Err(anyhow!(
                "node data directory {} does not exist. grant revoke writes revoked-grants.json \
                 on this machine; it does not send a remote revoke.",
                dir.display()
            ));
        }
        return Ok(dir.to_path_buf());
    }
    let dir = agentlink_core::config::default_data_dir("node")
        .map_err(|err| anyhow!(err.to_string()))?;
    let looks_like_node = dir.join("identity.json").is_file()
        || dir.join(agentlink_core::grant::OWNER_KEYS_FILE).is_file()
        || dir.join(agentlink_core::grant::GRANT_ISSUER_FILE).is_file();
    if looks_like_node {
        return Ok(dir);
    }
    Err(anyhow!(
        "grant revoke writes {}/revoked-grants.json on the node host. Pass \
         --data-dir <node-data-dir>. A remote revoke is not sent and the node \
         rejects one.",
        dir.display()
    ))
}


fn grant_node_data_dir(explicit: Option<&std::path::Path>) -> Result<std::path::PathBuf> {
    revoke_data_dir(explicit)
}

fn local_node_public_id(data_dir: &std::path::Path) -> Result<String> {
    let path = data_dir.join("identity.json");
    if !path.is_file() {
        return Err(anyhow!(
            "no identity.json in {} — pass --data-dir of this node",
            data_dir.display()
        ));
    }
    let value: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let id = value
        .get("public_hex")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("identity.json is missing public_hex"))?
        .trim()
        .to_ascii_lowercase();
    if !is_public_key_hex(&id) {
        return Err(anyhow!("identity.json public_hex is not a 32-byte key"));
    }
    Ok(id)
}

fn grant_paste_card(
    cli: &Cli,
    card: Option<&str>,
    data_dir: Option<&std::path::PathBuf>,
    policy: &Option<String>,
    ttl: &Option<String>,
    prompt: bool,
) -> Result<i32> {
    let card_owned = match card {
        Some(c) if !c.trim().is_empty() => c.trim().to_string(),
        _ => grant_local::paste_card_dialog()?,
    };
    let card = card_owned.as_str();
    let dir = grant_node_data_dir(data_dir.map(|p| p.as_path()))?;
    let node_id = local_node_public_id(&dir)?;
    let now = agentlink_core::util::unix_now();
    let req = if let Ok(offer) = agentlink_core::grant_offer::decode_offer(card) {
        let relay_fp = agentlink_core::grant_offer::load_node_relay_fingerprint(&dir)
            .map_err(|err| anyhow!(err.to_string()))?;
        agentlink_core::grant_offer::paste_offer_as_request(&dir, &offer, &node_id, relay_fp.as_deref(), now)
            .map_err(|err| anyhow!(err.to_string()))?
    } else if let Some(grantee) = agentlink_core::grant_offer::parse_raw_grantee_hex(card) {
        let policy = policy.as_deref().ok_or_else(|| {
            anyhow!("粘贴的是完整控制端公钥，请同时指定 --policy 与 --ttl。仅公钥能标识控制端，但不能证明此刻持有私钥；控制端之后仍须用私钥完成 E2E。名称无效。")
        })?;
        let ttl = ttl.as_deref().ok_or_else(|| anyhow!("粘贴裸公钥时必须指定 --ttl"))?;
        let policy = parse_access(policy)?;
        let ttl_secs = parse_ttl(ttl)? as u64;
        let draft = agentlink_core::grant_request::draft_request(
            &grantee,
            &node_id,
            policy,
            ttl_secs,
            now,
            agentlink_core::grant_request::DEFAULT_REQUEST_TTL_SECS,
        )
        .map_err(|err| anyhow!(err.to_string()))?;
        agentlink_core::grant_request::submit_request(&dir, &node_id, draft, now)
            .map_err(|err| anyhow!(err.to_string()))?
    } else {
        return Err(anyhow!(
            agentlink_core::grant_offer::decode_offer(card)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| "无法解析身份码".into())
        ));
    };
    let fp = agentlink_core::grant_offer::sha256_ssh_fingerprint(&req.grantee_id)
        .map_err(|err| anyhow!(err.to_string()))?;
    emit(
        cli.json,
        json!({
            "kind": "pending_request",
            "note": "not a grant; local allow required",
            "request_id": req.request_id,
            "grantee_id": req.grantee_id,
            "fingerprint": fp,
            "access": req.policy.capability_summary(),
            "ttl_secs": req.ttl_secs,
            "exp_unix": req.exp_unix,
            "status": "pending",
        }),
        || {
            eprintln!("已在【目标机】记录待批请求 {}（还不是 grant）", req.request_id);
            eprintln!("控制端公钥指纹: {fp}");
            eprintln!("控制端公钥: {}", req.grantee_id);
            eprintln!("请求权限: {}", req.policy.capability_summary());
            eprintln!("若同意，grant 有效期: {} 秒", req.ttl_secs);
            eprintln!("{}", grant_local::SIGNATURE_DISCLAIMER);
            eprintln!("{}", grant_local::SCOPE_NOTE);
            eprintln!(
                "请核对比指纹后在本机执行:\n  agentlink grant allow {} --data-dir {}\n或: agentlink grant prompt --data-dir {}\n图形入口: agentlink grant paste-ui --data-dir {}",
                req.request_id,
                dir.display(),
                dir.display(),
                dir.display()
            );
            eprintln!("这不是 `agentlink approve allow`（那是危险操作确认）。");
        },
    );
    if prompt {
        let body = grant_local::request_prompt_body(
            &req.request_id,
            &fp,
            &req.grantee_id,
            &req.policy.capability_summary(),
            req.ttl_secs,
            req.exp_unix,
        );
        let allow = grant_local::decision_prompt(&body)?;
        if allow {
            let issuer = agentlink_core::grant::load_issuer(&dir)
                .map_err(|err| anyhow!(err.to_string()))?
                .ok_or_else(|| anyhow!("no grant-issuer.json in {}", dir.display()))?;
            let requested_name = req.policy.preset_name().to_string();
            let shrink = grant_local::shrink_grant_prompt(
                &requested_name,
                req.ttl_secs,
                policy.clone(),
                ttl.clone(),
            )?;
            let Some((shrink_policy, shrink_ttl)) = shrink else {
                eprintln!("已取消签发，待批请求 {} 仍保留（粘贴身份码本身未授权）", req.request_id);
                return Ok(0);
            };
            let policy = shrink_policy.as_deref().map(parse_access).transpose()?;
            let ttl_secs = shrink_ttl;
            let (_req, grant) = agentlink_core::grant_request::allow_request_in_dir(
                &dir,
                &req.request_id,
                now,
                policy,
                ttl_secs,
            )
            .map_err(|err| anyhow!(err.to_string()))?;
            let _ = agentlink_core::grant_request::save_issued_grant(&dir, &grant);
            let path = agentlink_core::grant::save_grant(&config_dir(cli)?, &grant)
                .map_err(|err| anyhow!(err.to_string()))?;
            write_grant_result(cli, None, &grant, &path, &issuer, None)?;
            eprintln!("已在目标机本地签发；issuer 密钥未离开本机。");
        } else {
            let denied = agentlink_core::grant_request::deny_request(&dir, &req.request_id, now)
                .map_err(|err| anyhow!(err.to_string()))?;
            eprintln!("已拒绝待批请求 {}", denied.request_id);
        }
    }
    Ok(0)
}

async fn grant_cmd(cli: &Cli, action: &GrantCommand) -> Result<i32> {
    let mutating = !matches!(
        action,
        GrantCommand::List | GrantCommand::Show { .. } | GrantCommand::Pending { .. }
    );
    if mutating {
        grant_local::refuse_if_remote_exec()?;
    }
    let dir = config_dir(cli)?;
    match action {
        GrantCommand::Issue {
            node,
            ttl,
            policy,
            grantee,
            issuer_data_dir,
            out,
        } => {
            let ttl_secs = parse_ttl(&ttl)?;
            let policy = parse_access(&policy)?;
            let operator = Identity::load_or_create(&operator_identity_path(cli)?)
                .map_err(|err| anyhow!(err.to_string()))?;
            let grantee = grantee
                .clone()
                .unwrap_or_else(|| operator.public_hex().to_string());
            if !is_public_key_hex(&grantee) {
                return Err(anyhow!(
                    "--grantee must be a 32-byte ed25519 public key hex"
                ));
            }
            let issuer_data_dir = resolve_issuer_data_dir(issuer_data_dir.as_deref());
            let node_id =
                resolve_grant_node_local_or_relay(cli, &node, issuer_data_dir.as_deref()).await?;
            let issuer = grant_issuer(issuer_data_dir.as_deref(), &operator)?;
            let trust_owner_cmd = operator_trust_owner_cmd(&issuer, issuer_data_dir.as_deref());
            let now = agentlink_core::util::unix_now();
            let exp = now.saturating_add(ttl_secs);
            let grant = agentlink_core::grant::SignedGrant::sign(
                &issuer,
                &grantee,
                &node_id,
                policy,
                now,
                exp,
                uuid::Uuid::new_v4().to_string(),
            )
            .map_err(|err| anyhow!(err.to_string()))?;
            let path = agentlink_core::grant::save_grant(&dir, &grant)
                .map_err(|err| anyhow!(err.to_string()))?;
            write_grant_result(
                cli,
                out.as_deref(),
                &grant,
                &path,
                &issuer,
                trust_owner_cmd.as_deref(),
            )?;
            Ok(0)
        }
        GrantCommand::Refresh {
            node,
            ttl,
            issuer_data_dir,
            out,
        } => {
            let ttl_secs = parse_ttl(ttl)?;
            let operator = Identity::load_or_create(&operator_identity_path(cli)?)
                .map_err(|err| anyhow!(err.to_string()))?;
            let issuer_data_dir = resolve_issuer_data_dir(issuer_data_dir.as_deref());
            let node_id =
                resolve_grant_node_local_or_relay(cli, node, issuer_data_dir.as_deref()).await?;
            let stored = agentlink_core::grant::load_grant(&dir, &node_id)
                .map_err(|err| anyhow!(err.to_string()))?
                .ok_or_else(|| {
                    anyhow!(
                        "no stored grant for node {node_id}; run `agentlink grant issue --node {node_id}`"
                    )
                })?;
            let issuer = grant_issuer(issuer_data_dir.as_deref(), &operator)?;
            let trust_owner_cmd = operator_trust_owner_cmd(&issuer, issuer_data_dir.as_deref());
            let now = agentlink_core::util::unix_now();
            let exp = now.saturating_add(ttl_secs);
            let grant = agentlink_core::grant::refresh_grant(
                &issuer,
                &stored,
                now,
                exp,
                uuid::Uuid::new_v4().to_string(),
            )
            .map_err(|err| anyhow!(err.to_string()))?;
            let path = agentlink_core::grant::save_grant(&dir, &grant)
                .map_err(|err| anyhow!(err.to_string()))?;
            write_grant_result(
                cli,
                out.as_deref(),
                &grant,
                &path,
                &issuer,
                trust_owner_cmd.as_deref(),
            )?;
            Ok(0)
        }
        GrantCommand::Ensure {
            node,
            ttl,
            policy,
            grantee,
            issuer_data_dir,
        } => {
            let ttl_secs = parse_ttl(ttl)?;
            let policy = parse_access(policy)?;
            let operator = Identity::load_or_create(&operator_identity_path(cli)?)
                .map_err(|err| anyhow!(err.to_string()))?;
            let grantee = grantee
                .clone()
                .unwrap_or_else(|| operator.public_hex().to_string());
            if !is_public_key_hex(&grantee) {
                return Err(anyhow!(
                    "--grantee must be a 32-byte ed25519 public key hex"
                ));
            }
            let issuer_data_dir = resolve_issuer_data_dir(issuer_data_dir.as_deref());
            let node_id =
                resolve_grant_node_local_or_relay(cli, node, issuer_data_dir.as_deref()).await?;
            let issuer = grant_issuer(issuer_data_dir.as_deref(), &operator)?;
            let trust_owner_cmd = operator_trust_owner_cmd(&issuer, issuer_data_dir.as_deref());
            let (grant, action) = agentlink_core::grant::ensure_grant(
                &dir, &issuer, &node_id, &grantee, policy, ttl_secs,
            )
            .map_err(|err| anyhow!(err.to_string()))?;
            let path = agentlink_core::grant::grant_path(&dir, &node_id);
            let action = action.as_str();
            emit(
                cli.json,
                {
                    let mut value =
                        grant_result_json(&grant, &path, &issuer, trust_owner_cmd.as_deref());
                    value["action"] = json!(action);
                    value
                },
                || {
                    eprintln!(
                        "grant {action} for node {} expires unix {}",
                        grant.node_id,
                        grant.exp_unix
                    );
                    eprintln!("access: {}", grant.policy.capability_summary());
                    eprintln!("issuer: {}", issuer.public_hex());
                    eprintln!("jti: {}", grant.jti);
                    eprintln!("stored: {}", path.display());
                    if let Some(cmd) = trust_owner_cmd.as_deref() {
                        eprintln!("tip: if the node rejects this issuer, on the node host paste:");
                        eprintln!("  {cmd}");
                    }
                },
            );
            Ok(0)
        }
        GrantCommand::Show { node } => {
            let node_id = resolve_grant_node(cli, &node).await?;
            let grant = agentlink_core::grant::load_grant(&dir, &node_id)
                .map_err(|err| anyhow!(err.to_string()))?;
            let Some(grant) = grant else {
                return Err(anyhow!(
                    "no stored grant for node {node_id}; run `agentlink grant list` or \
                     `agentlink grant ensure --node {node_id}`"
                ));
            };
            // `--json` stays the bare SignedGrant object for existing consumers.
            emit(cli.json, json!(grant), || {
                let now = agentlink_core::util::unix_now();
                let name = agentlink_core::node_pin::name_for_id(&dir, &grant.node_id)
                    .ok()
                    .flatten();
                let path = agentlink_core::grant::grant_path(&dir, &grant.node_id);
                println!("{}", format_grant_show(name.as_deref(), &grant, now, &path));
                // Best-effort: a missing/unreadable identity only skips the tip.
                let operator = operator_identity_path(cli)
                    .ok()
                    .and_then(|path| Identity::load_or_create(&path).ok());
                if operator
                    .as_ref()
                    .is_some_and(|operator| grant_issuer_is_operator(&grant, operator))
                {
                    eprintln!("{}", grant_issuer_trust_tip(&grant.issuer_id));
                }
                eprintln!("{GRANT_LIST_FOOTER_TIP}");
            });
            Ok(0)
        }
        GrantCommand::List => {
            let grants = agentlink_core::grant::list_stored_grants(&dir)
                .map_err(|err| anyhow!(err.to_string()))?;
            let now = agentlink_core::util::unix_now();
            if grants.is_empty() {
                if cli.json {
                    println!("[]");
                } else {
                    println!("no local grants");
                    eprintln!("{GRANT_LIST_EMPTY_TIP}");
                }
                return Ok(0);
            }
            // A missing or unreadable pins file should not break an offline
            // listing; names are only a display nicety.
            let pin_name = |node_id: &str| {
                agentlink_core::node_pin::name_for_id(&dir, node_id)
                    .ok()
                    .flatten()
            };
            // Best-effort: a missing/unreadable identity only skips the tip.
            let operator = operator_identity_path(cli)
                .ok()
                .and_then(|path| Identity::load_or_create(&path).ok());
            if cli.json {
                let items: Vec<_> = grants
                    .iter()
                    .map(|stored| {
                        let grant = &stored.grant;
                        grant_list_json_item(
                            grant,
                            &stored.path,
                            pin_name(&grant.node_id).as_deref(),
                            now,
                            operator.as_ref(),
                        )
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&items)?);
            } else {
                for stored in &grants {
                    let grant = &stored.grant;
                    let name = pin_name(&grant.node_id);
                    println!(
                        "{}",
                        grant_list_line(
                            name.as_deref(),
                            &grant.node_id,
                            grant.policy.preset_name(),
                            now,
                            grant.exp_unix,
                            &grant.jti,
                        )
                    );
                }
                let operator_issuer = operator.as_ref().and_then(|operator| {
                    grants
                        .iter()
                        .find(|stored| grant_issuer_is_operator(&stored.grant, operator))
                        .map(|stored| stored.grant.issuer_id.trim())
                });
                if let Some(issuer) = operator_issuer {
                    eprintln!("{}", grant_issuer_trust_tip(issuer));
                }
                eprintln!("{GRANT_LIST_FOOTER_TIP}");
            }
            Ok(0)
        }
        GrantCommand::RevokeLocal { node } => {
            let target = resolve_local_grant_node(cli, &dir, node).await?;
            let removed = match std::fs::remove_file(&target.path) {
                Ok(()) => true,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
                Err(err) => {
                    return Err(anyhow!(
                        "remove local grant {}: {err}",
                        target.path.display()
                    ))
                }
            };
            emit(
                cli.json,
                json!({"node": target.node_id, "removed": removed}),
                || {
                    if removed {
                        eprintln!("removed local grant for {}", target.node_id);
                    } else {
                        eprintln!(
                            "no local grant for {}; run `agentlink grant list`",
                            target.node_id
                        );
                    }
                },
            );
            Ok(0)
        }
        GrantCommand::Revoke {
            node,
            data_dir,
            jti,
            issuer_data_dir,
        } => {
            // Prefer the stored local grant (works offline). With an explicit
            // jti, a hex node id or relay-resolved name is still usable when no
            // local grant exists.
            let target = match resolve_local_grant_node(cli, &dir, node).await {
                Ok(target) => Some(target),
                Err(err) => {
                    if jti.is_none() {
                        return Err(err);
                    }
                    resolve_grant_node(cli, node).await.ok().map(|node_id| {
                        LocalGrantMatch {
                            path: agentlink_core::grant::grant_path(&dir, &node_id),
                            node_id,
                        }
                    })
                }
            };
            let stored_grant = match &target {
                Some(target) => agentlink_core::grant::load_grant(&dir, &target.node_id)
                    .map_err(|err| anyhow!(err.to_string()))?,
                None => None,
            };
            let explicit_jti = jti.clone();
            let jti = match jti {
                Some(raw) if !raw.trim().is_empty() => raw.trim().to_ascii_lowercase(),
                Some(_) => return Err(anyhow!("`--jti` must not be empty")),
                None => stored_grant.as_ref().map(|grant| grant.jti.clone()).ok_or_else(|| {
                    anyhow!(
                        "no grant jti to revoke for `{node}`; pass `--jti <jti>` or keep a \
                         local grant (`agentlink grant list`)"
                    )
                })?,
            };
            // An explicit jti can name a grant other than the stored one; keep
            // the local file when it does and let the operator clear it.
            let keep_local_grant = !should_remove_local_grant(
                explicit_jti.as_deref(),
                stored_grant.as_ref().map(|grant| grant.jti.as_str()),
            );
            // Advisory prune metadata: only trust the expiry when the stored
            // grant is the one being revoked.
            let grant_exp = stored_grant
                .as_ref()
                .filter(|grant| grant.jti.eq_ignore_ascii_case(&jti))
                .map(|grant| grant.exp_unix);
            let node_id = target.as_ref().map(|target| target.node_id.clone());
            let label = node_id.clone().unwrap_or_else(|| node.clone());

            let _ = issuer_data_dir;
            let data_dir = match revoke_data_dir(data_dir.as_deref()) {
                Ok(dir) => dir,
                Err(err) => {
                    return Err(anyhow!(
                        "{err} `grant revoke-local` only deletes the controller's copy and does \
                         not revoke the node."
                    ));
                }
            };
            let denied = match grant_exp {
                Some(exp) => agentlink_core::grant::add_revoked_jti_until(
                    &data_dir, &jti, Some(exp),
                ),
                None => agentlink_core::grant::add_revoked_jti(&data_dir, &jti),
            }
            .map_err(|err| anyhow!(err.to_string()))?;
            let deny_file = data_dir.join(agentlink_core::grant::REVOKED_GRANTS_FILE);

            let removed = if keep_local_grant {
                false
            } else {
                match &target {
                    Some(target) => match std::fs::remove_file(&target.path) {
                        Ok(()) => true,
                        Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
                        Err(err) => {
                            return Err(anyhow!(
                                "remove local grant {}: {err}",
                                target.path.display()
                            ))
                        }
                    },
                    None => false,
                }
            };
            emit(
                cli.json,
                json!({
                    "node": label.clone(),
                    "jti": jti,
                    "remote": false,
                    "data_dir": data_dir,
                    "deny_file": deny_file,
                    "revoked": true,
                    "deny_list": denied,
                    "removed": removed,
                    "kept_local_grant": keep_local_grant,
                }),
                || {
                    eprintln!(
                        "added jti {jti} to {}; the node rejects that grant on the next request. \
                         A command that already started is not killed. A recorded terminal closes \
                         on its next message.",
                        deny_file.display()
                    );
                    if keep_local_grant {
                        eprintln!(
                            "kept local grant for {label}: `--jti {jti}` does not match the \
                             stored grant; run `agentlink grant revoke-local --node {label}` or \
                             revoke without `--jti` to clear it"
                        );
                    } else if removed {
                        eprintln!("removed local grant for {label}");
                    } else {
                        eprintln!("no local grant file for {label}");
                    }
                },
            );
            Ok(0)
        }
        GrantCommand::Pending { data_dir } => {
            let dir = grant_node_data_dir(data_dir.as_deref())?;
            let now = agentlink_core::util::unix_now();
            let _ = agentlink_core::grant_request::expire_pending(&dir, now);
            let reqs = agentlink_core::grant_request::list_requests(&dir)
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(
                cli.json,
                json!(reqs.iter().map(|r| json!({
                    "request_id": r.request_id,
                    "grantee_id": r.grantee_id,
                    "node_id": r.node_id,
                    "policy": r.policy,
                    "access": r.policy.capability_summary(),
                    "ttl_secs": r.ttl_secs,
                    "status": r.status,
                    "created_unix": r.created_unix,
                    "exp_unix": r.exp_unix,
                    "grant_jti": r.grant_jti,
                })).collect::<Vec<_>>()),
                || {
                    if reqs.is_empty() {
                        println!("no grant requests in {}", dir.display());
                        return;
                    }
                    for r in &reqs {
                        println!(
                            "{:<10} {}  {}  {}  ttl {}  expires unix {}  {}",
                            format!("{:?}:", r.status).to_lowercase(),
                            r.request_id,
                            &r.grantee_id[..16.min(r.grantee_id.len())],
                            r.policy.capability_summary(),
                            r.ttl_secs,
                            r.exp_unix,
                            if r.is_pending(now) { "PENDING" } else { "" }
                        );
                    }
                    eprintln!("allow with `agentlink grant allow <request-id> --data-dir {}`", dir.display());
                    eprintln!("this is not `agentlink approve allow` (held destructive ops).");
                },
            );
            Ok(0)
        }
        GrantCommand::Allow {
            request_id,
            data_dir,
            out,
            policy,
            ttl,
        } => {
            let dir = grant_node_data_dir(data_dir.as_deref())?;
            let now = agentlink_core::util::unix_now();
            let policy = policy.as_deref().map(parse_access).transpose()?;
            let ttl_secs = ttl.as_deref().map(parse_ttl).transpose()?.map(|v| v as u64);
            let (_req, grant) = agentlink_core::grant_request::allow_request_in_dir(
                &dir,
                request_id,
                now,
                policy,
                ttl_secs,
            )
            .map_err(|err| anyhow!(err.to_string()))?;
            let issuer = agentlink_core::grant::load_issuer(&dir)
                .map_err(|err| anyhow!(err.to_string()))?
                .ok_or_else(|| anyhow!("no grant-issuer.json in {}", dir.display()))?;
            let issued = agentlink_core::grant_request::save_issued_grant(&dir, &grant)
                .map_err(|err| anyhow!(err.to_string()))?;
            let path = agentlink_core::grant::save_grant(&config_dir(cli)?, &grant)
                .map_err(|err| anyhow!(err.to_string()))?;
            write_grant_result(cli, out.as_deref(), &grant, &path, &issuer, None)?;
            eprintln!(
                "signed locally on this node; issuer key stayed in {}; issued copy {}",
                dir.display(),
                issued.display()
            );
            Ok(0)
        }
        GrantCommand::Deny {
            request_id,
            data_dir,
        } => {
            let dir = grant_node_data_dir(data_dir.as_deref())?;
            let now = agentlink_core::util::unix_now();
            let req = agentlink_core::grant_request::deny_request(&dir, request_id, now)
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(
                cli.json,
                json!({"request_id": req.request_id, "status": "denied"}),
                || eprintln!("denied grant request {}", req.request_id),
            );
            Ok(0)
        }
        GrantCommand::Prompt {
            request_id,
            data_dir,
            policy,
            ttl,
        } => {
            let dir = grant_node_data_dir(data_dir.as_deref())?;
            let now = agentlink_core::util::unix_now();
            let _ = agentlink_core::grant_request::expire_pending(&dir, now);
            let reqs = agentlink_core::grant_request::list_requests(&dir)
                .map_err(|err| anyhow!(err.to_string()))?;
            let req = if let Some(id) = request_id.as_deref() {
                reqs.into_iter()
                    .find(|r| r.request_id == id)
                    .ok_or_else(|| anyhow!("no grant request {id}"))?
            } else {
                reqs.into_iter()
                    .find(|r| r.is_pending(now))
                    .ok_or_else(|| anyhow!("no pending grant requests in {}", dir.display()))?
            };
            if !req.is_pending(now) {
                return Err(anyhow!(
                    "request {} is not pending ({:?})",
                    req.request_id,
                    req.status
                ));
            }
            let fp = agentlink_core::grant_offer::sha256_ssh_fingerprint(&req.grantee_id)
                .map_err(|err| anyhow!(err.to_string()))?;
            let body = grant_local::request_prompt_body(
                &req.request_id,
                &fp,
                &req.grantee_id,
                &req.policy.capability_summary(),
                req.ttl_secs,
                req.exp_unix,
            );
            let allow = grant_local::decision_prompt(&body)?;
            if allow {
                let issuer = agentlink_core::grant::load_issuer(&dir)
                    .map_err(|err| anyhow!(err.to_string()))?
                    .ok_or_else(|| anyhow!("no grant-issuer.json in {}", dir.display()))?;
                let shrink = grant_local::shrink_grant_prompt(
                    req.policy.preset_name(),
                    req.ttl_secs,
                    policy.clone(),
                    ttl.clone(),
                )?;
                let Some((shrink_policy, shrink_ttl)) = shrink else {
                    eprintln!("已取消签发，待批请求 {} 仍保留（粘贴身份码本身未授权）", req.request_id);
                    return Ok(0);
                };
                let policy = shrink_policy.as_deref().map(parse_access).transpose()?;
                let ttl_secs = shrink_ttl;
                let (_req, grant) = agentlink_core::grant_request::allow_request_in_dir(
                    &dir,
                    &req.request_id,
                    now,
                    policy,
                    ttl_secs,
                )
                .map_err(|err| anyhow!(err.to_string()))?;
                let _ = agentlink_core::grant_request::save_issued_grant(&dir, &grant);
                let path = agentlink_core::grant::save_grant(&config_dir(cli)?, &grant)
                    .map_err(|err| anyhow!(err.to_string()))?;
                write_grant_result(cli, None, &grant, &path, &issuer, None)?;
                eprintln!("signed locally on this node; the issuer key was not sent anywhere");
            } else {
                let denied = agentlink_core::grant_request::deny_request(&dir, &req.request_id, now)
                    .map_err(|err| anyhow!(err.to_string()))?;
                eprintln!("denied grant request {}", denied.request_id);
            }
            Ok(0)
        }
        GrantCommand::Offer {
            policy,
            ttl,
            node,
            offer_ttl,
            relay_fp,
            out,
        } => {
            let operator = Identity::load_or_create(&operator_identity_path(cli)?)
                .map_err(|err| anyhow!(err.to_string()))?;
            let policy = parse_access(&policy)?;
            let ttl_secs = parse_ttl(&ttl)? as u64;
            let offer_ttl_secs = parse_ttl(&offer_ttl)? as u64;
            let now = agentlink_core::util::unix_now();
            let offer = agentlink_core::grant_offer::issue_offer(
                &operator,
                policy,
                ttl_secs,
                now,
                offer_ttl_secs,
                node.as_deref(),
                relay_fp.as_deref(),
            )
            .map_err(|err| anyhow!(err.to_string()))?;
            let card = agentlink_core::grant_offer::encode_offer(&offer)
                .map_err(|err| anyhow!(err.to_string()))?;
            let fp = offer
                .fingerprint()
                .map_err(|err| anyhow!(err.to_string()))?;
            if let Some(path) = out.as_deref() {
                if path == "-" {
                    println!("{card}");
                } else {
                    agentlink_core::util::write_secret(std::path::Path::new(path), card.as_bytes())
                        .map_err(|err| anyhow!(err.to_string()))?;
                    eprintln!("wrote {path}");
                }
            }
            emit(
                cli.json,
                json!({
                    "kind": "controller_offer",
                    "note": "public identity, not a grant, not a credential",
                    "card": card,
                    "grantee_id": offer.grantee_id,
                    "fingerprint": fp,
                    "access": offer.policy.capability_summary(),
                    "ttl_secs": offer.ttl_secs,
                    "offer_exp_unix": offer.exp_unix,
                    "node_id": offer.node_id,
                }),
                || {
                    if out.is_none() {
                        println!("{card}");
                    }
                    eprintln!("这是【控制端】身份码：公开身份，不是授权凭证，也不是 grant token；relay 不能据此授权。");
                    eprintln!("控制端公钥指纹: {fp}");
                    eprintln!("控制端公钥: {}", offer.grantee_id);
                    eprintln!("请求权限: {}", offer.policy.capability_summary());
                    eprintln!("若目标机同意，grant 有效期: {} 秒", offer.ttl_secs);
                    eprintln!("此身份码过期 unix: {}", offer.exp_unix);
                    if let Some(id) = offer.node_id.as_deref() {
                        eprintln!("已绑定目标机公钥: {id}");
                    }
                    eprintln!("请把上面以 {} 开头的整行复制到【目标机】本地运行：", agentlink_core::grant_offer::OFFER_PREFIX);
                    eprintln!("  agentlink grant paste '<身份码>' --data-dir <目标节点数据目录>");
                    eprintln!("然后在目标机核对指纹，再 `grant allow` / `grant prompt` / `grant paste-ui`。已有有效 grant 无需重复粘贴。");
                    eprintln!("文档: docs/grant-offer.md");
                },
            );
            Ok(0)
        }
        GrantCommand::PasteUi {
            data_dir,
            policy,
            ttl,
        } => grant_paste_card(cli, None, data_dir.as_ref(), policy, ttl, true),
        GrantCommand::Paste {
            card,
            data_dir,
            policy,
            ttl,
            prompt,
        } => grant_paste_card(cli, card.as_deref(), data_dir.as_ref(), policy, ttl, *prompt),
        GrantCommand::Request {
            grantee,
            policy,
            ttl,
            data_dir,
        } => {
            let dir = grant_node_data_dir(data_dir.as_deref())?;
            let node_id = local_node_public_id(&dir)?;
            let policy = parse_access(&policy)?;
            let ttl_secs = parse_ttl(&ttl)? as u64;
            let now = agentlink_core::util::unix_now();
            let draft = agentlink_core::grant_request::draft_request(
                grantee, &node_id, policy, ttl_secs, now,
                agentlink_core::grant_request::DEFAULT_REQUEST_TTL_SECS,
            )
            .map_err(|err| anyhow!(err.to_string()))?;
            let stored = agentlink_core::grant_request::submit_request(&dir, &node_id, draft, now)
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(
                cli.json,
                json!({
                    "request_id": stored.request_id,
                    "grantee_id": stored.grantee_id,
                    "node_id": stored.node_id,
                    "access": stored.policy.capability_summary(),
                    "ttl_secs": stored.ttl_secs,
                    "exp_unix": stored.exp_unix,
                    "status": "pending",
                    "note": "not a grant; run grant allow locally to sign",
                }),
                || {
                    eprintln!("recorded pending request {}", stored.request_id);
                    eprintln!("controller: {}", stored.grantee_id);
                    eprintln!("access: {}", stored.policy.capability_summary());
                    eprintln!(
                        "this is not a grant. On this machine allow with:\n  agentlink grant allow {} --data-dir {}",
                        stored.request_id,
                        dir.display()
                    );
                },
            );
            Ok(0)
        }
        GrantCommand::TrustOwner { key, data_dir } => {

            if !is_public_key_hex(&key) {
                return Err(anyhow!("owner key must be a 32-byte ed25519 public key hex"));
            }
            let dir = match data_dir {
                Some(dir) => dir.clone(),
                None => agentlink_core::config::default_data_dir("node")
                    .map_err(|err| anyhow!(err.to_string()))?,
            };
            let keys = agentlink_core::grant::add_owner_key(&dir, &key)
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(
                cli.json,
                json!({"data_dir": dir, "owner_keys": keys}),
                || eprintln!("{}", trust_owner_report(&dir, &keys)),
            );
            Ok(0)
        }
    }
}

fn warn_ca_only(settings: &agentlink_core::ClientSettings) {
    if let Some(warning) =
        agentlink_core::config::ca_only_warning(&settings.fingerprint, settings.trust.as_deref())
    {
        eprintln!("{warning}");
    }
}

async fn client_cmd(client: &Client, action: &ClientAction, json_out: bool) -> Result<i32> {
    match action {
        ClientAction::Create { name, out } => {
            let path = out
                .clone()
                .unwrap_or_else(|| PathBuf::from(format!("{name}.identity.json")));
            let identity =
                Identity::load_or_create(&path).map_err(|err| anyhow!(err.to_string()))?;
            let created = client
                .register_client(name, identity.public_hex())
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(
                json_out,
                json!({"name": name, "id": identity.public_hex(), "path": path, "relay": created}),
                || {
                    eprintln!("registered {name}");
                    eprintln!("id: {}", identity.public_hex());
                    eprintln!("key: {}", path.display());
                },
            );
            Ok(0)
        }
        ClientAction::List => {
            let clients = client
                .list_clients()
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_out, json!({"clients": clients}), || {
                for item in &clients {
                    let state = if item.revoked { "revoked" } else { "active" };
                    println!("{} {} {state}", item.id, item.name);
                }
            });
            Ok(0)
        }
        ClientAction::Grant {
            client: id,
            node,
            access,
        } => {
            let policy = parse_access(access)?;
            client
                .set_client_grant(id, node, policy)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(
                json_out,
                json!({"client": id, "node": node, "access": access}),
                || eprintln!("granted {access} on {node} to {id}"),
            );
            Ok(0)
        }
        ClientAction::Revoke { client: id } => {
            client
                .revoke_client(id)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_out, json!({"revoked": id}), || {
                eprintln!("revoked {id}")
            });
            Ok(0)
        }
    }
}

async fn approve_cmd(client: &Client, action: &ApproveAction, json_out: bool) -> Result<i32> {
    match action {
        ApproveAction::List => {
            let items = client
                .list_approvals()
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_out, json!({"approvals": items}), || {
                for item in &items {
                    println!("{} {} {}", item.approval_id, item.node_id, item.summary);
                }
            });
            Ok(0)
        }
        ApproveAction::Allow { approval_id, node } => {
            client
                .resolve_approval(approval_id, node, true)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_out, json!({"allow": true, "id": approval_id}), || {
                eprintln!("allowed {approval_id}");
            });
            Ok(0)
        }
        ApproveAction::Deny { approval_id, node } => {
            client
                .resolve_approval(approval_id, node, false)
                .await
                .map_err(|err| anyhow!(err.to_string()))?;
            emit(json_out, json!({"allow": false, "id": approval_id}), || {
                eprintln!("denied {approval_id}");
            });
            Ok(0)
        }
    }
}

pub(crate) fn emit(json_mode: bool, value: Value, human: impl FnOnce()) {
    if json_mode {
        println!("{value}");
    } else {
        human();
    }
}

fn encode_payload(path: &str, data: &[u8], truncated: bool) -> String {
    if let Ok(text) = std::str::from_utf8(data) {
        json!({
            "path": path,
            "encoding": "utf-8",
            "content": text,
            "bytes": data.len(),
            "truncated": truncated,
        })
        .to_string()
    } else {
        json!({
            "path": path,
            "encoding": "base64",
            "content_base64": STANDARD.encode(data),
            "bytes": data.len(),
            "truncated": truncated,
        })
        .to_string()
    }
}

fn spawn_shutdown(cancel: CancellationToken) {
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut terminate = signal(SignalKind::terminate()).ok();
            let mut interrupt = signal(SignalKind::interrupt()).ok();
            tokio::select! {
                _ = async {
                    if let Some(terminate) = terminate.as_mut() {
                        terminate.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {}
                _ = async {
                    if let Some(interrupt) = interrupt.as_mut() {
                        interrupt.recv().await;
                    } else {
                        std::future::pending::<()>().await;
                    }
                } => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        cancel.cancel();
    });
}

fn write_node_policy_files(
    data_dir: &std::path::Path,
    allow_cmd: &[String],
    deny_cmd: &[String],
    confirm_timeout: Option<u64>,
    audit_preset: Option<&str>,
) -> Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let limits_path = data_dir.join("limits.json");
    if !allow_cmd.is_empty() || !deny_cmd.is_empty() {
        let limits = serde_json::json!({
            "allow": allow_cmd,
            "deny": deny_cmd,
        });
        std::fs::write(&limits_path, serde_json::to_string_pretty(&limits)?)?;
    } else if !limits_path.exists() {
        let limits = serde_json::json!({
            "allow": [],
            "deny": agentlink_core::sandbox::baseline_deny(),
        });
        std::fs::write(&limits_path, serde_json::to_string_pretty(&limits)?)?;
    }
    let path = data_dir.join("confirm.toml");
    if confirm_timeout.is_some() || !path.exists() {
        let mut policy = if path.exists() {
            toml::from_str::<agentlink_core::confirm::ConfirmPolicy>(&std::fs::read_to_string(
                &path,
            )?)
            .unwrap_or_else(|_| agentlink_core::confirm::ConfirmPolicy::baseline())
        } else {
            agentlink_core::confirm::ConfirmPolicy::baseline()
        };
        if let Some(timeout) = confirm_timeout {
            policy.timeout_secs = timeout;
        }
        std::fs::write(&path, toml::to_string_pretty(&policy)?.as_bytes())?;
    }
    if let Some(preset) = audit_preset {
        let policy = agentlink_core::audit::AuditPolicy::preset(preset)
            .map_err(|err| anyhow!(err.to_string()))?;
        std::fs::create_dir_all(data_dir)?;
        std::fs::write(
            data_dir.join("audit.toml"),
            policy.to_toml().map_err(|err| anyhow!(err.to_string()))?,
        )?;
    }
    Ok(())
}

/// Client wait for official window capture: same env as the node picker,
/// plus 15s slack so a sitting picker is not abandoned by the 120s unary
/// default while the node is still waiting (and so Cancel can be sent).
fn desktop_unary_timeout() -> std::time::Duration {
    let secs = std::env::var("AGENTLINK_PORTAL_PICKER_TIMEOUT_SECS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(90)
        .clamp(5, 600);
    std::time::Duration::from_secs(secs.saturating_add(15))
}

async fn desktop_call(client: &Client, node: &str, name: &str, payload: Value) -> Result<Value> {
    client
        .call_op_timeout(
            node,
            Op::Extension {
                name: name.to_string(),
                payload,
            },
            desktop_unary_timeout(),
        )
        .await
        .map_err(|err| anyhow!(err))
}

/// Pick png/jpeg/webp from an output path extension.
fn screenshot_format_from_path(path: &std::path::Path) -> Option<&'static str> {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.to_ascii_lowercase())
        .as_deref()
    {
        Some("png") => Some("png"),
        Some("webp") => Some("webp"),
        Some("jpg") | Some("jpeg") => Some("jpeg"),
        _ => None,
    }
}

/// Resolve `--format`, including `auto` from the output path (default jpeg).
fn resolve_screenshot_format(requested: &str, out: Option<&std::path::Path>) -> Result<String> {
    let req = requested.trim().to_ascii_lowercase();
    match req.as_str() {
        "png" | "jpeg" | "webp" => Ok(req),
        "jpg" => Ok("jpeg".into()),
        "auto" => Ok(out
            .and_then(screenshot_format_from_path)
            .unwrap_or("jpeg")
            .to_string()),
        other => Err(anyhow!(
            "unsupported screenshot format `{other}`; use png, jpeg, webp, or auto"
        )),
    }
}

fn write_image(value: &Value, path: &std::path::Path) -> Result<()> {
    let encoded = value["data_b64"]
        .as_str()
        .ok_or_else(|| anyhow!("screenshot response has no image"))?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|err| anyhow!("screenshot bytes: {err}"))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, bytes)?;
    Ok(())
}

#[cfg(test)]
mod hyphen_value_cli_tests {
    use super::Cli;
    use clap::Parser;

    #[test]
    fn scroll_accepts_space_separated_negative_dy() {
        let cli = Cli::try_parse_from(["agentlink", "scroll", "node", "--dy", "-3"]).unwrap();
        match cli.command {
            super::Command::Scroll { dy, dx, .. } => {
                assert_eq!(dy, -3);
                assert_eq!(dx, 0);
            }
            other => panic!("expected Scroll, got {other:?}"),
        }
    }

    #[test]
    fn scroll_accepts_negative_x_y() {
        let cli = Cli::try_parse_from([
            "agentlink",
            "scroll",
            "node",
            "--x",
            "-10",
            "--y",
            "20",
            "--dy",
            "-1",
        ])
        .unwrap();
        match cli.command {
            super::Command::Scroll { x, y, dy, .. } => {
                assert_eq!(x.unwrap().as_json(), serde_json::json!(-10));
                assert_eq!(y.unwrap().as_json(), serde_json::json!(20));
                assert_eq!(dy, -1);
            }
            other => panic!("expected Scroll, got {other:?}"),
        }
    }

    #[test]
    fn click_accepts_space_separated_negative_drag_target() {
        let cli = Cli::try_parse_from([
            "agentlink",
            "click",
            "node",
            "100",
            "100",
            "--to-x",
            "-5",
            "--to-y",
            "50",
        ])
        .unwrap();
        match cli.command {
            super::Command::Click(args) => {
                assert_eq!(args.to_x.unwrap().as_json(), serde_json::json!(-5));
                assert_eq!(args.to_y.unwrap().as_json(), serde_json::json!(50));
            }
            other => panic!("expected Click, got {other:?}"),
        }
    }
}

#[cfg(test)]
mod screenshot_format_tests {
    use super::{resolve_screenshot_format, screenshot_format_from_path};
    use std::path::Path;

    #[test]
    fn extension_maps_to_format() {
        assert_eq!(screenshot_format_from_path(Path::new("a.PNG")), Some("png"));
        assert_eq!(screenshot_format_from_path(Path::new("a.webp")), Some("webp"));
        assert_eq!(screenshot_format_from_path(Path::new("a.JPEG")), Some("jpeg"));
        assert_eq!(screenshot_format_from_path(Path::new("a.bin")), None);
    }

    #[test]
    fn auto_uses_out_extension_else_jpeg() {
        assert_eq!(
            resolve_screenshot_format("auto", Some(Path::new("/tmp/x.png"))).unwrap(),
            "png"
        );
        assert_eq!(
            resolve_screenshot_format("auto", Some(Path::new("/tmp/x.webp"))).unwrap(),
            "webp"
        );
        assert_eq!(
            resolve_screenshot_format("auto", Some(Path::new("/tmp/x.bin"))).unwrap(),
            "jpeg"
        );
        assert_eq!(resolve_screenshot_format("auto", None).unwrap(), "jpeg");
    }

    #[test]
    fn explicit_format_wins_over_extension() {
        assert_eq!(
            resolve_screenshot_format("jpeg", Some(Path::new("/tmp/x.png"))).unwrap(),
            "jpeg"
        );
        assert_eq!(resolve_screenshot_format("jpg", None).unwrap(), "jpeg");
    }
}

#[cfg(test)]
mod coord_tests {
    use super::Coord;

    #[test]
    fn parses_pixels_and_fractions() {
        let pixel: Coord = "1920".parse().unwrap();
        assert_eq!(pixel.as_json(), serde_json::json!(1920));
        let fraction: Coord = "0.5".parse().unwrap();
        assert_eq!(fraction.as_json(), serde_json::json!(0.5));
        let zero: Coord = "0".parse().unwrap();
        assert_eq!(zero.as_json(), serde_json::json!(0));
        // A whole float is still emitted as an integer so the node sees pixels.
        let edge: Coord = "1.0".parse().unwrap();
        assert_eq!(edge.as_json(), serde_json::json!(1));
    }

    #[test]
    fn rejects_non_numbers() {
        assert!("left".parse::<Coord>().is_err());
        assert!("inf".parse::<Coord>().is_err());
    }
}


#[cfg(test)]
mod bg_argv_tests {
    use super::{normalize_bg_verb_before_node, normalize_cli_argv};
    use std::ffi::OsString;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    fn as_str(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn list_verb_before_node() {
        let mut args = os(&["agentlink", "bg", "list", "example"]);
        normalize_bg_verb_before_node(&mut args);
        assert_eq!(as_str(&args), ["agentlink", "bg", "example", "list"]);
    }

    #[test]
    fn list_already_node_first_unchanged() {
        let mut args = os(&["agentlink", "bg", "example", "list"]);
        normalize_bg_verb_before_node(&mut args);
        assert_eq!(as_str(&args), ["agentlink", "bg", "example", "list"]);
    }

    #[test]
    fn status_verb_node_id() {
        // Natural verb-first: same trailing order as canonical `bg NODE status ID`.
        let mut args = os(&["agentlink", "bg", "status", "example", "42"]);
        normalize_bg_verb_before_node(&mut args);
        assert_eq!(as_str(&args), ["agentlink", "bg", "example", "status", "42"]);
    }

    #[test]
    fn status_verb_legacy_id_node_still_rewrites() {
        // Older ID-before-NODE order when the id looks hex/numeric and the node does not.
        let mut args = os(&["agentlink", "bg", "status", "42", "example"]);
        normalize_bg_verb_before_node(&mut args);
        assert_eq!(as_str(&args), ["agentlink", "bg", "example", "status", "42"]);
    }

    #[test]
    fn kill_and_output_verb_before_node() {
        let mut kill = os(&["agentlink", "bg", "kill", "box", "7"]);
        normalize_bg_verb_before_node(&mut kill);
        assert_eq!(as_str(&kill), ["agentlink", "bg", "box", "kill", "7"]);

        let mut out = os(&["agentlink", "bg", "output", "tun1000-box", "7"]);
        normalize_bg_verb_before_node(&mut out);
        assert_eq!(
            as_str(&out),
            ["agentlink", "bg", "tun1000-box", "output", "7"]
        );

        // Legacy id-before-node still works when the node name is unambiguous.
        let mut legacy = os(&["agentlink", "bg", "kill", "7", "example"]);
        normalize_bg_verb_before_node(&mut legacy);
        assert_eq!(as_str(&legacy), ["agentlink", "bg", "example", "kill", "7"]);
    }

    #[test]
    fn start_verb_before_node_with_flags() {
        let mut args = os(&[
            "agentlink", "bg", "start", "--cwd", "/tmp", "--env", "A=1", "--env=B=2", "--shell",
            "example", "--", "sleep", "1",
        ]);
        normalize_bg_verb_before_node(&mut args);
        assert_eq!(
            as_str(&args),
            [
                "agentlink", "bg", "example", "start", "--cwd", "/tmp", "--env", "A=1",
                "--env=B=2", "--shell", "--", "sleep", "1",
            ]
        );
    }

    #[test]
    fn global_json_before_bg_still_rewrites() {
        let args = normalize_cli_argv([
            "agentlink",
            "--json",
            "bg",
            "list",
            "example",
        ]);
        assert_eq!(
            as_str(&args),
            ["agentlink", "--json", "bg", "example", "list"]
        );
    }

    #[test]
    fn non_bg_commands_untouched() {
        let mut args = os(&["agentlink", "ls", "example", "/tmp"]);
        normalize_bg_verb_before_node(&mut args);
        assert_eq!(as_str(&args), ["agentlink", "ls", "example", "/tmp"]);
    }
}

#[cfg(test)]
mod find_arg_order_tests {
    use super::{
        find_path_before_pattern_hint, find_unix_predicate_hint, looks_like_find_search_root,
        looks_like_glob_pattern, search_path_before_pattern_hint,
    };
    use std::ffi::OsString;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn detects_path_before_pattern() {
        let hint = find_path_before_pattern_hint("/tmp", Some("*.txt")).expect("hint");
        assert!(hint.contains("Did you mean"));
        assert!(hint.contains("'*.txt'"));
        assert!(hint.contains("/tmp"));
        assert!(find_path_before_pattern_hint("*.txt", Some("/tmp")).is_none());
        assert!(find_path_before_pattern_hint("*.txt", None).is_none());
    }

    #[test]
    fn search_detects_path_before_content_pattern() {
        let hint = search_path_before_pattern_hint("/tmp", Some("needle")).expect("hint");
        assert!(hint.contains("Did you mean"));
        assert!(hint.contains("needle"));
        assert!(hint.contains("/tmp"));
        // Correct order: content pattern then path.
        assert!(search_path_before_pattern_hint("needle", Some("/tmp")).is_none());
        // Both path-like: do not guess.
        assert!(search_path_before_pattern_hint("/tmp", Some("./src")).is_none());
        assert!(search_path_before_pattern_hint("/tmp", None).is_none());
    }

    #[test]
    fn search_root_and_glob_helpers() {
        assert!(looks_like_find_search_root("/tmp"));
        assert!(looks_like_find_search_root("./src"));
        assert!(looks_like_find_search_root("crates/cli"));
        assert!(!looks_like_find_search_root("*.rs"));
        assert!(!looks_like_find_search_root("README"));
        assert!(looks_like_glob_pattern("*.txt"));
        assert!(looks_like_glob_pattern("src/**/*.rs"));
        assert!(!looks_like_glob_pattern("/tmp"));
    }

    #[test]
    fn unix_name_flag_with_path_hint() {
        let hint = find_unix_predicate_hint(&os(&[
            "agentlink", "find", "box", "/tmp", "-name", "*.txt",
        ]))
        .expect("hint");
        assert!(hint.contains("Did you mean"));
        assert!(hint.contains("find <NODE> <PATTERN> [PATH]"));
        assert!(hint.contains("agentlink find box '*.txt' /tmp"));
    }

    #[test]
    fn unix_name_flag_without_path_hint() {
        let hint = find_unix_predicate_hint(&os(&[
            "agentlink", "find", "box", "-name", "*.rs",
        ]))
        .expect("hint");
        assert!(hint.contains("agentlink find box '*.rs'"));
    }

    #[test]
    fn unix_iname_flag_mentions_ignore_case() {
        let hint = find_unix_predicate_hint(&os(&[
            "agentlink", "find", "box", "/tmp", "-iname", "*.TXT",
        ]))
        .expect("hint");
        assert!(hint.contains("--ignore-case"));
        assert!(hint.contains("agentlink find box --ignore-case '*.TXT' /tmp"));
    }

    #[test]
    fn correct_find_order_has_no_hint() {
        assert!(
            find_unix_predicate_hint(&os(&["agentlink", "find", "box", "*.txt", "/tmp"]))
                .is_none()
        );
        assert!(
            find_unix_predicate_hint(&os(&["agentlink", "find", "box", "*.txt"])).is_none()
        );
    }

    #[test]
    fn global_flag_before_find_still_detected() {
        let hint = find_unix_predicate_hint(&os(&[
            "agentlink", "--json", "find", "n", "/tmp", "-name", "*.c",
        ]))
        .expect("hint");
        assert!(hint.contains("agentlink find n '*.c' /tmp"));
    }
}

#[cfg(test)]
mod port_arg_order_tests {
    use super::{
        port_forward_remote, port_reverse_local, port_status_value, port_swapped_arg_hint, Cli,
        Command, PortCommand,
    };
    use clap::Parser;
    use std::ffi::OsString;

    fn os(args: &[&str]) -> Vec<OsString> {
        args.iter().map(OsString::from).collect()
    }

    #[test]
    fn forward_swap_is_hinted() {
        let hint = port_swapped_arg_hint(&os(&[
            "agentlink",
            "port",
            "forward",
            "18080",
            "box",
            "127.0.0.1:80",
        ]))
        .expect("hint");
        assert!(hint.contains("port forward <NODE> <LOCAL_PORT> <REMOTE>"));
        assert!(hint.contains("agentlink port forward box 18080 127.0.0.1:80"));
    }

    #[test]
    fn reverse_swap_is_hinted() {
        let hint = port_swapped_arg_hint(&os(&[
            "agentlink",
            "port",
            "reverse",
            "8080",
            "box",
            "127.0.0.1:3000",
        ]))
        .expect("hint");
        assert!(hint.contains("port reverse <NODE> <REMOTE_PORT> <LOCAL>"));
        assert!(hint.contains("agentlink port reverse box 8080 127.0.0.1:3000"));
    }

    #[test]
    fn correct_order_has_no_hint() {
        assert!(
            port_swapped_arg_hint(&os(&[
                "agentlink",
                "port",
                "forward",
                "box",
                "18080",
                "127.0.0.1:80",
            ]))
            .is_none()
        );
        assert!(
            port_swapped_arg_hint(&os(&["agentlink", "port", "reverse", "box", "8080", "3000"]))
                .is_none()
        );
    }

    #[test]
    fn global_flag_before_port_still_detected() {
        let hint = port_swapped_arg_hint(&os(&[
            "agentlink",
            "--json",
            "port",
            "forward",
            "18080",
            "box",
            "127.0.0.1:80",
        ]))
        .expect("hint");
        assert!(hint.contains("agentlink port forward box 18080 127.0.0.1:80"));
    }

    #[test]
    fn forward_parse_composes_bare_port_tip() {
        // Validation is pure: no client/connect is involved in building this.
        let err = port_forward_remote("8080").unwrap_err().to_string();
        assert!(err.contains("did you mean 127.0.0.1:8080?"));
        let err = port_forward_remote("example.com").unwrap_err().to_string();
        assert!(err.contains("did you mean example.com:<PORT>?"));
        assert_eq!(
            port_forward_remote("example.com:80").unwrap(),
            ("example.com".to_string(), 80)
        );
    }

    #[test]
    fn reverse_parse_accepts_bare_port() {
        assert_eq!(
            port_reverse_local("3000").unwrap(),
            ("127.0.0.1".to_string(), 3000)
        );
        assert_eq!(
            port_reverse_local("10.0.0.5:3000").unwrap(),
            ("10.0.0.5".to_string(), 3000)
        );
        assert!(port_reverse_local("example.com").is_err());
    }

    #[test]
    fn port_status_parses_with_list_alias() {
        for action in ["status", "list"] {
            let cli = Cli::try_parse_from(["agentlink", "port", action]).unwrap();
            match cli.command {
                Command::Port {
                    action: PortCommand::Status,
                } => {}
                other => panic!("expected port status for {action}, got {other:?}"),
            }
        }
    }

    #[test]
    fn port_status_is_empty_and_points_at_process_scoped_maps() {
        let value = port_status_value();
        assert_eq!(value["maps"].as_array().map(Vec::len), Some(0));
        let tip = value["tip"].as_str().unwrap();
        assert!(tip.contains("no durable registry"), "{tip}");
        assert!(tip.contains("agentlink port forward"), "{tip}");
        assert!(tip.contains("agentlink port reverse"), "{tip}");
        let example = value["example"].as_str().unwrap();
        assert!(
            example.contains("agentlink port forward <NODE> <LOCAL_PORT> <REMOTE>"),
            "{example}"
        );
        assert!(
            example.contains("agentlink port reverse <NODE> <REMOTE_PORT> <LOCAL>"),
            "{example}"
        );
    }
}

#[cfg(test)]
mod dir_entry_kind_tests {
    use super::dir_entry_kind;
    use agentlink_core::protocol::DirEntry;

    fn entry(is_dir: bool, is_symlink: bool) -> DirEntry {
        DirEntry {
            name: "x".into(),
            is_dir,
            is_file: !is_dir && !is_symlink,
            is_symlink,
            size: 0,
            modified_unix_ms: None,
            mode: None,
        }
    }

    #[test]
    fn symlink_dir_and_file_kinds() {
        assert_eq!(dir_entry_kind(&entry(false, true)), "l");
        assert_eq!(dir_entry_kind(&entry(true, false)), "d");
        assert_eq!(dir_entry_kind(&entry(false, false)), "-");
    }
}


fn path_is_stdin(path: &std::path::Path) -> bool {
    path.as_os_str() == "-"
}

fn validate_write_path(path: &str) -> Result<()> {
    // Agents often pass `-` meaning stdin (curl/git style). Write's destination
    // is a remote path; `-` would create a literal file.
    if path_is_stdin(std::path::Path::new(path)) {
        return Err(anyhow!(
            "write path cannot be '-' (stdin); pass a remote path and pipe bytes on stdin or use --content TEXT"
        ));
    }
    if agentlink_core::paths::path_trailing_sep(path) {
        return Err(anyhow!(
            "write destination `{path}` ends with a slash; pass a file path (use mkdir if you need a directory)"
        ));
    }
    Ok(())
}

/// Remote path args must not be `-`. Agents treat `-` as stdin (curl/git); using it
/// as a node path creates or reads a literal `cwd/-`.
fn reject_dash_remote_path(kind: &str, path: &str) -> Result<()> {
    if path_is_stdin(std::path::Path::new(path)) {
        Err(anyhow!(
            "{kind} path cannot be '-' (stdin placeholder); pass a real remote path"
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod synonym_alias_tests {
    use super::{Cli, Command};
    use clap::Parser;

    #[test]
    fn edit_alias_parses_as_replace() {
        let cli = Cli::try_parse_from([
            "agentlink",
            "edit",
            "box",
            "/tmp/a",
            "old",
            "new",
            "--all",
        ])
        .expect("edit alias");
        match cli.command {
            Command::Replace {
                node,
                path,
                old,
                new,
                all,
            } => {
                assert_eq!(node, "box");
                assert_eq!(path, "/tmp/a");
                assert_eq!(old, "old");
                assert_eq!(new, "new");
                assert!(all);
            }
            other => panic!("expected Replace, got {other:?}"),
        }
    }

    #[test]
    fn grep_delete_move_sys_aliases() {
        let grep = Cli::try_parse_from(["agentlink", "grep", "box", "needle", "/tmp"]).unwrap();
        assert!(matches!(grep.command, Command::Search(_)));

        let delete = Cli::try_parse_from(["agentlink", "delete", "box", "/tmp/x"]).unwrap();
        assert!(matches!(delete.command, Command::Rm { .. }));

        let remove = Cli::try_parse_from(["agentlink", "remove", "box", "/tmp/x"]).unwrap();
        assert!(matches!(remove.command, Command::Rm { .. }));

        let move_ = Cli::try_parse_from(["agentlink", "move", "box", "/a", "/b"]).unwrap();
        assert!(matches!(move_.command, Command::Mv { .. }));

        let rename = Cli::try_parse_from(["agentlink", "rename", "box", "/a", "/b"]).unwrap();
        assert!(matches!(rename.command, Command::Mv { .. }));

        let sys = Cli::try_parse_from(["agentlink", "sys", "box"]).unwrap();
        assert!(matches!(sys.command, Command::Sysinfo { .. }));
    }

    #[test]
    fn desktop_alias_parses_as_view() {
        let view = Cli::try_parse_from(["agentlink", "view", "n"]).unwrap();
        let desktop = Cli::try_parse_from(["agentlink", "desktop", "n"]).unwrap();

        let node = match view.command {
            Command::View { node, .. } => node,
            other => panic!("expected View, got {other:?}"),
        };
        let alias_node = match desktop.command {
            Command::View { node, .. } => node,
            other => panic!("expected View via desktop alias, got {other:?}"),
        };
        assert_eq!(node, "n");
        assert_eq!(alias_node, node);
    }

    #[test]
    fn mkdir_p_and_rm_r_short_flags() {
        let mkdir = Cli::try_parse_from(["agentlink", "mkdir", "-p", "box", "/tmp/a/b"]).unwrap();
        match mkdir.command {
            Command::Mkdir {
                node,
                path,
                parents,
            } => {
                assert_eq!(node, "box");
                assert_eq!(path, "/tmp/a/b");
                assert!(parents);
            }
            other => panic!("expected Mkdir, got {other:?}"),
        }

        let rm = Cli::try_parse_from(["agentlink", "rm", "-r", "box", "/tmp/a"]).unwrap();
        match rm.command {
            Command::Rm {
                node,
                path,
                recursive,
            } => {
                assert_eq!(node, "box");
                assert_eq!(path, "/tmp/a");
                assert!(recursive);
            }
            other => panic!("expected Rm, got {other:?}"),
        }

        let rm_r = Cli::try_parse_from(["agentlink", "rm", "-R", "box", "/tmp/a"]).unwrap();
        assert!(matches!(
            rm_r.command,
            Command::Rm {
                recursive: true,
                ..
            }
        ));
    }

    #[test]
    fn path_dash_means_stdin() {
        assert!(super::path_is_stdin(std::path::Path::new("-")));
        assert!(!super::path_is_stdin(std::path::Path::new("patch.diff")));
    }

    #[test]
    fn write_rejects_dash_path_at_parse_site() {
        // CLI parses `write NODE -` fine; runtime must refuse before upload.
        // Guard the helper agents rely on so regressing path_is_stdin breaks tests.
        assert!(super::path_is_stdin(std::path::Path::new("-")));
        assert!(super::validate_write_path("-").is_err());
        let cli = Cli::try_parse_from(["agentlink", "write", "box", "-"]).expect("parses");
        match cli.command {
            Command::Write { path, .. } => assert_eq!(path, "-"),
            other => panic!("expected Write, got {other:?}"),
        }
    }

    #[test]
    fn write_rejects_trailing_separator_before_upload() {
        for path in ["/tmp/new-dir/", r"C:\tmp\new-dir\"] {
            let err = super::validate_write_path(path).unwrap_err().to_string();
            assert!(err.contains("ends with a slash"), "{err}");
            assert!(err.contains("pass a file path"), "{err}");
            assert!(err.contains("mkdir"), "{err}");
        }
        assert!(super::validate_write_path("/tmp/file.txt").is_ok());
    }

    #[test]
    fn reject_dash_remote_path_helper() {
        assert!(super::reject_dash_remote_path("mkdir", "-").is_err());
        assert!(super::reject_dash_remote_path("cat", "/tmp/x").is_ok());
        let mkdir = Cli::try_parse_from(["agentlink", "mkdir", "box", "-"]).unwrap();
        assert!(matches!(mkdir.command, Command::Mkdir { path, .. } if path == "-"));
        let cat = Cli::try_parse_from(["agentlink", "cat", "box", "-"]).unwrap();
        assert!(matches!(cat.command, Command::Cat { path, .. } if path == "-"));
    }

    #[test]
    fn reject_flag_like_program_catches_timeout_ms() {
        let err = super::reject_flag_like_program(
            "exec",
            &["--timeout-ms".into(), "5000".into(), "/bin/echo".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("looks like a CLI flag"), "{err}");
        assert!(err.contains("--timeout-secs"), "{err}");
        assert!(super::reject_flag_like_program("exec", &["/bin/echo".into(), "hi".into()]).is_ok());
        assert!(super::reject_flag_like_program("exec", &["-".into()]).is_ok());
    }

    #[test]
    fn reject_flag_like_program_rejects_whitespace_only() {
        let err = super::reject_flag_like_program("exec", &["   ".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("command is empty"), "{err}");
        let err = super::reject_flag_like_program("bg start", &["\t\n".into()])
            .unwrap_err()
            .to_string();
        assert!(err.contains("command is empty"), "{err}");
        assert!(super::reject_flag_like_program("exec", &[])
            .unwrap_err()
            .to_string()
            .contains("command is empty"));
    }

    #[test]
    fn message_mentions_os_error_respects_digit_boundary() {
        assert!(super::message_mentions_os_error("io: No such file or directory (os error 2)", 2));
        assert!(super::message_mentions_os_error("os error 2", 2));
        assert!(!super::message_mentions_os_error("io: Not a directory (os error 20)", 2));
        assert!(super::message_mentions_os_error("io: Not a directory (os error 20)", 20));
    }

    #[test]
    fn mkdir_error_hint_permission_forms_fall_through() {
        for msg in super::MKDIR_DEST_PERMISSION_FORMS {
            assert!(
                super::mkdir_error_hint(msg, "tun1000-box", "/srv/app/releases/v2", false)
                    .is_none(),
                "{msg}"
            );
            assert!(
                super::mkdir_error_hint(msg, "tun1000-box", "/srv/app/releases/v2", true)
                    .is_none(),
                "{msg}"
            );
        }
        // Existing EEXIST / ENOENT / ENOTDIR hints still win.
        assert!(super::mkdir_error_hint(
            "mkdir `/srv/app` already exists as a directory",
            "n",
            "/srv/app",
            false,
        )
        .is_some());
        assert!(super::mkdir_error_hint(
            "io: No such file or directory (os error 2)",
            "n",
            "/srv/app/x",
            false,
        )
        .is_some());
        assert!(super::mkdir_error_hint(
            "io: Not a directory (os error 20)",
            "n",
            "/srv/app/file/x",
            true,
        )
        .is_some());
    }

    #[test]
    fn mkdir_error_hint_enoent_suggests_parents() {
        let msg = "io: No such file or directory (os error 2)";
        let hint = super::mkdir_error_hint(msg, "tun1000-box", "/tmp/a/b", false).unwrap();
        assert!(hint.contains("Pass `-p`/`--parents`"), "{hint}");
        assert!(hint.contains("/tmp/a/b -p"), "{hint}");
        assert!(super::mkdir_error_hint(msg, "n", "/tmp/a/b", true).is_none());
    }

    #[test]
    fn mkdir_error_hint_enotdir_does_not_suggest_parents() {
        let msg = "io: Not a directory (os error 20)";
        let hint = super::mkdir_error_hint(msg, "tun1000-box", "/tmp/file/child", false).unwrap();
        assert!(hint.contains("exists but is not a directory"), "{hint}");
        assert!(!hint.contains("Pass `-p`/`--parents` to create intermediate"), "{hint}");
        // Substring trap: os error 20 must not be treated as ENOENT.
        assert!(!super::looks_like_enoent_message(msg), "os error 20 matched ENOENT");
        assert!(super::looks_like_enotdir_message(msg));
        // -p still tips ENOTDIR (parents only suppresses ENOENT).
        let hint_p = super::mkdir_error_hint(msg, "tun1000-box", "/tmp/file/child", true).unwrap();
        assert!(hint_p.contains("exists but is not a directory"), "{hint_p}");
        // Node already diagnosed: no double tip.
        assert!(super::mkdir_error_hint(
            "path component `/tmp/file` exists but is not a directory; `-p`/`--parents` cannot fix that — pick a different path or remove the blocking file",
            "n",
            "/tmp/file/child",
            true,
        )
        .is_none());
    }

    #[test]
    fn exec_cwd_error_hint_enotdir_does_not_suggest_mkdir() {
        let msg = "cwd /tmp/file: Not a directory";
        let hint = super::exec_cwd_error_hint(msg, "/tmp/file").unwrap();
        assert!(hint.contains("exists but is not a directory"), "{hint}");
        assert!(!hint.contains("mkdir"), "{hint}");
        assert!(hint.contains("`--cwd`"), "{hint}");
    }

    #[test]
    fn exec_cwd_error_hint_enoent_suggests_mkdir() {
        let msg = "cwd /tmp/missing: No such file or directory (os error 2)";
        let hint = super::exec_cwd_error_hint(msg, "/tmp/missing").unwrap();
        assert!(hint.contains("mkdir -p"), "{hint}");
        assert!(hint.contains("/tmp/missing"), "{hint}");
        assert!(super::exec_cwd_error_hint("spawn boom", "/tmp/x").is_none());
    }

    #[test]
    fn hint_exec_timeout_adds_raise_tip() {
        let err = super::hint_exec_timeout("timed out", 60).to_string();
        assert!(err.contains("tip: timed out after 60s"), "{err}");
        assert!(err.contains("--timeout-secs N"), "{err}");
        assert!(err.contains("0 waits forever"), "{err}");
    }

    #[test]
    fn hint_exec_timeout_mentions_short_limit() {
        let err = super::hint_exec_timeout("timed out", 1).to_string();
        assert!(err.contains("timed out after 1s"), "{err}");
        assert!(!err.contains("after 10s"), "{err}");
    }

    #[test]
    fn hint_exec_timeout_passes_through_unrelated_errors() {
        assert_eq!(
            super::hint_exec_timeout("spawn boom", 60).to_string(),
            "spawn boom"
        );
        assert_eq!(
            super::hint_exec_timeout("pty timed out: exit", 60).to_string(),
            "pty timed out: exit"
        );
    }

    #[test]
    fn hint_exec_timeout_zero_does_not_claim_cli_limit() {
        let err = super::hint_exec_timeout("timed out", 0).to_string();
        assert!(!err.contains("timed out after"), "{err}");
        assert!(err.contains("--timeout-secs 0"), "{err}");
    }

    #[test]
    fn hint_exec_timeout_keeps_cwd_hint() {
        let cwd_err = "cwd /tmp/missing: No such file or directory (os error 2)";
        let err = super::hint_exec_timeout(
            super::hint_exec_cwd_missing(cwd_err, Some("/tmp/missing")),
            60,
        )
        .to_string();
        assert!(err.contains("mkdir -p"), "{err}");
        assert!(!err.contains("timed out after"), "{err}");
    }

    #[test]
    fn hint_cp_error_enoent_adds_source_tip() {
        let err = super::hint_cp_error("/tmp/no-such: No such file or directory").to_string();
        assert!(err.contains("tip: check the source path exists"), "{err}");
        assert!(err.contains("node://<name>/abs/or/home-relative"), "{err}");
    }

    #[test]
    fn hint_cp_error_permission_adds_dest_tip() {
        let err = super::hint_cp_error("io: Permission denied (os error 13)").to_string();
        assert!(
            err.contains("tip: need write access to the destination"),
            "{err}"
        );
        assert!(err.contains("agentlink-node user"), "{err}");
    }

    #[test]
    fn hint_cp_error_dedupes_doubled_permission_denied() {
        let doubled = "io: Permission denied (os error 13): Permission denied (os error 13)";
        let err = super::hint_cp_error(doubled).to_string();
        assert_eq!(
            err.matches("Permission denied (os error 13)").count(),
            1,
            "{err}"
        );
        assert!(err.contains("tip: need write access"), "{err}");
    }

    #[test]
    fn hint_cp_error_special_file_adds_regular_files_tip() {
        let msg = "/tmp/fifo is not a regular file (refusing fifo/socket/device)";
        let err = super::hint_cp_error(msg).to_string();
        assert!(err.contains("tip: cp copies regular files"), "{err}");
        assert!(err.contains("not devices, fifos, or sockets"), "{err}");
    }

    #[test]
    fn hint_cp_error_passes_through_unrelated_errors() {
        assert_eq!(
            super::hint_cp_error("relay unavailable").to_string(),
            "relay unavailable"
        );
    }

    #[test]
    fn hint_cat_error_enoent_adds_remote_path_tip() {
        let err = super::hint_fs_error(
            "/tmp/no-such: No such file or directory",
            super::FsHint::Cat,
        )
        .to_string();
        assert!(
            err.contains("tip: check the remote path exists on the node"),
            "{err}"
        );
    }

    #[test]
    fn hint_write_error_enoent_adds_parent_dir_tip() {
        let err = super::hint_fs_error(
            "/tmp/no-such/file: No such file or directory",
            super::FsHint::Write,
        )
        .to_string();
        assert!(
            err.contains("tip: check the remote path's parent directory exists on the node"),
            "{err}"
        );
    }

    #[test]
    fn hint_write_error_permission_adds_write_access_tip() {
        let err = super::hint_fs_error("io: Permission denied (os error 13)", super::FsHint::Write)
            .to_string();
        assert!(
            err.contains(
                "tip: the agentlink-node user needs write access to that path (and its parent)"
            ),
            "{err}"
        );
    }

    #[test]
    fn hint_write_error_path_component_not_dir_adds_tip() {
        let msg = "path component `/tmp/al-file-not-dir-136` exists but is not a directory; cannot create parent directories for write/cp";
        let err = super::hint_fs_error(msg, super::FsHint::Write).to_string();
        assert!(
            err.contains("tip: a path component is a file (or other non-dir)"),
            "{err}"
        );
        assert!(err.contains("creating parents cannot fix that"), "{err}");
    }

    #[test]
    fn hint_cp_error_path_component_not_dir_adds_tip() {
        let msg = "path component `/tmp/al-file-not-dir-136` exists but is not a directory; cannot create parent directories for write/cp";
        let err = super::hint_cp_error(msg).to_string();
        assert!(
            err.contains("tip: a path component is a file (or other non-dir)"),
            "{err}"
        );
        assert!(err.contains("creating parents cannot fix that"), "{err}");
    }

    #[test]
    fn hint_cp_error_bare_enotdir_adds_tip() {
        let err = super::hint_cp_error("/tmp/file/child: Not a directory (os error 20)").to_string();
        assert!(
            err.contains("tip: a path component is a file (or other non-dir)"),
            "{err}"
        );
        assert!(err.contains("creating parents cannot fix that"), "{err}");
    }

    #[test]
    fn hint_write_error_bare_enotdir_adds_tip() {
        let err = super::hint_fs_error("ENOTDIR", super::FsHint::Write).to_string();
        assert!(
            err.contains("tip: a path component is a file (or other non-dir)"),
            "{err}"
        );
    }

    #[test]
    fn hint_cat_error_not_dir_adds_tip() {
        let err = super::hint_fs_error("/tmp/file/child: Not a directory", super::FsHint::Cat)
            .to_string();
        assert!(
            err.contains("tip: a path component is a file (or other non-dir)"),
            "{err}"
        );
        assert!(
            err.contains("check the path for a file where a directory is expected"),
            "{err}"
        );
    }

    #[test]
    fn hint_cat_error_eisdir_adds_ls_tip() {
        let err = super::hint_fs_error(
            "/tmp/some-dir: Is a directory (os error 21)",
            super::FsHint::Cat,
        )
        .to_string();
        assert!(
            err.contains("tip: that path is a directory, not a file"),
            "{err}"
        );
        assert!(
            err.contains("list it with `agentlink ls <node> <path>`"),
            "{err}"
        );
        assert!(
            err.contains("`agentlink cat` prints regular files only"),
            "{err}"
        );
        assert_eq!(err.matches("tip:").count(), 1, "{err}");
    }

    #[test]
    fn hint_cat_error_eisdir_tip_is_idempotent() {
        let once = super::hint_fs_error("EISDIR", super::FsHint::Cat).to_string();
        let twice = super::hint_fs_error(once.clone(), super::FsHint::Cat).to_string();
        assert_eq!(once, twice);
        assert_eq!(twice.matches("tip:").count(), 1, "{twice}");
    }

    #[test]
    fn hint_write_error_eisdir_adds_ls_tip() {
        let err =
            super::hint_fs_error("/tmp/some-dir: Is a directory", super::FsHint::Write).to_string();
        assert!(
            err.contains("tip: that path is a directory, not a file"),
            "{err}"
        );
        assert!(
            err.contains("list it with `agentlink ls <node> <path>`"),
            "{err}"
        );
    }

    #[test]
    fn hint_cp_error_eisdir_adds_tree_tip() {
        let err = super::hint_cp_error("/tmp/some-dir: Is a directory (os error 21)").to_string();
        assert!(
            err.contains("tip: that source is a directory, not a regular file"),
            "{err}"
        );
        assert!(err.contains("copy the tree with"), "{err}");
    }

    #[test]
    fn hint_fs_error_eisdir_leaves_other_failures_alone() {
        for (msg, kind) in [
            ("io: Permission denied (os error 13)", super::FsHint::Cat),
            ("/tmp/file/child: Not a directory (os error 20)", super::FsHint::Cat),
            ("relay unavailable", super::FsHint::Cat),
            ("os error 210 while reading", super::FsHint::Cat),
        ] {
            let err = super::hint_fs_error(msg, kind).to_string();
            assert!(!err.contains("list it with"), "{err}");
        }
    }

    #[test]
    fn hint_fs_error_passes_through_unrelated_errors() {
        assert_eq!(
            super::hint_fs_error("relay unavailable", super::FsHint::Write).to_string(),
            "relay unavailable"
        );
    }

    #[test]
    fn format_cp_progress_shows_human_sizes_and_percent() {
        let line = super::format_cp_progress(6 * 1024 * 1024, 8 * 1024 * 1024, 1.5, Some(2));
        assert_eq!(line, "6.0 MiB / 8.0 MiB  1.5 MiB/s  75%  eta 2s");
    }

    #[test]
    fn format_cp_progress_uses_kib_and_gib_scales() {
        let kib = super::format_cp_progress(512, 2048, 0.1, None);
        assert_eq!(kib, "512 B / 2.0 KiB  0.1 MiB/s  25%  eta --");
        let gib = super::format_cp_progress(
            1024 * 1024 * 1024,
            3 * 1024 * 1024 * 1024,
            2.0,
            None,
        );
        assert_eq!(gib, "1.0 GiB / 3.0 GiB  2.0 MiB/s  33%  eta --");
    }

    #[test]
    fn cp_progress_clear_seq_erases_width_then_newline() {
        let seq = super::cp_progress_clear_seq(7);
        assert_eq!(seq, format!("\r{}\r\n", " ".repeat(7)));
        assert!(seq.starts_with('\r'), "{seq:?}");
        assert!(seq.ends_with("\r\n"), "{seq:?}");
        assert_eq!(seq.chars().filter(|c| *c == ' ').count(), 7);
    }

    #[test]
    fn cp_progress_clear_seq_pads_at_least_one_column() {
        assert_eq!(super::cp_progress_clear_seq(0), "\r \r\n");
    }

    #[test]
    fn progress_width_keeps_max_across_updates() {
        let width = std::sync::atomic::AtomicUsize::new(0);
        for n in [40, 96, 61, 80] {
            width.fetch_max(n, std::sync::atomic::Ordering::Release);
        }
        assert_eq!(width.load(std::sync::atomic::Ordering::Acquire), 96);
    }

    #[test]
    fn reject_empty_shell_command_blank_only() {
        assert!(super::reject_empty_shell_command(None).is_ok());
        assert!(super::reject_empty_shell_command(Some("pwd")).is_ok());
        assert!(super::reject_empty_shell_command(Some("  echo hi  ")).is_ok());
        let err = super::reject_empty_shell_command(Some(""))
            .unwrap_err()
            .to_string();
        assert!(err.contains("shell: --command is empty"), "{err}");
        let err = super::reject_empty_shell_command(Some(" \t\n "))
            .unwrap_err()
            .to_string();
        assert!(err.contains("shell: --command is empty"), "{err}");
    }

    #[test]
    fn exec_parses_unknown_flag_after_node_into_cmd() {
        // Document clap behavior this guard exists for: after NODE, unknown
        // hyphen args land in trailing `cmd` instead of a clap error.
        let cli = Cli::try_parse_from([
            "agentlink",
            "exec",
            "box",
            "--timeout-ms",
            "5000",
            "--",
            "/bin/echo",
            "hi",
        ])
        .unwrap();
        match cli.command {
            Command::Exec { cmd, .. } => {
                assert_eq!(cmd[0], "--timeout-ms");
                assert_eq!(cmd[1], "5000");
            }
            _ => panic!("expected Exec"),
        }
    }
}


#[cfg(test)]
mod exec_env_tests {
    use super::{parse_env_pairs, normalize_cli_argv, Cli, Command, BgCommand};
    use clap::Parser;

    #[test]
    fn parse_env_pairs_ok_and_rejects() {
        let ok = parse_env_pairs(&[
            "FOO=bar".into(),
            "EMPTY=".into(),
            "PATH=/a:/b".into(),
        ])
        .unwrap();
        assert_eq!(
            ok,
            vec![
                ("FOO".into(), "bar".into()),
                ("EMPTY".into(), "".into()),
                ("PATH".into(), "/a:/b".into()),
            ]
        );
        assert!(parse_env_pairs(&["NOEQUALS".into()]).is_err());
        assert!(parse_env_pairs(&["".into()]).is_err());
        assert!(parse_env_pairs(&["=noval".into()]).is_err());
    }

    #[test]
    fn exec_parses_repeatable_env() {
        let cli = Cli::try_parse_from([
            "agentlink",
            "exec",
            "box",
            "--env",
            "A=1",
            "--env",
            "B=two=parts",
            "--",
            "printenv",
            "A",
        ])
        .expect("exec --env");
        match cli.command {
            Command::Exec { env, cmd, .. } => {
                assert_eq!(env, vec!["A=1".to_string(), "B=two=parts".to_string()]);
                assert_eq!(cmd, vec!["printenv".to_string(), "A".to_string()]);
            }
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn bg_start_parses_env_and_normalize_skips() {
        let cli = Cli::try_parse_from([
            "agentlink",
            "bg",
            "box",
            "start",
            "--cwd",
            "/tmp",
            "--env",
            "K=V",
            "--shell",
            "echo",
            "hi",
        ])
        .expect("bg start --env");
        match cli.command {
            Command::Bg {
                action: BgCommand::Start {
                    cwd,
                    env,
                    shell,
                    cmd,
                },
                ..
            } => {
                assert_eq!(cwd.as_deref(), Some("/tmp"));
                assert_eq!(env, vec!["K=V".to_string()]);
                assert!(shell);
                assert_eq!(cmd, vec!["echo".to_string(), "hi".to_string()]);
            }
            other => panic!("expected Bg Start, got {other:?}"),
        }

        // Verb-first form: skip --env/--cwd when locating NODE so NODE is not eaten.
        let argv = normalize_cli_argv([
            "agentlink",
            "bg",
            "start",
            "--env",
            "K=V",
            "--env=X=Y",
            "--cwd",
            "/tmp",
            "box",
            "myprog",
            "--flag",
        ]);
        let got: Vec<String> = argv
            .iter()
            .map(|s| s.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            got,
            vec![
                "agentlink",
                "bg",
                "box",
                "start",
                "--env",
                "K=V",
                "--env=X=Y",
                "--cwd",
                "/tmp",
                "myprog",
                "--flag",
            ],
            "{got:?}"
        );
    }
}

#[cfg(test)]
mod cp_done_tests {
    use super::format_cp_done;
    use agentlink_core::protocol::TransferStats;

    fn stats(logical: u64, payload: u64, skipped: bool, files: u32, files_skipped: u32) -> TransferStats {
        TransferStats {
            logical_bytes: logical,
            payload_bytes: payload,
            skipped,
            files,
            files_skipped,
            compressed: false,
            transport: "quic".into(),
            delta_copy_bytes: 0,
            resumed_bytes: 0,
        }
    }

    #[test]
    fn identical_single_file_says_up_to_date() {
        assert_eq!(
            format_cp_done(&stats(18, 0, true, 1, 1)),
            "already up to date; skipped 18 bytes (transport quic)"
        );
    }

    #[test]
    fn identical_multi_file_counts_files() {
        assert_eq!(
            format_cp_done(&stats(4096, 0, true, 3, 3)),
            "already up to date; skipped 3/3 files, 4.0 KiB (transport quic)"
        );
    }

    #[test]
    fn all_files_skipped_without_flag_still_up_to_date() {
        assert_eq!(
            format_cp_done(&stats(18, 0, false, 1, 1)),
            "already up to date; skipped 18 bytes (transport quic)"
        );
    }

    #[test]
    fn copied_path_unchanged() {
        assert_eq!(
            format_cp_done(&stats(4096, 1024, false, 2, 1)),
            "copied 4.0 KiB (payload 1.0 KiB, transport quic)"
        );
    }

    #[test]
    fn copied_humanizes_mib_and_keeps_small_bytes() {
        assert_eq!(
            format_cp_done(&stats(4 * 1024 * 1024, 4 * 1024 * 1024, false, 1, 0)),
            "copied 4.0 MiB (payload 4.0 MiB, transport quic)"
        );
        assert_eq!(
            format_cp_done(&stats(18, 0, false, 1, 0)),
            "copied 18 bytes (payload 0 bytes, transport quic)"
        );
    }
}

#[cfg(test)]
mod cp_progress_tests {
    use std::time::{Duration, Instant};

    use agentlink_core::protocol::TransferStats;
    use clap::{CommandFactory, Parser};
    use serde_json::Value;

    use super::{
        cp_done_value, cp_eta_secs, cp_newline_due, cp_progress_style, cp_rate_mib,
        format_cp_progress, format_eta_secs, render_cp_progress_update, Cli, Command, CpProgress,
        CpProgressMode, CpProgressStyle,
    };

    fn sample_stats() -> TransferStats {
        TransferStats {
            logical_bytes: 8 * 1024 * 1024,
            payload_bytes: 8 * 1024 * 1024,
            skipped: false,
            files: 3,
            files_skipped: 1,
            compressed: false,
            transport: "relay".into(),
            delta_copy_bytes: 0,
            resumed_bytes: 0,
        }
    }

    fn cp_progress(args: &[&str]) -> CpProgressMode {
        let mut full = vec!["agentlink", "cp"];
        full.extend_from_slice(args);
        let cli = Cli::try_parse_from(full).unwrap_or_else(|err| panic!("{err}"));
        match cli.command {
            Command::Cp(args) => args.progress,
            other => panic!("expected cp, got {other:?}"),
        }
    }

    #[test]
    fn progress_flag_defaults_to_auto_and_bare_flag_is_on() {
        assert_eq!(cp_progress(&["./a", "node://box/b"]), CpProgressMode::Auto);
        assert_eq!(
            cp_progress(&["--progress", "./a", "node://box/b"]),
            CpProgressMode::On
        );
        assert_eq!(
            cp_progress(&["--progress=off", "./a", "node://box/b"]),
            CpProgressMode::Off
        );
        assert_eq!(
            cp_progress(&["--progress=on", "./a", "node://box/b"]),
            CpProgressMode::On
        );
        assert_eq!(
            cp_progress(&["--progress=auto", "./a", "node://box/b"]),
            CpProgressMode::Auto
        );
        let err = Cli::try_parse_from([
            "agentlink",
            "cp",
            "--progress=sometimes",
            "./a",
            "node://box/b",
        ])
        .unwrap_err()
        .to_string();
        assert!(err.contains("auto") && err.contains("off"), "{err}");
    }

    #[test]
    fn progress_flag_with_json_does_not_change_the_mode() {
        let cli = Cli::try_parse_from([
            "agentlink",
            "--json",
            "cp",
            "--progress=on",
            "./a",
            "node://box/b",
        ])
        .unwrap();
        assert!(cli.json);
        match cli.command {
            Command::Cp(args) => assert_eq!(args.progress, CpProgressMode::On),
            other => panic!("expected cp, got {other:?}"),
        }
    }

    #[test]
    fn cli_command_and_parse_fit_on_default_two_mib_test_stack() {
        let handle = std::thread::Builder::new()
            .name("cli-2mib-stack".into())
            .stack_size(2 * 1024 * 1024)
            .spawn(|| {
                let mut cmd = Cli::command();
                let help = cmd.render_long_help().to_string();
                assert!(help.contains("relay") && help.contains("controller"));
                let parsed = Cli::try_parse_from([
                    "agentlink",
                    "--json",
                    "cp",
                    "--progress=on",
                    "./a",
                    "node://box/b",
                ])
                .expect("parse cp on 2 MiB stack");
                assert!(parsed.json);
            })
            .expect("spawn 2 MiB thread");
        handle.join().expect("2 MiB thread must not overflow stack");
    }

    #[test]
    fn cp_help_documents_progress() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("cp")
            .expect("cp")
            .render_long_help()
            .to_string();
        assert!(help.contains("--progress"), "{help}");
        assert!(help.contains("auto"), "{help}");
        assert!(help.contains("stderr"), "{help}");
        assert!(help.contains("ETA") || help.contains("eta"), "{help}");
        assert!(help.contains("--json") || help.contains("json"), "{help}");
        assert!(help.contains("overall"), "{help}");
    }

    #[test]
    fn progress_style_is_tty_for_auto_and_forced_for_on() {
        assert_eq!(
            cp_progress_style(CpProgressMode::Auto, true),
            CpProgressStyle::CarriageReturn
        );
        assert_eq!(
            cp_progress_style(CpProgressMode::Auto, false),
            CpProgressStyle::Quiet
        );
        assert_eq!(
            cp_progress_style(CpProgressMode::On, true),
            CpProgressStyle::CarriageReturn
        );
        assert_eq!(
            cp_progress_style(CpProgressMode::On, false),
            CpProgressStyle::Newline
        );
        assert_eq!(
            cp_progress_style(CpProgressMode::Off, true),
            CpProgressStyle::Quiet
        );
        assert_eq!(
            cp_progress_style(CpProgressMode::Off, false),
            CpProgressStyle::Quiet
        );
    }

    #[test]
    fn quiet_progress_installs_no_transfer_hook() {
        // Upload and download share this hook. Off, and auto without a tty, stay quiet.
        assert!(CpProgress::start(CpProgressStyle::Quiet).hook().is_none());
        assert!(CpProgress::start(CpProgressStyle::CarriageReturn)
            .hook()
            .is_some());
        assert!(CpProgress::start(CpProgressStyle::Newline).hook().is_some());
    }

    #[test]
    fn json_stdout_is_one_object_and_progress_stays_on_its_own_line() {
        let stdout = cp_done_value(&sample_stats()).to_string();
        let parsed: Value = serde_json::from_str(&stdout).expect("cp --json stdout is one value");
        assert_eq!(parsed["event"], "done");
        assert_eq!(parsed["stats"]["files"], 3);
        assert_eq!(parsed["stats"]["logical_bytes"], 8 * 1024 * 1024);
        assert!(parsed.get("sent").is_none(), "{parsed}");
        assert!(!stdout.contains("progress"), "{stdout}");

        let line = format_cp_progress(6 * 1024 * 1024, 8 * 1024 * 1024, 1.5, Some(4));
        assert!(line.contains("6.0 MiB / 8.0 MiB"), "{line}");
        assert!(line.contains("1.5 MiB/s"), "{line}");
        assert!(line.contains("75%"), "{line}");
        assert!(line.contains("eta 4s"), "{line}");
        let stderr_cr = render_cp_progress_update(CpProgressStyle::CarriageReturn, &line);
        let stderr_nl = render_cp_progress_update(CpProgressStyle::Newline, &line);
        assert!(stderr_cr.starts_with('\r'), "{stderr_cr:?}");
        assert!(!stderr_cr.contains('\n'), "{stderr_cr:?}");
        assert!(
            stderr_nl.ends_with('\n') && !stderr_nl.contains('\r'),
            "{stderr_nl:?}"
        );
        assert!(render_cp_progress_update(CpProgressStyle::Quiet, &line).is_empty());
        // Human progress on the same stream as the JSON object would not parse.
        assert!(serde_json::from_str::<Value>(&format!("{stderr_cr}{stdout}")).is_err());
        assert!(serde_json::from_str::<Value>(&format!("{stderr_nl}{stdout}")).is_err());
        assert!(serde_json::from_str::<Value>(&stdout).is_ok());
    }

    #[test]
    fn unknown_total_omits_percent_and_eta_scales() {
        assert_eq!(
            format_cp_progress(4096, 0, 0.5, None),
            "4.0 KiB  0.5 MiB/s"
        );
        assert_eq!(format_eta_secs(0), "0s");
        assert_eq!(format_eta_secs(59), "59s");
        assert_eq!(format_eta_secs(90), "1m30s");
        assert_eq!(format_eta_secs(3600 + 120), "1h02m");
    }

    #[test]
    fn rate_and_eta_ignore_bytes_already_present() {
        assert!((cp_rate_mib(0, 1024 * 1024, 1.0) - 1.0).abs() < 1e-9);
        assert!((cp_rate_mib(90 * 1024 * 1024, 91 * 1024 * 1024, 1.0) - 1.0).abs() < 1e-9);
        assert_eq!(cp_rate_mib(0, 0, 0.0), 0.0);
        assert_eq!(
            cp_eta_secs(0, 1024 * 1024, 4 * 1024 * 1024, 1.0),
            Some(3)
        );
        assert_eq!(cp_eta_secs(0, 100, 1000, 0.1), None);
        assert_eq!(cp_eta_secs(90, 90, 100, 1.0), None);
        assert_eq!(cp_eta_secs(0, 100, 100, 1.0), None);
        assert_eq!(cp_eta_secs(90, 91, 100, 1.0), Some(9));
    }

    #[test]
    fn newline_progress_is_immediate_then_throttled_until_complete() {
        let start = Instant::now();
        assert!(cp_newline_due(None, start, 1, 100));
        assert!(!cp_newline_due(Some(start), start, 50, 100));
        assert!(cp_newline_due(
            Some(start),
            start + Duration::from_millis(500),
            50,
            100
        ));
        assert!(cp_newline_due(Some(start), start, 100, 100));
    }
}


#[cfg(test)]
mod preview_combo_tests {
    use super::{preview_incompatible_flags, Cli};
    use clap::CommandFactory;

    fn with_clean_config_env<T>(f: impl FnOnce() -> T) -> T {
        let previous = std::env::var_os("AGENTLINK_CONFIG_DIR");
        std::env::remove_var("AGENTLINK_CONFIG_DIR");
        let result = f();
        match previous {
            Some(value) => std::env::set_var("AGENTLINK_CONFIG_DIR", value),
            None => std::env::remove_var("AGENTLINK_CONFIG_DIR"),
        }
        result
    }

    fn preview_matches(args: &[&str]) -> clap::ArgMatches {
        // The full `Cli` command graph is large; rustc's default test thread
        // stack (often 2 MiB) overflows while building it. Production `main`
        // uses the process stack.
        let argv: Vec<std::ffi::OsString> = args.iter().map(|s| (*s).into()).collect();
        std::thread::Builder::new()
            .name("preview-clap".into())
            .stack_size(8 * 1024 * 1024)
            .spawn(move || {
                Cli::command()
                    .try_get_matches_from(argv)
                    .map_err(|err| err.to_string())
            })
            .expect("spawn preview clap parse")
            .join()
            .expect("preview clap parse thread")
            .unwrap_or_else(|err| panic!("parse error: {err}"))
    }

    fn preview_combo(args: &[&str]) -> Result<(), String> {
        with_clean_config_env(|| {
            let matches = preview_matches(args);
            match preview_incompatible_flags(&matches) {
                Some(msg) => Err(msg),
                None => Ok(()),
            }
        })
    }

    #[test]
    fn preview_alone_is_accepted_and_defaults_are_not_user_supplied() {
        assert_eq!(
            preview_combo(&["agentlink", "controller", "--preview-ui"]),
            Ok(())
        );
        // Defaulted numeric flags must not be mistaken for user-supplied live paths.
        assert_eq!(
            preview_combo(&[
                "agentlink",
                "controller",
                "--preview-ui",
                "--max-fps",
                "30",
                "--connect-timeout-secs",
                "12",
            ]),
            Ok(())
        );
    }

    fn assert_rejects(extra: &[&str], flag: &str) {
        let mut args = vec!["agentlink", "controller", "--preview-ui"];
        args.extend_from_slice(extra);
        let err = preview_combo(&args).expect_err(flag);
        assert!(
            err.contains(flag),
            "expected {flag} in rejection, got: {err}"
        );
        assert!(
            err.contains("--preview-ui"),
            "rejection should mention --preview-ui: {err}"
        );
    }

    #[test]
    fn preview_rejects_explicit_data_dir() {
        assert_rejects(&["--data-dir", "/tmp/agentlink-review-data"], "--data-dir");
    }

    #[test]
    fn preview_rejects_explicit_config_dir() {
        assert_rejects(
            &["--config-dir", "/tmp/agentlink-review-config"],
            "--config-dir",
        );
    }

    #[test]
    fn preview_rejects_config_dir_from_env() {
        with_clean_config_env(|| {
            std::env::set_var("AGENTLINK_CONFIG_DIR", "/tmp/agentlink-review-env-config");
            let matches = preview_matches(&["agentlink", "controller", "--preview-ui"]);
            let err = preview_incompatible_flags(&matches)
                .expect("env config-dir must be rejected");
            assert!(
                err.contains("--config-dir"),
                "expected --config-dir in {err}"
            );
            std::env::remove_var("AGENTLINK_CONFIG_DIR");
        });
    }

    #[test]
    fn preview_rejects_debug_socket() {
        assert_rejects(
            &["--debug-socket", "/tmp/agentlink-review.sock"],
            "--debug-socket",
        );
    }

    #[test]
    fn preview_rejects_headless() {
        assert_rejects(&["--headless"], "--headless");
    }

    #[test]
    fn preview_rejects_open_desktop() {
        assert_rejects(&["--open-desktop", "preview-fixture-desktop"], "--open-desktop");
    }

    #[test]
    fn preview_rejects_background() {
        assert_rejects(&["--background"], "--background");
    }

    #[test]
    fn preview_rejects_combined_incompatible_flags() {
        let err = preview_combo(&[
            "agentlink",
            "controller",
            "--preview-ui",
            "--data-dir",
            "/tmp/d",
            "--config-dir",
            "/tmp/c",
            "--debug-socket",
            "/tmp/s",
            "--headless",
            "--open-desktop",
            "n1",
            "--background",
        ])
        .expect_err("combo");
        for flag in [
            "--data-dir",
            "--config-dir",
            "--debug-socket",
            "--headless",
            "--open-desktop",
            "--background",
        ] {
            assert!(err.contains(flag), "missing {flag} in {err}");
        }
    }
}
