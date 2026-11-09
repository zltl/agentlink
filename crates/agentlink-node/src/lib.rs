//! Node daemon.
//!
//! The node dials the relay, proves its ed25519 identity, and serves file,
//! command, PTY, search, edit, watch, and desktop operations. It reconnects
//! on its own. Screenshot and input handlers come from `agentlink-desktop`.

#![forbid(unsafe_code)]

pub mod audit;
mod daemon;
mod edit;
mod lock;
mod ops;
mod pipeline;
mod proc;
mod pty_session;
mod resume;
mod search;
pub mod status;
mod system;
mod transfer;
mod watch;

pub use daemon::{run, run_until_signal, save_node_config, set_liveness_for_test, NodeConfig};
pub use pipeline::{query_local, query_s3, record_local_change};
pub use status::{read_status, write_status, LinkState, LinkStatus};
