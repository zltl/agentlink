//! Shared core for agentlink.
//!
//! The CLI and the MCP server are thin shells over [`Client`]. The relay and
//! the node speak the same [`protocol`] and pin the relay certificate via
//! [`tls`]. Phase 2 (screenshots, input injection) and phase 3 (WebRTC) plug
//! in through [`extensions`] without a new transport.

#![deny(unsafe_code)]

pub mod accounts;
pub mod audit;
pub mod client;
pub mod compress;
pub mod config;
pub mod confirm;
pub mod copy;
pub mod delta;
pub mod e2e;
pub mod engine;
pub mod error;
pub mod extensions;
pub mod frame;
pub mod grant;
pub mod grant_authority;
pub mod grant_offer;
pub mod grant_request;
pub mod ice;
pub mod identity;
pub mod invite;
pub mod lan_priority;
pub mod node_pin;
pub mod operate_guide;
pub mod p2p;
pub mod paths;
pub mod pending;
pub mod permissions;
pub mod process;
pub mod protocol;
pub mod recording;
pub mod relay_url;
pub mod resume;
pub mod s3;
pub mod sandbox;
pub mod sparse;
pub mod tls;
pub mod transport_status;
pub mod tunnel;
pub mod turn;
pub mod util;
pub mod ws;

pub use client::{
    Client, ExecOutput, ExecRequest, ObservedConnectError, PairingInfo, PtyEvent, PtyRead,
    PtySession, PtyTestIo, PtyWriter,
};
pub use config::{
    apply_relay_defaults, is_public_relay, load_settings, save_settings, ClientSettings,
    FileConfig, DEFAULT_RELAY_TRUST,
};
pub use error::{Error, Result};
pub use extensions::{NodeExtension, PHASE2_INJECT_INPUT, PHASE2_SCREENSHOT, PHASE3_WEBRTC_SIGNAL};
pub use grant::{resolve_e2e_policy, SignedGrant, OWNER_KEYS_FILE};
pub use ice::{
    ice_attempts, is_default_stun_url, prepare_stun_urls, rewrite_ice_urls,
    stun_rewrite_mode_from_env, stun_rewrite_mode_from_value, stun_urls, stun_urls_from_env,
    stun_urls_ready_for_ice, IceAttempt, StunRewriteMode, DEFAULT_STUN_URLS,
};
pub use identity::Identity;
pub use invite::{decode_invite, encode_invite, parse_join_text, Invite, JoinText};
pub use lan_priority::{
    prefer_on_link_hosts_in_candidate, prefer_on_link_hosts_in_sdp, rewrite_candidate_line,
    rewrite_sdp_remote_hosts, HOST_ACCEPTANCE_MIN_WAIT,
};
pub use node_pin::{observe as observe_node_pin, PinStatus};
pub use operate_guide::{
    decode_operate_guide, encode_operate_guide, operate_guide_url, OperateGuide, OPERATE_GUIDE_KEYS,
};
pub use permissions::{parse_access, NodePolicy};
pub use protocol::{
    DirEntry, Envelope, FileStat, NodeInfo, Op, Role, PROTOCOL_VERSION, WS_PATH, WS_WEB_PATH,
};
pub use relay_url::{parse_relay_url, viewer_url, RelayUrl};
pub use tls::{parse_fingerprint, FingerprintVerifier, RelayCert, RelayTrust};
pub use transport_status::{ClosureCategory, ClosureSink, TransportObserver, TransportStatus};
pub use turn::{mint as mint_turn_credential, rest_credential, rest_username};
