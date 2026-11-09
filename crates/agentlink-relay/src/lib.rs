//! Relay / control server.
//!
//! Nodes and clients both dial out to the relay. The relay authenticates
//! them, stores pairing, and routes operation envelopes. It terminates TLS,
//! so it is a trusted part of a deployment: run it on a host you control.
//!
//! `/v1/connect` is the control socket. `/v1/webrtc` speaks the same JSON
//! envelopes for a browser viewer. `/v1/web` is the dashboard session for
//! files and a terminal. `GET /view` serves the desktop page. `GET /operate`
//! serves the documentation-only node guide. `GET /` is the machine dashboard.
//! Media is peer-to-peer WebRTC, not a relay frame.

#![deny(unsafe_code)]

mod db;
mod models;
mod operate;
mod server;
#[allow(dead_code)]
mod store;
mod view;
mod web;

#[cfg(test)]
mod accounts_test;

pub use db::{Database, OpenOptions, Opened};
pub use models::UserAccount;
pub use server::{serve, set_stale_after_for_test, RelayConfig, RelayHandle};
