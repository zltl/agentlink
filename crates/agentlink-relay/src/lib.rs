//! Relay / control server.
//!
//! Nodes and clients both dial out to the relay. The relay authenticates
//! them, stores pairing, and routes operation envelopes. It terminates TLS,
//! so it is a trusted part of a deployment: run it on a host you control.
//!
//! `/v1/connect` is the sealed-client control socket (CLI / phone / node).
//! Browser pages are **info and account only**: `GET /` (dashboard), login,
//! enroll tokens, audit, install downloads, and `GET /operate` (docs).
//! Former browser control paths (`/v1/web`, view tickets, `/view` desktop)
//! are retired fail-closed (410 / notice). Neutral authenticated relay and
//! WebRTC signaling for sealed clients remain. Media is peer-to-peer WebRTC.

#![deny(unsafe_code)]

mod audit_http;
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
pub use server::{
    serve, set_max_concurrent_connections_for_test, set_stale_after_for_test, RelayConfig,
    RelayHandle,
};
