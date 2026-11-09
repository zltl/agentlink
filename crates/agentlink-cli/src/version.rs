//! Version reported by the binary.
//!
//! `agentlink --version` is the crate version, or `AGENTLINK_RELEASE_VERSION`
//! when a release build sets it, followed by the git commit hash.
//! [`semver`] is the comparable version without that hash. `update` uses it
//! so `0.1.10 (abc...)` is not parsed as `0.1.0`.

pub const fn current() -> &'static str {
    env!("AGENTLINK_VERSION")
}

pub const fn semver() -> &'static str {
    env!("AGENTLINK_SEMVER")
}
