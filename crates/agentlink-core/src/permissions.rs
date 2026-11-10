//! Capability flags carried on enrollments, shares, and view tickets.
//!
//! A signed-in owner, admin, or sharee is full access. These presets no longer
//! clip that session. A view ticket may still carry a narrower flag set for
//! that one browser session. The relay does not see sealed operation payloads.

use serde::de::Deserializer;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::extensions::{permission_for_extension, ExtensionPerm};
use crate::protocol::Op;

fn default_allow_read() -> bool {
    true
}

/// What a node is allowed to do.
///
/// `Deserialize` upgrades a stored `remote-control` grant. Older JSON left
/// `allow_desktop` off, which blocked screenshots and `inject_input` after
/// intersection with a ceiling that already allowed them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct NodePolicy {
    /// Stat, list, and read file contents.
    #[serde(default = "default_allow_read")]
    pub allow_read: bool,
    /// Write, mkdir, remove, and rename.
    #[serde(default)]
    pub allow_write: bool,
    /// Run commands and open a PTY.
    #[serde(default)]
    pub allow_exec: bool,
    /// Screenshots and input injection.
    ///
    /// Also implied by [`Self::remote_control`]: watching and driving the
    /// desktop includes the JPEG fallback and `inject_input`. It does not
    /// imply write or exec.
    #[serde(default)]
    pub allow_desktop: bool,
    /// Phase 3: WebRTC signaling messages. Off unless explicitly enabled.
    ///
    /// Kept so an older `desktop_stream` flag still opens a view-only session.
    /// [`Self::allow_remote_view`] is the permission new callers should set.
    #[serde(default)]
    pub allow_desktop_stream: bool,
    /// Watch the screen. Does not allow mouse, keyboard, or clipboard writes.
    #[serde(default)]
    pub allow_remote_view: bool,
    /// Drive the pointer, keyboard, scroll, and clipboard. Implies view.
    #[serde(default)]
    pub allow_remote_control: bool,
}

impl Default for NodePolicy {
    fn default() -> Self {
        Self::read_only()
    }
}

impl NodePolicy {
    pub fn none() -> Self {
        Self {
            allow_read: false,
            allow_write: false,
            allow_exec: false,
            allow_desktop: false,
            allow_desktop_stream: false,
            allow_remote_view: false,
            allow_remote_control: false,
        }
    }

    pub fn read_only() -> Self {
        Self {
            allow_read: true,
            allow_write: false,
            allow_exec: false,
            allow_desktop: false,
            allow_desktop_stream: false,
            allow_remote_view: false,
            allow_remote_control: false,
        }
    }

    pub fn read_write() -> Self {
        Self {
            allow_read: true,
            allow_write: true,
            allow_exec: false,
            allow_desktop: false,
            allow_desktop_stream: false,
            allow_remote_view: false,
            allow_remote_control: false,
        }
    }

    /// Read, write, and exec. Screenshots and remote desktop stay off.
    pub fn exec() -> Self {
        Self {
            allow_read: true,
            allow_write: true,
            allow_exec: true,
            allow_desktop: false,
            allow_desktop_stream: false,
            allow_remote_view: false,
            allow_remote_control: false,
        }
    }

    /// Local ceiling that permits every phase-1 operation and nothing later.
    pub fn phase1_ceiling() -> Self {
        Self::exec()
    }

    /// Screenshots, input, and the accessibility tree, plus read, write, and exec.
    ///
    /// `allow_desktop_stream` stays off. Desktop still needs the node ceiling
    /// to allow it. A relay preset does not.
    pub fn desktop() -> Self {
        Self {
            allow_read: true,
            allow_write: true,
            allow_exec: true,
            allow_desktop: true,
            allow_desktop_stream: false,
            allow_remote_view: false,
            allow_remote_control: false,
        }
    }

    /// Watch a desktop. No pointer or keyboard.
    pub fn remote_view() -> Self {
        Self {
            allow_read: true,
            allow_write: false,
            allow_exec: false,
            allow_desktop: false,
            allow_desktop_stream: true,
            allow_remote_view: true,
            allow_remote_control: false,
        }
    }

    /// Watch and control a desktop. Control includes view, screenshots, and input.
    ///
    /// Write and exec stay off. `allow_desktop` is on so JPEG screenshots and
    /// `inject_input` survive intersection with this preset. A view-only grant
    /// does not set it, so pointer and keyboard stay denied there.
    pub fn remote_control() -> Self {
        Self {
            allow_read: true,
            allow_write: false,
            allow_exec: false,
            allow_desktop: true,
            allow_desktop_stream: true,
            allow_remote_view: true,
            allow_remote_control: true,
        }
    }

    /// Shell, files, screenshots, and remote desktop. Every flag is on.
    ///
    /// This is the explicit "everything" package. It is not the default for a
    /// new machine: enrollment uses [`Self::exec`] until the owner asks for a
    /// screen. [`Self::remote_control`] still leaves write and exec off, and
    /// [`Self::desktop`] still leaves the live stream off.
    pub fn full() -> Self {
        Self {
            allow_read: true,
            allow_write: true,
            allow_exec: true,
            allow_desktop: true,
            allow_desktop_stream: true,
            allow_remote_view: true,
            allow_remote_control: true,
        }
    }

    /// Screenshots, including the JPEG fallback used when a live stream has no frames yet.
    pub fn allows_screenshot(self) -> bool {
        self.allow_desktop || self.allows_remote_view()
    }

    /// Pointer, keyboard, and the `inject_input` extension.
    pub fn allows_input(self) -> bool {
        self.allow_desktop || self.allows_remote_control()
    }

    /// A stored remote-control policy from before `allow_desktop` was part of
    /// that preset. View-only policies are left unchanged.
    pub fn imply_control_desktop(mut self) -> Self {
        if self.allow_remote_control {
            self.allow_desktop = true;
            self.allow_remote_view = true;
            self.allow_desktop_stream = true;
        }
        self
    }

    pub fn allows_remote_view(self) -> bool {
        self.allow_remote_view || self.allow_desktop_stream
    }

    pub fn allows_remote_control(self) -> bool {
        self.allow_remote_control
    }

    pub fn intersect(self, other: Self) -> Self {
        Self {
            allow_read: self.allow_read && other.allow_read,
            allow_write: self.allow_write && other.allow_write,
            allow_exec: self.allow_exec && other.allow_exec,
            allow_desktop: self.allow_desktop && other.allow_desktop,
            allow_desktop_stream: self.allow_desktop_stream && other.allow_desktop_stream,
            allow_remote_view: self.allow_remote_view && other.allow_remote_view,
            allow_remote_control: self.allow_remote_control && other.allow_remote_control,
        }
    }

    pub fn allows(&self, op: &Op) -> std::result::Result<(), String> {
        let (ok, kind) = match op {
            Op::Stat { .. }
            | Op::ListDir { .. }
            | Op::ReadFile { .. }
            | Op::Search { .. }
            | Op::Find { .. }
            | Op::WatchStart { .. }
            | Op::WatchPoll { .. }
            | Op::WatchStop { .. }
            | Op::SysInfo => (self.allow_read, "read"),
            Op::WriteFile { .. }
            | Op::Mkdir { .. }
            | Op::Remove { .. }
            | Op::Rename { .. }
            | Op::Replace { .. }
            | Op::EditLines { .. }
            | Op::ApplyPatch { .. } => (self.allow_write, "write"),
            Op::Exec { .. }
            | Op::PtyOpen { .. }
            | Op::PtyInput { .. }
            | Op::PtyResize { .. }
            | Op::PtyClose { .. }
            | Op::BgStart { .. }
            | Op::BgList
            | Op::BgOutput { .. }
            | Op::BgStatus { .. }
            | Op::BgKill { .. } => (self.allow_exec, "exec"),
            // Revoke is authenticated by the issuer-signed SignedRevoke the node
            // verifies, so a narrow capability policy must not block it.
            Op::RevokeGrant { .. } => (true, "meta"),
            Op::Extension { name, .. } => {
                let ok = match name.as_str() {
                    crate::extensions::PHASE2_SCREENSHOT => self.allows_screenshot(),
                    crate::extensions::PHASE2_INJECT_INPUT => self.allows_input(),
                    _ => match permission_for_extension(name) {
                        ExtensionPerm::Desktop => self.allow_desktop,
                        ExtensionPerm::DesktopStream => self.allows_remote_view(),
                        ExtensionPerm::Unknown => false,
                    },
                };
                (ok, "extension")
            }
        };
        if ok {
            Ok(())
        } else {
            Err(format!(
                "{kind} is not allowed on this node ({})",
                self.preset_name()
            ))
        }
    }

    /// Human-readable list of what this policy actually allows.
    ///
    /// The short [`Self::preset_name`] (`desktop`, `exec`, …) is not enough:
    /// `desktop` also includes file read, write, and exec, and it does not
    /// include a live desktop stream.
    pub fn capability_summary(self) -> String {
        let mut parts = Vec::new();
        match (self.allow_read, self.allow_write) {
            (true, true) => parts.push("file read and write"),
            (true, false) => parts.push("file read (no write)"),
            (false, true) => parts.push("file write (no read)"),
            (false, false) => parts.push("no file access"),
        }
        if self.allow_exec {
            parts.push("exec/shell");
        } else {
            parts.push("no exec/shell");
        }
        if self.allow_desktop {
            parts.push("screenshots, input, and accessibility");
        } else {
            parts.push("no screenshots/input");
        }
        if self.allow_desktop_stream || self.allow_remote_view {
            parts.push("live desktop stream/view");
        } else {
            parts.push("no live desktop stream");
        }
        if self.allow_remote_control {
            parts.push("remote desktop control");
        } else {
            parts.push("no remote desktop control");
        }
        format!("{} ({})", self.preset_name(), parts.join("; "))
    }

    pub fn preset_name(self) -> &'static str {
        if self == Self::full() {
            return "full";
        }
        if self == Self::desktop() {
            return "desktop";
        }
        if self == Self::remote_control() {
            return "remote-control";
        }
        if self == Self::remote_view() {
            return "remote-view";
        }
        if self.allow_desktop
            || self.allow_desktop_stream
            || self.allow_remote_view
            || self.allow_remote_control
        {
            return "custom";
        }
        match (self.allow_read, self.allow_write, self.allow_exec) {
            (true, true, true) => "exec",
            (true, true, false) => "read-write",
            (true, false, false) => "read-only",
            (false, false, false) => "none",
            _ => "custom",
        }
    }
}

/// Parse `read-only`, `read-write`, `exec`, `desktop`, `remote-view`, `remote-control`, or `full`.
pub fn parse_access(s: &str) -> Result<NodePolicy> {
    match s.trim().to_ascii_lowercase().as_str() {
        "read-only" | "readonly" | "read" | "ro" => Ok(NodePolicy::read_only()),
        "read-write" | "readwrite" | "write" | "rw" => Ok(NodePolicy::read_write()),
        "exec" => Ok(NodePolicy::exec()),
        "desktop" => Ok(NodePolicy::desktop()),
        "remote-view" | "remote_view" | "view" => Ok(NodePolicy::remote_view()),
        "remote-control" | "remote_control" | "control" => Ok(NodePolicy::remote_control()),
        "full" | "all" | "full-access" | "full_access" => Ok(NodePolicy::full()),
        "none" => Ok(NodePolicy::none()),
        other => Err(Error::Message(format!(
            "unknown access '{other}' (expected read-only, read-write, exec, desktop, remote-view, remote-control, or full)"
        ))),
    }
}

#[derive(Deserialize)]
struct PolicyWire {
    #[serde(default = "default_allow_read")]
    allow_read: bool,
    #[serde(default)]
    allow_write: bool,
    #[serde(default)]
    allow_exec: bool,
    #[serde(default)]
    allow_desktop: bool,
    #[serde(default)]
    allow_desktop_stream: bool,
    #[serde(default)]
    allow_remote_view: bool,
    #[serde(default)]
    allow_remote_control: bool,
}

impl<'de> Deserialize<'de> for NodePolicy {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let raw = PolicyWire::deserialize(deserializer)?;
        Ok(Self {
            allow_read: raw.allow_read,
            allow_write: raw.allow_write,
            allow_exec: raw.allow_exec,
            allow_desktop: raw.allow_desktop,
            allow_desktop_stream: raw.allow_desktop_stream,
            allow_remote_view: raw.allow_remote_view,
            allow_remote_control: raw.allow_remote_control,
        }
        .imply_control_desktop())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_and_intersection() {
        let ro = parse_access("read-only").unwrap();
        assert!(ro.allows(&Op::Stat { path: "/".into() }).is_ok());
        assert!(ro
            .allows(&Op::Exec {
                program: "x".into(),
                args: vec![],
                cwd: None,
                env: vec![],
                timeout_ms: None,
                shell: false,
                stdin_b64: None,
            })
            .is_err());

        let effective = NodePolicy::exec().intersect(NodePolicy::read_only());
        assert_eq!(effective, NodePolicy::read_only());
        assert!(!effective.allow_desktop);
    }

    #[test]
    fn desktop_is_default_deny() {
        let policy = NodePolicy::exec();
        let op = Op::Extension {
            name: "screenshot".into(),
            payload: serde_json::json!({}),
        };
        assert!(policy.allows(&op).is_err());
        let mut desktop = policy;
        desktop.allow_desktop = true;
        assert!(desktop.allows(&op).is_ok());
        let unknown = Op::Extension {
            name: "something-else".into(),
            payload: serde_json::json!({}),
        };
        assert!(desktop.allows(&unknown).is_err());
    }

    #[test]
    fn new_ops_follow_read_write_exec() {
        let ro = NodePolicy::read_only();
        assert!(ro
            .allows(&Op::Search {
                path: ".".into(),
                pattern: "a".into(),
                literal: false,
                include: vec![],
                exclude: vec![],
                gitignore: true,
                include_hidden: false,
                case_insensitive: false,
                before: 0,
                after: 0,
                offset: 0,
                limit: 10,
            })
            .is_ok());
        assert!(ro.allows(&Op::SysInfo).is_ok());
        assert!(NodePolicy::none()
            .allows(&Op::RevokeGrant {
                revoke: crate::grant::SignedRevoke {
                    node_id: "n".into(),
                    jti: "j".into(),
                    nbf_unix: 0,
                    exp_unix: 1,
                    issuer_id: String::new(),
                    sig_hex: String::new(),
                    grant_exp_unix: None,
                },
            })
            .is_ok());
        assert!(ro
            .allows(&Op::Replace {
                path: "a".into(),
                old: "x".into(),
                new: "y".into(),
                replace_all: false,
            })
            .is_err());
        assert!(ro
            .allows(&Op::BgStart {
                program: "echo".into(),
                args: vec![],
                cwd: None,
                env: vec![],
                shell: true,
                stdin_b64: None,
            })
            .is_err());
        let rw = NodePolicy::read_write();
        assert!(rw
            .allows(&Op::ApplyPatch {
                root: ".".into(),
                patch: String::new(),
            })
            .is_ok());
        assert!(rw
            .allows(&Op::PtyOpen {
                command: None,
                cwd: None,
                rows: 24,
                cols: 80,
            })
            .is_err());
        assert!(NodePolicy::exec()
            .allows(&Op::BgKill { id: "1".into() })
            .is_ok());
    }

    #[test]
    fn desktop_preset_is_named_and_off_by_default() {
        let desktop = parse_access("desktop").unwrap();
        assert_eq!(desktop, NodePolicy::desktop());
        assert!(desktop.allow_desktop);
        assert!(!desktop.allow_desktop_stream);
        assert_eq!(desktop.preset_name(), "desktop");
        let summary = desktop.capability_summary();
        assert!(summary.contains("exec/shell"), "{summary}");
        assert!(summary.contains("file read and write"), "{summary}");
        assert!(summary.contains("no live desktop stream"), "{summary}");
        assert!(summary.starts_with("desktop ("), "{summary}");
        let view = NodePolicy::remote_view().capability_summary();
        assert!(view.contains("no exec/shell"), "{view}");
        assert!(view.contains("live desktop stream"), "{view}");
        assert_eq!(NodePolicy::exec().preset_name(), "exec");
        let mut partial = NodePolicy::read_only();
        partial.allow_desktop = true;
        assert_eq!(partial.preset_name(), "custom");
    }

    #[test]
    fn remote_view_allows_screenshots_but_not_input() {
        let view = parse_access("remote-view").unwrap();
        assert!(view.allows_remote_view());
        assert!(!view.allows_remote_control());
        assert!(!view.allow_desktop);
        assert!(!view.allow_write);
        assert!(!view.allow_exec);
        assert_eq!(view.preset_name(), "remote-view");
        let signal = Op::Extension {
            name: "webrtc_signal".into(),
            payload: serde_json::json!({}),
        };
        assert!(view.allows(&signal).is_ok());
        let shot = Op::Extension {
            name: "screenshot".into(),
            payload: serde_json::json!({}),
        };
        assert!(view.allows(&shot).is_ok());
        let inject = Op::Extension {
            name: "inject_input".into(),
            payload: serde_json::json!({}),
        };
        assert!(view.allows(&inject).is_err());
        let control = parse_access("remote-control").unwrap();
        assert!(control.allows_remote_control());
        assert!(control.allows_remote_view());
        assert!(control.allow_desktop);
        assert!(!control.allow_write);
        assert!(!control.allow_exec);
        assert!(control.allows(&shot).is_ok());
        assert!(control.allows(&inject).is_ok());
        assert!(control
            .allows(&Op::Mkdir {
                path: "a".into(),
                recursive: false,
            })
            .is_err());
        assert_eq!(control.preset_name(), "remote-control");
        let capped = control.intersect(NodePolicy::remote_view());
        assert!(capped.allows_remote_view());
        assert!(!capped.allows_remote_control());
        assert!(capped.allows(&shot).is_ok());
        assert!(capped.allows(&inject).is_err());
    }

    #[test]
    fn stored_remote_control_grant_gains_desktop_without_write() {
        let legacy = r#"{"allow_read":true,"allow_write":false,"allow_exec":false,"allow_desktop":false,"allow_desktop_stream":true,"allow_remote_view":true,"allow_remote_control":true}"#;
        let grant: NodePolicy = serde_json::from_str(legacy).unwrap();
        assert_eq!(grant, NodePolicy::remote_control());
        assert!(grant.allow_desktop);
        assert!(!grant.allow_write && !grant.allow_exec);
        assert_eq!(grant.preset_name(), "remote-control");
        let mut ceiling = NodePolicy::read_only();
        ceiling.allow_desktop = true;
        ceiling.allow_desktop_stream = true;
        ceiling.allow_remote_view = true;
        ceiling.allow_remote_control = true;
        let effective = ceiling.intersect(grant);
        assert!(effective.allows_screenshot());
        assert!(effective.allows_input());
        assert!(!effective.allow_write && !effective.allow_exec);
        let inject = Op::Extension {
            name: "inject_input".into(),
            payload: serde_json::json!({}),
        };
        assert!(effective.allows(&inject).is_ok());
        // A grant that was not rewritten still allows input when control is on.
        let mut unexpanded = NodePolicy::remote_control();
        unexpanded.allow_desktop = false;
        assert!(unexpanded.allows(&inject).is_ok());
        assert!(unexpanded.allows_screenshot());
        let view_only = r#"{"allow_read":true,"allow_write":false,"allow_exec":false,"allow_desktop":false,"allow_desktop_stream":true,"allow_remote_view":true,"allow_remote_control":false}"#;
        let view: NodePolicy = serde_json::from_str(view_only).unwrap();
        assert!(!view.allow_desktop);
        assert!(!view.allows_input());
        assert!(view.allows_screenshot());
        assert_eq!(view.preset_name(), "remote-view");
    }

    #[test]
    fn full_preset_enables_every_flag_without_renaming_narrower_policies() {
        let full = parse_access("full").unwrap();
        assert_eq!(full, NodePolicy::full());
        assert_eq!(parse_access("all").unwrap(), full);
        assert_eq!(parse_access("full-access").unwrap(), full);
        assert_eq!(parse_access("FULL_ACCESS").unwrap(), full);
        assert!(full.allow_read && full.allow_write && full.allow_exec);
        assert!(full.allow_desktop && full.allow_desktop_stream);
        assert!(full.allow_remote_view && full.allow_remote_control);
        assert_eq!(full.preset_name(), "full");
        assert_ne!(full, NodePolicy::remote_control());
        assert_ne!(full, NodePolicy::desktop());
        assert_ne!(full, NodePolicy::exec());
        assert!(!NodePolicy::remote_control().allow_write);
        assert!(!NodePolicy::remote_control().allow_exec);
        assert!(!NodePolicy::desktop().allow_desktop_stream);
        assert!(!NodePolicy::desktop().allow_remote_view);
        assert_eq!(parse_access("exec").unwrap(), NodePolicy::exec());
        assert_eq!(NodePolicy::exec().preset_name(), "exec");

        let stored_exec = r#"{"allow_read":true,"allow_write":true,"allow_exec":true,"allow_desktop":false,"allow_desktop_stream":false,"allow_remote_view":false,"allow_remote_control":false}"#;
        let exec: NodePolicy = serde_json::from_str(stored_exec).unwrap();
        assert_eq!(exec, NodePolicy::exec());
        assert_eq!(exec.preset_name(), "exec");

        let stored_control = r#"{"allow_read":true,"allow_write":false,"allow_exec":false,"allow_desktop":true,"allow_desktop_stream":true,"allow_remote_view":true,"allow_remote_control":true}"#;
        let control: NodePolicy = serde_json::from_str(stored_control).unwrap();
        assert_eq!(control.preset_name(), "remote-control");

        let round: NodePolicy =
            serde_json::from_str(&serde_json::to_string(&full).unwrap()).unwrap();
        assert_eq!(round, full);
        assert_eq!(round.preset_name(), "full");
    }
}
