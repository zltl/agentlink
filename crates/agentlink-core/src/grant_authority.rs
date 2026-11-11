//! Policy for a *future* A1 local grant authority helper. Not wired into
//! `grant allow` and not installed on any host.
//!
//! On 2026-11-11 08:17 (Asia/Shanghai, UTC+8) the owner chose A2: keep this
//! OS user's full shell and accept that a controller who already has
//! exec/full can read the issuer and mint further grants. This module stays
//! in-tree only so an A1 helper is not later mistaken for production policy.
//! Production contract: first unauthenticated grant is still local-only;
//! env-cleared exec after a valid grant is accepted inherent power; revoke
//! does not undo later grants. See `docs/grant-local-authority.md`.

/// How the process asking the helper to sign a grant was classified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerClass {
    /// Active graphical seat (e.g. logind session that has a seat).
    LocalSeat,
    /// Interactive login on the target without a seat (SSH/Cursor).
    InteractiveRemoteLogin,
    /// Spawned by the agentlink node (exec/pty/shell) or running in its cgroup.
    AgentlinkRemoteExec,
    /// Same OS user, but not identified as a seat or an interactive login.
    SameUserUnknown,
    /// A different OS user than the login / node user (e.g. a future exec user).
    OtherUser,
    /// Effective root, or a caller that can become root (sudo).
    PrivilegedRoot,
}

/// Optional tightening for interactive SSH/Cursor approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SshApprovalPolicy {
    /// Fingerprint disclosure on the SSH tty is enough (today's t421 usage).
    #[default]
    DiscloseOnTty,
    /// SSH must also pass a seat / polkit (or platform-equivalent) prompt.
    RequirePresencePrompt,
}

/// Decision the helper should return. The helper is not deployed yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityDecision {
    /// Sign after the local UI/CLI has shown the fingerprint and scope.
    SignAfterLocalDisclosure,
    /// Sign only after a mature OS presence prompt (polkit, UAC, …).
    SignAfterOsPresencePrompt,
    /// Refuse. Never treat this caller as a local approval.
    Refuse(&'static str),
}

/// Classify a caller from OS observations. All inputs are already attested by
/// the helper (SO_PEERCRED, logind, cgroup, euid) — this function does not
/// talk to the OS, so tests can cover the policy without touching production
/// users or sudoers.
pub fn classify_caller(
    euid_is_root: bool,
    same_uid_as_login: bool,
    in_node_or_exec_cgroup: bool,
    remote_exec_env_set: bool,
    has_active_seat: bool,
    interactive_login_session: bool,
) -> CallerClass {
    if euid_is_root {
        return CallerClass::PrivilegedRoot;
    }
    if !same_uid_as_login {
        return CallerClass::OtherUser;
    }
    if in_node_or_exec_cgroup || remote_exec_env_set {
        return CallerClass::AgentlinkRemoteExec;
    }
    if has_active_seat {
        return CallerClass::LocalSeat;
    }
    if interactive_login_session {
        return CallerClass::InteractiveRemoteLogin;
    }
    CallerClass::SameUserUnknown
}

/// Should the helper sign for this caller?
///
/// `shell_in_scope` is recorded for disclosure; it does not loosen the
/// decision. A same-UID unrestricted shell is why `AgentlinkRemoteExec` is
/// always refused.
pub fn decide_sign(
    caller: &CallerClass,
    ssh: SshApprovalPolicy,
    _shell_in_scope: bool,
) -> AuthorityDecision {
    match caller {
        CallerClass::LocalSeat => AuthorityDecision::SignAfterLocalDisclosure,
        CallerClass::InteractiveRemoteLogin => match ssh {
            SshApprovalPolicy::DiscloseOnTty => AuthorityDecision::SignAfterLocalDisclosure,
            SshApprovalPolicy::RequirePresencePrompt => {
                AuthorityDecision::SignAfterOsPresencePrompt
            }
        },
        CallerClass::AgentlinkRemoteExec => AuthorityDecision::Refuse(
            "caller is agentlink exec/pty or the node cgroup; this is not a local approval. A same-UID unrestricted exec can also clear env, ptrace, use the session bus, or write autostart — refusing the CLI is not the complete boundary",
        ),
        CallerClass::SameUserUnknown => AuthorityDecision::Refuse(
            "caller is the same OS user but not a seat or interactive login; do not guess",
        ),
        CallerClass::OtherUser => AuthorityDecision::Refuse(
            "caller is not the login user or the authority helper; no grant signature",
        ),
        CallerClass::PrivilegedRoot => AuthorityDecision::Refuse(
            "effective root or sudo cannot be promised unable to proxy-sign; refuse unattended signing",
        ),
    }
}

/// Landlock (or any path-only deny of the issuer file) is not sufficient.
pub fn landlock_issuer_path_alone_is_sufficient() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seat_may_sign_after_disclosure() {
        let class = classify_caller(false, true, false, false, true, true);
        assert_eq!(class, CallerClass::LocalSeat);
        assert_eq!(
            decide_sign(&class, SshApprovalPolicy::DiscloseOnTty, true),
            AuthorityDecision::SignAfterLocalDisclosure
        );
    }

    #[test]
    fn ssh_policy_can_require_presence() {
        let class = classify_caller(false, true, false, false, false, true);
        assert_eq!(class, CallerClass::InteractiveRemoteLogin);
        assert_eq!(
            decide_sign(&class, SshApprovalPolicy::DiscloseOnTty, true),
            AuthorityDecision::SignAfterLocalDisclosure
        );
        assert_eq!(
            decide_sign(&class, SshApprovalPolicy::RequirePresencePrompt, true),
            AuthorityDecision::SignAfterOsPresencePrompt
        );
    }

    #[test]
    fn exec_cgroup_or_env_is_refused_and_not_a_complete_story() {
        let by_cgroup = classify_caller(false, true, true, false, false, false);
        let by_env = classify_caller(false, true, false, true, false, false);
        assert_eq!(by_cgroup, CallerClass::AgentlinkRemoteExec);
        assert_eq!(by_env, CallerClass::AgentlinkRemoteExec);
        for class in [by_cgroup, by_env] {
            match decide_sign(&class, SshApprovalPolicy::DiscloseOnTty, true) {
                AuthorityDecision::Refuse(reason) => {
                    assert!(reason.contains("ptrace") || reason.contains("autostart"));
                }
                other => panic!("exec must be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_same_user_and_other_user_and_root_are_refused() {
        let unknown = classify_caller(false, true, false, false, false, false);
        assert_eq!(unknown, CallerClass::SameUserUnknown);
        assert!(matches!(
            decide_sign(&unknown, SshApprovalPolicy::DiscloseOnTty, false),
            AuthorityDecision::Refuse(_)
        ));
        let other = classify_caller(false, false, false, false, false, false);
        assert_eq!(other, CallerClass::OtherUser);
        assert!(matches!(
            decide_sign(&other, SshApprovalPolicy::DiscloseOnTty, false),
            AuthorityDecision::Refuse(_)
        ));
        let root = classify_caller(true, true, false, false, true, true);
        assert_eq!(root, CallerClass::PrivilegedRoot);
        match decide_sign(&root, SshApprovalPolicy::DiscloseOnTty, true) {
            AuthorityDecision::Refuse(reason) => assert!(reason.contains("root")),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn landlock_on_issuer_file_is_not_sold_as_the_boundary() {
        assert!(!landlock_issuer_path_alone_is_sufficient());
    }

    #[test]
    fn env_cleared_still_refused_if_in_exec_cgroup() {
        // Regression shape: env -u must not become a green path once a helper exists.
        let class = classify_caller(
            false, true, true, /* cgroup */ false, /* env cleared */ false, false,
        );
        assert_eq!(class, CallerClass::AgentlinkRemoteExec);
        assert!(matches!(
            decide_sign(&class, SshApprovalPolicy::DiscloseOnTty, true),
            AuthorityDecision::Refuse(_)
        ));
    }
}
