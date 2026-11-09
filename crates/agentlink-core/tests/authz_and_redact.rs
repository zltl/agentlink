use std::collections::BTreeSet;

use agentlink_core::audit::AuditPolicy;
use agentlink_core::grant::resolve_e2e_policy;
use agentlink_core::permissions::NodePolicy;

#[test]
fn relay_authenticated_session_stays_full_and_a_missing_grant_does_not() {
    let mut trusted = BTreeSet::new();
    trusted.insert("issuer".into());
    let stamped = resolve_e2e_policy(
        &trusted,
        &BTreeSet::new(),
        None,
        "node-b",
        "device",
        1_700_000_000,
        NodePolicy::none(),
        false,
        Some(NodePolicy::full()),
        None,
    )
    .expect("account session");
    assert!(stamped.allow_exec);
    let missing = resolve_e2e_policy(
        &trusted,
        &BTreeSet::new(),
        None,
        "node-b",
        "device",
        1_700_000_000,
        NodePolicy::full(),
        false,
        Some(NodePolicy::none()),
        None,
    );
    assert!(missing.is_err(), "owner keys still bind a non-account session");
}

#[test]
fn approval_redaction_uses_audit_patterns() {
    let policy = AuditPolicy::preset("standard").unwrap();
    let out = policy
        .redact
        .apply("curl -H 'Authorization: Bearer super-secret-token' https://example.invalid");
    assert!(!out.contains("super-secret-token"), "{out}");
    assert!(out.contains("[redacted]"), "{out}");
}
