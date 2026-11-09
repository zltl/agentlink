//! Property tests for framing, the block delta, path jail, and config parsing.

use agentlink_core::delta::{self, Plan};
use agentlink_core::frame::{self, DataFrame};
use agentlink_core::paths::{resolve_lexical, resolve_path};
use agentlink_core::protocol::PlanOp;
use agentlink_core::{load_settings, save_settings, ClientSettings};
use proptest::prelude::*;

fn apply_plan(old: &[u8], new_data: &[u8], plan: &Plan) -> Vec<u8> {
    let mut out = vec![0u8; new_data.len()];
    let mut cursor = 0u64;
    for op in &plan.ops {
        match *op {
            PlanOp::Copy { old: at, new, len } => {
                assert_eq!(new, cursor, "copy ops must cover the file in order");
                let at = at as usize;
                let new = new as usize;
                let len = len as usize;
                assert!(at + len <= old.len(), "copy reads past the old file");
                out[new..new + len].copy_from_slice(&old[at..at + len]);
                cursor += len as u64;
            }
            PlanOp::Lit { new, len } => {
                assert_eq!(new, cursor, "literal ops must cover the file in order");
                let new = new as usize;
                let len = len as usize;
                out[new..new + len].copy_from_slice(&new_data[new..new + len]);
                cursor += len as u64;
            }
        }
    }
    assert_eq!(cursor, new_data.len() as u64);
    assert_eq!(plan.literal_bytes + plan.copy_bytes, new_data.len() as u64);
    out
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn frame_roundtrip(
        offset in any::<u64>(),
        raw_len in any::<u32>(),
        payload in proptest::collection::vec(any::<u8>(), 0..4096),
        compressed in any::<bool>(),
        tar in any::<bool>(),
    ) {
        let frame = DataFrame {
            request_id: uuid::Uuid::new_v4().to_string(),
            offset,
            raw_len,
            compressed,
            tar,
            hole: false,
            payload,
        };
        let bytes = frame::encode(&frame).unwrap();
        prop_assert!(bytes.len() <= frame::MAX_FRAME);
        let routed = frame::request_id(&bytes);
        prop_assert_eq!(routed.as_deref(), Some(frame.request_id.as_str()));
        prop_assert_eq!(!frame::is_e2e(&bytes), true);
        let back = frame::decode(&bytes).unwrap();
        prop_assert_eq!(back, frame.clone());
        let sealed = frame::replace_payload(&bytes, &frame.payload, true).unwrap();
        prop_assert!(frame::is_e2e(&sealed));
        let opened = frame::decode(&sealed).unwrap();
        prop_assert_eq!(opened.payload, frame.payload);
        prop_assert_eq!(opened.request_id, frame.request_id);
    }

    #[test]
    fn frame_garbage_does_not_panic(data in proptest::collection::vec(any::<u8>(), 0..512)) {
        let _ = frame::decode(&data);
        let _ = frame::request_id(&data);
        let _ = frame::is_e2e(&data);
        if let Ok(frame) = frame::decode(&data) {
            if let Ok(again) = frame::encode(&frame) {
                let _ = frame::decode(&again);
            }
        }
    }

    #[test]
    fn delta_plan_roundtrip(
        old in proptest::collection::vec(any::<u8>(), 0..1200),
        new_data in proptest::collection::vec(any::<u8>(), 0..1200),
        block in 1usize..256,
    ) {
        let table = delta::signatures(&old, block);
        let plan = delta::plan(&new_data, &table);
        let got = apply_plan(&old, &new_data, &plan);
        prop_assert_eq!(got, new_data);
    }

    #[test]
    fn rolling_adler_matches_fresh(
        data in proptest::collection::vec(any::<u8>(), 1..180),
        window in 1usize..32,
    ) {
        prop_assume!(data.len() > window);
        let mut weak = delta::adler32(&data[..window]);
        for i in 0..data.len() - window {
            prop_assert_eq!(weak, delta::adler32(&data[i..i + window]));
            weak = delta::roll_adler(weak, window, data[i], data[i + window]);
        }
    }

    #[test]
    fn missing_ranges_cover_the_file_without_overlap(
        size in 0u64..5_000,
        starts in proptest::collection::vec(0u64..5_000, 0..6),
        lens in proptest::collection::vec(0u64..400, 0..6),
    ) {
        let have: Vec<_> = starts
            .into_iter()
            .zip(lens)
            .map(|(start, len)| agentlink_core::protocol::ByteRange {
                start: start.min(size),
                end: start.saturating_add(len).min(size),
            })
            .collect();
        let missing = delta::missing_ranges(size, &have);
        let mut cursor = 0u64;
        for range in &missing {
            prop_assert!(range.start >= cursor);
            prop_assert!(range.end <= size);
            prop_assert!(range.end > range.start);
            cursor = range.end;
        }
        let covered: u64 = delta::merge_ranges(have).iter().map(|r| r.len()).sum();
        let missed: u64 = missing.iter().map(|r| r.len()).sum();
        prop_assert!(covered + missed >= size || size == 0);
    }

    #[test]
    fn lexical_relative_paths_stay_in_the_jail(
        parts in proptest::collection::vec("[a-z0-9]{1,6}", 1..4),
    ) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let rel = parts.join("/");
        let resolved = resolve_lexical(Some(&root), &rel).unwrap();
        let root_c = std::fs::canonicalize(&root).unwrap();
        prop_assert!(resolved.starts_with(&root_c), "{resolved:?} not in {root_c:?}");
    }

    #[test]
    fn dotdot_cannot_escape(
        prefix in "[a-z]{0,4}",
    ) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let user = if prefix.is_empty() {
            "..".to_string()
        } else {
            format!("{prefix}/../../..")
        };
        let err = resolve_lexical(Some(&root), &user).unwrap_err();
        prop_assert!(err.to_string().contains("escapes"), "{err}");
    }

    #[test]
    fn config_roundtrip_trims_overrides(
        relay in "[a-z]{1,8}",
        token in "[a-z0-9]{1,12}",
        fp in "[a-f0-9]{8,16}",
    ) {
        let dir = tempfile::tempdir().unwrap();
        let relay_url = format!("wss://{relay}.example");
        let settings = ClientSettings {
            relay: relay_url.clone(),
            token: token.clone(),
            fingerprint: format!("sha256:{fp}"),
            trust: None,
        };
        save_settings(dir.path(), &settings).unwrap();
        let loaded = load_settings(dir.path(), None, None, None, None).unwrap();
        prop_assert_eq!(loaded.relay, relay_url.clone());
        prop_assert_eq!(loaded.token, settings.token);
        prop_assert_eq!(loaded.fingerprint, settings.fingerprint);
        let overridden = load_settings(
            dir.path(),
            Some("  ".into()),
            Some(format!("  {token}  ")),
            None,
            None,
        )
        .unwrap();
        prop_assert_eq!(overridden.relay, relay_url);
        prop_assert_eq!(overridden.token, token);
    }
}

#[test]
fn oversized_frame_is_rejected() {
    let mut bytes = vec![0u8; frame::MAX_FRAME + 1];
    bytes[0] = frame::FRAME_VERSION;
    bytes[1] = frame::KIND_DATA;
    let payload_len = (bytes.len() - frame::HEADER_LEN) as u32;
    bytes[32..36].copy_from_slice(&payload_len.to_le_bytes());
    let err = frame::decode(&bytes).unwrap_err();
    assert!(err.to_string().contains("too large"), "{err}");
}

#[test]
fn nul_byte_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let err = resolve_path(Some(&root), "a/\0b").unwrap_err();
    assert!(err.to_string().contains("NUL"), "{err}");
}

#[test]
fn malformed_config_does_not_invent_settings() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("config.json"), b"{").unwrap();
    let err = load_settings(dir.path(), None, None, None, None).unwrap_err();
    assert!(err.to_string().contains("missing"), "{err}");
    let err = agentlink_core::config::load_file(dir.path()).unwrap_err();
    assert!(
        err.to_string().contains("json") || err.to_string().contains("expected"),
        "{err}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_and_var_style_root_stay_inside() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    let outside = dir.path().join("outside");
    std::fs::create_dir(&real).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let resolved = resolve_lexical(Some(&link), "a/b").unwrap();
    let root_c = std::fs::canonicalize(&link).unwrap();
    assert!(resolved.starts_with(&root_c), "{resolved:?}");
    std::os::unix::fs::symlink(&outside, real.join("out")).unwrap();
    let err = resolve_path(Some(&link), "out/secret").unwrap_err();
    assert!(err.to_string().contains("escapes"), "{err}");

    #[cfg(target_os = "macos")]
    {
        let temp = std::env::temp_dir();
        let canon = std::fs::canonicalize(&temp).unwrap_or(temp.clone());
        let raw = temp.to_string_lossy();
        if raw.starts_with("/var") || raw.starts_with("/tmp") {
            let text = canon.to_string_lossy();
            assert!(
                text.starts_with("/private"),
                "macOS {raw} canonicalized to {text}, not /private"
            );
            let nested = canon.join("agentlink-var-jail");
            let _ = std::fs::remove_dir_all(&nested);
            if std::fs::create_dir(&nested).is_ok() {
                let child = resolve_lexical(Some(&nested), "child").unwrap();
                assert!(child.starts_with(&canon));
                let _ = std::fs::remove_dir_all(&nested);
            }
        }
    }
}

#[cfg(windows)]
#[test]
fn drive_letter_and_verbatim_prefix_cannot_leave_the_jail() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("root");
    std::fs::create_dir(&root).unwrap();
    for candidate in [r"C:\Windows", r"\\?\C:\Windows", r"D:\outside"] {
        match resolve_path(Some(&root), candidate) {
            Ok(path) => {
                let root_c = std::fs::canonicalize(&root).unwrap();
                assert!(
                    path.starts_with(&root_c),
                    "{candidate} resolved outside the jail to {}",
                    path.display()
                );
            }
            Err(err) => {
                let text = err.to_string();
                assert!(
                    text.contains("escapes")
                        || text.contains("not found")
                        || text.contains("sandbox")
                        || text.contains("cannot")
                        || text.contains("parent"),
                    "{candidate}: {text}"
                );
            }
        }
    }
    let _ = Path::new(r"\\?\");
}
