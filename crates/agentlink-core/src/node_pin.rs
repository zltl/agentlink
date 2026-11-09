//! Trust-on-first-use pin of a node name to its ed25519 id.
//!
//! End-to-end sessions are bound to the node id (the public key). A relay
//! that is only checked by a public CA can still tell the client that a
//! familiar name belongs to a different key. The first successful listing
//! stores the id. A later change is reported and is not written over the
//! saved pin. Callers refuse commands to that name until the file is edited
//! on purpose.
//!
//! This is not a substitute for pinning the relay certificate.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::util;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinStatus {
    /// First time this name was seen. The id is now stored.
    Saved,
    /// The stored id matches.
    Unchanged,
    /// The relay presented a different id. The file was not changed.
    Mismatch { previous: String },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct PinFile {
    #[serde(default)]
    nodes: BTreeMap<String, String>,
}

pub fn pin_path(dir: &Path) -> std::path::PathBuf {
    dir.join("node-pins.json")
}

/// Reverse lookup: the pinned name for `id`, if any.
///
/// Ids match case-insensitively. When several names share one id the first
/// in name order wins, so repeated calls stay stable.
pub fn name_for_id(dir: &Path, id: &str) -> Result<Option<String>> {
    let id = id.trim();
    if id.is_empty() {
        return Ok(None);
    }
    let path = pin_path(dir);
    if !path.exists() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&path)?;
    let file = serde_json::from_str::<PinFile>(&text)
        .map_err(|err| Error::Message(format!("node-pins.json: {err}")))?;
    Ok(file
        .nodes
        .into_iter()
        .find(|(_, pinned)| pinned.eq_ignore_ascii_case(id))
        .map(|(name, _)| name))
}

/// Compare `id` with the pin for `name`, storing it on the first sighting.
pub fn observe(dir: &Path, name: &str, id: &str) -> Result<PinStatus> {
    let name = name.trim();
    let id = id.trim().to_ascii_lowercase();
    if name.is_empty() || id.is_empty() {
        return Err(Error::Message("node pin needs a name and an id".into()));
    }
    let path = pin_path(dir);
    let mut file = if path.exists() {
        let text = std::fs::read_to_string(&path)?;
        serde_json::from_str::<PinFile>(&text)
            .map_err(|err| Error::Message(format!("node-pins.json: {err}")))?
    } else {
        PinFile::default()
    };
    if let Some(previous) = file.nodes.get(name) {
        if previous.eq_ignore_ascii_case(&id) {
            return Ok(PinStatus::Unchanged);
        }
        return Ok(PinStatus::Mismatch {
            previous: previous.clone(),
        });
    }
    file.nodes.insert(name.to_string(), id);
    if let Some(parent) = path.parent() {
        util::ensure_dir(parent)?;
    }
    util::write_secret(&path, serde_json::to_string_pretty(&file)?.as_bytes())?;
    Ok(PinStatus::Saved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_id_is_kept_and_a_substitute_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let first = "ab".repeat(32);
        let second = "cd".repeat(32);
        assert_eq!(
            observe(dir.path(), "laptop", &first).unwrap(),
            PinStatus::Saved
        );
        assert_eq!(
            observe(dir.path(), "laptop", &first).unwrap(),
            PinStatus::Unchanged
        );
        match observe(dir.path(), "laptop", &second).unwrap() {
            PinStatus::Mismatch { previous } => assert_eq!(previous, first),
            other => panic!("expected mismatch, got {other:?}"),
        }
        let text = std::fs::read_to_string(pin_path(dir.path())).unwrap();
        assert!(text.contains(&first));
        assert!(!text.contains(&second));
    }

    #[test]
    fn reverse_lookup_is_case_insensitive_and_stable() {
        let dir = tempfile::tempdir().unwrap();
        let id = "ab".repeat(32);
        assert_eq!(
            name_for_id(dir.path(), &id).unwrap(),
            None,
            "missing file means no name"
        );
        observe(dir.path(), "zeta", &id).unwrap();
        observe(dir.path(), "alpha", &id).unwrap();
        assert_eq!(
            name_for_id(dir.path(), &id.to_ascii_uppercase())
                .unwrap()
                .as_deref(),
            Some("alpha")
        );
        assert_eq!(name_for_id(dir.path(), &"cd".repeat(32)).unwrap(), None);
        assert_eq!(name_for_id(dir.path(), "  ").unwrap(), None);
    }
}
