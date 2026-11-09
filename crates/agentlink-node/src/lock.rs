//! Exclusive `data_dir` lock so only one node dials the relay per identity.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;

use agentlink_core::{Error, Result};

const LOCK_FILE: &str = "node.lock";

/// Held for the lifetime of [`crate::run`]. Dropping it releases the lock.
#[derive(Debug)]
pub(crate) struct NodeLock {
    _file: File,
}

/// Claim `data_dir/node.lock` for this process.
///
/// A second node on the same data directory dials the relay with the same
/// identity; each hello replaces the other socket and the loser sees
/// "Connection reset without closing handshake". Refuse the second start.
pub(crate) fn acquire_node_lock(data_dir: &Path) -> Result<NodeLock> {
    let path = data_dir.join(LOCK_FILE);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .map_err(|err| Error::Message(format!("open {}: {err}", path.display())))?;
    match file.try_lock() {
        Ok(()) => Ok(NodeLock { _file: file }),
        Err(TryLockError::WouldBlock) => Err(Error::Message(format!(
            "another agentlink node is already using data dir {}",
            data_dir.display()
        ))),
        Err(TryLockError::Error(err)) => {
            Err(Error::Message(format!("lock {}: {err}", path.display())))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_node_on_the_same_data_dir_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let first = acquire_node_lock(dir.path()).unwrap();
        assert!(dir.path().join(LOCK_FILE).exists());

        let err = acquire_node_lock(dir.path()).unwrap_err().to_string();
        assert!(err.contains("another agentlink node"), "{err}");
        assert!(err.contains(&dir.path().display().to_string()), "{err}");

        drop(first);
        acquire_node_lock(dir.path()).unwrap();
    }

    #[test]
    fn different_data_dirs_lock_independently() {
        let one = tempfile::tempdir().unwrap();
        let two = tempfile::tempdir().unwrap();
        let _first = acquire_node_lock(one.path()).unwrap();
        let _second = acquire_node_lock(two.path()).unwrap();
    }
}
