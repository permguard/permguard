// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The workspace lock: one mutating command at a time per `.permguard`.
//!
//! The same discipline as git's `index.lock` — an exclusively-created file
//! whose presence *is* the lock. Two terminals pulling and applying into the
//! same folder serialise here; readers never take it. The file records who
//! holds it, so the refusal can say something useful; a crash can leave it
//! behind, and the message says exactly what to remove.

use permguard_control_client::Store;

pub const LOCK_PATH: &str = ".permguard/lock";

/// Holds the lock for as long as it lives; dropping releases it.
pub struct LockGuard<'a> {
    store: &'a dyn Store,
}

impl<'a> LockGuard<'a> {
    /// Takes the lock or refuses, naming the holder found in the file.
    pub fn acquire(store: &'a dyn Store, holder: &str) -> Result<Self, String> {
        if store.create_exclusive(LOCK_PATH, holder.as_bytes())? {
            return Ok(Self { store });
        }
        let held_by = store
            .read(LOCK_PATH)?
            .map(|bytes| String::from_utf8_lossy(&bytes).trim().to_owned())
            .unwrap_or_default();
        Err(format!(
            "another permguard command is using this workspace ({held_by}); \
             if it crashed, remove {LOCK_PATH} and retry",
            held_by = if held_by.is_empty() {
                "holder unknown"
            } else {
                &held_by
            }
        ))
    }
}

impl Drop for LockGuard<'_> {
    fn drop(&mut self) {
        // Best-effort: an undeletable lock surfaces on the next acquire.
        let _ = self.store.remove(LOCK_PATH);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use permguard_control_client::FsStore;

    fn scratch() -> FsStore {
        let dir = std::env::temp_dir().join(format!(
            "permguard-workspace-lock-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        FsStore::new(dir)
    }

    #[test]
    fn the_lock_is_exclusive_and_released_on_drop() {
        let store = scratch();
        let guard = match LockGuard::acquire(&store, "pid 1") {
            Ok(guard) => guard,
            Err(error) => panic!("first acquire refused: {error}"),
        };
        let refused = match LockGuard::acquire(&store, "pid 2") {
            Err(refused) => refused,
            Ok(_) => panic!("the second acquire must refuse"),
        };
        assert!(refused.contains("pid 1"), "{refused}");
        assert!(refused.contains(LOCK_PATH));
        drop(guard);
        assert!(LockGuard::acquire(&store, "pid 3").is_ok());
    }
}
