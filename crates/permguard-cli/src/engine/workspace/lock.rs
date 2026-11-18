// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The workspace lock: one mutating command at a time per `.permguard`.
//!
//! An operating system lock on `.permguard/lock`, held for as long as the command runs: two
//! terminals pulling and applying into the same folder serialise here; readers never take it.
//! The kernel releases it when the process ends, however it ends, a `SIGTERM` or a `SIGKILL`
//! included, so a command that died never leaves the workspace locked (BUG-0212). The file
//! records who holds it, so a refusal can say who; it stays on disk between commands, since
//! removing it while another process opens it would let two of them each lock a file of their
//! own.

use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::Path;

pub const LOCK_PATH: &str = ".permguard/lock";

/// Holds the lock for as long as it lives; dropping releases it.
pub struct LockGuard {
    file: File,
}

/// Why the lock was not taken.
#[derive(Debug)]
pub enum Refused {
    /// A live process holds it: who, as its file says.
    Held(String),
    /// The lock file could not be opened or locked.
    Unusable(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Held(holder) => write!(
                formatter,
                "another permguard command is using this workspace ({holder}); wait for it to \
                 finish and retry"
            ),
            Self::Unusable(detail) => write!(formatter, "locking the workspace: {detail}"),
        }
    }
}

impl LockGuard {
    /// Takes the lock of the workspace at `root`, recording `holder`, or refuses, naming the
    /// holder found in the file.
    pub fn acquire(root: &Path, holder: &str) -> Result<Self, Refused> {
        let path = root.join(LOCK_PATH);
        let unusable =
            |error: std::io::Error| Refused::Unusable(format!("{}: {error}", path.display()));
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(unusable)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                // Read through the path, not the locked handle: where the lock is mandatory, the
                // holder's bytes may not be readable, and the refusal still stands.
                let mut held_by = String::new();
                let _ = File::open(&path).and_then(|mut file| file.read_to_string(&mut held_by));
                let held_by = held_by.trim();
                return Err(Refused::Held(if held_by.is_empty() {
                    "holder unknown".to_owned()
                } else {
                    held_by.to_owned()
                }));
            }
            Err(TryLockError::Error(error)) => return Err(unusable(error)),
        }
        // Whoever held it before is gone: what its file says is replaced.
        file.set_len(0).map_err(unusable)?;
        file.seek(SeekFrom::Start(0)).map_err(unusable)?;
        file.write_all(holder.as_bytes()).map_err(unusable)?;
        Ok(Self { file })
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        // Said by nobody once released; closing the handle releases the lock itself.
        let _ = self.file.set_len(0);
        let _ = self.file.unlock();
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "permguard-workspace-lock-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join(".permguard")).expect("the workspace");
        dir
    }

    #[test]
    fn the_lock_is_exclusive_and_released_on_drop() {
        let root = scratch("exclusive");
        let guard = LockGuard::acquire(&root, "pid 1").expect("the first acquire");
        let refused = match LockGuard::acquire(&root, "pid 2") {
            Err(Refused::Held(holder)) => holder,
            Err(other) => panic!("refused otherwise: {other}"),
            Ok(_) => panic!("the second acquire must refuse"),
        };
        // Where the lock is advisory the holder is read; where it is mandatory it may not be.
        assert!(
            refused.contains("pid 1") || refused == "holder unknown",
            "{refused}"
        );
        drop(guard);
        assert!(LockGuard::acquire(&root, "pid 3").is_ok());
    }

    /// BUG-0212: a lock file a dead process left behind, holder and all, locks nothing.
    #[test]
    fn a_lock_file_left_by_a_dead_process_is_taken_over() {
        let root = scratch("stale");
        std::fs::write(root.join(LOCK_PATH), "pid 999999 since then").expect("a stale file");
        let guard = LockGuard::acquire(&root, "pid 4").expect("a stale lock is taken over");
        drop(guard);
        assert!(
            root.join(LOCK_PATH).exists(),
            "the file stays, so no two processes lock two files"
        );
    }
}
