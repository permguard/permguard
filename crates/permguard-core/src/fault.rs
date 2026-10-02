// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Storage faults a test can ask for: an fsync that fails, and a disk that fills.
//!
//! A durable store is only as correct as its behaviour when the disk refuses. Those refusals are
//! rare and hard to provoke on a real filesystem, so the stores route their durability-relevant
//! writes and flushes through [`write`] and [`sync`], and a test [`inject`]s a fault for the
//! directory it owns:
//!
//! ```
//! use permguard_core::fault::{self, Fault};
//!
//! let volume = std::env::temp_dir().join("permguard-fault-doc");
//! let _fsync_fails = fault::inject(&volume, Fault::Fsync);
//! // … a store under `volume` now sees every flush fail with an I/O error, until the guard drops.
//! ```
//!
//! | Fault                   | What the store sees                                                      |
//! | ----------------------- | ------------------------------------------------------------------------ |
//! | [`Fault::Fsync`]        | every flush under the scope fails with an I/O error; the bytes written stay where they are |
//! | [`Fault::DiskFull`]     | writes under the scope succeed until the quota is spent, then fail with `StorageFull`, writing nothing |
//!
//! A fault is scoped to a directory and every path below it, and held by the guard [`inject`]
//! returns: tests running in parallel in one process do not see each other's faults. Nothing outside
//! the process can arm one — there is no variable, file or flag that does — so the hooks cost a
//! production store one relaxed atomic load per call and change nothing it does.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// A fault to inject under one scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Every flush fails.
    Fsync,
    /// Writes succeed until this many bytes have been written, then fail without writing.
    DiskFull { remaining_bytes: u64 },
}

struct Rule {
    id: u64,
    scope: PathBuf,
    fault: Fault,
}

static RULES: Mutex<Vec<Rule>> = Mutex::new(Vec::new());
static ARMED: AtomicUsize = AtomicUsize::new(0);
static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// Holds a fault in place; dropping it lifts the fault.
#[must_use = "the fault is lifted as soon as the guard drops"]
pub struct Injected {
    id: u64,
}

impl Drop for Injected {
    fn drop(&mut self) {
        let mut rules = RULES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let before = rules.len();
        rules.retain(|rule| rule.id != self.id);
        if rules.len() < before {
            ARMED.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Arms `fault` for `scope` and every path below it, until the returned guard drops.
pub fn inject(scope: impl AsRef<Path>, fault: Fault) -> Injected {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    RULES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(Rule {
            id,
            scope: scope.as_ref().to_path_buf(),
            fault,
        });
    ARMED.fetch_add(1, Ordering::SeqCst);

    Injected { id }
}

/// Runs `write`, which writes `len` bytes to a file at or below `path`, unless a disk-full fault
/// for that path has no room left for them.
pub fn write(path: &Path, len: usize, write: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    if ARMED.load(Ordering::Relaxed) > 0 {
        let mut rules = RULES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for rule in rules
            .iter_mut()
            .filter(|rule| path.starts_with(&rule.scope))
        {
            if let Fault::DiskFull { remaining_bytes } = &mut rule.fault {
                let len = len as u64;
                if len > *remaining_bytes {
                    return Err(io::Error::new(
                        io::ErrorKind::StorageFull,
                        "injected fault: no space left on device",
                    ));
                }
                *remaining_bytes -= len;
            }
        }
    }

    write()
}

/// Runs `flush`, which flushes a file or directory at or below `path`, unless an fsync fault is
/// armed for that path.
pub fn sync(path: &Path, flush: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    if ARMED.load(Ordering::Relaxed) > 0 {
        let rules = RULES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if rules
            .iter()
            .any(|rule| rule.fault == Fault::Fsync && path.starts_with(&rule.scope))
        {
            return Err(io::Error::other("injected fault: fsync failed"));
        }
    }

    flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("permguard-fault-{name}-{}", std::process::id()))
    }

    #[test]
    fn test_an_fsync_fault_fails_flushes_under_its_scope_only_while_held() {
        let volume = scope("fsync");
        let inside = volume.join("segment");
        let outside = scope("fsync-other").join("segment");
        let ok = || Ok(());

        let guard = inject(&volume, Fault::Fsync);
        assert!(sync(&inside, ok).is_err());
        assert!(sync(&volume, ok).is_err(), "the scope itself is covered");
        assert!(sync(&outside, ok).is_ok(), "a sibling scope is not");
        assert!(write(&inside, 10, ok).is_ok(), "writes are untouched");
        drop(guard);
        assert!(sync(&inside, ok).is_ok(), "lifted with its guard");
    }

    #[test]
    fn test_a_full_disk_accepts_writes_until_its_quota_and_then_writes_nothing() {
        let volume = scope("full");
        let path = volume.join("segment");
        let _full = inject(
            &volume,
            Fault::DiskFull {
                remaining_bytes: 10,
            },
        );
        let mut written = 0usize;
        let mut count = |len: usize| {
            write(&path, len, || {
                written += len;
                Ok(())
            })
        };

        assert!(count(6).is_ok());
        assert!(count(4).is_ok());
        let Err(refused) = count(1) else {
            panic!("the quota is spent and the write was accepted");
        };
        assert_eq!(refused.kind(), io::ErrorKind::StorageFull);
        assert_eq!(written, 10, "the refused write wrote nothing");
        assert!(sync(&path, || Ok(())).is_ok(), "flushes are untouched");
    }
}
