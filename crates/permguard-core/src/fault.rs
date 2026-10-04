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
//! | [`Fault::FsyncTimes`]   | the next flushes under the scope, as many as it says, fail; later ones succeed |
//! | [`Fault::WriteFails`]   | every write under the scope fails with an I/O error, writing nothing |
//! | [`Fault::DiskFull`]     | writes under the scope succeed until the quota is spent, then fail with `StorageFull`, writing nothing |
//!
//! A fault is scoped to a directory and every path below it — or, with [`inject_exact`], to one
//! path alone, which is how a test fails a directory's flush without failing the flushes of the
//! files in it — and held by the guard [`inject`] returns: tests running in parallel in one process do not see each other's faults. Nothing outside
//! the process can arm one — there is no variable, file or flag that does — so the hooks cost a
//! production store one atomic load per call and change nothing it does.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// A fault to inject under one scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// Every flush fails.
    Fsync,
    /// The next `remaining` flushes fail, and the ones after them succeed: how a test proves that a
    /// failed flush is not retried within one call. Every flush the rule covers counts against it,
    /// whatever other rules cover the same path, and a flush fails when any rule covering it fails
    /// it, so the outcome does not depend on the order faults were armed in.
    FsyncTimes { remaining: u64 },
    /// Writes succeed until this many bytes have been written, then fail without writing.
    DiskFull { remaining_bytes: u64 },
    /// Every write fails with an I/O error, writing nothing.
    WriteFails,
}

struct Rule {
    id: u64,
    scope: PathBuf,
    exact: bool,
    fault: Fault,
}

impl Rule {
    fn covers(&self, path: &Path) -> bool {
        if self.exact {
            path == self.scope
        } else {
            path.starts_with(&self.scope)
        }
    }
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
    arm(scope.as_ref(), fault, false)
}

/// Arms `fault` for exactly `path`, not what is below it, until the returned guard drops.
pub fn inject_exact(path: impl AsRef<Path>, fault: Fault) -> Injected {
    arm(path.as_ref(), fault, true)
}

fn arm(scope: &Path, fault: Fault, exact: bool) -> Injected {
    let id = NEXT_ID.fetch_add(1, Ordering::SeqCst);
    RULES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .push(Rule {
            id,
            scope: scope.to_path_buf(),
            exact,
            fault,
        });
    ARMED.fetch_add(1, Ordering::Release);

    Injected { id }
}

/// Runs `write`, which writes `len` bytes to a file at or below `path`, unless a write fault covers
/// that path or a disk-full fault for it has no room left for them. Whether the write fails is
/// decided over every rule before any quota is charged, so the order faults were armed in does
/// not matter and a failed write costs no quota.
pub fn write(path: &Path, len: usize, write: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    if ARMED.load(Ordering::Acquire) > 0 {
        let mut rules = RULES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let len = len as u64;
        if rules
            .iter()
            .any(|rule| rule.covers(path) && rule.fault == Fault::WriteFails)
        {
            return Err(io::Error::other("injected fault: the write failed"));
        }
        if rules.iter().any(|rule| {
            rule.covers(path)
                && matches!(rule.fault, Fault::DiskFull { remaining_bytes } if len > remaining_bytes)
        }) {
            return Err(io::Error::new(
                io::ErrorKind::StorageFull,
                "injected fault: no space left on device",
            ));
        }
        for rule in rules.iter_mut().filter(|rule| rule.covers(path)) {
            if let Fault::DiskFull { remaining_bytes } = &mut rule.fault {
                *remaining_bytes -= len;
            }
        }
    }

    write()
}

/// Runs `flush`, which flushes a file or directory at or below `path`, unless an fsync fault is
/// armed for that path.
pub fn sync(path: &Path, flush: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    if ARMED.load(Ordering::Acquire) > 0 {
        let mut rules = RULES
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut fails = false;
        for rule in rules.iter_mut().filter(|rule| rule.covers(path)) {
            match &mut rule.fault {
                Fault::Fsync => fails = true,
                Fault::FsyncTimes { remaining } if *remaining > 0 => {
                    *remaining -= 1;
                    fails = true;
                }
                _ => {}
            }
        }
        if fails {
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
        {
            let _exact = inject_exact(&outside, Fault::Fsync);
            assert!(
                sync(&outside, ok).is_err(),
                "an exact fault covers its path"
            );
            assert!(
                sync(&outside.join("file"), ok).is_ok(),
                "and nothing below it"
            );
        }
        {
            let _once = inject_exact(&outside, Fault::FsyncTimes { remaining: 1 });
            let _always = inject_exact(&outside, Fault::Fsync);
            assert!(sync(&outside, ok).is_err(), "the first flush fails");
            drop(_always);
            assert!(
                sync(&outside, ok).is_ok(),
                "the once-only rule counted the flush another rule also failed"
            );
        }
        assert!(write(&inside, 10, ok).is_ok(), "writes are untouched");
        drop(guard);
        assert!(sync(&inside, ok).is_ok(), "lifted with its guard");
        {
            let _full = inject(&volume, Fault::DiskFull { remaining_bytes: 5 });
            let fails = inject(&volume, Fault::WriteFails);
            assert!(write(&inside, 1, ok).is_err(), "a write fault fails writes");
            assert!(sync(&inside, ok).is_ok(), "and not flushes");
            drop(fails);
            assert!(
                write(&inside, 5, ok).is_ok(),
                "the failed write charged no quota, whatever the order"
            );
        }
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
