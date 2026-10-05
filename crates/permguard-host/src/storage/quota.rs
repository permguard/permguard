// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Quotas and the emergency floor: a write reserves its bytes and files before it lands.
//!
//! # Accounts
//!
//! A [`Quota`] keeps one account per scope, in memory. A scope is a path — the Host, a Plane, a
//! resource, then a stream or an upload session — and each account is measured from its directory,
//! so nothing is persisted and a crash costs only a new measurement. Sizes are the files' apparent
//! lengths; every file and directory is an inode.
//!
//! An account with a limit is measured when it is opened: enforcing the limit needs the count. One
//! without a limit — the Host's, by default — is measured later, by [`Quota::measure_pending`],
//! which the background pass calls, so startup never walks a large store; until then it counts
//! only what landed since, and [`Quota::usage`] says it is being measured. The floor does not
//! depend on any of this: it is judged against the filesystem's own free space.
//!
//! A [`Reservation`] charges every scope of its path at once, before anything is written, and is
//! refused when one of them would pass its [`Limit`]. What lands is recorded with
//! [`Reservation::land`]; a reservation dropped without landing is released whole.
//!
//! # The floor
//!
//! | Level   | [`Class::Ordinary`] writers may use        | [`Class::Maintenance`] writers may use |
//! | ------- | ------------------------------------------ | -------------------------------------- |
//! | quota   | what each scope of their path still allows | the same                               |
//! | floor   | nothing: they never take free space below  | the floor, down to their reserve       |
//! | reserve | nothing                                    | nothing: the last bytes stay free      |
//!
//! The floor and the reserve are [`Floors`]: `storage.floors.free_*` and
//! `storage.floors.maintenance_*`. They bind the writers charged to the quota; a write that is not
//! charged — a store still on its own format, a journal's failure record, another process — is
//! outside it. Free space is what the filesystem reports for an unprivileged
//! writer, less every reservation not yet landed; under a test's disk-full fault it is no more than
//! the fault leaves ([`permguard_core::fault::free_bytes`]).
//!
//! # Readiness
//!
//! [`Quota::readiness`] is false as soon as free space is below the floor plus the largest write a
//! journal under the quota may make, so the next required write is refused before it crosses the
//! floor, never in the middle of it. It is true again once space returns: every reservation, landing
//! and release judges it again, and so does [`Quota::refresh`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use permguard_core::volume::{Floors, Limit};

use super::journal::Readiness;
use super::{Dir, Result, StorageError};

/// Who is writing: an ordinary writer keeps the floor free; maintenance — garbage collection,
/// retention, the audit of their own action — may use it down to its reserve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Ordinary,
    Maintenance,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Account {
    limit: Limit,
    used_bytes: u64,
    used_files: u64,
    reserved_bytes: u64,
    reserved_files: u64,
    /// The directory it is measured from.
    dir: std::path::PathBuf,
    measured: bool,
}

fn limited(limit: &Limit) -> bool {
    limit.bytes.is_some() || limit.inodes.is_some()
}

#[derive(Debug)]
struct State {
    accounts: BTreeMap<Vec<String>, Account>,
    reserved_bytes: u64,
    reserved_files: u64,
    largest_write: u64,
}

#[derive(Debug)]
struct Shared {
    root: Dir,
    floors: Floors,
    state: Mutex<State>,
    readiness: Readiness,
}

/// The quotas of one volume, shared by every writer of it.
#[derive(Debug, Clone)]
pub struct Quota(Arc<Shared>);

/// One scope's account, as [`Quota::usage`] reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeUsage {
    /// The scope's path, `host` for the Host, then its names joined with `/`.
    pub scope: String,
    pub limit: Limit,
    pub used_bytes: u64,
    pub used_files: u64,
    pub reserved_bytes: u64,
    pub reserved_files: u64,
    /// Whether the account was measured: an account without a limit is measured in the background,
    /// and counts only what landed since the start until it is.
    pub measured: bool,
}

/// What `storage quota show` reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Usage {
    pub scopes: Vec<ScopeUsage>,
    pub floors: Floors,
    /// Free bytes as the floor judges them: the filesystem's, less every pending reservation.
    pub free_bytes: u64,
    /// Free inodes the same way, where the filesystem limits them.
    pub free_inodes: Option<u64>,
    pub ready: bool,
}

impl Quota {
    /// The quotas of the volume whose root is `root`, the Host account measured from it.
    pub fn open(root: Dir, floors: Floors, host: Limit) -> Result<Self> {
        // The reserve is the last of the floor: a reserve above it would leave maintenance less
        // room than ordinary writers.
        if floors.maintenance_bytes > floors.free_bytes
            || floors.maintenance_inodes > floors.free_inodes
        {
            return Err(StorageError::Refused(format!(
                "the maintenance reserve ({} bytes, {} inodes) exceeds the floor ({} bytes, {} \
                 inodes) it is part of",
                floors.maintenance_bytes,
                floors.maintenance_inodes,
                floors.free_bytes,
                floors.free_inodes
            )));
        }
        let measured = limited(&host);
        let (used_bytes, used_files) = if measured { measure(&root)? } else { (0, 0) };
        let mut accounts = BTreeMap::new();
        accounts.insert(
            Vec::new(),
            Account {
                limit: host,
                used_bytes,
                used_files,
                dir: root.path().to_path_buf(),
                measured,
                ..Account::default()
            },
        );
        let quota = Self(Arc::new(Shared {
            root,
            floors,
            state: Mutex::new(State {
                accounts,
                reserved_bytes: 0,
                reserved_files: 0,
                largest_write: 0,
            }),
            readiness: Readiness::new(),
        }));
        quota.refresh()?;

        Ok(quota)
    }

    /// The Host's scope, for `class`.
    pub fn host(&self, class: Class) -> Scope {
        Scope {
            quota: self.clone(),
            path: Vec::new(),
            class,
        }
    }

    /// Whether a required journal may still write: false once free space is below the floor plus
    /// the largest write a journal under this quota may make.
    pub fn readiness(&self) -> Readiness {
        self.0.readiness.clone()
    }

    /// Records that a writer under this quota may write `bytes` at once: readiness keeps that much
    /// above the floor.
    pub fn note_largest_write(&self, bytes: u64) -> Result<()> {
        {
            let mut state = self.state();
            state.largest_write = state.largest_write.max(bytes);
        }
        self.refresh()
    }

    /// Measures every account not measured yet, the ones without a limit; answers how many. Called
    /// by the background pass, off the startup path. A measurement races the writers it counts, so
    /// for these accounts, which enforce nothing, the figure is a report, not a bound.
    pub fn measure_pending(&self) -> Result<usize> {
        let pending: Vec<(Vec<String>, std::path::PathBuf)> = self
            .state()
            .accounts
            .iter()
            .filter(|(_, account)| !account.measured)
            .map(|(path, account)| (path.clone(), account.dir.clone()))
            .collect();
        for (path, dir) in &pending {
            // A directory gone since its account was opened is measured as empty, not a failed pass.
            let (bytes, files) = match Dir::open(dir) {
                Ok(dir) => measure(&dir)?,
                Err(_) if !dir.exists() => (0, 0),
                Err(error) => return Err(error),
            };
            if let Some(account) = self.state().accounts.get_mut(path) {
                account.used_bytes = bytes;
                account.used_files = files;
                account.measured = true;
            }
        }
        self.refresh()?;

        Ok(pending.len())
    }

    /// Judges readiness again against the space the filesystem reports now.
    pub fn refresh(&self) -> Result<()> {
        let state = self.state();
        self.judge(&state)?;

        Ok(())
    }

    /// Every account, the floors and the free space, for `storage quota show`.
    pub fn usage(&self) -> Result<Usage> {
        let state = self.state();
        let (free_bytes, free_inodes) = self.free(&state)?;
        let scopes = state
            .accounts
            .iter()
            .map(|(path, account)| ScopeUsage {
                scope: name_of(path),
                limit: account.limit,
                used_bytes: account.used_bytes,
                used_files: account.used_files,
                reserved_bytes: account.reserved_bytes,
                reserved_files: account.reserved_files,
                measured: account.measured,
            })
            .collect();

        Ok(Usage {
            scopes,
            floors: self.0.floors,
            free_bytes,
            free_inodes,
            ready: self.judge(&state)?,
        })
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Free bytes and inodes as the floor judges them: the filesystem's figure — no more than a
    /// test's disk-full fault leaves — less every pending reservation.
    fn free(&self, state: &State) -> Result<(u64, Option<u64>)> {
        let space = self.0.root.free_space()?;
        let bytes = match permguard_core::fault::free_bytes(self.0.root.path()) {
            Some(left) => space.bytes.min(left),
            None => space.bytes,
        };
        Ok((
            bytes.saturating_sub(state.reserved_bytes),
            space
                .inodes
                .map(|inodes| inodes.saturating_sub(state.reserved_files)),
        ))
    }

    fn judge(&self, state: &State) -> Result<bool> {
        let (bytes, inodes) = self.free(state)?;
        let floors = &self.0.floors;
        // One largest write of bytes, and one inode — a journal's roll — above the floor.
        let ready = bytes >= floors.free_bytes.saturating_add(state.largest_write)
            && inodes.is_none_or(|inodes| inodes >= floors.free_inodes.saturating_add(1));
        self.0.readiness.set(ready);

        Ok(ready)
    }
}

/// A scope of the quota: a path of accounts and the class of the writer using it.
#[derive(Debug, Clone)]
pub struct Scope {
    quota: Quota,
    path: Vec<String>,
    class: Class,
}

impl Scope {
    /// The account `name` below this one, measured from `dir` and bounded by `limit`: a Plane
    /// below the Host, a resource below a Plane, a stream or an upload session below a resource.
    /// Opening an account that exists already answers it with its new limit, keeping its counts:
    /// they are live, and a second measurement would race the writers it counts.
    pub fn child(&self, name: &str, dir: &Dir, limit: Limit) -> Result<Self> {
        let mut path = self.path.clone();
        path.push(super::dir::component(name)?.to_owned());
        // Measured now when the account enforces a limit and was not measured yet; an account
        // already measured keeps its live counts.
        // What the account had counted before the walk: whatever lands during it is added on top.
        let before = self
            .quota
            .state()
            .accounts
            .get(&path)
            .map(|account| (account.measured, account.used_bytes, account.used_files));
        let already = before.is_some_and(|(measured, _, _)| measured);
        let measured = if limited(&limit) && !already {
            Some(measure(dir)?)
        } else {
            None
        };
        {
            let mut state = self.quota.state();
            match state.accounts.get_mut(&path) {
                Some(account) => {
                    account.limit = limit;
                    if let Some((used_bytes, used_files)) = measured
                        && !account.measured
                    {
                        // Landings counted while the directory was walked are not lost: the walk
                        // may have missed them, and the account enforces its limit from now on.
                        let (_, bytes_before, files_before) = before.unwrap_or_default();
                        account.used_bytes = used_bytes
                            .saturating_add(account.used_bytes.saturating_sub(bytes_before));
                        account.used_files = used_files
                            .saturating_add(account.used_files.saturating_sub(files_before));
                        account.measured = true;
                    }
                }
                None => {
                    let (used_bytes, used_files) = measured.unwrap_or_default();
                    state.accounts.insert(
                        path.clone(),
                        Account {
                            limit,
                            used_bytes,
                            used_files,
                            dir: dir.path().to_path_buf(),
                            measured: measured.is_some(),
                            ..Account::default()
                        },
                    );
                }
            }
        }

        Ok(Self {
            quota: self.quota.clone(),
            path,
            class: self.class,
        })
    }

    /// This scope, for a maintenance writer.
    pub fn maintenance(&self) -> Self {
        Self {
            class: Class::Maintenance,
            ..self.clone()
        }
    }

    /// The quota this scope belongs to.
    pub fn quota(&self) -> &Quota {
        &self.quota
    }

    /// Reserves `bytes` and `files` on every scope of this path, before they are written.
    ///
    /// Refused with [`StorageError::QuotaExceeded`] when a scope would pass its limit, and with
    /// [`StorageError::BelowFloor`] when free space would drop below what this class must leave.
    pub fn reserve(&self, bytes: u64, files: u64) -> Result<Reservation> {
        let mut state = self.quota.state();
        for depth in 0..=self.path.len() {
            let prefix = &self.path[..depth];
            let Some(account) = state.accounts.get(prefix) else {
                continue;
            };
            let over = |limit: Option<u64>, used: u64, reserved: u64, more: u64| {
                limit
                    .is_some_and(|limit| used.saturating_add(reserved).saturating_add(more) > limit)
            };
            if over(
                account.limit.bytes,
                account.used_bytes,
                account.reserved_bytes,
                bytes,
            ) || over(
                account.limit.inodes,
                account.used_files,
                account.reserved_files,
                files,
            ) {
                return Err(StorageError::QuotaExceeded(format!(
                    "{} more bytes and {files} more files would pass the quota of `{}` (bytes \
                     {:?}, inodes {:?}; {} bytes and {} files used)",
                    bytes,
                    name_of(prefix),
                    account.limit.bytes,
                    account.limit.inodes,
                    account.used_bytes,
                    account.used_files
                )));
            }
        }

        let (free_bytes, free_inodes) = self.quota.free(&state)?;
        let floors = &self.quota.0.floors;
        let (keep_bytes, keep_inodes) = match self.class {
            Class::Ordinary => (floors.free_bytes, floors.free_inodes),
            Class::Maintenance => (floors.maintenance_bytes, floors.maintenance_inodes),
        };
        if free_bytes < bytes.saturating_add(keep_bytes)
            || free_inodes.is_some_and(|inodes| inodes < files.saturating_add(keep_inodes))
        {
            let refused = StorageError::BelowFloor(format!(
                "{bytes} bytes and {files} files would leave {} bytes and {} inodes free, below \
                 the {} bytes and {} inodes a {} writer must leave",
                free_bytes.saturating_sub(bytes),
                free_inodes.map_or_else(
                    || "unlimited".to_owned(),
                    |inodes| inodes.saturating_sub(files).to_string()
                ),
                keep_bytes,
                keep_inodes,
                match self.class {
                    Class::Ordinary => "required",
                    Class::Maintenance => "maintenance",
                }
            ));
            self.quota.judge(&state)?;
            return Err(refused);
        }

        state.reserved_bytes += bytes;
        state.reserved_files += files;
        for depth in 0..=self.path.len() {
            if let Some(account) = state.accounts.get_mut(&self.path[..depth]) {
                account.reserved_bytes += bytes;
                account.reserved_files += files;
            }
        }
        self.quota.judge(&state)?;

        Ok(Reservation {
            scope: self.clone(),
            bytes,
            files,
        })
    }

    /// Records that `bytes` and `files` were removed below this scope: a deletion, or the old
    /// content a replacement superseded.
    pub fn freed(&self, bytes: u64, files: u64) -> Result<()> {
        let mut state = self.quota.state();
        for depth in 0..=self.path.len() {
            if let Some(account) = state.accounts.get_mut(&self.path[..depth]) {
                account.used_bytes = account.used_bytes.saturating_sub(bytes);
                account.used_files = account.used_files.saturating_sub(files);
            }
        }
        self.quota.judge(&state)?;

        Ok(())
    }
}

/// Bytes and files held back on every scope of a path until they land; dropping it unlanded
/// releases them.
#[derive(Debug)]
#[must_use = "a reservation is released as soon as it drops"]
pub struct Reservation {
    scope: Scope,
    bytes: u64,
    files: u64,
}

impl Reservation {
    /// Records what landed, at most what was reserved, and releases the rest. It cannot fail: a
    /// writer calls it after its bytes are durable, when there is nothing left to refuse.
    pub fn land(self, bytes: u64, files: u64) {
        let (bytes, files) = (bytes.min(self.bytes), files.min(self.files));
        {
            let mut state = self.scope.quota.state();
            for depth in 0..=self.scope.path.len() {
                if let Some(account) = state.accounts.get_mut(&self.scope.path[..depth]) {
                    account.used_bytes += bytes;
                    account.used_files += files;
                }
            }
        }
        // `Drop` releases what was reserved; what landed is now counted as used.
        drop(self);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.scope.quota.state();
        state.reserved_bytes = state.reserved_bytes.saturating_sub(self.bytes);
        state.reserved_files = state.reserved_files.saturating_sub(self.files);
        for depth in 0..=self.scope.path.len() {
            if let Some(account) = state.accounts.get_mut(&self.scope.path[..depth]) {
                account.reserved_bytes = account.reserved_bytes.saturating_sub(self.bytes);
                account.reserved_files = account.reserved_files.saturating_sub(self.files);
            }
        }
        let _ = self.scope.quota.judge(&state);
    }
}

fn name_of(path: &[String]) -> String {
    if path.is_empty() {
        "host".to_owned()
    } else {
        path.join("/")
    }
}

/// The apparent bytes of every file below `dir`, and how many files and directories it holds.
///
/// Walked with an explicit stack, so a deep tree costs memory, not the thread's stack. A name that
/// disappears between the listing and its measurement — a sweep, a deletion — counts as nothing.
fn measure(dir: &Dir) -> Result<(u64, u64)> {
    let (mut bytes, mut files) = (0u64, 0u64);
    let mut pending: Vec<Dir> = vec![Dir::open(dir.path())?];
    while let Some(dir) = pending.pop() {
        for name in dir.names()? {
            let path = dir.child_path(&name);
            match std::fs::symlink_metadata(&path) {
                Ok(metadata) => {
                    bytes = bytes.saturating_add(metadata.len());
                    files = files.saturating_add(1);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(super::io(format!("measuring {}", path.display()))(error));
                }
            }
        }
        for name in dir.subdirs()? {
            match dir.subdir(&name, false) {
                Ok(below) => {
                    files = files.saturating_add(1);
                    pending.push(below);
                }
                Err(_) if !dir.child_path(&name).exists() => {}
                Err(error) => return Err(error),
            }
        }
    }

    Ok((bytes, files))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> Dir {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-quota-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        Dir::create_root(&path).expect("a scratch directory")
    }

    fn again(dir: &Dir) -> Dir {
        Dir::open(dir.path()).expect("opened again")
    }

    fn small_floors() -> Floors {
        Floors {
            free_bytes: 4096,
            free_inodes: 1,
            maintenance_bytes: 1024,
            maintenance_inodes: 1,
        }
    }

    #[test]
    fn accounts_are_measured_at_open_and_every_scope_of_a_path_is_charged() {
        let root = scratch("measure");
        let plane = root.subdir("control", true).expect("plane");
        std::fs::write(plane.child_path("held"), [0u8; 300]).expect("a file");
        let quota = Quota::open(again(&root), small_floors(), Limit::default()).expect("opens");
        let plane = quota
            .host(Class::Ordinary)
            .child(
                "control",
                &plane,
                Limit {
                    bytes: Some(1000),
                    inodes: None,
                },
            )
            .expect("account");

        // The Host has no limit: startup does not walk it; the background pass measures it.
        let host = |usage: &Usage| {
            usage
                .scopes
                .iter()
                .find(|s| s.scope == "host")
                .cloned()
                .expect("host")
        };
        let unmeasured = host(&quota.usage().expect("usage"));
        assert!(!unmeasured.measured);
        assert_eq!(unmeasured.used_bytes, 0);
        assert_eq!(quota.measure_pending().expect("measured"), 1);
        let usage = quota.usage().expect("usage");
        assert!(host(&usage).measured);
        let of = |name: &str| {
            usage
                .scopes
                .iter()
                .find(|scope| scope.scope == name)
                .cloned()
                .expect(name)
        };
        assert_eq!(of("host").used_bytes, 300);
        assert_eq!(of("host").used_files, 2, "the file and its directory");
        assert_eq!(of("control").used_bytes, 300);

        let reservation = plane.reserve(600, 1).expect("within the quota");
        assert_eq!(quota.usage().expect("usage").scopes[0].reserved_bytes, 600);
        let refused = plane
            .reserve(200, 0)
            .expect_err("600 reserved + 300 used + 200");
        assert!(
            matches!(refused, StorageError::QuotaExceeded(_)),
            "{refused}"
        );
        reservation.land(500, 1);

        let usage = quota.usage().expect("usage");
        let control = usage
            .scopes
            .iter()
            .find(|scope| scope.scope == "control")
            .expect("control");
        assert_eq!(
            (control.used_bytes, control.reserved_bytes),
            (800, 0),
            "what landed is used, the rest released"
        );
        plane.freed(500, 1).expect("deleted");
        drop(plane.reserve(600, 0).expect("room again"));
    }

    #[test]
    fn the_floor_holds_for_ordinary_writers_and_the_reserve_for_maintenance() {
        let root = scratch("floor");
        let _full = permguard_core::fault::inject(
            root.path(),
            permguard_core::fault::Fault::DiskFull {
                remaining_bytes: 10_000,
            },
        );
        let quota = Quota::open(again(&root), small_floors(), Limit::default()).expect("opens");
        let ordinary = quota.host(Class::Ordinary);
        let maintenance = ordinary.maintenance();

        // 10,000 free: an ordinary writer may take 5,904 and leave the 4,096 floor.
        drop(ordinary.reserve(5_904, 0).expect("down to the floor"));
        let refused = ordinary.reserve(5_905, 0).expect_err("into the floor");
        assert!(matches!(refused, StorageError::BelowFloor(_)), "{refused}");
        // Maintenance may use the floor down to its 1,024 reserve.
        drop(maintenance.reserve(8_976, 0).expect("into the floor"));
        let refused = maintenance.reserve(8_977, 0).expect_err("into the reserve");
        assert!(matches!(refused, StorageError::BelowFloor(_)), "{refused}");
    }

    #[test]
    fn readiness_falls_before_the_largest_write_would_cross_the_floor_and_returns() {
        let root = scratch("ready");
        let _full = permguard_core::fault::inject(
            root.path(),
            permguard_core::fault::Fault::DiskFull {
                remaining_bytes: 10_000,
            },
        );
        let quota = Quota::open(again(&root), small_floors(), Limit::default()).expect("opens");
        let readiness = quota.readiness();
        quota.note_largest_write(2_000).expect("noted");
        assert!(readiness.is_ready(), "10,000 free ≥ 4,096 + 2,000");

        let pending = quota.host(Class::Ordinary).reserve(4_000, 0).expect("fits");
        assert!(
            !readiness.is_ready(),
            "6,000 free < 4,096 + 2,000: the next largest write could cross"
        );
        drop(pending);
        assert!(readiness.is_ready(), "true again once the space returns");
    }
}
