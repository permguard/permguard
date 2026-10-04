// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The startup probe of the filesystem prerequisites (WP-1.3).
//!
//! The probe works only inside a fresh `<state>/fs-probe/<random>` directory, created exclusively
//! and removed afterwards on every path, and answers what it observed or the first guarantee the
//! volume failed:
//!
//! | Check              | What is done                                                       | Reason on failure                             |
//! | ------------------ | ------------------------------------------------------------------ | --------------------------------------------- |
//! | flush              | a file written and flushed, its directory flushed                  | [`Reason::Flush`]                             |
//! | permissions        | a file created owner-only reads back owner-only                    | [`Reason::Permissions`]                       |
//! | advisory lock      | an exclusive lock taken, and refused to a second handle            | [`Reason::Lock`]                              |
//! | atomic rename      | a file renamed over another: new bytes, same file, source gone     | [`Reason::Rename`], [`Reason::Identity`]      |
//! | no-replace link    | a hard link made to the same file, refused onto an occupied name   | [`Reason::HardLink`]                          |
//! | torn append        | a flushed file truncated; the bytes before the cut unchanged       | [`Reason::TornAppend`]                        |
//! | block reservation  | blocks reserved, only when the caller asks for a reserve           | [`Reason::Reservation`]                       |
//! | floors             | free bytes and free inodes at or above the configured floors       | [`Reason::FreeBytes`], [`Reason::FreeInodes`] |
//!
//! Creating and removing the probe directory are part of the flush check: create, rename and unlink
//! are durable only after their directory is flushed. A probe directory a crash left behind is
//! removed by the next probe. On a platform that cannot measure free space (Windows, a
//! compatibility mode) the floors are reported as not measured.
//!
//! # What the probe cannot prove
//!
//! The probe observes the API's behaviour on this mount. It cannot prove that a flush survives a
//! power loss, that a controller cache honours it, that pages persist in order, or that another
//! machine is fenced off the volume. Those are proven by the qualification evidence of the volume's
//! storage class, driver, filesystem and version (H-04), which [`super::qualify`] checks.

use std::hash::{BuildHasher as _, Hasher as _};
use std::io::Write as _;

use permguard_core::volume::Floors;

use super::dir::{Dir, FreeSpace};
use super::{StorageError, durability, io};

/// The directory below the state directory every probe works in.
pub const PROBE_DIRECTORY: &str = "fs-probe";

/// Why a volume is unsupported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Reason {
    /// Creating, renaming, removing or flushing a file or directory failed.
    Flush,
    /// A file created owner-only did not read back owner-only.
    Permissions,
    /// An exclusive advisory lock was not granted, or was granted twice.
    Lock,
    /// A rename did not replace its target with the new bytes and remove its source.
    Rename,
    /// A file did not keep its identity across a rename or a hard link.
    Identity,
    /// A hard link was refused, or replaced an existing name.
    HardLink,
    /// Truncating a flushed file failed or changed the bytes before the cut.
    TornAppend,
    /// Blocks could not be reserved.
    Reservation,
    /// Fewer free bytes than the floor.
    FreeBytes,
    /// Fewer free inodes than the floor.
    FreeInodes,
    /// The volume's tuple is not qualified for the profile in force.
    UnknownTuple,
}

/// A volume the Host does not run on, and why.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unsupported {
    pub reason: Reason,
    pub detail: String,
}

impl std::fmt::Display for Unsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unsupported volume ({:?}): {}", self.reason, self.detail)
    }
}

impl std::error::Error for Unsupported {}

/// What a probe is asked to check beyond the fixed guarantees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Request {
    pub floors: Floors,
    /// Bytes to reserve; zero when no stream declares a reserve, and then nothing is reserved.
    pub reserve_bytes: u64,
}

/// What the probe observed of the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The mounted filesystem's type.
    pub filesystem: String,
    /// The running kernel's release: a filesystem's code ships with its kernel.
    pub version: String,
    /// The device the state directory lives on.
    pub device: String,
}

/// A passed probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub identity: Identity,
    /// The space left; `None` where the platform cannot measure it.
    pub free: Option<FreeSpace>,
    /// The guarantees checked, in order, named by the reason each would have failed with.
    pub checked: Vec<Reason>,
}

fn unsupported(reason: Reason, detail: impl Into<String>) -> Unsupported {
    Unsupported {
        reason,
        detail: detail.into(),
    }
}

/// A fresh name for a probe directory: 16 hex characters from the process's random hasher keys.
fn fresh_name() -> String {
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    hasher.write_u128(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos()),
    );
    format!("{:016x}", hasher.finish())
}

/// Whether `name` is one a probe would have given its directory.
fn is_probe_name(name: &str) -> bool {
    name.len() == 16
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The files a probe creates: the only ones removing a probe directory touches.
const PROBE_FILES: [&str; 8] = [
    "flush",
    "lock",
    "rename-to",
    "rename-from",
    "linked",
    "occupied",
    "append",
    "reserve",
];

/// How old a probe directory must be before another probe takes it for a crash's leftover: no
/// probe runs this long, and one still running holds its directory's lock besides.
const LEFTOVER_AGE: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Probes the volume `state` lives on, inside a fresh `fs-probe/<random>` below it.
pub fn probe(state: &Dir, request: &Request) -> Result<Report, Unsupported> {
    probe_in(state, request, &fresh_name())
}

fn probe_in(state: &Dir, request: &Request, name: &str) -> Result<Report, Unsupported> {
    let flush = |error: StorageError| unsupported(Reason::Flush, error.to_string());
    let root = state.subdir(PROBE_DIRECTORY, true).map_err(flush)?;
    sweep_leftovers(&root).map_err(flush)?;
    let dir = root.create_subdir(name).map_err(flush)?;
    // Held for the whole probe, so a probe running beside this one never takes it for a leftover.
    if !dir.try_lock().map_err(flush)? {
        let _ = root.remove_subdir(name);
        return Err(flush(StorageError::Corruption(format!(
            "the probe directory {} was locked by somebody else as soon as it was created",
            dir.path().display()
        ))));
    }

    let checked = checks(&dir, request);
    let removed = remove(&root, &dir, name);
    match (checked, removed) {
        (Ok(report), Ok(())) => Ok(report),
        (Ok(_), Err(error)) => Err(flush(error)),
        (Err(failed), Ok(())) => Err(failed),
        (Err(mut failed), Err(error)) => {
            failed.detail = format!(
                "{}; and the probe directory could not be removed: {error}",
                failed.detail
            );
            Err(failed)
        }
    }
}

fn checks(dir: &Dir, request: &Request) -> Result<Report, Unsupported> {
    let mut checked = Vec::new();
    check_flush(dir, &mut checked)?;
    check_permissions(dir, &mut checked)?;
    check_lock(dir, &mut checked)?;
    check_rename(dir, &mut checked)?;
    check_hard_link(dir, &mut checked)?;
    check_torn_append(dir, &mut checked)?;
    if request.reserve_bytes > 0 {
        check_reservation(dir, request.reserve_bytes, &mut checked)?;
    }
    let free = check_floors(dir, &request.floors, &mut checked)?;
    Ok(Report {
        identity: identity(dir)?,
        free,
        checked,
    })
}

/// Writes `bytes` to the new file `name` and flushes it, through the fault shim.
fn write_flushed(dir: &Dir, name: &str, bytes: &[u8]) -> Result<(), StorageError> {
    let path = dir.child_path(name);
    let mut file = dir.create_exclusive(name)?;
    permguard_core::fault::write(&path, bytes.len(), || file.write_all(bytes))
        .map_err(io(format!("writing {}", path.display())))?;
    permguard_core::fault::sync(&path, || file.sync_all())
        .map_err(durability(format!("flushing {}", path.display())))
}

/// The identity of the file `name`: its device and inode where the platform has them.
fn file_identity(dir: &Dir, name: &str) -> Result<Option<(u64, u64)>, StorageError> {
    let Some(file) = dir.open_read(name)? else {
        return Ok(None);
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let metadata = file
            .metadata()
            .map_err(io(format!("reading {}", dir.child_path(name).display())))?;
        Ok(Some((metadata.dev(), metadata.ino())))
    }
    #[cfg(not(unix))]
    {
        drop(file);
        Ok(None)
    }
}

fn check_flush(dir: &Dir, checked: &mut Vec<Reason>) -> Result<(), Unsupported> {
    let failed = |error: StorageError| unsupported(Reason::Flush, error.to_string());
    write_flushed(dir, "flush", b"flushed").map_err(failed)?;
    dir.sync().map_err(failed)?;
    checked.push(Reason::Flush);
    Ok(())
}

fn check_permissions(dir: &Dir, checked: &mut Vec<Reason>) -> Result<(), Unsupported> {
    let failed = |error: StorageError| unsupported(Reason::Permissions, error.to_string());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let file = dir
            .open_read("flush")
            .map_err(failed)?
            .ok_or_else(|| unsupported(Reason::Permissions, "the flushed file is gone"))?;
        let mode = file
            .metadata()
            .map_err(io(format!("reading {}", dir.child_path("flush").display())))
            .map_err(failed)?
            .permissions()
            .mode();
        judge_permissions(mode & 0o777)?;
        checked.push(Reason::Permissions);
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, failed, checked);
        Ok(())
    }
}

/// The permission guarantee: a file the store creates owner-only stays owner-only.
fn judge_permissions(mode: u32) -> Result<(), Unsupported> {
    if mode == 0o600 {
        return Ok(());
    }
    Err(unsupported(
        Reason::Permissions,
        format!("a file created as 0600 reads back as {mode:04o}"),
    ))
}

fn check_lock(dir: &Dir, checked: &mut Vec<Reason>) -> Result<(), Unsupported> {
    let failed = |error: StorageError| unsupported(Reason::Lock, error.to_string());
    drop(dir.create_exclusive("lock").map_err(failed)?);
    let first = dir.open_write("lock").map_err(failed)?;
    let second = dir.open_write("lock").map_err(failed)?;
    let first_locked = first.try_lock().is_ok();
    let second = match second.try_lock() {
        Err(std::fs::TryLockError::WouldBlock) => SecondLock::Refused,
        Ok(()) => SecondLock::Granted,
        Err(std::fs::TryLockError::Error(error)) => SecondLock::Failed(error.to_string()),
    };
    let _ = first.unlock();
    judge_lock(first_locked, second)?;
    checked.push(Reason::Lock);
    Ok(())
}

/// What a second handle met when it asked for the lock.
#[derive(Debug, Clone, PartialEq, Eq)]
enum SecondLock {
    Refused,
    Granted,
    Failed(String),
}

/// The lock guarantee: the first exclusive lock is granted, and a second handle is refused.
fn judge_lock(first_locked: bool, second: SecondLock) -> Result<(), Unsupported> {
    match (first_locked, second) {
        (true, SecondLock::Refused) => Ok(()),
        (false, _) => Err(unsupported(
            Reason::Lock,
            "an exclusive lock was not granted",
        )),
        (true, SecondLock::Granted) => Err(unsupported(
            Reason::Lock,
            "a second exclusive lock was granted beside the first",
        )),
        (true, SecondLock::Failed(error)) => Err(unsupported(
            Reason::Lock,
            format!("asking for a second lock failed instead of being refused: {error}"),
        )),
    }
}

fn check_rename(dir: &Dir, checked: &mut Vec<Reason>) -> Result<(), Unsupported> {
    let failed = |error: StorageError| unsupported(Reason::Rename, error.to_string());
    write_flushed(dir, "rename-to", b"old").map_err(failed)?;
    write_flushed(dir, "rename-from", b"new").map_err(failed)?;
    let moved = file_identity(dir, "rename-from").map_err(failed)?;
    dir.rename("rename-from", "rename-to").map_err(failed)?;
    let target = dir.read("rename-to").map_err(failed)?;
    let source_remains = dir.exists("rename-from").map_err(failed)?;
    judge_rename(target.as_deref(), source_remains)?;
    let renamed = file_identity(dir, "rename-to").map_err(failed)?;
    judge_identity(moved, renamed)?;
    checked.push(Reason::Rename);
    if moved.is_some() {
        checked.push(Reason::Identity);
    }
    Ok(())
}

/// The rename guarantee: the target holds the new bytes, and the source name is gone.
fn judge_rename(target: Option<&[u8]>, source_remains: bool) -> Result<(), Unsupported> {
    if target == Some(b"new".as_slice()) && !source_remains {
        return Ok(());
    }
    Err(unsupported(
        Reason::Rename,
        "a rename did not replace its target with the new bytes and remove its source",
    ))
}

/// The identity guarantee: a file renamed or linked is the same file under its new name.
fn judge_identity(
    before: Option<(u64, u64)>,
    after: Option<(u64, u64)>,
) -> Result<(), Unsupported> {
    if before == after {
        return Ok(());
    }
    Err(unsupported(
        Reason::Identity,
        "a file renamed or linked is not the same file under its new name",
    ))
}

fn check_hard_link(dir: &Dir, checked: &mut Vec<Reason>) -> Result<(), Unsupported> {
    let failed = |error: StorageError| unsupported(Reason::HardLink, error.to_string());
    let made = dir.link("rename-to", "linked").map_err(failed)?;
    write_flushed(dir, "occupied", b"kept").map_err(failed)?;
    let replaced = dir.link("rename-to", "occupied").map_err(failed)?;
    let kept = dir.read("occupied").map_err(failed)?;
    judge_hard_link(made, replaced, kept.as_deref())?;
    judge_identity(
        file_identity(dir, "rename-to").map_err(failed)?,
        file_identity(dir, "linked").map_err(failed)?,
    )?;
    checked.push(Reason::HardLink);
    Ok(())
}

/// The no-replace guarantee: a link to a free name is made, and a link onto an existing name is
/// refused with the existing bytes left as they were.
fn judge_hard_link(made: bool, replaced: bool, kept: Option<&[u8]>) -> Result<(), Unsupported> {
    if made && !replaced && kept == Some(b"kept".as_slice()) {
        return Ok(());
    }
    Err(unsupported(
        Reason::HardLink,
        "a hard link was refused, or replaced the name it was linked onto",
    ))
}

fn check_torn_append(dir: &Dir, checked: &mut Vec<Reason>) -> Result<(), Unsupported> {
    let failed = |error: StorageError| unsupported(Reason::TornAppend, error.to_string());
    let bytes: Vec<u8> = (0u8..64).collect();
    write_flushed(dir, "append", &bytes).map_err(failed)?;
    let path = dir.child_path("append");
    let file = dir.open_write("append").map_err(failed)?;
    file.set_len(40)
        .map_err(io(format!("truncating {}", path.display())))
        .map_err(failed)?;
    permguard_core::fault::sync(&path, || file.sync_all())
        .map_err(durability(format!("flushing {}", path.display())))
        .map_err(failed)?;
    let read = dir.read("append").map_err(failed)?.unwrap_or_default();
    judge_torn_append(&read, &bytes[..40])?;
    checked.push(Reason::TornAppend);
    Ok(())
}

/// The truncation guarantee: after the cut the file is exactly the bytes before it.
fn judge_torn_append(read: &[u8], expected: &[u8]) -> Result<(), Unsupported> {
    if read == expected {
        return Ok(());
    }
    Err(unsupported(
        Reason::TornAppend,
        format!(
            "a file truncated to {} bytes reads back as {} different bytes",
            expected.len(),
            read.len()
        ),
    ))
}

fn check_reservation(dir: &Dir, bytes: u64, checked: &mut Vec<Reason>) -> Result<(), Unsupported> {
    let failed = |detail: String| unsupported(Reason::Reservation, detail);
    let file = dir
        .create_exclusive("reserve")
        .map_err(|error| failed(error.to_string()))?;
    reserve(&file, bytes).map_err(|error| failed(format!("reserving {bytes} bytes: {error}")))?;
    drop(file);
    dir.unlink("reserve")
        .map_err(|error| failed(error.to_string()))?;
    checked.push(Reason::Reservation);
    Ok(())
}

#[cfg(unix)]
fn reserve(file: &std::fs::File, bytes: u64) -> std::io::Result<()> {
    rustix::fs::fallocate(file, rustix::fs::FallocateFlags::empty(), 0, bytes).map_err(Into::into)
}

#[cfg(not(unix))]
fn reserve(_file: &std::fs::File, _bytes: u64) -> std::io::Result<()> {
    Err(std::io::Error::from(std::io::ErrorKind::Unsupported))
}

#[cfg(unix)]
fn check_floors(
    dir: &Dir,
    floors: &Floors,
    checked: &mut Vec<Reason>,
) -> Result<Option<FreeSpace>, Unsupported> {
    let free = dir.free_space().map_err(|error| {
        unsupported(Reason::FreeBytes, format!("measuring free space: {error}"))
    })?;
    judge_floors(free, floors)?;
    checked.push(Reason::FreeBytes);
    if free.inodes.is_some() {
        checked.push(Reason::FreeInodes);
    }
    Ok(Some(free))
}

/// Not measurable on this platform, a compatibility mode: reported as not measured.
#[cfg(not(unix))]
fn check_floors(
    _dir: &Dir,
    _floors: &Floors,
    _checked: &mut Vec<Reason>,
) -> Result<Option<FreeSpace>, Unsupported> {
    Ok(None)
}

/// The floors: free bytes and, where the filesystem limits them, free inodes at or above them.
#[cfg(unix)]
fn judge_floors(free: FreeSpace, floors: &Floors) -> Result<(), Unsupported> {
    if free.bytes < floors.free_bytes {
        return Err(unsupported(
            Reason::FreeBytes,
            format!(
                "{} bytes free, below the floor of {}",
                free.bytes, floors.free_bytes
            ),
        ));
    }
    if let Some(inodes) = free.inodes
        && inodes < floors.free_inodes
    {
        return Err(unsupported(
            Reason::FreeInodes,
            format!(
                "{inodes} inodes free, below the floor of {}",
                floors.free_inodes
            ),
        ));
    }
    Ok(())
}

fn identity(dir: &Dir) -> Result<Identity, Unsupported> {
    let failed = |error: StorageError| unsupported(Reason::Flush, format!("identifying: {error}"));
    let filesystem = dir.filesystem().map_err(failed)?;
    let device = dir
        .identity()
        .map_err(failed)?
        .split(':')
        .next()
        .unwrap_or_default()
        .to_owned();
    Ok(Identity {
        filesystem,
        version: kernel_release(),
        device,
    })
}

#[cfg(unix)]
fn kernel_release() -> String {
    rustix::system::uname()
        .release()
        .to_string_lossy()
        .into_owned()
}

#[cfg(not(unix))]
fn kernel_release() -> String {
    "unknown".to_owned()
}

/// Removes the probe directory, the files a probe makes in it, and flushes its parent. A directory
/// holding anything else is not removed: the error says so.
fn remove(root: &Dir, dir: &Dir, name: &str) -> Result<(), StorageError> {
    for file in PROBE_FILES {
        dir.unlink(file)?;
    }
    root.remove_subdir(name)?;
    root.sync()
}

/// Removes the probe directories a crash left behind: a name a probe gives, older than any probe
/// runs, whose lock nobody holds, holding nothing but a probe's files. Anything else in `fs-probe`
/// is left alone, and a leftover that cannot be removed is skipped rather than blocking the probe.
fn sweep_leftovers(root: &Dir) -> Result<(), StorageError> {
    for name in root.subdirs()? {
        if !is_probe_name(&name) {
            continue;
        }
        let young = std::fs::symlink_metadata(root.child_path(&name))
            .and_then(|metadata| metadata.modified())
            .map(|modified| modified.elapsed().unwrap_or_default() < LEFTOVER_AGE)
            .unwrap_or(true);
        if young {
            continue;
        }
        let Ok(leftover) = root.subdir(&name, false) else {
            continue;
        };
        if !leftover.try_lock().unwrap_or(false) {
            continue;
        }
        let _ = remove(root, &leftover, &name);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> (std::path::PathBuf, Dir) {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-probe-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        let dir = Dir::create_root(&path).expect("a state directory");
        (path, dir)
    }

    fn small() -> Request {
        Request {
            floors: Floors {
                free_bytes: 1,
                free_inodes: 1,
            },
            reserve_bytes: 0,
        }
    }

    /// Every directory and file below `path`, with the bytes of each file, the probe's own
    /// directory included.
    fn tree(path: &std::path::Path) -> Vec<(std::path::PathBuf, Option<Vec<u8>>)> {
        let mut found = Vec::new();
        let mut pending = vec![path.to_path_buf()];
        while let Some(directory) = pending.pop() {
            for entry in std::fs::read_dir(&directory).expect("listed") {
                let entry = entry.expect("an entry");
                let child = entry.path();
                if entry.file_type().expect("a type").is_dir() {
                    found.push((child.clone(), None));
                    pending.push(child);
                } else {
                    found.push((child.clone(), Some(std::fs::read(&child).expect("read"))));
                }
            }
        }
        found.sort();
        found
    }

    /// Whether the probe area holds nothing but what was there before the probe.
    fn probe_area_is_empty(path: &std::path::Path) -> bool {
        std::fs::read_dir(path.join(PROBE_DIRECTORY))
            .map(|entries| entries.count() == 0)
            .unwrap_or(true)
    }

    /// A probe of the test volume passes, checks every guarantee, reports what it saw, removes its
    /// directory and leaves everything else as it was.
    #[test]
    fn a_probe_passes_checks_every_guarantee_and_leaves_nothing_behind() {
        let (path, state) = scratch("passes");
        std::fs::write(path.join("unrelated"), b"left alone").expect("a neighbour");
        std::fs::create_dir_all(path.join("nested").join("empty")).expect("directories");
        std::fs::write(path.join("nested").join("file"), b"also").expect("a neighbour");
        drop(state.subdir(PROBE_DIRECTORY, true).expect("the probe area"));
        let before = tree(&path);

        let report = probe(&state, &small()).expect("the test volume passes");
        assert!(!report.identity.filesystem.is_empty());
        assert!(!report.identity.version.is_empty());
        assert!(!report.identity.device.is_empty());
        #[cfg(unix)]
        assert!(report.free.is_some_and(|free| free.bytes > 0));
        let mut expected = vec![
            Reason::Flush,
            Reason::Permissions,
            Reason::Lock,
            Reason::Rename,
            Reason::Identity,
            Reason::HardLink,
            Reason::TornAppend,
            Reason::FreeBytes,
        ];
        if state.free_space().expect("measured").inodes.is_some() {
            expected.push(Reason::FreeInodes);
        }
        assert_eq!(report.checked, expected, "every guarantee was checked");
        assert_eq!(
            tree(&path),
            before,
            "nothing was left and nothing else changed"
        );

        let reserved = probe(
            &state,
            &Request {
                reserve_bytes: 4096,
                ..small()
            },
        )
        .expect("a small reservation is made");
        expected.insert(7, Reason::Reservation);
        assert_eq!(reserved.checked, expected);
        assert_eq!(tree(&path), before);
    }

    /// A flush that fails in the flush check itself makes the volume unsupported, and the probe
    /// directory is removed all the same.
    #[test]
    fn a_failed_flush_makes_the_volume_unsupported_and_leaves_nothing_behind() {
        let (path, state) = scratch("flush");
        drop(state.subdir(PROBE_DIRECTORY, true).expect("the probe area"));
        std::fs::write(path.join("unrelated"), b"left alone").expect("a neighbour");
        let before = tree(&path);
        let name = "00000000000000aa";
        let _guard = permguard_core::fault::inject_exact(
            path.join(PROBE_DIRECTORY).join(name).join("flush"),
            permguard_core::fault::Fault::Fsync,
        );
        let refused = probe_in(&state, &small(), name).expect_err("unsupported");
        assert_eq!(refused.reason, Reason::Flush, "{refused}");
        assert!(refused.detail.contains("flush"), "{refused}");
        assert_eq!(tree(&path), before, "nothing left, nothing else changed");
    }

    /// A probe directory that cannot be created durably is removed again.
    #[test]
    fn a_probe_directory_whose_creation_fails_is_removed() {
        let (path, state) = scratch("create");
        drop(state.subdir(PROBE_DIRECTORY, true).expect("the probe area"));
        let _guard = permguard_core::fault::inject_exact(
            path.join(PROBE_DIRECTORY),
            permguard_core::fault::Fault::Fsync,
        );
        let refused = probe(&state, &small()).expect_err("unsupported");
        assert_eq!(refused.reason, Reason::Flush, "{refused}");
        drop(_guard);
        assert!(probe_area_is_empty(&path));
    }

    /// A probe never works in a directory it did not create: a name already taken, or a probe
    /// area that is a link, is refused with what was there left untouched.
    #[test]
    fn a_probe_works_only_in_a_directory_it_created() {
        let (path, state) = scratch("fresh");
        let name = "00000000000000bb";
        let taken = path.join(PROBE_DIRECTORY).join(name);
        std::fs::create_dir_all(taken.join("inner")).expect("somebody's directory");
        std::fs::write(taken.join("theirs"), b"not the probe's").expect("their file");
        let before = tree(&path);
        let refused = probe_in(&state, &small(), name).expect_err("unsupported");
        assert_eq!(refused.reason, Reason::Flush, "{refused}");
        assert_eq!(tree(&path), before, "what was there is untouched");

        #[cfg(unix)]
        {
            let (path, state) = scratch("linked");
            let outside = path.with_extension("outside");
            let _ = std::fs::remove_dir_all(&outside);
            std::fs::create_dir_all(&outside).expect("a directory elsewhere");
            std::os::unix::fs::symlink(&outside, path.join(PROBE_DIRECTORY)).expect("a link");
            let refused = probe(&state, &small()).expect_err("unsupported");
            assert_eq!(refused.reason, Reason::Flush, "{refused}");
            assert_eq!(std::fs::read_dir(&outside).expect("listed").count(), 0);
        }
    }

    /// Makes the directory at `path` look as old as a crash's leftover.
    fn age(path: &std::path::Path) {
        std::fs::File::open(path)
            .expect("opened")
            .set_modified(std::time::SystemTime::now() - LEFTOVER_AGE * 2)
            .expect("aged");
    }

    /// A probe directory a crash left behind is removed by the next probe. A young one, a locked
    /// one (a probe still running), one holding something a probe never makes, and anything not
    /// named like a probe are left alone, and none of them stops the probe.
    #[test]
    fn only_the_leftovers_of_a_crashed_probe_are_removed() {
        let (path, state) = scratch("leftover");
        let area = path.join(PROBE_DIRECTORY);
        let make = |name: &str, file: &str| {
            std::fs::create_dir_all(area.join(name)).expect("a directory");
            std::fs::write(area.join(name).join(file), b"x").expect("a file");
        };
        make("00000000000000cc", "flush");
        age(&area.join("00000000000000cc"));
        make("00000000000000dd", "flush");
        make("00000000000000ee", "flush");
        age(&area.join("00000000000000ee"));
        make("00000000000000ff", "theirs");
        age(&area.join("00000000000000ff"));
        make("not-a-probe", "flush");
        age(&area.join("not-a-probe"));

        let root = state
            .subdir(PROBE_DIRECTORY, false)
            .expect("the probe area");
        let running = root
            .subdir("00000000000000ee", false)
            .expect("a running probe");
        assert!(
            running.try_lock().expect("locked"),
            "the running probe's lock"
        );

        probe(&state, &small()).expect("passes, whatever is left around it");
        assert!(
            !area.join("00000000000000cc").exists(),
            "the crash's leftover is removed"
        );
        assert!(area.join("00000000000000dd").exists(), "a young one is not");
        assert!(
            area.join("00000000000000ee").exists(),
            "a locked one is not"
        );
        assert!(
            area.join("00000000000000ff").join("theirs").exists(),
            "nor what a probe never makes"
        );
        assert!(
            area.join("not-a-probe").exists(),
            "nor what is not named like a probe"
        );
    }

    #[cfg(unix)]
    #[test]
    fn floors_above_what_is_free_make_the_volume_unsupported() {
        let (path, state) = scratch("floors");
        drop(state.subdir(PROBE_DIRECTORY, true).expect("the probe area"));
        std::fs::write(path.join("unrelated"), b"left alone").expect("a neighbour");
        let before = tree(&path);
        let bytes = probe(
            &state,
            &Request {
                floors: Floors {
                    free_bytes: u64::MAX,
                    free_inodes: 1,
                },
                reserve_bytes: 0,
            },
        )
        .expect_err("unsupported");
        assert_eq!(bytes.reason, Reason::FreeBytes, "{bytes}");
        assert_eq!(tree(&path), before, "nothing left, nothing else changed");

        let free = state.free_space().expect("measured");
        let inodes = probe(
            &state,
            &Request {
                floors: Floors {
                    free_bytes: 1,
                    free_inodes: u64::MAX,
                },
                reserve_bytes: 0,
            },
        );
        match free.inodes {
            Some(_) => assert_eq!(inodes.expect_err("unsupported").reason, Reason::FreeInodes),
            None => assert!(inodes.is_ok(), "a filesystem without an inode limit"),
        }
    }

    #[test]
    fn a_reservation_the_volume_cannot_make_is_unsupported() {
        let (path, state) = scratch("reserve");
        drop(state.subdir(PROBE_DIRECTORY, true).expect("the probe area"));
        std::fs::write(path.join("unrelated"), b"left alone").expect("a neighbour");
        let before = tree(&path);
        let refused = probe(
            &state,
            &Request {
                reserve_bytes: 1 << 60,
                ..small()
            },
        )
        .expect_err("unsupported");
        assert_eq!(refused.reason, Reason::Reservation, "{refused}");
        assert_eq!(tree(&path), before, "nothing left, nothing else changed");
    }

    /// The guarantees a sound filesystem never breaks are judged from what was observed; each
    /// broken observation is its own reason.
    #[test]
    fn each_broken_guarantee_is_its_own_reason() {
        assert_eq!(judge_lock(true, SecondLock::Refused), Ok(()));
        for (first, second) in [
            (false, SecondLock::Refused),
            (true, SecondLock::Granted),
            (true, SecondLock::Failed("EIO".to_owned())),
        ] {
            assert_eq!(
                judge_lock(first, second).expect_err("broken").reason,
                Reason::Lock
            );
        }

        assert_eq!(judge_rename(Some(b"new"), false), Ok(()));
        for (target, remains) in [
            (Some(b"old".as_slice()), false),
            (Some(b"new".as_slice()), true),
            (None, false),
        ] {
            assert_eq!(
                judge_rename(target, remains).expect_err("broken").reason,
                Reason::Rename
            );
        }

        assert_eq!(judge_identity(Some((1, 2)), Some((1, 2))), Ok(()));
        assert_eq!(
            judge_identity(Some((1, 2)), Some((1, 3)))
                .expect_err("another file")
                .reason,
            Reason::Identity
        );

        assert_eq!(judge_hard_link(true, false, Some(b"kept")), Ok(()));
        for (made, replaced, kept) in [
            (false, false, Some(b"kept".as_slice())),
            (true, true, Some(b"kept".as_slice())),
            (true, false, Some(b"new".as_slice())),
        ] {
            assert_eq!(
                judge_hard_link(made, replaced, kept)
                    .expect_err("broken")
                    .reason,
                Reason::HardLink
            );
        }

        assert_eq!(judge_torn_append(b"abc", b"abc"), Ok(()));
        for read in [b"abd".as_slice(), b"abcd".as_slice()] {
            assert_eq!(
                judge_torn_append(read, b"abc").expect_err("broken").reason,
                Reason::TornAppend
            );
        }

        assert_eq!(judge_permissions(0o600), Ok(()));
        assert_eq!(
            judge_permissions(0o644)
                .expect_err("readable by others")
                .reason,
            Reason::Permissions
        );
    }
}
