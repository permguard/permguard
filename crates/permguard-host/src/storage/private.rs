// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The volume is private to the process that owns it (TS-5): verified at Bootstrap, not only
//! created so.
//!
//! The library creates directories `0700` and files `0600`, and a process that writes a volume
//! narrows its file-creation mask to the owner ([`restrict_creation_mask`]) so that a store writing
//! through the standard library creates them owner-only too. Creating them so is not proving them
//! so: a volume restored by a copy, edited by hand or remounted by an orchestrator that widens
//! permissions is what [`inspect`] finds. It walks the volume relative to the directory it holds,
//! never following a link, and reports each entry that is not private:
//!
//! | Breach              | What was found                                                        | Code                    |
//! | ------------------- | --------------------------------------------------------------------- | ----------------------- |
//! | [`Breach::Owner`]   | a directory or file owned by another user than the process's own     | `storage_owner`         |
//! | [`Breach::Mode`]    | a directory or file another user or group may read, write or traverse | `storage_mode`          |
//! | [`Breach::Link`]    | a symbolic link: the library never follows one, nobody should add one | `storage_link`          |
//! | [`Breach::Kind`]    | a FIFO, socket or device: nothing the library writes                  | `storage_file_kind`     |
//! | [`Breach::Escape`]  | a directory on another filesystem than the volume's: a mount inside it | `storage_path_escape`   |
//!
//! The group is not judged: an orchestrator gives the volume its group (`fsGroup`), and the mode
//! keeps that group out. The volume root is judged as everything below it: the Host creates it, or
//! the orchestrator's claim step does, inside the mount, and narrows it to the owner. Public
//! material is never kept on the volume; an export is written where its command is told to.

use std::path::{Path, PathBuf};

use super::{Result, StorageError};

/// What makes an entry of the volume not private.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Breach {
    /// Owned by another user than the process's own.
    Owner,
    /// Readable, writable or traversable by the group or by others.
    Mode,
    /// A symbolic link.
    Link,
    /// Neither a directory nor a regular file.
    Kind,
    /// A directory on another filesystem than the volume root's.
    Escape,
}

impl Breach {
    /// The registered code an operator's runbook branches on.
    pub fn code(self) -> &'static str {
        use permguard_core::codes::storage;
        match self {
            Self::Owner => storage::OWNER,
            Self::Mode => storage::MODE,
            Self::Link => storage::LINK,
            Self::Kind => storage::FILE_KIND,
            Self::Escape => storage::PATH_ESCAPE,
        }
    }
}

/// One entry that is not private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub breach: Breach,
    pub path: PathBuf,
    pub detail: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {}: {}",
            self.breach.code(),
            self.path.display(),
            self.detail
        )
    }
}

/// How many findings an inspection keeps; the rest are counted.
pub const MAX_FINDINGS: usize = 32;

/// What [`inspect`] saw.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Inspection {
    pub directories: u64,
    pub files: u64,
    /// The first [`MAX_FINDINGS`] entries that are not private, in walk order.
    pub findings: Vec<Finding>,
    /// The findings past those kept.
    pub more: u64,
}

impl Inspection {
    /// Whether every entry is private.
    pub fn is_private(&self) -> bool {
        self.findings.is_empty()
    }

    fn found(&mut self, breach: Breach, path: PathBuf, detail: String) {
        if self.findings.len() < MAX_FINDINGS {
            self.findings.push(Finding {
                breach,
                path,
                detail,
            });
        } else {
            self.more += 1;
        }
    }
}

/// Narrows the process's file-creation mask to the owner: what this process creates on the volume
/// afterwards, through the library or not, is created `0700` and `0600`. Process-wide, and called
/// before a process writes a volume ([`super::volume::Volume::claim`]).
#[cfg(unix)]
pub fn restrict_creation_mask() {
    rustix::process::umask(rustix::fs::Mode::from_raw_mode(0o077));
}

#[cfg(not(unix))]
pub fn restrict_creation_mask() {}

/// Walks the volume at `root` and reports every entry that is not private to this process's
/// effective user.
#[cfg(unix)]
pub fn inspect(root: &Path) -> Result<Inspection> {
    use rustix::fs::{AtFlags, CWD, FileType, OFlags};

    let uid = rustix::process::geteuid().as_raw();
    let mut inspection = Inspection::default();
    let stat = match rustix::fs::statat(CWD, root, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => stat,
        // Not created yet: nothing to judge, and the claim creates it owner-only.
        Err(rustix::io::Errno::NOENT) => return Ok(inspection),
        Err(error) => {
            return Err(StorageError::Io {
                what: format!("reading {}", root.display()),
                source: error.into(),
            });
        }
    };
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory {
        inspection.found(
            Breach::Link,
            root.to_path_buf(),
            "the volume root is not a directory reached without following a link".to_owned(),
        );
        return Ok(inspection);
    }
    let device = stat.st_dev;
    judge(&mut inspection, uid, root, stat.st_uid, mode_of(&stat));
    let fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|error| StorageError::Io {
        what: format!("opening {}", root.display()),
        source: error.into(),
    })?;
    inspection.directories += 1;
    walk(&mut inspection, uid, device, &fd, root)?;
    Ok(inspection)
}

#[cfg(not(unix))]
pub fn inspect(_root: &Path) -> Result<Inspection> {
    Ok(Inspection::default())
}

/// The mode bits of `stat`: `mode_t` is a `u16` on macOS and already a `u32` on Linux.
#[cfg(unix)]
#[allow(clippy::useless_conversion)]
fn mode_of(stat: &rustix::fs::Stat) -> u32 {
    u32::from(stat.st_mode)
}

/// Judges one entry by its owner and mode.
fn judge(inspection: &mut Inspection, uid: u32, path: &Path, owner: u32, mode: u32) {
    if owner != uid {
        inspection.found(
            Breach::Owner,
            path.to_path_buf(),
            format!("owned by uid {owner}, not by this process's {uid}"),
        );
    }
    let mode = mode & 0o7777;
    if mode & 0o077 != 0 {
        inspection.found(
            Breach::Mode,
            path.to_path_buf(),
            format!("mode {mode:04o}: the group or others have access; it must be owner-only"),
        );
    }
}

#[cfg(unix)]
fn walk(
    inspection: &mut Inspection,
    uid: u32,
    device: rustix::fs::Dev,
    dir: &rustix::fd::OwnedFd,
    path: &Path,
) -> Result<()> {
    use rustix::fs::{AtFlags, FileType, OFlags};

    let io = |what: String| {
        move |error: rustix::io::Errno| StorageError::Io {
            what,
            source: error.into(),
        }
    };
    let listing =
        rustix::fs::Dir::read_from(dir).map_err(io(format!("listing {}", path.display())))?;
    let mut names = Vec::new();
    for entry in listing {
        let entry = entry.map_err(io(format!("listing {}", path.display())))?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            names.push(entry.file_name().to_owned());
        }
    }
    names.sort();
    for name in names {
        let child = path.join(name.to_string_lossy().as_ref());
        let stat = match rustix::fs::statat(dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            // Removed while the walk ran: a temporary file of a store at work.
            Err(rustix::io::Errno::NOENT) => continue,
            Err(error) => return Err(io(format!("reading {}", child.display()))(error)),
        };
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => {
                inspection.files += 1;
                judge(inspection, uid, &child, stat.st_uid, mode_of(&stat));
            }
            FileType::Directory => {
                inspection.directories += 1;
                judge(inspection, uid, &child, stat.st_uid, mode_of(&stat));
                if stat.st_dev != device {
                    inspection.found(
                        Breach::Escape,
                        child,
                        "another filesystem is mounted here, outside the volume that was probed \
                         and qualified"
                            .to_owned(),
                    );
                    continue;
                }
                let fd = match rustix::fs::openat(
                    dir,
                    name.as_c_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    rustix::fs::Mode::empty(),
                ) {
                    Ok(fd) => fd,
                    Err(rustix::io::Errno::NOENT) => continue,
                    Err(error) => return Err(io(format!("opening {}", child.display()))(error)),
                };
                walk(inspection, uid, device, &fd, &child)?;
            }
            FileType::Symlink => inspection.found(
                Breach::Link,
                child,
                "a symbolic link: nothing on the volume is reached through one".to_owned(),
            ),
            other => inspection.found(
                Breach::Kind,
                child,
                format!("a {other:?}: the volume holds only directories and regular files"),
            ),
        }
    }
    Ok(())
}

/// Takes the group's and others' access away from every directory and regular file below `root`
/// that this process owns, the root included, and answers how many it narrowed (TS-5).
///
/// What the orchestrator's claim step runs before every start: an orchestrator that hands the volume
/// its group (`fsGroup`) re-grants that group read and write whenever the mount's root does not
/// match, and the Host refuses a volume its group can read. Entries another user owns, links and
/// anything that is neither a directory nor a file are left as they are, for Bootstrap to refuse;
/// nothing is followed.
#[cfg(unix)]
pub fn narrow(root: &Path) -> Result<u64> {
    use rustix::fs::{AtFlags, CWD, FileType, Mode, OFlags};

    fn private_mode(mode: u32) -> Option<Mode> {
        (mode & 0o077 != 0).then(|| {
            Mode::from_raw_mode(rustix::fs::RawMode::try_from(mode & 0o7700).unwrap_or(0o700))
        })
    }
    fn walk(uid: u32, dir: &rustix::fd::OwnedFd, path: &Path, narrowed: &mut u64) -> Result<()> {
        let io = |what: String| {
            move |error: rustix::io::Errno| StorageError::Io {
                what,
                source: error.into(),
            }
        };
        let mut names = Vec::new();
        for entry in
            rustix::fs::Dir::read_from(dir).map_err(io(format!("listing {}", path.display())))?
        {
            let entry = entry.map_err(io(format!("listing {}", path.display())))?;
            let name = entry.file_name().to_bytes();
            if name != b"." && name != b".." {
                names.push(entry.file_name().to_owned());
            }
        }
        for name in names {
            let child = path.join(name.to_string_lossy().as_ref());
            let stat = match rustix::fs::statat(dir, name.as_c_str(), AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                Err(rustix::io::Errno::NOENT) => continue,
                Err(error) => return Err(io(format!("reading {}", child.display()))(error)),
            };
            let kind = FileType::from_raw_mode(stat.st_mode);
            if stat.st_uid != uid || !matches!(kind, FileType::Directory | FileType::RegularFile) {
                continue;
            }
            if let Some(mode) = private_mode(mode_of(&stat)) {
                rustix::fs::chmodat(dir, name.as_c_str(), mode, AtFlags::empty())
                    .map_err(io(format!("narrowing {}", child.display())))?;
                *narrowed += 1;
            }
            if kind == FileType::Directory {
                let fd = rustix::fs::openat(
                    dir,
                    name.as_c_str(),
                    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(io(format!("opening {}", child.display())))?;
                walk(uid, &fd, &child, narrowed)?;
            }
        }
        Ok(())
    }

    let uid = rustix::process::geteuid().as_raw();
    let stat = rustix::fs::statat(CWD, root, AtFlags::SYMLINK_NOFOLLOW).map_err(|error| {
        StorageError::Io {
            what: format!("reading {}", root.display()),
            source: error.into(),
        }
    })?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Directory || stat.st_uid != uid {
        return Ok(0);
    }
    let mut narrowed = 0;
    if let Some(mode) = private_mode(mode_of(&stat)) {
        rustix::fs::chmodat(CWD, root, mode, AtFlags::empty()).map_err(|error| {
            StorageError::Io {
                what: format!("narrowing {}", root.display()),
                source: error.into(),
            }
        })?;
        narrowed += 1;
    }
    let fd = rustix::fs::open(
        root,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|error| StorageError::Io {
        what: format!("opening {}", root.display()),
        source: error.into(),
    })?;
    walk(uid, &fd, root, &mut narrowed)?;
    Ok(narrowed)
}

#[cfg(not(unix))]
pub fn narrow(_root: &Path) -> Result<u64> {
    Ok(0)
}

#[cfg(all(test, unix))]
mod tests {
    #![allow(clippy::expect_used)]

    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    /// A directory removed when the test ends.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "pg-host-private-{tag}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("the scratch directory");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn private_volume() -> Scratch {
        let volume = Scratch::new("volume");
        set_mode(volume.path(), 0o700);
        let host = volume.path().join("host");
        std::fs::create_dir(&host).expect("creates");
        set_mode(&host, 0o700);
        let file = host.join("VOLUME_ID");
        std::fs::write(&file, b"id").expect("writes");
        set_mode(&file, 0o600);
        volume
    }

    fn set_mode(path: &Path, mode: u32) {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
    }

    fn breaches(inspection: &Inspection) -> Vec<(Breach, String)> {
        inspection
            .findings
            .iter()
            .map(|finding| {
                (
                    finding.breach,
                    finding
                        .path
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                )
            })
            .collect()
    }

    #[test]
    fn a_private_volume_has_no_finding() {
        let volume = private_volume();
        let inspection = inspect(volume.path()).expect("inspects");
        assert!(inspection.is_private(), "{:?}", inspection.findings);
        assert_eq!((inspection.directories, inspection.files), (2, 1));
    }

    #[test]
    fn a_directory_or_file_others_reach_is_a_mode_breach() {
        let volume = private_volume();
        set_mode(&volume.path().join("host"), 0o750);
        set_mode(&volume.path().join("host/VOLUME_ID"), 0o604);
        let inspection = inspect(volume.path()).expect("inspects");
        assert_eq!(
            breaches(&inspection),
            vec![
                (Breach::Mode, "host".to_owned()),
                (Breach::Mode, "VOLUME_ID".to_owned())
            ]
        );
        assert!(
            inspection.findings[0]
                .to_string()
                .starts_with("storage_mode: ")
        );
    }

    #[test]
    fn the_volume_root_is_judged_like_its_content() {
        let volume = private_volume();
        set_mode(volume.path(), 0o755);
        let inspection = inspect(volume.path()).expect("inspects");
        assert_eq!(inspection.findings.len(), 1);
        assert_eq!(inspection.findings[0].breach, Breach::Mode);
        assert_eq!(inspection.findings[0].path, volume.path());
    }

    /// Nobody but root can give a file away, so the owner is judged here on what a walk reads.
    #[test]
    fn an_entry_another_user_owns_is_an_owner_breach() {
        let mut inspection = Inspection::default();
        judge(&mut inspection, 65532, Path::new("v/host"), 65532, 0o40700);
        assert!(inspection.is_private());
        judge(&mut inspection, 65532, Path::new("v/host"), 0, 0o40700);
        assert_eq!(inspection.findings.len(), 1);
        assert_eq!(inspection.findings[0].breach, Breach::Owner);
        assert_eq!(
            inspection.findings[0].breach.code(),
            permguard_core::codes::storage::OWNER
        );
    }

    /// What the claim step does after an orchestrator re-granted the volume's group: every entry
    /// the process owns is owner-only again, a link is neither followed nor touched.
    #[test]
    fn narrowing_makes_the_process_s_entries_owner_only_and_follows_no_link() {
        let volume = private_volume();
        set_mode(volume.path(), 0o2770);
        set_mode(&volume.path().join("host"), 0o2770);
        set_mode(&volume.path().join("host/VOLUME_ID"), 0o660);
        let outside = Scratch::new("narrow-outside");
        std::fs::write(outside.path().join("theirs"), b"x").expect("writes");
        set_mode(&outside.path().join("theirs"), 0o666);
        std::os::unix::fs::symlink(
            outside.path().join("theirs"),
            volume.path().join("host/link"),
        )
        .expect("links");
        assert_eq!(narrow(volume.path()).expect("narrows"), 3);
        let inspection = inspect(volume.path()).expect("inspects");
        assert_eq!(
            breaches(&inspection),
            vec![(Breach::Link, "link".to_owned())]
        );
        let theirs = std::fs::metadata(outside.path().join("theirs")).expect("reads");
        assert_eq!(
            theirs.permissions().mode() & 0o777,
            0o666,
            "nothing reached through the link"
        );
        assert_eq!(narrow(volume.path()).expect("again"), 0, "idempotent");
    }

    #[test]
    fn a_volume_not_yet_created_has_nothing_to_judge() {
        let parent = Scratch::new("absent");
        let inspection = inspect(&parent.path().join("volume")).expect("inspects");
        assert_eq!(inspection, Inspection::default());
    }

    #[test]
    fn a_link_is_reported_and_never_followed() {
        let volume = private_volume();
        let outside = Scratch::new("outside");
        // Something outside the volume that is not private: following the link would report it.
        set_mode(outside.path(), 0o777);
        std::fs::write(outside.path().join("secret"), b"x").expect("writes");
        set_mode(&outside.path().join("secret"), 0o666);
        std::os::unix::fs::symlink(outside.path(), volume.path().join("host/escape"))
            .expect("links");
        let inspection = inspect(volume.path()).expect("inspects");
        assert_eq!(
            breaches(&inspection),
            vec![(Breach::Link, "escape".to_owned())]
        );
        assert_eq!(
            inspection.findings[0].breach.code(),
            permguard_core::codes::storage::LINK
        );
    }

    #[test]
    fn a_volume_root_reached_through_a_link_is_refused() {
        let volume = private_volume();
        let parent = Scratch::new("parent");
        let link = parent.path().join("volume");
        std::os::unix::fs::symlink(volume.path(), &link).expect("links");
        let inspection = inspect(&link).expect("inspects");
        assert_eq!(inspection.findings.len(), 1);
        assert_eq!(inspection.findings[0].breach, Breach::Link);
        assert_eq!(
            inspection.directories, 0,
            "nothing below the link is walked"
        );
    }

    #[test]
    fn a_fifo_is_a_kind_breach() {
        let volume = private_volume();
        let fifo = volume.path().join("host/pipe");
        let made = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo runs");
        assert!(made.success());
        let inspection = inspect(volume.path()).expect("inspects");
        assert_eq!(
            breaches(&inspection),
            vec![(Breach::Kind, "pipe".to_owned())]
        );
        assert_eq!(
            inspection.findings[0].breach.code(),
            permguard_core::codes::storage::FILE_KIND
        );
    }

    #[test]
    fn findings_past_the_bound_are_counted() {
        let volume = private_volume();
        for index in 0..MAX_FINDINGS + 5 {
            let file = volume.path().join(format!("host/open-{index:03}"));
            std::fs::write(&file, b"x").expect("writes");
            set_mode(&file, 0o644);
        }
        let inspection = inspect(volume.path()).expect("inspects");
        assert_eq!(inspection.findings.len(), MAX_FINDINGS);
        assert_eq!(inspection.more, 5);
    }

    #[test]
    fn the_creation_mask_makes_what_the_standard_library_creates_owner_only() {
        let volume = private_volume();
        restrict_creation_mask();
        let dir = volume.path().join("host/plane");
        std::fs::create_dir_all(dir.join("nested")).expect("creates");
        std::fs::write(dir.join("nested/file"), b"x").expect("writes");
        let inspection = inspect(volume.path()).expect("inspects");
        assert!(inspection.is_private(), "{:?}", inspection.findings);
    }
}
