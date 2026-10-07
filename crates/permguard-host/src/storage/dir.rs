// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A directory held open, and every operation relative to it.
//!
//! # Why relative and no-follow
//!
//! A path re-resolved on every operation can be redirected between two of them: a component
//! swapped for a symbolic link sends the next write somewhere the store never meant to write. On
//! Unix a [`Dir`] holds the directory open and every open, link, rename and unlink below it names
//! one path component relative to that handle, never following a symbolic link. The root a
//! [`Dir`] is first opened at is the operator's configuration and is opened as given.
//!
//! Elsewhere (Windows) the same operations resolve paths, and the platform is a compatibility mode
//! below `production` ([`super::platform_mode`]).
//!
//! # Names
//!
//! A name is one path component: not empty, not `.` or `..`, no separator, no NUL. Anything else is
//! refused before the operating system sees it.

use std::fs::File;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(unix)]
use std::{collections::BTreeSet, sync::Mutex};

use sha2::{Digest as _, Sha256};

use super::{Result, StorageError, durability, io};

/// The prefix every temporary name carries, so a sweep can find what a crash left behind.
pub const TEMP_PREFIX: &str = ".tmp-";

/// The space left on a filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FreeSpace {
    /// Bytes an unprivileged writer can still use.
    pub bytes: u64,
    /// Inodes an unprivileged writer can still use; `None` where the filesystem does not limit
    /// them (it allocates inodes as it goes, and reports none in advance).
    pub inodes: Option<u64>,
}

/// A directory held open.
#[derive(Debug)]
pub struct Dir {
    path: PathBuf,
    #[cfg(unix)]
    fd: rustix::fd::OwnedFd,
}

/// Refuses anything that is not exactly one path component.
///
/// Off Unix it also refuses what Windows would not treat as a plain file name: an alternate data
/// stream (`:`), a reserved device name (`CON`, `NUL`, `COM1`…, with any extension) and a trailing
/// dot or space, which Windows strips.
pub fn component(name: &str) -> Result<&str> {
    let refused =
        name.is_empty() || name == "." || name == ".." || name.contains(['/', '\\', '\0']);
    if refused || (cfg!(not(unix)) && !plain_on_windows(name)) {
        return Err(StorageError::Name(name.to_owned()));
    }
    Ok(name)
}

/// Whether Windows reads `name` as the plain file name it spells.
fn plain_on_windows(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
        "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
    ];
    let stem = name.split('.').next().unwrap_or(name).trim_end();
    !name.contains(':')
        && !name.ends_with(['.', ' '])
        && !RESERVED
            .iter()
            .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}

/// A fresh temporary name: the prefix and 16 hex characters.
///
/// Unpredictable enough not to collide, and safety does not rest on it: a temporary file is created
/// exclusively and without following links, so a name somebody guessed and planted fails the
/// create instead of redirecting it.
pub fn temp_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut hasher = Sha256::new();
    hasher.update(std::process::id().to_be_bytes());
    hasher.update(nanos.to_be_bytes());
    hasher.update(COUNTER.fetch_add(1, Ordering::Relaxed).to_be_bytes());
    hasher.update(format!("{:?}", std::thread::current().id()).as_bytes());
    let digest = hasher.finalize();
    let mut name = String::from(TEMP_PREFIX);
    for byte in &digest[..8] {
        name.push_str(&format!("{byte:02x}"));
    }
    name
}

impl Dir {
    /// The path this directory was opened at, for messages and for the fault shim's scopes.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path of `name` below this directory, for messages and fault scopes; never opened.
    pub fn child_path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    /// Reads a whole file below this directory, or `None` when it does not exist.
    pub fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        let Some(mut file) = self.open_read(name)? else {
            return Ok(None);
        };
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(io(format!("reading {}", self.child_path(name).display())))?;
        Ok(Some(bytes))
    }

    /// Whether `name` exists below this directory, without following it.
    pub fn exists(&self, name: &str) -> Result<bool> {
        Ok(self.open_read(name)?.is_some())
    }

    /// Creates the directory at `path` and every missing parent, then opens it.
    ///
    /// Every directory it creates is flushed into its parent, outermost first, so a power loss
    /// cannot take away a directory whose files were already flushed. `path` is the operator's
    /// configuration and is resolved as given.
    pub fn create_root(path: &Path) -> Result<Self> {
        let missing: Vec<PathBuf> = path
            .ancestors()
            .take_while(|ancestor| !ancestor.as_os_str().is_empty() && !ancestor.exists())
            .map(Path::to_path_buf)
            .collect();
        std::fs::create_dir_all(path).map_err(io(format!("creating {}", path.display())))?;
        let parent_of = |dir: &Path| match dir.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        };
        for created in missing.iter().rev() {
            Self::open(&parent_of(created))?.sync()?;
        }
        let root = Self::open(path)?;
        if missing.is_empty() {
            // Already there: a process that died before flushing may have left it, so its entry
            // is flushed the first time this process meets it, as `subdir` does.
            Self::open(&parent_of(path))?.make_entry_durable(&root, false)?;
        }
        Ok(root)
    }

    /// What this directory is, whatever path it was opened by: its device and inode on Unix, its
    /// path elsewhere.
    pub fn identity(&self) -> Result<String> {
        self.identity_raw()
    }

    /// The space left on the filesystem holding this directory, for an unprivileged writer.
    pub fn free_space(&self) -> Result<FreeSpace> {
        self.free_space_raw()
    }

    /// The type of the filesystem holding this directory, as the platform names it: `ext4`, `xfs`,
    /// `apfs`; a type this build does not know by name is its number in hex.
    pub fn filesystem(&self) -> Result<String> {
        self.filesystem_raw()
    }

    /// Flushes the file `name` below this directory.
    pub fn sync_file(&self, name: &str) -> Result<()> {
        let path = self.child_path(name);
        let file = self.open_flushable(name)?;
        permguard_core::fault::sync(&path, || file.sync_all())
            .map_err(durability(format!("flushing {}", path.display())))
    }

    /// Flushes this directory: what was created, renamed or unlinked in it is durable once this
    /// returns.
    pub fn sync(&self) -> Result<()> {
        permguard_core::fault::sync(&self.path, || self.sync_raw())
            .map_err(durability(format!("flushing {}", self.path.display())))
    }

    /// Removes every temporary file a crash left behind; answers how many.
    ///
    /// A temporary file is never the authority for anything: it becomes durable only by being
    /// published or renamed, so one still here is a write that did not finish.
    ///
    /// Only for a directory no other writer is using: a subsystem's own, at recovery. A directory
    /// that other handles may be writing into sweeps with [`Self::sweep_temps_older_than`].
    pub fn sweep_temps(&self) -> Result<usize> {
        self.sweep_temps_older_than(std::time::Duration::ZERO)
    }

    /// Removes the temporary files last modified at least `age` ago; answers how many.
    ///
    /// A write in flight keeps its temporary for as long as one write takes, so an age longer than
    /// any write leaves every live temporary alone.
    pub fn sweep_temps_older_than(&self, age: std::time::Duration) -> Result<usize> {
        let now = std::time::SystemTime::now();
        let mut swept = 0;
        for name in self.names()? {
            if !name.starts_with(TEMP_PREFIX) {
                continue;
            }
            if !age.is_zero() {
                let Some(file) = self.open_read(&name)? else {
                    continue;
                };
                let modified = file
                    .metadata()
                    .and_then(|metadata| metadata.modified())
                    .map_err(io(format!("reading {}", self.child_path(&name).display())))?;
                if now.duration_since(modified).unwrap_or_default() < age {
                    continue;
                }
            }
            if self.unlink(&name)? {
                swept += 1;
            }
        }
        if swept > 0 {
            self.sync()?;
        }
        Ok(swept)
    }
}

#[cfg(unix)]
mod platform {
    use rustix::fs::{AtFlags, Mode, OFlags};
    use rustix::io::Errno;

    use super::*;

    fn os(error: Errno) -> std::io::Error {
        std::io::Error::from(error)
    }

    impl Dir {
        /// Opens the directory at `path`, the root a store is configured at.
        pub fn open(path: &Path) -> Result<Self> {
            let fd = rustix::fs::open(
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| StorageError::Io {
                what: format!("opening {}", path.display()),
                source: os(error),
            })?;
            Ok(Self {
                path: path.to_path_buf(),
                fd,
            })
        }

        /// The subdirectory `name`, created when `create` and absent.
        ///
        /// With `create`, the entry is durable in this directory once this returns: a directory
        /// this call creates is flushed into its parent, and so is one it finds already there the
        /// first time this process meets it, since a process that died before its flush may have
        /// left it behind.
        pub fn subdir(&self, name: &str, create: bool) -> Result<Self> {
            let name = component(name)?;
            let mut created = false;
            if create {
                match rustix::fs::mkdirat(&self.fd, name, Mode::from_raw_mode(0o700)) {
                    Ok(()) => created = true,
                    Err(Errno::EXIST) => {}
                    Err(error) => {
                        return Err(StorageError::Io {
                            what: format!("creating {}", self.child_path(name).display()),
                            source: os(error),
                        });
                    }
                }
            }
            let fd = rustix::fs::openat(
                &self.fd,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| StorageError::Io {
                what: format!("opening {}", self.child_path(name).display()),
                source: os(error),
            })?;
            let child = Self {
                path: self.child_path(name),
                fd,
            };
            if create {
                self.make_entry_durable(&child, created)?;
            }
            Ok(child)
        }

        /// Creates the subdirectory `name`, which must not exist, and opens it; its entry is flushed
        /// into this directory. If anything fails after the directory was made, it is removed
        /// again, so a failed creation leaves nothing behind.
        pub fn create_subdir(&self, name: &str) -> Result<Self> {
            let name = component(name)?;
            rustix::fs::mkdirat(&self.fd, name, Mode::from_raw_mode(0o700)).map_err(|error| {
                StorageError::Io {
                    what: format!("creating {}", self.child_path(name).display()),
                    source: os(error),
                }
            })?;
            let opened = rustix::fs::openat(
                &self.fd,
                name,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| StorageError::Io {
                what: format!("opening {}", self.child_path(name).display()),
                source: os(error),
            })
            .map(|fd| Self {
                path: self.child_path(name),
                fd,
            })
            .and_then(|child| self.make_entry_durable(&child, true).map(|()| child));
            if opened.is_err() {
                let _ = rustix::fs::unlinkat(&self.fd, name, AtFlags::REMOVEDIR);
            }
            opened
        }

        /// Flushes this directory so `child`'s entry in it is durable: always when the caller just
        /// created `child`, otherwise unless this process already did it for this parent and child.
        ///
        /// The memory is keyed by the identity of both directories and the entry's name, so a
        /// rename is a new entry. A directory this process creates is always flushed, so one it
        /// removes and creates again is never skipped; one that another process recreates under a
        /// reused inode number, between two meetings, can be: a store's own directories are only
        /// created through this library. The memory is bounded and forgets everything past its
        /// bound, which only costs flushes again.
        pub(super) fn make_entry_durable(&self, child: &Dir, created: bool) -> Result<()> {
            const BOUND: usize = 16 * 1024;
            static DURABLE: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
            let identity_of = |dir: &Dir| {
                rustix::fs::fstat(&dir.fd)
                    .map(|stat| format!("{}:{}", stat.st_dev, stat.st_ino))
                    .map_err(|error| StorageError::Io {
                        what: format!("reading {}", dir.path.display()),
                        source: os(error),
                    })
            };
            let name = child
                .path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_default();
            let identity = format!("{}/{}/{name}", identity_of(self)?, identity_of(child)?);
            let known = DURABLE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains(&identity);
            if created || !known {
                self.sync()?;
                let mut durable = DURABLE
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if durable.len() >= BOUND {
                    durable.clear();
                }
                durable.insert(identity);
            }
            Ok(())
        }

        /// Opens `name` with `flags` and refuses anything but a regular file: a directory, a
        /// device or a FIFO under a name the store owns is not its file, and a FIFO would block.
        fn open_regular(&self, name: &str, flags: OFlags) -> rustix::io::Result<File> {
            let fd = rustix::fs::openat(
                &self.fd,
                name,
                flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                Mode::empty(),
            )?;
            if rustix::fs::FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode)
                != rustix::fs::FileType::RegularFile
            {
                return Err(Errno::INVAL);
            }
            Ok(File::from(fd))
        }

        /// Creates `name` exclusively for writing: it must not exist, and is never a link.
        pub fn create_exclusive(&self, name: &str) -> Result<File> {
            let name = component(name)?;
            rustix::fs::openat(
                &self.fd,
                name,
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o600),
            )
            .map(File::from)
            .map_err(|error| StorageError::Io {
                what: format!("creating {}", self.child_path(name).display()),
                source: os(error),
            })
        }

        /// Opens `name` for reading, or `None` when it does not exist; a link or anything else
        /// that is not a regular file is refused.
        pub fn open_read(&self, name: &str) -> Result<Option<File>> {
            let name = component(name)?;
            match self.open_regular(name, OFlags::RDONLY) {
                Ok(file) => Ok(Some(file)),
                Err(Errno::NOENT) => Ok(None),
                Err(error) => Err(StorageError::Io {
                    what: format!("opening {}", self.child_path(name).display()),
                    source: os(error),
                }),
            }
        }

        /// Opens the existing regular file `name` for reading and writing; a link is refused.
        pub fn open_write(&self, name: &str) -> Result<File> {
            let name = component(name)?;
            self.open_regular(name, OFlags::RDWR)
                .map_err(|error| StorageError::Io {
                    what: format!("opening {}", self.child_path(name).display()),
                    source: os(error),
                })
        }

        /// Links `from` to `to`, never replacing: `false` when `to` already exists.
        pub fn link(&self, from: &str, to: &str) -> Result<bool> {
            let (from, to) = (component(from)?, component(to)?);
            match rustix::fs::linkat(&self.fd, from, &self.fd, to, AtFlags::empty()) {
                Ok(()) => Ok(true),
                Err(Errno::EXIST) => Ok(false),
                // FAT, exFAT and some network filesystems have no hard links; the link is of a
                // temporary this process just created, so a refusal is the filesystem's.
                Err(error) if [Errno::PERM, Errno::NOTSUP, Errno::OPNOTSUPP].contains(&error) => {
                    Err(StorageError::Io {
                        what: format!(
                            "publishing {} needs a hard link, which this filesystem refused; a \
                             volume without hard links is not supported",
                            self.child_path(to).display()
                        ),
                        source: os(error),
                    })
                }
                Err(error) => Err(StorageError::Io {
                    what: format!("publishing {}", self.child_path(to).display()),
                    source: os(error),
                }),
            }
        }

        /// Renames `from` over `to`, replacing it: only for replaceable views.
        pub fn rename(&self, from: &str, to: &str) -> Result<()> {
            let (from, to) = (component(from)?, component(to)?);
            rustix::fs::renameat(&self.fd, from, &self.fd, to).map_err(|error| StorageError::Io {
                what: format!("replacing {}", self.child_path(to).display()),
                source: os(error),
            })
        }

        /// Moves `from` below this directory to `to` below `into`, replacing `to` when it exists:
        /// how a file of a layout before the library is adopted into the layout after it
        /// (WP-1.11). Both directories are flushed, so the move survives a crash whole.
        pub fn move_to(&self, from: &str, into: &Dir, to: &str) -> Result<()> {
            let (from, to) = (component(from)?, component(to)?);
            rustix::fs::renameat(&self.fd, from, &into.fd, to).map_err(|error| {
                StorageError::Io {
                    what: format!(
                        "moving {} to {}",
                        self.child_path(from).display(),
                        into.child_path(to).display()
                    ),
                    source: os(error),
                }
            })?;
            crate::storage::crash::point("move.renamed");
            into.sync()?;
            crate::storage::crash::point("move.target_flushed");
            self.sync()
        }

        /// Unlinks `name`; `false` when it was already gone.
        pub fn unlink(&self, name: &str) -> Result<bool> {
            let name = component(name)?;
            match rustix::fs::unlinkat(&self.fd, name, AtFlags::empty()) {
                Ok(()) => Ok(true),
                Err(Errno::NOENT) => Ok(false),
                Err(error) => Err(StorageError::Io {
                    what: format!("removing {}", self.child_path(name).display()),
                    source: os(error),
                }),
            }
        }

        /// The regular files in this directory, by name; links and subdirectories are not listed.
        pub fn names(&self) -> Result<Vec<String>> {
            self.entries_of(rustix::fs::FileType::RegularFile)
        }

        /// The subdirectories of this directory, by name; a link to a directory is not listed.
        pub fn subdirs(&self) -> Result<Vec<String>> {
            self.entries_of(rustix::fs::FileType::Directory)
                .map(|names| {
                    names
                        .into_iter()
                        .filter(|name| name != "." && name != "..")
                        .collect()
                })
        }

        fn entries_of(&self, wanted: rustix::fs::FileType) -> Result<Vec<String>> {
            let listing =
                rustix::fs::Dir::read_from(&self.fd).map_err(|error| StorageError::Io {
                    what: format!("listing {}", self.path.display()),
                    source: os(error),
                })?;
            let mut names = Vec::new();
            for entry in listing {
                let entry = entry.map_err(|error| StorageError::Io {
                    what: format!("listing {}", self.path.display()),
                    source: os(error),
                })?;
                let Ok(name) = entry.file_name().to_str() else {
                    continue;
                };
                // Some filesystems do not report the type in the listing (XFS without `ftype`,
                // some FUSE and NFS mounts): asked of the entry itself, without following it.
                let kind = match entry.file_type() {
                    rustix::fs::FileType::Unknown => {
                        match rustix::fs::statat(&self.fd, name, AtFlags::SYMLINK_NOFOLLOW) {
                            Ok(stat) => rustix::fs::FileType::from_raw_mode(stat.st_mode),
                            Err(Errno::NOENT) => continue,
                            Err(error) => {
                                return Err(StorageError::Io {
                                    what: format!("listing {}", self.path.display()),
                                    source: os(error),
                                });
                            }
                        }
                    }
                    kind => kind,
                };
                if kind == wanted {
                    names.push(name.to_owned());
                }
            }
            names.sort();
            Ok(names)
        }

        pub(super) fn identity_raw(&self) -> Result<String> {
            rustix::fs::fstat(&self.fd)
                .map(|stat| format!("{}:{}", stat.st_dev, stat.st_ino))
                .map_err(|error| StorageError::Io {
                    what: format!("reading {}", self.path.display()),
                    source: os(error),
                })
        }

        /// Takes an exclusive advisory lock on this directory, without waiting: `false` when
        /// another handle holds it. Released when this `Dir` is dropped. The probe's check of the
        /// filesystem's locks; the volume's own lock is the file `host/LOCK`
        /// ([`crate::storage::volume`]).
        pub fn try_lock(&self) -> Result<bool> {
            match rustix::fs::flock(
                &self.fd,
                rustix::fs::FlockOperation::NonBlockingLockExclusive,
            ) {
                Ok(()) => Ok(true),
                Err(Errno::WOULDBLOCK) => Ok(false),
                Err(error) => Err(StorageError::Io {
                    what: format!("locking {}", self.path.display()),
                    source: os(error),
                }),
            }
        }

        /// Removes the empty subdirectory `name`; `false` when it was already gone.
        pub fn remove_subdir(&self, name: &str) -> Result<bool> {
            let name = component(name)?;
            match rustix::fs::unlinkat(&self.fd, name, AtFlags::REMOVEDIR) {
                Ok(()) => Ok(true),
                Err(Errno::NOENT) => Ok(false),
                Err(error) => Err(StorageError::Io {
                    what: format!("removing {}", self.child_path(name).display()),
                    source: os(error),
                }),
            }
        }

        pub(super) fn free_space_raw(&self) -> Result<FreeSpace> {
            let stat = rustix::fs::fstatvfs(&self.fd).map_err(|error| StorageError::Io {
                what: format!("measuring {}", self.path.display()),
                source: os(error),
            })?;
            Ok(FreeSpace {
                bytes: stat.f_bavail.saturating_mul(stat.f_frsize),
                inodes: (stat.f_files > 0).then_some(stat.f_favail),
            })
        }

        pub(super) fn filesystem_raw(&self) -> Result<String> {
            #[cfg(target_os = "linux")]
            if let Some(name) = rustix::fs::fstat(&self.fd)
                .ok()
                .and_then(|stat| mounted_filesystem(stat.st_dev))
            {
                return Ok(name);
            }
            let stat = rustix::fs::fstatfs(&self.fd).map_err(|error| StorageError::Io {
                what: format!("identifying {}", self.path.display()),
                source: os(error),
            })?;
            Ok(filesystem_name(&stat))
        }

        /// A read handle is enough to flush a file on Unix.
        pub(super) fn open_flushable(&self, name: &str) -> Result<File> {
            let name = component(name)?;
            self.open_regular(name, OFlags::RDONLY)
                .map_err(|error| StorageError::Io {
                    what: format!("opening {}", self.child_path(name).display()),
                    source: os(error),
                })
        }

        /// On Apple systems a plain `fsync` leaves the data in the drive's cache; `F_FULLFSYNC`
        /// is what the standard library's file flushes use there, and directories get the same. A
        /// filesystem that does not take it gets the plain `fsync`, the strongest it offers.
        #[cfg(target_vendor = "apple")]
        pub(super) fn sync_raw(&self) -> std::io::Result<()> {
            match rustix::fs::fcntl_fullfsync(&self.fd) {
                Err(Errno::INVAL | Errno::NOTSUP | Errno::NOTTY) => {
                    rustix::fs::fsync(&self.fd).map_err(os)
                }
                other => other.map_err(os),
            }
        }

        #[cfg(not(target_vendor = "apple"))]
        pub(super) fn sync_raw(&self) -> std::io::Result<()> {
            rustix::fs::fsync(&self.fd).map_err(os)
        }
    }
}

/// The type Linux mounted the device `dev` with, from `/proc/self/mountinfo`: exact where the magic
/// number is shared (ext2, ext3 and ext4 have one).
#[cfg(target_os = "linux")]
fn mounted_filesystem(dev: u64) -> Option<String> {
    let device = format!("{}:{}", rustix::fs::major(dev), rustix::fs::minor(dev));
    let table = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    table.lines().find_map(|line| {
        let mut fields = line.split(' ');
        if fields.nth(2)? != device {
            return None;
        }
        let (_, after) = line.split_once(" - ")?;
        after.split(' ').next().map(str::to_owned)
    })
}

/// Linux names a filesystem by its magic number: the ones a Host is likely to meet, by name. Used
/// only where the mount table does not answer.
#[cfg(target_os = "linux")]
fn filesystem_name(stat: &rustix::fs::StatFs) -> String {
    let magic = i128::from(stat.f_type);
    let named = [
        (0xEF53, "ext2/3/4"),
        (0x5846_5342, "xfs"),
        (0x9123_683E, "btrfs"),
        (0x2FC1_2FC1, "zfs"),
        (0xF2F5_2010, "f2fs"),
        (0x0102_1994, "tmpfs"),
        (0x6969, "nfs"),
        (0x6573_5546, "fuse"),
        (0x794C_7630, "overlayfs"),
        (0xFF53_4D42, "cifs"),
        (0xFE53_4D42, "smb2"),
        (0x5346_544E, "ntfs"),
        (0x4D44, "vfat"),
    ];
    named
        .iter()
        .find(|(number, _)| *number == magic)
        .map_or_else(|| format!("{magic:#x}"), |(_, name)| (*name).to_owned())
}

/// Apple names a filesystem in the statfs record itself.
#[cfg(target_vendor = "apple")]
fn filesystem_name(stat: &rustix::fs::StatFs) -> String {
    let bytes: Vec<u8> = stat
        .f_fstypename
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| byte.to_ne_bytes()[0])
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[cfg(all(unix, not(target_os = "linux"), not(target_vendor = "apple")))]
fn filesystem_name(_stat: &rustix::fs::StatFs) -> String {
    "unknown".to_owned()
}

#[cfg(not(unix))]
mod platform {
    use super::*;

    impl Dir {
        /// Opens the directory at `path`, the root a store is configured at.
        pub fn open(path: &Path) -> Result<Self> {
            if !path.is_dir() {
                return Err(StorageError::Io {
                    what: format!("opening {}", path.display()),
                    source: std::io::Error::from(std::io::ErrorKind::NotFound),
                });
            }
            Ok(Self {
                path: path.to_path_buf(),
            })
        }

        /// Creates the subdirectory `name`, which must not exist, and opens it.
        pub fn create_subdir(&self, name: &str) -> Result<Self> {
            let path = self.child_path(component(name)?);
            std::fs::create_dir(&path).map_err(io(format!("creating {}", path.display())))?;
            let opened = Self::open(&path);
            if opened.is_err() {
                let _ = std::fs::remove_dir(&path);
            }
            opened
        }

        /// The subdirectory `name`, created when `create` and absent.
        pub fn subdir(&self, name: &str, create: bool) -> Result<Self> {
            let path = self.child_path(component(name)?);
            if create {
                std::fs::create_dir_all(&path)
                    .map_err(io(format!("creating {}", path.display())))?;
            }
            Self::open(&path)
        }

        /// Creates `name` exclusively for writing.
        pub fn create_exclusive(&self, name: &str) -> Result<File> {
            let path = self.child_path(component(name)?);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .map_err(io(format!("creating {}", path.display())))
        }

        /// Opens `name` for reading, or `None` when it does not exist.
        pub fn open_read(&self, name: &str) -> Result<Option<File>> {
            let path = self.child_path(component(name)?);
            match File::open(&path) {
                Ok(file) => Ok(Some(file)),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(error) => Err(StorageError::Io {
                    what: format!("opening {}", path.display()),
                    source: error,
                }),
            }
        }

        /// Opens the existing `name` for reading and writing.
        pub fn open_write(&self, name: &str) -> Result<File> {
            let path = self.child_path(component(name)?);
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .map_err(io(format!("opening {}", path.display())))
        }

        /// Links `from` to `to`, never replacing: `false` when `to` already exists.
        pub fn link(&self, from: &str, to: &str) -> Result<bool> {
            let (from, to) = (
                self.child_path(component(from)?),
                self.child_path(component(to)?),
            );
            match std::fs::hard_link(&from, &to) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
                Err(error) => Err(StorageError::Io {
                    what: format!("publishing {}", to.display()),
                    source: error,
                }),
            }
        }

        /// Renames `from` over `to`, replacing it: only for replaceable views.
        pub fn rename(&self, from: &str, to: &str) -> Result<()> {
            let (from, to) = (
                self.child_path(component(from)?),
                self.child_path(component(to)?),
            );
            std::fs::rename(&from, &to).map_err(io(format!("replacing {}", to.display())))
        }

        /// Moves `from` below this directory to `to` below `into`, replacing `to` when it exists
        /// (WP-1.11); both directories are flushed.
        pub fn move_to(&self, from: &str, into: &Dir, to: &str) -> Result<()> {
            let (from, to) = (
                self.child_path(component(from)?),
                into.child_path(component(to)?),
            );
            std::fs::rename(&from, &to).map_err(io(format!(
                "moving {} to {}",
                from.display(),
                to.display()
            )))?;
            crate::storage::crash::point("move.renamed");
            into.sync()?;
            crate::storage::crash::point("move.target_flushed");
            self.sync()
        }

        /// Unlinks `name`; `false` when it was already gone.
        pub fn unlink(&self, name: &str) -> Result<bool> {
            let path = self.child_path(component(name)?);
            match std::fs::remove_file(&path) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(StorageError::Io {
                    what: format!("removing {}", path.display()),
                    source: error,
                }),
            }
        }

        /// The regular files in this directory, by name.
        pub fn names(&self) -> Result<Vec<String>> {
            self.entries_of(false)
        }

        /// The subdirectories of this directory, by name; a link to a directory is not listed.
        pub fn subdirs(&self) -> Result<Vec<String>> {
            self.entries_of(true)
        }

        fn entries_of(&self, directories: bool) -> Result<Vec<String>> {
            let mut names = Vec::new();
            for entry in std::fs::read_dir(&self.path)
                .map_err(io(format!("listing {}", self.path.display())))?
            {
                let entry = entry.map_err(io(format!("listing {}", self.path.display())))?;
                let kind = entry
                    .file_type()
                    .map_err(io(format!("listing {}", self.path.display())))?;
                let wanted = if directories {
                    kind.is_dir()
                } else {
                    kind.is_file()
                };
                if wanted {
                    names.push(entry.file_name().to_string_lossy().into_owned());
                }
            }
            names.sort();
            Ok(names)
        }

        /// The canonical path, so two spellings of one directory are one identity.
        pub(super) fn identity_raw(&self) -> Result<String> {
            std::fs::canonicalize(&self.path)
                .map(|path| path.display().to_string())
                .map_err(io(format!("resolving {}", self.path.display())))
        }

        /// No directory locks here: the platform is a compatibility mode, and one Host per volume
        /// is the operator's to ensure.
        pub fn try_lock(&self) -> Result<bool> {
            Ok(true)
        }

        /// Removes the empty subdirectory `name`; `false` when it was already gone.
        pub fn remove_subdir(&self, name: &str) -> Result<bool> {
            let path = self.child_path(component(name)?);
            match std::fs::remove_dir(&path) {
                Ok(()) => Ok(true),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
                Err(error) => Err(StorageError::Io {
                    what: format!("removing {}", path.display()),
                    source: error,
                }),
            }
        }

        /// Not measurable here: the platform is a compatibility mode.
        pub(super) fn free_space_raw(&self) -> Result<FreeSpace> {
            Err(StorageError::Io {
                what: format!("measuring {}", self.path.display()),
                source: std::io::Error::from(std::io::ErrorKind::Unsupported),
            })
        }

        pub(super) fn filesystem_raw(&self) -> Result<String> {
            Ok("unknown".to_owned())
        }

        /// Windows flushes a file only through a handle that may write.
        pub(super) fn open_flushable(&self, name: &str) -> Result<File> {
            let path = self.child_path(component(name)?);
            std::fs::OpenOptions::new()
                .write(true)
                .open(&path)
                .map_err(io(format!("opening {}", path.display())))
        }

        /// Nothing to flush: the platform is a compatibility mode.
        pub(super) fn make_entry_durable(&self, _child: &Dir, _created: bool) -> Result<()> {
            Ok(())
        }

        /// A directory cannot be flushed here: the platform is a compatibility mode.
        pub(super) fn sync_raw(&self) -> std::io::Result<()> {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-dir-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn a_name_is_exactly_one_component() {
        for refused in ["", ".", "..", "a/b", "a\\b", "a\0b"] {
            assert!(component(refused).is_err(), "{refused:?}");
        }
        assert_eq!(component("seg-1").ok(), Some("seg-1"));
    }

    #[test]
    fn what_windows_would_not_read_as_a_plain_name_is_refused_there() {
        for refused in ["a:b", "CON", "nul.txt", "Com1", "trailing.", "trailing "] {
            assert!(!plain_on_windows(refused), "{refused:?}");
        }
        for plain in ["seg-00000000000000000001.pgj", "console", "ab", ".tmp-0f"] {
            assert!(plain_on_windows(plain), "{plain:?}");
        }
    }

    /// A FIFO or a directory under a name the store owns is refused, never opened as its file.
    #[cfg(unix)]
    #[test]
    fn only_a_regular_file_is_opened() {
        let root = scratch("regular");
        let dir = Dir::create_root(&root).expect("a root");
        std::fs::create_dir(root.join("directory")).expect("a directory");
        let fifo = std::process::Command::new("mkfifo")
            .arg(root.join("fifo"))
            .status()
            .expect("mkfifo runs");
        assert!(fifo.success());
        assert!(dir.open_read("directory").is_err());
        assert!(
            dir.open_read("fifo").is_err(),
            "refused, and it did not block"
        );
        assert!(dir.open_write("fifo").is_err());
        assert!(dir.names().expect("listed").is_empty());
    }

    /// Every directory `create_root` makes exists afterwards, and a file is flushed by name.
    #[test]
    fn create_root_makes_every_missing_parent_and_files_flush_by_name() {
        let root = scratch("nested");
        let dir = Dir::create_root(&root.join("a").join("b")).expect("created");
        drop(dir.create_exclusive("file").expect("a file"));
        dir.sync_file("file").expect("flushed");
        assert!(root.join("a").join("b").join("file").is_file());
        let again = dir.subdir("c", true).expect("created");
        let _ = dir.subdir("c", true).expect("found");
        assert_eq!(again.path(), root.join("a").join("b").join("c"));
    }

    /// A directory that `subdir` or `create_root` creates is flushed into its parent, and a failed
    /// flush is reported, not swallowed.
    #[cfg(unix)]
    #[test]
    fn creating_a_directory_flushes_its_parent_and_reports_a_failed_flush() {
        let root = scratch("create-flush");
        let dir = Dir::create_root(&root).expect("a root");
        {
            let _guard = permguard_core::fault::inject(&root, permguard_core::fault::Fault::Fsync);
            assert!(matches!(
                dir.subdir("new", true)
                    .expect_err("the parent's flush failed"),
                StorageError::Durability { .. }
            ));
            assert!(matches!(
                Dir::create_root(&root.join("deeper").join("still")).expect_err("flush failed"),
                StorageError::Durability { .. }
            ));
        }
        // The memory skips a parent this process already flushed for a directory it found, never
        // one it has just created: a directory created again may carry a remembered identity.
        let child = dir.subdir("known", true).expect("created and flushed");
        let _guard = permguard_core::fault::inject(&root, permguard_core::fault::Fault::Fsync);
        dir.make_entry_durable(&child, false)
            .expect("found again: already durable, nothing to flush");
        assert!(
            dir.make_entry_durable(&child, true).is_err(),
            "just created: always flushed"
        );
    }

    /// A root that is already there, perhaps left by a process that died before flushing it, has
    /// its entry flushed into its parent the first time this process opens it.
    #[cfg(unix)]
    #[test]
    fn an_existing_root_is_flushed_into_its_parent_once() {
        let parent = scratch("existing-root");
        let root = parent.join("root");
        std::fs::create_dir_all(&root).expect("made outside the library");
        {
            let _guard =
                permguard_core::fault::inject_exact(&parent, permguard_core::fault::Fault::Fsync);
            assert!(
                Dir::create_root(&root).is_err(),
                "the parent's flush failed"
            );
        }
        Dir::create_root(&root).expect("flushed now");
        let _guard =
            permguard_core::fault::inject_exact(&parent, permguard_core::fault::Fault::Fsync);
        Dir::create_root(&root).expect("already durable for this process: no flush");
    }

    #[test]
    fn temporary_names_are_fresh_and_prefixed() {
        let first = temp_name();
        let second = temp_name();
        assert_ne!(first, second);
        assert!(first.starts_with(TEMP_PREFIX));
        assert_eq!(first.len(), TEMP_PREFIX.len() + 16);
    }

    /// A link planted where the store writes is refused, never followed.
    #[cfg(unix)]
    #[test]
    fn a_symbolic_link_is_never_followed() {
        let root = scratch("links");
        let dir = Dir::create_root(&root).expect("a root");
        let outside = scratch("links-outside");
        std::fs::create_dir_all(&outside).expect("an outside directory");
        std::fs::write(outside.join("secret"), b"outside").expect("a file outside");
        std::os::unix::fs::symlink(outside.join("secret"), root.join("planted")).expect("a link");
        std::os::unix::fs::symlink(&outside, root.join("sub")).expect("a directory link");

        assert!(dir.open_read("planted").is_err(), "a link is not opened");
        assert!(
            dir.create_exclusive("planted").is_err(),
            "nor created through"
        );
        assert!(dir.subdir("sub", false).is_err(), "nor descended into");
        assert!(!dir.names().expect("listed").contains(&"planted".to_owned()));
        assert!(
            dir.subdirs().expect("listed").is_empty(),
            "a linked directory is not listed"
        );
        std::fs::create_dir(root.join("real")).expect("a directory");
        assert_eq!(dir.subdirs().expect("listed"), ["real"]);
    }

    #[test]
    fn link_never_replaces_and_a_sweep_removes_temporaries() {
        let root = scratch("link");
        let dir = Dir::create_root(&root).expect("a root");
        std::fs::write(root.join("a"), b"one").expect("a");
        std::fs::write(root.join("b"), b"two").expect("b");
        assert!(
            !dir.link("a", "b").expect("linked"),
            "an existing name is kept"
        );
        assert_eq!(std::fs::read(root.join("b")).expect("b"), b"two");

        let temp = temp_name();
        drop(dir.create_exclusive(&temp).expect("a temp"));
        assert_eq!(
            dir.sweep_temps_older_than(std::time::Duration::from_secs(3600))
                .expect("swept"),
            0,
            "a fresh temporary may be a write in flight"
        );
        assert_eq!(dir.sweep_temps().expect("swept"), 1);
        assert!(!root.join(&temp).exists());
    }
}
