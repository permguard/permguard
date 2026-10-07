// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The volume's ownership: who may write it, and under which claim.
//!
//! ```text
//! <volume>/host/LOCK           empty; an exclusive advisory lock held for the process
//! <volume>/host/VOLUME_ID      view; 16 random bytes, written once
//! <volume>/host/FORMAT         view; the u64 layout version, written once, after VOLUME_ID
//! <volume>/host/VOLUME-CLAIM   view; the u64 lease generation, written by the orchestrator
//! ```
//!
//! [`Volume::claim`] is the first thing a process that writes the volume does, before it opens any
//! store: it takes `LOCK`, creates the volume when it is empty, checks what is there and reads the
//! claim. The [`Volume`] it answers holds the lock until it is dropped, so a second process on the
//! same mounted filesystem fails on `LOCK` instead of writing beside the first. The lock is an
//! advisory lock, and excludes only where the filesystem honours it: on a volume the prerequisite
//! probe ([`super::probe`]) qualified. `LOCK` is opened once and never again while it is held,
//! since a filesystem that emulates the lock with POSIX record locks releases it when the process
//! closes any descriptor of the file.
//!
//! # A fencing token, not a fence
//!
//! `LOCK` keeps two processes on one mount apart; it does nothing about two machines, or two pods,
//! that mount the same volume. The claim generation is what an orchestrator or the recovery operator
//! records when it hands the volume to a new owner, and every frame a journal appends carries it,
//! so recovery recognises a frame from a writer whose claim was superseded (H-05). That is evidence
//! in the data, not a fence: a partitioned old writer can ignore the file and go on writing. Before
//! a takeover the storage layer or the orchestrator must make the previous writer unable to write —
//! revoke its attachment, fence its node through an independent path, or rely on an equivalent
//! provider guarantee. Without one, failover is not automatic, and the operator confirms the old
//! writer is gone before the claim moves.

use std::fs::File;
use std::path::Path;

use permguard_core::assurance::AssuranceProfile;

use super::crash::point;
use super::format::{self, VIEW};
use super::write::{publish_immutable, read_view, replace_view};
use super::{Dir, Result, StorageError};

/// The directory below the volume root that holds the volume's own files.
pub const HOST: &str = "host";
/// The lock file, held exclusively for the life of the process that claimed the volume.
pub const LOCK: &str = "LOCK";
/// The volume's identity, random and written once.
pub const VOLUME_ID: &str = "VOLUME_ID";
/// The layout version, written once, last, when the volume is created.
pub const FORMAT: &str = "FORMAT";
/// The lease generation of the volume's current owner.
pub const VOLUME_CLAIM: &str = "VOLUME-CLAIM";

/// The layout version this build writes and reads.
pub const LAYOUT_VERSION: u64 = 1;

/// The generation of a volume without a claim, and of every frame written before claims existed.
pub const UNCLAIMED: u64 = 0;

/// A claimed volume: the lock is held until this is dropped.
#[derive(Debug)]
pub struct Volume {
    root: std::path::PathBuf,
    host: Dir,
    id: [u8; 16],
    generation: u64,
    // Held, never read: dropping it releases the lock.
    _lock: File,
}

impl Volume {
    /// Claims the volume at `root` for this process.
    ///
    /// Takes `LOCK` without waiting and fails with [`StorageError::Held`] when another process holds
    /// it. Without `FORMAT` the volume is still being created: a `VOLUME_ID` already there is kept,
    /// one is drawn otherwise, and `FORMAT` is written last. With `FORMAT`, a missing or unreadable
    /// `VOLUME_ID` is corruption. An absent `VOLUME-CLAIM` is [`UNCLAIMED`], refused from the
    /// `production` profile upward — after an empty volume was created, which is harmless: the
    /// claim the operator writes next makes it servable.
    pub fn claim(root: &Path, profile: AssuranceProfile) -> Result<Self> {
        let volume = Self::lock(root)?;
        if volume.generation == UNCLAIMED && profile.at_least(AssuranceProfile::Production) {
            return Err(StorageError::Refused(format!(
                "the volume at {} has no {VOLUME_CLAIM}; from the production profile upward a \
                 volume is served only under a claim the orchestrator or the operator wrote",
                root.display()
            )));
        }

        Ok(volume)
    }

    fn lock(root: &Path) -> Result<Self> {
        let host = Dir::create_root(root)?.subdir(HOST, true)?;
        let lock = open_lock(&host)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(StorageError::Held(format!(
                    "{} is held by another process on this mount",
                    host.child_path(LOCK).display()
                )));
            }
            Err(std::fs::TryLockError::Error(source)) => {
                return Err(StorageError::Io {
                    what: format!("locking {}", host.child_path(LOCK).display()),
                    source,
                });
            }
        }

        let id = match read_u64_view(&host, FORMAT)? {
            Some(version) => {
                check_layout(&host, version)?;
                read_id(&host)?.ok_or_else(|| {
                    StorageError::Corruption(format!(
                        "{} holds a layout and no {VOLUME_ID}",
                        host.path().display()
                    ))
                })?
            }
            None => create(&host)?,
        };
        let generation = read_u64_view(&host, VOLUME_CLAIM)?.unwrap_or(UNCLAIMED);

        Ok(Self {
            root: root.to_path_buf(),
            host,
            id,
            generation,
            _lock: lock,
        })
    }

    /// The volume's identity.
    pub fn id(&self) -> [u8; 16] {
        self.id
    }

    /// The volume's identity as 32 lowercase hex characters.
    pub fn id_hex(&self) -> String {
        self.id.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    /// The lease generation this process holds the volume under: every frame it appends carries it.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// The volume's root, the server's working directory: what a subsystem's generation
    /// directories are named relative to.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The `host` directory.
    pub fn host(&self) -> &Dir {
        &self.host
    }

    /// `options` for a journal this process writes: its frames carry this claim's generation, and
    /// opening it judges the frames already there against it.
    pub fn journal_options(&self, options: super::journal::Options) -> super::journal::Options {
        super::journal::Options {
            claim: self.generation,
            ..options
        }
    }
}

/// Holds an existing volume for an offline command that only reads it, such as `volume verify`:
/// takes `LOCK`, so it fails while a process holds the volume, and refuses a root that holds no
/// volume rather than creating one. The one thing it may write is `LOCK` itself, where a restored
/// copy lacks it.
pub fn hold(root: &Path) -> Result<Volume> {
    if !root.join(HOST).join(FORMAT).is_file() {
        return Err(StorageError::Refused(format!(
            "{} holds no volume: there is no {HOST}/{FORMAT}",
            root.display()
        )));
    }
    Volume::lock(root)
}

/// Records `generation` as the volume's claim, for the orchestrator or the recovery operator, and
/// answers the generation it replaced.
///
/// Takes `LOCK` like any writer, so it fails while a process holds the volume, and refuses a
/// generation that does not increase: a claim only moves forward, and moving it back would make the
/// data of the current owner look like a stale writer's. It never creates `root`, which must exist
/// as a mount point does, so a mistyped path is refused; inside it, the first claim creates the
/// volume.
pub fn set_claim(root: &Path, generation: u64) -> Result<u64> {
    if !root.is_dir() {
        return Err(StorageError::Refused(format!(
            "{} is not a directory; a claim is written on an existing volume root, a mount point, \
             and never creates one",
            root.display()
        )));
    }
    let volume = Volume::lock(root)?;
    if generation <= volume.generation {
        return Err(StorageError::Refused(format!(
            "the volume at {} is claimed at generation {}; a new claim must be higher, and {} is not",
            root.display(),
            volume.generation,
            generation
        )));
    }
    replace_view(&volume.host, VOLUME_CLAIM, VIEW, &generation.to_be_bytes())?;

    Ok(volume.generation)
}

/// Opens `LOCK`, creating it the first time; it is never removed. The handle answered is the one
/// the lock is taken on, and nothing here opens the file again.
fn open_lock(host: &Dir) -> Result<File> {
    match host.open_write(LOCK) {
        Ok(file) => Ok(file),
        Err(_) => match host.create_exclusive(LOCK) {
            Ok(file) => {
                drop(file);
                host.sync()?;
                host.open_write(LOCK)
            }
            // Another process created it in between: open what it made.
            Err(_) => host.open_write(LOCK),
        },
    }
}

/// Creates the volume's identity and then its layout: `VOLUME_ID` is kept when a creation that
/// crashed before `FORMAT` already wrote it.
fn create(host: &Dir) -> Result<[u8; 16]> {
    let id = match read_id(host)? {
        Some(id) => id,
        None => {
            let id = random_id()?;
            publish_once(host, VOLUME_ID, &id)?;
            id
        }
    };
    point("volume.id_written");
    publish_once(host, FORMAT, &LAYOUT_VERSION.to_be_bytes())?;
    point("volume.format_written");

    Ok(id)
}

fn publish_once(host: &Dir, name: &str, body: &[u8]) -> Result<()> {
    let content = format::encode_file(VIEW, 0, body);
    let verify = |held: &[u8]| format::decode_file(held, VIEW).is_ok_and(|(_, read)| read == body);
    let same = |held: &[u8]| held == content.as_slice();
    publish_immutable(host, name, &content, &verify, &same)?;

    Ok(())
}

fn read_id(host: &Dir) -> Result<Option<[u8; 16]>> {
    let Some(body) = read_view(host, VOLUME_ID, VIEW)? else {
        return Ok(None);
    };
    let id: [u8; 16] = body.as_slice().try_into().map_err(|_| {
        StorageError::Corruption(format!(
            "{} holds {} bytes, not the 16 of a volume identity",
            host.child_path(VOLUME_ID).display(),
            body.len()
        ))
    })?;

    Ok(Some(id))
}

fn read_u64_view(host: &Dir, name: &str) -> Result<Option<u64>> {
    let Some(body) = read_view(host, name, VIEW)? else {
        return Ok(None);
    };
    let bytes: [u8; 8] = body.as_slice().try_into().map_err(|_| {
        StorageError::Corruption(format!(
            "{} holds {} bytes, not a u64",
            host.child_path(name).display(),
            body.len()
        ))
    })?;

    Ok(Some(u64::from_be_bytes(bytes)))
}

fn check_layout(host: &Dir, version: u64) -> Result<()> {
    if version > LAYOUT_VERSION {
        return Err(StorageError::Unsupported(format!(
            "{} is laid out by version {version}; this build reads version {LAYOUT_VERSION}",
            host.path().display()
        )));
    }
    if version != LAYOUT_VERSION {
        return Err(StorageError::Corruption(format!(
            "{} names layout version {version}, which no build wrote",
            host.child_path(FORMAT).display()
        )));
    }

    Ok(())
}

fn random_id() -> Result<[u8; 16]> {
    use ring::rand::{SecureRandom as _, SystemRandom};

    let mut id = [0u8; 16];
    SystemRandom::new()
        .fill(&mut id)
        .map_err(|_| StorageError::Io {
            what: "drawing a volume identity".to_owned(),
            source: std::io::Error::other("the operating system's random source failed"),
        })?;

    Ok(id)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::storage::journal::{Journal, Options};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-volume-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    #[test]
    fn the_first_claim_creates_the_volume_and_later_claims_read_it() {
        let root = scratch("create");
        let first = Volume::claim(&root, AssuranceProfile::Development).expect("claims");
        let id = first.id();
        assert_ne!(id, [0; 16]);
        assert_eq!(first.generation(), UNCLAIMED);
        drop(first);

        let again = Volume::claim(&root, AssuranceProfile::Development).expect("claims again");
        assert_eq!(again.id(), id, "VOLUME_ID is written once");
        assert_eq!(again.id_hex().len(), 32);
        let host = root.join(HOST);
        for name in [LOCK, VOLUME_ID, FORMAT] {
            assert!(host.join(name).exists(), "{name}");
        }
    }

    #[test]
    fn a_second_claim_on_the_same_mount_fails_on_the_lock() {
        let root = scratch("held");
        let held = Volume::claim(&root, AssuranceProfile::Development).expect("claims");
        let refused = Volume::claim(&root, AssuranceProfile::Development).expect_err("held");
        assert!(matches!(refused, StorageError::Held(_)), "{refused}");
        drop(held);
        Volume::claim(&root, AssuranceProfile::Development).expect("free once released");
    }

    #[test]
    fn a_volume_without_a_claim_is_refused_from_production() {
        let root = scratch("unclaimed");
        std::fs::create_dir_all(&root).expect("a mount point");
        let refused = Volume::claim(&root, AssuranceProfile::Production).expect_err("no claim");
        assert!(matches!(refused, StorageError::Refused(_)), "{refused}");

        assert_eq!(set_claim(&root, 3).expect("claimed"), UNCLAIMED);
        let volume = Volume::claim(&root, AssuranceProfile::Regulated).expect("claimed");
        assert_eq!(volume.generation(), 3);
    }

    #[test]
    fn a_claim_only_moves_forward_and_never_beside_a_holder() {
        let root = scratch("forward");
        std::fs::create_dir_all(&root).expect("a mount point");
        assert_eq!(set_claim(&root, 5).expect("first claim"), UNCLAIMED);
        for lower in [5, 4, 0] {
            let refused = set_claim(&root, lower).expect_err("not higher");
            assert!(matches!(refused, StorageError::Refused(_)), "{refused}");
        }
        let held = Volume::claim(&root, AssuranceProfile::Development).expect("claims");
        let refused = set_claim(&root, 9).expect_err("held");
        assert!(matches!(refused, StorageError::Held(_)), "{refused}");
        drop(held);
        assert_eq!(set_claim(&root, 9).expect("moves"), 5);
    }

    #[test]
    fn a_claim_never_creates_the_volume_root() {
        let root = scratch("typo");
        let refused = set_claim(&root, 1).expect_err("no such root");
        assert!(matches!(refused, StorageError::Refused(_)), "{refused}");
        assert!(!root.exists(), "nothing is created at a mistyped path");

        std::fs::create_dir_all(&root).expect("a mount point");
        assert_eq!(set_claim(&root, 1).expect("claimed"), UNCLAIMED);
        assert!(
            root.join(HOST).join(VOLUME_ID).exists(),
            "the first claim creates the volume"
        );
    }

    #[test]
    fn a_layout_without_its_identity_or_of_another_version_is_refused() {
        let root = scratch("damaged");
        drop(Volume::claim(&root, AssuranceProfile::Development).expect("claims"));
        let host = root.join(HOST);

        let format = std::fs::read(host.join(FORMAT)).expect("FORMAT");
        std::fs::write(
            host.join(FORMAT),
            format::encode_file(VIEW, 0, &2u64.to_be_bytes()),
        )
        .expect("a newer layout");
        let refused = Volume::claim(&root, AssuranceProfile::Development).expect_err("newer");
        assert!(matches!(refused, StorageError::Unsupported(_)), "{refused}");
        std::fs::write(host.join(FORMAT), format).expect("restored");

        std::fs::remove_file(host.join(VOLUME_ID)).expect("identity removed");
        let refused = Volume::claim(&root, AssuranceProfile::Development).expect_err("no id");
        assert!(matches!(refused, StorageError::Corruption(_)), "{refused}");
        assert!(
            !host.join(VOLUME_ID).exists(),
            "a missing identity is never drawn again"
        );
    }

    #[test]
    fn a_creation_that_stopped_before_its_layout_keeps_its_identity() {
        let root = scratch("resume");
        drop(Volume::claim(&root, AssuranceProfile::Development).expect("claims"));
        let host = root.join(HOST);
        let id = std::fs::read(host.join(VOLUME_ID)).expect("VOLUME_ID");
        std::fs::remove_file(host.join(FORMAT)).expect("as if it crashed before FORMAT");

        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("completes");
        assert_eq!(std::fs::read(host.join(VOLUME_ID)).expect("VOLUME_ID"), id);
        assert!(host.join(FORMAT).exists());
        drop(volume);
    }

    #[test]
    fn a_journal_opened_under_the_claim_stamps_its_frames() {
        let root = scratch("stamp");
        std::fs::create_dir_all(&root).expect("a mount point");
        set_claim(&root, 7).expect("claimed");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claims");
        let dir = volume.host().subdir("journal", true).expect("dir");
        let (mut journal, _) =
            Journal::open(dir, volume.journal_options(Options::default())).expect("opens");
        journal.append(1, b"x").expect("appends");
        let frames = journal.frames().expect("frames");
        assert_eq!(frames[0].claim, 7);
    }
}
