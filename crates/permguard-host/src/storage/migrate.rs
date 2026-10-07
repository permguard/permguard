// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Migration of one subsystem's layout from one version to the next (WP-1.9).
//!
//! Layouts are versioned by subsystem. Each subsystem keeps a manifest below `host/layout/<name>/`
//! naming the version and the generation directory in force, and a binary declares the versions it
//! reads; a manifest outside that set is refused before anything is opened, so an older binary
//! never half-reads a newer layout and a downgrade is possible only where every active layout is
//! understood.
//!
//! ```text
//! preflight     old generation digested, free space measured, backup declared where required
//!   ─▶ INTENT   written and flushed before any new file exists
//!   ─▶ build    the new generation in its own directory beside the old; the old is never written
//!   ─▶ verify   digests and counts of the new generation, the old untouched, evidence byte for byte
//!   ─▶ switch   one atomic replacement of MANIFEST
//!   ─▶ COMMIT   written; the old generation stays, the rollback point
//!   ─▶ finalize explicitly, later: the old generation goes, with INTENT and COMMIT
//! ```
//!
//! Every step is a named crash point. Recovery reads INTENT, MANIFEST and COMMIT and lands on one
//! side: before the switch the new generation is abandoned, after it the migration is carried to
//! its commit, a finalize or a rollback in progress is completed. A migration runs offline on a
//! held volume (the maintenance mode); a server finding one pending refuses to start and names the
//! command that completes it (owner decisions of 2026-10-07).
//!
//! Evidence is never rewritten or re-signed: the framework compares every file the migration says
//! it carried, byte for byte, and refuses a build that changed one; the old generation's digests
//! are checked unchanged before the switch.

use std::collections::BTreeMap;
use std::fmt;

use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;

use super::crash::point;
use super::dir::Dir;
use super::format::VIEW;
use super::volume::Volume;
use super::write::{read_view, replace_view};
use super::{Result, StorageError};

/// The directory below `host/` holding one subdirectory per subsystem.
pub const LAYOUT: &str = "layout";
/// The view naming a subsystem's version and generation in force.
pub const MANIFEST: &str = "MANIFEST";
/// The view a migration writes before it builds anything.
pub const INTENT: &str = "INTENT";
/// The view a migration writes once the manifest is switched.
pub const COMMIT: &str = "COMMIT";
/// The most bytes a record takes.
pub const MAX_RECORD_BYTES: usize = 1024 * 1024;

/// The versions a binary reads for one subsystem: its current one and a bounded set of older ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reads {
    pub oldest: u16,
    pub current: u16,
}

impl Reads {
    /// From `oldest` to `current`, both read.
    pub fn from(oldest: u16, current: u16) -> Self {
        Self { oldest, current }
    }

    /// Only `version`.
    pub fn only(version: u16) -> Self {
        Self::from(version, version)
    }

    fn understands(&self, version: u16) -> bool {
        (self.oldest..=self.current).contains(&version)
    }
}

/// A subsystem's generation: its layout version and where it lives, relative to the volume root.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Generation {
    pub version: u16,
    pub generation: u64,
    pub directory: String,
}

/// `host/layout/<subsystem>/MANIFEST`: the generation in force, and the previous one while a
/// rollback is still possible.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayoutManifest {
    pub subsystem: String,
    pub active: Generation,
    pub previous: Option<Generation>,
    /// Seconds since the epoch, when the active generation was switched to.
    pub switched_at: u64,
}

/// `INTENT`: what a migration set out to do, written before any new file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationIntent {
    pub subsystem: String,
    pub from: Generation,
    pub to: Generation,
    /// Every file of the old generation, by path relative to it, and its digest.
    pub old_digests: BTreeMap<String, Digest>,
    /// The external backup the operator declared, when one was.
    pub backup: Option<String>,
    pub at: u64,
}

/// `COMMIT`: the migration as it landed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationCommit {
    pub subsystem: String,
    pub from: Generation,
    pub to: Generation,
    pub old_digests: BTreeMap<String, Digest>,
    pub new_digests: BTreeMap<String, Digest>,
    pub backup: Option<String>,
    pub committed_at: u64,
}

/// What a migration's build reports back, for the framework to verify.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Built {
    /// Files of the new generation carried from the old byte for byte, as `(old path, new path)`
    /// relative to each generation: evidence, which a migration never rewrites.
    pub carried: Vec<(String, String)>,
    /// Files of the old generation the new one does without, by path: a derived index the new
    /// layout rebuilds, a file the format retired. Never evidence.
    pub dropped: Vec<String>,
    /// How many files the new generation holds.
    pub files: usize,
}

/// One migration: from the version it reads to the version it writes.
pub trait Migration {
    /// The subsystem.
    fn subsystem(&self) -> &str;
    /// The layout version it reads.
    fn source_version(&self) -> u16;
    /// The layout version it writes.
    fn target_version(&self) -> u16;
    /// Builds the new generation below `new` from the old below `old`, writing nothing into
    /// `old`, and accounts for every old file as carried or dropped. The framework flushes the
    /// new generation before the switch; the build need not.
    fn build(&self, old: &Dir, new: &Dir) -> Result<Built>;
}

/// What the preflight is given.
#[derive(Debug, Clone)]
pub struct Preflight {
    /// The external backup the operator declares.
    backup: Option<String>,
    /// Whether a declared backup is required: from the `production` profile upward, derived from
    /// the profile and from nothing a caller sets.
    backup_required: bool,
    /// Where the new generation is built, relative to the volume root; it must not exist yet.
    to_directory: String,
    /// Seconds since the epoch, for the records.
    now: u64,
}

impl Preflight {
    /// A preflight under `profile`: a declared backup is required from `production` upward
    /// (owner decision of 2026-10-07).
    pub fn new(
        profile: permguard_core::assurance::AssuranceProfile,
        to_directory: &str,
        backup: Option<String>,
        now: u64,
    ) -> Self {
        Self {
            backup,
            backup_required: profile
                .at_least(permguard_core::assurance::AssuranceProfile::Production),
            to_directory: to_directory.to_owned(),
            now,
        }
    }
}

/// Where a subsystem's migration stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Phase {
    /// No migration: the active generation serves.
    Idle,
    /// The intent is written and the new generation is being built; the manifest is unchanged.
    Building,
    /// The manifest names the new generation and the commit is not written yet.
    Switched,
    /// Committed: the old generation is kept for a rollback until `finalize`.
    Committed,
    /// A finalize is removing the old generation and the records.
    Finalizing,
    /// A rollback is removing the new generation and the records.
    RollingBack,
}

impl Phase {
    /// The name as `migrate status` prints it.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Building => "building",
            Self::Switched => "switched",
            Self::Committed => "committed",
            Self::Finalizing => "finalizing",
            Self::RollingBack => "rolling_back",
        }
    }

    /// Whether a server may serve the subsystem: only when nothing is between two sides.
    pub fn serves(&self) -> bool {
        matches!(self, Self::Idle | Self::Committed)
    }
}

/// A subsystem as `migrate status` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub manifest: LayoutManifest,
    pub phase: Phase,
    /// The commit, while a rollback is still possible.
    pub commit: Option<MigrationCommit>,
}

/// A subsystem's layout on a held volume.
pub struct Layout<'a> {
    volume: &'a Volume,
    subsystem: String,
    dir: Dir,
}

impl<'a> Layout<'a> {
    /// Opens the layout of `subsystem` on `volume`, creating its directory, and completes any
    /// finalize or rollback a crash interrupted. A migration left between its intent and its
    /// commit is not touched here: [`Layout::recover`] does that, on request.
    pub fn open(volume: &'a Volume, subsystem: &str) -> Result<Self> {
        if subsystem.is_empty()
            || !subsystem
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b == b'-')
        {
            return Err(StorageError::Name(subsystem.to_owned()));
        }
        let dir = volume
            .host()
            .subdir(LAYOUT, true)?
            .subdir(subsystem, true)?;
        // A temporary a crashed record replacement left is never a record.
        dir.sweep_temps()?;
        let layout = Self {
            volume,
            subsystem: subsystem.to_owned(),
            dir,
        };
        layout.complete_interrupted()?;
        Ok(layout)
    }

    /// The manifest, or `None` when the subsystem was never laid out.
    pub fn manifest(&self) -> Result<Option<LayoutManifest>> {
        read_view(&self.dir, MANIFEST, VIEW)?
            .map(|body| LayoutManifest::decode(&body).map_err(|e| self.corruption(MANIFEST, e)))
            .transpose()
    }

    fn intent(&self) -> Result<Option<MigrationIntent>> {
        read_view(&self.dir, INTENT, VIEW)?
            .map(|body| MigrationIntent::decode(&body).map_err(|e| self.corruption(INTENT, e)))
            .transpose()
    }

    fn commit(&self) -> Result<Option<MigrationCommit>> {
        read_view(&self.dir, COMMIT, VIEW)?
            .map(|body| MigrationCommit::decode(&body).map_err(|e| self.corruption(COMMIT, e)))
            .transpose()
    }

    fn corruption(&self, name: &str, error: RecordError) -> StorageError {
        StorageError::Corruption(format!(
            "{} does not read as a layout record: {error}",
            self.dir.child_path(name).display()
        ))
    }

    /// Lays the subsystem out for the first time at `version` in `directory`, generation 1. A
    /// subsystem already laid out is left as it is.
    pub fn declare(&self, version: u16, directory: &str, now: u64) -> Result<LayoutManifest> {
        if let Some(manifest) = self.manifest()? {
            return Ok(manifest);
        }
        walk(&self.root()?, directory, true)?;
        let manifest = LayoutManifest {
            subsystem: self.subsystem.clone(),
            active: Generation {
                version,
                generation: 1,
                directory: directory.to_owned(),
            },
            previous: None,
            switched_at: now,
        };
        self.write(MANIFEST, &manifest.encode()?)?;
        Ok(manifest)
    }

    /// The active generation's directory, once the manifest's version is one `reads` understands:
    /// what a subsystem opens at start. Refused while a migration is between two sides.
    pub fn active(&self, reads: &Reads) -> Result<Dir> {
        let manifest = self.manifest()?.ok_or_else(|| {
            StorageError::Refused(format!(
                "{} is not laid out: nothing declared it",
                self.subsystem
            ))
        })?;
        let phase = self.phase(&manifest)?;
        if !phase.serves() {
            return Err(StorageError::Refused(format!(
                "a migration of {} is {}: run `migrate status`, then `migrate recover`, before \
                 the subsystem is served",
                self.subsystem,
                phase.as_str()
            )));
        }
        if !reads.understands(manifest.active.version) {
            return Err(StorageError::Unsupported(format!(
                "{} is laid out by version {}; this build reads versions {} to {}",
                self.subsystem, manifest.active.version, reads.oldest, reads.current
            )));
        }
        walk(&self.root()?, &manifest.active.directory, false)
    }

    /// Where the subsystem's migration stands.
    pub fn status(&self) -> Result<Option<Status>> {
        let Some(manifest) = self.manifest()? else {
            return Ok(None);
        };
        let phase = self.phase(&manifest)?;
        Ok(Some(Status {
            phase,
            commit: self.commit()?,
            manifest,
        }))
    }

    fn phase(&self, manifest: &LayoutManifest) -> Result<Phase> {
        let intent = self.intent()?;
        let commit = self.commit()?;
        Ok(match (intent, commit) {
            (None, None) => Phase::Idle,
            // The tail of a finalize or a rollback: the intent is removed first, the commit last,
            // and which of the two it was is what the manifest's generation says.
            (None, Some(commit)) => {
                if manifest.active.generation == commit.from.generation {
                    Phase::RollingBack
                } else {
                    Phase::Finalizing
                }
            }
            (Some(intent), None) => {
                if manifest.active.generation == intent.to.generation {
                    // A switched manifest keeps the old generation as `previous` until a
                    // finalize drops it, so one without is a finalize, whatever else is left.
                    if manifest.previous.is_none() {
                        Phase::Finalizing
                    } else {
                        Phase::Switched
                    }
                } else {
                    Phase::Building
                }
            }
            (Some(intent), Some(_)) => {
                if manifest.active.generation == intent.from.generation {
                    Phase::RollingBack
                } else if manifest.previous.is_none() {
                    Phase::Finalizing
                } else {
                    Phase::Committed
                }
            }
        })
    }

    /// Runs `migration` whole: preflight, intent, build, verify, switch, commit. The old
    /// generation stays until [`Layout::finalize`].
    pub fn migrate(
        &self,
        migration: &dyn Migration,
        preflight: Preflight,
    ) -> Result<MigrationCommit> {
        if migration.subsystem() != self.subsystem {
            return Err(StorageError::Refused(format!(
                "the migration is of {}, this layout of {}",
                migration.subsystem(),
                self.subsystem
            )));
        }
        let manifest = self.manifest()?.ok_or_else(|| {
            StorageError::Refused(format!(
                "{} is not laid out: nothing to migrate",
                self.subsystem
            ))
        })?;
        match self.phase(&manifest)? {
            Phase::Idle => {}
            Phase::Committed => {
                return Err(StorageError::Refused(format!(
                    "{} has a committed migration awaiting `migrate finalize` or `migrate rollback`",
                    self.subsystem
                )));
            }
            other => {
                return Err(StorageError::Refused(format!(
                    "a migration of {} is {}: `migrate recover` lands it first",
                    self.subsystem,
                    other.as_str()
                )));
            }
        }
        if manifest.active.version != migration.source_version() {
            return Err(StorageError::Refused(format!(
                "{} is at version {}, the migration reads version {}",
                self.subsystem,
                manifest.active.version,
                migration.source_version()
            )));
        }
        if migration.target_version() <= migration.source_version() {
            return Err(StorageError::Refused(format!(
                "a migration moves forward: {} to {} does not",
                migration.source_version(),
                migration.target_version()
            )));
        }

        // Preflight: the backup declared where it must be, the old generation digested (the
        // rollback point, verified intact), room for a generation of its size.
        if preflight.backup_required && preflight.backup.is_none() {
            return Err(StorageError::Refused(
                "no backup is declared, and the profile requires one before a migration".to_owned(),
            ));
        }
        let root = self.root()?;
        let old = walk(&root, &manifest.active.directory, false)?;
        let (old_digests, old_bytes) = digest_tree(&old)?;
        // The filesystem's figure, and the fault shim's where a test filled the disk.
        let free = root.free_space()?.bytes;
        let free =
            permguard_core::fault::free_bytes(root.path()).map_or(free, |left| left.min(free));
        if free < old_bytes.saturating_mul(2) {
            return Err(StorageError::Refused(format!(
                "{free} bytes free, a generation of {old_bytes} bytes needs twice that beside the \
                 old one"
            )));
        }
        let to = preflight.to_directory.as_str();
        let active = manifest.active.directory.as_str();
        if components(to).is_err()
            || to == super::volume::HOST
            || to.starts_with(&format!("{}/", super::volume::HOST))
            || to == active
            || to.starts_with(&format!("{active}/"))
            || active.starts_with(&format!("{to}/"))
            || root_has(&root, to)?
        {
            return Err(StorageError::Refused(format!(
                "`{to}` is not a free directory for the new generation: it exists, lies under \
                 `host/`, or is inside or around the active generation `{active}`"
            )));
        }

        let intent = MigrationIntent {
            subsystem: self.subsystem.clone(),
            from: manifest.active.clone(),
            to: Generation {
                version: migration.target_version(),
                generation: manifest.active.generation + 1,
                directory: preflight.to_directory.clone(),
            },
            old_digests,
            backup: preflight.backup.clone(),
            at: preflight.now,
        };
        self.write(INTENT, &intent.encode()?)?;
        point("migrate.intent_written");

        let new = walk(&root, &intent.to.directory, true)?;
        let built = migration.build(&old, &new)?;
        point("migrate.built");

        let new_digests = self.verify(&intent, &built, &old, &new)?;
        point("migrate.verified");

        self.switch(&manifest, &intent, preflight.now)?;
        point("migrate.switched");

        let commit = MigrationCommit {
            subsystem: intent.subsystem.clone(),
            from: intent.from.clone(),
            to: intent.to.clone(),
            old_digests: intent.old_digests.clone(),
            new_digests,
            backup: intent.backup.clone(),
            committed_at: preflight.now,
        };
        self.write(COMMIT, &commit.encode()?)?;
        point("migrate.committed");
        Ok(commit)
    }

    /// Verifies the new generation against what the build reported and the old one against the
    /// intent: counts, carried evidence byte for byte, and nothing written into the old.
    fn verify(
        &self,
        intent: &MigrationIntent,
        built: &Built,
        old: &Dir,
        new: &Dir,
    ) -> Result<BTreeMap<String, Digest>> {
        let (old_now, _) = digest_tree(old)?;
        if old_now != intent.old_digests {
            return Err(StorageError::Refused(format!(
                "the migration of {} wrote into the old generation, which a migration never does",
                self.subsystem
            )));
        }
        let (new_digests, _) = digest_tree(new)?;
        if new_digests.len() != built.files {
            return Err(StorageError::Refused(format!(
                "the new generation of {} holds {} files, the build declared {}",
                self.subsystem,
                new_digests.len(),
                built.files
            )));
        }
        // Every old file is accounted for exactly once, carried or dropped: evidence the build
        // rewrote and did not list would otherwise pass unseen.
        let mut accounted: BTreeMap<&str, usize> = BTreeMap::new();
        for from in built
            .carried
            .iter()
            .map(|(from, _)| from.as_str())
            .chain(built.dropped.iter().map(String::as_str))
        {
            *accounted.entry(from).or_default() += 1;
        }
        for (path, times) in &accounted {
            if *times > 1 {
                return Err(StorageError::Refused(format!(
                    "the migration of {} accounts for `{path}` {times} times",
                    self.subsystem
                )));
            }
            if !intent.old_digests.contains_key(*path) {
                return Err(StorageError::Refused(format!(
                    "the migration of {} accounts for `{path}`, which the old generation does not \
                     hold",
                    self.subsystem
                )));
            }
        }
        if let Some(unaccounted) = intent
            .old_digests
            .keys()
            .find(|path| !accounted.contains_key(path.as_str()))
        {
            return Err(StorageError::Refused(format!(
                "the migration of {} says nothing of `{unaccounted}`: every old file is carried \
                 byte for byte or dropped by name",
                self.subsystem
            )));
        }
        for (from, to) in &built.carried {
            match (intent.old_digests.get(from), new_digests.get(to)) {
                (Some(before), Some(after)) if before == after => {}
                (Some(_), Some(_)) => {
                    return Err(StorageError::Refused(format!(
                        "the migration of {} rewrote the evidence `{from}` as `{to}`: evidence is \
                         carried byte for byte or not at all",
                        self.subsystem
                    )));
                }
                _ => {
                    return Err(StorageError::Refused(format!(
                        "the migration of {} says it carried `{from}` to `{to}`, and one of them \
                         does not exist",
                        self.subsystem
                    )));
                }
            }
        }
        // Durable before the manifest points at it: a power loss after the switch must not find
        // files the build wrote and nothing flushed.
        flush_tree(new)?;
        Ok(new_digests)
    }

    fn switch(&self, manifest: &LayoutManifest, intent: &MigrationIntent, now: u64) -> Result<()> {
        let switched = LayoutManifest {
            subsystem: self.subsystem.clone(),
            active: intent.to.clone(),
            previous: Some(manifest.active.clone()),
            switched_at: now,
        };
        self.write(MANIFEST, &switched.encode()?)
    }

    /// Lands a migration a crash left between two sides: before the switch the new generation is
    /// abandoned, after it the commit is written; a finalize or a rollback in progress is
    /// completed. Answers the phase it found.
    pub fn recover(&self, now: u64) -> Result<Phase> {
        let Some(manifest) = self.manifest()? else {
            return Ok(Phase::Idle);
        };
        let phase = self.phase(&manifest)?;
        match phase {
            Phase::Idle | Phase::Committed => {}
            Phase::Building => {
                let intent = self.intent()?.expect("the phase read it");
                self.abandon(&intent.to.directory)?;
            }
            Phase::Switched => {
                // Offline on a held volume, so the new generation is as the build left it: the
                // digests recorded now are the ones the verification before the switch read.
                let intent = self.intent()?.expect("the phase read it");
                let root = self.root()?;
                let new = walk(&root, &intent.to.directory, false)?;
                let (new_digests, _) = digest_tree(&new)?;
                let commit = MigrationCommit {
                    subsystem: intent.subsystem.clone(),
                    from: intent.from.clone(),
                    to: intent.to.clone(),
                    old_digests: intent.old_digests.clone(),
                    new_digests,
                    backup: intent.backup.clone(),
                    committed_at: now,
                };
                self.write(COMMIT, &commit.encode()?)?;
                point("migrate.committed");
            }
            Phase::Finalizing | Phase::RollingBack => self.complete_interrupted()?,
        }
        Ok(phase)
    }

    /// Removes the old generation of a committed migration, with INTENT and COMMIT: the rollback
    /// horizon ends here and nowhere else.
    pub fn finalize(&self, now: u64) -> Result<()> {
        let manifest = self
            .manifest()?
            .ok_or_else(|| StorageError::Refused(format!("{} is not laid out", self.subsystem)))?;
        match self.phase(&manifest)? {
            Phase::Committed => {}
            Phase::Finalizing => return self.complete_interrupted(),
            other => {
                return Err(StorageError::Refused(format!(
                    "{} has no committed migration to finalize: it is {}; `migrate status` says \
                     what there is",
                    self.subsystem,
                    other.as_str()
                )));
            }
        }
        let finalized = LayoutManifest {
            previous: None,
            switched_at: now,
            ..manifest
        };
        self.write(MANIFEST, &finalized.encode()?)?;
        point("migrate.finalize_manifest");
        self.complete_interrupted()
    }

    /// Returns to the old generation of a committed migration, when the new one is as the commit
    /// left it: a generation the server has since written into is never discarded.
    pub fn rollback(&self, now: u64) -> Result<()> {
        let manifest = self
            .manifest()?
            .ok_or_else(|| StorageError::Refused(format!("{} is not laid out", self.subsystem)))?;
        match self.phase(&manifest)? {
            Phase::Committed => {}
            Phase::RollingBack => return self.complete_interrupted(),
            other => {
                return Err(StorageError::Refused(format!(
                    "{} has no committed migration to roll back: it is {}; `migrate status` says \
                     what there is",
                    self.subsystem,
                    other.as_str()
                )));
            }
        }
        // Compared and then switched by the one process holding the volume: nothing writes the
        // new generation between the two.
        let commit = self.commit()?.expect("the phase read it");
        let root = self.root()?;
        let new = walk(&root, &commit.to.directory, false)?;
        let (now_digests, _) = digest_tree(&new)?;
        if now_digests != commit.new_digests {
            let changed: Vec<&String> = now_digests
                .iter()
                .filter(|(path, digest)| commit.new_digests.get(*path) != Some(*digest))
                .map(|(path, _)| path)
                .chain(
                    commit
                        .new_digests
                        .keys()
                        .filter(|path| !now_digests.contains_key(*path)),
                )
                .collect();
            return Err(StorageError::Refused(format!(
                "the new generation of {} changed since the migration committed ({} files, \
                 {}{}): a rollback would lose what was written after it",
                self.subsystem,
                changed.len(),
                changed
                    .iter()
                    .take(3)
                    .map(|path| path.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                if changed.len() > 3 { ", …" } else { "" }
            )));
        }
        let previous = manifest.previous.clone().ok_or_else(|| {
            StorageError::Corruption(format!(
                "{} is committed and names no previous generation",
                self.dir.child_path(MANIFEST).display()
            ))
        })?;
        let restored = LayoutManifest {
            subsystem: self.subsystem.clone(),
            active: previous,
            previous: None,
            switched_at: now,
        };
        self.write(MANIFEST, &restored.encode()?)?;
        point("migrate.rollback_switched");
        self.complete_interrupted()
    }

    /// Completes a finalize or a rollback the records say is in progress; nothing otherwise.
    fn complete_interrupted(&self) -> Result<()> {
        let Some(manifest) = self.manifest()? else {
            return Ok(());
        };
        // The directories from whichever record is left: the intent goes before the commit.
        let (from, to) = match (self.intent()?, self.commit()?) {
            (Some(intent), _) => (intent.from.directory, intent.to.directory),
            (None, Some(commit)) => (commit.from.directory, commit.to.directory),
            (None, None) => return Ok(()),
        };
        match self.phase(&manifest)? {
            Phase::Finalizing => {
                self.remove_generation(&from)?;
                point("migrate.finalize_old_removed");
                self.remove_records()?;
                point("migrate.finalize_records_removed");
            }
            Phase::RollingBack => {
                self.remove_generation(&to)?;
                point("migrate.rollback_new_removed");
                self.remove_records()?;
                point("migrate.rollback_records_removed");
            }
            _ => {}
        }
        Ok(())
    }

    /// Abandons a build that never reached the switch: the new directory goes, then the intent.
    fn abandon(&self, to_directory: &str) -> Result<()> {
        self.remove_generation(to_directory)?;
        point("migrate.abandon_new_removed");
        self.dir.unlink(INTENT)?;
        self.dir.sync()?;
        point("migrate.abandon_intent_removed");
        Ok(())
    }

    /// The intent first, the commit last: a commit alone still names both generations, so the
    /// tail of a finalize or a rollback reads as what it is.
    fn remove_records(&self) -> Result<()> {
        self.dir.unlink(INTENT)?;
        self.dir.sync()?;
        self.dir.unlink(COMMIT)?;
        self.dir.sync()?;
        Ok(())
    }

    fn remove_generation(&self, directory: &str) -> Result<()> {
        let root = self.root()?;
        if !root_has(&root, directory)? {
            return Ok(());
        }
        let (parent, name) = split_last(directory);
        let parent = match parent {
            Some(parent) => walk(&root, parent, false)?,
            None => root,
        };
        remove_tree(&parent, name)
    }

    fn write(&self, name: &str, body: &[u8]) -> Result<()> {
        replace_view(&self.dir, name, VIEW, body)
    }

    fn root(&self) -> Result<Dir> {
        Dir::open(self.volume.root())
    }
}

/// Every subsystem laid out on `volume`, with where its migration stands.
pub fn status(volume: &Volume) -> Result<Vec<Status>> {
    // Reading creates nothing: a volume that lays nothing out stays as it is.
    let layout = match volume.host().subdir(LAYOUT, false) {
        Ok(layout) => layout,
        Err(StorageError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Vec::new());
        }
        Err(error) => return Err(error),
    };
    let mut all = Vec::new();
    for name in layout.subdirs()? {
        if let Some(status) = Layout::open(volume, &name)?.status()? {
            all.push(status);
        }
    }
    all.sort_by(|a, b| a.manifest.subsystem.cmp(&b.manifest.subsystem));
    Ok(all)
}

/// Refuses a volume a server may not serve: a migration between two sides, a subsystem laid out by
/// a version this build does not read, or a subsystem this build does not know. `declared` names
/// every subsystem the build reads and the versions it reads it at.
pub fn check_servable(volume: &Volume, declared: &[(&str, Reads)]) -> Result<()> {
    for status in status(volume)? {
        let name = status.manifest.subsystem.as_str();
        if !status.phase.serves() {
            return Err(StorageError::Refused(format!(
                "a migration of {name} is {}: run `migrate status`, then `migrate rollback` or \
                 `migrate recover`, before the server starts",
                status.phase.as_str()
            )));
        }
        let Some((_, reads)) = declared.iter().find(|(known, _)| *known == name) else {
            return Err(StorageError::Unsupported(format!(
                "the volume lays out {name}, which this build does not know: an older build \
                 cannot serve a volume with a layout it does not understand"
            )));
        };
        if !reads.understands(status.manifest.active.version) {
            return Err(StorageError::Unsupported(format!(
                "{name} is laid out by version {}; this build reads versions {} to {}",
                status.manifest.active.version, reads.oldest, reads.current
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Directories.

/// Opens `path`, a `/`-separated path of components relative to `root`, creating it when asked.
fn walk(root: &Dir, path: &str, create: bool) -> Result<Dir> {
    let mut dir = Dir::open(root.path())?;
    for component in components(path)? {
        dir = dir.subdir(component, create)?;
    }
    Ok(dir)
}

fn root_has(root: &Dir, path: &str) -> Result<bool> {
    let (parent, name) = split_last(path);
    let parent = match parent {
        Some(parent) => match walk(root, parent, false) {
            Ok(parent) => parent,
            Err(StorageError::Io { source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(false);
            }
            Err(error) => return Err(error),
        },
        None => Dir::open(root.path())?,
    };
    Ok(parent.subdirs()?.iter().any(|held| held == name) || parent.exists(name)?)
}

fn components(path: &str) -> Result<Vec<&str>> {
    let parts: Vec<&str> = path.split('/').collect();
    if parts.is_empty()
        || parts
            .iter()
            .any(|part| part.is_empty() || *part == "." || *part == "..")
    {
        return Err(StorageError::Name(path.to_owned()));
    }
    Ok(parts)
}

fn split_last(path: &str) -> (Option<&str>, &str) {
    match path.rsplit_once('/') {
        Some((parent, name)) => (Some(parent), name),
        None => (None, path),
    }
}

/// Every regular file below `dir`, recursively, by `/`-separated relative path and digest, and
/// their bytes in all.
fn digest_tree(dir: &Dir) -> Result<(BTreeMap<String, Digest>, u64)> {
    let mut digests = BTreeMap::new();
    let mut bytes = 0u64;
    digest_into(dir, "", &mut digests, &mut bytes)?;
    Ok((digests, bytes))
}

fn digest_into(
    dir: &Dir,
    prefix: &str,
    into: &mut BTreeMap<String, Digest>,
    bytes: &mut u64,
) -> Result<()> {
    let mut names = dir.names()?;
    names.sort();
    for name in names {
        let content = dir.read(&name)?.unwrap_or_default();
        *bytes = bytes.saturating_add(content.len() as u64);
        into.insert(format!("{prefix}{name}"), Digest::compute(&content));
    }
    let mut subdirs = dir.subdirs()?;
    subdirs.sort();
    for name in subdirs {
        digest_into(
            &dir.subdir(&name, false)?,
            &format!("{prefix}{name}/"),
            into,
            bytes,
        )?;
    }
    Ok(())
}

/// Flushes every regular file and directory below `dir`, `dir` included.
fn flush_tree(dir: &Dir) -> Result<()> {
    for name in dir.names()? {
        dir.sync_file(&name)?;
    }
    for name in dir.subdirs()? {
        flush_tree(&dir.subdir(&name, false)?)?;
    }
    dir.sync()
}

/// Removes the subdirectory `name` of `parent` and everything below it.
fn remove_tree(parent: &Dir, name: &str) -> Result<()> {
    let dir = parent.subdir(name, false)?;
    for file in dir.names()? {
        dir.unlink(&file)?;
    }
    for sub in dir.subdirs()? {
        remove_tree(&dir, &sub)?;
    }
    dir.sync()?;
    parent.remove_subdir(name)?;
    parent.sync()
}

// ---------------------------------------------------------------------------------------------
// Records: deterministic CBOR with integer labels, registered in `contracts/cbor/layout.json`.

type RecordResult<T> = std::result::Result<T, RecordError>;

/// Why a record did not read or write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    TooLarge(usize),
    Cbor(String),
    Malformed(String),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(bytes) => {
                write!(
                    f,
                    "{bytes} bytes; a layout record takes up to {MAX_RECORD_BYTES}"
                )
            }
            Self::Cbor(detail) => write!(f, "not canonical CBOR: {detail}"),
            Self::Malformed(detail) => write!(f, "not a layout record: {detail}"),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<RecordError> for StorageError {
    fn from(error: RecordError) -> Self {
        StorageError::Corruption(error.to_string())
    }
}

fn uint(value: u64) -> RecordResult<Value> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| RecordError::Malformed("an integer beyond the signed 64-bit range".to_owned()))
}

fn digests(map: &BTreeMap<String, Digest>) -> Value {
    Value::Map(
        map.iter()
            .map(|(path, digest)| (Value::Text(path.clone()), Value::Text(digest.to_string())))
            .collect(),
    )
}

impl Generation {
    fn encode(&self) -> RecordResult<Value> {
        Ok(Value::Map(vec![
            (Value::Int(1), uint(u64::from(self.version))?),
            (Value::Int(2), uint(self.generation)?),
            (Value::Int(3), Value::Text(self.directory.clone())),
        ]))
    }

    fn decode(value: Value) -> RecordResult<Self> {
        let mut map = Labelled::new(value, 3)?;
        let generation = Self {
            version: map.version(1)?,
            generation: map.uint(2)?,
            directory: map.text(3)?,
        };
        map.finish()?;
        Ok(generation)
    }
}

impl LayoutManifest {
    /// The canonical bytes.
    pub fn encode(&self) -> RecordResult<Vec<u8>> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.subsystem.clone())),
            (Value::Int(2), uint(u64::from(self.active.version))?),
            (Value::Int(3), uint(self.active.generation)?),
            (Value::Int(4), Value::Text(self.active.directory.clone())),
        ];
        if let Some(previous) = &self.previous {
            pairs.push((Value::Int(5), previous.encode()?));
        }
        pairs.push((Value::Int(6), uint(self.switched_at)?));
        cbor::encode(&Value::Map(pairs)).map_err(|e| RecordError::Cbor(e.to_string()))
    }

    /// Reads the canonical bytes, refusing an unknown label, a missing required one or a value
    /// of another type.
    pub fn decode(bytes: &[u8]) -> RecordResult<Self> {
        let mut map = Labelled::root(bytes, 6)?;
        let manifest = Self {
            subsystem: map.text(1)?,
            active: Generation {
                version: map.version(2)?,
                generation: map.uint(3)?,
                directory: map.text(4)?,
            },
            previous: map.optional(5)?.map(Generation::decode).transpose()?,
            switched_at: map.uint(6)?,
        };
        map.finish()?;
        Ok(manifest)
    }
}

impl MigrationIntent {
    /// The canonical bytes.
    pub fn encode(&self) -> RecordResult<Vec<u8>> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.subsystem.clone())),
            (Value::Int(2), uint(u64::from(self.from.version))?),
            (Value::Int(3), uint(u64::from(self.to.version))?),
            (Value::Int(4), uint(self.from.generation)?),
            (Value::Int(5), uint(self.to.generation)?),
            (Value::Int(6), Value::Text(self.to.directory.clone())),
            (Value::Int(7), digests(&self.old_digests)),
        ];
        if let Some(backup) = &self.backup {
            pairs.push((Value::Int(8), Value::Text(backup.clone())));
        }
        pairs.push((Value::Int(9), uint(self.at)?));
        pairs.push((Value::Int(10), Value::Text(self.from.directory.clone())));
        cbor::encode(&Value::Map(pairs)).map_err(|e| RecordError::Cbor(e.to_string()))
    }

    /// Reads the canonical bytes.
    pub fn decode(bytes: &[u8]) -> RecordResult<Self> {
        let mut map = Labelled::root(bytes, 10)?;
        let intent = Self {
            subsystem: map.text(1)?,
            from: Generation {
                version: map.version(2)?,
                generation: map.uint(4)?,
                directory: map.text(10)?,
            },
            to: Generation {
                version: map.version(3)?,
                generation: map.uint(5)?,
                directory: map.text(6)?,
            },
            old_digests: map.digests(7)?,
            backup: map.optional_text(8)?,
            at: map.uint(9)?,
        };
        map.finish()?;
        Ok(intent)
    }
}

impl MigrationCommit {
    /// The canonical bytes.
    pub fn encode(&self) -> RecordResult<Vec<u8>> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.subsystem.clone())),
            (Value::Int(2), uint(u64::from(self.from.version))?),
            (Value::Int(3), uint(u64::from(self.to.version))?),
            (Value::Int(4), uint(self.from.generation)?),
            (Value::Int(5), uint(self.to.generation)?),
            (Value::Int(6), Value::Text(self.to.directory.clone())),
            (Value::Int(7), digests(&self.old_digests)),
            (Value::Int(8), digests(&self.new_digests)),
        ];
        if let Some(backup) = &self.backup {
            pairs.push((Value::Int(9), Value::Text(backup.clone())));
        }
        pairs.push((Value::Int(10), uint(self.committed_at)?));
        pairs.push((Value::Int(11), Value::Text(self.from.directory.clone())));
        cbor::encode(&Value::Map(pairs)).map_err(|e| RecordError::Cbor(e.to_string()))
    }

    /// Reads the canonical bytes.
    pub fn decode(bytes: &[u8]) -> RecordResult<Self> {
        let mut map = Labelled::root(bytes, 11)?;
        let commit = Self {
            subsystem: map.text(1)?,
            from: Generation {
                version: map.version(2)?,
                generation: map.uint(4)?,
                directory: map.text(11)?,
            },
            to: Generation {
                version: map.version(3)?,
                generation: map.uint(5)?,
                directory: map.text(6)?,
            },
            old_digests: map.digests(7)?,
            new_digests: map.digests(8)?,
            backup: map.optional_text(9)?,
            committed_at: map.uint(10)?,
        };
        map.finish()?;
        Ok(commit)
    }
}

/// A decoded integer-labelled map, read label by label and then checked for leftovers.
struct Labelled {
    pairs: BTreeMap<i64, Value>,
}

impl Labelled {
    fn root(bytes: &[u8], highest: i64) -> RecordResult<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value = cbor::decode_canonical(bytes).map_err(|e| RecordError::Cbor(e.to_string()))?;
        Self::new(value, highest)
    }

    fn new(value: Value, highest: i64) -> RecordResult<Self> {
        let Value::Map(pairs) = value else {
            return Err(RecordError::Malformed("the root is a map".to_owned()));
        };
        let mut labelled = BTreeMap::new();
        for (key, value) in pairs {
            let Value::Int(label) = key else {
                return Err(RecordError::Malformed("labels are integers".to_owned()));
            };
            if label < 1 || label > highest {
                return Err(RecordError::Malformed(format!("unknown label {label}")));
            }
            labelled.insert(label, value);
        }
        Ok(Self { pairs: labelled })
    }

    fn take(&mut self, label: i64) -> RecordResult<Value> {
        self.pairs
            .remove(&label)
            .ok_or_else(|| RecordError::Malformed(format!("label {label} is required")))
    }

    fn optional(&mut self, label: i64) -> RecordResult<Option<Value>> {
        Ok(self.pairs.remove(&label))
    }

    fn text(&mut self, label: i64) -> RecordResult<String> {
        match self.take(label)? {
            Value::Text(text) => Ok(text),
            _ => Err(RecordError::Malformed(format!("label {label} is text"))),
        }
    }

    fn optional_text(&mut self, label: i64) -> RecordResult<Option<String>> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Text(text)) => Ok(Some(text)),
            Some(_) => Err(RecordError::Malformed(format!("label {label} is text"))),
        }
    }

    fn uint(&mut self, label: i64) -> RecordResult<u64> {
        match self.take(label)? {
            Value::Int(value) if value >= 0 => Ok(value as u64),
            _ => Err(RecordError::Malformed(format!(
                "label {label} is an unsigned integer"
            ))),
        }
    }

    fn version(&mut self, label: i64) -> RecordResult<u16> {
        u16::try_from(self.uint(label)?)
            .map_err(|_| RecordError::Malformed(format!("label {label} is a layout version")))
    }

    fn digests(&mut self, label: i64) -> RecordResult<BTreeMap<String, Digest>> {
        match self.take(label)? {
            Value::Map(pairs) => pairs
                .into_iter()
                .map(|(key, value)| match (key, value) {
                    (Value::Text(path), Value::Text(digest)) => Digest::parse(&digest)
                        .map(|digest| (path, digest))
                        .map_err(|e| RecordError::Malformed(format!("label {label}: {e}"))),
                    _ => Err(RecordError::Malformed(format!(
                        "label {label} is a map of path to digest"
                    ))),
                })
                .collect(),
            _ => Err(RecordError::Malformed(format!("label {label} is a map"))),
        }
    }

    fn finish(self) -> RecordResult<()> {
        match self.pairs.keys().next() {
            None => Ok(()),
            Some(label) => Err(RecordError::Malformed(format!("unexpected label {label}"))),
        }
    }
}

pub mod testing {
    //! A closed, test-only synthetic subsystem, for the framework's own tests and the crash-point
    //! harness: `notes`, version 1 keeps one file per note, version 2 keeps them under
    //! `<initial>/` and carries each byte for byte; an `INDEX` is derived. No production
    //! subsystem is laid out this way; a real migration comes with the package that owns it.

    use super::*;

    pub const SUBSYSTEM: &str = "notes";

    /// The migration from version 1 to version 2 of `notes`.
    pub struct NotesV2 {
        /// Set by a test that wants the build to rewrite a note it says it carried.
        pub tamper: bool,
        /// Set by a test that wants the build to write into the old generation.
        pub write_old: bool,
        /// Set by a test that wants the build to say nothing of the first note.
        pub omit: bool,
    }

    impl Migration for NotesV2 {
        fn subsystem(&self) -> &str {
            SUBSYSTEM
        }
        fn source_version(&self) -> u16 {
            1
        }
        fn target_version(&self) -> u16 {
            2
        }
        fn build(&self, old: &Dir, new: &Dir) -> Result<Built> {
            let mut carried = Vec::new();
            let mut names = old.names()?;
            names.sort();
            let mut index = String::new();
            for name in &names {
                let mut content = old.read(name)?.unwrap_or_default();
                if self.tamper {
                    content.push(b'!');
                }
                let initial = name.chars().next().unwrap_or('_').to_string();
                let letter = new.subdir(&initial, true)?;
                let path = letter.child_path(name);
                let mut file = letter.create_exclusive(name)?;
                std::io::Write::write_all(&mut file, &content).map_err(|e| StorageError::Io {
                    what: format!("writing {}", path.display()),
                    source: e,
                })?;
                file.sync_all().map_err(|e| StorageError::Io {
                    what: format!("flushing {}", path.display()),
                    source: e,
                })?;
                letter.sync()?;
                if !(self.omit && carried.is_empty()) {
                    carried.push((name.clone(), format!("{initial}/{name}")));
                }
                index.push_str(name);
                index.push('\n');
            }
            if self.write_old {
                let mut file = old.create_exclusive("INTRUDER")?;
                std::io::Write::write_all(&mut file, b"x").map_err(|e| StorageError::Io {
                    what: "writing".to_owned(),
                    source: e,
                })?;
            }
            replace_view(new, "INDEX", VIEW, index.as_bytes())?;
            Ok(Built {
                files: names.len() + 1,
                carried,
                dropped: Vec::new(),
            })
        }
    }

    /// Writes one note, flushed.
    pub fn write_note(dir: &Dir, name: &str, body: &[u8]) {
        let mut file = dir.create_exclusive(name).expect("created");
        std::io::Write::write_all(&mut file, body).expect("written");
        file.sync_all().expect("flushed");
        dir.sync().expect("flushed");
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::testing::*;
    use super::*;
    use permguard_core::assurance::AssuranceProfile;

    const NOW: u64 = 1_800_000_000;

    fn scratch(tag: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!(
            "permguard-host-migrate-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        path
    }

    fn laid_out(tag: &str) -> (std::path::PathBuf, Volume) {
        let root = scratch(tag);
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        layout.declare(1, "data/notes/g1", NOW).expect("declared");
        let old = layout
            .active(&Reads::only(1))
            .expect("the active generation");
        write_note(&old, "alpha", b"first note");
        write_note(&old, "beta", b"second note");
        (root, volume)
    }

    fn preflight() -> Preflight {
        Preflight::new(AssuranceProfile::Development, "data/notes/g2", None, NOW)
    }

    #[test]
    fn a_migration_builds_beside_verifies_switches_and_commits_keeping_the_old_generation() {
        let (root, volume) = laid_out("whole");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        let commit = layout
            .migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false,
                },
                preflight(),
            )
            .expect("migrates");
        assert_eq!(commit.to.version, 2);
        assert_eq!(commit.new_digests.len(), 3);
        assert_eq!(commit.new_digests["a/alpha"], commit.old_digests["alpha"]);
        let status = layout.status().expect("status").expect("laid out");
        assert_eq!(status.phase, Phase::Committed);
        assert_eq!(status.manifest.active.directory, "data/notes/g2");
        assert_eq!(
            status
                .manifest
                .previous
                .as_ref()
                .map(|p| p.directory.as_str()),
            Some("data/notes/g1")
        );
        assert!(
            root.join("data/notes/g1/alpha").is_file(),
            "the old generation stays"
        );
        assert!(root.join("data/notes/g2/a/alpha").is_file());
        // A version 1 reader is refused the new layout; a reader of both opens it.
        assert!(matches!(
            layout.active(&Reads::only(1)),
            Err(StorageError::Unsupported(_))
        ));
        layout.active(&Reads::from(1, 2)).expect("read");
        // A committed migration stays committed; another cannot start over it.
        assert!(matches!(
            layout.migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false
                },
                preflight()
            ),
            Err(StorageError::Refused(_))
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn finalize_removes_the_old_generation_and_the_records_and_only_then() {
        let (root, volume) = laid_out("finalize");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        assert!(matches!(
            layout.finalize(NOW),
            Err(StorageError::Refused(_))
        ));
        layout
            .migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false,
                },
                preflight(),
            )
            .expect("migrates");
        layout.finalize(NOW + 1).expect("finalized");
        let status = layout.status().expect("status").expect("laid out");
        assert_eq!(status.phase, Phase::Idle);
        assert!(status.manifest.previous.is_none());
        assert!(
            !root.join("data/notes/g1").exists(),
            "the old generation is gone"
        );
        assert!(root.join("data/notes/g2/INDEX").is_file());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn rollback_returns_to_the_old_generation_unless_the_new_one_changed() {
        let (root, volume) = laid_out("rollback");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        layout
            .migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false,
                },
                preflight(),
            )
            .expect("migrates");
        // The server wrote into the new generation: a rollback would lose it.
        let new = layout.active(&Reads::from(1, 2)).expect("new");
        write_note(
            &new.subdir("a", true).expect("a"),
            "aleph",
            b"after the migration",
        );
        let refused = layout.rollback(NOW + 1).expect_err("changed");
        assert!(refused.to_string().contains("changed since"), "{refused}");
        assert!(refused.to_string().contains("a/aleph"), "{refused}");
        assert_eq!(
            layout.status().expect("status").expect("laid out").phase,
            Phase::Committed
        );
        // Put back as the commit left it: the rollback goes through.
        new.subdir("a", false)
            .expect("a")
            .unlink("aleph")
            .expect("removed");
        layout.rollback(NOW + 2).expect("rolled back");
        let status = layout.status().expect("status").expect("laid out");
        assert_eq!(status.phase, Phase::Idle);
        assert_eq!(status.manifest.active.version, 1);
        assert_eq!(status.manifest.active.directory, "data/notes/g1");
        assert!(
            !root.join("data/notes/g2").exists(),
            "the new generation is gone"
        );
        assert_eq!(
            std::fs::read(root.join("data/notes/g1/alpha")).expect("read"),
            b"first note"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_build_that_rewrites_evidence_writes_into_the_old_generation_or_leaves_a_file_unaccounted_is_refused()
     {
        for (tamper, write_old, omit, says) in [
            (true, false, false, "rewrote the evidence"),
            (false, true, false, "wrote into the old generation"),
            (false, false, true, "says nothing of `alpha`"),
        ] {
            let (root, volume) = laid_out(&format!("refused-{tamper}-{write_old}-{omit}"));
            let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
            let refused = layout
                .migrate(
                    &NotesV2 {
                        tamper,
                        write_old,
                        omit,
                    },
                    preflight(),
                )
                .expect_err("refused");
            assert!(refused.to_string().contains(says), "{refused}");
            let status = layout.status().expect("status").expect("laid out");
            assert_eq!(status.manifest.active.version, 1, "not switched");
            assert_eq!(
                status.phase,
                Phase::Building,
                "the intent stays for recovery"
            );
            assert_eq!(layout.recover(NOW).expect("recovered"), Phase::Building);
            assert_eq!(
                layout.status().expect("status").expect("laid out").phase,
                Phase::Idle
            );
            assert!(!root.join("data/notes/g2").exists());
            let _ = std::fs::remove_dir_all(root);
        }
    }

    #[test]
    fn preflight_refuses_a_missing_required_backup_a_taken_directory_and_a_wrong_version() {
        let (root, volume) = laid_out("preflight");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        let required = Preflight::new(AssuranceProfile::Production, "data/notes/g2", None, NOW);
        let refused = layout
            .migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false,
                },
                required,
            )
            .expect_err("no backup");
        assert!(refused.to_string().contains("backup"), "{refused}");
        for taken in [
            "data/notes/g1",
            "data/notes/g1/next",
            "data/notes",
            "host/layout/x",
            "data/../x",
        ] {
            let preflight = Preflight::new(AssuranceProfile::Development, taken, None, NOW);
            assert!(
                matches!(
                    layout.migrate(
                        &NotesV2 {
                            tamper: false,
                            write_old: false,
                            omit: false
                        },
                        preflight
                    ),
                    Err(StorageError::Refused(_))
                ),
                "{taken}"
            );
        }
        // A disk a test filled: refused before the intent, so nothing is left to recover.
        let full = permguard_core::fault::inject(
            &root,
            permguard_core::fault::Fault::DiskFull { remaining_bytes: 1 },
        );
        let refused = layout
            .migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false,
                },
                preflight(),
            )
            .expect_err("no room");
        assert!(refused.to_string().contains("bytes free"), "{refused}");
        drop(full);
        assert_eq!(
            layout.status().expect("status").expect("laid out").phase,
            Phase::Idle
        );
        struct Wrong;
        impl Migration for Wrong {
            fn subsystem(&self) -> &str {
                SUBSYSTEM
            }
            fn source_version(&self) -> u16 {
                3
            }
            fn target_version(&self) -> u16 {
                4
            }
            fn build(&self, _: &Dir, _: &Dir) -> Result<Built> {
                Ok(Built::default())
            }
        }
        let refused = layout
            .migrate(&Wrong, preflight())
            .expect_err("wrong version");
        assert!(refused.to_string().contains("version"), "{refused}");
        assert_eq!(
            layout.status().expect("status").expect("laid out").phase,
            Phase::Idle
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn a_server_is_refused_a_pending_migration_an_unknown_subsystem_and_an_unread_version() {
        let (root, volume) = laid_out("servable");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        check_servable(&volume, &[(SUBSYSTEM, Reads::only(1))]).expect("idle at version 1");
        assert!(matches!(
            check_servable(&volume, &[]),
            Err(StorageError::Unsupported(_))
        ));
        layout
            .migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false,
                },
                preflight(),
            )
            .expect("migrates");
        assert!(matches!(
            check_servable(&volume, &[(SUBSYSTEM, Reads::only(1))]),
            Err(StorageError::Unsupported(_))
        ));
        check_servable(&volume, &[(SUBSYSTEM, Reads::from(1, 2))]).expect("committed serves");
        // Between two sides: the intent without its commit.
        layout
            .dir
            .unlink(COMMIT)
            .expect("a crash before the commit");
        let refused =
            check_servable(&volume, &[(SUBSYSTEM, Reads::from(1, 2))]).expect_err("pending");
        assert!(refused.to_string().contains("migrate status"), "{refused}");
        assert_eq!(layout.recover(NOW).expect("recovered"), Phase::Switched);
        check_servable(&volume, &[(SUBSYSTEM, Reads::from(1, 2))]).expect("landed forward");
        let _ = std::fs::remove_dir_all(root);
    }

    /// The tail of a finalize or a rollback, the intent gone and the commit not yet: read as what
    /// it was, by the manifest's generation, and completed on open.
    #[test]
    fn a_records_tail_reads_as_the_finalize_or_rollback_it_was_and_completes() {
        // Finalize: manifest without `previous`, intent removed, commit left.
        let (root, volume) = laid_out("tail-finalize");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        layout
            .migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false,
                },
                preflight(),
            )
            .expect("migrates");
        let manifest = layout.manifest().expect("read").expect("laid out");
        layout
            .write(
                MANIFEST,
                &LayoutManifest {
                    previous: None,
                    ..manifest
                }
                .encode()
                .expect("encodes"),
            )
            .expect("written");
        layout.dir.unlink(INTENT).expect("the intent went first");
        let manifest = layout.manifest().expect("read").expect("laid out");
        assert_eq!(layout.phase(&manifest).expect("phase"), Phase::Finalizing);
        drop(layout);
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opening completes the tail");
        assert_eq!(
            layout.status().expect("status").expect("laid out").phase,
            Phase::Idle
        );
        assert!(!root.join("data/notes/g1").exists());
        assert!(!layout.dir.exists(COMMIT).expect("looked"));
        let _ = std::fs::remove_dir_all(root);

        // Rollback: manifest back at the old generation, intent removed, commit left.
        let (root, volume) = laid_out("tail-rollback");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        layout
            .migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false,
                },
                preflight(),
            )
            .expect("migrates");
        let manifest = layout.manifest().expect("read").expect("laid out");
        layout
            .write(
                MANIFEST,
                &LayoutManifest {
                    subsystem: SUBSYSTEM.to_owned(),
                    active: manifest.previous.clone().expect("previous"),
                    previous: None,
                    switched_at: NOW,
                }
                .encode()
                .expect("encodes"),
            )
            .expect("written");
        layout.dir.unlink(INTENT).expect("the intent went first");
        let manifest = layout.manifest().expect("read").expect("laid out");
        assert_eq!(layout.phase(&manifest).expect("phase"), Phase::RollingBack);
        drop(layout);
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opening completes the tail");
        let status = layout.status().expect("status").expect("laid out");
        assert_eq!(status.phase, Phase::Idle);
        assert_eq!(status.manifest.active.version, 1);
        assert!(!root.join("data/notes/g2").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    /// The new generation is flushed by the framework before the switch: a flush that fails
    /// refuses the migration, whatever the build did.
    #[test]
    fn the_new_generation_is_flushed_before_the_switch() {
        let (root, volume) = laid_out("flush");
        let layout = Layout::open(&volume, SUBSYSTEM).expect("opens");
        // The build writes INDEX under a temporary name and renames it: only the framework's
        // flush names INDEX itself.
        let failing = permguard_core::fault::inject_exact(
            root.join("data/notes/g2/INDEX"),
            permguard_core::fault::Fault::Fsync,
        );
        let refused = layout
            .migrate(
                &NotesV2 {
                    tamper: false,
                    write_old: false,
                    omit: false,
                },
                preflight(),
            )
            .expect_err("the flush failed");
        assert!(
            matches!(refused, StorageError::Durability { .. }),
            "{refused}"
        );
        drop(failing);
        let status = layout.status().expect("status").expect("laid out");
        assert_eq!(status.manifest.active.version, 1, "not switched");
        assert_eq!(status.phase, Phase::Building);
        let _ = std::fs::remove_dir_all(root);
    }

    /// Reading the layouts of a volume that has none creates nothing on it.
    #[test]
    fn reading_the_layouts_of_a_volume_with_none_creates_nothing() {
        let root = scratch("untouched");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        assert!(status(&volume).expect("status").is_empty());
        check_servable(&volume, &[]).expect("nothing laid out serves");
        assert!(!root.join("host/layout").exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn the_records_round_trip_and_refuse_an_unknown_label() {
        let manifest = LayoutManifest {
            subsystem: "notes".to_owned(),
            active: Generation {
                version: 2,
                generation: 2,
                directory: "data/notes/g2".to_owned(),
            },
            previous: Some(Generation {
                version: 1,
                generation: 1,
                directory: "data/notes/g1".to_owned(),
            }),
            switched_at: NOW,
        };
        let bytes = manifest.encode().expect("encodes");
        assert_eq!(LayoutManifest::decode(&bytes).expect("decodes"), manifest);
        let mut pairs = match cbor::decode_canonical(&bytes).expect("cbor") {
            Value::Map(pairs) => pairs,
            _ => unreachable!(),
        };
        pairs.push((Value::Int(99), Value::Int(1)));
        let extra = cbor::encode(&Value::Map(pairs)).expect("encodes");
        assert!(LayoutManifest::decode(&extra).is_err());
        let intent = MigrationIntent {
            subsystem: "notes".to_owned(),
            from: manifest.previous.clone().expect("previous"),
            to: manifest.active.clone(),
            old_digests: BTreeMap::from([("alpha".to_owned(), Digest::compute(b"a"))]),
            backup: Some("s3://backups/notes/2026-10-07".to_owned()),
            at: NOW,
        };
        assert_eq!(
            MigrationIntent::decode(&intent.encode().expect("encodes")).expect("decodes"),
            intent
        );
        let commit = MigrationCommit {
            subsystem: "notes".to_owned(),
            from: intent.from.clone(),
            to: intent.to.clone(),
            old_digests: intent.old_digests.clone(),
            new_digests: BTreeMap::from([("a/alpha".to_owned(), Digest::compute(b"a"))]),
            backup: None,
            committed_at: NOW,
        };
        assert_eq!(
            MigrationCommit::decode(&commit.encode().expect("encodes")).expect("decodes"),
            commit
        );
    }
}
