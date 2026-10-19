// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The archive of the legacy event history (WP-6.2d, owner decisions of 2026-10-18 and
//! 2026-10-19): once the legacy journals are shipped whole and nothing they or the retired pull's
//! store hold is inside a window a loaded policy could read, the WP-1.9 framework carries
//! `events.directory` byte for byte into `data/events-legacy`.
//!
//! | Layout `events-legacy` | Where                       | What                                     |
//! | ---------------------- | --------------------------- | ---------------------------------------- |
//! | version 1              | `events.directory` as it is | a journal per `<zone>/<ledger>`, and the |
//! |                        |                             | pull's store per `pull/<zone>/<ledger>`  |
//! | version 2              | `data/events-legacy`        | the same files but `LOCK`, unchanged     |
//!
//! Drained is the eviction's own boundary: everything acknowledged, and every record, imported
//! record and unresolved gap older than `now - (retention_minimum + allowed_lateness +
//! clock_skew)`. So no decision changes when the plane stops reading it, which it does once the
//! layout is at version 2 (see [`archived`]). Beside the journal's format since the server
//! archives it at start, as the decision spool's archive sits beside the spool's. No record is converted, re-signed or imported into
//! the Host's stream. A file that is not the history's stops the migration, since `migrate
//! finalize` removes the old directory whole.

use std::path::Path;

use permguard_core::assurance::AssuranceProfile;
use permguard_host::storage::migrate::{Built, Layout, Preflight, Reads};
use permguard_host::storage::volume::Volume;
use permguard_host::storage::write::publish_immutable;
use permguard_host::storage::{Dir, Result, StorageError};
use serde_json::Value;

use crate::journal::Bounds;

/// The layout subsystem of the legacy event history.
pub const SUBSYSTEM: &str = "events-legacy";
/// The layout version of the history, as it is.
pub const SOURCE_VERSION: u16 = 1;
/// The layout version of the archive.
pub const TARGET_VERSION: u16 = 2;
/// Where the archive lives, relative to the volume root.
pub const TARGET: &str = "data/events-legacy";
/// The directory below `events.directory` the retired pull kept its store in.
pub const PULL: &str = "pull";
/// The claim a journal takes on its directory: dropped, never evidence.
const LOCK: &str = "LOCK";
/// The cursor of one subscription of the retired pull, its gaps among it: the Data Plane's
/// `temporal::imports` writes it under the journal's own name for its state.
const STORE_STATE: &str = crate::journal::STATE_FILE;
/// The records one subscription of the retired pull imported, one JSON line each,
/// `{"observe": .., "record": ..}`.
const STORE_RECORDS: &str = "imported.events";

/// Whether `name` is one of a subscription's files in the retired pull's store.
fn of_store(name: &str) -> bool {
    [STORE_STATE, STORE_RECORDS, crate::index::INDEX_FILE].contains(&name)
}

/// Whether the store of one subscription at `directory` holds nothing a loaded window could still
/// read: every imported record, observed or kept as evidence, occurred before `horizon`, in epoch
/// seconds, and every unresolved gap was noticed before it, so the occurrences it lost are older
/// still. A time that cannot be read keeps it. Read as the format the retired pull wrote, which no
/// release writes again.
fn store_drained_before(directory: &Path, horizon: i64) -> std::result::Result<bool, String> {
    let before = |instant: Option<&Value>| {
        instant
            .and_then(Value::as_str)
            .and_then(crate::index::epoch_seconds)
            .is_some_and(|at| at < horizon)
    };
    let read = |name: &str| match std::fs::read(directory.join(name)) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("reading {name}: {error}")),
    };
    if let Some(bytes) = read(STORE_STATE)? {
        let cursor: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("reading {STORE_STATE}: {error}"))?;
        let gaps = cursor
            .get("gaps")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for gap in gaps {
            let resolved = gap
                .get("resolved")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if !resolved && !before(gap.get("at")) {
                return Ok(false);
            }
        }
    }
    let Some(bytes) = read(STORE_RECORDS)? else {
        return Ok(true);
    };
    let text =
        String::from_utf8(bytes).map_err(|error| format!("reading {STORE_RECORDS}: {error}"))?;
    for (number, line) in text
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty())
    {
        let imported: Value = serde_json::from_str(line).map_err(|error| {
            format!(
                "reading the imported record at line {} of {STORE_RECORDS}: {error}",
                number + 1
            )
        })?;
        if !before(
            imported
                .get("record")
                .and_then(|record| record.get("occurred_at")),
        ) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// The layout the history is declared under, and the versions this build reads: version 1 only to
/// archive it.
pub fn layouts() -> Vec<(&'static str, Reads)> {
    vec![(SUBSYSTEM, Reads::from(SOURCE_VERSION, TARGET_VERSION))]
}

/// Whether the Data Plane reads the legacy history no longer: the layout is at version 2, as its
/// registration answers it.
pub fn archived(version: Option<u16>) -> bool {
    version == Some(TARGET_VERSION)
}

/// Where the legacy history stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// No history: nothing to archive.
    Absent,
    /// A journal holding something unshipped, or a record or gap a loaded window may still read.
    Undrained,
    /// Shipped whole and outside every window: to archive.
    Drained,
    /// Archived; a history still in place is the old generation `migrate finalize` removes.
    Archived,
    /// A history found once archived that is not the old generation kept: never archived twice.
    Orphan,
}

/// The migration of a drained history to `data/events-legacy`: every file carried byte for byte
/// but the journals' locks, anything else refused.
#[derive(Debug, Clone, Copy, Default)]
pub struct Migration;

impl permguard_host::storage::migrate::Migration for Migration {
    fn subsystem(&self) -> &str {
        SUBSYSTEM
    }

    fn source_version(&self) -> u16 {
        SOURCE_VERSION
    }

    fn target_version(&self) -> u16 {
        TARGET_VERSION
    }

    fn build(&self, old: &Dir, new: &Dir) -> Result<Built> {
        let foreign = foreign(old.path())?;
        if !foreign.is_empty() {
            return Err(beside(old.path(), &foreign));
        }
        let mut built = Built {
            carried: Vec::new(),
            dropped: Vec::new(),
            files: 0,
        };
        carry(old, new, "", &mut built)?;
        built.files = built.carried.len();
        Ok(built)
    }
}

/// Carries every file below `old` into `new` at the same path but the locks, `prefix` naming where
/// both are.
fn carry(old: &Dir, new: &Dir, prefix: &str, built: &mut Built) -> Result<()> {
    let mut names = old.names()?;
    names.sort();
    for name in names {
        let path = format!("{prefix}{name}");
        // The claim of a writer long gone, and no evidence.
        if name == LOCK {
            built.dropped.push(path);
            continue;
        }
        let bytes = old.read(&name)?.unwrap_or_default();
        let same = |held: &[u8]| held == bytes.as_slice();
        publish_immutable(new, &name, &bytes, &same, &same)?;
        built.carried.push((path.clone(), path));
    }
    let mut subdirs = old.subdirs()?;
    subdirs.sort();
    for name in subdirs {
        carry(
            &old.subdir(&name, false)?,
            &new.subdir(&name, true)?,
            &format!("{prefix}{name}/"),
            built,
        )?;
    }
    Ok(())
}

/// One entry below the history's directory: its `/`-separated path, a directory ending in `/`.
fn entries(directory: &Path) -> Result<Option<Vec<String>>> {
    fn walk(directory: &Path, prefix: &str, into: &mut Vec<String>) -> Result<()> {
        let listing = |source| StorageError::Io {
            what: format!("listing {}", directory.display()),
            source,
        };
        for entry in std::fs::read_dir(directory).map_err(listing)? {
            let entry = entry.map_err(listing)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // Not followed: a link is foreign whatever it points at.
            let kind = entry.file_type().map_err(listing)?;
            if kind.is_dir() {
                let path = format!("{prefix}{name}/");
                into.push(path.clone());
                walk(&entry.path(), &path, into)?;
            } else if kind.is_file() {
                into.push(format!("{prefix}{name}"));
            } else {
                // Named as a file that belongs to nothing, so it is refused as foreign.
                into.push(format!("{prefix}{name}\0"));
            }
        }
        Ok(())
    }
    match std::fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {
            return Err(StorageError::Refused(format!(
                "{} is not a directory",
                directory.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StorageError::Io {
                what: format!("reading {}", directory.display()),
                source,
            });
        }
    }
    let mut found = Vec::new();
    walk(directory, "", &mut found)?;
    found.sort();
    Ok(Some(found))
}

/// Whether `path`, an entry of [`entries`], belongs to the history: the zone and ledger
/// directories, a journal's own files below `<zone>/<ledger>/`, a store's below
/// `pull/<zone>/<ledger>/`.
fn of_history(path: &str) -> bool {
    let directory = path.ends_with('/');
    let parts: Vec<&str> = path.trim_end_matches('/').split('/').collect();
    match parts.as_slice() {
        [_] | [_, _] => directory,
        [first, _, _] if *first == PULL => directory,
        [first, _, _, name] if *first == PULL => !directory && of_store(name),
        [first, ..] if *first == PULL => false,
        [_, _, rest @ ..] => {
            let relative = format!("{}{}", rest.join("/"), if directory { "/" } else { "" });
            crate::journal::of_journal(&relative)
        }
        _ => false,
    }
}

/// What `directory` holds that is not the history's.
fn foreign(directory: &Path) -> Result<Vec<String>> {
    Ok(entries(directory)?
        .unwrap_or_default()
        .into_iter()
        .filter(|path| !of_history(path))
        .map(|path| path.trim_end_matches('\0').to_owned())
        .collect())
}

/// The refusal of a history holding `foreign` beside its files.
fn beside(directory: &Path, foreign: &[String]) -> StorageError {
    StorageError::Refused(format!(
        "{} holds {} beside the legacy event history; `migrate finalize` would remove them with \
         the directory: move them out of it, then archive again",
        directory.display(),
        foreign.join(", ")
    ))
}

/// Whether `directory` holds any file: a tree of empty directories holds no history.
fn holds_history(directory: &Path) -> Result<bool> {
    Ok(entries(directory)?.is_some_and(|found| found.iter().any(|path| !path.ends_with('/'))))
}

/// The journals and the stores below `directory`, as their directories.
fn streams(directory: &Path) -> Result<(Vec<std::path::PathBuf>, Vec<std::path::PathBuf>)> {
    let mut journals = Vec::new();
    let mut stores = Vec::new();
    for path in entries(directory)?.unwrap_or_default() {
        let parts: Vec<&str> = path.trim_end_matches('/').split('/').collect();
        if !path.ends_with('/') {
            continue;
        }
        match parts.as_slice() {
            [first, _, _] if *first == PULL => stores.push(directory.join(&path)),
            [first, _] if *first != PULL => journals.push(directory.join(&path)),
            _ => {}
        }
    }
    Ok((journals, stores))
}

/// Whether the history at `directory` is drained before `horizon`, in epoch seconds: every journal
/// acknowledged through its durable point with its newest record older, every store's records and
/// unresolved gaps older. A journal directory with no `STATE` holds nothing the plane reads.
fn drained(directory: &Path, bounds: Bounds, horizon: i64) -> Result<bool> {
    let unreadable = |what: &Path, error: &dyn std::fmt::Display| {
        StorageError::Refused(format!(
            "the legacy event history at {} cannot be read: {error}",
            what.display()
        ))
    };
    let (journals, stores) = streams(directory)?;
    // Each journal is opened as its shipper and the plane open it, so recovery (a torn tail cut,
    // a temporary swept, `RESERVE` filled) lands before the framework digests the old generation.
    for journal in journals {
        if !journal.join(crate::journal::STATE_FILE).is_file() {
            continue;
        }
        if !crate::journal::drained_before(&journal, bounds, horizon)
            .map_err(|error| unreadable(&journal, &error))?
        {
            return Ok(false);
        }
    }
    for store in stores {
        if !store_drained_before(&store, horizon).map_err(|error| unreadable(&store, &error))? {
            return Ok(false);
        }
    }
    Ok(true)
}

/// `directory` relative to the volume root, when it is inside the volume.
fn within(volume: &Volume, directory: &Path) -> Result<Option<String>> {
    let resolved = |path: &Path| {
        path.canonicalize().map_err(|error| {
            StorageError::Refused(format!("resolving {}: {error}", path.display()))
        })
    };
    let directory = resolved(directory)?;
    let root = resolved(volume.root())?;
    Ok(directory
        .strip_prefix(&root)
        .ok()
        .and_then(Path::to_str)
        .filter(|relative| !relative.is_empty())
        .map(|relative| relative.replace(std::path::MAIN_SEPARATOR, "/")))
}

/// Where the history at `directory` stands on `volume`, drained against `horizon`, in epoch
/// seconds. A version 1 declared by an archive that did not complete names the history it was
/// declared for.
pub fn standing(
    volume: &Volume,
    directory: &Path,
    bounds: Bounds,
    horizon: i64,
) -> Result<Standing> {
    let layout = Layout::open(volume, SUBSYSTEM)?;
    match layout.manifest()? {
        Some(manifest) if manifest.active.version == TARGET_VERSION => {
            if !holds_history(directory)? {
                return Ok(Standing::Archived);
            }
            // The old generation the commit keeps until `migrate finalize`.
            let relative = within(volume, directory)?;
            let kept = manifest
                .previous
                .as_ref()
                .is_some_and(|previous| relative.as_deref() == Some(previous.directory.as_str()));
            Ok(if kept {
                Standing::Archived
            } else {
                Standing::Orphan
            })
        }
        Some(manifest) => {
            let declared = volume.root().join(&manifest.active.directory);
            Ok(if drained(&declared, bounds, horizon)? {
                Standing::Drained
            } else {
                Standing::Undrained
            })
        }
        None if !holds_history(directory)? => Ok(Standing::Absent),
        None => Ok(if drained(directory, bounds, horizon)? {
            Standing::Drained
        } else {
            Standing::Undrained
        }),
    }
}

/// Archives the drained history at `directory` through the framework, under `profile`'s preflight
/// with `backup` declared. Anything but a drained history is refused, naming what it is; a history
/// outside the volume is refused.
pub fn archive(
    volume: &Volume,
    directory: &Path,
    bounds: Bounds,
    horizon: i64,
    profile: AssuranceProfile,
    backup: Option<String>,
    now: u64,
) -> Result<()> {
    match standing(volume, directory, bounds, horizon)? {
        Standing::Drained => {}
        Standing::Absent => {
            return Err(StorageError::Refused(format!(
                "no legacy event history is at {}: nothing to archive",
                directory.display()
            )));
        }
        Standing::Undrained => {
            return Err(StorageError::Refused(format!(
                "the legacy event history at {} holds records not yet shipped, or records or gaps \
                 a loaded window may still read: start the server with the temporal interface \
                 on, so its shipper sends them and the time passes, then archive it",
                directory.display()
            )));
        }
        Standing::Archived => {
            return Err(StorageError::Refused(format!(
                "`{SUBSYSTEM}` is archived already in {TARGET}"
            )));
        }
        Standing::Orphan => {
            return Err(StorageError::Refused(format!(
                "a legacy event history is at {}, and the volume archived `{SUBSYSTEM}` in \
                 {TARGET} already: it is not archived twice, and the plane does not read it",
                directory.display()
            )));
        }
    }
    // Refused before anything is declared or written: a refusal from inside the framework leaves
    // a migration for `migrate recover` to land.
    if let Some(obstacle) = obstacle(volume, directory)? {
        return Err(obstacle);
    }
    let layout = Layout::open(volume, SUBSYSTEM)?;
    if layout.manifest()?.is_none() {
        let relative = within(volume, directory)?.ok_or_else(|| outside(volume, directory))?;
        layout.declare(SOURCE_VERSION, &relative, now)?;
    }
    layout.migrate(&Migration, Preflight::new(profile, TARGET, backup, now))?;
    Ok(())
}

/// The directory a version 1 declared by an archive that did not complete names: where the history
/// waits, which `events.directory` may no longer name. Relative to the volume root.
pub fn waiting(volume: &Volume) -> Result<Option<String>> {
    let layout = Layout::open(volume, SUBSYSTEM)?;
    Ok(layout
        .manifest()?
        .filter(|manifest| manifest.active.version == SOURCE_VERSION)
        .map(|manifest| manifest.active.directory))
}

/// What keeps the history at `directory`, or the one a version 1 declared, from being archived as
/// it is: a place outside the volume or at or around the archive's, a declared directory gone, or
/// a file that is not the history's.
pub fn obstacle(volume: &Volume, directory: &Path) -> Result<Option<StorageError>> {
    let layout = Layout::open(volume, SUBSYSTEM)?;
    let directory = match layout.manifest()? {
        Some(manifest) => {
            let declared = volume.root().join(&manifest.active.directory);
            if !declared.is_dir() {
                return Ok(Some(StorageError::Refused(format!(
                    "the legacy event history was declared at {}, which is gone: put it back, or \
                     an empty directory there, then archive again",
                    declared.display()
                ))));
            }
            // Archiving the declared one would stop the plane reading the one it is configured
            // with, whatever that one still holds (after the review).
            let same = within(volume, &declared)?.is_some()
                && directory.canonicalize().ok() == declared.canonicalize().ok();
            if !same && holds_history(directory)? {
                return Ok(Some(StorageError::Refused(format!(
                    "the legacy event history was declared at {}, and `events.directory` names \
                     {}, which holds history too: archiving the first would stop the plane \
                     reading the second; point `events.directory` back at the declared one, or \
                     move the second's history into it",
                    declared.display(),
                    directory.display()
                ))));
            }
            declared
        }
        None => {
            let Some(relative) = within(volume, directory)? else {
                return Ok(Some(outside(volume, directory)));
            };
            // The framework would refuse it after the declaration, which nothing undoes.
            if relative == TARGET
                || relative.starts_with(&format!("{TARGET}/"))
                || TARGET.starts_with(&format!("{relative}/"))
            {
                return Ok(Some(StorageError::Refused(format!(
                    "the legacy event history at {} is at or around {TARGET}, where its archive \
                     goes: move it, then archive it",
                    directory.display()
                ))));
            }
            directory.to_path_buf()
        }
    };
    let foreign = foreign(&directory)?;
    Ok((!foreign.is_empty()).then(|| beside(&directory, &foreign)))
}

/// The refusal of a history outside the volume.
fn outside(volume: &Volume, directory: &Path) -> StorageError {
    StorageError::Refused(format!(
        "the legacy event history at {} is outside the volume {}: move it into the volume, then \
         archive it",
        directory.display(),
        volume.root().display()
    ))
}

/// The horizon below which no loaded window reads, at `now` in epoch seconds: the eviction's own,
/// `now - (retention_minimum + allowed_lateness + clock_skew)`.
pub fn horizon(bounds: Bounds, now: i64) -> i64 {
    let required = bounds.required_retention(bounds.retention_minimum);
    now.saturating_sub(i64::try_from(required.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests;
