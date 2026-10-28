// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The archive of a drained version 1 spool (WP-6.1c, owner decisions of 2026-10-16 and
//! 2026-10-18): once the legacy shipper has sent everything an upgraded Data Plane's spool held,
//! the WP-1.9 framework carries the spool byte for byte into `data/decisions/legacy`.
//!
//! | Layout `decisions-legacy` | Where                                             | What                                 |
//! | ------------------------- | ------------------------------------------------- | ------------------------------------ |
//! | version 1                 | the spool as it is (`log.spool_directory`)        | segments, `STATE`, `RESERVE`,        |
//! |                           |                                                   | `signers.json`, `ZONE_KEYS`, `LOCK`  |
//! | version 2                 | `data/decisions/legacy`                           | the same files but `LOCK`, unchanged |
//!
//! No record is converted or re-signed, and nothing is imported into the Host's stream: the
//! spool's positions are another identity's. A spool holding anything unshipped is never archived;
//! its shipper sends it first. A file that is not the spool's stops the migration, since
//! `migrate finalize` removes the old directory whole.

use std::path::Path;

use permguard_core::assurance::AssuranceProfile;
use permguard_host::storage::migrate::{Built, Layout, Preflight, Reads};
use permguard_host::storage::volume::Volume;
use permguard_host::storage::write::publish_immutable;
use permguard_host::storage::{Dir, Result, StorageError};

use crate::spool::{Bounds, LOCK_FILE, RESERVE_FILE, STATE_FILE, Spool, segment_seq};

/// The layout subsystem of the legacy spool.
pub const SUBSYSTEM: &str = "decisions-legacy";
/// The layout version of the spool, as it is.
pub const SOURCE_VERSION: u16 = 1;
/// The layout version of the archive.
pub const TARGET_VERSION: u16 = 2;
/// Where the spool is, relative to the volume root, unless `log.spool_directory` moved it.
pub const SPOOL: &str = "data/decisions/spool";
/// Where the archive lives, relative to the volume root.
pub const TARGET: &str = "data/decisions/legacy";
/// The file naming every zone key version a plane tagged under, with its witness (WP-3.3): kept
/// in the spool by the releases before this one, beside it since.
pub const ZONE_KEYS: &str = "ZONE_KEYS";

/// The files of a spool beside its segments, carried into the archive.
const CARRIED: [&str; 4] = [
    STATE_FILE,
    RESERVE_FILE,
    permguard_stream::SIGNERS_FILE,
    ZONE_KEYS,
];

/// The layout the spool is declared under, and the versions this build reads: version 1 only to
/// archive it.
pub fn layouts() -> Vec<(&'static str, Reads)> {
    vec![(SUBSYSTEM, Reads::from(SOURCE_VERSION, TARGET_VERSION))]
}

/// Where a legacy spool stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standing {
    /// No spool: nothing to archive.
    Absent,
    /// A spool holding something unshipped: its shipper sends it first.
    Undrained,
    /// A spool its shipper sent whole: to archive.
    Drained,
    /// Archived; a spool still in place is the old generation `migrate finalize` removes.
    Archived,
    /// A spool found once archived that is not the old generation kept: never archived twice.
    Orphan,
}

/// The migration of a drained spool to `data/decisions/legacy`: every file of the spool carried
/// byte for byte but its lock, anything else refused.
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
        let names = old.names()?;
        let mut carried = Vec::new();
        let mut dropped = Vec::new();
        for name in names {
            // The claim of a writer long gone, and no evidence.
            if name == LOCK_FILE {
                dropped.push(name);
                continue;
            }
            let bytes = old.read(&name)?.unwrap_or_default();
            let same = |held: &[u8]| held == bytes.as_slice();
            publish_immutable(new, &name, &bytes, &same, &same)?;
            carried.push((name.clone(), name));
        }
        Ok(Built {
            files: carried.len(),
            carried,
            dropped,
        })
    }
}

/// Whether `name` is one of a spool's files.
fn of_spool(name: &str) -> bool {
    name == LOCK_FILE || CARRIED.contains(&name) || segment_seq(name).is_some()
}

/// What `directory` holds that is not a spool's file: a file of another name, a directory, a
/// link, anything else; a directory ends in `/`.
fn foreign(directory: &Path) -> Result<Vec<String>> {
    let listing = |source| StorageError::Io {
        what: format!("listing {}", directory.display()),
        source,
    };
    let mut found = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(listing)? {
        let entry = entry.map_err(listing)?;
        let name = entry.file_name().to_string_lossy().into_owned();
        // Not followed: a link is foreign whatever it points at.
        let kind = entry.file_type().map_err(listing)?;
        if kind.is_dir() {
            found.push(format!("{name}/"));
        } else if !kind.is_file() || !of_spool(&name) {
            found.push(name);
        }
    }
    found.sort();
    Ok(found)
}

/// The refusal of a spool holding `foreign` beside its files.
fn beside(directory: &Path, foreign: &[String]) -> StorageError {
    StorageError::Refused(format!(
        "{} holds {} beside the decision spool; `migrate finalize` would remove them with the \
         directory: move them out of it, then archive again",
        directory.display(),
        foreign.join(", ")
    ))
}

/// The names in `directory`, or `None` when it does not exist.
fn listed(directory: &Path) -> Result<Option<Vec<String>>> {
    let entries = match std::fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(source) => {
            return Err(StorageError::Io {
                what: format!("listing {}", directory.display()),
                source,
            });
        }
    };
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|source| StorageError::Io {
            what: format!("listing {}", directory.display()),
            source,
        })?;
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    Ok(Some(names))
}

/// Whether `directory` holds a spool: its state or a segment. A directory holding only the zone key
/// witness, which the releases before this one created beside no spool, is none: the Data Plane
/// seeds its witness from it and no layout is declared for it (after the review).
fn holds_spool(directory: &Path) -> Result<bool> {
    Ok(listed(directory)?.is_some_and(|names| {
        names
            .iter()
            .any(|name| name == STATE_FILE || segment_seq(name).is_some())
    }))
}

/// Whether the spool at `directory` holds nothing its shipper has still to send: no terminal
/// record waiting and nothing above what was acknowledged, as the shipper reads it. Opened as the
/// shipper opens it, so a torn tail is cut, a temporary swept, `LOCK` taken and a short `RESERVE`
/// filled, all before the migration digests the old generation; a directory with no segment and
/// no state holds no record and is not opened.
fn drained(directory: &Path) -> Result<bool> {
    let names = listed(directory)?.unwrap_or_default();
    if !names
        .iter()
        .any(|name| name == STATE_FILE || segment_seq(name).is_some())
    {
        return Ok(true);
    }
    let unreadable = |error: crate::spool::SpoolError| {
        StorageError::Refused(format!(
            "the legacy decision spool at {} cannot be read: {error}",
            directory.display()
        ))
    };
    let spool = Spool::open(directory, Bounds::default()).map_err(unreadable)?;
    Ok(spool.terminal().map_err(unreadable)?.is_none()
        && spool
            .read_from(spool.acked(), 1)
            .map_err(unreadable)?
            .is_empty())
}

/// `spool` relative to the volume root, when it is inside the volume.
fn within(volume: &Volume, spool: &Path) -> Result<Option<String>> {
    let resolved = |path: &Path| {
        path.canonicalize().map_err(|error| {
            StorageError::Refused(format!("resolving {}: {error}", path.display()))
        })
    };
    let directory = resolved(spool)?;
    let root = resolved(volume.root())?;
    Ok(directory
        .strip_prefix(&root)
        .ok()
        .and_then(Path::to_str)
        .filter(|relative| !relative.is_empty())
        .map(|relative| relative.replace(std::path::MAIN_SEPARATOR, "/")))
}

/// Where the spool at `spool` stands on `volume`. A version 1 declared by an archive that did not
/// complete names the spool it was declared for.
pub fn standing(volume: &Volume, spool: &Path) -> Result<Standing> {
    let layout = Layout::open(volume, SUBSYSTEM)?;
    match layout.manifest()? {
        Some(manifest) if manifest.active.version == TARGET_VERSION => {
            if !holds_spool(spool)? {
                return Ok(Standing::Archived);
            }
            let relative = within(volume, spool)?;
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
            Ok(if drained(&declared)? {
                Standing::Drained
            } else {
                Standing::Undrained
            })
        }
        None if !holds_spool(spool)? => Ok(Standing::Absent),
        None => Ok(if drained(spool)? {
            Standing::Drained
        } else {
            Standing::Undrained
        }),
    }
}

/// Archives the drained spool at `spool` through the framework, under `profile`'s preflight with
/// `backup` declared. Anything but a drained spool is refused, naming what it is; a spool outside
/// the volume is refused.
pub fn archive(
    volume: &Volume,
    spool: &Path,
    profile: AssuranceProfile,
    backup: Option<String>,
    now: u64,
) -> Result<()> {
    match standing(volume, spool)? {
        Standing::Drained => {}
        Standing::Absent => {
            return Err(StorageError::Refused(format!(
                "no legacy decision spool is at {}: nothing to archive",
                spool.display()
            )));
        }
        Standing::Undrained => {
            return Err(StorageError::Refused(format!(
                "the legacy decision spool at {} holds records not yet shipped: start the server \
                 with the decision log on, so its shipper sends them, then archive it",
                spool.display()
            )));
        }
        Standing::Archived => {
            return Err(StorageError::Refused(format!(
                "`{SUBSYSTEM}` is archived already in {TARGET}"
            )));
        }
        Standing::Orphan => {
            return Err(StorageError::Refused(format!(
                "a legacy decision spool is at {}, and the volume archived `{SUBSYSTEM}` in \
                 {TARGET} already: it is not archived twice; once its shipper sent it, move it \
                 out of `log.spool_directory`",
                spool.display()
            )));
        }
    }
    // Refused before anything is declared or written: a refusal from inside the framework leaves
    // a migration for `migrate recover` to land.
    if let Some(obstacle) = obstacle(volume, spool)? {
        return Err(obstacle);
    }
    let layout = Layout::open(volume, SUBSYSTEM)?;
    if layout.manifest()?.is_none() {
        let relative = within(volume, spool)?.ok_or_else(|| outside(volume, spool))?;
        layout.declare(SOURCE_VERSION, &relative, now)?;
    }
    layout.migrate(&Migration, Preflight::new(profile, TARGET, backup, now))?;
    Ok(())
}

/// The directory a version 1 declared by an archive that did not complete names: where the spool
/// waits, which `log.spool_directory` may no longer name.
/// Relative to the volume root.
pub fn waiting(volume: &Volume) -> Result<Option<String>> {
    let layout = Layout::open(volume, SUBSYSTEM)?;
    Ok(layout
        .manifest()?
        .filter(|manifest| manifest.active.version == SOURCE_VERSION)
        .map(|manifest| manifest.active.directory))
}

/// What keeps the spool at `spool`, or the one a version 1 declared, from being archived as it is:
/// a place outside the volume or at the archive's, a declared directory gone, or a file that is
/// not the spool's.
pub fn obstacle(volume: &Volume, spool: &Path) -> Result<Option<StorageError>> {
    let layout = Layout::open(volume, SUBSYSTEM)?;
    let directory = match layout.manifest()? {
        Some(manifest) => {
            let declared = volume.root().join(&manifest.active.directory);
            if !declared.is_dir() {
                return Ok(Some(StorageError::Refused(format!(
                    "the legacy decision spool was declared at {}, which is gone: put it back, or \
                     an empty directory there, then archive again",
                    declared.display()
                ))));
            }
            declared
        }
        None => {
            let Some(relative) = within(volume, spool)? else {
                return Ok(Some(outside(volume, spool)));
            };
            // The framework would refuse it after the declaration, which nothing undoes.
            if relative == TARGET
                || relative.starts_with(&format!("{TARGET}/"))
                || TARGET.starts_with(&format!("{relative}/"))
            {
                return Ok(Some(StorageError::Refused(format!(
                    "the legacy decision spool at {} is at or around {TARGET}, where its archive \
                     goes: move it, then archive it",
                    spool.display()
                ))));
            }
            spool.to_path_buf()
        }
    };
    let foreign = foreign(&directory)?;
    Ok((!foreign.is_empty()).then(|| beside(&directory, &foreign)))
}

/// The refusal of a spool outside the volume.
fn outside(volume: &Volume, spool: &Path) -> StorageError {
    StorageError::Refused(format!(
        "the legacy decision spool at {} is outside the volume {}: move it into the volume, then \
         archive it",
        spool.display(),
        volume.root().display()
    ))
}

#[cfg(test)]
mod tests;
