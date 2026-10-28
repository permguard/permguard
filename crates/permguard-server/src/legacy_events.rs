// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The archive of the drained legacy event history (WP-6.2d, owner decisions of 2026-10-19): the
//! journals and the retired pull's store in `events.directory`, at start below the `production`
//! profile, offline with a backup declared from it upward.
//!
//! | Where the history stands | At start                                                      |
//! | ------------------------ | ------------------------------------------------------------- |
//! | absent, archived         | nothing                                                       |
//! | undrained                | nothing: the Data Plane ships and reads it, as before         |
//! | drained                  | archived below `production`; a warning naming the command     |
//! |                          | from it upward, or naming what keeps it from being archived   |
//! | an orphan                | a warning: never archived twice, and not read                 |
//!
//! No case refuses the start: nothing is lost while a history waits for its archive. Drained is
//! measured against the horizon the plane's eviction uses, from the configuration in force.

use std::io::Write;
use std::path::Path;

use anyhow::{Context as _, Result};
use permguard_core::assurance::AssuranceProfile;
use permguard_events::archive::{
    SUBSYSTEM, Standing, TARGET, archive as carry, horizon, obstacle, standing,
};
use permguard_events::journal::Bounds;
use permguard_host::storage::volume::Volume;

const COMPONENT: &str = "host";

/// The bounds the Data Plane holds its event history to, from `config`: the retention, the
/// lateness and the skew its eviction measures against.
pub fn bounds_of(config: &permguard_core::Config) -> Bounds {
    Bounds {
        max_bytes: config.events_max_bytes(),
        segment_bytes: config.events_segment_bytes(),
        max_record_bytes: config.events_max_record_bytes(),
        retention_minimum: config.events_retention_minimum(),
        allowed_lateness: config.events_allowed_lateness(),
        clock_skew: config.events_clock_skew(),
    }
}

/// Archives the history at `directory` when it is drained against `bounds` at `now` and the
/// profile is below `production`; warns otherwise, as the table above says. Never fails: an
/// archive that could not be made is said, and one interrupted inside the framework is landed by
/// `migrate recover`, which the next start names (WP-1.9). `config_file` is what the production
/// warning names.
pub fn archive_at_start(
    volume: &Volume,
    directory: &Path,
    bounds: Bounds,
    config_file: &Path,
    profile: AssuranceProfile,
    now: u64,
) {
    // A declared version 1 names where the history waits, which `events.directory` may no longer
    // name: `standing` reads that one, and `obstacle` refuses it while the configured one holds
    // history too.
    let directory = directory.to_path_buf();
    let horizon = horizon(bounds, i64::try_from(now).unwrap_or(i64::MAX));
    let unarchived = |reason: &dyn std::fmt::Display| {
        tracing::warn!(
            event.name = "events.legacy_unarchived",
            component = COMPONENT,
            directory = %directory.display(),
            "the legacy event history is drained and not archived: {reason}"
        );
    };
    let found = match standing(volume, &directory, bounds, horizon) {
        Ok(found) => found,
        Err(error) => {
            tracing::warn!(
                event.name = "events.legacy_unreadable",
                component = COMPONENT,
                directory = %directory.display(),
                "the legacy event history cannot be read, so it is not archived: {error}"
            );
            return;
        }
    };
    match found {
        Standing::Absent | Standing::Archived | Standing::Undrained => {}
        Standing::Orphan => {
            tracing::warn!(
                event.name = "events.legacy_orphan",
                component = COMPONENT,
                directory = %directory.display(),
                "a legacy event history is on the volume, which archived `{SUBSYSTEM}` in \
                 {TARGET} already: it is not archived twice, and the Data Plane does not read it"
            );
        }
        Standing::Drained if profile.at_least(AssuranceProfile::Production) => {
            unarchived(&command(volume.root(), config_file));
        }
        Standing::Drained => match obstacle(volume, &directory) {
            Ok(Some(reason)) => unarchived(&reason),
            Err(error) => unarchived(&error),
            Ok(None) => match carry(volume, &directory, bounds, horizon, profile, None, now) {
                Ok(()) => tracing::info!(
                    event.name = "events.legacy_archived",
                    component = COMPONENT,
                    directory = %directory.display(),
                    "the drained legacy event history was carried into {TARGET}; `migrate \
                     finalize --subsystem {SUBSYSTEM}` removes its old directory"
                ),
                Err(error) => unarchived(&error),
            },
        },
    }
}

/// What a drained history asks for from the production profile upward.
fn command(volume: &Path, config_file: &Path) -> String {
    format!(
        "from the production profile upward its archive declares a backup: run `permguard \
         migrate events --volume {} --backup <reference> --config {}` with the server stopped",
        volume.display(),
        config_file.display()
    )
}

/// `migrate events`: archives the drained legacy event history at `directory` into
/// `data/events-legacy` byte for byte, with an external backup declared, offline, holding the
/// volume (WP-6.2d). `working_dir` is the configuration's, which must be the volume: the
/// configuration names `events.directory` relative to it.
pub fn migrate_events(
    volume_root: &Path,
    backup: &str,
    working_dir: &Path,
    directory: &Path,
    bounds: Bounds,
    out: &mut dyn Write,
) -> Result<()> {
    use permguard_host::storage::volume::hold;

    let volume = hold(volume_root)
        .with_context(|| format!("holding the volume at {}", volume_root.display()))?;
    migrate_events_on(&volume, backup, working_dir, directory, bounds, out)
}

/// [`migrate_events`] on `volume`, held by the caller (TC-3).
pub fn migrate_events_on(
    volume: &permguard_host::storage::volume::Volume,
    backup: &str,
    working_dir: &Path,
    directory: &Path,
    bounds: Bounds,
    out: &mut dyn Write,
) -> Result<()> {
    let volume_root = volume.root();

    if backup.trim().is_empty() {
        anyhow::bail!("`--backup` names the external backup taken before the migration");
    }
    let resolved = |path: &Path| {
        path.canonicalize()
            .with_context(|| format!("resolving {}", path.display()))
    };
    if resolved(volume_root)? != resolved(working_dir)? {
        anyhow::bail!(
            "`--volume` {} is not the working directory {} the configuration names; \
             `events.directory` is read relative to it: name the same directory",
            volume_root.display(),
            working_dir.display()
        );
    }
    let now = permguard_host::authz::store::now();
    let horizon = horizon(bounds, i64::try_from(now).unwrap_or(i64::MAX));
    let reading = || {
        format!(
            "reading the legacy event history at {}",
            directory.display()
        )
    };
    let said = match standing(volume, directory, bounds, horizon).with_context(reading)? {
        Standing::Absent => format!("{SUBSYSTEM}: nothing to archive at {}", directory.display()),
        Standing::Archived => format!("{SUBSYSTEM}: archived already in {TARGET}"),
        Standing::Undrained | Standing::Orphan | Standing::Drained => {
            carry(
                volume,
                directory,
                bounds,
                horizon,
                AssuranceProfile::Production,
                Some(backup.to_owned()),
                now,
            )
            .with_context(|| {
                format!(
                    "archiving the legacy event history at {}",
                    directory.display()
                )
            })?;
            format!(
                "{SUBSYSTEM}: carried from {} into {TARGET}; the old directory stays until \
                 `migrate finalize --subsystem {SUBSYSTEM}` removes it",
                directory.display()
            )
        }
    };
    writeln!(out, "{said}").context("writing the result")?;
    Ok(())
}

#[cfg(test)]
mod tests;
