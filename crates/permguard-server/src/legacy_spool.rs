// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The archive of a drained version 1 decision spool (WP-6.1c, owner decisions of 2026-10-18):
//! at start below the `production` profile, offline with a backup declared from it upward.
//!
//! | Where the spool stands | At start                                                     |
//! | ---------------------- | ------------------------------------------------------------ |
//! | absent, archived       | nothing                                                      |
//! | undrained              | nothing: the Data Plane's legacy shipper sends it            |
//! | drained                | archived below `production`; a warning naming the command    |
//! |                        | from it upward, or naming what keeps it from being archived  |
//! | an orphan              | a warning: never archived twice, still shipped while it holds |
//! |                        | anything                                                     |
//!
//! No case refuses the start: nothing is lost while a spool waits for its archive.

use std::io::Write;
use std::path::Path;

use anyhow::{Context as _, Result};
use permguard_core::assurance::AssuranceProfile;
use permguard_decisions::archive::{
    SPOOL, SUBSYSTEM, Standing, TARGET, archive as carry, obstacle, standing, waiting,
};
use permguard_host::storage::volume::Volume;

const COMPONENT: &str = "host";

/// Archives the spool at `setting` below `working_dir` when it is drained and the profile is below
/// `production`; warns otherwise, as the table above says. Never fails: an archive that could not
/// be made is said, and one interrupted inside the framework is landed by `migrate recover`, which
/// the next start names (WP-1.9).
pub fn archive_at_start(
    volume: &Volume,
    working_dir: &Path,
    setting: &str,
    profile: AssuranceProfile,
    now: u64,
) {
    // Where a declared version 1 says the spool waits, which `log.spool_directory` may no longer
    // name (after the review).
    let setting = match waiting(volume) {
        Ok(Some(declared)) => declared,
        _ => setting.to_owned(),
    };
    let spool = working_dir.join(&setting);
    let unarchived = |reason: &dyn std::fmt::Display| {
        tracing::warn!(
            event.name = "decisions.legacy_unarchived",
            component = COMPONENT,
            spool = %spool.display(),
            "the legacy decision spool is drained and not archived: {reason}"
        );
    };
    let found = match standing(volume, &spool) {
        Ok(found) => found,
        Err(error) => {
            // The Data Plane refuses to start over a spool it cannot ship; nothing to add here.
            tracing::warn!(
                event.name = "decisions.legacy_unreadable",
                component = COMPONENT,
                spool = %spool.display(),
                "the legacy decision spool cannot be read, so it is not archived: {error}"
            );
            return;
        }
    };
    match found {
        Standing::Absent | Standing::Archived | Standing::Undrained => {}
        Standing::Orphan => {
            tracing::warn!(
                event.name = "decisions.legacy_orphan",
                component = COMPONENT,
                spool = %spool.display(),
                "a legacy decision spool is on the volume, which archived `{SUBSYSTEM}` in \
                 {TARGET} already: it is not archived twice; once its shipper sent it, move it \
                 out of `log.spool_directory`"
            );
        }
        Standing::Drained if profile.at_least(AssuranceProfile::Production) => {
            unarchived(&command(working_dir, &setting));
        }
        Standing::Drained => match obstacle(volume, &spool) {
            Ok(Some(reason)) => unarchived(&reason),
            Err(error) => unarchived(&error),
            Ok(None) => match carry(volume, &spool, profile, None, now) {
                Ok(()) => tracing::info!(
                    event.name = "decisions.legacy_archived",
                    component = COMPONENT,
                    spool = %spool.display(),
                    "the drained legacy decision spool was carried into {TARGET}; `migrate \
                     finalize --subsystem {SUBSYSTEM}` removes its old directory"
                ),
                Err(error) => unarchived(&error),
            },
        },
    }
}

/// What a drained spool at `setting` asks for from the production profile upward.
fn command(working_dir: &Path, setting: &str) -> String {
    format!(
        "from the production profile upward its archive declares a backup: run `permguard \
         migrate decisions --volume {} --backup <reference> --legacy {setting}` with the server \
         stopped",
        working_dir.display()
    )
}

/// `migrate decisions`: archives the drained legacy decision spool into `data/decisions/legacy`
/// byte for byte, with an external backup declared, offline, holding the volume (WP-6.1c).
pub fn migrate_decisions(
    volume_root: &Path,
    backup: &str,
    legacy: Option<&Path>,
    out: &mut dyn Write,
) -> Result<()> {
    use permguard_host::storage::volume::hold;

    if backup.trim().is_empty() {
        anyhow::bail!("`--backup` names the external backup taken before the migration");
    }
    // A relative `--legacy` names a directory of the volume, as `log.spool_directory` does.
    let spool = match legacy {
        Some(given) if given.is_relative() => volume_root.join(given),
        Some(given) => given.to_path_buf(),
        None => volume_root.join(SPOOL),
    };
    let volume = hold(volume_root)
        .with_context(|| format!("holding the volume at {}", volume_root.display()))?;
    let reading = || format!("reading the legacy decision spool at {}", spool.display());
    let said = match standing(&volume, &spool).with_context(reading)? {
        Standing::Absent => format!("{SUBSYSTEM}: nothing to archive at {}", spool.display()),
        Standing::Archived => format!("{SUBSYSTEM}: archived already in {TARGET}"),
        Standing::Undrained | Standing::Orphan | Standing::Drained => {
            carry(
                &volume,
                &spool,
                AssuranceProfile::Production,
                Some(backup.to_owned()),
                permguard_host::authz::store::now(),
            )
            .with_context(|| {
                format!("archiving the legacy decision spool at {}", spool.display())
            })?;
            format!(
                "{SUBSYSTEM}: carried from {} into {TARGET}; the old directory stays until \
                 `migrate finalize --subsystem {SUBSYSTEM}` removes it",
                spool.display()
            )
        }
    };
    writeln!(out, "{said}").context("writing the result")?;
    Ok(())
}

#[cfg(test)]
mod tests;
