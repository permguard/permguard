// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The migrations of a volume's subsystem layouts, run offline under the volume's lock: the same
//! code the server binary's `migrate` command and the command line's run.

use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Subcommand;

/// What can be asked of the subsystem layouts from the command line (WP-1.9). Every command runs
/// offline: it takes the volume's lock, so it fails while a server holds the volume, and the
/// server refuses to start while a migration is between two sides.
#[derive(Subcommand, Debug, Clone, PartialEq, Eq)]
pub enum MigrateCommand {
    /// List every subsystem laid out on the volume: its version, generation and where its
    /// migration stands.
    Status {
        /// The volume's root, the server's working directory.
        #[arg(long, value_name = "DIRECTORY")]
        volume: PathBuf,
    },
    /// Land a migration a crash interrupted: before the switch the new generation is abandoned,
    /// after it the commit is written, a finalize or a rollback in progress is completed.
    Recover {
        /// The volume's root, the server's working directory.
        #[arg(long, value_name = "DIRECTORY")]
        volume: PathBuf,

        /// The subsystem.
        #[arg(long, value_name = "NAME")]
        subsystem: String,
    },
    /// Return a committed migration to its old generation, when the new one is as the commit
    /// left it; a generation the server has since written into is never discarded.
    Rollback {
        /// The volume's root, the server's working directory.
        #[arg(long, value_name = "DIRECTORY")]
        volume: PathBuf,

        /// The subsystem.
        #[arg(long, value_name = "NAME")]
        subsystem: String,
    },
    /// Remove the old generation of a committed migration: the rollback horizon ends here, and
    /// only here.
    Finalize {
        /// The volume's root, the server's working directory.
        #[arg(long, value_name = "DIRECTORY")]
        volume: PathBuf,

        /// The subsystem.
        #[arg(long, value_name = "NAME")]
        subsystem: String,
    },
    /// Migrate the legacy `ring.json` key rings into `host/keys/<ring>` with an external backup
    /// declared (WP-3.1): what a server under the production profile asks for before it starts.
    /// A ring whose legacy directory holds no `ring.json` is left for the server to lay out.
    Keys {
        /// The volume's root, the server's working directory.
        #[arg(long, value_name = "DIRECTORY")]
        volume: PathBuf,

        /// The external backup taken before the migration, as the operator names it.
        #[arg(long, value_name = "REFERENCE")]
        backup: String,

        /// A ring kept outside its default legacy directory, as `<ring>=<directory>`;
        /// `operations/keys/{operations,control,data}` below the volume otherwise.
        #[arg(long = "legacy", value_name = "RING=DIRECTORY")]
        legacy: Vec<String>,
    },
    /// Carry the legacy JSON-lines audit chain into `host/audit/legacy`, byte for byte, with an
    /// external backup declared (WP-3.8): what a server under the production profile asks for
    /// before it starts.
    Audit {
        /// The volume's root, the server's working directory.
        #[arg(long, value_name = "DIRECTORY")]
        volume: PathBuf,

        /// The external backup taken before the migration, as the operator names it.
        #[arg(long, value_name = "REFERENCE")]
        backup: String,

        /// The directory the chain is in, when `audit.directory` moved it; `operations/audit`
        /// below the volume otherwise.
        #[arg(long, value_name = "DIRECTORY")]
        legacy: Option<PathBuf>,
    },
    /// Archive the drained legacy decision spool into `data/decisions/legacy`, byte for byte,
    /// with an external backup declared (WP-6.1c): what a server under the production profile
    /// names once the spool's shipper sent it. A spool holding anything unshipped is refused.
    Decisions {
        /// The volume's root, the server's working directory.
        #[arg(long, value_name = "DIRECTORY")]
        volume: PathBuf,

        /// The external backup taken before the migration, as the operator names it.
        #[arg(long, value_name = "REFERENCE")]
        backup: String,

        /// The spool's directory, when `log.spool_directory` moved it; `data/decisions/spool`
        /// below the volume otherwise.
        #[arg(long, value_name = "DIRECTORY")]
        legacy: Option<PathBuf>,
    },
    /// Archive the drained legacy event history, the journals and the retired pull's store in
    /// `events.directory`, into `data/events-legacy`, byte for byte, with an external backup
    /// declared (WP-6.2d): what a server under the production profile names once it is shipped
    /// and older than every window a loaded policy reads. Anything else is refused.
    Events {
        /// The volume's root, the server's working directory.
        #[arg(long, value_name = "DIRECTORY")]
        volume: PathBuf,

        /// The external backup taken before the migration, as the operator names it.
        #[arg(long, value_name = "REFERENCE")]
        backup: String,

        /// The server's configuration file, read as `permguard <config file>` reads it: where
        /// the history is, and the retention, lateness and skew it is measured against.
        #[arg(long, value_name = "CONFIG_FILE")]
        config: PathBuf,
    },
}

/// `migrate keys` (WP-3.1): every legacy ring with a `ring.json` migrated into `host/keys/<ring>`
/// with the backup declared, offline, on `volume`, held by the caller.
pub fn migrate_keys_on(
    volume: &permguard_host::storage::volume::Volume,
    backup: &str,
    overrides: &[String],
    out: &mut dyn Write,
) -> Result<()> {
    use permguard_host::keys::migration::{lay_out, needs_migration};
    use permguard_host::keys::ring::{CONTROL_ATTEST, DATA_ATTEST, HOST_OPERATIONS};

    let volume_root = volume.root();
    if backup.trim().is_empty() {
        anyhow::bail!("`--backup` names the external backup taken before the migration");
    }
    let mut directories = vec![
        (
            HOST_OPERATIONS,
            volume_root.join("operations/keys/operations"),
        ),
        (CONTROL_ATTEST, volume_root.join("operations/keys/control")),
        (DATA_ATTEST, volume_root.join("operations/keys/data")),
    ];
    for given in overrides {
        let (ring, directory) = given
            .split_once('=')
            .with_context(|| format!("`--legacy {given}` is not `<ring>=<directory>`"))?;
        let held = directories
            .iter_mut()
            .find(|(name, _)| *name == ring)
            .with_context(|| format!("`{ring}` is not a ring with a legacy directory"))?;
        held.1 = std::path::PathBuf::from(directory);
    }
    let now = permguard_core::time::unix_now();
    for (ring, directory) in directories {
        if !needs_migration(volume, ring, Some(&directory))
            .with_context(|| format!("reading the layout of {ring}"))?
        {
            writeln!(out, "{ring}: nothing to migrate at {}", directory.display())
                .context("writing the result")?;
            continue;
        }
        lay_out(
            volume,
            ring,
            Some(&directory),
            permguard_core::assurance::AssuranceProfile::Production,
            Some(backup.to_owned()),
            now,
        )
        .with_context(|| format!("migrating the legacy ring of {ring}"))?;
        writeln!(
            out,
            "{ring}: migrated from {} into host/keys/{ring}; the private halves of its retired \
             keys stay in the old directory until `migrate finalize --subsystem {}` removes it",
            directory.display(),
            permguard_host::keys::migration::subsystem(ring)
        )
        .context("writing the result")?;
    }
    Ok(())
}

/// `migrate audit`: carries the legacy JSON-lines audit chain into `host/audit/legacy` byte for
/// byte, with an external backup declared (WP-3.8), on `volume`, held by the caller. A volume
/// without one is declared at once.
pub fn migrate_audit_on(
    volume: &permguard_host::storage::volume::Volume,
    backup: &str,
    legacy: Option<&std::path::Path>,
    out: &mut dyn Write,
) -> Result<()> {
    use permguard_host::audit::jsonl::{Laid, lay_out, needs_migration};

    let volume_root = volume.root();
    if backup.trim().is_empty() {
        anyhow::bail!("`--backup` names the external backup taken before the migration");
    }
    // A relative `--legacy` names a directory of the volume, as `audit.directory` does.
    let directory = match legacy {
        Some(given) if given.is_relative() => volume_root.join(given),
        Some(given) => given.to_path_buf(),
        None => volume_root.join("operations/audit"),
    };
    if !needs_migration(volume, Some(&directory))
        .with_context(|| format!("reading the legacy audit chain in {}", directory.display()))?
    {
        writeln!(
            out,
            "audit-legacy: nothing to migrate at {}",
            directory.display()
        )
        .context("writing the result")?;
        return Ok(());
    }
    let laid = lay_out(
        volume,
        Some(&directory),
        permguard_core::assurance::AssuranceProfile::Production,
        Some(backup.to_owned()),
        permguard_core::time::unix_now(),
    )
    .with_context(|| {
        format!(
            "migrating the legacy audit chain in {}",
            directory.display()
        )
    })?;
    let said = match laid {
        Laid::Migrated => format!(
            "audit-legacy: carried from {} into host/audit/legacy; the old directory stays until \
             `migrate finalize --subsystem audit-legacy` removes it",
            directory.display()
        ),
        Laid::Fresh | Laid::Current => "audit-legacy: laid out already".to_owned(),
    };
    writeln!(out, "{said}").context("writing the result")?;
    Ok(())
}

/// Runs one offline `migrate` command but `events`, which reads the server's configuration
/// (`legacy_events::migrate_events`), holding the volume it names (WP-1.9).
pub fn migrate(what: &MigrateCommand, out: &mut dyn Write) -> Result<()> {
    use permguard_host::storage::volume::hold;

    let volume_root = match what {
        MigrateCommand::Status { volume }
        | MigrateCommand::Recover { volume, .. }
        | MigrateCommand::Rollback { volume, .. }
        | MigrateCommand::Finalize { volume, .. }
        | MigrateCommand::Keys { volume, .. }
        | MigrateCommand::Audit { volume, .. }
        | MigrateCommand::Decisions { volume, .. } => volume,
        // Dispatched with its configuration before this is reached.
        MigrateCommand::Events { .. } => {
            anyhow::bail!("`migrate events` reads the server's configuration it names")
        }
    };
    let volume = hold(volume_root)
        .with_context(|| format!("holding the volume at {}", volume_root.display()))?;
    migrate_on(&volume, what, out)
}

/// [`migrate`] on `volume`, held by the caller: the command line runs the migration a plan names
/// under the lock it verified and spent the plan under, so no new claim slips between the two
/// (TC-3). The volume a command names is the one held.
pub fn migrate_on(
    volume: &permguard_host::storage::volume::Volume,
    what: &MigrateCommand,
    out: &mut dyn Write,
) -> Result<()> {
    use permguard_host::storage::migrate::{self, Layout};

    let now = permguard_core::time::unix_now();
    let volume_root = volume.root();
    let subsystem = match what {
        MigrateCommand::Status { .. } => None,
        MigrateCommand::Recover { subsystem, .. }
        | MigrateCommand::Rollback { subsystem, .. }
        | MigrateCommand::Finalize { subsystem, .. } => Some(subsystem.as_str()),
        MigrateCommand::Keys { backup, legacy, .. } => {
            return migrate_keys_on(volume, backup, legacy, out);
        }
        MigrateCommand::Audit { backup, legacy, .. } => {
            return migrate_audit_on(volume, backup, legacy.as_deref(), out);
        }
        MigrateCommand::Decisions { backup, legacy, .. } => {
            return crate::legacy_spool::migrate_decisions_on(
                volume,
                backup,
                legacy.as_deref(),
                out,
            );
        }
        MigrateCommand::Events { .. } => {
            anyhow::bail!("`migrate events` reads the server's configuration it names")
        }
    };
    match (what, subsystem) {
        (MigrateCommand::Status { .. }, _) => {
            let all = migrate::status(volume).context("reading the layouts")?;
            if all.is_empty() {
                writeln!(out, "no subsystem is laid out on {}", volume_root.display())
                    .context("writing the result")?;
            }
            for status in all {
                let previous = status
                    .manifest
                    .previous
                    .as_ref()
                    .map(|p| format!(", previous version {} in {}", p.version, p.directory))
                    .unwrap_or_default();
                let kept = status
                    .commit
                    .as_ref()
                    .map(|commit| {
                        format!(
                            ", old generation kept for {}s",
                            now.saturating_sub(commit.committed_at)
                        )
                    })
                    .unwrap_or_default();
                writeln!(
                    out,
                    "{}: version {} generation {} in {} ({}{previous}{kept})",
                    status.manifest.subsystem,
                    status.manifest.active.version,
                    status.manifest.active.generation,
                    status.manifest.active.directory,
                    status.phase.as_str()
                )
                .context("writing the result")?;
            }
        }
        (MigrateCommand::Recover { .. }, Some(subsystem)) => {
            let layout = Layout::open(volume, subsystem)
                .with_context(|| format!("opening the layout of {subsystem}"))?;
            let found = layout
                .recover(now)
                .with_context(|| format!("recovering the migration of {subsystem}"))?;
            writeln!(
                out,
                "{subsystem}: found {}, now {}",
                found.as_str(),
                layout
                    .status()?
                    .map_or("not laid out", |status| status.phase.as_str())
            )
            .context("writing the result")?;
        }
        (MigrateCommand::Rollback { .. }, Some(subsystem)) => {
            Layout::open(volume, subsystem)
                .with_context(|| format!("opening the layout of {subsystem}"))?
                .rollback(now)
                .with_context(|| format!("rolling back the migration of {subsystem}"))?;
            writeln!(out, "{subsystem}: rolled back to the previous generation")
                .context("writing the result")?;
        }
        (MigrateCommand::Finalize { .. }, Some(subsystem)) => {
            Layout::open(volume, subsystem)
                .with_context(|| format!("opening the layout of {subsystem}"))?
                .finalize(now)
                .with_context(|| format!("finalizing the migration of {subsystem}"))?;
            writeln!(out, "{subsystem}: finalized; the old generation is removed")
                .context("writing the result")?;
        }
        _ => unreachable!("every command names its subsystem or needs none"),
    }
    Ok(())
}
