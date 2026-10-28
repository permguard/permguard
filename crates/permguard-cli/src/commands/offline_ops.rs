// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard backup verify` and `permguard migrate …` (TC-3): a snapshot checked against its
//! signed manifest, and the layout migrations of a stopped server's volume, offline.
//!
//! | Command            | Does                                                                     |
//! | ------------------ | ------------------------------------------------------------------------ |
//! | `backup verify`    | the snapshot's files against the manifest, under the exported bundle     |
//! | `migrate plan`     | holds the volume, signs a plan naming the subsystem and the backup       |
//! | `migrate run`      | checks the plan against the volume and its claim, spends it, migrates    |
//! | `migrate status`   | every subsystem laid out, its version, generation and phase              |
//! | `migrate rollback` | a committed migration back to its old generation                         |
//!
//! The migrations are the server binary's own (`permguard_server::app::migrate`,
//! `legacy_events::migrate_events`): one implementation, reached from both.

use std::path::Path;
use std::process::ExitCode;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use permguard_host::operations::backup::{self, Consistency};
use permguard_host::operations::journal::Initiator;
use permguard_host::operations::mutation::Mutations;
use permguard_server::command::MigrateCommand;

use super::host::{
    INITIATOR, Reserved, claim, custodian, hold, open_identity, open_plans, refusal_text,
    rooted_file, volume_of,
};
use super::host_ops::BundleFile;
use super::restore::{config_of, hex, planner};
use crate::args::{BackupVerifyAction, Globals, MigrateAction};
use crate::failure::Failure;
use crate::output::Report;
use crate::session::render;
use crate::trace::Trace;

/// The most bytes a manifest or a bundle file is read to.
const MAX_FILE_BYTES: usize = 64 * 1024 * 1024;

/// What `backup verify` answers of a snapshot.
#[derive(Debug, Serialize)]
struct BackupVerified {
    /// `application_consistent` or `crash_consistent`.
    consistency: String,
    operation_id: String,
    volume_id: String,
    host_id: String,
    /// When the manifest was signed, RFC 3339.
    at: String,
    /// The files that differ from the manifest; empty when it is consistent.
    differences: Vec<String>,
    /// Append-only files grown past the prepare, their bound prefix intact.
    grown: Vec<String>,
}

impl Report for BackupVerified {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Snapshot {}", self.consistency.replace('_', "-"))?;
        writeln!(out, "backup       {}", self.operation_id)?;
        writeln!(out, "volume_id    {}", self.volume_id)?;
        writeln!(out, "host_id      {}", self.host_id)?;
        writeln!(out, "prepared at  {}", self.at)?;
        for difference in &self.differences {
            writeln!(out, "differs      {difference}")?;
        }
        for grown in &self.grown {
            writeln!(out, "grown        {grown}")?;
        }
        Ok(())
    }
}

/// The manifest file: its COSE bytes, or their base64url text as the Host prints them.
fn manifest_bytes(bytes: Vec<u8>) -> Vec<u8> {
    std::str::from_utf8(&bytes)
        .ok()
        .map(str::trim)
        .and_then(|text| URL_SAFE_NO_PAD.decode(text).ok())
        .unwrap_or(bytes)
}

fn read(path: &Path, flag: &str, what: &str) -> Result<Vec<u8>, Failure> {
    crate::confirm::read_named(path, flag, what, MAX_FILE_BYTES)
}

/// Runs `permguard backup …`.
pub fn backup_command(
    globals: &Globals,
    action: BackupVerifyAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let BackupVerifyAction::Verify {
        manifest,
        bundle,
        pin,
    } = action;
    let volume = volume_of(globals)?;
    let manifest = manifest_bytes(read(
        &rooted_file(globals, &manifest),
        "--manifest",
        "snapshot manifest",
    )?);
    let held: BundleFile = serde_json::from_slice(&read(
        &rooted_file(globals, &bundle),
        "--bundle",
        "keys bundle",
    )?)
    .map_err(|error| Failure::usage(format!("--bundle: not a keys bundle file: {error}")))?;
    let decode = |value: &str| {
        URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| Failure::usage("--bundle: a member is not base64url"))
    };
    let bundle_manifest = decode(&held.manifest)?;
    let items = held
        .items
        .iter()
        .map(|item| decode(item))
        .collect::<Result<Vec<_>, _>>()?;
    let verdict =
        backup::verify(&volume, &manifest, &bundle_manifest, &items, &pin).map_err(|error| {
            Failure::not_passed(error, permguard_core::codes::client::BACKUP_UNVERIFIED)
        })?;
    let (consistency, differences) = match verdict.consistency {
        Consistency::ApplicationConsistent => ("application_consistent", Vec::new()),
        Consistency::CrashConsistent(differences) => ("crash_consistent", differences),
    };
    let report = BackupVerified {
        consistency: consistency.to_owned(),
        operation_id: hex(&verdict.manifest.operation_id),
        volume_id: hex(&verdict.manifest.volume_id),
        host_id: hex(&verdict.manifest.host_id),
        at: permguard_core::time::to_rfc3339(
            i64::try_from(verdict.manifest.at).unwrap_or(i64::MAX),
        ),
        differences,
        grown: verdict.grown,
    };
    render(&report, globals.output, trace)?;
    if report.differences.is_empty() {
        Ok(ExitCode::SUCCESS)
    } else {
        Err(Failure::not_passed(
            "the snapshot differs from its manifest: it is only crash-consistent and must pass \
             normal recovery",
            permguard_core::codes::client::BACKUP_UNVERIFIED,
        ))
    }
}

/// What a migrate command printed, line by line, as the server binary prints it.
#[derive(Debug, Serialize)]
struct Migrated {
    #[serde(skip_serializing_if = "Option::is_none")]
    subsystem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    plan_id: Option<String>,
    lines: Vec<String>,
}

impl Report for Migrated {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        for line in &self.lines {
            writeln!(out, "{line}")?;
        }
        Ok(())
    }
}

/// What `migrate plan` answers.
#[derive(Debug, Serialize)]
struct MigratePlan {
    subsystem: String,
    backup: String,
    volume_id: String,
    generation: u64,
    plan_id: String,
    plan_digest: String,
    /// RFC 3339.
    expires: String,
}

impl Report for MigratePlan {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Migration planned ({}, offline)", self.subsystem)?;
        writeln!(out, "backup      {}", self.backup)?;
        writeln!(out, "volume_id   {}", self.volume_id)?;
        writeln!(out, "generation  {}", self.generation)?;
        writeln!(out, "plan_id     {}", self.plan_id)?;
        writeln!(out, "digest      {}", self.plan_digest)?;
        writeln!(out, "expires     {}", self.expires)?;
        writeln!(out)?;
        writeln!(
            out,
            "Run it with `migrate run --confirm-file <file>`, the claim unchanged."
        )
    }
}

/// What a migration plan stores for its run: the subsystem, the volume, the backup, and the
/// legacy locations, one per line. None of them may hold a line break.
fn stored_target(subsystem: &str, volume_id: &str, backup: &str, legacy: &[String]) -> String {
    let mut lines = vec![
        subsystem.to_owned(),
        volume_id.to_owned(),
        backup.to_owned(),
    ];
    lines.extend(legacy.iter().cloned());
    lines.join("\n")
}

/// A printable value of 1 to 256 bytes, kept in a plan.
fn printable(value: &str, what: &str) -> Result<(), Failure> {
    if value.trim().is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
        return Err(Failure::usage(format!(
            "{what} is printable text of 1 to 256 bytes"
        )));
    }
    Ok(())
}

/// Runs `permguard migrate …`.
pub fn migrate_command(
    globals: &Globals,
    server_config: Option<&Path>,
    action: MigrateAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let volume = volume_of(globals)?;
    match action {
        MigrateAction::Status => {
            // A read: a forensic volume is shown too.
            let held = hold(&volume, trace)?;
            let lines = migrate_held(&held, &MigrateCommand::Status { volume })
                .map_err(Failure::unavailable)?;
            render(
                &Migrated {
                    subsystem: None,
                    plan_id: None,
                    lines,
                },
                globals.output,
                trace,
            )?;
        }
        MigrateAction::Rollback { subsystem } => {
            // A write: a volume restored for forensics is refused.
            let held = claim(&volume, trace)?;
            let lines = migrate_held(
                &held,
                &MigrateCommand::Rollback {
                    volume,
                    subsystem: subsystem.clone(),
                },
            )
            .map_err(Failure::unavailable)?;
            render(
                &Migrated {
                    subsystem: Some(subsystem),
                    plan_id: None,
                    lines,
                },
                globals.output,
                trace,
            )?;
        }
        MigrateAction::Plan {
            subsystem,
            backup,
            legacy,
            out,
        } => plan(
            globals,
            server_config,
            &volume,
            &subsystem,
            &backup,
            &legacy,
            &rooted_file(globals, &out),
            trace,
        )?,
        MigrateAction::Run { confirm_file } => {
            run(
                globals,
                server_config,
                &volume,
                confirm_file.as_deref(),
                trace,
            )?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The server binary's migration `what` on `held`, its lines kept.
fn migrate_held(
    held: &permguard_host::storage::volume::Volume,
    what: &MigrateCommand,
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    permguard_server::app::migrate_on(held, what, &mut out)
        .map_err(|error| format!("{error:#}"))?;
    Ok(lines_of(&out))
}

fn lines_of(out: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(out)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The rings whose legacy directory `--legacy <ring>=<directory>` may move.
const LEGACY_RINGS: [&str; 3] = [
    permguard_host::keys::ring::HOST_OPERATIONS,
    permguard_host::keys::ring::CONTROL_ATTEST,
    permguard_host::keys::ring::DATA_ATTEST,
];

/// Refuses `--legacy` values the subsystem's migration would refuse, before a plan is signed or
/// spent (after the TC-3 review).
fn checked_legacy(subsystem: &str, legacy: &[String]) -> Result<(), Failure> {
    for location in legacy {
        printable(location, "--legacy")?;
    }
    match subsystem {
        "keys" => {
            let mut seen = Vec::new();
            for location in legacy {
                let (ring, directory) = location.split_once('=').ok_or_else(|| {
                    Failure::usage(format!("`--legacy {location}` is not `<ring>=<directory>`"))
                })?;
                if !LEGACY_RINGS.contains(&ring) || directory.is_empty() {
                    return Err(Failure::usage(format!(
                        "`--legacy {location}`: the rings with a legacy directory are {}",
                        LEGACY_RINGS.join(", ")
                    )));
                }
                if seen.contains(&ring) {
                    return Err(Failure::usage(format!(
                        "`{ring}` is named twice by --legacy"
                    )));
                }
                seen.push(ring);
            }
            Ok(())
        }
        "audit" | "decisions" if legacy.len() > 1 => Err(Failure::usage(format!(
            "`{subsystem}` takes one --legacy directory"
        ))),
        "events" if !legacy.is_empty() => Err(Failure::usage(
            "`events` reads where the history is from --server-config, not --legacy",
        )),
        _ => Ok(()),
    }
}

/// What an `events` plan binds of the configuration: the working directory and the history's
/// directory, which its run must find unchanged.
fn events_binding(config: &permguard_core::Config) -> Vec<String> {
    vec![
        config.working_dir().display().to_string(),
        config.events_directory().display().to_string(),
    ]
}

#[allow(clippy::too_many_arguments)]
fn plan(
    globals: &Globals,
    server_config: Option<&Path>,
    volume: &Path,
    subsystem: &str,
    backup: &str,
    legacy: &[String],
    out: &Path,
    trace: &Trace,
) -> Result<(), Failure> {
    use permguard_host::api::plans::{Issue, sign_plan};
    use permguard_host::operations::mutation::{Applied, Begin, Failure as Refused};
    use permguard_host::operations::plan::{MIGRATE, PlanSigner};

    printable(backup, "--backup")?;
    checked_legacy(subsystem, legacy)?;
    let now = permguard_host::authz::store::now();
    let config = config_of(server_config)?;
    // An `events` plan binds where the history is, as the configuration names it now.
    let bound: Vec<String> = if subsystem == "events" {
        events_binding(&config)
    } else {
        legacy.to_vec()
    };
    for value in &bound {
        printable(value, "a bound location")?;
    }
    // Claimed before anything is signed: an `--out` already there plans nothing.
    let reserved = Reserved::claim(out)?;
    let held = claim(volume, trace)?;
    let custodian = custodian(&held, server_config)?;
    let opened = open_identity(&held, server_config)?;
    let mutations = Mutations::open_offline_as(&held, env!("CARGO_PKG_VERSION"), Some(&opened))
        .map_err(|error| Failure::unavailable(format!("opening the mutation journal: {error}")))?;
    mutations
        .recover(&permguard_host::identity::Identities(&opened))
        .map_err(|error| Failure::unavailable(format!("recovering: {error}")))?;
    let time = std::sync::Arc::new(permguard_host::time::TimeGuard::system(
        config.time_max_clock_skew(),
    ));
    let rings =
        permguard_server::offline::rings(&config, &held, opened.host_id(), None, &custodian, time)
            .map_err(|error| Failure::unavailable(format!("the key rings: {error:#}")))?;
    let signer = rings
        .iter()
        .find(|ring| ring.id() == permguard_host::keys::ring::HOST_OPERATIONS);
    let planner = planner()?;
    let mut parameters: Vec<(&str, &str)> = vec![("subsystem", subsystem), ("backup", backup)];
    parameters.extend(bound.iter().map(|location| ("legacy", location.as_str())));
    let issued = sign_plan(
        signer.map(|ring| ring.as_ref() as &dyn PlanSigner),
        Issue {
            kind: MIGRATE,
            internal: MIGRATE,
            stored_target: stored_target(subsystem, &held.id_hex(), backup, &bound),
            target: held.id_hex(),
            revision: held.generation(),
            parameters: &parameters,
            principal: &planner,
        },
        opened.host_id(),
        false,
        now,
    )
    .map_err(|refusal| {
        Failure::unavailable(format!(
            "{}: configure `operations.keys` in the server's configuration, `--server-config \
             <file>`, and start the server once",
            refusal_text(&refusal)
        ))
    })?;
    // The receipt's file first, then the plan: a plan held is never without its file.
    reserved.fill(&issued.envelope)?;
    let replay = open_plans(&held, &mutations, now)?;
    let target = Some(format!("migrate-plan:{subsystem}:{}", issued.plan.plan_id));
    let recorded = mutations.run(
        Begin {
            domain: permguard_host::api::replay::DOMAIN,
            operation: "migrate.plan",
            action: "host.migrate.planned",
            initiator: Initiator::System(INITIATOR.to_owned()),
            request: None,
            target: target.clone(),
        },
        |applying| {
            replay
                .plan(applying, issued.plan.clone())
                .map_err(|refusal| Refused::Refused(refusal_text(&refusal)))?;
            Ok(Applied {
                revision: held.generation(),
                target,
                value: (),
            })
        },
    );
    if let Err(error) = recorded {
        let _ = std::fs::remove_file(out);
        return Err(Failure::unavailable(format!("recording the plan: {error}")));
    }
    trace.say(format!("plan receipt written to {}", out.display()));
    render(
        &MigratePlan {
            subsystem: subsystem.to_owned(),
            backup: backup.to_owned(),
            volume_id: held.id_hex(),
            generation: held.generation(),
            plan_id: issued.plan.plan_id.clone(),
            plan_digest: issued.plan_digest,
            expires: permguard_host::api::grants::rfc3339(issued.expires),
        },
        globals.output,
        trace,
    )
}

fn run(
    globals: &Globals,
    server_config: Option<&Path>,
    volume: &Path,
    confirm_file: Option<&Path>,
    trace: &Trace,
) -> Result<(), Failure> {
    use permguard_host::operations::plan::MIGRATE;

    let not_a_receipt = || Failure::usage("--confirm-file is not a migration's receipt");
    let now = permguard_host::authz::store::now();
    let receipt = crate::confirm::read_bytes(
        confirm_file,
        "migration receipt",
        permguard_host::operations::plan::MAX_ENVELOPE_BYTES,
    )?;
    let config = config_of(server_config)?;
    // Held from the plan's check to the migration's end: no new claim slips between them.
    let held = claim(volume, trace)?;
    let (plan_id, migration) = {
        let opened = open_identity(&held, server_config)?;
        let mutations = Mutations::open_offline_as(&held, env!("CARGO_PKG_VERSION"), Some(&opened))
            .map_err(|error| {
                Failure::unavailable(format!("opening the mutation journal: {error}"))
            })?;
        mutations
            .recover(&permguard_host::identity::Identities(&opened))
            .map_err(|error| Failure::unavailable(format!("recovering: {error}")))?;
        let replay = open_plans(&held, &mutations, now)?;
        let planner = planner()?;
        let plan = permguard_host::api::plans::held_plan(&replay, &planner, &receipt, now)
            .map_err(|refusal| {
                Failure::usage(format!("--confirm-file: {}", refusal_text(&refusal)))
            })?;
        if plan.kind != MIGRATE || plan.operation != MIGRATE {
            return Err(not_a_receipt());
        }
        let mut lines = plan.target.split('\n');
        let (Some(subsystem), Some(volume_id), Some(backup)) =
            (lines.next(), lines.next(), lines.next())
        else {
            return Err(not_a_receipt());
        };
        let bound: Vec<String> = lines.map(str::to_owned).collect();
        if volume_id != held.id_hex() {
            return Err(Failure::usage("the plan migrates another volume"));
        }
        if plan.revision != held.generation() {
            return Err(Failure::usage(format!(
                "the plan was made under the claim generation {}, the volume is held under {}: \
                 plan again",
                plan.revision,
                held.generation()
            )));
        }
        let migration = migration_of(volume, subsystem, backup, &bound, &config)?;
        // Spent before the migration: whatever happens to it, the receipt runs once.
        permguard_host::api::plans::consume_plan(&mutations, &replay, &planner, &plan)
            .map_err(|error| Failure::unavailable(format!("consuming the plan: {error}")))?;
        (plan.plan_id, migration)
    };
    let migrated = match &migration {
        Migration::Server(_, what) => migrate_held(&held, what),
        Migration::Events { backup } => {
            let mut out = Vec::new();
            permguard_server::legacy_events::migrate_events_on(
                &held,
                backup,
                config.working_dir(),
                &config.events_directory(),
                permguard_server::legacy_events::bounds_of(&config),
                &mut out,
            )
            .map(|()| lines_of(&out))
            .map_err(|error| format!("{error:#}"))
        }
    };
    // After the plan is spent a failure says so: a run again is refused, the cause fixed and
    // planned again (after the TC-3 review).
    let lines = migrated.map_err(|error| {
        Failure::unavailable(format!(
            "the plan {plan_id} is spent and the migration did not complete: {error}; fix the \
             cause, then `migrate plan` again"
        ))
    })?;
    render(
        &Migrated {
            subsystem: Some(migration.subsystem().to_owned()),
            plan_id: Some(plan_id),
            lines,
        },
        globals.output,
        trace,
    )
}

/// The migration a plan names.
enum Migration {
    Server(String, MigrateCommand),
    Events { backup: String },
}

impl Migration {
    fn subsystem(&self) -> &str {
        match self {
            Self::Server(subsystem, _) => subsystem,
            Self::Events { .. } => "events",
        }
    }
}

/// The migration a plan's stored values name, refused before the plan is spent when its values
/// are not that migration's, or when an `events` plan's configuration moved.
fn migration_of(
    volume: &Path,
    subsystem: &str,
    backup: &str,
    bound: &[String],
    config: &permguard_core::Config,
) -> Result<Migration, Failure> {
    let refused =
        |error: Failure| Failure::usage(format!("the plan cannot run: {}", error.message));
    if subsystem == "events" {
        if bound != events_binding(config).as_slice() {
            return Err(Failure::usage(
                "the plan archives the event history the configuration named then, and \
                 --server-config names another now: plan again",
            ));
        }
        return Ok(Migration::Events {
            backup: backup.to_owned(),
        });
    }
    checked_legacy(subsystem, bound).map_err(refused)?;
    let volume = volume.to_path_buf();
    let backup = backup.to_owned();
    let one = || bound.first().map(std::path::PathBuf::from);
    let what = match subsystem {
        "keys" => MigrateCommand::Keys {
            volume,
            backup,
            legacy: bound.to_vec(),
        },
        "audit" => MigrateCommand::Audit {
            volume,
            backup,
            legacy: one(),
        },
        "decisions" => MigrateCommand::Decisions {
            volume,
            backup,
            legacy: one(),
        },
        other => {
            return Err(Failure::usage(format!(
                "the plan names `{other}`, which is not a migration"
            )));
        }
    };
    Ok(Migration::Server(subsystem.to_owned(), what))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TC-3: a manifest file reads as the COSE bytes or as their base64url text.
    #[test]
    fn a_manifest_reads_raw_or_as_text() {
        let raw = vec![0x84_u8, 0x40, 0xa0, 0x41, 0x00];
        assert_eq!(manifest_bytes(raw.clone()), raw);
        let text = format!("{}\n", URL_SAFE_NO_PAD.encode(&raw)).into_bytes();
        assert_eq!(manifest_bytes(text), raw);
    }

    /// TC-3, after the review: an `events` plan runs only under the configuration it bound, and a
    /// plan's legacy values are checked again before it is spent.
    #[test]
    fn a_plan_runs_only_what_it_bound() {
        let file = std::env::temp_dir().join(format!(
            "permguard-cli-bound-{}-{:?}.yml",
            std::process::id(),
            std::thread::current().id()
        ));
        if std::fs::write(&file, "public:\n  http: 0.0.0.0:5556\n").is_err() {
            panic!("a configuration file");
        }
        let config = permguard_server::offline::config(env!("CARGO_PKG_VERSION"), Some(&file))
            .unwrap_or_else(|error| panic!("a configuration: {error:#}"));
        let _ = std::fs::remove_file(&file);
        let volume = Path::new("/volume");
        let bound = events_binding(&config);
        assert!(matches!(
            migration_of(volume, "events", "snap", &bound, &config),
            Ok(Migration::Events { .. })
        ));
        let moved = vec![bound[0].clone(), "elsewhere".to_owned()];
        assert!(migration_of(volume, "events", "snap", &moved, &config).is_err());
        assert!(migration_of(volume, "keys", "snap", &["nothing=/d".to_owned()], &config).is_err());
        assert!(
            migration_of(volume, "audit", "snap", &[], &config).is_ok_and(|migration| matches!(
                migration,
                Migration::Server(_, MigrateCommand::Audit { .. })
            ))
        );
        assert!(
            migration_of(volume, "decisions", "snap", &[], &config).is_ok_and(
                |migration| matches!(
                    migration,
                    Migration::Server(_, MigrateCommand::Decisions { .. })
                )
            )
        );
        assert!(migration_of(volume, "other", "snap", &[], &config).is_err());
    }

    /// TC-3: a plan keeps the subsystem, the volume, the backup and the legacy locations, and
    /// refuses a value that would break its lines.
    #[test]
    fn a_plan_binds_its_values_one_per_line() {
        assert_eq!(
            stored_target("keys", "ab", "snap-1", &["control=dir".to_owned()]),
            "keys\nab\nsnap-1\ncontrol=dir"
        );
        assert!(printable("snap\n2", "--backup").is_err());
        assert!(printable("", "--backup").is_err());
        assert!(printable("snap-2026-10-25", "--backup").is_ok());
    }
}
