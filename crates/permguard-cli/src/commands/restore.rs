// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard restore plan|run` (WP-7.9, `1-architecture/8-architecture-storage-operations.md`
//! restore modes, P9): a snapshot restored offline, the server stopped.
//!
//! | Step   | Does                                                                                      |
//! | ------ | ----------------------------------------------------------------------------------------- |
//! | `plan` | holds the volume, proves the fence, scans it, opens its identity and rings, signs a plan   |
//! | `run`  | checks the plan against the volume and its claim, scans again, consumes it, transitions    |
//!
//! The fence is proven before anything opens the identity, whose open records a new `BOOT`: the
//! plan binds the snapshot's boot id and the claim generation it proved, and the run requires
//! that same generation. `dr` and `forensic` record the marker only, before the plan is spent;
//! `clone` spends the plan, runs the offline emergency reset, then records the marker, through
//! the mutation transaction. A forensic volume is terminal: no later restore but a forensic one,
//! and no offline command that writes, works on it.

use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use serde::Serialize;

use permguard_core::authz::Principal;
use permguard_host::operations::journal::Initiator;
use permguard_host::operations::mutation::Mutations;
use permguard_host::restore::{self, Marker, Mode};
use permguard_host::storage::volume::Volume;

use super::host::{
    INITIATOR, ResetReport, audit_offline, custodian, emergency, hold, open_identity, open_plans,
    refusal_text, reset_report, volume_of, write_new,
};
use crate::args::{Globals, RestoreAction};
use crate::failure::{EXIT_READY, Failure};
use crate::output::Report;
use crate::session::render;
use crate::trace::Trace;

/// At most this many findings are named in a refusal; the count says the rest.
const NAMED_FINDINGS: usize = 10;

/// What a plan step answers.
#[derive(Debug, Serialize)]
struct RestorePlan {
    mode: String,
    host_id: String,
    volume_id: String,
    /// The claim generation the fence was proven under, which the run requires.
    generation: u64,
    /// The boot id of the snapshot's last start.
    previous_boot_id: String,
    files_checked: u64,
    reason: String,
    plan_id: String,
    plan_digest: String,
    /// RFC 3339.
    expires: String,
}

impl Report for RestorePlan {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Restore planned ({}, offline)", self.mode)?;
        writeln!(out, "host_id           {}", self.host_id)?;
        writeln!(out, "volume_id         {}", self.volume_id)?;
        writeln!(out, "generation        {}", self.generation)?;
        writeln!(out, "previous boot id  {}", self.previous_boot_id)?;
        writeln!(out, "files checked     {}", self.files_checked)?;
        writeln!(out, "reason            {}", self.reason)?;
        writeln!(out, "plan_id           {}", self.plan_id)?;
        writeln!(out, "digest            {}", self.plan_digest)?;
        writeln!(out, "expires           {}", self.expires)?;
        writeln!(out)?;
        writeln!(
            out,
            "Run it with `restore run --mode {} --confirm-file <file>`, the claim unchanged.",
            self.mode
        )
    }
}

/// What a run answers.
#[derive(Serialize)]
struct RestoreReport {
    mode: String,
    host_id: String,
    generation: u64,
    previous_boot_id: String,
    plan_id: String,
    /// The emergency reset a `clone` ran.
    #[serde(skip_serializing_if = "Option::is_none")]
    reset: Option<ResetReport>,
}

impl Report for RestoreReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Volume restored ({})", self.mode)?;
        writeln!(out, "host_id           {}", self.host_id)?;
        writeln!(out, "generation        {}", self.generation)?;
        writeln!(out, "previous boot id  {}", self.previous_boot_id)?;
        writeln!(out, "plan_id           {}", self.plan_id)?;
        writeln!(out)?;
        if let Some(reset) = &self.reset {
            reset.render_terminal(out)?;
            writeln!(out)?;
        }
        writeln!(
            out,
            "{}",
            match self.mode.as_str() {
                "forensic" => {
                    "The server refuses to start on this volume: read it with the offline tools."
                }
                "clone" => {
                    "This volume is a new Host: no membership, lease or producer run of the \
                     snapshot's Host starts on it."
                }
                _ => {
                    "The next start is a new incarnation of the same Host: a new boot id, and \
                     every remote task opens its session for a fresh lease."
                }
            }
        )
    }
}

/// Runs one `restore …` command.
pub fn restore_command(
    globals: &Globals,
    server_config: Option<&Path>,
    action: RestoreAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    match action {
        RestoreAction::Plan { mode, reason, out } => {
            plan(globals, server_config, mode_of(&mode)?, reason, &out, trace)?;
        }
        RestoreAction::Run { mode, confirm_file } => {
            run(
                globals,
                server_config,
                mode_of(&mode)?,
                confirm_file.as_deref(),
                trace,
            )?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

fn mode_of(text: &str) -> Result<Mode, Failure> {
    Mode::parse(text).ok_or_else(|| {
        Failure::usage(format!(
            "`{text}` is not a restore mode: dr, forensic or clone"
        ))
    })
}

pub(super) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn unhex16(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 || !text.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0_u8; 16];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(text.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(out)
}

/// What the plan stores for the run to read back: `<mode>\n<volume_id>\n<previous boot id>`.
fn stored_target(mode: Mode, volume: &Volume, previous_boot_id: &[u8; 16]) -> String {
    format!(
        "{}\n{}\n{}",
        mode.as_str(),
        volume.id_hex(),
        hex(previous_boot_id)
    )
}

/// Refuses a volume already restored under its current claim, since a restore runs once per
/// fence, and a forensic volume to any mode but `forensic`: it is never served, so never made
/// servable by a later restore.
fn not_restored(held: &Volume, mode: Mode) -> Result<(), Failure> {
    let marked = restore::marked(held)
        .map_err(|error| Failure::unavailable(format!("reading the restore marker: {error}")))?;
    match marked {
        Some(marker) if marker.mode == Mode::Forensic && mode != Mode::Forensic => {
            Err(Failure::usage(format!(
                "the volume was restored for forensics and is never served: a `{}` restore starts \
                 from the snapshot itself",
                mode.as_str()
            )))
        }
        Some(marker) if marker.generation >= held.generation() => Err(Failure::usage(format!(
            "the volume was restored ({}) under the claim generation {}: raise it with \
             `volume claim` to restore again",
            marker.mode.as_str(),
            marker.generation
        ))),
        _ => Ok(()),
    }
}

/// The full integrity scan of `held` against its claim: every journal of the storage library and
/// every object tree the server verifies. Any finding refuses the restore before it writes.
fn scan(held: &Volume, trace: &Trace) -> Result<u64, Failure> {
    use permguard_host::storage::verify::{self, Budget, Mode as ScanMode};
    // The trees the composed planes declare: the Control Plane's objects are the only ones.
    let trees = permguard_control_plane::module().verified_trees();
    let report = verify::volume(
        held.root(),
        Some(held.generation()),
        &trees,
        ScanMode::Full,
        &mut Budget::unbounded(),
    )
    .map_err(|error| Failure::unavailable(format!("scanning the volume: {error}")))?;
    if !report.findings.is_empty() {
        let named: Vec<String> = report
            .findings
            .iter()
            .take(NAMED_FINDINGS)
            .map(|finding| format!("{}: {}", finding.path.display(), finding.what))
            .collect();
        return Err(Failure::unavailable(format!(
            "the volume holds {} damaged file(s); nothing was restored or repaired:\n{}",
            report.findings.len(),
            named.join("\n")
        )));
    }
    trace.say(format!(
        "{} files and {} bytes scanned, no finding",
        report.files_checked, report.bytes_read
    ));
    Ok(report.files_checked)
}

/// The configuration a restore or a migration reads, refused when it requires dual control: an
/// offline plan then needs an approval, which an offline volume cannot collect.
pub(super) fn config_of(server_config: Option<&Path>) -> Result<permguard_core::Config, Failure> {
    let config = permguard_server::offline::config(env!("CARGO_PKG_VERSION"), server_config)
        .map_err(|error| Failure::usage(format!("--server-config: {error:#}")))?;
    if config
        .assurance()
        .requires(permguard_core::assurance::Control::OperationsDualControl)
    {
        return Err(Failure::usage(
            "the assurance profile requires dual control, under which an offline restore or \
             migration needs an approval that no offline volume can collect yet: nothing was \
             planned",
        ));
    }
    Ok(config)
}

pub(super) fn planner() -> Result<Principal, Failure> {
    Principal::new(INITIATOR).map_err(|error| Failure::internal(format!("the planner: {error}")))
}

fn plan(
    globals: &Globals,
    server_config: Option<&Path>,
    mode: Mode,
    reason: String,
    out: &Path,
    trace: &Trace,
) -> Result<(), Failure> {
    use permguard_host::api::plans::{Issue, sign_plan};
    use permguard_host::operations::mutation::{Applied, Begin, Failure as Refused};
    use permguard_host::operations::plan::{PlanSigner, RESTORE};

    if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
        return Err(Failure::usage(
            "--reason is printable text of 1 to 256 bytes",
        ));
    }
    let now = permguard_host::authz::store::now();
    let volume = volume_of(globals)?;
    let held = hold(&volume, trace)?;
    not_restored(&held, mode)?;
    // The fence first: the identity's open below records a new `BOOT`.
    let boot = restore::fence(&held).map_err(Failure::usage)?;
    let files_checked = scan(&held, trace)?;
    let config = config_of(server_config)?;

    // The keys a restore needs before any writable transition: the identity and every ring,
    // through the configured custody.
    let custodian = custodian(&held, server_config)?;
    let opened = open_identity(&held, server_config)?;
    let mutations = Mutations::open_offline_as(&held, env!("CARGO_PKG_VERSION"), Some(&opened))
        .map_err(|error| Failure::unavailable(format!("opening the mutation journal: {error}")))?;
    mutations
        .recover(&permguard_host::identity::Identities(&opened))
        .and_then(|_| mutations.recover(&restore::Restores(&held)))
        .map_err(|error| Failure::unavailable(format!("recovering: {error}")))?;
    let time = Arc::new(permguard_host::time::TimeGuard::system(
        config.time_max_clock_skew(),
    ));
    let rings =
        permguard_server::offline::rings(&config, &held, opened.host_id(), None, &custodian, time)
            .map_err(|error| Failure::unavailable(format!("the key rings: {error:#}")))?;
    let signer = rings
        .iter()
        .find(|ring| ring.id() == permguard_host::keys::ring::HOST_OPERATIONS);
    let planner = planner()?;
    let previous_boot_id = hex(&boot.boot_id);
    let issued = sign_plan(
        signer.map(|ring| ring.as_ref() as &dyn PlanSigner),
        Issue {
            kind: RESTORE,
            internal: RESTORE,
            stored_target: stored_target(mode, &held, &boot.boot_id),
            target: held.id_hex(),
            revision: held.generation(),
            parameters: &[
                ("mode", mode.as_str()),
                ("previous_boot_id", previous_boot_id.as_str()),
                ("reason", reason.as_str()),
            ],
            principal: &planner,
        },
        opened.host_id(),
        false,
        now,
    )
    .map_err(|refusal| {
        let remedy = if signer.is_some() {
            "start the server once, which activates the ring's first key and records it"
        } else {
            "configure `operations.keys` in the server's configuration, `--server-config <file>`"
        };
        Failure::unavailable(format!("{}: {remedy}", refusal_text(&refusal)))
    })?;

    // The plans store, then the receipt file, so an `--out` already there records nothing; then
    // the plan.
    let replay = open_plans(&held, &mutations, now)?;
    write_new(out, &issued.envelope)?;
    let target = Some(format!("restore-plan:{}", mode.as_str()));
    let recorded = mutations.run(
        Begin {
            domain: restore::DOMAIN,
            operation: restore::PLAN,
            action: restore::AUDIT_PLANNED,
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
        &RestorePlan {
            mode: mode.as_str().to_owned(),
            host_id: opened.host_id_text(),
            volume_id: held.id_hex(),
            generation: held.generation(),
            previous_boot_id,
            files_checked,
            reason,
            plan_id: issued.plan.plan_id.clone(),
            plan_digest: issued.plan_digest,
            expires: permguard_host::api::grants::rfc3339(issued.expires),
        },
        globals.output,
        trace,
    )?;
    // The lock lives as long as the volume; it is held until the process exits.
    std::mem::forget(held);
    Ok(())
}

fn run(
    globals: &Globals,
    server_config: Option<&Path>,
    mode: Mode,
    confirm_file: Option<&Path>,
    trace: &Trace,
) -> Result<(), Failure> {
    use permguard_host::operations::plan::RESTORE;

    let now = permguard_host::authz::store::now();
    let volume = volume_of(globals)?;
    let held = hold(&volume, trace)?;
    not_restored(&held, mode)?;
    // The scan before anything writes: opening the identity, the journal or the plans store does.
    scan(&held, trace)?;
    let receipt = crate::confirm::read_bytes(
        confirm_file,
        "restore receipt",
        permguard_host::operations::plan::MAX_ENVELOPE_BYTES,
    )?;
    let config = config_of(server_config)?;
    let custodian = custodian(&held, server_config)?;
    let time = Arc::new(permguard_host::time::TimeGuard::system(
        config.time_max_clock_skew(),
    ));
    let mut opened = open_identity(&held, server_config)?;
    if mode == Mode::Clone {
        let suite = permguard_host::identity::suite_of(&held)
            .map_err(|error| Failure::unavailable(format!("reading the identity: {error}")))?
            .unwrap_or(permguard_host::identity::Suite::Ed25519Sha256V1);
        let provisioner = permguard_server::offline::provisioner(&custodian, &held, suite)
            .map_err(|error| Failure::unavailable(format!("{error:#}")))?;
        opened = opened.with_provisioner(provisioner);
    }
    let opened = Arc::new(opened);
    // One audit engine for the mutations and the checkpoints a clone's reset seals.
    let audit = Arc::new(audit_offline(&held, &opened, Some(&time))?);
    let mutations = Mutations::open(
        &held,
        Arc::clone(&audit) as Arc<dyn permguard_host::operations::mutation::Projection>,
        Arc::clone(&time),
    )
    .map_err(|error| Failure::unavailable(format!("opening the mutation journal: {error}")))?;
    let store = permguard_host::membership::Store::open(&held)
        .map_err(|error| Failure::unavailable(format!("opening the memberships: {error}")))?;
    mutations
        .recover(&permguard_host::identity::Identities(&opened))
        .and_then(|_| mutations.recover(&permguard_host::membership::Memberships(&store)))
        .and_then(|_| mutations.recover(&restore::Restores(&held)))
        .map_err(|error| Failure::unavailable(format!("recovering: {error}")))?;

    // The receipt the plan step wrote, held in the plans store, neither run nor expired; the
    // volume and its claim as it bound them.
    let replay = open_plans(&held, &mutations, now)?;
    let planner = planner()?;
    let plan = permguard_host::api::plans::held_plan(&replay, &planner, &receipt, now).map_err(
        |refusal| {
            Failure::usage(format!(
                "--confirm-file {}: {}",
                confirm_file
                    .map(|path| path.display().to_string())
                    .unwrap_or_default(),
                refusal_text(&refusal)
            ))
        },
    )?;
    if plan.kind != RESTORE || plan.operation != RESTORE {
        return Err(Failure::usage("--confirm-file is not a restore's receipt"));
    }
    let mut bound = plan.target.split('\n');
    let (Some(planned), Some(volume_id), Some(previous), None) =
        (bound.next(), bound.next(), bound.next(), bound.next())
    else {
        return Err(Failure::usage("--confirm-file is not a restore's receipt"));
    };
    let previous_boot_id = unhex16(previous)
        .ok_or_else(|| Failure::usage("--confirm-file is not a restore's receipt"))?;
    if planned != mode.as_str() {
        return Err(Failure::usage(format!(
            "the plan restores in `{planned}` mode, not `{}`",
            mode.as_str()
        )));
    }
    if volume_id != held.id_hex() {
        return Err(Failure::usage("the plan restores another volume"));
    }
    if plan.revision != held.generation() {
        return Err(Failure::usage(format!(
            "the plan proved the fence under the claim generation {}, the volume is held under \
             {}: plan again",
            plan.revision,
            held.generation()
        )));
    }
    // Every ring the server composes, through the configured custody, before anything changes:
    // the restore verifies its keys first.
    let rings = permguard_server::offline::rings(
        &config,
        &held,
        opened.host_id(),
        Some(Arc::clone(&opened) as Arc<dyn permguard_host::keys::ring::Binder>),
        &custodian,
        time,
    )
    .map_err(|error| Failure::unavailable(format!("the key rings: {error:#}")))?;

    let plan_id =
        unhex16(&plan.plan_id).ok_or_else(|| Failure::internal("the plan's id is not 16 bytes"))?;
    let marker = Marker {
        mode,
        at: now,
        generation: held.generation(),
        previous_boot_id,
        plan_id,
    };
    // For `clone` the audit engine is the snapshot identity's: the marker's record names the Host
    // the volume was restored from.
    let record = || {
        restore::record(
            &mutations,
            &held,
            &marker,
            Initiator::System(INITIATOR.to_owned()),
        )
        .map_err(|error| Failure::unavailable(format!("recording the restore: {error}")))
    };
    let consume = || {
        permguard_host::api::plans::consume_plan(&mutations, &replay, &planner, &plan)
            .map_err(|error| Failure::unavailable(format!("consuming the plan: {error}")))
    };
    let reset = match mode {
        // The marker is the whole transition, so it comes first: a crash before the plan is spent
        // leaves the marker, which refuses a second run and, for `forensic`, every start.
        Mode::Dr | Mode::Forensic => {
            record()?;
            consume()?;
            None
        }
        // Spent before the identity changes; the marker records the reset once it is done.
        Mode::Clone => {
            consume()?;
            let done = emergency(&store, &mutations, &opened, &rings, &audit, now, trace)?;
            record()?;
            Some(done)
        }
    };
    render(
        &RestoreReport {
            mode: mode.as_str().to_owned(),
            host_id: reset.as_ref().map_or_else(
                || opened.host_id_text(),
                |done| permguard_host::identity::record::uuid_text(&done.reset.host_id),
            ),
            generation: held.generation(),
            previous_boot_id: hex(&previous_boot_id),
            plan_id: plan.plan_id.clone(),
            reset: reset.as_ref().map(reset_report),
        },
        globals.output,
        trace,
    )?;
    std::mem::forget(held);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// WP-7.9: a boot id reads back from the hex the plan stores, and nothing else does.
    #[test]
    fn a_boot_id_reads_back_from_its_hex_only() {
        let id = [0xab_u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 0xff];
        assert_eq!(unhex16(&hex(&id)), Some(id));
        assert_eq!(unhex16(&hex(&id)[..30]), None);
        assert_eq!(unhex16(&format!("{}0", hex(&id))), None);
        assert_eq!(unhex16(&"g".repeat(32)), None);
        assert_eq!(unhex16(&"+1".repeat(16)), None);
    }
}
