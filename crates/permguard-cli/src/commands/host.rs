// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard host grants`: the grant store of a volume, offline (WP-2.4, owner decision of
//! 2026-10-06).
//!
//! The Host API that lists, issues and revokes grants arrives with the dedicated Host listener
//! (WP-2.5); until then an operator works on the volume itself, with the server stopped: the
//! process lock refuses a volume another process holds. `bootstrap` writes the one recovery
//! administrator's commitment, once; `issue`, `revoke` and `list` append to and read the journal.
//!
//! Bootstrap, issue and revoke are operations of the Host's security-mutation transaction
//! (WP-3.6), as the Host API's are: an intent in `host/audit/mutations/`, a `security` record of
//! each phase in the volume's audit trail, the grant written with its operation id. The CLI is
//! their initiator, `cli`; a mutation a crash left open is resolved before anything else.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use serde::Serialize;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::{Principal, Selector};
use permguard_host::authz::{AuthzError, GrantId, GrantRecord, GrantStore, Issue};
use permguard_host::keys::custody::Custodian;
use permguard_host::keys::ring::HOST_IDENTITY;
use permguard_host::operations::grants;
use permguard_host::operations::journal::Initiator;
use permguard_host::operations::mutation::{MutationError, Mutations};
use permguard_host::storage::volume::Volume;

use crate::args::{Globals, GrantsAction, HostAction, IdentityAction, ResetAction};
use crate::failure::{EXIT_READY, Failure};
use crate::output::Report;
use crate::session::render;
use crate::trace::Trace;

/// Runs one `host …` command.
pub fn host_command(
    globals: &Globals,
    server_config: Option<&Path>,
    action: HostAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    match action {
        HostAction::Grants { action } => grants(globals, server_config, action, trace),
        HostAction::Identity { action } => identity(globals, server_config, action, trace),
    }
}

fn grants(
    globals: &Globals,
    server_config: Option<&Path>,
    action: GrantsAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    let now = permguard_host::authz::store::now();
    match action {
        GrantsAction::Bootstrap {
            volume,
            fingerprint,
        } => {
            let (store, mutations) = open_mutable(&volume, server_config, trace)?;
            let (commitment, grant) =
                grants::bootstrap(&mutations, &store, &fingerprint, now).map_err(refused)?;
            render(
                &BootstrapReport {
                    principal: commitment.principal.to_string(),
                    fingerprint: commitment.fingerprint,
                    created_at: permguard_core::time::to_rfc3339(
                        i64::try_from(commitment.created_at).unwrap_or(i64::MAX),
                    ),
                    grant: grant.as_ref().map(grant_report),
                    already_there: grant.is_none(),
                },
                globals.output,
                trace,
            )?;
        }
        GrantsAction::Issue {
            volume,
            principal,
            operations,
            selector,
            types,
            expires,
            issued_by,
        } => {
            let (store, mutations) = open_mutable(&volume, server_config, trace)?;
            let expires_at = match expires {
                Some(text) => Some(
                    permguard_core::time::from_rfc3339(&text)
                        .and_then(|seconds| u64::try_from(seconds).ok())
                        .ok_or_else(|| {
                            Failure::usage(format!("`{text}` is not an RFC 3339 instant"))
                        })?,
                ),
                None => None,
            };
            let record = grants::issue(
                &mutations,
                &store,
                Initiator::System(INITIATOR.to_owned()),
                Issue {
                    principal: Principal::new(principal)
                        .map_err(|error| Failure::usage(format!("--principal: {error}")))?,
                    operations,
                    selector: Selector::parse(&selector)
                        .map_err(|error| Failure::usage(format!("--selector: {error}")))?,
                    resource_types: if types.is_empty() {
                        vec!["*".to_owned()]
                    } else {
                        types
                    },
                    constraints: BTreeMap::new(),
                    issued_by,
                    expires_at,
                },
                now,
            )
            .map_err(refused)?;
            render(&grant_report(&record), globals.output, trace)?;
        }
        GrantsAction::Revoke {
            volume,
            grant_id,
            by,
        } => {
            let (store, mutations) = open_mutable(&volume, server_config, trace)?;
            let id =
                GrantId::parse(&grant_id).map_err(|error| Failure::usage(error.to_string()))?;
            let record = grants::revoke(
                &mutations,
                &store,
                Initiator::System(INITIATOR.to_owned()),
                id,
                &by,
                now,
            )
            .map_err(refused)?;
            render(&grant_report(&record), globals.output, trace)?;
        }
        GrantsAction::List {
            volume,
            principal,
            selector,
        } => {
            let (store, _held) = open(&volume, trace)?;
            let grants: Vec<GrantReportBody> = store
                .records()
                .iter()
                .filter(|record| {
                    principal
                        .as_deref()
                        .is_none_or(|wanted| record.principal_id.as_str() == wanted)
                })
                .filter(|record| {
                    selector
                        .as_deref()
                        .is_none_or(|wanted| record.selector.to_string() == wanted)
                })
                .map(grant_report)
                .collect();
            render(
                &GrantsReport {
                    revision: store.revision(),
                    grants,
                },
                globals.output,
                trace,
            )?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

/// The initiator the CLI's operations name in the mutation journal and the audit trail.
const INITIATOR: &str = "cli";

/// Opens the grant store and the mutation journal of `volume`, resolving any grant mutation a
/// crash left open: what a command that mutates needs.
fn open_mutable(
    volume: &Path,
    server_config: Option<&Path>,
    trace: &Trace,
) -> Result<(std::sync::Arc<GrantStore>, Mutations), Failure> {
    let (store, held) = open(volume, trace)?;
    let mutations = offline_engine(&held, server_config, trace)?;
    let recovered = mutations
        .recover(&grants::Grants(&store))
        .map_err(|error| Failure::unavailable(format!("recovering grant mutations: {error}")))?;
    if !recovered.reconciled.is_empty() || !recovered.failed.is_empty() {
        trace.say(format!(
            "grant mutations left open by a crash: {} committed, {} failed",
            recovered.reconciled.len(),
            recovered.failed.len()
        ));
    }
    // The lock lives as long as the volume; it is held until the process exits.
    std::mem::forget(held);
    Ok((store, mutations))
}

/// Opens the grant store of `volume`, writing nothing but what the store's own open repairs.
fn open(
    volume: &std::path::Path,
    trace: &Trace,
) -> Result<(std::sync::Arc<GrantStore>, Volume), Failure> {
    trace.say(format!("volume: {}", volume.display()));
    // An existing volume only: a mistyped path must not become a fresh volume holding grants the
    // server never sees. The volume's own layout marker is what says it is one.
    if !volume.join("host").join("FORMAT").is_file() {
        return Err(Failure::usage(format!(
            "{} is not a Server Host volume: no host/FORMAT; start the server once, or check the path",
            volume.display()
        )));
    }
    // Offline: the claim takes the process lock, so a volume a running server holds is refused
    // here with the lock's own message rather than written under it. The development profile is
    // the one that serves an unclaimed volume; the profile the server runs under is its own.
    let held = Volume::claim(volume, AssuranceProfile::Development)
        .map_err(|error| Failure::unavailable(format!("claiming the volume: {error}")))?;
    let (store, recovery) = GrantStore::open(&held).map_err(failure)?;
    if recovery.truncated_bytes > 0 {
        trace.say(format!(
            "the grant journal recovered, truncating {} byte(s)",
            recovery.truncated_bytes
        ));
    }
    Ok((store, held))
}

fn refused(error: MutationError<AuthzError>) -> Failure {
    match error {
        MutationError::Refused(error) => failure(error),
        MutationError::RequestIdReused(detail) => Failure::usage(detail),
        other @ (MutationError::AuditUnavailable(_) | MutationError::Unavailable(_)) => {
            Failure::unavailable(other)
        }
        other @ (MutationError::Unrecorded(_) | MutationError::Indeterminate(_)) => {
            Failure::internal(other)
        }
    }
}

fn failure(error: AuthzError) -> Failure {
    match error {
        AuthzError::Invalid(_)
        | AuthzError::Unknown(_)
        | AuthzError::Terminal(..)
        | AuthzError::Conflict { .. } => Failure::usage(error),
        AuthzError::Storage(_) => Failure::unavailable(error),
        AuthzError::Record(_) => Failure::internal(error),
    }
}

#[derive(Serialize)]
struct GrantReportBody {
    grant_id: String,
    principal: String,
    operations: Vec<String>,
    selector: String,
    resource_types: Vec<String>,
    status: &'static str,
    revision: u64,
    issued_by: String,
    issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

fn grant_report(record: &GrantRecord) -> GrantReportBody {
    let instant =
        |seconds: u64| permguard_core::time::to_rfc3339(i64::try_from(seconds).unwrap_or(i64::MAX));
    GrantReportBody {
        grant_id: record.grant_id.to_string(),
        principal: record.principal_id.to_string(),
        operations: record.operations.clone(),
        selector: record.selector.to_string(),
        resource_types: record.resource_types.clone(),
        status: record.status.as_str(),
        revision: record.revision,
        issued_by: record.issued_by.clone(),
        issued_at: instant(record.issued_at),
        expires_at: record.expires_at.map(instant),
    }
}

impl Report for GrantReportBody {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "grant      {}", self.grant_id)?;
        writeln!(out, "principal  {}", self.principal)?;
        writeln!(out, "operations {}", self.operations.join(", "))?;
        writeln!(out, "selector   {}", self.selector)?;
        writeln!(out, "types      {}", self.resource_types.join(", "))?;
        writeln!(
            out,
            "status     {} (revision {})",
            self.status, self.revision
        )?;
        writeln!(out, "issued     {} by {}", self.issued_at, self.issued_by)?;
        if let Some(expires) = &self.expires_at {
            writeln!(out, "expires    {expires}")?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct GrantsReport {
    revision: u64,
    grants: Vec<GrantReportBody>,
}

impl Report for GrantsReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(
            out,
            "{} grant(s) at revision {}",
            self.grants.len(),
            self.revision
        )?;
        for grant in &self.grants {
            writeln!(
                out,
                "{}  {:<8} {}  {}  {}",
                grant.grant_id,
                grant.status,
                grant.principal,
                grant.operations.join(","),
                grant.selector
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
struct BootstrapReport {
    principal: String,
    fingerprint: String,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    grant: Option<GrantReportBody>,
    already_there: bool,
}

impl Report for BootstrapReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.already_there {
            writeln!(
                out,
                "the volume already commits to this recovery administrator"
            )?;
        } else {
            writeln!(out, "recovery administrator committed")?;
        }
        writeln!(out, "principal   {}", self.principal)?;
        writeln!(out, "fingerprint {}", self.fingerprint)?;
        writeln!(out, "created     {}", self.created_at)?;
        if let Some(grant) = &self.grant {
            writeln!(out)?;
            grant.render_terminal(out)?;
        }
        Ok(())
    }
}

/// The mutation engine of a volume opened offline, its records stamped with the volume's
/// identity when it has one.
fn offline_engine(
    held: &Volume,
    server_config: Option<&Path>,
    trace: &Trace,
) -> Result<Mutations, Failure> {
    let identity = if permguard_host::identity::is_provisioned(held)
        .map_err(|error| Failure::unavailable(format!("reading the identity: {error}")))?
    {
        Some(open_identity(held, server_config)?)
    } else {
        trace.say("the volume holds no Host identity yet; records name its volume id".to_owned());
        None
    };
    Mutations::open_offline_as(held, env!("CARGO_PKG_VERSION"), identity.as_ref())
        .map_err(|error| Failure::unavailable(format!("opening the mutation journal: {error}")))
}

/// The custody `serve` keeps the volume's keys in (WP-3.2, owner decision of 2026-10-08): read
/// from the server's configuration and the environment, as `serve` reads them. Without
/// `--server-config` the keys are the `development` custody's plaintext files.
fn custodian(
    held: &Volume,
    server_config: Option<&Path>,
) -> Result<std::sync::Arc<Custodian>, Failure> {
    let Some(file) = server_config else {
        return Ok(std::sync::Arc::new(Custodian::development()));
    };
    let config = permguard_server::offline::config(env!("CARGO_PKG_VERSION"), Some(file))
        .map_err(|error| Failure::usage(format!("--server-config: {error:#}")))?;
    permguard_server::offline::custodian(&config, held)
        .map_err(|error| Failure::unavailable(format!("the custody of the keys: {error:#}")))
}

/// What a failure to reach the identity's keys says when no configuration named their custody.
fn without_custody(server_config: Option<&Path>, error: impl std::fmt::Display) -> String {
    match server_config {
        Some(_) => error.to_string(),
        None => format!(
            "{error}: a volume whose keys are sealed or in a token or a KMS is opened with the \
             server's configuration, `--server-config <file>`"
        ),
    }
}

fn open_identity(
    held: &Volume,
    server_config: Option<&Path>,
) -> Result<permguard_host::identity::Identity, Failure> {
    use permguard_host::identity::{self, Identity, IdentityError};

    let not_provisioned = || {
        Failure::usage(format!(
            "{}: run `permguard host identity provision --volume <path>` first",
            IdentityError::NotProvisioned
        ))
    };
    let (_, keys) = identity::directories(held)
        .map_err(|error| Failure::unavailable(format!("the identity directory: {error}")))?;
    let host_id = identity::host_id_of(held)
        .map_err(|error| Failure::unavailable(format!("reading the identity: {error}")))?
        .ok_or_else(not_provisioned)?;
    let suite = identity::suite_of(held)
        .map_err(|error| Failure::unavailable(format!("reading the identity: {error}")))?
        .unwrap_or(identity::Suite::Ed25519Sha256V1);
    let stored = identity::stored_public(
        permguard_host::storage::Dir::open(keys.path())
            .map_err(|error| Failure::unavailable(format!("the identity's keys: {error}")))?,
    );
    let custodied = custodian(held, server_config)?
        .plan(HOST_IDENTITY, host_id, keys, stored, suite)
        .map_err(|error| Failure::unavailable(without_custody(server_config, error)))?;
    // Sealing and rewrapping are the start's, which records them in the operations audit.
    if !custodied.plan.sealed.is_empty() || !custodied.plan.rewrapped.is_empty() {
        return Err(Failure::usage(
            "the identity's keys are still to be sealed, or rewrapped under the current \
             key-encryption key: the server does it at its start and records it, so start it \
             once before working on the volume offline",
        ));
    }
    Identity::open(held, custodied.provider).map_err(|error| match error {
        IdentityError::NotProvisioned => not_provisioned(),
        other => Failure::unavailable(without_custody(server_config, other)),
    })
}

fn identity(
    globals: &Globals,
    server_config: Option<&Path>,
    action: IdentityAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    use permguard_host::identity::{self, Identity, Suite};

    let now = permguard_host::authz::store::now();
    match action {
        IdentityAction::Provision { volume, suite } => {
            let suite = Suite::from_name(&suite).ok_or_else(|| {
                Failure::usage(format!(
                    "`{suite}` is not a suite: pg-ed25519-sha256-v1 or pg-p256-sha256-v1"
                ))
            })?;
            trace.say(format!("volume: {}", volume.display()));
            // Provisioning comes before the first start, so the volume may be created here.
            let held = Volume::claim(&volume, AssuranceProfile::Development)
                .map_err(|error| Failure::unavailable(format!("claiming the volume: {error}")))?;
            let (_, keys) = identity::directories(&held).map_err(|error| {
                Failure::unavailable(format!("the identity directory: {error}"))
            })?;
            let stored =
                identity::stored_public(permguard_host::storage::Dir::open(keys.path()).map_err(
                    |error| Failure::unavailable(format!("the identity's keys: {error}")),
                )?);
            // Generated where `serve` keeps it: sealed under `file`, in the token, in the KMS.
            let custodian = custodian(&held, server_config)?;
            let opened = Identity::provision_with(
                &held,
                |host_id| {
                    custodian
                        .provider(HOST_IDENTITY, *host_id, keys, stored, suite)
                        .map(|(provider, _)| provider)
                        .map_err(identity::IdentityError::from)
                },
                suite,
                now,
                now.saturating_mul(1000),
            )
            .map_err(|error| match error {
                identity::IdentityError::Provisioned => Failure::usage(error),
                other => Failure::unavailable(other),
            })?;
            let audit = audit_offline(&held, &opened)?;
            audit
                .append(
                    &permguard_core::AuditEvent::new(
                        identity::AUDIT_PROVISIONED,
                        permguard_core::Subject::System(INITIATOR),
                    )
                    .on(&opened.host_id_text()),
                    None,
                )
                .map_err(|error| {
                    Failure::unavailable(format!("recording the provisioning: {error}"))
                })?;
            let custody = custodian.custody_of(HOST_IDENTITY).as_str();
            if server_config.is_none() {
                trace.say(
                    "no --server-config: the key is a plaintext file of the `development` custody, \
                     which a server on `pkcs11` or `kms` refuses"
                        .to_owned(),
                );
            }
            render(
                &identity_report(&opened, true, Some(custody)),
                globals.output,
                trace,
            )?;
            std::mem::forget(held);
        }
        IdentityAction::Show { volume } => {
            let (_store, held) = open(&volume, trace)?;
            let opened = open_identity(&held, server_config)?;
            render(
                &identity_report(&opened, false, None),
                globals.output,
                trace,
            )?;
        }
        IdentityAction::Rotate {
            volume,
            expected_epoch,
        } => {
            let (_store, held) = open(&volume, trace)?;
            let opened = open_identity(&held, server_config)?;
            let mutations =
                Mutations::open_offline_as(&held, env!("CARGO_PKG_VERSION"), Some(&opened))
                    .map_err(|error| {
                        Failure::unavailable(format!("opening the mutation journal: {error}"))
                    })?;
            mutations
                .recover(&identity::Identities(&opened))
                .map_err(|error| Failure::unavailable(format!("recovering: {error}")))?;
            identity::rotate(
                &mutations,
                &opened,
                Initiator::System(INITIATOR.to_owned()),
                expected_epoch,
                now,
            )
            .map_err(|error| match error {
                MutationError::Refused(identity::IdentityError::Conflict { .. }) => {
                    Failure::usage(error)
                }
                other @ (MutationError::AuditUnavailable(_) | MutationError::Unavailable(_)) => {
                    Failure::unavailable(other)
                }
                other => Failure::internal(other),
            })?;
            render(
                &identity_report(&opened, false, None),
                globals.output,
                trace,
            )?;
            std::mem::forget(held);
        }
        IdentityAction::Reset { action } => reset(globals, server_config, action, trace)?,
    }
    Ok(ExitCode::from(EXIT_READY))
}

/// The plan an offline reset writes and its run confirms (WP-4.1): what it binds is the Host,
/// its epoch, the reason and every live membership at its revision.
#[derive(Debug, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetPlan {
    kind: String,
    mode: String,
    host_id: String,
    epoch: u64,
    reason: String,
    memberships: Vec<ResetPlanned>,
    /// The memberships as the plan bound them: `<id>:<revision>`, in id order.
    bound: String,
    /// SHA-256 over every member above.
    digest: String,
}

#[derive(Debug, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ResetPlanned {
    membership_id: String,
    role: String,
    status: String,
    /// `orphan` offline for a membership this Host is a member of; `revoke_local` or
    /// `reject_local` for one it coordinates.
    step: String,
    peer: String,
    address: Option<String>,
}

const RESET_PLAN_KIND: &str = permguard_core::domains::format::IDENTITY_RESET_PLAN_V1;

impl ResetPlan {
    fn digest_of(&self) -> String {
        let mut bytes = Vec::new();
        for part in [
            self.kind.as_str(),
            self.mode.as_str(),
            self.host_id.as_str(),
            &self.epoch.to_string(),
            self.reason.as_str(),
            self.bound.as_str(),
        ] {
            bytes.extend_from_slice(&(part.len() as u64).to_be_bytes());
            bytes.extend_from_slice(part.as_bytes());
        }
        permguard_objects::digest::Digest::compute(&bytes).to_string()
    }
}

impl Report for ResetPlan {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Host identity reset planned (emergency, offline)")?;
        writeln!(out, "host_id  {}", self.host_id)?;
        writeln!(out, "epoch    {}", self.epoch)?;
        writeln!(out, "digest   {}", self.digest)?;
        for held in &self.memberships {
            writeln!(
                out,
                "  {} {:<11} {:<9} {:<12} {}{}",
                held.membership_id,
                held.role,
                held.status,
                held.step,
                held.peer,
                held.address
                    .as_deref()
                    .map(|address| format!(" {address}"))
                    .unwrap_or_default()
            )?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "No coordinator is reached offline: every membership marked `orphan` stays active for \
             its coordinator until revoked there. Run with `reset run --confirm-file <file>`."
        )
    }
}

#[derive(Serialize)]
struct ResetReport {
    old_host_id: String,
    host_id: String,
    fingerprint: String,
    witness: String,
    ended: Vec<String>,
    /// Each membership left `orphaned`, with the coordinator to revoke it out of band.
    orphaned: Vec<ResetOrphanedReport>,
}

#[derive(Serialize)]
struct ResetOrphanedReport {
    membership_id: String,
    coordinator: String,
    address: Option<String>,
}

impl Report for ResetReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Host identity reset")?;
        writeln!(out, "old host_id       {}", self.old_host_id)?;
        writeln!(out, "host_id           {}", self.host_id)?;
        writeln!(out, "first fingerprint {}", self.fingerprint)?;
        writeln!(out, "witness           {}", self.witness)?;
        for id in &self.ended {
            writeln!(out, "  ended     {id}")?;
        }
        for orphaned in &self.orphaned {
            writeln!(
                out,
                "  orphaned  {} coordinator {}{}",
                orphaned.membership_id,
                orphaned.coordinator,
                orphaned
                    .address
                    .as_deref()
                    .map(|address| format!(" at {address}"))
                    .unwrap_or_default()
            )?;
        }
        writeln!(out)?;
        writeln!(
            out,
            "Give the server the new witness as `host.identity.witness`. Each orphaned \
             membership's coordinator must revoke it: until then the old identity's key may still \
             use it there."
        )
    }
}

/// The plan of `held`'s state: its identity and every live membership.
fn reset_plan(
    identity: &permguard_host::identity::Identity,
    store: &permguard_host::membership::Store,
    reason: String,
) -> ResetPlan {
    use permguard_host::membership::reset::{self as settle, Step};
    let planned = settle::plan(store);
    let mut plan = ResetPlan {
        kind: RESET_PLAN_KIND.to_owned(),
        mode: "emergency".to_owned(),
        host_id: identity.host_id_text(),
        epoch: identity.epoch(),
        reason,
        memberships: planned
            .iter()
            .map(|(id, held, step)| {
                let peer = match held.role {
                    permguard_host::membership::record::Role::Coordinator => &held.request.member,
                    permguard_host::membership::record::Role::Member => &held.request.coordinator,
                };
                ResetPlanned {
                    membership_id: permguard_host::identity::record::uuid_text(id),
                    role: held.role.as_str().to_owned(),
                    status: held.status.as_str().to_owned(),
                    step: match step {
                        Step::RevokeRemote => "orphan",
                        other => other.as_str(),
                    }
                    .to_owned(),
                    peer: permguard_host::identity::record::uuid_text(&peer.host_id),
                    address: held.request.coordinator_address.clone(),
                }
            })
            .collect(),
        bound: settle::digest_target(&planned),
        digest: String::new(),
    };
    plan.digest = plan.digest_of();
    plan
}

fn reset(
    globals: &Globals,
    server_config: Option<&Path>,
    action: ResetAction,
    trace: &Trace,
) -> Result<(), Failure> {
    use permguard_host::identity::{self, IdentityError};
    use permguard_host::membership::Store;

    let now = permguard_host::authz::store::now();
    let open_members = |held: &Volume| {
        Store::open(held)
            .map_err(|error| Failure::unavailable(format!("opening the memberships: {error}")))
    };
    match action {
        ResetAction::Plan {
            volume,
            reason,
            out,
        } => {
            if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
                return Err(Failure::usage(
                    "--reason is printable text of 1 to 256 bytes",
                ));
            }
            let (_store, held) = open(&volume, trace)?;
            let opened = open_identity(&held, server_config)?;
            let plan = reset_plan(&opened, open_members(&held)?.as_ref(), reason);
            let bytes = serde_json::to_vec_pretty(&plan)
                .map_err(|error| Failure::internal(format!("writing the plan: {error}")))?;
            write_new(&out, &bytes)?;
            trace.say(format!("plan written to {}", out.display()));
            render(&plan, globals.output, trace)?;
            std::mem::forget(held);
        }
        ResetAction::Run {
            volume,
            confirm_file,
        } => {
            let (_store, held) = open(&volume, trace)?;
            let config =
                permguard_server::offline::config(env!("CARGO_PKG_VERSION"), server_config)
                    .map_err(|error| Failure::usage(format!("--server-config: {error:#}")))?;
            let custodian = custodian(&held, server_config)?;
            let suite = identity::suite_of(&held)
                .map_err(|error| Failure::unavailable(format!("reading the identity: {error}")))?
                .unwrap_or(identity::Suite::Ed25519Sha256V1);
            let provisioner = permguard_server::offline::provisioner(&custodian, &held, suite)
                .map_err(|error| Failure::unavailable(format!("{error:#}")))?;
            let time = std::sync::Arc::new(permguard_host::time::TimeGuard::system(
                config.time_max_clock_skew(),
            ));
            // A reset a crash interrupted is completed, whatever its plan: its rings too.
            if let Some(old) = identity::reset::marked(&held)
                .map_err(|error| Failure::unavailable(format!("reading the identity: {error}")))?
            {
                let rings = permguard_server::offline::rings(
                    &config,
                    &held,
                    old,
                    None,
                    &custodian,
                    std::sync::Arc::clone(&time),
                )
                .map_err(|error| Failure::unavailable(format!("the key rings: {error:#}")))?;
                let mutations = Mutations::open_offline_as(&held, env!("CARGO_PKG_VERSION"), None)
                    .map_err(|error| {
                        Failure::unavailable(format!("opening the mutation journal: {error}"))
                    })?;
                let resumed = identity::reset::resume_run(
                    &mutations,
                    &held,
                    &provisioner,
                    &rings,
                    suite,
                    Initiator::System(INITIATOR.to_owned()),
                    now,
                )
                .map_err(|error| Failure::unavailable(format!("completing the reset: {error}")))?
                .ok_or_else(|| Failure::internal("the reset under way was completed meanwhile"))?;
                trace.say("an interrupted reset was completed".to_owned());
                render(
                    &ResetReport {
                        old_host_id: identity::record::uuid_text(&resumed.old_host_id),
                        host_id: identity::record::uuid_text(&resumed.host_id),
                        fingerprint: resumed.fingerprint,
                        witness: resumed.witness,
                        ended: Vec::new(),
                        orphaned: Vec::new(),
                    },
                    globals.output,
                    trace,
                )?;
                std::mem::forget(held);
                return Ok(());
            }
            let confirm_file = confirm_file.ok_or_else(|| {
                Failure::usage("--confirm-file names the plan `reset plan` wrote")
            })?;
            let plan: ResetPlan = std::fs::read(&confirm_file)
                .map_err(|error| {
                    Failure::usage(format!(
                        "--confirm-file {}: {error}",
                        confirm_file.display()
                    ))
                })
                .and_then(|bytes| {
                    serde_json::from_slice(&bytes).map_err(|error| {
                        Failure::usage(format!("--confirm-file is not a reset plan: {error}"))
                    })
                })?;
            if plan.kind != RESET_PLAN_KIND || plan.digest != plan.digest_of() {
                return Err(Failure::usage(
                    "--confirm-file is not a reset plan `reset plan` wrote, or it was edited",
                ));
            }
            let opened = std::sync::Arc::new(
                open_identity(&held, server_config)?.with_provisioner(provisioner),
            );
            let mutations =
                Mutations::open_offline_as(&held, env!("CARGO_PKG_VERSION"), Some(opened.as_ref()))
                    .map_err(|error| {
                        Failure::unavailable(format!("opening the mutation journal: {error}"))
                    })?;
            let store = open_members(&held)?;
            mutations
                .recover(&identity::Identities(&opened))
                .and_then(|_| mutations.recover(&permguard_host::membership::Memberships(&store)))
                .map_err(|error| Failure::unavailable(format!("recovering: {error}")))?;
            let current = reset_plan(&opened, &store, plan.reason.clone());
            if current.digest != plan.digest {
                return Err(Failure::usage(
                    "the identity or its memberships changed since the plan: plan again",
                ));
            }
            // Every ring the server composes: `host.operations` signs the manifests that end
            // the memberships this Host coordinates, and every ring retires with the identity.
            let rings = permguard_server::offline::rings(
                &config,
                &held,
                opened.host_id(),
                Some(std::sync::Arc::clone(&opened)
                    as std::sync::Arc<dyn permguard_host::keys::ring::Binder>),
                &custodian,
                time,
            )
            .map_err(|error| Failure::unavailable(format!("the key rings: {error:#}")))?;
            let done = permguard_host::membership::reset::emergency(
                &store,
                &mutations,
                &opened,
                &rings,
                &Initiator::System(INITIATOR.to_owned()),
                now,
            )
            .map_err(|error| match error {
                permguard_host::membership::reset::EmergencyError::Identity(
                    MutationError::Refused(IdentityError::Refused(_)),
                ) => Failure::usage(error),
                other => Failure::unavailable(other),
            })?;
            render(
                &ResetReport {
                    old_host_id: identity::record::uuid_text(&done.reset.old_host_id),
                    host_id: identity::record::uuid_text(&done.reset.host_id),
                    fingerprint: done.reset.fingerprint,
                    witness: done.reset.witness,
                    ended: done
                        .ended
                        .iter()
                        .map(|held| identity::record::uuid_text(&held.request.membership_id))
                        .collect(),
                    orphaned: done
                        .orphaned
                        .iter()
                        .map(|held| ResetOrphanedReport {
                            membership_id: identity::record::uuid_text(&held.request.membership_id),
                            coordinator: identity::record::uuid_text(
                                &held.request.coordinator.host_id,
                            ),
                            address: held.request.coordinator_address.clone(),
                        })
                        .collect(),
                },
                globals.output,
                trace,
            )?;
            std::mem::forget(held);
        }
    }
    Ok(())
}

/// Writes `bytes` to a new file at `path`, readable by its owner only.
fn write_new(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    use std::io::Write as _;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| Failure::usage(format!("--out {}: {error}", path.display())))?;
    file.write_all(bytes)
        .map_err(|error| Failure::unavailable(format!("writing {}: {error}", path.display())))
}

/// An audit engine on `held`, stamped with `identity`.
fn audit_offline(
    held: &Volume,
    identity: &permguard_host::identity::Identity,
) -> Result<permguard_host::audit::Engine, Failure> {
    let time = std::sync::Arc::new(permguard_host::time::TimeGuard::system(
        std::time::Duration::from_secs(30),
    ));
    permguard_host::audit::Engine::open(
        held,
        permguard_host::audit::Stamp {
            host_id: identity.host_id(),
            boot_id: identity.boot_id(),
            build: env!("CARGO_PKG_VERSION").to_owned(),
            config_revision: permguard_host::audit::config_revision(std::iter::empty()),
        },
        time,
        None,
    )
    .map_err(|error| Failure::unavailable(format!("opening the audit trails: {error}")))
}

#[derive(Serialize)]
struct IdentityReport {
    host_id: String,
    subject: String,
    epoch: u64,
    suite: &'static str,
    fingerprint: String,
    first_fingerprint: String,
    /// Printed at provisioning only: a witness read back from the volume it is meant to check
    /// checks nothing.
    #[serde(skip_serializing_if = "Option::is_none")]
    witness: Option<String>,
    /// Printed at provisioning: the custody the key was generated under, which the server's must
    /// be (WP-3.2).
    #[serde(skip_serializing_if = "Option::is_none")]
    custody: Option<&'static str>,
    #[serde(skip)]
    provisioned: bool,
}

fn identity_report(
    identity: &permguard_host::identity::Identity,
    provisioned: bool,
    custody: Option<&'static str>,
) -> IdentityReport {
    IdentityReport {
        host_id: identity.host_id_text(),
        subject: identity.subject(),
        epoch: identity.epoch(),
        suite: identity.suite().name(),
        fingerprint: identity.fingerprint(),
        first_fingerprint: identity.first_fingerprint().to_owned(),
        witness: provisioned.then(|| identity.witness()),
        custody,
        provisioned,
    }
}

impl Report for IdentityReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.provisioned {
            writeln!(out, "Host identity provisioned")?;
        }
        writeln!(out, "host_id           {}", self.host_id)?;
        writeln!(out, "subject           {}", self.subject)?;
        writeln!(out, "epoch             {}", self.epoch)?;
        writeln!(out, "suite             {}", self.suite)?;
        writeln!(out, "fingerprint       {}", self.fingerprint)?;
        writeln!(out, "first fingerprint {}", self.first_fingerprint)?;
        if let Some(witness) = &self.witness {
            writeln!(out, "witness           {witness}")?;
        }
        if let Some(custody) = self.custody {
            writeln!(out, "custody           {custody}")?;
        }
        if self.provisioned {
            writeln!(out)?;
            writeln!(
                out,
                "Keep the witness outside this volume and give it to the server as \
                 `host.identity.witness`: from the `production` profile up it is required, and a \
                 volume whose witness differs is refused."
            )?;
        }
        Ok(())
    }
}
