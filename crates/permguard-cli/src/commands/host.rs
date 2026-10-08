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
use std::process::ExitCode;

use serde::Serialize;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::{Principal, Selector};
use permguard_host::authz::{AuthzError, GrantId, GrantRecord, GrantStore, Issue};
use permguard_host::operations::grants;
use permguard_host::operations::journal::Initiator;
use permguard_host::operations::mutation::{MutationError, Mutations};
use permguard_host::storage::volume::Volume;

use crate::args::{Globals, GrantsAction, HostAction, IdentityAction};
use crate::failure::{EXIT_READY, Failure};
use crate::output::Report;
use crate::session::render;
use crate::trace::Trace;

/// Runs one `host …` command.
pub fn host_command(
    globals: &Globals,
    action: HostAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    match action {
        HostAction::Grants { action } => grants(globals, action, trace),
        HostAction::Identity { action } => identity(globals, action, trace),
    }
}

fn grants(globals: &Globals, action: GrantsAction, trace: &Trace) -> Result<ExitCode, Failure> {
    let now = permguard_host::authz::store::now();
    match action {
        GrantsAction::Bootstrap {
            volume,
            fingerprint,
        } => {
            let (store, mutations) = open_mutable(&volume, trace)?;
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
            let (store, mutations) = open_mutable(&volume, trace)?;
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
            let (store, mutations) = open_mutable(&volume, trace)?;
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
    volume: &std::path::Path,
    trace: &Trace,
) -> Result<(std::sync::Arc<GrantStore>, Mutations), Failure> {
    let (store, held) = open(volume, trace)?;
    let mutations = offline_engine(&held, trace)?;
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
fn offline_engine(held: &Volume, trace: &Trace) -> Result<Mutations, Failure> {
    let identity = if permguard_host::identity::is_provisioned(held)
        .map_err(|error| Failure::unavailable(format!("reading the identity: {error}")))?
    {
        Some(open_identity(held)?)
    } else {
        trace.say("the volume holds no Host identity yet; records name its volume id".to_owned());
        None
    };
    Mutations::open_offline_as(held, env!("CARGO_PKG_VERSION"), identity.as_ref())
        .map_err(|error| Failure::unavailable(format!("opening the mutation journal: {error}")))
}

fn open_identity(held: &Volume) -> Result<permguard_host::identity::Identity, Failure> {
    let (_, keys) = permguard_host::identity::directories(held)
        .map_err(|error| Failure::unavailable(format!("the identity directory: {error}")))?;
    permguard_host::identity::Identity::open(
        held,
        std::sync::Arc::new(permguard_host::keys::FileKeyProvider::new(keys)),
    )
    .map_err(|error| match error {
        permguard_host::identity::IdentityError::NotProvisioned => Failure::usage(format!(
            "{error}: run `permguard host identity provision --volume <path>` first"
        )),
        other => Failure::internal(other),
    })
}

fn identity(globals: &Globals, action: IdentityAction, trace: &Trace) -> Result<ExitCode, Failure> {
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
            let opened = Identity::provision(
                &held,
                std::sync::Arc::new(permguard_host::keys::FileKeyProvider::new(keys)),
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
            render(&identity_report(&opened, true), globals.output, trace)?;
            std::mem::forget(held);
        }
        IdentityAction::Show { volume } => {
            let (_store, held) = open(&volume, trace)?;
            let opened = open_identity(&held)?;
            render(&identity_report(&opened, false), globals.output, trace)?;
        }
        IdentityAction::Rotate {
            volume,
            expected_epoch,
        } => {
            let (_store, held) = open(&volume, trace)?;
            let opened = open_identity(&held)?;
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
            render(&identity_report(&opened, false), globals.output, trace)?;
            std::mem::forget(held);
        }
    }
    Ok(ExitCode::from(EXIT_READY))
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
    #[serde(skip)]
    provisioned: bool,
}

fn identity_report(
    identity: &permguard_host::identity::Identity,
    provisioned: bool,
) -> IdentityReport {
    IdentityReport {
        host_id: identity.host_id_text(),
        subject: identity.subject(),
        epoch: identity.epoch(),
        suite: identity.suite().name(),
        fingerprint: identity.fingerprint(),
        first_fingerprint: identity.first_fingerprint().to_owned(),
        witness: provisioned.then(|| identity.witness()),
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
