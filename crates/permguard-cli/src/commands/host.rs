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
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::Principal;
use permguard_host::authz::{AuthzError, GrantRecord, GrantStore};
use permguard_host::keys::custody::Custodian;
use permguard_host::keys::ring::HOST_IDENTITY;
use permguard_host::operations::grants;
use permguard_host::operations::journal::Initiator;
use permguard_host::operations::mutation::{MutationError, Mutations};
use permguard_host::storage::volume::Volume;

use crate::args::{
    Globals, GrantRevokeAction, GrantsAction, HoldsAction, HostAction, IdentityAction,
    InviteAction, MemberChangeArgs, MemberRevokeAction, MembersAction, PinAction, ResetAction,
};
use crate::failure::{EXIT_READY, Failure};
use crate::output::Report;
use crate::session::render;
use crate::trace::Trace;
use permguard_host::api::host_input::{IdentityPin, InvitationHandoff, PinStore};

/// The `--volume` target an offline command works on (TC-1): stated, never guessed.
fn volume_of(globals: &Globals) -> Result<std::path::PathBuf, Failure> {
    globals.volume.clone().ok_or_else(|| {
        Failure::usage(
            "an offline host command works on a volume: name it with --volume <dir>, the \
             server stopped",
        )
    })
}

/// Runs one `host …` command.
pub fn host_command(
    globals: &Globals,
    server_config: Option<&Path>,
    action: HostAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    match action {
        HostAction::Grants { action } => grants(globals, server_config, action, trace),
        HostAction::Holds { action } => holds(globals, server_config, action, trace),
        HostAction::Identity { action } => identity(globals, server_config, action, trace),
        HostAction::Members { action } => members(globals, action, trace),
        HostAction::Streams { action } => streams(globals, action, trace),
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
        GrantsAction::Bootstrap { fingerprint } => {
            let volume = volume_of(globals)?;
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
            principal,
            operations,
            selector,
            types,
            expires,
            expected_revision,
        } => {
            let backend = online_host(globals, trace, false)?;
            let answer = backend
                .create_grant(&permguard_host::api::CreateGrant {
                    request_id: request_id(),
                    expected_revision,
                    principal,
                    operations,
                    selector,
                    resource_types: types,
                    constraints: BTreeMap::new(),
                    expires_at: expires,
                })
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
        }
        GrantsAction::Revoke { action } => grant_revoke(globals, action, trace)?,
        GrantsAction::List {
            principal,
            selector,
        } => {
            let backend = online_host(globals, trace, false)?;
            let answer = backend
                .grants(principal.as_deref(), selector.as_deref())
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
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
    let held = claim(volume, trace)?;
    let (store, recovery) = GrantStore::open(&held).map_err(failure)?;
    if recovery.truncated_bytes > 0 {
        trace.say(format!(
            "the grant journal recovered, truncating {} byte(s)",
            recovery.truncated_bytes
        ));
    }
    Ok((store, held))
}

/// Claims `volume`, an existing one only, without opening any store: what `host holds` reads and
/// writes beside the grants (after the review).
fn claim(volume: &std::path::Path, trace: &Trace) -> Result<Volume, Failure> {
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
    Volume::claim(volume, AssuranceProfile::Development)
        .map_err(|error| Failure::unavailable(format!("claiming the volume: {error}")))
}

/// `permguard host holds …` (WP-7.3c): offline, on the volume of a stopped server, through the
/// Host's mutation transaction, the holds a crash left open resolved first.
fn holds(
    globals: &Globals,
    server_config: Option<&Path>,
    action: HoldsAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    use permguard_host::holds::{self, Deadline, HoldStore, NewHold};

    let volume = volume_of(globals)?;
    let held = claim(&volume, trace)?;
    let store = HoldStore::open(&held)
        .map_err(|error| Failure::unavailable(format!("opening the holds: {error}")))?;
    let now = permguard_host::authz::store::now();
    match action {
        HoldsAction::List => {
            let listed = store.list().map_err(hold_refused)?;
            std::mem::forget(held);
            render(
                &HoldListReport {
                    holds: listed.iter().map(|hold| HoldView::of(hold, now)).collect(),
                },
                globals.output,
                trace,
            )?;
        }
        HoldsAction::Add {
            resource,
            owner,
            reason,
            expires_at,
            review_at,
        } => {
            let mutations = offline_holds(&held, &store, server_config, trace)?;
            std::mem::forget(held);
            let at = |text: String| {
                permguard_core::time::from_rfc3339(&text)
                    .and_then(|seconds| u64::try_from(seconds).ok())
                    .ok_or_else(|| Failure::usage(format!("`{text}` is not an RFC 3339 instant")))
            };
            let deadline = match (expires_at, review_at) {
                (Some(text), None) => Deadline::Expires(at(text)?),
                (None, Some(text)) => Deadline::Review(at(text)?),
                _ => {
                    return Err(Failure::usage(
                        "a hold names exactly one of --expires-at and --review-at",
                    ));
                }
            };
            let added = holds::add(
                &mutations,
                &store,
                Initiator::System("cli".to_owned()),
                NewHold {
                    resource,
                    owner,
                    reason,
                    deadline,
                },
                now,
            )
            .map_err(hold_mutation_refused)?;
            render(
                &HoldReport {
                    action: "added",
                    hold: HoldView::of(&added, now),
                },
                globals.output,
                trace,
            )?;
        }
        HoldsAction::Release { id } => {
            let mutations = offline_holds(&held, &store, server_config, trace)?;
            std::mem::forget(held);
            let released =
                holds::release(&mutations, &store, Initiator::System("cli".to_owned()), &id)
                    .map_err(hold_mutation_refused)?;
            render(
                &HoldReport {
                    action: "released",
                    hold: HoldView::of(&released, now),
                },
                globals.output,
                trace,
            )?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

/// The offline transaction, the hold operations a crash left open resolved first.
fn offline_holds(
    held: &Volume,
    store: &permguard_host::holds::HoldStore,
    server_config: Option<&Path>,
    trace: &Trace,
) -> Result<Mutations, Failure> {
    let mutations = offline_engine(held, server_config, trace)?;
    let recovered = mutations
        .recover(&permguard_host::holds::Holds(store))
        .map_err(|error| Failure::unavailable(format!("recovering hold mutations: {error}")))?;
    if !recovered.reconciled.is_empty() || !recovered.failed.is_empty() {
        trace.say(format!(
            "hold mutations left open by a crash: {} committed, {} failed",
            recovered.reconciled.len(),
            recovered.failed.len()
        ));
    }
    Ok(mutations)
}

fn hold_refused(error: permguard_host::holds::HoldError) -> Failure {
    use permguard_host::holds::HoldError;
    match error {
        HoldError::Invalid(_) | HoldError::NotFound(_) => Failure::usage(error.to_string()),
        HoldError::Storage(_) => Failure::unavailable(error.to_string()),
        HoldError::Record(_) => Failure::internal(error.to_string()),
    }
}

fn hold_mutation_refused(error: MutationError<permguard_host::holds::HoldError>) -> Failure {
    match error {
        MutationError::Refused(error) => hold_refused(error),
        MutationError::RequestIdReused(detail) => Failure::usage(detail),
        other @ (MutationError::AuditUnavailable(_) | MutationError::Unavailable(_)) => {
            Failure::unavailable(other)
        }
        other @ (MutationError::Unrecorded(_) | MutationError::Indeterminate(_)) => {
            Failure::internal(other)
        }
    }
}

/// One hold as the CLI reports it: its times in RFC 3339 and where it stands now.
#[derive(Debug, Serialize)]
struct HoldView {
    id: String,
    resource: String,
    owner: String,
    reason: String,
    status: &'static str,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    review_at: Option<String>,
}

impl HoldView {
    fn of(hold: &permguard_host::holds::Hold, now: u64) -> Self {
        let when = |seconds: u64| {
            permguard_core::time::to_rfc3339(i64::try_from(seconds).unwrap_or(i64::MAX))
        };
        Self {
            id: hold.id.clone(),
            resource: hold.resource.clone(),
            owner: hold.owner.clone(),
            reason: hold.reason.clone(),
            status: hold.status(now).as_str(),
            created_at: when(hold.created_at),
            expires_at: hold.expires_at.map(when),
            review_at: hold.review_at.map(when),
        }
    }

    fn render(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "  id:       {}", self.id)?;
        writeln!(out, "  resource: {}", self.resource)?;
        writeln!(out, "  owner:    {}", self.owner)?;
        writeln!(out, "  reason:   {}", self.reason)?;
        writeln!(out, "  status:   {}", self.status)?;
        if let Some(at) = &self.expires_at {
            writeln!(out, "  expires:  {at}")?;
        }
        if let Some(at) = &self.review_at {
            writeln!(out, "  review:   {at}")?;
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
struct HoldReport {
    action: &'static str,
    #[serde(flatten)]
    hold: HoldView,
}

impl Report for HoldReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "hold {}", self.action)?;
        self.hold.render(out)
    }
}

#[derive(Debug, Serialize)]
struct HoldListReport {
    holds: Vec<HoldView>,
}

impl Report for HoldListReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        if self.holds.is_empty() {
            return writeln!(out, "no holds");
        }
        for hold in &self.holds {
            hold.render(out)?;
            writeln!(out)?;
        }
        writeln!(out, "{} hold(s).", self.holds.len())
    }
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
        IdentityAction::Provision { suite } => {
            let volume = volume_of(globals)?;
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
            let audit = audit_offline(&held, &opened, None)?;
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
        IdentityAction::Show => {
            let identity = online_host(globals, trace, false)?
                .identity()
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&identity, globals, trace)?;
        }
        IdentityAction::Verify { url, fingerprint } => {
            let identity = online_host_at(globals, trace, &url, false)?
                .identity()
                .map_err(|failure| Failure::from_client(&failure))?;
            let verified = verify_identity(&identity)?;
            if verified.first_fingerprint() != fingerprint {
                return Err(Failure::usage(format!(
                    "the peer identity fingerprint is {}, not {fingerprint}",
                    verified.first_fingerprint()
                )));
            }
            let answer = online_host(globals, trace, false)?
                .verify_identity(&permguard_host::api::VerifyIdentity {
                    address: peer_address(&url)?,
                    host_id: permguard_host::identity::record::uuid_text(&verified.host_id),
                    fingerprint,
                })
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
        }
        IdentityAction::Rotate { expected_epoch } => {
            let answer = online_host(globals, trace, false)?
                .rotate_identity(&permguard_host::api::RotateIdentity {
                    request_id: request_id(),
                    expected_epoch,
                })
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
        }
        IdentityAction::Pin { action } => pin(globals, action, trace)?,
        IdentityAction::Reset { action } => reset(globals, server_config, action, trace)?,
    }
    Ok(ExitCode::from(EXIT_READY))
}

static REQUEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!(
        "cli-{nanos}-{}-{}",
        std::process::id(),
        REQUEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

fn online_host(
    globals: &Globals,
    trace: &Trace,
    invitation_token: bool,
) -> Result<Box<dyn permguard_control_client::host::Host>, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    let url = crate::session::resolve_endpoint_url(
        "host.endpoint",
        globals.host_endpoint.as_deref(),
        &store,
        trace,
    )?;
    online_host_with_store(globals, trace, &url, &store, invitation_token)
}

fn online_host_at(
    globals: &Globals,
    trace: &Trace,
    url: &str,
    invitation_token: bool,
) -> Result<Box<dyn permguard_control_client::host::Host>, Failure> {
    let store = crate::session::open_store(globals, trace)?;
    online_host_with_store(globals, trace, url, &store, invitation_token)
}

fn online_host_with_store(
    globals: &Globals,
    trace: &Trace,
    url: &str,
    store: &crate::settings::Store,
    invitation_token: bool,
) -> Result<Box<dyn permguard_control_client::host::Host>, Failure> {
    let mut effective = globals.clone();
    if invitation_token {
        effective.token_file = None;
    }
    let tls = crate::target::tls(&effective, store, trace)?;
    permguard_control_client::host::client(url, &tls, crate::narrator::for_run(globals.verbose))
        .map_err(Failure::usage)
}

fn require_verified_tls_endpoint(url: &str, skip_verification: bool) -> Result<(), Failure> {
    let endpoint = permguard_control_client::Endpoint::parse(url).map_err(Failure::usage)?;
    if !endpoint.is_tls() || skip_verification {
        return Err(Failure::usage(
            "a membership invitation is read and sent only over verified TLS",
        ));
    }
    Ok(())
}

#[derive(Debug, Serialize)]
struct JsonReport(serde_json::Value);

impl Report for JsonReport {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&self.0).unwrap_or_else(|_| "null".to_owned())
        )
    }
}

/// `permguard host streams …` (WP-5.7b): the Host API's stream reads, printed as it answers
/// them; `runs` lists the frontier's runs, the producer's and each consumer's, as one history.
fn streams(
    globals: &Globals,
    action: crate::args::StreamsAction,
    trace: &Trace,
) -> Result<ExitCode, Failure> {
    use crate::args::StreamsAction;
    use permguard_control_client::host::StreamName;

    let host = online_host(globals, trace, false)?;
    let failed =
        |failure: permguard_control_client::catalog::Failure| Failure::from_client(&failure);
    let args = match &action {
        StreamsAction::List => {
            render_json(&host.streams().map_err(failed)?, globals, trace)?;
            return Ok(ExitCode::SUCCESS);
        }
        StreamsAction::Frontier(args)
        | StreamsAction::Signers(args)
        | StreamsAction::Runs(args)
        | StreamsAction::Subscriptions(args)
        | StreamsAction::Gaps(args)
        | StreamsAction::Anchors(args) => args,
    };
    let stream = StreamName {
        plane: &args.plane,
        stream_type: &args.stream_type,
        resource: &args.resource,
    };
    match action {
        StreamsAction::List => {}
        StreamsAction::Frontier(_) => {
            render_json(
                &host.stream_frontier(&stream).map_err(failed)?,
                globals,
                trace,
            )?;
        }
        StreamsAction::Runs(_) => {
            let frontier = host.stream_frontier(&stream).map_err(failed)?;
            render_json(&runs_of(frontier), globals, trace)?;
        }
        StreamsAction::Signers(_) => {
            render_json(
                &host.stream_signers(&stream).map_err(failed)?,
                globals,
                trace,
            )?;
        }
        StreamsAction::Subscriptions(_) => {
            render_json(
                &host.stream_subscriptions(&stream).map_err(failed)?,
                globals,
                trace,
            )?;
        }
        StreamsAction::Gaps(_) => {
            render_json(&host.stream_gaps(&stream).map_err(failed)?, globals, trace)?;
        }
        StreamsAction::Anchors(_) => {
            render_json(
                &host.stream_anchors(&stream).map_err(failed)?,
                globals,
                trace,
            )?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// The run history `host streams runs` prints: every run of the frontier, the producer's then
/// each consumer's, with its role and what it holds (owner decision of 2026-10-17).
fn runs_of(frontier: permguard_host::api::streams::Frontier) -> serde_json::Value {
    let mut runs: Vec<serde_json::Value> = frontier
        .producer
        .into_iter()
        .map(|run| {
            serde_json::json!({
                "role": "producer",
                "run": run.run,
                "ended": run.ended,
                "last_seq": run.last_seq,
                "sealed": run.sealed,
                "acknowledged": run.acknowledged,
                "oldest_retained": run.low_watermark,
            })
        })
        .collect();
    runs.extend(frontier.consumer.into_iter().map(|run| {
        serde_json::json!({
            "role": "consumer",
            "producer": run.producer,
            "run": run.run,
            "acked": run.acked,
            "oldest_retained": run.oldest_retained,
        })
    }));
    serde_json::json!({ "resource": frontier.resource, "runs": runs })
}

fn render_json(value: &impl Serialize, globals: &Globals, trace: &Trace) -> Result<(), Failure> {
    let value = serde_json::to_value(value)
        .map_err(|error| Failure::internal(format!("rendering the Host answer: {error}")))?;
    render(&JsonReport(value), globals.output, trace)
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path, what: &str) -> Result<T, Failure> {
    let bytes = crate::confirm::read_bytes(Some(path), what, 1024 * 1024)?;
    permguard_host::api::decode_external_json(&bytes).map_err(|error| {
        // Serde may quote an unknown field name. These documents can carry invitations,
        // evidence and other secrets, so only the structural position crosses the trust
        // boundary into an operator-visible error.
        Failure::usage(format!(
            "{}: invalid {what} JSON at line {} column {}",
            path.display(),
            error.line(),
            error.column()
        ))
    })
}

fn rooted_file(globals: &Globals, path: &Path) -> std::path::PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        globals.workdir.join(path)
    }
}

fn verify_identity(
    identity: &permguard_host::api::IdentityView,
) -> Result<permguard_host::identity::Verified, Failure> {
    let decode = |text: &str| {
        URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| Failure::usage("the Host returned identity bytes that are not base64url"))
    };
    let document = decode(&identity.document)?;
    let first = decode(&identity.first_public_key)?;
    let successions = identity
        .successions
        .iter()
        .map(|item| decode(item))
        .collect::<Result<Vec<_>, _>>()?;
    permguard_host::identity::verify_published(&document, &successions, &first)
        .map_err(|error| Failure::usage(format!("the Host identity proof is invalid: {error}")))
}

/// The Host-to-Host session endpoint corresponding to an administrative Host endpoint.
fn peer_address(address: &str) -> Result<String, Failure> {
    if let Some(authority) = address.strip_prefix("grpcs://") {
        return Ok(format!("https://{authority}"));
    }
    if address.starts_with("https://") {
        return Ok(address.to_owned());
    }
    Err(Failure::usage(
        "the Host endpoint has no canonical HTTPS peer-session address",
    ))
}

fn members(globals: &Globals, action: MembersAction, trace: &Trace) -> Result<ExitCode, Failure> {
    use permguard_control_client::host::Change;
    use permguard_host::api::members::{
        ApproveMember, AssuranceOffer, CreateInvite, JoinMembership, PlanMemberRevoke,
        RunMemberRevoke, TaskView, VerifyMember,
    };

    match action {
        MembersAction::Invite { action } => match action {
            InviteAction::Create {
                selector,
                tasks,
                expires,
                expect_fingerprint,
                min_assurance,
            } => {
                let tasks: Vec<TaskView> =
                    read_json(&rooted_file(globals, &tasks), "membership tasks")?;
                let backend = online_host(globals, trace, false)?;
                let identity = backend
                    .identity()
                    .map_err(|failure| Failure::from_client(&failure))?;
                let verified = verify_identity(&identity)?;
                let created = backend
                    .create_invite(&CreateInvite {
                        request_id: request_id(),
                        selector: selector.clone(),
                        tasks: tasks.clone(),
                        expires,
                        expected_fingerprint: expect_fingerprint,
                        min_assurance,
                        max_uses: 1,
                    })
                    .map_err(|failure| Failure::from_client(&failure))?;
                let store = crate::session::open_store(globals, trace)?;
                let address = crate::session::resolve_endpoint_url(
                    "host.endpoint",
                    globals.host_endpoint.as_deref(),
                    &store,
                    trace,
                )?;
                let address = peer_address(&address)?;
                render_json(
                    &InvitationHandoff {
                        version: 1,
                        coordinator: permguard_host::api::members::CoordinatorView {
                            address,
                            host_id: permguard_host::identity::record::uuid_text(&verified.host_id),
                            fingerprint: verified.first_fingerprint().to_owned(),
                        },
                        invite_id: created.invite_id,
                        token: created.token,
                        requested: permguard_host::api::members::NarrowView { selector, tasks },
                        expires: created.expires,
                    },
                    globals,
                    trace,
                )?;
            }
            InviteAction::List => {
                let answer = online_host(globals, trace, false)?
                    .invites()
                    .map_err(|failure| Failure::from_client(&failure))?;
                render_json(&answer, globals, trace)?;
            }
            InviteAction::Revoke { id } => {
                let answer = online_host(globals, trace, false)?
                    .delete_invite(&id, &request_id())
                    .map_err(|failure| Failure::from_client(&failure))?;
                render_json(&answer, globals, trace)?;
            }
        },
        MembersAction::Join {
            coordinator_url,
            pin_fingerprint,
        } => {
            // Resolve and classify both channels before opening the secret handoff. In
            // particular, a misspelled or clear-text target must not become an oracle for a
            // token file's existence or contents.
            let store = crate::session::open_store(globals, trace)?;
            let member_url = crate::session::resolve_endpoint_url(
                "host.endpoint",
                globals.host_endpoint.as_deref(),
                &store,
                trace,
            )?;
            require_verified_tls_endpoint(&member_url, globals.tls_skip_verify)?;
            require_verified_tls_endpoint(&coordinator_url, globals.tls_skip_verify)?;
            let token_file = globals.token_file.as_deref().ok_or_else(|| {
                Failure::usage("host members join reads its invitation handoff from --token-file")
            })?;
            let handoff: InvitationHandoff =
                read_json(&rooted_file(globals, token_file), "invitation handoff")?;
            if handoff.version != 1 {
                return Err(Failure::usage("the invitation handoff version is not 1"));
            }
            if handoff.coordinator.address != coordinator_url {
                return Err(Failure::usage(
                    "the coordinator URL differs from the invitation handoff",
                ));
            }
            let fingerprint = match pin_fingerprint {
                Some(fingerprint) => fingerprint,
                None => {
                    let pins = read_pin_store(&pin_store_path(&store))?;
                    let url = canonical_url(&coordinator_url)?;
                    pins.pins
                        .iter()
                        .find(|pin| pin.url == url && pin.host_id == handoff.coordinator.host_id)
                        .map(|pin| pin.fingerprint.clone())
                        .ok_or_else(|| {
                            Failure::usage(
                                "host members join needs --pin-fingerprint or an exact local pin \
                                 for the coordinator URL and Host id",
                            )
                        })?
                }
            };
            if handoff.coordinator.fingerprint != fingerprint {
                return Err(Failure::usage(
                    "the coordinator fingerprint differs from the invitation handoff",
                ));
            }
            let answer = online_host_with_store(globals, trace, &member_url, &store, true)?
                .join(&JoinMembership {
                    request_id: request_id(),
                    coordinator: handoff.coordinator,
                    invite_id: handoff.invite_id,
                    token: handoff.token,
                    requested: handoff.requested,
                })
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
        }
        MembersAction::Pending => {
            let answer = online_host(globals, trace, false)?
                .members(Some("pending"))
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
        }
        MembersAction::Approve {
            id,
            expected_revision,
            narrow,
            assurance_result,
        } => {
            let narrow = narrow
                .as_deref()
                .map(|path| read_json(&rooted_file(globals, path), "membership narrowing"))
                .transpose()?;
            let assurance: Option<AssuranceOffer> = assurance_result
                .as_deref()
                .map(|path| read_json(&rooted_file(globals, path), "assurance result"))
                .transpose()?;
            let answer = online_host(globals, trace, false)?
                .approve_member(
                    &id,
                    &ApproveMember {
                        request_id: request_id(),
                        expected_revision,
                        narrow,
                        lease_policy: None,
                        assurance,
                    },
                )
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
        }
        MembersAction::Reject(args) => change_member(globals, trace, Change::Reject, args)?,
        MembersAction::Suspend(args) => change_member(globals, trace, Change::Suspend, args)?,
        MembersAction::Resume(args) => change_member(globals, trace, Change::Resume, args)?,
        MembersAction::Fence(args) => change_member(globals, trace, Change::Fence, args)?,
        MembersAction::List => {
            let answer = online_host(globals, trace, false)?
                .members(None)
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
        }
        MembersAction::Get { id } => {
            let answer = online_host(globals, trace, false)?
                .member(&id)
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
        }
        MembersAction::Revoke { action } => match action {
            MemberRevokeAction::Plan {
                id,
                reason,
                expected_revision,
                out,
            } => {
                let answer = online_host(globals, trace, false)?
                    .plan_member_revoke(
                        &id,
                        &PlanMemberRevoke {
                            request_id: request_id(),
                            reason,
                            expected_revision,
                        },
                    )
                    .map_err(|failure| Failure::from_client(&failure))?;
                write_new(
                    &rooted_file(globals, &out),
                    &serde_json::to_vec_pretty(&answer).map_err(Failure::internal)?,
                )?;
                render_json(&answer, globals, trace)?;
            }
            MemberRevokeAction::Run { id, confirm_file } => {
                let plan: permguard_host::api::Planned = read_json(
                    &rooted_file(globals, &confirm_file),
                    "membership revocation plan",
                )?;
                let answer = online_host(globals, trace, false)?
                    .run_member_revoke(
                        &id,
                        &RunMemberRevoke {
                            request_id: request_id(),
                            receipt: plan.receipt,
                        },
                    )
                    .map_err(|failure| Failure::from_client(&failure))?;
                render_json(&answer, globals, trace)?;
            }
        },
        MembersAction::Sessions { id } => {
            let backend = online_host(globals, trace, false)?;
            if let Some(id) = id {
                let answer = backend
                    .member_sessions(&id)
                    .map_err(|failure| Failure::from_client(&failure))?;
                render_json(&answer, globals, trace)?;
            } else {
                let members = backend
                    .members(None)
                    .map_err(|failure| Failure::from_client(&failure))?;
                let mut all = BTreeMap::new();
                for member in members.members {
                    let sessions = backend
                        .member_sessions(&member.membership_id)
                        .map_err(|failure| Failure::from_client(&failure))?;
                    all.insert(member.membership_id, sessions);
                }
                render_json(&all, globals, trace)?;
            }
        }
        MembersAction::Verify { id } => {
            let answer = online_host(globals, trace, false)?
                .verify_member(
                    &id,
                    &VerifyMember {
                        request_id: request_id(),
                    },
                )
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)?;
        }
    }
    Ok(ExitCode::from(EXIT_READY))
}

fn change_member(
    globals: &Globals,
    trace: &Trace,
    change: permguard_control_client::host::Change,
    args: MemberChangeArgs,
) -> Result<(), Failure> {
    let answer = online_host(globals, trace, false)?
        .change_member(
            change,
            &args.id,
            &permguard_host::api::members::ChangeMember {
                request_id: request_id(),
                expected_revision: args.expected_revision,
                reason: Some(args.reason),
            },
        )
        .map_err(|failure| Failure::from_client(&failure))?;
    render_json(&answer, globals, trace)
}

fn grant_revoke(
    globals: &Globals,
    action: GrantRevokeAction,
    trace: &Trace,
) -> Result<(), Failure> {
    match action {
        GrantRevokeAction::Plan {
            grant_id,
            expected_revision,
            out,
        } => {
            let answer = online_host(globals, trace, false)?
                .plan_grant_revoke(
                    &grant_id,
                    &permguard_host::api::PlanRevoke {
                        request_id: request_id(),
                        expected_revision,
                    },
                )
                .map_err(|failure| Failure::from_client(&failure))?;
            write_new(
                &rooted_file(globals, &out),
                &serde_json::to_vec_pretty(&answer).map_err(Failure::internal)?,
            )?;
            render_json(&answer, globals, trace)
        }
        GrantRevokeAction::Run {
            grant_id,
            confirm_file,
        } => {
            let plan: permguard_host::api::Planned = read_json(
                &rooted_file(globals, &confirm_file),
                "grant revocation plan",
            )?;
            let answer = online_host(globals, trace, false)?
                .run_grant_revoke(
                    &grant_id,
                    &permguard_host::api::RunRevoke {
                        request_id: request_id(),
                        receipt: plan.receipt,
                    },
                )
                .map_err(|failure| Failure::from_client(&failure))?;
            render_json(&answer, globals, trace)
        }
    }
}

fn canonical_url(url: &str) -> Result<String, Failure> {
    let endpoint = permguard_control_client::Endpoint::parse(url).map_err(Failure::usage)?;
    let scheme = match (endpoint.is_grpc(), endpoint.is_tls()) {
        (false, false) => "http",
        (false, true) => "https",
        (true, false) => "grpc",
        (true, true) => "grpcs",
    };
    Ok(format!(
        "{scheme}://{}",
        endpoint.authority().to_lowercase()
    ))
}

fn pin_store_path(store: &crate::settings::Store) -> std::path::PathBuf {
    store
        .path()
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("host-pins.json")
}

fn read_pin_store(path: &Path) -> Result<PinStore, Failure> {
    let pins = if path.is_file() {
        read_json::<PinStore>(path, "Host identity pin store")?
    } else {
        PinStore {
            version: 1,
            pins: Vec::new(),
        }
    };
    if pins.version != 1 {
        return Err(Failure::usage(
            "the Host identity pin store version is not 1",
        ));
    }
    Ok(pins)
}

fn pin(globals: &Globals, action: PinAction, trace: &Trace) -> Result<(), Failure> {
    let store = crate::session::open_store(globals, trace)?;
    let path = pin_store_path(&store);
    let mut pins = read_pin_store(&path)?;
    match action {
        PinAction::Add {
            url,
            host_id,
            fingerprint,
        } => {
            let url = canonical_url(&url)?;
            format!("{host_id} {fingerprint}")
                .parse::<permguard_core::peer::PinnedPeer>()
                .map_err(Failure::usage)?;
            if let Some(existing) = pins
                .pins
                .iter()
                .find(|pin| pin.url == url && pin.host_id == host_id)
            {
                if existing.fingerprint != fingerprint {
                    return Err(Failure::usage(
                        "that endpoint and Host id are pinned to a different fingerprint",
                    ));
                }
            } else {
                pins.pins.push(IdentityPin {
                    url,
                    host_id,
                    fingerprint,
                });
                pins.pins.sort_by(|left, right| {
                    (&left.url, &left.host_id).cmp(&(&right.url, &right.host_id))
                });
                write_pin_store(&path, &pins)?;
            }
            render_json(&pins, globals, trace)?;
        }
        PinAction::List => render_json(&pins, globals, trace)?,
        PinAction::Remove { url, host_id } => {
            let url = canonical_url(&url)?;
            let before = pins.pins.len();
            pins.pins
                .retain(|pin| !(pin.url == url && pin.host_id == host_id));
            if pins.pins.len() == before {
                return Err(Failure::usage("that endpoint and Host id are not pinned"));
            }
            write_pin_store(&path, &pins)?;
            render_json(&pins, globals, trace)?;
        }
    }
    Ok(())
}

fn write_pin_store(path: &Path, pins: &PinStore) -> Result<(), Failure> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .map_err(|error| Failure::unavailable(format!("creating the pin directory: {error}")))?;
    let directory = permguard_host::storage::Dir::open(parent)
        .map_err(|error| Failure::unavailable(format!("opening the pin directory: {error}")))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Failure::usage("the Host identity pin store needs a UTF-8 file name"))?;
    let mut bytes = serde_json::to_vec_pretty(pins).map_err(Failure::internal)?;
    bytes.push(b'\n');
    permguard_host::storage::write::replace_bytes(&directory, name, &bytes)
        .map_err(|error| Failure::unavailable(format!("publishing {}: {error}", path.display())))
}

/// What an offline reset's plan step answers (WP-4.1, WP-3.9): the receipt it wrote binds the
/// Host, its epoch, the reason and every live membership at its revision.
#[derive(Debug, Serialize)]
struct ResetPlan {
    mode: String,
    host_id: String,
    epoch: u64,
    reason: String,
    memberships: Vec<ResetPlanned>,
    plan_id: String,
    plan_digest: String,
    /// RFC 3339.
    expires: String,
    /// The approvals the Host API must record before the run, under `operations.dual_control`.
    approvals_required: u64,
}

#[derive(Debug, Serialize)]
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

/// The mode an offline reset runs in: no coordinator is reached.
const RESET_MODE: &str = "emergency";

/// What a Host API refusal says, for a CLI failure.
fn refusal_text(refusal: &permguard_host::api::Refusal) -> String {
    refusal
        .error()
        .map_or_else(|| "denied".to_owned(), ToString::to_string)
}

impl Report for ResetPlan {
    fn render_terminal(&self, out: &mut dyn std::io::Write) -> std::io::Result<()> {
        writeln!(out, "Host identity reset planned (emergency, offline)")?;
        writeln!(out, "host_id   {}", self.host_id)?;
        writeln!(out, "epoch     {}", self.epoch)?;
        writeln!(out, "plan_id   {}", self.plan_id)?;
        writeln!(out, "digest    {}", self.plan_digest)?;
        writeln!(out, "expires   {}", self.expires)?;
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
        if self.approvals_required > 0 {
            writeln!(
                out,
                "The plan requires {} approval(s) before it runs, each by another holder of \
                 `identity.admin`: `POST /host/v1/plans/{}/approve` on the Host API.",
                self.approvals_required, self.plan_id
            )?;
        }
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

/// The plan of `held`'s state: its identity and every live membership, and the memberships as it
/// binds them, `<id>:<revision>` in id order. The receipt's fields are the plan step's to fill.
fn reset_plan(
    identity: &permguard_host::identity::Identity,
    store: &permguard_host::membership::Store,
    reason: String,
) -> (ResetPlan, String) {
    use permguard_host::membership::reset::{self as settle, Step};
    let planned = settle::plan(store);
    let plan = ResetPlan {
        mode: RESET_MODE.to_owned(),
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
        plan_id: String::new(),
        plan_digest: String::new(),
        expires: String::new(),
        approvals_required: 0,
    };
    (plan, settle::digest_target(&planned))
}

fn reset(
    globals: &Globals,
    server_config: Option<&Path>,
    action: ResetAction,
    trace: &Trace,
) -> Result<(), Failure> {
    let volume = volume_of(globals)?;
    use permguard_host::identity::{self, IdentityError};
    use permguard_host::membership::Store;

    let now = permguard_host::authz::store::now();
    let open_members = |held: &Volume| {
        Store::open(held)
            .map_err(|error| Failure::unavailable(format!("opening the memberships: {error}")))
    };
    match action {
        ResetAction::Plan { reason, out } => {
            use permguard_host::api::plans::{Issue, sign_plan};
            use permguard_host::operations::mutation::{Applied, Begin, Failure as Refused};
            use permguard_host::operations::plan::{IDENTITY_RESET, PlanSigner};

            if reason.is_empty() || reason.len() > 256 || reason.chars().any(char::is_control) {
                return Err(Failure::usage(
                    "--reason is printable text of 1 to 256 bytes",
                ));
            }
            let (_store, held) = open(&volume, trace)?;
            let config =
                permguard_server::offline::config(env!("CARGO_PKG_VERSION"), server_config)
                    .map_err(|error| Failure::usage(format!("--server-config: {error:#}")))?;
            let custodian = custodian(&held, server_config)?;
            let opened = open_identity(&held, server_config)?;
            let mutations =
                Mutations::open_offline_as(&held, env!("CARGO_PKG_VERSION"), Some(&opened))
                    .map_err(|error| {
                        Failure::unavailable(format!("opening the mutation journal: {error}"))
                    })?;
            let store = open_members(&held)?;
            mutations
                .recover(&identity::Identities(&opened))
                .and_then(|_| mutations.recover(&permguard_host::membership::Memberships(&store)))
                .map_err(|error| Failure::unavailable(format!("recovering: {error}")))?;
            let (mut plan, bound) = reset_plan(&opened, &store, reason);

            // The receipt is signed by the volume's `host.operations`, as the Host API's are.
            let time = std::sync::Arc::new(permguard_host::time::TimeGuard::system(
                config.time_max_clock_skew(),
            ));
            let rings = permguard_server::offline::rings(
                &config,
                &held,
                opened.host_id(),
                None,
                &custodian,
                time,
            )
            .map_err(|error| Failure::unavailable(format!("the key rings: {error:#}")))?;
            let signer = rings
                .iter()
                .find(|ring| ring.id() == permguard_host::keys::ring::HOST_OPERATIONS);
            let planner = Principal::new(INITIATOR)
                .map_err(|error| Failure::internal(format!("the planner: {error}")))?;
            let issued = sign_plan(
                signer.map(|ring| ring.as_ref() as &dyn PlanSigner),
                Issue {
                    kind: IDENTITY_RESET,
                    internal: IDENTITY_RESET,
                    stored_target: format!("{RESET_MODE}\n{bound}"),
                    target: opened.host_id_text(),
                    revision: opened.epoch(),
                    parameters: &[
                        ("mode", RESET_MODE),
                        ("memberships", bound.as_str()),
                        ("reason", plan.reason.as_str()),
                    ],
                    principal: &planner,
                },
                opened.host_id(),
                config
                    .assurance()
                    .requires(permguard_core::assurance::Control::OperationsDualControl),
                now,
            )
            .map_err(|refusal| {
                // A ring is given its first key by the server's start, which records it: never
                // here.
                let remedy = if signer.is_some() {
                    "start the server once, which activates the ring's first key and records it"
                } else {
                    "configure `operations.keys` in the server's configuration, \
                     `--server-config <file>`"
                };
                Failure::unavailable(format!("{}: {remedy}", refusal_text(&refusal)))
            })?;

            // The plans store the Host API reads, approvals included; then the receipt file, so
            // an `--out` already there records nothing; then the plan.
            let replay = open_plans(&held, &mutations, now)?;
            write_new(&out, &issued.envelope)?;
            let target = Some(format!("reset:{}", opened.host_id_text()));
            let recorded = mutations.run(
                Begin {
                    domain: identity::DOMAIN,
                    operation: identity::reset::RESET_PLAN,
                    action: identity::reset::AUDIT_RESET_PLANNED,
                    initiator: Initiator::System(INITIATOR.to_owned()),
                    request: None,
                    target: target.clone(),
                },
                |applying| {
                    replay
                        .plan(applying, issued.plan.clone())
                        .map_err(|refusal| Refused::Refused(refusal_text(&refusal)))?;
                    Ok(Applied {
                        revision: opened.epoch(),
                        target,
                        value: (),
                    })
                },
            );
            if let Err(error) = recorded {
                let _ = std::fs::remove_file(&out);
                return Err(Failure::unavailable(format!("recording the plan: {error}")));
            }
            plan.plan_id = issued.plan.plan_id.clone();
            plan.plan_digest = issued.plan_digest;
            plan.expires = permguard_host::api::grants::rfc3339(issued.expires);
            plan.approvals_required = issued.approvals_required;
            trace.say(format!("plan receipt written to {}", out.display()));
            render(&plan, globals.output, trace)?;
            std::mem::forget(held);
        }
        ResetAction::Run { confirm_file } => {
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
            let receipt = crate::confirm::read_bytes(
                confirm_file.as_deref(),
                "reset receipt",
                permguard_host::operations::plan::MAX_ENVELOPE_BYTES,
            )?;
            let opened = std::sync::Arc::new(
                open_identity(&held, server_config)?.with_provisioner(provisioner),
            );
            // One audit engine for the mutations and the checkpoints the reset seals (WP-4.9).
            let audit = std::sync::Arc::new(audit_offline(&held, &opened, Some(&time))?);
            let mutations = Mutations::open(
                &held,
                std::sync::Arc::clone(&audit)
                    as std::sync::Arc<dyn permguard_host::operations::mutation::Projection>,
                std::sync::Arc::clone(&time),
            )
            .map_err(|error| {
                Failure::unavailable(format!("opening the mutation journal: {error}"))
            })?;
            let store = open_members(&held)?;
            mutations
                .recover(&identity::Identities(&opened))
                .and_then(|_| mutations.recover(&permguard_host::membership::Memberships(&store)))
                .map_err(|error| Failure::unavailable(format!("recovering: {error}")))?;

            // The receipt the plan step wrote, held in the plans store, neither run nor expired,
            // its approvals given; the volume as it bound it.
            let replay = open_plans(&held, &mutations, now)?;
            let planner = Principal::new(INITIATOR)
                .map_err(|error| Failure::internal(format!("the planner: {error}")))?;
            let plan = permguard_host::api::plans::held_plan(&replay, &planner, &receipt, now)
                .map_err(|refusal| {
                    Failure::usage(format!(
                        "--confirm-file {}: {}",
                        confirm_file
                            .as_deref()
                            .map(Path::display)
                            .map(|shown| shown.to_string())
                            .unwrap_or_default(),
                        refusal_text(&refusal)
                    ))
                })?;
            let bound = plan
                .target
                .strip_prefix(RESET_MODE)
                .and_then(|rest| rest.strip_prefix('\n'));
            let (_, current) = reset_plan(&opened, &store, String::new());
            match bound {
                Some(bound)
                    if plan.kind == permguard_host::operations::plan::IDENTITY_RESET
                        && plan.operation == permguard_host::operations::plan::IDENTITY_RESET =>
                {
                    if plan.revision != opened.epoch() || bound != current {
                        return Err(Failure::usage(
                            "the identity or its memberships changed since the plan: plan again",
                        ));
                    }
                }
                _ => {
                    return Err(Failure::usage(
                        "--confirm-file is not an offline reset's receipt",
                    ));
                }
            }
            // Spent before anything changes: an interrupted reset completes without it.
            permguard_host::api::plans::consume_plan(&mutations, &replay, &planner, &plan)
                .map_err(|error| Failure::unavailable(format!("consuming the plan: {error}")))?;
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
            // The trails sealed under `host.operations` before it retires with the identity: a
            // reset requires that recovery checkpoint, so a volume without the ring is refused
            // before the identity or a membership changes (WP-4.9).
            let signer = rings
                .iter()
                .find(|ring| ring.id() == permguard_host::keys::ring::HOST_OPERATIONS)
                .ok_or_else(|| {
                    Failure::unavailable(
                        "no host.operations ring: a reset requires a recovery audit checkpoint; \
                         the identity and its memberships are unchanged, plan again",
                    )
                })?;
            audit.seal_with(std::sync::Arc::clone(signer)
                as std::sync::Arc<
                    dyn permguard_host::audit::checkpoint::CheckpointSigner,
                >);
            let evidence = || -> Result<(), String> {
                let sealed = audit.checkpoint_all().map_err(|error| error.to_string())?;
                trace.say(format!("{} audit checkpoint(s) sealed", sealed.len()));
                Ok(())
            };
            let done = permguard_host::membership::reset::emergency(
                &store,
                &mutations,
                &opened,
                &rings,
                &Initiator::System(INITIATOR.to_owned()),
                now,
                &evidence,
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

/// The plans store of `held`, its operations a crash left open resolved.
fn open_plans(
    held: &Volume,
    mutations: &Mutations,
    now: u64,
) -> Result<permguard_host::api::Replay, Failure> {
    let (replay, _) = permguard_host::api::Replay::open(held, now)
        .map_err(|error| Failure::unavailable(format!("opening the plans: {error}")))?;
    mutations
        .recover(&replay)
        .map_err(|error| Failure::unavailable(format!("recovering the plans: {error}")))?;
    Ok(replay)
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
    time: Option<&std::sync::Arc<permguard_host::time::TimeGuard>>,
) -> Result<permguard_host::audit::Engine, Failure> {
    // The guard the command's other engines share, when it has one.
    let time = time.map_or_else(
        || {
            std::sync::Arc::new(permguard_host::time::TimeGuard::system(
                std::time::Duration::from_secs(30),
            ))
        },
        std::sync::Arc::clone,
    );
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

#[cfg(test)]
mod wp_4_8_tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn the_independent_host_cli_vector_matches_the_closed_private_shapes() {
        let vector: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../contracts/vectors/host-cli.json"
        )))
        .expect("the independent vector is JSON");
        let handoff: InvitationHandoff =
            serde_json::from_value(vector["invitation_handoff"].clone())
                .expect("the invitation handoff has the closed versioned shape");
        let pins: PinStore = serde_json::from_value(vector["pin_store"].clone())
            .expect("the pin store has the closed versioned shape");
        let tasks: Vec<permguard_host::api::members::TaskView> =
            serde_json::from_value(vector["membership_tasks"].clone())
                .expect("the independent tasks have the closed non-empty shape");
        let narrow: permguard_host::api::members::NarrowView =
            serde_json::from_value(vector["membership_narrowing"].clone())
                .expect("the independent narrowing has the closed non-empty shape");
        let assurance: permguard_host::api::members::AssuranceOffer =
            serde_json::from_value(vector["assurance_result"].clone())
                .expect("the independent assurance result has approvals and evidence");

        assert_eq!(handoff.version, 1);
        assert_eq!(pins.version, 1);
        assert_eq!(pins.pins.len(), 1);
        assert!(!tasks.is_empty());
        assert_eq!(narrow.tasks, tasks);
        assert!(!assurance.approvals.is_empty());
        assert!(!assurance.evidence.is_empty());
        assert_eq!(handoff.requested, narrow);
        assert_eq!(handoff.coordinator.host_id, pins.pins[0].host_id);
        assert_eq!(handoff.coordinator.fingerprint, pins.pins[0].fingerprint);
        for (bytes, digest, shape) in [
            (
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../contracts/vectors/host-cli-tasks.json"
                ))
                .as_slice(),
                "sha256:b52bb2c65a2ef1402be6a0e30748b192bbf6f5aa9fab606679e4479bbb298fc1",
                &vector["membership_tasks"],
            ),
            (
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../contracts/vectors/host-cli-narrow.json"
                ))
                .as_slice(),
                "sha256:40ae5fb8f2e0da8cda987a9be7d931f2cf94047b7130e23bfc8bb8b0d90f8676",
                &vector["membership_narrowing"],
            ),
            (
                include_bytes!(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../contracts/vectors/host-cli-assurance-result.json"
                ))
                .as_slice(),
                "sha256:b2a0f2573f90d09b8c8c325cb5bd862f608fbd7ccd3656467f4eea6f1e62208d",
                &vector["assurance_result"],
            ),
        ] {
            assert_eq!(
                permguard_objects::digest::Digest::compute(bytes).to_string(),
                digest,
                "the independently generated fixture bytes stay exact"
            );
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(bytes).expect("fixture JSON"),
                *shape,
                "the standalone fixture and aggregate vector have one shape"
            );
        }
        for case in vector["coordinator_addresses"]
            .as_array()
            .expect("coordinator address cases")
        {
            let actual = match peer_address(case["administration"].as_str().expect("an admin URL"))
            {
                Ok(address) => address,
                Err(_) => panic!("the admin URL has a canonical peer URL"),
            };
            assert_eq!(actual, case["peer"].as_str().expect("a peer URL"));
        }
        for (name, malformed) in vector["unknown_nested_fields"]
            .as_object()
            .expect("the independent malformed cases")
        {
            let refused = match name.as_str() {
                "tasks_limits" => serde_json::from_value::<
                    Vec<permguard_host::api::members::TaskView>,
                >(malformed.clone())
                .is_err(),
                "narrowing_task" => serde_json::from_value::<
                    permguard_host::api::members::NarrowView,
                >(malformed.clone())
                .is_err(),
                "assurance_approval" | "assurance_evidence" => serde_json::from_value::<
                    permguard_host::api::members::AssuranceOffer,
                >(malformed.clone())
                .is_err(),
                other => panic!("an unknown malformed golden case `{other}`"),
            };
            assert!(refused, "the nested unknown field in `{name}` is refused");
        }
    }
}
