// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The grant store as a domain of the mutation engine (WP-3.6), and the grant operations that
//! do not come through the Host API: the offline CLI, the expiry the Host writes and the
//! recovery administrator's bootstrap.
//!
//! | Operation          | Initiator                 | Audit action               |
//! | ------------------ | ------------------------- | -------------------------- |
//! | `grants.create`    | the principal, or the CLI | `host.grant.issued`        |
//! | `grants.revoke.plan` | the principal           | `host.grant.revoke_planned` |
//! | `grants.revoke.run`  | the principal           | `host.grant.revoked`       |
//! | `grants.revoke`    | the CLI                   | `host.grant.revoked`       |
//! | `grants.expire`    | `expiry`                  | `host.grant.expired`       |
//! | `grants.bootstrap` | `bootstrap`               | `host.grant.issued`        |

use super::journal::{Initiator, OperationId};
use super::mutation::{
    Applied, Begin, Domain, Failure, MutationError, Mutations, Observed, Outcome,
};
use crate::authz::{
    AuthzError, Bootstrap, GrantId, GrantRecord, GrantStore, Issue, validate_issue,
};

/// The domain name intents carry.
pub const DOMAIN: &str = "grants";

/// The operations.
pub const CREATE: &str = "grants.create";
pub const REVOKE_PLAN: &str = "grants.revoke.plan";
pub const REVOKE_RUN: &str = "grants.revoke.run";
pub const REVOKE: &str = "grants.revoke";
pub const EXPIRE: &str = "grants.expire";
pub const BOOTSTRAP: &str = "grants.bootstrap";

/// The `security` audit actions their records carry.
pub const AUDIT_ISSUED: &str = "host.grant.issued";
pub const AUDIT_REVOKE_PLANNED: &str = "host.grant.revoke_planned";
pub const AUDIT_REVOKED: &str = "host.grant.revoked";
pub const AUDIT_EXPIRED: &str = "host.grant.expired";

/// The grant store, as recovery sees it.
pub struct Grants<'a>(pub &'a GrantStore);

impl Domain for Grants<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, operation_id: &OperationId, _target: Option<&str>) -> Option<Observed> {
        self.0
            .operation(operation_id)
            .map(|(revision, grant_id)| Observed {
                revision,
                target: Some(grant_id.to_string()),
            })
    }
}

/// How a grant store error ends an operation: a journal or record failure may have written
/// the frame, which the journal keeps after a restart when its failure was not recorded, so it
/// leaves the intent for recovery; anything else is a refusal before any write.
pub fn failure<E>(error: AuthzError, render: impl FnOnce(AuthzError) -> E) -> Failure<E> {
    match error {
        AuthzError::Storage(_) | AuthzError::Record(_) => Failure::Indeterminate(render(error)),
        other => Failure::Refused(render(other)),
    }
}

/// Issues `issue` as `initiator`, with no request id: the offline CLI. A request the store would
/// never write is refused before the operation begins.
pub fn issue(
    mutations: &Mutations,
    store: &GrantStore,
    initiator: Initiator,
    issue: Issue,
    now: u64,
) -> Result<GrantRecord, MutationError<AuthzError>> {
    validate_issue(&issue, now).map_err(MutationError::Refused)?;
    one(
        mutations,
        Begin {
            domain: DOMAIN,
            operation: CREATE,
            action: AUDIT_ISSUED,
            initiator,
            request: None,
            target: None,
        },
        |applying| store.issue(applying, issue, now, None),
    )
}

/// Revokes `grant_id` as `initiator`, recording `by` in the transition, with no request id and
/// no plan: the offline CLI.
pub fn revoke(
    mutations: &Mutations,
    store: &GrantStore,
    initiator: Initiator,
    grant_id: GrantId,
    by: &str,
    now: u64,
) -> Result<GrantRecord, MutationError<AuthzError>> {
    one(
        mutations,
        Begin {
            domain: DOMAIN,
            operation: REVOKE,
            action: AUDIT_REVOKED,
            initiator,
            request: None,
            target: Some(grant_id.to_string()),
        },
        |applying| store.revoke(applying, grant_id, by, now, None),
    )
}

/// What [`expire_due`] wrote, and what it could not.
#[derive(Debug, Default)]
pub struct Expiry {
    pub expired: Vec<GrantId>,
    /// The grants whose expiry is not written, with why: they allow nothing all the same, since
    /// a grant past its time is not active, and their expiry is written at the next pass.
    pub unwritten: Vec<(GrantId, String)>,
}

/// Writes the expiry of every active grant past its time at `now`, one operation each. A grant
/// whose expiry cannot be written does not stop the others.
pub fn expire_due(mutations: &Mutations, store: &GrantStore, now: u64) -> Expiry {
    let mut expiry = Expiry::default();
    for grant_id in store.due(now) {
        let written = one(
            mutations,
            Begin {
                domain: DOMAIN,
                operation: EXPIRE,
                action: AUDIT_EXPIRED,
                initiator: Initiator::System("expiry".to_owned()),
                request: None,
                target: Some(grant_id.to_string()),
            },
            |applying| store.expire(applying, grant_id, now),
        );
        match written {
            Ok(_) => expiry.expired.push(grant_id),
            Err(error) => expiry.unwritten.push((grant_id, error.to_string())),
        }
    }
    if !expiry.unwritten.is_empty() {
        tracing::warn!(
            event.name = "authz.expiry_unwritten",
            component = "host",
            unwritten = expiry.unwritten.len(),
            "the expiry of grants past their time was not written; they allow nothing meanwhile"
        );
    }
    expiry
}

/// Writes the bootstrap commitment once and issues the recovery administrator's grant,
/// `authz.admin` on `host`, when the committed principal holds none: one operation, the
/// commitment included. A bootstrap already done, the same principal committed and holding the
/// grant, is answered without an operation.
pub fn bootstrap(
    mutations: &Mutations,
    store: &GrantStore,
    fingerprint: &str,
    now: u64,
) -> Result<(Bootstrap, Option<GrantRecord>), MutationError<AuthzError>> {
    let wanted =
        crate::authz::store::bootstrap_principal(fingerprint).map_err(MutationError::Refused)?;
    if let Some(held) = store.bootstrap()
        && held.principal == wanted
        && store.recovery_issue(&held, now).is_none()
    {
        return Ok((held, None));
    }
    let mut committed = None;
    let mut issued = None;
    let outcome = mutations.run(
        Begin {
            domain: DOMAIN,
            operation: BOOTSTRAP,
            action: AUDIT_ISSUED,
            initiator: Initiator::System("bootstrap".to_owned()),
            request: None,
            target: None,
        },
        |applying| {
            let (held, written) = store
                .commit_bootstrap(applying, fingerprint, now)
                .map_err(|error| failure(error, |error| error))?;
            let revision = store.revision();
            let applied = match store.recovery_issue(&held, now) {
                Some(issue) => {
                    let record = store
                        .issue(applying, issue, now, None)
                        .map_err(|error| failure(error, |error| error))?;
                    let applied = Applied {
                        revision: record.revision,
                        target: Some(record.grant_id.to_string()),
                        value: (),
                    };
                    issued = Some(record);
                    applied
                }
                None => Applied {
                    revision,
                    target: None,
                    value: (),
                },
            };
            tracing::info!(
                event.name = "authz.bootstrap",
                component = "host",
                fingerprint = %held.fingerprint,
                written,
                granted = issued.is_some(),
                "the recovery administrator is committed"
            );
            committed = Some(held);
            Ok(applied)
        },
    )?;
    match (outcome, committed) {
        (Outcome::Applied(()), Some(held)) => Ok((held, issued)),
        _ => Err(MutationError::Unrecorded(
            "the bootstrap answered without applying".to_owned(),
        )),
    }
}

/// Runs one grant operation that no caller retries, answering the record it left.
fn one(
    mutations: &Mutations,
    begin: Begin,
    apply: impl FnOnce(&super::mutation::Applying<'_>) -> Result<GrantRecord, AuthzError>,
) -> Result<GrantRecord, MutationError<AuthzError>> {
    let mut left = None;
    let outcome = mutations.run(begin, |applying| {
        let record = apply(applying).map_err(|error| failure(error, |error| error))?;
        let applied = Applied {
            revision: record.revision,
            target: Some(record.grant_id.to_string()),
            value: (),
        };
        left = Some(record);
        Ok(applied)
    })?;
    match (outcome, left) {
        (Outcome::Applied(()), Some(record)) => Ok(record),
        _ => Err(MutationError::Unrecorded(
            "an operation with no request id answered without applying".to_owned(),
        )),
    }
}
