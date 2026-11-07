// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's directory as a domain of the mutation engine (WP-8.1): every change to a role, a
//! member, a local user or a link is one security mutation, journaled, audited and recovered
//! after a crash like a grant's.
//!
//! | Operation                           | Audit action                    |
//! | ----------------------------------- | ------------------------------- |
//! | `directory.role.create`             | `host.role.created`             |
//! | `directory.role.update`             | `host.role.updated`             |
//! | `directory.role.delete`             | `host.role.deleted`             |
//! | `directory.member.add`              | `host.member.added`             |
//! | `directory.member.remove`           | `host.member.removed`           |
//! | `directory.user.create`             | `host.user.created`             |
//! | `directory.user.update`             | `host.user.updated`             |
//! | `directory.user.password`           | `host.user.password_set`        |
//! | `directory.user.factor`             | `host.user.factor_set`          |
//! | `directory.user.status`             | `host.user.status_set`          |
//! | `directory.user.link`               | `host.user.linked`              |
//! | `directory.user.unlink`             | `host.user.unlinked`            |
//! | `directory.user.delete`             | `host.user.deleted`             |
//! | `directory.service_account.create`  | `iam.service_account.created`   |
//! | `directory.service_account.update`  | `iam.service_account.updated`   |
//! | `directory.service_account.suspend` | `iam.service_account.suspended` |
//! | `directory.service_account.resume`  | `iam.service_account.resumed`   |
//! | `directory.service_account.delete`  | `iam.service_account.deleted`   |
//! | `directory.credential.create`       | `iam.credential.created`        |
//! | `directory.credential.revoke`       | `iam.credential.revoked`        |
//!
//! A password, a factor, a client secret and a token never reach an audit record: the record names the operation
//! and the user, nothing of the secret.

use super::journal::Initiator;
use super::mutation::{Applied, Begin, Failure, MutationError, Mutations, Outcome};
use crate::authz::directory::{Change, Directory, DirectoryError, MUTATION_DOMAIN, Written};

/// The operation and the audit action of `change`.
pub fn names(change: &Change) -> (&'static str, &'static str) {
    match change {
        Change::CreateRole { .. } => ("directory.role.create", "host.role.created"),
        Change::UpdateRole { .. } => ("directory.role.update", "host.role.updated"),
        Change::DeleteRole { .. } => ("directory.role.delete", "host.role.deleted"),
        Change::AddMember { .. } => ("directory.member.add", "host.member.added"),
        Change::RemoveMember { .. } => ("directory.member.remove", "host.member.removed"),
        Change::CreateUser { .. } => ("directory.user.create", "host.user.created"),
        Change::UpdateUser { .. } => ("directory.user.update", "host.user.updated"),
        Change::SetPassword { .. } => ("directory.user.password", "host.user.password_set"),
        Change::SetFactor { .. } => ("directory.user.factor", "host.user.factor_set"),
        Change::SetStatus { .. } => ("directory.user.status", "host.user.status_set"),
        Change::Link { .. } => ("directory.user.link", "host.user.linked"),
        Change::Unlink { .. } => ("directory.user.unlink", "host.user.unlinked"),
        Change::DeleteUser { .. } => ("directory.user.delete", "host.user.deleted"),
        Change::CreateServiceAccount { .. } => (
            "directory.service_account.create",
            "iam.service_account.created",
        ),
        Change::UpdateServiceAccount { .. } => (
            "directory.service_account.update",
            "iam.service_account.updated",
        ),
        Change::SetAccountStatus { active: true, .. } => (
            "directory.service_account.resume",
            "iam.service_account.resumed",
        ),
        Change::SetAccountStatus { active: false, .. } => (
            "directory.service_account.suspend",
            "iam.service_account.suspended",
        ),
        Change::DeleteServiceAccount { .. } => (
            "directory.service_account.delete",
            "iam.service_account.deleted",
        ),
        Change::AddCredential { .. } => ("directory.credential.create", "iam.credential.created"),
        Change::RevokeCredential { .. } => {
            ("directory.credential.revoke", "iam.credential.revoked")
        }
    }
}

/// How a directory error ends an operation: a journal or record failure may have written the
/// frame, so it leaves the intent for recovery; anything else is a refusal before any write.
pub fn failure<E>(error: DirectoryError, render: impl FnOnce(DirectoryError) -> E) -> Failure<E> {
    match error {
        DirectoryError::Storage(_) | DirectoryError::Record(_) => {
            Failure::Indeterminate(render(error))
        }
        other => Failure::Refused(render(other)),
    }
}

/// Applies `change` as one operation of `initiator`, recording `by` in the transition, with no
/// request id: the CLI, a sign-in, the Host itself. The Host API runs its own, with the caller's
/// request id, through the same names.
pub fn change(
    mutations: &Mutations,
    directory: &Directory,
    initiator: Initiator,
    change: Change,
    by: &str,
    now: u64,
    expected_revision: Option<u64>,
) -> Result<Written, MutationError<DirectoryError>> {
    let (operation, action) = names(&change);
    let target = change.target().to_owned();
    let mut written = None;
    let outcome = mutations.run(
        Begin {
            domain: MUTATION_DOMAIN,
            operation,
            action,
            initiator,
            request: None,
            target: Some(target.clone()),
        },
        |applying| {
            let done = directory
                .apply(applying, change, by, now, expected_revision)
                .map_err(|error| failure(error, |error| error))?;
            written = Some(done);
            Ok(Applied {
                revision: done.revision,
                target: Some(target),
                value: (),
            })
        },
    )?;
    match (outcome, written) {
        (Outcome::Applied(()), Some(written)) => Ok(written),
        _ => Err(MutationError::Unrecorded(
            "a directory operation answered without applying".to_owned(),
        )),
    }
}
