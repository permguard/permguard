// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The recovery principal's commitment as a domain of the mutation engine (WP-3.6): the offline
//! `permguard host grants bootstrap`, audited as every security mutation is.
//!
//! | Operation          | Initiator   | Audit action                |
//! | ------------------ | ----------- | --------------------------- |
//! | `grants.bootstrap` | `bootstrap` | `host.bootstrap.committed`  |

use super::journal::{Initiator, OperationId};
use super::mutation::{
    Applied, Begin, Domain, Failure, MutationError, Mutations, Observed, Outcome,
};
use crate::authz::{AuthzError, Bootstrap, BootstrapStore};

/// The domain name intents carry.
pub const DOMAIN: &str = "grants";

/// The operation.
pub const BOOTSTRAP: &str = "grants.bootstrap";

/// The `security` audit action its records carry.
pub const AUDIT_COMMITTED: &str = "host.bootstrap.committed";

/// The bootstrap store, as recovery sees it: a commitment written is the operation applied.
pub struct Grants<'a>(pub &'a BootstrapStore);

impl Domain for Grants<'_> {
    fn name(&self) -> &'static str {
        DOMAIN
    }

    fn observe(&self, _operation_id: &OperationId, _target: Option<&str>) -> Option<Observed> {
        self.0.bootstrap().map(|held| Observed {
            revision: 1,
            target: Some(held.principal.as_str().to_owned()),
        })
    }
}

/// How a bootstrap store error ends an operation: a storage failure may have written the file,
/// which leaves the intent for recovery; anything else is a refusal before any write.
pub fn failure<E>(error: AuthzError, render: impl FnOnce(AuthzError) -> E) -> Failure<E> {
    match error {
        AuthzError::Storage(_) => Failure::Indeterminate(render(error)),
        other => Failure::Refused(render(other)),
    }
}

/// Writes the bootstrap commitment once, as one operation. A bootstrap already done for the same
/// certificate is answered without an operation; one for another certificate is refused.
pub fn bootstrap(
    mutations: &Mutations,
    store: &BootstrapStore,
    fingerprint: &str,
    now: u64,
) -> Result<(Bootstrap, bool), MutationError<AuthzError>> {
    let wanted =
        crate::authz::store::bootstrap_principal(fingerprint).map_err(MutationError::Refused)?;
    if let Some(held) = store.bootstrap() {
        if held.principal == wanted {
            return Ok((held, false));
        }
        return Err(MutationError::Refused(AuthzError::Invalid(format!(
            "the volume already commits to the recovery principal `{}`; a bootstrap is written once",
            held.principal
        ))));
    }
    let mut committed = None;
    let outcome = mutations.run(
        Begin {
            domain: DOMAIN,
            operation: BOOTSTRAP,
            action: AUDIT_COMMITTED,
            initiator: Initiator::System("bootstrap".to_owned()),
            request: None,
            target: Some(wanted.as_str().to_owned()),
        },
        |applying| {
            let (held, written) = store
                .commit(applying, fingerprint, now)
                .map_err(|error| failure(error, |error| error))?;
            tracing::info!(
                event.name = "authz.bootstrap",
                component = "host",
                fingerprint = %held.fingerprint,
                written,
                "the recovery principal is committed"
            );
            let applied = Applied {
                revision: 1,
                target: Some(held.principal.as_str().to_owned()),
                value: (),
            };
            committed = Some((held, written));
            Ok(applied)
        },
    )?;
    match (outcome, committed) {
        (Outcome::Applied(()), Some(held)) => Ok(held),
        _ => Err(MutationError::Unrecorded(
            "the bootstrap answered without applying".to_owned(),
        )),
    }
}
