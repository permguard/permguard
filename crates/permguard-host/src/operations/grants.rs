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

    fn observe(
        &self,
        _operation_id: &OperationId,
        _target: Option<&str>,
    ) -> Result<Option<Observed>, String> {
        Ok(self.0.bootstrap().map(|held| Observed {
            revision: 1,
            target: Some(held.principal.as_str().to_owned()),
        }))
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

/// The development operator a provisioned volume hands out, `certificate_pem`, committed as the
/// bootstrap principal when the volume commits none (BUG-0066): the client certificate
/// `autogenerate` wrote acts, where it otherwise maps to nobody. Answers the commitment, or `None`
/// when one is held already, for this certificate or another: a commitment is never replaced.
pub fn bootstrap_development_operator(
    mutations: &Mutations,
    store: &BootstrapStore,
    certificate_pem: &[u8],
    now: u64,
) -> Result<Option<Bootstrap>, MutationError<AuthzError>> {
    if store.bootstrap().is_some() {
        return Ok(None);
    }
    let fingerprint = crate::authz::store::certificate_fingerprint(certificate_pem)
        .map_err(MutationError::Refused)?;
    bootstrap(mutations, store, &fingerprint, now).map(|(held, _)| Some(held))
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::storage::volume::Volume;

    fn pem_of(der: &[u8]) -> Vec<u8> {
        use base64::Engine as _;
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
        .into_bytes()
    }

    /// BUG-0066: a provisioned volume's operator certificate is committed as the bootstrap
    /// principal, by the SHA-256 of its DER, once; a held commitment is never replaced.
    #[test]
    fn the_development_operator_is_committed_once_and_never_replaces_a_commitment() {
        let root = std::env::temp_dir().join(format!(
            "permguard-grants-operator-{}-{}",
            std::process::id(),
            permguard_core::time::unix_now()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("the root");
        let volume = Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let mutations = Mutations::open_offline(&volume, "test").expect("the journal");
        let store = BootstrapStore::open(&volume).expect("the store");

        let committed =
            bootstrap_development_operator(&mutations, &store, &pem_of(b"operator"), 1_800_000_000)
                .expect("committed")
                .expect("a commitment");
        let expected = {
            use sha2::Digest as _;
            permguard_core::encoding::hex(&sha2::Sha256::digest(b"operator"))
        };
        assert_eq!(
            committed.principal.as_str(),
            format!("cert:sha256:{expected}")
        );
        assert_eq!(
            store.bootstrap().map(|held| held.principal),
            Some(committed.principal.clone())
        );
        assert_eq!(
            bootstrap_development_operator(&mutations, &store, &pem_of(b"another"), 1_800_000_001)
                .expect("answered"),
            None,
            "a commitment is never replaced"
        );
        assert!(
            bootstrap_development_operator(&mutations, &store, b"not pem", 1)
                .expect("answered")
                .is_none(),
            "held already: the file is not even read"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_without_a_certificate_has_no_fingerprint() {
        for pem in [
            &b"not pem"[..],
            b"-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----",
        ] {
            assert!(crate::authz::store::certificate_fingerprint(pem).is_err());
        }
    }
}
