// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host identity on the Host API (WP-2.2): `GET /host/v1/identity` under `identity.read`,
//! and `POST /host/v1/identity/rotate` under `identity.admin` (owner decision of 2026-10-08), a
//! security mutation of the domain `identity`. The reset arrives with the memberships (WP-11).
//!
//! Binary members are base64url without padding: the signed document and each succession record
//! as their COSE_Sign1 bytes, and the epoch-1 public key a peer pins the chain to (owner decision
//! of 2026-10-08).

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use permguard_core::authz::{Actor, operations};
use permguard_core::{ErrorClass, codes};

use super::{HostApi, Mutation, Receipt, Refusal};
use crate::identity::{self, Identity, IdentityError};
use crate::operations::mutation::{Applied, Failure};

/// `GET /host/v1/identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityView {
    /// The signed identity document of the current epoch, COSE_Sign1.
    pub document: String,
    /// Every succession record, oldest first, COSE_Sign1 each.
    pub successions: Vec<String>,
    /// The epoch-1 public key, the suite's raw bytes: what the first fingerprint pins.
    pub first_public_key: String,
    /// The protocol versions this Host speaks.
    pub protocol_versions: Vec<String>,
}

/// `POST /host/v1/identity/rotate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RotateIdentity {
    pub request_id: String,
    /// The epoch the caller read; the rotation produces the next one.
    pub expected_epoch: u64,
}

/// What a rotation answers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityRotated {
    /// The receipt; its revision is the new epoch.
    pub receipt: Receipt,
    /// The succession record to the new epoch, COSE_Sign1.
    pub succession: String,
}

impl HostApi {
    /// `GET /host/v1/identity`.
    pub fn identity(&self, actor: &Actor) -> Result<IdentityView, Refusal> {
        let _admitted = self.admit(actor, operations::IDENTITY_READ)?;
        let identity = self.host_identity()?;
        Ok(IdentityView {
            document: URL_SAFE_NO_PAD.encode(identity.document()),
            successions: identity
                .successions()
                .iter()
                .map(|record| URL_SAFE_NO_PAD.encode(record))
                .collect(),
            first_public_key: URL_SAFE_NO_PAD.encode(identity.first_public_key()),
            protocol_versions: identity::PROTOCOLS
                .iter()
                .map(|protocol| (*protocol).to_owned())
                .collect(),
        })
    }

    /// `POST /host/v1/identity/rotate`.
    pub async fn rotate_identity(
        &self,
        actor: &Actor,
        rotate: RotateIdentity,
    ) -> Result<IdentityRotated, Refusal> {
        let admitted = self.admit(actor, operations::IDENTITY_ADMIN)?;
        let identity = self.host_identity()?;
        let mutation = Mutation {
            request_id: rotate.request_id.clone(),
            expected_revision: Some(rotate.expected_epoch),
        };
        let expected = rotate.expected_epoch;
        let now = self.time.now_secs();
        let current = || {
            let epoch = identity.epoch();
            if epoch == expected {
                Ok(())
            } else {
                Err(Refusal::revision_mismatch(expected, epoch))
            }
        };
        self.transact(
            identity::DOMAIN,
            &admitted.principal,
            identity::ROTATE,
            identity::AUDIT_ROTATED,
            &mutation,
            &rotate,
            Some(format!("epoch:{}", expected.saturating_add(1))),
            current,
            |applying| {
                let rotated = identity
                    .rotate(applying, Some(expected), now)
                    .map_err(|error| match error {
                        IdentityError::Storage(_) | IdentityError::Indeterminate(_) => {
                            Failure::Indeterminate(refusal_of(error))
                        }
                        other => Failure::Refused(refusal_of(other)),
                    })?;
                Ok(Applied {
                    revision: rotated.epoch,
                    target: Some(format!("epoch:{}", rotated.epoch)),
                    value: IdentityRotated {
                        receipt: self.receipt(applying.operation_id(), rotated.epoch),
                        succession: URL_SAFE_NO_PAD.encode(&rotated.succession),
                    },
                })
            },
            |operation_id, epoch, _| {
                let record = usize::try_from(epoch.saturating_sub(2))
                    .ok()
                    .and_then(|index| identity.successions().get(index).cloned())
                    .ok_or_else(|| {
                        Refusal::new(
                            ErrorClass::Internal,
                            codes::host::MUTATION_UNRECORDED,
                            "the rotation was applied before a restart and its succession record \
                             is not held: read the identity before retrying",
                        )
                    })?;
                Ok(IdentityRotated {
                    receipt: self.receipt(operation_id, epoch),
                    succession: URL_SAFE_NO_PAD.encode(record),
                })
            },
        )
    }

    /// The Host identity, or the refusal a route without one answers.
    fn host_identity(&self) -> Result<&Identity, Refusal> {
        self.identity.as_deref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::host::IDENTITY_UNAVAILABLE,
                "no Host identity is open on this process",
            )
        })
    }
}

fn refusal_of(error: IdentityError) -> Refusal {
    match error {
        IdentityError::Conflict { expected, current } => {
            Refusal::revision_mismatch(expected, current)
        }
        other => Refusal::Api(
            permguard_core::ApiError::new(
                ErrorClass::Unavailable,
                codes::host::IDENTITY_UNAVAILABLE,
                "the Host identity could not rotate",
            )
            .with_internal(other.to_string()),
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::api::testing::{Recording, actor, admin, facade, reopen_with, scratch};
    use permguard_core::authz::Actor;

    fn rotate(request_id: &str, expected_epoch: u64) -> RotateIdentity {
        RotateIdentity {
            request_id: request_id.to_owned(),
            expected_epoch,
        }
    }

    #[test]
    fn the_identity_is_read_under_identity_read_and_verifies_from_its_first_key() {
        let api = facade("identity-read");
        assert!(matches!(
            api.identity(&actor("spiffe://acme/nobody")),
            Err(Refusal::Denied(_))
        ));
        assert!(matches!(
            api.identity(&Actor::Anonymous),
            Err(Refusal::Denied(_))
        ));
        let view = api.identity(&admin()).expect("read");
        let document = URL_SAFE_NO_PAD.decode(&view.document).expect("base64url");
        let first = URL_SAFE_NO_PAD
            .decode(&view.first_public_key)
            .expect("base64url");
        permguard_objects::cose::Sign1::decode(&document)
            .expect("decodes")
            .verify(
                crate::identity::Suite::Ed25519Sha256V1,
                &first,
                permguard_core::domains::protected::HOST_IDENTITY,
            )
            .expect("the epoch-1 document verifies under the first key");
        assert!(view.successions.is_empty());
        assert_eq!(
            view.protocol_versions,
            vec![permguard_core::domains::protected::HOST_SESSION.to_owned()]
        );
    }

    #[tokio::test]
    async fn a_rotation_needs_identity_admin_states_its_epoch_and_is_replayed() {
        let trail = std::sync::Arc::new(Recording::default());
        let (api, _, volume) = reopen_with(&scratch("identity-rotate"), Vec::new(), trail.clone());
        std::mem::forget(volume);
        let refused = api
            .rotate_identity(&actor("spiffe://acme/nobody"), rotate("r1", 1))
            .await
            .expect_err("no grant");
        assert!(matches!(refused, Refusal::Denied(_)));
        let stale = api
            .rotate_identity(&admin(), rotate("r0", 5))
            .await
            .expect_err("a stale epoch");
        assert!(matches!(stale, Refusal::Conflict { revision: 1, .. }));
        let rotated = api
            .rotate_identity(&admin(), rotate("r1", 1))
            .await
            .expect("rotated");
        assert_eq!(rotated.receipt.revision, 2);
        let again = api
            .rotate_identity(&admin(), rotate("r1", 1))
            .await
            .expect("replayed");
        assert_eq!(again, rotated, "the stored answer, not a second rotation");
        let view = api.identity(&admin()).expect("read");
        assert_eq!(view.successions, vec![rotated.succession.clone()]);
        let phases: Vec<_> = trail
            .events
            .lock()
            .expect("lock")
            .iter()
            .filter(|record| record.0 == crate::identity::AUDIT_ROTATED)
            .map(|record| (record.2.clone(), record.3))
            .collect();
        assert_eq!(
            phases,
            vec![
                (Some("epoch:2".to_owned()), Some("intent")),
                (Some("epoch:2".to_owned()), Some("applied")),
            ]
        );
    }

    #[tokio::test]
    async fn a_rotation_whose_commit_failed_is_answered_after_a_restart_from_the_successions() {
        use permguard_core::fault::{Fault, inject};

        let trail = std::sync::Arc::new(Recording::default());
        let root = scratch("identity-reconciled");
        {
            let (api, _, volume) = reopen_with(&root, Vec::new(), trail.clone());
            let journal = volume
                .host()
                .path()
                .join(crate::audit::DIRECTORY)
                .join(crate::operations::mutation::DIRECTORY);
            let armed = std::sync::Arc::new(std::sync::Mutex::new(None));
            let holder = armed.clone();
            *trail.on_intent.lock().expect("lock") = Some(Box::new(move || {
                *holder.lock().expect("lock") = Some(inject(&journal, Fault::WriteFails));
            }));
            let refused = api
                .rotate_identity(&admin(), rotate("r1", 1))
                .await
                .expect_err("the commit could not be written");
            assert_eq!(
                refused.error().expect("refusal").code(),
                codes::host::MUTATION_UNRECORDED
            );
            drop(armed.lock().expect("lock").take());
        }
        let (api, _, _volume) = reopen_with(&root, Vec::new(), trail);
        let answered = api
            .rotate_identity(&admin(), rotate("r1", 1))
            .await
            .expect("the retry learns the rotation");
        assert_eq!(answered.receipt.revision, 2);
        let view = api.identity(&admin()).expect("read");
        assert_eq!(view.successions, vec![answered.succession]);
    }
}
