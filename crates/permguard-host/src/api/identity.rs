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
use crate::membership::member::Target;
use crate::operations::mutation::{Applied, Failure};

/// `GET /host/v1/identity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityView {
    pub host_id: String,
    pub epoch: u64,
    /// The current identity key's fingerprint. `first_public_key` remains the chain's pin.
    pub fingerprint: String,
    /// The signed identity document of the current epoch, COSE_Sign1.
    pub document: String,
    /// Every succession record, oldest first, COSE_Sign1 each.
    pub successions: Vec<String>,
    /// The epoch-1 public key, the suite's raw bytes: what the first fingerprint pins.
    pub first_public_key: String,
    /// The protocol versions this Host speaks.
    pub protocol_versions: Vec<String>,
}

/// `POST /host/v1/identity/verify`: the pinned peer to prove on a live PeerChannel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyIdentity {
    pub address: String,
    pub host_id: String,
    pub fingerprint: String,
}

/// A peer identity proved on the connection that answered this request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdentityVerified {
    pub host_id: String,
    pub epoch: u64,
    pub fingerprint: String,
    pub verified: bool,
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
            host_id: identity.host_id_text(),
            epoch: identity.epoch(),
            fingerprint: identity.fingerprint(),
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

    /// `POST /host/v1/identity/verify`: the peer must sign both a fresh transcript and this
    /// TLS 1.3 connection's exporter. Reading its public identity is not proof.
    pub async fn verify_identity(
        &self,
        actor: &Actor,
        request: VerifyIdentity,
    ) -> Result<IdentityVerified, Refusal> {
        let _admitted = self.admit(actor, operations::IDENTITY_READ)?;
        let host_id = host_id(&request.host_id)?;
        let connector = self
            .memberships
            .as_ref()
            .and_then(|memberships| memberships.connector.as_deref())
            .ok_or_else(|| {
                Refusal::new(
                    ErrorClass::Unavailable,
                    codes::host::PEER_CLIENT_UNCONFIGURED,
                    "this Host cannot open a proven peer channel: its Host listener has no TLS \
                     certificate or no client CA",
                )
            })?;
        let proved = connector
            .prove(Target {
                address: request.address,
                host_id,
                fingerprint: request.fingerprint.clone(),
            })
            .await
            .map_err(|refusal| {
                Refusal::new(ErrorClass::Unavailable, refusal.code, refusal.reason)
            })?;
        if proved.host_id != host_id || proved.fingerprint != request.fingerprint {
            return Err(Refusal::new(
                ErrorClass::Validation,
                codes::host::SESSION_REFUSED,
                "the proven peer differs from the Host id or fingerprint requested",
            ));
        }
        Ok(IdentityVerified {
            host_id: crate::identity::record::uuid_text(&proved.host_id),
            epoch: proved.epoch,
            fingerprint: proved.fingerprint,
            verified: true,
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
    pub(super) fn host_identity(&self) -> Result<&Identity, Refusal> {
        let identity = self.open_identity()?;
        if identity.is_retired() {
            return Err(Refusal::new(
                ErrorClass::Unavailable,
                codes::host::IDENTITY_UNAVAILABLE,
                "the Host identity was reset: restart the process to serve the new one",
            ));
        }
        Ok(identity)
    }

    /// The identity open in this process, retired or not.
    pub(super) fn open_identity(&self) -> Result<&Identity, Refusal> {
        self.identity.as_deref().ok_or_else(|| {
            Refusal::new(
                ErrorClass::Unavailable,
                codes::host::IDENTITY_UNAVAILABLE,
                "no Host identity is open on this process",
            )
        })
    }
}

fn host_id(text: &str) -> Result<[u8; 16], Refusal> {
    let digits: String = text.chars().filter(|character| *character != '-').collect();
    if !text.is_ascii() || text.len() != 36 || digits.len() != 32 {
        return Err(Refusal::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            "the peer Host id is not canonical UUID text",
        ));
    }
    let mut id = [0u8; 16];
    for (at, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digits[at * 2..at * 2 + 2], 16).map_err(|_| {
            Refusal::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                "the peer Host id is not canonical UUID text",
            )
        })?;
    }
    if crate::identity::record::uuid_text(&id) != text {
        return Err(Refusal::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            "the peer Host id is not canonical UUID text",
        ));
    }
    Ok(id)
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
    use crate::membership::member::{Connector, Exchange, Exchanged, ProvedPeer};
    use permguard_core::authz::Actor;

    struct Proof(ProvedPeer);

    impl Connector for Proof {
        fn prove(
            &self,
            _target: Target,
        ) -> permguard_core::BoxFuture<'_, Result<ProvedPeer, crate::session::Refusal>> {
            Box::pin(std::future::ready(Ok(self.0.clone())))
        }

        fn exchange(
            &self,
            _target: Target,
            _exchange: Exchange,
        ) -> permguard_core::BoxFuture<'_, Result<Exchanged, crate::session::Refusal>> {
            panic!("identity verification must not send a membership or Task request")
        }
    }

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
        assert_eq!(
            view.host_id,
            api.host_identity().expect("identity").host_id_text()
        );
        assert_eq!(view.epoch, 1);
        assert_eq!(
            view.fingerprint,
            api.host_identity().expect("identity").first_fingerprint()
        );
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
    async fn identity_verification_requires_a_live_peer_proof() {
        let api = facade("identity-live-proof");
        let refused = api
            .verify_identity(
                &admin(),
                VerifyIdentity {
                    address: "https://peer.example:9443".to_owned(),
                    host_id: "0198f2aa-0000-7000-8000-000000000002".to_owned(),
                    fingerprint:
                        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                            .to_owned(),
                },
            )
            .await
            .expect_err("a facade without a peer connector cannot prove a copied document");
        assert_eq!(
            refused.error().expect("an API refusal").code(),
            codes::host::PEER_CLIENT_UNCONFIGURED
        );
    }

    #[tokio::test]
    async fn identity_verification_binds_the_live_proof_without_mutating_memberships() {
        let mut api = facade("identity-live-proof-binding");
        let requested_host = host_id("0198f2aa-0000-7000-8000-000000000002").expect("host id");
        let fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let request = VerifyIdentity {
            address: "https://peer.example:9443".to_owned(),
            host_id: crate::identity::record::uuid_text(&requested_host),
            fingerprint: fingerprint.to_owned(),
        };
        let before = api.members(&admin(), None).expect("members before proof");

        let install = |api: &mut HostApi, peer| {
            std::sync::Arc::get_mut(api.memberships.as_mut().expect("memberships"))
                .expect("the facade owns its membership service")
                .connector = Some(std::sync::Arc::new(Proof(peer)));
        };
        install(
            &mut api,
            ProvedPeer {
                host_id: [7; 16],
                epoch: 4,
                fingerprint: fingerprint.to_owned(),
            },
        );
        let wrong_host = api
            .verify_identity(&admin(), request.clone())
            .await
            .expect_err("another proved Host is refused");
        assert_eq!(
            wrong_host.error().expect("API refusal").code(),
            codes::host::SESSION_REFUSED
        );

        install(
            &mut api,
            ProvedPeer {
                host_id: requested_host,
                epoch: 4,
                fingerprint:
                    "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                        .to_owned(),
            },
        );
        let wrong_fingerprint = api
            .verify_identity(&admin(), request.clone())
            .await
            .expect_err("another proved fingerprint is refused");
        assert_eq!(
            wrong_fingerprint.error().expect("API refusal").code(),
            codes::host::SESSION_REFUSED
        );

        install(
            &mut api,
            ProvedPeer {
                host_id: requested_host,
                epoch: 4,
                fingerprint: fingerprint.to_owned(),
            },
        );
        let proved = api
            .verify_identity(&admin(), request)
            .await
            .expect("the requested peer proves the live channel");
        assert_eq!(
            proved.host_id,
            crate::identity::record::uuid_text(&requested_host)
        );
        assert_eq!(proved.epoch, 4);
        assert_eq!(proved.fingerprint, fingerprint);
        assert!(proved.verified);
        assert_eq!(
            api.members(&admin(), None).expect("members after proof"),
            before,
            "identity proof neither enrolls nor updates a membership"
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
