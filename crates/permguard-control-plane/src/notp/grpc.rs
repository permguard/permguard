// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! NOTP's gRPC shape: the tonic service, extraction, and nothing else. The
//! same facade the HTTP routes call, so the two surfaces cannot drift.

use tonic::{Request, Response, Status};

use permguard_core::{ApiError, ErrorClass};
use permguard_notp as notp;
use permguard_objects::digest::Digest;

use super::NotpFacade;
use crate::v1::git_like_store_server::GitLikeStore;
use crate::v1::{
    CommitPushRequest, CommitPushResponse, FetchObjectsRequest, FetchObjectsResponse,
    GetKeyRingRequest, GetKeyRingResponse, GetRefRequest, GetRefResponse, NegotiatePullRequest,
    NegotiatePullResponse, NegotiatePushRequest, NegotiatePushResponse, UploadObjectsRequest,
    UploadObjectsResponse,
};
use crate::wire;

fn bad(detail: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ErrorClass::Validation,
        permguard_core::codes::notp::BODY_REJECTED,
        format!("the request is not a valid NOTP message: {detail}"),
    )
}

fn digest(text: &str) -> Result<Digest, ApiError> {
    Digest::parse(text).map_err(bad)
}

/// Proto optionals ride as empty strings; the domain speaks `Option`.
fn optional_digest(text: &str) -> Result<Option<Digest>, ApiError> {
    if text.is_empty() {
        Ok(None)
    } else {
        Ok(Some(digest(text)?))
    }
}

fn digests(texts: &[String]) -> Result<Vec<Digest>, ApiError> {
    texts.iter().map(|t| digest(t)).collect()
}

fn strings(digests: Vec<Digest>) -> Vec<String> {
    digests.into_iter().map(|d| d.to_string()).collect()
}

/// The ref state a client names, from its proto shape.
fn expected(
    message: Option<&crate::v1::ExpectedRef>,
) -> Result<Option<notp::ExpectedRef>, ApiError> {
    message
        .map(|expected| {
            Ok(notp::ExpectedRef {
                counter: expected.counter,
                digest: digest(&expected.digest)?,
            })
        })
        .transpose()
}

/// A transfer session id: exactly 16 bytes.
fn transfer_id(bytes: &[u8]) -> Result<notp::TransferId, ApiError> {
    bytes
        .try_into()
        .map_err(|_| bad("a transfer id is 16 bytes"))
}

/// A request id, under the grammar the CBOR codec enforces.
fn request_id(text: &str) -> Result<String, ApiError> {
    if !notp::is_request_id(text) {
        return Err(bad("a request id is printable text of 1 to 128 bytes"));
    }
    Ok(text.to_owned())
}

/// gRPC carries an absent string as empty; the domain speaks `Option`.
fn optional_text(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_owned())
}

#[tonic::async_trait]
impl GitLikeStore for NotpFacade {
    async fn get_ref(
        &self,
        request: Request<GetRefRequest>,
    ) -> Result<Response<GetRefResponse>, Status> {
        let actor = permguard_transport::actor_of(request.extensions());
        let message = request.into_inner();
        match self
            .get_ref(&actor, &message.zone, &message.ledger, &message.r#ref)
            .await
        {
            Ok(answered) => Ok(Response::new(GetRefResponse {
                head: answered.head.to_string(),
                counter: answered.counter,
                statement: answered.statement,
                ref_digest: answered.ref_digest.to_string(),
            })),
            Err(refusal) => Err(wire::grpc_refusal(&refusal, self.disclosure)),
        }
    }

    async fn negotiate_push(
        &self,
        request: Request<NegotiatePushRequest>,
    ) -> Result<Response<NegotiatePushResponse>, Status> {
        let actor = permguard_transport::actor_of(request.extensions());
        let message = request.into_inner();
        let outcome = async {
            let domain = notp::NegotiatePushRequest {
                r#ref: message.r#ref.clone(),
                new_head: digest(&message.new_head)?,
                expected_ref: expected(message.expected_ref.as_ref())?,
                closure: message
                    .closure
                    .iter()
                    .map(|claim| {
                        Ok(notp::ObjectClaim {
                            digest: digest(&claim.digest)?,
                            size: claim.size,
                        })
                    })
                    .collect::<Result<Vec<_>, ApiError>>()?,
                request_id: request_id(&message.request_id)?,
            };
            self.negotiate_push(&actor, &message.zone, &message.ledger, &domain)
                .await
        }
        .await;
        match outcome {
            Ok(response) => Ok(Response::new(NegotiatePushResponse {
                missing: strings(response.missing),
                max_batch_bytes: response.max_batch_bytes,
                max_batch_objects: response.max_batch_objects,
                compression: response.compression.unwrap_or_default(),
                transfer_id: response.transfer_id.to_vec(),
                reservation: response.reservation,
                expiry: response.expiry,
            })),
            Err(refusal) => Err(wire::grpc_refusal(&refusal, self.disclosure)),
        }
    }

    async fn upload_objects(
        &self,
        request: Request<UploadObjectsRequest>,
    ) -> Result<Response<UploadObjectsResponse>, Status> {
        let actor = permguard_transport::actor_of(request.extensions());
        let message = request.into_inner();
        let outcome = async {
            let domain = notp::UploadObjectsRequest {
                transfer_id: transfer_id(&message.transfer_id)?,
                objects: message.objects,
                compression: optional_text(&message.compression),
            };
            self.upload(&actor, &message.zone, &message.ledger, &domain)
                .await
        }
        .await;
        match outcome {
            Ok(response) => Ok(Response::new(UploadObjectsResponse {
                received: strings(response.received),
                remaining: response.remaining,
            })),
            Err(refusal) => Err(wire::grpc_refusal(&refusal, self.disclosure)),
        }
    }

    async fn commit_push(
        &self,
        request: Request<CommitPushRequest>,
    ) -> Result<Response<CommitPushResponse>, Status> {
        let actor = permguard_transport::actor_of(request.extensions());
        let message = request.into_inner();
        let outcome = async {
            let domain = notp::CommitPushRequest {
                r#ref: message.r#ref.clone(),
                new_head: digest(&message.new_head)?,
                expected_ref: expected(message.expected_ref.as_ref())?,
                transfer_id: transfer_id(&message.transfer_id)?,
                request_id: request_id(&message.request_id)?,
            };
            self.commit_push(&actor, &message.zone, &message.ledger, &domain)
                .await
        }
        .await;
        match outcome {
            Ok(response) => Ok(Response::new(CommitPushResponse {
                head: response.head.to_string(),
                counter: response.counter,
                statement: response.statement,
                ref_digest: response.ref_digest.to_string(),
            })),
            Err(refusal) => Err(wire::grpc_refusal(&refusal, self.disclosure)),
        }
    }

    async fn negotiate_pull(
        &self,
        request: Request<NegotiatePullRequest>,
    ) -> Result<Response<NegotiatePullResponse>, Status> {
        let actor = permguard_transport::actor_of(request.extensions());
        let message = request.into_inner();
        let outcome = async {
            let domain = notp::NegotiatePullRequest {
                r#ref: message.r#ref.clone(),
                at: optional_digest(&message.at)?,
                have: digests(&message.have)?,
                checkpoint: expected(message.checkpoint.as_ref())?,
            };
            self.negotiate_pull(&actor, &message.zone, &message.ledger, &domain)
                .await
        }
        .await;
        match outcome {
            Ok(response) => Ok(Response::new(NegotiatePullResponse {
                head: response.head.to_string(),
                counter: response.counter,
                statement: response.statement,
                missing: strings(response.missing),
                max_batch_bytes: response.max_batch_bytes,
                max_batch_objects: response.max_batch_objects,
                compression: response.compression.unwrap_or_default(),
                transfer_id: response.transfer_id.to_vec(),
                ref_digest: response.ref_digest.to_string(),
                expiry: response.expiry,
            })),
            Err(refusal) => Err(wire::grpc_refusal(&refusal, self.disclosure)),
        }
    }

    async fn fetch_objects(
        &self,
        request: Request<FetchObjectsRequest>,
    ) -> Result<Response<FetchObjectsResponse>, Status> {
        let actor = permguard_transport::actor_of(request.extensions());
        let message = request.into_inner();
        let outcome = async {
            let domain = notp::FetchObjectsRequest {
                digests: digests(&message.digests)?,
                accept_compression: optional_text(&message.accept_compression),
                transfer_id: transfer_id(&message.transfer_id)?,
            };
            self.fetch(&actor, &message.zone, &message.ledger, &domain)
                .await
        }
        .await;
        match outcome {
            Ok(response) => Ok(Response::new(FetchObjectsResponse {
                objects: response.objects,
                compression: response.compression.unwrap_or_default(),
                expiry: response.expiry,
            })),
            Err(refusal) => Err(wire::grpc_refusal(&refusal, self.disclosure)),
        }
    }

    async fn get_key_ring(
        &self,
        _request: Request<GetKeyRingRequest>,
    ) -> Result<Response<GetKeyRingResponse>, Status> {
        match self.keyring() {
            Ok(jwks) => Ok(Response::new(GetKeyRingResponse { jwks })),
            Err(error) => Err(wire::grpc_error(&error, self.disclosure)),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;
    use std::time::Duration;

    use permguard_core::Disclosure;
    use permguard_core::authz::{Actor, ActorContext, Credential, Principal};
    use permguard_core::keys::KeyManager as _;
    use permguard_host::composition::Authorization;
    use permguard_std::catalog::FileCatalog;
    use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
    use tonic::Request;

    use super::*;
    use crate::engine::EngineLimits;

    /// A facade whose authorization is closed: nobody holds anything.
    fn closed_facade() -> NotpFacade {
        let root =
            std::env::temp_dir().join(format!("permguard-notp-grpc-authz-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let keys = Arc::new(DirectoryKeyManager::new(
            root.join("keys"),
            KeyPolicy {
                publish_ahead: Duration::ZERO,
                rotate_every: Duration::from_secs(3600),
                retain: Duration::from_secs(3600),
                verify_retain: Duration::from_secs(3600),
            },
        ));
        keys.maintain().expect("the ring publishes");
        keys.maintain().expect("the ring activates");
        let keys = crate::handles::head_signer_for_tests(keys);
        NotpFacade::new(
            Arc::new(FileCatalog::new(root.join("zones"))),
            root.join("zones"),
            keys,
            [0x11; 16],
            EngineLimits {
                max_batch_bytes: 8 * 1024 * 1024,
                max_batch_objects: 1000,
                max_push_objects: 1000,
                max_push_bytes: 64 * 1024 * 1024,
                ledger_quota_bytes: 256 * 1024 * 1024,
            },
            crate::engine::TransferPolicy {
                ttl: Duration::from_secs(900),
                grace: Duration::from_secs(3600),
            },
            crate::handles::ref_mutations_for_tests(&root.join("volume")),
            None,
            permguard_languages::registry::Enabled::everything(),
            true,
            None,
            Disclosure::Minimal,
            false,
            permguard_core::metrics::Metrics::none(),
            Arc::new(Authorization::closed()),
        )
    }

    /// F-21 and F-22 over gRPC for the ledger reads: nobody is `UNAUTHENTICATED`, somebody
    /// without a grant `PERMISSION_DENIED`, before any zone or ledger is looked up.
    #[tokio::test]
    async fn a_ref_read_and_a_pull_are_authorized_over_grpc_before_any_lookup() {
        let facade = closed_facade();
        let nobody = GitLikeStore::get_ref(
            &facade,
            Request::new(GetRefRequest {
                zone: "delivery".to_owned(),
                ledger: "main".to_owned(),
                r#ref: "main".to_owned(),
            }),
        )
        .await
        .expect_err("F-21");
        assert_eq!(nobody.code(), tonic::Code::Unauthenticated);
        assert_eq!(
            nobody
                .metadata()
                .get(wire::GRPC_ERROR_CODE)
                .and_then(|v| v.to_str().ok()),
            Some("unauthenticated")
        );

        let mut request = Request::new(NegotiatePullRequest {
            zone: "delivery".to_owned(),
            ledger: "main".to_owned(),
            r#ref: "main".to_owned(),
            at: String::new(),
            have: Vec::new(),
            checkpoint: None,
        });
        request
            .extensions_mut()
            .insert(Arc::new(Actor::Authenticated(ActorContext::new(
                Principal::new("spiffe://acme/billing").expect("p"),
                Credential::SanUri,
                None,
            ))));
        let somebody = GitLikeStore::negotiate_pull(&facade, request)
            .await
            .expect_err("F-22");
        assert_eq!(somebody.code(), tonic::Code::PermissionDenied);
        assert_eq!(
            somebody
                .metadata()
                .get(wire::GRPC_ERROR_CODE)
                .and_then(|v| v.to_str().ok()),
            Some("forbidden")
        );
    }
}
