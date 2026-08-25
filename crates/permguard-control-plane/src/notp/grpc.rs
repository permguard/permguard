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
        "body_rejected",
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
        let message = request.into_inner();
        match self
            .get_ref(&message.zone, &message.ledger, &message.r#ref)
            .await
        {
            Ok(answered) => Ok(Response::new(GetRefResponse {
                head: answered.head,
                counter: answered.counter,
                statement: answered.statement,
            })),
            Err(error) => Err(wire::grpc_error(&error, self.disclosure)),
        }
    }

    async fn negotiate_push(
        &self,
        request: Request<NegotiatePushRequest>,
    ) -> Result<Response<NegotiatePushResponse>, Status> {
        let message = request.into_inner();
        let outcome = async {
            let domain = notp::NegotiatePushRequest {
                r#ref: message.r#ref.clone(),
                new_head: digest(&message.new_head)?,
                expected_old: optional_digest(&message.expected_old)?,
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
            };
            self.negotiate_push(&message.zone, &message.ledger, &domain)
                .await
        }
        .await;
        match outcome {
            Ok(response) => Ok(Response::new(NegotiatePushResponse {
                missing: strings(response.missing),
                max_batch_bytes: response.max_batch_bytes,
                max_batch_objects: response.max_batch_objects,
                compression: response.compression.unwrap_or_default(),
            })),
            Err(error) => Err(wire::grpc_error(&error, self.disclosure)),
        }
    }

    async fn upload_objects(
        &self,
        request: Request<UploadObjectsRequest>,
    ) -> Result<Response<UploadObjectsResponse>, Status> {
        let message = request.into_inner();
        let domain = notp::UploadObjectsRequest {
            objects: message.objects,
            compression: optional_text(&message.compression),
        };
        match self.upload(&message.zone, &message.ledger, &domain).await {
            Ok(response) => Ok(Response::new(UploadObjectsResponse {
                received: strings(response.received),
            })),
            Err(error) => Err(wire::grpc_error(&error, self.disclosure)),
        }
    }

    async fn commit_push(
        &self,
        request: Request<CommitPushRequest>,
    ) -> Result<Response<CommitPushResponse>, Status> {
        let message = request.into_inner();
        let outcome = async {
            let domain = notp::CommitPushRequest {
                r#ref: message.r#ref.clone(),
                new_head: digest(&message.new_head)?,
                expected_old: optional_digest(&message.expected_old)?,
            };
            self.commit_push(&message.zone, &message.ledger, &domain)
                .await
        }
        .await;
        match outcome {
            Ok(response) => Ok(Response::new(CommitPushResponse {
                head: response.head.to_string(),
                counter: response.counter,
                statement: response.statement,
            })),
            Err(error) => Err(wire::grpc_error(&error, self.disclosure)),
        }
    }

    async fn negotiate_pull(
        &self,
        request: Request<NegotiatePullRequest>,
    ) -> Result<Response<NegotiatePullResponse>, Status> {
        let message = request.into_inner();
        let outcome = async {
            let domain = notp::NegotiatePullRequest {
                r#ref: message.r#ref.clone(),
                at: optional_digest(&message.at)?,
                have: digests(&message.have)?,
            };
            self.negotiate_pull(&message.zone, &message.ledger, &domain)
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
            })),
            Err(error) => Err(wire::grpc_error(&error, self.disclosure)),
        }
    }

    async fn fetch_objects(
        &self,
        request: Request<FetchObjectsRequest>,
    ) -> Result<Response<FetchObjectsResponse>, Status> {
        let message = request.into_inner();
        let outcome = async {
            let domain = notp::FetchObjectsRequest {
                digests: digests(&message.digests)?,
                accept_compression: optional_text(&message.accept_compression),
            };
            self.fetch(&message.zone, &message.ledger, &domain).await
        }
        .await;
        match outcome {
            Ok(response) => Ok(Response::new(FetchObjectsResponse {
                objects: response.objects,
                compression: response.compression.unwrap_or_default(),
            })),
            Err(error) => Err(wire::grpc_error(&error, self.disclosure)),
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
