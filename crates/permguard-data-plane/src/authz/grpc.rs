// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision endpoint's gRPC shape.
//!
//! Field for field the HTTP surface, which is the point: a deployment picks a
//! transport, not a set of semantics. Everything below this file is shared —
//! the same [`Decider`], the same taxonomy, the same audit record — so the two
//! surfaces cannot drift into two products.
//!
//! # The one thing a transport does own
//!
//! How a refusal is said. gRPC has no status codes to reuse, so the same
//! classes map onto its own:
//!
//! | Class | gRPC |
//! | --- | --- |
//! | the payload is not a request | `INVALID_ARGUMENT` |
//! | the ledger is not served here | `NOT_FOUND` |
//! | the ledger cannot be evaluated | `UNAVAILABLE` |
//! | this process failed | `INTERNAL` |
//!
//! and the structured half — the class and the code a client switches on —
//! rides as metadata, never parsed out of a sentence.

use tonic::{Request, Response, Status};

use permguard_core::{ApiError, Disclosure, ErrorClass};

use super::configuration;
use super::decide::Decider;
use super::translate;
use crate::v1::policy_decision_point_server::PolicyDecisionPoint;
use crate::v1::{
    Endpoints, EvaluateRequest, EvaluateResponse, GetConfigurationRequest,
    GetConfigurationResponse, StoreScope,
};

/// The gRPC metadata keys carrying the structured half of a refusal — the same
/// keys the control plane uses, because a client should learn one convention.
pub const GRPC_ERROR_CLASS: &str = "x-permguard-error-class";
pub const GRPC_ERROR_CODE: &str = "x-permguard-error-code";

/// The service the plane mounts.
pub struct PdpApi {
    pub decider: std::sync::Arc<Decider>,
    pub disclosure: Disclosure,
    pub base_url: String,
}

#[tonic::async_trait]
impl PolicyDecisionPoint for PdpApi {
    async fn evaluate(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        self.answer(request).await
    }

    /// The boxcarred call. The same handler: a request with no evaluations is
    /// one check, exactly as on the HTTP side.
    async fn evaluate_many(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        self.answer(request).await
    }

    /// The same configuration the HTTP binding publishes, field for field.
    ///
    /// Built from the one [`configuration::configuration`] both transports call, so a caller
    /// cannot learn a different interface depending on how it asked.
    async fn get_configuration(
        &self,
        _request: Request<GetConfigurationRequest>,
    ) -> Result<Response<GetConfigurationResponse>, Status> {
        let document = configuration::configuration(&self.base_url);

        Ok(Response::new(GetConfigurationResponse {
            r#interface: document.interface.to_owned(),
            pdp: document.pdp,
            endpoints: Some(Endpoints {
                evaluation: document.endpoints.evaluation,
                evaluations: document.endpoints.evaluations,
            }),
            capabilities: document.capabilities,
            store_scope: Some(StoreScope {
                r#in: document.store_scope.r#in.to_owned(),
                zone: document.store_scope.zone.to_owned(),
                ledger: document.store_scope.ledger.to_owned(),
                profile: document.store_scope.profile.to_owned(),
            }),
        }))
    }
}

impl PdpApi {
    async fn answer(
        &self,
        request: Request<EvaluateRequest>,
    ) -> Result<Response<EvaluateResponse>, Status> {
        // The transport's own request id, when the caller sent one and the
        // payload did not.
        let carried = request
            .metadata()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        // The same header, over the other transport: gRPC metadata carries
        // `traceparent` exactly as HTTP does.
        let trace = request
            .metadata()
            .get("traceparent")
            .and_then(|value| value.to_str().ok())
            .and_then(super::wire::TraceContext::parse);
        let mut wire =
            translate::request_from_proto(request.into_inner()).map_err(|malformed| {
                status_of(
                    &ApiError::new(ErrorClass::Validation, malformed.code, malformed.message),
                    self.disclosure,
                )
            })?;
        if wire.request_id.is_none() {
            wire.request_id = carried;
        }

        match self.decider.decide(&wire, trace).await {
            Ok(answered) => Ok(Response::new(translate::response_to_proto(answered))),
            Err(failed) => Err(status_of(&failed, self.disclosure)),
        }
    }
}

/// Turns a refusal into the gRPC answer, class and code as metadata.
fn status_of(failed: &ApiError, disclosure: Disclosure) -> Status {
    let message = failed.disclosed_message(disclosure);
    let mut status = match failed.class() {
        ErrorClass::Validation => Status::invalid_argument(message),
        ErrorClass::NotFound => Status::not_found(message),
        ErrorClass::Conflict => Status::failed_precondition(message),
        ErrorClass::Unavailable => Status::unavailable(message),
        ErrorClass::Internal => Status::internal(message),
    };
    let metadata = status.metadata_mut();
    if let Ok(class) = tonic::metadata::MetadataValue::try_from(failed.class().as_str()) {
        metadata.insert(GRPC_ERROR_CLASS, class);
    }
    if let Ok(code) = tonic::metadata::MetadataValue::try_from(failed.code()) {
        metadata.insert(GRPC_ERROR_CODE, code);
    }

    status
}
