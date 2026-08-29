// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The temporal interface's gRPC shape.
//!
//! Field for field the HTTP surface, which is the point: a deployment picks a transport, not a set
//! of semantics. Everything below this file is shared — the same [`Submitter`], the same journal,
//! the same taxonomy — so the two surfaces cannot drift into two products.
//!
//! # The two things a transport does own
//!
//! **How a refusal is said.** gRPC has no status codes to reuse, so the classes map onto its own,
//! and the structured half rides as metadata rather than being parsed out of a sentence.
//!
//! **How "no verdict" is said.** JSON leaves `decision` out; proto3 cannot, because a bare `bool`
//! defaults to `false` and a caller reading a history-only receipt would see a deny. So the field
//! is a `BoolValue`, whose absence is a value on the wire.

use tonic::{Request, Response, Status};

use permguard_core::{ApiError, Disclosure, ErrorClass};
use permguard_languages::temporal::{Outcome, StoreBody, SubmitRequest, SubmitResponse};

use super::configuration;
use super::submit::Submitter;
use crate::v1::temporal_policy_decision_point_server::TemporalPolicyDecisionPoint;
use crate::v1::{
    DecisionHistory, EventWatermark, GetTemporalConfigurationRequest,
    GetTemporalConfigurationResponse, Reason, StoreScope, SubmitEventRequest, SubmitEventResponse,
    SubmitOutcome, TemporalEndpoints,
};

/// The gRPC metadata keys carrying the structured half of a refusal — the same keys every other
/// surface uses, because a client should learn one convention.
pub const GRPC_ERROR_CLASS: &str = "x-permguard-error-class";
pub const GRPC_ERROR_CODE: &str = "x-permguard-error-code";

/// The service the plane mounts.
pub struct TemporalPdpApi {
    pub submitter: std::sync::Arc<Submitter>,
    pub disclosure: Disclosure,
    pub base_url: String,
    pub pdp: String,
}

#[tonic::async_trait]
impl TemporalPolicyDecisionPoint for TemporalPdpApi {
    async fn submit_event(
        &self,
        request: Request<SubmitEventRequest>,
    ) -> Result<Response<SubmitEventResponse>, Status> {
        let wire = from_proto(request.into_inner()).map_err(|malformed| {
            status_of(
                &ApiError::new(ErrorClass::Validation, malformed.code, malformed.message),
                self.disclosure,
            )
        })?;

        match self.submitter.submit(&wire).await {
            Ok(answered) => Ok(Response::new(to_proto(answered))),
            Err(failed) => Err(status_of(&failed, self.disclosure)),
        }
    }

    /// The same configuration the HTTP binding publishes, field for field.
    ///
    /// Built from the one [`configuration::document`] both transports call, so a caller cannot
    /// learn a different interface depending on how it asked.
    async fn get_temporal_configuration(
        &self,
        _request: Request<GetTemporalConfigurationRequest>,
    ) -> Result<Response<GetTemporalConfigurationResponse>, Status> {
        let document = configuration::document(&self.base_url, &self.pdp);

        Ok(Response::new(GetTemporalConfigurationResponse {
            r#interface: document.interface,
            pdp: document.pdp,
            endpoints: Some(TemporalEndpoints {
                submission: document.endpoints.submission,
            }),
            event_types: document.event_types,
            capabilities: document.capabilities,
            store_scope: Some(StoreScope {
                r#in: document.store_scope.r#in,
                zone: document.store_scope.zone,
                ledger: document.store_scope.ledger,
                profile: document.store_scope.profile,
            }),
        }))
    }
}

/// The proto submission, as the one domain request both transports deserialize into.
///
/// A missing `store` or `event` is left absent rather than defaulted here: what a submission must
/// state is the interface's rule, and [`Submitter`] is where it is stated once. What *is* refused
/// here is a value this transport carried and JSON cannot: an occurrence whose amount arrived as
/// `NaN` would otherwise reach a policy as an absent field, and an absent field decides.
pub fn from_proto(
    request: SubmitEventRequest,
) -> Result<SubmitRequest, permguard_languages::Malformed> {
    let event = match request.event {
        Some(event) => {
            let data = match event.data {
                // Through prost's own `Struct`, so the JSON a gRPC caller sends and the JSON an
                // HTTP caller sends become the same value — including the escapes an occurrence
                // uses for entities and decimals, which a hand-written mapping would flatten.
                Some(data) => Some(serde_json::Value::Object(
                    crate::authz::translate::json_from_struct(data)?,
                )),
                None => None,
            };

            Some(permguard_languages::temporal::EventBody {
                kind: some(event.r#type),
                data,
            })
        }
        None => None,
    };

    Ok(SubmitRequest {
        store: request.store.map(|store| StoreBody {
            zone: some(store.zone),
            ledger: some(store.ledger),
            profile: some(store.profile),
        }),
        event,
    })
}

/// The domain answer, as proto.
pub fn to_proto(response: SubmitResponse) -> SubmitEventResponse {
    SubmitEventResponse {
        outcome: match response.outcome {
            Outcome::Decided => SubmitOutcome::Decided as i32,
            Outcome::Accepted => SubmitOutcome::Accepted as i32,
        },
        event_id: response.event_id,
        watermark: Some(EventWatermark {
            instance: response.watermark.instance,
            sequence: response.watermark.sequence,
            history: response.watermark.history.unwrap_or_default(),
        }),
        // Absent for a history-only receipt. A bare `bool` would default to `false` there, which a
        // caller could not tell from a decided deny.
        decision: response.decision,
        decision_id: response.decision_id.unwrap_or_default(),
        policies: response.policies,
        reason: response.reason.map(|reason| Reason {
            code: reason.code,
            message: reason.message,
        }),
        history: Some(DecisionHistory {
            mode: response.history.mode,
            watermark: response.history.watermark.unwrap_or_default(),
            staleness_seconds: response.history.staleness_seconds.unwrap_or_default(),
        }),
    }
}

/// A proto string, as the optional field it stands for.
///
/// proto3 cannot tell an absent string from an empty one, so the mapping is made here: empty is
/// absent, and the interface's own "this is required" rule then applies to both the same way.
fn some(value: String) -> Option<String> {
    if value.is_empty() {
        return None;
    }

    Some(value)
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
