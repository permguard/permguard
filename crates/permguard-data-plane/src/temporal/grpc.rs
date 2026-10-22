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
    GetTemporalConfigurationResponse, GetTemporalSignersRequest, GetTemporalSignersResponse,
    Reason, StoreScope, SubmitEventRequest, SubmitEventResponse, SubmitOutcome, TemporalEndpoints,
    TemporalPartitionEvaluation, TemporalSignerSpan,
};

/// The gRPC metadata keys carrying the structured half of a refusal — the same keys every other
/// surface uses, because a client should learn one convention.
pub use permguard_core::{GRPC_ERROR_CLASS, GRPC_ERROR_CODE};

/// The service the plane mounts.
pub struct TemporalPdpApi {
    pub submitter: std::sync::Arc<Submitter>,
    pub disclosure: Disclosure,
    pub base_url: String,
    /// Who serves the interface, its build and its phase: the discovery document's common header
    /// (WP-7.4a).
    pub describer: permguard_core::stages::Describer,
    pub pdp: String,
    /// The Host's authorization: `event.submit` on the exact ledger (WP-6.2a).
    pub authorization: std::sync::Arc<permguard_host::composition::Authorization>,
}

#[tonic::async_trait]
impl TemporalPolicyDecisionPoint for TemporalPdpApi {
    async fn submit_event(
        &self,
        request: Request<SubmitEventRequest>,
    ) -> Result<Response<SubmitEventResponse>, Status> {
        let actor = permguard_transport::actor_of(request.extensions());
        let wire = from_proto(request.into_inner()).map_err(|malformed| {
            status_of(
                &ApiError::new(ErrorClass::Validation, malformed.code, malformed.message),
                self.disclosure,
            )
        })?;

        // Authorization before anything is read or written, as over HTTP (WP-6.2a).
        let (source, authorized) =
            super::gate(&self.authorization, &actor, self.submitter.root(), &wire)
                .map_err(|denial| crate::authz::gate::grpc_denial(&denial))?;
        match self
            .submitter
            .submit(&wire, &source, authorized.as_ref())
            .await
        {
            Ok(answered) => Ok(Response::new(to_proto(super::submit::disclosed(
                answered,
                self.disclosure,
            )))),
            Err(failed) => Err(status_of(&failed, self.disclosure)),
        }
    }

    /// The same signers document the HTTP binding serves, field for field.
    async fn get_signers(
        &self,
        request: Request<GetTemporalSignersRequest>,
    ) -> Result<Response<GetTemporalSignersResponse>, Status> {
        let asked = request.into_inner();
        let streams = self.submitter.streams();

        // Only a journal that already exists answers: opening one on a read would let a request
        // with an invented name create directories.
        if !streams
            .ledgers()
            .iter()
            .any(|(zone, ledger)| zone == &asked.zone && ledger == &asked.ledger)
        {
            return Err(status_of(
                &super::http::not_held(&asked.zone, &asked.ledger),
                self.disclosure,
            ));
        }

        let state = streams
            .state(&asked.zone, &asked.ledger)
            .map_err(|error| status_of(&super::http::unreadable(&error), self.disclosure))?;
        let held = streams
            .signers(&asked.zone, &asked.ledger)
            .map_err(|error| status_of(&super::http::unreadable(&error), self.disclosure))?;
        let instance = streams
            .instance(&asked.zone, &asked.ledger)
            .unwrap_or_default();
        let until = if asked.until_seq == 0 {
            u64::MAX
        } else {
            asked.until_seq
        };

        let spans = held
            .covering(asked.from_seq, until)
            .iter()
            .map(|span| {
                Ok(TemporalSignerSpan {
                    from_seq: span.from,
                    kid: span.kid.clone(),
                    jwk: serde_json::to_vec(&span.jwk).map_err(|error| {
                        status_of(
                            &ApiError::new(
                                ErrorClass::Internal,
                                permguard_core::codes::stream::SIGNER_MALFORMED,
                                error.to_string(),
                            ),
                            self.disclosure,
                        )
                    })?,
                })
            })
            .collect::<Result<Vec<_>, Status>>()?;

        let producer = streams.producer();
        Ok(Response::new(GetTemporalSignersResponse {
            producer_class: producer.class.clone(),
            producer: producer.id.clone(),
            instance,
            durable_through: state.durable_through,
            signed_through: state.signed_through,
            acked_through: state.acked_through,
            spans,
        }))
    }

    /// The same configuration the HTTP binding publishes, field for field.
    ///
    /// Built from the one [`configuration::document`] both transports call, so a caller cannot
    /// learn a different interface depending on how it asked.
    async fn get_temporal_configuration(
        &self,
        _request: Request<GetTemporalConfigurationRequest>,
    ) -> Result<Response<GetTemporalConfigurationResponse>, Status> {
        let header = self
            .describer
            .header(permguard_core::domains::interface::PDP_TEMPORAL_V1ALPHA1)
            .map_err(|refused| status_of(&refused, self.disclosure))?;
        let document = configuration::document(&self.base_url, &self.pdp, header);

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
            version: document.header.version,
            component: document.header.component,
            state: document.header.state,
            stage: document.header.stage,
            sunset: document.header.sunset,
            limits: document.limits.into_iter().collect(),
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
            Outcome::Indeterminate => SubmitOutcome::Indeterminate as i32,
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
        evaluations: response
            .evaluations
            .into_iter()
            .map(|evaluation| TemporalPartitionEvaluation {
                partition: evaluation.partition,
                decision: evaluation.decision,
                policies: evaluation.policies,
                reason: evaluation.reason.map(|reason| Reason {
                    code: reason.code,
                    message: reason.message,
                }),
            })
            .collect(),
        reason: response.reason.map(|reason| Reason {
            code: reason.code,
            message: reason.message,
        }),
        history: Some(DecisionHistory {
            mode: response.history.mode,
            watermark: response.history.watermark.unwrap_or_default(),
            staleness_seconds: response.history.staleness_seconds,
            gaps: response.history.gaps,
            frontier: response
                .history
                .frontier
                .into_iter()
                .map(|run| crate::v1::FrontierRun {
                    origin: run.origin,
                    run: run.run,
                    covered_through: run.covered_through,
                    low_watermark: run.low_watermark,
                    gaps: run
                        .gaps
                        .into_iter()
                        .map(|gap| crate::v1::FrontierGap {
                            from: gap.from,
                            through: gap.through,
                        })
                        .collect(),
                })
                .collect(),
            origin_set_revision: response.history.origin_set_revision,
            max_staleness_seconds: response.history.max_staleness_seconds,
            degraded: response.history.degraded,
            time: response.history.time,
            quarantined: response.history.quarantined,
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

/// Turns a refusal into the gRPC answer under the temporal contract's own table: a conflict is
/// `ABORTED`.
fn status_of(failed: &ApiError, disclosure: Disclosure) -> Status {
    crate::authz::grpc::status_under(failed, disclosure, permguard_core::StatusTable::TemporalPdp)
}
