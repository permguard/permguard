// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The canonical evaluation pipeline (WP-7.5d, IFACE-02, `6-contracts/0-interfaces-model.md`,
//! boundary and canonical pipeline).
//!
//! ```text
//! transport adapter ── strict decode ─▶ EvaluationRequest { interface_id, question: Native | Temporal }
//!                                         │  interface_id fixed by the adapter's route, never the body
//!                                         ▼
//!                                   evaluate(services, actor, request)
//!                                         ├─ authorize the actor on the exact ledger
//!                                         └─ the interface's handler
//!                                              ├─ Native:   Decider::decide_signed   (stateless)
//!                                              └─ Temporal: Submitter::submit        (durable, idempotent)
//! ```
//!
//! A tagged sum, not a lowest-common-denominator object: the question an adapter decoded is the
//! one its interface defines, and the pairing is fixed when the request is built, so no caller
//! data selects another interface or a runtime. The two handlers share the services — the
//! authorization gate, the verified snapshot `Decider::loaded` resolves, the scheduler and the
//! decision log — and never a transaction: temporal durability and idempotency stay in the
//! temporal handler.

use std::sync::Arc;

use permguard_core::authz::Actor;
use permguard_core::{AccessDenial, ApiError, ErrorClass};
use permguard_languages::temporal::{SubmitRequest, SubmitResponse};

use crate::authz::decide::Decider;
use crate::authz::wire::{CheckRequest, CheckResponse, TraceContext};
use crate::temporal::submit::Submitter;

/// What is asked, in the shape of the interface that defines it.
#[derive(Debug)]
pub enum Question {
    /// A `permguard.api.pdp.native.v1` check, single or boxcarred, with its partition inputs.
    Native(Box<CheckRequest>),
    /// A `permguard.api.pdp.temporal.v1alpha1` occurrence.
    Temporal(Box<SubmitRequest>),
}

/// One evaluation as every interface hands it to the shared services.
///
/// Built only by [`EvaluationRequest::native`] and [`EvaluationRequest::temporal`]: the interface
/// id is the one the question's shape belongs to, set by the adapter that decoded it. The handler
/// is selected by the question's variant, and stamps its own interface on the record.
#[derive(Debug)]
pub struct EvaluationRequest {
    interface_id: &'static str,
    /// The transport's own correlation handle, when the caller sent one.
    request_id: Option<String>,
    /// The caller's W3C trace context, when it propagated one.
    trace: Option<TraceContext>,
    question: Question,
}

/// The store a question names: zone, ledger and profile, each as the caller wrote it, resolved
/// to immutable ids by the gate and the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Store<'a> {
    pub zone: Option<&'a str>,
    pub ledger: Option<&'a str>,
    pub profile: Option<&'a str>,
}

impl EvaluationRequest {
    /// A native check, with the transport's request id and trace.
    pub fn native(
        request: CheckRequest,
        request_id: Option<String>,
        trace: Option<TraceContext>,
    ) -> Self {
        Self {
            interface_id: permguard_core::domains::interface::PDP_NATIVE_V1,
            request_id,
            trace,
            question: Question::Native(Box::new(request)),
        }
    }

    /// A temporal occurrence. The temporal contract carries its own identifiers in the event.
    pub fn temporal(request: SubmitRequest) -> Self {
        Self {
            interface_id: permguard_core::domains::interface::PDP_TEMPORAL_V1ALPHA1,
            request_id: None,
            trace: None,
            question: Question::Temporal(Box::new(request)),
        }
    }

    /// The exact evaluation interface this request was asked through.
    pub fn interface_id(&self) -> &'static str {
        self.interface_id
    }

    /// The question, in its interface's shape.
    pub fn question(&self) -> &Question {
        &self.question
    }

    /// The store the question names.
    pub fn store(&self) -> Store<'_> {
        match &self.question {
            Question::Native(request) => Store {
                zone: request.zone.as_deref(),
                ledger: request.ledger.as_deref(),
                profile: request.profile.as_deref(),
            },
            Question::Temporal(request) => {
                let store = request.store.as_ref();
                Store {
                    zone: store.and_then(|store| store.zone.as_deref()),
                    ledger: store.and_then(|store| store.ledger.as_deref()),
                    profile: store.and_then(|store| store.profile.as_deref()),
                }
            }
        }
    }
}

/// The answer, in the shape of the interface that was asked.
#[derive(Debug)]
pub enum Answer {
    Native(Box<CheckResponse>),
    Temporal(Box<SubmitResponse>),
}

/// Why an evaluation was not answered: the authorization gate's denial, or the handler's error.
/// Each transport maps both as it always has.
#[derive(Debug)]
pub enum Refused {
    Denied(AccessDenial),
    Failed(ApiError),
}

/// The shared services a surface evaluates through. A surface that does not serve an interface
/// holds no handler for it, and a question of that interface is refused.
pub struct Services<'a> {
    pub authorization: &'a permguard_host::composition::Authorization,
    pub decider: &'a Decider,
    pub submitter: Option<&'a Arc<Submitter>>,
}

/// Evaluates `request` for `actor`, the context the transport authenticated: authorization on
/// the exact ledger before anything is read, then the interface's own handler.
pub async fn evaluate(
    services: &Services<'_>,
    actor: &Actor,
    request: EvaluationRequest,
) -> Result<Answer, Refused> {
    let EvaluationRequest {
        request_id,
        trace,
        question,
        ..
    } = request;
    match question {
        Question::Native(mut wire) => {
            // What a signed response binds, taken before the transport's request id is filled
            // into the body (WP-6.6b); the actor the record names (IFACE-04).
            let asker =
                crate::authz::signing::asker(actor, &wire, services.decider.response_signing())
                    .map_err(Refused::Denied)?;
            // The transport's handle, when the payload carries none: the body wins, because it is
            // the one a boxcarred evaluation can carry per entry.
            if wire.request_id.is_none() {
                wire.request_id = request_id;
            }
            // Authorization before evaluation, and before the mirror is looked up (WP-2.4, P8).
            let authorized = crate::authz::gate::evaluation(
                services.authorization,
                actor,
                services.decider.root(),
                wire.zone.as_deref(),
                wire.ledger.as_deref(),
            )
            .map_err(Refused::Denied)?;
            services
                .decider
                .decide_signed(&wire, trace, authorized.as_ref(), asker)
                .await
                .map(|answered| Answer::Native(Box::new(answered)))
                .map_err(Refused::Failed)
        }
        Question::Temporal(wire) => {
            let Some(submitter) = services.submitter else {
                return Err(Refused::Failed(ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::common::UNAVAILABLE,
                    "this surface does not serve the temporal interface",
                )));
            };
            // Authorization before anything is read or written, and the source the occurrence
            // is recorded under: the principal the gate authorized (WP-6.2a).
            let (source, authorized) =
                crate::temporal::gate(services.authorization, actor, submitter.root(), &wire)
                    .map_err(Refused::Denied)?;
            submitter
                .submit(&wire, &source, authorized.as_ref())
                .await
                .map(|answered| Answer::Temporal(Box::new(answered)))
                .map_err(Refused::Failed)
        }
    }
}

/// The refusal an adapter answers when the shared services hand it another interface's answer:
/// unreachable, since the handler is chosen by the question the adapter built, and a failure
/// rather than a panic if it ever were reached.
#[cold]
pub fn mismatched(adapter: &str) -> ApiError {
    ApiError::new(
        ErrorClass::Internal,
        permguard_core::codes::common::INTERNAL,
        format!("the {adapter} adapter was handed another interface's answer"),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use serde_json::json;

    use super::*;

    /// IFACE-02: the interface is the one the question's shape belongs to, fixed when the request
    /// is built; and the store reads the same from either shape.
    #[test]
    fn a_question_is_tagged_with_its_own_interface_and_names_its_store() {
        let native: CheckRequest = serde_json::from_value(json!({
            "zone": "acme", "ledger": "main-ledger", "profile": "default",
            "subject": {"type": "user", "id": "alice"},
            "resource": {"type": "document", "id": "budget"},
            "action": {"name": "read"},
        }))
        .expect("a check");
        let asked = EvaluationRequest::native(native, Some("r-1".to_owned()), None);
        assert_eq!(
            asked.interface_id(),
            permguard_core::domains::interface::PDP_NATIVE_V1
        );
        assert!(matches!(asked.question(), Question::Native(_)));
        assert_eq!(
            asked.store(),
            Store {
                zone: Some("acme"),
                ledger: Some("main-ledger"),
                profile: Some("default"),
            }
        );

        let temporal: SubmitRequest = serde_json::from_value(json!({
            "store": {"zone": "acme", "ledger": "agent-governance", "profile": "temporal"},
        }))
        .expect("a submission");
        let asked = EvaluationRequest::temporal(temporal);
        assert_eq!(
            asked.interface_id(),
            permguard_core::domains::interface::PDP_TEMPORAL_V1ALPHA1
        );
        assert!(matches!(asked.question(), Question::Temporal(_)));
        assert_eq!(
            asked.store(),
            Store {
                zone: Some("acme"),
                ledger: Some("agent-governance"),
                profile: Some("temporal"),
            }
        );
        let unnamed = EvaluationRequest::temporal(SubmitRequest::default());
        assert_eq!(
            unnamed.store(),
            Store {
                zone: None,
                ledger: None,
                profile: None,
            }
        );
    }
}
