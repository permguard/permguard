// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Client for the stateful PDP interface, over either transport.

use permguard_languages::temporal::{
    HistoryScope, Outcome, PartitionEvaluation, Reason, SubmitRequest, SubmitResponse, Watermark,
};
use serde_json::Value;

use crate::catalog::Failure;
use crate::endpoint::Endpoint;
use crate::http::Client;
use crate::pdp_v1 as proto;
use crate::tls::TlsOptions;

const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub trait TemporalPdp {
    fn submit(&self, payload: &Value) -> Result<Value, Failure>;
    fn configuration(&self) -> Result<Value, Failure>;
}

pub fn client(
    url: &str,
    tls: &TlsOptions,
    narrator: Box<dyn crate::narrate::Narrator>,
) -> Result<Box<dyn TemporalPdp>, String> {
    if url.starts_with("grpc://") || url.starts_with("grpcs://") {
        return Ok(Box::new(GrpcTemporal::connect(url, tls, narrator)?));
    }
    let endpoint = Endpoint::parse(url).map_err(|error| error.to_string())?;

    Ok(Box::new(HttpTemporal::new(
        endpoint,
        tls.clone(),
        narrator,
    )?))
}

struct HttpTemporal {
    endpoint: Endpoint,
    client: Client,
}

impl HttpTemporal {
    fn new(
        endpoint: Endpoint,
        tls: TlsOptions,
        narrator: Box<dyn crate::narrate::Narrator>,
    ) -> Result<Self, String> {
        let client = Client::new(TIMEOUT, tls, endpoint.is_tls())
            .map_err(|error| error.to_string())?
            .with_narrator(narrator);

        Ok(Self { endpoint, client })
    }

    fn call(&self, method: &str, path: &str, body: Option<&str>) -> Result<Value, Failure> {
        let response = self
            .client
            .request(&self.endpoint, method, path, body)
            .map_err(|error| Failure {
                class: "unavailable".to_owned(),
                reason: error.reason().to_owned(),
                detail: error.to_string(),
                usage: false,
            })?;
        let parsed: Value = serde_json::from_str(&response.body).map_err(|error| Failure {
            class: "internal".to_owned(),
            reason: "decode_failed".to_owned(),
            detail: format!("the answer to {method} {path} was unreadable: {error}"),
            usage: false,
        })?;
        if (200..300).contains(&response.status) {
            return Ok(parsed);
        }

        Err(http_refusal(&parsed, response.status))
    }
}

impl TemporalPdp for HttpTemporal {
    fn submit(&self, payload: &Value) -> Result<Value, Failure> {
        // Read the same top-level contract before either transport. HTTP still sends the caller's
        // bytes unchanged; this check prevents the gRPC branch from becoming the stricter client.
        serde_json::from_value::<SubmitRequest>(payload.clone()).map_err(|error| Failure {
            class: "validation".to_owned(),
            reason: "payload_malformed".to_owned(),
            detail: error.to_string(),
            usage: true,
        })?;
        let answer = self.call(
            "POST",
            permguard_languages::temporal::SUBMISSION_PATH,
            Some(&payload.to_string()),
        )?;

        validated(answer)
    }

    fn configuration(&self) -> Result<Value, Failure> {
        self.call(
            "GET",
            permguard_languages::temporal::CONFIGURATION_PATH,
            None,
        )
    }
}

struct GrpcTemporal(crate::grpc::GrpcChannel);

impl GrpcTemporal {
    fn connect(
        url: &str,
        tls: &TlsOptions,
        narrator: Box<dyn crate::narrate::Narrator>,
    ) -> Result<Self, String> {
        Ok(Self(crate::grpc::GrpcChannel::connect(url, tls, narrator)?))
    }

    fn client(
        &self,
    ) -> proto::temporal_policy_decision_point_client::TemporalPolicyDecisionPointClient<
        tonic::transport::Channel,
    > {
        proto::temporal_policy_decision_point_client::TemporalPolicyDecisionPointClient::new(
            self.0.channel(),
        )
    }
}

impl TemporalPdp for GrpcTemporal {
    fn submit(&self, payload: &Value) -> Result<Value, Failure> {
        let request: SubmitRequest =
            serde_json::from_value(payload.clone()).map_err(|error| Failure {
                class: "validation".to_owned(),
                reason: "payload_malformed".to_owned(),
                detail: error.to_string(),
                usage: true,
            })?;
        let wire = to_proto(request)?;
        let mut client = self.client();
        let answer = self
            .0
            .run("SubmitEvent", client.submit_event(wire))
            .map_err(grpc_refusal)?;

        validated(from_proto(answer)?)
    }

    fn configuration(&self) -> Result<Value, Failure> {
        let mut client = self.client();
        let answer = self
            .0
            .run(
                "GetTemporalConfiguration",
                client.get_temporal_configuration(proto::GetTemporalConfigurationRequest {}),
            )
            .map_err(grpc_refusal)?;
        let endpoints = answer.endpoints.unwrap_or_default();
        let scope = answer.store_scope.unwrap_or_default();

        Ok(serde_json::json!({
            "interface": answer.r#interface,
            "pdp": answer.pdp,
            "endpoints": {"submission": endpoints.submission},
            "event_types": answer.event_types,
            "capabilities": answer.capabilities,
            "store_scope": {
                "in": scope.r#in,
                "zone": scope.zone,
                "ledger": scope.ledger,
                "profile": scope.profile,
            },
        }))
    }
}

fn to_proto(request: SubmitRequest) -> Result<proto::SubmitEventRequest, Failure> {
    let malformed = |detail: String| Failure {
        class: "validation".to_owned(),
        reason: "payload_malformed".to_owned(),
        detail,
        usage: true,
    };
    let store = request.store.map(|store| proto::EventStore {
        zone: store.zone.unwrap_or_default(),
        ledger: store.ledger.unwrap_or_default(),
        profile: store.profile.unwrap_or_default(),
    });
    let event = match request.event {
        Some(event) => {
            let data = match event.data {
                Some(Value::Object(map)) => {
                    crate::grpc::structure(Some(&map)).map_err(malformed)?
                }
                Some(_) => {
                    return Err(malformed(
                        "event.data must be an object on both transports".to_owned(),
                    ));
                }
                None => None,
            };
            Some(proto::TypedEvent {
                r#type: event.kind.unwrap_or_default(),
                data,
            })
        }
        None => None,
    };

    Ok(proto::SubmitEventRequest { store, event })
}

/// The answer contract both transports hold a plane to.
///
/// # Why this is shared rather than per transport
///
/// gRPC gets a shape for free: the generated types will not decode an answer that is missing its
/// outcome or its watermark, so the gRPC client refused malformed answers by accident of its
/// encoding. HTTP had no such accident — any JSON body under a 2xx was returned to the caller —
/// so the same plane behaving badly was caught on one transport and passed through on the other.
/// A client that is stricter on one wire is a client whose tests prove nothing about the other.
///
/// The cross-field rules are the part neither encoding could express. `decided` without a decision
/// is an answer that claims to have decided and does not say what; `accepted` *with* one is an
/// answer inventing a verdict for a submission that only recorded. Both are refused here rather
/// than handed on, because a caller that acts on them acts on an authorization answer nobody gave.
pub(crate) fn validated(answer: Value) -> Result<Value, Failure> {
    let refused = |detail: String| Failure {
        class: "internal".to_owned(),
        reason: "answer_malformed".to_owned(),
        detail,
        usage: false,
    };
    // Types and required members, from the one definition of the contract.
    let held: SubmitResponse = serde_json::from_value(answer.clone()).map_err(|error| {
        refused(format!(
            "the temporal answer does not hold its shape: {error}"
        ))
    })?;

    if held.watermark.instance.is_empty() {
        return Err(refused(
            "the temporal answer carries a watermark with no instance".to_owned(),
        ));
    }
    if held.history.mode.is_empty() {
        return Err(refused(
            "the temporal answer carries a history scope with no mode".to_owned(),
        ));
    }
    match held.outcome {
        Outcome::Decided => {
            if held.decision.is_none() {
                return Err(refused(
                    "the temporal answer says it decided and states no decision".to_owned(),
                ));
            }
            if held.decision_id.as_ref().is_none_or(|id| id.is_empty()) {
                return Err(refused(
                    "the temporal answer says it decided and names no decision id: an audit \
                     record nobody can be pointed at is not a decision"
                        .to_owned(),
                ));
            }
        }
        Outcome::Accepted => {
            if held.decision.is_some() || held.decision_id.is_some() {
                return Err(refused(
                    "the temporal answer only recorded the occurrence and still carries a \
                     decision: an accepted submission has no verdict to state"
                        .to_owned(),
                ));
            }
        }
    }

    Ok(answer)
}

fn from_proto(answer: proto::SubmitEventResponse) -> Result<Value, Failure> {
    let internal = |detail: String| Failure {
        class: "internal".to_owned(),
        reason: "decode_failed".to_owned(),
        detail,
        usage: false,
    };
    let outcome = match proto::SubmitOutcome::try_from(answer.outcome).ok() {
        Some(proto::SubmitOutcome::Decided) => Outcome::Decided,
        Some(proto::SubmitOutcome::Accepted) => Outcome::Accepted,
        _ => {
            return Err(internal(
                "the temporal answer carries no outcome".to_owned(),
            ));
        }
    };
    let watermark = answer
        .watermark
        .ok_or_else(|| internal("the temporal answer carries no watermark".to_owned()))?;
    let history = answer
        .history
        .ok_or_else(|| internal("the temporal answer carries no history scope".to_owned()))?;
    let response = SubmitResponse {
        outcome,
        event_id: answer.event_id,
        watermark: Watermark {
            instance: watermark.instance,
            sequence: watermark.sequence,
            history: (!watermark.history.is_empty()).then_some(watermark.history),
        },
        decision: answer.decision,
        decision_id: (!answer.decision_id.is_empty()).then_some(answer.decision_id),
        policies: answer.policies,
        evaluations: answer
            .evaluations
            .into_iter()
            .map(|evaluation| PartitionEvaluation {
                partition: evaluation.partition,
                decision: evaluation.decision,
                policies: evaluation.policies,
                reason: evaluation.reason.map(|reason| Reason {
                    code: reason.code,
                    message: reason.message,
                }),
            })
            .collect(),
        reason: answer.reason.map(|reason| Reason {
            code: reason.code,
            message: reason.message,
        }),
        history: HistoryScope {
            mode: history.mode,
            watermark: (!history.watermark.is_empty()).then_some(history.watermark),
            staleness_seconds: history.staleness_seconds,
            gaps: history.gaps,
        },
    };
    if matches!(response.outcome, Outcome::Decided) != response.decision.is_some() {
        return Err(internal(
            "the temporal outcome and decision presence disagree".to_owned(),
        ));
    }

    serde_json::to_value(response).map_err(|error| internal(error.to_string()))
}

fn http_refusal(parsed: &Value, status: u16) -> Failure {
    let field = |name: &str| {
        parsed
            .get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    Failure {
        class: match field("class").as_str() {
            "" => "unavailable".to_owned(),
            held => held.to_owned(),
        },
        reason: match field("code").as_str() {
            "" => format!("http_{status}"),
            held => held.to_owned(),
        },
        detail: match field("message") {
            held if held.is_empty() => format!("the endpoint refused status {status}"),
            held => held,
        },
        usage: (400..500).contains(&status),
    }
}

fn grpc_refusal(status: tonic::Status) -> Failure {
    let metadata = |key: &str| {
        status
            .metadata()
            .get(key)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned)
    };
    let (class, reason, usage) = match status.code() {
        tonic::Code::InvalidArgument => ("validation", "invalid_argument", true),
        tonic::Code::NotFound => ("not_found", "not_found", true),
        tonic::Code::AlreadyExists | tonic::Code::Aborted | tonic::Code::FailedPrecondition => {
            ("conflict", "conflict", true)
        }
        tonic::Code::Unavailable | tonic::Code::ResourceExhausted => {
            ("unavailable", "unavailable", false)
        }
        _ => ("internal", "internal", false),
    };

    Failure {
        class: metadata(crate::grpc::GRPC_ERROR_CLASS).unwrap_or_else(|| class.to_owned()),
        reason: metadata(crate::grpc::GRPC_ERROR_CODE).unwrap_or_else(|| reason.to_owned()),
        detail: status.message().to_owned(),
        usage,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accepted(staleness_seconds: Option<u64>) -> proto::SubmitEventResponse {
        proto::SubmitEventResponse {
            outcome: proto::SubmitOutcome::Accepted as i32,
            event_id: "event-1".to_owned(),
            watermark: Some(proto::EventWatermark {
                instance: "plane-1".to_owned(),
                sequence: 1,
                history: "history-1".to_owned(),
            }),
            decision: None,
            decision_id: String::new(),
            policies: Vec::new(),
            reason: None,
            history: Some(proto::DecisionHistory {
                mode: "shared-eventual".to_owned(),
                watermark: "import-1".to_owned(),
                staleness_seconds,
                gaps: 0,
            }),
            evaluations: Vec::new(),
        }
    }

    #[test]
    fn grpc_preserves_a_zero_staleness_value() {
        let answer = from_proto(accepted(Some(0))).expect("the answer converts");

        assert_eq!(answer["history"]["staleness_seconds"], 0);
    }

    #[test]
    fn grpc_preserves_an_absent_staleness_value() {
        let answer = from_proto(accepted(None)).expect("the answer converts");

        assert!(answer["history"].get("staleness_seconds").is_none());
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod contract_tests {
    use super::*;
    use serde_json::json;

    fn answer(outcome: &str, extra: Value) -> Value {
        let mut held = json!({
            "outcome": outcome,
            "event_id": "e-1",
            "watermark": {"instance": "i-1", "sequence": 1},
            "history": {"mode": "local", "staleness_seconds": 0, "gaps": 0},
            "policies": [],
            "evaluations": []
        });
        if let (Some(held), Some(extra)) = (held.as_object_mut(), extra.as_object()) {
            for (key, value) in extra {
                held.insert(key.clone(), value.clone());
            }
        }

        held
    }

    /// One table, and both transports answer to it.
    ///
    /// The rules are stated once because they are one contract: a plane does not become allowed to
    /// answer differently by being reached over a different wire. gRPC used to enforce the
    /// required members by accident of its encoding and HTTP enforced nothing, so the same bad
    /// answer was a refusal on one transport and a value on the other.
    #[test]
    fn the_same_answers_are_refused_whichever_transport_carried_them() {
        let decided = json!({"decision": true, "decision_id": "d-1"});
        let cases: Vec<(&str, Value, Option<&str>)> = vec![
            (
                "a decided answer that states its decision",
                answer("decided", decided.clone()),
                None,
            ),
            (
                "an accepted answer with no verdict",
                answer("accepted", json!({})),
                None,
            ),
            (
                "decided with no decision",
                answer("decided", json!({"decision_id": "d-1"})),
                Some("states no decision"),
            ),
            (
                "decided with no decision id",
                answer("decided", json!({"decision": true})),
                Some("names no decision id"),
            ),
            (
                "decided with an empty decision id",
                answer("decided", json!({"decision": true, "decision_id": ""})),
                Some("names no decision id"),
            ),
            (
                "accepted while carrying a decision",
                answer("accepted", json!({"decision": true})),
                Some("has no verdict to state"),
            ),
            (
                "a watermark with no instance",
                answer(
                    "accepted",
                    json!({"watermark": {"instance": "", "sequence": 1}}),
                ),
                Some("no instance"),
            ),
            (
                "a history scope with no mode",
                answer(
                    "accepted",
                    json!({"history": {"mode": "", "staleness_seconds": 0, "gaps": 0}}),
                ),
                Some("no mode"),
            ),
            (
                "an outcome nothing defines",
                answer("pondered", json!({})),
                Some("does not hold its shape"),
            ),
            (
                "a sequence that is not a number",
                answer(
                    "accepted",
                    json!({"watermark": {"instance": "i-1", "sequence": "one"}}),
                ),
                Some("does not hold its shape"),
            ),
        ];

        for (what, body, expected) in cases {
            match (validated(body), expected) {
                (Ok(_), None) => {}
                (Err(failure), Some(fragment)) => assert!(
                    failure.detail.contains(fragment),
                    "{what}: refused for the wrong reason: {}",
                    failure.detail
                ),
                (Ok(_), Some(fragment)) => {
                    panic!("{what}: was accepted and must be refused ({fragment})")
                }
                (Err(failure), None) => panic!("{what}: was refused: {}", failure.detail),
            }
        }
    }
}
