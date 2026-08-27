// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Protobuf in, JSON out: the one file that knows both shapes of the same
//! request.
//!
//! It exists so [`super::grpc`] can stay about gRPC and [`super::decide`] can
//! stay about decisions. The mapping is mechanical and total — every field of
//! the proto has a field in the payload and the other way round — which is
//! what "the two transports are the same contract" has to mean in practice,
//! and what the round-trip test below actually checks.
//!
//! The free-form parts (`properties`, `context`, the entity graph) are
//! `google.protobuf.Struct` and `Value` on the wire: policy data, whose schema
//! belongs to a policy language and not to a transport.

use prost_types::{ListValue, Struct, Value as ProtoValue, value::Kind};
use serde_json::{Map, Value};

use std::collections::{BTreeMap, HashMap};

use super::wire::{
    ActionBody, CheckRequest, CheckResponse, Decision, DecisionContext, EntityBody, EvaluationBody,
    Malformed, OptionsBody, PartitionInputBody, Reason, Semantic,
};
use crate::v1::{
    Action as ProtoAction, Decision as ProtoDecision, DecisionContext as ProtoContext,
    Entity as ProtoEntity, EvaluateRequest, EvaluateResponse, Evaluation as ProtoEvaluation,
    EvaluationsSemantic, PartitionInput as ProtoPartitionInput, Reason as ProtoReason,
};

/// The payload a proto request means, **or a refusal**.
///
/// Only one thing here can fail, and it is the one thing proto3 cannot express: an enum value
/// nobody defined. The generated field is a plain `i32`, so a peer built against a newer — or
/// simply wrong — schema can send `47` for `evaluations_semantic`. Reading that as the default
/// answered a question the caller did not ask: they said "stop at the first permit" in a spelling
/// this build does not know, and got `execute_all`. HTTP refuses an unknown spelling outright,
/// because the contract's own enum does; this now says the same thing.
pub fn request_from_proto(request: EvaluateRequest) -> Result<CheckRequest, Malformed> {
    let semantic = semantic_from_proto(request.evaluations_semantic)?;

    Ok(CheckRequest {
        zone: some(request.zone),
        ledger: some(request.ledger),
        profile: some(request.profile),
        subject: request.subject.map(entity_from_proto),
        resource: request.resource.map(entity_from_proto),
        action: request.action.map(action_from_proto),
        context: request.context.map(map_from_struct),
        principal: request.principal.map(entity_from_proto),
        partition_inputs: inputs_from_proto(request.partition_inputs),
        // The removed extension has no field here to carry one: its tag is reserved in the
        // schema, so a peer still sending the old message cannot have its graph decoded as
        // something else. A gRPC caller hears about it the way an HTTP one does — from the
        // contract's own refusal — because there is nothing here for them to have sent.
        entities: None,
        evaluations: request
            .evaluations
            .into_iter()
            .map(evaluation_from_proto)
            .collect(),
        options: Some(OptionsBody {
            evaluations_semantic: semantic,
        }),
        request_id: some(request.request_id),
    })
}

/// The proto answer a payload answer means.
pub fn response_to_proto(response: CheckResponse) -> EvaluateResponse {
    EvaluateResponse {
        decision: response.decision,
        request_id: response.request_id.unwrap_or_default(),
        context: response.context.map(context_to_proto),
        evaluations: response
            .evaluations
            .unwrap_or_default()
            .into_iter()
            .map(decision_to_proto)
            .collect(),
    }
}

fn entity_from_proto(entity: ProtoEntity) -> EntityBody {
    EntityBody {
        kind: some(entity.r#type),
        id: some(entity.id),
        properties: entity.properties.map(map_from_struct),
    }
}

fn action_from_proto(action: ProtoAction) -> ActionBody {
    ActionBody {
        name: some(action.name),
        properties: action.properties.map(map_from_struct),
    }
}

/// The partition inputs a proto request carries, by the partition each names.
///
/// gRPC and HTTP carry the same extension, in the same shape, or the transport would be deciding
/// what a policy sees — which is the one thing a transport may not do.
fn inputs_from_proto(
    inputs: HashMap<String, ProtoPartitionInput>,
) -> BTreeMap<String, PartitionInputBody> {
    inputs
        .into_iter()
        .map(|(name, held)| {
            (
                name,
                PartitionInputBody {
                    kind: some(held.r#type),
                    data: held.data.map(json_from_proto),
                },
            )
        })
        .collect()
}

/// The other direction, for a client built from this contract.
pub fn inputs_to_proto(
    inputs: &BTreeMap<String, PartitionInputBody>,
) -> HashMap<String, ProtoPartitionInput> {
    inputs
        .iter()
        .map(|(name, held)| {
            (
                name.clone(),
                ProtoPartitionInput {
                    r#type: held.kind.clone().unwrap_or_default(),
                    data: held.data.as_ref().map(proto_from_json),
                },
            )
        })
        .collect()
}

fn evaluation_from_proto(evaluation: ProtoEvaluation) -> EvaluationBody {
    EvaluationBody {
        subject: evaluation.subject.map(entity_from_proto),
        resource: evaluation.resource.map(entity_from_proto),
        action: evaluation.action.map(action_from_proto),
        context: evaluation.context.map(map_from_struct),
        // The wrapper carries the distinction a map cannot: present — even with no entries —
        // replaces the request's defaults with exactly what it states, and absent inherits them.
        // Read as a bare map, `{}` was indistinguishable from "unset" and inherited, so the same
        // boxcarred request was decided against the defaults over gRPC and against nothing over
        // HTTP.
        partition_inputs: evaluation
            .partition_inputs
            .map(|held| inputs_from_proto(held.inputs)),
        entities: None,
        request_id: some(evaluation.request_id),
    }
}

fn semantic_from_proto(semantic: i32) -> Result<Option<Semantic>, Malformed> {
    match EvaluationsSemantic::try_from(semantic) {
        Ok(EvaluationsSemantic::DenyOnFirstDeny) => Ok(Some(Semantic::DenyOnFirstDeny)),
        Ok(EvaluationsSemantic::PermitOnFirstPermit) => Ok(Some(Semantic::PermitOnFirstPermit)),
        Ok(EvaluationsSemantic::ExecuteAll) => Ok(Some(Semantic::ExecuteAll)),
        // Unspecified is the default, which is what absent means everywhere else in this contract.
        Ok(EvaluationsSemantic::Unspecified) => Ok(None),
        // A number nobody defined. Not the default: the caller asked for something, and this build
        // does not know what.
        Err(_) => Err(Malformed {
            code: "field_unknown",
            message: format!(
                "`evaluations_semantic` is {semantic}, which is not a semantic this build defines \
                 (execute_all, deny_on_first_deny, permit_on_first_permit)"
            ),
        }),
    }
}

fn context_to_proto(context: DecisionContext) -> ProtoContext {
    ProtoContext {
        id: context.id.unwrap_or_default(),
        reason_admin: context.reason_admin.map(reason_to_proto),
        reason_user: context.reason_user.map(reason_to_proto),
        policies: context.policies,
    }
}

fn reason_to_proto(reason: Reason) -> ProtoReason {
    ProtoReason {
        code: reason.code,
        message: reason.message,
    }
}

fn decision_to_proto(decision: Decision) -> ProtoDecision {
    ProtoDecision {
        decision: decision.decision,
        request_id: decision.request_id.unwrap_or_default(),
        context: decision.context.map(context_to_proto),
    }
}

/// An empty proto string is an absent field: proto3 has no other way to say it,
/// and the contract's "absent" and "empty" mean the same thing here — a name
/// nobody wrote.
fn some(value: String) -> Option<String> {
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

/// A proto number that is a whole number, as JSON writes whole numbers.
///
/// `f64` is the only number proto carries, and `serde_json` renders `42f64` as `42.0`. Every
/// integer a caller wrote would arrive at a policy as a decimal — legal JSON, and not the value
/// they sent.
fn integral(value: f64) -> Option<serde_json::Number> {
    if value.fract() != 0.0 || !value.is_finite() {
        return None;
    }

    // Bounded by what a double represents *exactly*, not by what a `u64` holds. `u64::MAX as f64`
    // rounds up to 2^64, so a bound written that way accepts 2^64 and the cast then saturates it
    // back to `u64::MAX` — a number changed on the way through, silently. Past 2^53 a double no
    // longer counts one at a time, so nothing there is an integer anybody sent.
    if value.abs() > EXACT_INTEGER {
        return None;
    }

    #[allow(clippy::cast_possible_truncation)]
    Some(serde_json::Number::from(value as i64))
}

/// The largest integer an IEEE-754 double represents exactly: 2^53.
const EXACT_INTEGER: f64 = 9_007_199_254_740_992.0;

fn map_from_struct(value: Struct) -> Map<String, Value> {
    value
        .fields
        .into_iter()
        .map(|(key, value)| (key, json_from_proto(value)))
        .collect()
}

fn json_from_proto(value: ProtoValue) -> Value {
    match value.kind {
        None | Some(Kind::NullValue(_)) => Value::Null,
        Some(Kind::BoolValue(value)) => Value::Bool(value),
        // proto has one number type and JSON has two readings of it. A caller that sent `42` over
        // HTTP must not have it arrive as `42.0` over gRPC: Cedar has no floating-point type at
        // all, so the same request answered on one transport and refused as unreadable on the
        // other — the diagnosis differed, which is the same as the contract differing.
        Some(Kind::NumberValue(value)) => integral(value)
            .or_else(|| serde_json::Number::from_f64(value))
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Some(Kind::StringValue(value)) => Value::String(value),
        Some(Kind::ListValue(list)) => {
            Value::Array(list.values.into_iter().map(json_from_proto).collect())
        }
        Some(Kind::StructValue(value)) => Value::Object(map_from_struct(value)),
    }
}

/// The other direction, for the tests and for any client this workspace writes.
pub fn struct_from_map(map: &Map<String, Value>) -> Struct {
    Struct {
        fields: map
            .iter()
            .map(|(key, value)| (key.clone(), proto_from_json(value)))
            .collect(),
    }
}

/// The other direction of one value.
pub fn proto_from_json(value: &Value) -> ProtoValue {
    let kind = match value {
        Value::Null => Kind::NullValue(0),
        Value::Bool(value) => Kind::BoolValue(*value),
        Value::Number(value) => Kind::NumberValue(value.as_f64().unwrap_or_default()),
        Value::String(value) => Kind::StringValue(value.clone()),
        Value::Array(items) => Kind::ListValue(ListValue {
            values: items.iter().map(proto_from_json).collect(),
        }),
        Value::Object(map) => Kind::StructValue(struct_from_map(map)),
    };

    ProtoValue { kind: Some(kind) }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    #[test]
    fn a_proto_request_means_the_same_as_the_json_one() {
        let proto = EvaluateRequest {
            zone: "acme".to_owned(),
            ledger: "main-ledger".to_owned(),
            profile: String::new(),
            subject: Some(ProtoEntity {
                r#type: "user".to_owned(),
                id: "alice".to_owned(),
                properties: Some(struct_from_map(
                    json!({"department": "sales"})
                        .as_object()
                        .expect("an object"),
                )),
            }),
            resource: Some(ProtoEntity {
                r#type: "document".to_owned(),
                id: "budget".to_owned(),
                properties: None,
            }),
            action: Some(ProtoAction {
                name: "read".to_owned(),
                properties: None,
            }),
            context: Some(struct_from_map(
                json!({"tenant": "acme", "attempts": 2, "trusted": true})
                    .as_object()
                    .expect("an object"),
            )),
            principal: None,
            // Both partition inputs ride gRPC, each addressed by the partition's own name.
            partition_inputs: HashMap::from([
                (
                    "admin-cedar".to_owned(),
                    ProtoPartitionInput {
                        r#type: permguard_languages::input::CEDAR_ENTITIES_V1.to_owned(),
                        data: Some(proto_from_json(&json!([{"uid": {"type": "Group"}}]))),
                    },
                ),
                (
                    "admin-rego".to_owned(),
                    ProtoPartitionInput {
                        r#type: permguard_languages::input::REGO_DATA_V1.to_owned(),
                        data: Some(proto_from_json(&json!({"team": "payments"}))),
                    },
                ),
            ]),
            evaluations: vec![ProtoEvaluation {
                action: Some(ProtoAction {
                    name: "delete".to_owned(),
                    properties: None,
                }),
                request_id: "one".to_owned(),
                ..ProtoEvaluation::default()
            }],
            evaluations_semantic: EvaluationsSemantic::DenyOnFirstDeny as i32,
            request_id: "abc".to_owned(),
        };

        let payload = request_from_proto(proto).expect("the semantic is one this build defines");
        let resolved = payload.resolve(256).expect("it is well formed");

        assert_eq!(resolved.zone, "acme");
        assert_eq!(resolved.profile, super::super::wire::DEFAULT_PROFILE);
        assert_eq!(resolved.semantic, Semantic::DenyOnFirstDeny);
        assert_eq!(resolved.request_id.as_deref(), Some("abc"));
        assert_eq!(resolved.queries.len(), 1, "one boxcarred evaluation");
        let (query, request_id) = &resolved.queries[0];
        assert_eq!(request_id.as_deref(), Some("one"));
        assert_eq!(query.action.name, "delete", "the evaluation overrides");
        assert_eq!(query.subject.properties["department"], json!("sales"));
        // `2`, not `2.0`: what a caller sent over HTTP is what arrives over gRPC.
        assert_eq!(query.context["attempts"], json!(2));
        assert_eq!(query.context["trusted"], json!(true));
        // The inputs arrive as the caller addressed them, by name and by type. Who reads which is
        // decided at materialisation, against the ledger's own manifest.
        assert_eq!(query.partition_inputs.len(), 2);
        let cedar = query
            .partition_inputs
            .get("admin-cedar")
            .expect("the store survived the trip");
        assert_eq!(
            cedar.kind.as_deref(),
            Some(permguard_languages::input::CEDAR_ENTITIES_V1)
        );
        assert!(
            cedar.data.as_ref().expect("its data").is_array(),
            "a Cedar store is an array, and it crossed as one"
        );
        let rego = query
            .partition_inputs
            .get("admin-rego")
            .expect("the document survived the trip");
        assert_eq!(
            rego.kind.as_deref(),
            Some(permguard_languages::input::REGO_DATA_V1)
        );
        assert!(rego.data.as_ref().expect("its data").is_object());
    }

    #[test]
    fn an_answer_survives_the_trip_back() {
        let answer = CheckResponse {
            decision: false,
            request_id: Some("abc".to_owned()),
            context: Some(DecisionContext {
                id: Some("d1".to_owned()),
                reason_admin: Some(Reason {
                    code: "403".to_owned(),
                    message: "denied by 01a0".to_owned(),
                }),
                reason_user: Some(Reason {
                    code: "403".to_owned(),
                    message: "insufficient privileges".to_owned(),
                }),
                policies: vec!["01a0".to_owned()],
            }),
            evaluations: Some(vec![Decision {
                decision: true,
                request_id: Some("one".to_owned()),
                context: None,
            }]),
        };

        let proto = response_to_proto(answer);
        assert!(!proto.decision);
        assert_eq!(proto.request_id, "abc");
        let context = proto.context.expect("a context");
        assert_eq!(context.id, "d1");
        assert_eq!(context.policies, vec!["01a0".to_owned()]);
        assert_eq!(
            context.reason_admin.expect("an admin reason").message,
            "denied by 01a0"
        );
        assert_eq!(proto.evaluations.len(), 1);
        assert!(proto.evaluations[0].decision);
    }

    #[test]
    fn every_json_shape_crosses_and_comes_back() {
        // Protobuf's `Value` has one number type, an IEEE-754 double, and JSON has two readings of
        // it. A whole number therefore comes back whole: `1` used to arrive as `1.0`, and a policy
        // language with no floating-point type at all — Cedar — could not read it, so the same
        // request was answered over HTTP and refused as unreadable over gRPC. Everything else
        // crosses untouched, `1.5` included.
        let value = json!({
            "string": "s", "number": 1.5, "bool": false, "null": null,
            "whole": 42, "negative": -7,
            "list": [1, "two", {"three": 3}],
            "nested": {"deep": {"deeper": true}}
        });
        let object = value.as_object().expect("an object").clone();

        let round_tripped = Value::Object(map_from_struct(struct_from_map(&object)));
        assert_eq!(
            round_tripped, value,
            "what a caller sent is what a policy is given, on either transport"
        );
        assert!(
            round_tripped["whole"].is_u64() && round_tripped["negative"].is_i64(),
            "a whole number stays whole: {round_tripped}"
        );
        assert!(
            round_tripped["number"].as_f64() == Some(1.5),
            "and one that is not stays as it was"
        );
    }

    #[test]
    fn an_empty_proto_string_is_an_absent_field() {
        let payload = request_from_proto(EvaluateRequest::default()).expect("it converts");

        assert!(payload.zone.is_none(), "and so the request is refused");
        assert_eq!(
            payload.resolve(256).expect_err("refused").code,
            "zone_required"
        );
    }

    /// An evaluation that states **no** inputs and one that states **none** are different
    /// requests, and they stay different across the transport.
    ///
    /// The round trip a reviewer asked for, and the bug it found: `partition_inputs` was a bare
    /// proto3 map inside `Evaluation`, and a map cannot tell an absent field from an empty one.
    /// A caller writing `"partition_inputs": {}` over HTTP replaced the request's defaults with
    /// nothing; the same JSON mapped onto the old message arrived as zero entries, was read as
    /// "unset", and *inherited the defaults* — one request, two answers, decided by which
    /// transport carried it.
    #[test]
    fn an_evaluation_that_states_no_inputs_crosses_as_stating_none() {
        use permguard_languages::input::REGO_DATA_V1;

        // The payload as a PEP writes it, read by the very type the HTTP binding reads.
        let json = serde_json::json!({
            "zone": "acme", "ledger": "l",
            "subject": {"type": "User", "id": "alice"},
            "resource": {"type": "Service", "id": "payments-api"},
            "action": {"name": "read"},
            "partition_inputs": {
                "p": {"type": REGO_DATA_V1, "data": {"from": "the top"}}
            },
            "evaluations": [
                {"request_id": "inherits"},
                {"request_id": "states-none", "partition_inputs": {}}
            ]
        });
        let over_http: CheckRequest =
            serde_json::from_value(json).expect("the contract reads it");

        // The same payload, out to the wire and back — which is the trip a gRPC caller's request
        // actually makes.
        let proto = EvaluateRequest {
            zone: "acme".to_owned(),
            ledger: "l".to_owned(),
            subject: over_http.subject.clone().map(|held| ProtoEntity {
                r#type: held.kind.unwrap_or_default(),
                id: held.id.unwrap_or_default(),
                properties: None,
            }),
            resource: over_http.resource.clone().map(|held| ProtoEntity {
                r#type: held.kind.unwrap_or_default(),
                id: held.id.unwrap_or_default(),
                properties: None,
            }),
            action: Some(ProtoAction {
                name: "read".to_owned(),
                properties: None,
            }),
            partition_inputs: inputs_to_proto(&over_http.partition_inputs),
            evaluations: over_http
                .evaluations
                .iter()
                .map(|held| ProtoEvaluation {
                    request_id: held.request_id.clone().unwrap_or_default(),
                    partition_inputs: held.partition_inputs.as_ref().map(|inputs| {
                        crate::v1::PartitionInputs {
                            inputs: inputs_to_proto(inputs),
                        }
                    }),
                    ..ProtoEvaluation::default()
                })
                .collect(),
            ..EvaluateRequest::default()
        };
        let over_grpc = request_from_proto(proto).expect("it converts");

        // Both bindings, asked the same question, must give the same two questions.
        for (transport, request) in [("http", &over_http), ("grpc", &over_grpc)] {
            let asked = request.asked(256).expect("it is well formed");
            assert_eq!(asked.queries.len(), 2, "{transport}");

            let inherits = &asked.queries[0].0.partition_inputs;
            assert_eq!(
                inherits.len(),
                1,
                "{transport}: what an evaluation does not state, it inherits"
            );
            assert!(inherits.contains_key("p"), "{transport}");

            let states_none = &asked.queries[1].0.partition_inputs;
            assert!(
                states_none.is_empty(),
                "{transport}: `{{}}` replaces the defaults whole — it does not inherit them"
            );
        }
    }

    /// An enum value nobody defined is refused, not read as the default.
    ///
    /// proto3 gives an enum field as a plain `i32`, so a peer built against another schema — or
    /// simply wrong — can send anything. Reading `47` as `execute_all` answered a question the
    /// caller did not ask, and the HTTP binding refuses the same thing outright because the
    /// contract's own enum does.
    #[test]
    fn a_semantic_this_build_does_not_define_is_refused() {
        let refused = request_from_proto(EvaluateRequest {
            evaluations_semantic: 47,
            ..EvaluateRequest::default()
        })
        .expect_err("47 is not a semantic");

        assert_eq!(refused.code, "field_unknown");
        assert!(refused.message.contains("47"), "{}", refused.message);

        // And every value it does define still crosses.
        for defined in [
            EvaluationsSemantic::Unspecified,
            EvaluationsSemantic::ExecuteAll,
            EvaluationsSemantic::DenyOnFirstDeny,
            EvaluationsSemantic::PermitOnFirstPermit,
        ] {
            assert!(
                request_from_proto(EvaluateRequest {
                    evaluations_semantic: defined as i32,
                    ..EvaluateRequest::default()
                })
                .is_ok(),
                "{defined:?} is a semantic this build defines"
            );
        }
    }
}
