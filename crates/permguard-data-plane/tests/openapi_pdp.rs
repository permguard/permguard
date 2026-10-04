// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The data plane's REST documents, `pdp-native-v1.json` and `pdp-temporal-v1alpha1.json`, checked
//! against the wire types that serialise to them.
//!
//! Every value is built through the real types, so a renamed or added member fails here rather
//! than in a client; and `assert_covered` fails when a schema names a member no value carried, so
//! a document cannot describe a member the types no longer have.

#![allow(clippy::expect_used)]

use permguard_conformance::schema::Document;
use permguard_languages::request::{
    ActionBody, CheckRequest, CheckResponse, Decision, DecisionContext, EntityBody, EvaluationBody,
    OptionsBody, PartitionInputBody, Reason, Semantic,
};
use permguard_languages::temporal::{
    EventBody, HistoryScope, Outcome, PartitionEvaluation, StoreBody, SubmitRequest,
    SubmitResponse, Watermark,
};
use serde_json::{Map, Value, json};

fn open(value: Value) -> Option<Map<String, Value>> {
    value.as_object().cloned()
}

fn entity(kind: &str, id: &str) -> EntityBody {
    EntityBody {
        kind: Some(kind.to_owned()),
        id: Some(id.to_owned()),
        properties: open(json!({ "tier": "gold", "nested": { "any": [1, 2] } })),
    }
}

fn reason(code: &str) -> Reason {
    Reason {
        code: code.to_owned(),
        message: format!("because {code}"),
    }
}

fn context() -> DecisionContext {
    DecisionContext {
        id: Some("decision-1".to_owned()),
        reason_admin: Some(reason("denied")),
        reason_user: Some(reason("not_permitted")),
        policies: vec!["policy-a".to_owned()],
        absent_inputs: vec!["guardrail".to_owned()],
    }
}

#[test]
fn test_pdp_native_v1_document_describes_what_the_wire_types_serialise() {
    let doc = Document::load("pdp-native-v1.json");

    // The whole request, every member present, entities included (it is declared to be refused).
    let mut inputs = std::collections::BTreeMap::new();
    inputs.insert(
        "guardrail".to_owned(),
        PartitionInputBody {
            kind: Some("permguard.input.cedar.entities.v1".to_owned()),
            data: Some(json!([{ "uid": { "type": "User", "id": "a" } }])),
        },
    );
    let entry = EvaluationBody {
        subject: Some(entity("User", "bob")),
        resource: Some(entity("Doc", "d1")),
        action: Some(ActionBody {
            name: Some("read".to_owned()),
            properties: open(json!({ "mode": "fast" })),
        }),
        context: open(json!({ "ip": "10.0.0.1" })),
        partition_inputs: Some(inputs.clone()),
        entities: Some(json!([])),
        request_id: Some("entry-1".to_owned()),
    };
    let mut request = CheckRequest {
        zone: Some("zone".to_owned()),
        ledger: Some("ledger".to_owned()),
        profile: Some("default".to_owned()),
        subject: Some(entity("User", "alice")),
        resource: Some(entity("Doc", "d0")),
        action: Some(ActionBody {
            name: Some("write".to_owned()),
            properties: open(json!({})),
        }),
        context: open(json!({ "time": "noon" })),
        principal: Some(entity("Service", "gateway")),
        partition_inputs: inputs,
        entities: Some(json!({ "removed": true })),
        evaluations: vec![entry, EvaluationBody::default()],
        options: Some(OptionsBody {
            evaluations_semantic: Some(Semantic::ExecuteAll),
        }),
        request_id: Some("req-1".to_owned()),
    };
    doc.check("CheckRequest", &request);
    // The empty request is a request the plane refuses by name, not one the schema refuses.
    doc.check("CheckRequest", &CheckRequest::default());
    for semantic in [
        Semantic::ExecuteAll,
        Semantic::DenyOnFirstDeny,
        Semantic::PermitOnFirstPermit,
    ] {
        request.options = Some(OptionsBody {
            evaluations_semantic: Some(semantic),
        });
        doc.check("CheckRequest", &request);
        doc.check("Semantic", &semantic);
    }
    doc.check("OptionsBody", &OptionsBody::default());

    // The answers: single, and boxcarred with every optional member.
    let decided = Decision {
        decision: false,
        request_id: Some("entry-1".to_owned()),
        context: Some(context()),
    };
    doc.check("Decision", &decided);
    doc.check(
        "Decision",
        &Decision {
            decision: true,
            request_id: None,
            context: None,
        },
    );
    doc.check(
        "CheckResponse",
        &CheckResponse {
            decision: true,
            request_id: None,
            context: None,
            evaluations: None,
        },
    );
    doc.check(
        "CheckResponse",
        &CheckResponse {
            decision: false,
            request_id: Some("req-1".to_owned()),
            context: Some(context()),
            evaluations: Some(vec![decided]),
        },
    );
    doc.check("DecisionContext", &DecisionContext::default());

    // The discovery document, as the handler serves it: a value of the real type.
    let configuration = permguard_data_plane::authz::configuration::configuration("http://host/");
    doc.check("Configuration", &configuration);

    // Negative cases: the structural envelopes are closed, the dynamic containers are not.
    assert!(!doc.accepts_json("CheckRequest", &json!({ "zone": "z", "unknown": 1 })));
    assert!(!doc.accepts_json("CheckRequest", &json!({ "evaluations": [{ "bogus": 1 }] })));
    assert!(!doc.accepts_json("EntityBody", &json!({ "propertiez": {} })));
    assert!(!doc.accepts_json("OptionsBody", &json!({ "evaluations_semantic": "all" })));
    assert!(!doc.accepts_json("CheckResponse", &json!({ "decision": true, "extra": 1 })));
    assert!(!doc.accepts_json("CheckResponse", &json!({})));
    assert!(doc.accepts_json(
        "EntityBody",
        &json!({ "properties": { "anything": [1, null] } })
    ));

    doc.assert_covered();
}

#[test]
fn test_pdp_temporal_v1alpha1_document_describes_what_the_wire_types_serialise() {
    let doc = Document::load("pdp-temporal-v1alpha1.json");

    let request = SubmitRequest {
        store: Some(StoreBody {
            zone: Some("zone".to_owned()),
            ledger: Some("ledger".to_owned()),
            profile: Some("sessions".to_owned()),
        }),
        event: Some(EventBody {
            kind: Some("permguard.event.dogwood.v1".to_owned()),
            data: Some(json!({ "id": "e1", "anything": { "goes": true } })),
        }),
    };
    doc.check("SubmitRequest", &request);
    doc.check("SubmitRequest", &SubmitRequest::default());
    assert!(!doc.accepts_json("SubmitRequest", &json!({ "store": {}, "unknown": 1 })));
    assert!(!doc.accepts_json("SubmitRequest", &json!({ "event": { "bogus": 1 } })));
    assert!(!doc.accepts_json("SubmitRequest", &json!({ "store": { "region": "x" } })));

    // A decided answer carrying every optional member, once per history mode.
    let history = |mode: &str| HistoryScope {
        mode: mode.to_owned(),
        watermark: Some("wm-1".to_owned()),
        staleness_seconds: Some(12),
        gaps: 3,
    };
    for mode in ["local", "shared-eventual", "shared-bounded"] {
        doc.check(
            "SubmitResponse",
            &SubmitResponse {
                outcome: Outcome::Decided,
                event_id: "e1".to_owned(),
                watermark: Watermark {
                    instance: "instance-1".to_owned(),
                    sequence: 7,
                    history: Some("sha256:abc".to_owned()),
                },
                decision: Some(false),
                decision_id: Some("decision-1".to_owned()),
                policies: vec!["policy-a".to_owned()],
                evaluations: vec![
                    PartitionEvaluation {
                        partition: "sessions".to_owned(),
                        decision: false,
                        policies: vec!["policy-a".to_owned()],
                        reason: Some(permguard_languages::temporal::Reason {
                            code: "denied".to_owned(),
                            message: "no".to_owned(),
                        }),
                    },
                    PartitionEvaluation {
                        partition: "quiet".to_owned(),
                        decision: true,
                        policies: Vec::new(),
                        reason: None,
                    },
                ],
                reason: Some(permguard_languages::temporal::Reason {
                    code: "denied".to_owned(),
                    message: "no".to_owned(),
                }),
                history: history(mode),
            },
        );
    }
    // The other two outcomes carry no verdict, and a local history omits what it never had.
    for outcome in [Outcome::Accepted, Outcome::Indeterminate] {
        doc.check(
            "SubmitResponse",
            &SubmitResponse {
                outcome,
                event_id: "e2".to_owned(),
                watermark: Watermark {
                    instance: "instance-1".to_owned(),
                    sequence: 8,
                    history: None,
                },
                decision: None,
                decision_id: None,
                policies: Vec::new(),
                evaluations: Vec::new(),
                reason: None,
                history: HistoryScope::local(),
            },
        );
        doc.check("Outcome", &outcome);
    }
    assert!(!doc.accepts_json("Outcome", &json!("pending")));
    assert!(!doc.accepts_json("HistoryScope", &json!({ "mode": "shared-sometimes" })));

    // The discovery document, as the handler serves it.
    let configuration =
        permguard_data_plane::temporal::configuration::document("http://host/", "pdp-1");
    doc.check("Document", &configuration);

    // GET /events/v1alpha1/signers: the body is built with `json!` in the handler
    // (crates/permguard-data-plane/src/temporal/http.rs, `signers`), from the same types.
    let mut signers = permguard_stream::Signers::empty();
    let jwk = serde_json::to_value(permguard_core::keys::Jwk::okp(
        "k1", "Ed25519", "EdDSA", "AAAA",
    ))
    .expect("a public key serialises");
    signers
        .observe(0, "k1", &jwk)
        .expect("the first key is recorded");
    signers
        .observe(
            100,
            "k2",
            &serde_json::to_value(permguard_core::keys::Jwk::ec(
                "k2", "P-256", "ES256", "BBBB", "CCCC",
            ))
            .expect("a public key serialises"),
        )
        .expect("a rotation");
    let body = json!({
        "producer": permguard_events::Producer::data_plane("plane-1", "instance-1"),
        "durable_through": 120_u64,
        "signed_through": 110_u64,
        "acked_through": 100_u64,
        "spans": signers.covering(0, u64::MAX),
    });
    doc.check_json("SignersResponse", &body);
    doc.check_json(
        "SignersResponse",
        &json!({
            "producer": permguard_events::Producer::data_plane("plane-1", "instance-1"),
            "durable_through": 0,
            "signed_through": 0,
            "acked_through": 0,
            "spans": [],
        }),
    );
    assert!(!doc.accepts_json("SignersResponse", &json!({ "producer": {} })));

    doc.assert_covered();
}
