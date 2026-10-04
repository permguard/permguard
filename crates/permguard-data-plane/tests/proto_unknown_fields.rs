// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A protobuf field the contract does not name never changes what is decided (P8).
//!
//! Standard protobuf decoding skips an unknown field, so the request a policy sees is the request
//! without it: these vectors append unknown and retired fields, at the top level and inside an
//! evaluation, and prove the canonical question is byte-for-byte the one the clean request gives.
//! The interfaces model records the limit of this: a reader that skips cannot tell the caller
//! that it skipped, which is why `regulated` needs a decoder that detects unknown fields.

use permguard_data_plane::authz::translate::request_from_proto;
use permguard_data_plane::temporal::grpc::from_proto;
use permguard_data_plane::v1::{
    Action, Entity, EvaluateRequest, Evaluation, EventStore, SubmitEventRequest, TypedEvent,
};
use prost::Message;

fn entity(kind: &str, id: &str) -> Option<Entity> {
    Some(Entity {
        r#type: kind.to_owned(),
        id: id.to_owned(),
        properties: None,
    })
}

fn request() -> EvaluateRequest {
    EvaluateRequest {
        zone: "z".to_owned(),
        ledger: "l".to_owned(),
        profile: "p".to_owned(),
        subject: entity("user", "alice"),
        resource: entity("doc", "1"),
        action: Some(Action {
            name: "read".to_owned(),
            properties: None,
        }),
        evaluations: vec![Evaluation {
            subject: entity("user", "bob"),
            request_id: "e1".to_owned(),
            ..Evaluation::default()
        }],
        ..EvaluateRequest::default()
    }
}

/// A length-delimited field `number` carrying `payload`, appended raw.
fn field(number: u32, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::new();
    prost::encoding::encode_key(
        number,
        prost::encoding::WireType::LengthDelimited,
        &mut bytes,
    );
    prost::encoding::encode_varint(payload.len() as u64, &mut bytes);
    bytes.extend_from_slice(payload);
    bytes
}

#[test]
fn test_an_unknown_or_retired_protobuf_field_never_changes_the_canonical_question() {
    let clean = request().encode_to_vec();

    // The retired `entities` (9), a field no version defined (99), and an unknown field inside
    // the first evaluation (its retired 5 and an unknown 77).
    let mut evaluation = request().evaluations[0].encode_to_vec();
    evaluation.extend(field(5, b"{\"admin\":true}"));
    evaluation.extend(field(77, b"allow"));
    let mut dirty = request().encode_to_vec();
    dirty.extend(field(9, b"[{\"uid\":\"admin\"}]"));
    dirty.extend(field(99, b"permit"));
    dirty.extend(field(10, &evaluation));

    let read = |bytes: &[u8]| {
        let decoded = EvaluateRequest::decode(bytes).expect("a protobuf request decodes");
        serde_json::to_value(request_from_proto(decoded).expect("the request is well formed"))
            .expect("the canonical question serialises")
    };
    let mut expected = request();
    expected.evaluations.push(request().evaluations[0].clone());
    let expected = read(&expected.encode_to_vec());

    assert_eq!(read(&dirty), expected);
    assert_ne!(
        read(&clean),
        expected,
        "the appended evaluation is a real one"
    );
}

/// The temporal submission drives a decision too: an unknown field at the top level, inside the
/// store or inside the typed event changes nothing a policy sees.
#[test]
fn test_an_unknown_protobuf_field_never_changes_a_temporal_submission() {
    let submission = SubmitEventRequest {
        store: Some(EventStore {
            zone: "z".to_owned(),
            ledger: "l".to_owned(),
            profile: "p".to_owned(),
        }),
        event: Some(TypedEvent {
            r#type: "payments.transfer".to_owned(),
            data: None,
        }),
    };
    let read = |bytes: &[u8]| {
        let decoded = SubmitEventRequest::decode(bytes).expect("a protobuf submission decodes");
        serde_json::to_value(from_proto(decoded).expect("the submission is well formed"))
            .expect("the canonical submission serialises")
    };

    let mut store = submission.store.clone().expect("set").encode_to_vec();
    store.extend(field(9, b"other-zone"));
    let mut event = submission.event.clone().expect("set").encode_to_vec();
    event.extend(field(7, b"{\"amount\":0}"));
    let mut dirty = Vec::new();
    dirty.extend(field(1, &store));
    dirty.extend(field(2, &event));
    dirty.extend(field(42, b"permit"));

    assert_eq!(read(&dirty), read(&submission.encode_to_vec()));
}
