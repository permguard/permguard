// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The stream engine's golden vectors (`contracts/vectors/stream.json`, WP-5.1), computed by an
//! independent generator and reproduced here by `permguard_stream::engine`.

#![allow(clippy::expect_used)]

use permguard_core::domains::{digest, protected};
use permguard_objects::cose::Sign1;
use permguard_objects::crypto::suite::Suite;
use permguard_stream::engine::run::statement_digest;
use permguard_stream::engine::{
    Fence, RunEnd, RunStatement, State, decode_group, encode_group, record_digest,
};
use serde_json::Value;

fn vectors() -> Value {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../contracts/vectors/stream.json"
    ))
    .expect("the vectors read");
    serde_json::from_str(&text).expect("the vectors parse")
}

fn hex(value: &Value) -> Vec<u8> {
    let text = value.as_str().expect("hex text");
    (0..text.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
        .collect()
}

fn id(value: &Value) -> [u8; 16] {
    hex(value).try_into().expect("16 bytes")
}

/// The statement the envelope carries, verified under the vectors' operations key.
fn verified(v: &Value, envelope: &[u8]) -> Vec<u8> {
    let sign1 = Sign1::decode(envelope).expect("a COSE_Sign1");
    assert_eq!(
        sign1.header().expect("a header").kid,
        v["kid"].as_str().expect("a kid").as_bytes()
    );
    sign1
        .verify(
            Suite::Ed25519Sha256V1,
            &hex(&v["operations_public"]),
            protected::STREAM_RUN,
        )
        .expect("verifies")
        .to_vec()
}

#[test]
fn the_run_statements_are_the_bytes_the_independent_generator_computed() {
    let v = vectors();
    let producer = id(&v["producer_host_id"]);
    let genesis_envelope = hex(&v["genesis"]["cose_sign1"]);
    let payload = verified(&v, &genesis_envelope);
    assert_eq!(payload, hex(&v["genesis"]["payload"]));
    let genesis = RunStatement::decode(&payload).expect("decodes");
    assert_eq!(genesis.key.resource, v["resource"].as_str().expect("text"));
    assert_eq!(genesis.key.producer_host_id, producer);
    assert_eq!(genesis.run_id, id(&v["genesis"]["run_id"]));
    assert_eq!(genesis.producer_boot_id, id(&v["producer_boot_id"]));
    assert_eq!(
        genesis.fence,
        Some(Fence {
            membership_id: id(&v["membership_id"]),
            task_id: "decisions".to_owned(),
            epoch: 4,
        })
    );
    assert_eq!(genesis.predecessor, None);
    assert_eq!(genesis.encode().expect("encodes"), payload);
    assert_eq!(
        statement_digest(&genesis_envelope).to_vec(),
        hex(&v["genesis"]["digest"])
    );

    let successor_payload = verified(&v, &hex(&v["successor"]["cose_sign1"]));
    assert_eq!(successor_payload, hex(&v["successor"]["payload"]));
    let successor = RunStatement::decode(&successor_payload).expect("decodes");
    assert_eq!(successor.encode().expect("encodes"), successor_payload);
    let end = RunEnd::decode(&hex(&v["run_end"])).expect("decodes");
    assert_eq!(end.encode().expect("encodes"), hex(&v["run_end"]));
    assert_eq!(successor.predecessor, Some(end));
    assert_eq!(end.run_id, genesis.run_id);
    assert_eq!(
        successor.approval.map(|approval| approval.to_vec()),
        Some(hex(&v["successor"]["approval"]))
    );
}

#[test]
fn the_frames_and_states_are_the_bytes_the_independent_generator_computed() {
    let v = vectors();
    let records: Vec<Vec<u8>> = v["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|record| record.as_str().expect("text").as_bytes().to_vec())
        .collect();
    let group = encode_group(1, records.iter().map(Vec::as_slice)).expect("encodes");
    assert_eq!(group, hex(&v["group"]));
    assert_eq!(decode_group(&group).expect("decodes"), (1, records.clone()));
    assert_eq!(
        record_digest(digest::DECISION_RECORD, records.last().expect("a record")).to_vec(),
        hex(&v["last_record_digest"])
    );
    for name in ["state", "state_pending"] {
        let bytes = hex(&v[name]);
        let state = State::decode(&bytes).expect("decodes");
        assert_eq!(state.encode().expect("encodes"), bytes, "{name}");
        assert_eq!(state.run_id, id(&v["genesis"]["run_id"]));
    }
    let pending = State::decode(&hex(&v["state_pending"])).expect("decodes");
    assert_eq!(
        pending.pending_successor,
        Some(hex(&v["successor"]["cose_sign1"]))
    );
    assert_eq!(pending.forked_at_seq, Some(2));
}
