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

/// The `data.attest` key of the vectors (RFC 8032 section 7.1 test 1), signing as a ring would.
struct VectorSigner(ring::signature::Ed25519KeyPair, String);

impl permguard_core::keys::Sign for VectorSigner {
    fn active_key_id(&self) -> permguard_core::keys::Result<permguard_core::keys::KeyId> {
        Ok(permguard_core::keys::KeyId::new(self.1.clone()))
    }

    fn sign(
        &self,
        payload: &[u8],
    ) -> permguard_core::keys::Result<permguard_core::keys::Signature> {
        Ok(permguard_core::keys::Signature::new(
            permguard_core::keys::KeyId::new(self.1.clone()),
            "EdDSA",
            self.0.sign(payload).as_ref().to_vec(),
        ))
    }
}

/// WP-5.2: the two chained batches, built here from the stream key, the run's fence and the
/// records, are the generator's bytes; each verifies and answers its envelope and records; the
/// signer spans and the cutover are its CBOR.
#[test]
fn the_sealed_batch_is_the_bytes_the_independent_generator_computed() {
    use permguard_stream::engine::batch::{
        Envelope, GENESIS_HEAD, KeyView, SealedBatch, digest_string,
    };
    use permguard_stream::engine::{Cutover, Span, Spans, StreamKey};
    let v = vectors();
    let b = &v["batches"];
    let jwk: permguard_core::keys::Jwk =
        serde_json::from_value(b["attest_jwk"].clone()).expect("a JWK");
    let signer = VectorSigner(
        ring::signature::Ed25519KeyPair::from_seed_unchecked(&hex(&Value::from(
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        )))
        .expect("the seed"),
        jwk.kid.clone(),
    );
    let records: Vec<Vec<u8>> = b["records"]
        .as_array()
        .expect("records")
        .iter()
        .map(|record| record.as_str().expect("text").as_bytes().to_vec())
        .collect();
    let run = id(&v["genesis"]["run_id"]);
    let key = StreamKey::new(
        "data",
        "decisions",
        1,
        v["resource"].as_str().expect("a resource"),
        id(&v["producer_host_id"]),
    )
    .expect("a key");
    let membership = id(&v["membership_id"]);
    let envelope = |first: u64, batch: &[Vec<u8>], previous: String| {
        let digests: Vec<String> = batch
            .iter()
            .map(|record| digest_string(digest::DECISION_RECORD, record))
            .collect();
        let run_hex: String = run.iter().map(|byte| format!("{byte:02x}")).collect();
        Envelope {
            descriptor_version: 1,
            stream_key: KeyView::of(&key),
            run: run_hex.clone(),
            membership_id: Some(permguard_host::identity::record::uuid_text(&membership)),
            epoch: Some(4),
            first_seq: first,
            last_seq: first + batch.len() as u64 - 1,
            count: batch.len() as u64,
            previous_head: previous,
            head: digests.last().cloned().expect("a record"),
            merkle_root: permguard_stream::merkle::root(&digests).expect("a root"),
            batch_id: format!("{run_hex}-{first}"),
            created_at: permguard_core::time::to_rfc3339(1_800_000_200),
            key_set_epoch: 1,
        }
    };
    let first = envelope(1, &records[..2], GENESIS_HEAD.to_owned());
    let second = envelope(3, &records[2..], first.head.clone());
    for (envelope, batch, name) in [
        (&first, &records[..2], "first"),
        (&second, &records[2..], "second"),
    ] {
        let file = b[name]["file"].as_str().expect("a file").as_bytes();
        let sealed = SealedBatch::seal(&signer, &jwk, protected::DECISION_BATCH, envelope, batch)
            .expect("sealed")
            .encode()
            .expect("encoded");
        assert_eq!(sealed, file, "the {name} batch");
        let (read, carried) = SealedBatch::decode(file)
            .expect("decodes")
            .verify(
                std::slice::from_ref(&jwk),
                protected::DECISION_BATCH,
                digest::DECISION_RECORD,
            )
            .expect("verifies");
        assert_eq!(&read, envelope);
        assert_eq!(carried, batch);
        assert_eq!(
            serde_json::to_value(&read).expect("JSON"),
            b[name]["envelope"]
        );
    }
    let signers = hex(&b["signers"]);
    let spans = Spans::decode(&signers).expect("the spans decode");
    assert_eq!(
        spans,
        Spans {
            runs: vec![(
                run,
                vec![Span {
                    from_seq: 1,
                    kid: jwk.kid.clone(),
                    jwk: permguard_stream::engine::canonical_jwk(&jwk).expect("canonical"),
                }]
            )]
        }
    );
    assert_eq!(spans.encode().expect("encodes"), signers);
    let cutover = hex(&b["cutover"]);
    let decoded = Cutover::decode(&cutover).expect("the cutover decodes");
    assert_eq!(
        decoded,
        Cutover {
            stream: format!(
                "data/decisions/{}/{}",
                key.resource_component(),
                v["genesis"]["run_id"].as_str().expect("hex")
            ),
            membership_id: membership,
            ring: "data.attest".to_owned(),
            kid: "data.attest:next".to_owned(),
            from_seq: 4,
            confirmed: false,
        }
    );
    assert_eq!(decoded.stream, b["stream"].as_str().expect("a stream"));
    assert_eq!(decoded.encode().expect("encodes"), cutover);
}

/// WP-5.3: the ship message, the answers, a consumer's STATE and a fork mark are the bytes the
/// independent generator computed.
#[test]
fn the_ingest_records_are_the_bytes_the_independent_generator_computed() {
    use permguard_stream::engine::ingest::{Answer, Outcome, Ship};
    use permguard_stream::engine::{ConsumerState, ForkMark};
    let v = vectors();
    let i = &v["ingest"];
    let ship = Ship {
        batch: v["batches"]["first"]["file"]
            .as_str()
            .expect("a file")
            .as_bytes()
            .to_vec(),
        statement: hex(&i["statement"]),
    };
    assert_eq!(ship.encode().expect("encodes"), hex(&i["ship"]));
    assert_eq!(Ship::decode(&hex(&i["ship"])).expect("decodes"), ship);
    let ok = Answer::of(Outcome::Ok, 2);
    assert_eq!(ok.encode().expect("encodes"), hex(&i["answer_ok"]));
    let ahead = Answer {
        outcome: Outcome::OutOfOrder,
        acked: 2,
        expected_seq: Some(3),
    };
    assert_eq!(
        ahead.encode().expect("encodes"),
        hex(&i["answer_out_of_order"])
    );
    assert_eq!(
        Answer::decode(&hex(&i["answer_out_of_order"])).expect("decodes"),
        ahead
    );
    // A STATE written before WP-6.1b, with no opening time: the same bytes as before.
    let state = ConsumerState {
        acked: 2,
        oldest_retained: 1,
        opened: None,
    };
    assert_eq!(state.encode().expect("encodes"), hex(&i["consumer_state"]));
    let mark = ForkMark {
        run: id(&v["genesis"]["run_id"]),
        at_seq: 3,
    };
    assert_eq!(mark.encode().expect("encodes"), hex(&i["fork_mark"]));
    assert_eq!(
        ForkMark::decode(&hex(&i["fork_mark"])).expect("decodes"),
        mark
    );
}

/// WP-5.4: a producer's subscriptions, active, paused and stopped, are the bytes the independent
/// generator computed.
#[test]
fn the_subscriptions_are_the_bytes_the_independent_generator_computed() {
    use permguard_stream::engine::{Subscription, SubscriptionState};
    let v = vectors();
    let f = &v["fanout"];
    let membership = id(&v["membership_id"]);
    let run = id(&v["genesis"]["run_id"]);
    for (name, subscription) in [
        (
            "subscription_active",
            Subscription {
                membership_id: membership,
                task_id: "decisions".to_owned(),
                required: true,
                runs: vec![(run, 2)],
                boots: Vec::new(),
                points: Vec::new(),
                state: SubscriptionState::Active,
            },
        ),
        (
            "subscription_paused",
            Subscription {
                membership_id: membership,
                task_id: "decisions".to_owned(),
                required: false,
                runs: Vec::new(),
                boots: Vec::new(),
                points: Vec::new(),
                state: SubscriptionState::Paused { epoch: 4 },
            },
        ),
        (
            "subscription_stopped",
            Subscription {
                membership_id: membership,
                task_id: "decisions".to_owned(),
                required: true,
                runs: Vec::new(),
                boots: Vec::new(),
                points: Vec::new(),
                state: SubscriptionState::Stopped {
                    reason: "fork".to_owned(),
                },
            },
        ),
    ] {
        assert_eq!(
            subscription.encode().expect("encodes"),
            hex(&f[name]),
            "{name}"
        );
        assert_eq!(
            Subscription::decode(&hex(&f[name])).expect("decodes"),
            subscription
        );
    }
}
