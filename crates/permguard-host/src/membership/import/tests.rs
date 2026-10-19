// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use super::super::record::Role;
use super::super::tests::Host;
use super::*;
use crate::composition::Payload as _;
use crate::keys::ring::{HOST_OPERATIONS, Ring};

fn checkpoint() -> Checkpoint {
    Checkpoint {
        coordinator: [1; 16],
        resource: "plane/data/zone/z/ledger/l".to_owned(),
        revision: [2; 32],
        origins: vec![
            CheckpointOrigin {
                host_id: [3; 16],
                runs: vec![
                    CheckpointRun {
                        run: [4; 16],
                        acked: 9,
                        oldest_retained: 1,
                        admitted_at: Some(1_700_000_000),
                    },
                    CheckpointRun {
                        run: [5; 16],
                        acked: 0,
                        oldest_retained: 1,
                        admitted_at: None,
                    },
                ],
            },
            // A required origin with nothing shipped yet.
            CheckpointOrigin {
                host_id: [6; 16],
                runs: Vec::new(),
            },
        ],
        issued_at: 1_700_000_100,
        channel_binding: [7; 32],
        ring_epoch: 0,
        key_set_digest: [0; 32],
    }
}

fn ring<'a>(host: &'a Host, id: &str) -> &'a Ring {
    host.rings
        .iter()
        .find(|ring| ring.id() == id)
        .expect("the ring")
}

/// The pin a manifest takes of `statement`, as its issuance builds it.
fn pin_of(statement: &RingStatement) -> RingPin {
    let payload = Sign1::decode(&statement.binding).expect("a binding");
    let binding = crate::keys::record::Binding::decode(payload.payload_unverified()).expect("read");
    RingPin {
        owner: Role::Coordinator,
        ring: statement.ring.clone(),
        epoch: statement.epoch,
        key_set_digest: binding.key_set_digest,
        binding: statement.binding.clone(),
        retiring: false,
    }
}

#[test]
fn a_request_reads_back_and_refuses_what_is_not_one() {
    for request in [
        Request::Origins,
        Request::Batch {
            host_id: [1; 16],
            run: [2; 16],
            seq: 3,
        },
    ] {
        assert_eq!(
            Request::decode(&request.encode().expect("encodes")).expect("decodes"),
            request
        );
    }
    let zero = encode(vec![
        (Value::Int(1), Value::Text(BATCH.to_owned())),
        (Value::Int(2), Value::Bytes(vec![1; 16])),
        (Value::Int(3), Value::Bytes(vec![2; 16])),
        (Value::Int(4), Value::Int(0)),
    ])
    .expect("encodes");
    assert!(Request::decode(&zero).is_err(), "sequences start at 1");
    let unknown =
        encode(vec![(Value::Int(1), Value::Text("everything".to_owned()))]).expect("encodes");
    assert!(Request::decode(&unknown).is_err());
    let extra = encode(vec![
        (Value::Int(1), Value::Text(ORIGINS.to_owned())),
        (Value::Int(9), Value::Int(1)),
    ])
    .expect("encodes");
    assert!(Request::decode(&extra).is_err(), "an unknown label");
    assert!(Request::decode(&vec![0; MAX_REQUEST_BYTES + 1]).is_err());
}

#[test]
fn origins_read_back_by_host_each_once() {
    let origin = |host: u8| Origin {
        host_id: [host; 16],
        membership_id: [host + 1; 16],
        manifest: vec![host; 8],
    };
    let answer = Origins {
        checkpoint: vec![9; 4],
        origins: vec![origin(1), origin(3)],
    };
    assert_eq!(
        Origins::decode(&answer.encode().expect("encodes")).expect("decodes"),
        answer
    );
    let unordered = Origins {
        checkpoint: Vec::new(),
        origins: vec![origin(3), origin(1)],
    };
    assert!(Origins::decode(&unordered.encode().expect("encodes")).is_err());
    let twice = Origins {
        checkpoint: Vec::new(),
        origins: vec![origin(1), origin(1)],
    };
    assert!(Origins::decode(&twice.encode().expect("encodes")).is_err());
    let many = Origins {
        checkpoint: Vec::new(),
        origins: (0..=MAX_ORIGINS as u8).map(origin).collect(),
    };
    assert!(Origins::decode(&many.encode().expect("encodes")).is_err());
}

#[test]
fn a_checkpoint_reads_back_and_refuses_an_impossible_run() {
    let held = checkpoint();
    assert_eq!(
        Checkpoint::decode(&held.encode().expect("encodes")).expect("decodes"),
        held
    );
    for (acked, oldest) in [(3, 0), (3, 5)] {
        let mut broken = checkpoint();
        broken.origins[0].runs[0].acked = acked;
        broken.origins[0].runs[0].oldest_retained = oldest;
        assert!(
            Checkpoint::decode(&broken.encode().expect("encodes")).is_err(),
            "acked {acked}, oldest retained {oldest}"
        );
    }
    // A run whose whole prefix went holds from past what it acknowledged.
    let mut gone = checkpoint();
    gone.origins[0].runs[0].oldest_retained = 10;
    assert!(Checkpoint::decode(&gone.encode().expect("encodes")).is_ok());
    let mut unordered = checkpoint();
    unordered.origins.reverse();
    assert!(Checkpoint::decode(&unordered.encode().expect("encodes")).is_err());
    let mut runs_unordered = checkpoint();
    runs_unordered.origins[0].runs.reverse();
    assert!(Checkpoint::decode(&runs_unordered.encode().expect("encodes")).is_err());
}

#[test]
fn a_signed_checkpoint_verifies_under_the_pinned_control_attest_and_nothing_else() {
    let host = Host::new("import-checkpoint");
    let control = ring(&host, CONTROL_ATTEST);
    let signed = checkpoint().sign_with(control).expect("signed");
    let statement = host.statement(CONTROL_ATTEST);
    let pin = pin_of(&statement);
    let read =
        verify_checkpoint(&signed, std::slice::from_ref(&statement), &pin).expect("it verifies");
    assert_eq!(read.origins, checkpoint().origins);
    assert_eq!(
        read.ring_epoch, pin.epoch,
        "the signer binds its ring's epoch"
    );
    assert_eq!(read.key_set_digest, pin.key_set_digest);

    // Another ring's pin, another Host's statement, a statement that is not the pinned one.
    let operations = host.statement(HOST_OPERATIONS);
    assert!(
        verify_checkpoint(
            &signed,
            std::slice::from_ref(&operations),
            &pin_of(&operations)
        )
        .is_err()
    );
    let other = Host::new("import-checkpoint-other");
    let foreign = other.statement(CONTROL_ATTEST);
    assert!(verify_checkpoint(&signed, std::slice::from_ref(&foreign), &pin).is_err());
    assert!(
        verify_checkpoint(&signed, std::slice::from_ref(&foreign), &pin_of(&foreign)).is_err(),
        "signed under another set"
    );
    // The right keys claimed as another ring's: only a `control.attest` pin verifies.
    let mut renamed = statement.clone();
    renamed.ring = HOST_OPERATIONS.to_owned();
    let mut renamed_pin = pin.clone();
    renamed_pin.ring = HOST_OPERATIONS.to_owned();
    assert!(
        verify_checkpoint(&signed, std::slice::from_ref(&renamed), &renamed_pin).is_err(),
        "a pin of another ring"
    );
    // The same keys pinned at another epoch: the checkpoint names the epoch it was signed at.
    let mut later = statement.clone();
    later.epoch += 1;
    let mut later_pin = pin.clone();
    later_pin.epoch += 1;
    assert!(
        verify_checkpoint(&signed, std::slice::from_ref(&later), &later_pin).is_err(),
        "signed at another epoch"
    );
    // Signed by another ring of the same Host, under the right content type.
    let forged = checkpoint()
        .sign_with(ring(&host, HOST_OPERATIONS))
        .expect("signed");
    assert!(verify_checkpoint(&forged, std::slice::from_ref(&statement), &pin).is_err());
    // Its claims changed after the signature.
    let Value::Array(mut parts) = permguard_objects::cbor::decode_canonical(&signed).expect("cbor")
    else {
        panic!("an envelope is an array");
    };
    let mut claims = Checkpoint::decode(&match &parts[2] {
        Value::Bytes(bytes) => bytes.clone(),
        _ => panic!("a payload"),
    })
    .expect("claims");
    claims.issued_at += 1;
    parts[2] = Value::Bytes(claims.encode().expect("encodes"));
    let tampered = permguard_objects::cbor::encode(&Value::Array(parts)).expect("encodes");
    assert!(verify_checkpoint(&tampered, std::slice::from_ref(&statement), &pin).is_err());
}

#[test]
fn the_revision_moves_with_the_origin_set_and_not_with_its_order() {
    let a = ([1; 16], [2; 16]);
    let b = ([4; 16], [5; 16]);
    let both = revision(&[a, b]).expect("a revision");
    assert_eq!(both, revision(&[b, a]).expect("a revision"));
    assert_ne!(both, revision(&[a]).expect("a revision"), "a member left");
    assert_ne!(
        both,
        revision(&[a, ([4; 16], [6; 16])]).expect("a revision"),
        "the same Host under another membership"
    );
}

#[test]
fn a_checkpoint_out_of_its_bounds_does_not_read() {
    for resource in [String::new(), "r".repeat(513)] {
        let mut held = checkpoint();
        held.resource = resource;
        assert!(Checkpoint::decode(&held.encode().expect("encodes")).is_err());
    }
    let mut at_bound = checkpoint();
    at_bound.resource = "r".repeat(512);
    assert!(Checkpoint::decode(&at_bound.encode().expect("encodes")).is_ok());
    let origin = |host: usize| CheckpointOrigin {
        host_id: (host as u128).to_be_bytes(),
        runs: Vec::new(),
    };
    let mut many = checkpoint();
    many.origins = (0..=MAX_ORIGINS).map(origin).collect();
    assert!(Checkpoint::decode(&many.encode().expect("encodes")).is_err());
    many.origins.pop();
    assert!(Checkpoint::decode(&many.encode().expect("encodes")).is_ok());
    let run = |at: usize| CheckpointRun {
        run: (at as u128).to_be_bytes(),
        acked: 1,
        oldest_retained: 1,
        admitted_at: None,
    };
    let mut runs = checkpoint();
    runs.origins = vec![
        CheckpointOrigin {
            host_id: [1; 16],
            runs: (0..MAX_CHECKPOINT_RUNS / 2).map(run).collect(),
        },
        CheckpointOrigin {
            host_id: [2; 16],
            runs: (0..=MAX_CHECKPOINT_RUNS / 2).map(run).collect(),
        },
    ];
    assert!(
        Checkpoint::decode(&runs.encode().expect("encodes")).is_err(),
        "the run bound counts over every origin"
    );
    runs.origins[1].runs.pop();
    assert!(Checkpoint::decode(&runs.encode().expect("encodes")).is_ok());
}
