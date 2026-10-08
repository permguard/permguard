// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

#![allow(clippy::expect_used)]

use permguard_objects::cbor;

use super::*;
use crate::identity::record::uuid_v7;

fn host(byte: u8) -> [u8; 16] {
    uuid_v7(1_800_000_000_000, [byte; 10])
}

fn hello() -> Hello {
    Hello {
        version: VERSION,
        host: host(1),
        epoch: 1,
        declared_assurance: AssuranceProfile::Production,
        nonce: [3; NONCE_BYTES],
        operation: Operation::Enroll,
        membership_id: None,
        task: None,
    }
}

fn transcript() -> Transcript {
    Transcript {
        initiator_host: host(1),
        responder_host: host(2),
        initiator_epoch: 1,
        responder_epoch: 4,
        nonce_a: [3; NONCE_BYTES],
        nonce_b: [4; NONCE_BYTES],
        membership_id: Some("m-1".to_owned()),
        task: Some("replicate".to_owned()),
        operation: Operation::Task,
        expires_at: 1_800_000_060,
        tls_exporter: [5; EXPORTER_BYTES],
        hello_digest: hello_digest(b"hello"),
        challenge_digest: challenge_digest(b"challenge"),
        signer: Role::Responder,
    }
}

/// `bytes` with one more label: a closed map refuses it.
fn with_extra_label(bytes: &[u8]) -> Vec<u8> {
    let Value::Map(mut pairs) = cbor::decode_canonical(bytes).expect("decoded") else {
        panic!("a map")
    };
    pairs.push((Value::Int(99), Value::Int(0)));
    cbor::encode(&Value::Map(pairs)).expect("encoded")
}

#[test]
fn every_message_round_trips_and_refuses_an_unknown_label() {
    let hello = hello();
    let bytes = hello.encode().expect("encoded");
    assert_eq!(Hello::decode(&bytes).expect("decoded"), hello);
    assert!(Hello::decode(&with_extra_label(&bytes)).is_err());

    let challenge = Challenge {
        host: host(2),
        epoch: 4,
        declared_assurance: AssuranceProfile::Regulated,
        nonce: [4; NONCE_BYTES],
        expires: 1_800_000_060,
    };
    let bytes = challenge.encode().expect("encoded");
    assert_eq!(Challenge::decode(&bytes).expect("decoded"), challenge);
    assert!(Challenge::decode(&with_extra_label(&bytes)).is_err());

    let transcript = transcript();
    let bytes = transcript.encode().expect("encoded");
    assert_eq!(Transcript::decode(&bytes).expect("decoded"), transcript);
    assert!(Transcript::decode(&with_extra_label(&bytes)).is_err());

    let presentation = Presentation {
        document: vec![1, 2],
        successions: vec![vec![3], vec![4, 5]],
        first_public_key: vec![6; 32],
    };
    let bytes = presentation.encode().expect("encoded");
    assert_eq!(Presentation::decode(&bytes).expect("decoded"), presentation);
    assert!(Presentation::decode(&with_extra_label(&bytes)).is_err());
}

#[test]
fn an_absent_optional_member_is_omitted_never_null() {
    let without = Transcript {
        membership_id: None,
        task: None,
        ..transcript()
    };
    let Value::Map(pairs) =
        cbor::decode_canonical(&without.encode().expect("encoded")).expect("decoded")
    else {
        panic!("a map")
    };
    let labels: Vec<i64> = pairs
        .iter()
        .map(|(key, _)| match key {
            Value::Int(label) => *label,
            _ => panic!("integer labels"),
        })
        .collect();
    assert_eq!(labels, vec![1, 2, 3, 4, 5, 6, 7, 10, 11, 12, 13, 14, 15]);
    let Value::Map(pairs) =
        cbor::decode_canonical(&hello().encode().expect("encoded")).expect("decoded")
    else {
        panic!("a map")
    };
    assert_eq!(pairs.len(), 6);
}

#[test]
fn the_transcript_names_its_protocol_and_refuses_another() {
    let bytes = transcript().encode().expect("encoded");
    let Value::Map(mut pairs) = cbor::decode_canonical(&bytes).expect("decoded") else {
        panic!("a map")
    };
    assert_eq!(pairs[0].1, Value::Text(HOST_SESSION.to_owned()));
    pairs[0].1 = Value::Text(HOST_SESSION.replace(".v1", ".v2"));
    let other = cbor::encode(&Value::Map(pairs)).expect("encoded");
    assert!(Transcript::decode(&other).is_err());
}

#[test]
fn a_hello_out_of_its_bounds_is_refused() {
    let refused = |hello: Hello| {
        let bytes = hello.encode().expect("encoded");
        Hello::decode(&bytes).expect_err("refused")
    };
    refused(Hello {
        version: 2,
        ..hello()
    });
    refused(Hello {
        epoch: 0,
        ..hello()
    });
    let mut not_v7 = host(1);
    not_v7[6] = 0x40;
    refused(Hello {
        host: not_v7,
        ..hello()
    });
    refused(Hello {
        membership_id: Some("m".repeat(MAX_NAME_BYTES + 1)),
        ..hello()
    });
    refused(Hello {
        task: Some(String::new()),
        ..hello()
    });
    Hello::decode(
        &Hello {
            membership_id: Some("m".repeat(MAX_NAME_BYTES)),
            ..hello()
        }
        .encode()
        .expect("encoded"),
    )
    .expect("a name at its bound is accepted");
}

#[test]
fn a_nonce_of_another_length_an_unknown_operation_or_profile_is_refused() {
    let bytes = hello().encode().expect("encoded");
    let rewrite = |label: i64, value: Value| {
        let Value::Map(mut pairs) = cbor::decode_canonical(&bytes).expect("decoded") else {
            panic!("a map")
        };
        for pair in &mut pairs {
            if pair.0 == Value::Int(label) {
                pair.1 = value.clone();
            }
        }
        cbor::encode(&Value::Map(pairs)).expect("encoded")
    };
    assert!(Hello::decode(&rewrite(5, Value::Bytes(vec![3; NONCE_BYTES - 1]))).is_err());
    assert!(Hello::decode(&rewrite(5, Value::Bytes(vec![3; NONCE_BYTES + 1]))).is_err());
    assert!(Hello::decode(&rewrite(6, Value::Text("admin".to_owned()))).is_err());
    assert!(Hello::decode(&rewrite(4, Value::Text("trusted".to_owned()))).is_err());
}

#[test]
fn a_message_beyond_the_frame_bound_is_refused_before_it_is_parsed() {
    let presentation = Presentation {
        document: vec![0; MAX_FRAME_BYTES],
        successions: Vec::new(),
        first_public_key: Vec::new(),
    };
    let bytes = presentation.encode().expect("encoded");
    let refused = Presentation::decode(&bytes).expect_err("refused");
    assert!(refused.0.contains("beyond"), "{refused}");
}

#[test]
fn the_digests_are_domain_separated() {
    assert_ne!(hello_digest(b"same"), challenge_digest(b"same"));
    assert_ne!(hello_digest(b"one"), hello_digest(b"two"));
}
