// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each profile of the application does, built by itself.
//!
//! | Profile               | What is proven                                                        |
//! | --------------------- | --------------------------------------------------------------------- |
//! | no language           | policies have no engine to load them, and nothing is built            |
//! | `cedar`               | validated, compiled, decided: permit, deny, default, and the context  |
//! | `rego`                | validated, compiled, decided                                          |
//! | `dogwood`             | validated; refused by an evaluator that keeps no history              |
//! | `cedar,decisions`     | an answer becomes a record; a chain; a batch signed and verified      |
//! | `cedar,events`        | an event record with no decision record; a batch signed and verified  |
//! | both models           | one decision and what it was decided about, in two separate chains    |

#![allow(clippy::expect_used)]

#[allow(unused_imports)]
use permguard_evaluator::{Evaluator, Policies, Refused, Resolution};
#[allow(unused_imports)]
use permguard_evaluator_fixture::asks;

#[cfg(feature = "cedar")]
const READERS: &str = r#"permit (
    principal == User::"alice",
    action == Action::"read",
    resource == Document::"budget"
);"#;
#[cfg(feature = "cedar")]
const NOBODY_DELETES: &str = r#"forbid (principal, action == Action::"delete", resource);"#;

#[cfg(feature = "cedar")]
fn cedar() -> Evaluator {
    Evaluator::builder()
        .engine(permguard_evaluator::engines::cedar())
        .load(
            Policies::of("cedar")
                .policy("readers", READERS)
                .policy("nobody-deletes", NOBODY_DELETES),
        )
        .expect("Cedar reads its policies")
        .build()
        .expect("they compile")
}

#[cfg(not(any(feature = "cedar", feature = "rego", feature = "dogwood")))]
#[test]
fn with_no_language_nothing_loads_and_nothing_is_built() {
    let refused = Evaluator::builder()
        .load(Policies::of("cedar").policy("readers", "permit (principal, action, resource);"))
        .err()
        .expect("no engine reads Cedar in this build");
    assert_eq!(refused, Refused::NoEngine("cedar".to_owned()));

    let nothing = Evaluator::builder()
        .build()
        .err()
        .expect("nothing to decide with");
    assert_eq!(nothing, Refused::NothingLoaded);
}

#[cfg(feature = "cedar")]
#[test]
fn cedar_decides_who_may_do_what_to_what() {
    let evaluator = cedar();

    let allowed = evaluator
        .evaluate(&asks("alice", "read", "budget"))
        .expect("asked");
    assert!(allowed.permitted());
    assert_eq!(allowed.permits(), ["readers"]);

    let silent = evaluator
        .evaluate(&asks("bob", "read", "budget"))
        .expect("asked");
    assert_eq!(silent.resolution(), Resolution::DenyByDefault);

    let refused = evaluator
        .evaluate(&asks("alice", "delete", "budget"))
        .expect("asked");
    assert_eq!(refused.resolution(), Resolution::Deny);
    assert_eq!(refused.denials(), ["nobody-deletes"]);
}

#[cfg(feature = "cedar")]
#[test]
fn cedar_reads_the_context_of_a_request() {
    let evaluator = Evaluator::builder()
        .engine(permguard_evaluator::engines::cedar())
        .load(Policies::of("cedar").policy(
            "office-hours",
            r#"permit (principal, action, resource) when { context.office == true };"#,
        ))
        .expect("loaded")
        .build()
        .expect("built");
    let mut request = asks("alice", "read", "budget");

    request.context.insert("office".to_owned(), true.into());
    assert!(evaluator.evaluate(&request).expect("asked").permitted());
    request.context.insert("office".to_owned(), false.into());
    assert!(!evaluator.evaluate(&request).expect("asked").permitted());
}

#[cfg(feature = "rego")]
#[test]
fn rego_decides_who_may_do_what_to_what() {
    const GATEWAY: &str = "package gateway\nimport rego.v1\ndefault allow := false\nallow if { input.subject.id == \"alice\" }\n";
    let evaluator = Evaluator::builder()
        .engine(permguard_evaluator::engines::rego())
        .load(Policies::of("rego").policy("gateway", GATEWAY))
        .expect("Rego reads its policy")
        .build()
        .expect("it compiles");

    assert!(
        evaluator
            .evaluate(&asks("alice", "read", "budget"))
            .expect("asked")
            .permitted()
    );
    assert!(
        !evaluator
            .evaluate(&asks("bob", "read", "budget"))
            .expect("asked")
            .permitted()
    );
}

#[cfg(feature = "dogwood")]
#[test]
fn dogwood_is_linked_and_refused_by_an_evaluator_that_keeps_no_history() {
    let engine = permguard_evaluator::engines::dogwood();
    assert_eq!(engine.name(), "dogwood");

    let refused = Evaluator::builder()
        .engine(engine)
        .load(Policies::of("dogwood").policy("any", "permit (principal, action, resource);"))
        .err()
        .expect("Dogwood decides against a past");
    assert_eq!(refused, Refused::Temporal("dogwood".to_owned()));
}

/// A ring the application holds itself: Ed25519, published under its own name.
#[cfg(any(feature = "decisions", feature = "events"))]
mod ring_of_its_own {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
    use permguard_core::keys::{Jwk, KeyId, Result, Sign, Signature};
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    pub struct Ring(Ed25519KeyPair);

    pub const KID: &str = "application-key-1";

    impl Ring {
        pub fn generate() -> Self {
            let pkcs8 =
                Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).expect("a key");
            Self(Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("the key just made"))
        }

        pub fn published(&self) -> Vec<Jwk> {
            vec![Jwk::okp(
                KID,
                "Ed25519",
                "EdDSA",
                B64.encode(self.0.public_key().as_ref()),
            )]
        }
    }

    impl Sign for Ring {
        fn active_key_id(&self) -> Result<KeyId> {
            Ok(KeyId::new(KID))
        }

        fn sign(&self, payload: &[u8]) -> Result<Signature> {
            Ok(Signature::new(
                KeyId::new(KID),
                "EdDSA",
                self.0.sign(payload).as_ref().to_vec(),
            ))
        }
    }
}

#[cfg(all(feature = "cedar", feature = "decisions"))]
#[test]
fn an_answer_becomes_a_record_a_chain_and_a_signed_batch_with_no_host() {
    use permguard_decisions::record::{Body, GENESIS, Outcome, Sampling, digest_of};
    use permguard_decisions::{Envelope, Signed, chain, merkle};

    let evaluator = cedar();
    let mut prev = GENESIS.to_owned();
    let mut values = Vec::new();
    let mut digests = Vec::new();
    for (seq, (principal, action)) in [("alice", "read"), ("bob", "read"), ("alice", "delete")]
        .into_iter()
        .enumerate()
    {
        let request = asks(principal, action, "budget");
        let decision = evaluator.evaluate(&request).expect("asked");
        let record = permguard_evaluator_fixture::decision_record(
            &decision,
            &request,
            seq as u64 + 1,
            &prev,
        );
        // The record says what the evaluator said, in the record's own spelling.
        let Body::Decision(body) = &record.body else {
            panic!("a decision record");
        };
        assert_eq!(body.decision, decision.permitted());
        match decision.resolution() {
            Resolution::Permit => {
                assert_eq!(body.outcome, Some(Outcome::Permit));
                assert_eq!(body.policies, ["readers"]);
                assert_eq!(body.reason.code, "200");
            }
            Resolution::DenyByDefault => {
                assert_eq!(body.outcome, Some(Outcome::DenyByDefault));
                assert!(body.policies.is_empty());
                assert_eq!(body.reason.code, "403");
            }
            Resolution::Deny => {
                assert_eq!(body.outcome, Some(Outcome::Deny));
                assert_eq!(body.policies, ["nobody-deletes"]);
            }
            Resolution::Indeterminate => panic!("nothing failed"),
        }
        assert_eq!(body.causes, None);

        let value = record.to_value().expect("it serializes");
        prev = digest_of(&value).expect("it digests");
        digests.push(prev.clone());
        values.push(value);
    }

    let verified = chain::verify(&values, Some(GENESIS)).expect("a chain");
    assert_eq!((verified.first_seq, verified.last_seq), (1, 3));
    assert_eq!(verified.head, prev);

    // Signed under a ring the application holds, verified against the set it publishes.
    let keys = ring_of_its_own::Ring::generate();
    let envelope = Envelope {
        stream: verified.stream.clone(),
        first_seq: 1,
        last_seq: 3,
        count: 3,
        previous_head: GENESIS.to_owned(),
        head: verified.head.clone(),
        merkle_root: merkle::root(&digests).expect("three leaves"),
        sampling: Sampling {
            permits: "1.0".to_owned(),
        },
        at: "2026-11-17T10:00:05Z".to_owned(),
    };
    let signed = Signed::create(&envelope, &keys).expect("signed");
    assert_eq!(
        signed.verify(&keys.published()).expect("verifies"),
        envelope
    );

    // Another ring's set does not verify it.
    let other = ring_of_its_own::Ring::generate();
    assert!(signed.verify(&other.published()).is_err());
}

#[cfg(feature = "events")]
#[test]
fn an_event_record_needs_no_decision_record() {
    use permguard_events::envelope::{Envelope, Signed};
    use permguard_events::record::{GENESIS, VERSION, digest_of, validate};
    use permguard_events::{chain, merkle};

    let mut prev = GENESIS.to_owned();
    let mut values = Vec::new();
    for seq in 1..=2u64 {
        let record = permguard_evaluator_fixture::event_record(
            seq,
            &prev,
            serde_json::json!({"user": "alice", "n": seq}),
        );
        let value = record.to_value().expect("it serializes");
        assert_eq!(validate(&value).expect("a valid event record"), record);
        prev = digest_of(&value).expect("it digests");
        values.push(value);
    }

    let verified = chain::verify(&values, Some(GENESIS)).expect("a chain");
    assert_eq!(verified.head, prev);

    let keys = ring_of_its_own::Ring::generate();
    let envelope = Envelope {
        stream: verified.stream.clone(),
        first_seq: 1,
        last_seq: 2,
        count: 2,
        previous_head: GENESIS.to_owned(),
        head: verified.head.clone(),
        merkle_root: merkle::root(&verified.digests).expect("two leaves"),
        event_types: vec!["application.login.v1".to_owned()],
        record_version: VERSION,
        at: "2026-11-17T10:00:05Z".to_owned(),
    };
    let signed = Signed::create(&envelope, &keys).expect("signed");
    assert_eq!(
        signed.verify(&keys.published()).expect("verifies"),
        envelope
    );
}

#[cfg(all(feature = "cedar", feature = "decisions", feature = "events"))]
#[test]
fn a_decision_and_what_happened_are_two_chains_kept_together_with_no_store() {
    use permguard_decisions::record as decisions;
    use permguard_events::record as events;

    let evaluator = cedar();
    let request = asks("alice", "read", "budget");
    let decision = evaluator.evaluate(&request).expect("asked");

    let decided =
        permguard_evaluator_fixture::decision_record(&decision, &request, 1, decisions::GENESIS)
            .to_value()
            .expect("it serializes");
    let happened = permguard_evaluator_fixture::event_record(
        1,
        events::GENESIS,
        serde_json::json!({"user": "alice"}),
    )
    .to_value()
    .expect("it serializes");

    permguard_decisions::chain::verify(std::slice::from_ref(&decided), None).expect("a chain");
    permguard_events::chain::verify(std::slice::from_ref(&happened), None).expect("a chain");
    // Two domains: one value digests differently as a decision record and as an event record.
    assert_ne!(
        decisions::digest_of(&decided).expect("it digests"),
        events::digest_of(&decided).expect("it digests")
    );
}
