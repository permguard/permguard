// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The client's trust boundary, attacked one lie at a time.
//!
//! `verify_statement` is what stands between a workspace and a compromised
//! or impersonated server: every test here presents one specific forgery —
//! a foreign key, a swapped kid, a tampered byte, a replayed counter, a
//! statement for somebody else's ledger — and asserts the refusal, with the
//! words an operator would read. The one happy path at the top is the
//! baseline that proves the refusals are refusals, not breakage.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use base64::Engine as _;
use permguard_control_client::checkpoint::Checkpoint;
use permguard_control_client::verify::verify_statement;
use permguard_objects::digest::Digest;
use permguard_objects::statement::{HeadStatement, SignedHead};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

const ZONE: &str = "zone-guid";
const LEDGER: &str = "ledger-guid";
const REF: &str = "main";

fn keypair() -> Ed25519KeyPair {
    let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).expect("a key generates");
    Ed25519KeyPair::from_pkcs8(doc.as_ref()).expect("the key loads")
}

fn jwks_for(kid: &str, key: &Ed25519KeyPair) -> Vec<u8> {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref());
    format!(
        r#"{{"keys":[{{"kid":"{kid}","kty":"OKP","crv":"Ed25519","x":"{x}","alg":"EdDSA","use":"sig"}}]}}"#
    )
    .into_bytes()
}

fn statement(counter: u64, content: &[u8]) -> HeadStatement {
    HeadStatement {
        zone: ZONE.into(),
        ledger: LEDGER.into(),
        r#ref: REF.into(),
        digest: Digest::compute(content),
        counter,
        signed_at: 1_700_000_000,
    }
}

fn signed(statement: &HeadStatement, kid: &[u8], key: &Ed25519KeyPair) -> Vec<u8> {
    SignedHead::sign(statement, key, kid)
        .expect("the statement signs")
        .encode()
}

fn checkpoint(counter: u64, content: &[u8]) -> Checkpoint {
    Checkpoint {
        head: Digest::compute(content).to_string(),
        counter,
    }
}

/// Runs the verification against the standard identity, returning the error.
fn refused(jwks: &[u8], envelope: &[u8], checkpoint: Option<&Checkpoint>) -> String {
    verify_statement(jwks, envelope, ZONE, LEDGER, REF, checkpoint)
        .expect_err("the forgery must be refused")
}

#[test]
fn the_honest_case_verifies_and_advances() {
    let key = keypair();
    let envelope = signed(&statement(2, b"new"), b"k1", &key);

    let verified = verify_statement(
        &jwks_for("k1", &key),
        &envelope,
        ZONE,
        LEDGER,
        REF,
        Some(&checkpoint(1, b"old")),
    )
    .expect("an honest statement verifies");

    assert_eq!(verified.counter, 2);
    assert_eq!(verified.digest, Digest::compute(b"new"));
}

#[test]
fn seeing_the_same_head_again_is_not_an_attack() {
    // A retried pull presents the counter the checkpoint already holds, with
    // the same digest: idempotence, not equivocation.
    let key = keypair();
    let envelope = signed(&statement(2, b"same"), b"k1", &key);

    verify_statement(
        &jwks_for("k1", &key),
        &envelope,
        ZONE,
        LEDGER,
        REF,
        Some(&checkpoint(2, b"same")),
    )
    .expect("the same head twice is fine");
}

#[test]
fn a_kid_the_ring_never_published_is_refused() {
    let key = keypair();
    let envelope = signed(&statement(1, b"x"), b"rogue-key", &key);

    let error = refused(&jwks_for("k1", &key), &envelope, None);
    assert!(error.contains("no key `rogue-key`"), "{error}");
}

#[test]
fn a_signature_from_the_wrong_key_is_refused_even_under_the_right_kid() {
    // The impersonation case: the attacker knows a published kid but not its
    // private half, so they sign with their own key and borrow the name.
    let ring_key = keypair();
    let attacker = keypair();
    let envelope = signed(&statement(1, b"x"), b"k1", &attacker);

    let error = refused(&jwks_for("k1", &ring_key), &envelope, None);
    assert!(error.contains("does not verify"), "{error}");
}

#[test]
fn a_key_outside_the_pinned_profile_is_refused_before_any_crypto_runs() {
    let key = keypair();
    let envelope = signed(&statement(1, b"x"), b"k1", &key);
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.public_key().as_ref());

    // The right key material presented under the wrong profile: refused on
    // the profile, so nothing downstream ever depends on a lax ring.
    for wrong in [
        format!(r#"{{"keys":[{{"kid":"k1","kty":"RSA","x":"{x}","alg":"EdDSA"}}]}}"#),
        format!(
            r#"{{"keys":[{{"kid":"k1","kty":"OKP","crv":"X25519","x":"{x}","alg":"EdDSA"}}]}}"#
        ),
        format!(
            r#"{{"keys":[{{"kid":"k1","kty":"OKP","crv":"Ed25519","x":"{x}","alg":"none"}}]}}"#
        ),
    ] {
        let error = refused(wrong.as_bytes(), &envelope, None);
        assert!(error.contains("pinned Ed25519 profile"), "{error}");
    }
}

#[test]
fn a_tampered_envelope_is_refused() {
    let key = keypair();
    let mut envelope = signed(&statement(1, b"x"), b"k1", &key);
    // Flip one bit near the end — inside the signature or the payload,
    // either way the envelope no longer attests what it claims.
    let last = envelope.len() - 1;
    envelope[last] ^= 0x01;

    let error = refused(&jwks_for("k1", &key), &envelope, None);
    assert!(
        error.contains("does not verify") || error.contains("does not parse"),
        "{error}"
    );
}

#[test]
fn a_statement_for_somebody_elses_ledger_is_refused() {
    let key = keypair();
    let jwks = jwks_for("k1", &key);

    let mut foreign = statement(1, b"x");
    foreign.ledger = "other-ledger".into();
    let error = refused(&jwks, &signed(&foreign, b"k1", &key), None);
    assert!(error.contains("not the tracked ledger"), "{error}");

    let mut foreign = statement(1, b"x");
    foreign.zone = "other-zone".into();
    let error = refused(&jwks, &signed(&foreign, b"k1", &key), None);
    assert!(error.contains("not the tracked ledger"), "{error}");
}

#[test]
fn a_statement_for_another_ref_is_refused() {
    let key = keypair();
    let mut foreign = statement(1, b"x");
    foreign.r#ref = "feature/other".into();

    let error = refused(&jwks_for("k1", &key), &signed(&foreign, b"k1", &key), None);
    assert!(error.contains("attests the ref `feature/other`"), "{error}");
}

#[test]
fn a_replayed_older_head_is_rollback() {
    // The signature is genuine — an old statement replayed by a compromised
    // server is exactly the attack the counter exists to catch.
    let key = keypair();
    let envelope = signed(&statement(3, b"old"), b"k1", &key);

    let error = refused(
        &jwks_for("k1", &key),
        &envelope,
        Some(&checkpoint(5, b"accepted")),
    );
    assert!(error.contains("rollback"), "{error}");
    assert!(error.contains("counter 3 below the accepted 5"), "{error}");
}

#[test]
fn two_heads_for_one_counter_is_equivocation() {
    let key = keypair();
    let envelope = signed(&statement(5, b"forked"), b"k1", &key);

    let error = refused(
        &jwks_for("k1", &key),
        &envelope,
        Some(&checkpoint(5, b"accepted")),
    );
    assert!(error.contains("equivocation"), "{error}");
}

#[test]
fn malformed_inputs_are_parse_errors_never_panics() {
    let key = keypair();
    let envelope = signed(&statement(1, b"x"), b"k1", &key);

    let error = refused(b"not json", &envelope, None);
    assert!(error.contains("key ring does not parse"), "{error}");

    let error = refused(&jwks_for("k1", &key), b"not cose", None);
    assert!(error.contains("does not parse"), "{error}");

    let x = "@@not-base64@@";
    let bad_x = format!(
        r#"{{"keys":[{{"kid":"k1","kty":"OKP","crv":"Ed25519","x":"{x}","alg":"EdDSA"}}]}}"#
    );
    let error = refused(bad_x.as_bytes(), &envelope, None);
    assert!(error.contains("does not decode"), "{error}");

    let corrupt = Checkpoint {
        head: "not-a-digest".into(),
        counter: 1,
    };
    let error = refused(&jwks_for("k1", &key), &envelope, Some(&corrupt));
    assert!(error.contains("checkpoint is corrupt"), "{error}");
}
