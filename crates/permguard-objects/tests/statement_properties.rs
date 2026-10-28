// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A signed head statement round-trips through its wire bytes, and no single flipped byte of those
//! bytes yields a statement that verifies.

#![allow(clippy::unwrap_used)]

use permguard_objects::Digest;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::statement::{HeadStatement, SignedHead};
use proptest::prelude::*;
use ring::signature::{Ed25519KeyPair, KeyPair as _};

/// One key for every case: generating a key per case would spend the run on key generation.
fn key() -> &'static Ed25519KeyPair {
    static KEY: std::sync::OnceLock<Ed25519KeyPair> = std::sync::OnceLock::new();
    KEY.get_or_init(|| Ed25519KeyPair::from_seed_unchecked(&[7u8; 32]).expect("a seed makes a key"))
}

fn statement() -> impl Strategy<Value = HeadStatement> {
    (
        "[a-z0-9-]{1,16}",
        "[a-z0-9-]{1,16}",
        "refs/[a-z0-9/]{1,16}",
        any::<[u8; 32]>(),
        0..=i64::MAX as u64,
        any::<i64>(),
        (
            any::<[u8; 16]>(),
            any::<[u8; 32]>(),
            0..=i64::MAX as u64,
            any::<[u8; 32]>(),
        ),
    )
        .prop_map(
            |(zone, ledger, r#ref, digest, counter, signed_at, (authority, state, epoch, set))| {
                HeadStatement {
                    zone,
                    ledger,
                    r#ref,
                    digest: Digest::compute(&digest),
                    counter,
                    signed_at,
                    authority_host_id: authority,
                    ref_digest: Digest::compute(&state),
                    ring_epoch: epoch,
                    key_set_digest: Digest::compute(&set),
                }
            },
        )
}

proptest! {
    #[test]
    fn a_signed_head_round_trips_and_verifies_as_the_statement_it_signed(statement in statement()) {
        let signed = SignedHead::sign(&statement, key(), b"control.attest:k").unwrap();
        let decoded = SignedHead::decode(&signed.encode().expect("it encodes")).unwrap();

        prop_assert_eq!(&decoded, &signed);
        prop_assert_eq!(decoded.encode(), signed.encode());
        prop_assert_eq!(decoded.statement_unverified().unwrap(), statement.clone());
        prop_assert_eq!(decoded.verify(Suite::Ed25519Sha256V1, key().public_key().as_ref()).unwrap(), statement);
        prop_assert_eq!(decoded.kid().unwrap(), b"control.attest:k".to_vec());
    }

    #[test]
    fn no_flipped_byte_yields_a_verifying_statement(statement in statement(), at in any::<prop::sample::Index>()) {
        let mut bytes = SignedHead::sign(&statement, key(), b"control.attest:k").unwrap().encode().unwrap();
        let at = at.index(bytes.len());
        bytes[at] ^= 0x01;

        let verified = SignedHead::decode(&bytes)
            .ok()
            .and_then(|head| head.verify(Suite::Ed25519Sha256V1, key().public_key().as_ref()).ok());
        prop_assert!(verified.is_none(), "byte {} flipped and the head still verified", at);
    }
}
