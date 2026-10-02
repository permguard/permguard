// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Key identifiers that cannot be rebound: RFC 7638 thumbprints, the ring-prefixed `kid`, and the
//! digest of a published key set.
//!
//! A label such as `2026-08-09` names a slot, not a key: whoever controls the key set can put
//! different material under the same label and every verifier that matched on the label follows.
//! A thumbprint is the SHA-256 of the key's own required JWK members, so a `kid` built from it
//! names exactly one public key, and a verifier that finds a key under a `kid` checks that the two
//! agree before using it.
//!
//! The key-set digest commits a whole published set — ring, epoch, suite and every thumbprint — so
//! two peers that persisted `(epoch, digest)` detect a set that changed without its epoch moving.
//! The thumbprints are sorted bytewise before encoding: canonical CBOR fixes map order, not array
//! order, and an array in two orders is two digests of one set.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use sha2::{Digest as _, Sha256};

use super::suite::Suite;
use crate::cbor::{self, Value};

/// Why a thumbprint or a key-set digest could not be computed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ThumbprintError {
    /// The public key is not in the suite's encoding.
    KeyMalformed { suite: Suite, length: usize },
    /// Two keys of one set share a thumbprint, so the set does not describe two keys.
    DuplicateThumbprint(String),
    /// The epoch does not fit the integer model of the canonical encoding.
    EpochRange(u64),
}

impl fmt::Display for ThumbprintError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KeyMalformed { suite, length } => write!(
                formatter,
                "a {length}-byte public key is not a key of {suite}, which publishes {} bytes",
                suite.public_key_len()
            ),
            Self::DuplicateThumbprint(thumbprint) => {
                write!(
                    formatter,
                    "the thumbprint `{thumbprint}` appears twice in one key set"
                )
            }
            Self::EpochRange(epoch) => write!(formatter, "the epoch {epoch} cannot be encoded"),
        }
    }
}

impl std::error::Error for ThumbprintError {}

/// The RFC 7638 thumbprint of a public key: base64url of the SHA-256 over the required JWK members
/// in lexicographic order, serialised without whitespace.
///
/// For an Edwards key the members are `crv`, `kty`, `x`; for a NIST curve `crv`, `kty`, `x`, `y`.
/// The values are base64url and the names are plain ASCII, so the JSON is written directly and is
/// already its own canonical form.
pub fn jwk_thumbprint(suite: Suite, public_key: &[u8]) -> Result<String, ThumbprintError> {
    let malformed = || ThumbprintError::KeyMalformed {
        suite,
        length: public_key.len(),
    };
    if public_key.len() != suite.public_key_len() {
        return Err(malformed());
    }
    let json = match suite {
        Suite::Ed25519Sha256V1 => {
            format!(
                r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
                B64.encode(public_key)
            )
        }
        Suite::P256Sha256V1 => {
            if public_key[0] != 0x04 {
                return Err(malformed());
            }
            format!(
                r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
                B64.encode(&public_key[1..33]),
                B64.encode(&public_key[33..65])
            )
        }
    };

    Ok(B64.encode(Sha256::digest(json.as_bytes())))
}

/// The `kid` a signature carries: the ring's name, a colon, the thumbprint.
pub fn kid(ring: &str, thumbprint: &str) -> String {
    format!("{ring}:{thumbprint}")
}

/// The ring and the thumbprint a `kid` names, when it has the profile's shape.
pub fn split_kid(kid: &str) -> Option<(&str, &str)> {
    let (ring, thumbprint) = kid.rsplit_once(':')?;
    (!ring.is_empty() && !thumbprint.is_empty() && !thumbprint.contains(':'))
        .then_some((ring, thumbprint))
}

/// The digest of one published key set.
///
/// `SHA-256("permguard.key-set.v1\n" || CBOR({ring, epoch, algorithm, keys_by_thumbprint}))`, with
/// the thumbprints sorted bytewise and required unique.
pub fn key_set_digest(
    ring: &str,
    epoch: u64,
    suite: Suite,
    thumbprints: &[&str],
) -> Result<[u8; 32], ThumbprintError> {
    let mut sorted: Vec<&str> = thumbprints.to_vec();
    sorted.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    if let Some(window) = sorted.windows(2).find(|window| window[0] == window[1]) {
        return Err(ThumbprintError::DuplicateThumbprint(window[0].to_owned()));
    }
    let epoch = i64::try_from(epoch).map_err(|_| ThumbprintError::EpochRange(epoch))?;

    let encoded = cbor::encode(&Value::Map(vec![
        (Value::Text("ring".into()), Value::Text(ring.to_owned())),
        (Value::Text("epoch".into()), Value::Int(epoch)),
        (
            Value::Text("algorithm".into()),
            Value::Text(suite.name().to_owned()),
        ),
        (
            Value::Text("keys_by_thumbprint".into()),
            Value::Array(
                sorted
                    .into_iter()
                    .map(|thumbprint| Value::Text(thumbprint.to_owned()))
                    .collect(),
            ),
        ),
    ]));

    let mut hasher = Sha256::new();
    hasher.update(permguard_core::domains::digest::KEY_SET.as_bytes());
    hasher.update(&encoded);

    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::SigningKey;

    #[test]
    fn test_a_kid_names_its_ring_and_splits_back() {
        let kid = kid("host.identity", "abc_DEF-123");
        assert_eq!(kid, "host.identity:abc_DEF-123");
        assert_eq!(split_kid(&kid), Some(("host.identity", "abc_DEF-123")));
        assert_eq!(split_kid("no-colon"), None);
        assert_eq!(split_kid(":x"), None);
        assert_eq!(split_kid("ring:"), None);
    }

    #[test]
    fn test_thumbprints_follow_the_key_and_not_a_label() {
        for suite in Suite::ALL {
            let first =
                SigningKey::from_pkcs8(suite, &SigningKey::generate_pkcs8(suite).unwrap()).unwrap();
            let second =
                SigningKey::from_pkcs8(suite, &SigningKey::generate_pkcs8(suite).unwrap()).unwrap();
            let a = jwk_thumbprint(suite, first.public_key()).unwrap();
            let b = jwk_thumbprint(suite, second.public_key()).unwrap();

            assert_ne!(a, b);
            assert_eq!(a, jwk_thumbprint(suite, first.public_key()).unwrap());
            assert_eq!(a.len(), 43, "base64url of 32 bytes without padding");
        }
        assert!(matches!(
            jwk_thumbprint(Suite::P256Sha256V1, &[0u8; 65]),
            Err(ThumbprintError::KeyMalformed { .. })
        ));
    }

    #[test]
    fn test_the_key_set_digest_ignores_order_and_refuses_duplicates() {
        let one = key_set_digest("data.attest", 3, Suite::Ed25519Sha256V1, &["b", "a"]).unwrap();
        let two = key_set_digest("data.attest", 3, Suite::Ed25519Sha256V1, &["a", "b"]).unwrap();
        let other_epoch =
            key_set_digest("data.attest", 4, Suite::Ed25519Sha256V1, &["a", "b"]).unwrap();
        let other_ring =
            key_set_digest("control.attest", 3, Suite::Ed25519Sha256V1, &["a", "b"]).unwrap();

        assert_eq!(one, two);
        assert_ne!(one, other_epoch);
        assert_ne!(one, other_ring);
        assert_eq!(
            key_set_digest("data.attest", 3, Suite::Ed25519Sha256V1, &["a", "a"]),
            Err(ThumbprintError::DuplicateThumbprint("a".to_owned()))
        );
    }
}
