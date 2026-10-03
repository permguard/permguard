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
    /// A member of the set is not an unpadded base64url SHA-256 thumbprint.
    NotAThumbprint(String),
    /// The ring name is empty.
    EmptyRing,
    /// A published set holds no key; an absent ring is a `disabled` capability, never an empty set.
    EmptySet,
    /// The epoch does not fit the integer model of the canonical encoding.
    EpochRange(u64),
    /// The bytes are not a key-set statement of this profile.
    Encoding(String),
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
            Self::NotAThumbprint(value) => write!(
                formatter,
                "`{value}` is not an unpadded base64url SHA-256 thumbprint"
            ),
            Self::EmptyRing => formatter.write_str("a key set names its ring"),
            Self::EmptySet => formatter.write_str("a published key set holds at least one key"),
            Self::EpochRange(epoch) => write!(formatter, "the epoch {epoch} cannot be encoded"),
            Self::Encoding(detail) => write!(formatter, "not a key-set statement: {detail}"),
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

/// The ring and the thumbprint a `kid` names, when it has the profile's shape: a non-empty ring,
/// a colon, and a canonical thumbprint.
pub fn split_kid(kid: &str) -> Option<(&str, &str)> {
    let (ring, thumbprint) = kid.rsplit_once(':')?;
    (!ring.is_empty() && is_thumbprint(thumbprint)).then_some((ring, thumbprint))
}

/// Whether `value` is an RFC 7638 SHA-256 thumbprint in its only encoding: 43 characters of
/// unpadded base64url that decode to 32 bytes and encode back to themselves.
pub fn is_thumbprint(value: &str) -> bool {
    value.len() == 43
        && B64
            .decode(value)
            .is_ok_and(|bytes| bytes.len() == 32 && B64.encode(&bytes) == value)
}

const RING: &str = "ring";
const EPOCH: &str = "epoch";
const ALGORITHM: &str = "algorithm";
const KEYS_BY_THUMBPRINT: &str = "keys_by_thumbprint";

/// The public statement a key-set digest commits: one ring, one epoch, one suite, its keys.
///
/// The encoding is a closed deterministic-CBOR map with exactly the text keys `ring`, `epoch`,
/// `algorithm` and `keys_by_thumbprint`. `epoch` is an unsigned integer, `algorithm` the exact
/// suite id, and the thumbprints are one or more, unique and sorted bytewise: canonical CBOR fixes map order,
/// not array order, and an array in two orders would be two digests of one set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    ring: String,
    epoch: u64,
    suite: Suite,
    thumbprints: Vec<String>,
}

impl KeySet {
    /// The set of `thumbprints`, in any order, published by `ring` at `epoch` under `suite`.
    pub fn new(
        ring: &str,
        epoch: u64,
        suite: Suite,
        thumbprints: &[&str],
    ) -> Result<Self, ThumbprintError> {
        if ring.is_empty() {
            return Err(ThumbprintError::EmptyRing);
        }
        if i64::try_from(epoch).is_err() {
            return Err(ThumbprintError::EpochRange(epoch));
        }
        if thumbprints.is_empty() {
            return Err(ThumbprintError::EmptySet);
        }
        if let Some(bad) = thumbprints.iter().find(|value| !is_thumbprint(value)) {
            return Err(ThumbprintError::NotAThumbprint((*bad).to_owned()));
        }
        let mut sorted: Vec<String> = thumbprints
            .iter()
            .map(|value| (*value).to_owned())
            .collect();
        sorted.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if let Some(window) = sorted.windows(2).find(|window| window[0] == window[1]) {
            return Err(ThumbprintError::DuplicateThumbprint(window[0].clone()));
        }

        Ok(Self {
            ring: ring.to_owned(),
            epoch,
            suite,
            thumbprints: sorted,
        })
    }

    /// The ring that publishes the set.
    pub fn ring(&self) -> &str {
        &self.ring
    }

    /// The epoch of the set.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The suite every key of the set belongs to.
    pub fn suite(&self) -> Suite {
        self.suite
    }

    /// The thumbprints, sorted bytewise.
    pub fn thumbprints(&self) -> &[String] {
        &self.thumbprints
    }

    /// The canonical bytes the digest covers.
    pub fn encode(&self) -> Result<Vec<u8>, ThumbprintError> {
        cbor::encode(&Value::Map(vec![
            (Value::Text(RING.into()), Value::Text(self.ring.clone())),
            // Within range by construction: `new` and `decode` refuse a larger epoch.
            (
                Value::Text(EPOCH.into()),
                Value::Int(i64::try_from(self.epoch).unwrap_or(i64::MAX)),
            ),
            (
                Value::Text(ALGORITHM.into()),
                Value::Text(self.suite.name().to_owned()),
            ),
            (
                Value::Text(KEYS_BY_THUMBPRINT.into()),
                Value::Array(
                    self.thumbprints
                        .iter()
                        .map(|thumbprint| Value::Text(thumbprint.clone()))
                        .collect(),
                ),
            ),
        ]))
        .map_err(|error| ThumbprintError::Encoding(error.to_string()))
    }

    /// Reads a key-set statement strictly: canonical bytes, exactly the four keys with their exact
    /// types, a known suite id, and unique thumbprints already in bytewise order.
    pub fn decode(bytes: &[u8]) -> Result<Self, ThumbprintError> {
        let encoding = |detail: &str| ThumbprintError::Encoding(detail.to_owned());
        let Value::Map(map) =
            cbor::decode_canonical(bytes).map_err(|error| encoding(&error.to_string()))?
        else {
            return Err(encoding("a key set is a map"));
        };
        if map.len() != 4 {
            return Err(encoding("a key set has exactly four members"));
        }
        let member = |name: &str| {
            map.iter()
                .find(|(key, _)| *key == Value::Text(name.to_owned()))
                .map(|(_, value)| value)
                .ok_or_else(|| encoding(&format!("the member `{name}` is missing")))
        };
        let Value::Text(ring) = member(RING)? else {
            return Err(encoding("`ring` is text"));
        };
        let epoch = match member(EPOCH)? {
            Value::Int(epoch) => {
                u64::try_from(*epoch).map_err(|_| encoding("`epoch` is an unsigned integer"))?
            }
            _ => return Err(encoding("`epoch` is an unsigned integer")),
        };
        let Value::Text(algorithm) = member(ALGORITHM)? else {
            return Err(encoding("`algorithm` is text"));
        };
        let suite = Suite::from_name(algorithm)
            .ok_or_else(|| encoding(&format!("`{algorithm}` is not a suite of this profile")))?;
        let Value::Array(keys) = member(KEYS_BY_THUMBPRINT)? else {
            return Err(encoding("`keys_by_thumbprint` is an array"));
        };
        let mut thumbprints = Vec::with_capacity(keys.len());
        for key in keys {
            let Value::Text(thumbprint) = key else {
                return Err(encoding("a thumbprint is text"));
            };
            thumbprints.push(thumbprint.as_str());
        }
        let set = Self::new(ring, epoch, suite, &thumbprints)?;
        if set.thumbprints.iter().map(String::as_str).ne(thumbprints) {
            return Err(encoding("the thumbprints are not in bytewise order"));
        }

        Ok(set)
    }

    /// `SHA-256("permguard.key-set.v1\n" || canonical-CBOR(set))`.
    pub fn digest(&self) -> Result<[u8; 32], ThumbprintError> {
        let mut hasher = Sha256::new();
        hasher.update(permguard_core::domains::digest::KEY_SET.as_bytes());
        hasher.update(self.encode()?);

        Ok(hasher.finalize().into())
    }
}

/// The digest of one published key set; see [`KeySet`].
pub fn key_set_digest(
    ring: &str,
    epoch: u64,
    suite: Suite,
    thumbprints: &[&str],
) -> Result<[u8; 32], ThumbprintError> {
    KeySet::new(ring, epoch, suite, thumbprints).and_then(|set| set.digest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::suite::SigningKey;

    #[test]
    fn test_a_kid_names_its_ring_and_splits_back() {
        let thumbprint = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";
        let kid = kid("host.identity", thumbprint);
        assert_eq!(kid, format!("host.identity:{thumbprint}"));
        assert_eq!(split_kid(&kid), Some(("host.identity", thumbprint)));
        assert_eq!(split_kid("no-colon"), None);
        assert_eq!(split_kid(&format!(":{thumbprint}")), None);
        assert_eq!(split_kid("ring:"), None);
        assert_eq!(split_kid("ring:abc_DEF-123"), None, "not a thumbprint");
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

    const A: &str = "FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk";
    const B: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

    #[test]
    fn test_the_key_set_digest_ignores_order_and_refuses_duplicates() {
        let one = key_set_digest("data.attest", 3, Suite::Ed25519Sha256V1, &[B, A]).unwrap();
        let two = key_set_digest("data.attest", 3, Suite::Ed25519Sha256V1, &[A, B]).unwrap();
        let other_epoch =
            key_set_digest("data.attest", 4, Suite::Ed25519Sha256V1, &[A, B]).unwrap();
        let other_ring =
            key_set_digest("control.attest", 3, Suite::Ed25519Sha256V1, &[A, B]).unwrap();
        let other_suite = key_set_digest("data.attest", 3, Suite::P256Sha256V1, &[A, B]).unwrap();

        assert_eq!(one, two);
        assert_ne!(one, other_epoch);
        assert_ne!(one, other_ring);
        assert_ne!(one, other_suite);
        assert_eq!(
            key_set_digest("data.attest", 3, Suite::Ed25519Sha256V1, &[A, A]),
            Err(ThumbprintError::DuplicateThumbprint(A.to_owned()))
        );
    }

    #[test]
    fn test_only_canonical_thumbprints_enter_a_set() {
        assert!(is_thumbprint(A));
        for bad in [
            "a",
            "",
            "FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kk=",
            "FtIu+VbGrfe/KB6CH7GNwODB72MNxj/ml11dEvO+7kk",
            // The last character carries two bits no 32-byte value sets: decodable, not canonical.
            "FtIu-VbGrfe_KB6CH7GNwODB72MNxj_ml11dEvO-7kl",
        ] {
            assert!(!is_thumbprint(bad), "{bad}");
            assert_eq!(
                KeySet::new("data.attest", 1, Suite::Ed25519Sha256V1, &[bad]),
                Err(ThumbprintError::NotAThumbprint(bad.to_owned()))
            );
        }
        assert_eq!(
            KeySet::new("", 1, Suite::Ed25519Sha256V1, &[A]),
            Err(ThumbprintError::EmptyRing)
        );
        assert_eq!(
            KeySet::new("data.attest", 1, Suite::Ed25519Sha256V1, &[]),
            Err(ThumbprintError::EmptySet)
        );
    }

    fn statement(members: Vec<(Value, Value)>) -> Vec<u8> {
        cbor::encode(&Value::Map(members)).expect("it encodes")
    }

    fn members() -> Vec<(Value, Value)> {
        vec![
            (
                Value::Text("ring".into()),
                Value::Text("data.attest".into()),
            ),
            (Value::Text("epoch".into()), Value::Int(3)),
            (
                Value::Text("algorithm".into()),
                Value::Text("pg-ed25519-sha256-v1".into()),
            ),
            (
                Value::Text("keys_by_thumbprint".into()),
                Value::Array(vec![Value::Text(A.into()), Value::Text(B.into())]),
            ),
        ]
    }

    #[test]
    fn test_a_key_set_statement_decodes_only_in_its_closed_form() {
        let set = KeySet::new("data.attest", 3, Suite::Ed25519Sha256V1, &[B, A]).unwrap();
        assert_eq!(
            KeySet::decode(&set.encode().expect("it encodes")).unwrap(),
            set
        );
        assert_eq!(KeySet::decode(&statement(members())).unwrap(), set);

        let mut unknown = members();
        unknown.push((Value::Text("comment".into()), Value::Text("x".into())));
        let mut missing = members();
        missing.pop();
        let mut negative = members();
        negative[1].1 = Value::Int(-1);
        let mut text_epoch = members();
        text_epoch[1].1 = Value::Text("3".into());
        let mut other_suite = members();
        other_suite[2].1 = Value::Text("EdDSA".into());
        let mut unsorted = members();
        unsorted[3].1 = Value::Array(vec![Value::Text(B.into()), Value::Text(A.into())]);
        let mut repeated = members();
        repeated[3].1 = Value::Array(vec![Value::Text(A.into()), Value::Text(A.into())]);
        let mut bytes_member = members();
        bytes_member[3].1 = Value::Array(vec![Value::Bytes(vec![0; 32])]);
        let mut empty = members();
        empty[3].1 = Value::Array(Vec::new());
        let mut renamed = members();
        renamed[0].0 = Value::Text("rings".into());

        for (name, bytes) in [
            ("an unknown key", statement(unknown)),
            ("a missing key", statement(missing)),
            ("a negative epoch", statement(negative)),
            ("a text epoch", statement(text_epoch)),
            ("a JWS name for the suite", statement(other_suite)),
            ("unsorted thumbprints", statement(unsorted)),
            ("a repeated thumbprint", statement(repeated)),
            ("a thumbprint as bytes", statement(bytes_member)),
            ("a renamed key", statement(renamed)),
            ("an empty set", statement(empty)),
        ] {
            assert!(KeySet::decode(&bytes).is_err(), "{name} was accepted");
        }

        // A duplicate key never reaches the member checks: the canonical decoder refuses it.
        let mut duplicate = set.encode().expect("it encodes");
        duplicate[0] = 0xa5;
        duplicate.extend_from_slice(&statement(vec![members().remove(0)])[1..]);
        assert!(KeySet::decode(&duplicate).is_err());
    }
}
