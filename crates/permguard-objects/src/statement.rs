// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signed head statement: a COSE_Sign1 envelope (Ed25519, embedded
//! payload) binding a head digest to its context — zone, ledger, ref,
//! counter, signing time — plus the client-side freshness rules.
//!
//! The profile is pinned: `alg = EdDSA` with Ed25519 keys, nothing else.
//! Algorithm agility lives in profile versions and key-ring rotation, never
//! in runtime negotiation.

use std::fmt;

use ring::signature::{self, Ed25519KeyPair, UnparsedPublicKey};

use crate::cbor::{self, CborError, Value};
use crate::digest::{Digest, DigestError};

/// COSE algorithm identifier for EdDSA (RFC 9053).
const COSE_ALG_EDDSA: i64 = -8;
/// COSE header labels (RFC 9052).
const COSE_HEADER_ALG: i64 = 1;
const COSE_HEADER_KID: i64 = 4;

// HeadStatement CBOR integer keys, normative.
const KEY_ZONE: i64 = 1;
const KEY_LEDGER: i64 = 2;
const KEY_REF: i64 = 3;
const KEY_DIGEST: i64 = 4;
const KEY_COUNTER: i64 = 5;
const KEY_SIGNED_AT: i64 = 6;

/// The context-bound statement the server signs when serving a ref head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadStatement {
    pub zone: String,
    pub ledger: String,
    pub r#ref: String,
    pub digest: Digest,
    pub counter: u64,
    pub signed_at: i64,
}

impl HeadStatement {
    /// The canonical CBOR bytes of the statement — the signed payload.
    pub fn encode(&self) -> Result<Vec<u8>, StatementError> {
        let counter = i64::try_from(self.counter).map_err(|_| StatementError::CounterRange)?;
        Ok(cbor::encode(&Value::Map(vec![
            (Value::Int(KEY_ZONE), Value::Text(self.zone.clone())),
            (Value::Int(KEY_LEDGER), Value::Text(self.ledger.clone())),
            (Value::Int(KEY_REF), Value::Text(self.r#ref.clone())),
            (Value::Int(KEY_DIGEST), Value::Text(self.digest.to_string())),
            (Value::Int(KEY_COUNTER), Value::Int(counter)),
            (Value::Int(KEY_SIGNED_AT), Value::Int(self.signed_at)),
        ])))
    }

    fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        let value = cbor::decode_canonical(bytes)?;
        let Value::Map(map) = value else {
            return Err(StatementError::Schema("statement must be a map"));
        };
        let text = |key: i64| -> Result<String, StatementError> {
            match map.iter().find(|(k, _)| *k == Value::Int(key)) {
                Some((_, Value::Text(t))) => Ok(t.clone()),
                _ => Err(StatementError::Schema("expected text field")),
            }
        };
        let int = |key: i64| -> Result<i64, StatementError> {
            match map.iter().find(|(k, _)| *k == Value::Int(key)) {
                Some((_, Value::Int(n))) => Ok(*n),
                _ => Err(StatementError::Schema("expected integer field")),
            }
        };
        if map.len() != 6 {
            return Err(StatementError::Schema(
                "statement must have exactly six fields",
            ));
        }
        Ok(HeadStatement {
            zone: text(KEY_ZONE)?,
            ledger: text(KEY_LEDGER)?,
            r#ref: text(KEY_REF)?,
            digest: Digest::parse(&text(KEY_DIGEST)?)?,
            counter: u64::try_from(int(KEY_COUNTER)?).map_err(|_| StatementError::CounterRange)?,
            signed_at: int(KEY_SIGNED_AT)?,
        })
    }
}

/// A COSE_Sign1 envelope with the statement embedded as the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHead {
    /// Canonical bytes of the protected header map.
    protected: Vec<u8>,
    /// Canonical bytes of the statement.
    payload: Vec<u8>,
    /// Ed25519 signature over the COSE Sig_structure.
    signature: Vec<u8>,
}

impl SignedHead {
    /// Sign a statement with a server key.
    pub fn sign(
        statement: &HeadStatement,
        key: &Ed25519KeyPair,
        kid: &[u8],
    ) -> Result<Self, StatementError> {
        Self::sign_with(statement, kid, |bytes| {
            Ok(key.sign(bytes).as_ref().to_vec())
        })
    }

    /// Sign a statement through an external signer — a key manager, a KMS —
    /// that produces a raw Ed25519 signature over the given bytes. The
    /// signer never sees COSE; this function owns the structure.
    pub fn sign_with<F>(
        statement: &HeadStatement,
        kid: &[u8],
        signer: F,
    ) -> Result<Self, StatementError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, StatementError>,
    {
        let protected = protected_header(kid);
        let payload = statement.encode()?;
        let to_sign = sig_structure(&protected, &payload);
        let signature = signer(&to_sign)?;
        Ok(SignedHead {
            protected,
            payload,
            signature,
        })
    }

    /// The `kid` this envelope claims, for key-ring lookup.
    pub fn kid(&self) -> Result<Vec<u8>, StatementError> {
        let Value::Map(map) = cbor::decode_canonical(&self.protected)? else {
            return Err(StatementError::Schema("protected header must be a map"));
        };
        match map.iter().find(|(k, _)| *k == Value::Int(COSE_HEADER_KID)) {
            Some((_, Value::Bytes(kid))) => Ok(kid.clone()),
            _ => Err(StatementError::Schema("missing kid")),
        }
    }

    /// Verify the envelope against one Ed25519 public key and return the
    /// statement. The algorithm is pinned: the protected header must declare
    /// EdDSA, and the key must be an Ed25519 key — nothing else verifies.
    pub fn verify(&self, public_key: &[u8]) -> Result<HeadStatement, StatementError> {
        let Value::Map(map) = cbor::decode_canonical(&self.protected)? else {
            return Err(StatementError::Schema("protected header must be a map"));
        };
        match map.iter().find(|(k, _)| *k == Value::Int(COSE_HEADER_ALG)) {
            Some((_, Value::Int(alg))) if *alg == COSE_ALG_EDDSA => {}
            _ => return Err(StatementError::Algorithm),
        }
        let to_verify = sig_structure(&self.protected, &self.payload);
        UnparsedPublicKey::new(&signature::ED25519, public_key)
            .verify(&to_verify, &self.signature)
            .map_err(|_| StatementError::Signature)?;
        HeadStatement::decode(&self.payload)
    }

    /// The statement inside the envelope, **without verifying** the
    /// signature — for the server matching its own cache against its own
    /// ref, never for trusting received material.
    pub fn statement_unverified(&self) -> Result<HeadStatement, StatementError> {
        HeadStatement::decode(&self.payload)
    }

    /// The wire form: canonical CBOR array
    /// `[protected: bstr, unprotected: {}, payload: bstr, signature: bstr]`.
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&Value::Array(vec![
            Value::Bytes(self.protected.clone()),
            Value::Map(vec![]),
            Value::Bytes(self.payload.clone()),
            Value::Bytes(self.signature.clone()),
        ]))
    }

    /// Parse the wire form.
    pub fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        let Value::Array(items) = cbor::decode_canonical(bytes)? else {
            return Err(StatementError::Schema("envelope must be an array"));
        };
        let [
            Value::Bytes(protected),
            Value::Map(unprotected),
            Value::Bytes(payload),
            Value::Bytes(sig),
        ] = items.as_slice()
        else {
            return Err(StatementError::Schema(
                "envelope must be [bstr, map, bstr, bstr]",
            ));
        };
        if !unprotected.is_empty() {
            return Err(StatementError::Schema("unprotected header must be empty"));
        }
        Ok(SignedHead {
            protected: protected.clone(),
            payload: payload.clone(),
            signature: sig.clone(),
        })
    }
}

fn protected_header(kid: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::Map(vec![
        (Value::Int(COSE_HEADER_ALG), Value::Int(COSE_ALG_EDDSA)),
        (Value::Int(COSE_HEADER_KID), Value::Bytes(kid.to_vec())),
    ]))
}

/// The COSE Sig_structure for Signature1 (RFC 9052 §4.4), external AAD empty.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Vec<u8> {
    cbor::encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))
}

/// The state of one key in the published ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyState {
    /// Signs new statements and verifies.
    Signing,
    /// No longer signs; existing signatures stay valid.
    VerifyOnly,
    /// Compromised: its signatures verify nothing.
    Revoked,
}

/// One key of the ring.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingKey {
    pub kid: Vec<u8>,
    pub public_key: Vec<u8>,
    pub state: KeyState,
}

/// The published key ring: a monotonic epoch plus the keys. Clients persist
/// the epoch and reject any ring with a lower one — the head-counter rule,
/// applied to the trust material itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRing {
    pub epoch: u64,
    pub keys: Vec<RingKey>,
}

impl KeyRing {
    /// Find a key that may verify, by kid. Revoked keys verify nothing.
    pub fn verification_key(&self, kid: &[u8]) -> Option<&RingKey> {
        self.keys
            .iter()
            .find(|k| k.kid == kid && !matches!(k.state, KeyState::Revoked))
    }
}

/// The freshness verdict of the (counter, digest) rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Freshness {
    /// Newer head: accept and persist the new checkpoint.
    Newer,
    /// Same counter, same digest: a retry or a re-sign — accept.
    Same,
    /// Same counter, different digest: the server said two different things.
    Equivocation,
    /// Lower counter: an old head presented as current.
    Rollback,
}

/// Apply the rollback/equivocation table against the persisted checkpoint.
/// `last` is `None` when the client has no checkpoint (first clone, lost
/// state): trust on first use, protected from then on.
pub fn check_freshness(last: Option<(u64, &Digest)>, received: (u64, &Digest)) -> Freshness {
    match last {
        None => Freshness::Newer,
        Some((last_counter, last_digest)) => {
            let (counter, digest) = received;
            if counter > last_counter {
                Freshness::Newer
            } else if counter < last_counter {
                Freshness::Rollback
            } else if digest == last_digest {
                Freshness::Same
            } else {
                Freshness::Equivocation
            }
        }
    }
}

/// Why a statement or envelope was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StatementError {
    Cbor(CborError),
    Digest(DigestError),
    Schema(&'static str),
    /// The protected header does not pin EdDSA.
    Algorithm,
    /// The signature does not verify.
    Signature,
    /// An external signer failed to produce a signature.
    Signer(String),
    /// The counter does not fit the signed integer model.
    CounterRange,
}

impl fmt::Display for StatementError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StatementError::Cbor(e) => write!(f, "encoding: {e}"),
            StatementError::Digest(e) => write!(f, "digest: {e}"),
            StatementError::Schema(what) => write!(f, "schema: {what}"),
            StatementError::Algorithm => write!(f, "algorithm not pinned to EdDSA/Ed25519"),
            StatementError::Signature => write!(f, "signature verification failed"),
            StatementError::Signer(detail) => write!(f, "the signer failed: {detail}"),
            StatementError::CounterRange => write!(f, "counter out of range"),
        }
    }
}

impl std::error::Error for StatementError {}

impl From<CborError> for StatementError {
    fn from(e: CborError) -> Self {
        StatementError::Cbor(e)
    }
}

impl From<DigestError> for StatementError {
    fn from(e: DigestError) -> Self {
        StatementError::Digest(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::KeyPair as _;

    fn test_key() -> Ed25519KeyPair {
        let doc = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap()
    }

    fn sample_statement() -> HeadStatement {
        HeadStatement {
            zone: "0198f2aa-0000-7000-8000-000000000001".into(),
            ledger: "0198f3bb-0000-7000-8000-000000000002".into(),
            r#ref: "main".into(),
            digest: Digest::compute(b"commit"),
            counter: 42,
            signed_at: 1_787_836_802,
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = test_key();
        let statement = sample_statement();
        let signed = SignedHead::sign(&statement, &key, b"2026-08-srv-1").unwrap();
        let wire = signed.encode();
        let parsed = SignedHead::decode(&wire).unwrap();
        assert_eq!(parsed.kid().unwrap(), b"2026-08-srv-1".to_vec());
        let verified = parsed.verify(key.public_key().as_ref()).unwrap();
        assert_eq!(verified, statement);
    }

    #[test]
    fn wrong_key_fails() {
        let signed = SignedHead::sign(&sample_statement(), &test_key(), b"k1").unwrap();
        let other = test_key();
        assert_eq!(
            signed.verify(other.public_key().as_ref()),
            Err(StatementError::Signature)
        );
    }

    #[test]
    fn tampered_payload_fails() {
        let key = test_key();
        let mut signed = SignedHead::sign(&sample_statement(), &key, b"k1").unwrap();
        let mut other = sample_statement();
        other.counter = 41;
        signed.payload = other.encode().unwrap();
        assert_eq!(
            signed.verify(key.public_key().as_ref()),
            Err(StatementError::Signature)
        );
    }

    #[test]
    fn freshness_table() {
        let d1 = Digest::compute(b"1");
        let d2 = Digest::compute(b"2");
        assert_eq!(check_freshness(None, (1, &d1)), Freshness::Newer);
        assert_eq!(
            check_freshness(Some((41, &d1)), (42, &d2)),
            Freshness::Newer
        );
        assert_eq!(check_freshness(Some((42, &d1)), (42, &d1)), Freshness::Same);
        assert_eq!(
            check_freshness(Some((42, &d1)), (42, &d2)),
            Freshness::Equivocation
        );
        assert_eq!(
            check_freshness(Some((42, &d1)), (41, &d1)),
            Freshness::Rollback
        );
    }

    #[test]
    fn ring_lookup_skips_revoked() {
        let ring = KeyRing {
            epoch: 3,
            keys: vec![
                RingKey {
                    kid: b"old".to_vec(),
                    public_key: vec![1],
                    state: KeyState::Revoked,
                },
                RingKey {
                    kid: b"cur".to_vec(),
                    public_key: vec![2],
                    state: KeyState::Signing,
                },
            ],
        };
        assert!(ring.verification_key(b"old").is_none());
        assert!(ring.verification_key(b"cur").is_some());
    }
}
