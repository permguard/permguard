// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signed head statement: a COSE_Sign1 envelope (embedded payload) binding a ref's state to
//! its context and to the key set that signs it, plus the client-side freshness rules.
//!
//! ```text
//! protected  {1 alg, 3 content type "application/vnd.permguard.head.v1+cbor", 4 kid}
//! payload    {1 zone, 2 ledger, 3 ref, 4 head, 5 counter, 6 signed_at,
//!             7 authority_host_id, 8 ref_digest, 9 ring_epoch, 10 key_set_digest}
//! ```
//!
//! The target statement (WP-7.1; owner decisions of 2026-10-14): labels 1 to 6 are today's, 7 to
//! 10 bind the authority Host, the ref state's digest and the signing ring's epoch and key set; a
//! six-field statement is refused. The algorithm is the signing key's suite, Ed25519 or P-256; a
//! verifier passes the suite of the key it trusts, never one the envelope chose.

use std::fmt;

use ring::signature::Ed25519KeyPair;

use crate::cbor::{self, CborError, Value};
use crate::crypto::suite::Suite;
use crate::digest::{Digest, DigestError};

/// COSE header labels (RFC 9052).
const COSE_HEADER_ALG: i64 = 1;
const COSE_HEADER_CONTENT_TYPE: i64 = 3;
const COSE_HEADER_KID: i64 = 4;
/// The content type every head statement carries.
pub const CONTENT_TYPE: &str = permguard_core::domains::protected::NOTP_HEAD;

// HeadStatement CBOR integer keys, normative.
const KEY_ZONE: i64 = 1;
const KEY_LEDGER: i64 = 2;
const KEY_REF: i64 = 3;
const KEY_DIGEST: i64 = 4;
const KEY_COUNTER: i64 = 5;
const KEY_SIGNED_AT: i64 = 6;
const KEY_AUTHORITY: i64 = 7;
const KEY_REF_DIGEST: i64 = 8;
const KEY_RING_EPOCH: i64 = 9;
const KEY_KEY_SET: i64 = 10;
/// The most bytes a head statement's payload takes.
pub const MAX_STATEMENT_BYTES: usize = 2048;

/// The context-bound statement the server signs when serving a ref head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadStatement {
    pub zone: String,
    pub ledger: String,
    pub r#ref: String,
    /// The ref's head.
    pub digest: Digest,
    pub counter: u64,
    pub signed_at: i64,
    /// The Host whose Control Plane is the ref's authority.
    pub authority_host_id: [u8; 16],
    /// The digest of the ref's state, `permguard_objects::refstate`.
    pub ref_digest: Digest,
    /// The epoch of the ring that signs it.
    pub ring_epoch: u64,
    /// The digest of that ring's key set at that epoch.
    pub key_set_digest: Digest,
}

impl HeadStatement {
    /// The canonical CBOR bytes of the statement — the signed payload.
    pub fn encode(&self) -> Result<Vec<u8>, StatementError> {
        let counter = i64::try_from(self.counter).map_err(|_| StatementError::CounterRange)?;
        let epoch = i64::try_from(self.ring_epoch).map_err(|_| StatementError::CounterRange)?;
        Ok(cbor::encode(&Value::Map(vec![
            (Value::Int(KEY_ZONE), Value::Text(self.zone.clone())),
            (Value::Int(KEY_LEDGER), Value::Text(self.ledger.clone())),
            (Value::Int(KEY_REF), Value::Text(self.r#ref.clone())),
            (Value::Int(KEY_DIGEST), Value::Text(self.digest.to_string())),
            (Value::Int(KEY_COUNTER), Value::Int(counter)),
            (Value::Int(KEY_SIGNED_AT), Value::Int(self.signed_at)),
            (
                Value::Int(KEY_AUTHORITY),
                Value::Bytes(self.authority_host_id.to_vec()),
            ),
            (
                Value::Int(KEY_REF_DIGEST),
                Value::Text(self.ref_digest.to_string()),
            ),
            (Value::Int(KEY_RING_EPOCH), Value::Int(epoch)),
            (
                Value::Int(KEY_KEY_SET),
                Value::Text(self.key_set_digest.to_string()),
            ),
        ]))?)
    }

    fn decode(bytes: &[u8]) -> Result<Self, StatementError> {
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(StatementError::Schema("statement out of its bound"));
        }
        let value = cbor::decode_canonical(bytes)?;
        let Value::Map(map) = value else {
            return Err(StatementError::Schema("statement must be a map"));
        };
        let field = |key: i64| {
            map.iter()
                .find(|(k, _)| *k == Value::Int(key))
                .map(|(_, v)| v)
        };
        let text = |key: i64| -> Result<String, StatementError> {
            match field(key) {
                Some(Value::Text(t)) => Ok(t.clone()),
                _ => Err(StatementError::Schema("expected text field")),
            }
        };
        let int = |key: i64| -> Result<i64, StatementError> {
            match field(key) {
                Some(Value::Int(n)) => Ok(*n),
                _ => Err(StatementError::Schema("expected integer field")),
            }
        };
        if map.len() != 10 {
            return Err(StatementError::Schema(
                "statement must have exactly ten fields",
            ));
        }
        let authority_host_id = match field(KEY_AUTHORITY) {
            Some(Value::Bytes(bytes)) => <[u8; 16]>::try_from(bytes.as_slice())
                .map_err(|_| StatementError::Schema("the authority is 16 bytes"))?,
            _ => return Err(StatementError::Schema("expected the authority's bytes")),
        };
        Ok(HeadStatement {
            zone: text(KEY_ZONE)?,
            ledger: text(KEY_LEDGER)?,
            r#ref: text(KEY_REF)?,
            digest: Digest::parse(&text(KEY_DIGEST)?)?,
            counter: u64::try_from(int(KEY_COUNTER)?).map_err(|_| StatementError::CounterRange)?,
            signed_at: int(KEY_SIGNED_AT)?,
            authority_host_id,
            ref_digest: Digest::parse(&text(KEY_REF_DIGEST)?)?,
            ring_epoch: u64::try_from(int(KEY_RING_EPOCH)?)
                .map_err(|_| StatementError::CounterRange)?,
            key_set_digest: Digest::parse(&text(KEY_KEY_SET)?)?,
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
    /// Sign a statement with an Ed25519 server key.
    pub fn sign(
        statement: &HeadStatement,
        key: &Ed25519KeyPair,
        kid: &[u8],
    ) -> Result<Self, StatementError> {
        Self::sign_with(statement, Suite::Ed25519Sha256V1, kid, |bytes| {
            Ok(key.sign(bytes).as_ref().to_vec())
        })
    }

    /// Sign a statement through an external signer — a key manager, a KMS — whose key is of
    /// `suite` and that produces a raw signature over the given bytes. The signer never sees
    /// COSE; this function owns the structure.
    pub fn sign_with<F>(
        statement: &HeadStatement,
        suite: Suite,
        kid: &[u8],
        signer: F,
    ) -> Result<Self, StatementError>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, StatementError>,
    {
        let protected = protected_header(suite, kid)?;
        let payload = statement.encode()?;
        let to_sign = sig_structure(&protected, &payload)?;
        let signature = signer(&to_sign)?;
        Ok(SignedHead {
            protected,
            payload,
            signature,
        })
    }

    /// The protected header, closed: `alg`, the content type and `kid`, each present. A label
    /// this reader does not know is signed data it cannot honour, so it is refused rather than
    /// skipped; another content type is another artifact.
    fn protected_map(&self) -> Result<Vec<(Value, Value)>, StatementError> {
        let Value::Map(map) = cbor::decode_canonical(&self.protected)? else {
            return Err(StatementError::Schema("protected header must be a map"));
        };
        if map.len() != 3
            || map.iter().any(|(key, _)| {
                *key != Value::Int(COSE_HEADER_ALG)
                    && *key != Value::Int(COSE_HEADER_CONTENT_TYPE)
                    && *key != Value::Int(COSE_HEADER_KID)
            })
        {
            return Err(StatementError::Schema(
                "protected header carries an unknown or missing label",
            ));
        }
        match map
            .iter()
            .find(|(key, _)| *key == Value::Int(COSE_HEADER_CONTENT_TYPE))
        {
            Some((_, Value::Text(content_type))) if content_type == CONTENT_TYPE => Ok(map),
            _ => Err(StatementError::Schema(
                "protected header names another content type",
            )),
        }
    }

    /// The `kid` this envelope claims, for key-ring lookup.
    pub fn kid(&self) -> Result<Vec<u8>, StatementError> {
        let map = self.protected_map()?;
        match map.iter().find(|(k, _)| *k == Value::Int(COSE_HEADER_KID)) {
            Some((_, Value::Bytes(kid))) => Ok(kid.clone()),
            _ => Err(StatementError::Schema("missing kid")),
        }
    }

    /// Verify the envelope against one public key of `suite` and return the statement. The
    /// algorithm is the key's: the protected header must declare the suite's, nothing else
    /// verifies.
    pub fn verify(&self, suite: Suite, public_key: &[u8]) -> Result<HeadStatement, StatementError> {
        let map = self.protected_map()?;
        match map.iter().find(|(k, _)| *k == Value::Int(COSE_HEADER_ALG)) {
            Some((_, Value::Int(alg))) if *alg == suite.cose_alg() => {}
            _ => return Err(StatementError::Algorithm),
        }
        let to_verify = sig_structure(&self.protected, &self.payload)?;
        suite
            .verify(public_key, &to_verify, &self.signature)
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
    pub fn encode(&self) -> Result<Vec<u8>, StatementError> {
        Ok(cbor::encode(&Value::Array(vec![
            Value::Bytes(self.protected.clone()),
            Value::Map(vec![]),
            Value::Bytes(self.payload.clone()),
            Value::Bytes(self.signature.clone()),
        ]))?)
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

fn protected_header(suite: Suite, kid: &[u8]) -> Result<Vec<u8>, StatementError> {
    Ok(cbor::encode(&Value::Map(vec![
        (Value::Int(COSE_HEADER_ALG), Value::Int(suite.cose_alg())),
        (
            Value::Int(COSE_HEADER_CONTENT_TYPE),
            Value::Text(CONTENT_TYPE.to_owned()),
        ),
        (Value::Int(COSE_HEADER_KID), Value::Bytes(kid.to_vec())),
    ]))?)
}

/// The COSE Sig_structure for Signature1 (RFC 9052 §4.4), external AAD empty.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, StatementError> {
    Ok(cbor::encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))?)
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

/// The freshness verdict of the (counter, digest) rules, over the ref state's digest (WP-7.1).
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
    /// The protected header does not name the trusted key's algorithm.
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
            StatementError::Algorithm => write!(f, "the algorithm is not the key's suite"),
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
            authority_host_id: [7; 16],
            ref_digest: Digest::compute(b"ref state"),
            ring_epoch: 3,
            key_set_digest: Digest::compute(b"key set"),
        }
    }

    #[test]
    fn sign_verify_round_trip() {
        let key = test_key();
        let statement = sample_statement();
        let signed = SignedHead::sign(&statement, &key, b"2026-08-srv-1").unwrap();
        let wire = signed.encode().expect("it encodes");
        let parsed = SignedHead::decode(&wire).unwrap();
        assert_eq!(parsed.kid().unwrap(), b"2026-08-srv-1".to_vec());
        let verified = parsed
            .verify(Suite::Ed25519Sha256V1, key.public_key().as_ref())
            .unwrap();
        assert_eq!(verified, statement);
    }

    /// Today's form, properly signed, is refused by the target reader: the six-field payload
    /// under the target header, and the target payload under today's `{alg, kid}` header.
    #[test]
    fn todays_six_field_statement_and_header_are_refused() {
        let key = test_key();
        let sign = |protected: Vec<u8>, payload: Vec<u8>| {
            let to_sign = sig_structure(&protected, &payload).unwrap();
            SignedHead {
                protected,
                payload,
                signature: key.sign(&to_sign).as_ref().to_vec(),
            }
        };
        let statement = sample_statement();
        let six = cbor::encode(&Value::Map(vec![
            (Value::Int(KEY_ZONE), Value::Text(statement.zone.clone())),
            (
                Value::Int(KEY_LEDGER),
                Value::Text(statement.ledger.clone()),
            ),
            (Value::Int(KEY_REF), Value::Text(statement.r#ref.clone())),
            (
                Value::Int(KEY_DIGEST),
                Value::Text(statement.digest.to_string()),
            ),
            (Value::Int(KEY_COUNTER), Value::Int(42)),
            (Value::Int(KEY_SIGNED_AT), Value::Int(statement.signed_at)),
        ]))
        .unwrap();
        let target = protected_header(Suite::Ed25519Sha256V1, b"k1").unwrap();
        assert_eq!(
            sign(target, six).verify(Suite::Ed25519Sha256V1, key.public_key().as_ref()),
            Err(StatementError::Schema(
                "statement must have exactly ten fields"
            ))
        );
        let today = cbor::encode(&Value::Map(vec![
            (Value::Int(COSE_HEADER_ALG), Value::Int(-8)),
            (Value::Int(COSE_HEADER_KID), Value::Bytes(b"k1".to_vec())),
        ]))
        .unwrap();
        assert!(matches!(
            sign(today, statement.encode().unwrap())
                .verify(Suite::Ed25519Sha256V1, key.public_key().as_ref()),
            Err(StatementError::Schema(_))
        ));
        // Another content type is another artifact, however well it is signed.
        let other = cbor::encode(&Value::Map(vec![
            (Value::Int(COSE_HEADER_ALG), Value::Int(-8)),
            (
                Value::Int(COSE_HEADER_CONTENT_TYPE),
                Value::Text("application/vnd.permguard.other+cbor".to_owned()),
            ),
            (Value::Int(COSE_HEADER_KID), Value::Bytes(b"k1".to_vec())),
        ]))
        .unwrap();
        assert_eq!(
            sign(other, statement.encode().unwrap())
                .verify(Suite::Ed25519Sha256V1, key.public_key().as_ref()),
            Err(StatementError::Schema(
                "protected header names another content type"
            ))
        );
    }

    #[test]
    fn wrong_key_fails() {
        let signed = SignedHead::sign(&sample_statement(), &test_key(), b"k1").unwrap();
        let other = test_key();
        assert_eq!(
            signed.verify(Suite::Ed25519Sha256V1, other.public_key().as_ref()),
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
            signed.verify(Suite::Ed25519Sha256V1, key.public_key().as_ref()),
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
