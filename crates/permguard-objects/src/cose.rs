// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! COSE_Sign1 (RFC 9052) in one profile, for every signed container a Host issues: the identity
//! document, its succession records, proof transcripts and ring bindings (WP-2.2 onward).
//!
//! | Part        | Profile                                                                      |
//! | ----------- | ---------------------------------------------------------------------------- |
//! | envelope    | untagged canonical CBOR array `[protected, unprotected, payload, signature]` |
//! | protected   | a closed map: `1` alg, `3` content type (text), `4` kid (bytes)              |
//! | unprotected | empty                                                                        |
//! | payload     | embedded                                                                     |
//! | AAD         | empty                                                                        |
//!
//! The algorithm is the suite the verifier expects, never one the envelope chooses, and the
//! content type is the one the verifier expects: a document of one kind never verifies as
//! another, whoever signed it.

use std::fmt;

use crate::cbor::{self, CborError, Value};
use crate::crypto::suite::{SignatureError, Suite};

/// COSE header labels (RFC 9052).
const ALG: i64 = 1;
const CONTENT_TYPE: i64 = 3;
const KID: i64 = 4;

/// A COSE_Sign1 envelope of this profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sign1 {
    protected: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

/// The protected header of an envelope, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub alg: i64,
    pub content_type: String,
    pub kid: Vec<u8>,
}

/// Why an envelope did not encode, decode or verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoseError {
    /// Not canonical CBOR.
    Cbor(String),
    /// Canonical CBOR, and not an envelope of this profile.
    Schema(&'static str),
    /// The envelope declares another algorithm than the expected suite's.
    Algorithm { expected: i64, declared: i64 },
    /// The envelope carries another content type than the expected one.
    ContentType { expected: String, declared: String },
    /// The signature does not verify.
    Signature(SignatureError),
    /// The signer refused.
    Signer(String),
}

impl fmt::Display for CoseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Cbor(detail) => write!(f, "not canonical CBOR: {detail}"),
            Self::Schema(detail) => write!(f, "not a COSE_Sign1 of this profile: {detail}"),
            Self::Algorithm { expected, declared } => write!(
                f,
                "the envelope declares algorithm {declared}, and {expected} is expected"
            ),
            Self::ContentType { expected, declared } => write!(
                f,
                "the envelope carries `{declared}`, and `{expected}` is expected"
            ),
            Self::Signature(error) => write!(f, "the signature does not verify: {error:?}"),
            Self::Signer(detail) => write!(f, "the signer refused: {detail}"),
        }
    }
}

impl std::error::Error for CoseError {}

impl From<CborError> for CoseError {
    fn from(error: CborError) -> Self {
        Self::Cbor(error.to_string())
    }
}

impl Sign1 {
    /// Signs `payload` as `content_type` under `kid`: `signer` receives the Sig_structure and
    /// answers the suite's raw signature over it. The signer never sees COSE.
    pub fn sign_with(
        suite: Suite,
        content_type: &str,
        kid: &[u8],
        payload: Vec<u8>,
        signer: impl FnOnce(&[u8]) -> Result<Vec<u8>, String>,
    ) -> Result<Self, CoseError> {
        let protected = cbor::encode(&Value::Map(vec![
            (Value::Int(ALG), Value::Int(suite.cose_alg())),
            (
                Value::Int(CONTENT_TYPE),
                Value::Text(content_type.to_owned()),
            ),
            (Value::Int(KID), Value::Bytes(kid.to_vec())),
        ]))?;
        let to_sign = sig_structure(&protected, &payload)?;
        let signature = signer(&to_sign).map_err(CoseError::Signer)?;
        Ok(Self {
            protected,
            payload,
            signature,
        })
    }

    /// The protected header, closed: a label this reader does not know is signed data it cannot
    /// honour, so it is refused rather than skipped.
    pub fn header(&self) -> Result<Header, CoseError> {
        let Value::Map(pairs) = cbor::decode_canonical(&self.protected)? else {
            return Err(CoseError::Schema("the protected header is a map"));
        };
        let (mut alg, mut content_type, mut kid) = (None, None, None);
        for (key, value) in pairs {
            match (key, value) {
                (Value::Int(ALG), Value::Int(value)) => alg = Some(value),
                (Value::Int(CONTENT_TYPE), Value::Text(value)) => content_type = Some(value),
                (Value::Int(KID), Value::Bytes(value)) => kid = Some(value),
                _ => {
                    return Err(CoseError::Schema(
                        "the protected header carries an unknown label or a value of another type",
                    ));
                }
            }
        }
        match (alg, content_type, kid) {
            (Some(alg), Some(content_type), Some(kid)) => Ok(Header {
                alg,
                content_type,
                kid,
            }),
            _ => Err(CoseError::Schema(
                "the protected header names alg, content type and kid",
            )),
        }
    }

    /// Verifies the envelope as `content_type` under `public_key` of `suite`, and answers the
    /// payload.
    pub fn verify(
        &self,
        suite: Suite,
        public_key: &[u8],
        content_type: &str,
    ) -> Result<&[u8], CoseError> {
        let header = self.header()?;
        if header.alg != suite.cose_alg() {
            return Err(CoseError::Algorithm {
                expected: suite.cose_alg(),
                declared: header.alg,
            });
        }
        if header.content_type != content_type {
            return Err(CoseError::ContentType {
                expected: content_type.to_owned(),
                declared: header.content_type,
            });
        }
        let to_verify = sig_structure(&self.protected, &self.payload)?;
        suite
            .verify(public_key, &to_verify, &self.signature)
            .map_err(CoseError::Signature)?;
        Ok(&self.payload)
    }

    /// The payload, **without verifying** the signature: for reading the key a document names
    /// before checking it against that key, never for trusting what it says.
    pub fn payload_unverified(&self) -> &[u8] {
        &self.payload
    }

    /// The wire form.
    pub fn encode(&self) -> Result<Vec<u8>, CoseError> {
        Ok(cbor::encode(&Value::Array(vec![
            Value::Bytes(self.protected.clone()),
            Value::Map(vec![]),
            Value::Bytes(self.payload.clone()),
            Value::Bytes(self.signature.clone()),
        ]))?)
    }

    /// Reads the wire form.
    pub fn decode(bytes: &[u8]) -> Result<Self, CoseError> {
        Self::from_value(cbor::decode_canonical(bytes)?)
    }

    /// Reads one decoded item, as a CBOR sequence holds it.
    pub fn from_value(value: Value) -> Result<Self, CoseError> {
        let Value::Array(items) = value else {
            return Err(CoseError::Schema("the envelope is an array"));
        };
        let [
            Value::Bytes(protected),
            Value::Map(unprotected),
            Value::Bytes(payload),
            Value::Bytes(signature),
        ] = items.as_slice()
        else {
            return Err(CoseError::Schema("the envelope is [bstr, map, bstr, bstr]"));
        };
        if !unprotected.is_empty() {
            return Err(CoseError::Schema("the unprotected header is empty"));
        }
        Ok(Self {
            protected: protected.clone(),
            payload: payload.clone(),
            signature: signature.clone(),
        })
    }
}

/// The Sig_structure of Signature1 (RFC 9052 §4.4), external AAD empty.
fn sig_structure(protected: &[u8], payload: &[u8]) -> Result<Vec<u8>, CoseError> {
    Ok(cbor::encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected.to_vec()),
        Value::Bytes(Vec::new()),
        Value::Bytes(payload.to_vec()),
    ]))?)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::crypto::suite::SigningKey;

    fn signed(suite: Suite, key: &SigningKey, content_type: &str) -> Sign1 {
        Sign1::sign_with(suite, content_type, b"kid", b"payload".to_vec(), |bytes| {
            key.sign(bytes)
                .map(|signature| signature.to_vec())
                .map_err(|error| format!("{error:?}"))
        })
        .expect("signed")
    }

    #[test]
    fn an_envelope_verifies_under_its_suite_key_and_content_type_and_nothing_else() {
        for suite in [Suite::Ed25519Sha256V1, Suite::P256Sha256V1] {
            let key = SigningKey::from_pkcs8(
                suite,
                &SigningKey::generate_pkcs8(suite).expect("generated"),
            )
            .expect("loaded");
            let envelope = signed(suite, &key, "permguard.test.v1");
            let decoded = Sign1::decode(&envelope.encode().expect("encodes")).expect("decodes");
            assert_eq!(
                decoded
                    .verify(suite, key.public_key(), "permguard.test.v1")
                    .expect("verifies"),
                b"payload"
            );
            assert!(matches!(
                decoded.verify(suite, key.public_key(), "permguard.other.v1"),
                Err(CoseError::ContentType { .. })
            ));
            let other = if suite == Suite::Ed25519Sha256V1 {
                Suite::P256Sha256V1
            } else {
                Suite::Ed25519Sha256V1
            };
            assert!(matches!(
                decoded.verify(other, key.public_key(), "permguard.test.v1"),
                Err(CoseError::Algorithm { .. })
            ));
            let stranger = SigningKey::from_pkcs8(
                suite,
                &SigningKey::generate_pkcs8(suite).expect("generated"),
            )
            .expect("loaded");
            assert!(matches!(
                decoded.verify(suite, stranger.public_key(), "permguard.test.v1"),
                Err(CoseError::Signature(_))
            ));
        }
    }

    #[test]
    fn a_header_with_an_unknown_label_or_an_unprotected_member_is_refused() {
        let protected = cbor::encode(&Value::Map(vec![
            (Value::Int(ALG), Value::Int(-8)),
            (Value::Int(CONTENT_TYPE), Value::Text("x".into())),
            (Value::Int(KID), Value::Bytes(vec![1])),
            (Value::Int(33), Value::Bytes(vec![])),
        ]))
        .expect("encodes");
        let envelope = Sign1 {
            protected,
            payload: vec![],
            signature: vec![0; 64],
        };
        assert!(matches!(envelope.header(), Err(CoseError::Schema(_))));
        let bytes = cbor::encode(&Value::Array(vec![
            Value::Bytes(vec![0xa0]),
            Value::Map(vec![(Value::Int(4), Value::Bytes(vec![1]))]),
            Value::Bytes(vec![]),
            Value::Bytes(vec![]),
        ]))
        .expect("encodes");
        assert!(matches!(Sign1::decode(&bytes), Err(CoseError::Schema(_))));
    }
}
