// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Sealed batches (WP-5.2; owner decisions of 2026-10-13).
//!
//! ```text
//! record_digest  = "sha256:" hex(SHA-256(record_domain || record_bytes))
//! merkle_root    = RFC 6962 over the record digests, as the `sha256:…` strings
//! envelope       = canonical JSON (RFC 8785) {descriptor_version, stream_key, run,
//!                  membership_id?, epoch?, first_seq, last_seq, count, previous_head, head,
//!                  merkle_root, batch_id, created_at, key_set_epoch}
//! signature      = flattened JWS, protected {typ, alg, kid}, over the envelope
//! batch file     = canonical JSON {signature, records: [base64url(record_bytes)]}
//! ```
//!
//! `previous_head` is the head of the batch before in the same run, zeros at a run's first batch;
//! `batch_id` is `<run>-<first_seq>`. The signature authenticates the envelope, and the envelope
//! the records: their count, the head, the previous head and the Merkle root. A verifier refuses a
//! non-canonical file, an unknown member, another `typ` or algorithm, and a record its
//! commitments do not cover.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use permguard_core::keys::Jwk;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{StreamError, StreamKey, hex, record_digest};

/// The head before a run's first batch.
pub const GENESIS_HEAD: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// A record's digest as the envelope and the Merkle leaves spell it.
pub fn digest_string(domain: &str, record: &[u8]) -> String {
    format!("sha256:{}", hex(&record_digest(domain, record)))
}

/// The stream key as an envelope names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyView {
    pub plane: String,
    #[serde(rename = "type")]
    pub stream_type: String,
    pub resource: String,
    /// The producer's `host_id`, as UUID text.
    pub producer_host_id: String,
}

impl KeyView {
    pub fn of(key: &StreamKey) -> Self {
        Self {
            plane: key.plane.clone(),
            stream_type: key.stream_type.clone(),
            resource: key.resource.clone(),
            producer_host_id: permguard_host::identity::record::uuid_text(&key.producer_host_id),
        }
    }
}

/// What a sealed batch's signature covers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub descriptor_version: u32,
    pub stream_key: KeyView,
    /// The run, as hex.
    pub run: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub membership_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch: Option<u64>,
    pub first_seq: u64,
    pub last_seq: u64,
    pub count: u64,
    pub previous_head: String,
    pub head: String,
    pub merkle_root: String,
    pub batch_id: String,
    /// RFC 3339, UTC.
    pub created_at: String,
    /// The signing ring's epoch.
    pub key_set_epoch: u64,
}

impl Envelope {
    /// The canonical bytes the signature covers.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, StreamError> {
        let value =
            serde_json::to_value(self).map_err(|error| StreamError::Invalid(error.to_string()))?;
        crate::jcs::canonicalize(&value).map_err(|error| StreamError::Invalid(error.to_string()))
    }
}

/// The protected header of a batch signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Protected {
    pub typ: String,
    pub alg: String,
    pub kid: String,
}

/// A flattened JWS: each member base64url.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Jws {
    pub protected: String,
    pub payload: String,
    pub signature: String,
}

/// A sealed batch's file: the signature and the exact record bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SealedBatch {
    pub signature: Jws,
    /// base64url of each record's exact bytes, in sequence order.
    pub records: Vec<String>,
}

/// The algorithm a key signs with, as its JWK names it: `EdDSA` or `ES256`.
fn algorithm(jwk: &Jwk) -> Result<&'static str, StreamError> {
    match permguard_host::keys::ring::suite_of(jwk) {
        Some(permguard_objects::crypto::suite::Suite::Ed25519Sha256V1) => Ok("EdDSA"),
        Some(permguard_objects::crypto::suite::Suite::P256Sha256V1) => Ok("ES256"),
        _ => Err(StreamError::Sign(format!(
            "the key `{}` is of no suite a batch is signed with",
            jwk.kid
        ))),
    }
}

impl SealedBatch {
    /// Signs `envelope` under `signer`'s active key, whose public key is `jwk`, and carries
    /// `records`.
    pub fn seal(
        signer: &dyn permguard_core::keys::Sign,
        jwk: &Jwk,
        typ: &str,
        envelope: &Envelope,
        records: &[Vec<u8>],
    ) -> Result<Self, StreamError> {
        let protected = Protected {
            typ: typ.to_owned(),
            alg: algorithm(jwk)?.to_owned(),
            kid: jwk.kid.clone(),
        };
        let protected = B64.encode(
            crate::jcs::canonicalize(
                &serde_json::to_value(&protected)
                    .map_err(|error| StreamError::Invalid(error.to_string()))?,
            )
            .map_err(|error| StreamError::Invalid(error.to_string()))?,
        );
        let payload = B64.encode(envelope.signed_bytes()?);
        let signature = signer
            .sign(format!("{protected}.{payload}").as_bytes())
            .map_err(|error| StreamError::Sign(error.to_string()))?;
        if signature.key_id().as_str() != jwk.kid {
            return Err(StreamError::Sign(
                "the signing key rotated mid-signature".to_owned(),
            ));
        }
        Ok(Self {
            signature: Jws {
                protected,
                payload,
                signature: B64.encode(signature.bytes()),
            },
            records: records.iter().map(|record| B64.encode(record)).collect(),
        })
    }

    /// The file's canonical bytes: what is persisted, sent and retried.
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let value =
            serde_json::to_value(self).map_err(|error| StreamError::Invalid(error.to_string()))?;
        crate::jcs::canonicalize(&value).map_err(|error| StreamError::Invalid(error.to_string()))
    }

    /// Reads a batch file, refusing non-canonical bytes, duplicate or unknown members.
    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_BATCH_FILE_BYTES {
            return Err(StreamError::Invalid(
                "a batch is out of its bound".to_owned(),
            ));
        }
        let value: Value = crate::jcs::decode_canonical(bytes)
            .map_err(|error| StreamError::Invalid(format!("a batch: {error}")))?;
        serde_json::from_value(value).map_err(|error| StreamError::Invalid(error.to_string()))
    }

    /// The key the protected header names, unverified: which signer span the batch falls in.
    pub fn kid(&self) -> Result<String, StreamError> {
        Ok(self.protected()?.kid)
    }

    fn protected(&self) -> Result<Protected, StreamError> {
        let invalid = |detail: String| StreamError::Invalid(format!("a batch: {detail}"));
        let bytes = B64
            .decode(&self.signature.protected)
            .map_err(|error| invalid(error.to_string()))?;
        serde_json::from_value(
            crate::jcs::decode_canonical(&bytes).map_err(|error| invalid(error.to_string()))?,
        )
        .map_err(|error| invalid(error.to_string()))
    }

    /// Verifies the batch against `keys` and `typ`, and its records against the commitments the
    /// signature covers: answers the envelope and the record bytes.
    pub fn verify(
        &self,
        keys: &[Jwk],
        typ: &str,
        domain: &str,
    ) -> Result<(Envelope, Vec<Vec<u8>>), StreamError> {
        let invalid = |detail: &str| StreamError::Invalid(format!("a batch: {detail}"));
        let decode = |text: &str| {
            B64.decode(text)
                .map_err(|error| invalid(&error.to_string()))
        };
        let protected = self.protected()?;
        if protected.typ != typ {
            return Err(invalid(&format!(
                "`typ` is `{}`, not `{typ}`",
                protected.typ
            )));
        }
        let jwk = keys
            .iter()
            .find(|jwk| jwk.kid == protected.kid)
            .ok_or_else(|| invalid(&format!("signed by the unknown key `{}`", protected.kid)))?;
        let alg = algorithm(jwk)?;
        if protected.alg != alg {
            return Err(invalid("the algorithm is not its key's"));
        }
        let mut public = decode(&jwk.x)?;
        if let Some(y) = jwk.y.as_deref() {
            public.insert(0, 0x04);
            public.extend(decode(y)?);
        }
        // The key's own suite picks the verifier, never the header.
        let verifier: &dyn ring::signature::VerificationAlgorithm = match alg {
            "EdDSA" => &ring::signature::ED25519,
            _ => &ring::signature::ECDSA_P256_SHA256_FIXED,
        };
        ring::signature::UnparsedPublicKey::new(verifier, &public)
            .verify(
                format!("{}.{}", self.signature.protected, self.signature.payload).as_bytes(),
                &decode(&self.signature.signature)?,
            )
            .map_err(|_| invalid("the signature does not verify"))?;
        let envelope: Envelope = serde_json::from_value(
            crate::jcs::decode_canonical(&decode(&self.signature.payload)?)
                .map_err(|error| invalid(&error.to_string()))?,
        )
        .map_err(|error| invalid(&error.to_string()))?;
        let records = self
            .records
            .iter()
            .map(|record| decode(record))
            .collect::<Result<Vec<_>, _>>()?;
        if envelope.first_seq == 0
            || envelope.last_seq < envelope.first_seq
            || envelope.last_seq - envelope.first_seq + 1 != envelope.count
            || records.len() as u64 != envelope.count
        {
            return Err(invalid("its range, count and records disagree"));
        }
        let digests: Vec<String> = records
            .iter()
            .map(|record| digest_string(domain, record))
            .collect();
        if digests.last() != Some(&envelope.head) {
            return Err(invalid("its head is not its last record's digest"));
        }
        if crate::merkle::root(&digests).as_ref() != Some(&envelope.merkle_root) {
            return Err(invalid("its Merkle root does not cover its records"));
        }
        if envelope.batch_id != format!("{}-{}", envelope.run, envelope.first_seq) {
            return Err(invalid("its batch id is not its run and first sequence"));
        }
        Ok((envelope, records))
    }
}

/// The most bytes a batch file takes.
pub const MAX_BATCH_FILE_BYTES: usize = 16 * 1024 * 1024;
