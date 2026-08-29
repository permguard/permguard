// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signed head a batch of event records travels under.
//!
//! # One signature for many records
//!
//! An asymmetric signature per event would put an Ed25519 operation on the append path and make
//! sustained ingest a signing benchmark. So records are chained — which is cheap — and a
//! *contiguous run* of them is covered by one signed envelope carrying the run's bounds, its head
//! and a Merkle root. A reader that wants one record proves it with an inclusion path against that
//! root, without being shown its neighbours.
//!
//! Group signing amortizes the cost, but it does not weaken the promise: a caller is never told
//! its event is signed before the checkpoint covering that sequence is durable.
//!
//! # `typ`, and why it is not optional
//!
//! The protected header declares `typ: permguard.event.batch.v1`. The decision log's envelope
//! carries no `typ` at all, and that asymmetry is deliberate rather than an oversight to
//! replicate: a verifier handed a signature must be able to refuse one made for a different kind
//! of evidence before it looks at the payload. Without a type in the *protected* header, an
//! attacker who obtains a valid signature over one envelope shape can present it as the other, and
//! the algorithm and key would both check out.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use serde::{Deserialize, Serialize};

use permguard_core::keys::{Jwk, KeyManager};
use permguard_decisions::jcs;

use crate::record::Stream;

/// The algorithm this product signs event batches with.
pub const ALGORITHM: &str = "EdDSA";

/// The registered type of a signed event batch, declared in the protected header.
pub const BATCH_TYPE: &str = "permguard.event.batch.v1";

/// One batch, as the wire carries it: the signed envelope and the records it covers.
///
/// Defined here rather than on either side of the exchange, because both sides must agree about
/// it byte for byte — the producer signs an envelope over records it sends verbatim, and the
/// receiver verifies that envelope against exactly those bytes. Two definitions would be two
/// chances to render the same batch two ways.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// The signed envelope, which is what a key actually signed.
    pub signature: Signed,
    /// The records, verbatim, in sequence order.
    pub records: Vec<serde_json::Value>,
}

/// What a batch attests to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// The complete stream identity: producer class, id, instance, zone and ledger.
    pub stream: Stream,
    /// The first sequence in the batch.
    pub first_seq: u64,
    /// The last sequence in the batch.
    pub last_seq: u64,
    /// How many records it carries — checked against the range, so a batch cannot omit records
    /// inside its own bounds.
    pub count: u64,
    /// The head of the previous batch of this stream, or the genesis.
    pub previous_head: String,
    /// The digest of the record at `last_seq`.
    pub head: String,
    /// The Merkle root over the digests of the records it covers.
    pub merkle_root: String,
    /// The registered event types this batch covers, sorted and deduplicated.
    ///
    /// A batch may cover adjacent records of several registered types — one producer stream is one
    /// causal order, and splitting it by type would destroy that. Each record is still validated
    /// against its own type's contract; this field only lets a reader skip a batch that cannot
    /// contain what it is looking for.
    pub event_types: Vec<String>,
    /// The record schema version every covered record carries.
    pub record_version: u32,
    /// When it was assembled, informational.
    pub at: String,
}

impl Envelope {
    /// The exact bytes a signature covers.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        let value =
            serde_json::to_value(self).map_err(|error| EnvelopeError::Shape(error.to_string()))?;

        jcs::canonicalize(&value).map_err(|error| EnvelopeError::Shape(error.to_string()))
    }

    /// Whether the envelope's own numbers agree with each other.
    ///
    /// Checked before signing and again after verifying: a signature over an envelope that
    /// contradicts itself is a valid signature over nonsense, and the second check is what stops a
    /// producer's bug from becoming a reader's.
    pub fn check_shape(&self) -> Result<(), EnvelopeError> {
        if self.last_seq < self.first_seq {
            return Err(EnvelopeError::Shape(format!(
                "the batch ends at {} and starts at {}",
                self.last_seq, self.first_seq
            )));
        }
        let span = self.last_seq - self.first_seq + 1;
        if span != self.count {
            return Err(EnvelopeError::Shape(format!(
                "the batch spans {span} sequences and claims {} records: a batch may not omit \
                 records inside its own bounds",
                self.count
            )));
        }
        if self.event_types.is_empty() {
            return Err(EnvelopeError::Shape(
                "a batch covers at least one registered event type".to_owned(),
            ));
        }
        let mut sorted = self.event_types.clone();
        sorted.sort_unstable();
        sorted.dedup();
        if sorted != self.event_types {
            return Err(EnvelopeError::Shape(
                "the covered event types are not sorted and deduplicated, so two producers of the \
                 same batch would sign different bytes"
                    .to_owned(),
            ));
        }

        Ok(())
    }
}

/// The protected header of an event-batch signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protected {
    /// Always `EdDSA` — a signature whose algorithm the verifier chooses is how
    /// algorithm-confusion attacks start.
    pub alg: String,
    /// Always [`BATCH_TYPE`]. What stops a signature made over other evidence being presented
    /// here.
    pub typ: String,
    /// Which key, in the producer's published set.
    pub kid: String,
}

/// A signed batch envelope, in JWS compact-detached form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    /// The protected header, base64url — `{"alg","typ","kid"}`.
    pub protected: String,
    /// The payload, base64url: the canonical envelope bytes.
    pub payload: String,
    /// The signature over `protected || "." || payload`, base64url.
    pub signature: String,
}

impl Signed {
    /// Signs `envelope` under the manager's active key.
    pub fn create(envelope: &Envelope, keys: &dyn KeyManager) -> Result<Self, EnvelopeError> {
        envelope.check_shape()?;
        let payload = B64.encode(envelope.signed_bytes()?);
        let key_id = keys
            .active_key_id()
            .map_err(|error| EnvelopeError::Signing(error.to_string()))?;
        let protected = B64.encode(
            serde_json::to_vec(&Protected {
                alg: ALGORITHM.to_owned(),
                typ: BATCH_TYPE.to_owned(),
                kid: key_id.as_str().to_owned(),
            })
            .map_err(|error| EnvelopeError::Shape(error.to_string()))?,
        );

        let signing_input = format!("{protected}.{payload}");
        let signature = keys
            .sign(signing_input.as_bytes())
            .map_err(|error| EnvelopeError::Signing(error.to_string()))?;
        if signature.algorithm() != ALGORITHM {
            return Err(EnvelopeError::Algorithm(signature.algorithm().to_owned()));
        }

        Ok(Self {
            protected,
            payload,
            signature: B64.encode(signature.bytes()),
        })
    }

    /// The header, decoded — **not** verified.
    pub fn protected(&self) -> Result<Protected, EnvelopeError> {
        let bytes = B64
            .decode(&self.protected)
            .map_err(|error| EnvelopeError::Encoding(error.to_string()))?;

        serde_json::from_slice(&bytes).map_err(|error| EnvelopeError::Encoding(error.to_string()))
    }

    /// The envelope, decoded — **not** verified. Callers use [`Self::verify`].
    pub fn envelope(&self) -> Result<Envelope, EnvelopeError> {
        let bytes = B64
            .decode(&self.payload)
            .map_err(|error| EnvelopeError::Encoding(error.to_string()))?;

        serde_json::from_slice(&bytes).map_err(|error| EnvelopeError::Encoding(error.to_string()))
    }

    /// Verifies the signature against a published key set, and the envelope against itself.
    ///
    /// The order matters: algorithm, then type, then key, then signature, then shape. Each check
    /// is refused before anything more expensive is attempted, and the type is refused before the
    /// key is even looked up — a signature made over another kind of evidence must not get as far
    /// as a cryptographic operation.
    /// The JWS compact serialization: `protected.payload.signature`.
    ///
    /// What a checkpoint file holds. The three parts are already base64url, so this is a join
    /// rather than an encoding — and a verifier reads it back with [`Signed::from_compact`]
    /// without either side needing a second format.
    pub fn compact(&self) -> String {
        format!("{}.{}.{}", self.protected, self.payload, self.signature)
    }

    /// Reads back what [`Signed::compact`] wrote.
    pub fn from_compact(text: &str) -> Result<Self, EnvelopeError> {
        let mut parts = text.trim().split('.');
        let (Some(protected), Some(payload), Some(signature), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(EnvelopeError::Shape(
                "a compact JWS is three base64url parts separated by dots".to_owned(),
            ));
        };
        if protected.is_empty() || payload.is_empty() || signature.is_empty() {
            return Err(EnvelopeError::Shape(
                "a compact JWS has no empty part".to_owned(),
            ));
        }

        Ok(Self {
            protected: protected.to_owned(),
            payload: payload.to_owned(),
            signature: signature.to_owned(),
        })
    }

    pub fn verify(&self, keys: &[Jwk]) -> Result<Envelope, EnvelopeError> {
        let header = self.protected()?;
        if header.alg != ALGORITHM {
            return Err(EnvelopeError::Algorithm(header.alg));
        }
        if header.typ != BATCH_TYPE {
            return Err(EnvelopeError::Type(header.typ));
        }
        let key = keys
            .iter()
            .find(|candidate| candidate.kid == header.kid)
            .ok_or_else(|| EnvelopeError::UnknownKey(header.kid.clone()))?;
        let public = B64
            .decode(&key.x)
            .map_err(|error| EnvelopeError::Encoding(error.to_string()))?;
        let signature = B64
            .decode(&self.signature)
            .map_err(|error| EnvelopeError::Encoding(error.to_string()))?;
        let signing_input = format!("{}.{}", self.protected, self.payload);

        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
            .verify(signing_input.as_bytes(), &signature)
            .map_err(|_| EnvelopeError::Signature)?;

        let envelope = self.envelope()?;
        envelope.check_shape()?;

        Ok(envelope)
    }
}

/// Why an envelope could not be produced, read or trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The envelope contradicts itself.
    Shape(String),
    /// The signature declares an algorithm this product does not sign or accept.
    Algorithm(String),
    /// The signature declares a type that is not an event batch.
    Type(String),
    /// The named key is not in the published set.
    UnknownKey(String),
    /// The signature does not verify.
    Signature,
    /// Something was not base64url or not JSON.
    Encoding(String),
    /// The signing key manager refused.
    Signing(String),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Shape(detail) => {
                write!(formatter, "the batch envelope is not coherent: {detail}")
            }
            Self::Algorithm(found) => write!(
                formatter,
                "the batch declares the algorithm `{found}` and this product signs and accepts \
                 only {ALGORITHM}"
            ),
            Self::Type(found) => write!(
                formatter,
                "the batch declares the type `{found}` and this is the event log, which accepts \
                 only {BATCH_TYPE}: a signature made over other evidence is not evidence here"
            ),
            Self::UnknownKey(kid) => {
                write!(formatter, "no published key is named `{kid}`")
            }
            Self::Signature => write!(formatter, "the signature does not verify"),
            Self::Encoding(detail) => write!(formatter, "the batch does not decode: {detail}"),
            Self::Signing(detail) => write!(formatter, "the batch could not be signed: {detail}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::record::{GENESIS, Producer};

    fn envelope() -> Envelope {
        Envelope {
            stream: Stream::new(Producer::data_plane("dp", "i1"), "acme", "l"),
            first_seq: 1,
            last_seq: 3,
            count: 3,
            previous_head: GENESIS.to_owned(),
            head: "sha256:abc".to_owned(),
            merkle_root: "sha256:def".to_owned(),
            event_types: vec!["permguard.dogwood.event.v1".to_owned()],
            record_version: 1,
            at: "2026-08-28T10:15:31Z".to_owned(),
        }
    }

    #[test]
    fn a_batch_whose_count_contradicts_its_range_is_refused() {
        let mut broken = envelope();
        broken.count = 2;

        assert!(matches!(
            broken
                .check_shape()
                .expect_err("three sequences, two records"),
            EnvelopeError::Shape(_)
        ));
    }

    #[test]
    fn a_batch_that_ends_before_it_starts_is_refused() {
        let mut broken = envelope();
        broken.last_seq = 0;

        assert!(broken.check_shape().is_err());
    }

    /// Two producers assembling the same batch must sign the same bytes.
    #[test]
    fn the_covered_types_are_sorted_and_deduplicated_or_the_batch_is_refused() {
        let mut unsorted = envelope();
        unsorted.event_types = vec!["b.v1".to_owned(), "a.v1".to_owned()];
        assert!(unsorted.check_shape().is_err());

        let mut duplicated = envelope();
        duplicated.event_types = vec!["a.v1".to_owned(), "a.v1".to_owned()];
        assert!(duplicated.check_shape().is_err());

        let mut sorted = envelope();
        sorted.event_types = vec!["a.v1".to_owned(), "b.v1".to_owned()];
        assert!(sorted.check_shape().is_ok());
    }

    #[test]
    fn a_batch_covering_no_type_is_refused() {
        let mut none = envelope();
        none.event_types.clear();

        assert!(none.check_shape().is_err());
    }

    /// The signed bytes are canonical, so two builds serialize one envelope identically.
    #[test]
    fn the_signed_bytes_are_canonical() {
        let bytes = envelope().signed_bytes().expect("it canonicalizes");
        let text = String::from_utf8(bytes).expect("canonical JSON is UTF-8");

        assert!(text.starts_with('{') && text.ends_with('}'));
        assert!(
            !text.contains(' '),
            "canonical JSON carries no insignificant whitespace: {text}"
        );
    }

    #[test]
    fn the_protected_header_declares_the_event_batch_type() {
        // Built by hand rather than signed, so the assertion is about the constant and not about a
        // key manager being available in a unit test.
        let header = Protected {
            alg: ALGORITHM.to_owned(),
            typ: BATCH_TYPE.to_owned(),
            kid: "k1".to_owned(),
        };

        assert_eq!(header.typ, "permguard.event.batch.v1");
        assert_ne!(
            header.typ, "permguard.decision.v1",
            "an event batch must never be confusable with a decision batch"
        );
    }
}
