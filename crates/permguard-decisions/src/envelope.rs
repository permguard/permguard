// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The signed batch envelope: what a producer attests to when it ships.
//!
//! # What is signed, and what is not
//!
//! The signature covers the **envelope**, not the records. It does not have
//! to cover them: `head` is the digest of the last record, and the chain binds
//! every record to it, so altering any record in a verified run changes the
//! head and breaks the signature. One asymmetric operation per batch instead
//! of one per decision — the trade Certificate Transparency makes with signed
//! tree heads, Rekor with checkpoints and CloudTrail with hourly digests.
//!
//! `previous_head` is the other half: it lets a verifier check **continuity
//! between batches**, not merely the integrity of the one in hand.
//!
//! # The form
//!
//! [JWS] flattened JSON serialisation, `alg: EdDSA`, `kid` naming a key in the
//! producer's published set, over the canonical bytes of the envelope. Not a
//! JWT: this is not a bearer token and carries no claims semantics — the
//! payload is a statement about a stream, and reusing token vocabulary for it
//! would invite token handling.
//!
//! [JWS]: https://www.rfc-editor.org/rfc/rfc7515

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use permguard_core::{Jwk, KeyManager};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jcs;
use crate::record::{Sampling, Stream};

/// The algorithm this product signs decision batches with.
pub const ALGORITHM: &str = "EdDSA";

/// What a batch attests to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    /// Whose history, and which incarnation.
    pub stream: Stream,
    /// The first sequence in the batch.
    pub first_seq: u64,
    /// The last sequence in the batch.
    pub last_seq: u64,
    /// How many records it carries — checked against the range, so a batch
    /// cannot omit records inside its own bounds.
    pub count: u64,
    /// The head of the previous batch of this stream, or the genesis.
    pub previous_head: String,
    /// The digest of the record at `last_seq`.
    pub head: String,
    /// The Merkle root over the digests of the records it contains.
    pub merkle_root: String,
    /// What this batch claims to be complete about.
    pub sampling: Sampling,
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

    /// Checks what the envelope says about itself, before any signature.
    ///
    /// Cheap, and it catches the batch that claims a range it does not fill —
    /// which a signature would otherwise happily attest to.
    pub fn check_shape(&self) -> Result<(), EnvelopeError> {
        if self.last_seq < self.first_seq {
            return Err(EnvelopeError::Range {
                first_seq: self.first_seq,
                last_seq: self.last_seq,
            });
        }
        let spanned = self.last_seq - self.first_seq + 1;
        if spanned != self.count {
            return Err(EnvelopeError::Count {
                spanned,
                count: self.count,
            });
        }

        Ok(())
    }
}

/// A batch: the envelope, its signature, and the records verbatim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    /// The signed statement.
    pub signature: Signed,
    /// The records, exactly as the producer wrote them.
    pub records: Vec<Value>,
}

/// A JWS in its flattened JSON serialisation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed {
    /// The protected header, base64url — `{"alg","kid"}`.
    pub protected: String,
    /// The payload, base64url: the canonical envelope bytes.
    pub payload: String,
    /// The signature over `protected || "." || payload`, base64url.
    pub signature: String,
}

/// The protected header of a decision-batch signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Protected {
    /// Always `EdDSA` — a signature whose algorithm the verifier chooses is
    /// how algorithm-confusion attacks start.
    pub alg: String,
    /// Which key, in the producer's published set.
    pub kid: String,
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

    /// The header, decoded.
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

    /// Verifies the signature against `keys` and returns what it attests to.
    ///
    /// The algorithm is not read from the header and then honoured: it is
    /// **required** to be the one this product signs with, so a header cannot
    /// talk a verifier into a weaker check or into treating a MAC as a
    /// signature.
    pub fn verify(&self, keys: &[Jwk]) -> Result<Envelope, EnvelopeError> {
        let protected = self.protected()?;
        if protected.alg != ALGORITHM {
            return Err(EnvelopeError::Algorithm(protected.alg));
        }
        let key = keys
            .iter()
            .find(|candidate| candidate.kid == protected.kid)
            .ok_or_else(|| EnvelopeError::UnknownKey(protected.kid.clone()))?;
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

/// Why an envelope or its signature was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The envelope is not renderable as canonical JSON.
    Shape(String),
    /// `last_seq` is before `first_seq`.
    Range { first_seq: u64, last_seq: u64 },
    /// The range and the count disagree.
    Count { spanned: u64, count: u64 },
    /// Base64 or JSON that does not decode.
    Encoding(String),
    /// An algorithm this product does not sign or verify with.
    Algorithm(String),
    /// A `kid` that is not in the published set.
    UnknownKey(String),
    /// The signature does not verify.
    Signature,
    /// The key manager could not sign.
    Signing(String),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shape(detail) => {
                write!(formatter, "the envelope cannot be canonicalised: {detail}")
            }
            Self::Range {
                first_seq,
                last_seq,
            } => write!(
                formatter,
                "the batch claims sequences {first_seq}..{last_seq}, which is not a range"
            ),
            Self::Count { spanned, count } => write!(
                formatter,
                "the batch spans {spanned} sequences but declares {count} records: a batch may not omit records inside its own range"
            ),
            Self::Encoding(detail) => {
                write!(formatter, "the signature is not well formed: {detail}")
            }
            Self::Algorithm(alg) => write!(
                formatter,
                "`{alg}` is not the algorithm decision batches are signed with ({ALGORITHM})"
            ),
            Self::UnknownKey(kid) => write!(
                formatter,
                "no published key is named `{kid}`: this batch cannot be attributed"
            ),
            Self::Signature => write!(formatter, "the signature does not verify"),
            Self::Signing(detail) => {
                write!(formatter, "this plane cannot sign right now: {detail}")
            }
        }
    }
}

impl std::error::Error for EnvelopeError {}
