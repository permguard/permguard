// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The pull half: negotiate what is missing, then fetch it in batches.
//!
//! The negotiation carries the signed head statement, so a client verifies
//! provenance and freshness **before** a single object is transferred, and
//! before its checkpoint is allowed to move.
//!
//! The target messages (WP-7.1): every answer naming a head names its `ref_digest`; the
//! negotiation opens a transfer session that a fetch names; a client may present the checkpoint
//! it holds.

use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;

use crate::codec::*;

/// `GET …/refs/{name}`: `{1 head, 2 counter, 3 statement, 4 ref_digest}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetRefResponse {
    pub head: Digest,
    pub counter: u64,
    /// The COSE_Sign1 envelope of the head statement.
    pub statement: Vec<u8>,
    pub ref_digest: Digest,
}

/// `POST …/notp/pull/negotiate`: `{1 ref, 2? at, 3 have, 4? checkpoint}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatePullRequest {
    pub r#ref: String,
    /// Pin the pull to a specific commit, reachable from the ref.
    pub at: Option<Digest>,
    /// Complete verified checkpoints the client holds.
    pub have: Vec<Digest>,
    /// The ref state the client last verified, `{counter, digest}`.
    pub checkpoint: Option<ExpectedRef>,
}

/// `{1 head, 2 counter, 3 statement, 4 missing, 5 max_batch_bytes, 6 max_batch_objects,
/// 7? compression, 8 transfer_id, 9 ref_digest, 10 expiry}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatePullResponse {
    pub head: Digest,
    pub counter: u64,
    pub statement: Vec<u8>,
    pub missing: Vec<Digest>,
    pub max_batch_bytes: u64,
    pub max_batch_objects: u64,
    /// The batch compression the server speaks; see the push twin.
    pub compression: Option<String>,
    pub transfer_id: TransferId,
    pub ref_digest: Digest,
    /// When the session closes, in unix seconds.
    pub expiry: u64,
}

/// `POST …/notp/objects/fetch`: `{1 digests, 2? accept_compression, 3 transfer_id}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectsRequest {
    pub digests: Vec<Digest>,
    /// The compression the client accepts for the response batch, if any.
    pub accept_compression: Option<String>,
    pub transfer_id: TransferId,
}

/// `{1 objects, 2? compression, 3 expiry}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectsResponse {
    pub objects: Vec<Vec<u8>>,
    /// How `objects` are encoded; `None` raw.
    pub compression: Option<String>,
    /// When the session closes, in unix seconds.
    pub expiry: u64,
}

impl GetRefResponse {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(cbor::encode(&map(vec![
            (1, Value::Text(self.head.to_string())),
            (2, uint_value(self.counter)?),
            (3, Value::Bytes(self.statement.clone())),
            (4, Value::Text(self.ref_digest.to_string())),
        ]))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 3, 4])?;
        Ok(Self {
            head: digest(need(pairs, 1)?)?,
            counter: uint(need(pairs, 2)?)?,
            statement: bytes(need(pairs, 3)?)?,
            ref_digest: digest(need(pairs, 4)?)?,
        })
    }
}

impl NegotiatePullRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut pairs = vec![
            (1, Value::Text(self.r#ref.clone())),
            (3, digests(&self.have)),
        ];
        if let Some(at) = &self.at {
            pairs.push((2, Value::Text(at.to_string())));
        }
        if let Some(checkpoint) = &self.checkpoint {
            pairs.push((4, checkpoint.value()?));
        }
        Ok(cbor::encode(&map(pairs))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 3, 4])?;
        Ok(Self {
            r#ref: text(need(pairs, 1)?)?,
            at: opt_digest(pairs, 2)?,
            have: digest_list(need(pairs, 3)?)?,
            checkpoint: opt_expected(pairs, 4)?,
        })
    }
}

impl NegotiatePullResponse {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut pairs = vec![
            (1, Value::Text(self.head.to_string())),
            (2, uint_value(self.counter)?),
            (3, Value::Bytes(self.statement.clone())),
            (4, digests(&self.missing)),
            (5, uint_value(self.max_batch_bytes)?),
            (6, uint_value(self.max_batch_objects)?),
            (8, Value::Bytes(self.transfer_id.to_vec())),
            (9, Value::Text(self.ref_digest.to_string())),
            (10, uint_value(self.expiry)?),
        ];
        if let Some(compression) = &self.compression {
            pairs.push((7, Value::Text(compression.clone())));
        }
        Ok(cbor::encode(&map(pairs))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
        Ok(Self {
            head: digest(need(pairs, 1)?)?,
            counter: uint(need(pairs, 2)?)?,
            statement: bytes(need(pairs, 3)?)?,
            missing: digest_list(need(pairs, 4)?)?,
            max_batch_bytes: uint(need(pairs, 5)?)?,
            max_batch_objects: uint(need(pairs, 6)?)?,
            compression: opt_text(pairs, 7)?,
            transfer_id: transfer_id(need(pairs, 8)?)?,
            ref_digest: digest(need(pairs, 9)?)?,
            expiry: uint(need(pairs, 10)?)?,
        })
    }
}

impl FetchObjectsRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut pairs = vec![
            (1, digests(&self.digests)),
            (3, Value::Bytes(self.transfer_id.to_vec())),
        ];
        if let Some(accept) = &self.accept_compression {
            pairs.push((2, Value::Text(accept.clone())));
        }
        Ok(cbor::encode(&map(pairs))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 3])?;
        Ok(Self {
            digests: digest_list(need(pairs, 1)?)?,
            accept_compression: opt_text(pairs, 2)?,
            transfer_id: transfer_id(need(pairs, 3)?)?,
        })
    }
}

impl FetchObjectsResponse {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut pairs = vec![
            (
                1,
                Value::Array(
                    self.objects
                        .iter()
                        .map(|o| Value::Bytes(o.clone()))
                        .collect(),
                ),
            ),
            (3, uint_value(self.expiry)?),
        ];
        if let Some(compression) = &self.compression {
            pairs.push((2, Value::Text(compression.clone())));
        }
        Ok(cbor::encode(&map(pairs))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 3])?;
        Ok(Self {
            objects: bytes_list(need(pairs, 1)?)?,
            compression: opt_text(pairs, 2)?,
            expiry: uint(need(pairs, 3)?)?,
        })
    }
}
