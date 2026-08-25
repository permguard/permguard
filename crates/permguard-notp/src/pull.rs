// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The pull half: negotiate what is missing, then fetch it in batches.
//!
//! The negotiation carries the signed head statement, so a client verifies
//! provenance and freshness **before** a single object is transferred, and
//! before its checkpoint is allowed to move.

use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;

use crate::codec::*;

/// `POST …/notp/pull/negotiate`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatePullRequest {
    pub r#ref: String,
    /// Pin the pull to a specific commit, reachable from the ref.
    pub at: Option<Digest>,
    /// Complete verified checkpoints the client holds.
    pub have: Vec<Digest>,
}

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
}

/// `POST …/notp/objects/fetch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectsRequest {
    pub digests: Vec<Digest>,
    /// The compression the client accepts for the response batch, if any.
    pub accept_compression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchObjectsResponse {
    pub objects: Vec<Vec<u8>>,
    /// How `objects` are encoded; `None` raw.
    pub compression: Option<String>,
}

impl NegotiatePullRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut pairs = vec![
            (1, Value::Text(self.r#ref.clone())),
            (3, digests(&self.have)),
        ];
        if let Some(at) = &self.at {
            pairs.push((2, Value::Text(at.to_string())));
        }
        cbor::encode(&map(pairs))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = as_pairs(&value)?;
        Ok(Self {
            r#ref: text(need(pairs, 1)?)?,
            at: opt_digest(pairs, 2)?,
            have: digest_list(need(pairs, 3)?)?,
        })
    }
}

impl NegotiatePullResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut pairs = vec![
            (1, Value::Text(self.head.to_string())),
            (2, Value::Int(self.counter as i64)),
            (3, Value::Bytes(self.statement.clone())),
            (4, digests(&self.missing)),
            (5, Value::Int(self.max_batch_bytes as i64)),
            (6, Value::Int(self.max_batch_objects as i64)),
        ];
        if let Some(compression) = &self.compression {
            pairs.push((7, Value::Text(compression.clone())));
        }
        cbor::encode(&map(pairs))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = as_pairs(&value)?;
        Ok(Self {
            head: digest(need(pairs, 1)?)?,
            counter: uint(need(pairs, 2)?)?,
            statement: bytes(need(pairs, 3)?)?,
            missing: digest_list(need(pairs, 4)?)?,
            max_batch_bytes: uint(need(pairs, 5)?)?,
            max_batch_objects: uint(need(pairs, 6)?)?,
            compression: opt_text(pairs, 7)?,
        })
    }
}

impl FetchObjectsRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut pairs = vec![(1, digests(&self.digests))];
        if let Some(accept) = &self.accept_compression {
            pairs.push((2, Value::Text(accept.clone())));
        }
        cbor::encode(&map(pairs))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = as_pairs(&value)?;
        Ok(Self {
            digests: digest_list(need(pairs, 1)?)?,
            accept_compression: opt_text(pairs, 2)?,
        })
    }
}

impl FetchObjectsResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut pairs = vec![(
            1,
            Value::Array(
                self.objects
                    .iter()
                    .map(|o| Value::Bytes(o.clone()))
                    .collect(),
            ),
        )];
        if let Some(compression) = &self.compression {
            pairs.push((2, Value::Text(compression.clone())));
        }
        cbor::encode(&map(pairs))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = as_pairs(&value)?;
        Ok(Self {
            objects: bytes_list(need(pairs, 1)?)?,
            compression: opt_text(pairs, 2)?,
        })
    }
}
