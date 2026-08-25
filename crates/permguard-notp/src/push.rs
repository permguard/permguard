// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The push half: negotiate the delta, upload what is missing, commit.
//!
//! Negotiate once, N idempotent batches, finalize once — and the finalize is
//! a compare-and-swap, so a client that lost the answer may repeat it and a
//! client that fell behind is told to converge instead of overwriting.

use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;

use crate::codec::*;

/// One declared object of a push delta: the digest and the size the client
/// claims — the byte quota needs the size, and upload re-checks the truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectClaim {
    pub digest: Digest,
    pub size: u64,
}

/// `POST …/notp/push/negotiate`.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatePushRequest {
    pub r#ref: String,
    pub new_head: Digest,
    /// `None` is the creation case: the ref must not exist yet.
    pub expected_old: Option<Digest>,
    /// The delta closure, declared up front.
    pub closure: Vec<ObjectClaim>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatePushResponse {
    pub missing: Vec<Digest>,
    pub max_batch_bytes: u64,
    pub max_batch_objects: u64,
    /// The batch compression the server speaks (`"deflate"`); `None` means
    /// uncompressed batches. Advertised here, echoed by the client per batch.
    pub compression: Option<String>,
}

/// `POST …/notp/objects` — one batch of object bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadObjectsRequest {
    pub objects: Vec<Vec<u8>>,
    /// How `objects` are encoded: `None` raw, or an algorithm the server
    /// advertised at negotiation. Digests always name the raw bytes.
    pub compression: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadObjectsResponse {
    pub received: Vec<Digest>,
}

/// `POST …/notp/push/commit`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPushRequest {
    pub r#ref: String,
    pub new_head: Digest,
    pub expected_old: Option<Digest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPushResponse {
    pub head: Digest,
    pub counter: u64,
    /// The COSE_Sign1 envelope of the head statement.
    pub statement: Vec<u8>,
}

impl NegotiatePushRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut pairs = vec![
            (1, Value::Text(self.r#ref.clone())),
            (2, Value::Text(self.new_head.to_string())),
            (
                4,
                Value::Array(
                    self.closure
                        .iter()
                        .map(|c| {
                            map(vec![
                                (1, Value::Text(c.digest.to_string())),
                                (2, Value::Int(c.size as i64)),
                            ])
                        })
                        .collect(),
                ),
            ),
        ];
        if let Some(old) = &self.expected_old {
            pairs.push((3, Value::Text(old.to_string())));
        }
        cbor::encode(&map(pairs))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = as_pairs(&value)?;
        let closure = match need(pairs, 4)? {
            Value::Array(items) => items
                .iter()
                .map(|item| {
                    let entry = as_pairs(item)?;
                    Ok(ObjectClaim {
                        digest: digest(need(entry, 1)?)?,
                        size: uint(need(entry, 2)?)?,
                    })
                })
                .collect::<Result<Vec<_>>>()?,
            _ => return Err(WireError::Schema("closure must be an array")),
        };
        Ok(Self {
            r#ref: text(need(pairs, 1)?)?,
            new_head: digest(need(pairs, 2)?)?,
            expected_old: opt_digest(pairs, 3)?,
            closure,
        })
    }
}

impl NegotiatePushResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut pairs = vec![
            (1, digests(&self.missing)),
            (2, Value::Int(self.max_batch_bytes as i64)),
            (3, Value::Int(self.max_batch_objects as i64)),
        ];
        if let Some(compression) = &self.compression {
            pairs.push((4, Value::Text(compression.clone())));
        }
        cbor::encode(&map(pairs))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = as_pairs(&value)?;
        Ok(Self {
            missing: digest_list(need(pairs, 1)?)?,
            max_batch_bytes: uint(need(pairs, 2)?)?,
            max_batch_objects: uint(need(pairs, 3)?)?,
            compression: opt_text(pairs, 4)?,
        })
    }
}

impl UploadObjectsRequest {
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

impl UploadObjectsResponse {
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&map(vec![(1, digests(&self.received))]))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = as_pairs(&value)?;
        Ok(Self {
            received: digest_list(need(pairs, 1)?)?,
        })
    }
}

impl CommitPushRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut pairs = vec![
            (1, Value::Text(self.r#ref.clone())),
            (2, Value::Text(self.new_head.to_string())),
        ];
        if let Some(old) = &self.expected_old {
            pairs.push((3, Value::Text(old.to_string())));
        }
        cbor::encode(&map(pairs))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = as_pairs(&value)?;
        Ok(Self {
            r#ref: text(need(pairs, 1)?)?,
            new_head: digest(need(pairs, 2)?)?,
            expected_old: opt_digest(pairs, 3)?,
        })
    }
}

impl CommitPushResponse {
    pub fn encode(&self) -> Vec<u8> {
        cbor::encode(&map(vec![
            (1, Value::Text(self.head.to_string())),
            (2, Value::Int(self.counter as i64)),
            (3, Value::Bytes(self.statement.clone())),
        ]))
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = as_pairs(&value)?;
        Ok(Self {
            head: digest(need(pairs, 1)?)?,
            counter: uint(need(pairs, 2)?)?,
            statement: bytes(need(pairs, 3)?)?,
        })
    }
}
