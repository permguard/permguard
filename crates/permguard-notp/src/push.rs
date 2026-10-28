// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The push half: negotiate the delta, upload what is missing, commit.
//!
//! Negotiate once, N idempotent batches, finalize once — and the finalize is
//! a compare-and-swap, so a client that lost the answer may repeat it and a
//! client that fell behind is told to converge instead of overwriting.
//!
//! The target messages (WP-7.1; owner decisions of 2026-10-14): a replacement names the ref
//! state it expects, `expected_ref {counter, digest}`, where today's messages named the old head
//! (label 3, retired and refused); the negotiation opens a transfer session, `transfer_id`, with a
//! reservation and an expiry, which every later message names; `request_id` makes a negotiation
//! and a commit idempotent per caller.

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
///
/// `{1 ref, 2 new_head, 4 closure, 5? expected_ref, 6 request_id}`; label 3, today's
/// `expected_old`, is retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatePushRequest {
    pub r#ref: String,
    pub new_head: Digest,
    /// `None` is the creation case: the ref must not exist yet.
    pub expected_ref: Option<ExpectedRef>,
    /// The delta closure, declared up front.
    pub closure: Vec<ObjectClaim>,
    pub request_id: String,
}

/// `{1 missing, 2 max_batch_bytes, 3 max_batch_objects, 4? compression, 5 transfer_id,
/// 6 reservation, 7 expiry}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiatePushResponse {
    pub missing: Vec<Digest>,
    pub max_batch_bytes: u64,
    pub max_batch_objects: u64,
    /// The batch compression the server speaks (`"deflate"`); `None` means
    /// uncompressed batches. Advertised here, echoed by the client per batch.
    pub compression: Option<String>,
    /// The transfer session every later message names.
    pub transfer_id: TransferId,
    /// The bytes the session may land.
    pub reservation: u64,
    /// When the session closes, in unix seconds.
    pub expiry: u64,
}

/// `POST …/notp/objects` — one batch of object bytes: `{1 objects, 2? compression,
/// 3 transfer_id}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadObjectsRequest {
    pub objects: Vec<Vec<u8>>,
    /// How `objects` are encoded: `None` raw, or an algorithm the server
    /// advertised at negotiation. Digests always name the raw bytes.
    pub compression: Option<String>,
    pub transfer_id: TransferId,
}

/// `{1 received, 2 remaining}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadObjectsResponse {
    pub received: Vec<Digest>,
    /// What the session's reservation has left.
    pub remaining: u64,
}

/// `POST …/notp/push/commit`: `{1 ref, 2 new_head, 4? expected_ref, 5 transfer_id,
/// 6 request_id}`; label 3 is retired.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPushRequest {
    pub r#ref: String,
    pub new_head: Digest,
    pub expected_ref: Option<ExpectedRef>,
    pub transfer_id: TransferId,
    pub request_id: String,
}

/// `{1 head, 2 counter, 3 statement, 4 ref_digest}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitPushResponse {
    pub head: Digest,
    pub counter: u64,
    /// The COSE_Sign1 envelope of the head statement.
    pub statement: Vec<u8>,
    pub ref_digest: Digest,
}

impl NegotiatePushRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut closure = Vec::with_capacity(self.closure.len());
        for claim in &self.closure {
            closure.push(map(vec![
                (1, Value::Text(claim.digest.to_string())),
                (2, uint_value(claim.size)?),
            ]));
        }
        let mut pairs = vec![
            (1, Value::Text(self.r#ref.clone())),
            (2, Value::Text(self.new_head.to_string())),
            (4, Value::Array(closure)),
            (6, Value::Text(self.request_id.clone())),
        ];
        if let Some(expected) = &self.expected_ref {
            pairs.push((5, expected.value()?));
        }
        Ok(cbor::encode(&map(pairs))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 4, 5, 6])?;
        let closure = match need(pairs, 4)? {
            Value::Array(items) => items
                .iter()
                .map(|item| {
                    let entry = closed(item, &[1, 2])?;
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
            expected_ref: opt_expected(pairs, 5)?,
            closure,
            request_id: request_id(need(pairs, 6)?)?,
        })
    }
}

impl NegotiatePushResponse {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut pairs = vec![
            (1, digests(&self.missing)),
            (2, uint_value(self.max_batch_bytes)?),
            (3, uint_value(self.max_batch_objects)?),
            (5, Value::Bytes(self.transfer_id.to_vec())),
            (6, uint_value(self.reservation)?),
            (7, uint_value(self.expiry)?),
        ];
        if let Some(compression) = &self.compression {
            pairs.push((4, Value::Text(compression.clone())));
        }
        Ok(cbor::encode(&map(pairs))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 3, 4, 5, 6, 7])?;
        Ok(Self {
            missing: digest_list(need(pairs, 1)?)?,
            max_batch_bytes: uint(need(pairs, 2)?)?,
            max_batch_objects: uint(need(pairs, 3)?)?,
            compression: opt_text(pairs, 4)?,
            transfer_id: transfer_id(need(pairs, 5)?)?,
            reservation: uint(need(pairs, 6)?)?,
            expiry: uint(need(pairs, 7)?)?,
        })
    }
}

impl UploadObjectsRequest {
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
            (3, Value::Bytes(self.transfer_id.to_vec())),
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
            transfer_id: transfer_id(need(pairs, 3)?)?,
        })
    }
}

impl UploadObjectsResponse {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(cbor::encode(&map(vec![
            (1, digests(&self.received)),
            (2, uint_value(self.remaining)?),
        ]))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2])?;
        Ok(Self {
            received: digest_list(need(pairs, 1)?)?,
            remaining: uint(need(pairs, 2)?)?,
        })
    }
}

impl CommitPushRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut pairs = vec![
            (1, Value::Text(self.r#ref.clone())),
            (2, Value::Text(self.new_head.to_string())),
            (5, Value::Bytes(self.transfer_id.to_vec())),
            (6, Value::Text(self.request_id.clone())),
        ];
        if let Some(expected) = &self.expected_ref {
            pairs.push((4, expected.value()?));
        }
        Ok(cbor::encode(&map(pairs))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 4, 5, 6])?;
        Ok(Self {
            r#ref: text(need(pairs, 1)?)?,
            new_head: digest(need(pairs, 2)?)?,
            expected_ref: opt_expected(pairs, 4)?,
            transfer_id: transfer_id(need(pairs, 5)?)?,
            request_id: request_id(need(pairs, 6)?)?,
        })
    }
}

impl CommitPushResponse {
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
