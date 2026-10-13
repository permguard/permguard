// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Runs: the signed statement that opens one authorized incarnation of a stream key (WP-5.1;
//! owner decisions of 2026-10-13).
//!
//! | Record          | Shape                                                                                   |
//! | --------------- | --------------------------------------------------------------------------------------- |
//! | run statement   | COSE_Sign1 `permguard.stream.run.v1` under the producer's `host.operations` key, payload {1 plane, 2 stream_type, 3 descriptor_version, 4 resource, 5 producer_host_id, 6 run_id, 7 producer_boot_id, 8 opened_at, 9? predecessor, 10? fence, 11? approval} |
//! | run end         | {1 run_id, 2 last_seq, 3 last_record_digest}: a predecessor, and the TERMINAL frame     |
//! | fence           | {1 membership_id, 2 task_id, 3 epoch}                                                   |
//!
//! A genesis run names no predecessor; an ordinary rollover names the run it ends; a successor
//! after a fork names it too and carries the digest of the operator-approved plan that
//! authorizes it (`approval`, WP-3.9). A standalone Host's run carries no fence.

use permguard_core::domains::{digest, protected};
use permguard_core::keys::Sign as _;
use permguard_objects::cbor::Value;
use permguard_objects::cose::Sign1;
use sha2::{Digest as _, Sha256};

use super::codec::{Map, encode, uint};
use super::{StreamError, StreamKey};

/// The most bytes a run statement's payload takes.
pub const MAX_STATEMENT_BYTES: usize = 4096;
/// The most bytes a run end takes.
pub const MAX_RUN_END_BYTES: usize = 128;

/// The membership task a run ships under, at the epoch it was opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fence {
    pub membership_id: [u8; 16],
    pub task_id: String,
    pub epoch: u64,
}

impl Fence {
    fn value(&self) -> Result<Value, StreamError> {
        Ok(Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.membership_id.to_vec())),
            (Value::Int(2), Value::Text(self.task_id.clone())),
            (Value::Int(3), uint(self.epoch)?),
        ]))
    }

    fn read(value: Value) -> Result<Self, StreamError> {
        let mut map = Map::of(value, "a run fence")?;
        let fence = Self {
            membership_id: map.fixed(1)?,
            task_id: map.text(2)?,
            epoch: map.uint(3)?,
        };
        map.finish()?;
        if fence.task_id.is_empty() || fence.epoch == 0 {
            return Err(StreamError::Invalid(
                "a run fence names a task and an epoch of at least 1".to_owned(),
            ));
        }
        Ok(fence)
    }
}

/// Where a run ended: what its successor names and its TERMINAL frame holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunEnd {
    pub run_id: [u8; 16],
    /// Its last sequence; zero for a run that took no record.
    pub last_seq: u64,
    /// The digest of its last record; zeros for a run that took none.
    pub last_record_digest: [u8; 32],
}

impl RunEnd {
    fn value(&self) -> Result<Value, StreamError> {
        Ok(Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.run_id.to_vec())),
            (Value::Int(2), uint(self.last_seq)?),
            (
                Value::Int(3),
                Value::Bytes(self.last_record_digest.to_vec()),
            ),
        ]))
    }

    fn read(value: Value) -> Result<Self, StreamError> {
        let mut map = Map::of(value, "a run end")?;
        let end = Self {
            run_id: map.fixed(1)?,
            last_seq: map.uint(2)?,
            last_record_digest: map.fixed(3)?,
        };
        map.finish()?;
        Ok(end)
    }

    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        permguard_objects::cbor::encode(&self.value()?)
            .map_err(|error| StreamError::Invalid(error.to_string()))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_RUN_END_BYTES {
            return Err(StreamError::Invalid(
                "a run end is out of its bound".to_owned(),
            ));
        }
        let value = permguard_objects::cbor::decode_canonical(bytes)
            .map_err(|error| StreamError::Invalid(format!("a run end: {error}")))?;
        Self::read(value)
    }
}

/// One run's statement: its stream key, its identity and what authorizes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunStatement {
    pub key: StreamKey,
    pub run_id: [u8; 16],
    pub producer_boot_id: [u8; 16],
    pub opened_at: u64,
    /// The run it succeeds; `None` at genesis.
    pub predecessor: Option<RunEnd>,
    /// The membership task the run ships under; `None` on a standalone Host.
    pub fence: Option<Fence>,
    /// The digest of the operator-approved plan a successor after a fork carries.
    pub approval: Option<[u8; 32]>,
}

impl RunStatement {
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let mut pairs = vec![
            (1, Value::Text(self.key.plane.clone())),
            (2, Value::Text(self.key.stream_type.clone())),
            (3, uint(u64::from(self.key.version))?),
            (4, Value::Text(self.key.resource.clone())),
            (5, Value::Bytes(self.key.producer_host_id.to_vec())),
            (6, Value::Bytes(self.run_id.to_vec())),
            (7, Value::Bytes(self.producer_boot_id.to_vec())),
            (8, uint(self.opened_at)?),
        ];
        if let Some(predecessor) = &self.predecessor {
            pairs.push((9, predecessor.value()?));
        }
        if let Some(fence) = &self.fence {
            pairs.push((10, fence.value()?));
        }
        if let Some(approval) = &self.approval {
            pairs.push((11, Value::Bytes(approval.to_vec())));
        }
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_STATEMENT_BYTES {
            return Err(StreamError::Invalid(
                "a run statement is out of its bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "a run statement")?;
        let plane = map.text(1)?;
        let stream_type = map.text(2)?;
        let version = u32::try_from(map.uint(3)?)
            .map_err(|_| StreamError::Invalid("a descriptor version is out of range".to_owned()))?;
        let statement = Self {
            key: StreamKey::new(&plane, &stream_type, version, &map.text(4)?, map.fixed(5)?)?,
            run_id: map.fixed(6)?,
            producer_boot_id: map.fixed(7)?,
            opened_at: map.uint(8)?,
            predecessor: map.optional(9).map(RunEnd::read).transpose()?,
            fence: map.optional(10).map(Fence::read).transpose()?,
            approval: map
                .optional_bytes(11)?
                .map(|bytes| super::codec::fixed::<32>(bytes, "an approval"))
                .transpose()?,
        };
        map.finish()?;
        if statement.approval.is_some() && statement.predecessor.is_none() {
            return Err(StreamError::Invalid(
                "an approval authorizes a successor, which names its predecessor".to_owned(),
            ));
        }
        Ok(statement)
    }

    /// Signs the statement under `operations`, the producer's `host.operations` ring.
    pub fn sign(
        &self,
        operations: &permguard_host::keys::ring::Ring,
    ) -> Result<Vec<u8>, StreamError> {
        let kid = operations
            .active_key_id()
            .map_err(|error| StreamError::Sign(error.to_string()))?;
        Sign1::sign_with(
            operations.suite(),
            protected::STREAM_RUN,
            kid.as_str().as_bytes(),
            self.encode()?,
            |bytes| {
                let signature = operations.sign(bytes).map_err(|error| error.to_string())?;
                if signature.key_id() != &kid {
                    return Err("the signing key rotated mid-signature".to_owned());
                }
                Ok(signature.bytes().to_vec())
            },
        )
        .and_then(|envelope| envelope.encode())
        .map_err(|error| StreamError::Sign(error.to_string()))
    }

    /// The statement `envelope` carries, verified under the key of `operations` its `kid` names
    /// among the ring's published keys: what a consumer checks a run it is shown by.
    pub fn verify(
        envelope: &[u8],
        operations: &permguard_host::keys::ring::Ring,
    ) -> Result<Self, StreamError> {
        let statement = operations
            .statement()
            .map_err(|error| StreamError::Sign(error.to_string()))?;
        Self::verify_under(envelope, statement.keys)
    }

    /// The statement `envelope` carries, verified under any key `operations` ever published,
    /// destroyed ones included: what the producer checks the runs of its own segments by, so a
    /// stream stays readable after the key that opened its first run is gone (WP-5.1, after the
    /// review).
    pub fn verify_own(
        envelope: &[u8],
        operations: &permguard_host::keys::ring::Ring,
    ) -> Result<Self, StreamError> {
        let failed =
            |error: permguard_host::keys::ring::RingError| StreamError::Sign(error.to_string());
        let Some((seq, ..)) = operations.frontier().map_err(failed)? else {
            return Err(StreamError::Sign(
                "the `host.operations` ring holds no key".to_owned(),
            ));
        };
        let keys = operations
            .history(seq)
            .map_err(failed)?
            .keys
            .into_iter()
            .filter_map(|key| serde_json::from_str::<permguard_core::keys::Jwk>(&key.jwk).ok());
        Self::verify_under(envelope, keys)
    }

    fn verify_under(
        envelope: &[u8],
        keys: impl IntoIterator<Item = permguard_core::keys::Jwk>,
    ) -> Result<Self, StreamError> {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
        let sign1 =
            Sign1::decode(envelope).map_err(|error| StreamError::Invalid(error.to_string()))?;
        let header = sign1
            .header()
            .map_err(|error| StreamError::Invalid(error.to_string()))?;
        let jwk = keys
            .into_iter()
            .find(|jwk| jwk.kid.as_bytes() == header.kid.as_slice())
            .ok_or_else(|| {
                StreamError::Invalid("the run is signed by no key of `host.operations`".to_owned())
            })?;
        let suite = permguard_host::keys::ring::suite_of(&jwk).ok_or_else(|| {
            StreamError::Invalid("an operations key of no known suite".to_owned())
        })?;
        let mut public = B64
            .decode(&jwk.x)
            .map_err(|error| StreamError::Invalid(error.to_string()))?;
        if let Some(y) = jwk.y.as_deref() {
            public.insert(0, 0x04);
            public.extend(
                B64.decode(y)
                    .map_err(|error| StreamError::Invalid(error.to_string()))?,
            );
        }
        let payload = sign1
            .verify(suite, &public, protected::STREAM_RUN)
            .map_err(|error| StreamError::Invalid(error.to_string()))?;
        Self::decode(payload)
    }
}

/// The digest a STATE and a check cite a run statement's envelope by.
pub fn statement_digest(envelope: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(digest::STREAM_RUN.as_bytes());
    hasher.update(envelope);
    hasher.finalize().into()
}
