// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `policy.mirror` task's messages (WP-7.12): how a member pulls over the Host task transport.
//!
//! A task message names the read and the ledger, and carries that read's own NOTP body; the answer
//! is that read's NOTP answer, unchanged. The Host authorized the task session for its resource,
//! and the Control Plane checks the ledger is under it before anything is read: the same reads, the
//! same transfer sessions and the same refusals as the public surfaces.
//!
//! ```text
//! MirrorRequest = {1 operation, 2 zone, 3 ledger, 4 body}
//!   1 get_ref         body GetRefRequest {1 ref}            answer GetRefResponse
//!   2 negotiate_pull  body NegotiatePullRequest             answer NegotiatePullResponse
//!   3 fetch_objects   body FetchObjectsRequest              answer FetchObjectsResponse
//!   4 key_ring        body empty                            answer the JWKS document
//! ```

use permguard_objects::cbor::{self, Value};

use crate::codec::*;

/// The read a `policy.mirror` message asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MirrorOperation {
    GetRef,
    NegotiatePull,
    FetchObjects,
    KeyRing,
}

impl MirrorOperation {
    fn label(self) -> u64 {
        match self {
            Self::GetRef => 1,
            Self::NegotiatePull => 2,
            Self::FetchObjects => 3,
            Self::KeyRing => 4,
        }
    }

    fn from_label(label: u64) -> Result<Self> {
        match label {
            1 => Ok(Self::GetRef),
            2 => Ok(Self::NegotiatePull),
            3 => Ok(Self::FetchObjects),
            4 => Ok(Self::KeyRing),
            _ => Err(WireError::Schema("a mirror operation is 1 to 4")),
        }
    }
}

/// One `policy.mirror` task message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MirrorRequest {
    pub operation: MirrorOperation,
    /// The zone id.
    pub zone: String,
    /// The ledger id.
    pub ledger: String,
    /// The operation's own NOTP message; empty for the key ring.
    pub body: Vec<u8>,
}

impl MirrorRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(cbor::encode(&map(vec![
            (1, uint_value(self.operation.label())?),
            (2, Value::Text(self.zone.clone())),
            (3, Value::Text(self.ledger.clone())),
            (4, Value::Bytes(self.body.clone())),
        ]))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 3, 4])?;
        let request = Self {
            operation: MirrorOperation::from_label(uint(need(pairs, 1)?)?)?,
            zone: text(need(pairs, 2)?)?,
            ledger: text(need(pairs, 3)?)?,
            body: bytes(need(pairs, 4)?)?,
        };
        if request.operation == MirrorOperation::KeyRing && !request.body.is_empty() {
            return Err(WireError::Schema(
                "the key ring is asked with an empty body",
            ));
        }
        Ok(request)
    }
}
