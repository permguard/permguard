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
//!   5 list_ledgers    zone, ledger and body empty           answer ListLedgersAnswer (WP-7.2a)
//!
//! ListLedgersAnswer = {1 ledgers: [{1 zone_id, 2 zone_name, 3 ledger_id, 4 ledger_name}],
//!                      2 complete}
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
    /// The ledgers under the session's resource (WP-7.2a): what a member's selectors resolve
    /// against, and what a complete listing proves absent.
    ListLedgers,
}

impl MirrorOperation {
    fn label(self) -> u64 {
        match self {
            Self::GetRef => 1,
            Self::NegotiatePull => 2,
            Self::FetchObjects => 3,
            Self::KeyRing => 4,
            Self::ListLedgers => 5,
        }
    }

    fn from_label(label: u64) -> Result<Self> {
        match label {
            1 => Ok(Self::GetRef),
            2 => Ok(Self::NegotiatePull),
            3 => Ok(Self::FetchObjects),
            4 => Ok(Self::KeyRing),
            5 => Ok(Self::ListLedgers),
            _ => Err(WireError::Schema("a mirror operation is 1 to 5")),
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
        if request.operation == MirrorOperation::ListLedgers
            && !(request.zone.is_empty() && request.ledger.is_empty() && request.body.is_empty())
        {
            return Err(WireError::Schema(
                "the ledgers are listed with an empty zone, ledger and body",
            ));
        }
        Ok(request)
    }
}

/// The most ledgers one listing names: beyond it the listing says it is not complete.
pub const MAX_LISTED_LEDGERS: usize = 4096;

/// One ledger a listing names, by its ids and its current names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedLedger {
    pub zone_id: String,
    pub zone_name: String,
    pub ledger_id: String,
    pub ledger_name: String,
}

/// The answer to `list_ledgers` (WP-7.2a): every ledger under the session's resource, sorted by
/// `(zone_id, ledger_id)`, and whether that is all of them. An incomplete listing proves nothing
/// absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListLedgersAnswer {
    pub ledgers: Vec<ListedLedger>,
    pub complete: bool,
}

impl ListLedgersAnswer {
    pub fn encode(&self) -> Result<Vec<u8>> {
        let ledgers = self
            .ledgers
            .iter()
            .map(|ledger| {
                map(vec![
                    (1, Value::Text(ledger.zone_id.clone())),
                    (2, Value::Text(ledger.zone_name.clone())),
                    (3, Value::Text(ledger.ledger_id.clone())),
                    (4, Value::Text(ledger.ledger_name.clone())),
                ])
            })
            .collect();
        Ok(cbor::encode(&map(vec![
            (1, Value::Array(ledgers)),
            (2, Value::Bool(self.complete)),
        ]))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2])?;
        let Value::Array(items) = need(pairs, 1)? else {
            return Err(WireError::Schema("the ledgers are an array"));
        };
        if items.len() > MAX_LISTED_LEDGERS {
            return Err(WireError::Schema("a listing names at most 4096 ledgers"));
        }
        let ledgers = items
            .iter()
            .map(|item| {
                let pairs = closed(item, &[1, 2, 3, 4])?;
                Ok(ListedLedger {
                    zone_id: text(need(pairs, 1)?)?,
                    zone_name: text(need(pairs, 2)?)?,
                    ledger_id: text(need(pairs, 3)?)?,
                    ledger_name: text(need(pairs, 4)?)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        if ledgers.windows(2).any(|pair| {
            (&pair[0].zone_id, &pair[0].ledger_id) >= (&pair[1].zone_id, &pair[1].ledger_id)
        }) {
            return Err(WireError::Schema(
                "the ledgers are sorted by zone and ledger id, each once",
            ));
        }
        let Value::Bool(complete) = need(pairs, 2)? else {
            return Err(WireError::Schema("`complete` is a boolean"));
        };
        Ok(Self {
            ledgers,
            complete: *complete,
        })
    }
}
