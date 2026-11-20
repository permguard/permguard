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
//!   5 list_ledgers    zone and ledger empty; body empty, or answer ListLedgersAnswer (WP-7.2a)
//!                     ListLedgersRequest (BUG-0192)
//!
//! ListLedgersRequest = {1 held: [{1 zone_id, 2 ledger_id}]}
//! ListLedgersAnswer  = {1 ledgers: [{1 zone_id, 2 zone_name, 3 ledger_id, 4 ledger_name}],
//!                       2 complete, ? 3 deleted: [{1 zone_id, 2 ledger_id}]}
//! ```
//!
//! A listing asked with a [`ListLedgersRequest`] names the ledgers the member mirrors under the
//! task, and its answer carries `deleted`: those among them the coordinator deleted, from their
//! tombstones (BUG-0192). Asked with an empty body, as a member that predates it asks, the answer
//! carries no `deleted`, so that member's closed decoder reads it; a coordinator that predates it
//! refuses a body, and the member asks again without one.

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
        if request.operation == MirrorOperation::ListLedgers {
            if !(request.zone.is_empty() && request.ledger.is_empty()) {
                return Err(WireError::Schema(
                    "the ledgers are listed with an empty zone and ledger",
                ));
            }
            if !request.body.is_empty() {
                ListLedgersRequest::decode(&request.body)?;
            }
        }
        Ok(request)
    }
}

/// The most ledgers one listing names: beyond it the listing says it is not complete.
pub const MAX_LISTED_LEDGERS: usize = 4096;

/// One ledger by its ids alone: what a member mirrors, and what a coordinator deleted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct LedgerIds {
    pub zone_id: String,
    pub ledger_id: String,
}

fn ids_value(ids: &[LedgerIds]) -> Value {
    Value::Array(
        ids.iter()
            .map(|ids| {
                map(vec![
                    (1, Value::Text(ids.zone_id.clone())),
                    (2, Value::Text(ids.ledger_id.clone())),
                ])
            })
            .collect(),
    )
}

fn ids_of(value: &Value) -> Result<Vec<LedgerIds>> {
    let Value::Array(items) = value else {
        return Err(WireError::Schema("the ledger ids are an array"));
    };
    if items.len() > MAX_LISTED_LEDGERS {
        return Err(WireError::Schema("a listing names at most 4096 ledgers"));
    }
    let ids = items
        .iter()
        .map(|item| {
            let pairs = closed(item, &[1, 2])?;
            Ok(LedgerIds {
                zone_id: text(need(pairs, 1)?)?,
                ledger_id: text(need(pairs, 2)?)?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WireError::Schema(
            "the ledger ids are sorted by zone and ledger id, each once",
        ));
    }
    Ok(ids)
}

/// The body of a `list_ledgers` that asks which of the ledgers the member mirrors were deleted
/// (BUG-0192): their ids, sorted, each once, at most [`MAX_LISTED_LEDGERS`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListLedgersRequest {
    pub held: Vec<LedgerIds>,
}

impl ListLedgersRequest {
    pub fn encode(&self) -> Result<Vec<u8>> {
        Ok(cbor::encode(&map(vec![(1, ids_value(&self.held))]))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1])?;
        Ok(Self {
            held: ids_of(need(pairs, 1)?)?,
        })
    }
}

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
    /// The ledgers the request named that the coordinator deleted, when the request named any:
    /// absent from an answer to an empty body (BUG-0192).
    pub deleted: Option<Vec<LedgerIds>>,
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
        let mut pairs = vec![(1, Value::Array(ledgers)), (2, Value::Bool(self.complete))];
        if let Some(deleted) = &self.deleted {
            pairs.push((3, ids_value(deleted)));
        }
        Ok(cbor::encode(&map(pairs))?)
    }

    pub fn decode(input: &[u8]) -> Result<Self> {
        let value = cbor::decode_canonical(input)?;
        let pairs = closed(&value, &[1, 2, 3])?;
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
        let deleted = field(pairs, 3).map(ids_of).transpose()?;
        Ok(Self {
            ledgers,
            complete: *complete,
            deleted,
        })
    }
}
