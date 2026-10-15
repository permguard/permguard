// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A producer stream's STATE: its run and watermarks (WP-5.1; owner decision of 2026-10-13).
//!
//! | Field                  | Meaning                                                              |
//! | ---------------------- | -------------------------------------------------------------------- |
//! | 1 run_id               | the current run                                                      |
//! | 2 run_statement_digest | the digest of its statement, as the segments hold it                 |
//! | 3 next_seq             | the sequence the next record takes                                   |
//! | 4 durable_seq          | the last sequence flushed when STATE was written                     |
//! | 5 signed_seq           | the last sequence sealed in a signed batch (WP-5.2)                  |
//! | 6 acknowledged_seq     | the last sequence every required subscription acknowledged (WP-5.4) |
//! | 7 oldest_retained_seq  | the first sequence still kept (WP-5.6)                               |
//! | 8? pending_successor   | the signed statement of a rollover begun and not yet written         |
//! | 9? forked_at_seq       | the sequence a consumer reported a fork at: no run opens unapproved  |
//! | 10? unshipped          | {1 tail, 2 truncate_safe, 3 run}: what an incomplete drain left      |
//!
//! The segments are the authority: recovery re-derives the head from them, and STATE only names
//! which of their runs it is the state of.

use permguard_objects::cbor::Value;

use super::StreamError;
use super::codec::{Map, encode, uint};

/// The most bytes a STATE takes: its fields and a pending successor's envelope.
pub const MAX_STATE_BYTES: usize = 8192;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    pub run_id: [u8; 16],
    pub run_statement_digest: [u8; 32],
    pub next_seq: u64,
    pub durable_seq: u64,
    pub signed_seq: u64,
    pub acknowledged_seq: u64,
    pub oldest_retained_seq: u64,
    pub pending_successor: Option<Vec<u8>>,
    pub forked_at_seq: Option<u64>,
    pub unshipped: Option<Unshipped>,
}

/// What an incomplete drain left on a stream (WP-5.8, owner decisions of 2026-10-15): the newest
/// run still behind, its last sequence and its `truncate_safe`. Kept until that run is shipped
/// through `tail` and every run before it through its end, so the volume is never taken for
/// scratch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unshipped {
    pub tail: u64,
    pub truncate_safe: u64,
    pub run: [u8; 16],
}

impl Unshipped {
    fn value(&self) -> Result<Value, StreamError> {
        Ok(Value::Map(vec![
            (Value::Int(1), uint(self.tail)?),
            (Value::Int(2), uint(self.truncate_safe)?),
            (Value::Int(3), Value::Bytes(self.run.to_vec())),
        ]))
    }

    fn read(value: Value) -> Result<Self, StreamError> {
        let mut map = Map::of(value, "an unshipped mark")?;
        let mark = Self {
            tail: map.uint(1)?,
            truncate_safe: map.uint(2)?,
            run: map.fixed(3)?,
        };
        map.finish()?;
        if mark.truncate_safe >= mark.tail {
            return Err(StreamError::Invalid(
                "an unshipped mark whose tail is shipped".to_owned(),
            ));
        }
        Ok(mark)
    }
}

impl State {
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let mut pairs = vec![
            (1, Value::Bytes(self.run_id.to_vec())),
            (2, Value::Bytes(self.run_statement_digest.to_vec())),
            (3, uint(self.next_seq)?),
            (4, uint(self.durable_seq)?),
            (5, uint(self.signed_seq)?),
            (6, uint(self.acknowledged_seq)?),
            (7, uint(self.oldest_retained_seq)?),
        ];
        if let Some(pending) = &self.pending_successor {
            pairs.push((8, Value::Bytes(pending.clone())));
        }
        if let Some(forked) = self.forked_at_seq {
            pairs.push((9, uint(forked)?));
        }
        if let Some(unshipped) = &self.unshipped {
            pairs.push((10, unshipped.value()?));
        }
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(StreamError::Invalid(
                "a STATE is out of its bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "a stream STATE")?;
        let state = Self {
            run_id: map.fixed(1)?,
            run_statement_digest: map.fixed(2)?,
            next_seq: map.uint(3)?,
            durable_seq: map.uint(4)?,
            signed_seq: map.uint(5)?,
            acknowledged_seq: map.uint(6)?,
            oldest_retained_seq: map.uint(7)?,
            pending_successor: map.optional_bytes(8)?,
            forked_at_seq: map.optional_uint(9)?,
            unshipped: map.optional(10).map(Unshipped::read).transpose()?,
        };
        map.finish()?;
        if state.next_seq == 0
            || state.durable_seq >= state.next_seq
            || state.signed_seq > state.durable_seq
            || state.acknowledged_seq > state.signed_seq
        {
            return Err(StreamError::Invalid(
                "a STATE whose watermarks are out of order".to_owned(),
            ));
        }
        Ok(state)
    }
}
