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
//! | 11? base               | what the frames below the journal's `BASE` gave its open (WP-5.6)    |
//!
//! `base` is {1 first_index, 2 statement, 3 last_seq, 4 last_digest, 5 ended}: the journal index
//! the deleted prefix ends before, the signed statement of the run open there, the last sequence
//! and record digest that run reached below it, and whether it had ended (owner decision of
//! 2026-10-17). It is written before `BASE`, so a journal that starts after frame 0 always finds
//! it; one whose `BASE` is still below it ignores it.
//!
//! The segments are the authority: recovery re-derives the head from them, and STATE only names
//! which of their runs it is the state of.

use permguard_objects::cbor::Value;

use super::StreamError;
use super::codec::{Map, encode, uint};

/// The most bytes a STATE takes: its fields, a pending successor's envelope and a base's statement.
pub const MAX_STATE_BYTES: usize = 12288;

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
    pub base: Option<Base>,
}

/// What the frames below a journal's `BASE` gave its open (WP-5.6; owner decision of 2026-10-17).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base {
    /// The journal index the deleted prefix ends before.
    pub first_index: u64,
    /// The signed statement of the run open at `first_index`, as its RUN_OPEN frame held it.
    pub statement: Vec<u8>,
    /// The last sequence that run reached below `first_index`, 0 for none.
    pub last_seq: u64,
    /// The record digest at `last_seq`, zeros for none.
    pub last_digest: [u8; 32],
    /// Whether that run had ended below `first_index`.
    pub ended: bool,
}

impl Base {
    fn value(&self) -> Result<Value, StreamError> {
        Ok(Value::Map(vec![
            (Value::Int(1), uint(self.first_index)?),
            (Value::Int(2), Value::Bytes(self.statement.clone())),
            (Value::Int(3), uint(self.last_seq)?),
            (Value::Int(4), Value::Bytes(self.last_digest.to_vec())),
            (Value::Int(5), Value::Bool(self.ended)),
        ]))
    }

    fn read(value: Value) -> Result<Self, StreamError> {
        let mut map = Map::of(value, "a STATE base")?;
        let base = Self {
            first_index: map.uint(1)?,
            statement: map.bytes(2)?,
            last_seq: map.uint(3)?,
            last_digest: map.fixed(4)?,
            ended: map.boolean(5)?,
        };
        map.finish()?;
        if base.first_index == 0 || base.statement.len() > super::run::MAX_STATEMENT_BYTES {
            return Err(StreamError::Invalid(
                "a STATE base at frame 0 or over the statement bound".to_owned(),
            ));
        }
        Ok(base)
    }
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
        if let Some(base) = &self.base {
            pairs.push((11, base.value()?));
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
            base: map.optional(11).map(Base::read).transpose()?,
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
