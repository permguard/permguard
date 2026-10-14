// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The ingest of shipped batches at the coordinator (WP-5.3; owner decisions of 2026-10-14).
//!
//! ```text
//! message  {1 the sealed batch file's exact bytes, 2 the member's ring statement}
//! answer   {1 outcome, 2 acked, 3? expected_seq}
//!          outcome  ok | out_of_order | fork | unverifiable | gone | closed
//! ```
//!
//! `acked` is the highest contiguous sequence the consumer holds of the batch's run;
//! `expected_seq` comes with `out_of_order` only. A store that cannot answer now is the refusal
//! `store_unavailable`, the answer `deferred`: the replay window keeps no refusal, so the retry is
//! answered afresh. A fork found here suspends the membership through the session's incidents.

use std::sync::Arc;

use permguard_core::codes;
use permguard_host::membership::Store;
use permguard_host::membership::record::RingPin;
use permguard_host::membership::task::{Incidents, TaskContext, TaskHandler};
use permguard_host::session::Refusal;
use permguard_objects::cbor::Value;

use super::codec::{Map, encode, uint};
use super::{Consumer, RecordCodec, StreamError};

/// The answer of a batch the consumer holds through `acked`.
pub const OK: &str = "ok";
/// The most bytes an ingest answer takes.
pub const MAX_ANSWER_BYTES: usize = 64;
/// The version of the `decisions.ship` and `events.ship` contracts this ingest serves.
pub const VERSION: u64 = 1;

/// What an ingest answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Ok,
    OutOfOrder,
    Fork,
    Unverifiable,
    Gone,
    Closed,
}

impl Outcome {
    pub fn code(self) -> &'static str {
        match self {
            Self::Ok => OK,
            Self::OutOfOrder => codes::stream::OUT_OF_ORDER,
            Self::Fork => codes::stream::FORK,
            Self::Unverifiable => codes::stream::UNVERIFIABLE,
            Self::Gone => codes::stream::GONE,
            Self::Closed => codes::stream::CLOSED,
        }
    }

    fn of(code: &str) -> Option<Self> {
        [
            Self::Ok,
            Self::OutOfOrder,
            Self::Fork,
            Self::Unverifiable,
            Self::Gone,
            Self::Closed,
        ]
        .into_iter()
        .find(|outcome| outcome.code() == code)
    }
}

/// The message a member ships a batch in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ship {
    /// The sealed batch file, byte for byte.
    pub batch: Vec<u8>,
    /// The member's ring statement, `permguard_host::membership::RingStatement` encoded.
    pub statement: Vec<u8>,
}

impl Ship {
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        encode(vec![
            (1, Value::Bytes(self.batch.clone())),
            (2, Value::Bytes(self.statement.clone())),
        ])
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > permguard_host::membership::record::MAX_BODY_BYTES {
            return Err(StreamError::Invalid(
                "a shipped batch is out of the task message's bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "a shipped batch")?;
        let ship = Self {
            batch: map.bytes(1)?,
            statement: map.bytes(2)?,
        };
        map.finish()?;
        Ok(ship)
    }
}

/// The answer to a shipped batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Answer {
    pub outcome: Outcome,
    pub acked: u64,
    /// With `out_of_order` only: the sequence to resend from.
    pub expected_seq: Option<u64>,
}

impl Answer {
    pub fn of(outcome: Outcome, acked: u64) -> Self {
        Self {
            outcome,
            acked,
            expected_seq: None,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let mut pairs = vec![
            (1, Value::Text(self.outcome.code().to_owned())),
            (2, uint(self.acked)?),
        ];
        if let Some(expected) = self.expected_seq {
            pairs.push((3, uint(expected)?));
        }
        encode(pairs)
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_ANSWER_BYTES {
            return Err(StreamError::Invalid(
                "an ingest answer is out of its bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "an ingest answer")?;
        let text = map.text(1)?;
        let outcome = Outcome::of(&text)
            .ok_or_else(|| StreamError::Invalid(format!("`{text}` is no ingest outcome")))?;
        let answer = Self {
            outcome,
            acked: map.uint(2)?,
            expected_seq: map.optional_uint(3)?,
        };
        map.finish()?;
        if answer.expected_seq.is_some() != (outcome == Outcome::OutOfOrder) {
            return Err(StreamError::Invalid(
                "an expected sequence comes with `out_of_order` only".to_owned(),
            ));
        }
        Ok(answer)
    }
}

/// The task a batch is shipped under, as the coordinator's session knows it.
pub struct Shipping<'a> {
    pub membership_id: [u8; 16],
    /// The lease's membership epoch.
    pub epoch: u64,
    /// The member's `host_id`: the producer.
    pub member: [u8; 16],
    /// The lease's resource, canonical.
    pub resource: &'a str,
    /// The member's pins that verify `(stream, seq)`: current, or retiring below its cutover.
    pub pins: &'a dyn Fn(&str, u64) -> Vec<RingPin>,
}

/// A fork the ingest found: the stream and the first sequence that differed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forked {
    pub stream: String,
    pub at_seq: u64,
}

/// Where the member's pins are read: the membership store, or a test's own.
pub trait StreamPins: Send + Sync {
    /// The member's pins of `ring` that verify sequence `seq` of `stream` under `membership_id`.
    fn verifying_pins(
        &self,
        membership_id: &[u8; 16],
        ring: &str,
        stream: &str,
        seq: u64,
    ) -> Vec<RingPin>;
}

impl StreamPins for Store {
    fn verifying_pins(
        &self,
        membership_id: &[u8; 16],
        ring: &str,
        stream: &str,
        seq: u64,
    ) -> Vec<RingPin> {
        Store::verifying_pins(self, membership_id, ring, stream, seq)
    }
}

/// The coordinator's handler of a ship task, `decisions.ship` or `events.ship` version 1: the
/// consumer of the task's descriptor, and where the member's pins are read.
pub struct Ingest<C> {
    pub consumer: Arc<Consumer<C>>,
    pub pins: Arc<dyn StreamPins>,
}

impl<C: RecordCodec> Ingest<C> {
    fn answer(
        &self,
        context: &TaskContext,
        body: &[u8],
        incidents: Option<&dyn Incidents>,
    ) -> Result<Vec<u8>, Refusal> {
        let ring = self.consumer.ring();
        let pins = |stream: &str, seq: u64| {
            self.pins
                .verifying_pins(&context.membership_id, ring, stream, seq)
        };
        let shipping = Shipping {
            membership_id: context.membership_id,
            epoch: context.epoch,
            member: context.member,
            resource: &context.resource,
            pins: &pins,
        };
        let deferred = |error: StreamError| {
            // The member retries; the coordinator says why (after the review).
            tracing::error!(
                event.name = "host.stream.ingest_deferred",
                component = "stream",
                task = %context.task_id,
                error = %error,
                "a shipped batch could not be kept now: the member retries"
            );
            Refusal {
                code: codes::stream::STORE_UNAVAILABLE,
                reason: format!("the stream cannot keep the batch now: {error}"),
            }
        };
        let (answer, forked) = self.consumer.ingest(&shipping, body).map_err(deferred)?;
        if let Some(forked) = forked {
            let suspended = match incidents {
                Some(incidents) => incidents.stream_forked(&forked.stream, forked.at_seq),
                None => Err("no session reported it".to_owned()),
            };
            if let Err(error) = suspended {
                tracing::error!(
                    event.name = "host.stream.fork_unsuspended",
                    component = "stream",
                    stream = %forked.stream,
                    error = %error,
                    "a forked stream's membership could not be suspended"
                );
            }
        }
        answer.encode().map_err(deferred)
    }
}

impl<C: RecordCodec> TaskHandler for Ingest<C> {
    fn handle(&self, context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        self.answer(context, body, None)
    }

    fn handle_with(
        &self,
        context: &TaskContext,
        body: &[u8],
        incidents: &dyn Incidents,
    ) -> Result<Vec<u8>, Refusal> {
        self.answer(context, body, Some(incidents))
    }
}
