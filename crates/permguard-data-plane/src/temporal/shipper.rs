// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Shipping events to the control plane: at-least-once, and never at the cost of the history.
//!
//! ```text
//! local durable journal ─▶ contiguous signed batch ─▶ control plane ─▶ durable ack ─▶ advance
//! ```
//!
//! # What makes this different from shipping decisions
//!
//! The pattern is the decision shipper's, and deliberately so. The difference is what an
//! acknowledgement *permits*: a decision record acknowledged may be deleted, because it was only
//! ever evidence. An event record acknowledged may be deleted **only if no loaded policy could
//! still read it** — it is also the history this plane decides against. So the shipper advances
//! the acknowledgement watermark and stops there; what may actually be evicted is
//! `min(acked, retention-safe)`, and that second number is the policies'.
//!
//! # A control-plane outage is not a reason to stop deciding
//!
//! While the journal has capacity, decisions continue and the backlog grows. When capacity or
//! retention safety is threatened, submissions fail closed — because the alternative is discarding
//! temporal history, and an event silently lost changes what *future* authorizations mean. There
//! is no mode in which this drops events to keep going.
//!
//! # One batch, one stream
//!
//! A batch covers a contiguous run of one producer stream, so a plane serving several ledgers
//! ships several batches. Merging them would produce a batch whose records do not chain, and whose
//! Merkle root would attest a set nobody can verify as a sequence.

use std::sync::Arc;

use permguard_control_client::events::{EventSink, ShipError, Shipped};
use permguard_core::{KeyManager, Metrics};
use permguard_events::chain;
use permguard_events::envelope::{Envelope, Signed};
use serde_json::Value;
use tracing::{error, info, warn};

use super::measure;
use super::streams::Streams;

const COMPONENT: &str = "temporal";

/// The most records one batch carries.
///
/// Bounded by count as well as bytes: a batch of a million tiny records is a batch the receiver
/// has to hold in memory while it verifies a Merkle tree over it.
pub const MAX_BATCH_RECORDS: usize = 10_000;

/// What one round concluded, for one ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Round {
    /// Nothing was waiting.
    Idle,
    /// A batch landed and the acknowledgement moved.
    Shipped {
        /// How many records went.
        records: usize,
        /// What the control plane now holds.
        acked: u64,
    },
    /// The store could not take it. The records are still here, and so is the history.
    Deferred(String),
    /// The batch was refused on its merits. This is an incident.
    Stopped {
        /// The server's code.
        code: String,
        /// What it said.
        detail: String,
    },
}

/// Everything a round needs, resolved once.
pub struct Shipper {
    streams: Arc<Streams>,
    sink: Box<dyn EventSink>,
    keys: Arc<dyn KeyManager>,
    /// The most bytes one batch carries.
    max_bytes: u64,
    metrics: Metrics,
}

impl Shipper {
    /// Builds a shipper for this plane's journals.
    pub fn new(
        streams: Arc<Streams>,
        sink: Box<dyn EventSink>,
        keys: Arc<dyn KeyManager>,
        max_bytes: u64,
        metrics: Metrics,
    ) -> Self {
        Self {
            streams,
            sink,
            keys,
            max_bytes,
            metrics,
        }
    }

    /// Runs one round over every ledger this plane holds a journal for.
    ///
    /// Every ledger, not the first with something waiting: one tenant's outage must not starve
    /// another's shipping, and a round that stopped at the first deferral would do exactly that.
    pub fn round(&self) -> Vec<((String, String), Round)> {
        let mut rounds = Vec::new();
        for (zone, ledger) in self.streams.ledgers() {
            let round = self.ship(&zone, &ledger);
            self.publish(&zone, &ledger, &round);
            rounds.push(((zone, ledger), round));
        }

        rounds
    }

    /// One ledger's round.
    pub fn ship(&self, zone: &str, ledger: &str) -> Round {
        let state = match self.streams.state(zone, ledger) {
            Ok(state) => state,
            Err(error) => return Round::Deferred(error.to_string()),
        };
        let pending =
            match self
                .streams
                .read_from(zone, ledger, state.acked_through, MAX_BATCH_RECORDS)
            {
                Ok(pending) if pending.is_empty() => return Round::Idle,
                Ok(pending) => pending,
                Err(error) => return Round::Deferred(error.to_string()),
            };
        // Only what is durable: a record written and not yet flushed is not one this plane may ask
        // anybody else to hold, because a crash would leave the receiver holding what the producer
        // does not.
        let pending: Vec<Value> = pending
            .into_iter()
            .filter(|record| {
                record
                    .get("seq")
                    .and_then(Value::as_u64)
                    .unwrap_or(u64::MAX)
                    <= state.durable_through
            })
            .collect();
        if pending.is_empty() {
            return Round::Idle;
        }
        let records = self.bound(pending);

        let previous_head = match self.streams.head_at(zone, ledger, state.acked_through) {
            Ok(head) => head,
            Err(error) => return Round::Deferred(error.to_string()),
        };
        let batch = match self.batch(&records, &previous_head) {
            Ok(batch) => batch,
            Err(detail) => {
                // A batch this plane cannot build is this plane's bug, not the receiver's: it must
                // be visible, and it must not spin.
                error!(
                    event.name = "events.unshippable",
                    component = COMPONENT,
                    zone,
                    ledger,
                    detail = detail.as_str(),
                    "this plane cannot assemble a batch from its own journal"
                );

                return Round::Stopped {
                    code: "unshippable".to_owned(),
                    detail,
                };
            }
        };

        // The signed checkpoint, persisted before the batch leaves.
        //
        // `signed_through` claims a signed checkpoint covering it is on this volume, and until this
        // ran the claim was made from the control plane's acknowledgement — which is a statement
        // about the *receiver*, and left the watermark as a second copy of `acked_through` with no
        // local evidence behind it. Written here, in the order the watermarks are defined:
        // durable, then signed, then acknowledged.
        let covering = self.envelope_range(&batch);
        if let Some((first_seq, last_seq)) = covering {
            if let Err(error) = self.streams.checkpoint(
                zone,
                ledger,
                first_seq,
                last_seq,
                &batch.signature.compact(),
            ) {
                // Deferred rather than stopped: the records are durable and the batch can be
                // rebuilt and re-signed on the next round. What must not happen is shipping it
                // while claiming a checkpoint this volume does not hold.
                return Round::Deferred(error.to_string());
            }

            // Which key signed this stretch, recorded beside the journal with the public key
            // itself — the kid the signature carries, never whatever key is active now. Deferred
            // on failure for the checkpoint's own reason: a stretch of signed stream whose key
            // nobody can name is a stream a verifier cannot check offline.
            if let Err(error) = self.note_signer(zone, ledger, first_seq, &batch) {
                return Round::Deferred(error);
            }
        }

        match self.sink.ship(&batch) {
            Ok(Shipped::Acknowledged { acked }) => {
                // The head recorded is the digest *at* `acked`, not the digest of whatever this
                // batch ended with. They are the same in the ordinary case and not in the ones
                // that matter — a partial acknowledgement, or one from a store further ahead than
                // this journal believes — and getting it wrong means the next batch declares a
                // `previous_head` nobody holds.
                if acked > state.durable_through {
                    error!(
                        event.name = "events.ack_ahead",
                        component = COMPONENT,
                        zone,
                        ledger,
                        acked,
                        durable = state.durable_through,
                        "the control plane acknowledged a sequence this plane has not made \
                         durable: its journal and the store disagree about the same stream"
                    );

                    return Round::Stopped {
                        code: "ack_ahead".to_owned(),
                        detail: format!(
                            "the store acknowledged sequence {acked}, and this plane is durable \
                             only through {}: the journal and the store disagree about the same \
                             stream",
                            state.durable_through
                        ),
                    };
                }
                // Signed already — by the checkpoint written before this batch left — so this
                // only has to record what the receiver confirmed. A partial acknowledgement is
                // still covered: the checkpoint spans the whole batch, and `acked` is inside it.
                if let Err(error) = self.streams.acknowledge(zone, ledger, acked) {
                    return Round::Deferred(error.to_string());
                }
                self.metrics.count(&measure::SHIPPED, &[("outcome", "ok")]);
                info!(
                    event.name = "events.shipped",
                    component = COMPONENT,
                    zone,
                    ledger,
                    records = records.len(),
                    acked,
                    "an event batch is durable on the control plane"
                );

                Round::Shipped {
                    records: records.len(),
                    acked,
                }
            }
            Ok(Shipped::OutOfOrder { expected_seq }) => {
                // Nothing is lost: the store needs an earlier batch first, and the next round
                // reads from what it acknowledged.
                self.metrics
                    .count(&measure::SHIPPED, &[("outcome", "out_of_order")]);
                warn!(
                    event.name = "events.out_of_order",
                    component = COMPONENT,
                    zone,
                    ledger,
                    expected_seq,
                    "the control plane needs an earlier batch first"
                );

                Round::Deferred(format!("the store expects sequence {expected_seq}"))
            }
            Err(ShipError::Unavailable(detail)) => {
                self.metrics
                    .count(&measure::SHIPPED, &[("outcome", "deferred")]);

                Round::Deferred(detail)
            }
            Err(ShipError::Rejected { code, detail }) => {
                self.metrics
                    .count(&measure::SHIPPED, &[("outcome", "rejected")]);
                error!(
                    event.name = "events.rejected",
                    component = COMPONENT,
                    zone,
                    ledger,
                    code = code.as_str(),
                    detail = detail.as_str(),
                    "the control plane refused an event batch on its merits: this is an incident, \
                     not a retry"
                );

                Round::Stopped { code, detail }
            }
        }
    }

    /// Trims a read to the byte bound, keeping at least one record.
    ///
    /// At least one, always: a single record larger than the bound would otherwise stall the
    /// stream behind it for ever.
    fn bound(&self, records: Vec<Value>) -> Vec<Value> {
        let mut kept = Vec::new();
        let mut bytes = 0u64;
        for record in records {
            let size = serde_json::to_vec(&record)
                .map(|body| body.len())
                .unwrap_or(0) as u64;
            if !kept.is_empty() && bytes + size > self.max_bytes {
                break;
            }
            bytes += size;
            kept.push(record);
        }

        kept
    }

    /// One signed batch over a contiguous run.
    /// Records which key signed the batch starting at `first_seq`, beside the journal.
    fn note_signer(
        &self,
        zone: &str,
        ledger: &str,
        first_seq: u64,
        batch: &permguard_events::Batch,
    ) -> Result<(), String> {
        let kid = batch
            .signature
            .protected()
            .map_err(|error| error.to_string())?
            .kid;
        let published = self.keys.public_keys().map_err(|error| error.to_string())?;
        let jwk = published
            .into_iter()
            .find(|key| key.kid == kid)
            .ok_or_else(|| {
                format!("the ring no longer publishes `{kid}`, which just signed a batch")
            })?;
        let jwk = serde_json::to_value(&jwk).map_err(|error| error.to_string())?;

        self.streams
            .note_signer(zone, ledger, first_seq, &kid, &jwk)
            .map_err(|error| error.to_string())
    }

    /// The sequence range a batch's own records cover.
    ///
    /// Taken from the records rather than from the envelope's fields so that what is checkpointed
    /// is what is shipped, even if the two ever disagree.
    fn envelope_range(&self, batch: &permguard_events::Batch) -> Option<(u64, u64)> {
        let sequences: Vec<u64> = batch
            .records
            .iter()
            .filter_map(|record| record.get("seq")?.as_u64())
            .collect();

        Some((*sequences.iter().min()?, *sequences.iter().max()?))
    }

    fn batch(
        &self,
        records: &[Value],
        previous_head: &str,
    ) -> Result<permguard_events::Batch, String> {
        let verified = chain::verify(records, Some(previous_head)).map_err(|e| e.to_string())?;
        let merkle_root = permguard_decisions::merkle::root(&verified.digests)
            .ok_or_else(|| "an empty batch has no root".to_owned())?;
        let mut event_types: Vec<String> = records
            .iter()
            .filter_map(|record| Some(record.get("event_type")?.as_str()?.to_owned()))
            .collect();
        event_types.sort();
        event_types.dedup();

        let envelope = Envelope {
            stream: verified.stream,
            first_seq: verified.first_seq,
            last_seq: verified.last_seq,
            count: records.len() as u64,
            previous_head: previous_head.to_owned(),
            head: verified.head,
            merkle_root,
            event_types,
            record_version: 1,
            at: now(),
        };

        Ok(permguard_events::Batch {
            signature: Signed::create(&envelope, self.keys.as_ref())
                .map_err(|error| error.to_string())?,
            records: records.to_vec(),
        })
    }

    /// Publishes the backlog this ledger is carrying.
    fn publish(&self, zone: &str, ledger: &str, round: &Round) {
        let Ok(state) = self.streams.state(zone, ledger) else {
            return;
        };
        let labels = [("zone", zone), ("ledger", ledger)];
        // The number an operator watches: how far the control plane is behind what this plane has
        // made durable. Steadily climbing means the outage has outlasted the journal's capacity,
        // and that is when submissions start failing closed.
        self.metrics.set(
            &measure::BACKLOG,
            &labels,
            state.durable_through.saturating_sub(state.acked_through) as f64,
        );
        if matches!(round, Round::Shipped { .. }) {
            self.metrics
                .set(&measure::LAST_SHIPPED, &labels, unix_seconds());
        }
    }
}

/// This moment, as the canonical instant an envelope states.
fn now() -> String {
    permguard_events::index::render_epoch_seconds(unix_seconds() as i64)
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
}

fn unix_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as f64)
        .unwrap_or_default()
}

/// The bounded exponential backoff a round waits after a deferral.
///
/// Bounded and jittered, both for the same reason: a fleet of planes that all lost the control
/// plane at once must not come back in lockstep, and a plane that has been retrying for an hour
/// must not be retrying once an hour.
#[derive(Debug, Clone, Copy)]
pub struct Backoff {
    /// The first wait after a deferral.
    pub base: std::time::Duration,
    /// The longest wait, however many deferrals there have been.
    pub ceiling: std::time::Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            base: std::time::Duration::from_secs(1),
            ceiling: std::time::Duration::from_secs(60),
        }
    }
}

impl Backoff {
    /// How long to wait after `failures` consecutive deferrals.
    ///
    /// Deterministic in the exponent and jittered in the result: `attempt` doubles the wait up to
    /// the ceiling, and the jitter spreads a fleet across the window rather than clustering it at
    /// the boundary.
    pub fn wait(&self, failures: u32, jitter: f64) -> std::time::Duration {
        if failures == 0 {
            return std::time::Duration::ZERO;
        }
        let doubled = self
            .base
            .saturating_mul(2u32.saturating_pow(failures.saturating_sub(1).min(16)));
        let capped = doubled.min(self.ceiling);
        // Full jitter over `[capped/2, capped]`: never zero, so a hot loop is impossible, and
        // never the same for two planes, so a fleet does not synchronise.
        let jitter = jitter.clamp(0.0, 1.0);
        let half = capped / 2;

        half + capped.mul_f64(jitter) / 2
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_bounded_and_never_reaches_zero() {
        let backoff = Backoff::default();

        assert_eq!(backoff.wait(0, 0.5), std::time::Duration::ZERO);
        for failures in 1..40u32 {
            let waited = backoff.wait(failures, 0.5);
            assert!(
                waited > std::time::Duration::ZERO,
                "a zero wait is a hot loop"
            );
            assert!(
                waited <= backoff.ceiling,
                "an hour of deferrals must not become an hour between attempts"
            );
        }
        assert!(backoff.wait(1, 0.0) < backoff.wait(8, 0.0), "it doubles");
    }

    /// Two planes that lost the control plane at the same moment do not come back together.
    #[test]
    fn the_jitter_spreads_a_fleet_across_the_window() {
        let backoff = Backoff::default();

        assert_ne!(backoff.wait(6, 0.0), backoff.wait(6, 1.0));
        assert!(backoff.wait(6, 0.0) < backoff.wait(6, 1.0));
    }
}
