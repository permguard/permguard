// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The shipping half: batches leave, acknowledgements come back, the spool
//! shrinks.
//!
//! # What one round does
//!
//! ```text
//! read from `acked` ──► sign a batch ──► ship ──► acknowledge ──► truncate
//!       │                                  │
//!       └── nothing to send: sleep         └── refused: retry, or stop and alarm
//! ```
//!
//! # Retry against stop, which is not a matter of taste
//!
//! A shipper that retries a batch nobody can verify loops forever and never
//! surfaces the incident. One that drops a batch the store merely could not
//! take right now loses records that were durable on its own disk. So the two
//! are separated at the source — [`ShipError`] has exactly these two shapes —
//! and this loop honours the distinction rather than re-deriving it from a
//! status code.
//!
//! # Backoff, and why it is bounded both ways
//!
//! Exponential from the batch interval to a ceiling: a control plane that is
//! down for an hour must not be met with an hour of retries per second, and a
//! control plane that comes back must not wait an hour to be noticed. The
//! ceiling is what makes recovery prompt; the growth is what makes an outage
//! cheap.

use std::sync::Arc;
use std::time::Duration;

use permguard_control_client::decisions::{DecisionLog, ShipError, Shipped};
use permguard_core::{KeyManager, Metrics};
use permguard_decisions::envelope::{Batch, Envelope, Signed};
use permguard_decisions::record::Sampling;
use permguard_decisions::{chain, merkle, record};
use serde_json::Value;
use tracing::{error, info, warn};

use super::journal::Journal;
use super::measure;

const COMPONENT: &str = "data-plane";

/// How long a round waits after a failure, at most.
const MAX_BACKOFF: Duration = Duration::from_secs(60);

/// What one round of shipping did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Round {
    /// Nothing was waiting.
    Idle,
    /// A batch landed and the spool was truncated.
    Shipped {
        /// How many records went.
        records: usize,
        /// What the control plane now holds.
        acked: u64,
    },
    /// The store could not take it. The records are still here.
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
    journal: Arc<Journal>,
    sink: Box<dyn DecisionLog>,
    keys: Arc<dyn KeyManager>,
    /// The most records one batch carries.
    max_records: usize,
    /// The most bytes one batch carries.
    max_bytes: u64,
    sampling: String,
    metrics: Metrics,
}

impl Shipper {
    /// Builds a shipper for one journal.
    pub fn new(
        journal: Arc<Journal>,
        sink: Box<dyn DecisionLog>,
        keys: Arc<dyn KeyManager>,
        max_bytes: u64,
        sampling: impl Into<String>,
        metrics: Metrics,
    ) -> Self {
        Self {
            journal,
            sink,
            keys,
            // Bounded by count as well as bytes: a batch of a million tiny
            // records is a batch the receiver has to hold in memory.
            max_records: 10_000,
            max_bytes,
            sampling: sampling.into(),
            metrics,
        }
    }

    /// Runs one round.
    pub fn round(&self) -> Round {
        let pending = match self.journal.pending(self.max_records) {
            Ok(pending) if pending.is_empty() => return Round::Idle,
            Ok(pending) => pending,
            Err(error) => return Round::Deferred(error.to_string()),
        };
        let records = self.bound(pending);

        let batch = match self.batch(&records) {
            Ok(batch) => batch,
            Err(detail) => {
                // A batch this plane cannot build is this plane's bug, not the
                // receiver's: it must be visible, and it must not spin.
                error!(
                    event.name = "decisions.unshippable",
                    component = COMPONENT,
                    detail = detail.as_str(),
                    "this plane cannot assemble a batch from its own spool"
                );

                return Round::Stopped {
                    code: "unshippable".to_owned(),
                    detail,
                };
            }
        };
        let body = match serde_json::to_value(&batch) {
            Ok(body) => body,
            Err(error) => {
                return Round::Stopped {
                    code: "unshippable".to_owned(),
                    detail: error.to_string(),
                };
            }
        };

        match self.sink.ship(&body) {
            Ok(Shipped::Acknowledged { acked, .. }) => {
                // The head recorded has to be the digest *at* `acked`, not the
                // digest of whatever this batch ended with. They are the same
                // number in the ordinary case and not in the ones that matter:
                // an acknowledgement covering only part of the batch, or one
                // from a store further ahead than this spool believes. Getting
                // it wrong means the next batch declares a `previous_head`
                // nobody holds, and the receiver refuses it on its merits —
                // an incident manufactured out of a stale answer.
                let Some(head) = records
                    .iter()
                    .find(|record| record.get("seq").and_then(Value::as_u64) == Some(acked))
                    .and_then(|record| record::digest_of(record).ok())
                    .or_else(|| self.journal.digest_at(acked).ok().flatten())
                else {
                    // The store is ahead of this spool and the record it
                    // acknowledged is not here to be digested. Truncating on
                    // that number would delete records that are still this
                    // plane's only copy, so nothing is truncated and this is
                    // reported as what it is.
                    error!(
                        event.name = "decisions.ack_ahead",
                        component = COMPONENT,
                        acked,
                        "the control plane acknowledged a sequence this plane does not hold: its \
                         spool and the store disagree about the same stream"
                    );

                    return Round::Stopped {
                        code: "ack_ahead".to_owned(),
                        detail: format!(
                            "the store acknowledged sequence {acked}, which this plane does not \
                             hold: the spool and the store disagree about the same stream"
                        ),
                    };
                };
                if let Err(error) = self.journal.acknowledge(acked, &head) {
                    return Round::Deferred(error.to_string());
                }
                self.metrics.count(&measure::SHIPPED, &[("outcome", "ok")]);
                info!(
                    event.name = "decisions.shipped",
                    component = COMPONENT,
                    records = records.len(),
                    acked,
                    "a decision batch is durable on the control plane"
                );

                Round::Shipped {
                    records: records.len(),
                    acked,
                }
            }
            Ok(Shipped::OutOfOrder { expected_seq }) => {
                // Nothing is lost: the store needs an earlier batch first, and
                // the next round reads from what it acknowledged.
                self.metrics
                    .count(&measure::SHIPPED, &[("outcome", "out_of_order")]);
                warn!(
                    event.name = "decisions.out_of_order",
                    component = COMPONENT,
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
                    event.name = "decisions.rejected",
                    component = COMPONENT,
                    code = code.as_str(),
                    detail = detail.as_str(),
                    "the control plane refused a decision batch on its merits: this is an incident, not a retry"
                );

                Round::Stopped { code, detail }
            }
        }
    }

    /// Trims a read to the byte bound, keeping at least one record.
    ///
    /// At least one, always: a single record larger than the bound would
    /// otherwise stall the stream behind it forever.
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

    fn batch(&self, records: &[Value]) -> Result<Batch, String> {
        let verified = chain::verify(records, None).map_err(|error| error.to_string())?;
        let leaves: Vec<String> = records
            .iter()
            .map(|record| record::digest_of(record).unwrap_or_default())
            .collect();
        // From the spool, never from memory: the head the receiver holds is
        // durable state, and a restart that guessed it would ship a batch
        // claiming to continue a history nobody has.
        let previous_head = self.journal.previous_head();
        let envelope = Envelope {
            stream: verified.stream,
            first_seq: verified.first_seq,
            last_seq: verified.last_seq,
            count: records.len() as u64,
            previous_head,
            head: verified.head,
            merkle_root: merkle::root(&leaves).ok_or("an empty batch is not shipped")?,
            sampling: Sampling {
                permits: self.sampling.clone(),
            },
            at: now(),
        };

        Ok(Batch {
            signature: Signed::create(&envelope, self.keys.as_ref())
                .map_err(|error| error.to_string())?,
            records: records.to_vec(),
        })
    }
}

/// How long to wait after `failures` consecutive failures.
pub fn backoff(base: Duration, failures: u32) -> Duration {
    let factor = 1u64 << failures.min(6);

    base.saturating_mul(factor as u32).min(MAX_BACKOFF)
}

fn now() -> String {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs() as i64)
        .unwrap_or_default();

    permguard_core::time::to_rfc3339(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_then_stops_growing() {
        let base = Duration::from_secs(1);

        assert_eq!(backoff(base, 0), Duration::from_secs(1));
        assert_eq!(backoff(base, 3), Duration::from_secs(8));
        assert_eq!(
            backoff(base, 30),
            MAX_BACKOFF,
            "a control plane that comes back must not wait an hour to be noticed"
        );
    }
}
