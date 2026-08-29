// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the event store counts about itself.
//!
//! Two questions, and the numbers that answer them: *is it accepting* — batches and records by
//! outcome, and how long ingest takes; *is it serving* — reads by scope and outcome, and how much
//! work a filtered read did that a consumer did not see.

use permguard_core::metrics::{Metric, SECONDS};

/// Batches offered, by outcome: `accepted`, `replayed`, `out_of_order`, `refused`.
pub const BATCHES: Metric = Metric::counter(
    "permguard_events_batches_total",
    "Event batches offered to the store, by outcome.",
);

/// Records made durable, by zone and ledger.
pub const RECORDS: Metric = Metric::counter(
    "permguard_events_records_total",
    "Event records made durable, by zone and ledger.",
);

/// Streams closed because two different records claimed one sequence.
///
/// Never zero for long without a reason: a fork is a bug or an attack, and both are worth paging.
pub const FORKS: Metric = Metric::counter(
    "permguard_events_forks_total",
    "Producer streams closed permanently because two records claimed one sequence.",
);

/// How long accepting one batch took, verification and flush included.
pub const INGEST_SECONDS: Metric = Metric::histogram(
    "permguard_events_ingest_seconds",
    "How long accepting one event batch took.",
    SECONDS,
);

/// Reads answered, by scope and outcome: `ok`, `expired`, `refused`.
pub const READS: Metric = Metric::counter(
    "permguard_events_reads_total",
    "Event reads answered, by scope and outcome.",
);

/// Positions examined to answer a read.
///
/// Against `permguard_events_records_returned_total`, this is what makes a sparse filter visible:
/// a store examining a thousand positions to return two is a store that needs a better index, and
/// the difference is not otherwise observable from outside.
pub const EXAMINED: Metric = Metric::counter(
    "permguard_events_positions_examined_total",
    "Positions examined while answering reads, by scope.",
);

/// Records returned to readers.
pub const RETURNED: Metric = Metric::counter(
    "permguard_events_records_returned_total",
    "Event records returned to readers, by scope.",
);

/// The one number worth alerting on for trust: a plane serving ingestion with zero trusted
/// producers accepts nothing, and from the outside that failure looks like a producer at fault
/// rather than a receiver that never loaded its trust.
pub const TRUSTED_PRODUCERS: Metric = Metric::gauge(
    "permguard_event_trusted_producers",
    "How many bound producer keys this plane currently accepts event batches under.",
);
