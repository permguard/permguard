// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the decision log reports about itself.
//!
//! The numbers here answer three operational questions and no others: is the
//! log keeping up, is it losing anything, and how close is the spool to the
//! decision only a deployment can make.

use permguard_core::metrics::Metric;

/// Records written to the spool, by kind.
pub const WRITTEN: Metric = Metric::counter(
    "permguard_decisions_written_total",
    "Decision-log records written to the spool, by kind.",
);

/// Permits not recorded because sampling said so.
///
/// Separate from `dropped`: a sampled-out permit was never a record and leaves
/// no hole, while a dropped one is loss. Conflating them would make a
/// completeness claim unreadable.
pub const SAMPLED_OUT: Metric = Metric::counter(
    "permguard_decisions_sampled_out_total",
    "Permits deliberately not recorded, at the declared rate.",
);

/// Records discarded because the spool reached a bound.
///
/// Anything above zero is loss, and the stream that carried them has ended.
pub const DROPPED: Metric = Metric::counter(
    "permguard_decisions_dropped_total",
    "Decision records discarded when a stream ended under pressure.",
);

/// Streams ended by a discontinuity, by reason.
pub const DISCONTINUITIES: Metric = Metric::counter(
    "permguard_decisions_discontinuities_total",
    "Streams ended by a signed discontinuity, by reason.",
);

/// How far the spool has run ahead of what the control plane has confirmed.
///
/// The single most useful gauge here: a number that climbs and does not come
/// back is a shipper that is not shipping, and it is visible long before the
/// spool is full.
pub const UNSHIPPED: Metric = Metric::gauge(
    "permguard_decisions_unshipped_records",
    "Records written but not yet acknowledged durable by the control plane.",
);

/// How many bytes the spool is holding.
pub const SPOOL_BYTES: Metric = Metric::gauge(
    "permguard_decisions_spool_bytes",
    "Bytes of decision records held on this volume.",
);

/// Where the live stream stands.
pub const SEQUENCE: Metric = Metric::gauge(
    "permguard_decisions_sequence",
    "The highest sequence written in the live stream.",
);

/// The highest sequence the control plane confirmed durable.
pub const ACKED: Metric = Metric::gauge(
    "permguard_decisions_acked_sequence",
    "The highest contiguous sequence the control plane confirmed durable.",
);

/// Batches shipped, by outcome: `ok`, `out_of_order`, `deferred`, `rejected`.
///
/// `rejected` above zero is an incident: the control plane refused a batch on
/// its merits, and no amount of retrying changes that answer.
pub const SHIPPED: Metric = Metric::counter(
    "permguard_decisions_shipped_total",
    "Decision batches shipped, by outcome.",
);

/// Every metric this module publishes.
pub const ALL: &[Metric] = &[
    WRITTEN,
    SHIPPED,
    SAMPLED_OUT,
    DROPPED,
    DISCONTINUITIES,
    UNSHIPPED,
    SPOOL_BYTES,
    SEQUENCE,
    ACKED,
];
