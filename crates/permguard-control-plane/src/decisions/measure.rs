// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the decision-log store reports about itself.

use permguard_core::metrics::{Metric, SECONDS};

/// Batches accepted, by outcome: `ok`, `replay`, `out_of_order`.
pub const BATCHES: Metric = Metric::counter(
    "permguard_decisions_batches_total",
    "Decision-log batches accepted, by outcome.",
);

/// Batches refused, by why: `unattributable`, `unverifiable`, `conflict`,
/// `closed`, `unavailable`.
pub const REFUSALS: Metric = Metric::counter(
    "permguard_decisions_refusals_total",
    "Decision-log batches refused, by reason.",
);

/// Records stored, by zone and ledger.
///
/// Labelled by tenancy because retention, export and billing are all per zone,
/// and an operator asking "who is producing this volume" should not have to
/// read files to find out.
pub const RECORDS: Metric = Metric::counter(
    "permguard_decisions_records_total",
    "Decision records stored, by zone and ledger.",
);

/// Streams closed permanently after a cryptographic conflict.
///
/// Anything above zero is an incident, not a metric to watch trend.
pub const CLOSED: Metric = Metric::counter(
    "permguard_decisions_streams_closed_total",
    "Decision streams closed permanently after a conflict.",
);

/// Where each producer stream stands.
pub const ACKED: Metric = Metric::gauge(
    "permguard_decisions_stream_acked",
    "The highest contiguous durable sequence, by producer stream.",
);

/// How long accepting one batch took, flush included.
pub const INGEST_SECONDS: Metric = Metric::histogram(
    "permguard_decisions_ingest_seconds",
    "How long accepting one decision batch took, including making it durable.",
    SECONDS,
);

/// Pages served to readers, by scope kind.
pub const READS: Metric = Metric::counter(
    "permguard_decisions_reads_total",
    "Pages of decision records served, by scope kind and outcome.",
);
