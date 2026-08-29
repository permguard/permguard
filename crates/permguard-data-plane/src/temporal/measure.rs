// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the temporal path counts about itself.
//!
//! The stateless path's questions plus the ones only a stateful interface has: *is the history
//! keeping up* — how long the durable append takes, how far behind the shipper is; *is anybody
//! retrying* — idempotent submissions and, separately, conflicts, which are not the same event and
//! must never be counted as one.
//!
//! Labels are the zone and ledger names, like the decision path's, and bounded the same way.

use permguard_core::metrics::{Metric, SECONDS};

/// Occurrences submitted, by zone, ledger and outcome: `decided`, `accepted`, `refused`.
pub const SUBMISSIONS: Metric = Metric::counter(
    "permguard_temporal_submissions_total",
    "Temporal event submissions, by zone, ledger and outcome.",
);

/// Submissions that never reached the journal, by why.
pub const REFUSALS: Metric = Metric::counter(
    "permguard_temporal_refusals_total",
    "Temporal submissions refused before anything was recorded, by reason.",
);

/// How long one whole submission took: validation, the durable append, the fan-out and the log.
pub const SUBMISSION_SECONDS: Metric = Metric::histogram(
    "permguard_temporal_submission_seconds",
    "How long a temporal submission took, end to end.",
    SECONDS,
);

/// How long the durable append took — the `fsync`, which is the floor under every submission.
///
/// Separated from the total on purpose: a plane that has become slow is either waiting on its disk
/// or evaluating a large policy set, and these two numbers are what tell those apart.
pub const APPEND_SECONDS: Metric = Metric::histogram(
    "permguard_temporal_append_seconds",
    "How long making one event record durable took.",
    SECONDS,
);

/// How long observing and deciding one occurrence took, across the addressed partitions.
pub const APPLY_SECONDS: Metric = Metric::histogram(
    "permguard_temporal_apply_seconds",
    "How long observing and deciding one occurrence took.",
    SECONDS,
);

/// Retries recognised as the occurrence already recorded, answered from what was stored.
pub const IDEMPOTENT: Metric = Metric::counter(
    "permguard_temporal_idempotent_total",
    "Submissions recognised as an already-recorded occurrence, by zone and ledger.",
);

/// One event id carrying two different occurrences. Never zero for long without a reason.
pub const CONFLICTS: Metric = Metric::counter(
    "permguard_temporal_conflicts_total",
    "Submissions whose event id was already recorded with different content.",
);

/// Where each ledger's journal stands: `durable`, `signed`, `acknowledged`, `oldest_retained`.
pub const WATERMARK: Metric = Metric::gauge(
    "permguard_temporal_watermark",
    "The sequence each of a ledger's event watermarks stands at.",
);

/// How many bytes one ledger's journal holds.
pub const JOURNAL_BYTES: Metric = Metric::gauge(
    "permguard_temporal_journal_bytes",
    "Bytes held by a ledger's event journal.",
);

/// Shipping rounds, by outcome: `ok`, `out_of_order`, `deferred`, `rejected`.
pub const SHIPPED: Metric = Metric::counter(
    "permguard_temporal_shipped_total",
    "Event shipping rounds, by outcome.",
);

/// How far the control plane is behind what this plane has made durable.
///
/// The number an operator watches through an outage: while it climbs, decisions continue and the
/// journal absorbs them. When the journal's capacity or its retention safety is threatened,
/// submissions start failing closed — because the alternative is discarding temporal history.
pub const BACKLOG: Metric = Metric::gauge(
    "permguard_temporal_backlog_records",
    "Durable event records the control plane has not yet acknowledged, by zone and ledger.",
);

/// When a batch last landed, as seconds since the epoch.
pub const LAST_SHIPPED: Metric = Metric::gauge(
    "permguard_temporal_last_shipped_seconds",
    "When an event batch last landed on the control plane, by zone and ledger.",
);

/// Import rounds, by outcome: `ok`, `quarantined`.
pub const IMPORTS: Metric = Metric::counter(
    "permguard_temporal_imports_total",
    "Event import rounds, by outcome.",
);

/// Records imported from other planes, by zone and ledger.
pub const IMPORTED: Metric = Metric::counter(
    "permguard_temporal_imported_records_total",
    "Event records imported from other planes, by zone and ledger.",
);

/// Times a subscription fell behind what the control plane still holds.
///
/// Expected retention behaviour rather than corruption — and worth counting, because a
/// subscription that keeps falling behind is one whose plane is offline longer than the store
/// retains, and its history has holes an operator should know about.
pub const IMPORT_GAPS: Metric = Metric::counter(
    "permguard_temporal_import_gaps_total",
    "Times an import subscription resumed from the oldest available position, leaving a gap.",
);

/// How many holes an imported history currently has that nobody has accepted.
///
/// A gauge and not a counter: a counter says how many times this plane fell behind retention, and
/// this says whether its history is whole *now*. `shared-bounded` refuses to decide while it is
/// above zero, and `shared-eventual` decides while it is above zero — which is exactly why an
/// operator needs to see the number in both modes.
pub const IMPORT_GAPS_OPEN: Metric = Metric::gauge(
    "permguard_temporal_import_gaps_open",
    "Unresolved holes in an imported history, by zone and ledger.",
);

/// How stale the imported history is, in seconds.
///
/// What `shared-bounded` fails decisions closed on. Published whether or not that mode is on, so a
/// deployment can see what it would be committing to before it commits to it.
pub const IMPORT_STALENESS: Metric = Metric::gauge(
    "permguard_temporal_import_staleness_seconds",
    "How long ago an import subscription last read successfully, by zone and ledger.",
);

/// `fsync`s performed on the event journals, by zone and ledger.
///
/// Read against [`SUBMISSIONS`]: one flush per submission means every submission paid for its own
/// disk barrier, and a ratio well below one means concurrent submissions are sharing them, which is
/// what `events.stream.group_commit_max_delay` buys. It never goes the other way — a record is
/// never acknowledged before the flush covering it returned.
pub const FLUSHES: Metric = Metric::counter(
    "permguard_temporal_flushes_total",
    "Journal flushes performed, by zone and ledger.",
);

/// How many records one flush covered.
///
/// The distribution, not the average: a deployment where most flushes carry one record and a few
/// carry two hundred is a deployment whose load is bursty, and that is a different thing to tune
/// from one where every flush carries ten.
pub const BATCH_RECORDS: Metric = Metric::histogram(
    "permguard_temporal_batch_records",
    "How many event records one journal flush covered.",
    BATCH_SIZES,
);

/// Boundaries for [`BATCH_RECORDS`]: one, a handful, a burst, the cap.
const BATCH_SIZES: &[f64] = &[1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0, 1024.0];
