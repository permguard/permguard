// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the decision path counts about itself.
//!
//! Three questions, and the numbers that answer them: *is it answering* —
//! decisions by outcome, and how long they take; *is it warm* — cache hits,
//! misses, evictions and what is held; *is anything unserveable* — the ledgers
//! this engine had to refuse.
//!
//! Labels are the zone and ledger **names** a PEP asked for, plus the outcome.
//! Bounded by what this plane mirrors, like the synchronization metrics — a
//! decision path cannot be made to mint series by a caller naming ledgers that
//! do not exist, because those are counted under a single `unserved` series.

use permguard_core::metrics::{Metric, SECONDS};

/// Decisions answered, by outcome — the four results of the algebra: `permit`, `deny` (a policy
/// said no), `deny_by_default` (nothing permitted) and `indeterminate` (a partition could not
/// evaluate, and no policy denied). A batch is not one of the algebra's results: it counts
/// `indeterminate` when it is refused, and otherwise the `permit` or `deny` its semantic gave.
///
/// # Reading it as an SLO
///
/// `indeterminate` is the evaluation-failure rate: requests the plane answered with a typed
/// refusal instead of a decision, which a PEP fails closed on. It is not a deny rate, and it is
/// never folded into one; a dashboard that counts `deny + indeterminate` as "denied" would hide a
/// broken partition behind policy. The partition failures behind it are counted by cause in
/// [`PARTITION_FAILURES`].
pub const DECISIONS: Metric = Metric::counter(
    "permguard_authz_decisions_total",
    "Authorization decisions, by outcome.",
);

/// Partition evaluations that failed, by the stable code of the cause:
/// `evaluation_deadline_exceeded`, `evaluation_panicked`, `evaluation_failed`,
/// `evaluation_input_rejected`. Every one makes its request indeterminate unless a policy denied it
/// — a failure beside a deny that stood is counted too. Stateless and temporal decisions alike.
pub const PARTITION_FAILURES: Metric = Metric::counter(
    "permguard_authz_partition_failures_total",
    "Partition evaluations that failed, by cause.",
);

/// Requests that never reached a decision, by why: `malformed`,
/// `ledger_not_served`, `ledger_empty`, `ledger_incompatible`,
/// `ledger_damaged`, `profile_unknown`.
pub const REFUSALS: Metric = Metric::counter(
    "permguard_authz_refusals_total",
    "Authorization requests refused before a decision, by reason.",
);

/// How long one whole request took — evaluations, cache lookups and all.
pub const REQUEST_SECONDS: Metric = Metric::histogram(
    "permguard_authz_request_seconds",
    "How long an authorization request took.",
    SECONDS,
);

/// How long one evaluation took inside a partition. The number that separates
/// "the policy set is large" from "the request is large".
pub const EVALUATION_SECONDS: Metric = Metric::histogram(
    "permguard_authz_evaluation_seconds",
    "How long one evaluation took.",
    SECONDS,
);

/// Evaluations answered, counting a boxcarred batch as what it is: many.
pub const EVALUATIONS: Metric = Metric::counter(
    "permguard_authz_evaluations_total",
    "Evaluations answered, by outcome.",
);

/// Partitions compiled: the expensive path, and the one the cache exists to
/// keep off the hot path.
pub const COMPILATIONS: Metric = Metric::counter(
    "permguard_authz_compilations_total",
    "Partitions compiled from the volume.",
);

/// How long compiling one partition took.
pub const COMPILE_SECONDS: Metric = Metric::histogram(
    "permguard_authz_compile_seconds",
    "How long compiling one partition took.",
    SECONDS,
);

/// Cache lookups, by result: `hit`, `miss`.
pub const CACHE_LOOKUPS: Metric = Metric::counter(
    "permguard_authz_cache_lookups_total",
    "Decision cache lookups, by result.",
);

/// Entries dropped because a bound was reached. Steadily climbing means the
/// bounds are too small for what this plane serves.
pub const CACHE_EVICTIONS: Metric = Metric::counter(
    "permguard_authz_cache_evictions_total",
    "Decision cache entries evicted to stay inside the configured bounds.",
);

/// How many entries the cache holds, and how many bytes they weigh.
pub const CACHE_ENTRIES: Metric = Metric::gauge(
    "permguard_authz_cache_entries",
    "Compiled partitions and heads held in memory.",
);

/// The bytes those entries weigh, against `authz.cache.bytes`.
pub const CACHE_BYTES: Metric = Metric::gauge(
    "permguard_authz_cache_bytes",
    "Bytes of compiled partitions held in memory.",
);

/// Ledgers this engine refuses to serve, by zone and ledger: the load gate
/// said no, and the block file remembers it. Anything above zero is somebody's
/// upgrade waiting to happen.
pub const BLOCKED: Metric = Metric::gauge(
    "permguard_authz_blocked_ledgers",
    "Ledgers this engine cannot serve.",
);

/// Decision audit records handled by the asynchronous audit worker.
pub const AUDIT_RECORDS: Metric = Metric::counter(
    "permguard_authz_audit_records_total",
    "Decision audit records handled by the queue, by outcome.",
);

/// Decision audit entries waiting for the worker.
pub const AUDIT_QUEUE_DEPTH: Metric = Metric::gauge(
    "permguard_authz_audit_queue_depth",
    "Decision audit records queued but not yet recorded.",
);
