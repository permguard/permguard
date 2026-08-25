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

/// Decisions answered, by zone, ledger and outcome: `permit`, `deny`,
/// `refused` (the request could not be evaluated at all).
pub const DECISIONS: Metric = Metric::counter(
    "permguard_authz_decisions_total",
    "Authorization decisions, by zone, ledger and outcome.",
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
    "How long one evaluation took, by zone, ledger and partition.",
    SECONDS,
);

/// Evaluations answered, counting a boxcarred batch as what it is: many.
pub const EVALUATIONS: Metric = Metric::counter(
    "permguard_authz_evaluations_total",
    "Evaluations answered, by zone, ledger and outcome.",
);

/// Partitions compiled: the expensive path, and the one the cache exists to
/// keep off the hot path.
pub const COMPILATIONS: Metric = Metric::counter(
    "permguard_authz_compilations_total",
    "Partitions compiled from the volume, by zone, ledger and partition.",
);

/// How long compiling one partition took.
pub const COMPILE_SECONDS: Metric = Metric::histogram(
    "permguard_authz_compile_seconds",
    "How long compiling one partition took, by zone and ledger.",
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
    "Mirrors this engine cannot serve, by zone and ledger.",
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
