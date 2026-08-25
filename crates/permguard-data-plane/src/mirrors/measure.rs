// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the synchronization loop counts about itself.
//!
//! Two questions an operator asks at three in the morning, and the numbers
//! that answer them: *is my policy current* — the age of each mirror's last
//! successful round, and the counter it stands at — and *what is growing* —
//! the bytes and ledgers per zone.
//!
//! Labels are zone and ledger **identities**, which is a bounded set: this
//! plane mirrors only what it was configured to follow, and a renamed zone
//! keeps its series instead of starting a new one.

use permguard_core::metrics::{Metric, SECONDS};

/// Rounds of the loop, by how they ended: `ok`, `partial` (some mirror
/// failed), `skipped` (the previous round was still working).
pub const ROUNDS: Metric = Metric::counter(
    "permguard_sync_rounds_total",
    "Synchronization rounds, by outcome.",
);

/// How long a whole round took, discovery included.
pub const ROUND_SECONDS: Metric = Metric::histogram(
    "permguard_sync_round_seconds",
    "How long a synchronization round took.",
    SECONDS,
);

/// What happened when a freshly mirrored ledger was read for serving:
/// `ready` (compiled and in memory), `empty`, `blocked` (this engine may not
/// serve it), `damaged`. Anything but `ready` means that ledger answers
/// `unavailable` until something changes.
pub const WARMED: Metric = Metric::counter(
    "permguard_sync_warmed_total",
    "Mirrors prepared for serving after a sync, by zone, ledger and outcome.",
);

/// Per-mirror attempts, by outcome: `ok`, `unchanged`, `failed`, `timeout`.
pub const MIRRORS: Metric = Metric::counter(
    "permguard_sync_mirrors_total",
    "Mirror attempts, by zone, ledger and outcome.",
);

/// How long one mirror took — the number that shows a slow ledger before its
/// timeout starts firing.
pub const MIRROR_SECONDS: Metric = Metric::histogram(
    "permguard_sync_mirror_seconds",
    "How long one mirror took, by zone and ledger.",
    SECONDS,
);

/// Objects fetched, and bytes as they rode the wire.
pub const FETCHED_OBJECTS: Metric = Metric::counter(
    "permguard_sync_fetched_objects_total",
    "Objects fetched into mirrors, by zone and ledger.",
);

/// Where each mirror stands: the ref counter it last accepted. A gauge that
/// stops moving while the control plane's counter climbs is the whole story.
pub const MIRROR_COUNTER: Metric = Metric::gauge(
    "permguard_sync_mirror_counter",
    "The ref counter each mirror last accepted, by zone and ledger.",
);

/// How long ago a mirror last completed a round, in seconds. Freshness, as a
/// number a page can be written against.
pub const MIRROR_AGE: Metric = Metric::gauge(
    "permguard_sync_mirror_age_seconds",
    "Seconds since each mirror last synchronized, by zone and ledger.",
);

/// How many mirrors this plane keeps, and how many zones they belong to.
pub const MIRRORS_HELD: Metric =
    Metric::gauge("permguard_sync_mirrors", "Mirrors this plane holds.");
pub const ZONES_HELD: Metric = Metric::gauge(
    "permguard_sync_zones",
    "Zones this plane holds mirrors for.",
);

/// Ledgers per zone — what makes one zone the busy one on a dashboard.
pub const ZONE_LEDGERS: Metric =
    Metric::gauge("permguard_sync_zone_ledgers", "Mirrors held, by zone.");

/// Bytes on the volume, per mirror and per zone: the map of who is occupying
/// the disk, which is the question a full volume asks in retrospect.
pub const MIRROR_BYTES: Metric = Metric::gauge(
    "permguard_sync_mirror_bytes",
    "Bytes one mirror occupies on the volume, by zone and ledger.",
);
pub const ZONE_BYTES: Metric = Metric::gauge(
    "permguard_sync_zone_bytes",
    "Bytes all mirrors of a zone occupy on the volume, by zone.",
);

/// Mirrors removed because they are no longer followed, or no longer exist.
pub const REAPED: Metric =
    Metric::counter("permguard_sync_reaped_total", "Mirrors removed, by reason.");
