// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Named crash points: every step of every protocol, where a crash-point test kills the process.
//!
//! A protocol is crash-safe only if recovery is right at *every* step, not at the random ones a
//! kill happens to land on. Each step calls [`point`] with its name; built with the `crash-points`
//! feature, a process whose `PERMGUARD_CRASH_AT` names that point aborts there: no unwinding, no
//! destructors, nothing after the point runs. A build without the feature carries no check at all.
//!
//! An abort is a process crash, not a power loss. The kernel keeps what the process wrote, flushed
//! or not, so a point between a write and its flush recovers here exactly like the point after the
//! flush. These tests prove recovery is right whatever step the *process* dies at; that a flush
//! really reaches the medium is a property of the storage stack, which no in-process test can
//! show, and is the qualification evidence of H-04 (WP-1.3). The random `SIGKILL` rounds of the
//! conformance crash harness run the same protocols without named points.

/// The environment variable a crash-point test sets in the child it will kill.
pub const CRASH_AT: &str = "PERMGUARD_CRASH_AT";

/// Every crash point, in the order each protocol reaches them.
pub const POINTS: &[&str] = &[
    "immutable.temp_created",
    "immutable.temp_written",
    "immutable.temp_flushed",
    "immutable.linked",
    "immutable.temp_removed",
    "immutable.parent_flushed",
    "view.temp_written",
    "view.temp_flushed",
    "view.renamed",
    "view.parent_flushed",
    "journal.frame_written",
    "journal.frame_flushed",
    "journal.roll_old_flushed",
    "journal.roll_segment_created",
    "journal.roll_header_flushed",
    "journal.roll_parent_flushed",
    "tombstone.written",
    "tombstone.unlinked",
    "tombstone.parent_flushed",
    "tombstone.removed",
    "failure.recorded",
    "failure.cut_segments_removed",
    "failure.cut_flushed",
    "failure.record_removed",
];

/// The crash point `name`: aborts here when this process was told to.
#[inline]
pub fn point(name: &'static str) {
    #[cfg(feature = "crash-points")]
    if std::env::var(CRASH_AT).as_deref() == Ok(name) {
        std::process::abort();
    }
    #[cfg(not(feature = "crash-points"))]
    let _ = name;
}
