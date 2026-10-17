// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Retention and its garbage collection (WP-5.6b; owner decisions of 2026-10-15 and 2026-10-17).
//!
//! | Class      | Producer deletes                                 | Consumer deletes                                    |
//! | ---------- | ------------------------------------------------ | --------------------------------------------------- |
//! | `evidence` | at or below `truncate_safe`                      | past its task's retention, after the anchor         |
//! | `history`  | at or below `min(truncate_safe, retention_safe)` | the same, never below a registered floor            |
//!
//! Every producer and consumer handle is [`Prunable`]: `plan` says what a pass would delete and
//! changes nothing; `run` deletes, at most [`MAX_PRUNE_BATCHES`] batch files per stream, holding
//! the stream's own lock for that stream alone. For each run it writes the [`Anchor`] first,
//! then the audit record the caller writes, then deletes; a record that cannot be written
//! deletes nothing. A stream with nothing to delete is audited too. A pass that finds another of
//! the same handle running does nothing ([`Lease`]). A deletion stops at the end of a whole batch
//! file, and a journal segment goes only when nothing it holds is still kept.
//!
//! [`Anchor`]: super::anchor::Anchor

use std::sync::atomic::{AtomicBool, Ordering};

use super::StreamError;

/// The most batch files one pass deletes of one stream (owner decision of 2026-10-17).
pub const MAX_PRUNE_BATCHES: usize = 1024;

/// What one pass deleted, or would delete, of one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pruned {
    /// The stream: plane, type, resource digest, producer and, for a consumer, run.
    pub stream: String,
    /// `producer` or `consumer`.
    pub role: &'static str,
    /// The run whose prefix goes; `None` for a stream with nothing to delete.
    pub run: Option<[u8; 16]>,
    /// The last sequence deleted, 0 with nothing to delete.
    pub through: u64,
    /// The batch files deleted.
    pub batches: u64,
}

impl Pruned {
    /// A stream with nothing to delete.
    pub(crate) fn nothing(stream: String, role: &'static str) -> Self {
        Self {
            stream,
            role,
            run: None,
            through: 0,
            batches: 0,
        }
    }
}

/// The floor a Plane registers for a `history` stream (owner decision of 2026-10-17): per
/// resource and run, the last sequence no loaded temporal contract reads any more; `None` keeps
/// the run whole.
pub trait RetentionFloor: Send + Sync {
    fn retention_safe(&self, resource: &str, run: &[u8; 16]) -> Option<u64>;
}

/// A consumer's retention at the job (WP-5.6b): the `retention_seconds` of the task that ships
/// `resource` from `producer`; `None` when no task does, which keeps everything.
pub trait RetentionSource: Send + Sync {
    fn retention_seconds(&self, resource: &str, producer: &[u8; 16]) -> Option<u64>;
}

/// The audit record a pass writes for each stream before it deletes anything.
pub type Audit<'a> = &'a dyn Fn(&Pruned) -> Result<(), String>;

/// A handle the garbage collection job runs.
pub trait Prunable: Send + Sync {
    /// The handle's name, `<role> <plane>/<type>` version.
    fn name(&self) -> String;
    /// What a pass at `now` would delete; deletes nothing and writes no anchor, mark or record.
    /// Opening a stream to plan may still finish what a crash left, as any open does.
    fn plan(&self, now: u64) -> Result<Vec<Pruned>, StreamError>;
    /// One bounded pass at `now`, each stream audited through `audit` before it deletes; `None`
    /// when another pass of this handle is running.
    fn run(&self, now: u64, audit: Audit<'_>) -> Result<Option<Vec<Pruned>>, StreamError>;
}

/// What keeps a handle's passes from overlapping: held for one pass.
#[derive(Debug, Default)]
pub struct Lease(AtomicBool);

/// A pass holding the lease, released when dropped.
pub struct Held<'a>(&'a Lease);

impl Lease {
    /// The lease for one pass; `None` while another holds it.
    pub fn take(&self) -> Option<Held<'_>> {
        self.0
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Held(self))
    }
}

impl Drop for Held<'_> {
    fn drop(&mut self) {
        (self.0).0.store(false, Ordering::Release);
    }
}
