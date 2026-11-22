// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Member-reported task progress as the coordinator keeps it (WP-4.4; owner decisions of
//! 2026-10-11).
//!
//! Two documents of the member store a task: the last report, its exact bytes, with the
//! coordinator's `received_at`, and the last session leased for it, from the coordinator's clock.
//!
//! A report is what the member says it did, never proof that it is reachable: the coordinator
//! keeps it verbatim, numbered per incarnation of the member, answers `{report_seq, received_at}`,
//! and shows it apart from its own
//! `last_session_at`. A report is stale once its `received_at` is older than the lease policy's
//! `max_session_seconds`, or its epoch is no longer the membership's; silence changes nothing.

use super::record::{KeptProgress, LastSession, Manifest, TaskProgress};
use super::store::Doc;
use super::{MembershipError, Store};

pub use super::files::PROGRESS as DIRECTORY;

/// What a coordinator observed of one task of a membership.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub task_id: String,
    /// The last session leased for the task, from the coordinator's own clock.
    pub last_session_at: Option<u64>,
    /// The last report, as the member sent it, and when it arrived.
    pub progress: Option<(TaskProgress, u64)>,
    /// Whether that report is stale: past its session bound, or of another epoch.
    pub stale: bool,
    /// The `zone.secrets` receipts of the task, one per resource: the tuples confirmed and the
    /// transcript digest, never a key (WP-4.7).
    pub zone_receipts: Vec<super::zone::Receipt>,
}

/// Whether a report of `epoch` received at `received_at` is stale at `now`, for a membership at
/// `current_epoch` whose sessions last `max_session_seconds` (owner decision).
pub fn stale(
    epoch: u64,
    received_at: u64,
    current_epoch: u64,
    max_session_seconds: u64,
    now: u64,
) -> bool {
    epoch != current_epoch || received_at.saturating_add(max_session_seconds) < now
}

/// A kept report, read: the report as the member sent it, and when it arrived.
fn kept_report(bytes: &[u8]) -> Result<(TaskProgress, u64), MembershipError> {
    let kept = KeptProgress::decode(bytes)?;
    Ok((TaskProgress::decode(&kept.report)?, kept.received_at))
}

impl Store {
    /// Keeps `report` with `received_at`, when its `report_seq` is above the one held from the
    /// same incarnation of the member (a restarted member numbers from anew): the write is
    /// durable before the caller answers.
    pub fn keep_progress(
        &self,
        report: &TaskProgress,
        bytes: &[u8],
        received_at: u64,
    ) -> Result<(), MembershipError> {
        let kept = KeptProgress {
            report: bytes.to_vec(),
            received_at,
        }
        .encode()?;
        // Held against the report the store keeps, in the step that keeps this one: of two
        // reports that arrive together, the lower never replaces the higher.
        self.store.change(
            &Doc::Progress {
                membership: &report.membership_id,
                task: &report.task_id,
            },
            &mut |held| {
                if let Some(held) = held.map(kept_report).transpose()?
                    && held.0.member_boot_id == report.member_boot_id
                    && report.report_seq <= held.0.report_seq
                {
                    return Err(MembershipError::OutOfOrder(format!(
                        "report {} is not above the {} held",
                        report.report_seq, held.0.report_seq
                    )));
                }
                Ok(Some(kept.clone()))
            },
        )
    }

    /// The last report kept for `task_id` of `id`, and when it arrived.
    pub fn progress(
        &self,
        id: &[u8; 16],
        task_id: &str,
    ) -> Result<Option<(TaskProgress, u64)>, MembershipError> {
        self.store
            .doc(&Doc::Progress {
                membership: id,
                task: task_id,
            })?
            .as_deref()
            .map(kept_report)
            .transpose()
    }

    /// Keeps the session just leased for `task_id` of `id`.
    pub fn keep_last_session(
        &self,
        id: &[u8; 16],
        task_id: &str,
        last: &LastSession,
    ) -> Result<(), MembershipError> {
        self.store.keep(
            &Doc::Session {
                membership: id,
                task: task_id,
            },
            &last.encode()?,
        )
    }

    /// The last session leased for `task_id` of `id`.
    pub fn last_session(
        &self,
        id: &[u8; 16],
        task_id: &str,
    ) -> Result<Option<LastSession>, MembershipError> {
        self.store
            .doc(&Doc::Session {
                membership: id,
                task: task_id,
            })?
            .map(|bytes| LastSession::decode(&bytes).map_err(MembershipError::from))
            .transpose()
    }

    /// What this coordinator observed of every task `manifest` grants, at `now`.
    pub fn observed(
        &self,
        manifest: &Manifest,
        now: u64,
    ) -> Result<Vec<Observed>, MembershipError> {
        manifest
            .tasks
            .iter()
            .map(|task| {
                let progress = self.progress(&manifest.membership_id, &task.task_id)?;
                let stale = progress.as_ref().is_some_and(|(report, received_at)| {
                    stale(
                        report.manifest_epoch,
                        *received_at,
                        manifest.epoch,
                        manifest.lease_policy.max_session_seconds,
                        now,
                    )
                });
                Ok(Observed {
                    task_id: task.task_id.clone(),
                    last_session_at: self
                        .last_session(&manifest.membership_id, &task.task_id)?
                        .map(|last| last.at),
                    progress,
                    stale,
                    zone_receipts: self.zone_receipts(&manifest.membership_id, &task.task_id)?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
