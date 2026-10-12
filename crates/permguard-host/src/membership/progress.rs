// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Member-reported task progress as the coordinator keeps it (WP-4.4; owner decisions of
//! 2026-10-11).
//!
//! ```text
//! host/members/progress/<membership_id>/
//! ├── <task_id>.cbor       the last report, its exact bytes, with the coordinator's received_at
//! └── <task_id>.session    the last session leased for the task, from the coordinator's clock
//! ```
//!
//! A report is what the member says it did, never proof that it is reachable: the coordinator
//! keeps it verbatim, numbered per incarnation of the member, answers `{report_seq, received_at}`,
//! and shows it apart from its own
//! `last_session_at`. A report is stale once its `received_at` is older than the lease policy's
//! `max_session_seconds`, or its epoch is no longer the membership's; silence changes nothing.

use super::record::{KeptProgress, LastSession, Manifest, TaskProgress};
use super::{MembershipError, Store, hex};
use crate::storage::format;
use crate::storage::write::{read_view, replace_view};

/// The directory below `host/members/`.
pub const DIRECTORY: &str = "progress";

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

impl Store {
    /// The directory of `id`'s progress; `None` when nothing was ever kept, created when `create`.
    pub(super) fn progress_dir(
        &self,
        id: &[u8; 16],
        create: bool,
    ) -> Result<Option<crate::storage::dir::Dir>, MembershipError> {
        if !create && !self.dir.subdirs()?.iter().any(|name| name == DIRECTORY) {
            return Ok(None);
        }
        let progress = self.dir.subdir(DIRECTORY, create)?;
        if !create && !progress.subdirs()?.contains(&hex(id)) {
            return Ok(None);
        }
        Ok(Some(progress.subdir(&hex(id), create)?))
    }

    /// Keeps `report` with `received_at`, when its `report_seq` is above the one held from the
    /// same incarnation of the member (a restarted member numbers from anew): the write is
    /// durable before the caller answers.
    pub fn keep_progress(
        &self,
        report: &TaskProgress,
        bytes: &[u8],
        received_at: u64,
    ) -> Result<(), MembershipError> {
        let _keeping = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((held, _)) = self.progress(&report.membership_id, &report.task_id)?
            && held.member_boot_id == report.member_boot_id
            && report.report_seq <= held.report_seq
        {
            return Err(MembershipError::OutOfOrder(format!(
                "report {} is not above the {} held",
                report.report_seq, held.report_seq
            )));
        }
        let kept = KeptProgress {
            report: bytes.to_vec(),
            received_at,
        }
        .encode()?;
        let dir = self
            .progress_dir(&report.membership_id, true)?
            .ok_or_else(|| MembershipError::Storage("the progress directory".to_owned()))?;
        replace_view(
            &dir,
            &format!("{}.cbor", report.task_id),
            format::VIEW,
            &kept,
        )?;
        Ok(())
    }

    /// The last report kept for `task_id` of `id`, and when it arrived.
    pub fn progress(
        &self,
        id: &[u8; 16],
        task_id: &str,
    ) -> Result<Option<(TaskProgress, u64)>, MembershipError> {
        let Some(dir) = self.progress_dir(id, false)? else {
            return Ok(None);
        };
        let Some(bytes) = read_view(&dir, &format!("{task_id}.cbor"), format::VIEW)? else {
            return Ok(None);
        };
        let kept = KeptProgress::decode(&bytes)?;
        Ok(Some((
            TaskProgress::decode(&kept.report)?,
            kept.received_at,
        )))
    }

    /// Keeps the session just leased for `task_id` of `id`.
    pub fn keep_last_session(
        &self,
        id: &[u8; 16],
        task_id: &str,
        last: &LastSession,
    ) -> Result<(), MembershipError> {
        let dir = self
            .progress_dir(id, true)?
            .ok_or_else(|| MembershipError::Storage("the progress directory".to_owned()))?;
        replace_view(
            &dir,
            &format!("{task_id}.session"),
            format::VIEW,
            &last.encode()?,
        )?;
        Ok(())
    }

    /// The last session leased for `task_id` of `id`.
    pub fn last_session(
        &self,
        id: &[u8; 16],
        task_id: &str,
    ) -> Result<Option<LastSession>, MembershipError> {
        let Some(dir) = self.progress_dir(id, false)? else {
            return Ok(None);
        };
        read_view(&dir, &format!("{task_id}.session"), format::VIEW)?
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
