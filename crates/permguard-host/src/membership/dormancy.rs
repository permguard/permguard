// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Dormancy and expiry (WP-4.6; owner decisions of 2026-10-12).
//!
//! ```text
//! last successful session + dormant_after  ─▶ suspended  no task session; `host.membership.dormant`
//! last successful session + revoke_after   ─▶ revoked    terminal; `host.membership.revoked`
//! ```
//!
//! The clock is the coordinator's: a session is a lease it issued for any task of the membership
//! (`last_session_at`, WP-4.4), and the clock starts at the later of the last one and the
//! membership's last entry into `active`, its approval or a resume, so a resume restarts it. A
//! member's claim never moves it. Revocation is unconditional: a membership suspended by an
//! operator or a clone alarm, or held for review, is revoked too; a held one is not suspended, the
//! hold already refusing its sessions.
//!
//! Time is [`TimeGuard::now`](crate::time::TimeGuard::now): carried forward by monotonic time and
//! never earlier than the highest wall time the volume keeps, so a clock set back never shortens a
//! dormancy. A lease asked past the threshold is refused before the pass suspends, so the pass's
//! cadence opens no window.

use super::record::{Role, Status};
use super::service::Coordinating;
use super::{AUDIT_DORMANT, AUDIT_REVOKED, DORMANT, MembershipError, REVOKE_DORMANT, Store};
use crate::operations::journal::Initiator;

/// The initiator of dormancy's transitions, naming their reason.
pub const INITIATOR: &str = "dormancy";

/// What a membership's dormancy calls for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Due {
    /// Silent past `dormant_after`, active and not held: suspended.
    Suspend,
    /// Silent past `revoke_after`, active, suspended or held: revoked.
    Revoke,
}

impl Due {
    /// The status it moves the membership to.
    pub fn status(self) -> Status {
        match self {
            Self::Suspend => Status::Suspended,
            Self::Revoke => Status::Revoked,
        }
    }
}

impl Store {
    /// Where the dormancy clock of `id` starts: the later of the last lease this coordinator
    /// issued for any of its tasks and its last entry into `active`. None for a membership this
    /// Host does not coordinate or that was never active.
    pub fn dormant_since(&self, id: &[u8; 16]) -> Result<Option<u64>, MembershipError> {
        let Some(held) = self.membership(id) else {
            return Ok(None);
        };
        let (Role::Coordinator, Some((manifest, ..))) = (held.role, &held.manifest) else {
            return Ok(None);
        };
        let Some(mut since) = self.active_since(id) else {
            return Ok(None);
        };
        for task in &manifest.tasks {
            if let Some(last) = self.last_session(id, &task.task_id)? {
                since = since.max(last.at);
            }
        }
        Ok(Some(since))
    }

    /// What the dormancy of `id` calls for at `now`, under the thresholds its manifest signs.
    pub fn dormancy(&self, id: &[u8; 16], now: u64) -> Result<Option<Due>, MembershipError> {
        let Some(held) = self.membership(id) else {
            return Ok(None);
        };
        let Some((manifest, ..)) = &held.manifest else {
            return Ok(None);
        };
        if held.role != Role::Coordinator
            || !matches!(held.status, Status::Active | Status::Suspended)
        {
            return Ok(None);
        }
        let Some(since) = self.dormant_since(id)? else {
            return Ok(None);
        };
        let silent = now.saturating_sub(since);
        let policy = &manifest.lease_policy;
        Ok(if silent >= policy.revoke_after_seconds {
            Some(Due::Revoke)
        } else if silent >= policy.dormant_after_seconds
            && held.status == Status::Active
            && held.held_epoch.is_none()
        {
            Some(Due::Suspend)
        } else {
            None
        })
    }
}

impl Coordinating {
    /// Suspends every membership this Host coordinates silent past its `dormant_after` and revokes
    /// every one silent past its `revoke_after`, each its own mutation: the server's periodic
    /// pass. Answers how many it moved; one that fails is logged and tried again at the next pass.
    pub fn dormancy_due(&self) -> usize {
        let mut moved = 0;
        for (id, _) in self.store.memberships() {
            match self.dormancy_of(&id) {
                Ok(true) => moved += 1,
                Ok(false) => {}
                Err(error) => tracing::warn!(
                    event.name = "host.membership.dormancy_failed",
                    component = "host",
                    membership = %crate::identity::record::uuid_text(&id),
                    error = %error,
                    "a dormant membership could not be moved; the next pass tries again"
                ),
            }
        }
        moved
    }

    /// Applies what the dormancy of `id` calls for now; answers whether it moved it.
    pub fn dormancy_of(&self, id: &[u8; 16]) -> Result<bool, MembershipError> {
        let now = self.time.now_secs();
        let Some(due) = self.store.dormancy(id, now)? else {
            return Ok(false);
        };
        let coordinator = self.coordinator();
        let next = self
            .store
            .check_successor(&coordinator, id, due.status(), None, now)?;
        let (operation, action) = match due {
            Due::Suspend => (DORMANT, AUDIT_DORMANT),
            Due::Revoke => (REVOKE_DORMANT, AUDIT_REVOKED),
        };
        self.change(
            operation,
            action,
            Initiator::System(INITIATOR.to_owned()),
            id,
            |applying| {
                self.store
                    .transition(applying, &coordinator, &next, now)
                    .map(|_| ())
            },
        )?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests;
