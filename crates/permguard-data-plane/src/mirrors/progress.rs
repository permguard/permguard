// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `policy.mirror` progress (WP-7.2d, `1-architecture/3-architecture-server-host-membership.md`,
//! task progress): what a member reports doing, never proof that it is reachable.
//!
//! After every round, each followed task whose session opened reports one bounded snapshot on
//! it: one resource per mirror of the task.
//!
//! | Member              | Value                                                          |
//! | ------------------- | -------------------------------------------------------------- |
//! | `resource`          | the ledger as an authorization resource under the task's plane |
//! | `state`             | `unverified`, `blocked`, `stale`, `tombstoned` or `verified`   |
//! | `frontier`          | the counter of the verified head                               |
//! | `checkpoint_digest` | the verified head                                              |
//! | `verified_at`       | when this plane verified it, unix seconds                      |
//! | `reason`            | why it is not `verified`                                       |
//!
//! More mirrors than a report carries report the most urgent: unverified and blocked first, then
//! stale, then tombstoned, then the oldest verification.

use std::path::Path;
use std::time::Duration;

use permguard_host::composition::MirrorTask;
use permguard_host::membership::record::{MAX_PROGRESS_RESOURCES, ProgressResource};
use tracing::warn;

use super::layout;

const COMPONENT: &str = "data-plane";

/// The progress states, most urgent first.
pub const UNVERIFIED: &str = "unverified";
pub const BLOCKED: &str = "blocked";
pub const STALE: &str = "stale";
pub const TOMBSTONED: &str = "tombstoned";
pub const VERIFIED: &str = "verified";

fn urgency(state: &str) -> u8 {
    match state {
        UNVERIFIED => 0,
        BLOCKED => 1,
        STALE => 2,
        TOMBSTONED => 3,
        _ => 4,
    }
}

/// The snapshot `task` reports: one resource per mirror of it under `root`, the most urgent first
/// and no more than a report carries.
pub fn resources(
    root: &Path,
    task: &MirrorTask,
    stale_after: Option<Duration>,
) -> Vec<ProgressResource> {
    let authority = layout::authority_name(&task.coordinator);
    let label = super::round::task_label(task);
    // The ledgers as the coordinator's plane names them, under the resource the task covers.
    let plane = permguard_core::authz::Resource::parse(&task.resource)
        .ok()
        .and_then(|resource| resource.plane_id().map(ToOwned::to_owned))
        .unwrap_or_else(|| "control".to_owned());
    let Ok(held) = layout::on_disk(root) else {
        return Vec::new();
    };
    let mut resources: Vec<ProgressResource> = held
        .into_iter()
        .filter(|mirror| mirror.authority.as_deref() == Some(authority.as_str()))
        .filter_map(|mirror| {
            let path = mirror.path(root);
            let identity = crate::authz::store::identity_of(&path)?;
            (identity.task.as_deref() == Some(label.as_str()))
                .then(|| one(&path, &mirror, &plane, stale_after))
        })
        .collect();
    resources.sort_by(|left, right| {
        (urgency(&left.state), left.verified_at, &left.resource).cmp(&(
            urgency(&right.state),
            right.verified_at,
            &right.resource,
        ))
    });
    resources.truncate(MAX_PROGRESS_RESOURCES);
    resources
}

/// One mirror's progress.
fn one(
    path: &Path,
    mirror: &layout::Mirror,
    plane: &str,
    stale_after: Option<Duration>,
) -> ProgressResource {
    let resource =
        permguard_core::authz::Resource::ledger(plane, &mirror.zone_id, &mirror.ledger_id)
            .to_string();
    // Read only: an abandoned switch may still be appending, and a reader must not cut it.
    let state = match super::state::peek(path) {
        Ok(Some(state)) => state,
        Ok(None) => {
            return ProgressResource {
                resource,
                state: UNVERIFIED.to_owned(),
                frontier: None,
                checkpoint_digest: None,
                verified_at: None,
                reason: Some("no verified state yet".to_owned()),
            };
        }
        Err(error) => {
            return ProgressResource {
                resource,
                state: UNVERIFIED.to_owned(),
                frontier: None,
                checkpoint_digest: None,
                verified_at: None,
                reason: Some(error),
            };
        }
    };
    let head = state.head.to_string();
    let (state_name, reason) = if let Some(block) =
        crate::authz::block::read(path).filter(|block| block.commit == head)
    {
        (BLOCKED, Some(block.reason))
    } else if let (Some(bound), Some(age)) = (stale_after, crate::authz::store::synced_age(path))
        && age >= bound
    {
        (
            STALE,
            Some(format!(
                "last verified {}s ago, past the bound of {}s",
                age.as_secs(),
                bound.as_secs()
            )),
        )
    } else if matches!(super::tombstone::read(path), Ok(Some(_))) {
        (
            TOMBSTONED,
            Some("its task no longer lists it: a reap candidate".to_owned()),
        )
    } else {
        (VERIFIED, None)
    };
    ProgressResource {
        resource,
        state: state_name.to_owned(),
        frontier: Some(state.counter.to_string()),
        checkpoint_digest: Some(state.head),
        verified_at: Some(state.verified_at),
        reason,
    }
}

/// Reports every task's snapshot on its session, within `deadline`; a report that fails is
/// logged, and the next round reports again.
pub async fn report(
    root: &Path,
    sessions: &[(MirrorTask, super::task::Shared)],
    stale_after: Option<Duration>,
    deadline: Duration,
) {
    for (task, session) in sessions {
        let resources = resources(root, task, stale_after);
        let sent = tokio::time::timeout(deadline, async {
            session.lock().await.report(resources).await
        })
        .await;
        let failure = match sent {
            Ok(Ok(())) => continue,
            Ok(Err(refusal)) => refusal.to_string(),
            Err(_) => "the report ran out of the round's deadline".to_owned(),
        };
        warn!(
            event.name = "sync.progress_failed",
            component = COMPONENT,
            task = task.task_id.as_str(),
            error = failure.as_str(),
            "the task's progress could not be reported: the next round reports it again"
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_objects::digest::Digest;

    use super::*;
    use crate::authz::store::{Identity, record};
    use crate::mirrors::state::{MirrorState, commit};
    use crate::mirrors::tombstone::{Tombstone, write};

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-mirror-progress-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory");
        dir
    }

    fn task() -> MirrorTask {
        MirrorTask {
            membership_id: [1; 16],
            task_id: "mirror".into(),
            coordinator: [0x11; 16],
            revision: 2,
            resource: "plane/control".into(),
            required: true,
            max_body_bytes: 1 << 20,
        }
    }

    /// A mirror of `ledger` under `coordinator`, listed by `label`, verified at `verified_at` when
    /// given; its path.
    fn mirror(
        root: &Path,
        coordinator: [u8; 16],
        label: &str,
        ledger: &str,
        verified_at: Option<u64>,
    ) -> std::path::PathBuf {
        let authority = layout::authority_name(&coordinator);
        let path = root.join(&authority).join("zone").join(ledger);
        std::fs::create_dir_all(&path).expect("the mirror");
        record(
            &path,
            &Identity {
                zone_id: "zone".into(),
                zone_name: "acme".into(),
                ledger_id: ledger.into(),
                ledger_name: ledger.into(),
                server: format!("host:{authority}"),
                authority: Some(authority),
                task: Some(label.into()),
            },
        )
        .expect("the identity");
        if let Some(verified_at) = verified_at {
            commit(
                &path,
                &MirrorState {
                    revision: 2,
                    authority: coordinator,
                    zone: "zone".into(),
                    ledger: ledger.into(),
                    reference: "main".into(),
                    head: Digest::compute(ledger.as_bytes()),
                    counter: 7,
                    ref_digest: Digest::compute(b"ref"),
                    ring_epoch: 1,
                    key_set_digest: [3; 32],
                    verified_at,
                    closure_digest: Digest::compute(b"closure"),
                    verified: b"statement".to_vec(),
                    ring_binding: b"binding".to_vec(),
                },
            )
            .expect("switched");
            crate::authz::store::touch_synced(&path);
        }
        path
    }

    /// WP-7.2d: a task reports each of its own mirrors, under its coordinator only, in its state —
    /// unverified, blocked, stale, tombstoned, verified — the most urgent first, the oldest
    /// verification first within a state.
    #[test]
    fn a_task_reports_each_of_its_mirrors_most_urgent_first() {
        let root = scratch("states");
        let label = super::super::round::task_label(&task());
        mirror(&root, [0x11; 16], &label, "verified-new", Some(200));
        mirror(&root, [0x11; 16], &label, "verified-old", Some(100));
        mirror(&root, [0x11; 16], &label, "unverified", None);
        let blocked = mirror(&root, [0x11; 16], &label, "blocked", Some(300));
        crate::authz::block::write(
            &blocked,
            &Digest::compute(b"blocked").to_string(),
            "this engine may not serve it",
        );
        let tombstoned = mirror(&root, [0x11; 16], &label, "tombstoned", Some(400));
        write(
            &tombstoned,
            &Tombstone {
                first_absent_at: 1,
                task: label.clone(),
                revision: 2,
            },
        )
        .expect("a candidate");
        // Not this task's: another task of the coordinator, and this label under another one.
        mirror(&root, [0x11; 16], "another/task", "other-task", Some(1));
        mirror(&root, [0x22; 16], &label, "other-authority", Some(1));

        let reported = resources(&root, &task(), None);
        let states: Vec<(&str, &str)> = reported
            .iter()
            .map(|resource| (resource.resource.as_str(), resource.state.as_str()))
            .collect();
        assert_eq!(
            states,
            vec![
                ("plane/control/zone/zone/ledger/unverified", UNVERIFIED),
                ("plane/control/zone/zone/ledger/blocked", BLOCKED),
                ("plane/control/zone/zone/ledger/tombstoned", TOMBSTONED),
                ("plane/control/zone/zone/ledger/verified-old", VERIFIED),
                ("plane/control/zone/zone/ledger/verified-new", VERIFIED),
            ]
        );
        let blocked = &reported[1];
        assert_eq!(
            blocked.reason.as_deref(),
            Some("this engine may not serve it")
        );
        let verified = &reported[3];
        assert_eq!(verified.frontier.as_deref(), Some("7"));
        assert_eq!(
            verified.checkpoint_digest,
            Some(Digest::compute(b"verified-old"))
        );
        assert_eq!(verified.verified_at, Some(100));
        assert_eq!(verified.reason, None);
        assert_eq!(reported[0].frontier, None, "nothing verified");

        // Past the staleness bound, a verified mirror is stale, and says how old.
        let aged = root
            .join(layout::authority_name(&[0x11; 16]))
            .join("zone")
            .join("verified-new")
            .join(crate::authz::store::SYNCED_FILE);
        std::fs::File::options()
            .write(true)
            .open(&aged)
            .expect("the marker")
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(120))
            .expect("aged");
        let reported = resources(&root, &task(), Some(Duration::from_secs(60)));
        let stale: Vec<&ProgressResource> = reported
            .iter()
            .filter(|resource| resource.state == STALE)
            .collect();
        assert_eq!(stale.len(), 1, "{reported:?}");
        assert_eq!(
            stale[0].resource,
            "plane/control/zone/zone/ledger/verified-new"
        );
        assert!(
            stale[0]
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("past the bound of 60s")),
            "{stale:?}"
        );
        assert_eq!(
            reported.iter().position(|resource| resource.state == STALE),
            Some(2),
            "stale after unverified and blocked"
        );
    }

    /// WP-7.2d: a report carries no more than its bound, the most urgent kept.
    #[test]
    fn a_report_carries_no_more_than_its_bound_and_keeps_the_most_urgent() {
        let root = scratch("bound");
        let label = super::super::round::task_label(&task());
        for at in 0..MAX_PROGRESS_RESOURCES {
            mirror(
                &root,
                [0x11; 16],
                &label,
                &format!("verified-{at:03}"),
                Some(1000 + at as u64),
            );
        }
        mirror(&root, [0x11; 16], &label, "unverified", None);
        let reported = resources(&root, &task(), None);
        assert_eq!(reported.len(), MAX_PROGRESS_RESOURCES);
        assert_eq!(reported[0].state, UNVERIFIED);
        assert!(
            reported.iter().all(|resource| resource.resource
                != format!(
                    "plane/control/zone/zone/ledger/verified-{:03}",
                    MAX_PROGRESS_RESOURCES - 1
                )),
            "the most recent verification is the one left out"
        );
    }
}
