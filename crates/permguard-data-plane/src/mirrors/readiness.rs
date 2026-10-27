// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the mirrors say about this plane's readiness (P2, F-13).
//!
//! A Data Plane whose required ledgers are not mirrored and verified is in Load and decides
//! nothing. The ledgers a coordinator's tasks cover are known only once it answers, so the rule is
//! by coordinator (session interpretation, status.md): a coordinator one of whose `policy.mirror`
//! tasks is required — the local task of a process hosting both Planes always is (WP-7.7) — is
//! satisfied when a round from it succeeded in this process, or when the volume already holds at
//! least one mirror under its authority whose last verified synchronization is younger than
//! `mirrors.expire_after`, and none under it older. Otherwise the plane waits, stalled since the
//! first round that found it so, and the Host lists it in `load` with the reason.
//!
//! A coordinator that is satisfied once and then lost — down, its checkpoints ageing past the
//! bound — is reported as degraded on a plane that already serves: the phases do not go back, and
//! the decision path refuses an expired mirror on its own.

use std::path::Path;
use std::time::{Duration, SystemTime};

use permguard_core::PlaneHealth;

use super::round::Outcome;
use crate::authz::store;

/// Reports every coordinator from `outcome` and what `root` holds: a required one as satisfied or
/// awaited; an optional one never awaited, but named as degraded once the plane serves without it.
pub fn report(
    health: &PlaneHealth,
    root: &Path,
    expire_after: Option<Duration>,
    outcome: &Outcome,
    now: SystemTime,
) {
    let held = store::mirrors(root);
    // The coordinators of this Host's `policy.mirror` tasks (WP-7.2a): required when one of
    // their signed tasks is, their mirrors the ones under their authority.
    for (key, required) in &outcome.coordinators {
        let requirement = format!("mirrors:{key}");
        let authority = key.strip_prefix("host:").unwrap_or(key);
        match satisfied(
            key,
            |identity| identity.authority.as_deref() == Some(authority),
            expire_after,
            outcome,
            &held,
        ) {
            Ok(()) => health.satisfy(&requirement),
            Err(reason) if *required || health.phase().accepts_work() => {
                health.wait(&requirement, reason, now);
            }
            Err(_) => {}
        }
    }
}

/// Whether the coordinator `key` is satisfied, or why not, in the terms an operator would fix it
/// in.
fn satisfied(
    key: &str,
    follows: impl Fn(&store::Identity) -> bool,
    expire_after: Option<Duration>,
    outcome: &Outcome,
    held: &[store::Mirror],
) -> Result<(), String> {
    let this_round = outcome.sources.iter().find(|reported| reported.url == key);
    if this_round.is_some_and(super::round::SourceOutcome::succeeded) {
        return Ok(());
    }

    // No successful round: what the volume holds decides, and only verified checkpoints count.
    let matching: Vec<&store::Mirror> = held
        .iter()
        .filter(|mirror| follows(&mirror.identity))
        .collect();
    let round = match this_round {
        Some(reported) if !reported.answered => "the coordinator did not answer".to_owned(),
        Some(reported) => format!(
            "{} of its ledgers failed to mirror this round",
            reported.failed
        ),
        None => "no round has asked the coordinator yet".to_owned(),
    };
    if matching.is_empty() {
        return Err(format!(
            "{round}, and the volume holds no mirror under its authority"
        ));
    }
    let mut fresh = 0;
    for mirror in &matching {
        match store::synced_age(&mirror.path) {
            None => {
                return Err(format!(
                    "{round}, and the mirror {} was never verified by this plane",
                    mirror.log_id()
                ));
            }
            Some(age) if expire_after.is_some_and(|bound| age >= bound) => {
                return Err(format!(
                    "{round}, and the mirror {} was last verified {}s ago, past `mirrors.expire_after`",
                    mirror.log_id(),
                    age.as_secs()
                ));
            }
            Some(_) => fresh += 1,
        }
    }
    debug_assert_eq!(fresh, matching.len());

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::lifecycle::{Kind, Phase};
    use permguard_core::{Health, PlaneHealth};

    const CP: &str = "11111111111111111111111111111111";
    const OTHER: &str = "22222222222222222222222222222222";

    fn key(authority: &str) -> String {
        format!("host:{authority}")
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pg-mirror-readiness-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("the scratch directory is created");
        dir
    }

    fn plane_in_load() -> (Health, PlaneHealth) {
        let health = Health::new();
        health
            .lifecycle()
            .enter("data", Kind::Plane, true, Phase::Load);
        health
            .lifecycle()
            .advance(permguard_core::lifecycle::HOST, Phase::Ready);
        (health.clone(), PlaneHealth::new(health, "data"))
    }

    /// A round in which each `(authority, required, answered)` coordinator answered or not.
    fn round(coordinators: &[(&str, bool, bool)]) -> Outcome {
        Outcome {
            unreachable: coordinators.iter().filter(|(_, _, up)| !up).count(),
            sources: coordinators
                .iter()
                .map(
                    |(authority, _, answered)| super::super::round::SourceOutcome {
                        url: key(authority),
                        answered: *answered,
                        failed: 0,
                    },
                )
                .collect(),
            coordinators: coordinators
                .iter()
                .map(|(authority, required, _)| (key(authority), *required))
                .collect(),
            ..Outcome::default()
        }
    }

    fn mirror(root: &Path, authority: &str, zone: &str, synced: Option<SystemTime>) {
        let path = root
            .join(authority)
            .join(format!("{zone}-id"))
            .join("main-id");
        std::fs::create_dir_all(&path).expect("the mirror directory is created");
        store::record(
            &path,
            &store::Identity {
                task: Some("00000000-0000-0000-0000-000000000000/local".to_owned()),
                authority: Some(authority.to_owned()),
                zone_id: format!("{zone}-id"),
                zone_name: zone.to_owned(),
                ledger_id: "main-id".to_owned(),
                ledger_name: "main".to_owned(),
                server: key(authority),
            },
        )
        .expect("the identity is written");
        if let Some(when) = synced {
            store::touch_synced(&path);
            let synced = std::fs::File::options()
                .write(true)
                .open(path.join(store::SYNCED_FILE))
                .expect("the marker opens");
            synced.set_modified(when).expect("the marker is dated");
        }
    }

    #[test]
    fn f13_the_coordinator_down_and_no_checkpoint_keeps_the_plane_in_load() {
        let root = scratch("down-empty");
        let (health, plane) = plane_in_load();
        let now = SystemTime::now();
        report(
            &plane,
            &root,
            Some(Duration::from_secs(600)),
            &round(&[(CP, true, false)]),
            now,
        );
        health.lifecycle().settle("data");
        let data = health.lifecycle().component("data").expect("listed");
        assert_eq!(data.state.as_str(), "load");
        assert_eq!(data.stalled_since, Some(now));
        assert_eq!(
            data.reason.as_deref(),
            Some(
                "the coordinator did not answer, and the volume holds no mirror under its authority"
            )
        );
        assert!(!health.is_ready(), "a required plane in load is not ready");
        assert!(
            health.is_live(),
            "a remote dependency never touches liveness"
        );
    }

    #[test]
    fn f13_the_coordinator_down_with_a_fresh_checkpoint_is_ready() {
        let root = scratch("down-fresh");
        mirror(&root, CP, "acme", Some(SystemTime::now()));
        let (health, plane) = plane_in_load();
        report(
            &plane,
            &root,
            Some(Duration::from_secs(600)),
            &round(&[(CP, true, false)]),
            SystemTime::now(),
        );
        health.lifecycle().settle("data");
        assert_eq!(health.lifecycle().phase("data"), Some(Phase::Ready));
        assert!(health.is_ready());
    }

    #[test]
    fn a_checkpoint_past_expire_after_does_not_satisfy_and_an_unverified_mirror_never_does() {
        let root = scratch("down-stale");
        mirror(
            &root,
            CP,
            "acme",
            Some(SystemTime::now() - Duration::from_secs(3600)),
        );
        let (health, plane) = plane_in_load();
        let down = round(&[(CP, true, false)]);
        report(
            &plane,
            &root,
            Some(Duration::from_secs(600)),
            &down,
            SystemTime::now(),
        );
        health.lifecycle().settle("data");
        let data = health.lifecycle().component("data").expect("listed");
        assert_eq!(data.state.as_str(), "load");
        assert!(
            data.reason
                .as_deref()
                .is_some_and(|reason| reason.contains("past `mirrors.expire_after`")),
            "{:?}",
            data.reason
        );

        // Without a bound the same checkpoint counts, however old.
        report(&plane, &root, None, &down, SystemTime::now());
        assert_eq!(health.lifecycle().phase("data"), Some(Phase::Ready));

        // A mirror this plane never verified is not a checkpoint.
        let root = scratch("down-unverified");
        mirror(&root, CP, "acme", None);
        let (health, plane) = plane_in_load();
        report(&plane, &root, None, &down, SystemTime::now());
        health.lifecycle().settle("data");
        assert_eq!(health.lifecycle().phase("data"), Some(Phase::Load));
    }

    #[test]
    fn a_successful_round_satisfies_and_an_optional_coordinator_never_gates() {
        let root = scratch("round");
        let (health, plane) = plane_in_load();
        report(
            &plane,
            &root,
            Some(Duration::from_secs(600)),
            &round(&[(CP, true, true), (OTHER, false, false)]),
            SystemTime::now(),
        );
        health.lifecycle().settle("data");
        assert_eq!(health.lifecycle().phase("data"), Some(Phase::Ready));
        assert!(health.lifecycle().awaiting("data").is_empty());

        // A later round that loses both degrades a serving plane; it does not go back.
        health.set_ready(true);
        report(
            &plane,
            &root,
            Some(Duration::from_secs(600)),
            &round(&[(CP, true, false), (OTHER, false, false)]),
            SystemTime::now(),
        );
        let data = health.lifecycle().component("data").expect("listed");
        assert_eq!(data.state.as_str(), "serving");
        // Both are named: the required one, and the optional one no round reached either.
        let named: Vec<&str> = data
            .degraded
            .iter()
            .map(|degraded| degraded.capability.as_str())
            .collect();
        assert_eq!(
            named,
            vec![
                format!("mirrors:{}", key(CP)),
                format!("mirrors:{}", key(OTHER))
            ]
        );
        assert!(health.is_ready());
        // The degradation clears with the next good round.
        report(
            &plane,
            &root,
            Some(Duration::from_secs(600)),
            &round(&[(CP, true, true), (OTHER, false, true)]),
            SystemTime::now(),
        );
        assert!(
            health
                .lifecycle()
                .component("data")
                .is_some_and(|data| data.degraded.is_empty())
        );
    }

    #[test]
    fn an_optional_coordinator_is_never_awaited_and_is_named_degraded_once_the_plane_serves() {
        let root = scratch("optional");
        let (health, plane) = plane_in_load();
        let down = round(&[(OTHER, false, false)]);
        report(&plane, &root, None, &down, SystemTime::now());
        assert!(
            health.lifecycle().awaiting("data").is_empty(),
            "never awaited in load"
        );
        health.lifecycle().settle("data");
        health.set_ready(true);
        report(&plane, &root, None, &down, SystemTime::now());
        let data = health.lifecycle().component("data").expect("listed");
        assert_eq!(data.state.as_str(), "serving");
        assert_eq!(
            data.degraded.len(),
            1,
            "named once the plane serves without it"
        );
        assert!(health.is_ready());
        report(
            &plane,
            &root,
            None,
            &round(&[(OTHER, false, true)]),
            SystemTime::now(),
        );
        assert!(
            health
                .lifecycle()
                .component("data")
                .expect("listed")
                .degraded
                .is_empty()
        );
    }

    /// WP-7.2a: a fresh mirror under the coordinator's authority satisfies it while it is down;
    /// one under another authority does not.
    #[test]
    fn only_a_mirror_under_its_own_authority_satisfies_a_coordinator() {
        let root = scratch("task-fresh");
        mirror(&root, CP, "acme", Some(SystemTime::now()));
        mirror(&root, OTHER, "other", Some(SystemTime::now()));
        let (health, plane) = plane_in_load();
        report(
            &plane,
            &root,
            Some(Duration::from_secs(600)),
            &round(&[(CP, true, false)]),
            SystemTime::now(),
        );
        health.lifecycle().settle("data");
        assert_ne!(
            health
                .lifecycle()
                .component("data")
                .expect("listed")
                .state
                .as_str(),
            "load",
            "its own fresh mirror satisfies it"
        );

        let elsewhere = scratch("task-elsewhere");
        mirror(&elsewhere, OTHER, "acme", Some(SystemTime::now()));
        let (health, plane) = plane_in_load();
        report(
            &plane,
            &elsewhere,
            Some(Duration::from_secs(600)),
            &round(&[(CP, true, false)]),
            SystemTime::now(),
        );
        health.lifecycle().settle("data");
        assert_eq!(
            health
                .lifecycle()
                .component("data")
                .expect("listed")
                .state
                .as_str(),
            "load",
            "another coordinator's mirror is not this one's"
        );
    }
}
