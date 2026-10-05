// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the mirrors say about this plane's readiness (P2, F-13).
//!
//! A Data Plane whose required ledgers are not mirrored and verified is in Load and decides
//! nothing. The ledgers a source requires are known only once it answers — a source follows zone
//! and ledger *patterns* — so the rule is by source (session interpretation, status.md): a
//! required source is satisfied when a round from it succeeded in this process, or when the volume
//! already holds at least one mirror matching its patterns whose last verified synchronization is
//! younger than `mirrors.expire_after`, and none matching it older. Otherwise the plane waits,
//! stalled since the first round that found it so, and the Host lists it in `load` with the reason.
//!
//! A source that is satisfied once and then lost — the coordinator down, the checkpoints ageing
//! past the bound — is reported as degraded on a plane that already serves: the phases do not go
//! back, and the decision path refuses an expired mirror on its own.

use std::path::Path;
use std::time::{Duration, SystemTime};

use permguard_core::PlaneHealth;

use super::round::Outcome;
use super::source::Source;
use crate::authz::store;

/// The requirement a source is reported under: one per server, by its URL.
pub fn requirement(source: &Source) -> String {
    format!("mirrors:{}", source.url())
}

/// Reports every source from `outcome` and what `root` holds: a required one as satisfied or
/// awaited; an optional one never awaited, but named as degraded once the plane serves without it.
pub fn report(
    health: &PlaneHealth,
    sources: &[Source],
    root: &Path,
    expire_after: Option<Duration>,
    outcome: &Outcome,
    now: SystemTime,
) {
    let held = store::mirrors(root);
    for source in sources {
        let requirement = requirement(source);
        match satisfied(source, expire_after, outcome, &held) {
            Ok(()) => health.satisfy(&requirement),
            Err(reason) if source.required() || health.phase().accepts_work() => {
                health.wait(&requirement, reason, now);
            }
            Err(_) => {}
        }
    }
}

/// Whether `source` is satisfied, or why not, in the terms an operator would fix it in.
fn satisfied(
    source: &Source,
    expire_after: Option<Duration>,
    outcome: &Outcome,
    held: &[store::Mirror],
) -> Result<(), String> {
    let this_round = outcome
        .sources
        .iter()
        .find(|reported| reported.url == source.url());
    if this_round.is_some_and(super::round::SourceOutcome::succeeded) {
        return Ok(());
    }

    // No successful round: what the volume holds decides, and only verified checkpoints count.
    let matching: Vec<&store::Mirror> = held
        .iter()
        .filter(|mirror| source.follows(&mirror.identity))
        .collect();
    let round = match this_round {
        Some(reported) if !reported.answered => "the server did not answer".to_owned(),
        Some(reported) => format!(
            "{} of its ledgers failed to mirror this round",
            reported.failed
        ),
        None => "no round has asked the server yet".to_owned(),
    };
    if matching.is_empty() {
        return Err(format!(
            "{round}, and the volume holds no mirror matching its patterns"
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
    use permguard_core::mirrors::MirrorSource;
    use permguard_core::{Health, PlaneHealth};

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

    fn source(url: &str, required: bool) -> Source {
        Source::compile(
            &MirrorSource {
                url: url.to_owned(),
                tls: permguard_core::mirrors::MirrorTls::default(),
                zones: vec!["acme".to_owned()],
                ledgers: Vec::new(),
                required,
            },
            Path::new("/var/lib/permguard"),
        )
        .expect("compiles")
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

    fn unreachable(url: &str) -> Outcome {
        Outcome {
            unreachable: 1,
            sources: vec![super::super::round::SourceOutcome {
                url: url.to_owned(),
                answered: false,
                failed: 0,
            }],
            ..Outcome::default()
        }
    }

    fn succeeded(url: &str) -> Outcome {
        Outcome {
            synchronized: 1,
            sources: vec![super::super::round::SourceOutcome {
                url: url.to_owned(),
                answered: true,
                failed: 0,
            }],
            ..Outcome::default()
        }
    }

    fn mirror(root: &Path, zone: &str, ledger: &str, synced: Option<SystemTime>) {
        let path = root.join(format!("{zone}-id")).join(format!("{ledger}-id"));
        std::fs::create_dir_all(&path).expect("the mirror directory is created");
        store::record(
            &path,
            &store::Identity {
                zone_id: format!("{zone}-id"),
                zone_name: zone.to_owned(),
                ledger_id: format!("{ledger}-id"),
                ledger_name: ledger.to_owned(),
                server: "http://cp".to_owned(),
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
            &[source("http://cp", true)],
            &root,
            Some(Duration::from_secs(600)),
            &unreachable("http://cp"),
            now,
        );
        health.lifecycle().settle("data");
        let data = health.lifecycle().component("data").expect("listed");
        assert_eq!(data.state.as_str(), "load");
        assert_eq!(data.stalled_since, Some(now));
        assert_eq!(
            data.reason.as_deref(),
            Some("the server did not answer, and the volume holds no mirror matching its patterns")
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
        mirror(&root, "acme", "main", Some(SystemTime::now()));
        let (health, plane) = plane_in_load();
        report(
            &plane,
            &[source("http://cp", true)],
            &root,
            Some(Duration::from_secs(600)),
            &unreachable("http://cp"),
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
            "acme",
            "main",
            Some(SystemTime::now() - Duration::from_secs(3600)),
        );
        let (health, plane) = plane_in_load();
        let sources = [source("http://cp", true)];
        report(
            &plane,
            &sources,
            &root,
            Some(Duration::from_secs(600)),
            &unreachable("http://cp"),
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
        report(
            &plane,
            &sources,
            &root,
            None,
            &unreachable("http://cp"),
            SystemTime::now(),
        );
        assert_eq!(health.lifecycle().phase("data"), Some(Phase::Ready));

        // A mirror this plane never verified is not a checkpoint.
        let root = scratch("down-unverified");
        mirror(&root, "acme", "main", None);
        let (health, plane) = plane_in_load();
        report(
            &plane,
            &sources,
            &root,
            None,
            &unreachable("http://cp"),
            SystemTime::now(),
        );
        health.lifecycle().settle("data");
        assert_eq!(health.lifecycle().phase("data"), Some(Phase::Load));
    }

    #[test]
    fn a_successful_round_satisfies_and_an_optional_source_never_gates() {
        let root = scratch("round");
        let (health, plane) = plane_in_load();
        let sources = [source("http://cp", true), source("http://other", false)];
        report(
            &plane,
            &sources,
            &root,
            Some(Duration::from_secs(600)),
            &Outcome {
                sources: vec![
                    super::super::round::SourceOutcome {
                        url: "http://cp".to_owned(),
                        answered: true,
                        failed: 0,
                    },
                    super::super::round::SourceOutcome {
                        url: "http://other".to_owned(),
                        answered: false,
                        failed: 0,
                    },
                ],
                ..Outcome::default()
            },
            SystemTime::now(),
        );
        health.lifecycle().settle("data");
        assert_eq!(health.lifecycle().phase("data"), Some(Phase::Ready));
        assert!(health.lifecycle().awaiting("data").is_empty());

        // A later round that loses the server degrades a serving plane; it does not go back.
        health.set_ready(true);
        report(
            &plane,
            &sources,
            &root,
            Some(Duration::from_secs(600)),
            &unreachable("http://cp"),
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
        assert_eq!(named, vec!["mirrors:http://cp", "mirrors:http://other"]);
        assert!(health.is_ready());
        assert!(
            report_succeeds_again(&health, &plane, &sources, &root),
            "the degradation clears with the next good round"
        );
    }

    #[test]
    fn an_optional_source_is_never_awaited_and_is_named_degraded_once_the_plane_serves() {
        let root = scratch("optional");
        let (health, plane) = plane_in_load();
        let sources = [source("http://other", false)];
        report(
            &plane,
            &sources,
            &root,
            None,
            &unreachable("http://other"),
            SystemTime::now(),
        );
        assert!(
            health.lifecycle().awaiting("data").is_empty(),
            "never awaited in load"
        );
        health.lifecycle().settle("data");
        health.set_ready(true);
        report(
            &plane,
            &sources,
            &root,
            None,
            &unreachable("http://other"),
            SystemTime::now(),
        );
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
            &sources,
            &root,
            None,
            &succeeded("http://other"),
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

    fn report_succeeds_again(
        health: &Health,
        plane: &PlaneHealth,
        sources: &[Source],
        root: &Path,
    ) -> bool {
        let mut both = succeeded("http://cp");
        both.sources.extend(succeeded("http://other").sources);
        report(
            plane,
            sources,
            root,
            Some(Duration::from_secs(600)),
            &both,
            SystemTime::now(),
        );
        health
            .lifecycle()
            .component("data")
            .is_some_and(|data| data.degraded.is_empty())
    }
}
