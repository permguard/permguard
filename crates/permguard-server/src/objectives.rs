// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The readiness monitor of the declared service objectives (TS-5): readiness becomes false before
//! a safety margin is exhausted, not after the objective has been violated.
//!
//! | Objective               | Measured as                                                    | Held when                       |
//! | ----------------------- | -------------------------------------------------------------- | ------------------------------- |
//! | `mirror_staleness`      | `permguard_sync_mirror_age_seconds`, the stalest mirror        | past four fifths of it          |
//! | `spool_headroom`        | `permguard_decisions_spool_bytes` against the spool's capacity | less free than the headroom     |
//! | `checkpoint_export_lag` | the Host degraded on `audit_egress`                            | while it is                     |
//! | `backup_interval`       | the newest finalized backup, or the volume's creation          | past four fifths of it          |
//! | the qualification       | the qualified record's `expires_at`, from `production`         | once it has passed              |
//!
//! A hold names its objective and is released by the first pass that measures it within its
//! margin. The other objectives are validated at Bootstrap against the bounds that act on them
//! ([`permguard_core::objectives`]): what a subsystem enforces itself is not measured twice. The
//! hold's reason is a sentence of numbers; the objective is the only label, so the telemetry it
//! reaches stays bounded.

use std::sync::Arc;
use std::time::Duration;

use permguard_core::objectives::{Objectives, within_margin};

/// What a stale qualification holds readiness under, beside the objectives.
pub const STORAGE_QUALIFICATION: &str = "storage_qualification";

/// How often the measures are read.
pub const PASS: Duration = Duration::from_secs(15);

/// What one pass measured; `None` where nothing measured it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Measures {
    /// Seconds since the stalest mirror last synchronized.
    pub mirror_age: Option<f64>,
    /// Bytes the decision spool holds, and the most it may hold.
    pub spool: Option<(f64, u64)>,
    /// Whether the Host is degraded on its audit checkpoints' egress.
    pub audit_egress_degraded: bool,
    /// How long since the newest finalized backup, or since the volume was created without one.
    pub since_backup: Option<Duration>,
    /// When the volume's qualification record expired, once it has: from `production` the volume
    /// is then out of Ready like an unqualified one (TS-5).
    pub qualification_expired_at: Option<i64>,
}

/// Each monitored objective, with the reason to hold readiness for it, or `None` to release it.
pub fn judge(objectives: &Objectives, measures: &Measures) -> Vec<(&'static str, Option<String>)> {
    let mut judged = vec![(
        STORAGE_QUALIFICATION,
        measures.qualification_expired_at.map(|at| {
            format!(
                "{}: the volume's qualification record expired at {}: renew its evidence",
                permguard_core::codes::storage::QUALIFICATION_STALE,
                permguard_core::time::to_rfc3339(at)
            )
        }),
    )];
    if let Some(objective) = objectives.mirror_staleness {
        let margin = within_margin(objective);
        judged.push((
            "mirror_staleness",
            measures
                .mirror_age
                .filter(|age| *age > margin.as_secs_f64())
                .map(|age| {
                    format!(
                        "the stalest mirror is {age:.0}s old, past {}s, four fifths of the \
                         {}s objective",
                        margin.as_secs(),
                        objective.as_secs()
                    )
                }),
        ));
    }
    if let Some(headroom) = objectives.spool_headroom {
        judged.push((
            "spool_headroom",
            measures.spool.and_then(|(held, capacity)| {
                if capacity == 0 {
                    return None;
                }
                #[allow(clippy::cast_precision_loss)]
                let capacity = capacity as f64;
                let free = 100.0 * (capacity - held) / capacity;
                (free < f64::from(headroom)).then(|| {
                    format!(
                        "the decision spool has {free:.1}% free, under the {headroom}% headroom"
                    )
                })
            }),
        ));
    }
    if objectives.checkpoint_export_lag.is_some() {
        judged.push((
            "checkpoint_export_lag",
            measures.audit_egress_degraded.then(|| {
                "the audit checkpoints are not leaving the volume within their bound".to_owned()
            }),
        ));
    }
    if let Some(interval) = objectives.backup_interval {
        let margin = within_margin(interval);
        judged.push((
            "backup_interval",
            measures
                .since_backup
                .filter(|since| *since > margin)
                .map(|since| {
                    format!(
                        "no backup finalized for {}s, past {}s, four fifths of the {}s interval",
                        since.as_secs(),
                        margin.as_secs(),
                        interval.as_secs()
                    )
                }),
        ));
    }
    judged
}

/// The monitor, running until dropped.
pub struct Monitoring(tokio::task::JoinHandle<()>);

impl Drop for Monitoring {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What a pass reads the measures from.
pub struct Sources {
    pub health: permguard_core::Health,
    pub metrics: permguard_core::Metrics,
    pub backups: Arc<permguard_host::operations::backup::Backups>,
    /// The decision spool's capacity, when this process spools decisions.
    pub spool_capacity: Option<u64>,
    /// The Host's guarded time: a monitor never reads a clock of its own.
    pub time: Arc<permguard_host::time::TimeGuard>,
    /// When the volume was created, in seconds: without a finalized backup, the backup interval
    /// runs from there, so a restart never restarts it.
    pub volume_created: u64,
    /// When the volume's qualification record expires, from `production`: judged at every pass,
    /// not only at Bootstrap.
    pub qualification_expires_at: Option<i64>,
}

/// Measures every [`PASS`] and holds or releases readiness by objective.
pub fn drive(objectives: Objectives, sources: Sources) -> Monitoring {
    let sources = Arc::new(sources);
    Monitoring(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PASS);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            // A backups listing and a metrics snapshot: off the async threads.
            let measuring = Arc::clone(&sources);
            let Ok(measures) = tokio::task::spawn_blocking(move || measure(&measuring)).await
            else {
                continue;
            };
            let lifecycle = sources.health.lifecycle();
            let held = lifecycle.holds();
            for (objective, hold) in judge(&objectives, &measures) {
                match hold {
                    Some(reason) => {
                        if !held.contains_key(objective) {
                            tracing::warn!(
                                event.name = "host.objective_margin",
                                code = permguard_core::codes::storage::OBJECTIVE_MARGIN,
                                objective,
                                reason = %reason,
                                "readiness held: an objective's margin is exhausted"
                            );
                        }
                        lifecycle.hold(objective, reason);
                    }
                    None if held.contains_key(objective) => {
                        tracing::info!(
                            event.name = "host.objective_restored",
                            objective,
                            "readiness released: the objective is within its margin again"
                        );
                        lifecycle.release(objective);
                    }
                    None => {}
                }
            }
        }
    }))
}

/// When a record expiring at `expires_at` expired, once `now` has reached it.
pub fn expired(expires_at: Option<i64>, now: i64) -> Option<i64> {
    expires_at.filter(|at| *at <= now)
}

fn measure(sources: &Sources) -> Measures {
    use permguard_core::metrics::Reading;

    let gauge = |name: &str| {
        sources
            .metrics
            .snapshot()
            .into_iter()
            .filter(|sample| sample.metric.name() == name)
            .filter_map(|sample| match sample.reading {
                Reading::Value(value) => Some(value),
                Reading::Distribution { .. } => None,
            })
            .reduce(f64::max)
    };
    let newest = sources.backups.list().ok().and_then(|listed| {
        listed
            .into_iter()
            .filter(|backup| backup.state == permguard_host::operations::backup::FINALIZED)
            .filter_map(|backup| backup.ended_at)
            .max()
    });
    let now = sources.time.now_secs();
    let since_backup = Some(Duration::from_secs(
        now.saturating_sub(newest.unwrap_or(sources.volume_created)),
    ));
    let qualification_expired_at = expired(sources.qualification_expires_at, sources.time.now());
    Measures {
        mirror_age: gauge("permguard_sync_mirror_age_seconds"),
        spool: gauge("permguard_decisions_spool_bytes").zip(sources.spool_capacity),
        audit_egress_degraded: sources
            .health
            .lifecycle()
            .component(permguard_core::lifecycle::HOST)
            .is_some_and(|host| {
                host.degraded
                    .iter()
                    .any(|degraded| degraded.capability == "audit_egress")
            }),
        since_backup,
        qualification_expired_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn objectives() -> Objectives {
        Objectives {
            mirror_staleness: Some(Duration::from_secs(300)),
            spool_headroom: Some(20),
            checkpoint_export_lag: Some(Duration::from_secs(3600)),
            backup_interval: Some(Duration::from_secs(86_400)),
            ..Objectives::default()
        }
    }

    fn held(judged: &[(&'static str, Option<String>)]) -> Vec<&'static str> {
        judged
            .iter()
            .filter(|(_, hold)| hold.is_some())
            .map(|(objective, _)| *objective)
            .collect()
    }

    #[test]
    fn within_every_margin_nothing_is_held() {
        let judged = judge(
            &objectives(),
            &Measures {
                mirror_age: Some(240.0),
                spool: Some((800.0, 1000)),
                audit_egress_degraded: false,
                since_backup: Some(Duration::from_secs(69_120)),
                qualification_expired_at: None,
            },
        );
        assert_eq!(
            judged.len(),
            5,
            "every declared objective, and the qualification"
        );
        assert!(held(&judged).is_empty(), "{judged:?}");
    }

    /// Each objective is held before it is violated: past four fifths, or below the headroom.
    #[test]
    fn each_objective_is_held_once_its_margin_is_exhausted() {
        let cases = [
            (
                Measures {
                    mirror_age: Some(241.0),
                    ..Measures::default()
                },
                "mirror_staleness",
            ),
            (
                Measures {
                    spool: Some((801.0, 1000)),
                    ..Measures::default()
                },
                "spool_headroom",
            ),
            (
                Measures {
                    audit_egress_degraded: true,
                    ..Measures::default()
                },
                "checkpoint_export_lag",
            ),
            (
                Measures {
                    since_backup: Some(Duration::from_secs(69_121)),
                    ..Measures::default()
                },
                "backup_interval",
            ),
        ];
        for (measures, objective) in cases {
            let judged = judge(&objectives(), &measures);
            assert_eq!(held(&judged), [objective], "{judged:?}");
            let reason = judged
                .iter()
                .find(|(name, _)| *name == objective)
                .and_then(|(_, hold)| hold.clone())
                .unwrap_or_default();
            assert!(!reason.is_empty());
        }
    }

    #[test]
    fn a_qualification_record_that_expires_while_serving_holds_readiness() {
        let judged = judge(
            &Objectives::default(),
            &Measures {
                qualification_expired_at: Some(1_800_000_000),
                ..Measures::default()
            },
        );
        assert_eq!(held(&judged), [STORAGE_QUALIFICATION]);
        let reason = judged[0].1.clone().unwrap_or_default();
        assert!(
            reason.starts_with("storage_qualification_stale"),
            "{reason}"
        );
    }

    /// The record expires at its `expires_at`, not a second later, and never without one.
    #[test]
    fn a_record_expires_at_its_expiry() {
        assert_eq!(expired(Some(100), 99), None);
        assert_eq!(expired(Some(100), 100), Some(100));
        assert_eq!(expired(Some(100), 101), Some(100));
        assert_eq!(expired(None, i64::MAX), None);
    }

    #[test]
    fn an_objective_not_declared_is_not_monitored() {
        let judged = judge(
            &Objectives::default(),
            &Measures {
                mirror_age: Some(1e9),
                audit_egress_degraded: true,
                ..Measures::default()
            },
        );
        assert_eq!(judged.len(), 1, "only the qualification: {judged:?}");
        assert!(held(&judged).is_empty());
    }
}
