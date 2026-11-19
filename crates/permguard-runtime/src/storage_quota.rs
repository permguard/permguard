// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The volume's quota and emergency floor in a running server (BUG-0062).
//!
//! The Host's [`Quota`] is opened at start, on the volume's root, with `storage.floors` and
//! `storage.quotas.host`: a quota on the Host measures the volume then, as the engine does for
//! every limited account. A pass every [`PASS`] judges the floor against the space the filesystem
//! reports, and every [`MEASURE_EVERY`] passes measures the volume again.
//!
//! | What the pass finds                          | What the Host does                                         |
//! | -------------------------------------------- | ---------------------------------------------------------- |
//! | free space below the floor plus one write    | readiness held, `degraded: storage_floor`, a WARN, coded  |
//! | free space back above it                     | readiness released, an INFO                                |
//! | the volume at or past `storage.quotas.host`  | a WARN, coded `storage_quota_exceeded`, once per crossing  |
//! | every pass                                   | the gauges below                                           |
//!
//! The floor needs no writer to be charged: it is judged against the filesystem's own free space,
//! so readiness goes false before the next write the Host makes would cross it, and comes back
//! once space is freed. A Host quota is measured and reported, and the server charges no writer to
//! it yet: a write past it is not refused. `storage.quotas.planes` is validated and not opened, a
//! Plane's data having no directory of its own on the volume to measure it from.

use std::time::Duration;

use permguard_core::metrics::Metric;
use permguard_core::volume::VolumeConfig;
use permguard_host::storage::quota::{Quota, Usage};
use permguard_host::storage::volume::Volume;
use permguard_host::storage::{Dir, journal};

/// How often the floor is judged.
pub const PASS: Duration = Duration::from_secs(5);
/// Every how many passes the volume is measured again: once a minute.
pub const MEASURE_EVERY: u64 = 12;
/// The key and the degraded capability readiness is held under below the floor.
pub const FLOOR_HOLD: &str = "storage_floor";

/// Free bytes on the volume as the floor judges them.
pub const FREE_BYTES: Metric = Metric::gauge(
    "permguard_storage_free_bytes",
    "Free bytes on the volume as the emergency floor judges them.",
);
/// The floor, `storage.floors.free_bytes`.
pub const FLOOR_BYTES: Metric = Metric::gauge(
    "permguard_storage_floor_bytes",
    "The emergency floor of free bytes ordinary writers leave on the volume.",
);
/// Bytes the volume holds, as last measured.
pub const USED_BYTES: Metric = Metric::gauge(
    "permguard_storage_used_bytes",
    "Bytes the volume holds, as last measured.",
);
/// `storage.quotas.host.bytes`; absent when the Host has no quota.
pub const QUOTA_BYTES: Metric = Metric::gauge(
    "permguard_storage_quota_bytes",
    "The Host's quota of bytes on the volume, storage.quotas.host.bytes.",
);
/// 1 while free space is above the floor, 0 while readiness is held for it.
pub const FLOOR_READY: Metric = Metric::gauge(
    "permguard_storage_floor_ready",
    "1 while free space is above the emergency floor, 0 while readiness is held for it.",
);

/// The Host's quota on `volume`, as `storage` configures it: the volume measured when the Host
/// has a quota, and readiness kept one journal write above the floor.
pub fn for_volume(volume: &Volume, storage: &VolumeConfig) -> anyhow::Result<Quota> {
    let root = Dir::open(volume.root())?;
    let quota = Quota::open(root, storage.floors, storage.quotas.host)?;
    quota.note_largest_write(journal::largest_write(&journal::Options::default()))?;

    Ok(quota)
}

/// The pass, stopped when this is dropped.
pub struct Watching(tokio::task::JoinHandle<()>);

impl Drop for Watching {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Judges `quota` now and every [`PASS`] until the handle is dropped.
pub fn watch(
    quota: Quota,
    health: permguard_core::Health,
    metrics: permguard_core::Metrics,
) -> Watching {
    Watching(tokio::spawn(async move {
        let mut interval = tokio::time::interval(PASS);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut judged = Judged::default();
        let mut pass: u64 = 0;
        loop {
            interval.tick().await;
            let measuring = quota.clone();
            let measure = pass.is_multiple_of(MEASURE_EVERY);
            pass = pass.wrapping_add(1);
            // A walk of the volume and a statvfs: off the async threads.
            let Ok(usage) = tokio::task::spawn_blocking(move || {
                if measure {
                    measuring.remeasure()?;
                }
                measuring.usage()
            })
            .await
            else {
                continue;
            };
            match usage {
                Ok(usage) => judge(&usage, &health, &metrics, &mut judged),
                Err(error) => tracing::warn!(
                    event.name = "host.storage_unmeasured",
                    error = %error,
                    "the volume's free space or usage could not be read; readiness is left as it was"
                ),
            }
        }
    }))
}

/// What the previous pass found, so a crossing is said once.
#[derive(Debug, Default)]
pub struct Judged {
    below_floor: bool,
    over_quota: bool,
}

/// Holds or releases readiness for the floor, says a quota crossing once, and sets the gauges.
pub fn judge(
    usage: &Usage,
    health: &permguard_core::Health,
    metrics: &permguard_core::Metrics,
    judged: &mut Judged,
) {
    let lifecycle = health.lifecycle();
    if usage.ready {
        if judged.below_floor {
            tracing::info!(
                event.name = "host.storage_floor_restored",
                "readiness released: free space is above the emergency floor again"
            );
        }
        lifecycle.release_as(FLOOR_HOLD, FLOOR_HOLD);
    } else {
        let reason = format!(
            "{}: {} bytes free, the floor is {} bytes and one write must stay above it",
            permguard_core::codes::storage::FREE_BYTES,
            usage.free_bytes.unwrap_or_default(),
            usage.floors.free_bytes
        );
        if !judged.below_floor {
            tracing::warn!(
                event.name = "host.storage_floor",
                code = permguard_core::codes::storage::FREE_BYTES,
                reason = %reason,
                "readiness held: free space is at the emergency floor"
            );
        }
        lifecycle.hold_as(FLOOR_HOLD, FLOOR_HOLD, reason);
    }
    judged.below_floor = !usage.ready;

    let host = usage.scopes.iter().find(|scope| scope.scope == "host");
    let over = host.is_some_and(|host| {
        host.limit
            .bytes
            .is_some_and(|limit| host.used_bytes >= limit)
            || host
                .limit
                .inodes
                .is_some_and(|limit| host.used_files >= limit)
    });
    if over
        && !judged.over_quota
        && let Some(host) = host
    {
        tracing::warn!(
            event.name = "host.storage_quota_exceeded",
            code = permguard_core::codes::storage::QUOTA_EXCEEDED,
            used_bytes = host.used_bytes,
            used_files = host.used_files,
            "the volume is at or past storage.quotas.host; the server charges no writer to it \
             yet, so writes are not refused"
        );
    }
    judged.over_quota = over;

    if let Some(free) = usage.free_bytes {
        metrics.set(&FREE_BYTES, &[], free as f64);
    }
    metrics.set(&FLOOR_BYTES, &[], usage.floors.free_bytes as f64);
    metrics.set(&FLOOR_READY, &[], if usage.ready { 1.0 } else { 0.0 });
    if let Some(host) = host
        && host.measured
    {
        metrics.set(&USED_BYTES, &[], host.used_bytes as f64);
        if let Some(limit) = host.limit.bytes {
            metrics.set(&QUOTA_BYTES, &[], limit as f64);
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::collections::BTreeMap;
    use std::sync::{Arc, Mutex};

    use permguard_core::metrics::{Label, Recorder, Sample};
    use permguard_core::volume::{Floors, Limit};
    use permguard_host::storage::quota::ScopeUsage;

    use super::*;

    /// The last value each gauge was set to.
    #[derive(Debug, Default)]
    struct Gauges(Mutex<BTreeMap<String, f64>>);

    impl Recorder for Gauges {
        fn record(&self, metric: &Metric, _labels: &[Label<'_>], value: f64) {
            if let Ok(mut gauges) = self.0.lock() {
                gauges.insert(metric.name().to_owned(), value);
            }
        }

        fn snapshot(&self) -> Vec<Sample> {
            Vec::new()
        }
    }

    fn usage(ready: bool, used_bytes: u64) -> Usage {
        Usage {
            scopes: vec![ScopeUsage {
                scope: "host".to_owned(),
                limit: Limit {
                    bytes: Some(16 * 1024),
                    inodes: None,
                },
                used_bytes,
                used_files: 3,
                reserved_bytes: 0,
                reserved_files: 0,
                measured: true,
            }],
            floors: Floors::default(),
            free_bytes: Some(if ready { u64::MAX / 2 } else { 1 }),
            free_inodes: None,
            ready,
        }
    }

    #[test]
    fn readiness_is_held_below_the_floor_and_released_once_space_returns() {
        let health = permguard_core::Health::new();
        let metrics = permguard_core::Metrics::none();
        let mut judged = Judged::default();

        judge(&usage(false, 0), &health, &metrics, &mut judged);
        let holds = health.lifecycle().holds();
        assert!(
            holds[FLOOR_HOLD].contains(permguard_core::codes::storage::FREE_BYTES),
            "{holds:?}"
        );
        assert!(!health.lifecycle().ready(), "held below the floor");

        judge(&usage(true, 0), &health, &metrics, &mut judged);
        assert!(
            !health.lifecycle().holds().contains_key(FLOOR_HOLD),
            "released once space returns"
        );
    }

    #[test]
    fn the_gauges_report_the_floor_the_free_space_and_the_hosts_usage_against_its_quota() {
        let health = permguard_core::Health::new();
        let gauges = Arc::new(Gauges::default());
        let metrics = permguard_core::Metrics::new(Arc::clone(&gauges) as Arc<dyn Recorder>);
        let mut judged = Judged::default();

        judge(&usage(true, 20 * 1024), &health, &metrics, &mut judged);
        let set = gauges.0.lock().expect("the gauges").clone();
        assert_eq!(
            set.get("permguard_storage_floor_ready"),
            Some(&1.0),
            "{set:?}"
        );
        assert_eq!(
            set.get("permguard_storage_used_bytes"),
            Some(&20480.0),
            "{set:?}"
        );
        assert_eq!(
            set.get("permguard_storage_quota_bytes"),
            Some(&16384.0),
            "{set:?}"
        );
        assert_eq!(
            set.get("permguard_storage_floor_bytes"),
            Some(&(permguard_core::volume::DEFAULT_FREE_BYTES as f64)),
            "{set:?}"
        );
        assert!(
            judged.over_quota,
            "a crossing is remembered, so it is said once"
        );

        judge(&usage(false, 20 * 1024), &health, &metrics, &mut judged);
        let set = gauges.0.lock().expect("the gauges").clone();
        assert_eq!(
            set.get("permguard_storage_floor_ready"),
            Some(&0.0),
            "{set:?}"
        );
    }
}
