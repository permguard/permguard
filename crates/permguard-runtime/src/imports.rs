// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The import pass of a `shared-bounded` member (BUG-0130).
//!
//! `shared-bounded` decides only on shared history the Host verified within
//! `events.pull.max_staleness`, and the Host verifies a coordinator's checkpoint when it imports.
//! The re-pin pass imports once a minute, so a bound below a minute refused most decisions with
//! nothing behind. A `shared-bounded` member imports on its own pass instead, every half of its
//! bound, within [`FLOOR`] and [`CEILING`]: a healthy import keeps the history fresher than the bound
//! asks, and the re-pin pass leaves the import to it.

use std::sync::Arc;
use std::time::Duration;

use permguard_host::api::HostApi;

/// The shortest pass: each one opens an import session per ledger.
pub const FLOOR: Duration = Duration::from_secs(2);
/// The longest: the re-pin pass's.
pub const CEILING: Duration = crate::repin::PASS;

/// The pass a bound of `max_staleness` is met by: half of it, within [`FLOOR`] and [`CEILING`].
pub fn interval_for(max_staleness: Duration) -> Duration {
    (max_staleness / 2).clamp(FLOOR, CEILING)
}

/// The running pass; dropping it stops it.
pub struct Importing(tokio::task::JoinHandle<()>);

impl Drop for Importing {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Imports what this Host's import tasks have due now and every [`interval_for`] `max_staleness`,
/// until the handle is dropped. A bound the pass cannot meet, below twice the [`FLOOR`], is said
/// once at start.
pub fn drive(api: Arc<HostApi>, max_staleness: Duration) -> Importing {
    let every = interval_for(max_staleness);
    if max_staleness < FLOOR * 2 {
        tracing::warn!(
            event.name = "host.import_bound_unmet",
            component = "host",
            max_staleness_seconds = max_staleness.as_secs_f64(),
            pass_seconds = every.as_secs_f64(),
            "events.pull.max_staleness is below twice the shortest import pass: decisions are \
             refused history_stale between passes; declare at least 4s"
        );
    }
    Importing(tokio::spawn(async move {
        let mut interval = tokio::time::interval(every);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            let imported = api.import_due().await;
            if imported > 0 {
                tracing::debug!(
                    event.name = "host.membership.imported",
                    component = "host",
                    batches = imported,
                    "this Host's import tasks brought the origins' batches"
                );
            }
        }
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pass_is_half_the_bound_within_its_floor_and_ceiling() {
        assert_eq!(
            interval_for(Duration::from_secs(10)),
            Duration::from_secs(5)
        );
        assert_eq!(interval_for(Duration::from_secs(1)), FLOOR);
        assert_eq!(interval_for(Duration::from_secs(600)), CEILING);
        // The default bound is met with room: a pass of half of it.
        let default = permguard_core::config::DEFAULT_EVENTS_PULL_MAX_STALENESS;
        assert!(interval_for(default) * 2 <= default);
    }
}
