// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The status lists a member holds (WP-12.1, `2-security/9` Delivery and Signals): fetched on their
//! own cadence, never behind another task's, and reported.
//!
//! | Rule     | Here                                                                                       |
//! | -------- | ------------------------------------------------------------------------------------------ |
//! | cadence  | every half of the shortest `ttl` held, at least every 15 s and at most every 30 s           |
//! | bound    | one pass takes at most 30 s; one that does not finish is dropped and the next one tries     |
//! | reported | every 15 s: `degraded: token-status` while a list is past half its lifetime without a fresher one, or held in memory only; not ready while one has expired; the metrics below |
//! | sync     | on the IAM Host, every minute, the tokens' statuses brought to what the directory says, so a change whose sync failed is never left `VALID`; `degraded: token-sync` while it fails |

use std::sync::Arc;
use std::time::Duration;

use permguard_core::metrics::labels;
use permguard_host::api::HostApi;
use permguard_host::membership::token_status::HeldLists;

/// How often the lists' standing is reported.
pub const WATCH: Duration = Duration::from_secs(15);
/// The longest a fetch pass may take.
pub const PASS_BOUND: Duration = Duration::from_secs(30);
/// The cadence when no list is held yet, and the longest between two passes.
pub const LONGEST: Duration = Duration::from_secs(30);
/// The shortest between two passes.
pub const SHORTEST: Duration = Duration::from_secs(15);

/// The capability the lists degrade, and the readiness they hold, on the Host.
pub const CAPABILITY: &str = "token-status";
/// The capability the IAM Host degrades while its tokens' statuses cannot follow its directory.
pub const SYNC_CAPABILITY: &str = "token-sync";
/// How often the IAM Host brings its tokens' statuses to its directory.
pub const SYNC_EVERY: Duration = Duration::from_secs(60);

/// The age of the oldest list held.
pub const LIST_AGE: permguard_core::Metric = permguard_core::Metric::gauge(
    "permguard_token_status_list_age_seconds",
    "Seconds since the oldest status list this member holds was issued; 0 when it holds none.",
);

/// The list tokens refused.
pub const LISTS_REFUSED: permguard_core::Metric = permguard_core::Metric::counter(
    "permguard_token_status_list_rejected_total",
    "Status list tokens this member refused, by reason: signature, rollback, expired, size.",
);

/// Where the lists' standing is reported.
#[derive(Clone)]
pub struct Observing {
    pub health: permguard_core::server::Health,
    pub metrics: permguard_core::Metrics,
    pub time: Arc<permguard_host::time::TimeGuard>,
}

/// The running fetch and report; dropping them stops them.
pub struct Watching(Vec<tokio::task::JoinHandle<()>>);

impl Drop for Watching {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// The wait before the next fetch: half the shortest `ttl` held, within [`SHORTEST`] and
/// [`LONGEST`].
pub fn cadence(lists: &HeldLists) -> Duration {
    lists
        .all()
        .iter()
        .map(|list| list.ttl / 2)
        .filter(|half| *half > 0)
        .min()
        .map_or(LONGEST, |half| {
            Duration::from_secs(half).clamp(SHORTEST, LONGEST)
        })
}

/// Starts the fetch of the lists `api`'s `token.status` tasks deliver, and their report.
pub fn drive(api: Arc<HostApi>, lists: Arc<HeldLists>, observing: Observing) -> Watching {
    let syncing = {
        let api = Arc::clone(&api);
        let health = observing.health.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(SYNC_EVERY);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                let syncing = Arc::clone(&api);
                let synced =
                    tokio::task::spawn_blocking(move || syncing.sync_token_statuses("iam")).await;
                let lifecycle = health.lifecycle();
                match synced {
                    Ok(Ok(_)) => {
                        lifecycle.restore(permguard_core::lifecycle::HOST, SYNC_CAPABILITY)
                    }
                    Ok(Err(refusal)) => {
                        let detail = refusal.error().map(ToString::to_string).unwrap_or_default();
                        tracing::warn!(
                            event.name = "iam.token_sync_failed",
                            component = "host",
                            error = %detail,
                            "the tokens' statuses could not follow the directory: the next pass tries again"
                        );
                        lifecycle.degrade(
                            permguard_core::lifecycle::HOST,
                            SYNC_CAPABILITY,
                            format!("the tokens' statuses do not follow the directory: {detail}"),
                        );
                    }
                    Err(_) => {}
                }
            }
        })
    };
    let fetching = {
        let lists = Arc::clone(&lists);
        tokio::spawn(async move {
            loop {
                match tokio::time::timeout(PASS_BOUND, api.token_status_due()).await {
                    Ok(0) => {}
                    Ok(accepted) => tracing::debug!(
                        event.name = "host.token_status_refreshed",
                        component = "host",
                        lists = accepted,
                        "this Host's token.status tasks brought fresher status lists"
                    ),
                    Err(_) => tracing::warn!(
                        event.name = "host.token_status_slow",
                        component = "host",
                        bound_seconds = PASS_BOUND.as_secs(),
                        "fetching the status lists took past its bound: the next pass tries again"
                    ),
                }
                tokio::time::sleep(cadence(&lists)).await;
            }
        })
    };
    let reporting = tokio::spawn(async move {
        let mut interval = tokio::time::interval(WATCH);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            report(&lists, &observing);
        }
    });
    Watching(vec![syncing, fetching, reporting])
}

/// Reports the lists once: the metrics, `degraded: token-status` while one is aging or held in
/// memory only, and readiness held while one has expired, since every token of it is refused.
pub fn report(lists: &HeldLists, observing: &Observing) {
    let standing = lists.standing(observing.time.now_secs());
    #[allow(clippy::cast_precision_loss)]
    let age = standing.oldest_age.unwrap_or(0) as f64;
    observing.metrics.set(&LIST_AGE, &[], age);
    for (reason, refused) in lists.take_refused() {
        #[allow(clippy::cast_precision_loss)]
        observing
            .metrics
            .add(&LISTS_REFUSED, &[(labels::REASON, reason)], refused as f64);
    }
    let lifecycle = observing.health.lifecycle();
    let mut behind = Vec::new();
    if !standing.aging.is_empty() {
        behind.push(format!(
            "{} status list(s) past half their lifetime without a fresher one",
            standing.aging.len()
        ));
    }
    if !standing.unkept.is_empty() {
        behind.push(format!(
            "{} status list(s) held in memory only: the volume did not take them",
            standing.unkept.len()
        ));
    }
    if behind.is_empty() {
        lifecycle.restore(permguard_core::lifecycle::HOST, CAPABILITY);
    } else {
        lifecycle.degrade(
            permguard_core::lifecycle::HOST,
            CAPABILITY,
            format!("{}; the IAM Host is not reached", behind.join("; ")),
        );
    }
    if standing.expired.is_empty() {
        lifecycle.release(CAPABILITY);
    } else {
        lifecycle.hold(
            CAPABILITY,
            format!(
                "{} status list(s) expired: every token of them is refused until a fresher one arrives",
                standing.expired.len()
            ),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The cadence follows the shortest `ttl` held, within its bounds.
    #[test]
    fn the_cadence_is_half_the_shortest_ttl_within_its_bounds() {
        let lists = HeldLists::in_memory();
        assert_eq!(cadence(&lists), LONGEST, "nothing held yet");
    }

    /// Every reason a list is refused for is a word the `reason` label admits.
    #[test]
    fn every_refusal_reason_is_a_registered_label_value() {
        for reason in ["signature", "rollback", "expired", "size"] {
            assert!(labels::REASON.admits(reason), "{reason}");
        }
    }
}
