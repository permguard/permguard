// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Whether the shared backend answers, in a running server (iteration 03, E28, WP-29.1).
//!
//! On `postgresql-s3` a Host's state is the database's and the bucket's, and when either does
//! not answer the process cannot change anything: every change, and every token, is refused,
//! never served from a copy in memory. Readiness says so too, so a load balancer sends the work
//! to an instance that can do it. A check every [`PASS`] asks both whether they answer.
//!
//! | What the check finds                              | What the Host does                                   |
//! | ------------------------------------------------- | ---------------------------------------------------- |
//! | the database or the bucket refuses or is gone     | readiness held, `degraded: storage_backend`, a WARN  |
//! | no answer within [`BOUND`]                        | the same, and no second check while the first waits  |
//! | both answer again                                 | readiness released, an INFO                          |
//!
//! What a Plane decides with what it holds, a Data Plane's mirror, is not the backend's and goes
//! on: the Data Plane keeps its volume.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use permguard_host::backend::Ready;

/// How often the backend is asked.
pub const PASS: Duration = Duration::from_secs(5);
/// How long a check may wait for an answer before the backend is held as not answering.
pub const BOUND: Duration = Duration::from_secs(10);
/// The key and the degraded capability readiness is held under while the backend does not answer.
pub const HOLD: &str = "storage_backend";

/// The running check; dropped, it stops.
pub struct Watching(tokio::task::JoinHandle<()>);

impl Drop for Watching {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Asks `ready` now and every [`PASS`] until the handle is dropped, holding readiness on
/// `health` while it does not answer.
pub fn watch(ready: Ready, health: permguard_core::Health) -> Watching {
    watch_every(ready, health, PASS, BOUND)
}

/// [`watch`], a check every `pass`, unanswered past `bound`.
fn watch_every(
    ready: Ready,
    health: permguard_core::Health,
    pass: Duration,
    bound: Duration,
) -> Watching {
    Watching(tokio::spawn(async move {
        let mut interval = tokio::time::interval(pass);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // A check that outlived its bound runs on until the connection gives up: no other is
        // started meanwhile, so the checks never pile up on a backend that does not answer.
        let running = Arc::new(AtomicBool::new(false));
        let mut held = false;
        loop {
            interval.tick().await;
            if running.load(Ordering::SeqCst) {
                judge(
                    &health,
                    &mut held,
                    Err(format!(
                        "the backend has not answered a check for over {bound:?}"
                    )),
                );
                continue;
            }
            running.store(true, Ordering::SeqCst);
            let (asking, done) = (Arc::clone(&ready), Arc::clone(&running));
            let check = tokio::task::spawn_blocking(move || {
                let answer = asking();
                done.store(false, Ordering::SeqCst);
                answer
            });
            let answer = match tokio::time::timeout(bound, check).await {
                Ok(Ok(answer)) => answer,
                Ok(Err(_)) => Err("the check did not run to its end".to_owned()),
                Err(_) => Err(format!("the backend did not answer within {bound:?}")),
            };
            judge(&health, &mut held, answer);
        }
    }))
}

/// Holds or releases readiness on what a check answered, saying a change once.
fn judge(health: &permguard_core::Health, held: &mut bool, answer: Result<(), String>) {
    let lifecycle = health.lifecycle();
    match answer {
        Ok(()) => {
            if *held {
                lifecycle.release_as(HOLD, HOLD);
                *held = false;
                tracing::info!(
                    event.name = "storage.backend_answers",
                    component = "host",
                    "the database and the bucket answer again: readiness is released"
                );
            }
        }
        Err(reason) => {
            lifecycle.hold_as(HOLD, HOLD, reason.clone());
            if !*held {
                *held = true;
                tracing::warn!(
                    event.name = "storage.backend_unanswering",
                    component = "host",
                    code = permguard_core::codes::common::UNAVAILABLE,
                    reason = %reason,
                    "the database or the bucket does not answer: readiness is held, and no change \
                     is made until both answer"
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// A backend that stops answering holds readiness at the next check, once; one that answers
    /// again releases it.
    const TEST_PASS: Duration = Duration::from_millis(20);
    const TEST_BOUND: Duration = Duration::from_millis(200);

    /// Waits, in real time, for `holds` to say `held` of the backend, at most two seconds.
    async fn until_held(lifecycle: &permguard_core::lifecycle::Lifecycle, held: bool) -> bool {
        for _ in 0..200 {
            if lifecycle.holds().contains_key(HOLD) == held {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    #[tokio::test]
    async fn readiness_follows_whether_the_backend_answers() {
        let answering = Arc::new(AtomicBool::new(true));
        let asked = Arc::clone(&answering);
        let ready: Ready = Arc::new(move || {
            if asked.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err("PostgreSQL: connection refused".to_owned())
            }
        });
        let health = permguard_core::Health::new();
        let lifecycle = health.lifecycle();
        let _watching = watch_every(ready, health.clone(), TEST_PASS, TEST_BOUND);
        tokio::time::sleep(TEST_PASS * 5).await;
        assert!(!lifecycle.holds().contains_key(HOLD), "answering: not held");
        answering.store(false, Ordering::SeqCst);
        assert!(until_held(lifecycle, true).await, "not answering: held");
        assert_eq!(
            lifecycle.holds().get(HOLD).map(String::as_str),
            Some("PostgreSQL: connection refused")
        );
        answering.store(true, Ordering::SeqCst);
        assert!(
            until_held(lifecycle, false).await,
            "answering again: released"
        );
    }

    /// A check that does not answer within the bound holds readiness, and no second check is
    /// started while it waits.
    #[tokio::test]
    async fn a_check_that_does_not_answer_holds_readiness_and_is_not_repeated() {
        let started = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let release = Arc::new(AtomicBool::new(false));
        let (counting, waiting) = (Arc::clone(&started), Arc::clone(&release));
        let ready: Ready = Arc::new(move || {
            counting.fetch_add(1, Ordering::SeqCst);
            while !waiting.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(5));
            }
            Ok(())
        });
        let health = permguard_core::Health::new();
        let lifecycle = health.lifecycle();
        let _watching = watch_every(ready, health.clone(), TEST_PASS, TEST_BOUND);
        assert!(until_held(lifecycle, true).await, "unanswered: held");
        tokio::time::sleep(TEST_BOUND * 2).await;
        assert_eq!(started.load(Ordering::SeqCst), 1, "one check at a time");
        release.store(true, Ordering::SeqCst);
        assert!(
            until_held(lifecycle, false).await,
            "answered at last: released"
        );
    }
}
