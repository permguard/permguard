// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Taking a profile out of service when evaluating it keeps overrunning its deadline.
//!
//! # Why this is not a per-provider breaker
//!
//! The thing that hangs is a provider, and the obvious design quarantines the provider that hung.
//! It cannot be built here honestly: a provider runs inside upstream's engine, synchronously, and
//! nothing observable from outside says *which* of the providers a profile declares was the one
//! that did not return. What is observable is that evaluating **this profile against this ledger**
//! overran the deadline it was given.
//!
//! So that is the granularity, and naming it that way is the point — a breaker that claimed to know
//! which provider was at fault would be inventing the attribution, and an operator would act on it.
//!
//! # Why it is not a per-provider *substitution* either
//!
//! Upstream offers a resolver hook, and the tempting shape is to install one that short-circuits a
//! quarantined provider. Its contract forbids it: returning `Some(Err(_))` from a resolver is
//! documented as **undefined behavior for the decision outcome**, and the only other answers are
//! `None` — which falls back to running the script this is trying to avoid — or `Some(Ok(value))`,
//! which invents a value inside an authorization decision and can turn a deny into a permit.
//!
//! Refusing the request before evaluating is the one fail-closed option that does not depend on
//! behaviour upstream declares undefined.
//!
//! # Recovering
//!
//! A breaker that never closes is an outage with extra steps. After the cooldown the next request
//! is allowed through — one, not all — and its outcome decides: in time closes the breaker, another
//! overrun re-opens it. A provider that comes back is served again without anybody restarting a
//! plane.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// How many consecutive overruns open the breaker.
///
/// More than one, because a single overrun is as likely to be a slow disk or a noisy neighbour as a
/// provider that has stopped returning, and taking a profile out of service for that would make
/// this the outage rather than the cure.
const OVERRUNS_TO_OPEN: u32 = 3;

/// How long a profile stays out before one request is let through to test it.
const COOLDOWN: Duration = Duration::from_secs(30);

/// What a profile is allowed to do right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admits {
    /// Evaluate normally.
    Yes,
    /// Refuse: evaluating this has been overrunning and the cooldown has not elapsed.
    No {
        /// How many consecutive overruns opened it, for the message.
        overruns: u32,
        /// How long until one request is let through.
        retry_in: Duration,
    },
    /// The one request after a cooldown, whose outcome decides whether the breaker closes.
    Probe,
}

#[derive(Debug, Default)]
struct State {
    /// Deadline observations newer than the last successful evaluation.
    ///
    /// Tokens make completion order explicit: an old provider that finally
    /// returns must not close a breaker opened by newer work.
    overruns: BTreeSet<u64>,
    latest_in_time: u64,
    opened_at: Option<Instant>,
    probing: bool,
}

/// The breaker, keyed by what can actually be attributed.
#[derive(Debug, Default)]
pub struct Quarantine {
    held: Mutex<HashMap<String, State>>,
    next_token: AtomicU64,
}

const WATCHING: u8 = 0;
const FINISHED: u8 = 1;
const OVERRAN: u8 = 2;

/// One evaluation's deadline observation.
///
/// Its timer belongs to the process, not to the request future. If the client
/// disconnects while synchronous provider work continues, the timer still
/// records the overrun and protects later requests from spending every blocking
/// permit on the same profile.
pub struct DeadlineWatch {
    quarantine: Arc<Quarantine>,
    key: String,
    token: u64,
    deadline: Instant,
    status: Arc<AtomicU8>,
    timer: tokio::task::AbortHandle,
}

impl DeadlineWatch {
    /// Records how the work actually finished. A watchdog that reached the
    /// deadline first already owns the observation, so the late completion is
    /// deliberately a no-op rather than a second overrun.
    pub fn finish(self) {
        let late = Instant::now() >= self.deadline;
        let target = if late { OVERRAN } else { FINISHED };
        if self
            .status
            .compare_exchange(WATCHING, target, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.timer.abort();
        match late {
            true => {
                self.quarantine.record_overrun(&self.key, self.token);
            }
            false => self.quarantine.record_in_time(&self.key, self.token),
        }
    }
}

impl Quarantine {
    pub fn new() -> Self {
        Self::default()
    }

    /// Watches one admitted evaluation against an absolute deadline.
    pub fn watch(
        self: &Arc<Self>,
        key: String,
        deadline: Instant,
        runtime: &tokio::runtime::Handle,
    ) -> DeadlineWatch {
        let token = self.next_token.fetch_add(1, Ordering::Relaxed) + 1;
        let status = Arc::new(AtomicU8::new(WATCHING));
        let quarantine = Arc::clone(self);
        let watched_key = key.clone();
        let watched_status = Arc::clone(&status);
        let timer = runtime
            .spawn(async move {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                if watched_status
                    .compare_exchange(WATCHING, OVERRAN, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    quarantine.record_overrun(&watched_key, token);
                }
            })
            .abort_handle();

        DeadlineWatch {
            quarantine: Arc::clone(self),
            key,
            token,
            deadline,
            status,
            timer,
        }
    }

    /// What `key` may do now, and marks a probe as taken so only one request is let through.
    pub fn admits(&self, key: &str) -> Admits {
        let Ok(mut held) = self.held.lock() else {
            // A poisoned breaker cannot say a profile is healthy, and refusing every decision over
            // a poisoned mutex would be worse than the thing it guards. It stops guarding.
            return Admits::Yes;
        };
        let Some(state) = held.get_mut(key) else {
            return Admits::Yes;
        };
        let Some(opened_at) = state.opened_at else {
            return Admits::Yes;
        };
        let elapsed = opened_at.elapsed();
        if elapsed < COOLDOWN {
            return Admits::No {
                overruns: overrun_count(state),
                retry_in: COOLDOWN.saturating_sub(elapsed),
            };
        }
        if state.probing {
            // A probe is already out. Everybody else keeps waiting rather than joining it: the
            // point of one request is to find out cheaply, not to re-open the flood.
            return Admits::No {
                overruns: overrun_count(state),
                retry_in: COOLDOWN,
            };
        }
        state.probing = true;

        Admits::Probe
    }

    /// Records that evaluating `key` finished inside its deadline.
    fn record_in_time(&self, key: &str, token: u64) {
        let Ok(mut held) = self.held.lock() else {
            return;
        };
        let state = held.entry(key.to_owned()).or_default();
        if token <= state.latest_in_time {
            return;
        }
        state.latest_in_time = token;
        state.overruns.retain(|overrun| *overrun > token);
        if state.overruns.len() < OVERRUNS_TO_OPEN as usize {
            state.opened_at = None;
            state.probing = false;
        }
    }

    /// Records that evaluating `key` overran its deadline, and reports whether that opened it.
    fn record_overrun(&self, key: &str, token: u64) -> bool {
        let Ok(mut held) = self.held.lock() else {
            return false;
        };
        let state = held.entry(key.to_owned()).or_default();
        if token <= state.latest_in_time || !state.overruns.insert(token) {
            return false;
        }
        while state.overruns.len() > OVERRUNS_TO_OPEN as usize {
            if let Some(oldest) = state.overruns.first().copied() {
                state.overruns.remove(&oldest);
            }
        }
        state.probing = false;
        if state.overruns.len() >= OVERRUNS_TO_OPEN as usize {
            let first = state.opened_at.is_none();
            state.opened_at = Some(Instant::now());

            return first;
        }

        false
    }
}

fn overrun_count(state: &State) -> u32 {
    u32::try_from(state.overruns.len()).unwrap_or(u32::MAX)
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    const KEY: &str = "acme/agent-governance/session-access";

    /// One overrun is not a verdict.
    #[test]
    fn a_single_overrun_does_not_take_a_profile_out_of_service() {
        let held = Quarantine::new();
        assert!(!held.record_overrun(KEY, 1));
        assert_eq!(held.admits(KEY), Admits::Yes);
    }

    /// Enough of them in a row is.
    #[test]
    fn repeated_overruns_open_the_breaker_and_it_refuses() {
        let held = Quarantine::new();
        assert!(!held.record_overrun(KEY, 1));
        assert!(!held.record_overrun(KEY, 2));
        assert!(
            held.record_overrun(KEY, 3),
            "the third opens it, and says so once"
        );
        assert!(
            !held.record_overrun(KEY, 4),
            "and a fourth does not announce it again"
        );

        match held.admits(KEY) {
            Admits::No { overruns, .. } => assert_eq!(overruns, 3),
            other => panic!("an open breaker refuses: {other:?}"),
        }
    }

    /// Recovery clears it, so a slow patch does not leave a profile out for ever.
    #[test]
    fn an_evaluation_in_time_closes_the_breaker() {
        let held = Quarantine::new();
        for token in 1..=3 {
            held.record_overrun(KEY, token);
        }
        assert!(matches!(held.admits(KEY), Admits::No { .. }));

        held.record_in_time(KEY, 4);
        assert_eq!(
            held.admits(KEY),
            Admits::Yes,
            "an evaluation that finished in time is the evidence the breaker was waiting for"
        );
    }

    /// A profile that never overran is never guarded.
    #[test]
    fn an_untroubled_profile_is_admitted_without_bookkeeping() {
        let held = Quarantine::new();
        assert_eq!(held.admits("something-else"), Admits::Yes);
    }

    /// An old provider returning must not erase a newer timeout observation.
    #[test]
    fn a_stale_completion_does_not_close_newer_overruns() {
        let held = Quarantine::new();
        held.record_overrun(KEY, 2);
        held.record_in_time(KEY, 1);

        let state = held.held.lock().expect("the breaker is readable");
        assert_eq!(state[KEY].overruns, BTreeSet::from([2]));
    }

    /// The timer survives independently of the request that started the work.
    #[tokio::test]
    async fn a_watchdog_records_work_that_has_not_returned() {
        let held = Arc::new(Quarantine::new());
        held.record_overrun(KEY, 1);
        held.record_overrun(KEY, 2);
        held.next_token.store(2, Ordering::Relaxed);
        let _watch = held.watch(
            KEY.to_owned(),
            Instant::now() + Duration::from_millis(5),
            &tokio::runtime::Handle::current(),
        );

        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(matches!(held.admits(KEY), Admits::No { overruns: 3, .. }));
    }
}
