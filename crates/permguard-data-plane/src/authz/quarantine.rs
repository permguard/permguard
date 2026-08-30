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
///
/// Not `Copy`, and deliberately: [`Admits::Probe`] carries a reservation that has to be given back
/// if the probe never runs, and a type that could be copied could not own that.
#[derive(Debug)]
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
    ///
    /// Carries the reservation. Hold it until the evaluation actually starts, then hand it over
    /// with [`ProbeLease::started`]; drop it and the reservation goes back.
    Probe(ProbeLease),
}

/// The right to be the one request let through a cooldown.
///
/// # Why a lease rather than a flag
///
/// Reserving the probe and starting it are not the same instant. Between them the request still has
/// to take a blocking permit, and that can be refused — at which point nothing evaluated, no
/// watchdog exists, and nothing will ever record an outcome. A bare `probing` flag set at
/// reservation time is then set for ever: every later request is told a probe is already out, the
/// cooldown never produces another one, and the profile stays quarantined until the process
/// restarts. That is a breaker that has stopped being a breaker.
///
/// So the reservation is owned. Every path that fails to start the probe — at capacity, an error
/// before the work is handed over, a cancelled request, an unwind — drops this, and the drop gives
/// the reservation back. Only [`started`](Self::started) hands it to the watchdog, which is the
/// one thing that guarantees an outcome will be recorded.
#[must_use = "dropping the lease gives the probe reservation back, which is only right if the probe never ran"]
#[derive(Debug)]
pub struct ProbeLease {
    quarantine: Arc<Quarantine>,
    key: String,
    /// Set once the evaluation is under way and the watchdog owns the outcome.
    handed_over: bool,
}

impl ProbeLease {
    /// The evaluation has begun; from here the watchdog will record how it ended.
    ///
    /// Call this only once the work is actually running — after the blocking permit is held — so
    /// that a refusal before that point still returns the reservation.
    pub fn started(mut self) {
        self.handed_over = true;
    }
}

impl Drop for ProbeLease {
    fn drop(&mut self) {
        if !self.handed_over {
            self.quarantine.release_probe(&self.key);
        }
    }
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

    /// What `key` may do now, and reserves the probe so only one request is let through.
    ///
    /// The reservation comes back inside [`Admits::Probe`]. Whoever receives it owns it: hand it to
    /// the watchdog with [`ProbeLease::started`] once the evaluation is under way, or drop it and
    /// the next request may probe instead.
    pub fn admits(self: &Arc<Self>, key: &str) -> Admits {
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

        Admits::Probe(ProbeLease {
            quarantine: Arc::clone(self),
            key: key.to_owned(),
            handed_over: false,
        })
    }

    /// Gives a reservation back, because the probe it was taken for never ran.
    ///
    /// Only clears the flag: the breaker stays open and the cooldown keeps whatever position it had
    /// reached, because nothing was learned. A probe that did not evaluate is not evidence that the
    /// profile recovered, and treating it as such would close a breaker on no observation at all.
    fn release_probe(&self, key: &str) {
        let Ok(mut held) = self.held.lock() else {
            return;
        };
        if let Some(state) = held.get_mut(key) {
            state.probing = false;
        }
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

    /// Opens the breaker on `key`, the way three overruns in a row would.
    fn opened(held: &Arc<Quarantine>) {
        assert!(!held.record_overrun(KEY, 1));
        assert!(!held.record_overrun(KEY, 2));
        assert!(held.record_overrun(KEY, 3), "the third opens it");
    }

    /// Moves the cooldown into the past, so a probe is due without a test waiting thirty seconds.
    fn cooldown_elapsed(held: &Arc<Quarantine>) {
        let mut state = held.held.lock().expect("the breaker is writable");
        let state = state.get_mut(KEY).expect("the breaker knows this profile");
        state.opened_at = Some(
            Instant::now()
                .checked_sub(COOLDOWN + Duration::from_secs(1))
                .expect("this machine has been up longer than one cooldown"),
        );
    }

    /// One overrun is not a verdict.
    #[test]
    fn a_single_overrun_does_not_take_a_profile_out_of_service() {
        let held = Arc::new(Quarantine::new());
        assert!(!held.record_overrun(KEY, 1));
        assert!(matches!(held.admits(KEY), Admits::Yes));
    }

    /// Enough of them in a row is.
    #[test]
    fn repeated_overruns_open_the_breaker_and_it_refuses() {
        let held = Arc::new(Quarantine::new());
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
        let held = Arc::new(Quarantine::new());
        for token in 1..=3 {
            held.record_overrun(KEY, token);
        }
        assert!(matches!(held.admits(KEY), Admits::No { .. }));

        held.record_in_time(KEY, 4);
        assert!(
            matches!(held.admits(KEY), Admits::Yes),
            "an evaluation that finished in time is the evidence the breaker was waiting for"
        );
    }

    /// A profile that never overran is never guarded.
    #[test]
    fn an_untroubled_profile_is_admitted_without_bookkeeping() {
        let held = Arc::new(Quarantine::new());
        assert!(matches!(held.admits("something-else"), Admits::Yes));
    }

    /// An old provider returning must not erase a newer timeout observation.
    #[test]
    fn a_stale_completion_does_not_close_newer_overruns() {
        let held = Arc::new(Quarantine::new());
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

    /// A reserved probe that never runs gives the reservation back.
    ///
    /// # Why this is the test that matters
    ///
    /// Reserving the probe and running it are separated by taking a blocking permit, and that can
    /// be refused. When it is, nothing evaluates, no watchdog is created, and nothing will ever
    /// record an outcome — so a reservation that is not returned is held for the life of the
    /// process. Every later request is then told a probe is already out, the cooldown never yields
    /// another one, and the profile is quarantined until somebody restarts the plane. The breaker
    /// would have become the outage it exists to prevent.
    #[test]
    fn a_probe_that_never_ran_gives_its_reservation_back() {
        let held = Arc::new(Quarantine::new());
        opened(&held);
        assert!(
            matches!(held.admits(KEY), Admits::No { .. }),
            "an open breaker refuses before its cooldown"
        );

        cooldown_elapsed(&held);
        let lease = match held.admits(KEY) {
            Admits::Probe(lease) => lease,
            other => panic!("the cooldown lets one request through: {other:?}"),
        };
        assert!(
            matches!(held.admits(KEY), Admits::No { .. }),
            "while a probe is out, nobody else joins it"
        );

        // What `Blocking::run` does when it refuses at capacity: the closure holding the lease is
        // dropped without ever being called.
        drop(lease);

        assert!(
            matches!(held.admits(KEY), Admits::Probe(_)),
            "the reservation came back, so the cooldown can produce another probe"
        );
    }

    /// A probe that started belongs to the watchdog, and still excludes everybody else.
    #[test]
    fn a_probe_that_started_is_not_given_back() {
        let held = Arc::new(Quarantine::new());
        opened(&held);
        cooldown_elapsed(&held);

        let lease = match held.admits(KEY) {
            Admits::Probe(lease) => lease,
            other => panic!("the cooldown lets one request through: {other:?}"),
        };
        lease.started();

        assert!(
            matches!(held.admits(KEY), Admits::No { .. }),
            "a probe that is running is the one request allowed: its outcome decides, and until it \
             arrives nothing else may spend capacity on this profile"
        );
    }

    /// Returning a reservation is not evidence of recovery.
    #[test]
    fn a_returned_reservation_does_not_close_the_breaker() {
        let held = Arc::new(Quarantine::new());
        opened(&held);
        cooldown_elapsed(&held);

        drop(match held.admits(KEY) {
            Admits::Probe(lease) => lease,
            other => panic!("a probe is due: {other:?}"),
        });

        let state = held.held.lock().expect("the breaker is readable");
        let state = &state[KEY];
        assert!(
            state.opened_at.is_some(),
            "nothing evaluated, so nothing was learned: the breaker stays open"
        );
        assert_eq!(
            state.overruns.len(),
            OVERRUNS_TO_OPEN as usize,
            "and the overruns that opened it are untouched"
        );
    }
}
