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

use std::collections::HashMap;
use std::sync::Mutex;
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

#[derive(Debug, Clone, Copy)]
struct State {
    overruns: u32,
    opened_at: Option<Instant>,
    probing: bool,
}

/// The breaker, keyed by what can actually be attributed.
#[derive(Debug, Default)]
pub struct Quarantine {
    held: Mutex<HashMap<String, State>>,
}

impl Quarantine {
    pub fn new() -> Self {
        Self::default()
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
                overruns: state.overruns,
                retry_in: COOLDOWN.saturating_sub(elapsed),
            };
        }
        if state.probing {
            // A probe is already out. Everybody else keeps waiting rather than joining it: the
            // point of one request is to find out cheaply, not to re-open the flood.
            return Admits::No {
                overruns: state.overruns,
                retry_in: COOLDOWN,
            };
        }
        state.probing = true;

        Admits::Probe
    }

    /// Records that evaluating `key` finished inside its deadline.
    pub fn in_time(&self, key: &str) {
        if let Ok(mut held) = self.held.lock() {
            held.remove(key);
        }
    }

    /// Records that evaluating `key` overran its deadline, and reports whether that opened it.
    pub fn overran(&self, key: &str) -> bool {
        let Ok(mut held) = self.held.lock() else {
            return false;
        };
        let state = held.entry(key.to_owned()).or_insert(State {
            overruns: 0,
            opened_at: None,
            probing: false,
        });
        state.overruns = state.overruns.saturating_add(1);
        state.probing = false;
        if state.overruns >= OVERRUNS_TO_OPEN {
            let first = state.opened_at.is_none();
            state.opened_at = Some(Instant::now());

            return first;
        }

        false
    }
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
        assert!(!held.overran(KEY));
        assert_eq!(held.admits(KEY), Admits::Yes);
    }

    /// Enough of them in a row is.
    #[test]
    fn repeated_overruns_open_the_breaker_and_it_refuses() {
        let held = Quarantine::new();
        assert!(!held.overran(KEY));
        assert!(!held.overran(KEY));
        assert!(held.overran(KEY), "the third opens it, and says so once");
        assert!(
            !held.overran(KEY),
            "and a fourth does not announce it again"
        );

        match held.admits(KEY) {
            Admits::No { overruns, .. } => assert_eq!(overruns, 4),
            other => panic!("an open breaker refuses: {other:?}"),
        }
    }

    /// Recovery clears it, so a slow patch does not leave a profile out for ever.
    #[test]
    fn an_evaluation_in_time_closes_the_breaker() {
        let held = Quarantine::new();
        for _ in 0..3 {
            held.overran(KEY);
        }
        assert!(matches!(held.admits(KEY), Admits::No { .. }));

        held.in_time(KEY);
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
}
