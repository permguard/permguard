// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Failed sign-ins (WP-8.1): `attempts` failures within `window` lock a user for `duration`, and
//! a source address at four times as many, so one office behind one address is not locked out by
//! one person's typing while a source trying many users is. A locked user's password is not even
//! checked. Held in memory, bounded.

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

/// The defaults: five failures in fifteen minutes lock for fifteen minutes.
pub const DEFAULT_ATTEMPTS: u32 = 5;
pub const DEFAULT_WINDOW: Duration = Duration::from_secs(900);
pub const DEFAULT_DURATION: Duration = Duration::from_secs(900);
/// A source address's failures are bounded at this many times a user's.
pub const SOURCE_FACTOR: u32 = 4;
/// The most users and sources tracked; past it the quietest go.
const MAX_TRACKED: usize = 100_000;

#[derive(Debug, Default, Clone)]
struct Tally {
    failures: VecDeque<Duration>,
    locked_until: Option<Duration>,
}

impl Tally {
    fn locked(&self, now: Duration) -> bool {
        self.locked_until.is_some_and(|until| now < until)
    }

    fn fail(&mut self, now: Duration, attempts: u32, window: Duration, duration: Duration) -> bool {
        while self
            .failures
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= window)
        {
            self.failures.pop_front();
        }
        self.failures.push_back(now);
        if self.failures.len() >= attempts as usize {
            self.locked_until = Some(now + duration);
            self.failures.clear();
        }
        self.locked(now)
    }
}

/// The failed sign-ins of one Host.
pub struct Lockout {
    attempts: u32,
    window: Duration,
    duration: Duration,
    users: Mutex<HashMap<String, Tally>>,
    sources: Mutex<HashMap<IpAddr, Tally>>,
    time: Arc<crate::time::TimeGuard>,
}

impl std::fmt::Debug for Lockout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lockout")
            .field("attempts", &self.attempts)
            .field("window", &self.window)
            .field("duration", &self.duration)
            .finish_non_exhaustive()
    }
}

impl Lockout {
    pub fn new(
        attempts: u32,
        window: Duration,
        duration: Duration,
        time: Arc<crate::time::TimeGuard>,
    ) -> Self {
        Self {
            attempts: attempts.max(1),
            window,
            duration,
            users: Mutex::new(HashMap::new()),
            sources: Mutex::new(HashMap::new()),
            time,
        }
    }

    /// Whether `user`, or `source`, is locked now.
    pub fn locked(&self, user: &str, source: Option<IpAddr>) -> bool {
        let now = self.time.elapsed();
        let user_locked = self
            .users
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(user)
            .is_some_and(|tally| tally.locked(now));
        user_locked
            || source.is_some_and(|source| {
                self.sources
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&source)
                    .is_some_and(|tally| tally.locked(now))
            })
    }

    /// Counts a failure of `user` from `source`; whether either is locked now.
    pub fn failed(&self, user: &str, source: Option<IpAddr>) -> bool {
        let now = self.time.elapsed();
        let user_locked = {
            let mut users = self.users.lock().unwrap_or_else(PoisonError::into_inner);
            bound(&mut users, now);
            users.entry(user.to_owned()).or_default().fail(
                now,
                self.attempts,
                self.window,
                self.duration,
            )
        };
        let source_locked = source.is_some_and(|source| {
            let mut sources = self.sources.lock().unwrap_or_else(PoisonError::into_inner);
            bound(&mut sources, now);
            sources.entry(source).or_default().fail(
                now,
                self.attempts.saturating_mul(SOURCE_FACTOR),
                self.window,
                self.duration,
            )
        });
        if user_locked || source_locked {
            tracing::warn!(
                event.name = "host.signin_locked",
                component = "host",
                user = %user,
                source = ?source,
                "failed sign-ins locked a user or a source address"
            );
        }
        user_locked || source_locked
    }

    /// Clears `user`'s failures after a sign-in that succeeded.
    pub fn succeeded(&self, user: &str) {
        self.users
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(user);
    }

    /// The users locked now and for how much longer: what an administrator sees.
    pub fn locked_users(&self) -> Vec<(String, Duration)> {
        let now = self.time.elapsed();
        self.users
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter_map(|(user, tally)| {
                tally
                    .locked_until
                    .filter(|until| now < *until)
                    .map(|until| (user.clone(), until - now))
            })
            .collect()
    }

    /// Unlocks `user` at once: an administrator's act.
    pub fn unlock(&self, user: &str) -> bool {
        self.users
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(user)
            .is_some()
    }
}

fn bound<K: std::hash::Hash + Eq + Clone>(map: &mut HashMap<K, Tally>, now: Duration) {
    if map.len() < MAX_TRACKED {
        return;
    }
    map.retain(|_, tally| tally.locked(now) || !tally.failures.is_empty());
    if map.len() >= MAX_TRACKED
        && let Some(quietest) = map
            .iter()
            .filter(|(_, tally)| !tally.locked(now))
            .min_by_key(|(_, tally)| tally.failures.back().copied())
            .map(|(key, _)| key.clone())
    {
        map.remove(&quietest);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::time::{ManualClock, ManualMonotonic, TimeGuard};

    #[test]
    fn failures_in_the_window_lock_for_the_duration_and_a_source_at_four_times() {
        let mono = Arc::new(ManualMonotonic::default());
        let time = Arc::new(TimeGuard::new(
            Arc::new(ManualClock::at(1_800_000_000)),
            mono.clone(),
            Duration::from_secs(30),
        ));
        let lockout = Lockout::new(3, Duration::from_secs(60), Duration::from_secs(300), time);
        let office: IpAddr = "203.0.113.7".parse().expect("an address");
        assert!(!lockout.failed("alice", Some(office)));
        mono.advance(Duration::from_secs(61));
        assert!(
            !lockout.failed("alice", Some(office)),
            "the first failure left the window"
        );
        assert!(!lockout.failed("alice", Some(office)));
        assert!(
            lockout.failed("alice", Some(office)),
            "three within the window"
        );
        assert!(lockout.locked("alice", None));
        assert_eq!(lockout.locked_users().len(), 1);
        mono.advance(Duration::from_secs(301));
        assert!(!lockout.locked("alice", None), "the lock ends");
        // One source trying many users is locked at twelve failures; each user is not.
        for (n, user) in (0..12).map(|n| (n, format!("user{n}"))) {
            let locked = lockout.failed(&user, Some(office));
            assert_eq!(locked, n == 11, "failure {n}");
        }
        assert!(lockout.locked("somebody-else", Some(office)));
        assert!(!lockout.locked(
            "somebody-else",
            Some("198.51.100.1".parse().expect("an address"))
        ));
        lockout.failed("bob", None);
        lockout.succeeded("bob");
        assert!(!lockout.unlock("bob"), "a success clears the failures");
    }
}
