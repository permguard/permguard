// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a member keeps between two shipments (iteration 04, WP-31.1 and WP-31.2;
//! `1-architecture/6` Shipping): the ship sessions it holds open across batches, and each task's
//! token bucket.
//!
//! | Kept            | Rule                                                                                       |
//! | --------------- | ------------------------------------------------------------------------------------------ |
//! | a session       | one per membership, task and stream, kept until its lease is four fifths gone or it idles  |
//! | the window      | at most the task's signed `max_concurrency` sessions; the one idle longest gives way       |
//! | a bucket        | one per task, refilled at its signed `max_rate_per_minute`, shared by every stream of it   |
//! | in use          | a session a round is sending on is taken out and marked: no second round sends on it       |
//!
//! Nothing here is held across an await: a round takes a session out under the lock, sends on it
//! with no lock held, and puts it back. A second round, a drain or the reconciliation, finds the
//! stream in use and leaves it to the first, so a stream never has two batches in flight.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use super::member::MemberTask;

/// A session with nothing sent for this long is closed.
pub const IDLE: Duration = Duration::from_secs(30);

/// How long a `rate_limited` answer empties the bucket: the bucket and the coordinator disagree.
pub const RATE_LIMITED_WAIT: Duration = Duration::from_secs(1);

/// A membership's task on one stream.
pub type StreamKey = ([u8; 16], String, String);

/// A membership's task.
pub type TaskKey = ([u8; 16], String);

/// A session kept open.
pub struct Held {
    pub task: MemberTask,
    /// The wall-clock second past which a new session replaces it: four fifths of its lease.
    pub renew_at: u64,
    /// When it last sent, on the monotonic clock.
    pub used: Duration,
}

impl Held {
    /// `task`, renewed once four fifths of its lease have passed, last used at `now`.
    pub fn new(task: MemberTask, now: Duration) -> Self {
        let issued = task.lease.issued_at;
        let life = task.lease.expires_at.saturating_sub(issued);
        Self {
            renew_at: issued.saturating_add(life.saturating_mul(4) / 5),
            task,
            used: now,
        }
    }
}

/// A task's token bucket: `max_rate_per_minute` messages a minute, at most a second's worth at
/// once, and never fewer than one.
#[derive(Debug, Clone, PartialEq)]
pub struct Bucket {
    rate_per_minute: u64,
    tokens: f64,
    at: Duration,
}

impl Bucket {
    /// A full bucket at `now`.
    pub fn new(rate_per_minute: u64, now: Duration) -> Self {
        let mut bucket = Self {
            rate_per_minute,
            tokens: 0.0,
            at: now,
        };
        bucket.tokens = bucket.capacity();
        bucket
    }

    fn capacity(&self) -> f64 {
        (self.rate_per_minute as f64 / 60.0).ceil().max(1.0)
    }

    fn refill(&mut self, now: Duration) {
        let elapsed = now.saturating_sub(self.at).as_secs_f64();
        self.tokens =
            (self.tokens + elapsed * self.rate_per_minute as f64 / 60.0).min(self.capacity());
        self.at = now;
    }

    /// The rate changed with a manifest revision: kept from now on.
    pub fn rate(&mut self, rate_per_minute: u64, now: Duration) {
        if rate_per_minute != self.rate_per_minute {
            self.refill(now);
            self.rate_per_minute = rate_per_minute;
            self.tokens = self.tokens.min(self.capacity());
        }
    }

    /// Takes a token at `now`: whether one was there.
    pub fn take(&mut self, now: Duration) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// How long from `now` until a token is there; zero when one is.
    pub fn wait(&self, now: Duration) -> Duration {
        let mut bucket = self.clone();
        bucket.refill(now);
        if bucket.tokens >= 1.0 || self.rate_per_minute == 0 {
            return Duration::ZERO;
        }
        Duration::from_secs_f64((1.0 - bucket.tokens) * 60.0 / self.rate_per_minute as f64)
    }

    /// Empties the bucket for `wait` from `now`: a `rate_limited` answer.
    pub fn empty_for(&mut self, wait: Duration, now: Duration) {
        self.refill(now);
        self.tokens = -(wait.as_secs_f64() * self.rate_per_minute as f64 / 60.0);
    }
}

#[derive(Default)]
struct Kept {
    sessions: BTreeMap<StreamKey, Box<Held>>,
    busy: BTreeSet<StreamKey>,
    buckets: BTreeMap<TaskKey, Bucket>,
    /// Where each task's next round starts among its streams: the round robin.
    turns: BTreeMap<TaskKey, usize>,
}

/// The ship sessions and buckets a member keeps (iteration 04, WP-31.2): one per Host.
#[derive(Default)]
pub struct ShipSessions {
    kept: Mutex<Kept>,
}

/// What taking a stream for a round answered.
pub enum Taken {
    /// Another round is sending on it.
    Busy,
    /// The session kept for it, if any; the stream is marked in use until [`ShipSessions::put`].
    Free(Option<Box<Held>>),
}

impl ShipSessions {
    fn kept(&self) -> std::sync::MutexGuard<'_, Kept> {
        self.kept.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes `key` for a round: its kept session, unless another round holds it. A session past
    /// its renewal at `now_secs` is dropped, so the round opens a new one.
    pub fn take(&self, key: &StreamKey, now_secs: u64) -> Taken {
        let mut kept = self.kept();
        if !kept.busy.insert(key.clone()) {
            return Taken::Busy;
        }
        let held = kept.sessions.remove(key);
        Taken::Free(held.filter(|held| now_secs < held.renew_at))
    }

    /// Ends the round on `key`, keeping `held` when it is still good.
    pub fn put(&self, key: &StreamKey, held: Option<Box<Held>>) {
        let mut kept = self.kept();
        kept.busy.remove(key);
        if let Some(held) = held {
            kept.sessions.insert(key.clone(), held);
        }
    }

    /// Makes room for a new session of `task` within `max_concurrency`: closes the sessions of the
    /// task idle longest, never one in use. Answers whether there is room.
    pub fn make_room(&self, task: &TaskKey, max_concurrency: u64) -> bool {
        let mut kept = self.kept();
        let open = |kept: &Kept| {
            let held = kept
                .sessions
                .keys()
                .filter(|key| key.0 == task.0 && key.1 == task.1)
                .count();
            let busy = kept
                .busy
                .iter()
                .filter(|key| key.0 == task.0 && key.1 == task.1)
                .count();
            // The stream being taken is marked busy already: it is the one asking for room.
            (held + busy).saturating_sub(1) as u64
        };
        while open(&kept) >= max_concurrency.max(1) {
            let Some(oldest) = kept
                .sessions
                .iter()
                .filter(|(key, _)| key.0 == task.0 && key.1 == task.1)
                .min_by_key(|(_, held)| held.used)
                .map(|(key, _)| key.clone())
            else {
                return false;
            };
            kept.sessions.remove(&oldest);
        }
        true
    }

    /// Closes every session idle since before `now - IDLE`, and every session of a task not in
    /// `live`: a membership that ended, a task its manifest dropped.
    pub fn sweep(&self, now: Duration, live: &BTreeSet<TaskKey>) {
        let mut kept = self.kept();
        kept.sessions.retain(|key, held| {
            live.contains(&(key.0, key.1.clone())) && now.saturating_sub(held.used) < IDLE
        });
        kept.buckets.retain(|task, _| live.contains(task));
        kept.turns.retain(|task, _| live.contains(task));
    }

    /// Takes a token of `task`'s bucket at `now`, its rate `rate_per_minute`.
    pub fn token(&self, task: &TaskKey, rate_per_minute: u64, now: Duration) -> bool {
        let mut kept = self.kept();
        let bucket = kept
            .buckets
            .entry(task.clone())
            .or_insert_with(|| Bucket::new(rate_per_minute, now));
        bucket.rate(rate_per_minute, now);
        bucket.take(now)
    }

    /// Whether `task`'s bucket has a token at `now`, taking none: asked before a batch is sealed,
    /// so none is sealed that the rate would not let leave.
    pub fn token_ready(&self, task: &TaskKey, rate_per_minute: u64, now: Duration) -> bool {
        let mut kept = self.kept();
        let bucket = kept
            .buckets
            .entry(task.clone())
            .or_insert_with(|| Bucket::new(rate_per_minute, now));
        bucket.rate(rate_per_minute, now);
        bucket.wait(now).is_zero()
    }

    /// How long until `task`'s bucket has a token.
    pub fn token_wait(&self, task: &TaskKey, now: Duration) -> Duration {
        self.kept()
            .buckets
            .get(task)
            .map_or(Duration::ZERO, |bucket| bucket.wait(now))
    }

    /// The coordinator answered `rate_limited` for `task`.
    pub fn rate_limited(&self, task: &TaskKey, now: Duration) {
        if let Some(bucket) = self.kept().buckets.get_mut(task) {
            bucket.empty_for(RATE_LIMITED_WAIT, now);
        }
    }

    /// `streams` in the order `task`'s round takes them: from its turn on, and the turn moved one
    /// on, so a busy stream never starves a quiet one.
    pub fn in_turn(&self, task: &TaskKey, mut streams: Vec<String>) -> Vec<String> {
        streams.sort();
        if streams.is_empty() {
            return streams;
        }
        let mut kept = self.kept();
        let turn = kept.turns.entry(task.clone()).or_insert(0);
        let start = *turn % streams.len();
        *turn = turn.wrapping_add(1);
        streams.rotate_left(start);
        streams
    }

    /// How many sessions are kept, in use or not: a measure.
    pub fn held(&self) -> usize {
        let kept = self.kept();
        kept.sessions.len() + kept.busy.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// `1-architecture/6` Shipping, the lease's limits: a task's rate is a token bucket, a
    /// second's worth at once, refilled at the signed rate.
    #[test]
    fn a_tasks_bucket_holds_a_seconds_worth_and_refills_at_its_rate() {
        let mut bucket = Bucket::new(600, ms(0));
        for n in 0..10 {
            assert!(bucket.take(ms(0)), "token {n} of the first second's ten");
        }
        assert!(!bucket.take(ms(0)), "an eleventh at once is over the rate");
        assert_eq!(
            bucket.wait(ms(0)),
            ms(100),
            "one token every 100 ms at 600 a minute"
        );
        assert!(!bucket.take(ms(50)));
        assert!(bucket.take(ms(100)), "refilled after 100 ms");
        assert!(bucket.take(ms(5_000)));
        assert!(bucket.take(ms(5_000)));
        let mut taken = 2;
        while bucket.take(ms(5_000)) {
            taken += 1;
        }
        assert_eq!(
            taken, 10,
            "an idle bucket refills to a second's worth, not more"
        );
    }

    /// A slow rate still lets one message through, and a rate below one a second waits its turn.
    #[test]
    fn a_slow_rate_keeps_one_token_and_waits_for_the_next() {
        let mut bucket = Bucket::new(6, ms(0));
        assert!(bucket.take(ms(0)));
        assert!(!bucket.take(ms(0)));
        assert_eq!(bucket.wait(ms(0)), Duration::from_secs(10));
        assert!(bucket.take(Duration::from_secs(10)));
    }

    /// `rate_limited`: the bucket is emptied for a second, whatever it held.
    #[test]
    fn a_rate_limited_answer_empties_the_bucket_for_a_second() {
        let mut bucket = Bucket::new(600, ms(0));
        bucket.empty_for(RATE_LIMITED_WAIT, ms(0));
        assert!(!bucket.take(ms(900)));
        assert!(bucket.take(ms(1_100)));
    }

    /// A manifest revision changes the rate from then on, never granting what the lower rate
    /// would not have.
    #[test]
    fn a_new_rate_applies_from_its_revision() {
        let mut bucket = Bucket::new(600, ms(0));
        bucket.rate(60, ms(0));
        assert!(bucket.take(ms(0)));
        assert!(
            !bucket.take(ms(0)),
            "a second's worth at 60 a minute is one"
        );
    }

    /// The streams of a task take turns: each round starts one further on.
    #[test]
    fn the_streams_of_a_task_take_turns() {
        let sessions = ShipSessions::default();
        let task: TaskKey = ([1; 16], "decisions".to_owned());
        let streams = vec!["c".to_owned(), "a".to_owned(), "b".to_owned()];
        assert_eq!(sessions.in_turn(&task, streams.clone()), ["a", "b", "c"]);
        assert_eq!(sessions.in_turn(&task, streams.clone()), ["b", "c", "a"]);
        assert_eq!(sessions.in_turn(&task, streams.clone()), ["c", "a", "b"]);
        assert_eq!(sessions.in_turn(&task, streams), ["a", "b", "c"]);
    }

    /// A stream another round is sending on is left to it, and free again once put back.
    #[test]
    fn a_stream_in_use_is_left_to_the_round_holding_it() {
        let sessions = ShipSessions::default();
        let key: StreamKey = (
            [1; 16],
            "decisions".to_owned(),
            "plane/data/zone/z".to_owned(),
        );
        assert!(matches!(sessions.take(&key, 0), Taken::Free(None)));
        assert!(matches!(sessions.take(&key, 0), Taken::Busy));
        sessions.put(&key, None);
        assert!(matches!(sessions.take(&key, 0), Taken::Free(None)));
    }
}
