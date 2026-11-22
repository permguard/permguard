// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's time guard (WP-2.12): one service every time-dependent Host path reads.
//!
//! | Reading                    | For                                                 | Refuses in anomaly |
//! | -------------------------- | --------------------------------------------------- | ------------------ |
//! | [`TimeGuard::now`]         | expiry comparisons, timestamps a record carries      | no                 |
//! | [`TimeGuard::elapsed`]     | how long an already-open session or window has run   | no                 |
//! | [`TimeGuard::trusted_now`] | new leases and time-sensitive signatures            | yes                |
//!
//! Every wall reading is checked against monotonic time: the wall clock is expected where the last
//! reading plus the monotonic time since puts it. A reading more than the configured bound
//! (`time.max_clock_skew`) behind that is a backward jump, and opens a [`ClockAnomaly`]. The
//! anomaly closes once the wall clock reaches the time it was expected at when the jump was seen,
//! which is the highest wall time the guard knew of: the operator resolves time by correcting the
//! clock, and the guard notices (owner decisions of 2026-10-07).
//!
//! The highest wall time observed is kept in the [`ClockMark`], so a restart under a clock set
//! back is caught at Bootstrap too, where no monotonic reading links the two processes.
//!
//! | Backend            | Keeps the mark in  |
//! | ------------------ | ------------------ |
//! | [`files`], default | `host/state/CLOCK` |
//!
//! Ordering never depends on any of this: journals and trails order by sequence, and keep doing so
//! through an anomaly, which is itself recorded.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

pub use permguard_core::time::{Clock, ManualClock, SystemClock};

pub mod files;
#[cfg(any(test, feature = "test-support"))]
pub mod suite;

/// The capability the Host reports as degraded while the clock is in anomaly.
pub const CAPABILITY: &str = "time";
/// The audit action written when a backward jump beyond the bound is seen.
pub const AUDIT_CLOCK_ANOMALY: &str = "host.clock_anomaly";
/// The audit action written when the wall clock has caught up again.
pub const AUDIT_CLOCK_RESTORED: &str = "host.clock_restored";

/// Why the mark was not read or raised.
#[derive(Debug)]
pub enum MarkError {
    /// The mark held does not read as one: the check it carries cannot be made.
    Record(String),
    /// The store could not be read or written.
    Unavailable(Box<dyn std::error::Error + Send + Sync>),
}

impl std::fmt::Display for MarkError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Record(detail) => formatter.write_str(detail),
            Self::Unavailable(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for MarkError {}

/// The store of the highest wall time the Host observed: the only way the guard reads and
/// raises it (`1-architecture/8` Store contracts).
pub trait ClockMark: Send + Sync {
    /// The mark, seconds since the epoch; `None` when none was ever kept. One that is there and
    /// does not read is an error, never none.
    fn read(&self) -> Result<Option<i64>, MarkError>;

    /// Raises the mark to `mark`. It only rises: one not above the mark held changes nothing,
    /// whoever raised that one.
    fn raise(&self, mark: i64) -> Result<(), MarkError>;

    /// What an operator does when the mark itself is wrong, left by a run under a clock set
    /// ahead: said where the anomaly it opens is logged.
    fn remedy(&self) -> String;
}

/// How far the high-water mark may run ahead of what is on the volume before it is written again:
/// a restart misses at most this much of a backward step.
const PERSIST_EVERY: i64 = 60;

/// Where monotonic time comes from, so a test can move it.
pub trait Monotonic: Send + Sync {
    /// Time since a fixed origin; never goes backward.
    fn elapsed(&self) -> Duration;
}

/// The operating system's monotonic clock, from the instant this was built.
#[derive(Debug, Clone, Copy)]
pub struct SystemMonotonic {
    origin: Instant,
}

impl SystemMonotonic {
    /// A monotonic clock starting now.
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for SystemMonotonic {
    fn default() -> Self {
        Self::new()
    }
}

impl Monotonic for SystemMonotonic {
    fn elapsed(&self) -> Duration {
        self.origin.elapsed()
    }
}

/// A monotonic clock that moves only when told to, and only forward.
#[derive(Debug, Default)]
pub struct ManualMonotonic(std::sync::atomic::AtomicU64);

impl ManualMonotonic {
    /// Moves the clock forward by `by`.
    pub fn advance(&self, by: Duration) {
        let nanos = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
        self.0.fetch_add(nanos, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Monotonic for ManualMonotonic {
    fn elapsed(&self) -> Duration {
        Duration::from_nanos(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
}

/// A backward step of the wall clock beyond the configured bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockAnomaly {
    /// The wall time read, seconds since the epoch.
    pub observed: i64,
    /// Where the wall clock was expected, seconds since the epoch: the anomaly closes once the
    /// wall clock reaches it.
    pub expected: i64,
    /// The bound in force, whole seconds.
    pub bound: u64,
}

impl ClockAnomaly {
    /// How far back the clock stepped, in seconds.
    pub fn jump(&self) -> i64 {
        self.expected.saturating_sub(self.observed)
    }
}

impl std::fmt::Display for ClockAnomaly {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "the wall clock reads {} where {} was expected, {}s back against a bound of {}s; \
             it clears once the wall clock reaches {}",
            self.observed,
            self.expected,
            self.jump(),
            self.bound,
            self.expected
        )
    }
}

impl std::error::Error for ClockAnomaly {}

/// What changed in the guard's state, as an [`Observer`] is told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transition {
    /// A backward jump beyond the bound was seen.
    Opened(ClockAnomaly),
    /// The wall clock reached `anomaly.expected`; `observed` is the reading that did.
    Closed {
        anomaly: ClockAnomaly,
        observed: i64,
    },
}

/// Told of every transition: the composition root wires readiness, the audit trail and the log.
pub trait Observer: Send + Sync {
    /// Called after the transition, outside the guard's state lock, one transition at a time and
    /// in the order they happened.
    fn transition(&self, transition: &Transition);
}

#[derive(Debug)]
struct State {
    /// The last wall reading the guard trusted, and the monotonic time it was read at.
    anchor_wall: i64,
    anchor_mono: Duration,
    /// The highest wall time observed, and the last value written to the volume.
    high_water: i64,
    persisted: i64,
    anomaly: Option<ClockAnomaly>,
    /// The monotonic time the anomaly was seen at: in anomaly, wall time is projected from
    /// `anomaly.expected` by the monotonic time since.
    anomaly_mono: Duration,
    /// Transitions not yet delivered, in the order they happened.
    pending: std::collections::VecDeque<Transition>,
}

/// The Host's one time service.
pub struct TimeGuard {
    wall: Arc<dyn Clock>,
    monotonic: Arc<dyn Monotonic>,
    bound: Duration,
    state: Mutex<State>,
    store: Option<Arc<dyn ClockMark>>,
    observers: Mutex<Vec<Arc<dyn Observer>>>,
    /// Held while transitions are delivered, so observers hear them one at a time and in order.
    delivering: Mutex<()>,
}

impl std::fmt::Debug for TimeGuard {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TimeGuard")
            .field("bound", &self.bound)
            .field("anomaly", &self.anomaly())
            .finish()
    }
}

impl TimeGuard {
    /// A guard over `wall` and `monotonic` that keeps nothing on a volume: what a component built
    /// outside a server, or a test, reads.
    pub fn new(wall: Arc<dyn Clock>, monotonic: Arc<dyn Monotonic>, bound: Duration) -> Self {
        let now = wall.now();
        let anchor_mono = monotonic.elapsed();
        Self {
            wall,
            monotonic,
            bound,
            state: Mutex::new(State {
                anchor_wall: now,
                anchor_mono,
                high_water: now,
                persisted: now,
                anomaly: None,
                anomaly_mono: anchor_mono,
                pending: std::collections::VecDeque::new(),
            }),
            store: None,
            observers: Mutex::new(Vec::new()),
            delivering: Mutex::new(()),
        }
    }

    /// A guard whose wall clock reads `seconds` and never moves: what a test of a time-bounded
    /// check reads.
    pub fn fixed(seconds: u64) -> Self {
        Self::new(
            Arc::new(ManualClock::at(i64::try_from(seconds).unwrap_or(i64::MAX))),
            Arc::new(ManualMonotonic::default()),
            permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
        )
    }

    /// The operating system's clocks, nothing kept on a volume.
    pub fn system(bound: Duration) -> Self {
        Self::new(
            Arc::new(SystemClock),
            Arc::new(SystemMonotonic::new()),
            bound,
        )
    }

    /// A guard for the Host that keeps `mark`: the high-water mark a previous process left is
    /// checked first, so a clock set back across a restart opens the anomaly at once. A damaged
    /// mark fails the start: the check it carries cannot be made, and nothing silently forgets
    /// it.
    pub fn open(
        mark: Arc<dyn ClockMark>,
        wall: Arc<dyn Clock>,
        monotonic: Arc<dyn Monotonic>,
        bound: Duration,
    ) -> Result<Self, MarkError> {
        let persisted = mark.read()?;
        let remedy = mark.remedy();
        let mut guard = Self::new(wall, monotonic, bound);
        guard.store = Some(mark);
        {
            let state = guard
                .state
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner);
            if let Some(mark) = persisted {
                state.persisted = mark;
                if state.anchor_wall.saturating_add(bound_secs(bound)) < mark {
                    let anomaly = ClockAnomaly {
                        observed: state.anchor_wall,
                        expected: mark,
                        bound: bound.as_secs(),
                    };
                    // The mark itself may be what is wrong: a previous run under a clock set
                    // ahead. The remedy is said where an operator looks.
                    tracing::warn!(
                        event.name = "host.clock_mark_ahead",
                        component = "host",
                        mark,
                        observed = state.anchor_wall,
                        remedy = %remedy,
                        "the wall clock is behind the high-water mark a previous run left; the \
                         remedy is what to do if the mark itself is wrong"
                    );
                    state.anomaly = Some(anomaly);
                    state.anomaly_mono = state.anchor_mono;
                }
                state.high_water = state.high_water.max(mark);
            }
        }
        let high_water = guard
            .state
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner)
            .high_water;
        if persisted != Some(high_water) {
            guard.persist(high_water)?;
            guard
                .state
                .get_mut()
                .unwrap_or_else(PoisonError::into_inner)
                .persisted = high_water;
        }

        Ok(guard)
    }

    /// Registers `observer`; when the clock is already in anomaly it is told at once, so a guard
    /// opened in anomaly at Bootstrap reaches readiness and the trail like a later one. The
    /// replay and the transitions still to be delivered never overlap or reorder. An observer may
    /// read the guard; it may not register another observer.
    pub fn observe(&self, observer: Arc<dyn Observer>) {
        let held = self
            .delivering
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let replay = {
            let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            // What observers have heard so far: the state before the first transition not yet
            // delivered.
            let heard = match state.pending.front() {
                Some(Transition::Opened(_)) => None,
                Some(Transition::Closed { anomaly, .. }) => Some(anomaly.clone()),
                None => state.anomaly.clone(),
            };
            self.observers
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(Arc::clone(&observer));
            heard
        };
        if let Some(anomaly) = replay {
            observer.transition(&Transition::Opened(anomaly));
        }
        drop(held);
        self.deliver();
    }

    /// The bound in force.
    pub fn bound(&self) -> Duration {
        self.bound
    }

    /// The anomaly in force, if any.
    pub fn anomaly(&self) -> Option<ClockAnomaly> {
        self.state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .anomaly
            .clone()
    }

    /// Wall time, seconds since the epoch, for expiry comparisons and the times records carry.
    /// Never refuses, and never earlier than the guard already knew: in anomaly it is the time the
    /// wall clock was expected at, carried forward by monotonic time, until the wall clock passes
    /// it — so an expiry is never judged against a clock set back.
    pub fn now(&self) -> i64 {
        self.read().0
    }

    /// [`TimeGuard::now`] as unsigned seconds, for the stores that keep them so.
    pub fn now_secs(&self) -> u64 {
        u64::try_from(self.now()).unwrap_or(0)
    }

    /// Monotonic time since the guard's origin: the measure of an already-open session or window.
    pub fn elapsed(&self) -> Duration {
        self.monotonic.elapsed()
    }

    /// Wall time for a new lease or a time-sensitive signature: refused while the clock is in
    /// anomaly.
    pub fn trusted_now(&self) -> Result<i64, ClockAnomaly> {
        let (now, anomaly) = self.read();
        match anomaly {
            Some(anomaly) => Err(anomaly),
            None => Ok(now),
        }
    }

    /// The gate a new lease passes (the task sessions' leases, WP-4.3): refused while the clock is in
    /// anomaly. A lease already granted keeps its expiry; only granting a new one stops.
    pub fn lease_now(&self) -> Result<i64, ClockAnomaly> {
        self.trusted_now()
    }

    /// Reads the clocks once, for the periodic pass that notices a jump, or its end, when nothing
    /// else reads the time.
    pub fn tick(&self) {
        let _ = self.read();
    }

    fn read(&self) -> (i64, Option<ClockAnomaly>) {
        let wall = self.wall.now();
        let mono = self.monotonic.elapsed();
        let mut persist = None;
        let (now, anomaly) = {
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            match state.anomaly.clone() {
                None => {
                    // Where the wall clock should be: the last trusted reading carried forward by
                    // monotonic time, and never below the highest wall time seen, so a walk back
                    // in steps each inside the bound is caught as one jump.
                    let since = mono.saturating_sub(state.anchor_mono).as_secs();
                    let expected = state
                        .anchor_wall
                        .saturating_add(i64::try_from(since).unwrap_or(i64::MAX))
                        .max(state.high_water);
                    if wall.saturating_add(bound_secs(self.bound)) < expected {
                        let anomaly = ClockAnomaly {
                            observed: wall,
                            expected,
                            bound: self.bound.as_secs(),
                        };
                        state.anomaly = Some(anomaly.clone());
                        state.anomaly_mono = mono;
                        state.pending.push_back(Transition::Opened(anomaly));
                    } else {
                        state.anchor_wall = wall;
                        state.anchor_mono = mono;
                    }
                }
                Some(anomaly) if wall >= anomaly.expected => {
                    state.anomaly = None;
                    state.anchor_wall = wall;
                    state.anchor_mono = mono;
                    state.pending.push_back(Transition::Closed {
                        anomaly,
                        observed: wall,
                    });
                }
                Some(_) => {}
            }
            if state.anomaly.is_none() && wall > state.high_water {
                state.high_water = wall;
                if self.store.is_some() && wall.saturating_sub(state.persisted) >= PERSIST_EVERY {
                    state.persisted = wall;
                    persist = Some(wall);
                }
            }
            let now = match &state.anomaly {
                None => wall,
                Some(anomaly) => {
                    let since = mono.saturating_sub(state.anomaly_mono).as_secs();
                    wall.max(
                        anomaly
                            .expected
                            .saturating_add(i64::try_from(since).unwrap_or(i64::MAX)),
                    )
                }
            };
            (now, state.anomaly.clone())
        };
        if let Some(mark) = persist
            && let Err(error) = self.persist(mark)
        {
            // The mark only narrows what a restart could miss; failing to move it forward leaves
            // the older mark in place, which is still checked.
            tracing::warn!(
                event.name = "host.clock_mark_not_written",
                component = "host",
                error = %error,
                "the clock's high-water mark could not be written; the previous one stays in force"
            );
        }
        self.deliver();
        (now, anomaly)
    }

    /// Delivers the pending transitions, in order, one deliverer at a time: a reader that finds
    /// another delivering leaves its transition queued for that one, which looks again before it
    /// lets go.
    fn deliver(&self) {
        loop {
            let held = match self.delivering.try_lock() {
                Ok(held) => held,
                Err(std::sync::TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
                Err(std::sync::TryLockError::WouldBlock) => return,
            };
            loop {
                let batch: Vec<Transition> = self
                    .state
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .pending
                    .drain(..)
                    .collect();
                if batch.is_empty() {
                    break;
                }
                let observers = self
                    .observers
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .clone();
                for transition in &batch {
                    for observer in &observers {
                        observer.transition(transition);
                    }
                }
            }
            drop(held);
            if self
                .state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pending
                .is_empty()
            {
                return;
            }
        }
    }

    fn persist(&self, mark: i64) -> Result<(), MarkError> {
        match &self.store {
            Some(store) => store.raise(mark),
            None => Ok(()),
        }
    }
}

fn bound_secs(bound: Duration) -> i64 {
    i64::try_from(bound.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::storage::volume::Volume;

    const START: i64 = 1_800_000_000;
    const BOUND: Duration = Duration::from_secs(30);

    struct Recorded(Mutex<Vec<Transition>>);

    impl Observer for Recorded {
        fn transition(&self, transition: &Transition) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(transition.clone());
        }
    }

    fn guard() -> (Arc<ManualClock>, Arc<ManualMonotonic>, TimeGuard) {
        let wall = Arc::new(ManualClock::at(START));
        let mono = Arc::new(ManualMonotonic::default());
        let guard = TimeGuard::new(wall.clone(), mono.clone(), BOUND);
        (wall, mono, guard)
    }

    #[test]
    fn a_backward_jump_beyond_the_bound_opens_the_anomaly_and_refuses_trusted_time() {
        let (wall, mono, guard) = guard();
        let seen = Arc::new(Recorded(Mutex::new(Vec::new())));
        guard.observe(seen.clone());
        assert_eq!(guard.trusted_now(), Ok(START));

        mono.advance(Duration::from_secs(100));
        wall.jump(100 - 31);
        let refused = guard.trusted_now().expect_err("31s back against 30s");
        assert_eq!(refused.expected, START + 100);
        assert_eq!(refused.jump(), 31);
        assert!(guard.lease_now().is_err(), "no new lease");
        // Expiry keeps reading, at the expected time rather than the set-back one; durations too.
        assert_eq!(guard.now(), START + 100);
        assert_eq!(guard.elapsed(), Duration::from_secs(100));
        assert_eq!(
            seen.0.lock().expect("held").as_slice(),
            &[Transition::Opened(refused)]
        );
    }

    /// A walk back in steps each inside the bound is one jump against the highest time seen: the
    /// same reference a restart is checked against.
    #[test]
    fn a_walk_back_in_steps_inside_the_bound_is_caught() {
        let (wall, _, guard) = guard();
        for _ in 0..2 {
            wall.jump(-15);
            assert!(
                guard.trusted_now().is_ok(),
                "15s, then 30s back: inside the bound"
            );
        }
        wall.jump(-15);
        let anomaly = guard.trusted_now().expect_err("45s back in all");
        assert_eq!((anomaly.expected, anomaly.observed), (START, START - 45));
    }

    /// An observer that reads the guard, and by reading closes the anomaly, hears the opening
    /// first and the closing second.
    #[test]
    fn transitions_reach_observers_in_order_even_when_an_observer_reads_the_guard() {
        struct Corrects {
            wall: Arc<ManualClock>,
            guard: std::sync::OnceLock<Arc<TimeGuard>>,
            seen: Mutex<Vec<Transition>>,
        }
        impl Observer for Corrects {
            fn transition(&self, transition: &Transition) {
                self.seen
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(transition.clone());
                if matches!(transition, Transition::Opened(_))
                    && let Some(guard) = self.guard.get()
                {
                    // The operator corrects the clock while the anomaly is being reported.
                    self.wall.jump(120);
                    guard.tick();
                }
            }
        }
        let wall = Arc::new(ManualClock::at(START));
        let guard = Arc::new(TimeGuard::new(
            wall.clone(),
            Arc::new(ManualMonotonic::default()),
            BOUND,
        ));
        let observer = Arc::new(Corrects {
            wall: wall.clone(),
            guard: std::sync::OnceLock::new(),
            seen: Mutex::new(Vec::new()),
        });
        let _ = observer.guard.set(Arc::clone(&guard));
        guard.observe(observer.clone());
        wall.jump(-120);
        guard.tick();
        let seen = observer.seen.lock().expect("held").clone();
        assert!(
            matches!(
                seen.as_slice(),
                [Transition::Opened(_), Transition::Closed { .. }]
            ),
            "{seen:?}"
        );
        assert!(guard.anomaly().is_none());
    }

    #[test]
    fn a_step_inside_the_bound_and_a_forward_jump_are_not_anomalies() {
        let (wall, mono, guard) = guard();
        mono.advance(Duration::from_secs(100));
        wall.jump(100 - 30);
        assert!(guard.trusted_now().is_ok(), "exactly the bound");
        wall.jump(3_600);
        assert!(guard.trusted_now().is_ok(), "forward");
        assert!(guard.anomaly().is_none());
    }

    #[test]
    fn the_anomaly_closes_once_the_wall_clock_reaches_the_expected_time() {
        let (wall, mono, guard) = guard();
        let seen = Arc::new(Recorded(Mutex::new(Vec::new())));
        guard.observe(seen.clone());
        wall.jump(-120);
        guard.tick();
        let anomaly = guard.anomaly().expect("open");
        wall.jump(119);
        mono.advance(Duration::from_secs(5));
        assert!(guard.trusted_now().is_err(), "one second short");
        wall.jump(1);
        assert_eq!(guard.trusted_now(), Ok(START));
        assert_eq!(
            seen.0.lock().expect("held").as_slice(),
            &[
                Transition::Opened(anomaly.clone()),
                Transition::Closed {
                    anomaly,
                    observed: START
                }
            ]
        );
    }

    #[test]
    fn a_restart_under_a_clock_set_back_opens_the_anomaly_from_the_volume() {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-time-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let profile = permguard_core::assurance::AssuranceProfile::Development;
        {
            let volume = Volume::claim(&root, profile).expect("claimed");
            let guard = TimeGuard::open(
                Arc::new(files::FileClockMark::open(&volume).expect("the mark opens")),
                Arc::new(ManualClock::at(START)),
                Arc::new(ManualMonotonic::default()),
                BOUND,
            )
            .expect("opened");
            assert!(guard.anomaly().is_none(), "a fresh volume has no mark");
        }
        let volume = Volume::claim(&root, profile).expect("claimed again");
        let guard = TimeGuard::open(
            Arc::new(files::FileClockMark::open(&volume).expect("the mark opens")),
            Arc::new(ManualClock::at(START - 31)),
            Arc::new(ManualMonotonic::default()),
            BOUND,
        )
        .expect("opened");
        let anomaly = guard.anomaly().expect("set back across the restart");
        assert_eq!(anomaly.expected, START);
        let seen = Arc::new(Recorded(Mutex::new(Vec::new())));
        guard.observe(seen.clone());
        assert_eq!(
            seen.0.lock().expect("held").as_slice(),
            &[Transition::Opened(anomaly)],
            "an observer registered later is told"
        );
        drop((guard, volume));
        let volume = Volume::claim(&root, profile).expect("claimed a third time");
        TimeGuard::open(
            Arc::new(files::FileClockMark::open(&volume).expect("the mark opens")),
            Arc::new(ManualClock::at(START - 30)),
            Arc::new(ManualMonotonic::default()),
            BOUND,
        )
        .expect("opened")
        .trusted_now()
        .expect("inside the bound");
        drop(volume);
        let _ = std::fs::remove_dir_all(root);
    }

    /// What only the file backend can prove: a mark damaged at rest fails the start, and is
    /// never read as no mark, which would forget the check it carries.
    #[test]
    fn a_damaged_mark_fails_the_start() {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-time-damaged-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let volume = Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let mark = Arc::new(files::FileClockMark::open(&volume).expect("the mark opens"));
        mark.raise(START).expect("raised");
        let state = volume.host().subdir("state", false).expect("state");
        crate::storage::write::replace_view(
            &state,
            "CLOCK",
            crate::storage::format::VIEW,
            b"short",
        )
        .expect("a view of another length");
        assert!(matches!(mark.read(), Err(MarkError::Record(_))));
        let refused = TimeGuard::open(
            mark,
            Arc::new(ManualClock::at(START)),
            Arc::new(ManualMonotonic::default()),
            BOUND,
        )
        .expect_err("a damaged mark");
        assert!(
            refused.to_string().contains("where a wall time takes 8"),
            "{refused}"
        );
        drop(volume);
        let _ = std::fs::remove_dir_all(root);
    }

    /// The file backend passes the contract's suite, each case on a volume of its own.
    #[test]
    fn the_file_backend_keeps_the_contract() {
        let made = std::sync::atomic::AtomicUsize::new(0);
        let volumes = Mutex::new(Vec::new());
        suite::run(&|| {
            let case = made.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "permguard-host-time-suite-{case}-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            let _ = std::fs::remove_dir_all(&root);
            let volume = Volume::claim(
                &root,
                permguard_core::assurance::AssuranceProfile::Development,
            )
            .expect("claimed");
            let store = Arc::new(files::FileClockMark::open(&volume).expect("the mark opens"));
            volumes.lock().expect("held").push(volume);
            store
        });
    }

    #[test]
    fn the_mark_moves_forward_on_the_volume_as_time_passes() {
        let root = std::env::temp_dir().join(format!(
            "permguard-host-time-mark-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let profile = permguard_core::assurance::AssuranceProfile::Development;
        let volume = Volume::claim(&root, profile).expect("claimed");
        let wall = Arc::new(ManualClock::at(START));
        let mono = Arc::new(ManualMonotonic::default());
        let guard = TimeGuard::open(
            Arc::new(files::FileClockMark::open(&volume).expect("the mark opens")),
            wall.clone(),
            mono.clone(),
            BOUND,
        )
        .expect("opened");
        mono.advance(Duration::from_secs(3_600));
        wall.jump(3_600);
        guard.tick();
        let mark = files::FileClockMark::open(&volume)
            .expect("the mark opens")
            .read()
            .expect("read");
        assert_eq!(mark, Some(START + 3_600));
        drop((guard, volume));
        let _ = std::fs::remove_dir_all(root);
    }
}
