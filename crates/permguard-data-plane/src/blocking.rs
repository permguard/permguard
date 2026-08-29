// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Running blocking work under an async runtime, with a bound on how much of it there can be.
//!
//! # Why a bound, when `spawn_blocking` already exists
//!
//! A journal append is a write, an `fsync`, and a wait on a condition variable; a history replay is
//! a file scan; a policy evaluation is arithmetic. None of that yields, so none of it may run on a
//! runtime worker: a worker inside an `fsync` is a worker not polling anything, and enough of them
//! is a process whose health endpoint stops answering while its disk is busy.
//!
//! `tokio::task::spawn_blocking` moves the work off the workers, which is the first half. The half
//! it does not do is refuse. Its pool queues without limit, so a plane under more load than its
//! disk can take does not slow down — it accumulates, and every queued task holds whatever the
//! caller was holding. What looks like backpressure is a queue growing until memory decides.
//!
//! So the bound is here, and it is a bound on *concurrency*, not a queue: a permit is taken before
//! the work is handed over, and when none is free the caller is refused immediately with an error
//! it can return. Refusing is the honest answer — the plane is at capacity, saying so now is worth
//! more than saying it later — and it is fail-closed: no permit, no work, no answer invented.
//!
//! # What it deliberately does not do
//!
//! It does not order anything. Ordering within a ledger is the journal's sequencer's job and stays
//! there; this only decides how many pieces of blocking work exist at once, across every ledger.
//! Two ledgers are unrelated and both may hold permits; two submissions to one ledger are ordered
//! by the sequencer whichever permit they got.

use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use permguard_core::metrics::{Label, Metric, Metrics, SECONDS as BUCKETS};

/// How many pieces of blocking work may be in flight at once.
const IN_FLIGHT: Metric = Metric::gauge(
    "permguard_blocking_in_flight",
    "Blocking operations currently running, against the configured bound.",
);

/// The bound itself, so a dashboard can draw the ceiling beside the line.
const CAPACITY: Metric = Metric::gauge(
    "permguard_blocking_capacity",
    "How many blocking operations may run at once.",
);

/// Refusals. The number worth alerting on: it is the plane saying it is at capacity.
const REFUSED: Metric = Metric::counter(
    "permguard_blocking_refused_total",
    "Blocking operations refused because the bound was reached.",
);

/// How long the work itself took, once it had a permit.
const SECONDS: Metric = Metric::histogram(
    "permguard_blocking_seconds",
    "How long one blocking operation ran.",
    BUCKETS,
);

/// Why a piece of blocking work produced no answer.
#[derive(Debug)]
pub enum Refused {
    /// The bound was reached. The plane is busy, not broken.
    AtCapacity(AtCapacity),
    /// The work never finished: the runtime is going down, or it unwound.
    ///
    /// Kept distinct from [`Refused::AtCapacity`] because the two mean opposite things to whoever
    /// is looking — one is load, the other is a fault — and answering both the same way would hide
    /// the second inside the first.
    Failed(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AtCapacity(held) => write!(out, "{held}"),
            Self::Failed(why) => write!(out, "a blocking operation did not finish: {why}"),
        }
    }
}

impl std::error::Error for Refused {}

/// The plane is doing as much blocking work as it is allowed to.
///
/// Carried rather than logged where it happens: the caller knows which surface it is answering and
/// what that surface's refusal looks like, and this type is only the fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtCapacity {
    /// The bound that was reached, for the message the caller builds.
    pub capacity: usize,
}

impl std::fmt::Display for AtCapacity {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            out,
            "this plane is already running {} blocking operations, which is its configured bound",
            self.capacity
        )
    }
}

impl std::error::Error for AtCapacity {}

/// A bounded place to run blocking work.
#[derive(Debug, Clone)]
pub struct Blocking {
    permits: Arc<Semaphore>,
    running: Arc<AtomicUsize>,
    capacity: usize,
    metrics: Metrics,
}

/// The one blocking budget shared by every request path in this data plane.
static SHARED: OnceLock<Blocking> = OnceLock::new();

/// The process-wide pool, composed from the deployment's configured bound.
pub fn shared(context: &permguard_core::ServerContext<'_>) -> Blocking {
    SHARED
        .get_or_init(|| Blocking::new(context.config().max_blocking(), context.metrics().clone()))
        .clone()
}

/// A permit whose metrics follow the work rather than the awaiting request.
///
/// `spawn_blocking` work continues when its future is dropped. Keeping the
/// decrement here makes the gauge recover on the blocking thread even when an
/// HTTP timeout or disconnected client no longer reaches the code after
/// `.await`.
struct Permit {
    permit: Option<OwnedSemaphorePermit>,
    running: Arc<AtomicUsize>,
    metrics: Metrics,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let left = self.running.fetch_sub(1, Ordering::AcqRel) - 1;
        self.metrics.set(&IN_FLIGHT, &[], left as f64);
        // Release only after publishing the decrement. A new admission then
        // observes the lower count and publishes its own increment.
        drop(self.permit.take());
    }
}

impl Blocking {
    /// A pool of `capacity` concurrent operations.
    ///
    /// A capacity of zero would refuse everything, which is never what a configuration means, so it
    /// is read as one: a plane that can do one thing at a time is slow, and a plane that can do
    /// nothing is broken.
    pub fn new(capacity: usize, metrics: Metrics) -> Self {
        let capacity = capacity.max(1);
        metrics.set(&CAPACITY, &[], capacity as f64);

        Self {
            permits: Arc::new(Semaphore::new(capacity)),
            running: Arc::new(AtomicUsize::new(0)),
            capacity,
            metrics,
        }
    }

    /// The bound this was built with.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many operations are running right now.
    pub fn in_flight(&self) -> usize {
        self.running.load(Ordering::Acquire)
    }

    /// Runs `work` off the runtime's workers, or refuses because the bound is reached.
    ///
    /// The permit is taken *before* the work is handed over and held until it finishes, so the
    /// gauge is the truth rather than an estimate, and the refusal happens here rather than in a
    /// queue nobody can see.
    pub async fn run<T, F>(&self, labels: &[Label<'_>], work: F) -> Result<T, Refused>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = self.permit(labels).map_err(Refused::AtCapacity)?;
        let started = std::time::Instant::now();
        let done = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await;

        match done {
            Ok(outcome) => {
                self.metrics
                    .observe(&SECONDS, labels, started.elapsed().as_secs_f64());

                Ok(outcome)
            }
            // The pool itself failed — the runtime is shutting down, or the work unwound. Both are
            // the caller's to report, and neither is "at capacity".
            Err(error) => Err(Refused::Failed(error.to_string())),
        }
    }

    /// Takes a permit, or reports that there is none.
    fn permit(&self, labels: &[Label<'_>]) -> Result<Permit, AtCapacity> {
        match Arc::clone(&self.permits).try_acquire_owned() {
            Ok(permit) => {
                let running = self.running.fetch_add(1, Ordering::AcqRel) + 1;
                self.metrics.set(&IN_FLIGHT, &[], running as f64);

                Ok(Permit {
                    permit: Some(permit),
                    running: Arc::clone(&self.running),
                    metrics: self.metrics.clone(),
                })
            }
            Err(_) => {
                self.metrics.count(&REFUSED, labels);

                Err(AtCapacity {
                    capacity: self.capacity,
                })
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn pool(capacity: usize) -> Blocking {
        Blocking::new(capacity, Metrics::none())
    }

    /// Work that fits under the bound all runs, and runs at once.
    ///
    /// The concurrency is the point rather than the completion: a pool that ran them one after
    /// another would also finish, and would also be wrong.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn work_within_the_bound_runs_together() {
        let pool = pool(4);
        let peak = Arc::new(AtomicUsize::new(0));
        let running = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..4 {
            let (pool, peak, running) = (pool.clone(), Arc::clone(&peak), Arc::clone(&running));
            handles.push(tokio::spawn(async move {
                pool.run(&[], move || {
                    let now = running.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    std::thread::sleep(std::time::Duration::from_millis(50));
                    running.fetch_sub(1, Ordering::SeqCst);
                })
                .await
            }));
        }
        for handle in handles {
            handle.await.expect("the task joins").expect("it ran");
        }

        assert!(
            peak.load(Ordering::SeqCst) > 1,
            "the pool ran everything one at a time"
        );
    }

    /// At the bound, the next caller is refused rather than queued.
    ///
    /// This is the property the whole type exists for: `spawn_blocking` on its own would have
    /// accepted this work and held it in a queue nobody can see or measure, and the plane would
    /// have looked healthy while its latency grew without limit.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn work_beyond_the_bound_is_refused_and_not_queued() {
        let pool = pool(1);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let occupied = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.run(&[], move || held.recv().ok()).await })
        };
        // Wait for the one permit to actually be taken.
        for _ in 0..200 {
            if pool.in_flight() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(pool.in_flight(), 1, "the first operation holds the permit");

        let refused = pool.run(&[], || ()).await;
        assert!(
            matches!(refused, Err(Refused::AtCapacity(held)) if held.capacity == 1),
            "a caller at the bound is refused immediately: {refused:?}"
        );

        drop(release);
        occupied.await.expect("the task joins").expect("it ran");
        // And the permit comes back, so the refusal was not permanent.
        assert!(pool.run(&[], || ()).await.is_ok());
        assert_eq!(pool.in_flight(), 0);
    }

    /// A permit is returned even when the work unwinds.
    ///
    /// Otherwise one panicking operation would shrink the pool for the life of the process, and a
    /// plane would degrade towards refusing everything for a reason nothing reports.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_permit_comes_back_when_the_work_unwinds() {
        let pool = pool(1);
        let failed = pool.run(&[], || panic!("the work unwinds")).await;
        assert!(
            matches!(failed, Err(Refused::Failed(_))),
            "an unwound operation is a fault, not capacity: {failed:?}"
        );
        assert_eq!(pool.in_flight(), 0, "the permit was returned");
        assert!(
            pool.run(&[], || 7).await.is_ok(),
            "and the pool still works"
        );
    }

    /// Cancelling the waiter does not leak either the permit or its gauge.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cancelled_waiters_release_capacity_when_their_work_finishes() {
        let pool = pool(1);
        let (release, held) = std::sync::mpsc::channel::<()>();
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.run(&[], move || held.recv().ok()).await })
        };
        for _ in 0..200 {
            if pool.in_flight() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(pool.in_flight(), 1);

        waiter.abort();
        assert_eq!(
            pool.in_flight(),
            1,
            "dropping the future does not pretend its blocking work stopped"
        );
        drop(release);
        for _ in 0..200 {
            if pool.in_flight() == 0 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(pool.in_flight(), 0, "the guard publishes completion itself");
    }

    /// Zero is read as one: a configuration never means "refuse everything".
    #[test]
    fn a_bound_of_zero_is_read_as_one() {
        assert_eq!(pool(0).capacity(), 1);
    }
}
