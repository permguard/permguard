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
//! # Pools, so none starves another (TS-3, P5)
//!
//! A policy evaluation is CPU that does not yield; a decision record is an append and the group
//! flush that settles it; a load is a few reads of the ledger's state. Sharing one bound let a
//! stalled disk hold every permit while evaluations, which needed only a core, were refused — and,
//! under `required` evidence, let the records waiting for their flush take every permit the next
//! request's load needed. So each kind of work has its own permits:
//!
//! | Pool           | Runs                                                     | Bound                                 |
//! | -------------- | -------------------------------------------------------- | ------------------------------------- |
//! | [`evaluation`] | policy evaluation                                        | the Host's cores, and a bounded queue |
//! | [`evidence`]   | decision-record appends and the group flush they wait on | `max_blocking`, no queue              |
//! | [`shared`]     | ledger loads, temporal staging and replay                | `max_blocking`, no queue              |
//!
//! The evaluation pool runs as many evaluations as there are cores — more at once would only make
//! each slower — and lets a burst wait in a queue of its own size, each waiter no longer than its
//! request's deadline; past the queue it refuses at once. The disk pools keep their immediate
//! refusal: a disk that is not keeping up does not get faster by being queued for.
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

/// The metrics of one pool.
#[derive(Debug)]
struct Instruments {
    /// What the pool's messages call its work.
    work: &'static str,
    in_flight: Metric,
    capacity: Metric,
    refused: Metric,
    seconds: Metric,
    /// How many wait for a slot, for a pool with a queue.
    queued: Option<Metric>,
}

/// The storage pool: disk work, refused at its bound.
static STORAGE: Instruments = Instruments {
    work: "blocking",
    // How many pieces of blocking work are in flight.
    in_flight: Metric::gauge(
        "permguard_blocking_in_flight",
        "Blocking operations currently running, against the configured bound.",
    ),
    // The bound itself, so a dashboard can draw the ceiling beside the line.
    capacity: Metric::gauge(
        "permguard_blocking_capacity",
        "How many blocking operations may run at once.",
    ),
    // Refusals. The number worth alerting on: it is the plane saying it is at capacity.
    refused: Metric::counter(
        "permguard_blocking_refused_total",
        "Blocking operations refused because the bound was reached.",
    ),
    // How long the work itself took, once it had a permit.
    seconds: Metric::histogram(
        "permguard_blocking_seconds",
        "How long one blocking operation ran.",
        BUCKETS,
    ),
    queued: None,
};

/// The evidence pool: decision records and the flush they wait on, refused at its bound.
static EVIDENCE: Instruments = Instruments {
    work: "evidence",
    in_flight: Metric::gauge(
        "permguard_evidence_in_flight",
        "Decision records being appended or waiting for their group flush.",
    ),
    capacity: Metric::gauge(
        "permguard_evidence_capacity",
        "How many decision records may be appended or awaiting their flush at once.",
    ),
    refused: Metric::counter(
        "permguard_evidence_refused_total",
        "Decision records refused because the evidence pool's bound was reached.",
    ),
    seconds: Metric::histogram(
        "permguard_evidence_seconds",
        "How long one decision record took to append and settle.",
        BUCKETS,
    ),
    queued: None,
};

/// The evaluation pool: CPU work, as many at once as the cores, a burst queued in front.
static EVALUATION: Instruments = Instruments {
    work: "evaluation",
    in_flight: Metric::gauge(
        "permguard_evaluation_in_flight",
        "Policy evaluations currently running, against the evaluation pool's size.",
    ),
    capacity: Metric::gauge(
        "permguard_evaluation_capacity",
        "How many policy evaluations may run at once.",
    ),
    refused: Metric::counter(
        "permguard_evaluation_refused_total",
        "Policy evaluations refused: the queue was full, or the request's deadline passed waiting.",
    ),
    seconds: Metric::histogram(
        "permguard_evaluation_seconds",
        "How long one policy evaluation ran, once it had a slot.",
        BUCKETS,
    ),
    queued: Some(Metric::gauge(
        "permguard_evaluation_queued",
        "Policy evaluations waiting for a slot.",
    )),
};

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
    /// How many may wait beyond it; zero for a pool that refuses at the bound.
    pub queue: usize,
    /// What the pool runs, as its message names it.
    work: &'static str,
    /// Whether the refusal came from a deadline passing in the queue rather than a full queue.
    timed_out: bool,
}

impl std::fmt::Display for AtCapacity {
    fn fmt(&self, out: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match (self.queue, self.timed_out) {
            (0, _) => write!(
                out,
                "this plane is already running {} {} operations, which is its configured bound",
                self.capacity, self.work
            ),
            (queue, false) => write!(
                out,
                "this plane is already running {} {} operations with {queue} more waiting, which \
                 is its configured bound",
                self.capacity, self.work
            ),
            (_, true) => write!(
                out,
                "this plane's {} {} slots stayed busy until the request's deadline",
                self.capacity, self.work
            ),
        }
    }
}

impl std::error::Error for AtCapacity {}

/// A bounded place to run blocking work.
#[derive(Debug, Clone)]
pub struct Blocking {
    /// The slots work runs in.
    permits: Arc<Semaphore>,
    /// Slots and queue together, for a pool with a queue: what admission takes first.
    admitted: Option<Arc<Semaphore>>,
    running: Arc<AtomicUsize>,
    waiting: Arc<AtomicUsize>,
    capacity: usize,
    queue: usize,
    metrics: Metrics,
    instruments: &'static Instruments,
}

/// The storage pool shared by every request path in this data plane.
static SHARED: OnceLock<Blocking> = OnceLock::new();

/// The evaluation pool shared by every request path in this data plane.
static EVALUATING: OnceLock<Blocking> = OnceLock::new();

/// The evidence pool shared by every request path in this data plane.
static RECORDING: OnceLock<Blocking> = OnceLock::new();

/// The process-wide evidence pool: as many decision records at once as `max_blocking`, apart from
/// the loads and replay [`shared`] bounds.
pub fn evidence(context: &permguard_core::PlaneContext<'_>) -> Blocking {
    RECORDING
        .get_or_init(|| {
            Blocking::evidence(context.config().max_blocking(), context.metrics().clone())
        })
        .clone()
}

/// The process-wide storage pool, composed from the deployment's configured bound.
pub fn shared(context: &permguard_core::PlaneContext<'_>) -> Blocking {
    SHARED
        .get_or_init(|| Blocking::new(context.config().max_blocking(), context.metrics().clone()))
        .clone()
}

/// The process-wide evaluation pool, sized to the configured slots (the Host's cores unless set)
/// and queue.
pub fn evaluation(context: &permguard_core::PlaneContext<'_>) -> Blocking {
    EVALUATING
        .get_or_init(|| {
            Blocking::evaluation(
                context.config().evaluation_concurrency(),
                context.config().evaluation_queue(),
                context.metrics().clone(),
            )
        })
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
    /// The admission a queued pool took first; released with the slot.
    admission: Option<OwnedSemaphorePermit>,
    running: Arc<AtomicUsize>,
    metrics: Metrics,
    instruments: &'static Instruments,
}

impl Drop for Permit {
    fn drop(&mut self) {
        let left = self.running.fetch_sub(1, Ordering::AcqRel) - 1;
        self.metrics
            .set(&self.instruments.in_flight, &[], left as f64);
        // Release only after publishing the decrement. A new admission then
        // observes the lower count and publishes its own increment.
        drop(self.permit.take());
        drop(self.admission.take());
    }
}

/// A waiter in the queue, counted for as long as it waits — a caller that gives up while waiting
/// drops it, and the count follows.
struct Waiting {
    waiting: Arc<AtomicUsize>,
    metrics: Metrics,
    instruments: &'static Instruments,
}

impl Waiting {
    fn new(pool: &Blocking) -> Self {
        let now = pool.waiting.fetch_add(1, Ordering::AcqRel) + 1;
        if let Some(queued) = &pool.instruments.queued {
            pool.metrics.set(queued, &[], now as f64);
        }
        Self {
            waiting: Arc::clone(&pool.waiting),
            metrics: pool.metrics.clone(),
            instruments: pool.instruments,
        }
    }
}

impl Drop for Waiting {
    fn drop(&mut self) {
        let left = self.waiting.fetch_sub(1, Ordering::AcqRel) - 1;
        if let Some(queued) = &self.instruments.queued {
            self.metrics.set(queued, &[], left as f64);
        }
    }
}

impl Blocking {
    /// A storage pool of `capacity` concurrent operations, refusing at the bound.
    ///
    /// A capacity of zero would refuse everything, which is never what a configuration means, so it
    /// is read as one: a plane that can do one thing at a time is slow, and a plane that can do
    /// nothing is broken.
    pub fn new(capacity: usize, metrics: Metrics) -> Self {
        Self::built(capacity, 0, metrics, &STORAGE)
    }

    /// An evidence pool of `capacity` decision records at once, refusing at the bound.
    pub fn evidence(capacity: usize, metrics: Metrics) -> Self {
        Self::built(capacity, 0, metrics, &EVIDENCE)
    }

    /// An evaluation pool: `capacity` evaluations at once, `queue` more waiting for a slot.
    pub fn evaluation(capacity: usize, queue: usize, metrics: Metrics) -> Self {
        Self::built(capacity, queue, metrics, &EVALUATION)
    }

    fn built(
        capacity: usize,
        queue: usize,
        metrics: Metrics,
        instruments: &'static Instruments,
    ) -> Self {
        let capacity = capacity.max(1);
        metrics.set(&instruments.capacity, &[], capacity as f64);

        Self {
            permits: Arc::new(Semaphore::new(capacity)),
            admitted: (queue > 0).then(|| Arc::new(Semaphore::new(capacity + queue))),
            running: Arc::new(AtomicUsize::new(0)),
            waiting: Arc::new(AtomicUsize::new(0)),
            capacity,
            queue,
            metrics,
            instruments,
        }
    }

    /// The bound this was built with.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many may wait beyond the bound.
    pub fn queue(&self) -> usize {
        self.queue
    }

    /// How many operations are running right now.
    pub fn in_flight(&self) -> usize {
        self.running.load(Ordering::Acquire)
    }

    /// How many operations are waiting for a slot right now.
    pub fn waiting(&self) -> usize {
        self.waiting.load(Ordering::Acquire)
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
        self.run_until(labels, None, work).await
    }

    /// [`Blocking::run`], waiting in the queue no later than `deadline` when the pool has one.
    pub async fn run_until<T, F>(
        &self,
        labels: &[Label<'_>],
        deadline: Option<std::time::Instant>,
        work: F,
    ) -> Result<T, Refused>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let permit = self
            .permit(labels, deadline)
            .await
            .map_err(Refused::AtCapacity)?;
        let started = std::time::Instant::now();
        let done = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work()
        })
        .await;

        match done {
            Ok(outcome) => {
                self.metrics.observe(
                    &self.instruments.seconds,
                    labels,
                    started.elapsed().as_secs_f64(),
                );

                Ok(outcome)
            }
            // The pool itself failed — the runtime is shutting down, or the work unwound. Both are
            // the caller's to report, and neither is "at capacity".
            Err(error) => Err(Refused::Failed(error.to_string())),
        }
    }

    fn at_capacity(&self, labels: &[Label<'_>], timed_out: bool) -> AtCapacity {
        self.metrics.count(&self.instruments.refused, labels);

        AtCapacity {
            capacity: self.capacity,
            queue: self.queue,
            work: self.instruments.work,
            timed_out,
        }
    }

    /// Takes a slot — after a place in the queue, for a pool with one — or reports that there is
    /// none.
    async fn permit(
        &self,
        labels: &[Label<'_>],
        deadline: Option<std::time::Instant>,
    ) -> Result<Permit, AtCapacity> {
        let (permit, admission) = match &self.admitted {
            None => match Arc::clone(&self.permits).try_acquire_owned() {
                Ok(permit) => (permit, None),
                Err(_) => return Err(self.at_capacity(labels, false)),
            },
            Some(admitted) => {
                let Ok(admission) = Arc::clone(admitted).try_acquire_owned() else {
                    return Err(self.at_capacity(labels, false));
                };
                let permit = match Arc::clone(&self.permits).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        let _waiting = Waiting::new(self);
                        let slot = Arc::clone(&self.permits).acquire_owned();
                        let slot = match deadline {
                            Some(deadline) => {
                                tokio::time::timeout_at(deadline.into(), slot).await.ok()
                            }
                            None => Some(slot.await),
                        };
                        match slot {
                            // A slot that frees as the deadline passes is no use to the request:
                            // it would only run an evaluation that refuses every partition.
                            Some(Ok(_))
                                if deadline.is_some_and(|deadline| {
                                    std::time::Instant::now() >= deadline
                                }) =>
                            {
                                return Err(self.at_capacity(labels, true));
                            }
                            Some(Ok(permit)) => permit,
                            // The semaphore is never closed; a closed one is a pool going away,
                            // and refusing is the honest answer to that too.
                            Some(Err(_)) => return Err(self.at_capacity(labels, false)),
                            None => return Err(self.at_capacity(labels, true)),
                        }
                    }
                };
                (permit, Some(admission))
            }
        };
        let running = self.running.fetch_add(1, Ordering::AcqRel) + 1;
        self.metrics
            .set(&self.instruments.in_flight, &[], running as f64);

        Ok(Permit {
            permit: Some(permit),
            admission,
            running: Arc::clone(&self.running),
            metrics: self.metrics.clone(),
            instruments: self.instruments,
        })
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

    /// Takes the pool's only slot with work that runs until `release` drops, and waits until it
    /// is taken.
    async fn occupy(
        pool: &Blocking,
    ) -> (
        std::sync::mpsc::Sender<()>,
        tokio::task::JoinHandle<Result<Option<()>, Refused>>,
    ) {
        let (release, held) = std::sync::mpsc::channel::<()>();
        let occupied = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.run(&[], move || held.recv().ok()).await })
        };
        for _ in 0..200 {
            if pool.in_flight() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(pool.in_flight(), 1, "the first operation holds the slot");
        (release, occupied)
    }

    /// TS-3: a burst wider than the evaluation slots waits in the queue and runs when a slot
    /// frees; past the queue the next caller is refused at once, and told how much was waiting.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn an_evaluation_burst_waits_in_its_queue_and_is_refused_past_it() {
        let pool = Blocking::evaluation(1, 1, Metrics::none());
        let (release, occupied) = occupy(&pool).await;

        let queued = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.run(&[], || 7).await })
        };
        for _ in 0..200 {
            if pool.waiting() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(
            pool.waiting(),
            1,
            "the second caller waits instead of being refused"
        );

        let refused = pool.run(&[], || ()).await;
        match refused {
            Err(Refused::AtCapacity(held)) => {
                assert_eq!((held.capacity, held.queue), (1, 1));
                assert!(held.to_string().contains("1 more waiting"), "{held}");
            }
            other => panic!("a caller past the queue is refused at once: {other:?}"),
        }

        drop(release);
        occupied.await.expect("joins").expect("it ran");
        assert_eq!(queued.await.expect("joins").expect("the queued one ran"), 7);
        assert_eq!((pool.in_flight(), pool.waiting()), (0, 0));
    }

    /// A waiter whose deadline passes before a slot frees is refused, and gives its place back.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_waiter_whose_deadline_passes_is_refused_and_leaves_the_queue() {
        let pool = Blocking::evaluation(1, 1, Metrics::none());
        let (release, occupied) = occupy(&pool).await;

        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(50);
        let started = std::time::Instant::now();
        let refused = pool.run_until(&[], Some(deadline), || ()).await;
        match refused {
            Err(Refused::AtCapacity(held)) => {
                assert!(held.to_string().contains("deadline"), "{held}");
            }
            other => panic!("a waiter past its deadline is refused: {other:?}"),
        }
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(pool.waiting(), 0, "the waiter left the queue");

        // Its place in the queue came back: the next caller waits rather than being refused.
        let queued = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.run(&[], || 1).await })
        };
        for _ in 0..200 {
            if pool.waiting() == 1 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        assert_eq!(pool.waiting(), 1);
        drop(release);
        occupied.await.expect("joins").expect("it ran");
        assert_eq!(queued.await.expect("joins").expect("ran"), 1);
    }

    /// The storage pool keeps refusing at its bound — a disk that is not keeping up does not get
    /// faster by being queued for — and holding all of it leaves the evaluation pool untouched.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_full_storage_pool_neither_queues_nor_takes_the_evaluation_pool() {
        let storage = pool(1);
        let evaluation = Blocking::evaluation(1, 4, Metrics::none());
        let (release, occupied) = occupy(&storage).await;

        assert!(matches!(
            storage.run(&[], || ()).await,
            Err(Refused::AtCapacity(held)) if held.queue == 0
        ));
        assert_eq!(storage.waiting(), 0);
        assert_eq!(
            evaluation
                .run(&[], || 3)
                .await
                .expect("evaluation still runs"),
            3
        );

        drop(release);
        occupied.await.expect("joins").expect("it ran");
    }
}
