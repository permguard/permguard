// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The bounded pool a profile's partitions are evaluated on.
//!
//! # Why a profile fans out at all
//!
//! A profile is several partitions, and every one of them answers the same question: a Cedar
//! partition consulting an org chart and a Rego partition running guardrails have nothing to say to
//! each other, and neither needs the other's answer. Asked one after another, a request costs the
//! sum of them; asked together, it costs the slowest.
//!
//! # Why a pool, and not a thread per partition
//!
//! An authorization decision is measured in microseconds and an OS thread costs tens of them to
//! create. A thread per partition per request would spend more time being born than deciding, and —
//! worse — it would let a caller decide how many threads this process holds. So the threads are
//! made once, and they are **bounded**: a profile with forty partitions and ten thousand callers
//! cannot turn into forty thousand threads.
//!
//! # What the caller does while it waits
//!
//! It works. The first job runs on the calling thread and only the rest are handed out, so a
//! single-partition profile — the common one — dispatches nothing at all and costs exactly what it
//! did when the loop was sequential. The concurrency one caller can reach is therefore
//! `workers + 1`, and that is the whole of it.
//!
//! # Determinism
//!
//! Results come back **in the order the jobs were given**, whatever order they finished in. A
//! decision that depended on which partition won a race would not be a decision.
//!
//! # The queue is bounded, and a full queue is not a queue
//!
//! Work is handed out through a **bounded** channel. When it is full the submitting thread runs
//! the job itself instead of waiting for room — which is backpressure with nowhere for work to
//! accumulate: the depth of the queue is fixed, and the only other place a job can be is on a
//! thread that is already busy with it.
//!
//! An unbounded queue was the wrong shape for a decision path. A request whose transport timeout
//! has already fired releases the concurrency permit that was limiting how many of these could be
//! in flight, and the next request is admitted while the previous one's work is still queued. With
//! nothing bounding the queue, that is how a plane under load accumulates work nobody is waiting
//! for. The queue cannot grow now, and [`Query::deadline`](crate::evaluate::Query::deadline) is
//! what ends the work already running.
//!
//! # Fail-closed
//!
//! A job that panics does not take a worker with it and does not silently shorten the answer:
//! [`Fanout::run`] reports that a result is missing, and an authorization path turns a missing
//! verdict into a deny. Nothing here can turn into a permit.

use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, mpsc};

/// A unit of work, owned: the pool outlives any one request, so nothing may be borrowed from one.
type Job = Box<dyn FnOnce() + Send + 'static>;

/// The largest pool this build will build, however many cores it finds.
///
/// A PDP is not a batch job. Past a handful of threads the wins are gone and the contention is
/// not, and the number of partitions a real profile holds is small.
pub const MAX_WORKERS: usize = 8;

/// Why a fan-out could not answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lost {
    /// Which job never produced a result.
    pub index: usize,
}

impl std::fmt::Display for Lost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the evaluation of partition {} produced no answer",
            self.index
        )
    }
}

/// How many jobs may wait per worker before a submitting thread does the work itself.
///
/// Small on purpose. A deep queue only converts a latency problem into a memory one: the jobs at
/// the back belong to requests whose callers have long since been answered by a timeout.
const QUEUE_PER_WORKER: usize = 4;

/// A fixed set of worker threads, and the bounded queue they take work from.
pub struct Fanout {
    /// Guarded because the pool is shared by every thread that decides; sending is a pointer move.
    work: Mutex<mpsc::SyncSender<Job>>,
    workers: usize,
}

impl Fanout {
    /// Builds a pool of at most this many workers.
    ///
    /// # What happens when a thread will not start
    ///
    /// It is counted, and the pool reports what it actually has. A pool that claimed workers it
    /// never got would accept jobs into a bounded queue nobody reads: the first few sends fill the
    /// buffer, the next blocks, and the caller waits for a result that cannot arrive. A decision
    /// path that hangs is worse than one that is slow, and far worse than one that says so.
    ///
    /// A pool with **no** workers is not an error either: [`Fanout::run`] then does every job on
    /// the calling thread. Sequential rather than parallel, which is a real degradation and a
    /// legitimate answer — the alternative on a machine that cannot spawn a thread is refusing to
    /// decide at all.
    pub fn with_workers(workers: usize) -> Self {
        let workers = workers.max(1);
        let (sender, receiver) = mpsc::sync_channel::<Job>(workers * QUEUE_PER_WORKER);
        let receiver = Arc::new(Mutex::new(receiver));

        let mut started = 0usize;
        for _ in 0..workers {
            let receiver = Arc::clone(&receiver);
            // Detached on purpose: the pool lives as long as the process, and a worker that is
            // waiting for work holds nothing.
            std::thread::Builder::new()
                .name("permguard-evaluate".to_owned())
                .spawn(move || {
                    loop {
                        let job = {
                            let Ok(queue) = receiver.lock() else {
                                // The queue is poisoned only if a worker panicked while holding
                                // it, which it cannot: the lock is released before a job runs.
                                return;
                            };
                            queue.recv()
                        };
                        let Ok(job) = job else {
                            return;
                        };
                        // A policy engine should not panic. If one does, it takes the request
                        // down and not the pool: the caller hears a missing answer and denies.
                        let _ = std::panic::catch_unwind(AssertUnwindSafe(job));
                    }
                })
                .map(|_| started += 1)
                .unwrap_or_else(|error| {
                    // Said once, plainly. A pool quietly smaller than it was asked for is a plane
                    // that got slower for a reason nothing recorded.
                    tracing::warn!(
                        event.name = "evaluate.worker_not_started",
                        component = "languages",
                        error = %error,
                        "an evaluation worker could not be started"
                    );
                });
        }
        if started == 0 {
            tracing::warn!(
                event.name = "evaluate.pool_empty",
                component = "languages",
                asked = workers,
                "no evaluation worker could be started: every partition will be evaluated on the \
                 calling thread, one after another"
            );
        }

        Self {
            work: Mutex::new(sender),
            workers: started,
        }
    }

    /// The pool this process decides on.
    ///
    /// One per process, sized to the machine and capped: it is an execution resource, like the
    /// allocator, and not a collaborator anybody swaps — there is no behaviour to choose, only
    /// threads to share. A test that needs its own builds one with [`Fanout::with_workers`].
    pub fn shared() -> &'static Fanout {
        static SHARED: LazyLock<Fanout> = LazyLock::new(|| {
            let cores = std::thread::available_parallelism().map_or(2, std::num::NonZero::get);

            Fanout::with_workers(cores.min(MAX_WORKERS))
        });

        &SHARED
    }

    /// How many workers this pool holds.
    pub fn workers(&self) -> usize {
        self.workers
    }

    /// Runs every job, and answers in the order they were given.
    ///
    /// The first runs here, on the calling thread; the rest are queued. So one caller reaches at
    /// most `workers + 1` concurrent jobs, and a caller with one job queues nothing.
    ///
    /// A pool with no workers runs everything here, in order. Slower, and an answer.
    pub fn run<T: Send + 'static>(
        &self,
        jobs: Vec<Box<dyn FnOnce() -> T + Send + 'static>>,
    ) -> Result<Vec<T>, Lost> {
        let count = jobs.len();
        if count == 0 {
            return Ok(Vec::new());
        }
        if self.workers == 0 {
            // Nothing is listening on the queue, so nothing is sent to it: sending would fill a
            // bounded buffer and then block for ever on a result that cannot come.
            return Ok(jobs.into_iter().map(|job| job()).collect());
        }

        let mut jobs = jobs.into_iter();
        // Taken before anything is dispatched: this one is the caller's own work.
        let Some(mine) = jobs.next() else {
            return Ok(Vec::new());
        };

        let (sender, results) = mpsc::channel::<(usize, T)>();
        // What the queue had no room for. Run here, after dispatching the rest, so the workers are
        // already busy while this thread catches up — and so that a full pool degrades to "the
        // caller does the work" rather than to "the caller waits for a slot".
        let mut mine_too: Vec<Box<dyn FnOnce() + Send + 'static>> = Vec::new();
        for (offset, job) in jobs.enumerate() {
            let index = offset + 1;
            let sender = sender.clone();
            let queued = Box::new(move || {
                let value = job();
                // A closed receiver means the caller is gone, which cannot happen while it is
                // blocked below — but a send that cannot be delivered is not an error worth
                // panicking a worker over.
                let _ = sender.send((index, value));
            });
            if let Err(refused) = self.submit(queued) {
                mine_too.push(refused);
            }
        }
        // The caller's own handle, dropped so the loop below ends when the last job is done.
        drop(sender);

        let mut slots: Vec<Option<T>> = Vec::with_capacity(count);
        slots.push(Some(mine()));
        slots.resize_with(count, || None);
        for job in mine_too {
            job();
        }

        for (index, value) in results {
            if let Some(slot) = slots.get_mut(index) {
                *slot = Some(value);
            }
        }

        let mut answered = Vec::with_capacity(count);
        for (index, slot) in slots.into_iter().enumerate() {
            // A panicked job leaves a hole. Reported, never skipped: an answer one partition
            // short is not the answer to this request.
            answered.push(slot.ok_or(Lost { index })?);
        }

        Ok(answered)
    }

    /// Queues a job, or answers that the queue is full.
    ///
    /// Never blocks waiting for room: a caller holding a slot while the queue drains is a caller
    /// that has turned a bounded queue back into an unbounded wait.
    fn submit(&self, job: Job) -> Result<(), Job> {
        // A poisoned queue means a panic while holding the lock, which nothing here does — the
        // lock is released before a job runs. If it ever happened, the caller does the work.
        let Ok(sender) = self.work.lock() else {
            return Err(job);
        };

        sender.try_send(job).map_err(|failed| match failed {
            mpsc::TrySendError::Full(job) | mpsc::TrySendError::Disconnected(job) => job,
        })
    }
}

/// How many jobs are running right now, for a test that has to prove it.
#[derive(Debug, Default)]
pub struct Watch {
    running: AtomicUsize,
    highest: AtomicUsize,
}

impl Watch {
    /// Records one job starting, and remembers the high-water mark.
    pub fn entered(&self) -> usize {
        let running = self.running.fetch_add(1, Ordering::SeqCst) + 1;
        self.highest.fetch_max(running, Ordering::SeqCst);

        running
    }

    /// Records one job finishing.
    pub fn left(&self) {
        self.running.fetch_sub(1, Ordering::SeqCst);
    }

    /// The most that ever ran at once.
    pub fn highest(&self) -> usize {
        self.highest.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use std::sync::Barrier;
    use std::time::Duration;

    #[test]
    fn two_partitions_are_evaluated_at_the_same_time() {
        // Not "both were called" — that a sequential loop also satisfies. Each job waits on a
        // barrier the other must reach, so the pair completes only if they overlap in time. A
        // sequential implementation deadlocks here and the test times out rather than passing.
        let pool = Fanout::with_workers(2);
        let barrier = Arc::new(Barrier::new(2));
        let jobs: Vec<Box<dyn FnOnce() -> usize + Send + 'static>> = (0..2usize)
            .map(|index| {
                let barrier = Arc::clone(&barrier);
                Box::new(move || {
                    barrier.wait();

                    index
                }) as Box<dyn FnOnce() -> usize + Send + 'static>
            })
            .collect();

        assert_eq!(pool.run(jobs).expect("both answered"), vec![0, 1]);
    }

    #[test]
    fn the_answers_come_back_in_the_order_they_were_asked() {
        let pool = Fanout::with_workers(4);
        let jobs: Vec<Box<dyn FnOnce() -> usize + Send + 'static>> = (0..8usize)
            .map(|index| {
                Box::new(move || {
                    // The later the job, the sooner it finishes: a result order that followed
                    // completion would come back reversed.
                    std::thread::sleep(Duration::from_millis(((8 - index) * 4) as u64));

                    index
                }) as Box<dyn FnOnce() -> usize + Send + 'static>
            })
            .collect();

        assert_eq!(
            pool.run(jobs).expect("all answered"),
            (0..8usize).collect::<Vec<usize>>()
        );
    }

    #[test]
    fn no_more_than_the_pool_plus_the_caller_ever_run_at_once() {
        let pool = Fanout::with_workers(2);
        let watch = Arc::new(Watch::default());
        let jobs: Vec<Box<dyn FnOnce() -> usize + Send + 'static>> = (0..16)
            .map(|_| {
                let watch = Arc::clone(&watch);
                Box::new(move || {
                    let running = watch.entered();
                    std::thread::sleep(Duration::from_millis(5));
                    watch.left();

                    running
                }) as Box<dyn FnOnce() -> usize + Send + 'static>
            })
            .collect();

        pool.run(jobs).expect("all answered");
        assert!(
            watch.highest() <= pool.workers() + 1,
            "{} ran at once with {} workers and one caller",
            watch.highest(),
            pool.workers()
        );
    }

    /// The queue has a depth, and work that does not fit is done rather than accumulated.
    ///
    /// This is the shape that matters under load: a request whose transport timeout has fired
    /// releases the concurrency permit that was limiting how many of these could be in flight, and
    /// the next request is admitted while the previous one's work is still outstanding. With an
    /// unbounded queue that is how a plane accumulates work nobody is waiting for. Here the queue
    /// cannot grow past its bound — everything else is either running or already done.
    #[test]
    fn work_that_does_not_fit_in_the_queue_is_done_rather_than_queued() {
        let pool = Fanout::with_workers(2);
        let held = Arc::new(Barrier::new(3));
        let watch = Arc::new(Watch::default());

        // Two jobs that sit on both workers until this thread joins them, so the queue is the only
        // place anything else could go — and it is bounded.
        let count = 2 + pool.workers() * QUEUE_PER_WORKER + 8;
        let jobs: Vec<Box<dyn FnOnce() -> usize + Send + 'static>> = (0..count)
            .map(|index| {
                let watch = Arc::clone(&watch);
                let held = Arc::clone(&held);
                Box::new(move || {
                    watch.entered();
                    if index == 1 || index == 2 {
                        held.wait();
                    }
                    watch.left();

                    index
                }) as Box<dyn FnOnce() -> usize + Send + 'static>
            })
            .collect();

        let answered = std::thread::spawn(move || pool.run(jobs));
        // Let the two blockers take both workers, then release everything.
        std::thread::sleep(Duration::from_millis(50));
        held.wait();

        let answered = answered
            .join()
            .expect("the caller finished")
            .expect("all answered");
        assert_eq!(
            answered,
            (0..count).collect::<Vec<usize>>(),
            "every job ran, in order, whether it was queued or done by the caller"
        );
    }

    /// A submission that does not fit comes back to the caller instead of waiting for room.
    #[test]
    fn a_full_queue_hands_the_work_back_rather_than_blocking() {
        let pool = Fanout::with_workers(1);
        let held = Arc::new(Barrier::new(2));
        let blocker = Arc::clone(&held);

        // Occupy the only worker.
        assert!(
            pool.submit(Box::new(move || {
                blocker.wait();
            }))
            .is_ok()
        );

        // Fill the queue to its bound.
        for _ in 0..(pool.workers() * QUEUE_PER_WORKER) {
            let _ = pool.submit(Box::new(|| {}));
        }

        // The next one does not fit, and is handed straight back — not blocked on.
        let refused = pool.submit(Box::new(|| {}));
        assert!(
            refused.is_err(),
            "a full queue answers immediately; waiting for room is an unbounded wait wearing a \
             bounded queue's clothes"
        );

        held.wait();
    }

    #[test]
    fn a_job_that_panics_is_a_missing_answer_and_not_a_short_one() {
        let pool = Fanout::with_workers(2);
        let jobs: Vec<Box<dyn FnOnce() -> usize + Send + 'static>> = vec![
            Box::new(|| 0),
            Box::new(|| panic!("an engine came apart")),
            Box::new(|| 2),
        ];

        assert_eq!(pool.run(jobs).expect_err("one is missing").index, 1);
        // And the pool is still usable: the worker caught it.
        let again: Vec<Box<dyn FnOnce() -> usize + Send + 'static>> =
            vec![Box::new(|| 7), Box::new(|| 8)];
        assert_eq!(pool.run(again).expect("still working"), vec![7, 8]);
    }

    #[test]
    fn one_job_is_run_by_the_caller_and_queued_nowhere() {
        // A pool with no workers at all still answers a single job, because that job was never
        // going to be dispatched: the caller runs it. This is the single-partition profile, and
        // it costs exactly what a sequential loop cost.
        let pool = Fanout::with_workers(1);
        let here = std::thread::current().id();
        let jobs: Vec<Box<dyn FnOnce() -> std::thread::ThreadId + Send + 'static>> =
            vec![Box::new(|| std::thread::current().id())];

        assert_eq!(pool.run(jobs).expect("answered"), vec![here]);
    }

    /// A pool that got no workers answers on the calling thread rather than waiting for ever.
    ///
    /// Constructed by hand, because a machine that cannot spawn a thread is not something a test
    /// can arrange — and the property under test is what `run` does when `workers` is zero, which
    /// is exactly the state a failed spawn leaves behind.
    #[test]
    fn a_pool_with_no_workers_runs_everything_locally_instead_of_hanging() {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Job>(1);
        // The receiver is dropped: nothing will ever take a job off this queue, which is the shape
        // a pool of zero workers has.
        drop(receiver);
        let empty = Fanout {
            work: Mutex::new(sender),
            workers: 0,
        };

        let jobs: Vec<Box<dyn FnOnce() -> usize + Send + 'static>> = (0..5usize)
            .map(|n| Box::new(move || n * 2) as Box<dyn FnOnce() -> usize + Send>)
            .collect();

        assert_eq!(
            empty
                .run(jobs)
                .expect("a pool with no workers still answers"),
            vec![0, 2, 4, 6, 8],
            "and in the order the jobs were given"
        );
    }

    /// The pool reports what it actually has, so a caller's concurrency assumption is not a lie.
    #[test]
    fn a_pool_reports_the_workers_it_started() {
        let pool = Fanout::with_workers(3);

        assert_eq!(pool.workers(), 3);
    }
}
