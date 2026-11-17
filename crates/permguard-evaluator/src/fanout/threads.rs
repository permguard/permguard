// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one place this package starts a thread, and it is compiled only with the `threads`
//! feature: the kernel by itself reaches no operating system interface, so a build that decides
//! on the caller's own thread, on a desktop, a phone or one day in a browser, links none of this.

use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, mpsc};

use super::{Job, QUEUE_PER_WORKER};

/// The machine's parallelism, when it can be read.
pub(super) fn cores() -> usize {
    std::thread::available_parallelism().map_or(2, std::num::NonZero::get)
}

/// Starts at most `workers` threads on one bounded queue, and answers the queue's sending half
/// with how many threads actually started.
pub(super) fn start(workers: usize) -> (mpsc::SyncSender<Job>, usize) {
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

    (sender, started)
}
