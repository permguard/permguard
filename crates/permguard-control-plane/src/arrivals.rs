// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A tail that waits for its next record (iteration 04, WP-33.1; `3-control-plane/3` Reads,
//! `7-contracts/5` Request).
//!
//! | Rule              | Here                                                                                   |
//! | ----------------- | -------------------------------------------------------------------------------------- |
//! | bound             | `wait_ms` clamped to [`MAX_WAIT`], 25 s, under a usual proxy's idle timeout            |
//! | wake              | an ingest that acknowledged a batch moves the counter; every waiting read reads again   |
//! | bounded waiters   | at most [`MAX_WAITERS`] reads wait at once; past them a read is answered at once        |
//! | a lost wake       | costs a read its wait at most: it then answers what it holds                            |
//! | authorization     | the read itself is authorized at every reading, so a wait reveals nothing new           |
//!
//! The counter says only that something arrived somewhere: a woken read reads its own scope again,
//! and goes on waiting when nothing of it came.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

/// The longest a read waits, whatever it asks.
pub const MAX_WAIT: Duration = Duration::from_secs(25);

/// The most reads waiting at once on one plane.
pub const MAX_WAITERS: usize = 256;

/// The arrivals one consumer announces, and the reads waiting for them.
#[derive(Debug)]
pub struct Arrivals {
    arrived: tokio::sync::watch::Sender<u64>,
    waiting: Arc<tokio::sync::Semaphore>,
}

impl Default for Arrivals {
    fn default() -> Self {
        Self {
            arrived: tokio::sync::watch::channel(0).0,
            waiting: Arc::new(tokio::sync::Semaphore::new(MAX_WAITERS)),
        }
    }
}

impl Arrivals {
    /// What the consumer calls once an ingest acknowledged a batch.
    pub fn wake(self: &Arc<Self>) -> permguard_host::composition::Wake {
        let arrivals = Arc::downgrade(self);
        Arc::new(move || {
            if let Some(arrivals) = arrivals.upgrade() {
                arrivals.arrived.send_modify(|count| *count = count.wrapping_add(1));
            }
        })
    }

    /// The longest a read waits, in milliseconds: what discovery publishes as `max_wait_ms`.
    pub fn max_wait_ms() -> u64 {
        u64::try_from(MAX_WAIT.as_millis()).unwrap_or(u64::MAX)
    }

    /// Reads with `read` until what it answers `holds` something, or `wait` passes: then the last
    /// answer. A zero wait, or no room among the waiting reads, reads once.
    pub async fn read_waiting<T, R, F>(&self, wait: Duration, mut read: R, holds: F) -> T
    where
        R: FnMut() -> std::pin::Pin<Box<dyn Future<Output = T> + Send>>,
        F: Fn(&T) -> bool,
    {
        let wait = wait.min(MAX_WAIT);
        let permit = if wait.is_zero() {
            None
        } else {
            Arc::clone(&self.waiting).try_acquire_owned().ok()
        };
        let mut arrived = self.arrived.subscribe();
        let answer = read().await;
        let Some(_permit) = permit else {
            return answer;
        };
        let deadline = tokio::time::Instant::now() + wait;
        let mut answer = answer;
        loop {
            if holds(&answer) {
                return answer;
            }
            match tokio::time::timeout_at(deadline, arrived.changed()).await {
                Ok(Ok(())) => {
                    arrived.borrow_and_update();
                    answer = read().await;
                }
                // The wait is over, or the consumer is gone: what is held is the answer.
                Ok(Err(_)) | Err(_) => return answer,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn reader(held: &Arc<AtomicU64>) -> impl FnMut() -> std::pin::Pin<Box<dyn Future<Output = u64> + Send>> {
        let held = Arc::clone(held);
        move || {
            let held = Arc::clone(&held);
            Box::pin(async move { held.load(Ordering::SeqCst) })
        }
    }

    /// A waiting read answers as soon as an arrival brings it something, not at its deadline.
    #[tokio::test]
    async fn a_waiting_read_answers_when_a_record_arrives() {
        let arrivals = Arc::new(Arrivals::default());
        let held = Arc::new(AtomicU64::new(0));
        let wake = arrivals.wake();
        let arriving = Arc::clone(&held);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            arriving.store(3, Ordering::SeqCst);
            wake();
        });
        let started = std::time::Instant::now();
        let answer = arrivals
            .read_waiting(Duration::from_secs(10), reader(&held), |count| *count > 0)
            .await;
        assert_eq!(answer, 3);
        assert!(started.elapsed() < Duration::from_secs(2), "{:?}", started.elapsed());
    }

    /// An arrival of nothing this read keeps it waiting; its deadline answers what it holds.
    #[tokio::test]
    async fn a_read_woken_for_another_scope_goes_on_waiting_until_its_deadline() {
        let arrivals = Arc::new(Arrivals::default());
        let held = Arc::new(AtomicU64::new(0));
        let wake = arrivals.wake();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(20)).await;
            wake();
        });
        let started = std::time::Instant::now();
        let answer = arrivals
            .read_waiting(Duration::from_millis(300), reader(&held), |count| *count > 0)
            .await;
        assert_eq!(answer, 0);
        assert!(started.elapsed() >= Duration::from_millis(300));
    }

    /// No wait asked, or none past the bound: one read, at once.
    #[tokio::test]
    async fn without_a_wait_a_read_answers_at_once_and_a_wait_is_bounded() {
        let arrivals = Arc::new(Arrivals::default());
        let held = Arc::new(AtomicU64::new(0));
        let started = std::time::Instant::now();
        let answer = arrivals
            .read_waiting(Duration::ZERO, reader(&held), |count| *count > 0)
            .await;
        assert_eq!(answer, 0);
        assert!(started.elapsed() < Duration::from_millis(100));
        assert_eq!(Arrivals::max_wait_ms(), 25_000);
    }
}
