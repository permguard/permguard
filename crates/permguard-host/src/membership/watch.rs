// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Watches: one long-lived request per task session, the member's (WP-4.4; owner decisions of
//! 2026-10-11).
//!
//! A member sends a `watch` message with the counter it holds per key; the session then belongs
//! to the watch. A handler publishes hints through the [`Hub`]; each watch whose task, selector
//! and resource cover the hint queues it, coalesced by key, the newest counter winning. The
//! transport sends what a watch yields: the hints queued, or a heartbeat when nothing came for
//! [`HEARTBEAT`]. A queue past [`MAX_WATCH_KEYS`] keys ends the watch `watch_overflow`; a fence,
//! a membership no longer active or the lease's expiry end it too. A hint carries no policy and
//! grants nothing: the member runs its ordinary round.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError, Weak};
use std::time::Duration;

use permguard_core::authz::{Resource, Selector};
use permguard_core::codes;

use super::record::{
    Lease, MAX_WATCH_KEYS, Status, TaskAnswer, TaskType, WatchEvent, WatchHint, WatchRequest,
};
use crate::session::{Refusal, Watching};

/// How long a quiet watch waits before it sends a heartbeat (owner decision).
pub const HEARTBEAT: Duration = Duration::from_secs(15);

#[derive(Debug, Default)]
struct Pending {
    /// The counter the member holds, or was last sent, per key.
    known: BTreeMap<String, u64>,
    /// What is queued, per key: the newest head and counter.
    queued: BTreeMap<String, (String, u64)>,
    overflowed: bool,
}

/// One watch's queue, as the hub delivers to it.
pub struct Queue {
    task_type: TaskType,
    selector: Selector,
    resource: Resource,
    pending: Mutex<Pending>,
    wake: Mutex<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl std::fmt::Debug for Queue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Queue")
            .field("task_type", &self.task_type)
            .field("resource", &self.resource)
            .finish_non_exhaustive()
    }
}

impl Queue {
    fn covers(&self, task_type: TaskType, resource: &Resource) -> bool {
        task_type == self.task_type
            && self.selector.contains(resource)
            && Selector::under(self.resource.clone()).contains(resource)
    }

    fn offer(&self, hint: &WatchHint) {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending
            .known
            .get(&hint.key)
            .is_some_and(|known| *known >= hint.counter)
            || pending
                .queued
                .get(&hint.key)
                .is_some_and(|(_, queued)| *queued >= hint.counter)
        {
            return;
        }
        if !pending.queued.contains_key(&hint.key) && pending.queued.len() >= MAX_WATCH_KEYS {
            pending.overflowed = true;
        } else {
            pending
                .queued
                .insert(hint.key.clone(), (hint.head.clone(), hint.counter));
        }
        drop(pending);
        if let Some(wake) = self
            .wake
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
        {
            wake();
        }
    }

    /// Takes what is queued; `None` once the queue overflowed.
    #[doc(hidden)]
    pub fn take(&self) -> Option<Vec<WatchHint>> {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if pending.overflowed {
            return None;
        }
        let queued = std::mem::take(&mut pending.queued);
        let hints: Vec<WatchHint> = queued
            .into_iter()
            .map(|(key, (head, counter))| WatchHint { key, head, counter })
            .collect();
        for hint in &hints {
            pending.known.insert(hint.key.clone(), hint.counter);
        }
        // What the watch remembers is bounded as its queue is: past it, the member runs an
        // ordinary round.
        if pending.known.len() > MAX_WATCH_KEYS {
            pending.overflowed = true;
        }
        Some(hints)
    }
}

/// Where handlers publish hints, and where watches are registered.
#[derive(Debug, Default)]
pub struct Hub {
    queues: Mutex<Vec<Weak<Queue>>>,
}

impl Hub {
    /// Offers `hint`, about `resource`, to every live watch of `task_type` covering it.
    pub fn publish(&self, task_type: TaskType, resource: &Resource, hint: &WatchHint) {
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        queues.retain(|queue| queue.strong_count() > 0);
        for queue in queues.iter().filter_map(Weak::upgrade) {
            if queue.covers(task_type, resource) {
                queue.offer(hint);
            }
        }
    }

    /// Registers a watch of `task_type` over `lease`'s selector and resource, from `request`'s
    /// positions.
    #[doc(hidden)]
    pub fn subscribe(
        &self,
        task_type: TaskType,
        lease: &Lease,
        request: &WatchRequest,
    ) -> Result<Arc<Queue>, String> {
        let resource = Resource::parse(&lease.resource).map_err(|error| error.to_string())?;
        let queue = Arc::new(Queue {
            task_type,
            selector: lease.selector.clone(),
            resource,
            pending: Mutex::new(Pending {
                known: request.positions.iter().cloned().collect(),
                ..Pending::default()
            }),
            wake: Mutex::new(None),
        });
        let mut queues = self.queues.lock().unwrap_or_else(PoisonError::into_inner);
        queues.retain(|held| held.strong_count() > 0);
        queues.push(Arc::downgrade(&queue));
        Ok(queue)
    }

    /// How many watches are live, for the tests.
    pub fn live(&self) -> usize {
        self.queues
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .filter(|queue| queue.strong_count() > 0)
            .count()
    }
}

/// What a watch checks before it sends: the session's lease and the membership it serves.
pub(crate) trait Fence: Send + Sync {
    /// `Err` when the watch must end: a refusal with its code.
    fn check(&self) -> Result<(), Refusal>;
}

/// A task session that became a watch.
pub(crate) struct Watch {
    pub(crate) queue: Arc<Queue>,
    pub(crate) request_id: String,
    pub(crate) fence: Box<dyn Fence>,
    pub(crate) heartbeat: Duration,
}

impl Watch {
    fn event(&self, hints: Vec<WatchHint>) -> Result<Vec<u8>, Refusal> {
        let body = WatchEvent { hints }.encode().map_err(|error| Refusal {
            code: codes::common::UNAVAILABLE,
            reason: error.0,
        })?;
        TaskAnswer {
            request_id: self.request_id.clone(),
            body,
        }
        .encode()
        .map_err(|error| Refusal {
            code: codes::common::UNAVAILABLE,
            reason: error.0,
        })
    }

    fn ready(&self) -> Result<Option<Vec<u8>>, Refusal> {
        self.fence.check()?;
        match self.queue.take() {
            None => Err(Refusal {
                code: codes::host::WATCH_OVERFLOW,
                reason: "the watch's queue overflowed: run an ordinary round".to_owned(),
            }),
            Some(hints) if hints.is_empty() => Ok(None),
            Some(hints) => self.event(hints).map(Some),
        }
    }
}

impl Watching for Watch {
    fn poll(&mut self) -> Result<Option<Vec<u8>>, Refusal> {
        self.ready()
    }

    fn heartbeat(&mut self) -> Result<Vec<u8>, Refusal> {
        self.fence.check()?;
        self.event(Vec::new())
    }

    fn on_hint(&self, wake: Box<dyn Fn() + Send + Sync>) {
        *self
            .queue
            .wake
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(wake);
    }

    fn interval(&self) -> Duration {
        self.heartbeat
    }
}

/// The fence of a coordinator's watch: the membership active at the lease's epoch, the lease
/// running.
pub(crate) struct LeaseFence {
    pub(crate) store: Arc<super::Store>,
    pub(crate) time: Arc<crate::time::TimeGuard>,
    pub(crate) lease: Lease,
}

impl Fence for LeaseFence {
    fn check(&self) -> Result<(), Refusal> {
        let ended = |code: &'static str, reason: &str| Refusal {
            code,
            reason: reason.to_owned(),
        };
        let held = self
            .store
            .membership(&self.lease.membership_id)
            .ok_or_else(|| ended(codes::host::MEMBERSHIP_UNKNOWN, "the membership is gone"))?;
        if held.held_epoch.is_some() {
            return Err(ended(codes::host::MEMBERSHIP_HELD, "held for review"));
        }
        let Some((manifest, ..)) = held.manifest else {
            return Err(ended(
                codes::host::MEMBERSHIP_TRANSITION_REFUSED,
                "no manifest",
            ));
        };
        if manifest.epoch != self.lease.epoch {
            return Err(ended(
                codes::host::EPOCH_STALE,
                "the membership moved to another epoch",
            ));
        }
        if manifest.status != Status::Active {
            return Err(ended(
                codes::host::MEMBERSHIP_TRANSITION_REFUSED,
                "the membership is no longer active",
            ));
        }
        if self.time.now_secs() >= self.lease.expires_at {
            return Err(ended(codes::host::LEASE_EXPIRED, "the lease expired"));
        }
        Ok(())
    }
}
