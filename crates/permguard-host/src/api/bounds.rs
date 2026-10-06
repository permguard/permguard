// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Per-principal rate and concurrency (the envelope's *bounds*): one principal cannot hold the
//! Host listener for everybody else. The transport bounds the body, the request count and the
//! time per surface; this bounds each principal, after it is authenticated, so an anonymous
//! flood is the transport's problem and never fills these tables.
//!
//! A token bucket per principal for the rate, a counter per principal for the requests in
//! flight. The bounds are fixed in this release; a setting arrives when a deployment needs one.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use permguard_core::authz::Principal;
use permguard_core::{ErrorClass, codes};

use super::Refusal;

/// Requests one principal may have in flight at once.
pub const CONCURRENT_PER_PRINCIPAL: u32 = 16;
/// Sustained requests per second one principal may make.
pub const RATE_PER_SECOND: f64 = 50.0;
/// How far above the rate a principal may burst.
pub const BURST: f64 = 100.0;
/// Principals remembered before idle entries are dropped.
const REMEMBERED: usize = 4096;

#[derive(Debug)]
struct Slot {
    in_flight: u32,
    tokens: f64,
    refilled: Instant,
}

/// The bounds of every principal, shared by both transports.
#[derive(Debug)]
pub struct Bounds {
    slots: Mutex<HashMap<String, Slot>>,
    concurrent: u32,
    rate: f64,
    burst: f64,
}

impl Default for Bounds {
    fn default() -> Self {
        Self::new(CONCURRENT_PER_PRINCIPAL, RATE_PER_SECOND, BURST)
    }
}

impl Bounds {
    /// Bounds of `concurrent` requests in flight and `rate` per second with `burst` above it.
    pub fn new(concurrent: u32, rate: f64, burst: f64) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            concurrent,
            rate,
            burst,
        }
    }

    /// Admits one request of `principal`, or refuses it as `principal_bound_exceeded`.
    pub fn admit(&self, principal: &Principal) -> Result<Permit<'_>, Refusal> {
        self.admit_at(principal, Instant::now())
    }

    fn admit_at(&self, principal: &Principal, now: Instant) -> Result<Permit<'_>, Refusal> {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if slots.len() >= REMEMBERED {
            // A principal idle long enough to have refilled its bucket is forgotten: its next
            // request starts from a full bucket anyway, which is exactly its state now.
            let full_after = std::time::Duration::from_secs_f64(self.burst / self.rate);
            slots.retain(|_, slot| {
                slot.in_flight > 0 || now.saturating_duration_since(slot.refilled) < full_after
            });
        }
        let slot = slots
            .entry(principal.as_str().to_owned())
            .or_insert_with(|| Slot {
                in_flight: 0,
                tokens: self.burst,
                refilled: now,
            });
        let elapsed = now.saturating_duration_since(slot.refilled).as_secs_f64();
        slot.tokens = (slot.tokens + elapsed * self.rate).min(self.burst);
        slot.refilled = now;
        if slot.in_flight >= self.concurrent {
            return Err(Refusal::new(
                ErrorClass::Unavailable,
                codes::host::PRINCIPAL_BOUND_EXCEEDED,
                format!(
                    "this principal already has {} requests in flight",
                    self.concurrent
                ),
            ));
        }
        if slot.tokens < 1.0 {
            return Err(Refusal::new(
                ErrorClass::Unavailable,
                codes::host::PRINCIPAL_BOUND_EXCEEDED,
                "this principal is sending faster than its bound allows; retry shortly",
            ));
        }
        slot.tokens -= 1.0;
        slot.in_flight += 1;
        Ok(Permit {
            bounds: self,
            principal: principal.as_str().to_owned(),
        })
    }

    fn release(&self, principal: &str) {
        let mut slots = self
            .slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(slot) = slots.get_mut(principal) {
            slot.in_flight = slot.in_flight.saturating_sub(1);
        }
    }
}

/// One admitted request; dropping it releases the concurrency slot.
#[derive(Debug)]
pub struct Permit<'a> {
    bounds: &'a Bounds,
    principal: String,
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.bounds.release(&self.principal);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::time::Duration;

    use super::*;

    fn alice() -> Principal {
        Principal::new("alice").expect("a principal")
    }

    #[test]
    fn concurrency_is_bounded_per_principal_and_released_on_drop() {
        let bounds = Bounds::new(2, 1000.0, 1000.0);
        let now = Instant::now();
        let first = bounds.admit_at(&alice(), now).expect("first");
        let _second = bounds.admit_at(&alice(), now).expect("second");
        let third = bounds
            .admit_at(&alice(), now)
            .expect_err("third is one too many");
        assert_eq!(
            third.error().expect("refusal").code(),
            codes::host::PRINCIPAL_BOUND_EXCEEDED
        );
        assert_eq!(third.error().expect("refusal").http_status(), 503);
        // Another principal has its own slots.
        let _bob = bounds
            .admit_at(&Principal::new("bob").expect("p"), now)
            .expect("bob is admitted");
        drop(first);
        let _again = bounds.admit_at(&alice(), now).expect("released");
    }

    #[test]
    fn idle_principals_are_forgotten_once_the_table_is_full() {
        let bounds = Bounds::new(1, 10.0, 10.0);
        let start = Instant::now();
        for index in 0..REMEMBERED {
            let name = Principal::new(format!("p{index}")).expect("a principal");
            drop(bounds.admit_at(&name, start).expect("admitted"));
        }
        assert_eq!(bounds.slots.lock().expect("lock").len(), REMEMBERED);
        // Later than a full refill: everybody idle is forgotten, the newcomer is remembered.
        let later = start + Duration::from_secs(2);
        drop(
            bounds
                .admit_at(&Principal::new("newcomer").expect("p"), later)
                .expect("admitted"),
        );
        assert_eq!(bounds.slots.lock().expect("lock").len(), 1);
    }

    #[test]
    fn the_rate_refills_with_time() {
        let bounds = Bounds::new(100, 10.0, 2.0);
        let now = Instant::now();
        drop(bounds.admit_at(&alice(), now).expect("one"));
        drop(bounds.admit_at(&alice(), now).expect("two"));
        let refused = bounds
            .admit_at(&alice(), now)
            .expect_err("the burst is spent");
        assert_eq!(
            refused.error().expect("refusal").code(),
            codes::host::PRINCIPAL_BOUND_EXCEEDED
        );
        let later = now + Duration::from_millis(150);
        drop(
            bounds
                .admit_at(&alice(), later)
                .expect("1.5 tokens came back"),
        );
        assert!(bounds.admit_at(&alice(), later).is_err());
    }
}
