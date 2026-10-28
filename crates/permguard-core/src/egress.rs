// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The no-network decision invariant, enforced where a connection is made (TS-4).
//!
//! A decision may read local files, memory and a local HSM; it must not call a Control Plane, a
//! key-discovery endpoint, a remote KMS, an event store or an identity service. Everything a
//! decision needs is resolved before the request: a verified mirror, a compiled partition, a grant
//! snapshot, a local key. The invariant is easy to state and easy to break by accident — a cache
//! miss that "just fetches", a signer that moved to a KMS — so it is not left to review.
//!
//! Two halves:
//!
//! | Half      | Where                                                                       |
//! | --------- | --------------------------------------------------------------------------- |
//! | the scope | [`decision`] around the decision path, [`Carried`] onto the threads it uses |
//! | the check | [`check`] before each outbound client's connection and name resolution      |
//!
//! The clients that check, and the ones that need not:
//!
//! | Client                                   | Checks at                                       |
//! | ---------------------------------------- | ----------------------------------------------- |
//! | the control client over HTTP (`connect`) | before the name is resolved                     |
//! | the control client over gRPC (`call`)    | before the channel dials, on its first call     |
//! | the Host peer client                     | before the name is resolved and the socket dials |
//! | the Vault Transit custody (`send`)       | on the caller's thread, before the job is queued |
//! | the telemetry exporter                   | never: it runs on its own threads, off the path |
//!
//! A new outbound client calls [`check`] before it reaches the network.
//!
//! On the decision path the check refuses: the connection is never made, the caller gets an error
//! it already knows how to turn into a refusal, and the decision fails closed. The refusal is
//! counted in `permguard_decision_path_egress_total` — a number that is zero on a correct plane, in
//! production as in a test, and that the serving gate reads off the release candidate after its
//! run. Outside the scope — the mirror loop, the shippers, the CLI — the check costs one
//! thread-local read and changes nothing.

use std::cell::Cell;
use std::future::Future;
use std::pin::Pin;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use crate::metrics::{Metric, Metrics};

/// What a refused call was reaching for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// A name resolution.
    Resolve,
    /// A Control Plane or catalog endpoint.
    ControlPlane,
    /// A peer Host's listener.
    HostPeer,
    /// A remote key-management service.
    Kms,
}

impl Target {
    /// The word a message and a log name it by.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Resolve => "name resolution",
            Self::ControlPlane => "Control Plane",
            Self::HostPeer => "peer Host",
            Self::Kms => "remote KMS",
        }
    }
}

/// Network calls refused on the decision path. Zero on a correct plane.
pub const REFUSED: Metric = Metric::counter(
    "permguard_decision_path_egress_total",
    "Network calls refused because they were made on the decision path: zero on a correct plane.",
);

thread_local! {
    /// Set while this thread runs decision work: a poll of a decision's future, or blocking work
    /// a decision handed over.
    static ON_THREAD: Cell<usize> = const { Cell::new(0) };
}

/// Marks the thread for as long as it lives, and restores it when dropped — even when the work it
/// covers unwinds, because a runtime's threads are reused, and one left marked would refuse the
/// mirror loop's next connection.
struct Entered;

impl Entered {
    fn enter() -> Self {
        ON_THREAD.with(|depth| depth.set(depth.get() + 1));
        Self
    }
}

impl Drop for Entered {
    fn drop(&mut self) {
        ON_THREAD.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

/// A future whose every poll runs on the decision path, on whichever worker polls it.
struct Scoped<F> {
    inner: Pin<Box<F>>,
}

impl<F: Future> Future for Scoped<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<F::Output> {
        let _entered = Entered::enter();
        self.inner.as_mut().poll(context)
    }
}

/// Every refusal since the process started, whatever metrics were installed: what a test reads.
static REFUSALS: AtomicU64 = AtomicU64::new(0);

/// Where refusals are counted, once the composition installed it.
static INSTALLED: OnceLock<Metrics> = OnceLock::new();

/// Counts refusals in `metrics` from now on, the series published at zero so a reader can tell
/// "none" from "not counted". The first installation wins: one process, one count.
pub fn install(metrics: Metrics) {
    if INSTALLED.set(metrics.clone()).is_ok() {
        metrics.add(&REFUSED, &[], 0.0);
    }
}

/// Runs `future` as the decision path: any outbound call it makes while it is polled is refused.
///
/// The mark is set for each poll on the thread that polls, not for the task: a future that moves
/// between workers carries it, and a worker that goes on to poll something else does not. Work
/// the decision spawns as a task of its own is outside it; work it hands a blocking thread is
/// carried with [`carried`].
pub async fn decision<F: Future>(future: F) -> F::Output {
    Scoped {
        inner: Box::pin(future),
    }
    .await
}

/// Whether the caller is on the decision path.
pub fn on_decision_path() -> bool {
    ON_THREAD.with(|depth| depth.get() > 0)
}

/// Whether the decision path's scope was set where work was handed off, to be restored where it
/// runs: a blocking thread does not inherit the task-local of the task that spawned the work.
#[derive(Debug, Clone, Copy)]
#[must_use]
pub struct Carried(bool);

/// The scope of the caller, to carry onto another thread.
pub fn carried() -> Carried {
    Carried(on_decision_path())
}

impl Carried {
    /// Runs `work` under the scope that was carried.
    pub fn run<T>(self, work: impl FnOnce() -> T) -> T {
        if !self.0 {
            return work();
        }
        let _entered = Entered::enter();
        work()
    }
}

/// Every refusal since the process started.
pub fn refusals() -> u64 {
    REFUSALS.load(Ordering::Acquire)
}

/// Asks to reach `target`: refused on the decision path, allowed anywhere else.
///
/// Call it before the connection or the resolution, never after: a refusal must mean nothing left
/// the process.
pub fn check(target: Target) -> std::io::Result<()> {
    if !on_decision_path() {
        return Ok(());
    }
    REFUSALS.fetch_add(1, Ordering::AcqRel);
    if let Some(metrics) = INSTALLED.get() {
        metrics.count(&REFUSED, &[]);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "a {} call on the decision path was refused: a decision must not reach the network",
            target.as_str()
        ),
    ))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn outside_the_decision_path_every_call_is_allowed() {
        assert!(!on_decision_path());
        assert!(check(Target::ControlPlane).is_ok());
    }

    #[tokio::test]
    async fn on_the_decision_path_a_call_is_refused_and_counted() {
        let before = refusals();
        let refused = decision(async { check(Target::Resolve) }).await;
        let error = refused.expect_err("refused on the decision path");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("name resolution"), "{error}");
        assert!(refusals() > before);
        // And the scope ends with the decision.
        assert!(check(Target::Resolve).is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_scope_follows_the_decision_onto_a_blocking_thread_and_leaves_it() {
        let refused = decision(async {
            let carried = carried();
            tokio::task::spawn_blocking(move || carried.run(|| check(Target::Kms)))
                .await
                .expect("joins")
        })
        .await;
        assert!(
            refused.is_err(),
            "the blocking half of a decision is the decision path"
        );

        // A thread that ran decision work and is reused for something else is not marked.
        let carried = carried();
        let allowed = tokio::task::spawn_blocking(move || carried.run(|| check(Target::Kms)))
            .await
            .expect("joins");
        assert!(allowed.is_ok());
    }

    #[test]
    fn a_decision_that_panics_while_polled_leaves_no_mark() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.block_on(decision(async { panic!("the decision unwinds") }))
        }));
        assert!(unwound.is_err());
        assert!(!on_decision_path(), "the poll's mark went with the unwind");
    }

    #[test]
    fn a_thread_that_unwound_inside_the_scope_is_not_left_marked() {
        let unwound = std::panic::catch_unwind(|| {
            Carried(true).run(|| panic!("the work unwinds"));
        });
        assert!(unwound.is_err());
        assert!(!on_decision_path());
    }
}
