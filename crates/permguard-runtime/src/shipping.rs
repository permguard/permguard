// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The evidence-aware drain and its recovery (WP-5.8, owner decisions of 2026-10-15).
//!
//! ```text
//! drain   ─▶ ship until no stream is behind its required subscriptions, or the deadline
//!         ─▶ shipped: complete
//!         ─▶ not shipped: each stream behind marked `unshipped` in its STATE, incomplete (75)
//! start   ─▶ in Load, one pass on the marked streams within the drain budget
//!         ─▶ a mark that remains keeps the Host `degraded: evidence`
//! ```
//!
//! The engine never truncates past an acknowledgement, so a stream left behind keeps every record
//! the next process ships.
//!
//! Shipping itself is continuous (iteration 04, `1-architecture/6` Shipping): [`drive`] runs one
//! shipper per Host, woken by every durable append, which ships after a short linger what the
//! memberships' ship tasks and the local ones have due. The membership pass only asks it to
//! reconcile.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};

use permguard_core::Drained;
use permguard_host::api::HostApi;

/// How long a drain waits before asking a coordinator again that took nothing.
const RETRY: Duration = Duration::from_millis(250);

/// The first wait before a round goes again over streams still behind, and the longest: a
/// deferral's backoff or a coordinator that does not answer keeps them so.
const BEHIND_FIRST: Duration = Duration::from_millis(250);
const BEHIND_LONGEST: Duration = Duration::from_secs(5);

/// Appends that end a linger early: a batch's worth, `max_batch_records` as the chart and the lab
/// sign it.
const FULL_BATCH: u64 = 1000;

/// The window the freshness objective is judged over, and the most samples it keeps.
const FRESHNESS_WINDOW: Duration = Duration::from_secs(300);
const FRESHNESS_SAMPLES: usize = 10_000;

/// The capability a freshness past its objective degrades the Host on: `degraded: freshness`.
pub const FRESHNESS: &str = "freshness";

/// From the wake of an append to the acknowledgement of everything due then (iteration 04,
/// `1-architecture/6` Freshness).
pub const SHIP_FRESHNESS: permguard_core::metrics::Metric =
    permguard_core::metrics::Metric::histogram(
        "permguard_stream_ship_freshness_seconds",
        "Seconds from an append waking the shipper to the acknowledgement of everything due then.",
        &[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 300.0],
    );

/// The ship sessions kept open.
pub const SHIP_SESSIONS: permguard_core::metrics::Metric = permguard_core::metrics::Metric::gauge(
    "permguard_stream_ship_sessions",
    "Ship sessions the member keeps open across batches.",
);

/// The shipper's rounds, by how they ended: `ok` caught up, `partial` shipped and still behind,
/// `deferred` behind with nothing shipped, `empty` nothing due.
pub const SHIP_ROUNDS: permguard_core::metrics::Metric = permguard_core::metrics::Metric::counter(
    "permguard_stream_ship_rounds_total",
    "Shipping rounds, by outcome.",
);

/// What the shipper reports to, beside the Host it ships for.
#[derive(Clone)]
pub struct Observing {
    pub health: permguard_core::Health,
    pub metrics: permguard_core::Metrics,
    /// `objectives.evidence_freshness`, when declared.
    pub objective: Option<Duration>,
}

/// The freshness samples of the window, oldest first, and whether the objective is passed now.
#[derive(Debug, Default)]
pub struct Freshness {
    samples: std::collections::VecDeque<(Duration, Duration)>,
}

impl Freshness {
    /// Keeps `sample`, taken at `now` on the monotonic clock, and forgets what left the window.
    pub fn observe(&mut self, now: Duration, sample: Duration) {
        self.samples.push_back((now, sample));
        while self
            .samples
            .front()
            .is_some_and(|(at, _)| now.saturating_sub(*at) > FRESHNESS_WINDOW)
            || self.samples.len() > FRESHNESS_SAMPLES
        {
            self.samples.pop_front();
        }
    }

    /// The p99 of the window, `None` without a sample.
    pub fn p99(&self) -> Option<Duration> {
        let mut sorted: Vec<Duration> = self.samples.iter().map(|(_, sample)| *sample).collect();
        if sorted.is_empty() {
            return None;
        }
        sorted.sort();
        let index = (sorted.len() * 99).div_ceil(100).saturating_sub(1);
        sorted.get(index).copied()
    }
}

/// The component the drain and the recovery log as.
const COMPONENT: &str = "host";

/// Ships until no stream is behind its required subscriptions or `deadline`; a stream still
/// behind is marked `unshipped` and the drain is incomplete. A drain that cannot read or mark its
/// streams fails: it is never reported complete.
pub async fn drain(api: &HostApi, deadline: Instant) -> Result<Drained> {
    if !api.ships_streams() {
        return Ok(Drained::Complete);
    }
    // An identity reset retired the rings that ship (BUG-0163): nothing is shipped, but what is
    // behind is marked, so the next start, under the new identity, reports it.
    if api.identity_retired() {
        return mark_behind(api, true);
    }
    // A subscription is kept by the first pass that ships to it: every live membership's are
    // kept now, and one pass runs, before a stream is judged shipped (after the review).
    api.register_subscriptions()
        .map_err(|error| anyhow!("keeping the subscriptions to ship: {error}"))?;
    let mut passed = false;
    loop {
        let behind = api
            .shipping_behind()
            .map_err(|error| anyhow!("reading the streams to ship: {error}"))?;
        if passed && !behind {
            api.settle_unshipped()
                .map_err(|error| anyhow!("settling the unshipped marks: {error}"))?;
            return Ok(Drained::Complete);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        let first = !passed;
        passed = true;
        match tokio::time::timeout(left, api.ship_due()).await {
            // A coordinator deferring or unreachable is asked again shortly.
            Ok(0) if behind || !first => tokio::time::sleep(left.min(RETRY)).await,
            Ok(_) => {}
            Err(_) => break,
        }
    }
    // A deadline the listeners' drain already spent still marks what is behind, so the next
    // process recovers it (BUG-0222): only the shipping pass is skipped, never the marks.
    mark_behind(api, passed)
}

/// Marks every stream still behind `unshipped`: the drain is incomplete when one is. `passed`
/// says whether a shipping pass ran, or none was owed.
fn mark_behind(api: &HostApi, passed: bool) -> Result<Drained> {
    let marked = api
        .mark_unshipped()
        .map_err(|error| anyhow!("marking the unshipped streams: {error}"))?;
    if marked.is_empty() {
        if !passed {
            // Nothing was behind, but no pass confirmed it: the reason says what happened.
            return Ok(Drained::Incomplete(
                "the drain deadline passed before the shipping pass ran; no stream was behind \
                 its required subscriptions"
                    .to_owned(),
            ));
        }
        // Shipped as the deadline came.
        return Ok(Drained::Complete);
    }
    for mark in &marked {
        tracing::warn!(
            event.name = "host.stream_unshipped",
            component = COMPONENT,
            stream = %mark.stream,
            resource = %mark.resource,
            tail = mark.tail,
            truncate_safe = mark.truncate_safe,
            "a stream is left behind its required subscriptions: the volume holds evidence"
        );
    }
    let before = if passed {
        ""
    } else {
        "the drain deadline passed before the shipping pass ran: "
    };
    Ok(Drained::Incomplete(format!(
        "{before}{} stream(s) left unshipped behind their required subscriptions; the volume \
         keeps them for a fenced recovery",
        marked.len()
    )))
}

/// Prints the drain receipt of a recovery drain that completed (TD-2): one JSON line on standard
/// output, `{"drain_receipt": {"receipt", "bundle"}}`, which the drain controller reads from the
/// Job's log. A receipt the Host refuses to issue (a stream still behind) fails the drain, so the
/// Job never ends in success without one.
pub fn print_receipt(api: &HostApi) -> Result<()> {
    use std::io::Write as _;

    let export = api
        .drain_receipt()
        .map_err(|error| anyhow!("issuing the drain receipt: {error}"))?;
    let line = serde_json::json!({ "drain_receipt": export });
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").map_err(|error| anyhow!("printing the drain receipt: {error}"))?;
    out.flush()
        .map_err(|error| anyhow!("printing the drain receipt: {error}"))?;
    tracing::info!(
        event.name = "host.drain_receipt",
        component = COMPONENT,
        "the drain completed and its signed receipt is printed"
    );
    Ok(())
}

/// States, at every start, the streams an identity a reset retired left on this volume with
/// records no subscription acknowledged (BUG-0163, owner decision of 2026-11-19): they can never
/// ship, since their memberships ended with the identity and their batches name it, so they keep
/// the Host serving rather than degraded, and are said here and listed `retired` by `host streams
/// list`, each time the server starts, until the volume no longer holds them.
fn state_retired(api: &HostApi) {
    match api.streams_retired() {
        Ok(retired) => {
            for stream in retired {
                tracing::warn!(
                    event.name = "host.stream.retired_unshipped",
                    component = COMPONENT,
                    stream = %stream.stream,
                    resource = %stream.resource,
                    producer = %permguard_host::identity::record::uuid_text(&stream.producer),
                    records = stream.records,
                    "an identity a reset retired left records no subscription acknowledged: they stay on the volume and are never shipped"
                );
            }
        }
        Err(error) => tracing::error!(
            event.name = "host.stream.retired_unread",
            component = COMPONENT,
            error = %error,
            "the streams a retired identity left could not be read"
        ),
    }
}

/// Resumes shipping the streams an incomplete drain marked, while the Host is in Load: one pass
/// within `budget`. A mark that remains keeps the Host `degraded: evidence`, and the periodic
/// passes go on.
pub async fn resume(api: &HostApi, budget: Duration) {
    state_retired(api);
    let marked = match api.settle_unshipped() {
        Ok(marked) => marked,
        Err(error) => {
            tracing::error!(
                event.name = "host.stream_resume_failed",
                component = COMPONENT,
                error = %error,
                "the unshipped marks could not be read: the periodic passes try again"
            );
            return;
        }
    };
    if marked.is_empty() {
        return;
    }
    tracing::info!(
        event.name = "host.stream_resuming",
        component = COMPONENT,
        streams = marked.len(),
        "resuming the streams an incomplete drain left"
    );
    let _ = tokio::time::timeout(budget, api.ship_due()).await;
    match api.settle_unshipped() {
        Ok(remaining) if remaining.is_empty() => tracing::info!(
            event.name = "host.stream_resumed",
            component = COMPONENT,
            "every stream an incomplete drain left is shipped"
        ),
        Ok(remaining) => tracing::warn!(
            event.name = "host.stream_unshipped",
            component = COMPONENT,
            streams = remaining.len(),
            "streams are still behind their required subscriptions: degraded until shipped"
        ),
        Err(error) => tracing::error!(
            event.name = "host.stream_resume_failed",
            component = COMPONENT,
            error = %error,
            "the unshipped marks could not be settled: the periodic passes try again"
        ),
    }
}

/// The running shipper; dropping it stops it.
pub struct Shipping(tokio::task::JoinHandle<()>);

impl Drop for Shipping {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Runs this Host's shipper until the handle is dropped (iteration 04, WP-31.3): a round at once,
/// then one after each wake and `linger`, cut short when a batch's worth was appended; a round that
/// left something behind goes again after a wait from 250 ms doubling to 5 s, or as soon as a
/// task's bucket has a token. `None` when the Host ships nothing.
pub fn drive(api: Arc<HostApi>, linger: Duration) -> Option<Shipping> {
    drive_observed(api, linger, None)
}

/// [`drive`], reporting to `observing`: the freshness histogram, the sessions held, the rounds, and
/// `degraded: freshness` while the p99 of the last five minutes passes `evidence_freshness`.
pub fn drive_observed(
    api: Arc<HostApi>,
    linger: Duration,
    observing: Option<Observing>,
) -> Option<Shipping> {
    if !api.ships_anything() {
        return None;
    }
    let wake = Arc::new(tokio::sync::Notify::new());
    let full = Arc::new(tokio::sync::Notify::new());
    let appended = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let reconcile = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let (wake, full, appended) = (Arc::clone(&wake), Arc::clone(&full), Arc::clone(&appended));
        api.on_append(Arc::new(move || {
            if appended.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1 >= FULL_BATCH {
                full.notify_one();
            }
            wake.notify_one();
        }));
    }
    {
        let (wake, reconcile) = (Arc::clone(&wake), Arc::clone(&reconcile));
        api.set_shipper(Arc::new(move |asked| {
            if asked {
                reconcile.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            wake.notify_one();
        }));
    }
    Some(Shipping(tokio::spawn(async move {
        let mut again = Some(Duration::ZERO);
        let mut behind_wait = BEHIND_FIRST;
        let started = std::time::Instant::now();
        let mut freshness = Freshness::default();
        let mut exceeded = false;
        // When the oldest append not yet acknowledged woke the shipper.
        let mut pending: Option<std::time::Instant> = None;
        loop {
            let woken = match again {
                Some(wait) => {
                    tokio::select! {
                        () = wake.notified() => true,
                        () = tokio::time::sleep(wait) => false,
                    }
                }
                None => {
                    wake.notified().await;
                    true
                }
            };
            if woken && pending.is_none() {
                pending = Some(std::time::Instant::now());
            }
            // The linger: what is appended meanwhile leaves in the same round, unless a batch's
            // worth is there first.
            if !linger.is_zero() && appended.load(std::sync::atomic::Ordering::Relaxed) < FULL_BATCH
            {
                tokio::select! {
                    () = full.notified() => {}
                    () = tokio::time::sleep(linger) => {}
                }
            }
            appended.store(0, std::sync::atomic::Ordering::Relaxed);
            let reconciling = reconcile.swap(false, std::sync::atomic::Ordering::SeqCst);
            let round = api.ship_round(reconciling).await;
            if round.shipped > 0 {
                tracing::debug!(
                    event.name = "host.shipped",
                    component = COMPONENT,
                    batches = round.shipped,
                    "the shipper delivered batches"
                );
            }
            // Behind: a bucket empty, a deferral, a session lost. The round goes again when the
            // bucket refills, or after a wait that grows while nothing moves.
            let behind = round.behind || api.shipping_behind().unwrap_or(false);
            if let Some(observing) = &observing {
                let outcome = match (round.shipped > 0, behind) {
                    (true, false) => "ok",
                    (true, true) => "partial",
                    (false, true) => "deferred",
                    (false, false) => "empty",
                };
                observing.metrics.count(
                    &SHIP_ROUNDS,
                    &[(permguard_core::metrics::labels::OUTCOME, outcome)],
                );
                #[allow(clippy::cast_precision_loss)]
                observing
                    .metrics
                    .set(&SHIP_SESSIONS, &[], api.ship_sessions_open() as f64);
            }
            // Caught up: everything due when the oldest pending append woke the shipper is
            // acknowledged, and that wait is one freshness sample.
            if !behind && let Some(since) = pending.take() {
                let sample = since.elapsed();
                if let Some(observing) = &observing {
                    observing
                        .metrics
                        .observe(&SHIP_FRESHNESS, &[], sample.as_secs_f64());
                    freshness.observe(started.elapsed(), sample);
                    exceeded = judge_freshness(observing, &freshness, exceeded);
                }
            }
            again = if let Some(token) = round.retry_after {
                Some(token)
            } else if behind {
                let wait = behind_wait;
                behind_wait = if round.shipped > 0 {
                    BEHIND_FIRST
                } else {
                    (behind_wait * 2).min(BEHIND_LONGEST)
                };
                Some(wait)
            } else {
                behind_wait = BEHIND_FIRST;
                None
            };
        }
    })))
}

/// `degraded: freshness` while the window's p99 passes the declared objective, logged once when it
/// starts and once when it clears. Answers whether it is passed now.
fn judge_freshness(observing: &Observing, freshness: &Freshness, before: bool) -> bool {
    let (Some(objective), Some(p99)) = (observing.objective, freshness.p99()) else {
        return before;
    };
    let lifecycle = observing.health.lifecycle();
    if p99 > objective {
        let reason = format!(
            "the p99 of the last five minutes is {}ms, past the {}ms evidence_freshness objective",
            p99.as_millis(),
            objective.as_millis()
        );
        if !before {
            tracing::warn!(
                event.name = "host.freshness_exceeded",
                component = COMPONENT,
                reason = %reason,
                "evidence reaches its consumers later than its objective"
            );
        }
        lifecycle.degrade(permguard_core::lifecycle::HOST, FRESHNESS, reason);
        true
    } else {
        if before {
            tracing::info!(
                event.name = "host.freshness_restored",
                component = COMPONENT,
                "evidence reaches its consumers within its objective again"
            );
            lifecycle.restore(permguard_core::lifecycle::HOST, FRESHNESS);
        }
        false
    }
}

/// The evidence drained at shutdown for a Host with no listener: the producers ship to their
/// required subscriptions before the deadline, and a stream left behind makes the drain
/// incomplete, marked `unshipped` and resumed at the next start.
///
/// A served Host does this in its Host listener's service, after its requests. A Host embedded in
/// an application has no such service, and would otherwise stop with decisions it owes a
/// coordinator and say nothing: a composition that makes it a member registers this.
#[derive(Debug, Default)]
pub struct EvidenceDrain;

impl permguard_core::Service for EvidenceDrain {
    fn name(&self) -> &'static str {
        "evidence-drain"
    }

    /// Nothing starts: the periodic passes are the composition's, and this is their last one.
    fn start<'a>(
        &'a self,
        _context: &'a permguard_core::ServerContext<'a>,
    ) -> permguard_core::BoxFuture<'a, Result<()>> {
        Box::pin(std::future::ready(Ok(())))
    }

    fn drain<'a>(
        &'a self,
        context: &'a permguard_core::ServerContext<'a>,
        deadline: Instant,
    ) -> permguard_core::BoxFuture<'a, Result<Drained>> {
        Box::pin(async move {
            match context.host_handles::<HostApi>() {
                // No membership side, so nothing is owed anybody.
                None => Ok(Drained::Complete),
                Some(api) => drain(&api, deadline).await,
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// Iteration 04, `1-architecture/8` (evidence freshness): the p99 is the window's, five
    /// minutes, and a sample older than it no longer counts.
    #[test]
    fn the_freshness_p99_is_the_last_five_minutes() {
        let mut freshness = Freshness::default();
        assert_eq!(freshness.p99(), None);
        for n in 0..99 {
            freshness.observe(Duration::from_secs(n), ms(300));
        }
        freshness.observe(Duration::from_secs(99), ms(9_000));
        assert_eq!(
            freshness.p99(),
            Some(ms(300)),
            "one slow sample in a hundred"
        );
        freshness.observe(Duration::from_secs(100), ms(9_000));
        assert_eq!(freshness.p99(), Some(ms(9_000)), "two in a hundred and one");
        // Six minutes on, only what came since counts.
        freshness.observe(Duration::from_secs(460), ms(200));
        assert_eq!(freshness.p99(), Some(ms(200)));
    }

    /// Past the declared objective the Host is `degraded: freshness`, said once; back within it,
    /// restored; never a readiness hold. Undeclared, nothing is judged.
    #[test]
    fn a_freshness_past_its_objective_degrades_the_host_and_clears_by_itself() {
        let health = permguard_core::Health::new();
        let observing = Observing {
            health: health.clone(),
            metrics: permguard_core::Metrics::none(),
            objective: Some(Duration::from_secs(2)),
        };
        let mut freshness = Freshness::default();
        freshness.observe(ms(0), ms(3_000));
        assert!(judge_freshness(&observing, &freshness, false));
        assert!(
            health.lifecycle().holds().is_empty(),
            "never a readiness hold"
        );
        let mut within = Freshness::default();
        within.observe(ms(0), ms(500));
        assert!(!judge_freshness(&observing, &within, true));
        let undeclared = Observing {
            objective: None,
            ..observing
        };
        assert!(!judge_freshness(&undeclared, &freshness, false));
    }
}
