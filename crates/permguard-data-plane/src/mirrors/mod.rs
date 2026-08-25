// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Keeping the ledgers this plane serves current, without asking anybody.
//!
//! # What it is
//!
//! A lifecycle service with one job: every so often, ask each configured
//! server what it has, mirror the zones and ledgers this plane follows, and
//! remove the mirrors it no longer follows. Each ledger gets its own
//! directory on the volume, and they are all live at once — a PDP serving
//! four ledgers is four mirrors, not four processes.
//!
//! # The cadence, honestly
//!
//! | Setting | Default | What it guarantees |
//! | --- | --- | --- |
//! | `mirrors.interval` | 30s | how often a round *starts*, not how long it takes |
//! | `mirrors.jitter` | 0.1 | the spread that stops every replica waking at the same instant: each round waits `interval ± (interval × jitter)/2`, drawn again every round |
//! | `mirrors.timeout` | 2m | **per ledger**: a ledger that exceeds it is abandoned for this round |
//! | `mirrors.parallelism` | 4 | how many ledgers are mirrored at once |
//!
//! A tick that arrives while the previous round is still working is
//! **skipped** and counted, not queued: rounds never overlap, so a slow
//! control plane produces a slower cadence rather than a growing pile of
//! work. And what a timeout can do is bounded by what a thread can be told —
//! see [`round`] for the exact promise.
//!
//! # What it never does
//!
//! Accept anything it cannot prove. Every mirror advances through the same
//! verification the CLI uses: the signed head statement checked against the
//! published ring, the `(counter, digest)` table that refuses a rollback or
//! an equivocation, and the whole closure present before a checkpoint moves.
//! A compromised or confused server can make this plane *stale*. It cannot
//! make it serve policy nobody signed.

pub mod layout;
pub mod measure;
pub mod round;
pub mod source;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use permguard_core::{BoxFuture, ServerContext, Service, Subject, ready};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

const COMPONENT: &str = "data-plane";

/// The service the plane mounts. Does nothing at all when the deployment
/// configured no servers — a PDP that is fed by other means is a legitimate
/// deployment, not a misconfiguration.
pub struct MirrorService {
    /// A cadence override, for a test that cannot wait thirty seconds.
    tick: Option<Duration>,
    running: Mutex<Option<Running>>,
}

struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl Default for MirrorService {
    fn default() -> Self {
        Self::new()
    }
}

impl MirrorService {
    /// Builds the service; what it follows comes from the configuration.
    pub fn new() -> Self {
        Self {
            tick: None,
            running: Mutex::new(None),
        }
    }

    /// Runs on a fixed cadence regardless of configuration — what a test that
    /// cannot wait thirty seconds asks for.
    #[cfg(test)]
    pub fn every(mut self, tick: Duration) -> Self {
        self.tick = Some(tick);

        self
    }
}

impl Service for MirrorService {
    fn name(&self) -> &'static str {
        "sync"
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            if !config.mirrors_enabled() || config.mirror_sources().is_empty() {
                info!(
                    event.name = "sync.disabled",
                    component = COMPONENT,
                    "this plane mirrors nothing: it serves whatever its volume already holds"
                );

                return Ok(());
            }

            // Patterns compile here, at startup, where a typo is somebody's
            // problem to fix now rather than a mirror that follows nothing.
            let sources = source::compile(config.mirror_sources(), config.working_dir())?;
            for source in &sources {
                let (zones, ledgers) = source.patterns();
                info!(
                    event.name = "sync.following",
                    component = COMPONENT,
                    server = source.url(),
                    zone.patterns = zones.as_str(),
                    ledger.patterns = ledgers.as_str(),
                    "following"
                );
            }

            let root = config.mirrors_directory();
            std::fs::create_dir_all(&root)
                .map_err(|error| anyhow!("preparing {}: {error}", root.display()))?;

            let interval = self.tick.unwrap_or_else(|| config.mirrors_interval());
            let context_for_round = Arc::new(round::Context {
                sources,
                root,
                // The same decider both surfaces answer from: a ledger that
                // arrives here is checked and compiled once, and the first
                // request after a sync is as fast as the thousandth.
                decider: Some(crate::authz::decider(context)),
                deadline: config.mirrors_timeout(),
                parallelism: config.mirrors_parallelism(),
                stale_after: config.mirrors_stale_after(),
                // One pool for the life of the plane, not one per round: work
                // abandoned by one round is still outstanding during the next,
                // and a pool rebuilt every round would forget that.
                permits: Arc::new(tokio::sync::Semaphore::new(
                    config.mirrors_parallelism().max(1),
                )),
                metrics: context.metrics().clone(),
            });
            let jitter = config.mirrors_jitter();
            let recorder = context.recorder().cloned();

            // The first round runs before the loop, so a plane that starts is
            // a plane that has already tried: nobody has to wait an interval
            // to learn the configuration is wrong.
            report(&recorder, round::run(Arc::clone(&context_for_round)).await).await;

            let (stop, mut stopped) = watch::channel(false);
            let working = Arc::new(AtomicBool::new(false));

            let task = tokio::spawn(async move {
                loop {
                    let wait = with_jitter(interval, jitter);
                    tokio::select! {
                        _ = tokio::time::sleep(wait) => {
                            // Rounds never overlap. A tick that finds the
                            // previous round still working is skipped and
                            // counted — a slow server slows the cadence, it
                            // does not build a backlog.
                            if working.swap(true, Ordering::SeqCst) {
                                context_for_round
                                    .metrics
                                    .count(&measure::ROUNDS, &[("outcome", "skipped")]);
                                debug!(
                                    event.name = "sync.round_skipped",
                                    component = COMPONENT,
                                    "the previous round is still working"
                                );
                                continue;
                            }
                            let outcome = round::run(Arc::clone(&context_for_round)).await;
                            working.store(false, Ordering::SeqCst);
                            report(&recorder, outcome).await;
                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the sync service lock is poisoned"))? =
                Some(Running { task, stop });

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the sync service lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(running) = running else {
                return Ok(());
            };
            let _ = running.stop.send(true);
            match running.task.await {
                Ok(()) => debug!(
                    event.name = "sync.stopped",
                    component = COMPONENT,
                    "no longer mirroring"
                ),
                Err(error) => warn!(
                    event.name = "sync.stop_failed",
                    component = COMPONENT,
                    error = %error,
                    "the sync task did not finish"
                ),
            }

            Ok(())
        })
    }
}

/// Spreads the wait, so replicas of this plane do not all wake at once and
/// ask one control plane for everything at the same instant.
///
/// The wait is drawn from `interval ± (interval × fraction) / 2` — so `0.1`
/// means ±5% of the interval — and it is drawn **again for every round**, not
/// once at startup: a fleet that happened to align on its first tick does not
/// stay aligned.
fn with_jitter(interval: Duration, fraction: f64) -> Duration {
    if fraction <= 0.0 {
        return interval;
    }
    // No random-number dependency for something this small: the nanoseconds
    // of the clock are as unpredictable as this needs to be, and they cost
    // nothing.
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.subsec_nanos())
        .unwrap_or(0);
    let spread = interval.as_secs_f64() * fraction;
    let offset = spread * (f64::from(nanos) / f64::from(u32::MAX)) - spread / 2.0;

    Duration::from_secs_f64((interval.as_secs_f64() + offset).max(0.1))
}

/// Puts one round on the trail and in the log.
///
/// Every round is recorded, including the quiet ones: "nothing changed" is
/// the fact an auditor needs in order to say the plane was current at a given
/// hour, and a trail that only carries changes cannot answer that.
async fn report(recorder: &Option<permguard_core::AuditRecorder>, outcome: round::Outcome) {
    info!(
        event.name = "sync.round",
        component = COMPONENT,
        outcome = outcome.label(),
        synchronized = outcome.synchronized,
        blocked = outcome.blocked,
        failed = outcome.failed,
        reaped = outcome.reaped,
        unreachable = outcome.unreachable,
        "a synchronization round finished"
    );

    let Some(recorder) = recorder else {
        return;
    };
    let target = format!(
        "{} synchronized, {} blocked, {} failed, {} reaped, {} servers unreachable",
        outcome.synchronized, outcome.blocked, outcome.failed, outcome.reaped, outcome.unreachable
    );
    if let Err(error) = recorder
        .record_on("ledger.synchronized", Subject::System(COMPONENT), &target)
        .await
    {
        warn!(
            event.name = "sync.audit_failed",
            component = COMPONENT,
            error = %error,
            "the round happened and its audit record did not"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_jitter_means_the_interval_exactly() {
        let interval = Duration::from_secs(30);
        assert_eq!(with_jitter(interval, 0.0), interval);
    }

    #[test]
    fn jitter_stays_inside_its_fraction() {
        let interval = Duration::from_secs(30);
        for _ in 0..64 {
            let waited = with_jitter(interval, 0.1).as_secs_f64();
            assert!(
                (27.0..=33.0).contains(&waited),
                "a tenth of thirty seconds is ±1.5s, got {waited}"
            );
        }
    }

    #[test]
    fn a_wait_is_never_zero_however_the_numbers_fall() {
        assert!(with_jitter(Duration::from_millis(1), 0.5) >= Duration::from_millis(100));
    }
}
