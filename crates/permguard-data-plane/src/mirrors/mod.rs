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
//! | `mirrors.jitter` | 0.1 | the spread that stops every replica waking at the same instant: each round waits `interval × (1 + jitter × u)`, `u ∈ [-1, 1]` from the CSPRNG, drawn again every round |
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

pub mod hints;
pub mod layout;
pub mod measure;
pub mod progress;
pub mod readiness;
pub mod round;
pub mod source;
pub mod state;
pub mod task;
pub mod tombstone;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, anyhow};
use permguard_core::metrics::labels;
use permguard_core::{BoxFuture, PlaneContext, PlaneTask, Subject, ready};
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

impl PlaneTask for MirrorService {
    fn name(&self) -> &'static str {
        "sync"
    }

    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            // The tasks of this Host's memberships come and go with them: a Host that holds any
            // runs the round, which snapshots them every time (WP-7.2a).
            let tasks = crate::handles::mirror_tasks(context);
            if !config.mirrors_enabled() || (config.mirror_sources().is_empty() && tasks.is_none())
            {
                info!(
                    event.name = "sync.disabled",
                    component = COMPONENT,
                    "this plane mirrors nothing: it serves whatever its volume already holds"
                );
                context.health().service(
                    self.name(),
                    permguard_core::lifecycle::ServiceState::Disabled,
                    None,
                    None,
                    Some("this plane mirrors nothing".to_owned()),
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
            let selections = source::TaskSelections::compile(config.mirror_task_selections())?;
            let context_for_round = Arc::new(round::Context {
                sources,
                tasks,
                selections,
                root,
                // The same decider both surfaces answer from: a ledger that
                // arrives here is checked and compiled once, and the first
                // request after a sync is as fast as the thousandth.
                decider: Some(crate::authz::decider(context)),
                deadline: config.mirrors_timeout(),
                parallelism: config.mirrors_parallelism(),
                stale_after: config.mirrors_stale_after(),
                reap_grace: config.mirrors_reap_grace(),
                // One pool for the life of the plane, not one per round: work
                // abandoned by one round is still outstanding during the next,
                // and a pool rebuilt every round would forget that.
                permits: Arc::new(tokio::sync::Semaphore::new(
                    config.mirrors_parallelism().max(1),
                )),
                metrics: context.metrics().clone(),
            });
            let jitter = config.mirrors_jitter();
            let recorder = crate::handles::audit(context);
            let health = context.health();
            let name = self.name();
            let expire_after = config.mirrors_expire_after();

            // The first round runs before the loop, so a plane that starts is
            // a plane that has already tried: nobody has to wait an interval
            // to learn the configuration is wrong. What it found decides
            // whether the plane leaves Load (P2, F-13).
            let outcome = round::run(Arc::clone(&context_for_round)).await;
            readiness::report(
                &health,
                &context_for_round.sources,
                &context_for_round.root,
                expire_after,
                &outcome,
                std::time::SystemTime::now(),
            );
            health.service(
                name,
                service_state(&outcome),
                outcome.label_success().then(std::time::SystemTime::now),
                Some(std::time::SystemTime::now() + with_jitter(interval, jitter)),
                service_reason(&outcome),
            );
            report(&recorder, outcome).await;

            let (stop, mut stopped) = watch::channel(false);
            // What wakes a round before its tick: a ref hint, or a watch that ended (WP-7.2c,
            // F-19). Every task the plane follows is watched while the plane runs.
            let wake = Arc::new(tokio::sync::Notify::new());
            if let Some(tasks) = context_for_round.tasks.clone() {
                tokio::spawn(hints::run(
                    Arc::new(hints::Watching {
                        tasks,
                        selections: context_for_round.selections.clone(),
                        root: context_for_round.root.clone(),
                        wake: Arc::clone(&wake),
                        retry: interval,
                    }),
                    stopped.clone(),
                ));
            }

            let task = tokio::spawn(async move {
                let mut last_round = tokio::time::Instant::now();
                loop {
                    let wait = with_jitter(interval, jitter);
                    let spacing = HINT_SPACING.min(interval);
                    if !next_round(wait, spacing, last_round, &wake, &mut stopped).await {
                        break;
                    }
                    last_round = tokio::time::Instant::now();
                    // Rounds never overlap: the next wait starts when this round ends. Every tick
                    // a round outlasts is skipped and counted — a slow server slows the cadence,
                    // it does not build a backlog.
                    let outcome = round::run(Arc::clone(&context_for_round)).await;
                    let skipped = skipped_ticks(last_round.elapsed(), interval);
                    if skipped > 0 {
                        context_for_round.metrics.add(
                            &measure::ROUNDS,
                            &[(labels::OUTCOME, "skipped")],
                            skipped as f64,
                        );
                        debug!(
                            event.name = "sync.round_skipped",
                            component = COMPONENT,
                            ticks = skipped,
                            "the round outlasted its interval: the ticks it covered are skipped"
                        );
                    }
                    readiness::report(
                        &health,
                        &context_for_round.sources,
                        &context_for_round.root,
                        expire_after,
                        &outcome,
                        std::time::SystemTime::now(),
                    );
                    health.service(
                        name,
                        service_state(&outcome),
                        outcome.label_success().then(std::time::SystemTime::now),
                        Some(std::time::SystemTime::now() + with_jitter(interval, jitter)),
                        service_reason(&outcome),
                    );
                    report(&recorder, outcome).await;
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

    fn stop<'a>(&'a self, _context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
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

/// The loop's lifecycle state after a round: running, or in backoff when a server did not
/// answer — the next round is the retry, at the configured cadence.
fn service_state(outcome: &round::Outcome) -> permguard_core::lifecycle::ServiceState {
    if outcome.unreachable > 0 {
        permguard_core::lifecycle::ServiceState::Backoff
    } else {
        permguard_core::lifecycle::ServiceState::Running
    }
}

/// Why the loop is in backoff, when it is.
fn service_reason(outcome: &round::Outcome) -> Option<String> {
    (outcome.unreachable > 0).then(|| {
        format!(
            "{} server(s) did not answer; retrying at the configured interval",
            outcome.unreachable
        )
    })
}

/// How many ticks of `interval` a round that took `took` outlasted: the ones it skipped.
fn skipped_ticks(took: Duration, interval: Duration) -> u64 {
    if interval.is_zero() {
        return 0;
    }
    (took.as_nanos() / interval.as_nanos()) as u64
}

/// The least time between two rounds when a hint wakes the second one.
const HINT_SPACING: Duration = Duration::from_secs(1);

/// Waits for the next round: `wait` passing, or a wake, which still lets `spacing` pass since
/// `last_round` began. `false` when the service stops meanwhile.
///
/// A hinted round is an ordinary one: it negotiates, verifies and checkpoints like any other.
/// The spacing keeps a coordinator that hints in a burst from driving rounds back to back.
async fn next_round(
    wait: Duration,
    spacing: Duration,
    last_round: tokio::time::Instant,
    wake: &tokio::sync::Notify,
    stopped: &mut watch::Receiver<bool>,
) -> bool {
    tokio::select! {
        _ = tokio::time::sleep(wait) => true,
        _ = wake.notified() => tokio::select! {
            _ = tokio::time::sleep_until(last_round + spacing) => true,
            _ = stopped.changed() => false,
        },
        _ = stopped.changed() => false,
    }
}

/// Spreads the wait, so replicas of this plane do not all wake at once and
/// ask one control plane for everything at the same instant.
///
/// The wait is `interval × (1 + fraction × u)` with `u ∈ [-1, 1]` drawn from the operating
/// system's CSPRNG (F-20): `0.1` means ±10% of the interval, both halves reached. It is drawn
/// **again for every round** and per Host, not once at startup: a fleet that happened to align
/// on its first tick does not stay aligned, and a fleet running one build shares no sequence.
fn with_jitter(interval: Duration, fraction: f64) -> Duration {
    jittered(interval, fraction, uniform())
}

/// The wait for one draw `u ∈ [-1, 1]`, never below a tenth of a second.
fn jittered(interval: Duration, fraction: f64, u: f64) -> Duration {
    if fraction <= 0.0 {
        return interval;
    }
    let factor = 1.0 + fraction * u.clamp(-1.0, 1.0);

    Duration::from_secs_f64((interval.as_secs_f64() * factor).max(0.1))
}

/// One independent `u ∈ [-1, 1]` from the operating system's CSPRNG; `0`, the interval itself,
/// when it gives none, and said.
fn uniform() -> f64 {
    use ring::rand::SecureRandom as _;

    let mut bytes = [0u8; 4];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        warn!(
            event.name = "sync.jitter_unavailable",
            component = COMPONENT,
            "the operating system gave no randomness: this round waits the bare interval"
        );
        return 0.0;
    }

    2.0 * f64::from(u32::from_be_bytes(bytes)) / f64::from(u32::MAX) - 1.0
}

/// Puts one round on the trail and in the log.
///
/// Every round is recorded, including the quiet ones: "nothing changed" is
/// the fact an auditor needs in order to say the plane was current at a given
/// hour, and a trail that only carries changes cannot answer that.
async fn report(recorder: &Option<crate::handles::Audit>, outcome: round::Outcome) {
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

    if let Some(recorder) = recorder {
        audited(recorder, &outcome).await;
    }
}

/// Where a round's audit records go: the plane's audit handle, or a test's log.
trait Records: Sync {
    fn record_on<'a>(
        &'a self,
        action: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, std::result::Result<(), String>>;
}

impl Records for crate::handles::Audit {
    fn record_on<'a>(
        &'a self,
        action: &'a str,
        target: &'a str,
    ) -> BoxFuture<'a, std::result::Result<(), String>> {
        Box::pin(async move {
            permguard_host::composition::AuditHandle::record_on(
                self,
                action,
                Subject::System(COMPONENT),
                target,
            )
            .await
            .map_err(|error| error.to_string())
        })
    }
}

/// Records the round, then each reap candidacy on its own record: a mirror tombstoned, restored
/// or reaped (WP-7.2d).
async fn audited(recorder: &dyn Records, outcome: &round::Outcome) {
    let target = format!(
        "{} synchronized, {} blocked, {} failed, {} reaped, {} servers unreachable",
        outcome.synchronized, outcome.blocked, outcome.failed, outcome.reaped, outcome.unreachable
    );
    if let Err(error) = recorder.record_on("ledger.synchronized", &target).await {
        warn!(
            event.name = "sync.audit_failed",
            component = COMPONENT,
            error = %error,
            "the round happened and its audit record did not"
        );
    }
    for (action, mirror) in &outcome.candidacy {
        if let Err(error) = recorder.record_on(action, mirror).await {
            warn!(
                event.name = "sync.audit_failed",
                component = COMPONENT,
                error = %error,
                action = *action,
                "a reap candidacy changed and its audit record did not"
            );
        }
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

    /// F-20: the wait is `interval × (1 + jitter × u)` over the whole of `u ∈ [-1, 1]`, and the
    /// draws reach both halves.
    #[test]
    fn jitter_spreads_the_whole_fraction_over_both_halves() {
        let interval = Duration::from_secs(30);
        assert_eq!(jittered(interval, 0.1, -1.0), Duration::from_secs(27));
        assert_eq!(jittered(interval, 0.1, 1.0), Duration::from_secs(33));
        assert_eq!(jittered(interval, 0.1, 0.0), interval);
        assert_eq!(
            jittered(interval, 0.1, 7.0),
            Duration::from_secs(33),
            "a draw outside [-1, 1] is held to it"
        );

        let (mut below, mut above) = (0, 0);
        for _ in 0..256 {
            let waited = with_jitter(interval, 0.1);
            assert!(
                (Duration::from_secs(27)..=Duration::from_secs(33)).contains(&waited),
                "a tenth of thirty seconds is ±3s, got {waited:?}"
            );
            if waited < interval {
                below += 1;
            }
            if waited > interval {
                above += 1;
            }
        }
        assert!(
            below > 32 && above > 32,
            "both halves are drawn: {below} below, {above} above"
        );
    }

    #[test]
    fn a_wait_is_never_zero_however_the_numbers_fall() {
        assert!(with_jitter(Duration::from_millis(1), 0.5) >= Duration::from_millis(100));
    }

    /// WP-7.2c: a hint wakes the round before its tick, but never sooner than the spacing after
    /// the last one; without a hint the tick decides.
    #[tokio::test(start_paused = true)]
    async fn a_hint_wakes_the_round_no_sooner_than_its_spacing() {
        use tokio::time::Instant;
        let wake = tokio::sync::Notify::new();
        let (_stop, mut stopped) = watch::channel(false);
        let (wait, spacing) = (Duration::from_secs(30), Duration::from_secs(1));

        let begun = Instant::now();
        assert!(next_round(wait, spacing, begun, &wake, &mut stopped).await);
        assert_eq!(begun.elapsed(), wait, "no hint: the tick");

        let last = Instant::now();
        wake.notify_one();
        assert!(next_round(wait, spacing, last, &wake, &mut stopped).await);
        assert_eq!(last.elapsed(), spacing, "a hint at once: the spacing");

        let last = Instant::now();
        tokio::time::advance(Duration::from_secs(5)).await;
        wake.notify_one();
        let hinted = Instant::now();
        assert!(next_round(wait, spacing, last, &wake, &mut stopped).await);
        assert_eq!(
            hinted.elapsed(),
            Duration::ZERO,
            "a hint past the spacing: now"
        );
    }

    /// WP-7.2c: a stop ends the wait, a hinted one in its spacing included.
    #[tokio::test(start_paused = true)]
    async fn a_stop_ends_the_wait_for_the_next_round() {
        use tokio::time::Instant;
        let (wait, spacing) = (Duration::from_secs(30), Duration::from_secs(60));
        let (stop, mut stopped) = watch::channel(false);
        let _ = stop.send(true);
        let wake = tokio::sync::Notify::new();
        assert!(!next_round(wait, spacing, Instant::now(), &wake, &mut stopped).await);

        let (stop, mut stopped) = watch::channel(false);
        let waiting = tokio::spawn(async move {
            let wake = tokio::sync::Notify::new();
            wake.notify_one();
            let begun = Instant::now();
            let next = next_round(wait, spacing, begun, &wake, &mut stopped).await;
            (next, begun.elapsed())
        });
        tokio::time::sleep(Duration::from_secs(10)).await;
        let _ = stop.send(true);
        let (next, waited) = waiting.await.expect("the wait ends");
        assert!(!next, "a stop during the spacing");
        assert!(waited < spacing, "{waited:?}");
    }

    /// WP-7.2d: a round is recorded, and each reap candidacy on a record of its own naming the
    /// mirror.
    #[tokio::test]
    async fn a_round_records_each_reap_candidacy() {
        #[derive(Default)]
        struct Log(std::sync::Mutex<Vec<(String, String)>>);
        impl Records for Log {
            fn record_on<'a>(
                &'a self,
                action: &'a str,
                target: &'a str,
            ) -> BoxFuture<'a, std::result::Result<(), String>> {
                self.0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .push((action.to_owned(), target.to_owned()));
                Box::pin(std::future::ready(Ok(())))
            }
        }
        let log = Log::default();
        let outcome = round::Outcome {
            reaped: 1,
            candidacy: vec![
                ("mirror.tombstoned", "a/z/l1".to_owned()),
                ("mirror.restored", "a/z/l2".to_owned()),
                ("mirror.reaped", "a/z/l3".to_owned()),
            ],
            ..Default::default()
        };
        audited(&log, &outcome).await;
        let recorded = log
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let actions: Vec<(&str, &str)> = recorded
            .iter()
            .map(|(action, target)| (action.as_str(), target.as_str()))
            .collect();
        assert_eq!(
            actions,
            vec![
                (
                    "ledger.synchronized",
                    "0 synchronized, 0 blocked, 0 failed, 1 reaped, 0 servers unreachable"
                ),
                ("mirror.tombstoned", "a/z/l1"),
                ("mirror.restored", "a/z/l2"),
                ("mirror.reaped", "a/z/l3"),
            ]
        );
    }

    /// The skipped ticks are the ones a round outlasted: none within the interval, one per whole
    /// interval past it.
    #[test]
    fn a_round_skips_every_tick_it_outlasts() {
        let interval = Duration::from_secs(30);
        assert_eq!(skipped_ticks(Duration::from_secs(29), interval), 0);
        assert_eq!(skipped_ticks(Duration::from_secs(30), interval), 1);
        assert_eq!(skipped_ticks(Duration::from_secs(95), interval), 3);
        assert_eq!(skipped_ticks(Duration::from_secs(95), Duration::ZERO), 0);
    }
}
