// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reclaiming what nothing references.
//!
//! # The leak this closes
//!
//! A content-addressed store only ever adds. A push uploads its objects first
//! and commits second, so between the two they are legitimately unreachable —
//! and if the commit never comes (a connection lost, a conflict nobody
//! retried, a client that crashed) they stay unreachable forever. The same is
//! true of a history that moved: the objects only the abandoned side of it
//! reached are dead the moment the ref does not name them.
//!
//! Nothing else in this server ever deletes an object, so without this the
//! disk of every long-lived deployment climbs in one direction.
//!
//! # The rule, and why it is safe
//!
//! ```text
//! keep  =  reachable from ANY ref   ∪   pinned by a kept transfer session   ∪   younger than the grace period
//!       ∪  everything of a ledger a hold keeps
//! ```
//!
//! A hold (WP-7.3c) names a ledger, or a zone and so every ledger of it, and keeps all it holds,
//! unreachable objects included, until it expires or is released. The holds are read once per
//! pass, before any ledger: holds that cannot be read sweep nothing that pass.
//!
//! Reachability is computed from **every ref of the ledger**, not the default
//! one, walking commits to their predecessors, their manifest and their tree,
//! and trees to their entries. Everything else is a candidate — and a
//! candidate is only removed once it is **older than `storage.gc.grace`**,
//! which keeps an object a crash left behind safe for a while. What keeps a
//! push in flight safe is its transfer session (WP-7.12): every object its
//! closure declared is pinned while the session is open, and for the grace
//! after it ends, however long the push takes. An open session past its expiry
//! is closed first, and a pull session pins what its negotiation answered
//! missing until it expires. The server refuses a grace period shorter than any
//! write lasts.
//!
//! Two more properties this relies on, both already true of the store:
//! objects are **immutable and content-addressed**, so an object removed by
//! mistake can be re-uploaded byte-identically by any client that has it; and
//! ref updates are atomic, so a sweep either sees a ref before or after a
//! commit, never halfway.
//!
//! # A pass is bounded, and checked again before it deletes
//!
//! A pass removes at most `storage.gc.max_removals` objects (WP-7.11): one that reaches the bound
//! stops in the ledger it was sweeping, and the next pass starts there, the ledgers in the
//! catalog's order, wrapping around. The cursor lives in memory: a restart starts over, which only
//! sweeps again what is still unreachable and old; a ledger deleted meanwhile sends it back to the
//! first. A ledger that yields the bound's worth every pass keeps the cursor: the bound is sized
//! so it does not. Under each ledger's transfer lock, after its pins are read and its refs walked
//! and before anything of it is removed, the holds are read again: a hold added since the pass
//! began keeps the ledger whole.
//!
//! # What it never does
//!
//! It never reads an object to decide its fate — only the reachability walk
//! decodes, and only what a ref reaches. It never removes a ref, a signature
//! or anything outside the object fanout: the paths it touches are built from
//! digests it just listed. And it never runs on the request path.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Result, anyhow};
use permguard_core::catalog::{Catalog, Selector};
use permguard_core::metrics::{Metric, SECONDS};
use permguard_core::{BoxFuture, Metrics, PlaneContext, PlaneTask, Subject, ready};
use permguard_objects::digest::Digest;
use permguard_objects::object::{self, Object};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use crate::store::FileObjectStore;

const COMPONENT: &str = "control-plane";

/// Objects removed, by zone and ledger.
pub const REMOVED: Metric = Metric::counter(
    "permguard_gc_objects_removed_total",
    "Objects removed because nothing referenced them.",
);

/// Bytes reclaimed.
pub const RECLAIMED: Metric = Metric::counter(
    "permguard_gc_bytes_reclaimed_total",
    "Bytes reclaimed by removing unreferenced objects.",
);

/// Objects that are unreachable and still inside the grace period — the ones
/// a sweep deliberately left alone. A number that keeps climbing is a client
/// abandoning pushes.
pub const RETAINED: Metric = Metric::gauge(
    "permguard_gc_objects_retained",
    "Unreachable objects held back because they are younger than the grace period.",
);

/// Sweeps, by outcome: `ok`, `partial` (a ledger could not be swept).
pub const SWEEPS: Metric = Metric::counter(
    "permguard_gc_sweeps_total",
    "Garbage-collection sweeps, by outcome.",
);

/// How long a whole sweep took.
pub const SWEEP_SECONDS: Metric = Metric::histogram(
    "permguard_gc_sweep_seconds",
    "How long a garbage-collection sweep took.",
    SECONDS,
);

/// The service the control plane mounts.
pub struct GcService {
    /// A cadence override, for a test that cannot wait six hours.
    every: Option<Duration>,
    running: Mutex<Option<Running>>,
}

struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

impl Default for GcService {
    fn default() -> Self {
        Self::new()
    }
}

impl GcService {
    /// The service; what it does comes from the configuration.
    pub fn new() -> Self {
        Self {
            every: None,
            running: Mutex::new(None),
        }
    }

    /// Runs on a fixed cadence regardless of configuration — what a test asks
    /// for.
    #[cfg(test)]
    pub fn every(mut self, every: Duration) -> Self {
        self.every = Some(every);

        self
    }
}

impl PlaneTask for GcService {
    fn name(&self) -> &'static str {
        "gc"
    }

    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let config = context.config();
            if !config.gc_enabled() {
                info!(
                    event.name = "gc.disabled",
                    component = COMPONENT,
                    "unreferenced objects are kept: this store only grows"
                );

                return Ok(());
            }
            let Some(catalog) = context.catalog().cloned() else {
                debug!(
                    event.name = "gc.disabled",
                    component = COMPONENT,
                    "no catalog is composed: there is nothing to sweep"
                );

                return Ok(());
            };

            let sweep = Sweep {
                catalog,
                root: config.zones_directory(),
                grace: config.gc_grace(),
                metrics: context.metrics().clone(),
                recorder: crate::handles::audit(context),
                holds: crate::handles::holds(context),
                max_removals: usize::try_from(config.gc_max_removals()).unwrap_or(usize::MAX),
                cursor: Arc::new(Mutex::new(None)),
                serial: Arc::new(Mutex::new(())),
            };
            // The operator's plan and run on the Host API, over this very sweep (WP-7.11b). A
            // store whose collection is switched off keeps every object, an operator's run
            // included: the job is not provided then.
            if let Some(registration) = crate::handles::registration(context) {
                let job = Arc::new(ObjectsJob {
                    sweep: sweep.clone(),
                    runtime: tokio::runtime::Handle::try_current().ok(),
                });
                if let Err(error) = registration.provide_gc_job(permguard_host::gc::OBJECTS, job) {
                    warn!(
                        event.name = "gc.job_unprovided",
                        component = COMPONENT,
                        error = %error,
                        "the operator's object sweep is not served by this plane"
                    );
                }
            }
            let every = self.every.unwrap_or_else(|| config.gc_interval());
            info!(
                event.name = "gc.following",
                component = COMPONENT,
                interval.seconds = every.as_secs(),
                grace.seconds = sweep.grace.as_secs(),
                "unreferenced objects older than the grace period will be reclaimed"
            );

            let (stop, mut stopped) = watch::channel(false);
            let task = tokio::spawn(async move {
                loop {
                    tokio::select! {
                        // The first sweep is one interval away, not at start:
                        // a plane that has just come up is the worst moment to
                        // spend a directory walk, and nothing is urgent here.
                        _ = tokio::time::sleep(every) => {
                            let sweep = sweep.clone();
                            let outcome = tokio::task::spawn_blocking(move || {
                                let outcome = sweep.run();
                                (sweep, outcome)
                            })
                            .await;
                            if let Ok((sweep, outcome)) = outcome {
                                sweep.report(&outcome).await;
                            }
                        }
                        _ = stopped.changed() => break,
                    }
                }
            });

            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the gc service lock is poisoned"))? =
                Some(Running { task, stop });

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the gc service lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(running) = running else {
                return Ok(());
            };
            let _ = running.stop.send(true);
            let _ = running.task.await;

            Ok(())
        })
    }
}

/// Everything one sweep needs, resolved once.
#[derive(Clone)]
struct Sweep {
    catalog: Arc<dyn Catalog>,
    root: std::path::PathBuf,
    grace: Duration,
    metrics: Metrics,
    recorder: Option<crate::handles::Audit>,
    /// The Host's holds (WP-7.3c): `Ok(None)` without a Host; an error when a Host registered the
    /// plane and handed it none, which sweeps nothing (after the review).
    holds: std::result::Result<Option<Arc<permguard_host::holds::HoldStore>>, ()>,
    /// The most objects one pass removes (WP-7.11).
    max_removals: usize,
    /// The ledger, `<zone>/<ledger>`, the last pass stopped in at its bound: where the next starts.
    cursor: Arc<Mutex<Option<String>>>,
    /// Held by every pass that removes: the background pass and an operator's run never
    /// interleave (WP-7.11b).
    serial: Arc<Mutex<()>>,
}

/// What a pass covers: every ledger, a zone's, or one (WP-7.11b).
#[derive(Debug, Clone, PartialEq, Eq)]
enum Scope {
    All,
    Zone(String),
    Ledger(String, String),
}

impl Scope {
    /// The scope an operator's plan names: this Plane, or a zone or a ledger of it.
    fn of(resource: &permguard_core::authz::Resource) -> std::result::Result<Self, String> {
        use permguard_core::authz::Resource;
        match resource {
            Resource::Plane { plane } if plane == crate::service::PLANE => Ok(Self::All),
            Resource::Zone { plane, zone_id } if plane == crate::service::PLANE => {
                Ok(Self::Zone(zone_id.clone()))
            }
            Resource::Ledger {
                plane,
                zone_id,
                ledger_id,
            } if plane == crate::service::PLANE => {
                Ok(Self::Ledger(zone_id.clone(), ledger_id.clone()))
            }
            other => Err(format!("`{other}` is not this Plane's to sweep")),
        }
    }

    fn covers_zone(&self, zone: &str) -> bool {
        match self {
            Self::All => true,
            Self::Zone(of) | Self::Ledger(of, _) => of == zone,
        }
    }

    fn covers(&self, zone: &str, ledger: &str) -> bool {
        match self {
            Self::Ledger(of, which) => of == zone && which == ledger,
            _ => self.covers_zone(zone),
        }
    }
}

/// What a pass does: the background pass and an operator's run remove, a plan only counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Act {
    Sweep,
    Plan,
}

/// One ledger as a pass left it, for an operator's report.
#[derive(Debug)]
enum Left {
    Swept(Swept),
    /// A hold the pass listed keeps it whole, with this many objects.
    Held(usize),
    Skipped(String),
}

/// What one pass did, ledger by ledger.
#[derive(Debug, Default)]
struct Pass {
    outcome: Outcome,
    ledgers: Vec<(String, String, Left)>,
}

/// What a sweep did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub ledgers: usize,
    pub removed: usize,
    pub reclaimed: u64,
    /// Unreachable, and left alone because they are still young.
    pub retained: usize,
    /// Temporary files of interrupted writes, removed.
    pub temporaries: usize,
    /// Ledgers that could not be swept — a store that would not list, a ref
    /// that would not read. Nothing was removed for those.
    pub skipped: usize,
    /// Ledgers a hold keeps, left whole (WP-7.3c).
    pub held: usize,
    /// The holds could not be read: nothing was swept (after the review).
    pub holds_unreadable: bool,
    /// The pass reached its removal bound in this ledger, `<zone>/<ledger>`: the next starts there
    /// (WP-7.11).
    pub resumes_at: Option<String>,
}

impl Outcome {
    /// How the sweep ended, in one word.
    pub fn label(&self) -> &'static str {
        if self.skipped == 0 && !self.holds_unreadable {
            "ok"
        } else {
            "partial"
        }
    }
}

impl Sweep {
    /// One background pass over every ledger of every zone.
    fn run(&self) -> Outcome {
        self.pass(&Scope::All, Act::Sweep, false).outcome
    }

    /// One pass over the ledgers `scope` covers. `listing` keeps, for an operator's report, what
    /// each ledger was left as.
    fn pass(&self, scope: &Scope, act: Act, listing: bool) -> Pass {
        let _serial = (act == Act::Sweep).then(|| {
            self.serial
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
        });
        let started = Instant::now();
        let mut pass = Pass::default();
        let outcome = &mut pass.outcome;
        let now = permguard_host::authz::store::now();
        // The holds first, once: a pass that cannot know what is held removes nothing.
        let listed = match &self.holds {
            Ok(None) => Ok(Vec::new()),
            Ok(Some(store)) => store.list().map_err(|error| error.to_string()),
            Err(()) => Err("the Host handed this plane no holds".to_owned()),
        };
        let holds = match listed {
            Ok(holds) => holds,
            Err(error) => {
                warn!(
                    event.name = "gc.holds_unreadable",
                    component = COMPONENT,
                    error = %error,
                    "the holds could not be read: nothing is swept this round"
                );
                outcome.holds_unreadable = true;

                return pass;
            }
        };
        for hold in &holds {
            if hold.status(now) == permguard_host::holds::Status::ReviewDue {
                warn!(
                    event.name = "gc.hold_review_due",
                    component = COMPONENT,
                    hold = hold.id.as_str(),
                    "a hold is past its review date: it still keeps what it names"
                );
            }
        }
        let zones = match self.catalog.list_zones() {
            Ok(zones) => zones,
            Err(error) => {
                warn!(
                    event.name = "gc.failed",
                    component = COMPONENT,
                    error = %error,
                    "the catalog could not be listed: nothing is swept this round"
                );
                outcome.skipped += 1;

                return pass;
            }
        };

        let mut listed = std::collections::BTreeSet::new();
        let mut order: Vec<(String, String)> = Vec::new();
        for zone in zones.iter().filter(|zone| scope.covers_zone(&zone.id)) {
            let ledgers = match self.catalog.list_ledgers(&Selector::Id(zone.id.clone())) {
                Ok(ledgers) => ledgers,
                Err(error) => {
                    warn!(
                        event.name = "gc.zone_failed",
                        component = COMPONENT,
                        zone = zone.id.as_str(),
                        error = %error,
                        "a zone's ledgers could not be listed"
                    );
                    outcome.skipped += 1;
                    continue;
                }
            };
            for ledger in ledgers
                .iter()
                .filter(|ledger| scope.covers(&zone.id, &ledger.id))
            {
                listed.insert(format!("{}/{}", zone.id, ledger.id));
                order.push((zone.id.clone(), ledger.id.clone()));
            }
        }
        // Where the last whole pass stopped at its bound, wrapping around: every ledger gets its
        // turn. A plan and a scoped run neither read nor move it.
        let cursored = *scope == Scope::All && act == Act::Sweep;
        if cursored {
            let start = self
                .cursor
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
                .and_then(|key| {
                    order
                        .iter()
                        .position(|(zone, ledger)| format!("{zone}/{ledger}") == key)
                })
                .unwrap_or(0);
            order.rotate_left(start);
        }
        // A plan counts every candidate: the bound is a run's.
        let mut budget = match act {
            Act::Sweep => self.max_removals,
            Act::Plan => usize::MAX,
        };
        for (zone, ledger) in &order {
            let outcome = &mut pass.outcome;
            outcome.ledgers += 1;
            let directory = self.root.join(zone).join("ledgers").join(ledger);
            let store = FileObjectStore::new(&directory);
            if holds.iter().any(|hold| hold.keeps(zone, ledger, now)) {
                outcome.held += 1;
                if listing {
                    let left = match store.list_objects() {
                        Ok(objects) => Left::Held(objects.len()),
                        Err(error) => Left::Skipped(error.to_string()),
                    };
                    pass.ledgers.push((zone.clone(), ledger.clone(), left));
                }
                continue;
            }
            match self.sweep_ledger_as(&store, zone, ledger, &mut budget, act) {
                Ok(swept) => {
                    outcome.removed += swept.removed;
                    outcome.reclaimed += swept.reclaimed;
                    outcome.retained += swept.retained;
                    outcome.temporaries += swept.temporaries;
                    if swept.held {
                        outcome.held += 1;
                    }
                    let exhausted = swept.exhausted;
                    if listing {
                        pass.ledgers
                            .push((zone.clone(), ledger.clone(), Left::Swept(swept)));
                    }
                    if exhausted {
                        let key = format!("{zone}/{ledger}");
                        if cursored {
                            *self
                                .cursor
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(key.clone());
                        }
                        pass.outcome.resumes_at = Some(key);
                        break;
                    }
                }
                Err(error) => {
                    if listing {
                        pass.ledgers.push((
                            zone.clone(),
                            ledger.clone(),
                            Left::Skipped(error.to_string()),
                        ));
                    }
                    let outcome = &mut pass.outcome;
                    outcome.skipped += 1;
                    warn!(
                        event.name = "gc.ledger_failed",
                        component = COMPONENT,
                        zone = zone.as_str(),
                        ledger = ledger.as_str(),
                        error = %error,
                        "this ledger was left exactly as it was"
                    );
                }
            }
        }

        // A plan leaves the metrics as they were.
        if act == Act::Plan {
            return pass;
        }
        let outcome = &pass.outcome;
        // A ledger the catalog no longer lists stops counting toward what is retained. Only after a
        // listing that reached every zone and a whole pass that reached every ledger: neither a zone
        // that could not be listed, a pass cut at its bound nor a scoped run is evidence that a
        // ledger is gone.
        if *scope == Scope::All && outcome.skipped == 0 && outcome.resumes_at.is_none() {
            self.metrics
                .retain_aggregated(&RETAINED, permguard_core::Aggregate::Sum, |resource| {
                    listed.contains(resource)
                });
        }

        self.metrics.count(
            &SWEEPS,
            &[(permguard_core::metrics::labels::OUTCOME, outcome.label())],
        );
        self.metrics
            .observe(&SWEEP_SECONDS, &[], started.elapsed().as_secs_f64());

        pass
    }

    /// One ledger, with what a service adds around the sweep: labels, metrics
    /// and a line in the log.
    /// `zone` and `ledger` are ids: they key the retained-objects aggregate and name the ledger in the
    /// log, where a name would be a tenant identifier.
    #[cfg(test)]
    fn sweep_ledger(
        &self,
        store: &FileObjectStore,
        zone: &str,
        ledger: &str,
        budget: &mut usize,
    ) -> Result<Swept> {
        self.sweep_ledger_as(store, zone, ledger, budget, Act::Sweep)
    }

    /// [`Self::sweep_ledger`] as `act` does it: a plan removes nothing and leaves the metrics.
    fn sweep_ledger_as(
        &self,
        store: &FileObjectStore,
        zone: &str,
        ledger: &str,
        budget: &mut usize,
        act: Act,
    ) -> Result<Swept> {
        // The holds read again under the ledger's lock, right before its removals (WP-7.11).
        let held_now = || -> Result<bool> {
            let now = permguard_host::authz::store::now();
            match &self.holds {
                Ok(None) => Ok(false),
                Ok(Some(holds)) => holds
                    .keeps(zone, ledger, now)
                    .map_err(|error| anyhow!("{error}")),
                Err(()) => Err(anyhow!("the Host handed this plane no holds")),
            }
        };
        let swept = sweep_within(store, self.grace, budget, &held_now, act == Act::Plan)?;
        if act == Act::Plan {
            return Ok(swept);
        }

        if swept.removed > 0 {
            self.metrics.add(&REMOVED, &[], swept.removed as f64);
            self.metrics.add(&RECLAIMED, &[], swept.reclaimed as f64);
            info!(
                event.name = "gc.ledger_swept",
                component = COMPONENT,
                zone = zone,
                ledger = ledger,
                removed = swept.removed,
                bytes = swept.reclaimed,
                "unreferenced objects were reclaimed"
            );
        }
        self.metrics.set_aggregated(
            &RETAINED,
            permguard_core::Aggregate::Sum,
            &format!("{zone}/{ledger}"),
            swept.retained as f64,
        );

        Ok(swept)
    }

    /// Puts the sweep on the trail.
    ///
    /// Recorded whether or not anything was removed: "nothing was deleted at
    /// 03:00" is what lets an auditor account for a store's contents over
    /// time, and a trail that only carried deletions could not.
    async fn report(&self, outcome: &Outcome) {
        self.report_run(outcome, None).await;
    }

    /// [`Self::report`], naming the operator's plan a run spent and the scope it swept
    /// (WP-7.11b).
    async fn report_run(&self, outcome: &Outcome, run: Option<(&str, &Scope)>) {
        info!(
            event.name = "gc.sweep",
            component = COMPONENT,
            outcome = outcome.label(),
            ledgers = outcome.ledgers,
            removed = outcome.removed,
            bytes = outcome.reclaimed,
            retained = outcome.retained,
            temporaries = outcome.temporaries,
            skipped = outcome.skipped,
            held = outcome.held,
            holds_unreadable = outcome.holds_unreadable,
            "a garbage-collection sweep finished"
        );
        let Some(recorder) = &self.recorder else {
            return;
        };
        let target = match run {
            Some((plan_id, scope)) => format!(
                "{}; the run of plan {plan_id} on {}",
                trail_target(outcome),
                scope_label(scope)
            ),
            None => trail_target(outcome),
        };
        if let Err(error) = recorder
            .record_on("store.swept", Subject::System(COMPONENT), &target)
            .await
        {
            warn!(
                event.name = "gc.audit_failed",
                component = COMPONENT,
                error = %error,
                "objects were reclaimed and the audit record was not written"
            );
        }
    }
}

/// The scope a run swept, as its record names it.
fn scope_label(scope: &Scope) -> String {
    match scope {
        Scope::All => "every ledger".to_owned(),
        Scope::Zone(zone) => format!("zone {zone}"),
        Scope::Ledger(zone, ledger) => format!("ledger {zone}/{ledger}"),
    }
}

/// The operator's object sweep the Host API plans and runs (WP-7.11b): the background pass's
/// sweep, scoped, serialized with it and within its bound.
struct ObjectsJob {
    sweep: Sweep,
    /// The runtime a run's `store.swept` record is written on, without waiting for it: a job is
    /// called on a blocking thread, which never blocks on a runtime (after the review).
    runtime: Option<tokio::runtime::Handle>,
}

impl ObjectsJob {
    /// `pass` over `scope`, refused when a zone or ledger scope names nothing of the catalog.
    fn passed(
        &self,
        scope: &Scope,
        act: Act,
    ) -> std::result::Result<Pass, permguard_host::gc::GcError> {
        let pass = self.sweep.pass(scope, act, true);
        let outcome = &pass.outcome;
        if *scope != Scope::All
            && outcome.ledgers == 0
            && outcome.skipped == 0
            && !outcome.holds_unreadable
        {
            return Err(permguard_host::gc::GcError::NotFound(format!(
                "the catalog holds no ledger of {}",
                scope_label(scope)
            )));
        }
        Ok(pass)
    }
}

impl permguard_host::gc::GcJob for ObjectsJob {
    fn plan(
        &self,
        scope: &permguard_core::authz::Resource,
    ) -> std::result::Result<permguard_host::gc::Report, permguard_host::gc::GcError> {
        let scope = Scope::of(scope).map_err(permguard_host::gc::GcError::NotFound)?;
        Ok(report_of(&self.passed(&scope, Act::Plan)?))
    }

    fn run(
        &self,
        scope: &permguard_core::authz::Resource,
        plan_id: &str,
    ) -> std::result::Result<permguard_host::gc::Report, permguard_host::gc::GcError> {
        let scope = Scope::of(scope).map_err(permguard_host::gc::GcError::NotFound)?;
        let pass = self.passed(&scope, Act::Sweep)?;
        // Recorded like the background pass, whatever it removed; the Host records the run too.
        match &self.runtime {
            Some(runtime) => {
                let sweep = self.sweep.clone();
                let outcome = pass.outcome.clone();
                let plan_id = plan_id.to_owned();
                let recorded = scope.clone();
                runtime.spawn(async move {
                    sweep
                        .report_run(&outcome, Some((&plan_id, &recorded)))
                        .await;
                });
            }
            None => warn!(
                event.name = "gc.audit_failed",
                component = COMPONENT,
                "an operator's sweep ran without a runtime to record it on"
            ),
        }
        Ok(report_of(&pass))
    }
}

/// What an operator is answered of `pass`: every ledger it left, what it removed or would, what
/// it kept and why.
fn report_of(pass: &Pass) -> permguard_host::gc::Report {
    use permguard_host::gc::{Entry, Kept, MAX_ENTRIES, Report};
    let kept = |reasons: &[(&str, usize)]| -> Vec<Kept> {
        reasons
            .iter()
            .filter(|(_, count)| *count > 0)
            .map(|(reason, count)| Kept {
                reason: (*reason).to_owned(),
                count: *count as u64,
            })
            .collect()
    };
    let resource = |zone: &str, ledger: &str| {
        permguard_core::authz::Resource::ledger(crate::service::PLANE, zone, ledger).to_string()
    };
    let mut report = Report {
        resumes_at: pass.outcome.resumes_at.as_ref().map(|at| {
            let (zone, ledger) = at.split_once('/').unwrap_or((at.as_str(), ""));
            resource(zone, ledger)
        }),
        ..Report::default()
    };
    if pass.outcome.holds_unreadable {
        report
            .skipped
            .push("every ledger: the holds could not be read, nothing was swept".to_owned());
    }
    for (zone, ledger, left) in &pass.ledgers {
        let entry = match left {
            Left::Skipped(error) => {
                report
                    .skipped
                    .push(format!("{}: {error}", resource(zone, ledger)));
                continue;
            }
            Left::Held(objects) => Entry {
                resource: resource(zone, ledger),
                kept: kept(&[("held", *objects)]),
                ..Entry::default()
            },
            Left::Swept(swept) if swept.held => Entry {
                resource: resource(zone, ledger),
                kept: kept(&[("held", swept.held_objects)]),
                ..Entry::default()
            },
            Left::Swept(swept) => Entry {
                resource: resource(zone, ledger),
                candidates: swept.candidates as u64,
                candidate_bytes: swept.candidate_bytes,
                removed: swept.removed as u64,
                removed_bytes: swept.reclaimed,
                kept: kept(&[
                    ("reachable", swept.reached),
                    ("pinned", swept.pinned),
                    ("grace", swept.retained - swept.deferred),
                    ("bound", swept.deferred),
                ]),
            },
        };
        if report.entries.len() < MAX_ENTRIES {
            report.entries.push(entry);
        } else {
            report.omitted += 1;
        }
    }
    report
}

/// What the `store.swept` record names: every count of the pass, the held ledgers included
/// (WP-7.3c).
fn trail_target(outcome: &Outcome) -> String {
    if outcome.holds_unreadable {
        return "nothing swept: the holds could not be read".to_owned();
    }
    let counts = format!(
        "{} ledgers swept, {} objects removed, {} bytes reclaimed, {} retained, {} skipped, {} held",
        outcome.ledgers,
        outcome.removed,
        outcome.reclaimed,
        outcome.retained,
        outcome.skipped,
        outcome.held
    );
    match &outcome.resumes_at {
        Some(at) => format!("{counts}; stopped at its bound, resumes at {at}"),
        None => counts,
    }
}

/// What one ledger's sweep did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Objects removed.
    pub removed: usize,
    /// Bytes reclaimed by removing them.
    pub reclaimed: u64,
    /// Unreachable, and left alone because they are still young — what a push
    /// in flight looks like from here.
    pub retained: usize,
    /// Temporary files of writes a crash interrupted, removed once older than
    /// the grace period.
    pub temporaries: usize,
    /// A hold found under the ledger's lock kept it whole (WP-7.11).
    pub held: bool,
    /// The pass's removal bound was reached in this ledger: what is left goes at the next.
    pub exhausted: bool,
    /// Objects a ref reaches (WP-7.11b).
    pub reached: usize,
    /// Objects no ref reaches that a transfer session pins.
    pub pinned: usize,
    /// Objects old enough and unreachable: what a plan answers, what a run removes or leaves to
    /// the next past its bound.
    pub candidates: usize,
    pub candidate_bytes: u64,
    /// Candidates left past the bound, counted in `retained` too.
    pub deferred: usize,
    /// The objects a hold found under the lock kept, every one of the ledger's.
    pub held_objects: usize,
}

/// Sweeps one ledger's store: what its refs reach stays, the rest goes once it
/// is older than `grace`.
///
/// The unit the service is built from, and the one a test can drive: no
/// catalog, no clock but the filesystem's, no metrics. It answers what it did,
/// or refuses — a store whose closure has a hole is left exactly as it was.
pub fn sweep_once(store: &FileObjectStore, grace: Duration) -> Result<Swept> {
    let mut unbounded = usize::MAX;
    sweep_within(store, grace, &mut unbounded, &|| Ok(false), false)
}

/// [`sweep_once`], removing at most `budget` objects, and keeping the ledger whole when `held`
/// answers that a hold keeps it, asked under the ledger's transfer lock before anything is
/// removed (WP-7.11). A `plan` changes nothing: no session is closed, no temporary and no object
/// removed, every candidate counted (WP-7.11b).
pub(crate) fn sweep_within(
    store: &FileObjectStore,
    grace: Duration,
    budget: &mut usize,
    held: &dyn Fn() -> Result<bool>,
    plan: bool,
) -> Result<Swept> {
    // The transfer sessions first (WP-7.12): one past its expiry is closed before it stops
    // counting, and every session still kept pins what its transfer may touch. A session that
    // does not read stops the sweep of this ledger: what it pins is not known.
    let now = SystemTime::now();
    // Held to the end of the sweep: a negotiation that pins an object waits until the sweep has
    // decided, so nothing it was told is present is removed after it was told.
    let transfers = store.transfers().map_err(|error| anyhow!("{error}"))?;
    // A held ledger is kept whole, its transfer sessions too: asked before any is closed, and
    // asked again below, right before anything is removed (after the review).
    let kept_whole = || -> Result<Swept> {
        let objects = store.list_objects().map_err(|error| anyhow!("{error}"))?;
        Ok(Swept {
            held: true,
            held_objects: objects.len(),
            ..Swept::default()
        })
    };
    if held()? {
        return kept_whole();
    }
    let pinned = {
        let unix = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        // A plan closes nothing: a session past its expiry still pins what it pinned.
        if !plan {
            transfers
                .sweep(unix, grace)
                .map_err(|error| anyhow!("{error}"))?;
        }
        transfers.pins().map_err(|error| anyhow!("{error}"))?
    };
    let objects = store.list_objects().map_err(|error| anyhow!("{error}"))?;
    let reached = if objects.is_empty() {
        BTreeSet::new()
    } else {
        reachable(store)?
    };
    // The holds read again last, right before anything is removed: a hold added since the pass
    // began, even during the walk above, keeps the ledger whole, temporaries included (WP-7.11).
    if held()? {
        return Ok(Swept {
            held: true,
            held_objects: objects.len(),
            ..Swept::default()
        });
    }
    // A temporary is a write that never finished, unless it is younger than any write lasts: the
    // grace period that keeps a push in flight safe keeps its temporaries safe too.
    // A temporary that cannot be swept costs disk, not correctness: it never stops the
    // collection of the objects.
    let temporaries = if plan {
        0
    } else {
        match store.sweep_temporaries(grace) {
            Ok(swept) => swept,
            Err(error) => {
                warn!(
                    event.name = "gc.temporaries_not_swept",
                    component = COMPONENT,
                    ledger = %store.root().display(),
                    error = %error,
                    "the temporaries of interrupted writes could not be swept"
                );
                0
            }
        }
    };
    let mut swept = Swept {
        temporaries,
        ..Swept::default()
    };

    for object in objects {
        if reached.contains(&object.digest) {
            swept.reached += 1;
            continue;
        }
        if pinned.contains(&object.digest) {
            swept.pinned += 1;
            continue;
        }
        // Young and unreachable is what a push in flight looks like.
        let age = now
            .duration_since(object.modified)
            .unwrap_or(Duration::ZERO);
        if age < grace {
            swept.retained += 1;
            continue;
        }
        swept.candidates += 1;
        swept.candidate_bytes += object.bytes;
        if plan {
            continue;
        }
        // Past the bound the rest is left to the next pass, still counted as retained.
        if *budget == 0 {
            swept.exhausted = true;
            swept.retained += 1;
            swept.deferred += 1;
            continue;
        }
        *budget -= 1;
        let reclaimed = store
            .remove_object(&object.digest)
            .map_err(|error| anyhow!("{error}"))?;
        swept.removed += 1;
        swept.reclaimed += reclaimed;
    }
    drop(transfers);

    Ok(swept)
}

/// Everything every ref of this ledger reaches.
///
/// Every ref, not the default one: a ledger may serve several, and a sweep
/// that knew about one would delete the others. A hole in the closure — an
/// object a ref names and the store does not hold — stops the sweep for this
/// ledger rather than being walked around: a store that cannot be fully read
/// is not a store to delete from.
pub(crate) fn reachable(store: &FileObjectStore) -> Result<BTreeSet<Digest>> {
    let refs = store.list_refs().map_err(|error| anyhow!("{error}"))?;
    reachable_from(store, refs.into_iter().map(|(_, state)| state.head))
}

/// Everything `heads` reach in `store`; a hole in the closure is an error, as for [`reachable`].
pub(crate) fn reachable_from(
    store: &FileObjectStore,
    heads: impl IntoIterator<Item = Digest>,
) -> Result<BTreeSet<Digest>> {
    let mut reached = BTreeSet::new();
    let mut queue: Vec<Digest> = heads.into_iter().collect();

    while let Some(digest) = queue.pop() {
        if !reached.insert(digest.clone()) {
            continue;
        }
        let bytes = store
            .get_object(&digest)
            .map_err(|error| anyhow!("{error}"))?
            .ok_or_else(|| {
                anyhow!("the object {digest} is referenced and missing: refusing to sweep")
            })?;
        match object::decode(&bytes).map_err(|error| anyhow!("{digest}: {error}"))? {
            Object::Commit(commit) => {
                queue.push(commit.tree);
                queue.push(commit.manifest);
                queue.extend(commit.predecessors);
            }
            Object::Tree(tree) => {
                queue.extend(tree.entries.into_iter().map(|entry| entry.digest));
            }
            Object::Blob(_) => {}
        }
    }

    Ok(reached)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_core::assurance::AssuranceProfile;
    use permguard_host::holds::{Deadline, HoldStore, NewHold};
    use permguard_host::operations::journal::Initiator;
    use permguard_host::operations::mutation::Mutations;
    use permguard_host::storage::volume::Volume;
    use permguard_objects::object::Blob;
    use permguard_std::catalog::FileCatalog;

    use super::*;

    /// Two ledgers of one zone, each holding one orphan old enough to go, and the volume's holds.
    struct Fixture {
        sweep: Sweep,
        holds: Arc<HoldStore>,
        mutations: Mutations,
        zone: String,
        ledgers: Vec<(String, FileObjectStore, permguard_objects::Digest)>,
    }

    fn fixture(tag: &str) -> Fixture {
        let root = std::env::temp_dir().join(format!(
            "permguard-gc-holds-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let catalog = Arc::new(FileCatalog::new(root.join("zones")));
        let zone = catalog.create_zone("delivery").expect("a zone");
        let mut ledgers = Vec::new();
        for name in ["policies", "rules"] {
            let ledger = catalog
                .create_ledger(&Selector::Id(zone.id.clone()), name)
                .expect("a ledger");
            let store = FileObjectStore::new(
                root.join("zones")
                    .join(&zone.id)
                    .join("ledgers")
                    .join(&ledger.id),
            );
            let bytes = Blob {
                media_type: "application/vnd.permguard.policy.cedar".to_owned(),
                data: format!("permit (principal, action, resource); // {name}").into_bytes(),
            }
            .encode()
            .expect("a blob");
            let digest = store.put_object(&bytes).expect("stored").0;
            let hex = digest.to_string();
            let hex = &hex["sha256:".len()..];
            std::fs::File::options()
                .write(true)
                .open(store.root().join("objects").join(&hex[..2]).join(&hex[2..]))
                .expect("the object")
                .set_modified(std::time::SystemTime::now() - Duration::from_secs(30 * 86_400))
                .expect("aged");
            ledgers.push((ledger.id, store, digest));
        }
        let volume =
            Volume::claim(&root.join("volume"), AssuranceProfile::Development).expect("a volume");
        let holds = Arc::new(HoldStore::open(&volume).expect("the holds"));
        let mutations = Mutations::open_offline(&volume, "test").expect("the transaction");
        Fixture {
            sweep: Sweep {
                catalog,
                root: root.join("zones"),
                grace: Duration::from_secs(60),
                metrics: Metrics::none(),
                recorder: None,
                holds: Ok(Some(Arc::clone(&holds))),
                max_removals: usize::MAX,
                cursor: Arc::new(Mutex::new(None)),
                serial: Arc::new(Mutex::new(())),
            },
            holds,
            mutations,
            zone: zone.id,
            ledgers,
        }
    }

    fn hold(fixture: &Fixture, resource: String) -> String {
        permguard_host::holds::add(
            &fixture.mutations,
            &fixture.holds,
            Initiator::System("test".to_owned()),
            NewHold {
                resource,
                owner: "legal".to_owned(),
                reason: "litigation".to_owned(),
                deadline: Deadline::Review(permguard_host::authz::store::now() + 3_600),
            },
            permguard_host::authz::store::now(),
        )
        .expect("held")
        .id
    }

    fn present(fixture: &Fixture) -> Vec<bool> {
        fixture
            .ledgers
            .iter()
            .map(|(_, store, digest)| store.has_object(digest))
            .collect()
    }

    /// WP-7.3c, owner decision of 2026-10-21: a held ledger is not swept at all, its unreachable
    /// objects included; the ledger beside it is swept as before, and a released hold keeps
    /// nothing.
    #[test]
    fn a_held_ledger_is_not_swept() {
        let fixture = fixture("ledger");
        let id = hold(
            &fixture,
            format!(
                "plane/control/zone/{}/ledger/{}",
                fixture.zone, fixture.ledgers[0].0
            ),
        );

        let outcome = fixture.sweep.run();
        assert_eq!((outcome.held, outcome.removed, outcome.skipped), (1, 1, 0));
        assert_eq!(present(&fixture), vec![true, false]);

        permguard_host::holds::release(
            &fixture.mutations,
            &fixture.holds,
            Initiator::System("test".to_owned()),
            &id,
        )
        .expect("released");
        let outcome = fixture.sweep.run();
        assert_eq!((outcome.held, outcome.removed), (0, 1));
        assert_eq!(present(&fixture), vec![false, false]);
    }

    /// WP-7.3c, owner decision of 2026-10-21: a zone's hold keeps every ledger of the zone.
    #[test]
    fn a_zone_hold_keeps_every_ledger_of_the_zone() {
        let fixture = fixture("zone");
        hold(&fixture, format!("plane/control/zone/{}", fixture.zone));

        let outcome = fixture.sweep.run();
        assert_eq!((outcome.held, outcome.removed), (2, 0));
        assert_eq!(present(&fixture), vec![true, true]);
    }

    /// WP-7.3c, owner decision of 2026-10-21: holds that cannot be read sweep nothing that pass.
    #[test]
    fn unreadable_holds_sweep_nothing() {
        let fixture = fixture("unreadable");
        let volume = fixture
            .sweep
            .root
            .parent()
            .expect("the root")
            .join("volume");
        std::fs::write(
            volume
                .join("host")
                .join(permguard_host::holds::DIRECTORY)
                .join("01a00000-0000-7000-8000-00000000000c.json"),
            b"{ not a hold",
        )
        .expect("a broken hold");

        let outcome = fixture.sweep.run();
        assert!(outcome.holds_unreadable);
        assert_eq!(
            (outcome.removed, outcome.ledgers, outcome.label()),
            (0, 0, "partial")
        );
        assert_eq!(present(&fixture), vec![true, true]);
        assert_eq!(
            trail_target(&outcome),
            "nothing swept: the holds could not be read"
        );
    }

    /// WP-7.3c, after the review: a plane a Host registered, declaring it reads the holds and
    /// handed none, sweeps nothing: it cannot know what is held.
    #[test]
    fn a_plane_handed_no_holds_sweeps_nothing() {
        let mut fixture = fixture("missing");
        fixture.sweep.holds = Err(());

        let outcome = fixture.sweep.run();
        assert!(outcome.holds_unreadable);
        assert_eq!(present(&fixture), vec![true, true]);
    }

    /// WP-7.3c, owner decision of 2026-10-21: an expired hold keeps nothing; its ledger is swept.
    #[test]
    fn an_expired_hold_keeps_nothing_from_the_sweep() {
        let fixture = fixture("expired");
        let id = hold(
            &fixture,
            format!(
                "plane/control/zone/{}/ledger/{}",
                fixture.zone, fixture.ledgers[0].0
            ),
        );
        // Its deadline moved into the past, as the clock would move it.
        let path = fixture
            .sweep
            .root
            .parent()
            .expect("the root")
            .join("volume")
            .join("host")
            .join(permguard_host::holds::DIRECTORY)
            .join(format!("{id}.json"));
        let mut written: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).expect("the hold")).expect("JSON");
        written
            .as_object_mut()
            .expect("an object")
            .remove("review_at");
        written["expires_at"] = serde_json::json!(1);
        std::fs::write(&path, written.to_string()).expect("rewritten");

        let outcome = fixture.sweep.run();
        assert_eq!((outcome.held, outcome.removed), (0, 2));
        assert_eq!(present(&fixture), vec![false, false]);
    }

    /// WP-7.11: a hold added after a pass listed the holds still keeps its ledger whole: the
    /// sweep reads them again under the ledger's lock, before anything of it is removed.
    #[test]
    fn a_hold_added_during_a_pass_keeps_its_ledger() {
        let fixture = fixture("hold-during");
        let (ledger, store, digest) = &fixture.ledgers[0];
        hold(
            &fixture,
            format!("plane/control/zone/{}/ledger/{}", fixture.zone, ledger),
        );
        let temporary = store.root().join("objects").join(".tmp-stale");
        std::fs::write(&temporary, b"half").expect("a temporary");
        std::fs::File::options()
            .write(true)
            .open(&temporary)
            .expect("the temporary")
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(30 * 86_400))
            .expect("aged");
        let mut budget = usize::MAX;
        let swept = fixture
            .sweep
            .sweep_ledger(store, &fixture.zone, ledger, &mut budget)
            .expect("swept");
        assert!(swept.held);
        assert_eq!((swept.removed, swept.temporaries), (0, 0));
        assert!(store.has_object(digest), "kept");
        assert!(temporary.exists(), "its temporaries too");
        // The same temporary in a ledger no hold keeps is swept: the one above was kept.
        let (other, free, _) = &fixture.ledgers[1];
        let stale = free.root().join("objects").join(".tmp-stale");
        std::fs::write(&stale, b"half").expect("a temporary");
        std::fs::File::options()
            .write(true)
            .open(&stale)
            .expect("the temporary")
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(30 * 86_400))
            .expect("aged");
        let swept = fixture
            .sweep
            .sweep_ledger(free, &fixture.zone, other, &mut budget)
            .expect("swept");
        assert_eq!((swept.held, swept.temporaries), (false, 1));
    }

    /// WP-7.11: a pass removes at most its bound and the next resumes in the ledger it stopped
    /// in, so every ledger is reached however much is due; the record says where it resumes.
    #[test]
    fn a_pass_stops_at_its_bound_and_the_next_resumes_there() {
        let mut fixture = fixture("bounded");
        fixture.sweep.max_removals = 1;
        let first = fixture.sweep.run();
        assert_eq!(first.removed, 1);
        let resumes = first.resumes_at.clone().expect("cut at its bound");
        assert!(trail_target(&first).contains(&format!("resumes at {resumes}")));
        let gone: Vec<bool> = present(&fixture).iter().map(|held| !held).collect();
        assert_eq!(gone.iter().filter(|gone| **gone).count(), 1);
        let (stopped, _, _) = fixture
            .ledgers
            .iter()
            .find(|(_, store, digest)| store.has_object(digest))
            .expect("one left");
        assert_eq!(resumes, format!("{}/{}", fixture.zone, stopped));
        // An old orphan appears where the first pass already swept: the next pass starts where
        // the first stopped, so it removes the stopped ledger's and leaves this one's.
        let (_, swept_store, _) = fixture
            .ledgers
            .iter()
            .find(|(_, store, digest)| !store.has_object(digest))
            .expect("the swept ledger");
        let late = Blob {
            media_type: "application/vnd.permguard.policy.cedar".to_owned(),
            data: b"a late orphan".to_vec(),
        }
        .encode()
        .expect("a blob");
        let late = swept_store.put_object(&late).expect("stored").0;
        let hex = late.to_string();
        let hex = &hex["sha256:".len()..];
        std::fs::File::options()
            .write(true)
            .open(
                swept_store
                    .root()
                    .join("objects")
                    .join(&hex[..2])
                    .join(&hex[2..]),
            )
            .expect("the object")
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(30 * 86_400))
            .expect("aged");
        let second = fixture.sweep.run();
        assert_eq!(second.removed, 1);
        assert_eq!(present(&fixture), vec![false, false]);
        assert!(
            swept_store.has_object(&late),
            "the pass started where the last stopped"
        );
        let _ = fixture.sweep.run();
        assert!(!swept_store.has_object(&late));
        // Nothing left: the pass ends without a cursor.
        let last = fixture.sweep.run();
        assert_eq!((last.removed, last.resumes_at), (0, None));
    }

    /// WP-7.11: with no budget left a ledger is not swept at all, and is where the next pass
    /// starts.
    #[test]
    fn no_budget_removes_nothing() {
        let fixture = fixture("no-budget");
        let (ledger, store, digest) = &fixture.ledgers[0];
        let mut budget = 0;
        let swept = fixture
            .sweep
            .sweep_ledger(store, &fixture.zone, ledger, &mut budget)
            .expect("swept");
        assert!(swept.exhausted);
        assert_eq!(swept.removed, 0);
        assert!(store.has_object(digest));
    }

    /// WP-7.3c, owner decision of 2026-10-21: the `store.swept` record counts the held ledgers.
    #[test]
    fn the_sweep_record_counts_the_held_ledgers() {
        let target = trail_target(&Outcome {
            ledgers: 3,
            removed: 4,
            reclaimed: 5,
            retained: 6,
            temporaries: 0,
            skipped: 0,
            held: 2,
            holds_unreadable: false,
            resumes_at: None,
        });
        assert_eq!(
            target,
            "3 ledgers swept, 4 objects removed, 5 bytes reclaimed, 6 retained, 0 skipped, 2 held"
        );
    }

    fn job(fixture: &Fixture) -> ObjectsJob {
        ObjectsJob {
            sweep: fixture.sweep.clone(),
            runtime: None,
        }
    }

    fn ledger_resource(fixture: &Fixture, index: usize) -> permguard_core::authz::Resource {
        permguard_core::authz::Resource::ledger(
            crate::service::PLANE,
            &fixture.zone,
            &fixture.ledgers[index].0,
        )
    }

    /// An aged temporary in the first ledger's fanout: what an interrupted write leaves.
    fn temporary(fixture: &Fixture) -> std::path::PathBuf {
        let (_, store, digest) = &fixture.ledgers[0];
        let hex = digest.to_string();
        let path = store
            .root()
            .join("objects")
            .join(&hex["sha256:".len().."sha256:".len() + 2])
            .join(".tmp-00000000000000aa");
        std::fs::write(&path, b"interrupted").expect("written");
        std::fs::File::options()
            .write(true)
            .open(&path)
            .expect("the temporary")
            .set_modified(std::time::SystemTime::now() - Duration::from_secs(3_600))
            .expect("aged");
        path
    }

    /// WP-7.11b: a plan removes nothing, temporaries included, and counts what a run of the same
    /// scope removes; a run of one ledger leaves the other.
    #[test]
    fn a_plan_changes_nothing_and_counts_what_a_run_removes() {
        use permguard_host::gc::GcJob as _;
        let fixture = fixture("job-plan");
        let job = job(&fixture);
        let temporary = temporary(&fixture);
        let planned = job
            .plan(&permguard_core::authz::Resource::plane(
                crate::service::PLANE,
            ))
            .expect("planned");
        assert_eq!(planned.entries.len(), 2);
        for (index, entry) in planned.entries.iter().enumerate() {
            assert_eq!(entry.resource, ledger_resource(&fixture, index).to_string());
            assert_eq!(entry.candidates, 1, "{entry:?}");
            assert!(entry.candidate_bytes > 0);
            assert_eq!((entry.removed, entry.removed_bytes), (0, 0));
        }
        assert_eq!(
            present(&fixture),
            vec![true, true],
            "a plan removes nothing"
        );
        assert!(temporary.exists(), "a plan leaves the temporaries");
        assert!(planned.resumes_at.is_none());

        let ran = job
            .run(&ledger_resource(&fixture, 0), "plan-1")
            .expect("ran");
        assert_eq!(ran.entries.len(), 1, "the scope alone");
        assert_eq!(ran.entries[0].removed, 1);
        assert_eq!(
            ran.entries[0].removed_bytes,
            planned.entries[0].candidate_bytes
        );
        assert_eq!(present(&fixture), vec![false, true]);
        assert!(!temporary.exists(), "a run sweeps the temporaries");

        let replanned = job
            .plan(&permguard_core::authz::Resource::zone(
                crate::service::PLANE,
                &fixture.zone,
            ))
            .expect("planned");
        let candidates: Vec<u64> = replanned
            .entries
            .iter()
            .map(|entry| entry.candidates)
            .collect();
        assert_eq!(candidates, vec![0, 1]);
    }

    /// WP-7.11b: a plan closes no transfer session: one open past its expiry is still open after
    /// it, and still pins what it pinned; a run closes it as the background pass does.
    #[test]
    fn a_plan_closes_no_session_and_a_run_does() {
        use crate::transfer::{Direction, Session, State};
        use permguard_host::gc::{GcJob as _, Kept};
        let fixture = fixture("job-session");
        let (_, store, digest) = &fixture.ledgers[0];
        let now = permguard_host::authz::store::now();
        store
            .transfers()
            .expect("the transfers")
            .put(&Session {
                transfer_id: [7; 16],
                direction: Direction::Push,
                principal: "operator".to_owned(),
                authority_host_id: [1; 16],
                zone: fixture.zone.clone(),
                ledger: fixture.ledgers[0].0.clone(),
                r#ref: "main".to_owned(),
                request_id: "push-1".to_owned(),
                parameters: permguard_objects::Digest::compute(b"parameters"),
                new_head: Some(permguard_objects::Digest::compute(b"head")),
                expected_ref: None,
                max_batch_bytes: 1024,
                max_batch_objects: 10,
                reservation: 100,
                landed: 0,
                expiry: now - 10,
                state: State::Open,
                closed_at: None,
                pins: vec![digest.clone()],
                result: None,
            })
            .expect("an expired session");
        let open = |store: &FileObjectStore| {
            store
                .transfers()
                .expect("the transfers")
                .list()
                .expect("listed")
                .iter()
                .any(|session| session.state == State::Open)
        };
        let ledger = ledger_resource(&fixture, 0);
        let planned = job(&fixture).plan(&ledger).expect("planned");
        assert!(open(store), "a plan closes nothing");
        assert_eq!(
            planned.entries[0].kept,
            vec![Kept {
                reason: "pinned".to_owned(),
                count: 1,
            }]
        );
        assert_eq!(planned.entries[0].candidates, 0);
        job(&fixture).run(&ledger, "plan-4").expect("ran");
        assert!(!open(store), "a run closes the expired session");
        assert!(store.has_object(digest), "whose pin lasts the grace after");
    }

    /// WP-7.11, after the review: the holds are asked twice under the lock, before any session
    /// is closed and right before anything is removed; a hold that appears between the two keeps
    /// the ledger whole.
    #[test]
    fn a_hold_found_at_the_second_ask_keeps_the_ledger() {
        let fixture = fixture("held-late");
        let (_, store, digest) = &fixture.ledgers[0];
        let asked = std::cell::Cell::new(0);
        let held = || -> Result<bool> {
            asked.set(asked.get() + 1);
            Ok(asked.get() > 1)
        };
        let mut budget = usize::MAX;
        let swept =
            sweep_within(store, Duration::from_secs(60), &mut budget, &held, false).expect("swept");
        assert_eq!(asked.get(), 2);
        assert!(swept.held);
        assert_eq!((swept.removed, swept.held_objects), (0, 1));
        assert!(store.has_object(digest));
    }

    /// WP-7.11b, after the review: neither a plan nor a scoped run reads or moves the cursor the
    /// background pass resumes at; and a scope naming nothing of the catalog is refused.
    #[test]
    fn a_plan_or_a_scoped_run_leaves_the_cursor() {
        use permguard_host::gc::{GcError, GcJob as _};
        let mut fixture = fixture("job-cursor");
        fixture.sweep.max_removals = 0;
        let first = fixture.sweep.run();
        let at = first.resumes_at.clone().expect("stopped at its bound");
        let cursor = || fixture.sweep.cursor.lock().expect("the cursor").clone();
        assert_eq!(cursor().as_deref(), Some(at.as_str()));
        let job = job(&fixture);
        job.plan(&permguard_core::authz::Resource::plane(
            crate::service::PLANE,
        ))
        .expect("planned");
        assert_eq!(cursor().as_deref(), Some(at.as_str()), "a plan leaves it");
        job.run(&ledger_resource(&fixture, 1), "plan-5")
            .expect("ran");
        assert_eq!(
            cursor().as_deref(),
            Some(at.as_str()),
            "a scoped run leaves it"
        );
        assert!(matches!(
            job.plan(&permguard_core::authz::Resource::zone(
                crate::service::PLANE,
                "nothing"
            )),
            Err(GcError::NotFound(_))
        ));
        assert!(matches!(
            job.run(
                &permguard_core::authz::Resource::ledger(
                    crate::service::PLANE,
                    &fixture.zone,
                    "nothing"
                ),
                "plan-6"
            ),
            Err(GcError::NotFound(_))
        ));
    }

    /// WP-7.11b: a plan says why it keeps what it keeps: a held ledger whole, a young object for
    /// the grace, and the bound a run stops at.
    #[test]
    fn a_report_says_what_is_kept_and_why() {
        use permguard_host::gc::{GcJob as _, Kept};
        let mut fixture = fixture("job-kept");
        hold(
            &fixture,
            format!(
                "plane/control/zone/{}/ledger/{}",
                fixture.zone, fixture.ledgers[0].0
            ),
        );
        let (_, store, _) = &fixture.ledgers[1];
        store
            .put_object(
                &Blob {
                    media_type: "application/vnd.permguard.policy.cedar".to_owned(),
                    data: b"forbid (principal, action, resource);".to_vec(),
                }
                .encode()
                .expect("a blob"),
            )
            .expect("a young orphan");
        let plane = permguard_core::authz::Resource::plane(crate::service::PLANE);
        let planned = job(&fixture).plan(&plane).expect("planned");
        let held = Kept {
            reason: "held".to_owned(),
            count: 1,
        };
        let grace = Kept {
            reason: "grace".to_owned(),
            count: 1,
        };
        assert_eq!(planned.entries[0].kept, vec![held.clone()]);
        assert_eq!(planned.entries[0].candidates, 0);
        assert_eq!(planned.entries[1].kept, vec![grace.clone()]);
        assert_eq!(planned.entries[1].candidates, 1);
        assert_eq!(present(&fixture), vec![true, true]);

        // No removal left: the run stops in the unheld ledger and says it resumes there.
        fixture.sweep.max_removals = 0;
        let ran = job(&fixture).run(&plane, "plan-2").expect("ran");
        assert_eq!(ran.entries[0].kept, vec![held]);
        let bound = Kept {
            reason: "bound".to_owned(),
            count: 1,
        };
        assert_eq!(ran.entries[1].kept, vec![grace, bound]);
        assert_eq!(ran.entries[1].removed, 0);
        assert_eq!(
            ran.resumes_at.as_deref(),
            Some(ledger_resource(&fixture, 1).to_string().as_str())
        );
        assert_eq!(present(&fixture), vec![true, true]);
    }

    /// WP-7.11b: an operator's run waits for a pass in progress, and a scope that is not this
    /// Plane's is refused.
    #[test]
    fn a_run_waits_for_the_pass_in_progress() {
        use permguard_host::gc::GcJob as _;
        let fixture = fixture("job-serial");
        let job = job(&fixture);
        assert!(
            job.plan(&permguard_core::authz::Resource::plane("data-plane"))
                .is_err()
        );
        assert!(
            job.run(&permguard_core::authz::Resource::host(), "p")
                .is_err()
        );
        let serial = Arc::clone(&fixture.sweep.serial);
        let held = serial.lock().expect("the pass in progress");
        let running = std::thread::spawn(move || {
            job.run(
                &permguard_core::authz::Resource::plane(crate::service::PLANE),
                "plan-3",
            )
        });
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(present(&fixture), vec![true, true], "the run waits");
        drop(held);
        let ran = running.join().expect("joined").expect("ran");
        assert_eq!(
            ran.entries.iter().map(|entry| entry.removed).sum::<u64>(),
            2
        );
        assert_eq!(present(&fixture), vec![false, false]);
    }

    /// WP-7.11b: the record of an operator's run names its plan and scope.
    #[test]
    fn a_run_record_names_its_plan_and_scope() {
        assert_eq!(scope_label(&Scope::All), "every ledger");
        assert_eq!(scope_label(&Scope::Zone("z".to_owned())), "zone z");
        assert_eq!(
            scope_label(&Scope::Ledger("z".to_owned(), "l".to_owned())),
            "ledger z/l"
        );
        assert_eq!(
            Scope::of(&permguard_core::authz::Resource::zone(
                crate::service::PLANE,
                "z"
            )),
            Ok(Scope::Zone("z".to_owned()))
        );
        assert!(Scope::Ledger("z".to_owned(), "l".to_owned()).covers("z", "l"));
        assert!(!Scope::Ledger("z".to_owned(), "l".to_owned()).covers("z", "m"));
        assert!(!Scope::Zone("z".to_owned()).covers("y", "l"));
    }
}
