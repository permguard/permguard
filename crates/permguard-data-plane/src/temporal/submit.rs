// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one path both transports call: an occurrence in, a decision or a receipt out.
//!
//! # Everything that can be wrong lives here
//!
//! The bindings below are three lines each. That is deliberate and it is the same rule the
//! stateless interface follows: HTTP and gRPC must deserialize into the same domain request and
//! call the same implementation, because an interface whose two transports each carry a copy of
//! the validation has two interfaces, and the second one is the one that is wrong.

use std::sync::Arc;
use std::time::Instant;

use permguard_core::{ApiError, ErrorClass};
use permguard_events::record::{RECORD_TYPE, Record, occurrence_digest_of};
use permguard_languages::event::{Occurrence, OccurrenceBody};
use permguard_languages::temporal::{
    self, Applied, Checked, HistoryScope, Outcome, SubmitRequest, SubmitResponse, Temporal,
    Watermark,
};
use tracing::{debug, info, warn};

use crate::authz::decide::{Decider, Loaded};
use crate::authz::snapshot::Partition;

use super::measure;
use super::streams::{Failed, Streams, Written};

const COMPONENT: &str = "temporal";

/// One partition of the profile, with the remembering half it answers through.
type Addressed<'a> = (&'a Arc<Partition>, &'a dyn Temporal);

/// One partition, its engine, and what the schemas said about this occurrence.
type Verified<'a> = (Arc<Partition>, &'a dyn Temporal, Checked);

/// What the uncancellable core produced.
///
/// Both arms are boxed: they are the two ends of one submission and neither is rare, so sizing
/// every return by the larger of them would move a response-sized value through the pool's result
/// for no benefit.
enum Staged {
    /// The answer is complete: an accepted receipt, or a retry answered from what was recorded.
    Answered(Box<SubmitResponse>),
    /// A verdict was reached, and it may not leave before it is recorded.
    Decided(Box<Decided>),
}

/// A verdict, and everything the recording of it still needs.
///
/// Boxed because it is the rare arm: most submissions to a history-only kind answer without one,
/// and an enum sized by its largest variant would make every one of them carry this.
struct Decided {
    loaded: Loaded,
    occurrence: Occurrence,
    occurrence_kind: String,
    profile: String,
    zone: String,
    ledger: String,
    record: Record,
    watermark: Watermark,
    history: HistoryScope,
    evaluations: Vec<permguard_languages::temporal::PartitionEvaluation>,
    outcome: permguard_languages::evaluate::Outcome,
    decision_id: String,
    reason: permguard_languages::temporal::Reason,
}

/// The temporal interface's implementation.
///
/// Holds the [`Decider`] rather than duplicating it: the ledger a submission names is resolved,
/// bounded and compiled by exactly the code that resolves it for a stateless request.
pub struct Submitter {
    decider: Arc<Decider>,
    streams: Arc<Streams>,
    /// The bound on concurrent blocking work — see [`crate::blocking`].
    blocking: crate::blocking::Blocking,
    metrics: permguard_core::metrics::Metrics,
    /// How far a caller's clock may run ahead of this one before its `occurred_at` is refused.
    clock_skew: std::time::Duration,
    /// How late an occurrence may arrive and still be recorded.
    allowed_lateness: std::time::Duration,
    /// Which history this plane's decisions range over.
    consistency: permguard_core::config::Consistency,
    /// The imported histories, when this plane reads other planes' events: what the HTTP pull
    /// imported before WP-6.2c, read-only.
    imports: Option<Arc<super::imports::Imports>>,
    /// The origins the member Host imports over `events.import` (WP-6.2c2b1): the history and the
    /// freshness a shared mode decides on.
    imported: Option<Arc<super::imported::Imported>>,
    /// How stale imported history may be before `shared-bounded` fails decisions closed.
    max_staleness: std::time::Duration,
    /// The imported watermark each `(zone, ledger, history, partition)` has been rebuilt to.
    ///
    /// So a rebuild is paid once per watermark rather than once per submission: replaying even a
    /// bounded history costs something, and the answer does not change until more arrives.
    ///
    /// Keyed by history and not merely by ledger, because histories are independent: what one
    /// caller's engine has absorbed says nothing about another's, and a note kept per ledger would
    /// let the first history replayed stand in for every history the ledger holds.
    ///
    /// And keyed by **partition**, because the engine state the note describes belongs to one
    /// partition. A rebuild replays only the partitions of the profile that asked, so a note kept
    /// per history would let profile B's rebuild of partition B mark the history clean while
    /// partition A — invalidated by the same late arrival — had absorbed nothing. Profile A's next
    /// request would then find its engine non-empty and the note current, skip the rebuild, and
    /// decide against a history that is still missing the event.
    applied: std::sync::Mutex<std::collections::BTreeMap<(String, String, String, String), String>>,
    /// What warm histories may hold, per partition, zone and Host (DOGWOOD-02).
    warm: Arc<permguard_languages::warm::Budget>,
    /// What a cold history's replay may cost (DOGWOOD-03).
    replay: ReplayPlan,
    /// How many cold replays are running now.
    replaying: std::sync::atomic::AtomicUsize,
    /// One lock per ledger, held for writing while prewarm replays one of its histories and for
    /// reading from a submission's replay to its apply: a prewarm never replaces an engine a
    /// submission is feeding, and never holds another ledger's submissions (after the review).
    prewarming: std::sync::Mutex<Exclusions>,
}

/// The prewarm exclusion of each ledger, by zone and ledger.
type Exclusions = std::collections::HashMap<(String, String), Arc<std::sync::RwLock<()>>>;

/// What `ensure_history` left behind: the partitions whose replay was abandoned, and the imported
/// history it captured — what the replay read and what the decision cites (WP-6.4a).
struct Ensured {
    abandoned: std::collections::BTreeMap<String, permguard_languages::evaluate::Verdict>,
    shared: Option<super::imported::Shared>,
}

impl Ensured {
    fn of(
        shared: Option<super::imported::Shared>,
        abandoned: std::collections::BTreeMap<String, permguard_languages::evaluate::Verdict>,
    ) -> Self {
        Self { abandoned, shared }
    }
}

/// The replay plan of a cold history (DOGWOOD-03, owner decision of 2026-10-21).
///
/// A replay is part of the decision that needed it. Past any of these limits the partitions it was
/// for answer `E` `evaluation_deadline_exceeded` — the replay cannot finish within the decision's
/// budget — and the history stays marked for replay; the occurrence is durable either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplayPlan {
    /// The most records one replay reads.
    pub max_records: u64,
    /// The most bytes one replay feeds an engine, as the occurrences spell them.
    pub max_bytes: u64,
    /// How long one submission's replay may run.
    pub timeout: std::time::Duration,
    /// How many cold replays run at once; a submission needing another is turned away at once.
    pub concurrency: usize,
}

impl Default for ReplayPlan {
    fn default() -> Self {
        Self {
            max_records: permguard_core::config::DEFAULT_EVENTS_REPLAY_MAX_RECORDS,
            max_bytes: permguard_core::config::DEFAULT_EVENTS_REPLAY_MAX_BYTES,
            timeout: permguard_core::config::DEFAULT_EVENTS_REPLAY_TIMEOUT,
            concurrency: permguard_core::config::DEFAULT_EVENTS_REPLAY_CONCURRENCY,
        }
    }
}

impl ReplayPlan {
    /// The plan a configuration states.
    pub fn of(config: &permguard_core::config::Config) -> Self {
        Self {
            max_records: config.events_replay_max_records(),
            max_bytes: config.events_replay_max_bytes(),
            timeout: config.events_replay_timeout(),
            concurrency: config.events_replay_concurrency(),
        }
    }
}

/// One cold replay's slot, given back when it is dropped.
struct Replaying<'a>(&'a std::sync::atomic::AtomicUsize);

impl Drop for Replaying<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Submitter {
    pub fn new(
        decider: Arc<Decider>,
        streams: Arc<Streams>,
        blocking: crate::blocking::Blocking,
        metrics: permguard_core::metrics::Metrics,
    ) -> Self {
        let bounds = streams.bounds();

        Self {
            decider,
            streams,
            blocking,
            metrics,
            clock_skew: bounds.clock_skew,
            allowed_lateness: bounds.allowed_lateness,
            // Local unless a deployment says otherwise: a plane that silently began deciding
            // against another plane's events would answer the same request differently, with
            // nothing to explain why.
            consistency: permguard_core::config::Consistency::Local,
            imports: None,
            imported: None,
            max_staleness: permguard_core::config::DEFAULT_EVENTS_PULL_MAX_STALENESS,
            applied: std::sync::Mutex::new(std::collections::BTreeMap::new()),
            warm: permguard_languages::warm::Budget::new(
                permguard_languages::warm::Limits::default(),
            ),
            replay: ReplayPlan::default(),
            replaying: std::sync::atomic::AtomicUsize::new(0),
            prewarming: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// The prewarm exclusion of one ledger.
    fn exclusion(&self, zone: &str, ledger: &str) -> Arc<std::sync::RwLock<()>> {
        let mut locks = match self.prewarming.lock() {
            Ok(locks) => locks,
            Err(poisoned) => poisoned.into_inner(),
        };
        Arc::clone(
            locks
                .entry((zone.to_owned(), ledger.to_owned()))
                .or_default(),
        )
    }

    /// Replays up to `count` recently used histories of each ledger this plane journals
    /// (DOGWOOD-03, owner decision of 2026-10-21), and returns how many it warmed.
    ///
    /// Run in the background after load. It claims nothing: readiness is not touched, and a
    /// submission that arrives first replays its own history as it always does. What it replays is
    /// what the ledger's sequencer has applied, read under the ledger's exclusion where it cannot
    /// move, under the same plan a submission's replay runs under — including its concurrency
    /// slots — and only into a history still cold: it never replaces an engine a submission fed,
    /// and the occurrences waiting for their turn apply on top of it in order.
    pub async fn prewarm(self: &Arc<Self>, count: usize) -> usize {
        /// How far back the tail read for recently used histories goes, per ledger.
        const TAIL: u64 = 4096;

        if count == 0 {
            return 0;
        }
        let mut ledgers = self.streams.host_ledgers();
        ledgers.extend(self.streams.ledgers());
        ledgers.sort();
        ledgers.dedup();

        let mut warmed = 0;
        for (zone, ledger) in ledgers {
            let Ok(sequencer) = self.streams.sequencer(&zone, &ledger) else {
                continue;
            };
            // Only where to read the tail from: what is replayed is bounded again under the lock.
            let through = sequencer.applied_through();
            let after = through.saturating_sub(TAIL);
            let Ok(tail) = self.streams.read_from(
                &zone,
                &ledger,
                after,
                usize::try_from(through - after).unwrap_or(usize::MAX),
            ) else {
                continue;
            };
            // The most recent occurrence of each history, newest histories first.
            let mut picked: Vec<Record> = Vec::new();
            for value in tail.iter().rev() {
                let Ok(record) = permguard_events::record::validate(value) else {
                    continue;
                };
                let same = |held: &Record| {
                    held.profile == record.profile && held.history_key == record.history_key
                };
                if let Some(held) = picked.iter_mut().find(|held| same(held)) {
                    if record.occurred_at > held.occurred_at {
                        *held = record;
                    }
                } else if picked.len() < count {
                    picked.push(record);
                }
            }
            for record in picked {
                let Ok(loaded) = self.decider.loaded(&zone, &ledger, &record.profile).await else {
                    continue;
                };
                let this = Arc::clone(self);
                let (zone, ledger) = (zone.clone(), ledger.clone());
                let warm = tokio::task::spawn_blocking(move || {
                    this.prewarm_one(&loaded, &zone, &ledger, &record)
                })
                .await
                .unwrap_or(false);
                if warm {
                    warmed += 1;
                }
            }
        }

        warmed
    }

    /// Replays one history up to what the ledger has applied, if it is still cold.
    fn prewarm_one(&self, loaded: &Loaded, zone: &str, ledger: &str, record: &Record) -> bool {
        let exclusion = self.exclusion(zone, ledger);
        let Ok(_exclusive) = exclusion.write() else {
            return false;
        };
        // Read under the lock: a submission releases its turn only after its apply, and none
        // reaches its replay while this is held, so what the ledger has applied cannot move now.
        let Ok(sequencer) = self.streams.sequencer(zone, ledger) else {
            return false;
        };
        let through = sequencer.applied_through();
        let Ok(addressed) = self.addressed(loaded, &record.profile) else {
            return false;
        };
        let Ok(body) = serde_json::from_value::<OccurrenceBody>(record.event.clone()) else {
            return false;
        };
        let Ok(occurrence) = body.read() else {
            return false;
        };
        let history = history_of(&record.history_key);
        let mut checks: Vec<Verified<'_>> = Vec::with_capacity(addressed.len());
        for (partition, engine) in &addressed {
            engine.bind_warm(&self.warm, zone);
            if permguard_languages::guard::contained(|| engine.observed(&history)).unwrap_or(1) > 0
            {
                return false;
            }
            let Ok(Ok(checked)) =
                permguard_languages::guard::contained(|| engine.check(&occurrence))
            else {
                return false;
            };
            checks.push((Arc::clone(partition), *engine, checked));
        }

        matches!(
            self.ensure_history(&checks, &history, &occurrence, zone, ledger, through + 1),
            Ok(ensured) if ensured.abandoned.is_empty()
        )
    }

    /// Charges warm histories to this budget (DOGWOOD-02).
    pub fn with_warm(mut self, budget: Arc<permguard_languages::warm::Budget>) -> Self {
        self.warm = budget;

        self
    }

    /// Replays cold histories under this plan (DOGWOOD-03).
    pub fn with_replay(mut self, plan: ReplayPlan) -> Self {
        self.replay = plan;

        self
    }

    /// The warm budget, for a caller that reports what it holds.
    pub fn warm(&self) -> &Arc<permguard_languages::warm::Budget> {
        &self.warm
    }

    /// Decides against imported history as well, under this mode.
    pub fn with_shared_history(
        self,
        consistency: permguard_core::config::Consistency,
        imports: Arc<super::imports::Imports>,
        max_staleness: std::time::Duration,
    ) -> Self {
        let mut this = self.with_shared_mode(consistency, max_staleness);
        this.imports = Some(imports);

        this
    }

    /// Decides under this shared mode with no store of the retired pull, once the volume archived
    /// it (WP-6.2d): a decision is scoped as over a store that never read anything, so without
    /// the Host's import `shared-bounded` still refuses.
    pub fn with_shared_mode(
        mut self,
        consistency: permguard_core::config::Consistency,
        max_staleness: std::time::Duration,
    ) -> Self {
        self.consistency = consistency;
        self.max_staleness = max_staleness;

        self
    }

    /// Decides against the origins the member Host imports as well (WP-6.2c2b1): their records,
    /// and freshness from the checkpoint the Host last verified.
    pub fn with_imported(mut self, imported: Arc<super::imported::Imported>) -> Self {
        self.imported = Some(imported);

        self
    }

    /// The origins the member Host imports, when this plane reads them.
    pub fn imported(&self) -> Option<&Arc<super::imported::Imported>> {
        self.imported.as_ref()
    }

    /// The retired pull's store, when this plane still reads it: not once the volume archived it
    /// (WP-6.2d).
    pub fn imports(&self) -> Option<&Arc<super::imports::Imports>> {
        self.imports.as_ref()
    }

    /// Which history this plane's decisions range over.
    pub fn consistency(&self) -> permguard_core::config::Consistency {
        self.consistency
    }

    /// The journals this plane writes, for the surfaces that report on them.
    pub fn streams(&self) -> &Arc<Streams> {
        &self.streams
    }

    /// The decider whose services this submitter shares: the verified snapshot, the scheduler
    /// and the decision log (WP-7.5d).
    pub fn decider(&self) -> &Decider {
        &self.decider
    }

    /// Where the mirrors this plane decides against are, for the gate's resolution of names.
    pub fn root(&self) -> &std::path::Path {
        self.decider.root()
    }

    /// Submits one occurrence as `source`, the principal the request authenticated as, once the
    /// gate authorized `event.submit` on the `authorized` ids (WP-6.2a): the mirror recorded under
    /// must be that one.
    pub async fn submit(
        self: &Arc<Self>,
        request: &SubmitRequest,
        source: &str,
        authorized: Option<&(String, String)>,
    ) -> Result<SubmitResponse, ApiError> {
        let started = Instant::now();
        let answered = self.answer(request, source, authorized).await;
        self.metrics.observe(
            &measure::SUBMISSION_SECONDS,
            &[],
            started.elapsed().as_secs_f64(),
        );

        answered
    }

    async fn answer(
        self: &Arc<Self>,
        request: &SubmitRequest,
        source: &str,
        authorized: Option<&(String, String)>,
    ) -> Result<SubmitResponse, ApiError> {
        // The plane's own clock on this submission, which the decision record carries: how long
        // this plane took, separate from how long the transport took.
        let started_at = Instant::now();
        let Read {
            zone,
            ledger,
            profile,
            occurrence,
            event,
        } = self.read(request)?;
        // Taken before the occurrence is consumed by the response it becomes part of: it is
        // recorded beside the answer, so a retry under a different type is a routing conflict
        // rather than something answered from the first occurrence's outcome.
        let occurrence_kind = occurrence.kind.clone();

        // One resolution, and everything below is keyed by what it returned.
        //
        // A caller may name a ledger by its identifier or by its display name, and both resolve to
        // one mirror — so keying storage by whichever string arrived would let one ledger own two
        // journals: two sequences, two histories, two idempotency indexes, neither aware of the
        // other. The names are what a caller reads; the identifiers are what this plane stores
        // under, and from here `zone` and `ledger` are the identifiers.
        //
        // Resolved from the mirror's identity file rather than by loading the profile, because a
        // settled retry has to be answerable when the profile it was decided under is gone.
        let mirror = permguard_data_plane_mirror_of(self.decider.root(), &zone, &ledger)?;
        let (zone_name, ledger_name) = (zone.clone(), ledger.clone());
        let zone = mirror.identity.zone_id.clone();
        let ledger = mirror.identity.ledger_id.clone();
        // A mirror replaced between the gate and here never widens the grant (WP-6.2a, as the
        // decision path does since WP-2.4).
        if let Some((zone_id, ledger_id)) = authorized
            && (&zone, &ledger) != (zone_id, ledger_id)
        {
            self.metrics.count(
                &measure::REFUSALS,
                &[(permguard_core::metrics::labels::REASON, "store_changed")],
            );
            return Err(ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::common::UNAVAILABLE,
                "the store the request names changed while the request was authorized; retry",
            ));
        }
        self.streams
            .adopt((&zone, &ledger), (&zone_name, &ledger_name))
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::EVENT_JOURNAL_AMBIGUOUS,
                    error.to_string(),
                )
            })?;

        // Answered from the journal before the profile is loaded, and deliberately in that order.
        //
        // A completed submission is a fact this plane already stated to a caller. Re-deriving it
        // needs the profile, schema and commit it was decided under, and none of those is
        // guaranteed to still be here: a profile is updated, a schema tightened, a partition
        // removed. Loading them first makes a retry of a settled answer fail for reasons that
        // postdate the answer — the caller is told the event is unknown, or invalid, when in fact
        // it is durable and was answered.
        //
        // So the durable answer wins, and everything checked before returning it is checked
        // against what was recorded rather than against what is loaded now: same ledger, same
        // identifier, same occurrence bytes, same routing.
        if let Some(settled) = self.settled(
            &zone,
            &ledger,
            source,
            &event,
            &occurrence.event_id,
            &profile,
            &occurrence_kind,
        )? {
            self.metrics.count(
                &measure::SUBMISSIONS,
                &[(permguard_core::metrics::labels::OUTCOME, "replayed")],
            );

            return Ok(settled);
        }

        let loaded = self.decider.loaded(&zone, &ledger, &profile).await?;
        // Everything synchronous the submission does — validating the occurrence against every
        // addressed partition, appending it, taking its turn, rebuilding the history and evaluating
        // it — runs here, on the shared blocking pool, as one unit.
        //
        // # Why one unit and not several
        //
        // The turn is the reason. `Sequencer` advances only when a `Turn` is dropped, so the span
        // from "this sequence exists" to "this sequence has been applied" must not contain a
        // suspension point: a request cancelled inside it would drop the turn with the record
        // durable and unapplied. Splitting the work across two `blocking.run(...).await` calls would
        // put an `.await` in exactly that span. So the whole span is one closure, and
        // `spawn_blocking` work is not cancelled — the caller may go away, the unit still finishes.
        //
        // # Why it belongs on the pool at all
        //
        // What is inside is not bookkeeping. Replay rescans the journal, and `apply` reaches
        // upstream's engine, which runs providers synchronously and cannot be interrupted. Left on
        // a runtime worker — which is where it used to be — one slow evaluation blocks a thread the
        // whole process shares, outside the bound the deployment configured, and health checks and
        // unrelated ledgers go unanswered behind it. On the pool it costs one permit of a bounded
        // budget, and the ceiling refuses rather than queues.
        let staged = {
            let this = Arc::clone(self);
            let staging = (
                Loaded {
                    mirror: loaded.mirror.clone(),
                    head: Arc::clone(&loaded.head),
                    partitions: loaded.partitions.clone(),
                },
                temporal_event_type(request).to_owned(),
                zone.clone(),
                ledger.clone(),
                profile.clone(),
                occurrence.clone(),
                occurrence_kind.clone(),
                event,
                source.to_owned(),
            );
            self.blocking
                .run(&[], move || {
                    let (
                        loaded,
                        event_type,
                        zone,
                        ledger,
                        profile,
                        occurrence,
                        kind,
                        event,
                        source,
                    ) = staging;

                    this.stage(
                        loaded, event_type, zone, ledger, profile, occurrence, kind, event, source,
                    )
                })
                .await
                .map_err(|refused| match refused {
                    crate::blocking::Refused::AtCapacity(held) => {
                        self.metrics.count(
                            &measure::REFUSALS,
                            &[(permguard_core::metrics::labels::REASON, "at_capacity")],
                        );

                        ApiError::new(
                            ErrorClass::Unavailable,
                            permguard_core::codes::pdp_temporal::EVENT_SUBMISSION_AT_CAPACITY,
                            format!(
                                "{held}. A submission holds one of them from the durable append \
                                 through the evaluation that follows it, so this plane bounds how \
                                 many may be outstanding and refuses beyond it rather than \
                                 queueing behind a disk or a provider"
                            ),
                        )
                    }
                    crate::blocking::Refused::Failed(why) => ApiError::new(
                        ErrorClass::Unavailable,
                        permguard_core::codes::pdp_temporal::EVENT_NOT_DURABLE,
                        format!("the occurrence could not be applied: {why}"),
                    ),
                })??
        };
        let Decided {
            loaded,
            occurrence,
            occurrence_kind,
            profile,
            zone,
            ledger,
            record,
            watermark,
            history,
            evaluations,
            outcome,
            decision_id,
            reason,
        } = match staged {
            Staged::Answered(response) => return Ok(*response),
            Staged::Decided(decided) => *decided,
        };

        // Recorded before the answer leaves. A plane told to refuse rather than answer unrecorded
        // decisions refuses *here*, with the event already durable — which is the only order that
        // keeps both promises: the history is whole whatever happens next, and no verdict this
        // plane could not record has left it.
        self.decider
            .record_temporal(&crate::authz::decide::TemporalDecision {
                decision_id: &decision_id,
                mirror: &loaded.mirror,
                head: &loaded.head,
                profile: &profile,
                subject: (
                    occurrence.principal.kind.as_str(),
                    occurrence.principal.id.as_str(),
                ),
                resource: (
                    occurrence.resource.kind.as_str(),
                    occurrence.resource.id.as_str(),
                ),
                action: occurrence.action.as_str(),
                context: serde_json::to_value(&record.event).ok(),
                outcome: crate::authz::decide::recorded_outcome(outcome.resolution),
                causes: &outcome.causes(),
                policies: outcome.determining(),
                reason: &reason.code,
                request_id: None,
                latency_us: u64::try_from(started_at.elapsed().as_micros()).unwrap_or(u64::MAX),
                event: permguard_decisions::record::EventRef {
                    event_id: record.event_id.clone(),
                    event_type: record.event_type.clone(),
                    instance: watermark.instance.clone(),
                    sequence: watermark.sequence,
                    history: watermark.history.clone(),
                    consistency: Some(history.mode.clone()),
                    watermark: history.watermark.clone(),
                    // What the decision cited, as the answer says it (WP-6.4a).
                    frontier: history.frontier.clone(),
                    origin_set_revision: history.origin_set_revision.clone(),
                    max_staleness_seconds: history.max_staleness_seconds,
                    degraded: history.degraded.clone(),
                    time: Some(history.time.clone()),
                    quarantined: (history.quarantined > 0).then_some(history.quarantined),
                },
                actor: Some(source),
            })
            .await?;

        // An indeterminate result is answered as what it is — the occurrence is durable and
        // receipted, the verdict it did not get is never fabricated as a deny — and counted apart.
        let indeterminate = outcome.indeterminate();
        self.metrics.count(
            &measure::SUBMISSIONS,
            &[(
                permguard_core::metrics::labels::OUTCOME,
                if indeterminate {
                    "indeterminate"
                } else {
                    "decided"
                },
            )],
        );

        let response = SubmitResponse {
            outcome: if indeterminate {
                Outcome::Indeterminate
            } else {
                Outcome::Decided
            },
            event_id: occurrence.event_id,
            watermark,
            decision: (!indeterminate).then_some(outcome.permitted()),
            decision_id: Some(decision_id),
            policies: outcome.determining().to_vec(),
            evaluations,
            reason: Some(reason),
            history,
        };
        self.keep_outcome(
            &zone,
            &ledger,
            source,
            &response.event_id,
            crate::temporal::streams::Routed {
                profile: &profile,
                kind: &occurrence_kind,
            },
            &response,
        )?;

        Ok(response)
    }

    /// The uncancellable core: validate, append, order, replay, evaluate.
    ///
    /// Called only through [`crate::blocking::Blocking`], and everything in it is synchronous by
    /// design — see the call site for why the span may not be split and why it may not run on a
    /// runtime worker.
    #[allow(clippy::too_many_arguments)]
    fn stage(
        &self,
        loaded: Loaded,
        event_type: String,
        zone: String,
        ledger: String,
        profile: String,
        occurrence: Occurrence,
        occurrence_kind: String,
        event: serde_json::Value,
        source: String,
    ) -> Result<Staged, ApiError> {
        let addressed = self.addressed(&loaded, &profile)?;
        // Every engine charges its warm histories to this plane's budget, under this zone, before
        // it is handed any work (DOGWOOD-02).
        for (partition, engine) in &addressed {
            engine.bind_warm(&self.warm, &zone);
            // Each partition accepts the event version its manifest declares, version 1 when it
            // declares none (TL-5c): a version 2 partition never reads two bags, and a version 1
            // partition never projects.
            let accepts = partition
                .input
                .as_deref()
                .unwrap_or(permguard_languages::event::EVENT_TYPE);
            if accepts != event_type {
                return Err(ApiError::new(
                    ErrorClass::Validation,
                    permguard_core::codes::pdp_temporal::EVENT_TYPE_UNSUPPORTED,
                    format!(
                        "the partition `{}` accepts `{accepts}`, and the occurrence is \
                         `{event_type}`",
                        partition.name
                    ),
                ));
            }
        }

        // Every partition, before anything is written. A profile may address several with
        // different schemas, and an occurrence only some of them accept is not one this ledger can
        // hold: recording it would leave the addressed partitions holding different histories of
        // the same events.
        let mut checks: Vec<Verified<'_>> = Vec::with_capacity(addressed.len());
        for (partition, engine) in &addressed {
            let checked = contained(permguard_core::codes::common::INTERNAL, || {
                engine.check(&occurrence)
            })
            .map_err(|refused| {
                self.metrics.count(
                    &measure::REFUSALS,
                    &[(permguard_core::metrics::labels::REASON, refused.code)],
                );
                debug!(
                    event.name = "temporal.event_refused",
                    component = COMPONENT,
                    code = refused.code,
                    "an occurrence was refused before anything was recorded"
                );

                // An engine that came apart checking it refused nothing about the occurrence: that
                // is this plane's failure, not the caller's.
                let class = if refused.code == permguard_core::codes::common::INTERNAL {
                    ErrorClass::Internal
                } else {
                    ErrorClass::Validation
                };
                ApiError::new(
                    class,
                    refused.code,
                    format!("the partition `{}`: {}", partition.name, refused.message),
                )
            })?;
            checks.push((Arc::clone(partition), *engine, checked));
        }

        // Every addressed partition must agree about which history this occurrence belongs to.
        // Two partitions of one profile pinning it differently would be two answers to "which
        // events does this one see", and the record carries one history key.
        let history = self.history_key(&checks, &zone, &ledger)?;
        // The string that names it, computed once and used for all three things that must agree:
        // the record it is stored under, the index it is scanned by, and the engine that decides.
        let partition_key = history_of(&history);
        let decides = checks
            .first()
            .is_some_and(|(_, _, checked)| checked.decides);
        for (partition, _, checked) in &checks {
            if checked.decides == decides {
                continue;
            }

            return Err(ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::pdp_temporal::EVENT_KIND_DISAGREES,
                format!(
                    "the partitions of `{profile}` disagree about whether a `{}` event decides: \
                     `{}` says {}. One occurrence has one answer, and returning a verdict some \
                     partitions did not produce — or withholding one they did — is not it",
                    occurrence.kind,
                    partition.name,
                    if checked.decides {
                        "it does"
                    } else {
                        "it does not"
                    }
                ),
            ));
        }

        let observed_at = self.now()?;
        self.check_clock(&occurrence, &observed_at)?;

        // A loaded policy may ask for a wider history than this journal can retain. Check the
        // contract actually loaded for this ledger, not only the runtime's default at process
        // startup: accepting the event and discovering the mismatch after eviction would make the
        // same policy change its answer as the volume ages.
        self.admit_history_window(&checks, &zone, &ledger)?;

        let proposed = Record {
            v: 1,
            record_type: RECORD_TYPE.to_owned(),
            // Filled by the journal, which owns the stream identity: a producer a caller could
            // name is a producer a caller could impersonate.
            stream: permguard_events::record::Stream {
                producer: self.streams.producer().clone(),
                zone: zone.clone(),
                ledger: ledger.clone(),
            },
            seq: 0,
            prev: String::new(),
            event_type: event_type.clone(),
            event_id: occurrence.event_id.clone(),
            source: Some(source.clone()),
            occurrence_digest: occurrence_digest_of(&event).map_err(|error| {
                ApiError::new(
                    ErrorClass::Validation,
                    permguard_core::codes::pdp_temporal::EVENT_NOT_CANONICAL,
                    format!("the occurrence cannot be canonicalized: {error}"),
                )
            })?,
            kind: occurrence.kind.clone(),
            profile: profile.clone(),
            policy_partitions: addressed
                .iter()
                .map(|(partition, _)| partition.name.clone())
                .collect(),
            commit: loaded.head.commit.clone(),
            history_key: history.clone(),
            occurred_at: occurrence.occurred_at.clone(),
            observed_at,
            event,
        };

        // The append and the turn for what it assigned, in one uncancellable unit.
        //
        // # Why they cannot be separated
        //
        // The journal assigns a sequence, and `Sequencer` advances only when that sequence's
        // `Turn` is dropped — so a sequence nobody ever takes a turn for stalls every sequence
        // after it until the process restarts. `a_sequence_that_never_takes_its_turn_stalls_the_
        // ledger` is that invariant on its own.
        //
        // Anything that can suspend between the two makes that state reachable: a request
        // cancelled there — an HTTP timeout, a client that hung up — is dropped after the sequence
        // exists and before its turn is taken. Both halves therefore happen inside one
        // `spawn_blocking`, which cannot be cancelled: either the sequence is assigned and its turn
        // is held, or neither happened.
        //
        // Only for `Appended`. An idempotent retry assigns nothing, so there is no new sequence to
        // strand, and the recovery path deliberately takes the turn of an *older* sequence further
        // down — a cancellation there leaves the ledger exactly as stuck as it already was, and the
        // next retry heals it.
        //
        // The cost is that a permit is held while waiting for another submission to the same ledger
        // to apply. That is the pool doing its job: bounded, and refusing at the ceiling rather
        // than blocking a runtime worker as this used to.
        let (appended, appending, prepared) = {
            // The sequencer *before* the append, and its failure refuses before anything is
            // durable.
            //
            // Asking after the append is what this used to do, and the error had nowhere to go: the
            // record was already on disk, so the only options were to invent a turn or to return an
            // error for a sequence that now exists and would never be applied. A sequence nobody
            // takes a turn for stalls every sequence after it — and because the turn is waited on
            // while holding a blocking permit, every later submission to that ledger would hold one
            // for ever until the pool, which is shared with every other ledger and with the
            // stateless path, had none left. One unorderable ledger would have stopped the plane.
            //
            // Asked first, the failure costs nothing: no record, no sequence, no hole.
            let sequencer = self.streams.sequencer(&zone, &ledger).map_err(|error| {
                self.metrics.count(
                    &measure::REFUSALS,
                    &[(
                        permguard_core::metrics::labels::REASON,
                        permguard_core::codes::pdp_temporal::HISTORY_UNORDERABLE,
                    )],
                );

                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::HISTORY_UNORDERABLE,
                    format!(
                        "`{zone}/{ledger}` cannot order this occurrence against the ones before \
                         it, so it was not recorded: {error}"
                    ),
                )
            })?;
            // Timed around the append alone: the wait for a turn that follows is another
            // submission applying, and folding it in would make this metric report the ledger's
            // queue as the cost of a durable write.
            let started = Instant::now();
            let appended = self.streams.append(&zone, &ledger, proposed);
            let appending = started.elapsed();
            let prepared = match &appended {
                Ok((Written::Appended { seq, .. }, _)) => Some(sequencer.turn(*seq)),
                _ => None,
            };

            (appended, appending, prepared)
        };
        let (written, mut record) = appended.map_err(|failed| {
            // The turn, if one was taken, is dropped with `prepared` here — the sequence is
            // released rather than stranded.
            self.refuse_append(failed, &[])
        })?;
        self.metrics
            .observe(&measure::APPEND_SECONDS, &[], appending.as_secs_f64());
        self.publish_watermarks(&zone, &ledger);
        let mut recovering = false;
        let (sequence, instance) = match written {
            Written::Appended {
                seq, ref instance, ..
            } => (seq, instance.clone()),
            Written::Idempotent { seq } => {
                // The same occurrence, already durable and already observed. Nothing is written
                // again and nothing is observed again — observing it twice is the one thing an
                // idempotent retry must not do, because a temporal engine counts occurrences.
                //
                // But a retry is not a conflict: it is what a client does when it did not see the
                // first reply, and refusing it leaves that client with no way to learn the verdict
                // its own occurrence produced. So the answer given the first time is given again,
                // from disk, with nothing re-observed.
                self.metrics.count(&measure::IDEMPOTENT, &[]);
                let stored = self
                    .streams
                    .record_at(&zone, &ledger, seq)
                    .map_err(|error| {
                        ApiError::new(
                            ErrorClass::Unavailable,
                            permguard_core::codes::pdp_temporal::EVENT_RECORD_UNREADABLE,
                            format!(
                                "the occurrence index names `{}` at sequence {seq}, but its \
                                 durable event record cannot be read: {error}",
                                occurrence.event_id
                            ),
                        )
                    })?;
                let stored = permguard_events::record::validate(&stored).map_err(|error| {
                    ApiError::new(
                        ErrorClass::Unavailable,
                        permguard_core::codes::pdp_temporal::EVENT_RECORD_INVALID,
                        format!(
                            "the durable record for `{}` at sequence {seq} is invalid: {error}",
                            occurrence.event_id
                        ),
                    )
                })?;
                if stored.event_id != occurrence.event_id
                    || stored.occurrence_digest != record.occurrence_digest
                {
                    return Err(ApiError::new(
                        ErrorClass::Conflict,
                        permguard_core::codes::pdp_temporal::EVENT_ID_CONFLICT,
                        format!(
                            "`{}` names a different durable occurrence at sequence {seq}",
                            occurrence.event_id
                        ),
                    ));
                }
                if stored.profile != profile || stored.event_type != record.event_type {
                    return Err(ApiError::new(
                        ErrorClass::Conflict,
                        permguard_core::codes::pdp_temporal::EVENT_ROUTING_CONFLICT,
                        format!(
                            "`{}` was first submitted as type `{}` to profile `{}`, and a retry \
                             cannot route the same occurrence through type `{}` and profile \
                             `{profile}`",
                            occurrence.event_id,
                            stored.event_type,
                            stored.profile,
                            record.event_type
                        ),
                    ));
                }
                match self
                    .streams
                    .outcome(&zone, &ledger, &source, &occurrence.event_id)
                {
                    Ok(Some(held)) => match serde_json::from_value::<SubmitResponse>(held) {
                        Ok(response) => {
                            info!(
                                event.name = "temporal.idempotent",
                                component = COMPONENT,
                                sequence = seq,
                                "a retry of an occurrence this ledger already holds, answered as \
                                 it was answered the first time"
                            );
                            self.metrics.count(
                                &measure::SUBMISSIONS,
                                &[(permguard_core::metrics::labels::OUTCOME, "replayed")],
                            );

                            return Ok(Staged::Answered(Box::new(response)));
                        }
                        Err(error) => {
                            return Err(ApiError::new(
                                ErrorClass::Unavailable,
                                permguard_core::codes::pdp_temporal::EVENT_OUTCOME_UNREADABLE,
                                format!(
                                    "the durable answer for `{}` at sequence {seq} cannot be \
                                     decoded and must not be replaced by a new decision: {error}",
                                    occurrence.event_id
                                ),
                            ));
                        }
                    },
                    Ok(None) => warn!(
                        event.name = "temporal.outcome_missing",
                        component = COMPONENT,
                        sequence = seq,
                        "this occurrence is recorded and no answer was kept for it"
                    ),
                    Err(error) => {
                        return Err(ApiError::new(
                            ErrorClass::Unavailable,
                            permguard_core::codes::pdp_temporal::EVENT_OUTCOME_UNREADABLE,
                            format!(
                                "the durable answer index for `{}` at sequence {seq} cannot be \
                                 read and must not be replaced by a new decision: {error}",
                                occurrence.event_id
                            ),
                        ));
                    }
                }

                if stored.commit != loaded.head.commit
                    || stored.policy_partitions != record.policy_partitions
                    || stored.history_key != record.history_key
                {
                    return Err(ApiError::new(
                        ErrorClass::Unavailable,
                        permguard_core::codes::pdp_temporal::EVENT_RECOVERY_COMMIT_UNAVAILABLE,
                        format!(
                            "`{}` is durable at commit `{}`, but its answer was not committed and \
                             this plane currently serves commit `{}` with a different temporal \
                             contract. Recovering it under different policy or schema bytes would \
                             invent a new answer",
                            occurrence.event_id, stored.commit, loaded.head.commit
                        ),
                    ));
                }
                // No committed response exists. Rebuild this history from the journal up to the
                // record immediately before this one, then apply this occurrence once. This is
                // safe both after a process restart (the engine is fresh) and after an in-process
                // durability failure (the rebuild removes any partial application first).
                recovering = true;
                record = stored;
                self.invalidate_history(&zone, &ledger, &partition_key);

                (seq, record.stream.producer.instance.clone())
            }
        };

        // The receipt names the record's own place on the stream it names: its run and its
        // sequence there. `sequence` is the plane's local ordinal across the legacy journal and
        // the Host's runs, what turns and replays are ordered by; the two differ past the first
        // run, or beside a legacy journal (WP-6.2a, after the review).
        let watermark = Watermark {
            instance,
            sequence: record.seq,
            history: history.as_ref().map(|key| key.digest.clone()),
        };

        // This record's turn to be observed, taken before anything else that can fail and held
        // until the application is over.
        //
        // The journal decided the order when it assigned the sequence; without this, the thread
        // carrying that sequence merely races the thread carrying the next one to whichever
        // history lock they both want, and the history a temporal policy reads would be ordered by
        // the scheduler. Taken *before* `history_scope` so that a refusal there releases it on the
        // way out — a sequence journalled and then abandoned must not stop the ledger.
        // The sequencer is taken out of the map first and the wait is awaited on it, rather than
        // awaiting on a temporary: the turn is held across everything below, and a value borrowed
        // from an expression that ends at the semicolon cannot be.
        // Already held when the append assigned this sequence — taken there so nothing could be
        // cancelled between the two. Asking again would wait for a turn this task is holding.
        let turn = match prepared {
            Some(turn) => turn,
            None => {
                // Only the recovery path reaches here: an idempotent retry whose response was
                // never committed, taking the turn of a sequence that is already durable. An
                // `Appended` always arrives with its turn already held, taken beside the append.
                let sequencer = self.streams.sequencer(&zone, &ledger).map_err(|error| {
                    // The sequence this abandons is durable, so the history it belongs to is left
                    // one record short of the journal. Marking it for replay is what the module's
                    // liveness contract requires of every path that abandons a sequence: the next
                    // occurrence in this history is evaluated against a run rebuilt from the
                    // journal — which holds the record — rather than against a prefix missing it.
                    // Without this the ledger keeps answering, and answers from the hole.
                    self.invalidate_history(&zone, &ledger, &partition_key);
                    self.metrics.count(
                        &measure::REFUSALS,
                        &[(
                            permguard_core::metrics::labels::REASON,
                            permguard_core::codes::pdp_temporal::HISTORY_UNORDERABLE,
                        )],
                    );

                    ApiError::new(
                        ErrorClass::Unavailable,
                        permguard_core::codes::pdp_temporal::HISTORY_UNORDERABLE,
                        format!(
                            "`{zone}/{ledger}` cannot order this occurrence against the ones \
                             before it: {error}"
                        ),
                    )
                })?;

                sequencer.turn(sequence)
            }
        };

        // Two concurrent retries may both have observed the missing response before the first one
        // finished recovery. The ledger turn serializes their application; check again inside it
        // so the follower returns the response the leader just committed instead of rebuilding
        // and observing the same occurrence again.
        if recovering {
            match self
                .streams
                .outcome(&zone, &ledger, &source, &occurrence.event_id)
            {
                Ok(Some(held)) => {
                    let response =
                        serde_json::from_value::<SubmitResponse>(held).map_err(|error| {
                            ApiError::new(
                                ErrorClass::Unavailable,
                                permguard_core::codes::pdp_temporal::EVENT_OUTCOME_UNREADABLE,
                                format!(
                                    "the durable answer for `{}` cannot be decoded: {error}",
                                    occurrence.event_id
                                ),
                            )
                        })?;
                    self.metrics.count(
                        &measure::SUBMISSIONS,
                        &[(permguard_core::metrics::labels::OUTCOME, "replayed")],
                    );

                    return Ok(Staged::Answered(Box::new(response)));
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(ApiError::new(
                        ErrorClass::Unavailable,
                        permguard_core::codes::pdp_temporal::EVENT_OUTCOME_UNREADABLE,
                        format!(
                            "the durable answer index for `{}` cannot be read: {error}",
                            occurrence.event_id
                        ),
                    ));
                }
            }
        }

        // Order, under the turn. Everything with a lower sequence is durable and settled by now, so
        // this is the first point at which "has this history already moved past that instant" has a
        // stable answer — asked before the append it is a race, and two concurrent submissions can
        // both pass it and then be journalled either way round.
        if let Err(error) = self.admit_order(&zone, &ledger, &partition_key, &record, sequence) {
            // The record stays: it is evidence, and losing it would change what future decisions
            // mean. What is marked is the history, so the next occurrence in it is evaluated
            // against a run rebuilt from the journal — and `observable` sorts that run, so the late
            // arrival takes its right place there rather than being appended to what came after it.
            self.invalidate_history(&zone, &ledger, &partition_key);

            return Err(error);
        }

        // Replay while holding this sequence's turn. This used to happen before the append, which
        // allowed a later concurrent submission to pass the freshness check while an earlier,
        // durable sequence was still waiting to be applied. The current record is excluded by its
        // sequence, so rebuilding here cannot observe it twice.
        // Never while prewarm replays this ledger: it would replace the engine this feeds.
        let exclusion = self.exclusion(&zone, &ledger);
        let _replaying = exclusion.read().map_err(|_| {
            ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::pdp_temporal::HISTORY_LOCK_POISONED,
                "this plane's prewarm left its lock unusable",
            )
        })?;
        let Ensured {
            abandoned,
            shared: captured,
        } = match self.ensure_history(
            &checks,
            &partition_key,
            &occurrence,
            &zone,
            &ledger,
            sequence,
        ) {
            Ok(ensured) => ensured,
            Err(error) => {
                self.invalidate_history(&zone, &ledger, &partition_key);
                return Err(error);
            }
        };

        // The history this decision will range over, and — for a bounded mode — whether it is
        // fresh enough to range over at all. Checked after the event is durable and before it is
        // decided: the record is kept either way, because losing it would change what *future*
        // decisions mean, and only the answer is withheld.
        // What this decision ranges over, and the occurrence's own logical key (WP-6.4b).
        let window = window_of(&checks, &occurrence);
        let current = super::logical::key(
            record.source.as_deref(),
            &record.stream.producer.id,
            &record.event_id,
        );
        let history =
            match self.history_scope(&zone, &ledger, &partition_key, captured, window, &current) {
                Ok(history) => history,
                Err(error) => {
                    // The record is durable but was deliberately not applied. Mark this history dirty
                    // now: the next event in the same history repairs the hole from the journal before
                    // it is evaluated, without waiting for a process restart.
                    self.invalidate_history(&zone, &ledger, &partition_key);
                    return Err(error);
                }
            };

        // Durable, and this record's turn. Only now may an engine see it.
        let applying = Instant::now();
        let (verdicts, complete) = self.apply(
            &checks,
            &partition_key,
            &occurrence,
            &zone,
            &ledger,
            &abandoned,
        );
        if !abandoned.is_empty() {
            // Behind its journal: replayed before the next occurrence of this history.
            self.invalidate_history(&zone, &ledger, &partition_key);
        }
        if !complete {
            // A partition may have observed the occurrence before a sibling failed. Replaying the
            // complete retained run is the only state that makes all addressed partitions agree.
            self.invalidate_history(&zone, &ledger, &partition_key);
        }
        if recovering {
            // Recovery may have rewound an engine that had already processed later sequences in
            // this process. Publish the invalidation before releasing the ledger turn, so the next
            // submission rebuilds the complete retained run rather than using that prefix.
            self.invalidate_history(&zone, &ledger, &partition_key);
        }
        // Applied. The next sequence may go, whatever the verdict was.
        drop(turn);
        self.metrics.observe(
            &measure::APPLY_SECONDS,
            &[],
            applying.elapsed().as_secs_f64(),
        );

        if !decides {
            if !complete {
                self.metrics.count(
                    &measure::REFUSALS,
                    &[(
                        permguard_core::metrics::labels::REASON,
                        permguard_core::codes::pdp_temporal::EVENT_APPLICATION_INCOMPLETE,
                    )],
                );

                return Err(ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::EVENT_APPLICATION_INCOMPLETE,
                    format!(
                        "the occurrence `{}` is durable in `{zone}/{ledger}`, but not every \
                         partition of `{profile}` advanced. No accepted receipt was issued; the \
                         history must be rebuilt from the journal before this occurrence can be \
                         acknowledged",
                        occurrence.event_id
                    ),
                ));
            }
            self.metrics.count(
                &measure::SUBMISSIONS,
                &[(permguard_core::metrics::labels::OUTCOME, "accepted")],
            );

            let response = SubmitResponse {
                outcome: Outcome::Accepted,
                event_id: occurrence.event_id,
                watermark,
                decision: None,
                decision_id: None,
                policies: Vec::new(),
                evaluations: Vec::new(),
                reason: None,
                history,
            };
            self.keep_outcome(
                &zone,
                &ledger,
                &source,
                &response.event_id,
                crate::temporal::streams::Routed {
                    profile: &profile,
                    kind: &occurrence_kind,
                },
                &response,
            )?;

            return Ok(Staged::Answered(Box::new(response)));
        }

        // The profile's single registered batch semantic: an explicit deny wins, silence is not a
        // deny, and a partition that could not evaluate is an objection. The same `resolve` the
        // stateless path uses, so one ledger cannot mean two things.
        let evaluations = verdicts
            .iter()
            .map(
                |(partition, verdict)| permguard_languages::temporal::PartitionEvaluation {
                    partition: partition.clone(),
                    decision: verdict.permitted(),
                    policies: verdict.determining().to_vec(),
                    // A partition result `E` carries the native contract's code of its cause.
                    reason: verdict
                        .error()
                        .map(|error| permguard_languages::temporal::Reason {
                            code: error.code.to_owned(),
                            message: error.message,
                        }),
                },
            )
            .collect();
        let outcome = permguard_languages::evaluate::resolve(
            verdicts.into_iter().map(|(_, verdict)| verdict),
        );
        let decision_id = self
            .streams
            .decision_id(&zone, &ledger, &source, &occurrence.event_id)
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::DECISION_ID_NOT_DURABLE,
                    format!(
                        "the stable decision identity for `{}` could not be made durable: {error}",
                        occurrence.event_id
                    ),
                )
            })?;
        let reason = reason_of(&outcome);

        Ok(Staged::Decided(Box::new(Decided {
            loaded,
            occurrence,
            occurrence_kind,
            profile,
            zone,
            ledger,
            record,
            watermark,
            history,
            evaluations,
            outcome,
            decision_id,
            reason,
        })))
    }

    /// Keeps the answer given for one occurrence, so a retry of it is answered and not refused.
    ///
    /// This is part of the response commit, not a convenience copy. A successful answer whose
    /// retry answer was not durable creates an externally visible success the plane cannot later
    /// reproduce. The event and (for a decision) audit record stay durable, but the transport gets
    /// an unavailable error until this final durability boundary succeeds.
    fn keep_outcome(
        &self,
        zone: &str,
        ledger: &str,
        source: &str,
        event_id: &str,
        routed: crate::temporal::streams::Routed<'_>,
        response: &SubmitResponse,
    ) -> Result<(), ApiError> {
        let held = serde_json::to_value(response).map_err(|error| {
            ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::pdp_temporal::EVENT_OUTCOME_UNRENDERABLE,
                format!("the durable answer for `{event_id}` cannot be rendered: {error}"),
            )
        })?;
        self.streams
            .record_outcome(zone, ledger, source, event_id, routed, &held)
            .map_err(|error| {
                warn!(
                    event.name = "temporal.outcome_unwritable",
                    component = COMPONENT,
                    zone,
                    ledger,
                    event_id,
                    error = %error,
                    "the occurrence is durable but its retry answer is not: withholding success"
                );
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::EVENT_OUTCOME_NOT_DURABLE,
                    format!(
                        "the occurrence `{event_id}` is durable in `{zone}/{ledger}`, but its \
                         retry answer could not be made durable: {error}"
                    ),
                )
            })
    }

    /// Observes the occurrence into every addressed partition, in the profile's order.
    ///
    /// Sequential, and deliberately so: `is_authorized` both observes and decides, so two
    /// partitions running at once would each decide against a history the other had not yet
    /// updated. The profile's order is the order, and it is the same on every plane.
    fn apply(
        &self,
        checks: &[Verified<'_>],
        history: &str,
        occurrence: &Occurrence,
        zone: &str,
        ledger: &str,
        abandoned: &std::collections::BTreeMap<String, permguard_languages::evaluate::Verdict>,
    ) -> (Vec<(String, permguard_languages::evaluate::Verdict)>, bool) {
        let mut verdicts = Vec::with_capacity(checks.len());
        let mut complete = true;
        for (partition, engine, checked) in checks {
            // A partition whose replay was abandoned is not shown the occurrence: its history is
            // behind, and the answer is the `E` its replay plan gave (DOGWOOD-03).
            if let Some(verdict) = abandoned.get(&partition.name) {
                if let Some(failure) = verdict.failure() {
                    self.metrics.count(
                        &crate::authz::measure::PARTITION_FAILURES,
                        &[(permguard_core::metrics::labels::REASON, failure.code)],
                    );
                }
                // A decision kind answers the `E`. A history-only kind is accepted: the record is
                // durable, and the history stays marked, so the next submission replays it
                // (after the review).
                if checked.decides {
                    complete = false;
                    verdicts.push((partition.name.clone(), verdict.clone()));
                }
                continue;
            }
            // Inside the panic boundary: an engine that came apart applying a durable occurrence is
            // that partition's `E`, never a lost submission.
            let applied = permguard_languages::guard::contained(|| {
                engine.apply_replayed(history, occurrence, checked)
            })
            .unwrap_or_else(|_| {
                Applied::Decided(permguard_languages::evaluate::Verdict::panicked(
                    "the partition's engine came apart applying the occurrence",
                ))
            });
            match applied {
                Applied::Observed if !checked.decides => {}
                Applied::Observed => {
                    complete = false;
                    let message = format!(
                        "the partition declared `{}` as a decision kind but observed it without \
                         producing a decision",
                        occurrence.kind
                    );
                    self.metrics.count(
                        &crate::authz::measure::PARTITION_FAILURES,
                        &[(
                            permguard_core::metrics::labels::REASON,
                            permguard_core::codes::pdp_native::EVALUATION_FAILED,
                        )],
                    );
                    warn!(
                        event.name = "temporal.partition_failed",
                        component = COMPONENT,
                        zone,
                        ledger,
                        code = permguard_core::codes::pdp_native::EVALUATION_FAILED,
                        "a partition disagreed with its loaded event contract: failing closed"
                    );
                    verdicts.push((
                        partition.name.clone(),
                        permguard_languages::evaluate::Verdict::engine_failed(message),
                    ));
                }
                Applied::Decided(verdict) => {
                    if !checked.decides || verdict.error().is_some() {
                        complete = false;
                    }
                    // Every failure by its code — an `E`'s, and one beside a deny that stood —
                    // and never the engine's text, which can carry tenant data.
                    if let Some(failure) = verdict.failure() {
                        self.metrics.count(
                            &crate::authz::measure::PARTITION_FAILURES,
                            &[(permguard_core::metrics::labels::REASON, failure.code)],
                        );
                        warn!(
                            event.name = "temporal.partition_failed",
                            component = COMPONENT,
                            zone,
                            ledger,
                            code = failure.code,
                            denied = verdict.error().is_none(),
                            "a partition could not evaluate a durable occurrence"
                        );
                    } else if !checked.decides {
                        warn!(
                            event.name = "temporal.partition_failed",
                            component = COMPONENT,
                            zone,
                            ledger,
                            "a history-only event unexpectedly produced a decision: refusing to \
                             acknowledge an inconsistent history"
                        );
                    }
                    verdicts.push((partition.name.clone(), verdict));
                }
            }
        }

        (verdicts, complete)
    }

    /// Refuses a loaded temporal contract whose longest window can outlive the journal.
    /// Refuses to *decide* an occurrence that sorts behind one this history already holds.
    ///
    /// # Why an out-of-order arrival cannot simply be applied
    ///
    /// A temporal engine is fed occurrences in timestamp order, and that is not a convention — it
    /// is what lets it answer `within the last hour` without holding every event for ever.
    /// [`Temporal::rebuild`](permguard_languages::temporal::Temporal::rebuild) states the contract:
    /// a late arrival is not inserted, the affected history is rebuilt.
    ///
    /// The local path did not honour it. `allowed_lateness` admits an event whose instant is behind
    /// the clock, and nothing then compared that instant with what the engine had already seen — so
    /// an occurrence at `t1` submitted after one at `t2` was observed *after* it. `previous`,
    /// `since` and every window operator then answer from a sequence that never happened.
    ///
    /// # The order is the whole tuple, not the event time
    ///
    /// "Behind" is decided by [`super::imports::order_of`] — event time, then observed time, then
    /// producer, then sequence — because that is *the* order: the one every rebuilt run is sorted
    /// by. Comparing event time alone would leave the ties undecided, and ties happen: two
    /// submissions in one second journalled opposite to the instants they were stamped with, a
    /// clock stepped backwards between them, two producers logging the same event time. An
    /// occurrence equal on event time but behind on the tie break is exactly as out of order as
    /// one behind by an hour — the rebuilt run will sort it earlier than something the engine was
    /// already told about.
    ///
    /// # Why here, and not before the append
    ///
    /// Because before the append the answer is not stable. Two submissions racing for one ledger
    /// can both find nothing ahead of them and then be journalled in either order, so a check there
    /// refuses whichever loses a scheduling race and lets the same pair through on the next run.
    /// Under the turn every lower sequence is durable and settled, and `before_local_sequence`
    /// excludes this record and everything the journal placed after it. The question has one answer.
    ///
    /// # Why the record survives the refusal
    ///
    /// It is evidence, and evidence is not the plane's to discard: an occurrence that happened is
    /// an input to every *future* decision in its history, and dropping it because this one could
    /// not be answered would change what those later decisions mean. So the same bargain the
    /// freshness check makes is made here — the record is kept, the history is marked for replay,
    /// and only the answer is withheld. [`Self::observable`] sorts the run it rebuilds, so the late
    /// arrival is fed in its right place rather than appended to what came after it, and the
    /// history heals on the next occurrence instead of at the next restart.
    fn admit_order(
        &self,
        zone: &str,
        ledger: &str,
        history: &str,
        record: &Record,
        before_local_sequence: u64,
    ) -> Result<(), ApiError> {
        let this = record.to_value().map_err(|error| {
            ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::pdp_temporal::EVENT_NOT_CANONICAL,
                format!("the durable record cannot be canonicalized: {error}"),
            )
        })?;
        let order = super::imports::order_of(&this);
        let occurred_at_epoch = permguard_events::index::epoch_seconds(&record.occurred_at)
            .ok_or_else(|| {
                ApiError::new(
                    ErrorClass::Internal,
                    permguard_core::codes::pdp_temporal::EVENT_NOT_CANONICAL,
                    "the durable record's instant is not a canonical one".to_owned(),
                )
            })?;

        // From this occurrence's own second, inclusive: a record equal on event time is decided by
        // the tie break, and starting one second later would never see it. One surviving candidate
        // is enough to know the history has moved past this occurrence; the scan is bounded by the
        // index, not by retention.
        let query = permguard_events::index::Query {
            event_type: permguard_languages::event::EVENT_TYPE.to_owned(),
            history: history.to_owned(),
            action: None,
            kind: None,
            from: occurred_at_epoch,
            until: i64::MAX,
        };
        let behind = |candidate: &serde_json::Value| super::imports::order_of(candidate) > order;

        let mut newer =
            both(&query, |query| self.streams.scan(zone, ledger, query)).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::HISTORY_UNREADABLE,
                    format!("this plane's own journal could not be read: {error}"),
                )
            })?;
        // "Already observed" is everything below this sequence: this record and whatever the
        // journal placed after it have not been fed to the engine yet, and are not evidence of
        // where the history stands.
        newer
            .retain(|(position, candidate)| *position < before_local_sequence && behind(candidate));
        let mut newer: Vec<serde_json::Value> =
            newer.into_iter().map(|(_, candidate)| candidate).collect();
        // The imported half feeds the same engine in a shared mode, so it settles the same question.
        if let Some(imports) = &self.imports
            && self.consistency.is_shared()
            && newer.is_empty()
        {
            newer = both(&query, |query| imports.window(zone, ledger, query)).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::IMPORTED_HISTORY_UNREADABLE,
                    format!("the imported history could not be read: {error}"),
                )
            })?;
            newer.retain(behind);
        }
        if let Some(imported) = &self.imported
            && self.consistency.is_shared()
            && newer.is_empty()
        {
            newer = both(&query, |query| imported.window(zone, ledger, query, None)).map_err(
                |error| {
                    ApiError::new(
                        ErrorClass::Unavailable,
                        permguard_core::codes::pdp_temporal::IMPORTED_HISTORY_UNREADABLE,
                        format!("the imported history could not be read: {error}"),
                    )
                },
            )?;
            newer.retain(behind);
        }

        let Some(ahead) = newer.first() else {
            return Ok(());
        };
        let at = ahead
            .get("occurred_at")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("a later instant");
        self.metrics.count(
            &measure::REFUSALS,
            &[(
                permguard_core::metrics::labels::REASON,
                permguard_core::codes::pdp_temporal::EVENT_OUT_OF_ORDER,
            )],
        );

        Err(ApiError::new(
            ErrorClass::Conflict,
            permguard_core::codes::pdp_temporal::EVENT_OUT_OF_ORDER,
            format!(
                "`{}` occurred at {} and this history already holds an occurrence at {at} that \
                 sorts after it. A temporal engine is fed in its documented order — event time, \
                 then observed time, producer and sequence — so deciding this one now would place \
                 it after an event it sorts before, and every window operator would answer from an \
                 order that never happened. The occurrence is recorded and remains evidence; the \
                 history is rebuilt in order before the next decision is served from it",
                record.event_id, record.occurred_at
            ),
        ))
    }

    fn admit_history_window(
        &self,
        checks: &[Verified<'_>],
        zone: &str,
        ledger: &str,
    ) -> Result<(), ApiError> {
        let seconds = checks
            .iter()
            .map(|(_, engine, _)| engine.contract().max_window_seconds)
            .max()
            .unwrap_or_default();
        let seconds = u64::try_from(seconds).map_err(|_| {
            ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::pdp_temporal::HISTORY_WINDOW_INVALID,
                format!(
                    "a temporal partition of `{zone}/{ledger}` declares a negative maximum window"
                ),
            )
        })?;

        self.streams
            .bounds()
            .admits(std::time::Duration::from_secs(seconds))
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::HISTORY_RETENTION_INSUFFICIENT,
                    format!("`{zone}/{ledger}` cannot activate its temporal contract: {error}"),
                )
            })
    }

    /// The answer this ledger already gave for this occurrence, when it gave one.
    ///
    /// `None` means there is nothing settled to return — no entry, or an entry whose answer was
    /// never completed — and the caller takes the full path, which is where an incomplete record
    /// is recovered under its *original* commit rather than under whatever is loaded now.
    ///
    /// Everything here is a comparison against what was recorded. A mismatch is never resolved in
    /// favour of the request: an identifier reused over different bytes, or routed differently, is
    /// a conflict, because answering it from the first occurrence's outcome would answer a
    /// question nobody asked.
    #[allow(clippy::too_many_arguments)]
    fn settled(
        &self,
        zone: &str,
        ledger: &str,
        source: &str,
        event: &serde_json::Value,
        event_id: &str,
        profile: &str,
        kind: &str,
    ) -> Result<Option<SubmitResponse>, ApiError> {
        let known = self
            .streams
            .known(zone, ledger, source, event_id)
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::EVENT_OUTCOME_UNREADABLE,
                    format!("the durable answer index for `{event_id}` cannot be read: {error}"),
                )
            })?;
        let Some(known) = known else {
            return Ok(None);
        };
        if known.response.is_null() {
            // Durable, and never answered. The recovery path owns this: it requires the original
            // commit and contract, which is a stricter test than anything here.
            return Ok(None);
        }

        let digest = occurrence_digest_of(event).map_err(|error| {
            ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::pdp_temporal::EVENT_NOT_CANONICAL,
                format!("the occurrence `{event_id}` cannot be digested: {error}"),
            )
        })?;
        if digest != known.occurrence_digest {
            // Counted, like every other refusal. A refusal no metric records is one an operator
            // meets as an unexplained failure rate: this is the path a client reusing an
            // identifier lands on, and it has to be visible as itself.
            self.metrics.count(
                &measure::REFUSALS,
                &[(
                    permguard_core::metrics::labels::REASON,
                    permguard_core::codes::pdp_temporal::EVENT_ID_CONFLICT,
                )],
            );

            return Err(ApiError::new(
                ErrorClass::Conflict,
                permguard_core::codes::pdp_temporal::EVENT_ID_CONFLICT,
                format!(
                    "`{event_id}` is already recorded in `{zone}/{ledger}` over different \
                     content. An identifier names one occurrence: reusing it for another is \
                     refused rather than answered from the first"
                ),
            ));
        }

        // Recorded with the answer, so an entry that predates them cannot be checked and is not
        // answered from: such a retry takes the full path rather than trusting an unverifiable
        // claim about how it was routed.
        let (Some(was_profile), Some(was_kind)) = (&known.profile, &known.kind) else {
            return Ok(None);
        };
        if was_profile != profile || was_kind != kind {
            self.metrics.count(
                &measure::REFUSALS,
                &[(
                    permguard_core::metrics::labels::REASON,
                    permguard_core::codes::pdp_temporal::EVENT_ROUTING_CONFLICT,
                )],
            );

            return Err(ApiError::new(
                ErrorClass::Conflict,
                permguard_core::codes::pdp_temporal::EVENT_ROUTING_CONFLICT,
                format!(
                    "`{event_id}` was answered under profile `{was_profile}` as `{was_kind}`, \
                     and this retry states profile `{profile}` as `{kind}`. The same identifier \
                     routed two ways is a conflict, not a retry"
                ),
            ));
        }

        let response: SubmitResponse =
            serde_json::from_value(known.response.clone()).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::EVENT_OUTCOME_UNREADABLE,
                    format!(
                        "the durable answer for `{event_id}` cannot be decoded and must not be \
                         replaced by a new decision: {error}"
                    ),
                )
            })?;

        Ok(Some(response))
    }

    /// Marks one in-memory history as needing an authoritative replay before its next use.
    fn invalidate_history(&self, zone: &str, ledger: &str, history: &str) {
        match self.applied.lock() {
            Ok(mut applied) => {
                // Every partition of this history, not one: the event that made the history dirty
                // is missing from every engine that ranges over it, whichever profile absorbs it
                // first. Each partition stays stale until it is itself rebuilt.
                applied.retain(|(held_zone, held_ledger, held_history, _), _| {
                    !(held_zone == zone && held_ledger == ledger && held_history == history)
                });
            }
            Err(_) => warn!(
                event.name = "temporal.history_invalidation_failed",
                component = COMPONENT,
                zone,
                ledger,
                history,
                "the replay watermark is poisoned; the next submission will fail closed"
            ),
        }
    }

    /// Which history this decision ranges over, and how fresh it is.
    ///
    /// Reported for every mode, including `local`: an auditor reproducing a decision needs to know
    /// what was visible, and "only this plane's own events" is an answer to that question rather
    /// than the absence of one.
    fn history_scope(
        &self,
        zone: &str,
        ledger: &str,
        history: &str,
        captured: Option<super::imported::Shared>,
        window: Option<(i64, i64)>,
        current: &super::logical::Key,
    ) -> Result<HistoryScope, ApiError> {
        if let Some(imported) = &self.imported
            && self.consistency.is_shared()
        {
            return self.host_scope(imported, zone, ledger, history, captured, window, current);
        }
        if !self.consistency.is_shared() {
            return Ok(HistoryScope::local());
        }
        // The retired pull's store archived (WP-6.2d) and no import from the Host: the stalest
        // state there is, a store that never read anything.
        let state = match &self.imports {
            Some(imports) => imports.state(zone, ledger).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::IMPORTED_HISTORY_UNREADABLE,
                    format!(
                        "this plane's imported history for `{zone}/{ledger}` cannot be read: \
                         {error}"
                    ),
                )
            })?,
            None => super::imports::Cursor::default(),
        };
        let staleness = staleness_of(&state.read_at);
        self.metrics.set_aggregated(
            &measure::IMPORT_STALENESS,
            permguard_core::Aggregate::Max,
            &format!("{zone}/{ledger}"),
            staleness.unwrap_or_default() as f64,
        );

        // `shared-bounded` is the mode that says "decide only on history I can vouch is recent".
        // Honouring that means failing closed when it is not — including when this plane has never
        // managed a successful read, which is the stalest state there is.
        if matches!(
            self.consistency,
            permguard_core::config::Consistency::SharedBounded
        ) {
            let bound = self.max_staleness.as_secs();
            let held = staleness.unwrap_or(u64::MAX);
            if held > bound {
                self.metrics.count(
                    &measure::REFUSALS,
                    &[(
                        permguard_core::metrics::labels::REASON,
                        permguard_core::codes::pdp_temporal::HISTORY_STALE,
                    )],
                );

                return Err(ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::HISTORY_STALE,
                    match staleness {
                        Some(held) => format!(
                            "this plane last refreshed the shared history of `{zone}/{ledger}` \
                             {held}s ago, and `shared-bounded` decides only on history no older \
                             than {bound}s. The event is recorded; the decision is withheld"
                        ),
                        None => format!(
                            "this plane has never successfully read the shared history of \
                             `{zone}/{ledger}`, and `shared-bounded` decides only on history it \
                             can vouch for. The event is recorded; the decision is withheld"
                        ),
                    },
                ));
            }
        }

        // A hole is not staleness. Staleness is history this plane has not caught up with *yet*
        // and will; a gap is history it will never hold, because the control plane no longer had
        // it when this plane came back. Waiting does not fix it, so a freshness bound cannot
        // notice it: a subscription that resumed past a hole reports itself perfectly fresh while
        // deciding over fewer occurrences than actually happened.
        let gaps = state.gaps.iter().filter(|gap| !gap.resolved).count();
        self.metrics.set_aggregated(
            &measure::IMPORT_GAPS_OPEN,
            permguard_core::Aggregate::Sum,
            &format!("{zone}/{ledger}"),
            gaps as f64,
        );
        if gaps > 0
            && matches!(
                self.consistency,
                permguard_core::config::Consistency::SharedBounded
            )
        {
            self.metrics.count(
                &measure::REFUSALS,
                &[(
                    permguard_core::metrics::labels::REASON,
                    permguard_core::codes::pdp_temporal::HISTORY_INCOMPLETE,
                )],
            );
            let oldest = state
                .gaps
                .iter()
                .filter(|gap| !gap.resolved)
                .map(|gap| (gap.from_sequence, gap.to_sequence))
                .next()
                .unwrap_or_default();

            return Err(ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::pdp_temporal::HISTORY_INCOMPLETE,
                format!(
                    "the shared history of `{zone}/{ledger}` has {gaps} recorded gap(s) — the \
                     oldest lost sequences {} through {} — and `shared-bounded` decides only on a \
                     history it holds whole. The event is recorded; the decision is withheld until \
                     the gap is accepted explicitly",
                    oldest.0, oldest.1
                ),
            ));
        }

        Ok(HistoryScope {
            mode: self.consistency.as_str().to_owned(),
            watermark: (!state.offset.is_empty()).then_some(state.offset),
            staleness_seconds: staleness,
            // Reported for every mode, `shared-eventual` included: it decides through a hole, and
            // an auditor reproducing the decision has to be able to see that it did.
            gaps: gaps as u64,
            // The retired pull store holds no Host run, so it names no frontier nor origin set.
            max_staleness_seconds: Some(self.max_staleness.as_secs()),
            ..HistoryScope::local()
        })
    }

    /// The scope of a shared decision over the origins the member Host imports (WP-6.2c2b1, owner
    /// decision of 2026-10-18): freshness is this Host's age since it verified the coordinator's
    /// checkpoint, never an event's time; `shared-bounded` also wants every run the checkpoint
    /// names held through what it names, and no gap, the Host's or the HTTP pull's.
    #[allow(clippy::too_many_arguments)]
    fn host_scope(
        &self,
        imported: &super::imported::Imported,
        zone: &str,
        ledger: &str,
        history: &str,
        captured: Option<super::imported::Shared>,
        window: Option<(i64, i64)>,
        current: &super::logical::Key,
    ) -> Result<HistoryScope, ApiError> {
        let unreadable = |error: String| {
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::pdp_temporal::IMPORTED_HISTORY_UNREADABLE,
                format!(
                    "this plane's imported history for `{zone}/{ledger}` cannot be read: {error}"
                ),
            )
        };
        // The view the replay read (WP-6.4a, after the review), read again only when nothing
        // captured one.
        let shared = match captured {
            Some(shared) => shared,
            None => imported
                .shared(zone, ledger)
                .map_err(|error| unreadable(error.to_string()))?,
        };
        let legacy = match &self.imports {
            Some(imports) => Some(
                imports
                    .state(zone, ledger)
                    .map_err(|error| unreadable(error.to_string()))?,
            ),
            None => None,
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| since.as_secs())
            .unwrap_or_default();
        let staleness = shared
            .state
            .as_ref()
            .map(|state| now.saturating_sub(state.verified_at));
        self.metrics.set_aggregated(
            &measure::IMPORT_STALENESS,
            permguard_core::Aggregate::Max,
            &format!("{zone}/{ledger}"),
            staleness.unwrap_or_default() as f64,
        );
        let bounded = matches!(
            self.consistency,
            permguard_core::config::Consistency::SharedBounded
        );
        let refuse = |code: &'static str, reason: String| {
            self.metrics.count(
                &measure::REFUSALS,
                &[(permguard_core::metrics::labels::REASON, code)],
            );
            Err(ApiError::new(ErrorClass::Unavailable, code, reason))
        };
        if bounded {
            let bound = self.max_staleness.as_secs();
            match staleness {
                None => {
                    return refuse(
                        permguard_core::codes::pdp_temporal::HISTORY_STALE,
                        format!(
                            "this Host has never verified a coordinator's checkpoint of \
                             `{zone}/{ledger}`, and `shared-bounded` decides only on history it \
                             can vouch for. The event is recorded; the decision is withheld"
                        ),
                    );
                }
                Some(held) if held > bound => {
                    return refuse(
                        permguard_core::codes::pdp_temporal::HISTORY_STALE,
                        format!(
                            "this Host last verified the coordinator's checkpoint of \
                             `{zone}/{ledger}` {held}s ago, and `shared-bounded` decides only on \
                             history no older than {bound}s. The event is recorded; the decision \
                             is withheld"
                        ),
                    );
                }
                Some(_) => {}
            }
            if let Some((_, _, have, wanted)) = shared.behind.first() {
                return refuse(
                    permguard_core::codes::pdp_temporal::HISTORY_STALE,
                    format!(
                        "the coordinator's checkpoint of `{zone}/{ledger}` names an origin's run \
                         through {wanted} and this Host holds it through {have}, so \
                         `shared-bounded` would decide on less than the checkpoint vouches for. \
                         The event is recorded; the decision is withheld"
                    ),
                );
            }
        }
        let host_gaps = shared.state.as_ref().map_or(0, |state| state.gaps.len());
        let legacy_gaps = legacy.as_ref().map_or(0, |state| {
            state.gaps.iter().filter(|gap| !gap.resolved).count()
        });
        let gaps = host_gaps + legacy_gaps;
        self.metrics.set_aggregated(
            &measure::IMPORT_GAPS_OPEN,
            permguard_core::Aggregate::Sum,
            &format!("{zone}/{ledger}"),
            gaps as f64,
        );
        if gaps > 0 && bounded {
            return refuse(
                permguard_core::codes::pdp_temporal::HISTORY_INCOMPLETE,
                format!(
                    "the shared history of `{zone}/{ledger}` has {gaps} recorded gap(s), and \
                     `shared-bounded` decides only on a history it holds whole. The event is \
                     recorded; the decision is withheld until a snapshot or a change of the \
                     required origins resolves them"
                ),
            );
        }
        let legacy_mark = legacy
            .as_ref()
            .filter(|state| !state.offset.is_empty())
            .map(|state| state.offset.clone())
            .unwrap_or_default();
        // A digest conflict in this decision's window (WP-6.4b, owner decision of 2026-10-21): the
        // logical occurrence is quarantined; `shared-bounded` refuses, the frontier being
        // inconsistent, and `shared-eventual` decides without it and says so. No window is an
        // instant that is not a canonical one, which the replay refuses on its own.
        let quarantined = match window {
            Some((from, until)) => imported
                .quarantined(zone, ledger, history, from, until)
                .map_err(|error| unreadable(error.to_string()))?,
            None => Vec::new(),
        };
        if bounded && !quarantined.is_empty() {
            return refuse(
                permguard_core::codes::pdp_temporal::HISTORY_CONFLICTED,
                format!(
                    "the shared history of `{zone}/{ledger}` holds {} occurrence(s) in this \
                     decision's window recorded with different bytes by more than one origin, and \
                     `shared-bounded` decides only on a consistent history. The event is \
                     recorded; the decision is withheld while a conflicting occurrence is in the \
                     window",
                    quarantined.len()
                ),
            );
        }
        // The occurrence itself recorded with other bytes by another origin: quarantined, it is
        // no occurrence a decision can be about, in either mode.
        if imported
            .conflicting(zone, ledger)
            .map_err(|error| unreadable(error.to_string()))?
            .contains(current)
        {
            return refuse(
                permguard_core::codes::pdp_temporal::HISTORY_CONFLICTED,
                format!(
                    "the occurrence `{}` is recorded with different bytes by another origin of \
                     `{zone}/{ledger}`, so it is quarantined from shared history. The event is \
                     recorded; no decision is made about it",
                    current.1
                ),
            );
        }
        let own = imported.own();
        let conflicted_origins: std::collections::BTreeSet<&str> = quarantined
            .iter()
            .flat_map(|entry| entry.positions.iter().map(|(origin, _, _)| origin.as_str()))
            .filter(|origin| *origin != own)
            .collect();
        // The required origins a `shared-eventual` decision is degraded by (WP-6.4a): those behind
        // the checkpoint or gapped, and every one of them once the checkpoint is older than the
        // bound. A `shared-bounded` decision reaching here has none: it refused above.
        let stale = staleness.is_none_or(|held| held > self.max_staleness.as_secs());
        let degraded: Vec<String> = if bounded {
            Vec::new()
        } else {
            shared
                .required
                .iter()
                .filter(|origin| {
                    stale
                        || shared
                            .behind
                            .iter()
                            .any(|(behind, _, _, _)| super::imported::hex(behind) == **origin)
                        || shared.state.as_ref().is_some_and(|state| {
                            state
                                .gaps
                                .iter()
                                .any(|gap| super::imported::hex(&gap.origin) == **origin)
                        })
                })
                .map(String::as_str)
                // Every other origin that recorded a quarantined occurrence, required or not.
                .chain(conflicted_origins)
                .collect::<std::collections::BTreeSet<&str>>()
                .into_iter()
                .map(str::to_owned)
                .collect()
        };
        Ok(HistoryScope {
            mode: self.consistency.as_str().to_owned(),
            watermark: Some(format!("{legacy_mark}|{}", shared.watermark)),
            staleness_seconds: staleness,
            gaps: gaps as u64,
            frontier: shared.frontier,
            origin_set_revision: shared
                .state
                .as_ref()
                .map(|state| super::imported::hex(&state.revision)),
            max_staleness_seconds: Some(self.max_staleness.as_secs()),
            degraded,
            quarantined: quarantined.len() as u64,
            ..HistoryScope::local()
        })
    }

    /// Makes sure every addressed partition has observed the history it is about to decide against.
    ///
    /// # The two ways an engine ends up behind its own ledger
    ///
    /// A temporal engine's history lives in memory; the journal on disk is the authority. They agree
    /// only because this feeds one from the other, and there are exactly two ordinary reasons they
    /// stop agreeing:
    ///
    /// * **The engine is fresh.** A restart, or a cache eviction that recompiled the partition,
    ///   leaves an engine that has observed nothing sitting in front of a ledger with a history.
    ///   Nothing about the next decision looks wrong: it is a `deny` indistinguishable from a
    ///   correct one, because the login it should have seen is on disk and not in the engine.
    /// * **More history arrived.** Replication delivers older events later, and an engine fed out
    ///   of order either corrupts its windows or silently ignores what arrived.
    ///
    /// Both are answered the same way, because both are the same question — *what should this
    /// engine have seen* — and answering them differently is how a plane ends up with two ideas of
    /// what a policy saw. The run is rebuilt whole rather than appended to: replication does not
    /// respect event order, and Dogwood's engine is fed in order or not at all.
    ///
    /// The cost is bounded by retention, which is bounded by the longest window any loaded policy
    /// looks back over, and it is paid once per fresh engine and once per import that moves the
    /// watermark — never once per submission.
    fn ensure_history(
        &self,
        checks: &[Verified<'_>],
        history: &str,
        occurrence: &Occurrence,
        zone: &str,
        ledger: &str,
        before_local_sequence: u64,
    ) -> Result<Ensured, ApiError> {
        let imported = match (&self.imports, self.consistency.is_shared()) {
            (Some(imports), true) => Some(imports.state(zone, ledger).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::IMPORTED_HISTORY_UNREADABLE,
                    error.to_string(),
                )
            })?),
            _ => None,
        };
        let mut captured: Option<super::imported::Shared> = None;
        let mut watermark = imported
            .as_ref()
            .filter(|state| state.imported > 0)
            .map(|state| state.offset.clone())
            .unwrap_or_default();
        // What the plane has indexed of the origins the Host imports moves it too (WP-6.2c2b1).
        if let Some(host_imports) = &self.imported
            && self.consistency.is_shared()
        {
            let shared = host_imports.shared(zone, ledger).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::IMPORTED_HISTORY_UNREADABLE,
                    error.to_string(),
                )
            })?;
            watermark = format!("{watermark}|{}", shared.watermark);
            captured = Some(shared);
        }
        // The imported history as captured here is what a replay reads and what the decision
        // cites (WP-6.4a, after the review): one frontier, never two readings of a moving one.
        let bound: Option<Vec<permguard_core::frontier::FrontierRun>> =
            captured.as_ref().map(|shared| shared.frontier.clone());

        // The note is per partition — see the field. A partition needs a rebuild when its engine
        // has been told nothing (fresh: recompiled, evicted, or first sight of this history), or
        // when its own note is not at the current watermark (the imported history moved, or an
        // invalidation cleared it). Asked of the engines rather than remembered here, because what
        // a rebuild replaces is the engine: a note kept beside it would outlive the thing it
        // described.
        //
        // Read under the map lock and released before disk reads, schema checks and provider
        // execution. The journal sequencer already gives one submission at a time for this ledger;
        // holding one process-wide mutex through a rebuild would unnecessarily make an unrelated
        // tenant wait behind it.
        let key_of = |partition: &str| {
            (
                zone.to_owned(),
                ledger.to_owned(),
                history.to_owned(),
                partition.to_owned(),
            )
        };
        let stale: std::collections::BTreeSet<String> = {
            let applied = self.applied.lock().map_err(|_| {
                ApiError::new(
                    ErrorClass::Internal,
                    permguard_core::codes::pdp_temporal::HISTORY_LOCK_POISONED,
                    "this plane's record of what it has replayed is unusable",
                )
            })?;

            checks
                .iter()
                .filter(|(partition, engine, _)| {
                    // Inside the panic boundary, under this lock: a panic here would poison it and
                    // refuse every submission until a restart. One that came apart reads as a
                    // history never observed, which rebuilds it.
                    permguard_languages::guard::contained(|| engine.observed(history)).unwrap_or(0)
                        == 0
                        || applied.get(&key_of(&partition.name)) != Some(&watermark)
                })
                .map(|(partition, _, _)| partition.name.clone())
                .collect()
        };
        if stale.is_empty() {
            return Ok(Ensured {
                abandoned: std::collections::BTreeMap::new(),
                shared: captured,
            });
        }

        // The replay plan (DOGWOOD-03): a bounded number of cold replays at once, each within one
        // deadline, a record count and a byte count. Past any of them the stale partitions answer
        // `E` and stay marked for replay; nothing goes on working once the caller is answered.
        let abandon = |why: String| -> std::collections::BTreeMap<
            String,
            permguard_languages::evaluate::Verdict,
        > {
            warn!(
                event.name = "temporal.replay_abandoned",
                component = COMPONENT,
                zone,
                ledger,
                code = permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED,
                "a cold history's replay did not fit its plan: answering `E` rather than deciding \
                 against a history that is behind"
            );
            stale
                .iter()
                .map(|partition| {
                    (
                        partition.clone(),
                        permguard_languages::evaluate::Verdict::deadline_exceeded(why.clone()),
                    )
                })
                .collect()
        };
        if self
            .replaying
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            >= self.replay.concurrency
        {
            self.replaying
                .fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            return Ok(Ensured::of(
                captured.clone(),
                abandon(format!(
                    "{} cold histories are already being replayed, the most this plane runs at once \
                 (`events.replay.concurrency`)",
                    self.replay.concurrency
                )),
            ));
        }
        let _slot = Replaying(&self.replaying);
        let deadline = std::time::Instant::now() + self.replay.timeout;

        let Some(records) = self.observable(
            zone,
            ledger,
            history,
            occurrence,
            checks,
            before_local_sequence,
            bound.as_deref(),
        )?
        else {
            return Ok(Ensured::of(
                captured.clone(),
                abandon(format!(
                    "the history holds more than {} records, the most one replay reads \
                 (`events.replay.max_records`)",
                    self.replay.max_records
                )),
            ));
        };
        if std::time::Instant::now() >= deadline {
            return Ok(Ensured::of(
                captured.clone(),
                abandon(format!(
                    "the history could not be read within {:?} (`events.replay.timeout`)",
                    self.replay.timeout
                )),
            ));
        }
        let mut abandoned = std::collections::BTreeMap::new();
        // Only what is stale. A partition that is already up to date must not be rebuilt by a
        // sibling's staleness — a rebuild discards a history to replace it, and doing that
        // needlessly is a window somebody's concurrent decision falls into.
        let rebuilding: Vec<&Verified<'_>> = checks
            .iter()
            .filter(|(partition, _, _)| stale.contains(&partition.name))
            .collect();
        for (partition, engine, _) in rebuilding {
            let mut occurrences = Vec::new();
            let mut late = false;
            for stored in &records {
                // The checks are part of the replay's work, under the same deadline (after the
                // review).
                if std::time::Instant::now() >= deadline {
                    late = true;
                    break;
                }
                // A ledger history is shared by profiles, while a partition's history is not. A
                // record addressed to a sibling profile or partition remains valid evidence but is
                // never an input to this engine.
                if !stored
                    .record
                    .policy_partitions
                    .iter()
                    .any(|name| name == &partition.name)
                {
                    continue;
                }
                let checked = contained(permguard_core::codes::common::UNAVAILABLE, || {
                    engine.check(&stored.occurrence)
                })
                .map_err(|refused| {
                    if refused.code == permguard_core::codes::common::UNAVAILABLE {
                        return ApiError::new(
                            ErrorClass::Unavailable,
                            refused.code,
                            refused.message,
                        );
                    }
                    ApiError::new(
                        ErrorClass::Unavailable,
                        permguard_core::codes::pdp_temporal::HISTORY_CONTRACT_INCOMPATIBLE,
                        format!(
                            "the signed occurrence `{}` was addressed to partition `{}` under \
                             commit `{}` and is incompatible with the contract now loaded there: \
                             {}. It is retained as evidence but cannot be replayed silently",
                            stored.record.event_id, partition.name, stored.record.commit, refused
                        ),
                    )
                })?;
                let derived = checked_history_key(&checked)?;
                if derived != stored.record.history_key || history_of(&derived) != history {
                    return Err(ApiError::new(
                        ErrorClass::Unavailable,
                        permguard_core::codes::pdp_temporal::HISTORY_CONTRACT_INCOMPATIBLE,
                        format!(
                            "the signed occurrence `{}` carries history key {:?}, while partition \
                             `{}` derives {:?} from its current contract. Replaying it under a \
                             different key would put it in another principal's history",
                            stored.record.event_id,
                            stored.record.history_key,
                            partition.name,
                            derived
                        ),
                    ));
                }
                occurrences.push(stored.occurrence.clone());
            }
            if late {
                abandoned.insert(
                    partition.name.clone(),
                    permguard_languages::evaluate::Verdict::deadline_exceeded(format!(
                        "the history could not be checked within {:?} (`events.replay.timeout`)",
                        self.replay.timeout
                    )),
                );
                continue;
            }
            let bytes: u64 = occurrences
                .iter()
                .map(|occurrence| occurrence.weight() as u64)
                .sum();
            if bytes > self.replay.max_bytes {
                abandoned.insert(
                    partition.name.clone(),
                    permguard_languages::evaluate::Verdict::deadline_exceeded(format!(
                        "the history spells {bytes} bytes, more than the {} one replay feeds an \
                         engine (`events.replay.max_bytes`)",
                        self.replay.max_bytes
                    )),
                );
                continue;
            }
            let rebuilt = contained(permguard_core::codes::common::UNAVAILABLE, || {
                engine.rebuild(history, &occurrences, Some(deadline))
            });
            if let Err(refused) = &rebuilt
                && refused.code == permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED
            {
                abandoned.insert(
                    partition.name.clone(),
                    permguard_languages::evaluate::Verdict::deadline_exceeded(format!(
                        "{} (`events.replay.timeout` is {:?})",
                        refused.message, self.replay.timeout
                    )),
                );
                continue;
            }
            rebuilt.map_err(|refused| {
                warn!(
                    event.name = "temporal.rebuild_failed",
                    component = COMPONENT,
                    zone,
                    ledger,
                    code = refused.code,
                    "a partition could not absorb the history it decides against: failing closed \
                     rather than deciding against a history nobody can reproduce"
                );

                ApiError::new(ErrorClass::Unavailable, refused.code, refused.message)
            })?;
        }
        // Marked clean one partition at a time, and only the ones this pass actually rebuilt: the
        // sibling profile's partitions were not touched and their notes must keep saying so.
        let mut applied = self.applied.lock().map_err(|_| {
            ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::pdp_temporal::HISTORY_LOCK_POISONED,
                "this plane's record of what it has replayed is unusable",
            )
        })?;
        for partition in stale {
            if abandoned.contains_key(&partition) {
                continue;
            }
            applied.insert(key_of(&partition), watermark.clone());
        }

        Ok(Ensured {
            abandoned,
            shared: captured,
        })
    }

    /// The ordered run a partition of this ledger should have observed.
    ///
    /// This plane's own journal and, under a shared mode, what it has imported — merged into **one**
    /// run in the documented deterministic order. One function, because "what did this policy see"
    /// has one answer: a shared-mode rebuild that replayed only the imported half would silently
    /// discard everything this plane recorded itself.
    #[allow(clippy::too_many_arguments)]
    fn observable(
        &self,
        zone: &str,
        ledger: &str,
        history: &str,
        occurrence: &Occurrence,
        checks: &[Verified<'_>],
        before_local_sequence: u64,
        bound: Option<&[permguard_core::frontier::FrontierRun]>,
    ) -> Result<Option<Vec<StoredOccurrence>>, ApiError> {
        let unreadable = |what: &str, detail: String| {
            ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::pdp_temporal::HISTORY_UNREADABLE,
                format!("{what}: {detail}"),
            )
        };

        let (from, until) = window_of(checks, occurrence).ok_or_else(|| {
            unreadable(
                "this occurrence",
                "its instant is not a canonical one".to_owned(),
            )
        })?;
        let query = permguard_events::index::Query {
            event_type: permguard_languages::event::EVENT_TYPE.to_owned(),
            history: history.to_owned(),
            // Not narrowed by action or kind: what is being rebuilt is the history a *set* of
            // leaves will range over, and narrowing to one leaf's selectors would build an engine
            // that answers that leaf and lies to the others.
            action: None,
            kind: None,
            from,
            until,
        };

        // A range scan over this history and this window, never a read of the ledger.
        let mut records = both(&query, |query| self.streams.scan(zone, ledger, query))
            .map_err(|error| unreadable("this plane's own journal", error.to_string()))?;
        records.retain(|(position, _)| *position < before_local_sequence);
        let mut records: Vec<serde_json::Value> =
            records.into_iter().map(|(_, record)| record).collect();
        if let Some(imports) = &self.imports
            && self.consistency.is_shared()
        {
            // The imported half, read the same way: a range scan over its own index, bounded by
            // the same history partition and the same window. It used to be "load every imported
            // record and filter", so a plane in a shared mode paid its whole retained import
            // history on every decision while its own journal cost one window.
            records.extend(
                both(&query, |query| imports.window(zone, ledger, query))
                    .map_err(|error| unreadable("the imported history", error.to_string()))?,
            );
        }
        if let Some(imported) = &self.imported
            && self.consistency.is_shared()
        {
            records.extend(
                both(&query, |query| imported.window(zone, ledger, query, bound))
                    .map_err(|error| unreadable("the imported history", error.to_string()))?,
            );
        }
        // The replay plan's record bound, before anything is parsed (DOGWOOD-03).
        if records.len() as u64 > self.replay.max_records {
            return Ok(None);
        }
        let records = if self.consistency.is_shared() {
            // One logical occurrence applies once, whichever plane recorded it; one recorded with
            // different bytes is quarantined (WP-6.2c2b1).
            // The conflicts the durable logical index knows, beyond this window (WP-6.4b).
            let known = match &self.imported {
                Some(imported) => imported
                    .conflicting(zone, ledger)
                    .map_err(|error| unreadable("the logical index", error.to_string()))?,
                None => std::collections::BTreeSet::new(),
            };
            let (records, quarantined) = super::imported::deduplicated(records, &known);
            // A conflict the window itself shows, which an index rebuilt from the consumer alone
            // may not hold yet: `shared-bounded` still decides only on a consistent history.
            if quarantined > 0
                && self.consistency == permguard_core::config::Consistency::SharedBounded
            {
                return Err(ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::HISTORY_CONFLICTED,
                    format!(
                        "the shared history of `{zone}/{ledger}` holds {quarantined} \
                         occurrence(s) in this decision's window recorded with different bytes \
                         by more than one origin, and `shared-bounded` decides only on a \
                         consistent history. The event is recorded; the decision is withheld \
                         while a conflicting occurrence is in the window"
                    ),
                ));
            }
            if quarantined > 0 {
                tracing::warn!(
                    event.name = "temporal.occurrence_quarantined",
                    component = "temporal",
                    zone,
                    ledger,
                    quarantined,
                    "occurrences recorded with different bytes by more than one plane are left \
                     out of shared decisions"
                );
            }
            records
        } else {
            let mut records = records;
            records.sort_by_key(super::imports::order_of);
            records
        };

        let mut occurrences = Vec::with_capacity(records.len());
        for value in &records {
            let record = permguard_events::record::validate(value)
                .map_err(|error| unreadable("a stored record", error.to_string()))?;
            // Each record by the version it was written in: version 1 records stay as written and
            // replay beside version 2 ones (TL-5c).
            let occurrence =
                permguard_languages::event::read_typed(&record.event_type, &record.event)
                    .map_err(|why| unreadable("a stored occurrence", why))?;
            if occurrence.event_id != record.event_id
                || occurrence.kind != record.kind
                || occurrence.occurred_at != record.occurred_at
            {
                return Err(unreadable(
                    "a stored record",
                    "its filter fields do not match its typed occurrence".to_owned(),
                ));
            }
            occurrences.push(StoredOccurrence { record, occurrence });
        }

        Ok(Some(occurrences))
    }

    /// The occurrence's history key, which every addressed partition must agree on.
    fn history_key(
        &self,
        checks: &[Verified<'_>],
        zone: &str,
        ledger: &str,
    ) -> Result<Option<permguard_events::record::HistoryKey>, ApiError> {
        // Two option layers are intentional: the outer one says whether the first partition has
        // spoken; the inner one is its answer (`None` means global history). Collapsing the two made
        // a global partition disappear from agreement checking, so a profile could mix global and
        // per-principal history while the record and index carried only the latter.
        let mut agreed: Option<Option<permguard_events::record::HistoryKey>> = None;
        for (partition, _, checked) in checks {
            let key = checked_history_key(checked)?;
            match &agreed {
                None => agreed = Some(key),
                Some(held) if *held == key => {}
                Some(held) => {
                    return Err(ApiError::new(
                        ErrorClass::Validation,
                        permguard_core::codes::pdp_temporal::EVENT_HISTORY_DISAGREES,
                        format!(
                            "the partitions of `{zone}/{ledger}` derive different history keys \
                             for this occurrence: `{}` derives {:?} and an earlier one derived \
                             {:?}. This record version carries one history key, so accepting a \
                             mixture of global and partitioned history — or two different pins — \
                             would make at least one engine replay the wrong occurrences",
                            partition.name,
                            key.as_ref().map(|key| &key.pins),
                            held.as_ref().map(|key| &key.pins)
                        ),
                    ));
                }
            }
        }

        Ok(agreed.flatten())
    }

    /// Reads the submission: the store it names, and the occurrence it carries.
    fn read(&self, request: &SubmitRequest) -> Result<Read, ApiError> {
        let malformed = |code: &'static str, message: String| {
            self.metrics.count(
                &measure::REFUSALS,
                &[(permguard_core::metrics::labels::REASON, code)],
            );

            ApiError::new(ErrorClass::Validation, code, message)
        };

        let store = request.store.as_ref().ok_or_else(|| {
            malformed(
                permguard_core::codes::pdp_temporal::STORE_REQUIRED,
                "a submission names its store: `store.zone` and `store.ledger`".to_owned(),
            )
        })?;
        let named = |value: &Option<String>, field: &str| {
            value
                .as_deref()
                .map(str::trim)
                .filter(|held| !held.is_empty())
                .map(ToOwned::to_owned)
                .ok_or_else(|| {
                    malformed(
                        permguard_core::codes::pdp_temporal::STORE_REQUIRED,
                        format!("`store.{field}` is required: there is no default store"),
                    )
                })
        };
        let zone = named(&store.zone, "zone")?;
        let ledger = named(&store.ledger, "ledger")?;
        let profile = store
            .profile
            .as_deref()
            .map(str::trim)
            .filter(|held| !held.is_empty())
            .unwrap_or(permguard_languages::request::DEFAULT_PROFILE)
            .to_owned();

        let body = request.event.as_ref().ok_or_else(|| {
            malformed(
                permguard_core::codes::pdp_temporal::EVENT_REQUIRED,
                "a submission carries an event: `event.type` and `event.data`".to_owned(),
            )
        })?;
        let declared = body.kind.as_deref().unwrap_or_default();
        // The type is checked, never obeyed: one of the two registered versions, and which one the
        // addressed partitions accept is checked against their manifests in `stage` (TL-5c).
        if !EVENT_TYPES.contains(&declared) {
            return Err(malformed(
                permguard_core::codes::pdp_temporal::EVENT_TYPE_UNSUPPORTED,
                format!(
                    "`{declared}` is not an event type this plane accepts; it accepts `{}` and \
                     `{}`",
                    EVENT_TYPES[0], EVENT_TYPES[1]
                ),
            ));
        }
        let data = body.data.clone().ok_or_else(|| {
            malformed(
                permguard_core::codes::pdp_temporal::EVENT_REQUIRED,
                "`event.data` is required".to_owned(),
            )
        })?;
        let occurrence = if declared == permguard_languages::event::EVENT_TYPE_V2 {
            let parsed: permguard_languages::OccurrenceBodyV2 =
                serde_json::from_value(data.clone()).map_err(|error| {
                    malformed(
                        permguard_core::codes::pdp_temporal::EVENT_MALFORMED,
                        format!("`event.data` is not a `{declared}`: {error}"),
                    )
                })?;
            parsed.read()
        } else {
            let parsed: OccurrenceBody = serde_json::from_value(data.clone()).map_err(|error| {
                malformed(
                    permguard_core::codes::pdp_temporal::EVENT_MALFORMED,
                    format!("`event.data` is not a `{declared}`: {error}"),
                )
            })?;
            parsed.read()
        }
        .map_err(|why| malformed(why.code, why.message))?;

        Ok(Read {
            zone,
            ledger,
            profile,
            occurrence,
            event: data,
        })
    }

    /// The addressed partitions, each with its remembering half.
    fn addressed<'a>(
        &self,
        loaded: &'a Loaded,
        profile: &str,
    ) -> Result<Vec<Addressed<'a>>, ApiError> {
        // Present, because `Decider::loaded` refused a profile this ledger does not declare before
        // anything reached here, against the same `head` snapshot. Absent would mean this build
        // read one manifest two different ways, which is not a caller's mistake and not a state to
        // answer from.
        let declared = loaded.head.manifest.profiles.get(profile).ok_or_else(|| {
            ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::pdp_temporal::PROFILE_VANISHED,
                format!(
                    "the profile `{profile}` was resolved and is now absent from the same commit"
                ),
            )
        })?;
        if !permguard_objects::manifest::is_temporal_profile(&declared.r#type) {
            return Err(ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::pdp_temporal::PROFILE_NOT_TEMPORAL,
                format!(
                    "the profile `{profile}` is `{}`, which decides from the request alone. Submit \
                     to `{}` instead, or name a `{}` profile",
                    declared.r#type,
                    permguard_languages::request::EVALUATION_PATH,
                    temporal::INTERFACE
                ),
            ));
        }

        let mut addressed = Vec::with_capacity(loaded.partitions.len());
        for partition in &loaded.partitions {
            let engine = partition.evaluator().temporal().ok_or_else(|| {
                // The manifest gate refuses this combination at load, so reaching it means a
                // ledger was loaded by a build whose gate disagreed with this one. Fail closed.
                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::PARTITION_NOT_TEMPORAL,
                    format!(
                        "the partition `{}` runs `{}`, which keeps no history",
                        partition.name, partition.language
                    ),
                )
            })?;
            addressed.push((partition, engine));
        }
        if addressed.is_empty() {
            return Err(ApiError::new(
                ErrorClass::Unavailable,
                permguard_core::codes::pdp_temporal::PROFILE_EMPTY,
                format!("the profile `{profile}` names no partitions"),
            ));
        }

        Ok(addressed)
    }

    /// This plane's own clock, as the canonical instant a record carries.
    fn now(&self) -> Result<String, ApiError> {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX))
            .unwrap_or_default();

        permguard_events::index::render_epoch_seconds(seconds).ok_or_else(|| {
            ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::pdp_temporal::CLOCK_UNUSABLE,
                "this plane's clock is outside the range an event record can state".to_owned(),
            )
        })
    }

    /// Whether the caller's `occurred_at` is one this plane will record.
    ///
    /// Untrusted, and bounded from both sides. Too far ahead and a caller could place an event
    /// beyond every window a policy looks in, so nothing ever matches it; too far behind and it
    /// would land inside a window whose events have already decided something, changing the
    /// meaning of a decision already given.
    fn check_clock(&self, occurrence: &Occurrence, observed_at: &str) -> Result<(), ApiError> {
        let Some(now) = permguard_events::index::epoch_seconds(observed_at) else {
            return Err(ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::pdp_temporal::CLOCK_UNUSABLE,
                "this plane's clock is not a canonical instant".to_owned(),
            ));
        };
        let ahead = occurrence.occurred_at_epoch.saturating_sub(now);
        let behind = now.saturating_sub(occurrence.occurred_at_epoch);
        let skew = i64::try_from(self.clock_skew.as_secs()).unwrap_or(i64::MAX);
        let lateness = i64::try_from(self.allowed_lateness.as_secs()).unwrap_or(i64::MAX);

        if ahead > skew {
            self.metrics.count(
                &measure::REFUSALS,
                &[(
                    permguard_core::metrics::labels::REASON,
                    permguard_core::codes::pdp_temporal::EVENT_AHEAD_OF_CLOCK,
                )],
            );

            return Err(ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::pdp_temporal::EVENT_AHEAD_OF_CLOCK,
                format!(
                    "`{}` is {ahead}s ahead of this plane's clock, and it accepts at most {skew}s \
                     of skew. An event placed in the future sits outside every window a policy \
                     looks in until the clock reaches it",
                    occurrence.occurred_at
                ),
            ));
        }
        if behind > lateness {
            self.metrics.count(
                &measure::REFUSALS,
                &[(
                    permguard_core::metrics::labels::REASON,
                    permguard_core::codes::pdp_temporal::EVENT_TOO_LATE,
                )],
            );

            return Err(ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::pdp_temporal::EVENT_TOO_LATE,
                format!(
                    "`{}` is {behind}s old, and this plane accepts events up to {lateness}s late. \
                     Recording it now would put it inside windows that have already decided \
                     something, which would change what those decisions meant",
                    occurrence.occurred_at
                ),
            ));
        }

        Ok(())
    }

    /// Turns an append failure into the answer a caller can act on.
    fn refuse_append(&self, failed: Failed, labels: &[permguard_core::Label<'_>]) -> ApiError {
        match failed {
            Failed::Conflict { seq, stored_digest } => {
                self.metrics.count(&measure::CONFLICTS, labels);
                warn!(
                    event.name = "temporal.event_id_conflict",
                    component = COMPONENT,
                    sequence = seq,
                    stored = stored_digest.as_str(),
                    "one event id was submitted twice with different content"
                );

                ApiError::new(
                    ErrorClass::Conflict,
                    permguard_core::codes::pdp_temporal::EVENT_ID_CONFLICT,
                    format!(
                        "this event id is already recorded at sequence {seq} carrying a different \
                         occurrence. An id says two submissions are the same occurrence; two \
                         different ones under it is either a client that reuses ids or a replay, \
                         and neither is resolved by picking one"
                    ),
                )
            }
            // No `on_full: open`. A journal that cannot accept an event fails the request closed:
            // dropping it would silently change what every later decision in this ledger means.
            Failed::Journal(permguard_events::journal::JournalError::Full) => {
                self.metrics.count(
                    &measure::REFUSALS,
                    &[(
                        permguard_core::metrics::labels::REASON,
                        permguard_core::codes::pdp_temporal::JOURNAL_FULL,
                    )],
                );

                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::JOURNAL_FULL,
                    "this plane's event journal for that ledger is full. Temporal history is \
                     never dropped to make room: an event silently lost would change what future \
                     authorizations mean, so submissions fail until the control plane has \
                     acknowledged what is held"
                        .to_owned(),
                )
            }
            Failed::Journal(error) => {
                self.metrics.count(
                    &measure::REFUSALS,
                    &[(
                        permguard_core::metrics::labels::REASON,
                        permguard_core::codes::pdp_temporal::JOURNAL_UNAVAILABLE,
                    )],
                );
                warn!(
                    event.name = "temporal.journal_unavailable",
                    component = COMPONENT,
                    reason = %error,
                    "an occurrence could not be made durable: failing closed"
                );

                ApiError::new(
                    ErrorClass::Unavailable,
                    permguard_core::codes::pdp_temporal::JOURNAL_UNAVAILABLE,
                    format!(
                        "this occurrence could not be made durable, so it was not decided: {error}"
                    ),
                )
            }
            Failed::Digest(error) => ApiError::new(
                ErrorClass::Internal,
                permguard_core::codes::pdp_temporal::RECORD_NOT_CANONICAL,
                format!("the event record could not be canonicalized: {error}"),
            ),
        }
    }

    /// Publishes where this ledger's journal stands, after each append.
    fn publish_watermarks(&self, zone: &str, ledger: &str) {
        // A sequence number is a position in one ledger's stream; summed or compared across
        // ledgers it means nothing, so the watermarks stay in the journal and the backlog, which
        // is the difference an operator acts on, is what the shipper publishes.
        if let Ok(bytes) = self.streams.bytes(zone, ledger) {
            self.metrics.set_aggregated(
                &measure::JOURNAL_BYTES,
                permguard_core::Aggregate::Sum,
                &format!("{zone}/{ledger}"),
                bytes as f64,
            );
        }
    }
}

/// The window a decision about `occurrence` reads, `[from, until]` in epoch seconds: back from the
/// occurrence's own instant over the widest window the addressed partitions' policies declare,
/// taken from the loaded schemas rather than from retention. `max_window` is a validation and
/// retention ceiling — reading everything inside it because a leaf *could* ask for it is exactly
/// the read the index exists to avoid, and the widest declared window is the widest any leaf can
/// name. `None` when the instant is not a canonical one.
fn window_of(checks: &[Verified<'_>], occurrence: &Occurrence) -> Option<(i64, i64)> {
    let window = checks
        .iter()
        .map(|(_, engine, _)| engine.contract().max_window_seconds)
        .max()
        .unwrap_or(0);
    let until = permguard_events::index::epoch_seconds(&occurrence.occurred_at)?;
    Some((until.saturating_sub(window), until))
}

/// How long ago an instant was, in seconds, or `None` for one that never happened.
fn staleness_of(read_at: &str) -> Option<u64> {
    let then = permguard_events::index::epoch_seconds(read_at)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| i64::try_from(since.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or_default();

    u64::try_from(now.saturating_sub(then)).ok()
}

/// A submission, read.
struct Read {
    zone: String,
    ledger: String,
    profile: String,
    occurrence: Occurrence,
    /// The occurrence exactly as the caller sent it, which is what the record carries and what the
    /// occurrence digest is taken over.
    event: serde_json::Value,
}

/// One durable record and the typed occurrence it carries.
struct StoredOccurrence {
    record: Record,
    occurrence: Occurrence,
}

/// One history scan over every registered event version: a history written in version 1 and
/// continued in version 2 is one history (TL-5c). The caller orders what it read.
fn both<T, E>(
    query: &permguard_events::index::Query,
    mut read: impl FnMut(&permguard_events::index::Query) -> Result<Vec<T>, E>,
) -> Result<Vec<T>, E> {
    let mut held = Vec::new();
    for event_type in EVENT_TYPES {
        let mut each = query.clone();
        each.event_type = event_type.to_owned();
        held.extend(read(&each)?);
    }
    Ok(held)
}

/// The registered event types a temporal submission may assert, version 1 first.
const EVENT_TYPES: [&str; 2] = [
    permguard_languages::event::EVENT_TYPE,
    permguard_languages::event::EVENT_TYPE_V2,
];

/// The registered event type this submission asserted, after it was checked.
fn temporal_event_type(request: &SubmitRequest) -> String {
    request
        .event
        .as_ref()
        .and_then(|event| event.kind.clone())
        .unwrap_or_else(|| permguard_languages::event::EVENT_TYPE.to_owned())
}

/// The key a history is addressed by: the digest, or the empty string for global history.
///
/// One spelling, used for the durable record, for the journal's index and for the engine that
/// decides — because they are the same thing, and three functions deciding it separately is three
/// chances for a decision to be taken against a history the record was not stored in.
fn history_of(key: &Option<permguard_events::record::HistoryKey>) -> String {
    key.as_ref()
        .map(|key| key.digest.clone())
        .unwrap_or_default()
}

/// The history key one partition derives from its current contract.
fn checked_history_key(
    checked: &Checked,
) -> Result<Option<permguard_events::record::HistoryKey>, ApiError> {
    if checked.pins.is_empty() {
        return Ok(None);
    }
    let pins = checked.pin_names();
    let values = checked.pin_values();

    Ok(Some(permguard_events::record::HistoryKey {
        digest: history_digest(&pins, &values)?,
        pins,
        values,
    }))
}

/// The history key's digest: the index key, taken over the pins and their canonical values.
///
/// Domain-separated and length-delimited, like every other digest here. The pin *names* are hashed
/// beside the values because two schemas with different pins may derive the same values, and those
/// are different histories.
fn history_digest(pins: &[String], values: &[String]) -> Result<String, ApiError> {
    let value = serde_json::json!({"pins": pins, "values": values});

    permguard_events::record::history_digest_of(&value).map_err(|error| {
        ApiError::new(
            ErrorClass::Internal,
            permguard_core::codes::pdp_temporal::HISTORY_KEY_NOT_CANONICAL,
            format!("the history key could not be canonicalized: {error}"),
        )
    })
}

/// A temporal engine entry inside the panic boundary: a panic is refused under `code`, and its
/// own words — an engine's, which can carry policy text or tenant data — stay out of the refusal.
fn contained<T>(
    code: &'static str,
    work: impl FnOnce() -> Result<T, temporal::Refused>,
) -> Result<T, temporal::Refused> {
    permguard_languages::guard::contained(work).unwrap_or_else(|_| {
        Err(temporal::Refused::new(
            code,
            "the partition's engine came apart; nothing was decided",
        ))
    })
}

/// A response as this deployment may show it.
///
/// A failure's reason carries the engines' own words — what failed, against which attribute —
/// and those can carry tenant data. They are internal detail: under minimal disclosure each such
/// reason keeps its code and gets a fixed sentence, exactly as a refusal's message does; under
/// full disclosure they travel as written. Applied by both transports, to a first answer and to a
/// replayed one alike — one stored by an earlier release, under its codes, included: a partition
/// reason is only ever written for a failure, and the top-level reason keeps its words only when
/// it is one of the fixed sentences of a decided outcome.
pub fn disclosed(
    mut response: temporal::SubmitResponse,
    disclosure: permguard_core::Disclosure,
) -> temporal::SubmitResponse {
    use permguard_core::codes::{pdp_native, pdp_temporal};

    if disclosure == permguard_core::Disclosure::Full {
        return response;
    }
    if let Some(reason) = response.reason.as_mut() {
        let decided = [
            pdp_temporal::PERMITTED,
            pdp_temporal::DENIED,
            pdp_temporal::NOT_PERMITTED,
        ];
        if reason.code == pdp_native::EVALUATION_INDETERMINATE {
            reason.message =
                "the occurrence is recorded and could not be evaluated; this is not a deny"
                    .to_owned();
        } else if !decided.contains(&reason.code.as_str()) {
            reason.message = format!("the occurrence could not be decided: {}", reason.code);
        }
    }
    for evaluation in &mut response.evaluations {
        if let Some(reason) = evaluation.reason.as_mut() {
            reason.message = format!(
                "this partition could not evaluate the occurrence: {}",
                reason.code
            );
        }
    }

    response
}

/// The two audiences of one temporal decision's reason.
fn reason_of(outcome: &permguard_languages::evaluate::Outcome) -> temporal::Reason {
    if outcome.indeterminate() {
        return temporal::Reason {
            code: permguard_core::codes::pdp_native::EVALUATION_INDETERMINATE.to_owned(),
            message: outcome
                .errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        };
    }
    if outcome.permitted() {
        return temporal::Reason {
            code: permguard_core::codes::pdp_temporal::PERMITTED.to_owned(),
            message: "a policy permitted it against this partition's history".to_owned(),
        };
    }
    if outcome.denials.is_empty() {
        return temporal::Reason {
            code: permguard_core::codes::pdp_temporal::NOT_PERMITTED.to_owned(),
            message: "no policy permitted it against this partition's history".to_owned(),
        };
    }

    temporal::Reason {
        code: permguard_core::codes::pdp_temporal::DENIED.to_owned(),
        message: "a policy refused it against this partition's history".to_owned(),
    }
}

/// The mirror a request names, by identifier or by display name.
///
/// Reads only the identity each mirror keeps beside itself, so an answer already settled can be
/// found without compiling the profile it was settled under — which is the point: that profile may
/// have been updated or removed since.
fn permguard_data_plane_mirror_of(
    root: &std::path::Path,
    zone: &str,
    ledger: &str,
) -> Result<crate::authz::store::Mirror, ApiError> {
    crate::authz::store::find(root, zone, ledger).ok_or_else(|| {
        ApiError::new(
            ErrorClass::NotFound,
            permguard_core::codes::pdp_native::LEDGER_NOT_SERVED,
            format!("this plane does not serve `{zone}/{ledger}`"),
        )
    })
}
