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
    /// The imported histories, when this plane reads other planes' events.
    imports: Option<Arc<super::imports::Imports>>,
    /// How stale imported history may be before `shared-bounded` fails decisions closed.
    max_staleness: std::time::Duration,
    /// The imported watermark each `(zone, ledger, history)` has been rebuilt to.
    ///
    /// So a rebuild is paid once per watermark rather than once per submission: replaying even a
    /// bounded history costs something, and the answer does not change until more arrives.
    ///
    /// Keyed by history and not merely by ledger, because histories are independent: what one
    /// caller's engine has absorbed says nothing about another's, and a note kept per ledger would
    /// let the first history replayed stand in for every history the ledger holds.
    applied: std::sync::Mutex<std::collections::BTreeMap<(String, String, String), String>>,
}

impl Submitter {
    pub fn new(
        decider: Arc<Decider>,
        streams: Arc<Streams>,
        metrics: permguard_core::metrics::Metrics,
    ) -> Self {
        let bounds = streams.bounds();
        let blocking = crate::blocking::Blocking::new(
            permguard_core::config::default_max_blocking(),
            metrics.clone(),
        );

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
            max_staleness: permguard_core::config::DEFAULT_EVENTS_PULL_MAX_STALENESS,
            applied: std::sync::Mutex::new(std::collections::BTreeMap::new()),
        }
    }

    /// Decides against imported history as well, under this mode.
    pub fn with_shared_history(
        mut self,
        consistency: permguard_core::config::Consistency,
        imports: Arc<super::imports::Imports>,
        max_staleness: std::time::Duration,
    ) -> Self {
        self.consistency = consistency;
        self.imports = Some(imports);
        self.max_staleness = max_staleness;

        self
    }

    /// Which history this plane's decisions range over.
    pub fn consistency(&self) -> permguard_core::config::Consistency {
        self.consistency
    }

    /// The journals this plane writes, for the surfaces that report on them.
    pub fn streams(&self) -> &Arc<Streams> {
        &self.streams
    }

    /// Submits one occurrence.
    pub async fn submit(&self, request: &SubmitRequest) -> Result<SubmitResponse, ApiError> {
        let started = Instant::now();
        let answered = self.answer(request).await;
        self.metrics.observe(
            &measure::SUBMISSION_SECONDS,
            &[],
            started.elapsed().as_secs_f64(),
        );

        answered
    }

    async fn answer(&self, request: &SubmitRequest) -> Result<SubmitResponse, ApiError> {
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
        self.streams
            .adopt((&zone, &ledger), (&zone_name, &ledger_name))
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    "event_journal_ambiguous",
                    error.to_string(),
                )
            })?;
        let labels = [("zone", zone.as_str()), ("ledger", ledger.as_str())];

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
            &event,
            &occurrence.event_id,
            &profile,
            &occurrence_kind,
        )? {
            self.metrics.count(
                &measure::SUBMISSIONS,
                &[("outcome", "replayed"), ("zone", zone.as_str())],
            );

            return Ok(settled);
        }

        let loaded = self.decider.loaded(&zone, &ledger, &profile).await?;
        let addressed = self.addressed(&loaded, &profile)?;

        // Every partition, before anything is written. A profile may address several with
        // different schemas, and an occurrence only some of them accept is not one this ledger can
        // hold: recording it would leave the addressed partitions holding different histories of
        // the same events.
        let mut checks: Vec<Verified<'_>> = Vec::with_capacity(addressed.len());
        for (partition, engine) in &addressed {
            let checked = engine.check(&occurrence).map_err(|refused| {
                self.metrics
                    .count(&measure::REFUSALS, &[("reason", refused.code)]);
                debug!(
                    event.name = "temporal.event_refused",
                    component = COMPONENT,
                    zone = zone.as_str(),
                    ledger = ledger.as_str(),
                    partition = partition.name.as_str(),
                    code = refused.code,
                    "an occurrence was refused before anything was recorded"
                );

                ApiError::new(
                    ErrorClass::Validation,
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
                "event_kind_disagrees",
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
            event_type: temporal_event_type(request),
            event_id: occurrence.event_id.clone(),
            occurrence_digest: occurrence_digest_of(&event).map_err(|error| {
                ApiError::new(
                    ErrorClass::Validation,
                    "event_not_canonical",
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

        let appending = Instant::now();
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
        let appending = Instant::now();
        let (appended, prepared) = {
            let streams = Arc::clone(&self.streams);
            let (held_zone, held_ledger) = (zone.clone(), ledger.clone());
            self.blocking
                .run(&labels, move || {
                    let appended = streams.append(&held_zone, &held_ledger, proposed);
                    let prepared = match &appended {
                        Ok((Written::Appended { seq, .. }, _)) => streams
                            .sequencer(&held_zone, &held_ledger)
                            .ok()
                            .map(|sequencer| sequencer.turn(*seq)),
                        _ => None,
                    };

                    (appended, prepared)
                })
                .await
                .map_err(|refused| match refused {
                    crate::blocking::Refused::AtCapacity(held) => {
                        self.metrics
                            .count(&measure::REFUSALS, &[("reason", "at_capacity")]);

                        ApiError::new(
                            ErrorClass::Unavailable,
                            "event_append_at_capacity",
                            format!(
                                "{held}. An append waits for the flush that covers it and then for \
                                 its turn to be applied, so this plane bounds how many may be \
                                 outstanding and refuses beyond it rather than queueing behind a \
                                 disk"
                            ),
                        )
                    }
                    crate::blocking::Refused::Failed(why) => ApiError::new(
                        ErrorClass::Unavailable,
                        "event_not_durable",
                        format!("the occurrence could not be made durable: {why}"),
                    ),
                })?
        };
        let (written, mut record) = appended.map_err(|failed| {
            // The turn, if one was taken, is dropped with `prepared` here — the sequence is
            // released rather than stranded.
            self.refuse_append(failed, &labels)
        })?;
        self.metrics.observe(
            &measure::APPEND_SECONDS,
            &labels,
            appending.elapsed().as_secs_f64(),
        );
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
                self.metrics.count(&measure::IDEMPOTENT, &labels);
                let stored = self
                    .streams
                    .record_at(&zone, &ledger, seq)
                    .map_err(|error| {
                        ApiError::new(
                            ErrorClass::Unavailable,
                            "event_record_unreadable",
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
                        "event_record_invalid",
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
                        "event_id_conflict",
                        format!(
                            "`{}` names a different durable occurrence at sequence {seq}",
                            occurrence.event_id
                        ),
                    ));
                }
                if stored.profile != profile || stored.event_type != record.event_type {
                    return Err(ApiError::new(
                        ErrorClass::Conflict,
                        "event_routing_conflict",
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
                match self.streams.outcome(&zone, &ledger, &occurrence.event_id) {
                    Ok(Some(held)) => match serde_json::from_value::<SubmitResponse>(held) {
                        Ok(response) => {
                            info!(
                                event.name = "temporal.idempotent",
                                component = COMPONENT,
                                zone = zone.as_str(),
                                ledger = ledger.as_str(),
                                event_id = occurrence.event_id.as_str(),
                                sequence = seq,
                                "a retry of an occurrence this ledger already holds, answered as \
                                 it was answered the first time"
                            );
                            self.metrics.count(
                                &measure::SUBMISSIONS,
                                &[("outcome", "replayed"), ("zone", zone.as_str())],
                            );

                            return Ok(response);
                        }
                        Err(error) => {
                            return Err(ApiError::new(
                                ErrorClass::Unavailable,
                                "event_outcome_unreadable",
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
                        zone = zone.as_str(),
                        ledger = ledger.as_str(),
                        sequence = seq,
                        "this occurrence is recorded and no answer was kept for it"
                    ),
                    Err(error) => {
                        return Err(ApiError::new(
                            ErrorClass::Unavailable,
                            "event_outcome_unreadable",
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
                        "event_recovery_commit_unavailable",
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

        let watermark = Watermark {
            instance,
            sequence,
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
                let sequencer = self.streams.sequencer(&zone, &ledger).map_err(|error| {
                    ApiError::new(
                        ErrorClass::Unavailable,
                        "history_unorderable",
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
            match self.streams.outcome(&zone, &ledger, &occurrence.event_id) {
                Ok(Some(held)) => {
                    let response =
                        serde_json::from_value::<SubmitResponse>(held).map_err(|error| {
                            ApiError::new(
                                ErrorClass::Unavailable,
                                "event_outcome_unreadable",
                                format!(
                                    "the durable answer for `{}` cannot be decoded: {error}",
                                    occurrence.event_id
                                ),
                            )
                        })?;
                    self.metrics.count(
                        &measure::SUBMISSIONS,
                        &[("outcome", "replayed"), ("zone", zone.as_str())],
                    );

                    return Ok(response);
                }
                Ok(None) => {}
                Err(error) => {
                    return Err(ApiError::new(
                        ErrorClass::Unavailable,
                        "event_outcome_unreadable",
                        format!(
                            "the durable answer index for `{}` cannot be read: {error}",
                            occurrence.event_id
                        ),
                    ));
                }
            }
        }

        // Replay while holding this sequence's turn. This used to happen before the append, which
        // allowed a later concurrent submission to pass the freshness check while an earlier,
        // durable sequence was still waiting to be applied. The current record is excluded by its
        // sequence, so rebuilding here cannot observe it twice.
        if let Err(error) = self.ensure_history(
            &checks,
            &partition_key,
            &occurrence,
            &zone,
            &ledger,
            sequence,
        ) {
            self.invalidate_history(&zone, &ledger, &partition_key);
            return Err(error);
        }

        // The history this decision will range over, and — for a bounded mode — whether it is
        // fresh enough to range over at all. Checked after the event is durable and before it is
        // decided: the record is kept either way, because losing it would change what *future*
        // decisions mean, and only the answer is withheld.
        let history = match self.history_scope(&zone, &ledger) {
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
        let (verdicts, complete) = self.apply(&checks, &partition_key, &occurrence, &zone, &ledger);
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
            &labels,
            applying.elapsed().as_secs_f64(),
        );

        if !decides {
            if !complete {
                self.metrics.count(
                    &measure::REFUSALS,
                    &[("reason", "event_application_incomplete")],
                );

                return Err(ApiError::new(
                    ErrorClass::Unavailable,
                    "event_application_incomplete",
                    format!(
                        "the occurrence `{}` is durable in `{zone}/{ledger}`, but not every \
                         partition of `{profile}` advanced. No accepted receipt was issued; the \
                         history must be rebuilt from the journal before this occurrence can be \
                         acknowledged",
                        occurrence.event_id
                    ),
                ));
            }
            self.metrics
                .count(&measure::SUBMISSIONS, &[("outcome", "accepted")]);

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
                &response.event_id,
                crate::temporal::streams::Routed {
                    profile: &profile,
                    kind: &occurrence_kind,
                },
                &response,
            )?;

            return Ok(response);
        }

        // The profile's single registered batch semantic: an explicit deny wins, silence is not a
        // deny, and a partition that could not evaluate is an objection. The same `resolve` the
        // stateless path uses, so one ledger cannot mean two things.
        let evaluations = verdicts
            .iter()
            .map(
                |(partition, verdict)| permguard_languages::temporal::PartitionEvaluation {
                    partition: partition.clone(),
                    decision: verdict.permitted,
                    policies: verdict.determining.clone(),
                    reason: verdict.error.as_ref().map(|message| {
                        permguard_languages::temporal::Reason {
                            code: "partition_evaluation_failed".to_owned(),
                            message: message.clone(),
                        }
                    }),
                },
            )
            .collect();
        let outcome = permguard_languages::evaluate::resolve(
            verdicts.into_iter().map(|(_, verdict)| verdict),
        );
        let decision_id = self
            .streams
            .decision_id(&zone, &ledger, &occurrence.event_id)
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    "decision_id_not_durable",
                    format!(
                        "the stable decision identity for `{}` could not be made durable: {error}",
                        occurrence.event_id
                    ),
                )
            })?;
        let reason = reason_of(&outcome);

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
                permit: outcome.permitted,
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
                },
            })
            .await?;

        self.metrics.count(
            &measure::SUBMISSIONS,
            &[("outcome", "decided"), ("zone", zone.as_str())],
        );

        let response = SubmitResponse {
            outcome: Outcome::Decided,
            event_id: occurrence.event_id,
            watermark,
            decision: Some(outcome.permitted),
            decision_id: Some(decision_id),
            policies: outcome.determining().to_vec(),
            evaluations,
            reason: Some(reason),
            history,
        };
        self.keep_outcome(
            &zone,
            &ledger,
            &response.event_id,
            crate::temporal::streams::Routed {
                profile: &profile,
                kind: &occurrence_kind,
            },
            &response,
        )?;

        Ok(response)
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
        event_id: &str,
        routed: crate::temporal::streams::Routed<'_>,
        response: &SubmitResponse,
    ) -> Result<(), ApiError> {
        let held = serde_json::to_value(response).map_err(|error| {
            ApiError::new(
                ErrorClass::Internal,
                "event_outcome_unrenderable",
                format!("the durable answer for `{event_id}` cannot be rendered: {error}"),
            )
        })?;
        self.streams
            .record_outcome(zone, ledger, event_id, routed, &held)
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
                    "event_outcome_not_durable",
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
    ) -> (Vec<(String, permguard_languages::evaluate::Verdict)>, bool) {
        let mut verdicts = Vec::with_capacity(checks.len());
        let mut complete = true;
        for (partition, engine, checked) in checks {
            match engine.apply(history, occurrence, checked) {
                Applied::Observed if !checked.decides => {}
                Applied::Observed => {
                    complete = false;
                    let message = format!(
                        "the partition declared `{}` as a decision kind but observed it without \
                         producing a decision",
                        occurrence.kind
                    );
                    warn!(
                        event.name = "temporal.partition_failed",
                        component = COMPONENT,
                        zone,
                        ledger,
                        partition = partition.name.as_str(),
                        reason = message.as_str(),
                        "a partition disagreed with its loaded event contract: failing closed"
                    );
                    verdicts.push((
                        partition.name.clone(),
                        permguard_languages::evaluate::Verdict::refused(message),
                    ));
                }
                Applied::Decided(verdict) => {
                    if !checked.decides || verdict.error.is_some() {
                        complete = false;
                    }
                    if let Some(error) = verdict.error.as_deref() {
                        warn!(
                            event.name = "temporal.partition_failed",
                            component = COMPONENT,
                            zone,
                            ledger,
                            partition = partition.name.as_str(),
                            reason = error,
                            "a partition could not decide a durable occurrence: failing closed"
                        );
                    } else if !checked.decides {
                        warn!(
                            event.name = "temporal.partition_failed",
                            component = COMPONENT,
                            zone,
                            ledger,
                            partition = partition.name.as_str(),
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
                "history_window_invalid",
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
                    "history_retention_insufficient",
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
    fn settled(
        &self,
        zone: &str,
        ledger: &str,
        event: &serde_json::Value,
        event_id: &str,
        profile: &str,
        kind: &str,
    ) -> Result<Option<SubmitResponse>, ApiError> {
        let known = self
            .streams
            .known(zone, ledger, event_id)
            .map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    "event_outcome_unreadable",
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
                "event_not_canonical",
                format!("the occurrence `{event_id}` cannot be digested: {error}"),
            )
        })?;
        if digest != known.occurrence_digest {
            // Counted, like every other refusal. A refusal no metric records is one an operator
            // meets as an unexplained failure rate: this is the path a client reusing an
            // identifier lands on, and it has to be visible as itself.
            self.metrics
                .count(&measure::REFUSALS, &[("reason", "event_id_conflict")]);

            return Err(ApiError::new(
                ErrorClass::Conflict,
                "event_id_conflict",
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
            self.metrics
                .count(&measure::REFUSALS, &[("reason", "event_routing_conflict")]);

            return Err(ApiError::new(
                ErrorClass::Conflict,
                "event_routing_conflict",
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
                    "event_outcome_unreadable",
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
                applied.remove(&(zone.to_owned(), ledger.to_owned(), history.to_owned()));
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
    fn history_scope(&self, zone: &str, ledger: &str) -> Result<HistoryScope, ApiError> {
        let Some(imports) = &self.imports else {
            return Ok(HistoryScope::local());
        };
        if !self.consistency.is_shared() {
            return Ok(HistoryScope::local());
        }
        let state = imports.state(zone, ledger).map_err(|error| {
            ApiError::new(
                ErrorClass::Unavailable,
                "imported_history_unreadable",
                format!(
                    "this plane's imported history for `{zone}/{ledger}` cannot be read: {error}"
                ),
            )
        })?;
        let staleness = staleness_of(&state.read_at);
        self.metrics.set(
            &measure::IMPORT_STALENESS,
            &[("zone", zone), ("ledger", ledger)],
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
                self.metrics
                    .count(&measure::REFUSALS, &[("reason", "history_stale")]);

                return Err(ApiError::new(
                    ErrorClass::Unavailable,
                    "history_stale",
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
        if gaps > 0 {
            self.metrics.set(
                &measure::IMPORT_GAPS_OPEN,
                &[("zone", zone), ("ledger", ledger)],
                gaps as f64,
            );
        }
        if gaps > 0
            && matches!(
                self.consistency,
                permguard_core::config::Consistency::SharedBounded
            )
        {
            self.metrics
                .count(&measure::REFUSALS, &[("reason", "history_incomplete")]);
            let oldest = state
                .gaps
                .iter()
                .filter(|gap| !gap.resolved)
                .map(|gap| (gap.from_sequence, gap.to_sequence))
                .next()
                .unwrap_or_default();

            return Err(ApiError::new(
                ErrorClass::Unavailable,
                "history_incomplete",
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
    ) -> Result<(), ApiError> {
        let imported = match (&self.imports, self.consistency.is_shared()) {
            (Some(imports), true) => Some(imports.state(zone, ledger).map_err(|error| {
                ApiError::new(
                    ErrorClass::Unavailable,
                    "imported_history_unreadable",
                    error.to_string(),
                )
            })?),
            _ => None,
        };
        let watermark = imported
            .as_ref()
            .filter(|state| state.imported > 0)
            .map(|state| state.offset.clone())
            .unwrap_or_default();

        // Per history, not per ledger: replaying one caller's events says nothing about another's,
        // and a note kept per ledger would let the first history replayed stand in for all of them.
        let key = (zone.to_owned(), ledger.to_owned(), history.to_owned());
        // A fresh engine is one that has been told nothing. Asked of the engines rather than
        // remembered here, because what a rebuild replaces is the engine: a note kept beside it
        // would outlive the thing it described, and the partition recompiled after an eviction
        // would read as one that had already been fed.
        let fresh: Vec<&Verified<'_>> = checks
            .iter()
            .filter(|(_, engine, _)| engine.observed(history) == 0)
            .collect();
        // Read the replay note under the map lock and release it before disk reads, schema checks
        // and provider execution. The journal sequencer already gives one submission at a time
        // for this ledger; holding one process-wide mutex through a rebuild would unnecessarily
        // make an unrelated tenant wait behind it.
        let moved = self
            .applied
            .lock()
            .map_err(|_| {
                ApiError::new(
                    ErrorClass::Internal,
                    "history_lock_poisoned",
                    "this plane's record of what it has replayed is unusable",
                )
            })?
            .get(&key)
            != Some(&watermark);
        if fresh.is_empty() && !moved {
            return Ok(());
        }

        let records = self.observable(
            zone,
            ledger,
            history,
            occurrence,
            checks,
            before_local_sequence,
        )?;
        // Everything, when the watermark moved; only what is behind, when it did not. A partition
        // that is already up to date must not be rebuilt by a sibling's freshness — a rebuild
        // discards a history to replace it, and doing that needlessly is a window somebody's
        // concurrent decision falls into.
        let rebuilding: Vec<&Verified<'_>> = match moved {
            true => checks.iter().collect(),
            false => fresh,
        };
        for (partition, engine, _) in rebuilding {
            let mut occurrences = Vec::new();
            for stored in &records {
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
                let checked = engine.check(&stored.occurrence).map_err(|refused| {
                    ApiError::new(
                        ErrorClass::Unavailable,
                        "history_contract_incompatible",
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
                        "history_contract_incompatible",
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
            engine.rebuild(history, &occurrences).map_err(|refused| {
                warn!(
                    event.name = "temporal.rebuild_failed",
                    component = COMPONENT,
                    zone,
                    ledger,
                    partition = partition.name.as_str(),
                    code = refused.code,
                    "a partition could not absorb the history it decides against: failing closed \
                     rather than deciding against a history nobody can reproduce"
                );

                ApiError::new(ErrorClass::Unavailable, refused.code, refused.message)
            })?;
        }
        self.applied
            .lock()
            .map_err(|_| {
                ApiError::new(
                    ErrorClass::Internal,
                    "history_lock_poisoned",
                    "this plane's record of what it has replayed is unusable",
                )
            })?
            .insert(key, watermark);

        Ok(())
    }

    /// The ordered run a partition of this ledger should have observed.
    ///
    /// This plane's own journal and, under a shared mode, what it has imported — merged into **one**
    /// run in the documented deterministic order. One function, because "what did this policy see"
    /// has one answer: a shared-mode rebuild that replayed only the imported half would silently
    /// discard everything this plane recorded itself.
    fn observable(
        &self,
        zone: &str,
        ledger: &str,
        history: &str,
        occurrence: &Occurrence,
        checks: &[Verified<'_>],
        before_local_sequence: u64,
    ) -> Result<Vec<StoredOccurrence>, ApiError> {
        let unreadable = |what: &str, detail: String| {
            ApiError::new(
                ErrorClass::Unavailable,
                "history_unreadable",
                format!("{what}: {detail}"),
            )
        };

        // The window this partition's policies can actually look back over, taken from the loaded
        // schemas rather than from retention. `max_window` is a validation and retention ceiling —
        // reading everything inside it because a leaf *could* ask for it is exactly the read this
        // index exists to avoid, and the widest declared window is the widest any leaf can name.
        let window = checks
            .iter()
            .map(|(_, engine, _)| engine.contract().max_window_seconds)
            .max()
            .unwrap_or(0);
        let until =
            permguard_events::index::epoch_seconds(&occurrence.occurred_at).ok_or_else(|| {
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
            from: until.saturating_sub(window),
            until,
        };

        // A range scan over this history and this window, never a read of the ledger.
        let mut records = self
            .streams
            .scan(zone, ledger, &query)
            .map_err(|error| unreadable("this plane's own journal", error.to_string()))?;
        records.retain(|record| {
            record
                .get("seq")
                .and_then(serde_json::Value::as_u64)
                .is_some_and(|sequence| sequence < before_local_sequence)
        });
        if let Some(imports) = &self.imports
            && self.consistency.is_shared()
        {
            // The imported half, read the same way: a range scan over its own index, bounded by
            // the same history partition and the same window. It used to be "load every imported
            // record and filter", so a plane in a shared mode paid its whole retained import
            // history on every decision while its own journal cost one window.
            records.extend(
                imports
                    .window(zone, ledger, &query)
                    .map_err(|error| unreadable("the imported history", error.to_string()))?,
            );
        }
        records.sort_by_key(super::imports::order_of);

        let mut occurrences = Vec::with_capacity(records.len());
        for value in &records {
            let record = permguard_events::record::validate(value)
                .map_err(|error| unreadable("a stored record", error.to_string()))?;
            let body: OccurrenceBody = serde_json::from_value(record.event.clone())
                .map_err(|error| unreadable("a stored record", error.to_string()))?;
            let occurrence = body
                .read()
                .map_err(|malformed| unreadable("a stored occurrence", malformed.to_string()))?;
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

        Ok(occurrences)
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
                        "event_history_disagrees",
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
            self.metrics.count(&measure::REFUSALS, &[("reason", code)]);

            ApiError::new(ErrorClass::Validation, code, message)
        };

        let store = request.store.as_ref().ok_or_else(|| {
            malformed(
                "store_required",
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
                        "store_required",
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
                "event_required",
                "a submission carries an event: `event.type` and `event.data`".to_owned(),
            )
        })?;
        let declared = body.kind.as_deref().unwrap_or_default();
        // The type is checked, never obeyed. This build implements one occurrence contract; a
        // second one is a registry entry with its own validator, not a branch here.
        if declared != permguard_languages::event::EVENT_TYPE {
            return Err(malformed(
                "event_type_unsupported",
                format!(
                    "`{declared}` is not an event type this plane accepts; it accepts `{}`",
                    permguard_languages::event::EVENT_TYPE
                ),
            ));
        }
        let data = body
            .data
            .clone()
            .ok_or_else(|| malformed("event_required", "`event.data` is required".to_owned()))?;
        let parsed: OccurrenceBody = serde_json::from_value(data.clone()).map_err(|error| {
            malformed(
                "event_malformed",
                format!(
                    "`event.data` is not a `{}`: {error}",
                    permguard_languages::event::EVENT_TYPE
                ),
            )
        })?;
        let occurrence = parsed
            .read()
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
                "profile_vanished",
                format!(
                    "the profile `{profile}` was resolved and is now absent from the same commit"
                ),
            )
        })?;
        if !permguard_objects::manifest::is_temporal_profile(&declared.r#type) {
            return Err(ApiError::new(
                ErrorClass::Validation,
                "profile_not_temporal",
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
                    "partition_not_temporal",
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
                "profile_empty",
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
                "clock_unusable",
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
                "clock_unusable",
                "this plane's clock is not a canonical instant".to_owned(),
            ));
        };
        let ahead = occurrence.occurred_at_epoch.saturating_sub(now);
        let behind = now.saturating_sub(occurrence.occurred_at_epoch);
        let skew = i64::try_from(self.clock_skew.as_secs()).unwrap_or(i64::MAX);
        let lateness = i64::try_from(self.allowed_lateness.as_secs()).unwrap_or(i64::MAX);

        if ahead > skew {
            self.metrics
                .count(&measure::REFUSALS, &[("reason", "event_ahead_of_clock")]);

            return Err(ApiError::new(
                ErrorClass::Validation,
                "event_ahead_of_clock",
                format!(
                    "`{}` is {ahead}s ahead of this plane's clock, and it accepts at most {skew}s \
                     of skew. An event placed in the future sits outside every window a policy \
                     looks in until the clock reaches it",
                    occurrence.occurred_at
                ),
            ));
        }
        if behind > lateness {
            self.metrics
                .count(&measure::REFUSALS, &[("reason", "event_too_late")]);

            return Err(ApiError::new(
                ErrorClass::Validation,
                "event_too_late",
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
    fn refuse_append(&self, failed: Failed, labels: &[(&str, &str)]) -> ApiError {
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
                    "event_id_conflict",
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
                self.metrics
                    .count(&measure::REFUSALS, &[("reason", "journal_full")]);

                ApiError::new(
                    ErrorClass::Unavailable,
                    "journal_full",
                    "this plane's event journal for that ledger is full. Temporal history is \
                     never dropped to make room: an event silently lost would change what future \
                     authorizations mean, so submissions fail until the control plane has \
                     acknowledged what is held"
                        .to_owned(),
                )
            }
            Failed::Journal(error) => {
                self.metrics
                    .count(&measure::REFUSALS, &[("reason", "journal_unavailable")]);
                warn!(
                    event.name = "temporal.journal_unavailable",
                    component = COMPONENT,
                    reason = %error,
                    "an occurrence could not be made durable: failing closed"
                );

                ApiError::new(
                    ErrorClass::Unavailable,
                    "journal_unavailable",
                    format!(
                        "this occurrence could not be made durable, so it was not decided: {error}"
                    ),
                )
            }
            Failed::Digest(error) => ApiError::new(
                ErrorClass::Internal,
                "record_not_canonical",
                format!("the event record could not be canonicalized: {error}"),
            ),
        }
    }

    /// Publishes where this ledger's journal stands, after each append.
    fn publish_watermarks(&self, zone: &str, ledger: &str) {
        let Ok(state) = self.streams.state(zone, ledger) else {
            return;
        };
        for (name, value) in [
            ("durable", state.durable_through),
            ("signed", state.signed_through),
            ("acknowledged", state.acked_through),
            ("oldest_retained", state.oldest_retained),
        ] {
            self.metrics.set(
                &measure::WATERMARK,
                &[("zone", zone), ("ledger", ledger), ("watermark", name)],
                value as f64,
            );
        }
        if let Ok(bytes) = self.streams.bytes(zone, ledger) {
            self.metrics.set(
                &measure::JOURNAL_BYTES,
                &[("zone", zone), ("ledger", ledger)],
                bytes as f64,
            );
        }
    }
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
            "history_key_not_canonical",
            format!("the history key could not be canonicalized: {error}"),
        )
    })
}

/// The two audiences of one temporal decision's reason.
fn reason_of(outcome: &permguard_languages::evaluate::Outcome) -> temporal::Reason {
    if !outcome.errors.is_empty() {
        return temporal::Reason {
            code: "partition_failed".to_owned(),
            message: outcome.errors.join("; "),
        };
    }
    if outcome.permitted {
        return temporal::Reason {
            code: "permitted".to_owned(),
            message: "a policy permitted it against this partition's history".to_owned(),
        };
    }
    if outcome.denials.is_empty() {
        return temporal::Reason {
            code: "not_permitted".to_owned(),
            message: "no policy permitted it against this partition's history".to_owned(),
        };
    }

    temporal::Reason {
        code: "denied".to_owned(),
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
            "ledger_not_served",
            format!("this plane does not serve `{zone}/{ledger}`"),
        )
    })
}
