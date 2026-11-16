// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One Dogwood partition, compiled: the artifacts of a ledger commit, lowered once.
//!
//! # What "once" means, and why it is load and not request
//!
//! Parsing an event schema, lowering a policy set to Cedar and validating it are the expensive
//! things Dogwood does, and they answer the same question every time for a given commit. They
//! happen here, when a commit is loaded, and never again — a decision path that re-lowered a
//! policy set would spend most of a request doing work whose answer had not changed since the last
//! one.
//!
//! # Why the temporal half is not the evaluating half
//!
//! A Cedar partition answers a stateless question and can answer several at once. A Dogwood
//! partition has a past: `is_authorized` observes the event into the history *and* decides against
//! it, so two occurrences of one partition have an order, and the order is what the answer depends
//! on. That is why application is serialised here rather than left to whoever calls, and why a
//! Dogwood partition refuses the stateless PDP query outright instead of answering it with the
//! history left out.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use cedar_policy::{Entities, EntityUid, Schema};
use dogwood_language::Authorizer;
use permguard_language_core::value::Value;

use permguard_evaluator::evaluate::{Evaluating, Evaluator};
use permguard_evaluator::temporal::{Applied, Checked, Refused};
use permguard_language_core::artifact::Artifacts;
use permguard_language_core::evaluate::{Query, StoredPolicy, Verdict};
use permguard_language_core::temporal::{Contract, Pin, PinSource, Signature};

use super::analysis::*;
use super::occurrence::Occurrence;
use super::value;

impl Evaluating for super::Dogwood {
    fn compile(
        &self,
        policies: &[StoredPolicy],
        artifacts: &Artifacts,
    ) -> Result<Box<dyn Evaluator>, String> {
        let Analyzed {
            inputs,
            cedar_schema,
            contract,
            owners,
            identities,
            footprint,
            context,
            projections,
        } = analyze(policies, artifacts)?;

        Ok(Box::new(CompiledDogwood {
            histories: Arc::new(Shelf::default()),
            inputs,
            cedar_schema,
            contract,
            owners,
            identities,
            footprint,
            warm: std::sync::OnceLock::new(),
            context,
            projections,
        }))
    }
}

/// One history partition's engine, and what it has been told.
struct Held {
    /// Serialised on purpose. `is_authorized` both observes the event into the history and decides
    /// against it, so two occurrences of one history have an order — and a history that let two
    /// through at once would be deciding one against a history that did not yet include the other,
    /// with which one that was depending on the scheduler.
    ///
    /// Per history rather than per partition, so two callers' events do not queue behind each
    /// other: they are independent histories, and serialising them together would make one busy
    /// caller everybody else's latency.
    authorizer: Mutex<Authorizer>,
    /// How many occurrences this engine has been given since it was built or last rebuilt.
    ///
    /// The plane's cue that a history is cold and has to be replayed into this engine before it
    /// answers. Counted here rather than outside, because what a rebuild replaces is the engine,
    /// and a count kept beside it would survive the thing it described.
    observed: std::sync::atomic::AtomicU64,
    /// What the warm budget is charged for this engine: its lowered set and the events it observed.
    bytes: std::sync::atomic::AtomicU64,
}

/// What one observed event is charged, beyond its own spelled bytes (DOGWOOD-08).
///
/// Measured by `tests/warm_footprint.rs`: upstream's history keeps about 3.7 KiB per small event
/// plus about two bytes per byte it spells; the charge is held above that by the same test.
const EVENT_BASE_BYTES: u64 = 4096;

/// The factor on an event's spelled bytes, measured with [`EVENT_BASE_BYTES`].
const EVENT_BYTE_FACTOR: u64 = 4;

/// The factor on the compiled set's footprint that a warm engine is charged before any event: a
/// fresh authorizer keeps its own lowered set and Cedar state, measured at about 1.6 times the
/// footprint of the example partition.
const ENGINE_FOOTPRINT_FACTOR: u64 = 2;

/// What a warm engine is charged for one observed occurrence.
fn event_bytes(occurrence: &Occurrence) -> u64 {
    EVENT_BASE_BYTES.saturating_add((occurrence.weight() as u64).saturating_mul(EVENT_BYTE_FACTOR))
}

/// The history partitions this compiled partition currently holds engines for.
///
/// # Why the bound is bytes, and why eviction is safe
///
/// A schema that pins the caller has one history per caller, and each engine holds a lowered
/// policy set and the events it observed: memory grows with the tenant's callers and with what
/// they record — a caller-controlled allocation. The bound is therefore bytes, charged to a
/// [`permguard_evaluator::warm::Budget`] per partition, per zone and per Host (DOGWOOD-02), never a count.
///
/// Evicting one costs a rebuild and changes no answer: the durable journal is the authority, and a
/// history that is asked for again is replayed from it before it decides.
#[derive(Default)]
struct Histories {
    held: std::collections::HashMap<String, Arc<Held>>,
}

/// The warm histories behind their lock: what the budget evicts through.
#[derive(Default)]
struct Shelf(Mutex<Histories>);

impl Shelf {
    fn lock(&self) -> std::sync::LockResult<std::sync::MutexGuard<'_, Histories>> {
        self.0.lock()
    }
}

/// The budget evicts through this: it drops the engine, and any caller still holding the `Arc`
/// finishes with it.
impl permguard_evaluator::warm::Evict for Shelf {
    fn evict(&self, history: &str) {
        if let Ok(mut histories) = self.lock() {
            histories.held.remove(history);
        }
    }
}

/// Where this partition's warm histories are charged.
struct Warm {
    budget: Arc<permguard_evaluator::warm::Budget>,
    zone: String,
    owner: u64,
}

/// A Dogwood partition, compiled and ready.
struct CompiledDogwood {
    /// One engine per history partition, bounded by the warm budget.
    histories: Arc<Shelf>,
    /// The budget it charges, bound by the plane or, unbound, one of its own.
    warm: std::sync::OnceLock<Warm>,
    /// What it takes to build a fresh authorizer, for a cold history or a rebuild.
    inputs: Inputs,
    /// The lowered Cedar schema, for the checks that happen before a decision.
    cedar_schema: Schema,
    contract: Contract,
    /// The Permguard policy identity owning each rule of the joined set, by rule index.
    owners: Vec<String>,
    identities: Vec<String>,
    footprint: usize,
    /// The leaves of each action's context, by qualified action: one side of a version 2
    /// occurrence's projection.
    context: BTreeMap<String, super::projection::Side>,
    /// The one-sided fields `projections.json` declares, when the partition carries it.
    projections: Option<super::projection::Projections>,
}

/// The refusal of a history whose lock an earlier evaluation left poisoned: a panic's aftermath.
const POISONED: &str = permguard_core::codes::pdp_temporal::PARTITION_POISONED;

/// The `E` of a history this partition could not hold.
///
/// A map an earlier evaluation left poisoned is a panic's aftermath, and says so; any other
/// refusal is the engine failing to stand the history up.
fn unheld(refused: Refused) -> Verdict {
    if refused.code == POISONED {
        Verdict::panicked(refused.message)
    } else {
        Verdict::engine_failed(refused.message)
    }
}

impl CompiledDogwood {
    /// The engine for one history, building an empty one if this partition holds none.
    ///
    /// An engine built here has observed nothing, which is exactly what the plane reads to know it
    /// must replay before deciding. Cold and *empty* are the same state on purpose: a history this
    /// process has never held and one it evicted are indistinguishable, and both are answered from
    /// the durable record rather than from what happened to still be in memory.
    fn engine(&self, history: &str) -> Result<Arc<Held>, Refused> {
        {
            let histories = self.histories.lock().map_err(|_| {
                Refused::new(
                    POISONED,
                    "this partition's history is not in a state it can decide against, because an \
                     earlier evaluation of it panicked",
                )
            })?;
            if let Some(found) = histories.held.get(history) {
                return Ok(Arc::clone(found));
            }
        }

        // Built outside the map's lock: lowering a policy set is expensive, and holding the lock
        // across it would make one cold history block every other history's decisions.
        let fresh = Arc::new(Held {
            authorizer: Mutex::new(self.inputs.rebuild().map_err(|detail| {
                Refused::new(
                    permguard_core::codes::pdp_temporal::PARTITION_NOT_REBUILDABLE,
                    detail,
                )
            })?),
            observed: std::sync::atomic::AtomicU64::new(0),
            bytes: std::sync::atomic::AtomicU64::new(self.engine_bytes()),
        });

        let mut histories = self.histories.lock().map_err(|_| {
            Refused::new(
                POISONED,
                "this partition's history is not in a state it can decide against, because an \
                 earlier evaluation of it panicked",
            )
        })?;
        // Another caller may have built one meanwhile. Theirs wins: two engines for one history
        // would each hold half of it.
        if let Some(found) = histories.held.get(history) {
            return Ok(Arc::clone(found));
        }
        histories
            .held
            .insert(history.to_owned(), Arc::clone(&fresh));
        drop(histories);
        self.charge(history, &fresh);

        Ok(fresh)
    }

    /// The occurrence as this partition decides it: a version 2 occurrence's fields projected into
    /// its two bags by the schemas (TL-5c); a version 1 occurrence as it came.
    ///
    /// Replay projects every version 2 record by the schemas now loaded, whatever input the
    /// partition declares: a ledger moved back to version 1 reads its version 2 records as the
    /// schemas place them, one-sided fields being admitted under version 1 anyway. A record that no
    /// longer projects — a field the schemas dropped — makes its history unreplayable, exactly as a
    /// version 1 record that no longer checks does: it stays evidence and is never replayed
    /// silently.
    fn projected<'a>(
        &self,
        occurrence: &'a Occurrence,
    ) -> Result<std::borrow::Cow<'a, Occurrence>, Refused> {
        let Some(fields) = &occurrence.fields else {
            return Ok(std::borrow::Cow::Borrowed(occurrence));
        };
        let Some(signature) = self
            .contract
            .signature(&occurrence.action, &occurrence.kind)
        else {
            return Err(unknown_event(&self.contract, occurrence));
        };
        let empty = super::projection::Side::default();
        let (logged, request_context) = super::projection::project(
            fields,
            &super::projection::Side::of_event(super::projection::event_leaves(signature)),
            self.context.get(&occurrence.action).unwrap_or(&empty),
        )
        .map_err(|why| {
            Refused::new(
                permguard_core::codes::pdp_temporal::EVENT_FIELD_UNDECLARED,
                why,
            )
        })?;
        let mut projected = occurrence.clone();
        projected.logged = logged;
        projected.request_context = request_context;
        projected.fields = None;

        Ok(std::borrow::Cow::Owned(projected))
    }

    /// What a warm engine is charged before it observes anything.
    fn engine_bytes(&self) -> u64 {
        (self.footprint as u64).saturating_mul(ENGINE_FOOTPRINT_FACTOR)
    }

    /// The budget this partition charges: the plane's once bound, its own until then.
    fn warm(&self) -> &Warm {
        self.warm.get_or_init(|| {
            self.bound(
                permguard_evaluator::warm::Budget::new(permguard_evaluator::warm::Limits::default()),
                "",
            )
        })
    }

    fn bound(&self, budget: Arc<permguard_evaluator::warm::Budget>, zone: &str) -> Warm {
        let evictor: std::sync::Weak<dyn permguard_evaluator::warm::Evict> =
            Arc::downgrade(&self.histories)
                as std::sync::Weak<dyn permguard_evaluator::warm::Evict>;
        let owner = budget.register(evictor);

        Warm {
            budget,
            zone: zone.to_owned(),
            owner,
        }
    }

    /// Charges one engine's bytes as its history's most recent use, and evicts what that pushes
    /// out. Called with no lock held: the victims' owners take their own.
    ///
    /// An engine the budget already evicted is not charged again: it is held only by whoever is
    /// finishing with it. (An eviction landing between that check and the charge leaves one entry
    /// counted for the history until it is next charged or the partition is dropped — an
    /// overcount, never an undercount.)
    fn charge(&self, history: &str, engine: &Arc<Held>) {
        let current = self.histories.lock().is_ok_and(|histories| {
            histories
                .held
                .get(history)
                .is_some_and(|held| Arc::ptr_eq(held, engine))
        });
        if !current {
            return;
        }
        let warm = self.warm();
        let victims = warm.budget.charge(
            warm.owner,
            &warm.zone,
            history,
            engine.bytes.load(std::sync::atomic::Ordering::Relaxed),
        );
        permguard_evaluator::warm::evict_all(victims);
    }
}

impl Drop for CompiledDogwood {
    /// A partition the cache dropped holds nothing any more.
    fn drop(&mut self) {
        if let Some(warm) = self.warm.get() {
            warm.budget.release(warm.owner);
        }
    }
}

impl Evaluator for CompiledDogwood {
    /// Refuses: `E`, which the profile resolves to indeterminate.
    ///
    /// Not an omission: the stateless PDP asks whether a subject may act on a resource *now*, and
    /// a Dogwood policy's answer depends on what has already happened. Answering the stateless
    /// question against an empty history would return a verdict the partition does not hold — and
    /// it would return it as an ordinary permit or deny, indistinguishable from one the policies
    /// meant. The request is one this runtime cannot take on this interface.
    fn evaluate(&self, query: &Query) -> Verdict {
        // The stack an engine needs is its own to guarantee: see permguard_language_core::headroom.
        permguard_language_core::headroom::with(|| {
            let _ = query;

            Verdict::input_rejected(
                "this is a Dogwood partition, and a Dogwood policy decides against history. Submit \
                 the request as an event to the temporal interface \
                 (`permguard.api.pdp.temporal.v1alpha1`); the stateless interface has no history to \
                 decide it against"
                    .to_owned(),
            )
        })
    }

    fn footprint(&self) -> usize {
        self.footprint
    }

    fn policies(&self) -> Vec<String> {
        self.identities.clone()
    }

    fn temporal(&self) -> Option<&dyn permguard_evaluator::temporal::Temporal> {
        Some(self)
    }
}

impl permguard_evaluator::temporal::Temporal for CompiledDogwood {
    fn contract(&self) -> &Contract {
        &self.contract
    }

    fn check(&self, occurrence: &Occurrence) -> Result<Checked, Refused> {
        let occurrence = &*self.projected(occurrence)?;
        let Some(signature) = self
            .contract
            .signature(&occurrence.action, &occurrence.kind)
        else {
            return Err(unknown_event(&self.contract, occurrence));
        };
        self.check_scope(occurrence)?;
        self.check_entities(occurrence)?;

        // The logged bag is the event schema's, whole: a field it does not declare is a field no
        // temporal predicate can correlate on, so sending one is a mistake to hear about rather
        // than a value to store and never read.
        for (group, value) in &occurrence.logged {
            check_leaf(signature, "logged", &mut vec![group.clone()], value, true)?;
            // Declared is not the same as carriable. Upstream's public builder writes a logged
            // field either as one of the two scope aliases or inside a named group, so a bare
            // top-level leaf the schema declares — `requestId`, `sessionId` — has nowhere to go.
            // Accepting one and dropping it would store an event that answers differently from
            // the one that was sent; the pins that would have the same problem are refused a
            // load earlier, where an operator can act on it.
            if !matches!(value, Value::Object(_)) && !injectable(std::slice::from_ref(group)) {
                return Err(Refused::new(
                    permguard_core::codes::pdp_temporal::EVENT_FIELD_NOT_CARRIABLE,
                    format!(
                        "`logged.{group}` is a top-level field, and this build writes a logged \
                         field only as `{}` / `{}` or inside a group. It would be dropped rather \
                         than stored, so it is refused instead",
                        super::occurrence::CALLER_PRINCIPAL,
                        super::occurrence::CALLER_RESOURCE
                    ),
                ));
            }
        }
        // The request context is a different contract, and deliberately a looser one. The event
        // schema splices the action's `input` / `output` groups into the event, so those are
        // checked exactly as the logged bag is — but a group it does not splice (`system`, a
        // deployment's own) is Cedar-only context the event schema does not describe, and Dogwood's
        // value model cannot carry every type Cedar declares there anyway (it has no `datetime`).
        // Checking it against the event's fields would refuse context the action schema declares;
        // checking it against Cedar's own would refuse the very requests upstream accepts.
        for (group, value) in &occurrence.request_context {
            check_leaf(
                signature,
                "request_context",
                &mut vec![group.clone()],
                value,
                false,
            )?;
        }

        let mut pins = Vec::with_capacity(signature.pins.len());
        let mut injected = BTreeMap::new();
        for pin in &signature.pins {
            let value = pin_value(occurrence, pin)?;
            // If the caller also sent the pinned field, it must be the value its source says. One
            // of two different values is a lie about the request, and choosing either would decide
            // which — silently, and in the direction that happens to be cheaper to implement.
            if let Some(sent) = read_path(&occurrence.logged, &pin.field)
                && !sent.dom_eq(&value)
            {
                return Err(Refused::new(
                    permguard_core::codes::pdp_temporal::EVENT_PIN_CONTRADICTED,
                    format!(
                        "`logged.{}` was sent as {} and this partition's schema pins it to {}, \
                         which is {}. A pin decides which history the event belongs to, so it is \
                         derived from the request's authoritative roots and never taken from the \
                         caller",
                        pin.field.join("."),
                        value::render(sent),
                        pin.source.describe(),
                        value::render(&value)
                    ),
                ));
            }
            let rendered = value::canonical(&value);
            injected.insert(pin.field.clone(), rendered.clone());
            pins.push((pin.field.clone(), rendered));
        }

        Ok(Checked {
            decides: signature.decision,
            pins,
            injected,
        })
    }

    fn rebuild(
        &self,
        history: &str,
        occurrences: &[Occurrence],
        deadline: Option<std::time::Instant>,
    ) -> Result<(), Refused> {
        // Built before any lock is taken, so a rebuild that fails leaves this history deciding
        // against what it already had rather than against nothing.
        let mut fresh = self.inputs.rebuild().map_err(|detail| {
            Refused::new(
                permguard_core::codes::pdp_temporal::PARTITION_NOT_REBUILDABLE,
                detail,
            )
        })?;
        let mut bytes = self.engine_bytes();
        for (at, occurrence) in occurrences.iter().enumerate() {
            // Checked between events: the replay belongs to a decision whose budget is spent, and
            // abandoning it leaves the history as it was (DOGWOOD-03).
            if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Err(Refused::new(
                    permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED,
                    format!(
                        "the replay of this history did not finish within its budget: {at} of {} \
                         occurrences observed",
                        occurrences.len()
                    ),
                ));
            }
            bytes = bytes.saturating_add(event_bytes(occurrence));
            let occurrence = &*self.projected(occurrence).map_err(|refused| {
                Refused::new(
                    permguard_core::codes::pdp_temporal::HISTORY_NOT_REPLAYABLE,
                    format!(
                        "the occurrence `{}` is in this partition's history and does not project \
                         by its schemas: {}",
                        occurrence.event_id, refused.message
                    ),
                )
            })?;
            let event = crate::event::to_event(occurrence).map_err(|malformed| {
                Refused::new(
                    permguard_core::codes::pdp_temporal::HISTORY_NOT_REPLAYABLE,
                    format!(
                        "the occurrence `{}` is in this partition's history and cannot be replayed \
                         into it: {malformed}",
                        occurrence.event_id
                    ),
                )
            })?;
            // The verdicts of a replay are discarded: what is being rebuilt is the *history*, and
            // a decision made now against a partial replay would be a decision nobody asked for.
            // Entered with room to recurse in, like every other call into an engine — see
            // `permguard_language_core::headroom`; a replay that declined for want of stack would rebuild a history
            // missing the very events it is replaying.
            let _ = permguard_language_core::headroom::with(|| fresh.is_authorized(&event));
        }

        let engine = self.engine(history)?;
        let mut held = engine.authorizer.lock().map_err(|_| {
            Refused::new(
                POISONED,
                "this partition's history is not in a state it can be rebuilt from, because an \
                 earlier evaluation of it panicked",
            )
        })?;
        *held = fresh;
        // The count belongs to the authorizer that was just installed, not to the one it replaced.
        // Set under the same lock, so nobody can see a fresh authorizer with the old count or the
        // other way round.
        engine.observed.store(
            occurrences.len() as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        engine
            .bytes
            .store(bytes, std::sync::atomic::Ordering::Relaxed);
        drop(held);
        self.charge(history, &engine);

        Ok(())
    }

    fn apply_replayed(&self, history: &str, occurrence: &Occurrence, checked: &Checked) -> Applied {
        // Taken under the map's lock and held: an eviction landing after this takes the engine out
        // of the map, never out of this call, which decides against the whole history it holds.
        let held = self
            .histories
            .lock()
            .ok()
            .and_then(|histories| histories.held.get(history).map(Arc::clone));
        let Some(engine) = held else {
            return Applied::Decided(Verdict::engine_failed(
                "this history was evicted from the warm budget between its replay and this \
                 occurrence; it is replayed before the next one"
                    .to_owned(),
            ));
        };

        self.decide(history, &engine, occurrence, checked)
    }

    fn check_input(&self, input: Option<&str>) -> Result<(), String> {
        check_input(
            &self.contract,
            &self.context,
            self.projections.as_ref(),
            input,
        )
    }

    fn bind_warm(&self, budget: &Arc<permguard_evaluator::warm::Budget>, zone: &str) {
        // The first binding wins: the plane binds a partition before it hands it any work, and
        // one used unbound keeps the budget of its own it started with. A compiled partition
        // belongs to one ledger and so to one zone: a later call naming another zone is a no-op
        // too.
        if self
            .warm
            .get()
            .is_some_and(|warm| Arc::ptr_eq(&warm.budget, budget))
        {
            return;
        }
        let bound = self.bound(Arc::clone(budget), zone);
        if let Err(bound) = self.warm.set(bound) {
            budget.release(bound.owner);
        }
    }

    fn observed(&self, history: &str) -> u64 {
        // Absent is zero, and deliberately: a history this process never held and one it evicted
        // are the same state to a caller, and both must be replayed before they decide.
        let Ok(histories) = self.histories.lock() else {
            return 0;
        };

        histories
            .held
            .get(history)
            .map(|engine| engine.observed.load(std::sync::atomic::Ordering::Relaxed))
            .unwrap_or(0)
    }

    fn apply(&self, history: &str, occurrence: &Occurrence, checked: &Checked) -> Applied {
        // The history this occurrence belongs to, and no other. A schema that pins the caller has
        // one history per caller, and Alice's `Login` is invisible to Bob's `Read` because the two
        // are not in the same one — not because a policy checks.
        let engine = match self.engine(history) {
            Ok(engine) => engine,
            Err(refused) => return Applied::Decided(unheld(refused)),
        };

        self.decide(history, &engine, occurrence, checked)
    }
}

impl CompiledDogwood {
    /// Observes one durable occurrence into `engine` and decides it when its kind decides.
    fn decide(
        &self,
        history: &str,
        engine: &Arc<Held>,
        occurrence: &Occurrence,
        checked: &Checked,
    ) -> Applied {
        // Charged as it came, so a replayed history and a live one are charged alike.
        let charged = event_bytes(occurrence);
        let occurrence = match self.projected(occurrence) {
            Ok(projected) => projected,
            Err(refused) => return Applied::Decided(Verdict::engine_failed(refused.message)),
        };
        let event = match crate::event::to_event(&occurrence) {
            Ok(event) => event,
            // Checked before it was journalled, so this is not a caller's mistake reaching here
            // late — it is this build disagreeing with itself: the engine failing, `E`, and never
            // a deny, which would depend on which of the two was right.
            Err(malformed) => {
                return Applied::Decided(Verdict::engine_failed(malformed.to_string()));
            }
        };

        // The lock is held across the whole call because that is what makes this history ordered:
        // the event is observed and decided as one step.
        let response = match engine.authorizer.lock() {
            Ok(mut authorizer) => {
                // Counted before the call rather than after it, and under the lock: whatever
                // `is_authorized` answers, the event is in this authorizer's history once it
                // returns, and an engine that had observed something must never read as fresh.
                engine
                    .observed
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                engine
                    .bytes
                    .fetch_add(charged, std::sync::atomic::Ordering::Relaxed);

                // Entered with room to recurse in: this is where a Dogwood partition
                // actually decides, and a thread whose stack the platform under-reports would
                // have every policy here answer "recursion limit reached". See
                // `permguard_language_core::headroom`.
                permguard_language_core::headroom::with(|| authorizer.is_authorized(&event))
            }
            // A history whose lock a panicking thread left poisoned is one nobody can vouch for.
            // Fail closed rather than reach past the poison for the state.
            Err(_) => {
                return Applied::Decided(Verdict::panicked(
                    "this Dogwood partition's history is not in a state it can decide against, \
                     because an earlier evaluation of it panicked",
                ));
            }
        };
        // Charged once the engine's lock is released: an eviction this causes takes locks of its
        // own.
        self.charge(history, engine);

        let Some(response) = response else {
            // Upstream returns `None` for a history-only kind, and that is the whole answer: the
            // event is in the history and there is no verdict to invent.
            return Applied::Observed;
        };
        if !checked.decides {
            // The contract said this kind does not decide and the runtime decided it. Two answers
            // about what an event *is* is not a thing to reconcile at request time.
            return Applied::Decided(Verdict::engine_failed(format!(
                "the kind `{}` is not a decision kind in this partition's schema, and the runtime \
                 returned a verdict for it",
                occurrence.kind
            )));
        }

        let rules: Vec<usize> = response
            .diagnostics()
            .reason()
            .map(|rule| rule.rule_index)
            .collect();
        let determining: Vec<String> = rules
            .iter()
            .filter_map(|&index| self.owners.get(index).cloned())
            .collect();
        // Every determining rule has an owner, or the decision cannot say who decided it: an
        // attribution lost is not one to guess at, and a permit nobody can be cited for is not
        // released.
        if determining.len() != rules.len() {
            return Applied::Decided(Verdict::engine_failed(format!(
                "the runtime cited rules {rules:?} and this partition owns only {} of them",
                determining.len()
            )));
        }
        let errors: Vec<&str> = response.diagnostics().errors().collect();
        if !errors.is_empty() {
            // Upstream degrades rather than aborting: a provider that could not run or an
            // unresolvable attribute is reported beside a fail-closed deny with no determining
            // rule. Permguard reports that as what it is — `E`, a partition that could not
            // evaluate — so it is never mistaken for a deny a policy expressed. A forbid rule that
            // did determine the deny stands beside the failure: `D`, the failure kept. A permit
            // beside a failure is `E`.
            let message = errors.join("; ");
            return Applied::Decided(if response.allowed() {
                Verdict::engine_failed(message)
            } else {
                Verdict::deny_despite_failure(determining, message)
            });
        }

        Applied::Decided(if response.allowed() {
            Verdict::permit(determining)
        } else {
            Verdict::deny(determining)
        })
    }
}

impl CompiledDogwood {
    /// Checks the action, the principal and the resource against the action schema.
    ///
    /// Upstream's reference authorizer builds its Cedar request with no schema at all, so an
    /// action nothing declares and a principal of a type the action does not admit both reach the
    /// policies and are answered with an implicit deny — indistinguishable from a policy deciding
    /// so. Neither is a decision anyone made, and both are mistakes worth hearing about.
    fn check_scope(&self, occurrence: &Occurrence) -> Result<(), Refused> {
        let action = EntityUid::from_str(&action_uid(&occurrence.action)).map_err(|error| {
            Refused::new(
                permguard_core::codes::pdp_temporal::EVENT_ACTION_MALFORMED,
                format!(
                    "`{}` is not an action reference: {error}",
                    occurrence.action
                ),
            )
        })?;
        let Some(principals) = self.cedar_schema.principals_for_action(&action) else {
            return Err(Refused::new(
                permguard_core::codes::pdp_temporal::EVENT_ACTION_UNDECLARED,
                format!(
                    "this partition's action schema declares no action `{}`",
                    occurrence.action
                ),
            ));
        };
        let admitted: Vec<String> = principals.map(ToString::to_string).collect();
        if !admitted.contains(&occurrence.principal.kind) {
            return Err(Refused::new(
                permguard_core::codes::pdp_temporal::EVENT_PRINCIPAL_NOT_ADMITTED,
                format!(
                    "`{}` does not act on `{}` in this partition's action schema; it admits {}",
                    occurrence.principal.kind,
                    occurrence.action,
                    admitted.join(", ")
                ),
            ));
        }
        let admitted: Vec<String> = self
            .cedar_schema
            .resources_for_action(&action)
            .map(|held| held.map(ToString::to_string).collect())
            .unwrap_or_default();
        if !admitted.contains(&occurrence.resource.kind) {
            return Err(Refused::new(
                permguard_core::codes::pdp_temporal::EVENT_RESOURCE_NOT_ADMITTED,
                format!(
                    "`{}` is not a resource of `{}` in this partition's action schema; it admits \
                     {}",
                    occurrence.resource.kind,
                    occurrence.action,
                    admitted.join(", ")
                ),
            ));
        }

        Ok(())
    }

    /// Checks the attributed entity store against the augmented action schema.
    ///
    /// Before authorization, because afterwards there is nothing to see: Cedar reads an entity it
    /// was not given as one with no attributes, so a store whose types are wrong does not fail a
    /// policy — it makes `principal.role == "admin"` quietly unresolvable, and a rule meant to
    /// restrict stops restricting.
    fn check_entities(&self, occurrence: &Occurrence) -> Result<(), Refused> {
        if occurrence.entities.is_empty() {
            return Ok(());
        }
        let store: Vec<serde_json::Value> = occurrence
            .entities
            .iter()
            .map(|entity| {
                serde_json::json!({
                    "uid": {"type": entity.uid.kind, "id": entity.uid.id},
                    "attrs": entity
                        .attrs
                        .iter()
                        .map(|(name, held)| (name.clone(), value::to_json(held)))
                        .collect::<serde_json::Map<String, serde_json::Value>>(),
                    "parents": entity
                        .parents
                        .iter()
                        .map(|parent| serde_json::json!({"type": parent.kind, "id": parent.id}))
                        .collect::<Vec<serde_json::Value>>(),
                })
            })
            .collect();

        // The refusal is built inside, not outside: upstream's entity error is a large value, and
        // a closure that returned it would carry it out through every frame this grows.
        permguard_language_core::headroom::with(|| {
            Entities::from_json_value(serde_json::Value::Array(store), Some(&self.cedar_schema))
                .map(|_| ())
                .map_err(|error| {
                    Refused::new(
                        permguard_core::codes::pdp_temporal::EVENT_ENTITIES_REJECTED,
                        format!(
                            "the attributed entity store does not conform to this partition's \
                             action schema: {error}"
                        ),
                    )
                })
        })
    }
}

/// The refusal for an `(action, kind)` the schema does not derive.
fn unknown_event(contract: &Contract, occurrence: &Occurrence) -> Refused {
    let kinds_for_action: Vec<&str> = contract
        .signatures
        .iter()
        .filter(|held| held.action == occurrence.action)
        .map(|held| held.kind.as_str())
        .collect();

    if kinds_for_action.is_empty() {
        return Refused::new(
            permguard_core::codes::pdp_temporal::EVENT_ACTION_UNDECLARED,
            format!(
                "this partition's schema declares no action `{}`",
                occurrence.action
            ),
        );
    }

    Refused::new(
        permguard_core::codes::pdp_temporal::EVENT_KIND_UNDECLARED,
        format!(
            "this partition's schema declares no `{}` event of `{}`; it declares {}",
            occurrence.kind,
            occurrence.action,
            kinds_for_action.join(", ")
        ),
    )
}

/// Checks one leaf against the signature: that it is declared, and that its type matches.
///
/// `required` says what an undeclared path means. In the logged bag it is a refusal; in the
/// request context it is a Cedar-only field the event schema does not describe, which is passed
/// through — see the two call sites, which is where that difference is explained.
fn check_leaf(
    signature: &Signature,
    bag: &str,
    path: &mut Vec<String>,
    value: &Value,
    required: bool,
) -> Result<(), Refused> {
    let declared = signature.fields.iter().find(|field| field.path == *path);
    if let Some(field) = declared {
        return match compatible(&field.declared, value) {
            true => Ok(()),
            // A leaf whose type the renderer does not spell in a form this can read is not
            // reported as wrong — `compatible` answers `true` for those. What reaches here is a
            // leaf whose declared type is one of the shapes it does read, carrying something else.
            false => Err(Refused::new(
                permguard_core::codes::pdp_temporal::EVENT_FIELD_MISTYPED,
                format!(
                    "`{bag}.{}` is declared `{}` on a `{}` event of `{}`, and carries {}",
                    path.join("."),
                    field.declared,
                    signature.kind,
                    signature.action,
                    value::render(value)
                ),
            )),
        };
    }
    if let Value::Object(fields) = value {
        // Not a declared leaf, and a record: a group, so descend. A record that *is* a declared
        // leaf was answered above — upstream's matching reads both a whole record and its members,
        // and it is the declaration that says which this is.
        for (name, held) in fields {
            path.push(name.clone());
            let checked = check_leaf(signature, bag, path, held, required);
            path.pop();
            checked?;
        }

        return Ok(());
    }
    if !required {
        return Ok(());
    }

    Err(Refused::new(
        permguard_core::codes::pdp_temporal::EVENT_FIELD_UNDECLARED,
        format!(
            "`{bag}.{}` is not a field this partition's schema declares on a `{}` event of `{}`",
            path.join("."),
            signature.kind,
            signature.action
        ),
    ))
}

/// Whether a value can be what the schema declared, as far as the declaration can be read.
///
/// Upstream renders a field's type with Cedar's own printer and says so explicitly: the spelling
/// is for display and coarse classification, not a stable machine format, and a consumer wanting a
/// firm contract should match the leading token. So this matches the leading token, and answers
/// `true` for anything it does not recognise — a record type by name, an extension type — rather
/// than refusing a value because this build could not read the word for its type. Refusing on
/// unfamiliarity would turn a Cedar upgrade into an outage.
fn compatible(declared: &str, value: &Value) -> bool {
    // The `EntityTypes` rendering: a `principalType(A)` field, kept as its full declared set.
    if declared.contains(" | ") || declared.contains("::") {
        return match value {
            Value::Entity { ty, .. } => declared
                .split(" | ")
                .any(|held| entity_type_matches(held.trim(), ty)),
            _ => false,
        };
    }
    let token = declared
        .split(|character: char| character.is_whitespace() || character == '<')
        .find(|part| !part.is_empty())
        .unwrap_or(declared);

    match token {
        "String" => matches!(value, Value::String(_)),
        "Long" => matches!(value, Value::Int(_)),
        "Bool" | "Boolean" => matches!(value, Value::Bool(_)),
        "decimal" | "Decimal" => matches!(value, Value::Decimal(_)),
        "Set" => matches!(value, Value::Array(_)),
        _ => true,
    }
}

/// Whether a declared entity-type name names the type an entity reference carries.
///
/// The declared set comes from the action schema **as written**: upstream renders it from Cedar's
/// raw names, so an entity declared inside `namespace Drupe` appears as `OAuthUser`, while the
/// reference on the wire is the resolved `Drupe::OAuthUser`. Matching only on equality would
/// reject every namespaced schema; matching only on the last segment would let `Other::OAuthUser`
/// pass for `Drupe::OAuthUser`. So a qualified declaration is compared whole, and an unqualified
/// one against the reference's own last segment — which is what an unqualified name means.
fn entity_type_matches(declared: &str, ty: &str) -> bool {
    if declared.contains("::") {
        return declared == ty;
    }

    ty.rsplit("::").next() == Some(declared)
}

/// A qualified action, as a Cedar entity reference.
///
/// `Acme::Action::Transfer` names the action entity `Acme::Action::"Transfer"`, which is the form
/// a schema lookup takes. The last segment is the id and everything before it is the type.
fn action_uid(action: &str) -> String {
    match action.rsplit_once("::") {
        Some((namespace, id)) => format!("{namespace}::\"{id}\""),
        None => format!("\"{action}\""),
    }
}

/// The value a pin takes, read from the request root its schema names.
fn pin_value(occurrence: &Occurrence, pin: &Pin) -> Result<Value, Refused> {
    match &pin.source {
        PinSource::Principal => Ok(Value::Entity {
            ty: occurrence.principal.kind.clone(),
            id: occurrence.principal.id.clone(),
        }),
        PinSource::Resource => Ok(Value::Entity {
            ty: occurrence.resource.kind.clone(),
            id: occurrence.resource.id.clone(),
        }),
        PinSource::Context(path) => read_path(&occurrence.request_context, path)
            .cloned()
            .ok_or_else(|| {
                Refused::new(
                    permguard_core::codes::pdp_temporal::EVENT_PIN_SOURCE_ABSENT,
                    format!(
                        "this partition's schema pins `{}` to `{}`, and the request carries no \
                         such value. A pin decides which history the event belongs to, so it is \
                         not something to leave unset",
                        pin.field.join("."),
                        pin.source.describe()
                    ),
                )
            }),
    }
}

/// One value of a bag, by dotted path.
fn read_path<'a>(bag: &'a BTreeMap<String, Value>, path: &[String]) -> Option<&'a Value> {
    let (head, rest) = path.split_first()?;
    let mut held = bag.get(head)?;
    for segment in rest {
        let Value::Object(fields) = held else {
            return None;
        };
        held = fields.get(segment)?;
    }

    Some(held)
}

#[cfg(test)]
mod tests {

    #![allow(clippy::expect_used)]

    use super::super::artifacts as registry;
    use super::*;

    /// The history an occurrence belongs to, as a test spells it.
    ///
    /// The plane hashes the pin names and values into the digest the record carries; a test needs
    /// only *a* string that is the same for the same key and different for a different one, and
    /// joining the canonical values is that. What matters here is that two principals are two
    /// histories, which is the property these tests are about.
    fn history(checked: &Checked) -> String {
        checked.pin_values().join("\u{1f}")
    }

    use permguard_language_core::artifact::{ArtifactBlob, ArtifactType};
    use serde_json::{Value as Json, json};

    /// Upstream's own example: policy, action schema, and the event schema that is its default.
    const POLICY: &str =
        include_str!("../../permguard-languages/tests/fixtures/dogwood/read-login-not-logout.dw");
    const ACTION_SCHEMA: &str = include_str!(
        "../../permguard-languages/tests/fixtures/dogwood/read-login-not-logout.cedarschema"
    );
    const EVENT_SCHEMA: &str =
        include_str!("../../permguard-languages/tests/fixtures/dogwood/pinned.dwschema");
    /// Upstream's session-pinned alternative, whose pin is a bare top-level logged field.
    const SESSION_PINNED: &str =
        include_str!("../../permguard-languages/tests/fixtures/dogwood/session-pinned.dwschema");

    fn artifact(type_name: &str, data: &str) -> (&'static dyn ArtifactType, ArtifactBlob) {
        let held = crate::artifact_type(type_name).expect("a registered artifact");

        (
            held,
            ArtifactBlob {
                name: held.canonical_filename().unwrap_or("program").to_owned(),
                media_type: held.media_type().to_owned(),
                data: data.as_bytes().to_vec(),
            },
        )
    }

    fn bundle(parts: Vec<(&str, &str)>) -> Artifacts {
        let mut artifacts = Artifacts::default();
        for (type_name, data) in parts {
            let (held, blob) = artifact(type_name, data);
            artifacts.insert(held, blob);
        }

        artifacts
    }

    fn example() -> Box<dyn Evaluator> {
        compile_with(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::EVENT_SCHEMA, EVENT_SCHEMA),
        ])
        .expect("upstream's own example compiles")
    }

    fn compile_with(parts: Vec<(&str, &str)>) -> Result<Box<dyn Evaluator>, String> {
        compile_policy_with(POLICY, parts)
    }

    fn compile_policy_with(
        policy: &str,
        parts: Vec<(&str, &str)>,
    ) -> Result<Box<dyn Evaluator>, String> {
        super::super::Dogwood.compile(
            &[StoredPolicy {
                id: "01a0-read-login-not-logout".to_owned(),
                alias: Some("read_login_not_logout".to_owned()),
                source: policy.as_bytes().to_vec(),
            }],
            &bundle(parts),
        )
    }

    /// One occurrence of upstream's trace, in Permguard's own event contract.
    fn occurrence(at: i64, action: &str, kind: &str, user: &str, fields: Json) -> Occurrence {
        let instant = permguard_canonical::time::render_epoch_seconds(at)
            .expect("the trace's timepoints are instants");
        let body: super::super::occurrence::OccurrenceBody = serde_json::from_value(json!({
            "event_id": format!("{action}-{kind}-{at}"),
            "kind": kind,
            "action": action,
            "principal": format!("Drupe::OAuthUser::\"{user}\""),
            "resource": "Drupe::Gateway::\"gw1\"",
            "logged": fields,
            "request_context": {"input": fields["input"]},
            "occurred_at": instant,
        }))
        .expect("the body parses");

        body.read().expect("the occurrence is well formed")
    }

    /// One occurrence of upstream's trace as version 2: one canonical field map (TL-5c).
    fn occurrence_v2(at: i64, action: &str, kind: &str, user: &str, fields: Json) -> Occurrence {
        let instant = permguard_canonical::time::render_epoch_seconds(at)
            .expect("the trace's timepoints are instants");
        let body: super::super::occurrence::OccurrenceBodyV2 = serde_json::from_value(json!({
            "event_id": format!("{action}-{kind}-{at}"),
            "kind": kind,
            "action": action,
            "principal": format!("Drupe::OAuthUser::\"{user}\""),
            "resource": "Drupe::Gateway::\"gw1\"",
            "fields": fields,
            "occurred_at": instant,
        }))
        .expect("the body parses");

        body.read().expect("the occurrence is well formed")
    }

    /// The one-sided fields of upstream's pinned schema against its action schema.
    const PROJECTIONS: &str =
        r#"{"history_only": ["requestId", "sessionId"], "request_only": ["system"]}"#;

    /// TL-5c: a version 2 partition declares every one-sided field, per action and kind; the
    /// declarations belong to version 2; a declaration naming a field no side has is refused.
    #[test]
    fn a_version_2_partition_declares_every_one_sided_field() {
        let v2 = Some(super::super::occurrence::EVENT_TYPE_V2);
        let v1 = Some(super::super::occurrence::EVENT_TYPE);

        let bare = example();
        let temporal = bare.temporal().expect("it remembers");
        let why = temporal
            .check_input(v2)
            .expect_err("one-sided and undeclared");
        assert!(
            why.contains("history_only") || why.contains("request_only"),
            "{why}"
        );
        temporal
            .check_input(v1)
            .expect("version 1 needs no declaration");
        temporal
            .check_input(None)
            .expect("nor does an undeclared input");

        let declared = compile_with(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::EVENT_SCHEMA, EVENT_SCHEMA),
            (registry::PROJECTIONS, PROJECTIONS),
        ])
        .expect("it compiles");
        let temporal = declared.temporal().expect("it remembers");
        temporal
            .check_input(v2)
            .expect("every one-sided field is declared");
        for input in [v1, None] {
            let why = temporal
                .check_input(input)
                .expect_err("declarations nothing reads");
            assert!(why.contains("projections.json"), "{input:?}: {why}");
        }

        for (stray, needle) in [
            (
                r#"{"history_only": ["requestId", "sessionId", "nowhere"], "request_only": ["system"]}"#,
                "no event logs it",
            ),
            (
                r#"{"history_only": ["requestId", "sessionId"], "request_only": ["system", "elsewhere"]}"#,
                "no action's context",
            ),
            (
                r#"{"history_only": ["requestId"], "request_only": ["system"]}"#,
                "sessionId",
            ),
        ] {
            let compiled = compile_with(vec![
                (registry::ACTION_SCHEMA, ACTION_SCHEMA),
                (registry::EVENT_SCHEMA, EVENT_SCHEMA),
                (registry::PROJECTIONS, stray),
            ])
            .expect("it compiles");
            let why = compiled
                .temporal()
                .expect("it remembers")
                .check_input(v2)
                .expect_err("refused");
            assert!(why.contains(needle), "{stray}: {why}");
        }
    }

    /// TL-5c: version 2 decides as version 1 does, the shared fields reaching both the history and
    /// the request from one map; a field neither side declares is refused.
    #[test]
    fn a_version_2_occurrence_projects_and_decides_as_version_1_does() {
        let compiled = compile_with(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::EVENT_SCHEMA, EVENT_SCHEMA),
            (registry::PROJECTIONS, PROJECTIONS),
        ])
        .expect("it compiles");
        let temporal = compiled.temporal().expect("it remembers");

        let login = occurrence_v2(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        let checked = temporal.check(&login).expect("well formed");
        let key = history(&checked);
        assert!(matches!(
            temporal.apply(&key, &login, &checked),
            Applied::Observed
        ));
        // The read correlates the logged login's `input.user` with the request's
        // `context.input.user`: a permit says the one field reached both sides.
        let read = occurrence_v2(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        match temporal.apply(&key, &read, &checked) {
            Applied::Decided(verdict) => assert!(verdict.permitted(), "{verdict:?}"),
            other => panic!("{other:?}"),
        }

        let stray = occurrence_v2(
            101,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}, "bogus": 1}),
        );
        let refused = temporal
            .check(&stray)
            .expect_err("neither side declares it");
        assert_eq!(
            refused.code,
            permguard_core::codes::pdp_temporal::EVENT_FIELD_UNDECLARED
        );
    }

    /// TL-5c, the migration fixture: a version 1 history replayed by a version 2 partition decides
    /// the next version 2 occurrence as it would after the same events sent as version 2.
    #[test]
    fn a_version_1_history_replays_into_a_version_2_partition() {
        let compiled = compile_with(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::EVENT_SCHEMA, EVENT_SCHEMA),
            (registry::PROJECTIONS, PROJECTIONS),
        ])
        .expect("it compiles");
        let temporal = compiled.temporal().expect("it remembers");
        let read = occurrence_v2(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        let key = history(&checked);

        let mut verdicts = Vec::new();
        for login in [
            occurrence(
                5,
                "Drupe::Action::Login",
                "response",
                "alice",
                json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
            ),
            occurrence_v2(
                5,
                "Drupe::Action::Login",
                "response",
                "alice",
                json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
            ),
        ] {
            temporal
                .rebuild(&key, &[login], None)
                .expect("the history replays");
            match temporal.apply(&key, &read, &checked) {
                Applied::Decided(verdict) => verdicts.push(verdict.permitted()),
                other => panic!("{other:?}"),
            }
        }
        assert_eq!(
            verdicts,
            [true, true],
            "version 1 history and version 2 agree"
        );
    }

    /// The required conformance case "provider infinite loop, deep recursion, large collection":
    /// each is contained by upstream's sandbox and answers `E`, never a permit and never a hang.
    #[test]
    fn a_runaway_provider_is_contained_and_answers_e() {
        let policy = r#"@id("runaway")
permit (
    principal,
    action == Drupe::Action::"Read",
    resource
)
when { Run::Away(context.input.document).ok == true };
"#;
        for (case, script) in [
            ("an infinite loop", "fn evaluate(text) { loop { } }"),
            (
                "deep recursion",
                "fn down(n) { down(n + 1) } fn evaluate(text) { down(0) }",
            ),
            (
                "a large collection",
                "fn evaluate(text) { let a = []; loop { a.push(text); } }",
            ),
        ] {
            let providers = serde_json::json!({
                "availableProviders": {
                    "Run::Away": {
                        "argumentTypes": [{"paramType": "string"}],
                        "outputType": {
                            "paramType": "record",
                            "fields": {"ok": {"paramType": "bool"}},
                            "required": ["ok"]
                        },
                        "implementation": {"kind": "rhai", "script": script}
                    }
                }
            })
            .to_string();
            let compiled = compile_policy_with(
                policy,
                vec![
                    (registry::ACTION_SCHEMA, ACTION_SCHEMA),
                    (registry::EVENT_SCHEMA, EVENT_SCHEMA),
                    (registry::PROVIDERS, &providers),
                ],
            )
            .expect("it compiles");
            let temporal = compiled.temporal().expect("it remembers");
            let read = occurrence(
                100,
                "Drupe::Action::Read",
                "request",
                "alice",
                json!({"input": {"user": "alice", "document": "doc1"}}),
            );
            let checked = temporal.check(&read).expect("well formed");
            match temporal.apply(&history(&checked), &read, &checked) {
                Applied::Decided(verdict) => assert!(
                    verdict.error().is_some() && !verdict.permitted(),
                    "{case}: {verdict:?}"
                ),
                other => panic!("{case}: {other:?}"),
            }
        }
    }

    /// The whole point: upstream's policy, upstream's schema, upstream's trace, upstream's answers.
    #[test]
    fn the_upstream_example_reproduces_the_verdicts_upstream_records() {
        let compiled = example();
        let temporal = compiled.temporal().expect("a Dogwood partition remembers");

        // `expected.out` records four verdicts; the `Login::response` between them is history-only
        // and produces none, which is why it is not in that list.
        let trace: Vec<(i64, &str, &str, &str, Json)> = vec![
            (
                0,
                "Drupe::Action::Login",
                "request",
                "alice",
                json!({"input": {"user": "alice", "server": "s1"}}),
            ),
            (
                5,
                "Drupe::Action::Login",
                "response",
                "alice",
                json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
            ),
            (
                100,
                "Drupe::Action::Read",
                "request",
                "alice",
                json!({"input": {"user": "alice", "document": "doc1"}}),
            ),
            (
                4000,
                "Drupe::Action::Read",
                "request",
                "alice",
                json!({"input": {"user": "alice", "document": "doc4"}}),
            ),
            (
                4100,
                "Drupe::Action::Read",
                "request",
                "bob",
                json!({"input": {"user": "bob", "document": "doc2"}}),
            ),
        ];

        let mut verdicts = Vec::new();
        for (at, action, kind, user, fields) in trace {
            let event = occurrence(at, action, kind, user, fields);
            let checked = temporal
                .check(&event)
                .unwrap_or_else(|refused| panic!("@{at} {action}::{kind}: {refused}"));
            match temporal.apply(&history(&checked), &event, &checked) {
                Applied::Observed => assert!(!checked.decides, "@{at} decided nothing"),
                Applied::Decided(verdict) => {
                    assert!(verdict.error().is_none(), "@{at}: {verdict:?}");
                    verdicts.push((at, verdict.permitted()));
                }
            }
        }

        assert_eq!(
            verdicts,
            vec![(0, false), (100, true), (4000, false), (4100, false)],
            "upstream records DENY, ALLOW, DENY, DENY for this trace"
        );
    }

    /// The permit cites the Permguard identity of the policy, not an index into a joined string.
    #[test]
    fn a_verdict_cites_the_permguard_policy_that_decided_it() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        for (at, action, kind, fields) in [
            (
                0,
                "Drupe::Action::Login",
                "response",
                json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
            ),
            (
                100,
                "Drupe::Action::Read",
                "request",
                json!({"input": {"user": "alice", "document": "doc1"}}),
            ),
        ] {
            let event = occurrence(at, action, kind, "alice", fields);
            let checked = temporal.check(&event).expect("well formed");
            if let Applied::Decided(verdict) = temporal.apply(&history(&checked), &event, &checked)
            {
                assert!(verdict.permitted(), "the login is inside the window");
                assert_eq!(verdict.determining(), ["01a0-read-login-not-logout"]);
            }
        }
    }

    #[test]
    fn the_contract_is_read_from_the_loaded_schemas() {
        let compiled = example();
        let contract = compiled
            .temporal()
            .expect("it remembers")
            .contract()
            .clone();

        assert_eq!(contract.max_window_seconds, DEFAULT_MAX_WINDOW_SECONDS);
        assert_eq!(contract.kinds, ["error", "request", "response"]);
        assert_eq!(contract.decision_kinds, ["request"]);
        // The pinned schema's universal symmetric pin: one history per principal.
        assert_eq!(contract.history_pins, [vec!["callerPrincipal".to_owned()]]);
        assert!(contract.is_partitioned());
        assert!(contract.decides("request"));
        assert!(!contract.decides("response"));

        let read = contract
            .signature("Drupe::Action::Read", "request")
            .expect("the schema derives it");
        assert!(read.decision);
        assert!(
            read.fields
                .iter()
                .any(|field| field.path == ["input", "user"]),
            "the action schema's `ReadInput` is spliced into the event"
        );
        assert_eq!(read.pins.len(), 1);
        assert_eq!(read.pins[0].field, ["callerPrincipal"]);
        assert_eq!(read.pins[0].source, PinSource::Principal);
    }

    /// The pin is derived, and its value is the one a history key is built from.
    #[test]
    fn the_history_key_is_derived_from_the_request_and_not_from_the_caller() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&event).expect("well formed");

        assert_eq!(checked.pin_names(), ["callerPrincipal"]);
        assert_eq!(
            checked.pin_values(),
            [value::canonical(&Value::Entity {
                ty: "Drupe::OAuthUser".to_owned(),
                id: "alice".to_owned(),
            })]
        );
        // Two principals are two histories, so their keys differ.
        let other = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "bob",
            json!({"input": {"user": "bob", "document": "doc1"}}),
        );
        assert_ne!(
            checked.pin_values(),
            temporal.check(&other).expect("well formed").pin_values()
        );
    }

    /// A caller that sends the pinned field with another value is choosing its own history.
    #[test]
    fn a_pin_the_caller_contradicts_is_refused_rather_than_resolved() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let mut event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        event.logged.insert(
            "callerPrincipal".to_owned(),
            Value::Entity {
                ty: "Drupe::OAuthUser".to_owned(),
                id: "mallory".to_owned(),
            },
        );

        let refused = temporal
            .check(&event)
            .expect_err("a pin is not the caller's to set");
        assert_eq!(refused.code, "event_pin_contradicted");

        // The same value the schema derives is not a contradiction: a caller may state it.
        event.logged.insert(
            "callerPrincipal".to_owned(),
            Value::Entity {
                ty: "Drupe::OAuthUser".to_owned(),
                id: "alice".to_owned(),
            },
        );
        assert!(temporal.check(&event).is_ok());
    }

    #[test]
    fn an_undeclared_logged_field_is_refused_and_named() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1", "smuggled": "x"}}),
        );

        let refused = temporal
            .check(&event)
            .expect_err("the schema declares no such field");
        assert_eq!(refused.code, "event_field_undeclared");
        assert!(
            refused.message.contains("logged.input.smuggled"),
            "{refused}"
        );
    }

    #[test]
    fn a_logged_field_of_the_wrong_type_is_refused() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": 7, "document": "doc1"}}),
        );

        let refused = temporal
            .check(&event)
            .expect_err("`user` is declared `String`");
        assert_eq!(refused.code, "event_field_mistyped");
        assert!(refused.message.contains("logged.input.user"), "{refused}");
    }

    #[test]
    fn an_action_or_kind_the_schema_does_not_derive_is_refused_by_name() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        let unknown_kind = occurrence(
            100,
            "Drupe::Action::Read",
            "invented",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        assert_eq!(
            temporal
                .check(&unknown_kind)
                .expect_err("no such kind")
                .code,
            "event_kind_undeclared"
        );

        let unknown_action = occurrence(
            100,
            "Drupe::Action::Teleport",
            "request",
            "alice",
            json!({"input": {"user": "alice"}}),
        );
        assert_eq!(
            temporal
                .check(&unknown_action)
                .expect_err("no such action")
                .code,
            "event_action_undeclared"
        );
    }

    /// A principal of a type the action does not admit reaches no policy, so nothing decides it.
    #[test]
    fn a_principal_the_action_does_not_admit_is_refused_rather_than_implicitly_denied() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let mut event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        event.principal.kind = "Drupe::Gateway".to_owned();

        let refused = temporal
            .check(&event)
            .expect_err("`Read` admits no Gateway principal");
        assert_eq!(refused.code, "event_principal_not_admitted");
    }

    /// An attributed entity the action schema does not describe is refused before a decision.
    #[test]
    fn an_entity_store_that_does_not_conform_is_refused_before_authorization() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let mut event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        event
            .entities
            .push(super::super::occurrence::AttributedEntity {
                uid: super::super::occurrence::EntityRef {
                    kind: "Drupe::OAuthUser".to_owned(),
                    id: "alice".to_owned(),
                },
                // `OAuthUser` declares `id: String`, and nothing called `rank`.
                attrs: [("rank".to_owned(), Value::Int(1))].into_iter().collect(),
                parents: Vec::new(),
            });

        let refused = temporal
            .check(&event)
            .expect_err("Cedar reads an unrecognised store as an empty one");
        assert_eq!(refused.code, "event_entities_rejected");
    }

    /// A history whose map a panic poisoned is `evaluation_panicked`; one the engine could not
    /// rebuild is `evaluation_failed`.
    #[test]
    fn a_history_that_cannot_be_held_names_its_cause() {
        let poisoned = super::unheld(Refused::new(super::POISONED, "poisoned"));
        assert_eq!(
            poisoned.error().map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_PANICKED)
        );
        let unbuilt = super::unheld(Refused::new("partition_not_rebuildable", "no"));
        assert_eq!(
            unbuilt.error().map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_FAILED)
        );
    }

    /// The stateless PDP has no history to decide a Dogwood policy against, and says so.
    #[test]
    fn the_stateless_interface_refuses_rather_than_deciding_without_the_history() {
        let verdict = example().evaluate(&Query::default());

        assert!(!verdict.permitted());
        let error = verdict.error().expect("a refusal says why");
        assert_eq!(
            error.code,
            permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED,
            "a request this interface cannot take is `E`, not a deny"
        );
        let reason = error.message;
        assert!(
            reason.contains("permguard.api.pdp.temporal.v1alpha1"),
            "{reason}"
        );
    }

    #[test]
    fn a_partition_without_an_action_schema_does_not_compile() {
        let refused = compile_with(vec![(registry::EVENT_SCHEMA, EVENT_SCHEMA)])
            .err()
            .expect("there is nothing to lower against");

        assert!(refused.contains("action schema"), "{refused}");
    }

    #[test]
    fn the_max_window_directive_is_read_from_the_event_schema() {
        assert_eq!(
            max_window_seconds("decision event <A>::request { ...inputs(A) }"),
            Ok(DEFAULT_MAX_WINDOW_SECONDS)
        );
        assert_eq!(max_window_seconds("max_window = 30m\n"), Ok(1800));
        assert_eq!(
            max_window_seconds("// a comment\nmax_window = 7d\n"),
            Ok(604_800)
        );
        assert_eq!(max_window_seconds("max_window = 90s\n"), Ok(90));
        assert!(
            max_window_seconds("max_window = 5w\n").is_err(),
            "`w` is not a unit"
        );
        assert!(max_window_seconds("max_window = h\n").is_err(), "no amount");
        assert!(max_window_seconds("max_window 24h\n").is_err(), "no `=`");
    }

    /// The corpus: what upstream's grammar accepts and refuses, checked against this copy of it.
    ///
    /// This parser mirrors a grammar it cannot import — upstream keeps `event_schema` crate-private
    /// — so the only thing standing between the two is a list of cases. Each one below is read off
    /// `event_schema/grammar.pest` and `event_schema/parse.rs` rather than invented, and each is
    /// one that a line-by-line reading got wrong.
    #[test]
    fn the_parser_matches_the_grammar_it_mirrors() {
        // `WHITESPACE` includes newlines, and neither `max_window_decl` nor `interval` is atomic,
        // so upstream accepts the tokens split across lines and spaced apart.
        for accepted in [
            "max_window = 24h",
            "max_window=24h",
            "max_window   =   24h",
            "max_window\n=\n24h",
            "max_window = 24 h",
            "max_window\t=\t24\th",
            "// leading comment\n// another\nmax_window = 24h",
            "max_window = 24h // trailing",
        ] {
            assert_eq!(
                max_window_seconds(accepted),
                Ok(86_400),
                "upstream accepts `{}`",
                accepted.escape_debug()
            );
        }

        // `kw_max_window` ends where an identifier would continue, so these are not the directive
        // at all — and a schema without one takes the default rather than being refused.
        for defaulted in [
            "",
            "   \n\n  ",
            "// only a comment",
            "decision event <A>::request { ...inputs(A) }",
            "max_windows = 24h",
            "max_window_extra = 24h",
        ] {
            assert_eq!(
                max_window_seconds(defaulted),
                Ok(DEFAULT_MAX_WINDOW_SECONDS),
                "no directive in `{}`",
                defaulted.escape_debug()
            );
        }

        // `build_max_window` refuses a zero interval outright. As a retention floor, accepting it
        // would say every event may be deleted the moment it lands.
        for zero in ["max_window = 0s", "max_window = 0h", "max_window = 000d"] {
            let refused = max_window_seconds(zero).expect_err("upstream refuses a zero window");
            assert!(refused.contains("zero"), "{zero}: {refused}");
        }

        // `time_unit` is exactly `s`, `m`, `h`, `d`; `integer` is exactly `ASCII_DIGIT+`.
        for refused in [
            "max_window = 5w",
            "max_window = 5",
            "max_window = -5m",
            "max_window = +5m",
            "max_window = 5.5h",
            "max_window =",
            "max_window = m",
            "max_window 24h",
        ] {
            assert!(
                max_window_seconds(refused).is_err(),
                "upstream refuses `{}`",
                refused.escape_debug()
            );
        }

        // Every unit, at the boundary where the multiplication is what it says.
        assert_eq!(max_window_seconds("max_window = 1s"), Ok(1));
        assert_eq!(max_window_seconds("max_window = 1m"), Ok(60));
        assert_eq!(max_window_seconds("max_window = 1h"), Ok(3_600));
        assert_eq!(max_window_seconds("max_window = 1d"), Ok(86_400));

        // A number no window could mean overflows rather than wrapping into a small one.
        assert!(
            max_window_seconds("max_window = 99999999999999999999d").is_err(),
            "out of range is refused, not wrapped"
        );
    }

    /// Every window this parser reads is one the retention floor can be computed from.
    ///
    /// The property that matters downstream: a schema either yields a positive number of seconds
    /// or refuses. There is no third answer, and in particular never a zero or negative floor —
    /// which would tell the journal every event is immediately deletable.
    #[test]
    fn a_window_is_positive_or_it_is_a_refusal() {
        for amount in [1u64, 2, 7, 59, 60, 61, 3_599, 3_600, 100_000] {
            for unit in ["s", "m", "h", "d"] {
                let source = format!("max_window = {amount}{unit}");
                let held = max_window_seconds(&source).unwrap_or_else(|error| {
                    panic!("`{source}` should read: {error}");
                });
                assert!(held > 0, "`{source}` read as {held}");
            }
        }
    }

    /// A raised `max_window` is read as raised, and it is the number the store keeps history for.
    #[test]
    fn a_raised_max_window_reaches_the_contract() {
        let raised = format!("max_window = 48h\n{EVENT_SCHEMA}");
        let compiled = compile_with(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::EVENT_SCHEMA, &raised),
        ])
        .expect("it compiles");

        assert_eq!(
            compiled
                .temporal()
                .expect("it remembers")
                .contract()
                .max_window_seconds,
            48 * 3600
        );
    }

    /// Without an event schema the partition gets Dogwood's declared defaults, not no schema.
    #[test]
    fn a_partition_with_no_event_schema_gets_the_runtimes_own_default() {
        let compiled = compile_with(vec![(registry::ACTION_SCHEMA, ACTION_SCHEMA)])
            .expect("the event schema is optional");
        let contract = compiled.temporal().expect("it remembers").contract();

        assert_eq!(contract.decision_kinds, ["request"]);
        assert!(
            contract.is_partitioned(),
            "Dogwood's default pins `callerPrincipal` on every kind"
        );
    }

    /// The limitation upstream's public builder imposes, refused where an operator can see it.
    #[test]
    fn a_pin_this_build_cannot_write_refuses_the_load() {
        // A schema of its own, because upstream's example declares no `context.sessionId` and
        // Dogwood would refuse the pin's *source* before Permguard reached the pin's *target*.
        const WITH_SESSION: &str = r#"namespace Drupe {
  type ReadInput = { document: String, user: String };
  entity Gateway;
  entity OAuthUser = { id: String };
  action "Read" appliesTo {
    principal: [OAuthUser],
    resource: [Gateway],
    context: { input: ReadInput, sessionId: String }
  };
}
"#;
        const PERMIT: &str = "permit (principal, action == Drupe::Action::\"Read\", resource);\n";
        let refused = compile_policy_with(
            PERMIT,
            vec![
                (registry::ACTION_SCHEMA, WITH_SESSION),
                (registry::EVENT_SCHEMA, SESSION_PINNED),
            ],
        )
        .err()
        .expect("a pin nobody can write would put every session in one history");

        assert!(refused.contains("sessionId"), "{refused}");
        assert!(refused.contains("callerPrincipal"), "{refused}");
    }

    /// A field that would be dropped is refused rather than accepted and dropped.
    #[test]
    fn a_top_level_logged_field_is_refused_rather_than_silently_dropped() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let mut event = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        // Declared by the pinned schema, and with nowhere to go through the public builder.
        event
            .logged
            .insert("requestId".to_owned(), Value::String("u2".to_owned()));

        let refused = temporal.check(&event).expect_err("it would be dropped");
        assert_eq!(refused.code, "event_field_not_carriable");
        assert!(refused.message.contains("logged.requestId"), "{refused}");
    }

    const PROVIDERS: &str = r#"{
  "availableProviders": {
    "Strings::Matches": {
      "argumentTypes": [{"paramType": "string"}, {"paramType": "string"}],
      "outputType": {
        "paramType": "record",
        "fields": {"matched": {"paramType": "bool"}},
        "required": ["matched"]
      },
      "implementation": {"kind": "rhai", "scriptFile": "matches.rhai"}
    }
  }
}"#;
    const PROGRAM: &str =
        "fn evaluate(pattern, text) { #{ matched: regex_is_match(pattern, text) } }\n";

    #[test]
    fn a_provider_script_is_resolved_from_the_ledger_and_not_from_the_host() {
        let mut artifacts = bundle(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::PROVIDERS, PROVIDERS),
        ]);
        let (held, mut blob) = artifact(registry::RHAI_PROVIDER, PROGRAM);
        blob.name = "matches.rhai".to_owned();
        artifacts.insert(held, blob);

        let declarations = provider_declarations(PROVIDERS.as_bytes(), &artifacts)
            .expect("the script is carried by the partition");
        let declaration = declarations
            .get("Strings::Matches")
            .expect("it is declared");
        assert!(
            matches!(
                declaration.implementation.as_ref(),
                Some(dogwood_language::Implementation::Rhai { script: Some(held), script_file: None })
                    if held == PROGRAM
            ),
            "the reference is folded into the inline script"
        );
    }

    #[test]
    fn a_provider_script_the_partition_does_not_carry_refuses_the_load() {
        let artifacts = bundle(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::PROVIDERS, PROVIDERS),
        ]);

        let refused = provider_declarations(PROVIDERS.as_bytes(), &artifacts)
            .expect_err("there is no filesystem to fall back to");
        assert!(refused.contains("matches.rhai"), "{refused}");
        assert!(refused.contains("carries none"), "{refused}");
    }

    #[test]
    fn a_provider_script_no_declaration_references_refuses_the_load() {
        let mut artifacts = bundle(vec![
            (registry::ACTION_SCHEMA, ACTION_SCHEMA),
            (registry::PROVIDERS, PROVIDERS),
        ]);
        for name in ["matches.rhai", "orphan.rhai"] {
            let (held, mut blob) = artifact(registry::RHAI_PROVIDER, PROGRAM);
            blob.name = name.to_owned();
            artifacts.insert(held, blob);
        }

        let refused = provider_declarations(PROVIDERS.as_bytes(), &artifacts)
            .expect_err("a program nothing names is unaccounted for");
        assert!(refused.contains("orphan.rhai"), "{refused}");
    }

    #[test]
    fn a_provider_stating_both_a_script_and_a_file_refuses_the_load() {
        let both = PROVIDERS.replace(
            r#""implementation": {"kind": "rhai", "scriptFile": "matches.rhai"}"#,
            r#""implementation": {"kind": "rhai", "script": "fn evaluate(a, b) { #{ matched: true } }", "scriptFile": "matches.rhai"}"#,
        );
        let artifacts = bundle(vec![(registry::ACTION_SCHEMA, ACTION_SCHEMA)]);

        let refused = provider_declarations(both.as_bytes(), &artifacts)
            .expect_err("which of the two runs is not something to guess");
        assert!(refused.contains("scriptFile"), "{refused}");
    }

    /// A late arrival is answered by rebuilding, and the rebuilt history is the whole run.
    #[test]
    fn a_rebuild_replays_the_ordered_history_and_replaces_what_was_there() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        // A read with no login before it is denied.
        let read = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        assert_eq!(
            temporal.apply(&history(&checked), &read, &checked),
            Applied::Decided(Verdict::deny(Vec::new())),
            "nothing has happened yet"
        );

        // The login arrives late — it happened *before* the read this engine has already seen.
        // Inserting it would either corrupt the window or be silently ignored; rebuilding replays
        // the whole ordered run, and the answer changes because the history did.
        let login = occurrence(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        temporal
            .rebuild(&history(&checked), &[login, read.clone()], None)
            .expect("the partition rebuilds");

        let checked = temporal.check(&read).expect("well formed");
        match temporal.apply(&history(&checked), &read, &checked) {
            Applied::Decided(verdict) => assert!(
                verdict.permitted(),
                "the rebuilt history contains the login: {verdict:?}"
            ),
            other => panic!("a decision kind decided nothing: {other:?}"),
        }
    }

    /// Two principals are two histories, and one cannot see the other's events.
    ///
    /// # What this is actually about
    ///
    /// The example's schema pins `callerPrincipal`, and the policy never mentions the principal at
    /// all — the separation is not a condition somebody wrote and could have forgotten, it is a
    /// property of which history the question is asked in. So the test is the negative: alice's
    /// login must not permit bob's read, and the only reason it does not is that they are not in
    /// the same history.
    #[test]
    fn one_principals_login_does_not_permit_anothers_read() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        let login = occurrence(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        let checked = temporal.check(&login).expect("well formed");
        let alice = history(&checked);
        assert_eq!(
            temporal.apply(&alice, &login, &checked),
            Applied::Observed,
            "a history-only kind"
        );

        // Alice reads: permitted, because her login is in her history.
        let read = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        assert_eq!(
            history(&checked),
            alice,
            "the same caller, the same history"
        );
        match temporal.apply(&alice, &read, &checked) {
            Applied::Decided(verdict) => assert!(verdict.permitted(), "{verdict:?}"),
            other => panic!("{other:?}"),
        }

        // Bob reads: denied, and his engine has never been told anything.
        let read = occurrence(
            101,
            "Drupe::Action::Read",
            "request",
            "bob",
            json!({"input": {"user": "bob", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        let bob = history(&checked);
        assert_ne!(bob, alice, "a different caller is a different history");
        assert_eq!(
            temporal.observed(&bob),
            0,
            "and it starts cold, which is what tells a plane to replay before deciding"
        );
        match temporal.apply(&bob, &read, &checked) {
            Applied::Decided(verdict) => assert!(
                !verdict.permitted(),
                "alice's login is not in bob's history: {verdict:?}"
            ),
            other => panic!("{other:?}"),
        }
    }

    /// Holding a bounded number of histories evicts the coldest, and eviction changes no verdict.
    ///
    /// # What this is actually about
    ///
    /// A schema that pins the caller has one history per caller, and a tenant has as many callers
    /// as it has. Keeping an engine for each would make this plane's memory a function of somebody
    /// else's user base — a caller-controlled allocation, which is the thing a multi-tenant plane
    /// must never have.
    ///
    /// So there is a bound, and the safety of the bound is the whole assertion: an evicted history
    /// reads as *cold* rather than as empty-and-answered, which is what makes the plane replay it
    /// from the durable journal before it decides again. The answer after eviction is the answer
    /// before it; only the cost differs.
    #[test]
    fn evicting_a_cold_history_costs_a_replay_and_never_an_answer() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        // A partition bound that holds three engines and not four (DOGWOOD-02).
        let engine = 2 * compiled.footprint() as u64;
        let budget = permguard_evaluator::warm::Budget::new(permguard_evaluator::warm::Limits {
            host: u64::MAX,
            zone: u64::MAX,
            partition: engine * 3 + engine / 2,
        });
        temporal.bind_warm(&budget, "acme");

        let login_of = |user: &str| {
            occurrence(
                5,
                "Drupe::Action::Login",
                "response",
                user,
                json!({"input": {"user": user, "server": "s1"}, "output": {}}),
            )
        };
        let read_of = |user: &str| {
            occurrence(
                100,
                "Drupe::Action::Read",
                "request",
                user,
                json!({"input": {"user": user, "document": "doc1"}}),
            )
        };

        // The first caller logs in and reads: permitted, from a warm history.
        let login = login_of("first");
        let checked = temporal.check(&login).expect("well formed");
        let first = history(&checked);
        temporal.apply(&first, &login, &checked);
        assert!(temporal.observed(&first) > 0, "warm");

        // Then more callers than the bound holds, each touching its own history.
        for at in 0..3 {
            let user = format!("crowd-{at}");
            let held = login_of(&user);
            let checked = temporal.check(&held).expect("well formed");
            temporal.apply(&history(&checked), &held, &checked);
        }

        assert_eq!(
            temporal.observed(&first),
            0,
            "the coldest history was evicted, and reads as cold rather than as empty"
        );

        // Replayed from what the journal holds — which is what the plane does on seeing `0` — the
        // verdict is the one it was before the eviction.
        temporal
            .rebuild(&first, &[login_of("first")], None)
            .expect("an evicted history is rebuilt from the durable record");
        let read = read_of("first");
        let checked = temporal.check(&read).expect("well formed");
        match temporal.apply(&first, &read, &checked) {
            Applied::Decided(verdict) => assert!(
                verdict.permitted(),
                "eviction changed a verdict, which is the one thing it may not do: {verdict:?}"
            ),
            other => panic!("{other:?}"),
        }
    }

    /// DOGWOOD-02, DOGWOOD-08: every warm engine is charged its lowered set and the events it
    /// observed, to the budget the plane bound, under the zone it named; the budget's three bounds
    /// see the same bytes.
    #[test]
    fn a_warm_history_is_charged_its_set_and_its_events_to_the_bound_budget() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let budget =
            permguard_evaluator::warm::Budget::new(permguard_evaluator::warm::Limits::default());
        temporal.bind_warm(&budget, "acme");
        // A second binding is a no-op: the first wins.
        temporal.bind_warm(
            &permguard_evaluator::warm::Budget::new(permguard_evaluator::warm::Limits::default()),
            "other",
        );

        let login = occurrence(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        let checked = temporal.check(&login).expect("well formed");
        let key = history(&checked);
        temporal.apply(&key, &login, &checked);

        let (host, zone, _) = budget.held("acme", 1);
        let expected = 2 * compiled.footprint() as u64 + super::event_bytes(&login);
        assert_eq!(host, expected, "its set and its one event");
        assert_eq!(zone, expected, "charged under the zone the plane named");

        // A rebuild charges what it replayed, replacing what was there.
        temporal
            .rebuild(&key, &[login.clone(), login.clone()], None)
            .expect("it rebuilds");
        assert_eq!(
            budget.held("acme", 1).0,
            2 * compiled.footprint() as u64 + 2 * super::event_bytes(&login)
        );

        // Dropped by the cache, the partition holds nothing.
        drop(compiled);
        assert_eq!(budget.held("acme", 1), (0, 0, 0));
    }

    /// After the review: a history evicted between its replay and the occurrence answers `E`
    /// rather than being rebuilt empty and decided against one record; a held one decides.
    #[test]
    fn an_occurrence_after_a_replay_needs_the_history_still_held() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let login = occurrence(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        let read = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        let key = history(&checked);

        match temporal.apply_replayed(&key, &read, &checked) {
            Applied::Decided(verdict) => assert_eq!(
                verdict.error().map(|failure| failure.code),
                Some(permguard_core::codes::pdp_native::EVALUATION_FAILED),
                "{verdict:?}"
            ),
            other => panic!("{other:?}"),
        }
        assert_eq!(temporal.observed(&key), 0, "nothing was built empty");

        temporal
            .rebuild(&key, &[login], None)
            .expect("the history is replayed");
        match temporal.apply_replayed(&key, &read, &checked) {
            Applied::Decided(verdict) => assert!(verdict.permitted(), "{verdict:?}"),
            other => panic!("{other:?}"),
        }
    }

    /// DOGWOOD-03: a replay past its deadline is abandoned between two events, refused
    /// `evaluation_deadline_exceeded`, and the history keeps what it had.
    #[test]
    fn a_replay_past_its_deadline_stops_and_keeps_the_history() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");
        let login = occurrence(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        let checked = temporal.check(&login).expect("well formed");
        let key = history(&checked);
        temporal.apply(&key, &login, &checked);

        let refused = temporal
            .rebuild(
                &key,
                &[login.clone(), login.clone()],
                Some(std::time::Instant::now()),
            )
            .expect_err("no time is left");
        assert_eq!(
            refused.code,
            permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED
        );
        assert!(refused.message.contains("0 of 2"), "{}", refused.message);
        assert_eq!(temporal.observed(&key), 1, "the history kept what it had");

        temporal
            .rebuild(
                &key,
                &[login.clone(), login],
                Some(std::time::Instant::now() + std::time::Duration::from_secs(60)),
            )
            .expect("a replay with time left finishes");
        assert_eq!(temporal.observed(&key), 2);
    }

    /// A rebuild that cannot be built leaves the partition deciding against what it had.
    #[test]
    fn a_rebuild_that_fails_does_not_empty_the_history() {
        let compiled = example();
        let temporal = compiled.temporal().expect("it remembers");

        let login = occurrence(
            5,
            "Drupe::Action::Login",
            "response",
            "alice",
            json!({"input": {"user": "alice", "server": "s1"}, "output": {}}),
        );
        let checked = temporal.check(&login).expect("well formed");
        assert_eq!(
            temporal.apply(&history(&checked), &login, &checked),
            Applied::Observed
        );

        // A logged bag whose group is a bare value rather than a record of fields cannot become an
        // event, so the replay fails where it is attempted.
        let mut broken = login.clone();
        broken.logged.insert("input".to_owned(), Value::Int(7));
        let refused = temporal
            .rebuild(&history(&checked), &[broken], None)
            .expect_err("an unreplayable history is not a history");
        assert_eq!(refused.code, "history_not_replayable");

        // And the login is still there: the read that depends on it is still permitted.
        let read = occurrence(
            100,
            "Drupe::Action::Read",
            "request",
            "alice",
            json!({"input": {"user": "alice", "document": "doc1"}}),
        );
        let checked = temporal.check(&read).expect("well formed");
        match temporal.apply(&history(&checked), &read, &checked) {
            Applied::Decided(verdict) => assert!(verdict.permitted(), "{verdict:?}"),
            other => panic!("{other:?}"),
        }
    }
}
