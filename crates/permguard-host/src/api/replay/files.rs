// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The replay window and the plans on the file backend: `host/state/replay/` on the volume
//! (owner decision, 2026-10-06).
//!
//! ```text
//! host/state/
//! ├── replay/           the journal: results, plans and consumed plans, segmented
//! └── replay.new/       a compaction in progress; swept at open
//! ```
//!
//! The journal is read whole when it is opened and what it holds is kept in memory. What is past
//! the window is dropped from memory as it is met and from the disk when the journal is opened
//! again, by rewriting the live entries into a fresh journal and swapping the directories.
//!
//! A change holds the journal from the read that decides it to the frame that records it, so a
//! check and the write it guards are one step for every other change (`1-architecture/8` Store
//! contracts, whole rule); a read takes what is in memory and waits for no write.
//!
//! The payloads are JSON: the stored result is the answer the transports render, and nothing
//! outside this process ever reads these frames. The journal frames themselves are the storage
//! library's format, claim generation included.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Mutex, MutexGuard};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use super::{
    Decide, PER_PRINCIPAL, Plan, PlanApproval, ReplayError, ReplayStore, Stored, WINDOW, kept,
};
use crate::api::Refusal;
use crate::operations::journal::OperationId;
use crate::operations::mutation::{Applying, Observed};
use crate::storage::StorageError;
use crate::storage::dir::Dir;
use crate::storage::journal::{Journal, Options, Recovery};
use crate::storage::volume::Volume;

impl From<StorageError> for ReplayError {
    fn from(error: StorageError) -> Self {
        Self::Unavailable(Box::new(error))
    }
}

/// The directory below `host/`.
pub const DIRECTORY: &str = "state";
/// The journal directory below [`DIRECTORY`].
pub const JOURNAL: &str = "replay";
/// Where a compaction writes before it swaps.
pub(super) const COMPACTING: &str = "replay.new";
/// Where the superseded journal waits to be removed.
pub(super) const SUPERSEDED: &str = "replay.old";
/// Where a journal handle lives for the instant of a swap, so the lock never holds a handle
/// into a directory that is being renamed.
const PLACEHOLDER: &str = "replay.swap";

/// A stored result.
const FRAME_RESULT: u16 = 1;
/// A plan made.
const FRAME_PLAN: u16 = 2;
/// A plan consumed by its run step.
const FRAME_PLAN_CONSUMED: u16 = 3;
/// An approval of a plan (WP-3.9).
const FRAME_PLAN_APPROVED: u16 = 4;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct StoredResult {
    pub(super) principal: String,
    pub(super) request_id: String,
    pub(super) operation: String,
    pub(super) digest: String,
    pub(super) result: serde_json::Value,
    pub(super) recorded_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Approved {
    plan_id: String,
    /// The planner, whose plan it is.
    principal: String,
    approval: PlanApproval,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Consumed {
    plan_id: String,
    principal: String,
    /// When the consumed plan would have expired: the marker is kept exactly as long as the
    /// plan would have been, so a second run inside that time is `plan_expired`, not unknown.
    expires: u64,
}

#[derive(Default)]
pub(super) struct State {
    pub(super) results: BTreeMap<(String, String), StoredResult>,
    /// Request ids per principal, oldest first, so the cap drops the oldest.
    held: BTreeMap<String, VecDeque<String>>,
    plans: BTreeMap<(String, String), Plan>,
    consumed: BTreeMap<(String, String), u64>,
}

/// The replay journal of one volume.
pub struct FileReplay {
    /// Held by a change from the read that decides it to the frame that records it, and taken
    /// before `state`.
    journal: Mutex<Journal>,
    state: Mutex<State>,
}

impl std::fmt::Debug for FileReplay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileReplay").finish_non_exhaustive()
    }
}

impl FileReplay {
    /// Opens the journal of `volume`, replays it, drops what is past the window at `now` and,
    /// when anything was dropped, rewrites the live entries into a fresh journal.
    pub fn open(volume: &Volume, now: u64) -> Result<(Self, Recovery), ReplayError> {
        let state_dir = volume.host().subdir(DIRECTORY, true)?;
        sweep(&state_dir)?;
        let options = volume.journal_options(Options::default());
        let (journal, recovery) = Journal::open(state_dir.subdir(JOURNAL, true)?, options)?;
        let mut state = State::default();
        let mut dead = 0usize;
        for frame in journal.frames()? {
            if !apply(&mut state, frame.kind, &frame.payload, now)? {
                dead += 1;
            }
        }
        let replay = Self {
            journal: Mutex::new(journal),
            state: Mutex::new(state),
        };
        if dead > 0 {
            replay.compact(&state_dir, options, now)?;
            tracing::info!(
                event.name = "host.replay.compacted",
                component = crate::api::COMPONENT,
                dropped = dead,
                "the replay journal was rewritten without its expired entries"
            );
        }
        Ok((replay, recovery))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Rewrites the live entries into [`COMPACTING`], then swaps it in: the superseded journal is
    /// renamed aside, the fresh one renamed into place, and the superseded one removed. A crash
    /// between the renames leaves [`SUPERSEDED`] beside a missing [`JOURNAL`], which [`sweep`]
    /// puts back; a crash before them leaves [`COMPACTING`], which it removes.
    fn compact(&self, state_dir: &Dir, options: Options, now: u64) -> Result<(), ReplayError> {
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let state = self.state();
        remove_tree(state_dir, COMPACTING)?;
        let (mut fresh, _) = Journal::open(state_dir.subdir(COMPACTING, true)?, options)?;
        for result in state.results.values() {
            fresh.append(FRAME_RESULT, &encode(result)?)?;
        }
        for plan in state.plans.values() {
            if kept(plan.expires, now) {
                fresh.append(FRAME_PLAN, &encode(plan)?)?;
            }
        }
        for ((principal, plan_id), expires) in &state.consumed {
            if kept(*expires, now) {
                fresh.append(
                    FRAME_PLAN_CONSUMED,
                    &encode(&Consumed {
                        plan_id: plan_id.clone(),
                        principal: principal.clone(),
                        expires: *expires,
                    })?,
                )?;
            }
        }
        // Both handles are released before the directories move: a journal keeps its current
        // segment open and names its directory by path on the platforms without directory
        // handles, so the fresh journal is opened again where it now lives.
        drop(fresh);
        let superseded = std::mem::replace(&mut *journal, placeholder(state_dir, options)?);
        drop(superseded);
        state_dir.rename(JOURNAL, SUPERSEDED)?;
        state_dir.rename(COMPACTING, JOURNAL)?;
        state_dir.sync()?;
        remove_tree(state_dir, SUPERSEDED)?;
        let (reopened, _) = Journal::open(state_dir.subdir(JOURNAL, false)?, options)?;
        let placeholder = std::mem::replace(&mut *journal, reopened);
        drop(placeholder);
        remove_tree(state_dir, PLACEHOLDER)?;
        Ok(())
    }

    /// Records the `result` of `(principal, request_id)`, durably: what the Host API did before
    /// WP-3.6, whose answers now live in the mutation journal's commits. Kept for the tests of
    /// the results such a journal still holds, which answer until their window ends.
    #[cfg(test)]
    pub(crate) fn record<T: Serialize>(
        &self,
        principal: &permguard_core::authz::Principal,
        request_id: &str,
        operation: &str,
        digest: &str,
        result: &T,
    ) -> Result<(), ReplayError> {
        let now = permguard_core::time::unix_now();
        let stored = StoredResult {
            principal: principal.as_str().to_owned(),
            request_id: request_id.to_owned(),
            operation: operation.to_owned(),
            digest: digest.to_owned(),
            result: serde_json::to_value(result).map_err(|error| {
                ReplayError::Malformed(format!(
                    "a result of `{operation}` does not serialize: {error}"
                ))
            })?,
            recorded_at: now,
        };
        let bytes = encode(&stored)?;
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        journal.append(FRAME_RESULT, &bytes)?;
        let mut state = self.state();
        prune(&mut state, now);
        remember(&mut state, stored);
        Ok(())
    }
}

impl ReplayStore for FileReplay {
    fn result(
        &self,
        principal: &str,
        request_id: &str,
        now: u64,
    ) -> Result<Option<Stored>, ReplayError> {
        let mut state = self.state();
        prune(&mut state, now);
        Ok(state
            .results
            .get(&(principal.to_owned(), request_id.to_owned()))
            .map(|stored| Stored {
                operation: stored.operation.clone(),
                digest: stored.digest.clone(),
                result: stored.result.clone(),
            }))
    }

    fn held(&self) -> Result<usize, ReplayError> {
        Ok(self.state().results.len())
    }

    fn write_plan(&self, _applying: &Applying<'_>, plan: &Plan) -> Result<(), ReplayError> {
        let bytes = encode(plan)?;
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        journal.append(FRAME_PLAN, &bytes)?;
        self.state()
            .plans
            .insert((plan.principal.clone(), plan.plan_id.clone()), plan.clone());
        Ok(())
    }

    fn plan(&self, principal: &str, plan_id: &str) -> Result<Option<(Plan, bool)>, ReplayError> {
        let state = self.state();
        let key = (principal.to_owned(), plan_id.to_owned());
        Ok(state
            .plans
            .get(&key)
            .map(|plan| (plan.clone(), state.consumed.contains_key(&key))))
    }

    fn find(&self, plan_id: &str) -> Result<Option<(Plan, bool)>, ReplayError> {
        Ok(found(&self.state(), plan_id))
    }

    fn plans(&self) -> Result<Vec<(Plan, bool)>, ReplayError> {
        let state = self.state();
        Ok(state
            .plans
            .iter()
            .map(|(key, plan)| (plan.clone(), state.consumed.contains_key(key)))
            .collect())
    }

    fn approve(
        &self,
        _applying: &Applying<'_>,
        plan_id: &str,
        decide: Decide<'_>,
    ) -> Result<Option<Plan>, Refusal> {
        // Held from the read of the plan to the frame of its approval: the plan `decide` judged
        // is the plan the approval joins.
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some((plan, consumed)) = found(&self.state(), plan_id) else {
            return Ok(None);
        };
        let approval = decide(&plan, consumed)?;
        let bytes = encode(&Approved {
            plan_id: plan.plan_id.clone(),
            principal: plan.principal.clone(),
            approval: approval.clone(),
        })?;
        journal
            .append(FRAME_PLAN_APPROVED, &bytes)
            .map_err(ReplayError::from)?;
        let mut state = self.state();
        let held = state
            .plans
            .get_mut(&(plan.principal.clone(), plan.plan_id.clone()));
        Ok(held.map(|held| {
            held.approvals.push(approval);
            held.clone()
        }))
    }

    fn consume(
        &self,
        _applying: &Applying<'_>,
        principal: &str,
        plan_id: &str,
    ) -> Result<(), ReplayError> {
        let key = (principal.to_owned(), plan_id.to_owned());
        // Held from the read that finds the plan unconsumed to the frame that consumes it.
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let expires = {
            let state = self.state();
            if state.consumed.contains_key(&key) {
                return Err(ReplayError::PlanConsumed);
            }
            state
                .plans
                .get(&key)
                .ok_or(ReplayError::PlanUnknown)?
                .expires
        };
        let bytes = encode(&Consumed {
            plan_id: plan_id.to_owned(),
            principal: principal.to_owned(),
            expires,
        })?;
        journal.append(FRAME_PLAN_CONSUMED, &bytes)?;
        self.state().consumed.insert(key, expires);
        Ok(())
    }

    /// An approval shows as the plan `target` holding one recorded by `operation_id`; a plan
    /// consumed ahead of its change, `consume:<plan_id>`, as that plan consumed.
    fn operation(
        &self,
        operation_id: &OperationId,
        target: Option<&str>,
    ) -> Result<Option<Observed>, ReplayError> {
        // The window is held in memory, read whole when it was opened: it always answers.
        Ok(self.shown(operation_id, target))
    }
}

/// The plan `plan_id`, whoever made it, and whether it was run.
fn found(state: &State, plan_id: &str) -> Option<(Plan, bool)> {
    state
        .plans
        .iter()
        .find(|((_, held), _)| held == plan_id)
        .map(|(key, plan)| (plan.clone(), state.consumed.contains_key(key)))
}

impl FileReplay {
    fn shown(&self, operation_id: &OperationId, target: Option<&str>) -> Option<Observed> {
        let target = target?;
        let state = self.state();
        if let Some(plan_id) = target.strip_prefix("consume:") {
            let (key, _) = state
                .consumed
                .iter()
                .find(|((_, held), _)| held == plan_id)?;
            let revision = state.plans.get(key).map_or(0, |plan| plan.revision);
            return Some(Observed {
                revision,
                target: Some(target.to_owned()),
            });
        }
        let recorded = operation_id.to_string();
        state
            .plans
            .iter()
            .find(|((_, held), plan)| {
                held == target
                    && plan
                        .approvals
                        .iter()
                        .any(|approval| approval.operation_id == recorded)
            })
            .map(|(_, plan)| Observed {
                revision: plan.revision,
                target: Some(target.to_owned()),
            })
    }
}

/// Applies one frame to `state`; `false` when the frame is past its window at `now` and was
/// dropped rather than applied.
fn apply(state: &mut State, kind: u16, payload: &[u8], now: u64) -> Result<bool, ReplayError> {
    match kind {
        FRAME_RESULT => {
            let stored: StoredResult = decode(payload)?;
            if stored.recorded_at.saturating_add(WINDOW.as_secs()) <= now {
                return Ok(false);
            }
            remember(state, stored);
            Ok(true)
        }
        FRAME_PLAN => {
            let plan: Plan = decode(payload)?;
            if !kept(plan.expires, now) {
                return Ok(false);
            }
            state
                .plans
                .insert((plan.principal.clone(), plan.plan_id.clone()), plan);
            Ok(true)
        }
        FRAME_PLAN_CONSUMED => {
            let consumed: Consumed = decode(payload)?;
            let key = (consumed.principal, consumed.plan_id);
            if !kept(consumed.expires, now) {
                state.plans.remove(&key);
                return Ok(false);
            }
            state.consumed.insert(key, consumed.expires);
            Ok(true)
        }
        FRAME_PLAN_APPROVED => {
            let approved: Approved = decode(payload)?;
            let key = (approved.principal, approved.plan_id);
            match state.plans.get_mut(&key) {
                Some(plan) => {
                    plan.approvals.push(approved.approval);
                    Ok(true)
                }
                // The plan went with its window: the approval goes too.
                None => Ok(false),
            }
        }
        other => Err(ReplayError::Malformed(format!(
            "the replay journal holds a frame of unknown kind {other}"
        ))),
    }
}

/// Holds `stored`, dropping the principal's oldest result past [`PER_PRINCIPAL`].
pub(super) fn remember(state: &mut State, stored: StoredResult) {
    let held = state.held.entry(stored.principal.clone()).or_default();
    if !state
        .results
        .contains_key(&(stored.principal.clone(), stored.request_id.clone()))
    {
        held.push_back(stored.request_id.clone());
    }
    while held.len() > PER_PRINCIPAL {
        if let Some(oldest) = held.pop_front() {
            state.results.remove(&(stored.principal.clone(), oldest));
        }
    }
    state.results.insert(
        (stored.principal.clone(), stored.request_id.clone()),
        stored,
    );
}

/// Drops from memory what is past the window at `now`.
fn prune(state: &mut State, now: u64) {
    let expired: Vec<(String, String)> = state
        .results
        .iter()
        .filter(|(_, stored)| stored.recorded_at.saturating_add(WINDOW.as_secs()) <= now)
        .map(|(key, _)| key.clone())
        .collect();
    for key in expired {
        state.results.remove(&key);
        if let Some(held) = state.held.get_mut(&key.0) {
            held.retain(|request_id| *request_id != key.1);
        }
    }
    state.plans.retain(|_, plan| kept(plan.expires, now));
    state.consumed.retain(|_, expires| kept(*expires, now));
}

/// An empty journal under [`PLACEHOLDER`], held for the instant of a swap.
fn placeholder(state_dir: &Dir, options: Options) -> Result<Journal, ReplayError> {
    remove_tree(state_dir, PLACEHOLDER)?;
    let (journal, _) = Journal::open(state_dir.subdir(PLACEHOLDER, true)?, options)?;
    Ok(journal)
}

/// Removes what a compaction that did not finish left behind, and puts back a journal that was
/// renamed aside but not replaced.
fn sweep(state_dir: &Dir) -> Result<(), ReplayError> {
    let subdirs = state_dir.subdirs()?;
    let has = |name: &str| subdirs.iter().any(|held| held == name);
    if has(COMPACTING) {
        remove_tree(state_dir, COMPACTING)?;
    }
    if has(PLACEHOLDER) {
        remove_tree(state_dir, PLACEHOLDER)?;
    }
    if has(SUPERSEDED) {
        if has(JOURNAL) {
            remove_tree(state_dir, SUPERSEDED)?;
        } else {
            state_dir.rename(SUPERSEDED, JOURNAL)?;
            state_dir.sync()?;
        }
    }
    Ok(())
}

/// Removes the subdirectory `name` and the files in it; nothing when it is already gone.
fn remove_tree(state_dir: &Dir, name: &str) -> Result<(), ReplayError> {
    if !state_dir.subdirs()?.iter().any(|held| held == name) {
        return Ok(());
    }
    let dir = state_dir.subdir(name, false)?;
    for file in dir.names()? {
        dir.unlink(&file)?;
    }
    drop(dir);
    state_dir.remove_subdir(name)?;
    state_dir.sync()?;
    Ok(())
}

fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ReplayError> {
    serde_json::to_vec(value)
        .map_err(|error| ReplayError::Malformed(format!("a replay frame does not encode: {error}")))
}

fn decode<T: DeserializeOwned>(payload: &[u8]) -> Result<T, ReplayError> {
    serde_json::from_slice(payload)
        .map_err(|error| ReplayError::Malformed(format!("a replay frame does not decode: {error}")))
}
