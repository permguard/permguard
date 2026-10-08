// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The request-id replay window and the server-held plans: `host/state/replay/` on the volume
//! (owner decision, 2026-10-06).
//!
//! ```text
//! host/state/
//! ├── replay/           the journal: results, plans and consumed plans, segmented
//! └── replay.new/       a compaction in progress; swept at open
//! ```
//!
//! Every applied mutation is recorded as `{principal, request_id, operation, digest, result}`,
//! so a retry inside the window, from the same principal with the same request, is answered
//! with the stored result, across a restart. The window is [`WINDOW`] long and holds at most
//! [`PER_PRINCIPAL`] results per principal; what is past the window is dropped from memory as it
//! is met and from the disk when the journal is opened again, by rewriting the live entries into
//! a fresh journal and swapping the directories.
//!
//! A plan of a two-step mutation (`revoke/plan`, then `revoke/run`) lives in the same journal:
//! the plan step writes `{plan_id, operation, target, revision, digest, expires, principal}`, the
//! run step consumes it once, each inside its operation of the security-mutation transaction
//! (WP-3.6). `TODO(WP-3.9)`: the client-held COSE plan receipt replaces the server-held plan.
//!
//! Since WP-3.6 the answers a retry learns are the mutation journal's commits; the results this
//! journal holds from before answer until their window ends, and no new one is written.
//!
//! The payloads are JSON: the stored result is the answer the transports render, and nothing
//! outside this process ever reads these frames. The journal frames themselves are the storage
//! library's format, claim generation included.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};

use permguard_core::authz::Principal;
use permguard_core::{ErrorClass, codes};

use super::Refusal;
use crate::operations::mutation::Applying;
use crate::storage::StorageError;
use crate::storage::dir::Dir;
use crate::storage::journal::{Journal, Options, Recovery};
use crate::storage::volume::Volume;

/// The directory below `host/`.
pub const DIRECTORY: &str = "state";
/// The journal directory below [`DIRECTORY`].
pub const JOURNAL: &str = "replay";
/// Where a compaction writes before it swaps.
const COMPACTING: &str = "replay.new";
/// Where the superseded journal waits to be removed.
const SUPERSEDED: &str = "replay.old";
/// Where a journal handle lives for the instant of a swap, so the lock never holds a handle
/// into a directory that is being renamed.
const PLACEHOLDER: &str = "replay.swap";

/// How long a stored result answers a retry.
pub const WINDOW: Duration = Duration::from_secs(10 * 60);
/// How many results one principal may hold inside the window.
pub const PER_PRINCIPAL: usize = 4096;
/// How long a plan may be run after it was made.
pub const PLAN_LIFETIME: Duration = Duration::from_secs(10 * 60);

/// A stored result.
const FRAME_RESULT: u16 = 1;
/// A plan made.
const FRAME_PLAN: u16 = 2;
/// A plan consumed by its run step.
const FRAME_PLAN_CONSUMED: u16 = 3;

/// What the journal refuses with.
#[derive(Debug)]
pub enum ReplayError {
    /// The journal could not be read or written.
    Storage(StorageError),
    /// A frame does not decode, or a result does not deserialize as its operation's answer.
    Malformed(String),
}

impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Storage(error) => write!(f, "{error}"),
            Self::Malformed(detail) => f.write_str(detail),
        }
    }
}

impl std::error::Error for ReplayError {}

impl From<StorageError> for ReplayError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error)
    }
}

impl From<ReplayError> for Refusal {
    fn from(error: ReplayError) -> Self {
        Refusal::Api(
            permguard_core::ApiError::new(
                ErrorClass::Unavailable,
                codes::host::REPLAY_UNAVAILABLE,
                "the replay journal is unavailable before the mutation: nothing was applied",
            )
            .with_internal(error.to_string()),
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredResult {
    principal: String,
    request_id: String,
    operation: String,
    digest: String,
    result: serde_json::Value,
    recorded_at: u64,
}

/// A server-held plan: what `revoke/plan` wrote and `revoke/run` presents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Plan {
    pub plan_id: String,
    pub operation: String,
    pub target: String,
    pub revision: u64,
    pub digest: String,
    pub expires: u64,
    pub principal: String,
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
struct State {
    results: BTreeMap<(String, String), StoredResult>,
    /// Request ids per principal, oldest first, so the cap drops the oldest.
    held: BTreeMap<String, VecDeque<String>>,
    plans: BTreeMap<(String, String), Plan>,
    consumed: BTreeMap<(String, String), u64>,
}

/// The replay journal of one volume.
pub struct Replay {
    journal: Mutex<Journal>,
    state: Mutex<State>,
    /// The `(principal, request_id)` pairs with a mutation in flight: a second arrival with the
    /// same pair while the first is between its lookup and its record is refused, so two
    /// simultaneous retries cannot both apply.
    in_flight: Mutex<BTreeSet<(String, String)>>,
    /// Where the window is measured from (WP-2.12).
    time: Arc<crate::time::TimeGuard>,
}

/// One mutation in flight; dropping it lets the next arrival with the same pair in.
#[derive(Debug)]
pub struct InFlight<'a> {
    replay: &'a Replay,
    key: (String, String),
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.replay
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
    }
}

impl std::fmt::Debug for Replay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Replay").finish_non_exhaustive()
    }
}

impl Replay {
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
            in_flight: Mutex::new(BTreeSet::new()),
            time: Arc::new(crate::time::TimeGuard::system(
                permguard_core::config::DEFAULT_TIME_MAX_CLOCK_SKEW,
            )),
        };
        if dead > 0 {
            replay.compact(&state_dir, options, now)?;
            tracing::info!(
                event.name = "host.replay.compacted",
                component = super::COMPONENT,
                dropped = dead,
                "the replay journal was rewritten without its expired entries"
            );
        }
        Ok((replay, recovery))
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
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        remove_tree(state_dir, COMPACTING)?;
        let (mut fresh, _) = Journal::open(state_dir.subdir(COMPACTING, true)?, options)?;
        for result in state.results.values() {
            fresh.append(FRAME_RESULT, &encode(result)?)?;
        }
        for plan in state.plans.values() {
            if plan.expires > now {
                fresh.append(FRAME_PLAN, &encode(plan)?)?;
            }
        }
        for ((principal, plan_id), expires) in &state.consumed {
            if *expires > now {
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

    /// Takes the `(principal, request_id)` pair for the duration of one mutation, or refuses a
    /// second arrival while the first is in flight: it retries once the first has answered.
    pub fn begin(&self, principal: &Principal, request_id: &str) -> Result<InFlight<'_>, Refusal> {
        let key = (principal.as_str().to_owned(), request_id.to_owned());
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !in_flight.insert(key.clone()) {
            return Err(Refusal::new(
                ErrorClass::Conflict,
                codes::host::REQUEST_ID_REUSED,
                "a mutation with this request id is in flight; retry once it has answered",
            ));
        }
        Ok(InFlight { replay: self, key })
    }

    /// Measures the window against `time`, the Host's guard, instead of a guard of its own.
    pub fn with_time(mut self, time: Arc<crate::time::TimeGuard>) -> Self {
        self.time = time;
        self
    }

    /// The stored result of `(principal, request_id)` as `T`, when one is held inside the window
    /// for the same `operation` and the same request `digest`; the same request id under
    /// another operation or request is `request_id_reused`.
    pub fn lookup<T: DeserializeOwned>(
        &self,
        principal: &Principal,
        request_id: &str,
        operation: &str,
        digest: &str,
    ) -> Result<Option<T>, Refusal> {
        let now = self.time.now_secs();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune(&mut state, now);
        let key = (principal.as_str().to_owned(), request_id.to_owned());
        let Some(stored) = state.results.get(&key) else {
            return Ok(None);
        };
        if stored.operation != operation || stored.digest != digest {
            return Err(Refusal::new(
                ErrorClass::Conflict,
                codes::host::REQUEST_ID_REUSED,
                "this request id was already used for a different mutation inside the replay window",
            ));
        }
        let result = serde_json::from_value(stored.result.clone()).map_err(|error| {
            ReplayError::Malformed(format!(
                "a stored result of `{operation}` does not read as its answer: {error}"
            ))
        })?;
        Ok(Some(result))
    }

    /// Records the `result` of `(principal, request_id)`, durably: what the Host API did before
    /// WP-3.6, whose answers now live in the mutation journal's commits. Kept for the tests of
    /// the results such a journal still holds, which answer until their window ends.
    #[cfg(test)]
    pub(crate) fn record<T: Serialize>(
        &self,
        principal: &Principal,
        request_id: &str,
        operation: &str,
        digest: &str,
        result: &T,
    ) -> Result<(), ReplayError> {
        let now = self.time.now_secs();
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
        drop(journal);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        prune(&mut state, now);
        remember(&mut state, stored);
        Ok(())
    }

    /// Writes a plan, durably, inside the operation `applying` names (WP-3.6).
    pub fn plan(&self, _applying: &Applying<'_>, plan: Plan) -> Result<(), Refusal> {
        let bytes = encode(&plan)?;
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        journal
            .append(FRAME_PLAN, &bytes)
            .map_err(ReplayError::from)?;
        drop(journal);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .plans
            .insert((plan.principal.clone(), plan.plan_id.clone()), plan);
        Ok(())
    }

    /// The plan `plan_id` of `principal`, when it is held, not yet consumed and not expired at
    /// `now`: `plan_unknown` otherwise, `plan_expired` when it was run or has aged out.
    pub fn plan_of(&self, principal: &Principal, plan_id: &str, now: u64) -> Result<Plan, Refusal> {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let key = (principal.as_str().to_owned(), plan_id.to_owned());
        if state.consumed.contains_key(&key) {
            return Err(Refusal::new(
                ErrorClass::Conflict,
                codes::host::PLAN_EXPIRED,
                "this plan was already run",
            ));
        }
        let Some(plan) = state.plans.get(&key) else {
            return Err(Refusal::new(
                ErrorClass::NotFound,
                codes::host::PLAN_UNKNOWN,
                "no plan of that id is held for this principal",
            ));
        };
        if plan.expires <= now {
            return Err(Refusal::new(
                ErrorClass::Conflict,
                codes::host::PLAN_EXPIRED,
                "this plan has expired; plan again",
            ));
        }
        Ok(plan.clone())
    }

    /// Consumes `plan_id` of `principal`, durably, inside the run's operation: a second run finds
    /// it `plan_expired`. The caller decides what a failure here means: the plan's mutation is
    /// already applied.
    pub fn consume(
        &self,
        _applying: &Applying<'_>,
        principal: &Principal,
        plan_id: &str,
    ) -> Result<(), ReplayError> {
        let key = (principal.as_str().to_owned(), plan_id.to_owned());
        let expires = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .plans
            .get(&key)
            .map_or(0, |plan| plan.expires);
        let consumed = Consumed {
            plan_id: plan_id.to_owned(),
            principal: principal.as_str().to_owned(),
            expires,
        };
        let bytes = encode(&consumed)?;
        let mut journal = self
            .journal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        journal.append(FRAME_PLAN_CONSUMED, &bytes)?;
        drop(journal);
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.plans.remove(&key);
        state.consumed.insert(key, expires);
        Ok(())
    }

    /// How many results are held, for the tests and the start-up record.
    pub fn held(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .results
            .len()
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
            if plan.expires <= now {
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
            state.plans.remove(&key);
            if consumed.expires <= now {
                return Ok(false);
            }
            state.consumed.insert(key, consumed.expires);
            Ok(true)
        }
        other => Err(ReplayError::Malformed(format!(
            "the replay journal holds a frame of unknown kind {other}"
        ))),
    }
}

/// Holds `stored`, dropping the principal's oldest result past [`PER_PRINCIPAL`].
fn remember(state: &mut State, stored: StoredResult) {
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
    state.plans.retain(|_, plan| plan.expires > now);
    state.consumed.retain(|_, expires| *expires > now);
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

/// The digest a mutation's request is remembered by: SHA-256 over its JSON, hex.
pub fn digest_of<R: Serialize>(request: &R) -> Result<String, Refusal> {
    let bytes = serde_json::to_vec(request).map_err(|error| {
        ReplayError::Malformed(format!(
            "a request does not serialize for its digest: {error}"
        ))
    })?;
    Ok(hex(&Sha256::digest(&bytes)))
}

/// A fresh identifier: 16 bytes from the OS CSPRNG, hex. The one generator the process already
/// uses; a failure is the OS refusing random bytes, which nothing here can recover from, so the
/// mutation is refused rather than named by an id that is not random.
pub fn mint_id() -> Result<String, Refusal> {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 16];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        tracing::error!(
            event.name = "host.random_unavailable",
            component = super::COMPONENT,
            "the OS random source refused to fill an identifier"
        );
        return Err(Refusal::new(
            ErrorClass::Internal,
            codes::common::INTERNAL,
            "the random source refused an identifier; the mutation was not applied",
        ));
    }
    Ok(hex(&bytes))
}

fn hex(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push_str(&format!("{byte:02x}"));
    }
    text
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::api::testing::scratch;
    use permguard_core::assurance::AssuranceProfile;

    fn principal(name: &str) -> Principal {
        Principal::new(name).expect("a principal")
    }

    #[test]
    fn a_result_is_replayed_for_the_same_request_and_refused_for_another() {
        let root = scratch("replay-same");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (replay, _) = Replay::open(&volume, 1_000).expect("opens");
        let alice = principal("alice");
        assert!(
            replay
                .lookup::<u64>(&alice, "r1", "op", "d1")
                .expect("looked up")
                .is_none()
        );
        replay
            .record(&alice, "r1", "op", "d1", &42u64)
            .expect("recorded");
        assert_eq!(
            replay.lookup::<u64>(&alice, "r1", "op", "d1").expect("ok"),
            Some(42)
        );
        let reused = replay
            .lookup::<u64>(&alice, "r1", "op", "d2")
            .expect_err("another request under the same id");
        assert_eq!(
            reused.error().expect("refusal").code(),
            codes::host::REQUEST_ID_REUSED
        );
        let other_op = replay
            .lookup::<u64>(&alice, "r1", "other", "d1")
            .expect_err("another operation under the same id");
        assert_eq!(
            other_op.error().expect("refusal").code(),
            codes::host::REQUEST_ID_REUSED
        );
        // Another principal's namespace is its own.
        assert!(
            replay
                .lookup::<u64>(&principal("bob"), "r1", "op", "d1")
                .expect("ok")
                .is_none()
        );
    }

    #[test]
    fn a_result_survives_a_restart_and_an_expired_one_is_compacted_away() {
        let root = scratch("replay-restart");
        let alice = principal("alice");
        {
            let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
            let (replay, _) = Replay::open(&volume, 1_000).expect("opens");
            replay
                .record(&alice, "r1", "op", "d1", &"first")
                .expect("recorded");
        }
        {
            let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
            let now = crate::authz::store::now();
            let (replay, _) = Replay::open(&volume, now).expect("reopens");
            assert_eq!(replay.held(), 1, "the result is read back from the journal");
            assert_eq!(
                replay
                    .lookup::<String>(&alice, "r1", "op", "d1")
                    .expect("ok"),
                Some("first".to_owned())
            );
        }
        {
            let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
            let far = crate::authz::store::now() + WINDOW.as_secs() + 1;
            let (replay, _) = Replay::open(&volume, far).expect("reopens past the window");
            assert_eq!(replay.held(), 0, "past the window nothing is held");
            let state_dir = volume.host().subdir(DIRECTORY, false).expect("state");
            let names = state_dir.subdirs().expect("listed");
            assert_eq!(
                names,
                vec![JOURNAL.to_owned()],
                "the swap left only the journal"
            );
            // And the rewritten journal holds no result frame.
            let journal_dir = state_dir.subdir(JOURNAL, false).expect("journal");
            let (journal, _) =
                Journal::open(journal_dir, volume.journal_options(Options::default()))
                    .expect("the rewritten journal opens");
            assert!(journal.frames().expect("frames").is_empty());
        }
    }

    #[test]
    fn the_per_principal_cap_drops_the_oldest() {
        let mut state = State::default();
        for index in 0..=PER_PRINCIPAL {
            remember(
                &mut state,
                StoredResult {
                    principal: "alice".to_owned(),
                    request_id: format!("r{index}"),
                    operation: "op".to_owned(),
                    digest: "d".to_owned(),
                    result: serde_json::Value::Null,
                    recorded_at: 0,
                },
            );
        }
        assert_eq!(state.results.len(), PER_PRINCIPAL);
        assert!(
            !state
                .results
                .contains_key(&("alice".to_owned(), "r0".to_owned())),
            "the oldest went"
        );
        assert!(
            state
                .results
                .contains_key(&("alice".to_owned(), format!("r{PER_PRINCIPAL}")))
        );
    }

    #[test]
    fn a_plan_is_consumed_once_and_expires() {
        let root = scratch("replay-plan");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (replay, _) = Replay::open(&volume, 1_000).expect("opens");
        let alice = principal("alice");
        let plan = Plan {
            plan_id: "p1".to_owned(),
            operation: "grants.revoke".to_owned(),
            target: "g1".to_owned(),
            revision: 3,
            digest: "abc".to_owned(),
            expires: 2_000,
            principal: "alice".to_owned(),
        };
        replay
            .plan(&Applying::for_tests(1), plan.clone())
            .expect("planned");
        assert_eq!(replay.plan_of(&alice, "p1", 1_500).expect("held"), plan);
        let expired = replay.plan_of(&alice, "p1", 2_000).expect_err("expired");
        assert_eq!(
            expired.error().expect("refusal").code(),
            codes::host::PLAN_EXPIRED
        );
        let unknown = replay
            .plan_of(&principal("bob"), "p1", 1_500)
            .expect_err("not bob's");
        assert_eq!(
            unknown.error().expect("refusal").code(),
            codes::host::PLAN_UNKNOWN
        );
        replay
            .consume(&Applying::for_tests(2), &alice, "p1")
            .expect("consumed");
        let again = replay.plan_of(&alice, "p1", 1_500).expect_err("consumed");
        assert_eq!(
            again.error().expect("refusal").code(),
            codes::host::PLAN_EXPIRED
        );
        drop(replay);
        // Consumption survives a restart.
        let (replay, _) = Replay::open(&volume, 1_500).expect("reopens");
        let again = replay
            .plan_of(&alice, "p1", 1_500)
            .expect_err("still consumed");
        assert_eq!(
            again.error().expect("refusal").code(),
            codes::host::PLAN_EXPIRED
        );
    }

    #[test]
    fn a_consumed_plan_stays_consumed_across_a_compaction() {
        let root = scratch("replay-consumed-compact");
        let alice = principal("alice");
        let plan = Plan {
            plan_id: "p1".to_owned(),
            operation: "grants.revoke".to_owned(),
            target: "g1".to_owned(),
            revision: 1,
            digest: "d".to_owned(),
            expires: crate::authz::store::now() + 3_600,
            principal: "alice".to_owned(),
        };
        {
            let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
            let (replay, _) = Replay::open(&volume, 1_000).expect("opens");
            replay.plan(&Applying::for_tests(1), plan).expect("planned");
            replay
                .consume(&Applying::for_tests(2), &alice, "p1")
                .expect("consumed");
            // An expired result, so the next open compacts.
            replay
                .record(&alice, "old", "op", "d", &1u8)
                .expect("recorded");
        }
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let far = crate::authz::store::now() + WINDOW.as_secs() + 1;
        let (replay, _) = Replay::open(&volume, far).expect("reopens and compacts");
        assert_eq!(replay.held(), 0);
        let again = replay
            .plan_of(&alice, "p1", far)
            .expect_err("consumed, and still said so");
        assert_eq!(
            again.error().expect("refusal").code(),
            codes::host::PLAN_EXPIRED
        );
        // The journal reopened where it lives: a write after the swap lands and is durable.
        replay
            .record(&alice, "new", "op", "d", &2u8)
            .expect("the compacted journal takes a write");
        drop(replay);
        let (replay, _) =
            Replay::open(&volume, crate::authz::store::now()).expect("reopens at the clock");
        assert_eq!(
            replay.held(),
            1,
            "the write after the compaction is durable"
        );
        let state_dir = volume.host().subdir(DIRECTORY, false).expect("state");
        assert_eq!(
            state_dir.subdirs().expect("listed"),
            vec![JOURNAL.to_owned()],
            "no swap directory is left behind"
        );
    }

    #[test]
    fn a_second_arrival_of_a_request_in_flight_is_refused_until_the_first_answers() {
        let root = scratch("replay-in-flight");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (replay, _) = Replay::open(&volume, 1_000).expect("opens");
        let alice = principal("alice");
        let first = replay.begin(&alice, "r1").expect("the first is in flight");
        let second = replay
            .begin(&alice, "r1")
            .expect_err("the same pair, while in flight");
        assert_eq!(
            second.error().expect("refusal").code(),
            codes::host::REQUEST_ID_REUSED
        );
        assert!(
            replay.begin(&principal("bob"), "r1").is_ok(),
            "another principal's pair"
        );
        drop(first);
        drop(replay.begin(&alice, "r1").expect("free again"));
    }

    #[test]
    fn a_half_finished_compaction_is_swept_at_open() {
        let root = scratch("replay-sweep");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let alice = principal("alice");
        {
            let (replay, _) = Replay::open(&volume, 1_000).expect("opens");
            replay
                .record(&alice, "r1", "op", "d1", &1u8)
                .expect("recorded");
        }
        let state_dir = volume.host().subdir(DIRECTORY, false).expect("state");
        // A crash after the first rename: the journal is aside, nothing replaced it.
        state_dir
            .rename(JOURNAL, SUPERSEDED)
            .expect("renamed aside");
        state_dir
            .subdir(COMPACTING, true)
            .expect("a compaction had begun");
        let (replay, _) = Replay::open(&volume, 1_000).expect("reopens");
        assert_eq!(replay.held(), 1, "the journal renamed aside was put back");
        assert_eq!(
            state_dir.subdirs().expect("listed"),
            vec![JOURNAL.to_owned()]
        );
    }

    #[test]
    fn the_digest_follows_the_request_and_ids_are_distinct() {
        #[derive(Serialize)]
        struct Body {
            a: u8,
        }
        assert_eq!(
            digest_of(&Body { a: 1 }).expect("digest"),
            digest_of(&Body { a: 1 }).expect("digest")
        );
        assert_ne!(
            digest_of(&Body { a: 1 }).expect("digest"),
            digest_of(&Body { a: 2 }).expect("digest")
        );
        assert_ne!(mint_id().expect("minted"), mint_id().expect("minted"));
        assert_eq!(mint_id().expect("minted").len(), 32);
    }
}
