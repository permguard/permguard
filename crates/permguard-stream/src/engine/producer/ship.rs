// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Shipping a producer's batches to its subscriptions (WP-5.4; owner decisions of 2026-10-14).
//!
//! ```text
//! producer/<sha256(resource)>/<producer-host>/
//! ├── subscriptions/<membership>-<task>.cbor   {1 membership, 2 task, 3 required,
//! │                                             4 [{1 run, 2 acked, 3? boot,
//! │                                                4? [{1 acked, 2 at}]}], 5 state,
//! │                                             6? paused_epoch, 7? reason}
//! └── batches/<run>/PRUNED                     {1 through}: the batch files deleted
//! ```
//!
//! Each subscription keeps its own acknowledgement per run. `truncate_safe` of a run is the least
//! acknowledgement of the required subscriptions; it is kept as STATE's `acknowledged_seq` of the
//! current run, and the batch files every required subscription acknowledged are deleted, never
//! one beyond it. An optional subscription never blocks; with no required one nothing does. The
//! answers move a subscription as the contract says: `ok` moves its ack, `out_of_order` resends
//! from `expected_seq`, `unverifiable` pauses it until the membership's epoch moves, `fork` and
//! `gone` stop it, an ack beyond what the producer holds stops it as `ack_ahead`; a deferral backs
//! it off, from 100 ms doubled to 30 s with full jitter, in memory, on the monotonic clock
//! (iteration 04, G4).
//!
//! A coordinator restored from a snapshot (WP-7.9b) answers under a new boot id with what it held
//! then. Each run's acknowledgement keeps the boot id of the incarnation that answered it: the
//! first answer below it under another rewinds the run and resends from the coordinator's
//! position, or stops the subscription `producer_gap` when that position was already deleted;
//! a complete run acknowledged under an earlier incarnation is probed once, its last retained
//! batch sent again. A stream is probed in its next session, once it has something to ship.

use permguard_core::encoding::hex;
use std::sync::PoisonError;

use permguard_core::authz::Resource;
use permguard_core::codes;
use permguard_host::composition::{self, Shipment, StreamShipping, Subscribed};
use permguard_host::membership::local::LOCAL_MEMBERSHIP;
use permguard_host::storage::Dir;
use permguard_host::storage::format;
use permguard_host::storage::write::{read_view, replace_view};
use permguard_objects::cbor::Value;

use super::super::batch::SealedBatch;
use super::super::codec::{Map, encode, uint};
use super::super::ingest::{Answer, Outcome, Ship};
use super::super::state::Unshipped;
use super::super::{RecordCodec, StreamError};
use super::seal::{batches_of, pruned_of};
use super::{Physical, Producer, RECORDS, decode_group};

const SUBSCRIPTIONS: &str = "subscriptions";
const BATCHES: &str = "batches";
/// The most bytes a subscription's file takes.
pub const MAX_SUBSCRIPTION_BYTES: usize = 64 * 1024;
/// The first wait of a subscription backing off, and the longest, in milliseconds (iteration 04,
/// G4): five minutes after a coordinator recovers is not seconds of freshness.
const BACKOFF_BASE_MS: u64 = 100;
const BACKOFF_CAP_MS: u64 = 30_000;
/// What a ship message carries beside its batch's records: the envelope, the signature, the
/// framing; the statement is counted on its own.
const SHIP_OVERHEAD_BYTES: usize = 4096;

/// Where a subscription stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubscriptionState {
    Active,
    /// Answered `unverifiable` at the membership's `epoch`: resumes once the epoch moves.
    Paused {
        epoch: u64,
    },
    /// Answered `fork`, `gone`, `closed`, or acknowledged beyond what the producer holds:
    /// stopped until an operator acts.
    Stopped {
        reason: String,
    },
}

/// One subscription of a producer's stream: a membership's ship task.
/// When a run's acknowledgement reached a value: `(acked, at)`, `at` in seconds (WP-7.9b).
pub type Point = (u64, u64);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subscription {
    pub membership_id: [u8; 16],
    pub task_id: String,
    pub required: bool,
    /// The highest contiguous sequence the consumer acknowledged, per run, in run order.
    pub runs: Vec<([u8; 16], u64)>,
    /// The coordinator boot id each run's acknowledgement was last answered under (WP-7.9b):
    /// what tells a restored coordinator from one that lost acknowledged records. A run answered
    /// before it was recorded has none.
    pub boots: Vec<([u8; 16], [u8; 16])>,
    /// When each run's acknowledgement reached each kept point, `(acked, at)` oldest first, kept
    /// only under an acknowledged retention (WP-7.9b): what tells how long ago a batch was
    /// acknowledged.
    pub points: Vec<([u8; 16], Vec<Point>)>,
    pub state: SubscriptionState,
}

impl Subscription {
    pub(crate) fn new(subscribed: &Subscribed<'_>) -> Self {
        Self {
            membership_id: subscribed.membership_id,
            task_id: subscribed.task_id.to_owned(),
            required: subscribed.required,
            runs: Vec::new(),
            boots: Vec::new(),
            points: Vec::new(),
            state: SubscriptionState::Active,
        }
    }

    /// The points of `run`'s acknowledgement, oldest first.
    pub fn points(&self, run: &[u8; 16]) -> &[(u64, u64)] {
        self.points
            .iter()
            .find(|(held, _)| held == run)
            .map_or(&[], |(_, points)| points.as_slice())
    }

    /// The highest sequence of `run` acknowledged at or before `cutoff`, `0` when none was.
    pub fn acked_by(&self, run: &[u8; 16], cutoff: u64) -> u64 {
        self.points(run)
            .iter()
            .filter(|(_, at)| *at <= cutoff)
            .map(|(acked, _)| *acked)
            .max()
            .unwrap_or(0)
    }

    /// Records that `run`'s acknowledgement stands at its current value at `now`, under a
    /// retention of `retention` seconds, and answers whether the points changed. Every point
    /// dropped leaves less deletable, never more: a point above the acknowledgement (a restore
    /// lowered it), the previous newest when it is closer than a sixteenth of the retention to
    /// the one before, and every point older than the newest one already past the retention. A
    /// clock stepped back stamps no earlier than the newest point: later keeps more.
    pub(crate) fn note_acked(&mut self, run: [u8; 16], now: u64, retention: u64) -> bool {
        let acked = self.acked(&run);
        if acked == 0 {
            return false;
        }
        let at = match self.points.iter().position(|(held, _)| *held == run) {
            Some(at) => at,
            None => {
                self.points.push((run, Vec::new()));
                self.points.len() - 1
            }
        };
        let points = &mut self.points[at].1;
        let before = points.clone();
        points.retain(|(seq, _)| *seq <= acked);
        let now = now.max(points.last().map_or(0, |(_, at)| *at));
        if !points.last().is_some_and(|(seq, _)| *seq == acked) {
            let step = (retention / 16).max(1);
            if let [.., previous, newest] = points.as_slice()
                && newest.1.saturating_sub(previous.1) < step
            {
                points.pop();
            }
            points.push((acked, now));
        }
        let cutoff = now.saturating_sub(retention);
        if let Some(oldest) = points.iter().rposition(|(_, at)| *at <= cutoff) {
            points.drain(..oldest);
        }
        *points != before
    }

    /// The coordinator boot id `run`'s acknowledgement was last answered under.
    pub fn boot(&self, run: &[u8; 16]) -> Option<[u8; 16]> {
        self.boots
            .iter()
            .find(|(held, _)| held == run)
            .map(|(_, boot)| *boot)
    }

    /// Records `boot` for `run`, which then has an acknowledgement, if only of nothing: a boot is
    /// kept with its run.
    fn set_boot(&mut self, run: [u8; 16], boot: [u8; 16]) {
        if !self.runs.iter().any(|(held, _)| *held == run) {
            self.runs.push((run, 0));
        }
        match self.boots.iter_mut().find(|(held, _)| *held == run) {
            Some(held) => held.1 = boot,
            None => self.boots.push((run, boot)),
        }
    }

    /// The acknowledgement of `run`.
    pub fn acked(&self, run: &[u8; 16]) -> u64 {
        self.runs
            .iter()
            .find(|(held, _)| held == run)
            .map_or(0, |(_, acked)| *acked)
    }

    fn set_acked(&mut self, run: [u8; 16], acked: u64) {
        match self.runs.iter_mut().find(|(held, _)| *held == run) {
            Some(held) => held.1 = acked,
            None => self.runs.push((run, acked)),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let mut runs = Vec::new();
        for (run, acked) in &self.runs {
            let mut pairs = vec![
                (Value::Int(1), Value::Bytes(run.to_vec())),
                (Value::Int(2), uint(*acked)?),
            ];
            if let Some(boot) = self.boot(run) {
                pairs.push((Value::Int(3), Value::Bytes(boot.to_vec())));
            }
            let points = self.points(run);
            if !points.is_empty() {
                let mut kept = Vec::new();
                for (acked, at) in points {
                    kept.push(Value::Map(vec![
                        (Value::Int(1), uint(*acked)?),
                        (Value::Int(2), uint(*at)?),
                    ]));
                }
                pairs.push((Value::Int(4), Value::Array(kept)));
            }
            runs.push(Value::Map(pairs));
        }
        let mut pairs = vec![
            (1, Value::Bytes(self.membership_id.to_vec())),
            (2, Value::Text(self.task_id.clone())),
            (3, Value::Bool(self.required)),
            (4, Value::Array(runs)),
        ];
        match &self.state {
            SubscriptionState::Active => pairs.push((5, uint(0)?)),
            SubscriptionState::Paused { epoch } => {
                pairs.push((5, uint(1)?));
                pairs.push((6, uint(*epoch)?));
            }
            SubscriptionState::Stopped { reason } => {
                pairs.push((5, uint(2)?));
                pairs.push((7, Value::Text(reason.clone())));
            }
        }
        let bytes = encode(pairs)?;
        // What `decode` would refuse is never written: the subscription stays readable.
        if bytes.len() > MAX_SUBSCRIPTION_BYTES {
            return Err(StreamError::Invalid(format!(
                "a subscription of {} runs is out of its bound of {MAX_SUBSCRIPTION_BYTES} bytes",
                self.runs.len()
            )));
        }
        Ok(bytes)
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_SUBSCRIPTION_BYTES {
            return Err(StreamError::Invalid(
                "a subscription is out of its bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "a subscription")?;
        let membership_id = map.fixed(1)?;
        let task_id = map.text(2)?;
        let Value::Bool(required) = map.value(3)? else {
            return Err(StreamError::Invalid(
                "a subscription's requirement is a boolean".to_owned(),
            ));
        };
        let mut runs: Vec<([u8; 16], u64)> = Vec::new();
        let mut boots: Vec<([u8; 16], [u8; 16])> = Vec::new();
        let mut points: Vec<([u8; 16], Vec<Point>)> = Vec::new();
        for value in map.array(4)? {
            let mut run = Map::of(value, "a subscription's run")?;
            let id: [u8; 16] = run.fixed(1)?;
            let acked = run.uint(2)?;
            let boot = run
                .optional_bytes(3)?
                .map(|bytes| super::super::codec::fixed::<16>(bytes, "a run's coordinator boot id"))
                .transpose()?;
            let mut kept: Vec<(u64, u64)> = Vec::new();
            if let Some(value) = run.optional(4) {
                let Value::Array(values) = value else {
                    return Err(StreamError::Invalid(
                        "a run's acknowledgement points are an array".to_owned(),
                    ));
                };
                for value in values {
                    let mut point = Map::of(value, "an acknowledgement point")?;
                    let held = (point.uint(1)?, point.uint(2)?);
                    point.finish()?;
                    // Oldest first, neither going back: what `note_acked` writes.
                    if kept
                        .last()
                        .is_some_and(|last: &(u64, u64)| held.0 <= last.0 || held.1 < last.1)
                    {
                        return Err(StreamError::Invalid(
                            "a run's acknowledgement points are out of order".to_owned(),
                        ));
                    }
                    kept.push(held);
                }
            }
            run.finish()?;
            if let Some(boot) = boot {
                boots.push((id, boot));
            }
            if !kept.is_empty() {
                points.push((id, kept));
            }
            if runs.iter().any(|(held, _)| *held == id) {
                return Err(StreamError::Invalid(
                    "a subscription names a run twice".to_owned(),
                ));
            }
            runs.push((id, acked));
        }
        let state = match map.uint(5)? {
            0 => SubscriptionState::Active,
            1 => SubscriptionState::Paused {
                epoch: map.uint(6)?,
            },
            2 => SubscriptionState::Stopped {
                reason: map.text(7)?,
            },
            other => {
                return Err(StreamError::Invalid(format!(
                    "{other} is no subscription state"
                )));
            }
        };
        map.finish()?;
        super::super::name(&task_id, "task")?;
        Ok(Self {
            membership_id,
            task_id,
            required,
            runs,
            boots,
            points,
            state,
        })
    }
}

/// The bounds a stream's unacknowledged records are held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressureBounds {
    pub max_bytes: u64,
    pub max_age_secs: u64,
}

/// The retained batch file of `run` holding `seq`, sealing nothing: what a probe sends again.
fn retained_holding(
    physical: &Physical,
    run: &[u8; 16],
    seq: u64,
) -> Result<Option<Vec<u8>>, StreamError> {
    let dir = physical
        .writer()
        .dir
        .subdir(BATCHES, true)?
        .subdir(&hex(run), true)?;
    match batches_of(&dir)?
        .into_iter()
        .find(|(first, last, _)| (*first..=*last).contains(&seq))
    {
        Some((_, _, name)) => Ok(dir.read(&name)?),
        None => Ok(None),
    }
}

/// The subscriptions directory of a producer stream.
fn subscriptions_dir(dir: &Dir) -> Result<Dir, StreamError> {
    Ok(dir.subdir(SUBSCRIPTIONS, true)?)
}

fn file_name(membership_id: &[u8; 16], task_id: &str) -> Result<String, StreamError> {
    super::super::name(task_id, "task")?;
    Ok(format!("{}-{task_id}.cbor", hex(membership_id)))
}

/// Every subscription of the stream in `dir`, creating nothing: none when it never had one
/// (WP-5.7a, a read path).
pub(super) fn subscriptions_held(dir: &Dir) -> Result<Vec<Subscription>, StreamError> {
    if !dir.subdirs()?.iter().any(|name| name == SUBSCRIPTIONS) {
        return Ok(Vec::new());
    }
    subscriptions_of(dir)
}

/// Every subscription of the stream in `dir`.
pub(super) fn subscriptions_of(dir: &Dir) -> Result<Vec<Subscription>, StreamError> {
    let subscriptions = subscriptions_dir(dir)?;
    let mut found = Vec::new();
    for name in subscriptions.names()? {
        if !name.ends_with(".cbor") {
            continue;
        }
        if let Some(bytes) = read_view(&subscriptions, &name, format::VIEW)? {
            found.push(Subscription::decode(&bytes)?);
        }
    }
    Ok(found)
}

fn subscription_of(
    dir: &Dir,
    membership_id: &[u8; 16],
    task_id: &str,
) -> Result<Option<Subscription>, StreamError> {
    read_view(
        &subscriptions_dir(dir)?,
        &file_name(membership_id, task_id)?,
        format::VIEW,
    )?
    .map(|bytes| Subscription::decode(&bytes))
    .transpose()
}

pub(super) fn keep_subscription(dir: &Dir, subscription: &Subscription) -> Result<(), StreamError> {
    replace_view(
        &subscriptions_dir(dir)?,
        &file_name(&subscription.membership_id, &subscription.task_id)?,
        format::VIEW,
        &subscription.encode()?,
    )?;
    Ok(())
}

/// `truncate_safe` of `run`, fenced by `fence`: the least acknowledgement of the required
/// subscriptions of that membership, the only ones it is ever shipped to (after the review);
/// `None` when none exists, nothing blocking.
pub(super) fn truncate_safe_of(
    subscriptions: &[Subscription],
    run: &[u8; 16],
    fence: Option<[u8; 16]>,
) -> Option<u64> {
    subscriptions
        .iter()
        .filter(|subscription| {
            subscription.required && reads_run(subscription.membership_id, fence)
        })
        .map(|subscription| subscription.acked(run))
        .min()
}

/// What every required subscription of the fencing membership had acknowledged of `run` at
/// `cutoff` (WP-7.9b): the least of their acknowledgements by then; `None` when none exists.
pub(super) fn acknowledged_by(
    subscriptions: &[Subscription],
    run: &[u8; 16],
    fence: Option<[u8; 16]>,
    cutoff: u64,
) -> Option<u64> {
    subscriptions
        .iter()
        .filter(|subscription| {
            subscription.required && reads_run(subscription.membership_id, fence)
        })
        .map(|subscription| subscription.acked_by(run, cutoff))
        .min()
}

/// A carry begun in a stream's directory (BUG-0115): `{1 run, 2 through, 3 done}`.
const CARRY: &str = "CARRY";
/// The runs a stream carried into a fenced successor (BUG-0115): `{1 [run]}`.
const CARRIED: &str = "CARRIED";
/// How many records a carry reads at a time.
const CARRY_PAGE: usize = 256;

fn encode_carry(run: &[u8; 16], through: u64, done: u64) -> Result<Vec<u8>, StreamError> {
    encode(vec![
        (1, Value::Bytes(run.to_vec())),
        (2, uint(through)?),
        (3, uint(done)?),
    ])
}

fn decode_carry(bytes: &[u8]) -> Result<([u8; 16], u64, u64), StreamError> {
    let mut map = Map::read(bytes, "a stream's carry")?;
    let run = map.fixed(1)?;
    let through = map.uint(2)?;
    let done = map.uint(3)?;
    map.finish()?;
    Ok((run, through, done.min(through)))
}

fn encode_carried(runs: &[[u8; 16]]) -> Result<Vec<u8>, StreamError> {
    encode(vec![(
        1,
        Value::Array(runs.iter().map(|run| Value::Bytes(run.to_vec())).collect()),
    )])
}

/// The runs `dir`'s stream carried into a fenced successor (BUG-0115).
pub(super) fn carried_runs(dir: &Dir) -> Result<Vec<[u8; 16]>, StreamError> {
    let Some(bytes) = read_view(dir, CARRIED, format::VIEW)? else {
        return Ok(Vec::new());
    };
    let mut map = Map::read(&bytes, "a stream's carried runs")?;
    let mut runs = Vec::new();
    for value in map.array(1)? {
        let Value::Bytes(bytes) = value else {
            return Err(StreamError::Invalid("a carried run is 16 bytes".to_owned()));
        };
        runs.push(super::super::codec::fixed(bytes, "a carried run")?);
    }
    map.finish()?;
    Ok(runs)
}

/// Whether a subscription of `membership_id` reads a run fenced by `fence` (DEC-0034 option A):
/// a membership the runs it fences, the local task of a Host running both Planes every run, so
/// its own Control Plane reads what a membership ships and what none does.
pub(super) fn reads_run(membership_id: [u8; 16], fence: Option<[u8; 16]>) -> bool {
    membership_id == LOCAL_MEMBERSHIP || fence == Some(membership_id)
}

/// The fence of the runs `subscribed` ships.
fn fence_of(subscribed: &Subscribed<'_>) -> super::super::run::Fence {
    super::super::run::Fence {
        membership_id: subscribed.membership_id,
        task_id: subscribed.task_id.to_owned(),
        epoch: subscribed.epoch,
    }
}

/// The bytes of the records in `frames` past their run's floor in `floors`; `current` is the run
/// open before the first frame, when a prefix went (WP-5.6).
fn unacknowledged_bytes(
    frames: &[permguard_host::storage::journal::Frame],
    mut current: Option<[u8; 16]>,
    floors: &[([u8; 16], u64)],
) -> Result<u64, StreamError> {
    let mut bytes = 0u64;
    for frame in frames {
        match frame.kind {
            super::RUN_OPEN => {
                current = Some(
                    super::super::run::RunStatement::decode(
                        permguard_objects::cose::Sign1::decode(&frame.payload)
                            .map_err(|error| StreamError::Invalid(error.to_string()))?
                            .payload_unverified(),
                    )?
                    .run_id,
                );
            }
            RECORDS => {
                let floor = current
                    .and_then(|run| floors.iter().find(|(held, _)| *held == run))
                    .map(|(_, floor)| *floor);
                let Some(floor) = floor else {
                    continue;
                };
                let (first, records) = decode_group(&frame.payload)?;
                for (offset, record) in records.iter().enumerate() {
                    if first + offset as u64 > floor {
                        bytes += record.len() as u64;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(bytes)
}

/// The longest hold-off after `deferrals` earlier deferrals in a row, in milliseconds: 100 ms,
/// doubled each time, capped at 30 s. The hold-off itself is drawn in `[0, ceiling]` (full
/// jitter).
fn backoff_ceiling(deferrals: u32) -> u64 {
    BACKOFF_BASE_MS
        .saturating_mul(1u64.checked_shl(deferrals).unwrap_or(u64::MAX))
        .min(BACKOFF_CAP_MS)
}

/// Uniform in `[0, n]`, from the OS random source; 0 when it refuses.
fn jitter(n: u64) -> u64 {
    use ring::rand::SecureRandom as _;
    let mut bytes = [0u8; 8];
    if ring::rand::SystemRandom::new().fill(&mut bytes).is_err() {
        return 0;
    }
    u64::from_be_bytes(bytes) % n.saturating_add(1)
}

impl<C: RecordCodec> Producer<C> {
    /// Whether this producer's descriptor is the one `subscribed`'s task ships.
    fn ships(&self, subscribed: &Subscribed<'_>) -> bool {
        self.descriptor.task == Some(subscribed.task_type)
    }

    /// Rolls the stream of `physical` over to a successor fenced by `subscribed` when its task
    /// covers the stream and the current run is unfenced, or fenced by an older epoch of the same
    /// task (owner decision of 2026-10-13, WP-6.1): the run a subscription ships carries its
    /// fence. A run fenced by a task no live subscription holds any more, a membership that ended,
    /// belongs to nobody and is rolled over too (BUG-0198); so is one fenced by the local task
    /// when a membership covers the stream, which the local task reads whatever fences it
    /// (BUG-0229, DEC-0034 option A). A run fenced by another live membership is left to it, and
    /// a forked stream to its operator.
    fn fence_for(
        &self,
        physical: &Physical,
        subscribed: &Subscribed<'_>,
    ) -> Result<(), StreamError> {
        let covered = Resource::parse(&physical.key.resource)
            .is_ok_and(|resource| subscribed.selector.contains(&resource));
        if !covered {
            return Ok(());
        }
        let stale = {
            let writer = physical.writer();
            if writer
                .state
                .as_ref()
                .is_some_and(|state| state.forked_at_seq.is_some())
            {
                return Ok(());
            }
            match writer.run.as_ref().filter(|run| !run.ended) {
                None => false,
                Some(run) => match &run.statement.fence {
                    None => true,
                    Some(fence)
                        if fence.membership_id == subscribed.membership_id
                            && fence.task_id == subscribed.task_id =>
                    {
                        fence.epoch < subscribed.epoch
                    }
                    Some(fence) => {
                        let live = self.remembers(&fence.membership_id, &fence.task_id)
                            || subscriptions_held(&writer.dir)?.iter().any(|held| {
                                held.membership_id == fence.membership_id
                                    && held.task_id == fence.task_id
                            });
                        !live
                            || (fence.membership_id == LOCAL_MEMBERSHIP
                                && subscribed.membership_id != LOCAL_MEMBERSHIP)
                    }
                },
            }
        };
        if stale {
            // The open run no membership fenced, with records, when the Plane can rewrite them and
            // no local task reads them already: carried into the run this subscription fences, so
            // what was recorded before the first membership reaches its coordinator (BUG-0115).
            let carry = {
                let writer = physical.writer();
                let local = subscriptions_held(&writer.dir)?
                    .iter()
                    .any(|held| held.membership_id == LOCAL_MEMBERSHIP);
                writer
                    .run
                    .as_ref()
                    .filter(|run| {
                        !run.ended && run.statement.fence.is_none() && run.last_seq > 0 && !local
                    })
                    .map(|run| (run.statement.run_id, run.last_seq))
                    .filter(|_| self.carrier().is_some())
            };
            if let Some((run, through)) = carry {
                let writer = physical.writer();
                replace_view(
                    &writer.dir,
                    CARRY,
                    format::VIEW,
                    &encode_carry(&run, through, 0)?,
                )?;
            }
            // The subscription is kept before its run opens, so a restart between the two never
            // finds the run's fence held by nobody.
            {
                let writer = physical.writer();
                if subscription_of(&writer.dir, &subscribed.membership_id, subscribed.task_id)?
                    .is_none()
                {
                    keep_subscription(&writer.dir, &Subscription::new(subscribed))?;
                }
            }
            physical.rollover(&self.context, Some(fence_of(subscribed)), None)?;
        }
        // A carry begun is finished, here or after a restart (BUG-0115).
        self.carry_pending(physical)
    }

    /// The Plane's rewriter of its records, when it registered one (BUG-0115).
    fn carrier(&self) -> Option<composition::Rebase> {
        self.carrier
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Appends again, to the current run, the records of the run a `CARRY` names that are not yet
    /// carried, each rewritten for its new place by the Plane, the marker kept at every step so a
    /// restart resumes where it stopped; then names the run carried (BUG-0115).
    fn carry_pending(&self, physical: &Physical) -> Result<(), StreamError> {
        let marker = {
            let writer = physical.writer();
            read_view(&writer.dir, CARRY, format::VIEW)?
        };
        let Some(marker) = marker else {
            return Ok(());
        };
        let (run, through, mut done) = decode_carry(&marker)?;
        let Some(rebase) = self.carrier() else {
            return Ok(());
        };
        let resource = Resource::parse(&physical.key.resource)
            .map_err(|error| StreamError::Invalid(format!("the stream's resource: {error}")))?;
        // Whatever the run took before it ended, an append racing the rollover included.
        let through = self
            .produced_runs(&resource)?
            .iter()
            .find(|held| held.run == run)
            .map_or(through, |held| held.last_seq.max(through));
        while done < through {
            let page = self.produced_records(&resource, &run, done + 1, CARRY_PAGE)?;
            if page.records.is_empty() {
                break;
            }
            for (seq, bytes) in page.records {
                if seq <= done {
                    continue;
                }
                if seq > through {
                    break;
                }
                self.append_with(&resource, |position| {
                    Ok(vec![rebase(
                        &bytes,
                        composition::StreamPosition {
                            run_id: position.run_id,
                            seq: position.seq,
                            prev: position.prev,
                        },
                    )?])
                })?;
                done = seq;
                let writer = physical.writer();
                replace_view(
                    &writer.dir,
                    CARRY,
                    format::VIEW,
                    &encode_carry(&run, through, done)?,
                )?;
            }
        }
        let writer = physical.writer();
        let mut carried = carried_runs(&writer.dir)?;
        if !carried.contains(&run) {
            carried.push(run);
            replace_view(
                &writer.dir,
                CARRIED,
                format::VIEW,
                &encode_carried(&carried)?,
            )?;
        }
        writer.dir.unlink(CARRY)?;
        drop(writer);
        tracing::info!(
            event.name = "host.stream.run_carried",
            component = "stream",
            stream = %self.stream_name(),
            resource = %physical.key.resource,
            run = %hex(&run),
            records = done,
            "the records of a run no live membership fences were carried into the run a live one \
             fences: its coordinator receives them"
        );
        Ok(())
    }

    /// Whether any subscription of `membership_id` is live on `physical`: kept in its directory,
    /// or seen shipping by this process and not dropped since.
    fn membership_live(
        &self,
        physical: &Physical,
        membership_id: &[u8; 16],
    ) -> Result<bool, StreamError> {
        let remembered = self
            .fences
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
            .any(|(_, fence)| fence.membership_id == *membership_id);
        Ok(remembered
            || subscriptions_held(&physical.writer().dir)?
                .iter()
                .any(|held| held.membership_id == *membership_id))
    }

    /// States, once per run and process, the records of a covered run that `subscribed`'s
    /// membership will never be shipped: unfenced, written before any membership covered the
    /// stream; fenced by the local task, read only by this Host's own Control Plane; or fenced by
    /// a membership that ended (BUG-0105, DEC-0010 answer 3). Its batches name the fence they were
    /// sealed under, which no other membership's coordinator takes, so the loss is said, with its
    /// count, rather than left silent.
    fn state_unshipped(
        &self,
        physical: &Physical,
        subscribed: &Subscribed<'_>,
        runs: &[super::seal::RunView],
    ) -> Result<(), StreamError> {
        if subscribed.membership_id == LOCAL_MEMBERSHIP {
            return Ok(());
        }
        let carried = carried_runs(&physical.writer().dir)?;
        // A run whose carry is pending is on its way to a coordinator, not lost.
        let carrying = read_view(&physical.writer().dir, CARRY, format::VIEW)?
            .map(|marker| decode_carry(&marker).map(|(run, _, _)| run))
            .transpose()?;
        for (run, fence, last, _) in runs {
            if *last == 0
                || *fence == Some(subscribed.membership_id)
                || carried.contains(run)
                || carrying == Some(*run)
            {
                continue;
            }
            let reason = match fence {
                None => "written before any membership's task covered the stream",
                Some(held) if *held == LOCAL_MEMBERSHIP => {
                    "fenced by the local task: read by this Host's own Control Plane only"
                }
                Some(held) if !self.membership_live(physical, held)? => {
                    "fenced by a membership that ended"
                }
                Some(_) => continue,
            };
            if !self
                .stated
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(*run)
            {
                continue;
            }
            tracing::warn!(
                event.name = "host.stream.run_unshipped",
                component = "stream",
                stream = %self.stream_name(),
                resource = %physical.key.resource,
                run = %hex(run),
                records = *last,
                membership_id = %permguard_host::identity::record::uuid_text(&subscribed.membership_id),
                reason,
                "the records of this run are not shipped to this membership's coordinator"
            );
        }
        Ok(())
    }

    /// The live membership other than `subscribed`'s whose fence holds the open run of a stream
    /// `subscribed` covers, after [`Self::fence_for`]: named on health, as the stream cannot
    /// ship to `subscribed` (BUG-0198, BUG-0229).
    fn note_holder(&self, physical: &Physical, subscribed: &Subscribed<'_>) {
        if subscribed.membership_id == LOCAL_MEMBERSHIP {
            return;
        }
        let covered = Resource::parse(&physical.key.resource)
            .is_ok_and(|resource| subscribed.selector.contains(&resource));
        let holder = covered
            .then(|| {
                physical
                    .writer()
                    .run
                    .as_ref()
                    .filter(|run| !run.ended)
                    .and_then(|run| run.statement.fence.as_ref())
                    .map(|fence| fence.membership_id)
                    .filter(|held| *held != subscribed.membership_id)
            })
            .flatten();
        let key = (
            physical.key.resource.clone(),
            subscribed.membership_id,
            subscribed.task_id.to_owned(),
        );
        let mut held_by = self.held_by.lock().unwrap_or_else(PoisonError::into_inner);
        match holder {
            Some(holder) => {
                if held_by.insert(key, holder) != Some(holder) {
                    tracing::warn!(
                        event.name = "host.stream.run_held",
                        component = "stream",
                        stream = %self.stream_name(),
                        resource = %physical.key.resource,
                        membership_id = %permguard_host::identity::record::uuid_text(&subscribed.membership_id),
                        holder = %permguard_host::identity::record::uuid_text(&holder),
                        "the stream's open run is fenced by another live membership: nothing is shipped to this one"
                    );
                }
            }
            None => {
                held_by.remove(&key);
            }
        }
    }

    pub(super) fn signer_ring(&self) -> Result<&permguard_host::keys::ring::Ring, StreamError> {
        self.signer.as_deref().ok_or_else(|| {
            StreamError::Sign("the producer was handed no ring to seal under".to_owned())
        })
    }

    fn backoff_key(resource: &str, subscribed: &Subscribed<'_>) -> String {
        format!(
            "{resource}|{}|{}",
            hex(&subscribed.membership_id),
            subscribed.task_id
        )
    }

    /// The monotonic clock a backoff is measured on, in milliseconds.
    fn monotonic_ms(&self) -> u64 {
        u64::try_from(self.context.time.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// Holds `subscribed` off `resource` until the wall-clock second `until`, as a deferral would:
    /// what a test sets without the jitter.
    #[cfg(test)]
    pub(crate) fn hold_off(&self, resource: &str, subscribed: &Subscribed<'_>, until: u64) {
        let wait = until
            .saturating_sub(self.context.time.now_secs())
            .saturating_mul(1000);
        let until = self.monotonic_ms().saturating_add(wait);
        self.backoff
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(Self::backoff_key(resource, subscribed), (1, until));
    }

    /// The subscription of `membership_id`'s task `task_id` on `resource`'s stream.
    pub fn subscription(
        &self,
        resource: &Resource,
        membership_id: &[u8; 16],
        task_id: &str,
    ) -> Result<Option<Subscription>, StreamError> {
        let physical = self.physical(resource)?;
        let writer = physical.writer();
        subscription_of(&writer.dir, membership_id, task_id)
    }

    /// `truncate_safe` of `resource`'s run `run`: the least required acknowledgement, `None`
    /// when no required subscription exists.
    pub fn truncate_safe(
        &self,
        resource: &Resource,
        run: &[u8; 16],
    ) -> Result<Option<u64>, StreamError> {
        let signer = self.signer_ring()?;
        let physical = self.physical(resource)?;
        let fence = physical
            .runs(signer, &self.descriptor)?
            .into_iter()
            .find(|(held, ..)| held == run)
            .and_then(|(_, fence, ..)| fence);
        let writer = physical.writer();
        Ok(truncate_safe_of(
            &subscriptions_of(&writer.dir)?,
            run,
            fence,
        ))
    }

    /// Whether `resource`'s stream holds more unacknowledged than `bounds` allow: the bytes of
    /// the records past each run's `truncate_safe`, and the age of the oldest sealed batch no
    /// required subscription acknowledged (owner decision). With no required subscription, nothing
    /// is unacknowledged.
    pub fn pressure(
        &self,
        resource: &Resource,
        bounds: PressureBounds,
    ) -> Result<Option<&'static str>, StreamError> {
        self.measure_pressure(resource, bounds)
            .map(|measured| measured.verdict)
    }

    /// [`Self::pressure`], with the unacknowledged bytes and the oldest unacknowledged batch's
    /// time it measured (BUG-0119).
    pub fn measure_pressure(
        &self,
        resource: &Resource,
        bounds: PressureBounds,
    ) -> Result<permguard_host::composition::PressureMeasure, StreamError> {
        use permguard_host::composition::PressureMeasure;
        let signer = self.signer_ring()?;
        let physical = self.physical(resource)?;
        let runs = physical.runs(signer, &self.descriptor)?;
        // What the measure needs of the writer, taken under its lock and released before the
        // journal is read: a measure never stalls the flushes behind it (WP-6.1, after the
        // review).
        let (floors, current, first_index, records_dir, batches) = {
            let writer = physical.writer();
            let subscriptions = subscriptions_of(&writer.dir)?;
            let floors: Vec<([u8; 16], u64)> = runs
                .iter()
                .filter_map(|(run, fence, ..)| {
                    truncate_safe_of(&subscriptions, run, *fence).map(|safe| (*run, safe))
                })
                .collect();
            if floors.is_empty() {
                return Ok(PressureMeasure::default());
            }
            // Below the journal's first frame the run may have opened earlier (WP-5.6).
            let current = writer
                .base()
                .map(|base| {
                    Ok::<_, StreamError>(
                        super::super::run::RunStatement::decode(
                            permguard_objects::cose::Sign1::decode(&base.statement)
                                .map_err(|error| StreamError::Invalid(error.to_string()))?
                                .payload_unverified(),
                        )?
                        .run_id,
                    )
                })
                .transpose()?;
            (
                floors,
                current,
                writer.journal.first_index(),
                writer.dir.subdir(super::RECORDS_DIR, false)?,
                writer.dir.subdir(BATCHES, true)?,
            )
        };
        // Read without the lock: an append under way leaves at most a torn tail, which is not a
        // frame yet. A prefix deleted meanwhile moves the first frame, and the frames are then
        // read again under the lock.
        let frames = match permguard_host::storage::journal::read_frames(&records_dir) {
            Ok(frames)
                if frames
                    .first()
                    .is_none_or(|frame| frame.index == first_index) =>
            {
                frames
            }
            _ => physical.writer().journal.frames()?,
        };
        let bytes = unacknowledged_bytes(&frames, current, &floors)?;
        let mut measured = PressureMeasure {
            verdict: None,
            unacknowledged_bytes: Some(bytes),
            oldest_unacknowledged_at: None,
        };
        if bytes >= bounds.max_bytes {
            measured.verdict = Some(codes::stream::SPOOL_FULL);
            return Ok(measured);
        }
        // The age of the oldest sealed batch past its run's floor.
        let now = self.context.time.now_secs();
        let root = batches;
        for (run, floor) in &floors {
            let dir = root.subdir(&hex(run), true)?;
            let Some((_, _, name)) = batches_of(&dir)?
                .into_iter()
                .find(|(_, last, _)| last > floor)
            else {
                continue;
            };
            let bytes = dir.read(&name)?.unwrap_or_default();
            let created = SealedBatch::decode(&bytes)?
                .envelope_unverified()?
                .created_at;
            let created = permguard_core::time::from_rfc3339(&created)
                .and_then(|seconds| u64::try_from(seconds).ok())
                .ok_or_else(|| StreamError::Corruption(format!("`{name}` names no time")))?;
            measured.oldest_unacknowledged_at = Some(
                measured
                    .oldest_unacknowledged_at
                    .map_or(created, |oldest| oldest.min(created)),
            );
            if now.saturating_sub(created) >= bounds.max_age_secs {
                measured.verdict = Some(codes::stream::AGE_EXPIRY);
                return Ok(measured);
            }
        }
        Ok(measured)
    }

    /// Moves STATE's `acknowledged_seq` to the current run's `truncate_safe`. Deleting what every
    /// required subscription acknowledged is the garbage collection's (WP-5.6b, owner decision of
    /// 2026-10-15), never the shipping loop's.
    fn truncate(&self, physical: &Physical) -> Result<(), StreamError> {
        let signer = self.signer_ring()?;
        let runs = physical.runs(signer, &self.descriptor)?;
        let mut writer = physical.writer();
        let subscriptions = subscriptions_of(&writer.dir)?;
        let current = writer.run.as_ref().map(|current| current.statement.run_id);
        for (run, fence, last_seq, _) in &runs {
            if current != Some(*run) {
                continue;
            }
            if let Some(safe) = truncate_safe_of(&subscriptions, run, *fence) {
                writer.keep_acknowledged(safe.min(*last_seq))?;
            }
        }
        Ok(())
    }

    /// The physical stream of a lease's `resource`.
    fn stream_of(&self, resource: &str) -> Result<std::sync::Arc<Physical>, StreamError> {
        let resource =
            Resource::parse(resource).map_err(|error| StreamError::Invalid(error.to_string()))?;
        self.physical(&resource)
    }

    /// The batch file holding `seq` of `run`, sealing the next when none does yet.
    fn batch_holding(
        &self,
        physical: &Physical,
        resource: &str,
        run: [u8; 16],
        seq: u64,
        max_record_bytes: usize,
    ) -> Result<Option<Vec<u8>>, StreamError> {
        let resource =
            Resource::parse(resource).map_err(|error| StreamError::Invalid(error.to_string()))?;
        loop {
            let dir = physical
                .writer()
                .dir
                .subdir(BATCHES, true)?
                .subdir(&hex(&run), true)?;
            if let Some((_, _, name)) = batches_of(&dir)?
                .into_iter()
                .find(|(first, last, _)| (*first..=*last).contains(&seq))
            {
                return Ok(dir.read(&name)?);
            }
            if seq <= pruned_of(&dir)? {
                // Deleted when every required subscription had it: this one is behind them.
                return Err(StreamError::Invalid(format!(
                    "sequence {seq} of run {} was deleted after every required subscription \
                     acknowledged it",
                    hex(&run)
                )));
            }
            match self.seal_within(
                &resource,
                u64::from(self.descriptor.max_batch_records),
                max_record_bytes,
            )? {
                super::Sealing::Sealed { .. } => continue,
                super::Sealing::Nothing | super::Sealing::AwaitingCutover { .. } => {
                    return Ok(None);
                }
            }
        }
    }
}

impl<C: RecordCodec> Producer<C> {
    /// `<plane>/<type>`: the stream as its Plane declares it.
    fn stream_name(&self) -> String {
        format!("{}/{}", self.descriptor.plane, self.descriptor.stream_type)
    }

    /// The mark `physical` would take now: its newest run that a required subscription is
    /// behind on (interpretation of 2026-10-15), `None` when none is.
    fn behind_of(&self, physical: &Physical) -> Result<Option<Unshipped>, StreamError> {
        let signer = self.signer_ring()?;
        let runs = physical.runs(signer, &self.descriptor)?;
        let writer = physical.writer();
        let subscriptions = subscriptions_of(&writer.dir)?;
        Ok(runs.iter().rev().find_map(|(run, fence, last, _)| {
            truncate_safe_of(&subscriptions, run, *fence)
                .filter(|safe| safe < last)
                .map(|safe| Unshipped {
                    tail: *last,
                    truncate_safe: safe,
                    run: *run,
                })
        }))
    }

    /// Whether `mark` still holds on `physical` (owner decision of 2026-10-15, after the
    /// review): its run is behind its tail, or a run before it is behind its own end, whatever
    /// membership fences it. Runs opened after the drain owe the drain nothing.
    fn still_behind(&self, physical: &Physical, mark: Unshipped) -> Result<bool, StreamError> {
        let signer = self.signer_ring()?;
        let runs = physical.runs(signer, &self.descriptor)?;
        let writer = physical.writer();
        let subscriptions = subscriptions_of(&writer.dir)?;
        // A mark whose run is no longer listed holds every run listed to its end.
        let through = runs
            .iter()
            .position(|(run, ..)| *run == mark.run)
            .map_or(runs.len(), |at| at + 1);
        Ok(runs[..through].iter().any(|(run, fence, last, _)| {
            let owed = if *run == mark.run {
                (*last).min(mark.tail)
            } else {
                *last
            };
            truncate_safe_of(&subscriptions, run, *fence).is_some_and(|safe| safe < owed)
        }))
    }

    /// The mark `physical` holds, removed when nothing is behind at or below its tail; the one
    /// that remains carries what is acknowledged now.
    fn settle(&self, physical: &Physical) -> Result<Option<composition::Unshipped>, StreamError> {
        let held = physical
            .writer()
            .state
            .as_ref()
            .and_then(|state| state.unshipped);
        let Some(held) = held else {
            return Ok(None);
        };
        if !self.still_behind(physical, held)? {
            physical.writer().keep_unshipped(None)?;
            return Ok(None);
        }
        // What the marked run's required subscriptions acknowledge now.
        let now = Unshipped {
            truncate_safe: self
                .run_safe(physical, &held.run)?
                .unwrap_or(held.truncate_safe)
                .min(held.tail),
            ..held
        };
        Ok(Some(self.unshipped_of(physical, now)))
    }

    /// `truncate_safe` of `physical`'s run `run`, `None` when no required subscription holds it.
    fn run_safe(&self, physical: &Physical, run: &[u8; 16]) -> Result<Option<u64>, StreamError> {
        let signer = self.signer_ring()?;
        let fence = physical
            .runs(signer, &self.descriptor)?
            .into_iter()
            .find(|(held, ..)| held == run)
            .and_then(|(_, fence, ..)| fence);
        let writer = physical.writer();
        Ok(truncate_safe_of(
            &subscriptions_of(&writer.dir)?,
            run,
            fence,
        ))
    }

    fn unshipped_of(&self, physical: &Physical, mark: Unshipped) -> composition::Unshipped {
        composition::Unshipped {
            stream: self.stream_name(),
            resource: physical.key.resource.clone(),
            tail: mark.tail,
            truncate_safe: mark.truncate_safe,
        }
    }
}

impl<C: RecordCodec> StreamShipping for Producer<C> {
    fn on_append(&self, wake: composition::Wake) {
        self.add_wake(wake);
    }

    fn held(&self, subscribed: &Subscribed<'_>) -> Result<Vec<String>, String> {
        let wrap = |error: StreamError| error.to_string();
        if !self.ships(subscribed) {
            return Ok(Vec::new());
        }
        // A stream holds the task's subscription only once the task shipped on it: that is the
        // coverage, as `due` reads it.
        let mut held = Vec::new();
        for physical in self.every().map_err(wrap)? {
            if subscription_of(
                &physical.writer().dir,
                &subscribed.membership_id,
                subscribed.task_id,
            )
            .map_err(wrap)?
            .is_some()
            {
                held.push(physical.key.resource.clone());
            }
        }
        Ok(held)
    }

    fn acked_elsewhere(&self, subscribed: &Subscribed<'_>) -> Result<Vec<String>, String> {
        let wrap = |error: StreamError| error.to_string();
        let Some(boot) = subscribed.coordinator_boot_id else {
            return Ok(Vec::new());
        };
        if !self.ships(subscribed) {
            return Ok(Vec::new());
        }
        let signer = self.signer_ring().map_err(wrap)?;
        let mut found = Vec::new();
        for physical in self.every().map_err(wrap)? {
            let runs = match physical.runs(signer, &self.descriptor) {
                Err(StreamError::Forked { .. }) => continue,
                runs => runs.map_err(wrap)?,
            };
            let Some(subscription) = subscription_of(
                &physical.writer().dir,
                &subscribed.membership_id,
                subscribed.task_id,
            )
            .map_err(wrap)?
            else {
                continue;
            };
            if subscription.state != SubscriptionState::Active {
                continue;
            }
            let elsewhere = runs
                .iter()
                .filter(|(_, fence, ..)| reads_run(subscribed.membership_id, *fence))
                .any(|(run, _, last, _)| {
                    subscription.acked(run) >= *last
                        && *last > 0
                        && subscription.boot(run).is_some_and(|before| before != boot)
                });
            if elsewhere {
                found.push(physical.key.resource.clone());
            }
        }
        Ok(found)
    }

    fn retired(&self) -> Result<Vec<composition::Retired>, String> {
        self.retired_streams().map_err(|error| error.to_string())
    }

    fn close(&self) -> Result<usize, String> {
        let wrap = |error: StreamError| error.to_string();
        // Closed first: an append racing the seals is refused, never left unsealed behind them.
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        let mut sealed = 0;
        for physical in self.every().map_err(wrap)? {
            let resource = Resource::parse(&physical.key.resource)
                .map_err(|error| format!("the stream of `{}`: {error}", physical.key.resource))?;
            loop {
                match self.seal(&resource, u64::MAX) {
                    Ok(super::Sealing::Sealed { .. }) => sealed += 1,
                    // A forked stream seals nothing; one awaiting its cutover is sealed by the
                    // key the coordinator journals, which the reset retires: left to the drain's
                    // mark.
                    Ok(super::Sealing::Nothing | super::Sealing::AwaitingCutover { .. })
                    | Err(StreamError::Forked { .. }) => break,
                    Err(error) => return Err(error.to_string()),
                }
            }
        }
        Ok(sealed)
    }

    fn refused(&self) -> Result<Vec<composition::RefusedShipping>, String> {
        let wrap = |error: StreamError| error.to_string();
        let mut found = Vec::new();
        for physical in self.every().map_err(wrap)? {
            // A read: a stream nobody subscribed to yet gains no directory for being asked.
            let subscriptions = subscriptions_held(&physical.writer().dir).map_err(wrap)?;
            for subscription in subscriptions {
                let state = match &subscription.state {
                    SubscriptionState::Active => continue,
                    SubscriptionState::Paused { epoch } => format!("paused at epoch {epoch}"),
                    SubscriptionState::Stopped { reason } => format!("stopped: {reason}"),
                };
                found.push(composition::RefusedShipping {
                    membership_id: subscription.membership_id,
                    stream: self.stream_name(),
                    resource: physical.key.resource.clone(),
                    task_id: subscription.task_id.clone(),
                    state,
                });
            }
        }
        // A stream found corrupt, its sealed range's batches gone: it is not sealed again, so
        // nothing past it ships, and it is said so on health rather than only logged (BUG-0116).
        for (resource, why) in self
            .corrupt
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            found.push(composition::RefusedShipping {
                membership_id: [0; 16],
                stream: self.stream_name(),
                resource: resource.clone(),
                task_id: String::new(),
                state: format!("corrupt, not sealed again: {why}"),
            });
        }
        // Records a membership that ended never had acknowledged, waiting for a live one to carry
        // them to its coordinator: not shipped until then, and said so (BUG-0198, BUG-0164).
        for physical in self.every().map_err(wrap)? {
            let writer = physical.writer();
            let Some(marker) =
                read_view(&writer.dir, CARRY, format::VIEW).map_err(|error| error.to_string())?
            else {
                continue;
            };
            let (run, through, done) = decode_carry(&marker).map_err(wrap)?;
            let fence = writer
                .run
                .as_ref()
                .filter(|held| held.statement.run_id == run)
                .and_then(|held| held.statement.fence.clone());
            found.push(composition::RefusedShipping {
                membership_id: fence.as_ref().map_or([0; 16], |fence| fence.membership_id),
                stream: self.stream_name(),
                resource: physical.key.resource.clone(),
                task_id: fence.map(|fence| fence.task_id).unwrap_or_default(),
                state: format!(
                    "{} record(s) of run {} wait for a live membership covering the stream to \
                     carry them to its coordinator",
                    through.saturating_sub(done),
                    hex(&run)
                ),
            });
        }
        // A live subscription whose stream another live membership's run holds ships nothing,
        // and says so (BUG-0198, BUG-0229).
        for ((resource, membership_id, task_id), holder) in self
            .held_by
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .iter()
        {
            found.push(composition::RefusedShipping {
                membership_id: *membership_id,
                stream: self.stream_name(),
                resource: resource.clone(),
                task_id: task_id.clone(),
                state: format!(
                    "its open run is fenced by membership {}",
                    permguard_host::identity::record::uuid_text(holder)
                ),
            });
        }
        Ok(found)
    }

    fn behind(&self) -> Result<Vec<composition::Unshipped>, String> {
        let wrap = |error: StreamError| error.to_string();
        let mut found = Vec::new();
        for physical in self.every().map_err(wrap)? {
            if let Some(mark) = self.behind_of(&physical).map_err(wrap)? {
                found.push(self.unshipped_of(&physical, mark));
            }
        }
        Ok(found)
    }

    fn mark_unshipped(&self) -> Result<Vec<composition::Unshipped>, String> {
        let wrap = |error: StreamError| error.to_string();
        let mut marked = Vec::new();
        for physical in self.every().map_err(wrap)? {
            let Some(mark) = self.behind_of(&physical).map_err(wrap)? else {
                continue;
            };
            physical.writer().keep_unshipped(Some(mark)).map_err(wrap)?;
            marked.push(self.unshipped_of(&physical, mark));
        }
        Ok(marked)
    }

    fn unshipped_on(
        &self,
        subscribed: &Subscribed<'_>,
        resource: &str,
    ) -> Result<Option<composition::Unshipped>, String> {
        let wrap = |error: StreamError| error.to_string();
        if !self.ships(subscribed) {
            return Ok(None);
        }
        let physical = self.stream_of(resource).map_err(wrap)?;
        self.settle(&physical).map_err(wrap)
    }

    fn settle_unshipped(&self) -> Result<Vec<composition::Unshipped>, String> {
        let wrap = |error: StreamError| error.to_string();
        let mut remaining = Vec::new();
        for physical in self.every().map_err(wrap)? {
            remaining.extend(self.settle(&physical).map_err(wrap)?);
        }
        Ok(remaining)
    }

    fn due(&self, subscribed: &Subscribed<'_>) -> Result<Vec<String>, String> {
        let wrap = |error: StreamError| error.to_string();
        if !self.ships(subscribed) {
            return Ok(Vec::new());
        }
        let signer = self.signer_ring().map_err(wrap)?;
        let now = self.monotonic_ms();
        self.remember_fence(subscribed.selector, fence_of(subscribed));
        let mut due = Vec::new();
        for physical in self.every().map_err(wrap)? {
            self.fence_for(&physical, subscribed).map_err(wrap)?;
            self.note_holder(&physical, subscribed);
            // A forked stream ships nothing until its operator approves a successor, and keeps no
            // other stream from shipping (WP-6.1, found by its test).
            let runs = match physical.runs(signer, &self.descriptor) {
                Err(StreamError::Forked { .. }) => continue,
                runs => runs.map_err(wrap)?,
            };
            if Resource::parse(&physical.key.resource)
                .is_ok_and(|resource| subscribed.selector.contains(&resource))
            {
                self.state_unshipped(&physical, subscribed, &runs)
                    .map_err(wrap)?;
            }
            let fenced: Vec<&super::seal::RunView> = runs
                .iter()
                .filter(|(_, fence, ..)| reads_run(subscribed.membership_id, *fence))
                .collect();
            if fenced.is_empty() {
                continue;
            }
            let resource = physical.key.resource.clone();
            let writer = physical.writer();
            // A new key waiting for its cutover ships nothing until it is journaled (after the
            // review): no session is opened for it.
            if super::seal::cutover_of(&writer.dir)
                .map_err(wrap)?
                .is_some_and(|cutover| !cutover.confirmed)
            {
                continue;
            }
            let mut subscription =
                subscription_of(&writer.dir, &subscribed.membership_id, subscribed.task_id)
                    .map_err(wrap)?
                    .unwrap_or_else(|| Subscription::new(subscribed));
            let mut changed = subscription.required != subscribed.required;
            subscription.required = subscribed.required;
            match subscription.state {
                SubscriptionState::Paused { epoch } if subscribed.epoch > epoch => {
                    subscription.state = SubscriptionState::Active;
                    changed = true;
                }
                _ => {}
            }
            if changed
                || subscription_of(&writer.dir, &subscribed.membership_id, subscribed.task_id)
                    .map_err(wrap)?
                    .is_none()
            {
                keep_subscription(&writer.dir, &subscription).map_err(wrap)?;
            }
            drop(writer);
            if subscription.state != SubscriptionState::Active {
                continue;
            }
            let backing_off = self
                .backoff
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&Self::backoff_key(&resource, subscribed))
                .is_some_and(|(_, until)| *until > now);
            if backing_off {
                continue;
            }
            if fenced
                .iter()
                .any(|(run, _, last, _)| subscription.acked(run) < *last)
            {
                due.push(resource);
            }
        }
        Ok(due)
    }

    fn next(
        &self,
        subscribed: &Subscribed<'_>,
        resource: &str,
        max_bytes: u64,
    ) -> Result<Option<Shipment>, String> {
        let wrap = |error: StreamError| error.to_string();
        if !self.ships(subscribed) {
            return Ok(None);
        }
        let signer = self.signer_ring().map_err(wrap)?;
        let physical = self.stream_of(resource).map_err(wrap)?;
        let runs = physical.runs(signer, &self.descriptor).map_err(wrap)?;
        let subscription = {
            let writer = physical.writer();
            subscription_of(&writer.dir, &subscribed.membership_id, subscribed.task_id)
                .map_err(wrap)?
                .unwrap_or_else(|| Subscription::new(subscribed))
        };
        if subscription.state != SubscriptionState::Active {
            return Ok(None);
        }
        // The oldest run of the membership the subscription has not acknowledged through, or a
        // complete one acknowledged under an earlier incarnation of the coordinator, probed with
        // its last retained batch (WP-7.9b).
        let mut chosen = None;
        for (run, fence, last, _) in &runs {
            if !reads_run(subscribed.membership_id, *fence) {
                continue;
            }
            let acked = subscription.acked(run);
            if acked < *last {
                chosen = Some((run, None));
                break;
            }
            let earlier = matches!(
                (subscribed.coordinator_boot_id, subscription.boot(run)),
                (Some(now), Some(before)) if now != before
            );
            if earlier && let Some(probe) = retained_holding(&physical, run, acked).map_err(wrap)? {
                chosen = Some((run, Some(probe)));
                break;
            }
        }
        let Some((run, probe)) = chosen else {
            return Ok(None);
        };
        let statement = permguard_host::membership::statement_of(signer)
            .map_err(|error| error.to_string())?
            .encode()
            .map_err(|error| error.0)?;
        let budget = usize::try_from(max_bytes)
            .unwrap_or(usize::MAX)
            .saturating_sub(statement.len() + SHIP_OVERHEAD_BYTES);
        let batch = match probe {
            Some(batch) => batch,
            None => {
                let seq = subscription.acked(run) + 1;
                let Some(batch) = self
                    .batch_holding(&physical, resource, *run, seq, budget)
                    .map_err(wrap)?
                else {
                    return Ok(None);
                };
                batch
            }
        };
        let envelope = SealedBatch::decode(&batch)
            .and_then(|batch| batch.envelope_unverified())
            .map_err(wrap)?;
        let body = Ship { batch, statement }.encode().map_err(wrap)?;
        if body.len() as u64 > max_bytes {
            // Sealed for another task's wider bound, and immutable: this subscription cannot be
            // sent it, and stops rather than failing every pass (after the review).
            let writer = physical.writer();
            let mut subscription =
                subscription_of(&writer.dir, &subscribed.membership_id, subscribed.task_id)
                    .map_err(wrap)?
                    .unwrap_or_else(|| Subscription::new(subscribed));
            subscription.state = SubscriptionState::Stopped {
                reason: codes::stream::UNSHIPPABLE.to_owned(),
            };
            keep_subscription(&writer.dir, &subscription).map_err(wrap)?;
            return Ok(None);
        }
        Ok(Some(Shipment {
            request_id: format!(
                "ship-{}-{}-{:016x}",
                &envelope.run[..8],
                envelope.first_seq,
                jitter(u64::MAX - 1)
            ),
            body,
            run: *run,
            first_seq: envelope.first_seq,
            last_seq: envelope.last_seq,
        }))
    }

    fn answered(
        &self,
        subscribed: &Subscribed<'_>,
        resource: &str,
        shipment: &Shipment,
        answer: &[u8],
    ) -> Result<bool, String> {
        let wrap = |error: StreamError| error.to_string();
        if !self.ships(subscribed) {
            return Ok(false);
        }
        let answer = Answer::decode(answer).map_err(wrap)?;
        let signer = self.signer_ring().map_err(wrap)?;
        let physical = self.stream_of(resource).map_err(wrap)?;
        // What was sealed of the run: no consumer holds more than it was sent (after the review).
        let sealed = physical
            .runs(signer, &self.descriptor)
            .map_err(wrap)?
            .into_iter()
            .find(|(run, ..)| *run == shipment.run)
            .map_or(0, |(.., sealed)| sealed);
        let go_on = {
            let writer = physical.writer();
            let mut subscription =
                subscription_of(&writer.dir, &subscribed.membership_id, subscribed.task_id)
                    .map_err(wrap)?
                    .unwrap_or_else(|| Subscription::new(subscribed));
            let held = subscription.acked(&shipment.run);
            let stopped_before = matches!(subscription.state, SubscriptionState::Stopped { .. });
            // A coordinator restored from a snapshot answers under a new boot id with what it
            // held then (WP-7.9b): the first answer below the ack under another incarnation.
            let restored = match (
                subscribed.coordinator_boot_id,
                subscription.boot(&shipment.run),
            ) {
                (Some(now), Some(before)) => now != before,
                _ => false,
            };
            let deleted = if restored && answer.acked < held {
                let run_dir = writer
                    .dir
                    .subdir(BATCHES, true)
                    .and_then(|dir| dir.subdir(&hex(&shipment.run), true))
                    .map_err(|error| error.to_string())?;
                pruned_of(&run_dir).map_err(wrap)?
            } else {
                0
            };
            let go_on = match answer.outcome {
                Outcome::Ok | Outcome::OutOfOrder if answer.acked > sealed => {
                    subscription.state = SubscriptionState::Stopped {
                        reason: codes::stream::ACK_AHEAD.to_owned(),
                    };
                    false
                }
                // Restored below what was deleted: a durable producer gap, nothing reconstructed;
                // the ack stays where it was.
                Outcome::Ok | Outcome::OutOfOrder
                    if restored && answer.acked < held && answer.acked < deleted =>
                {
                    tracing::warn!(
                        event.name = "host.stream.producer_gap",
                        component = "host",
                        stream = %resource,
                        run = %hex(&shipment.run),
                        restored = answer.acked,
                        deleted,
                        "a restored coordinator needs records this producer already deleted: the \
                         subscription stops"
                    );
                    subscription.state = SubscriptionState::Stopped {
                        reason: codes::stream::PRODUCER_GAP.to_owned(),
                    };
                    false
                }
                // Restored: resent from the coordinator's position, byte for byte.
                Outcome::Ok | Outcome::OutOfOrder if restored && answer.acked < held => {
                    tracing::warn!(
                        event.name = "host.stream.coordinator_restored",
                        component = "host",
                        stream = %resource,
                        run = %hex(&shipment.run),
                        acked = held,
                        restored = answer.acked,
                        "the coordinator answers from a restored snapshot: resending from its \
                         position"
                    );
                    subscription.set_acked(shipment.run, answer.acked);
                    true
                }
                // A consumer acknowledging less than it had lost acknowledged records: an
                // incident, never a resend; the ack never moves backwards (after the review).
                Outcome::Ok | Outcome::OutOfOrder if answer.acked < held => {
                    subscription.state = SubscriptionState::Stopped {
                        reason: codes::stream::ACK_BEHIND.to_owned(),
                    };
                    false
                }
                // Short of the batch it was sent: shipped again next pass, never in a loop.
                Outcome::Ok if answer.acked < shipment.last_seq => {
                    subscription.set_acked(shipment.run, answer.acked);
                    false
                }
                Outcome::Ok => {
                    subscription.set_acked(shipment.run, answer.acked);
                    true
                }
                // The consumer's view: resent from its next sequence.
                Outcome::OutOfOrder => {
                    subscription.set_acked(shipment.run, answer.acked);
                    true
                }
                // Said when it happens (BUG-0104): the subscription waits for the membership to
                // move, and nothing ships under it until then.
                Outcome::Unverifiable => {
                    tracing::warn!(
                        event.name = "host.stream.unverifiable",
                        component = "host",
                        code = codes::stream::UNVERIFIABLE,
                        stream = %resource,
                        run = %hex(&shipment.run),
                        epoch = subscribed.epoch,
                        "the coordinator cannot verify the batch under the pins of this epoch: \
                         the subscription is paused until the membership moves"
                    );
                    subscription.state = SubscriptionState::Paused {
                        epoch: subscribed.epoch,
                    };
                    false
                }
                Outcome::Fork | Outcome::Gone | Outcome::Closed => {
                    subscription.state = SubscriptionState::Stopped {
                        reason: answer.outcome.code().to_owned(),
                    };
                    false
                }
            };
            // A subscription the coordinator stops is said when it stops, at ERROR, with its reason:
            // nothing ships under it until an operator acts (BUG-0027).
            if let SubscriptionState::Stopped { reason } = &subscription.state
                && !stopped_before
            {
                tracing::error!(
                    event.name = "host.stream.subscription_stopped",
                    component = "host",
                    code = %reason,
                    stream = %resource,
                    run = %hex(&shipment.run),
                    "the coordinator refused this stream: the subscription is stopped and nothing \
                     ships under it until an operator acts"
                );
            }
            // An answer that states a position names the incarnation that gave it; one that does
            // not, `unverifiable` above all, leaves the next its chance to be read as a restore.
            if let Some(boot) = subscribed.coordinator_boot_id
                && matches!(answer.outcome, Outcome::Ok | Outcome::OutOfOrder)
            {
                subscription.set_boot(shipment.run, boot);
            }
            // When the acknowledgement got where it stands: what the retention ages (WP-7.9b).
            if let Some(retention) = self.acknowledged_retention_secs() {
                subscription.note_acked(shipment.run, self.context.time.now_secs(), retention);
            }
            keep_subscription(&writer.dir, &subscription).map_err(wrap)?;
            go_on
        };
        self.backoff
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&Self::backoff_key(resource, subscribed));
        self.truncate(&physical).map_err(wrap)?;
        Ok(go_on)
    }

    fn deferred(&self, subscribed: &Subscribed<'_>, resource: &str) -> Result<(), String> {
        if !self.ships(subscribed) {
            return Ok(());
        }
        let now = self.monotonic_ms();
        let mut backoff = self.backoff.lock().unwrap_or_else(PoisonError::into_inner);
        let held = backoff
            .entry(Self::backoff_key(resource, subscribed))
            .or_insert((0, now));
        let ceiling = backoff_ceiling(held.0);
        held.0 = held.0.saturating_add(1);
        held.1 = now.saturating_add(jitter(ceiling));
        Ok(())
    }

    fn retain(&self, membership_id: &[u8; 16], task_ids: &[String]) -> Result<(), String> {
        let wrap = |error: StreamError| error.to_string();
        // A task dropped, or a membership that ended, fences no run any more (BUG-0198).
        self.forget_fences(membership_id, task_ids);
        self.held_by
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|(_, held, task), _| held != membership_id || task_ids.contains(task));
        let carrier = self.carrier().is_some();
        for physical in self.every().map_err(wrap)? {
            // A membership that ended leaves every run it fenced, the ones a restart ended too:
            // read before the writer is held, as reading them holds it.
            let views = match (task_ids.is_empty(), self.signer.as_deref()) {
                (true, Some(signer)) => physical.runs(signer, &self.descriptor).map_err(wrap)?,
                _ => Vec::new(),
            };
            let writer = physical.writer();
            let dir = subscriptions_dir(&writer.dir).map_err(wrap)?;
            let mut dropped = false;
            let held = subscriptions_of(&writer.dir).map_err(wrap)?;
            let local = held
                .iter()
                .any(|subscription| subscription.membership_id == LOCAL_MEMBERSHIP);
            for subscription in held {
                if subscription.membership_id == *membership_id
                    && !task_ids.contains(&subscription.task_id)
                {
                    // The open run this subscription fences outlives it: what its coordinator
                    // never acknowledged is carried into the run a live membership fences next,
                    // as for a run no membership fenced, so decisions answered while it ended
                    // still reach a coordinator (BUG-0198, BUG-0164). Marked now, while what it
                    // acknowledged is still known.
                    let open = writer
                        .run
                        .as_ref()
                        .filter(|run| {
                            !run.ended
                                && run.last_seq > 0
                                && run.statement.fence.as_ref().is_some_and(|fence| {
                                    fence.membership_id == subscription.membership_id
                                        && fence.task_id == subscription.task_id
                                })
                        })
                        .map(|run| (run.statement.run_id, run.last_seq));
                    // The latest run the ended membership fenced, open or ended, with records its
                    // coordinator never acknowledged.
                    let fenced = open.or_else(|| {
                        views
                            .iter()
                            .rev()
                            .find(|(run, fence, last, _)| {
                                *fence == Some(subscription.membership_id)
                                    && *last > subscription.acked(run)
                            })
                            .map(|(run, _, last, _)| (*run, *last))
                    });
                    if let Some((run_id, last_seq)) = fenced
                        && carrier
                        && !local
                        && read_view(&writer.dir, CARRY, format::VIEW)
                            .map_err(|error| error.to_string())?
                            .is_none()
                    {
                        let acked = subscription.acked(&run_id);
                        if acked < last_seq {
                            replace_view(
                                &writer.dir,
                                CARRY,
                                format::VIEW,
                                &encode_carry(&run_id, last_seq, acked).map_err(wrap)?,
                            )
                            .map_err(|error| error.to_string())?;
                        }
                    }
                    dir.unlink(
                        &file_name(&subscription.membership_id, &subscription.task_id)
                            .map_err(wrap)?,
                    )
                    .map_err(|error| error.to_string())?;
                    dropped = true;
                }
            }
            if dropped {
                dir.sync().map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{backoff_ceiling, jitter};

    /// `4-data-plane-decision-log.md` (Shipping): a deferral backs off with full-jitter
    /// exponential backoff, 100 ms doubled per deferral up to 30 s, and never beyond it however
    /// long the deferrals go on (iteration 04, G4).
    #[test]
    fn a_deferral_backs_off_exponentially_up_to_its_cap() {
        let ceilings: Vec<u64> = (0..12).map(backoff_ceiling).collect();
        assert_eq!(
            ceilings,
            vec![
                100, 200, 400, 800, 1_600, 3_200, 6_400, 12_800, 25_600, 30_000, 30_000, 30_000
            ]
        );
        for deferrals in [57, 58, 63, 64, 65, 1_000, u32::MAX] {
            assert_eq!(backoff_ceiling(deferrals), 30_000, "{deferrals} deferrals");
        }
    }

    /// Full jitter: the hold-off is drawn anywhere in `[0, ceiling]`, so producers deferred
    /// together do not come back together.
    #[test]
    fn the_hold_off_is_drawn_across_the_whole_window() {
        let draws: Vec<u64> = (0..2_000).map(|_| jitter(300)).collect();
        assert!(
            draws.iter().all(|draw| *draw <= 300),
            "never beyond the ceiling"
        );
        assert!(
            draws.iter().any(|draw| *draw < 30),
            "the bottom of the window"
        );
        assert!(
            draws.iter().any(|draw| *draw > 270),
            "the top of the window"
        );
        let distinct: std::collections::BTreeSet<_> = draws.iter().collect();
        assert!(distinct.len() > 100, "spread, not a few fixed values");
        assert_eq!(jitter(0), 0, "a zero ceiling holds nothing off");
    }
}
