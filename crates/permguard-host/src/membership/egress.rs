// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `audit.checkpoints` task, contract version 1 (WP-5.9; owner decisions of 2026-10-16):
//! the checkpoints a Host seals leave its volume for a coordinator that keeps them.
//!
//! ```text
//! member       task session over the trail's resource, within the task's selector
//!   ─▶ { class, checkpoint, statement, anchor? }       each checkpoint in the trail's order
//! coordinator  the envelope verified under the member's pinned `host.operations` statement,
//!              continuing the trail it keeps; kept before it is answered
//!   ─▶ { trail, checkpoint, received_at }              the envelope's digest, acknowledged
//! member       keeps the acknowledgement: retention deletes a day only once the seal that
//!              closes it is acknowledged
//! ```
//!
//! | Record           | Shape                                                                  |
//! | ---------------- | ---------------------------------------------------------------------- |
//! | checkpoint_ship  | {1 class, 2 checkpoint, 3 statement, 4? anchor}                        |
//! | checkpoint_ack   | {1 trail, 2 checkpoint, 3 received_at}                                 |
//! | egress_acks      | {1 [{1 trail, 2 name, 3 digest}]}: the member's, per membership and task |
//!
//! ```text
//! host/members/audit/<membership>/<sha256(trail)>/
//! ├── META                 the trail
//! ├── LAST                 {1 count, 2 digest}: the checkpoints kept and the last one's digest
//! ├── <count, 20 digits>.cose
//! └── ANCHOR               the member's last anchor of the trail
//! host/members/egress/<membership>-<task>.cbor     the member's acknowledgements
//! ```
//!
//! A checkpoint already kept is acknowledged again; one whose `previous_checkpoint` is not the
//! last kept is a fork of the trail, refused and kept nowhere. The first one kept may continue
//! any checkpoint: the trail before the export is the member's own.

use std::sync::Arc;

use sha2::{Digest as _, Sha256};

use permguard_core::authz::{Resource, Selector};
use permguard_core::codes;
use permguard_core::domains::protected;
use permguard_objects::cbor::Value;
use permguard_objects::cose::Sign1;

use super::member::Member;
use super::record::{RingStatement, Role, Status, TaskType};
use super::task::{TaskContext, TaskHandler};
use super::{MembershipError, Store, public_of, statement_matches};
use crate::audit::checkpoint::{Anchor, Checkpoint, MAX_CHECKPOINT_BYTES};
use crate::audit::{Class, EgressFloor, Engine};
use crate::identity::record::{Labelled, RecordError, encode, uint, uuid_text};
use crate::keys::ring::HOST_OPERATIONS;
use crate::operations::journal::Initiator;
use crate::session::Refusal;
use crate::storage::format;
use crate::storage::write::{read_view, replace_view};
use crate::time::TimeGuard;

/// The contract version this module speaks.
pub const VERSION: u64 = 1;
/// The most bytes one `audit.checkpoints` record takes: a checkpoint, a ring statement and an
/// anchor.
const MAX_RECORD_BYTES: usize = 64 * 1024;
/// The most trails one acknowledgement view names.
const MAX_TRAILS: usize = 4096;
/// The most bytes the member's acknowledgement view takes.
pub const MAX_ACKS_BYTES: usize = 1024 * 1024;
/// The most bytes the coordinator's last-kept record takes.
pub const MAX_KEPT_BYTES: usize = 128;
/// The directory of the coordinator's kept checkpoints, below the membership store.
const AUDIT: &str = "audit";
/// The directory of the member's acknowledgements, below the membership store.
const EGRESS: &str = "egress";
const META: &str = "META";
const LAST: &str = "LAST";
const ANCHOR: &str = "ANCHOR";

fn bounded(bytes: &[u8], what: &str) -> Result<(), RecordError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError(format!("{what} is out of its bound")));
    }
    Ok(())
}

/// The digest of a checkpoint envelope, as the next checkpoint and an anchor cite it.
pub fn envelope_digest(envelope: &[u8]) -> [u8; 32] {
    *crate::audit::checkpoint::envelope_digest(envelope).raw()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// What a member sends: one checkpoint of one trail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ship {
    pub class: String,
    /// The COSE_Sign1 `permguard.audit.checkpoint.v1`, as the member sealed it.
    pub checkpoint: Vec<u8>,
    /// The member's `host.operations` ring statement: what the key that signed is checked in.
    pub statement: Vec<u8>,
    /// The trail's `ANCHOR.cbor`, when retention deleted a prefix.
    pub anchor: Option<Vec<u8>>,
}

impl Ship {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.class.clone())),
            (Value::Int(2), Value::Bytes(self.checkpoint.clone())),
            (Value::Int(3), Value::Bytes(self.statement.clone())),
        ];
        if let Some(anchor) = &self.anchor {
            pairs.push((Value::Int(4), Value::Bytes(anchor.clone())));
        }
        let bytes = encode(pairs)?;
        bounded(&bytes, "a checkpoint shipment")?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a checkpoint shipment")?;
        let mut map = Labelled::read(bytes, "a checkpoint shipment")?;
        let ship = Self {
            class: map.text(1)?,
            checkpoint: map.bytes(2)?,
            statement: map.bytes(3)?,
            anchor: map.optional_bytes(4)?,
        };
        map.finish()?;
        Ok(ship)
    }
}

/// What a coordinator answers: the checkpoint it keeps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// `<class>:<resource>`.
    pub trail: String,
    /// The envelope's digest.
    pub checkpoint: [u8; 32],
    pub received_at: u64,
}

impl Ack {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Text(self.trail.clone())),
            (Value::Int(2), Value::Bytes(self.checkpoint.to_vec())),
            (Value::Int(3), uint(self.received_at)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a checkpoint acknowledgement")?;
        let mut map = Labelled::read(bytes, "a checkpoint acknowledgement")?;
        let ack = Self {
            trail: map.text(1)?,
            checkpoint: map.fixed(2)?,
            received_at: map.uint(3)?,
        };
        map.finish()?;
        Ok(ack)
    }
}

/// The last checkpoint of one trail a coordinator acknowledged, as the member keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acked {
    pub trail: String,
    /// The checkpoint's file name in the member's trail.
    pub name: String,
    pub digest: [u8; 32],
}

/// The member's acknowledgements of one membership's task.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Acks(pub Vec<Acked>);

impl Acks {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        if self.0.len() > MAX_TRAILS {
            return Err(RecordError(
                "an acknowledgement view names too many trails".to_owned(),
            ));
        }
        let mut held = self.0.clone();
        held.sort_by(|a, b| a.trail.cmp(&b.trail));
        encode(vec![(
            Value::Int(1),
            Value::Array(
                held.iter()
                    .map(|acked| {
                        Ok(Value::Map(vec![
                            (Value::Int(1), Value::Text(acked.trail.clone())),
                            (Value::Int(2), Value::Text(acked.name.clone())),
                            (Value::Int(3), Value::Bytes(acked.digest.to_vec())),
                        ]))
                    })
                    .collect::<Result<_, RecordError>>()?,
            ),
        )])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_ACKS_BYTES {
            return Err(RecordError(
                "the checkpoint acknowledgements are out of their bound".to_owned(),
            ));
        }
        let mut map = Labelled::read(bytes, "the checkpoint acknowledgements")?;
        let entries = map.array(1)?;
        map.finish()?;
        if entries.len() > MAX_TRAILS {
            return Err(RecordError(
                "an acknowledgement view names too many trails".to_owned(),
            ));
        }
        let mut held = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut map = Labelled::from_value(entry, "a checkpoint acknowledgement")?;
            held.push(Acked {
                trail: map.text(1)?,
                name: map.text(2)?,
                digest: map.fixed(3)?,
            });
            map.finish()?;
        }
        // Canonical: by trail, each once, as `encode` writes them.
        if held.windows(2).any(|pair| pair[0].trail >= pair[1].trail) {
            return Err(RecordError(
                "the checkpoint acknowledgements name each trail once, in order".to_owned(),
            ));
        }
        Ok(Self(held))
    }

    /// The last checkpoint of `trail` acknowledged.
    pub fn of(&self, trail: &str) -> Option<&Acked> {
        self.0.iter().find(|acked| acked.trail == trail)
    }

    fn keep(&mut self, acked: Acked) {
        self.0.retain(|held| held.trail != acked.trail);
        self.0.push(acked);
    }
}

fn refusal(code: &'static str, reason: impl Into<String>) -> Refusal {
    Refusal {
        code,
        reason: reason.into(),
    }
}

fn invalid(reason: impl Into<String>) -> Refusal {
    refusal(codes::common::INVALID_ARGUMENT, reason)
}

fn unavailable(reason: impl Into<String>) -> Refusal {
    refusal(codes::common::UNAVAILABLE, reason)
}

/// The coordinator's handler: verifies, keeps and acknowledges a member's checkpoints.
pub struct AuditCheckpoints {
    pub store: Arc<Store>,
    pub time: Arc<TimeGuard>,
}

impl AuditCheckpoints {
    /// The checkpoint `ship` carries, verified under the member's pinned `host.operations`
    /// statement, of the trail `trail`, sealed by the member.
    fn verified(
        &self,
        context: &TaskContext,
        ship: &Ship,
        trail: &str,
    ) -> Result<Checkpoint, Refusal> {
        let held = self
            .store
            .membership(&context.membership_id)
            .ok_or_else(|| invalid("no such membership"))?;
        let pins = held
            .manifest
            .as_ref()
            .map(|(manifest, ..)| manifest.ring_pins.clone())
            .unwrap_or_default();
        let statement = RingStatement::decode(&ship.statement)
            .map_err(|error| invalid(format!("the ring statement: {error}")))?;
        let pinned = pins.iter().any(|pin| {
            pin.owner == Role::Member
                && pin.ring == HOST_OPERATIONS
                && statement_matches(&statement, pin).is_ok()
        });
        if !pinned {
            return Err(invalid(
                "the ring statement is not the member's pinned `host.operations` set",
            ));
        }
        if ship.checkpoint.len() > MAX_CHECKPOINT_BYTES {
            return Err(invalid("a checkpoint over its bound"));
        }
        let sign1 = Sign1::decode(&ship.checkpoint)
            .map_err(|error| invalid(format!("the checkpoint: {error}")))?;
        let kid = String::from_utf8(
            sign1
                .header()
                .map_err(|error| invalid(format!("the checkpoint: {error}")))?
                .kid,
        )
        .map_err(|_| invalid("the checkpoint's kid is not text"))?;
        let (_, suite, public_key) = statement
            .keys
            .iter()
            .filter_map(|text| public_of(text))
            .find(|(held, ..)| *held == kid)
            .ok_or_else(|| invalid(format!("signed by `{kid}`, a key the statement lacks")))?;
        let payload = sign1
            .verify(suite, &public_key, protected::AUDIT_CHECKPOINT)
            .map_err(|error| invalid(format!("the checkpoint does not verify: {error}")))?;
        let checkpoint = Checkpoint::decode(payload)
            .map_err(|error| invalid(format!("the checkpoint: {error}")))?;
        if checkpoint.trail != trail {
            return Err(invalid(format!(
                "a checkpoint of `{}` shipped as `{trail}`",
                checkpoint.trail
            )));
        }
        if checkpoint.host_id != context.member {
            return Err(invalid("a checkpoint another Host sealed"));
        }
        Ok(checkpoint)
    }
}

impl TaskHandler for AuditCheckpoints {
    fn handle(&self, context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal> {
        let ship = Ship::decode(body).map_err(|error| invalid(error.0))?;
        let class = Class::parse(&ship.class)
            .ok_or_else(|| invalid(format!("`{}` is not an audit class", ship.class)))?;
        let trail = format!("{}:{}", class.as_str(), context.resource);
        let checkpoint = self.verified(context, &ship, &trail)?;
        let anchor = match &ship.anchor {
            Some(bytes) => {
                let anchor = Anchor::decode(bytes)
                    .map_err(|error| invalid(format!("the anchor: {error}")))?;
                if anchor.trail != trail {
                    return Err(invalid("an anchor of another trail"));
                }
                Some((bytes.as_slice(), *anchor.checkpoint.raw()))
            }
            None => None,
        };
        let digest = envelope_digest(&ship.checkpoint);
        self.store
            .keep_checkpoint(
                &context.membership_id,
                &trail,
                &ship.checkpoint,
                &checkpoint,
                digest,
                anchor,
            )
            .map_err(|error| match error {
                MembershipError::Unverified(reason) => invalid(reason),
                MembershipError::Invalid(reason) => {
                    tracing::error!(
                        event.name = "host.audit_checkpoint_forked",
                        component = "host",
                        membership_id = %uuid_text(&context.membership_id),
                        trail = %trail,
                        "a member's checkpoint does not continue the trail kept: refused"
                    );
                    refusal(codes::stream::FORK, reason)
                }
                other => unavailable(other.to_string()),
            })?;
        Ack {
            trail,
            checkpoint: digest,
            received_at: self.time.now_secs(),
        }
        .encode()
        .map_err(|error| unavailable(error.0))
    }
}

/// The last checkpoint a coordinator kept of a trail: how many it keeps, and its digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kept {
    pub count: u64,
    pub digest: [u8; 32],
}

impl Kept {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), uint(self.count)?),
            (Value::Int(2), Value::Bytes(self.digest.to_vec())),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_KEPT_BYTES {
            return Err(RecordError(
                "the last checkpoint kept is out of its bound".to_owned(),
            ));
        }
        let mut map = Labelled::read(bytes, "the last checkpoint kept")?;
        let kept = Self {
            count: map.uint(1)?,
            digest: map.fixed(2)?,
        };
        map.finish()?;
        Ok(kept)
    }
}

/// `(count, digest)` of the last checkpoint kept of a trail.
fn last_of(bytes: &[u8]) -> Result<(u64, [u8; 32]), RecordError> {
    Kept::decode(bytes).map(|kept| (kept.count, kept.digest))
}

impl Store {
    /// Keeps `envelope`, a member's checkpoint of `trail`, when it continues what is kept: an
    /// [`MembershipError::Invalid`] when it forks the trail, nothing kept.
    fn keep_checkpoint(
        &self,
        membership_id: &[u8; 16],
        trail: &str,
        envelope: &[u8],
        checkpoint: &Checkpoint,
        digest: [u8; 32],
        anchor: Option<(&[u8], [u8; 32])>,
    ) -> Result<(), MembershipError> {
        let _keeping = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = self
            .dir
            .subdir(AUDIT, true)?
            .subdir(&hex(membership_id), true)?
            .subdir(&hex(&Sha256::digest(trail.as_bytes())), true)?;
        let last = read_view(&dir, LAST, format::VIEW)?
            .map(|bytes| last_of(&bytes))
            .transpose()?;
        let count = match last {
            // Shipped again: already kept, acknowledged again.
            Some((_, held)) if held == digest => return Ok(()),
            Some((count, held)) => {
                if *checkpoint.previous_checkpoint.raw() != held {
                    // An older one shipped again is kept already: acknowledged, nothing written.
                    for at in 1..=count {
                        if read_view(&dir, &format!("{at:020}.cose"), format::VIEW)?.as_deref()
                            == Some(envelope)
                        {
                            return Ok(());
                        }
                    }
                    return Err(MembershipError::Invalid(format!(
                        "the checkpoint does not continue the trail `{trail}` as kept"
                    )));
                }
                count + 1
            }
            None => 1,
        };
        // An anchor names a seal the coordinator keeps, or the one shipped with it (after the
        // review): never one outside the chain.
        if let Some((_, cited)) = anchor
            && cited != digest
            && !(1..count).any(|at| {
                read_view(&dir, &format!("{at:020}.cose"), format::VIEW)
                    .ok()
                    .flatten()
                    .is_some_and(|held| envelope_digest(&held) == cited)
            })
        {
            return Err(MembershipError::Unverified(
                "the anchor names a checkpoint the coordinator does not keep".to_owned(),
            ));
        }
        if read_view(&dir, META, format::VIEW)?.is_none() {
            replace_view(&dir, META, format::VIEW, trail.as_bytes())?;
        }
        replace_view(&dir, &format!("{count:020}.cose"), format::VIEW, envelope)?;
        if let Some((anchor, _)) = anchor {
            replace_view(&dir, ANCHOR, format::VIEW, anchor)?;
        }
        replace_view(&dir, LAST, format::VIEW, &Kept { count, digest }.encode()?)?;
        Ok(())
    }

    /// The checkpoints a coordinator keeps of `membership_id`'s `trail`, in the order kept.
    pub fn kept_checkpoints(
        &self,
        membership_id: &[u8; 16],
        trail: &str,
    ) -> Result<Vec<Vec<u8>>, MembershipError> {
        let audit = self.dir.subdir(AUDIT, true)?;
        let member = hex(membership_id);
        if !audit.subdirs()?.contains(&member) {
            return Ok(Vec::new());
        }
        let member = audit.subdir(&member, false)?;
        let digest = hex(&Sha256::digest(trail.as_bytes()));
        if !member.subdirs()?.contains(&digest) {
            return Ok(Vec::new());
        }
        let dir = member.subdir(&digest, false)?;
        let Some((count, _)) = read_view(&dir, LAST, format::VIEW)?
            .map(|bytes| last_of(&bytes))
            .transpose()?
        else {
            return Ok(Vec::new());
        };
        (1..=count)
            .map(|at| {
                read_view(&dir, &format!("{at:020}.cose"), format::VIEW)?.ok_or_else(|| {
                    MembershipError::Storage(format!("checkpoint {at} of `{trail}` is missing"))
                })
            })
            .collect()
    }

    /// The member's acknowledgements of `membership_id`'s task `task_id`.
    pub fn egress_acks(
        &self,
        membership_id: &[u8; 16],
        task_id: &str,
    ) -> Result<Acks, MembershipError> {
        let dir = self.dir.subdir(EGRESS, true)?;
        Ok(
            read_view(&dir, &acks_name(membership_id, task_id), format::VIEW)?
                .map(|bytes| Acks::decode(&bytes))
                .transpose()?
                .unwrap_or_default(),
        )
    }

    fn keep_egress_ack(
        &self,
        membership_id: &[u8; 16],
        task_id: &str,
        acked: Acked,
    ) -> Result<(), MembershipError> {
        let _keeping = self
            .keeping
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = self.dir.subdir(EGRESS, true)?;
        let name = acks_name(membership_id, task_id);
        let mut acks = read_view(&dir, &name, format::VIEW)?
            .map(|bytes| Acks::decode(&bytes))
            .transpose()?
            .unwrap_or_default();
        acks.keep(acked);
        replace_view(&dir, &name, format::VIEW, &acks.encode()?)?;
        Ok(())
    }

    /// The `audit.checkpoints` tasks that export `resource`'s trails: every task of that type of
    /// a live membership this Host is a member of whose selector takes the resource, with
    /// whether it is required.
    pub fn exporting(&self, resource: &str) -> Vec<([u8; 16], String, bool)> {
        let Ok(resource) = Resource::parse(resource) else {
            return Vec::new();
        };
        let mut found = Vec::new();
        for (id, held) in self.memberships() {
            if held.role != Role::Member
                || matches!(
                    held.status,
                    Status::Revoked | Status::Rejected | Status::Expired | Status::Orphaned
                )
            {
                continue;
            }
            let Some((manifest, ..)) = &held.manifest else {
                continue;
            };
            for task in &manifest.tasks {
                if task.task_type == TaskType::AuditCheckpoints && takes(&task.selector, &resource)
                {
                    found.push((id, task.task_id.clone(), task.required));
                }
            }
        }
        found
    }
}

/// Whether `selector` takes `resource`.
fn takes(selector: &Selector, resource: &Resource) -> bool {
    selector.contains(resource)
}

/// Where a trail's checkpoints not yet acknowledged start in `listing` (after the review): after
/// the acknowledged one, matched by name and digest; from the first when the acknowledged one was
/// rewritten since, so the coordinator refuses it as a fork. Refused when the listing left older
/// checkpoints out and the acknowledged one is not among those shown: nothing is skipped.
pub fn pending_from(
    listing: &crate::audit::query::CheckpointList,
    acked: Option<&Acked>,
) -> Result<usize, String> {
    let found = acked.and_then(|acked| {
        listing
            .files
            .iter()
            .position(|file| file.name == acked.name)
            .map(|at| {
                (
                    at,
                    envelope_digest(&listing.files[at].envelope) == acked.digest,
                )
            })
    });
    match found {
        Some((at, true)) => Ok(at + 1),
        // Rewritten since it was acknowledged: shipped again from the first, refused as a fork.
        Some((_, false)) => Ok(0),
        None if listing.omitted > 0 => Err(format!(
            "{} older checkpoints are left out of the listing and none shown is acknowledged",
            listing.omitted
        )),
        None => Ok(0),
    }
}

fn acks_name(membership_id: &[u8; 16], task_id: &str) -> String {
    format!("{}-{task_id}.cbor", hex(membership_id))
}

/// What the export allows retention to delete (WP-5.9, owner decision): while a required task
/// exports a trail, the last checkpoint every such task acknowledged.
pub struct ExportFloor {
    pub store: Arc<Store>,
}

impl EgressFloor for ExportFloor {
    fn acknowledged(&self, class: Class, resource: &str) -> Option<Option<String>> {
        let trail = format!("{}:{resource}", class.as_str());
        let required: Vec<_> = self
            .store
            .exporting(resource)
            .into_iter()
            .filter(|(.., required)| *required)
            .collect();
        if required.is_empty() {
            return None;
        }
        // The least acknowledged of the required tasks; nothing while one acknowledged nothing,
        // or its acknowledgements cannot be read.
        let mut least: Option<String> = None;
        for (id, task_id, _) in &required {
            let acked = self
                .store
                .egress_acks(id, task_id)
                .ok()
                .and_then(|acks| acks.of(&trail).map(|acked| acked.name.clone()));
            let Some(acked) = acked else {
                return Some(None);
            };
            least = Some(match least {
                Some(held)
                    if crate::audit::checkpoint::order_of(&held)
                        <= crate::audit::checkpoint::order_of(&acked) =>
                {
                    held
                }
                _ => acked,
            });
        }
        Some(least)
    }
}

impl Member<'_> {
    /// Ships to every `audit.checkpoints` task the checkpoints of the trails it exports that it
    /// has not acknowledged, in each trail's order (WP-5.9): the periodic pass. A task whose
    /// coordinator refuses or cannot be reached stops there, logged; the next pass resumes.
    /// Answers how many checkpoints were acknowledged.
    pub async fn export_checkpoints(&self, initiator: Initiator, engine: &Engine) -> usize {
        let trails = match engine.trails_held() {
            Ok(trails) => trails,
            Err(error) => {
                tracing::warn!(
                    event.name = "host.audit_export_failed",
                    component = "host",
                    error = %error,
                    "the audit trails could not be listed: the next pass tries again"
                );
                return 0;
            }
        };
        let statement = match self
            .rings
            .iter()
            .find(|ring| ring.id() == HOST_OPERATIONS)
            .map(|ring| super::statement_of(ring).and_then(|statement| Ok(statement.encode()?)))
        {
            Some(Ok(statement)) => statement,
            Some(Err(error)) => {
                tracing::warn!(
                    event.name = "host.audit_export_failed",
                    component = "host",
                    error = %error,
                    "the operations ring's statement could not be read: nothing is exported"
                );
                return 0;
            }
            None => return 0,
        };
        let mut acknowledged = 0;
        for (class, resource) in trails {
            for (id, task_id, _) in self.store.exporting(&resource) {
                match self
                    .export_trail(
                        &initiator, engine, &statement, &id, &task_id, class, &resource,
                    )
                    .await
                {
                    Ok(count) => acknowledged += count,
                    Err(error) => tracing::warn!(
                        event.name = "host.audit_export_failed",
                        component = "host",
                        membership_id = %uuid_text(&id),
                        task = %task_id,
                        class = class.as_str(),
                        resource = %resource,
                        error = %error,
                        "audit checkpoints could not be exported: the next pass tries again"
                    ),
                }
            }
        }
        acknowledged
    }

    #[allow(clippy::too_many_arguments)]
    async fn export_trail(
        &self,
        initiator: &Initiator,
        engine: &Engine,
        statement: &[u8],
        id: &[u8; 16],
        task_id: &str,
        class: Class,
        resource: &str,
    ) -> Result<usize, MembershipError> {
        let storage = |error: String| MembershipError::Storage(error);
        let trail = format!("{}:{resource}", class.as_str());
        let listing = engine
            .checkpoints(class, resource, None)
            .map_err(|error| storage(format!("{error:?}")))?;
        let acked = self.store.egress_acks(id, task_id)?;
        let from = pending_from(&listing, acked.of(&trail)).map_err(storage)?;
        let files = listing.files;
        let pending = &files[from..];
        if pending.is_empty() {
            return Ok(0);
        }
        let anchor = engine
            .anchor_bytes(class, resource)
            .map_err(|error| storage(error.to_string()))?;
        let mut session = self
            .open_task(initiator.clone(), id, task_id, resource, Vec::new())
            .await?;
        let mut count = 0;
        for (at, file) in pending.iter().enumerate() {
            let digest = envelope_digest(&file.envelope);
            let body = Ship {
                class: class.as_str().to_owned(),
                checkpoint: file.envelope.clone(),
                statement: statement.to_vec(),
                // The anchor once a session, with the first checkpoint it ships.
                anchor: if at == 0 { anchor.clone() } else { None },
            }
            .encode()?;
            let answer = session
                .send(&format!("checkpoint-{}", hex(&digest)), body)
                .await?;
            let ack = Ack::decode(&answer)?;
            if ack.trail != trail || ack.checkpoint != digest {
                return Err(MembershipError::Unverified(
                    "the coordinator acknowledged another checkpoint".to_owned(),
                ));
            }
            self.store.keep_egress_ack(
                id,
                task_id,
                Acked {
                    trail: trail.clone(),
                    name: file.name.clone(),
                    digest,
                },
            )?;
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// A checkpoint of `security:host` whose previous is `previous`; its envelope is `bytes`, the
    /// store keeping what the handler verified.
    fn checkpoint(previous: [u8; 32]) -> Checkpoint {
        Checkpoint {
            trail: "security:host".to_owned(),
            period: "2026-10-16".to_owned(),
            first_seq: 0,
            last_seq: 1,
            head_digest: permguard_objects::Digest::from_raw([1; 32]),
            previous_checkpoint: permguard_objects::Digest::from_raw(previous),
            host_id: [2; 16],
            key_set_epoch: 1,
            created_at: 1,
        }
    }

    /// The store keeps a trail's checkpoints in the order they continue it: one shipped again,
    /// last or older, is acknowledged and kept once; one that continues another is refused and
    /// nothing kept.
    #[test]
    fn a_coordinator_keeps_a_trail_in_its_order_and_refuses_a_fork() {
        let root = crate::api::testing::scratch("egress-store");
        let volume = crate::storage::volume::Volume::claim(
            &root,
            permguard_core::assurance::AssuranceProfile::Development,
        )
        .expect("claimed");
        let store = Store::open(&volume).expect("the store");
        let member = [9; 16];
        let trail = "security:host";
        let first = b"first".to_vec();
        let second = b"second".to_vec();
        let (one, two) = (envelope_digest(&first), envelope_digest(&second));
        store
            .keep_checkpoint(&member, trail, &first, &checkpoint([0; 32]), one, None)
            .expect("the first may continue anything");
        store
            .keep_checkpoint(
                &member,
                trail,
                &second,
                &checkpoint(one),
                two,
                Some((b"anchor".as_slice(), one)),
            )
            .expect("the second continues it, its anchor citing the first");
        let third = b"third".to_vec();
        assert!(
            matches!(
                store.keep_checkpoint(
                    &member,
                    trail,
                    &third,
                    &checkpoint(two),
                    envelope_digest(&third),
                    Some((b"anchor".as_slice(), [3; 32])),
                ),
                Err(MembershipError::Unverified(_))
            ),
            "an anchor citing a checkpoint not kept"
        );
        for (again, digest) in [(&second, two), (&first, one)] {
            store
                .keep_checkpoint(&member, trail, again, &checkpoint([7; 32]), digest, None)
                .expect("shipped again: acknowledged");
        }
        let forked = b"forked".to_vec();
        assert!(matches!(
            store.keep_checkpoint(
                &member,
                trail,
                &forked,
                &checkpoint(one),
                envelope_digest(&forked),
                None
            ),
            Err(MembershipError::Invalid(_))
        ));
        assert_eq!(
            store.kept_checkpoints(&member, trail).expect("kept"),
            vec![first, second]
        );
        assert!(
            store
                .kept_checkpoints(&[8; 16], trail)
                .expect("kept")
                .is_empty()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    /// Where the pending checkpoints start: after the acknowledged one when its digest still
    /// matches, from the first when it was rewritten, refused when the listing hides older ones
    /// and none shown is acknowledged.
    #[test]
    fn the_pending_checkpoints_start_after_the_acknowledged_one_and_nothing_is_skipped() {
        use crate::audit::query::{CheckpointFile, CheckpointList};
        let file = |name: &str, envelope: &[u8]| CheckpointFile {
            name: name.to_owned(),
            envelope: envelope.to_vec(),
            witness: None,
        };
        let listing = CheckpointList {
            files: vec![
                file("2026-10-15.cose", b"a"),
                file("2026-10-16.1.cose", b"b"),
            ],
            omitted: 0,
        };
        let acked = |name: &str, digest: [u8; 32]| Acked {
            trail: "security:host".to_owned(),
            name: name.to_owned(),
            digest,
        };
        assert_eq!(pending_from(&listing, None), Ok(0));
        assert_eq!(
            pending_from(
                &listing,
                Some(&acked("2026-10-15.cose", envelope_digest(b"a")))
            ),
            Ok(1)
        );
        assert_eq!(
            pending_from(&listing, Some(&acked("2026-10-15.cose", [9; 32]))),
            Ok(0),
            "rewritten since: shipped again from the first"
        );
        assert_eq!(
            pending_from(&listing, Some(&acked("2026-10-01.cose", [9; 32]))),
            Ok(0)
        );
        let truncated = CheckpointList {
            omitted: 3,
            ..listing.clone()
        };
        assert!(pending_from(&truncated, None).is_err());
        assert!(pending_from(&truncated, Some(&acked("2026-10-01.cose", [9; 32]))).is_err());
        assert_eq!(
            pending_from(
                &truncated,
                Some(&acked("2026-10-16.1.cose", envelope_digest(b"b")))
            ),
            Ok(2)
        );
    }

    #[test]
    fn the_records_round_trip_and_refuse_what_they_do_not_name() {
        let ship = Ship {
            class: "security".to_owned(),
            checkpoint: vec![1, 2, 3],
            statement: vec![4, 5],
            anchor: Some(vec![6]),
        };
        assert_eq!(
            Ship::decode(&ship.encode().expect("encodes")).expect("decodes"),
            ship
        );
        let bare = Ship {
            anchor: None,
            ..ship
        };
        assert_eq!(
            Ship::decode(&bare.encode().expect("encodes")).expect("decodes"),
            bare
        );
        let ack = Ack {
            trail: "security:host".to_owned(),
            checkpoint: [7; 32],
            received_at: 9,
        };
        assert_eq!(
            Ack::decode(&ack.encode().expect("encodes")).expect("decodes"),
            ack
        );
        let acks = Acks(vec![
            Acked {
                trail: "security:host".to_owned(),
                name: "2026-10-16.1.cose".to_owned(),
                digest: [8; 32],
            },
            Acked {
                trail: "operations:host".to_owned(),
                name: "2026-10-15.cose".to_owned(),
                digest: [9; 32],
            },
        ]);
        let decoded = Acks::decode(&acks.encode().expect("encodes")).expect("decodes");
        assert_eq!(decoded.of("security:host"), acks.of("security:host"));
        assert_eq!(decoded.0.len(), 2);
        let unknown = encode(vec![
            (Value::Int(1), Value::Text("security:host".to_owned())),
            (Value::Int(2), Value::Bytes(vec![0; 32])),
            (Value::Int(3), Value::Int(1)),
            (Value::Int(9), Value::Int(1)),
        ])
        .expect("encodes");
        assert!(Ack::decode(&unknown).is_err(), "an unknown label");
        let entry = |trail: &str| {
            Value::Map(vec![
                (Value::Int(1), Value::Text(trail.to_owned())),
                (Value::Int(2), Value::Text("2026-10-16.cose".to_owned())),
                (Value::Int(3), Value::Bytes(vec![0; 32])),
            ])
        };
        for trails in [
            ["security:host", "access:host"],
            ["access:host", "access:host"],
        ] {
            let unordered = encode(vec![(
                Value::Int(1),
                Value::Array(trails.iter().map(|trail| entry(trail)).collect()),
            )])
            .expect("encodes");
            assert!(
                Acks::decode(&unordered).is_err(),
                "each trail once, in order: {trails:?}"
            );
        }
        assert!(
            Ship::decode(&vec![0; MAX_RECORD_BYTES + 1]).is_err(),
            "out of its bound"
        );
    }
}
