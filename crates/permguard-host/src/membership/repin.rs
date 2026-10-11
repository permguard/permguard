// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The ring re-pin protocol (WP-4.5; owner decisions of 2026-10-11).
//!
//! ```text
//! member       prepublishes a key: its ring's epoch rises, the identity binds the new set
//!   ─▶ task session: `kind: repin` { ring statement }
//! coordinator  verifies the binding under the pinned identity, its continuity against the pin
//!   ─▶ the manifest at the next epoch: the new pin current, the replaced one `retiring`
//!   ─▶ answers that manifest and a new lease on the same connection
//! member       persists the manifest ─▶ its ring may activate the key (the activation gate)
//!   ─▶ seals the old key's tails ─▶ `kind: cutover` { ring, epoch, streams [{stream, from_seq}] }
//! coordinator  journals the cutover before it answers: the old set verifies below each stream's
//!              `from_seq`, the new one at or above
//!   ─▶ `acknowledge(stream, through_seq)` as the stream consumer takes the old spans (WP-5.x)
//!   ─▶ once every stream is acknowledged below its cutover, a revision drops the retiring pin
//! ```
//!
//! The reverse direction: a coordinator whose `control.attest` or `host.operations` moved revises
//! every membership it coordinates (a successor re-pins its rings as they are), and its ring
//! activates the new key only once each member received that revision, by a lease or a sync.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::record::{
    Acknowledgement, Cutover, Delivered, Kind, Manifest, RingPin, RingStatement, Role, Status,
};
use super::{Coordinator, Held, MembershipError, Store, hex, verify_statement};
use crate::identity::Verified;
use crate::identity::record::RecordError;
use crate::operations::mutation::Applying;
use crate::storage::format;
use crate::storage::write::{read_view, replace_view};

/// A re-pin, a mutation of the store (`security`).
pub const AUDIT_REPINNED: &str = "host.membership.repinned";
/// A cutover journaled (`security`).
pub const AUDIT_CUTOVER: &str = "host.membership.cutover";
/// A stream's old spans acknowledged (`security`).
pub const AUDIT_ACKNOWLEDGED: &str = "host.membership.acknowledged";
/// A retiring pin dropped once every stream was acknowledged (`security`).
pub const AUDIT_PIN_RETIRED: &str = "host.membership.pin_retired";
/// The operations.
pub const REPIN: &str = "members.repin";
pub const CUTOVER: &str = "members.cutover";
pub const ACKNOWLEDGE: &str = "members.acknowledge";
pub const RETIRE_PIN: &str = "members.retire_pin";

/// Where a coordinator keeps the last manifest epoch each member received.
const DELIVERED: &str = "manifest.delivered";

/// A ring's cutover as the coordinator journaled it, and what was acknowledged since.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CutoverState {
    /// The ring epoch the re-pin accepted.
    pub epoch: u64,
    /// Each stream's first sequence under the new set.
    pub streams: BTreeMap<String, u64>,
    /// Each stream's spans under the old set acknowledged through this sequence.
    pub acknowledged: BTreeMap<String, u64>,
}

impl CutoverState {
    /// Whether every stream is acknowledged below its cutover.
    pub fn complete(&self) -> bool {
        self.streams.iter().all(|(stream, from)| {
            *from == 0
                || self
                    .acknowledged
                    .get(stream)
                    .is_some_and(|through| through.saturating_add(1) >= *from)
        })
    }
}

/// Applies a cutover or acknowledgement entry to `cutovers`.
pub(super) fn apply(
    cutovers: &mut BTreeMap<([u8; 16], String), CutoverState>,
    subject: [u8; 16],
    kind: Kind,
    detail: &[u8],
) -> Result<(), RecordError> {
    match kind {
        Kind::Cutover => {
            let cutover = Cutover::decode(detail)?;
            let state = cutovers.entry((subject, cutover.ring.clone())).or_default();
            if state.epoch != cutover.epoch {
                *state = CutoverState {
                    epoch: cutover.epoch,
                    ..CutoverState::default()
                };
            }
            for (stream, from) in cutover.streams {
                match state.streams.get(&stream) {
                    Some(held) if *held != from => {
                        return Err(RecordError(format!(
                            "the cutover of `{stream}` moved from {held} to {from}"
                        )));
                    }
                    _ => {
                        state.streams.insert(stream, from);
                    }
                }
            }
            Ok(())
        }
        Kind::Acknowledged => {
            let acknowledgement = Acknowledgement::decode(detail)?;
            let state = cutovers
                .get_mut(&(subject, acknowledgement.ring.clone()))
                .filter(|state| state.epoch == acknowledgement.epoch)
                .ok_or_else(|| RecordError("an acknowledgement of no cutover".to_owned()))?;
            if !state.streams.contains_key(&acknowledgement.stream) {
                return Err(RecordError(
                    "an acknowledgement of a stream the cutover names not".to_owned(),
                ));
            }
            let through = state
                .acknowledged
                .entry(acknowledgement.stream)
                .or_default();
            *through = (*through).max(acknowledgement.through_seq);
            Ok(())
        }
        _ => Err(RecordError("not a cutover entry".to_owned())),
    }
}

/// What a re-pin comes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Repin {
    /// The exact current set: nothing to issue.
    Retry,
    /// The next set: this manifest, the new pin current and the replaced one retiring.
    Successor(Box<Manifest>),
}

/// The kids of a statement's keys.
fn kids(keys: &[String]) -> Vec<String> {
    keys.iter()
        .filter_map(|text| serde_json::from_str::<serde_json::Value>(text).ok())
        .filter_map(|jwk| {
            jwk.get("kid")
                .and_then(|kid| kid.as_str())
                .map(str::to_owned)
        })
        .collect()
}

/// The current pin `manifest` holds for `owner`'s `ring`.
fn current<'m>(manifest: &'m Manifest, owner: Role, ring: &str) -> Option<&'m RingPin> {
    manifest
        .ring_pins
        .iter()
        .find(|pin| pin.owner == owner && pin.ring == ring && !pin.retiring)
}

/// Whether `manifest` keeps a retiring pin for `owner`'s `ring`.
fn retiring(manifest: &Manifest, owner: Role, ring: &str) -> bool {
    manifest
        .ring_pins
        .iter()
        .any(|pin| pin.owner == owner && pin.ring == ring && pin.retiring)
}

fn active_manifest(held: &Held) -> Result<&Manifest, MembershipError> {
    if held.role != Role::Coordinator {
        return Err(MembershipError::Unknown(
            "this Host is not the coordinator of that membership".to_owned(),
        ));
    }
    if let Some(seen) = held.held_epoch {
        return Err(MembershipError::Held(format!(
            "held for review since epoch {seen} was named"
        )));
    }
    match &held.manifest {
        Some((manifest, ..)) if held.status == Status::Active => Ok(manifest),
        _ => Err(MembershipError::Transition {
            from: held.status,
            to: Status::Active,
        }),
    }
}

impl Store {
    /// The member's statement `pin` names: journaled with a manifest at a re-pin, or presented at
    /// enrollment.
    pub(super) fn member_statement(&self, id: &[u8; 16], pin: &RingPin) -> Option<RingStatement> {
        let state = self.read();
        state
            .statements
            .range((*id, 0)..=(*id, u64::MAX))
            .rev()
            .flat_map(|(_, statements)| statements.iter())
            .find(|statement| statement.ring == pin.ring && statement.binding == pin.binding)
            .cloned()
            .or_else(|| {
                state.memberships.get(id).and_then(|held| {
                    held.request
                        .ring_statements
                        .iter()
                        .find(|statement| {
                            statement.ring == pin.ring && statement.binding == pin.binding
                        })
                        .cloned()
                })
            })
    }

    /// Checks `statement`, which `member` presents for its ring of `id`, against the pin: its
    /// binding under the pinned identity, then its continuity (WP-4.5).
    pub fn check_repin(
        &self,
        coordinator: &Coordinator<'_>,
        id: &[u8; 16],
        statement: &RingStatement,
        member: &Verified,
        now: u64,
    ) -> Result<Repin, MembershipError> {
        let held = self.held(id)?;
        let manifest = active_manifest(&held)?;
        let pin = current(manifest, Role::Member, &statement.ring).ok_or_else(|| {
            MembershipError::Invalid(format!(
                "the membership pins no `{}` of its member",
                statement.ring
            ))
        })?;
        let binding = verify_statement(statement, member, Some(now))?;
        match crate::keys::ring::continuity(
            Some((pin.epoch, pin.key_set_digest)),
            binding.epoch,
            &binding.key_set_digest,
            true,
        ) {
            crate::keys::ring::Continuity::Retry => return Ok(Repin::Retry),
            crate::keys::ring::Continuity::Rollback => {
                return Err(MembershipError::NotSuccessor(format!(
                    "`{}` at epoch {} is below the pinned {}: a rollback",
                    statement.ring, binding.epoch, pin.epoch
                )));
            }
            crate::keys::ring::Continuity::Equivocation => {
                return Err(MembershipError::Equivocation(format!(
                    "`{}` at the pinned epoch {} with another set",
                    statement.ring, pin.epoch
                )));
            }
            crate::keys::ring::Continuity::Accept | crate::keys::ring::Continuity::Unbound => {}
        }
        // One grace at a time: the replaced set's spans are acknowledged before another re-pin,
        // unless the new set only removes keys, an archive, which no cutover needs (owner
        // decision, after the review): then the current pin alone is replaced.
        if retiring(manifest, Role::Member, &statement.ring) {
            let held = self
                .member_statement(id, pin)
                .map(|held| kids(&held.keys))
                .unwrap_or_default();
            let presented = kids(&statement.keys);
            if presented.is_empty()
                || presented.len() >= held.len()
                || !presented.iter().all(|kid| held.contains(kid))
            {
                return Err(MembershipError::Transition {
                    from: Status::Active,
                    to: Status::Active,
                });
            }
            let mut next = self.check_successor(coordinator, id, Status::Active, None, now)?;
            for held in &mut next.ring_pins {
                if held.owner == Role::Member && held.ring == statement.ring && !held.retiring {
                    held.epoch = binding.epoch;
                    held.key_set_digest = binding.key_set_digest;
                    held.binding = statement.binding.clone();
                }
            }
            return Ok(Repin::Successor(Box::new(next)));
        }
        let replaced = pin.clone();
        let mut next = self.check_successor(coordinator, id, Status::Active, None, now)?;
        next.ring_pins
            .retain(|pin| !(pin.owner == Role::Member && pin.ring == statement.ring));
        next.ring_pins.push(RingPin {
            owner: Role::Member,
            ring: statement.ring.clone(),
            epoch: binding.epoch,
            key_set_digest: binding.key_set_digest,
            binding: statement.binding.clone(),
            retiring: false,
        });
        next.ring_pins.push(RingPin {
            retiring: true,
            ..replaced
        });
        Ok(Repin::Successor(Box::new(next)))
    }

    /// Journals `cutover` of `id`, durably, before the caller answers: only for a ring re-pinned
    /// at its epoch, each stream's `from_seq` fixed once (WP-4.5).
    pub fn record_cutover(
        &self,
        applying: &Applying<'_>,
        id: &[u8; 16],
        cutover: &Cutover,
        now: u64,
    ) -> Result<(), MembershipError> {
        let writing = self.begin();
        let held = self.held(id)?;
        let manifest = active_manifest(&held)?;
        let pinned = current(manifest, Role::Member, &cutover.ring)
            .is_some_and(|pin| pin.epoch == cutover.epoch)
            && retiring(manifest, Role::Member, &cutover.ring);
        if !pinned {
            return Err(MembershipError::Invalid(format!(
                "no re-pin of `{}` at epoch {} is in its grace: the cutover is outside it",
                cutover.ring, cutover.epoch
            )));
        }
        let known = self
            .read()
            .cutovers
            .get(&(*id, cutover.ring.clone()))
            .filter(|state| state.epoch == cutover.epoch)
            .cloned();
        // The first cutover of the epoch is journaled, a stream-less one included.
        let mut fresh = known.is_none();
        let state = known.unwrap_or_default();
        for (stream, from) in &cutover.streams {
            match state.streams.get(stream) {
                Some(held) if held != from => {
                    return Err(MembershipError::Equivocation(format!(
                        "the cutover of `{stream}` is fixed at {held}"
                    )));
                }
                Some(_) => {}
                None => fresh = true,
            }
        }
        if fresh {
            self.commit_with(
                &writing,
                applying,
                Kind::Cutover,
                *id,
                None,
                now,
                Some(cutover.encode()?),
                Vec::new(),
            )?;
        }
        Ok(())
    }

    /// Journals `acknowledgement` of `id`; answers whether every stream is now acknowledged below
    /// its cutover (WP-4.5).
    pub fn record_acknowledgement(
        &self,
        applying: &Applying<'_>,
        id: &[u8; 16],
        acknowledgement: &Acknowledgement,
        now: u64,
    ) -> Result<bool, MembershipError> {
        let writing = self.begin();
        let known = self
            .read()
            .cutovers
            .get(&(*id, acknowledgement.ring.clone()))
            .is_some_and(|state| {
                state.epoch == acknowledgement.epoch
                    && state.streams.contains_key(&acknowledgement.stream)
            });
        if !known {
            return Err(MembershipError::Invalid(format!(
                "no cutover of `{}` at epoch {} names the stream `{}`",
                acknowledgement.ring, acknowledgement.epoch, acknowledgement.stream
            )));
        }
        self.commit_with(
            &writing,
            applying,
            Kind::Acknowledged,
            *id,
            None,
            now,
            Some(acknowledgement.encode()?),
            Vec::new(),
        )?;
        Ok(self
            .cutover(id, &acknowledgement.ring)
            .is_some_and(|state| state.complete()))
    }

    /// The cutover of `ring` of `id`, if any.
    pub fn cutover(&self, id: &[u8; 16], ring: &str) -> Option<CutoverState> {
        self.read().cutovers.get(&(*id, ring.to_owned())).cloned()
    }

    /// The successor of `id`'s manifest without the retiring pin of the member's `ring`, once
    /// every stream of its cutover is acknowledged (WP-4.5).
    pub fn check_retire(
        &self,
        coordinator: &Coordinator<'_>,
        id: &[u8; 16],
        ring: &str,
        now: u64,
    ) -> Result<Manifest, MembershipError> {
        let held = self.held(id)?;
        let manifest = active_manifest(&held)?;
        let epoch = current(manifest, Role::Member, ring).map(|pin| pin.epoch);
        let complete = self
            .cutover(id, ring)
            .is_some_and(|state| Some(state.epoch) == epoch && state.complete());
        if !retiring(manifest, Role::Member, ring) || !complete {
            return Err(MembershipError::Invalid(format!(
                "`{ring}` has no retiring set whose every stream is acknowledged"
            )));
        }
        let mut next = self.check_successor(coordinator, id, Status::Active, None, now)?;
        next.ring_pins
            .retain(|pin| !(pin.owner == Role::Member && pin.ring == ring && pin.retiring));
        Ok(next)
    }

    /// The pins that verify `stream`'s sequence `seq` signed by the member's `ring` of `id`
    /// (WP-4.5; applied to the streams by WP-5.2): below the stream's cutover only the retiring
    /// set, at or above it only the current one; before a cutover is known, either.
    pub fn verifying_pins(
        &self,
        id: &[u8; 16],
        ring: &str,
        stream: &str,
        seq: u64,
    ) -> Vec<RingPin> {
        let Some(held) = self.membership(id) else {
            return Vec::new();
        };
        let Some((manifest, ..)) = &held.manifest else {
            return Vec::new();
        };
        let pins: Vec<&RingPin> = manifest
            .ring_pins
            .iter()
            .filter(|pin| pin.owner == Role::Member && pin.ring == ring)
            .collect();
        let from = self
            .cutover(id, ring)
            .filter(|state| {
                pins.iter()
                    .any(|pin| !pin.retiring && pin.epoch == state.epoch)
            })
            .and_then(|state| state.streams.get(stream).copied());
        pins.into_iter()
            .filter(|pin| match from {
                Some(from) => pin.retiring == (seq < from),
                None => true,
            })
            .cloned()
            .collect()
    }

    /// Keeps the manifest epoch the member of `id` was just delivered.
    pub fn keep_delivered(
        &self,
        id: &[u8; 16],
        delivered: &Delivered,
    ) -> Result<(), MembershipError> {
        if self
            .delivered(id)?
            .is_some_and(|held| held.epoch >= delivered.epoch)
        {
            return Ok(());
        }
        let dir = self
            .dir
            .subdir(super::progress::DIRECTORY, true)?
            .subdir(&hex(id), true)?;
        replace_view(&dir, DELIVERED, format::VIEW, &delivered.encode()?)?;
        Ok(())
    }

    /// The last manifest epoch the member of `id` was delivered, if any.
    pub fn delivered(&self, id: &[u8; 16]) -> Result<Option<Delivered>, MembershipError> {
        if !self
            .dir
            .subdirs()?
            .iter()
            .any(|name| name == super::progress::DIRECTORY)
        {
            return Ok(None);
        }
        let progress = self.dir.subdir(super::progress::DIRECTORY, false)?;
        if !progress.subdirs()?.contains(&hex(id)) {
            return Ok(None);
        }
        read_view(&progress.subdir(&hex(id), false)?, DELIVERED, format::VIEW)?
            .map(|bytes| Delivered::decode(&bytes).map_err(MembershipError::from))
            .transpose()
    }
}

fn domain(error: crate::operations::mutation::MutationError<MembershipError>) -> MembershipError {
    match error {
        crate::operations::mutation::MutationError::Refused(error) => error,
        other => MembershipError::Storage(other.to_string()),
    }
}

impl super::service::Coordinating {
    /// Runs one store change of `id` as an operation of the membership domain.
    fn change(
        &self,
        operation: &'static str,
        action: &'static str,
        initiator: crate::operations::journal::Initiator,
        id: &[u8; 16],
        apply: impl FnOnce(&Applying<'_>) -> Result<(), MembershipError>,
    ) -> Result<(), MembershipError> {
        use crate::operations::mutation::{Applied, Begin, Failure, Outcome};
        let target = crate::identity::record::uuid_text(id);
        let outcome = self
            .mutations
            .run(
                Begin {
                    domain: super::DOMAIN,
                    operation,
                    action,
                    initiator,
                    request: None,
                    target: Some(target.clone()),
                },
                |applying| {
                    apply(applying).map_err(|error| {
                        if error.is_indeterminate() {
                            Failure::Indeterminate(error)
                        } else {
                            Failure::Refused(error)
                        }
                    })?;
                    Ok(Applied {
                        revision: self.store.membership(id).map_or(0, |held| held.revision),
                        target: Some(target.clone()),
                        value: (),
                    })
                },
            )
            .map_err(domain)?;
        match outcome {
            Outcome::Applied(()) => Ok(()),
            _ => Err(MembershipError::Storage(format!(
                "`{operation}` answered without applying"
            ))),
        }
    }

    /// The re-pin `peer` asks for its ring of `id` with `statement`: the manifest issued at the
    /// next epoch, or nothing for the exact retry (WP-4.5).
    pub(crate) fn repin(
        &self,
        peer: &Verified,
        id: &[u8; 16],
        statement: &RingStatement,
        now: u64,
    ) -> Result<(), MembershipError> {
        let coordinator = self.coordinator();
        let Repin::Successor(next) =
            self.store
                .check_repin(&coordinator, id, statement, peer, now)?
        else {
            return Ok(());
        };
        let changed = self.change(
            REPIN,
            AUDIT_REPINNED,
            crate::operations::journal::Initiator::System(crate::identity::record::subject(
                &peer.host_id,
            )),
            id,
            |applying| {
                self.store
                    .transition_with(
                        applying,
                        &coordinator,
                        &next,
                        std::slice::from_ref(statement),
                        now,
                    )
                    .map(|_| ())
            },
        );
        match changed {
            // A concurrent re-pin of the same set issued it first: this one is its retry.
            Err(MembershipError::Transition { .. })
                if self
                    .store
                    .check_repin(&coordinator, id, statement, peer, now)?
                    == Repin::Retry =>
            {
                Ok(())
            }
            other => other,
        }
    }

    /// Journals `peer`'s `cutover` of `id` before it is answered (WP-4.5).
    pub(crate) fn cutover(
        &self,
        peer: &Verified,
        id: &[u8; 16],
        cutover: &Cutover,
        now: u64,
    ) -> Result<(), MembershipError> {
        self.change(
            CUTOVER,
            AUDIT_CUTOVER,
            crate::operations::journal::Initiator::System(crate::identity::record::subject(
                &peer.host_id,
            )),
            id,
            |applying| self.store.record_cutover(applying, id, cutover, now),
        )?;
        // A stream-less cutover leaves nothing to acknowledge: the replaced pin retires now.
        self.retire_if_complete(id, &cutover.ring, now)
    }

    /// Drops the retiring pin of the member's `ring` of `id` when its cutover is complete.
    fn retire_if_complete(
        &self,
        id: &[u8; 16],
        ring: &str,
        now: u64,
    ) -> Result<(), MembershipError> {
        let coordinator = self.coordinator();
        let Ok(next) = self.store.check_retire(&coordinator, id, ring, now) else {
            return Ok(());
        };
        self.change(
            RETIRE_PIN,
            AUDIT_PIN_RETIRED,
            crate::operations::journal::Initiator::System("host".to_owned()),
            id,
            |applying| {
                self.store
                    .transition(applying, &coordinator, &next, now)
                    .map(|_| ())
            },
        )
    }

    /// Retires every retiring pin whose cutover is complete: what an acknowledgement or a
    /// cutover did not finish, a crash or a refusal between them (the server's pass, after the
    /// review). Answers how many.
    pub fn retire_due(&self) -> Result<usize, MembershipError> {
        let now = self.time.now_secs();
        let mut retired = 0;
        for (id, held) in self.store.memberships() {
            let Ok(manifest) = active_manifest(&held) else {
                continue;
            };
            let rings: Vec<String> = manifest
                .ring_pins
                .iter()
                .filter(|pin| pin.owner == Role::Member && pin.retiring)
                .map(|pin| pin.ring.clone())
                .collect();
            for ring in rings {
                let before = self.store.membership(&id).map(|held| held.epoch());
                self.retire_if_complete(&id, &ring, now)?;
                if self.store.membership(&id).map(|held| held.epoch()) != before {
                    retired += 1;
                }
            }
        }
        Ok(retired)
    }

    /// Acknowledges a stream's spans under the retiring set of `id` (WP-4.5, the stream
    /// consumer's call, WP-5.x); once every stream of the cutover is acknowledged, the retiring
    /// pin is dropped by a manifest revision. Answers whether it was.
    pub fn acknowledge(
        &self,
        id: &[u8; 16],
        acknowledgement: &Acknowledgement,
    ) -> Result<bool, MembershipError> {
        let now = self.time.now_secs();
        let initiator = || crate::operations::journal::Initiator::System("host".to_owned());
        let mut complete = false;
        self.change(
            ACKNOWLEDGE,
            AUDIT_ACKNOWLEDGED,
            initiator(),
            id,
            |applying| {
                complete = self
                    .store
                    .record_acknowledgement(applying, id, acknowledgement, now)?;
                Ok(())
            },
        )?;
        if !complete {
            return Ok(false);
        }
        self.retire_if_complete(id, &acknowledgement.ring, now)?;
        Ok(true)
    }

    /// Revises every active membership this Host coordinates whose pins lag its own rings: a
    /// successor re-pins them as they are (WP-4.5, the reverse direction). Answers how many.
    pub fn revise_coordinated(&self) -> Result<usize, MembershipError> {
        let coordinator = self.coordinator();
        let now = self.time.now_secs();
        let mut revised = 0;
        for (id, held) in self.store.memberships() {
            let Ok(manifest) = active_manifest(&held) else {
                continue;
            };
            let lags = manifest
                .ring_pins
                .iter()
                .filter(|pin| pin.owner == Role::Coordinator)
                .any(|pin| {
                    coordinator
                        .statement(&pin.ring)
                        .is_ok_and(|statement| statement.epoch > pin.epoch)
                });
            if !lags {
                continue;
            }
            let next = self
                .store
                .check_successor(&coordinator, &id, Status::Active, None, now)?;
            self.change(
                REPIN,
                AUDIT_REPINNED,
                crate::operations::journal::Initiator::System("host".to_owned()),
                &id,
                |applying| {
                    self.store
                        .transition(applying, &coordinator, &next, now)
                        .map(|_| ())
                },
            )?;
            revised += 1;
        }
        Ok(revised)
    }
}

/// The activation gate of this Host's rings (WP-4.5, owner decision): a ring activates its
/// prepublished key only once every active membership pins the ring's epoch; on a membership this
/// Host coordinates, once its member also received that manifest.
pub struct PinGate {
    pub store: Arc<Store>,
}

impl crate::keys::ring::ActivationGate for PinGate {
    fn may_activate(&self, ring: &str, epoch: u64) -> bool {
        self.store.memberships().iter().all(|(id, held)| {
            let Some((manifest, ..)) = &held.manifest else {
                return true;
            };
            if held.status != Status::Active {
                return true;
            }
            let Some(pin) = current(manifest, held.role, ring) else {
                return true;
            };
            match held.role {
                Role::Member => pin.epoch >= epoch,
                Role::Coordinator => {
                    pin.epoch >= epoch
                        && self
                            .store
                            .delivered(id)
                            .ok()
                            .flatten()
                            .is_some_and(|delivered| delivered.epoch >= manifest.epoch)
                }
            }
        })
    }
}

#[cfg(test)]
mod tests;
