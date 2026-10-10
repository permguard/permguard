// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What an identity reset does to the memberships (WP-4.1, owner decisions of 2026-10-09), the
//! steps the Host API and the offline CLI share. Asking each coordinator to revoke is
//! [`super::member::Member::revoke`]; what is left is settled here, each membership its own
//! mutation.
//!
//! | Role        | Live status         | Step                                                         |
//! | ----------- | ------------------- | ------------------------------------------------------------ |
//! | coordinator | `pending`           | rejected here: a genesis in status `rejected`                |
//! | coordinator | `active`, `suspended` | revoked here: the successor in status `revoked`            |
//! | member      | any live one        | revoked at the coordinator, or, in an emergency, `orphaned`  |

use super::record::{Role, Status};
use super::{
    AUDIT_ORPHANED, AUDIT_REJECTED, AUDIT_REVOKED, Coordinator, DOMAIN, END_ON_RESET, Held,
    MembershipError, ORPHAN, Store,
};
use crate::identity::record::uuid_text;
use crate::operations::journal::Initiator;
use crate::operations::mutation::{Applied, Begin, Failure, MutationError, Mutations, Outcome};

/// What a reset does to one live membership.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// Asked of its coordinator; orphaned in an emergency when the coordinator does not answer.
    RevokeRemote,
    /// Revoked here, under this Host's operations key.
    RevokeLocal,
    /// Still pending: rejected here.
    RejectLocal,
}

impl Step {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RevokeRemote => "revoke_remote",
            Self::RevokeLocal => "revoke_local",
            Self::RejectLocal => "reject_local",
        }
    }
}

/// Every live membership and what a reset does to it, by id.
pub fn plan(store: &Store) -> Vec<([u8; 16], Held, Step)> {
    store
        .memberships()
        .into_iter()
        .filter(|(_, held)| !held.status.is_terminal())
        .map(|(id, held)| {
            let step = match (held.role, held.status) {
                (Role::Member, _) => Step::RevokeRemote,
                (Role::Coordinator, Status::Pending) => Step::RejectLocal,
                (Role::Coordinator, _) => Step::RevokeLocal,
            };
            (id, held, step)
        })
        .collect()
}

/// What a plan binds: every live membership at its revision, in id order.
pub fn digest_target(planned: &[([u8; 16], Held, Step)]) -> String {
    planned
        .iter()
        .map(|(id, held, _)| format!("{}:{}", uuid_text(id), held.revision))
        .collect::<Vec<_>>()
        .join(",")
}

fn failure(error: MembershipError) -> Failure<MembershipError> {
    if error.is_indeterminate() {
        Failure::Indeterminate(error)
    } else {
        Failure::Refused(error)
    }
}

fn engine(error: MutationError<MembershipError>) -> MembershipError {
    match error {
        MutationError::Refused(error) => error,
        other => MembershipError::Storage(other.to_string()),
    }
}

/// Checks, before anything is written, that every membership this Host coordinates can be ended
/// here: its successor issues, the rings it pins answer. A reset that would stop halfway stops
/// before it starts.
pub fn preflight(
    store: &Store,
    coordinator: &Coordinator<'_>,
    now: u64,
) -> Result<(), MembershipError> {
    for (id, _, step) in plan(store) {
        let to = match step {
            Step::RevokeRemote => continue,
            Step::RejectLocal => Status::Rejected,
            Step::RevokeLocal => Status::Revoked,
        };
        let manifest = store.check_successor(coordinator, &id, to, None, now)?;
        coordinator.ring(super::HOST_OPERATIONS)?;
        for pin in manifest
            .ring_pins
            .iter()
            .filter(|pin| pin.owner == Role::Coordinator)
        {
            coordinator.statement(&pin.ring)?;
        }
    }
    Ok(())
}

/// Revokes every invitation still issued: the identity that offered them leaves.
pub fn revoke_invites(
    store: &Store,
    mutations: &Mutations,
    initiator: &Initiator,
    now: u64,
) -> Result<usize, MembershipError> {
    let issued: Vec<[u8; 16]> = store
        .invitations(now)
        .into_iter()
        .filter(|(_, status)| *status == "issued")
        .map(|(invitation, _)| invitation.invite_id)
        .collect();
    for invite_id in &issued {
        let outcome = mutations
            .run(
                Begin {
                    domain: DOMAIN,
                    operation: super::INVITE_REVOKE,
                    action: super::AUDIT_INVITE_REVOKED,
                    initiator: initiator.clone(),
                    request: None,
                    target: Some(uuid_text(invite_id)),
                },
                |applying| {
                    store
                        .revoke_invite(applying, invite_id, now)
                        .map_err(failure)?;
                    Ok(Applied {
                        revision: 0,
                        target: Some(uuid_text(invite_id)),
                        value: (),
                    })
                },
            )
            .map_err(engine)?;
        if !matches!(outcome, Outcome::Applied(())) {
            return Err(MembershipError::Storage(
                "a revoked invitation answered without applying".to_owned(),
            ));
        }
    }
    Ok(issued.len())
}

/// Ends here every live membership this Host coordinates: a pending one rejected, any other
/// revoked, each a manifest under the coordinator's operations key. Answers them as now held.
pub fn end_coordinated(
    store: &Store,
    mutations: &Mutations,
    coordinator: &Coordinator<'_>,
    initiator: &Initiator,
    now: u64,
) -> Result<Vec<Held>, MembershipError> {
    let mut ended = Vec::new();
    for (id, _, step) in plan(store) {
        let (to, action) = match step {
            Step::RevokeRemote => continue,
            Step::RejectLocal => (Status::Rejected, AUDIT_REJECTED),
            Step::RevokeLocal => (Status::Revoked, AUDIT_REVOKED),
        };
        let manifest = store.check_successor(coordinator, &id, to, None, now)?;
        let outcome = mutations
            .run(
                Begin {
                    domain: DOMAIN,
                    operation: END_ON_RESET,
                    action,
                    initiator: initiator.clone(),
                    request: None,
                    target: Some(uuid_text(&id)),
                },
                |applying| {
                    if manifest.epoch == 1 {
                        store.approve(applying, coordinator, &manifest, now)
                    } else {
                        store.transition(applying, coordinator, &manifest, now)
                    }
                    .map_err(failure)?;
                    Ok(Applied {
                        revision: store.membership(&id).map_or(0, |held| held.revision),
                        target: Some(uuid_text(&id)),
                        value: (),
                    })
                },
            )
            .map_err(engine)?;
        if !matches!(outcome, Outcome::Applied(())) {
            return Err(MembershipError::Storage(
                "a membership ended by the reset answered without applying".to_owned(),
            ));
        }
        ended.push(store.membership(&id).ok_or_else(|| {
            MembershipError::Storage("an ended membership is no longer held".to_owned())
        })?);
    }
    Ok(ended)
}

/// Marks `ids` `orphaned`: terminal here, their coordinators to revoke them out of band.
pub fn orphan(
    store: &Store,
    mutations: &Mutations,
    ids: &[[u8; 16]],
    initiator: &Initiator,
    now: u64,
) -> Result<Vec<Held>, MembershipError> {
    let mut orphaned = Vec::new();
    for id in ids {
        let outcome = mutations
            .run(
                Begin {
                    domain: DOMAIN,
                    operation: ORPHAN,
                    action: AUDIT_ORPHANED,
                    initiator: initiator.clone(),
                    request: None,
                    target: Some(uuid_text(id)),
                },
                |applying| {
                    store.orphan(applying, id, now).map_err(failure)?;
                    Ok(Applied {
                        revision: store.membership(id).map_or(0, |held| held.revision),
                        target: Some(uuid_text(id)),
                        value: (),
                    })
                },
            )
            .map_err(engine)?;
        if !matches!(outcome, Outcome::Applied(())) {
            return Err(MembershipError::Storage(
                "an orphaned membership answered without applying".to_owned(),
            ));
        }
        orphaned.push(store.membership(id).ok_or_else(|| {
            MembershipError::Storage("an orphaned membership is no longer held".to_owned())
        })?);
    }
    Ok(orphaned)
}

/// What an emergency reset did (the offline CLI): the memberships it ended and orphaned, and the
/// identity it left.
#[derive(Debug)]
pub struct Emergency {
    pub ended: Vec<Held>,
    pub orphaned: Vec<Held>,
    pub reset: crate::identity::reset::Reset,
}

/// Why an emergency reset stopped.
#[derive(Debug)]
pub enum EmergencyError {
    /// A membership step: the identity is unchanged.
    Membership(MembershipError),
    /// The identity step, the memberships settled.
    Identity(MutationError<crate::identity::IdentityError>),
}

impl std::fmt::Display for EmergencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Membership(error) => {
                write!(
                    f,
                    "settling the memberships, the identity unchanged: {error}"
                )
            }
            Self::Identity(error) => write!(f, "resetting the identity: {error}"),
        }
    }
}

impl std::error::Error for EmergencyError {}

/// The emergency reset with no coordinator reached (owner decision of 2026-10-09): every live
/// membership this Host is a member of `orphaned`, every one it coordinates ended here, then the
/// identity reset. `rings` holds `host.operations` when a coordinated membership is live.
pub fn emergency(
    store: &Store,
    mutations: &Mutations,
    identity: &crate::identity::Identity,
    rings: &[std::sync::Arc<crate::keys::ring::Ring>],
    initiator: &Initiator,
    now: u64,
) -> Result<Emergency, EmergencyError> {
    let members: Vec<[u8; 16]> = plan(store)
        .into_iter()
        .filter(|(_, _, step)| *step == Step::RevokeRemote)
        .map(|(id, _, _)| id)
        .collect();
    let coordinator = Coordinator { identity, rings };
    // Nothing irreversible before every step is known to be possible.
    preflight(store, &coordinator, now).map_err(EmergencyError::Membership)?;
    // From here nothing new is taken under this identity; what was offered goes first.
    store.fence();
    revoke_invites(store, mutations, initiator, now).map_err(EmergencyError::Membership)?;
    let ended = end_coordinated(store, mutations, &coordinator, initiator, now)
        .map_err(EmergencyError::Membership)?;
    let orphaned =
        orphan(store, mutations, &members, initiator, now).map_err(EmergencyError::Membership)?;
    let reset = crate::identity::reset::run(mutations, identity, rings, initiator.clone(), now)
        .map_err(EmergencyError::Identity)?;
    Ok(Emergency {
        ended,
        orphaned,
        reset,
    })
}
