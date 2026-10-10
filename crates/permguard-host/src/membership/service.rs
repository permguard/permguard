// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a coordinator serves on a proven session (WP-4.1): the one request of an `enroll` or a
//! `membership` session, each a transaction of the mutation engine whose initiator is the peer
//! Host.
//!
//! | Operation    | Request                         | Answer                         | Mutation          |
//! | ------------ | ------------------------------- | ------------------------------ | ----------------- |
//! | `enroll`     | [`EnrollRequest`]               | [`EnrollAnswer`], `pending`    | `members.enroll`  |
//! | `membership` | [`MembershipRequest`] `fetch`   | [`MembershipAnswer`]           | none              |
//! | `membership` | [`MembershipRequest`] `revoke`  | [`MembershipAnswer`], `revoked`| `members.revoke.peer` |
//!
//! A refusal tells the peer one stable code; the reason goes to the log and the audit record,
//! never on the wire.

use std::sync::Arc;

use permguard_core::assurance::AssuranceProfile;
use permguard_core::codes;

use super::record::{Action, EnrollAnswer, EnrollRequest, MembershipRequest, Status};
use super::{
    AUDIT_ENROLLED, AUDIT_REVOKED, Capabilities, Coordinator, DOMAIN, ENROLL, Enrolling,
    MembershipError, REVOKE_PEER, Store,
};
use crate::identity::record::{subject, uuid_text};
use crate::identity::{Identity, Verified};
use crate::keys::registry::Registry;
use crate::operations::journal::Initiator;
use crate::operations::mutation::{Applied, Begin, Failure, MutationError, Mutations, Outcome};
use crate::session::record::{EXPORTER_BYTES, Operation};
use crate::session::{Refusal, Service, Session};
use crate::time::TimeGuard;

/// The coordinator's side of the memberships, as a session serves it.
pub struct Coordinating {
    pub store: Arc<Store>,
    pub mutations: Arc<Mutations>,
    pub identity: Arc<Identity>,
    pub keys: Arc<Registry>,
    pub capabilities: Capabilities,
    pub time: Arc<TimeGuard>,
}

fn refusal(code: &'static str, reason: impl Into<String>) -> Refusal {
    Refusal {
        code,
        reason: reason.into(),
    }
}

/// The stable code a membership refusal tells a peer.
pub fn code_of(error: &MembershipError) -> &'static str {
    match error {
        MembershipError::Enrollment(_) => codes::host::ENROLLMENT_REFUSED,
        MembershipError::Unknown(_) => codes::host::MEMBERSHIP_UNKNOWN,
        MembershipError::Transition { .. } => codes::host::MEMBERSHIP_TRANSITION_REFUSED,
        MembershipError::Equivocation(_) => codes::host::MANIFEST_EQUIVOCATION,
        MembershipError::NotSuccessor(_) => codes::host::MANIFEST_NOT_SUCCESSOR,
        MembershipError::Storage(_) | MembershipError::Ring(_) => codes::common::UNAVAILABLE,
        MembershipError::AssuranceRefused(_) => codes::host::ASSURANCE_REFUSED,
        MembershipError::AssuranceUnavailable(_) => codes::host::ASSURANCE_UNAVAILABLE,
        _ => codes::common::INVALID_ARGUMENT,
    }
}

fn of(error: MembershipError) -> Refusal {
    refusal(code_of(&error), error.to_string())
}

fn engine(error: MutationError<MembershipError>) -> Refusal {
    match error {
        MutationError::Refused(error) => of(error),
        other => refusal(codes::common::UNAVAILABLE, other.to_string()),
    }
}

fn failure(error: MembershipError) -> Failure<MembershipError> {
    if error.is_indeterminate() {
        Failure::Indeterminate(error)
    } else {
        Failure::Refused(error)
    }
}

impl Coordinating {
    fn coordinator(&self) -> Coordinator<'_> {
        Coordinator {
            identity: &self.identity,
            rings: self.keys.rings(),
        }
    }

    fn enroll(
        &self,
        session: &Session,
        peer: &Verified,
        presentation: &[u8],
        exporter: &[u8; EXPORTER_BYTES],
        bytes: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        let request =
            EnrollRequest::decode(bytes).map_err(|error| of(MembershipError::Invalid(error.0)))?;
        let now = self.time.now_secs();
        let enrolling = Enrolling {
            peer,
            presentation,
            declared_assurance: session.peer_declared_assurance,
            exporter,
        };
        let pending = self
            .store
            .check_enroll(&self.coordinator(), &enrolling, &request, now)
            .map_err(of)?;
        let outcome = self
            .mutations
            .run(
                Begin {
                    domain: DOMAIN,
                    operation: ENROLL,
                    action: AUDIT_ENROLLED,
                    initiator: Initiator::Principal(subject(&peer.host_id)),
                    request: None,
                    target: Some(uuid_text(&pending.membership_id)),
                },
                |applying| {
                    self.store
                        .enroll(applying, &pending, now)
                        .map_err(failure)?;
                    Ok(Applied {
                        revision: 1,
                        target: Some(uuid_text(&pending.membership_id)),
                        value: (),
                    })
                },
            )
            .map_err(engine)?;
        if !matches!(outcome, Outcome::Applied(())) {
            return Err(refusal(
                codes::common::UNAVAILABLE,
                "the enrollment answered without applying",
            ));
        }
        EnrollAnswer {
            membership_id: pending.membership_id,
            status: Status::Pending,
        }
        .encode()
        .map_err(|error| refusal(codes::common::UNAVAILABLE, error.0))
    }

    fn membership(
        &self,
        session: &Session,
        peer: &Verified,
        bytes: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        let request = MembershipRequest::decode(bytes)
            .map_err(|error| of(MembershipError::Invalid(error.0)))?;
        // The session named the membership; the request may not name another.
        if session.membership_id.as_deref() != Some(uuid_text(&request.membership_id).as_str()) {
            return Err(refusal(
                codes::host::MEMBERSHIP_UNKNOWN,
                "the request names another membership than the session",
            ));
        }
        let id = request.membership_id;
        let coordinator = self.coordinator();
        // Only the member of the membership reaches it.
        self.store
            .answer(&coordinator, &id, &peer.host_id, None)
            .map_err(of)?;
        if request.action == Action::Revoke {
            let held = self
                .store
                .membership(&id)
                .ok_or_else(|| of(MembershipError::Unknown("no such membership".to_owned())))?;
            // A membership that already ended answers the manifest that ended it; a pending one
            // ends by a rejection, a genesis; any other by its revoked successor.
            if !held.status.is_terminal() {
                let to = if held.status == Status::Pending {
                    Status::Rejected
                } else {
                    Status::Revoked
                };
                let now = self.time.now_secs();
                let next = self
                    .store
                    .check_successor(&coordinator, &id, to, None, now)
                    .map_err(of)?;
                self.mutations
                    .run(
                        Begin {
                            domain: DOMAIN,
                            operation: REVOKE_PEER,
                            action: AUDIT_REVOKED,
                            initiator: Initiator::Principal(subject(&peer.host_id)),
                            request: None,
                            target: Some(uuid_text(&id)),
                        },
                        |applying| {
                            if next.epoch == 1 {
                                self.store.approve(applying, &coordinator, &next, now)
                            } else {
                                self.store.transition(applying, &coordinator, &next, now)
                            }
                            .map_err(failure)?;
                            Ok(Applied {
                                revision: self
                                    .store
                                    .membership(&id)
                                    .map_or(0, |held| held.revision),
                                target: Some(uuid_text(&id)),
                                value: (),
                            })
                        },
                    )
                    .map_err(engine)?;
            }
        }
        self.store
            .answer(&coordinator, &id, &peer.host_id, request.held_epoch)
            .map_err(of)?
            .encode()
            .map_err(|error| refusal(codes::common::UNAVAILABLE, error.0))
    }
}

impl Service for Coordinating {
    fn serve(
        &self,
        session: &Session,
        peer: &Verified,
        presentation: &[u8],
        exporter: &[u8; EXPORTER_BYTES],
        request: &[u8],
    ) -> Result<Vec<u8>, Refusal> {
        // A reset retired this identity: a session established before it serves nothing more.
        if self.identity.is_retired() {
            return Err(refusal(
                codes::common::UNAVAILABLE,
                "this Host's identity was reset",
            ));
        }
        match session.operation {
            Operation::Enroll => self.enroll(session, peer, presentation, exporter, request),
            Operation::Membership => self.membership(session, peer, request),
            Operation::Task => Err(refusal(
                codes::host::NOT_SERVED_YET,
                "task sessions come with the task transport",
            )),
        }
    }
}

/// Whether `declared` meets `floor`.
pub fn meets(declared: AssuranceProfile, floor: AssuranceProfile) -> bool {
    super::rank(declared) >= super::rank(floor)
}
