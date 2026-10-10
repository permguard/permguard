// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The member's side (WP-4.1, owner decisions of 2026-10-09): every session is the member's to
//! open, so a join, a sync of the manifest and a revocation asked of the coordinator all go
//! through a [`Connector`] the server composes, its outbound TLS the Host listener's own.
//!
//! ```text
//! join    ─▶ session `enroll` (request digest in the hello) ─▶ answer {membership_id, pending}
//!         ─▶ `members.join`: the coordinator pinned, the token never kept
//! sync    ─▶ session `membership` {fetch, held_epoch} ─▶ manifests verified in order
//!         ─▶ `members.sync`: one transaction per manifest accepted
//! revoke  ─▶ session `membership` {revoke} ─▶ the successor in status `revoked`, the receipt
//! ```

use std::sync::Arc;

use permguard_core::BoxFuture;
use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::Selector;

use super::record::{
    Action, EnrollAnswer, EnrollRequest, HostRef, MembershipAnswer, MembershipRequest, Pending,
    Role, Status, Task,
};
use super::{
    AUDIT_JOINED, AUDIT_SYNCED, Capabilities, DOMAIN, Held, JOIN, MembershipError, SYNC, Store,
    rings_needed, statement_of, token_proof,
};
use crate::identity::record::uuid_text;
use crate::identity::{Identity, Verified};
use crate::keys::ring::Ring;
use crate::operations::journal::Initiator;
use crate::operations::mutation::{Applied, Begin, Failure, MutationError, Mutations, Outcome};
use crate::session::Refusal;
use crate::session::record::Operation;
use crate::time::TimeGuard;

/// The coordinator a member reaches: where, and the pin it is accepted by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `https://<host>:<port>`.
    pub address: String,
    pub host_id: [u8; 16],
    /// The coordinator's first fingerprint.
    pub fingerprint: String,
}

/// Builds the one request of a session from the connection's exporter: an enrollment's token
/// proof is bound to it.
pub type Build = Box<dyn FnOnce(&[u8; 32]) -> Result<Vec<u8>, Refusal> + Send>;

/// One exchange: a session of `operation` naming `membership_id`, carrying the request `build`
/// makes.
pub struct Exchange {
    pub operation: Operation,
    pub membership_id: Option<[u8; 16]>,
    pub build: Build,
}

/// What an exchange answered: the coordinator as its pin verified it, and its answer.
pub struct Exchanged {
    pub peer: Verified,
    pub answer: Vec<u8>,
}

/// Opens one session to a coordinator, sends one request, reads one answer.
pub trait Connector: Send + Sync {
    fn exchange(
        &self,
        target: Target,
        exchange: Exchange,
    ) -> BoxFuture<'_, Result<Exchanged, Refusal>>;
}

/// What a join names.
#[derive(Debug, Clone)]
pub struct Join {
    pub coordinator: Target,
    pub invite_id: [u8; 16],
    /// The token, from the coordinator's operator out of band; never kept.
    pub token: Vec<u8>,
    pub selector: Selector,
    pub tasks: Vec<Task>,
}

/// The member's memberships, and what reaching their coordinators takes.
pub struct Member<'a> {
    pub store: &'a Store,
    pub mutations: &'a Mutations,
    pub identity: &'a Identity,
    pub rings: &'a [Arc<Ring>],
    pub capabilities: &'a Capabilities,
    pub connector: &'a dyn Connector,
    pub declared_assurance: AssuranceProfile,
    pub time: &'a TimeGuard,
}

fn remote(refusal: Refusal) -> MembershipError {
    MembershipError::Remote {
        code: refusal.code.to_owned(),
        reason: refusal.reason,
    }
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

impl Member<'_> {
    fn host_ref(&self) -> HostRef {
        HostRef {
            host_id: self.identity.host_id(),
            epoch: self.identity.epoch(),
            fingerprint: self.identity.first_fingerprint().to_owned(),
        }
    }

    /// Joins a coordinator: enrolls on a session to it, then records the membership `pending`.
    pub async fn join(&self, initiator: Initiator, join: Join) -> Result<Held, MembershipError> {
        // A join retried after it was recorded answers what it recorded: the token is spent, and
        // the coordinator would refuse it.
        if let Some((_, held)) = self.store.memberships().into_iter().find(|(_, held)| {
            held.role == Role::Member
                && held.request.invite_id == join.invite_id
                && held.request.coordinator.host_id == join.coordinator.host_id
        }) {
            let same = held.request.coordinator.fingerprint == join.coordinator.fingerprint
                && held.request.coordinator_address.as_deref()
                    == Some(join.coordinator.address.as_str())
                && held.request.selector == join.selector
                && held.request.tasks == join.tasks;
            if !same {
                return Err(MembershipError::Invalid(
                    "this invitation was joined with another request: its membership is held"
                        .to_owned(),
                ));
            }
            return Ok(held);
        }
        if join.tasks.is_empty() {
            return Err(MembershipError::Invalid(
                "a membership grants at least one task".to_owned(),
            ));
        }
        for task in &join.tasks {
            if !self.capabilities.acts(task.task_type, Role::Member) {
                return Err(MembershipError::TaskUnserved(format!(
                    "no Plane of this Host acts in `{}` as the member",
                    task.task_type.as_str()
                )));
            }
        }
        // The rings the member's tasks need pinned, presented with their bindings.
        let mut statements = Vec::new();
        for (owner, ring) in rings_needed(&join.tasks) {
            if owner != Role::Member {
                continue;
            }
            let held = self
                .rings
                .iter()
                .find(|held| held.id() == ring)
                .ok_or_else(|| {
                    MembershipError::Ring(format!("this Host composes no ring `{ring}`"))
                })?;
            statements.push(statement_of(held)?);
        }
        let token = join.token.clone();
        let member = self.host_ref();
        let coordinator_id = join.coordinator.host_id;
        let (selector, tasks, invite_id) =
            (join.selector.clone(), join.tasks.clone(), join.invite_id);
        let request_member = member.clone();
        let request_statements = statements.clone();
        let build: super::member::Build = Box::new(move |exporter| {
            EnrollRequest {
                invite_id,
                token_proof: token_proof(
                    &token,
                    &coordinator_id,
                    &request_member.host_id,
                    exporter,
                ),
                selector,
                tasks,
                member: request_member,
                ring_statements: request_statements,
            }
            .encode()
            .map_err(|error| Refusal {
                code: permguard_core::codes::common::INVALID_ARGUMENT,
                reason: error.0,
            })
        });
        let exchanged = self
            .connector
            .exchange(
                join.coordinator.clone(),
                Exchange {
                    operation: Operation::Enroll,
                    membership_id: None,
                    build,
                },
            )
            .await
            .map_err(remote)?;
        let answer = EnrollAnswer::decode(&exchanged.answer)?;
        if exchanged.peer.host_id != join.coordinator.host_id
            || exchanged.peer.first_fingerprint() != join.coordinator.fingerprint
        {
            return Err(MembershipError::Unverified(
                "the coordinator is another Host than the one pinned".to_owned(),
            ));
        }
        let now = self.time.now_secs();
        let pending = Pending {
            membership_id: answer.membership_id,
            invite_id: join.invite_id,
            coordinator: HostRef {
                host_id: exchanged.peer.host_id,
                epoch: exchanged.peer.epoch,
                fingerprint: exchanged.peer.first_fingerprint().to_owned(),
            },
            member,
            selector: join.selector,
            tasks: join.tasks,
            member_assurance: self.declared_assurance,
            ring_statements: statements,
            requested_at: now,
            coordinator_address: Some(join.coordinator.address),
            identity: None,
        };
        let id = pending.membership_id;
        let outcome = self
            .mutations
            .run(
                Begin {
                    domain: DOMAIN,
                    operation: JOIN,
                    action: AUDIT_JOINED,
                    initiator,
                    request: None,
                    target: Some(uuid_text(&id)),
                },
                |applying| {
                    self.store.join(applying, &pending, now).map_err(failure)?;
                    Ok(Applied {
                        revision: 1,
                        target: Some(uuid_text(&id)),
                        value: (),
                    })
                },
            )
            .map_err(engine)?;
        if !matches!(outcome, Outcome::Applied(())) {
            return Err(MembershipError::Storage(
                "the join answered without applying".to_owned(),
            ));
        }
        self.store
            .membership(&id)
            .ok_or_else(|| MembershipError::Storage("the joined membership is not held".to_owned()))
    }

    fn target(held: &Held) -> Result<Target, MembershipError> {
        Ok(Target {
            address: held.request.coordinator_address.clone().ok_or_else(|| {
                MembershipError::Invalid("the membership names no coordinator address".to_owned())
            })?,
            host_id: held.request.coordinator.host_id,
            fingerprint: held.request.coordinator.fingerprint.clone(),
        })
    }

    /// Asks the coordinator for `action` on `id` and records every manifest it answers, each the
    /// exact successor of the one before.
    async fn ask(
        &self,
        initiator: Initiator,
        id: &[u8; 16],
        action: Action,
    ) -> Result<Held, MembershipError> {
        let held = self.store.membership(id).ok_or_else(|| {
            MembershipError::Unknown(format!("no membership `{}`", uuid_text(id)))
        })?;
        if held.role != Role::Member {
            return Err(MembershipError::Unknown(
                "this Host is the coordinator of that membership".to_owned(),
            ));
        }
        let request = MembershipRequest {
            action,
            membership_id: *id,
            held_epoch: Some(held.epoch()),
        }
        .encode()?;
        let exchanged = self
            .connector
            .exchange(
                Self::target(&held)?,
                Exchange {
                    operation: Operation::Membership,
                    membership_id: Some(*id),
                    build: Box::new(move |_| Ok(request)),
                },
            )
            .await
            .map_err(remote)?;
        let answer = MembershipAnswer::decode(&exchanged.answer)?;
        let now = self.time.now_secs();
        let accepted = self.store.check_sync(id, &exchanged.peer, &answer, now)?;
        for (manifest, envelope, digest) in accepted {
            let outcome = self
                .mutations
                .run(
                    Begin {
                        domain: DOMAIN,
                        operation: SYNC,
                        action: AUDIT_SYNCED,
                        initiator: initiator.clone(),
                        request: None,
                        target: Some(uuid_text(id)),
                    },
                    |applying| {
                        self.store
                            .accept(applying, &manifest, &envelope, &digest, now)
                            .map_err(failure)?;
                        Ok(Applied {
                            revision: self.store.membership(id).map_or(0, |held| held.revision),
                            target: Some(uuid_text(id)),
                            value: (),
                        })
                    },
                )
                .map_err(engine)?;
            if !matches!(outcome, Outcome::Applied(())) {
                return Err(MembershipError::Storage(
                    "a manifest answered without applying".to_owned(),
                ));
            }
        }
        // The receipt of a revocation is the coordinator's manifest that ended the membership:
        // revoked, or rejected while it was pending, or expired.
        if action == Action::Revoke
            && !self
                .store
                .membership(id)
                .is_some_and(|held| held.status.is_terminal() && held.status != Status::Orphaned)
        {
            return Err(MembershipError::Remote {
                code: permguard_core::codes::host::IDENTITY_RESET_INCOMPLETE.to_owned(),
                reason: "the coordinator answered no revoked manifest".to_owned(),
            });
        }
        self.store
            .membership(id)
            .ok_or_else(|| MembershipError::Storage("the membership is no longer held".to_owned()))
    }

    /// Fetches and records the coordinator's manifests since the one held.
    pub async fn sync(&self, initiator: Initiator, id: &[u8; 16]) -> Result<Held, MembershipError> {
        self.ask(initiator, id, Action::Fetch).await
    }

    /// Asks the coordinator to revoke `id`; its revoked manifest, recorded, is the receipt.
    pub async fn revoke(
        &self,
        initiator: Initiator,
        id: &[u8; 16],
    ) -> Result<Held, MembershipError> {
        self.ask(initiator, id, Action::Revoke).await
    }
}
