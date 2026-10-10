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
//! task    ─▶ session `task` (membership and task in the hello) ─▶ lease request {epoch, boot id}
//!         ─▶ the lease verified under the pinned operations key, bound to the connection, kept
//!         ─▶ task messages on the same connection, each naming the lease's epoch (WP-4.3)
//! ```

use std::sync::Arc;

use permguard_core::BoxFuture;
use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::Selector;

use super::record::{
    Action, EnrollAnswer, EnrollRequest, HostRef, Lease, LeaseAnswer, LeaseRequest,
    MembershipAnswer, MembershipRequest, Pending, Role, Status, Task, TaskAnswer, TaskMessage,
    channel_binding,
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

/// The first frame of a task session: the lease request, on a session naming the membership and
/// the task.
pub struct TaskOpen {
    pub membership_id: [u8; 16],
    pub task_id: String,
    pub request: Vec<u8>,
}

/// An open task session: the coordinator as its pin verified it, the connection's exporter, the
/// lease answer, and the connection itself for the messages that follow.
pub struct TaskOpened {
    pub peer: Verified,
    pub exporter: [u8; 32],
    pub answer: Vec<u8>,
    pub channel: Box<dyn TaskChannel>,
}

/// The connection of an open task session: one message, one answer, in order; closed when
/// dropped.
pub trait TaskChannel: Send {
    fn exchange(&mut self, message: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>, Refusal>>;
}

/// Opens one session to a coordinator, sends one request, reads one answer.
pub trait Connector: Send + Sync {
    fn exchange(
        &self,
        target: Target,
        exchange: Exchange,
    ) -> BoxFuture<'_, Result<Exchanged, Refusal>>;

    /// Opens a task session and sends its lease request (WP-4.3): the session stays open.
    fn open_task(
        &self,
        target: Target,
        open: TaskOpen,
    ) -> BoxFuture<'_, Result<TaskOpened, Refusal>> {
        let _ = (target, open);
        Box::pin(std::future::ready(Err(Refusal {
            code: permguard_core::codes::host::PEER_CLIENT_UNCONFIGURED,
            reason: "this connector opens no task session".to_owned(),
        })))
    }
}

/// Where a member's task stands (owner decision of 2026-10-10): what the task handlers (WP-4.4)
/// consult before a remote action.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// No lease was ever held for the task.
    Unleased,
    /// The lease runs until `expires_at`.
    Live { expires_at: u64 },
    /// The lease expired; local work continues, no new remote action without a new lease, until
    /// `until`.
    Grace { until: u64 },
    /// Beyond the offline grace: no new remote action.
    Offline,
}

/// An open task session, as the member holds it.
pub struct MemberTask {
    pub lease: Lease,
    channel: Box<dyn TaskChannel>,
}

impl MemberTask {
    /// The session's connection, for tests that send what a member never would.
    #[cfg(test)]
    pub(crate) fn channel_for_tests(&mut self) -> &mut dyn TaskChannel {
        self.channel.as_mut()
    }

    /// Sends one message under the lease's epoch: the handler's answer, or the coordinator's
    /// refusal.
    pub async fn send(
        &mut self,
        request_id: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, MembershipError> {
        let message = TaskMessage {
            membership_id: self.lease.membership_id,
            task_id: self.lease.task_id.clone(),
            epoch: self.lease.epoch,
            request_id: request_id.to_owned(),
            body,
        }
        .encode()?;
        let answer = self.channel.exchange(message).await.map_err(remote)?;
        let answer = TaskAnswer::decode(&answer)?;
        if answer.request_id != request_id {
            return Err(MembershipError::Unverified(
                "the answer names another request".to_owned(),
            ));
        }
        Ok(answer.body)
    }
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
                            .accept_with(
                                applying,
                                &manifest,
                                &envelope,
                                &digest,
                                &answer.ring_statements,
                                now,
                            )
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

    /// Opens a task session of `id` over `resource` (WP-4.3): only the member opens one. The
    /// lease is verified under the coordinator's pinned operations key, bound to this
    /// connection and this incarnation, and kept; evidence, when given, is appraised first and
    /// the revised manifest accepted as the exact successor.
    pub async fn open_task(
        &self,
        initiator: Initiator,
        id: &[u8; 16],
        task_id: &str,
        resource: &str,
        evidence: Vec<(String, Vec<u8>)>,
    ) -> Result<MemberTask, MembershipError> {
        let held = self.store.membership(id).ok_or_else(|| {
            MembershipError::Unknown(format!("no membership `{}`", uuid_text(id)))
        })?;
        // The coordinator never dials: a membership this Host coordinates opens no task session.
        if held.role != Role::Member {
            return Err(MembershipError::Unknown(
                "this Host is the coordinator of that membership".to_owned(),
            ));
        }
        if held.status != Status::Active || held.manifest.is_none() {
            return Err(MembershipError::Transition {
                from: held.status,
                to: Status::Active,
            });
        }
        let boot_id = self.identity.boot_id();
        let request = LeaseRequest {
            membership_id: *id,
            task_id: task_id.to_owned(),
            epoch: held.epoch(),
            resource: resource.to_owned(),
            member_boot_id: boot_id,
            evidence,
        }
        .encode()?;
        let opened = self
            .connector
            .open_task(
                Self::target(&held)?,
                TaskOpen {
                    membership_id: *id,
                    task_id: task_id.to_owned(),
                    request,
                },
            )
            .await
            .map_err(remote)?;
        let answer = LeaseAnswer::decode(&opened.answer)?;
        let now = self.time.now_secs();
        // A revision the appraisal at the session issued: the exact successor, accepted first.
        if let Some(envelope) = answer.manifest {
            let statements = self.store.statements_held(id, held.epoch());
            let accepted = self.store.check_sync(
                id,
                &opened.peer,
                &MembershipAnswer {
                    status: Status::Active,
                    manifests: vec![envelope],
                    ring_statements: statements.clone(),
                },
                now,
            )?;
            for (manifest, envelope, digest) in accepted {
                self.mutations
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
                                .accept_with(
                                    applying,
                                    &manifest,
                                    &envelope,
                                    &digest,
                                    &statements,
                                    now,
                                )
                                .map_err(failure)?;
                            Ok(Applied {
                                revision: 0,
                                target: Some(uuid_text(id)),
                                value: (),
                            })
                        },
                    )
                    .map_err(engine)?;
            }
        }
        let held = self.store.membership(id).ok_or_else(|| {
            MembershipError::Storage("the membership is no longer held".to_owned())
        })?;
        let Some((manifest, ..)) = &held.manifest else {
            return Err(MembershipError::Storage("no manifest held".to_owned()));
        };
        let statements = self.store.statements_held(id, manifest.epoch);
        let lease = super::verify_lease(&answer.lease, &opened.peer, manifest, &statements)?;
        let skew = manifest.lease_policy.clock_skew_seconds;
        let granted = manifest.tasks.iter().find(|task| task.task_id == task_id);
        let ours = lease.membership_id == *id
            && granted
                .is_some_and(|task| task.selector == lease.selector && task.limits == lease.limits)
            && lease.expires_at
                <= lease
                    .issued_at
                    .saturating_add(manifest.lease_policy.max_session_seconds)
                    .min(manifest.not_after)
            && lease.task_id == task_id
            && lease.epoch == manifest.epoch
            && lease.coordinator == held.request.coordinator.host_id
            && lease.coordinator == opened.peer.host_id
            && lease.member == self.identity.host_id()
            && lease.member_boot_id == boot_id
            && lease.resource == resource
            && lease.channel_binding == channel_binding(&opened.exporter);
        if !ours {
            return Err(MembershipError::Unverified(
                "the lease names another membership, task, scope, epoch, Host, incarnation, \
                 resource or connection, or runs past its bound"
                    .to_owned(),
            ));
        }
        // The coordinator's clock may run ahead within the skew it signed, no further.
        if lease.issued_at > now.saturating_add(skew) || lease.expires_at <= now {
            return Err(MembershipError::Unverified(
                "the lease is issued beyond the clock skew, or already expired".to_owned(),
            ));
        }
        self.store.keep_lease(id, task_id, &answer.lease)?;
        Ok(MemberTask {
            lease,
            channel: opened.channel,
        })
    }

    /// Where the task `task_id` of `id` stands at `now`: never extended locally.
    pub fn task_state(
        store: &Store,
        id: &[u8; 16],
        task_id: &str,
        boot_id: &[u8; 16],
        now: u64,
    ) -> Result<TaskState, MembershipError> {
        let Some(held) = store.membership(id) else {
            return Err(MembershipError::Unknown(format!(
                "no membership `{}`",
                uuid_text(id)
            )));
        };
        let Some((manifest, ..)) = &held.manifest else {
            return Ok(TaskState::Unleased);
        };
        let Some(envelope) = store.lease(id, task_id)? else {
            return Ok(TaskState::Unleased);
        };
        // This Host verified the lease when it kept it; its own file is read back as kept.
        let sign1 = permguard_objects::cose::Sign1::decode(&envelope)
            .map_err(|error| MembershipError::Storage(error.to_string()))?;
        let lease = Lease::decode(sign1.payload_unverified())?;
        // A lease of another incarnation, a restored or copied volume's predecessor, is none:
        // this one leases again before work.
        if lease.member_boot_id != *boot_id {
            return Ok(TaskState::Unleased);
        }
        // A lease of an epoch the membership has moved past grants nothing.
        if lease.epoch != manifest.epoch || held.status != Status::Active {
            return Ok(TaskState::Offline);
        }
        if now < lease.expires_at {
            return Ok(TaskState::Live {
                expires_at: lease.expires_at,
            });
        }
        let until = lease
            .issued_at
            .saturating_add(manifest.lease_policy.offline_grace_seconds);
        if now < until {
            Ok(TaskState::Grace { until })
        } else {
            Ok(TaskState::Offline)
        }
    }
}
