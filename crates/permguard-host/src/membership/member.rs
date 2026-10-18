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
    Action, Cutover, EnrollAnswer, EnrollRequest, HostRef, Lease, LeaseAnswer, LeaseRequest,
    MembershipAnswer, MembershipRequest, MessageKind, Pending, ProgressAnswer, Role, Status, Task,
    TaskAnswer, TaskMessage, TaskProgress, WatchEvent, WatchRequest, channel_binding,
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

/// The progress state of a stream an incomplete drain left behind (WP-5.8).
pub const UNSHIPPED: &str = "unshipped";
/// The progress state of a stream whose drain mark went: its tail is shipped (WP-5.8).
pub const SHIPPED: &str = "shipped";

/// The progress reports this process sent: the coordinator numbers them per incarnation.
static REPORT_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

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

/// A peer whose identity and connection-bound proof were verified on one live PeerChannel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProvedPeer {
    pub host_id: [u8; 16],
    pub epoch: u64,
    pub fingerprint: String,
}

/// The connection of an open task session: one message, one answer, in order; closed when
/// dropped.
pub trait TaskChannel: Send {
    fn exchange(&mut self, message: Vec<u8>) -> BoxFuture<'_, Result<Vec<u8>, Refusal>>;

    /// The next frame the coordinator sends unasked, on a session that became a watch (WP-4.4):
    /// a refusal when it ends the watch or sends nothing within the transport's bound.
    fn receive(&mut self) -> BoxFuture<'_, Result<Vec<u8>, Refusal>>;
}

/// Opens one session to a coordinator, sends one request, reads one answer.
pub trait Connector: Send + Sync {
    /// Opens a PeerChannel, completes both connection-bound proofs, then closes it without
    /// sending a membership or task request.
    fn prove(&self, target: Target) -> BoxFuture<'_, Result<ProvedPeer, Refusal>> {
        let _ = target;
        Box::pin(std::future::ready(Err(Refusal {
            code: permguard_core::codes::host::PEER_CLIENT_UNCONFIGURED,
            reason: "this connector proves no peer session".to_owned(),
        })))
    }

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
    /// The coordinator as the session proved it: what a re-pin's manifest and lease verify under.
    peer: crate::identity::Verified,
    /// The request id of the watch this session became (WP-4.4).
    watch: Option<String>,
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
        self.exchange(MessageKind::Handler, request_id, body).await
    }

    /// Reports `progress` for this session's task (WP-4.4): the coordinator keeps it, exactly, with
    /// the time it arrived, and answers both.
    pub async fn report(
        &mut self,
        progress: &TaskProgress,
    ) -> Result<ProgressAnswer, MembershipError> {
        let request_id = format!("progress-{}", progress.report_seq);
        let answer = self
            .exchange(MessageKind::Progress, &request_id, progress.encode()?)
            .await?;
        Ok(ProgressAnswer::decode(&answer)?)
    }

    /// Sends `body` as a message of `kind`, for tests that send what a member never would.
    #[cfg(test)]
    pub(crate) async fn exchange_for_tests(
        &mut self,
        kind: MessageKind,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, MembershipError> {
        self.exchange(kind, "test", body).await
    }

    /// Sends `cutover`, the first sequence of each stream under a re-pinned set (WP-4.5): answered
    /// once the coordinator journaled it.
    pub async fn cutover(&mut self, cutover: &Cutover) -> Result<(), MembershipError> {
        self.exchange(
            MessageKind::Cutover,
            &format!("cutover-{}-{}", cutover.ring, cutover.epoch),
            cutover.encode()?,
        )
        .await
        .map(|_| ())
    }

    /// Turns this session into a watch from `positions`, the counter held per key (WP-4.4): the
    /// coordinator answers at once, then sends hints and heartbeats, read with
    /// [`MemberTask::next_event`]. The session takes no other message.
    pub async fn watch(&mut self, positions: Vec<(String, u64)>) -> Result<(), MembershipError> {
        let request_id = "watch".to_owned();
        let answer = self
            .exchange(
                MessageKind::Watch,
                &request_id,
                WatchRequest { positions }.encode()?,
            )
            .await?;
        WatchEvent::decode(&answer)?;
        self.watch = Some(request_id);
        Ok(())
    }

    /// The next event of this session's watch: hints, or none for a heartbeat.
    pub async fn next_event(&mut self) -> Result<WatchEvent, MembershipError> {
        let Some(request_id) = self.watch.clone() else {
            return Err(MembershipError::Invalid(
                "this session is not a watch".to_owned(),
            ));
        };
        let frame = self.channel.receive().await.map_err(remote)?;
        let answer = TaskAnswer::decode(&frame)?;
        if answer.request_id != request_id {
            return Err(MembershipError::Unverified(
                "the event names another request".to_owned(),
            ));
        }
        Ok(WatchEvent::decode(&answer.body)?)
    }

    async fn exchange(
        &mut self,
        kind: MessageKind,
        request_id: &str,
        body: Vec<u8>,
    ) -> Result<Vec<u8>, MembershipError> {
        let message = TaskMessage {
            membership_id: self.lease.membership_id,
            task_id: self.lease.task_id.clone(),
            epoch: self.lease.epoch,
            request_id: request_id.to_owned(),
            body,
            kind,
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
    /// The streams this Host signs, as a re-pin cuts them over (WP-5.2); without an engine it
    /// signs none.
    pub streams: Option<&'a dyn crate::composition::StreamCutovers>,
    /// The streams this Host ships, as its ship tasks deliver them (WP-5.4); without an engine
    /// it ships none.
    pub shipping: Option<&'a dyn crate::composition::StreamShipping>,
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
        // the coordinator would refuse it. Only this identity's: after a reset the membership an
        // old identity joined is never the new one's (WP-4.9).
        if let Some((_, held)) = self.store.memberships().into_iter().find(|(_, held)| {
            held.role == Role::Member
                && held.request.invite_id == join.invite_id
                && held.request.coordinator.host_id == join.coordinator.host_id
                && held.request.member.host_id == self.identity.host_id()
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
            if !self
                .capabilities
                .acts(task.task_type, task.version, Role::Member)
            {
                return Err(MembershipError::TaskUnserved(format!(
                    "no Plane of this Host registered the {} of `{}` version {}",
                    super::record::ContractRole::of(task.task_type, Role::Member).as_str(),
                    task.task_type.as_str(),
                    task.version
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
        let capabilities = self.capabilities.list();
        let request_capabilities = capabilities.clone();
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
                capabilities: request_capabilities.clone(),
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
            capabilities,
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

    /// Accepts `envelope`, a revision the coordinator answered on a task session, as the exact
    /// successor of the manifest held.
    fn accept_revision(
        &self,
        initiator: Initiator,
        id: &[u8; 16],
        peer: &crate::identity::Verified,
        envelope: Vec<u8>,
        now: u64,
    ) -> Result<(), MembershipError> {
        let held = self.store.membership(id).ok_or_else(|| {
            MembershipError::Unknown(format!("no membership `{}`", uuid_text(id)))
        })?;
        let statements = self.store.statements_held(id, held.epoch());
        let accepted = self.store.check_sync(
            id,
            peer,
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
                            .accept_with(applying, &manifest, &envelope, &digest, &statements, now)
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
        Ok(())
    }

    /// Re-pins this Host's `ring` on the membership of `task` (WP-4.5): the statement of the
    /// ring's current set, the manifest the coordinator answers accepted as the exact successor
    /// carrying it, and the new lease on the same connection, which the session goes on under.
    /// Only once this returns may the ring's prepublished key take over.
    pub async fn repin(
        &self,
        initiator: Initiator,
        task: &mut MemberTask,
        ring: &str,
    ) -> Result<(), MembershipError> {
        let id = task.lease.membership_id;
        let statement = super::statement_of(
            self.rings
                .iter()
                .find(|held| held.id() == ring)
                .ok_or_else(|| MembershipError::Ring(format!("this Host composes no `{ring}`")))?,
        )?;
        let answer = task
            .exchange(
                MessageKind::Repin,
                &format!("repin-{ring}-{}", statement.epoch),
                statement.encode()?,
            )
            .await?;
        let answer = LeaseAnswer::decode(&answer)?;
        let envelope = answer.manifest.ok_or_else(|| {
            MembershipError::Unverified("the re-pin answered no manifest".to_owned())
        })?;
        let now = self.time.now_secs();
        let peer = task.peer.clone();
        // A revision this Host cannot verify with the statements it holds (the coordinator's own
        // rings moved since) is fetched with them by a sync (after the review).
        if let Err(MembershipError::Unverified(_)) =
            self.accept_revision(initiator.clone(), &id, &peer, envelope, now)
        {
            self.sync(initiator, &id).await?;
        }
        let held = self.store.membership(&id).ok_or_else(|| {
            MembershipError::Storage("the membership is no longer held".to_owned())
        })?;
        let Some((manifest, ..)) = &held.manifest else {
            return Err(MembershipError::Storage("no manifest held".to_owned()));
        };
        // The manifest pins the set this Host presented, and keeps the one it replaced retiring.
        let pinned = manifest.ring_pins.iter().any(|pin| {
            pin.owner == Role::Member
                && pin.ring == ring
                && !pin.retiring
                && pin.epoch == statement.epoch
                && pin.binding == statement.binding
        });
        if !pinned {
            return Err(MembershipError::Unverified(format!(
                "the manifest does not pin the `{ring}` set this Host presented"
            )));
        }
        let statements = self.store.statements_held(&id, manifest.epoch);
        let lease = super::verify_lease(&answer.lease, &peer, manifest, &statements)?;
        let skew = manifest.lease_policy.clock_skew_seconds;
        let same = Lease {
            epoch: task.lease.epoch,
            issued_at: task.lease.issued_at,
            ..lease.clone()
        } == task.lease;
        if !same || lease.epoch != manifest.epoch || lease.issued_at > now.saturating_add(skew) {
            return Err(MembershipError::Unverified(
                "the re-pin's lease is not this session's at the manifest's epoch".to_owned(),
            ));
        }
        self.store.keep_lease(&id, &lease.task_id, &answer.lease)?;
        task.lease = lease;
        Ok(())
    }

    /// A task session of `id` on the first of `tasks` that takes one, over its selector's prefix.
    async fn any_session(
        &self,
        initiator: &Initiator,
        id: &[u8; 16],
        tasks: &[Task],
    ) -> Result<MemberTask, MembershipError> {
        let mut last = MembershipError::Invalid("the membership grants no task".to_owned());
        for task in tasks {
            match self
                .open_task(
                    initiator.clone(),
                    id,
                    &task.task_id,
                    &task.selector.prefix().to_string(),
                    Vec::new(),
                )
                .await
            {
                Ok(session) => return Ok(session),
                Err(error) => last = error,
            }
        }
        Err(last)
    }

    /// Ends the grace of every ring of this Host that an active membership it is a member of keeps
    /// retiring, once the ring activated its new key: the cutover names each stream the
    /// membership fences under the ring from the first sequence the new key seals, and is
    /// stream-less only when this Host signs none (WP-5.2, owner decision). A stream engine that
    /// cannot say which streams it signs sends nothing. Answers how many rings were cut over.
    pub async fn cutover_due(&self, initiator: Initiator) -> usize {
        let mut done = 0;
        for (id, held) in self.store.memberships() {
            if held.role != Role::Member || held.status != Status::Active {
                continue;
            }
            let Some((manifest, ..)) = &held.manifest else {
                continue;
            };
            for pin in manifest
                .ring_pins
                .iter()
                .filter(|pin| pin.owner == Role::Member && !pin.retiring)
            {
                let retiring = manifest.ring_pins.iter().any(|other| {
                    other.owner == Role::Member && other.ring == pin.ring && other.retiring
                });
                let Some(ring) = self.rings.iter().find(|ring| ring.id() == pin.ring) else {
                    continue;
                };
                // Activated: the ring holds no key waiting to take over.
                let activated = ring.view().ok().is_some_and(|view| {
                    view.keys
                        .iter()
                        .all(|key| key.state != crate::keys::record::State::Prepublished)
                });
                if !retiring || !activated {
                    continue;
                }
                let streams = match self.due_streams(&id, ring) {
                    Ok(streams) => streams,
                    Err(error) => {
                        tracing::warn!(
                            event.name = "host.membership.cutover_failed",
                            component = "host",
                            membership_id = %uuid_text(&id),
                            ring = %pin.ring,
                            error = %error,
                            "a ring's streams are unknown: no cutover is sent, the next pass tries again"
                        );
                        continue;
                    }
                };
                let sent = async {
                    let mut session = self.any_session(&initiator, &id, &manifest.tasks).await?;
                    let mut chunks: Vec<&[(String, u64)]> =
                        streams.1.chunks(super::record::MAX_STREAMS).collect();
                    if chunks.is_empty() {
                        chunks.push(&[]);
                    }
                    for chunk in chunks {
                        session
                            .cutover(&Cutover {
                                ring: pin.ring.clone(),
                                epoch: pin.epoch,
                                streams: chunk.to_vec(),
                            })
                            .await?;
                    }
                    Ok::<_, MembershipError>(())
                }
                .await;
                match sent {
                    Ok(()) => {
                        done += 1;
                        if let (Some(engine), false) = (self.streams, streams.1.is_empty())
                            && let Err(error) = engine.journaled(&pin.ring, &streams.0, &streams.1)
                        {
                            tracing::warn!(
                                event.name = "host.membership.cutover_failed",
                                component = "host",
                                membership_id = %uuid_text(&id),
                                ring = %pin.ring,
                                error = %error,
                                "a journaled cutover could not be recorded: the next pass sends it again"
                            );
                        }
                    }
                    Err(error) => tracing::warn!(
                        event.name = "host.membership.cutover_failed",
                        component = "host",
                        membership_id = %uuid_text(&id),
                        ring = %pin.ring,
                        error = %error,
                        "a ring's cutover could not be sent: the next pass tries again"
                    ),
                }
            }
        }
        done
    }

    /// Ships what every active ship task of this Host's memberships has due (WP-5.4, owner
    /// decision): per stream, a session on its resource, batches until the engine has none or an
    /// answer stops it. A store the coordinator cannot reach now backs the subscription off.
    /// Answers how many batches were answered.
    /// Keeps a subscription for every ship task of every membership this Host is a member of
    /// and that has not ended, without shipping (WP-5.8, after the review): what a drain judges
    /// against, so a membership no pass reached yet is never taken as owed nothing.
    pub fn register_subscriptions(&self) -> Result<(), String> {
        let Some(engine) = self.shipping else {
            return Ok(());
        };
        for (id, held) in self.store.memberships() {
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
            for task in manifest.tasks.iter().filter(|task| {
                matches!(
                    task.task_type,
                    super::record::TaskType::DecisionsShip | super::record::TaskType::EventsShip
                )
            }) {
                engine.due(&crate::composition::Subscribed {
                    membership_id: id,
                    task_type: task.task_type,
                    task_id: &task.task_id,
                    required: task.required,
                    epoch: manifest.epoch,
                    selector: &task.selector,
                })?;
            }
        }
        Ok(())
    }

    pub async fn ship_due(&self, initiator: Initiator) -> usize {
        let Some(engine) = self.shipping else {
            return 0;
        };
        let mut shipped = 0;
        for (id, held) in self.store.memberships() {
            if held.role != Role::Member {
                continue;
            }
            // A membership that ended, a signed change, leaves its subscriptions: they stop
            // blocking deletion (after the review). A suspended one keeps them, to resume.
            if matches!(
                held.status,
                Status::Revoked | Status::Rejected | Status::Expired | Status::Orphaned
            ) {
                if let Err(error) = engine.retain(&id, &[]) {
                    tracing::warn!(
                        event.name = "host.membership.ship_failed",
                        component = "host",
                        membership_id = %uuid_text(&id),
                        error = %error,
                        "the subscriptions of an ended membership could not be dropped"
                    );
                }
                continue;
            }
            if held.status != Status::Active {
                continue;
            }
            let Some((manifest, ..)) = &held.manifest else {
                continue;
            };
            let tasks: Vec<&super::record::Task> = manifest
                .tasks
                .iter()
                .filter(|task| {
                    matches!(
                        task.task_type,
                        super::record::TaskType::DecisionsShip
                            | super::record::TaskType::EventsShip
                    )
                })
                .collect();
            let ids: Vec<String> = tasks.iter().map(|task| task.task_id.clone()).collect();
            if let Err(error) = engine.retain(&id, &ids) {
                tracing::warn!(
                    event.name = "host.membership.ship_failed",
                    component = "host",
                    membership_id = %uuid_text(&id),
                    error = %error,
                    "the subscriptions of a membership could not be kept to its manifest"
                );
            }
            for task in tasks {
                let subscription = crate::composition::Subscribed {
                    membership_id: id,
                    task_type: task.task_type,
                    task_id: &task.task_id,
                    required: task.required,
                    epoch: manifest.epoch,
                    selector: &task.selector,
                };
                let resources = match engine.due(&subscription) {
                    Ok(resources) => resources,
                    Err(error) => {
                        tracing::warn!(
                            event.name = "host.membership.ship_failed",
                            component = "host",
                            membership_id = %uuid_text(&id),
                            task = %task.task_id,
                            error = %error,
                            "a ship task's streams could not be read: the next pass tries again"
                        );
                        continue;
                    }
                };
                for resource in resources {
                    match self
                        .ship_stream(&initiator, &subscription, &resource, engine)
                        .await
                    {
                        Ok(count) => shipped += count,
                        Err(error) => tracing::warn!(
                            event.name = "host.membership.ship_failed",
                            component = "host",
                            membership_id = %uuid_text(&id),
                            task = %task.task_id,
                            error = %error,
                            "a stream could not be shipped: the next pass tries again"
                        ),
                    }
                }
            }
        }
        shipped
    }

    /// Ships `resource`'s stream on one session of `subscription`'s task.
    async fn ship_stream(
        &self,
        initiator: &Initiator,
        subscription: &crate::composition::Subscribed<'_>,
        resource: &str,
        engine: &dyn crate::composition::StreamShipping,
    ) -> Result<usize, MembershipError> {
        let storage = MembershipError::Storage;
        let mut session = self
            .open_task(
                initiator.clone(),
                &subscription.membership_id,
                subscription.task_id,
                resource,
                Vec::new(),
            )
            .await?;
        let max_bytes = session.lease.limits.max_body_bytes;
        // The lease's epoch: a revision the session took is the one a pause is set at (after the
        // review).
        let subscription = &crate::composition::Subscribed {
            epoch: session.lease.epoch,
            ..*subscription
        };
        // A stream an incomplete drain left behind is reported to the coordinator (WP-5.8).
        let marked = engine
            .unshipped_on(subscription, resource)
            .map_err(storage)?;
        let mut count = 0;
        let shipped = async {
            while let Some(shipment) = engine
                .next(subscription, resource, max_bytes)
                .map_err(storage)?
            {
                match session
                    .send(&shipment.request_id, shipment.body.clone())
                    .await
                {
                    Ok(answer) => {
                        count += 1;
                        if !engine
                            .answered(subscription, resource, &shipment, &answer)
                            .map_err(storage)?
                        {
                            break;
                        }
                    }
                    Err(MembershipError::Remote { code, .. })
                        if code == permguard_core::codes::stream::STORE_UNAVAILABLE =>
                    {
                        engine.deferred(subscription, resource).map_err(storage)?;
                        break;
                    }
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }
        .await;
        // Reported whatever ended the loop: a pass that shipped the tail and then lost its
        // session still tries to say so before the mark goes (after the review).
        if let Some(marked) = marked {
            let remaining = engine
                .unshipped_on(subscription, resource)
                .map_err(storage)?;
            self.report_unshipped(&mut session, subscription, &marked, remaining.as_ref())
                .await;
        }
        shipped.map(|()| count)
    }

    /// Reports a marked stream on its ship task's session (WP-5.8, interpretation of
    /// 2026-10-15): `unshipped` with its tail and what is acknowledged, or `shipped` once the
    /// mark went. A report that fails is logged: the next pass reports again.
    async fn report_unshipped(
        &self,
        session: &mut MemberTask,
        subscription: &crate::composition::Subscribed<'_>,
        marked: &crate::composition::Unshipped,
        remaining: Option<&crate::composition::Unshipped>,
    ) {
        let resource = match remaining {
            Some(remaining) => super::record::ProgressResource {
                resource: remaining.resource.clone(),
                state: UNSHIPPED.to_owned(),
                frontier: Some(remaining.tail.to_string()),
                checkpoint_digest: None,
                verified_at: None,
                reason: Some(format!("acknowledged through {}", remaining.truncate_safe)),
            },
            None => super::record::ProgressResource {
                resource: marked.resource.clone(),
                state: SHIPPED.to_owned(),
                frontier: Some(marked.tail.to_string()),
                checkpoint_digest: None,
                verified_at: None,
                reason: None,
            },
        };
        let progress = TaskProgress {
            membership_id: subscription.membership_id,
            task_id: subscription.task_id.to_owned(),
            manifest_epoch: session.lease.epoch,
            member_boot_id: self.identity.boot_id(),
            report_seq: REPORT_SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1,
            reported_at: self.time.now_secs(),
            resources: vec![resource],
        };
        if let Err(error) = session.report(&progress).await {
            tracing::warn!(
                event.name = "host.membership.progress_failed",
                component = "host",
                membership_id = %uuid_text(&subscription.membership_id),
                task = %subscription.task_id,
                error = %error,
                "an unshipped stream could not be reported: the next pass reports it again"
            );
        }
    }

    /// The active key of `ring` and the streams of membership `id` it cuts over, in order.
    fn due_streams(
        &self,
        id: &[u8; 16],
        ring: &Ring,
    ) -> Result<(String, Vec<(String, u64)>), String> {
        use permguard_core::keys::Sign as _;
        let kid = ring
            .active_key_id()
            .map_err(|error| error.to_string())?
            .as_str()
            .to_owned();
        let mut streams = match self.streams {
            Some(engine) => engine.due(id, ring.id(), &kid)?,
            None => Vec::new(),
        };
        streams.sort();
        streams.dedup();
        if streams.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err("a stream is due from two sequences".to_owned());
        }
        Ok((kid, streams))
    }

    /// Re-pins every ring of this Host that an active membership it is a member of pins at an
    /// older epoch (WP-4.5): one task session per ring and membership, on the first task that
    /// takes one. A failure is logged and the next one tried; answers how many were re-pinned.
    pub async fn repin_due(&self, initiator: Initiator) -> usize {
        let mut done = 0;
        for (id, held) in self.store.memberships() {
            if held.role != Role::Member || held.status != Status::Active {
                continue;
            }
            let Some((manifest, ..)) = &held.manifest else {
                continue;
            };
            for pin in manifest
                .ring_pins
                .iter()
                .filter(|pin| pin.owner == Role::Member && !pin.retiring)
            {
                let lagging = self
                    .rings
                    .iter()
                    .find(|ring| ring.id() == pin.ring)
                    .and_then(|ring| super::statement_of(ring).ok())
                    .is_some_and(|statement| statement.epoch > pin.epoch);
                if !lagging {
                    continue;
                }
                let repinned = async {
                    let mut session = self.any_session(&initiator, &id, &manifest.tasks).await?;
                    self.repin(initiator.clone(), &mut session, &pin.ring).await
                }
                .await;
                match repinned {
                    Ok(()) => done += 1,
                    Err(error) => tracing::warn!(
                        event.name = "host.membership.repin_failed",
                        component = "host",
                        membership_id = %uuid_text(&id),
                        ring = %pin.ring,
                        error = %error,
                        "a ring could not be re-pinned: the next pass tries again, and its key waits"
                    ),
                }
            }
        }
        done
    }

    /// Opens a task session of `id` over `resource` (WP-4.3): only the member opens one. The
    /// lease is verified under the coordinator's pinned operations key, bound to this
    /// connection and this incarnation, and kept; evidence, when given, is appraised first and
    /// the revised manifest accepted as the exact successor.
    /// A coordinator that moved past the epoch held is synced with once, and the session asked
    /// for again (WP-4.5, after the review: its own rings re-pinned).
    pub async fn open_task(
        &self,
        initiator: Initiator,
        id: &[u8; 16],
        task_id: &str,
        resource: &str,
        evidence: Vec<(String, Vec<u8>)>,
    ) -> Result<MemberTask, MembershipError> {
        match self
            .open_task_once(initiator.clone(), id, task_id, resource, evidence.clone())
            .await
        {
            Err(MembershipError::Remote { code, .. })
                if code == permguard_core::codes::host::EPOCH_STALE =>
            {
                self.sync(initiator.clone(), id).await?;
                self.open_task_once(initiator, id, task_id, resource, evidence)
                    .await
            }
            other => other,
        }
    }

    async fn open_task_once(
        &self,
        initiator: Initiator,
        id: &[u8; 16],
        task_id: &str,
        resource: &str,
        evidence: Vec<(String, Vec<u8>)>,
    ) -> Result<MemberTask, MembershipError> {
        // A reset under way opens no task session under the identity it retires (WP-4.9).
        self.store.unfenced()?;
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
            self.accept_revision(initiator.clone(), id, &opened.peer, envelope, now)?;
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
            peer: opened.peer.clone(),
            watch: None,
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
