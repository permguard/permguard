// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Task sessions, leases and fencing (WP-4.3; owner decisions of 2026-10-10).
//!
//! The member opens every task session; the coordinator never dials. On a proven `task`
//! session naming one membership and one task, the first frame is a [`LeaseRequest`]: the
//! coordinator finds the membership active, the peer its member and the epoch its own, admits
//! the task over the resource ([`super::appraisal::Appraisal::admit`]), refuses a second
//! incarnation of the member while another holds an open session (the clone alarm), and signs a
//! [`Lease`] bound to the connection. Every later frame is a [`TaskMessage`], fenced on its epoch
//! and on the lease's expiry before the task's handler (WP-4.4) sees it.
//!
//! | Observation                         | Answer                                                    |
//! | ----------------------------------- | --------------------------------------------------------- |
//! | an epoch below the current one      | `epoch_stale`, audited, the session ended                 |
//! | an epoch above any issued           | `epoch_unknown`, audited, the membership held until revoked |
//! | the lease expired                   | `lease_expired`, the session ended                        |
//! | another boot id holds a session     | `clone_suspected`, the membership suspended, a clone alarm |
//! | the clock in anomaly                | no new lease (`unavailable`)                              |

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use permguard_core::authz::Resource;
use permguard_core::codes;
use permguard_core::domains::protected;
use permguard_core::keys::Sign as _;
use permguard_core::{AuditEvent, AuditOutcome, Fact, Subject};
use permguard_objects::cose::Sign1;

use super::appraisal::{Appraisal, Evidence};
use super::record::{
    LastSession, Lease, LeaseAnswer, LeaseRequest, Limits, MessageKind, ProgressAnswer, Status,
    TaskAnswer, TaskMessage, TaskProgress, TaskType, WatchRequest, channel_binding,
};
use super::replay::{Gate, message_digest};
use super::watch::{Hub, LeaseFence, Watch};
use super::{
    APPRAISE, AUDIT_APPRAISED, AUDIT_SUSPENDED, DOMAIN, Held, MembershipError, Offered, SUSPEND,
};
use crate::identity::Verified;
use crate::identity::record::{subject, uuid_text};
use crate::keys::ring::HOST_OPERATIONS;
use crate::operations::journal::Initiator;
use crate::operations::mutation::{Applied, Begin, Failure, Outcome};
use crate::session::record::EXPORTER_BYTES;
use crate::session::{Refusal, Session, TaskRefusal, TaskSession, Watching};

/// A lease was issued (`security`).
pub const AUDIT_LEASE_ISSUED: &str = "host.membership.lease_issued";
/// A message or lease request named an epoch below the membership's (`security`).
pub const AUDIT_EPOCH_STALE: &str = "host.membership.epoch_stale";
/// A message or lease request named an epoch this coordinator never issued (`security`).
pub const AUDIT_EPOCH_UNKNOWN: &str = "host.membership.epoch_unknown";
/// Two incarnations of one member, two boot ids, at once (`security`).
pub const AUDIT_CLONE_ALARM: &str = "host.membership.clone_alarm";
/// A membership held for review, a mutation of the store.
pub const AUDIT_HELD: &str = "host.membership.held";
/// The operation that holds a membership for review.
pub const HOLD: &str = "members.hold";

/// One open task session, as the coordinator holds it in memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Live {
    pub task_id: String,
    pub epoch: u64,
    pub member_boot_id: [u8; 16],
    pub coordinator_boot_id: [u8; 16],
    pub opened_at: u64,
    pub expires_at: u64,
}

/// The open task sessions, by membership (owner decision: in memory, the connection alive).
#[derive(Debug, Default)]
pub struct LiveSessions {
    sessions: Mutex<BTreeMap<[u8; 16], BTreeMap<u64, Live>>>,
    next: Mutex<u64>,
}

/// Why a session was not opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unopened {
    /// Another incarnation of the member holds this open session.
    Clone(Live),
    /// The task holds its signed `max_concurrency` of running sessions.
    Busy,
}

/// Holds one session open; dropped with its connection.
#[derive(Debug)]
pub struct Opened {
    sessions: Arc<LiveSessions>,
    membership_id: [u8; 16],
    key: u64,
}

impl Drop for Opened {
    fn drop(&mut self) {
        let mut sessions = self
            .sessions
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(open) = sessions.get_mut(&self.membership_id) {
            open.remove(&self.key);
            if open.is_empty() {
                sessions.remove(&self.membership_id);
            }
        }
    }
}

impl LiveSessions {
    /// Opens `live` for `membership_id`, unless another incarnation of the member holds an open
    /// session whose lease runs at `now` (that one is answered), or its task already holds
    /// `max_concurrency` running sessions (WP-4.4).
    pub(crate) fn open(
        self: &Arc<Self>,
        membership_id: [u8; 16],
        live: Live,
        now: u64,
        max_concurrency: u64,
    ) -> Result<Opened, Unopened> {
        let mut sessions = self.sessions.lock().unwrap_or_else(PoisonError::into_inner);
        let open = sessions.entry(membership_id).or_default();
        if let Some(other) = open
            .values()
            .find(|other| other.member_boot_id != live.member_boot_id && now < other.expires_at)
        {
            return Err(Unopened::Clone(other.clone()));
        }
        let running = open
            .values()
            .filter(|other| other.task_id == live.task_id && now < other.expires_at)
            .count();
        if u64::try_from(running).unwrap_or(u64::MAX) >= max_concurrency {
            return Err(Unopened::Busy);
        }
        let key = {
            let mut next = self.next.lock().unwrap_or_else(PoisonError::into_inner);
            *next += 1;
            *next
        };
        open.insert(key, live);
        Ok(Opened {
            sessions: Arc::clone(self),
            membership_id,
            key,
        })
    }

    /// An open session of `membership_id` from another incarnation than `boot_id`, its lease
    /// running at `now`.
    fn conflict(&self, membership_id: &[u8; 16], boot_id: &[u8; 16], now: u64) -> Option<Live> {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(membership_id)?
            .values()
            .find(|other| other.member_boot_id != *boot_id && now < other.expires_at)
            .cloned()
    }

    /// The open sessions of `membership_id`.
    pub fn of(&self, membership_id: &[u8; 16]) -> Vec<Live> {
        self.sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(membership_id)
            .map(|open| open.values().cloned().collect())
            .unwrap_or_default()
    }
}

/// What a task's handler is told of the message it answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskContext {
    pub membership_id: [u8; 16],
    pub task_id: String,
    pub task_type: TaskType,
    /// The contract version the task speaks (WP-4.4).
    pub version: u64,
    pub epoch: u64,
    pub resource: String,
    pub member: [u8; 16],
    pub request_id: String,
    /// The task's signed limits: `max_batch_records` and `retention_seconds` are the handler's
    /// to apply (WP-4.4, owner decision).
    pub limits: Limits,
}

/// The handler a Plane registers for a task type and version (WP-4.4; none ships before
/// WP-4.7 and WP-7.x, so a declared contract answers `not_served_yet` until then).
pub trait TaskHandler: Send + Sync {
    /// Answers one message's body, or refuses it with a stable code; the session stays open.
    fn handle(&self, context: &TaskContext, body: &[u8]) -> Result<Vec<u8>, Refusal>;
}

/// The task handlers by task type and contract version (WP-4.4). A contract a Plane declared
/// without registering its handler answers `not_served_yet`.
#[derive(Clone, Default)]
pub struct TaskHandlers(BTreeMap<(TaskType, u64), Arc<dyn TaskHandler>>);

impl std::fmt::Debug for TaskHandlers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_list().entries(self.0.keys()).finish()
    }
}

impl TaskHandlers {
    pub fn register(mut self, task: TaskType, version: u64, handler: Arc<dyn TaskHandler>) -> Self {
        self.0.insert((task, version), handler);
        self
    }
}

/// What the coordinator's task sessions share: the open sessions, the appraisal, the handlers, the
/// rate windows and the watches.
#[derive(Debug)]
pub struct Tasks {
    pub live: Arc<LiveSessions>,
    pub appraisal: Arc<Appraisal>,
    pub handlers: TaskHandlers,
    /// The messages of the last minute, by membership and task (WP-4.4).
    pub rates: Rates,
    /// Where handlers publish watch hints (WP-4.4).
    pub hub: Arc<Hub>,
    /// How long a quiet watch waits before its heartbeat.
    pub watch_heartbeat: std::time::Duration,
}

impl Default for Tasks {
    fn default() -> Self {
        Self {
            live: Arc::default(),
            appraisal: Arc::default(),
            handlers: TaskHandlers::default(),
            rates: Rates::default(),
            hub: Arc::default(),
            watch_heartbeat: super::watch::HEARTBEAT,
        }
    }
}

/// When each of a task's messages of the last minute arrived, by membership and task.
type Taken = BTreeMap<([u8; 16], String), std::collections::VecDeque<u64>>;

/// The messages each task took in its last minute, against its signed `max_rate_per_minute`.
#[derive(Debug, Default)]
pub struct Rates(Mutex<Taken>);

impl Rates {
    /// Counts one message of `task_id` of `membership_id` at `now`, unless the task took
    /// `max_per_minute` in the minute before.
    fn admit(
        &self,
        membership_id: &[u8; 16],
        task_id: &str,
        max_per_minute: u64,
        now: u64,
    ) -> bool {
        let mut rates = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let taken = rates
            .entry((*membership_id, task_id.to_owned()))
            .or_default();
        while taken.front().is_some_and(|at| at.saturating_add(60) <= now) {
            taken.pop_front();
        }
        if u64::try_from(taken.len()).unwrap_or(u64::MAX) >= max_per_minute {
            return false;
        }
        taken.push_back(now);
        true
    }
}

fn refusal(code: &'static str, reason: impl Into<String>) -> Refusal {
    Refusal {
        code,
        reason: reason.into(),
    }
}

fn ended(code: &'static str, reason: impl Into<String>) -> TaskRefusal {
    TaskRefusal {
        refusal: refusal(code, reason),
        end: true,
    }
}

fn of(error: MembershipError) -> Refusal {
    refusal(super::service::code_of(&error), error.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl super::service::Coordinating {
    /// Writes a `security` record of a task session's observation; a record refused is logged,
    /// never answered to the peer as anything but the refusal it accompanies.
    fn observe(&self, action: &str, peer: &Verified, target: &str, facts: &[(&str, Fact<'_>)]) {
        let who = subject(&peer.host_id);
        let event = AuditEvent::new(action, Subject::System(&who))
            .on(target)
            .with_outcome(AuditOutcome::Ok)
            .with_facts(facts);
        if let Err(error) = self.mutations.project(&event) {
            tracing::error!(
                event.name = "host.membership.task_unrecorded",
                component = "host",
                action = action,
                error = %error,
                "a task session observation could not be recorded in the security trail"
            );
        }
    }

    /// The epoch a peer named against the membership's: stale and unknown are refused and
    /// audited, unknown also holds the membership for review.
    fn fence(
        &self,
        peer: &Verified,
        held: &Held,
        task_id: &str,
        named: u64,
        now: u64,
    ) -> Result<(), Refusal> {
        let id = held.request.membership_id;
        let target = uuid_text(&id);
        let current = held.epoch();
        if named < current {
            self.observe(
                AUDIT_EPOCH_STALE,
                peer,
                &target,
                &[
                    ("task", Fact::Text(task_id)),
                    ("presented", Fact::Uint(named)),
                    ("current", Fact::Uint(current)),
                ],
            );
            return Err(refusal(
                codes::host::EPOCH_STALE,
                format!("epoch {named} is behind the membership's {current}: sync and ask again"),
            ));
        }
        if named > current {
            self.observe(
                AUDIT_EPOCH_UNKNOWN,
                peer,
                &target,
                &[
                    ("task", Fact::Text(task_id)),
                    ("presented", Fact::Uint(named)),
                    ("current", Fact::Uint(current)),
                ],
            );
            if let Err(error) = self.hold(peer, &id, named, now) {
                tracing::error!(
                    event.name = "host.membership.hold_failed",
                    component = "host",
                    membership_id = %target,
                    error = %error,
                    "a membership naming an unknown epoch could not be held for review"
                );
            }
            return Err(refusal(
                codes::host::EPOCH_UNKNOWN,
                format!("epoch {named} was never issued: the membership is held for review"),
            ));
        }
        Ok(())
    }

    fn hold(
        &self,
        peer: &Verified,
        id: &[u8; 16],
        seen: u64,
        now: u64,
    ) -> Result<(), MembershipError> {
        self.mutations
            .run(
                Begin {
                    domain: DOMAIN,
                    operation: HOLD,
                    action: AUDIT_HELD,
                    initiator: Initiator::System(subject(&peer.host_id)),
                    request: None,
                    target: Some(uuid_text(id)),
                },
                |applying| {
                    self.store
                        .hold(applying, id, seen, now)
                        .map_err(Failure::Refused)?;
                    Ok(Applied {
                        revision: 0,
                        target: Some(uuid_text(id)),
                        value: (),
                    })
                },
            )
            .map(|_| ())
            .map_err(|error| MembershipError::Storage(error.to_string()))
    }

    /// Suspends a membership on a clone alarm: a `suspended` manifest, a new epoch.
    fn suspend_clone(
        &self,
        peer: &Verified,
        id: &[u8; 16],
        now: u64,
    ) -> Result<(), MembershipError> {
        let coordinator = self.coordinator();
        let manifest =
            self.store
                .check_successor(&coordinator, id, Status::Suspended, None, now)?;
        let outcome = self
            .mutations
            .run(
                Begin {
                    domain: DOMAIN,
                    operation: SUSPEND,
                    action: AUDIT_SUSPENDED,
                    initiator: Initiator::System(subject(&peer.host_id)),
                    request: None,
                    target: Some(uuid_text(id)),
                },
                |applying| {
                    self.store
                        .transition(applying, &coordinator, &manifest, now)
                        .map_err(Failure::Refused)?;
                    Ok(Applied {
                        revision: 0,
                        target: Some(uuid_text(id)),
                        value: (),
                    })
                },
            )
            .map_err(|error| MembershipError::Storage(error.to_string()))?;
        match outcome {
            Outcome::Applied(()) => Ok(()),
            _ => Err(MembershipError::Storage(
                "the suspension answered without applying".to_owned(),
            )),
        }
    }

    /// Appraises the evidence a lease request brings, as `POST …/appraise` does, the member's
    /// Host as the appraiser: the revised manifest and its envelope.
    fn appraise_at_session(
        &self,
        peer: &Verified,
        id: &[u8; 16],
        evidence: Vec<Evidence>,
        now: u64,
    ) -> Result<Vec<u8>, MembershipError> {
        let coordinator = self.coordinator();
        let who = subject(&peer.host_id);
        let (manifest, _) = self.store.check_appraise(
            &coordinator,
            id,
            &Offered {
                appraisal: &self.tasks.appraisal,
                approvals: &[],
                evidence: &evidence,
                principal: &who,
            },
            false,
            None,
            now,
        )?;
        let outcome = self
            .mutations
            .run(
                Begin {
                    domain: DOMAIN,
                    operation: APPRAISE,
                    action: AUDIT_APPRAISED,
                    initiator: Initiator::System(who.clone()),
                    request: None,
                    target: Some(uuid_text(id)),
                },
                |applying| {
                    let (envelope, _) = self
                        .store
                        .transition(applying, &coordinator, &manifest, now)
                        .map_err(Failure::Refused)?;
                    Ok(Applied {
                        revision: 0,
                        target: Some(uuid_text(id)),
                        value: envelope,
                    })
                },
            )
            .map_err(|error| match error {
                crate::operations::mutation::MutationError::Refused(error) => error,
                other => MembershipError::Storage(other.to_string()),
            })?;
        match outcome {
            Outcome::Applied(envelope) => Ok(envelope),
            _ => Err(MembershipError::Storage(
                "the appraisal answered without applying".to_owned(),
            )),
        }
    }

    /// Opens a task session: the lease, or the refusal that ends the session.
    pub(super) fn open_lease(
        &self,
        session: &Session,
        peer: &Verified,
        exporter: &[u8; EXPORTER_BYTES],
        bytes: &[u8],
    ) -> Result<(Vec<u8>, Box<dyn TaskSession>), Refusal> {
        let request = LeaseRequest::decode(bytes)
            .map_err(|error| refusal(codes::common::INVALID_ARGUMENT, error.0))?;
        let id = request.membership_id;
        // The hello named the membership and the task; the request may name no other.
        if session.membership_id.as_deref() != Some(uuid_text(&id).as_str())
            || session.task.as_deref() != Some(request.task_id.as_str())
        {
            return Err(refusal(
                codes::common::INVALID_ARGUMENT,
                "the lease request names another membership or task than the session",
            ));
        }
        let held = self
            .store
            .membership(&id)
            .filter(|held| {
                held.role == super::record::Role::Coordinator
                    && held.request.member.host_id == peer.host_id
            })
            .ok_or_else(|| {
                refusal(
                    codes::host::MEMBERSHIP_UNKNOWN,
                    "no membership of that id names this member",
                )
            })?;
        if let Some(seen) = held.held_epoch {
            return Err(refusal(
                codes::host::MEMBERSHIP_HELD,
                format!("held for review since epoch {seen} was named: revoke it and enroll again"),
            ));
        }
        // No new lease while the clock is in anomaly; a lease's times are wall time.
        // A pending membership has no manifest, no epoch, no task yet: refused before any epoch
        // is read, so nothing pending is ever held.
        let Some((current, ..)) = held.manifest.clone() else {
            return Err(refusal(
                codes::host::MEMBERSHIP_TRANSITION_REFUSED,
                "the membership is pending: no task yet",
            ));
        };
        // No new lease while the clock is in anomaly; a lease's times are wall time.
        let now = self
            .time
            .lease_now()
            .map_err(|anomaly| refusal(codes::common::UNAVAILABLE, anomaly.to_string()))?;
        let now = u64::try_from(now).unwrap_or(0);
        self.fence(peer, &held, &request.task_id, request.epoch, now)?;
        if current.status != Status::Active {
            return Err(refusal(
                codes::host::MEMBERSHIP_TRANSITION_REFUSED,
                format!("the membership is {}: no task is leased", current.status),
            ));
        }
        // The task and the resource, and no other incarnation open, before anything is written.
        let resource = Resource::parse(&request.resource)
            .map_err(|error| refusal(codes::common::INVALID_ARGUMENT, error.to_string()))?;
        let granted = current
            .tasks
            .iter()
            .find(|task| task.task_id == request.task_id)
            .ok_or_else(|| {
                refusal(
                    codes::common::INVALID_ARGUMENT,
                    format!("the membership grants no task `{}`", request.task_id),
                )
            })?;
        if !granted.selector.contains(&resource) {
            return Err(refusal(
                codes::common::INVALID_ARGUMENT,
                format!("`{resource}` is outside the task's selector"),
            ));
        }
        let target = uuid_text(&id);
        if let Some(other) = self.tasks.live.conflict(&id, &request.member_boot_id, now) {
            return Err(self.clone_alarm(peer, &id, &request, &other, now));
        }

        // Evidence at the session revises the binding last, a new epoch (WP-4.2 owner decision).
        let (manifest, revised) = if request.evidence.is_empty() {
            (current, None)
        } else {
            let evidence = request
                .evidence
                .iter()
                .map(|(verifier, evidence)| Evidence {
                    verifier: verifier.clone(),
                    evidence: evidence.clone(),
                })
                .collect();
            let envelope = self
                .appraise_at_session(peer, &id, evidence, now)
                .map_err(of)?;
            let manifest = Sign1::decode(&envelope)
                .ok()
                .and_then(|sign1| super::record::Manifest::decode(sign1.payload_unverified()).ok())
                .ok_or_else(|| refusal(codes::common::UNAVAILABLE, "the revision does not read"))?;
            (manifest, Some(envelope))
        };
        let admitted = self
            .tasks
            .appraisal
            .admit(&manifest, &request.task_id, &resource, now)
            .map_err(of)?;
        let task = manifest
            .tasks
            .iter()
            .find(|task| task.task_id == request.task_id)
            .cloned()
            .ok_or_else(|| refusal(codes::common::INVALID_ARGUMENT, "no such task"))?;
        let expires_at = now
            .saturating_add(manifest.lease_policy.max_session_seconds)
            .min(admitted.not_after.unwrap_or(u64::MAX))
            .min(manifest.not_after);
        let coordinator_boot_id = self.identity.boot_id();

        // Signed only by a key of the operations set the manifest pins: after a rotation the
        // member could not verify it, so none is issued until the re-pin (owner decision).
        let operations = self
            .keys
            .rings()
            .iter()
            .find(|ring| ring.id() == HOST_OPERATIONS)
            .cloned()
            .ok_or_else(|| refusal(codes::common::UNAVAILABLE, "no `host.operations` ring"))?;
        let active = operations
            .active_key_id()
            .map_err(|error| refusal(codes::common::UNAVAILABLE, error.to_string()))?;
        let pinned =
            super::pinned_kids(&manifest, &self.store.statements_held(&id, manifest.epoch));
        if !pinned.iter().any(|kid| kid == active.as_str()) {
            return Err(refusal(
                codes::common::UNAVAILABLE,
                "the operations key rotated past the one the manifest pins: re-pin first",
            ));
        }

        // Open, the clone check repeated under the lock that inserts, the task's signed
        // concurrency with it (WP-4.4).
        let opened = match self.tasks.live.open(
            id,
            Live {
                task_id: request.task_id.clone(),
                epoch: manifest.epoch,
                member_boot_id: request.member_boot_id,
                coordinator_boot_id,
                opened_at: now,
                expires_at,
            },
            now,
            task.limits.max_concurrency,
        ) {
            Ok(opened) => opened,
            Err(Unopened::Clone(other)) => {
                return Err(self.clone_alarm(peer, &id, &request, &other, now));
            }
            Err(Unopened::Busy) => {
                return Err(refusal(
                    codes::host::TASK_BUSY,
                    format!(
                        "the task holds its {} running session(s): open one when another closes",
                        task.limits.max_concurrency
                    ),
                ));
            }
        };

        let lease = Lease {
            membership_id: id,
            task_id: request.task_id.clone(),
            epoch: manifest.epoch,
            coordinator: self.identity.host_id(),
            member: peer.host_id,
            coordinator_boot_id,
            member_boot_id: request.member_boot_id,
            selector: task.selector.clone(),
            resource: request.resource.clone(),
            limits: task.limits,
            issued_at: now,
            expires_at,
            channel_binding: channel_binding(exporter),
            binding_digest: admitted.binding,
        };
        let envelope = sign_lease(&operations, &lease).map_err(of)?;
        // The coordinator's own clock of the task's sessions, what `last_session_at` shows and
        // dormancy reads: kept before the lease is recorded and answered (WP-4.4).
        self.store
            .keep_last_session(
                &id,
                &request.task_id,
                &LastSession {
                    at: now,
                    member_boot_id: request.member_boot_id,
                },
            )
            .map_err(|error| refusal(codes::common::UNAVAILABLE, error.to_string()))?;
        // No lease without its record: the trail refusing it refuses the lease (fail closed).
        let (boot, coordinator_boot) = (hex(&request.member_boot_id), hex(&coordinator_boot_id));
        let who = subject(&peer.host_id);
        self.mutations
            .project(
                &AuditEvent::new(AUDIT_LEASE_ISSUED, Subject::System(&who))
                    .on(&target)
                    .with_outcome(AuditOutcome::Ok)
                    .with_facts(&[
                        ("task", Fact::Text(&request.task_id)),
                        ("epoch", Fact::Uint(manifest.epoch)),
                        ("resource", Fact::Text(&request.resource)),
                        ("member_boot_id", Fact::Text(&boot)),
                        ("coordinator_boot_id", Fact::Text(&coordinator_boot)),
                        ("expires_at", Fact::Uint(expires_at)),
                    ]),
            )
            .map_err(|error| {
                refusal(
                    codes::host::AUDIT_UNAVAILABLE,
                    format!("the lease could not be recorded: {error}"),
                )
            })?;

        let answer = LeaseAnswer {
            lease: envelope,
            manifest: revised,
        }
        .encode()
        .map_err(|error| refusal(codes::common::UNAVAILABLE, error.0))?;
        Ok((
            answer,
            Box::new(CoordinatorTask {
                coordinating: self.clone(),
                peer: peer.clone(),
                lease,
                task_type: task.task_type,
                version: task.version,
                watch: None,
                watching: false,
                _opened: opened,
            }),
        ))
    }

    /// A second incarnation of the member while another holds an open session: the alarm
    /// recorded, the membership suspended, the refusal answered.
    fn clone_alarm(
        &self,
        peer: &Verified,
        id: &[u8; 16],
        request: &LeaseRequest,
        other: &Live,
        now: u64,
    ) -> Refusal {
        let target = uuid_text(id);
        let (open, new) = (hex(&other.member_boot_id), hex(&request.member_boot_id));
        self.observe(
            AUDIT_CLONE_ALARM,
            peer,
            &target,
            &[
                ("task", Fact::Text(&request.task_id)),
                ("open_boot_id", Fact::Text(&open)),
                ("new_boot_id", Fact::Text(&new)),
            ],
        );
        if let Err(error) = self.suspend_clone(peer, id, now) {
            tracing::error!(
                event.name = "host.membership.clone_unsuspended",
                component = "host",
                membership_id = %target,
                error = %error,
                "a membership with two incarnations of its member could not be suspended"
            );
        }
        refusal(
            codes::host::CLONE_SUSPECTED,
            "another incarnation of this member holds a session: the membership is suspended",
        )
    }
}

/// Signs `lease` under the coordinator's `host.operations` ring.
pub fn sign_lease(
    operations: &crate::keys::ring::Ring,
    lease: &Lease,
) -> Result<Vec<u8>, MembershipError> {
    let kid = operations
        .active_key_id()
        .map_err(|error| MembershipError::Ring(error.to_string()))?;
    let envelope = Sign1::sign_with(
        operations.suite(),
        protected::MEMBERSHIP_LEASE,
        kid.as_str().as_bytes(),
        lease.encode()?,
        |bytes| {
            let signature = operations.sign(bytes).map_err(|error| error.to_string())?;
            if signature.key_id() != &kid {
                return Err("the signing key rotated mid-signature".to_owned());
            }
            Ok(signature.bytes().to_vec())
        },
    )
    .map_err(|error| MembershipError::Ring(error.to_string()))?;
    envelope
        .encode()
        .map_err(|error| MembershipError::Ring(error.to_string()))
}

/// The coordinator's side of one open task session.
struct CoordinatorTask {
    coordinating: super::service::Coordinating,
    peer: Verified,
    lease: Lease,
    task_type: TaskType,
    version: u64,
    /// The watch this session became, until the transport takes it.
    watch: Option<Box<dyn Watching>>,
    /// Whether the session became a watch: it takes no other message.
    watching: bool,
    _opened: Opened,
}

fn kept(code: &'static str, reason: impl Into<String>) -> TaskRefusal {
    TaskRefusal {
        refusal: refusal(code, reason),
        end: false,
    }
}

impl CoordinatorTask {
    /// Keeps a progress report the member sent for this session's task (WP-4.4).
    fn progress(&self, message: &TaskMessage, now: u64) -> Result<Vec<u8>, TaskRefusal> {
        let report = TaskProgress::decode(&message.body)
            .map_err(|error| kept(codes::common::INVALID_ARGUMENT, error.0))?;
        if report.membership_id != self.lease.membership_id
            || report.task_id != self.lease.task_id
            || report.manifest_epoch != self.lease.epoch
            || report.member_boot_id != self.lease.member_boot_id
        {
            return Err(kept(
                codes::common::INVALID_ARGUMENT,
                "the report names another membership, task, epoch or incarnation than its session",
            ));
        }
        self.coordinating
            .store
            .keep_progress(&report, &message.body, now)
            .map_err(|error| kept(super::service::code_of(&error), error.to_string()))?;
        let body = ProgressAnswer {
            report_seq: report.report_seq,
            received_at: now,
        }
        .encode()
        .map_err(|error| ended(codes::common::UNAVAILABLE, error.0))?;
        TaskAnswer {
            request_id: message.request_id.clone(),
            body,
        }
        .encode()
        .map_err(|error| ended(codes::common::UNAVAILABLE, error.0))
    }

    /// Turns the session into a watch (WP-4.4): one per session, its answer an empty event.
    fn watch(&mut self, message: &TaskMessage) -> Result<Vec<u8>, TaskRefusal> {
        let request = WatchRequest::decode(&message.body)
            .map_err(|error| kept(codes::common::INVALID_ARGUMENT, error.0))?;
        let parts = &self.coordinating;
        let queue = parts
            .tasks
            .hub
            .subscribe(self.task_type, &self.lease, &request)
            .map_err(|error| ended(codes::common::INVALID_ARGUMENT, error))?;
        let mut watch = Watch {
            queue,
            request_id: message.request_id.clone(),
            fence: Box::new(LeaseFence {
                store: Arc::clone(&parts.store),
                time: Arc::clone(&parts.time),
                lease: self.lease.clone(),
            }),
            heartbeat: parts.tasks.watch_heartbeat,
        };
        let answer = watch
            .heartbeat()
            .map_err(|refusal| TaskRefusal { refusal, end: true })?;
        self.watch = Some(Box::new(watch));
        self.watching = true;
        Ok(answer)
    }

    /// Answers a message for the task's handler through the replay gate (WP-4.4).
    fn handled(&self, message: &TaskMessage, bytes: &[u8]) -> Result<Vec<u8>, TaskRefusal> {
        let parts = &self.coordinating;
        let id = &self.lease.membership_id;
        let digest = message_digest(bytes, &self.lease.resource);
        let reservation = match parts
            .store
            .gate(id, &self.lease.task_id, &message.request_id, &digest)
            .map_err(|error| ended(codes::common::UNAVAILABLE, error.to_string()))?
        {
            Gate::Replay(answer) => return Ok(answer),
            Gate::Reused => {
                return Err(kept(
                    codes::host::REQUEST_ID_REUSED,
                    "this request id answered another message, or is being answered",
                ));
            }
            Gate::New(reservation) => reservation,
        };
        let Some(handler) = parts.tasks.handlers.0.get(&(self.task_type, self.version)) else {
            return Err(kept(
                codes::host::NOT_SERVED_YET,
                "no handler serves this task's version yet",
            ));
        };
        let context = TaskContext {
            membership_id: self.lease.membership_id,
            task_id: self.lease.task_id.clone(),
            task_type: self.task_type,
            version: self.version,
            epoch: self.lease.epoch,
            resource: self.lease.resource.clone(),
            member: self.peer.host_id,
            request_id: message.request_id.clone(),
            limits: self.lease.limits,
        };
        let body = handler
            .handle(&context, &message.body)
            .map_err(|refusal| TaskRefusal {
                refusal,
                end: false,
            })?;
        // An answer the member could not read, nor the window keep, is never sent.
        if body.len() > super::record::MAX_BODY_BYTES {
            tracing::error!(
                event.name = "host.membership.task_answer_oversized",
                component = "host",
                task_type = self.task_type.as_str(),
                bytes = body.len(),
                "a task handler answered over the task message bound"
            );
            return Err(kept(
                codes::common::UNAVAILABLE,
                "the handler's answer is over the task message bound",
            ));
        }
        let answer = TaskAnswer {
            request_id: message.request_id.clone(),
            body,
        }
        .encode()
        .map_err(|error| ended(codes::common::UNAVAILABLE, error.0))?;
        // Kept before it is answered: a repeat after a crash before this reaches the handler
        // again, which a handler's own idempotency answers.
        parts
            .store
            .remember(reservation, &answer)
            .map_err(|error| ended(codes::common::UNAVAILABLE, error.to_string()))?;
        Ok(answer)
    }
}

impl TaskSession for CoordinatorTask {
    fn message(&mut self, bytes: &[u8]) -> Result<Vec<u8>, TaskRefusal> {
        if self.watching {
            return Err(ended(
                codes::common::INVALID_ARGUMENT,
                "the session belongs to its watch",
            ));
        }
        let message = TaskMessage::decode(bytes)
            .map_err(|error| ended(codes::common::INVALID_ARGUMENT, error.0))?;
        let parts = &self.coordinating;
        if message.membership_id != self.lease.membership_id
            || message.task_id != self.lease.task_id
        {
            return Err(ended(
                codes::common::INVALID_ARGUMENT,
                "the message names another membership or task than its session",
            ));
        }
        let held = parts
            .store
            .membership(&self.lease.membership_id)
            .ok_or_else(|| ended(codes::host::MEMBERSHIP_UNKNOWN, "the membership is gone"))?;
        if let Some(seen) = held.held_epoch {
            return Err(ended(
                codes::host::MEMBERSHIP_HELD,
                format!("held for review since epoch {seen} was named"),
            ));
        }
        let now = parts.time.now_secs();
        // The message's epoch, then the lease's: a lease issued before a fence is stale too.
        parts
            .fence(&self.peer, &held, &message.task_id, message.epoch, now)
            .map_err(|refusal| TaskRefusal { refusal, end: true })?;
        parts
            .fence(&self.peer, &held, &message.task_id, self.lease.epoch, now)
            .map_err(|refusal| TaskRefusal { refusal, end: true })?;
        if held.status != Status::Active {
            return Err(ended(
                codes::host::MEMBERSHIP_TRANSITION_REFUSED,
                format!("the membership is {}: the session ends", held.status),
            ));
        }
        if now >= self.lease.expires_at {
            return Err(ended(
                codes::host::LEASE_EXPIRED,
                "the lease expired: open a new session",
            ));
        }
        // The task's signed limits on a body and on the messages a minute (the task-limits
        // invariant).
        if u64::try_from(message.body.len()).unwrap_or(u64::MAX) > self.lease.limits.max_body_bytes
        {
            return Err(kept(
                codes::common::INVALID_ARGUMENT,
                "the body is over the task's signed `max_body_bytes`",
            ));
        }
        if !parts.tasks.rates.admit(
            &self.lease.membership_id,
            &self.lease.task_id,
            self.lease.limits.max_rate_per_minute,
            now,
        ) {
            return Err(kept(
                codes::host::RATE_LIMITED,
                "the task is over its signed `max_rate_per_minute`",
            ));
        }
        match message.kind {
            MessageKind::Progress => self.progress(&message, now),
            MessageKind::Watch => self.watch(&message),
            MessageKind::Handler => self.handled(&message, bytes),
        }
    }

    fn take_watch(&mut self) -> Option<Box<dyn Watching>> {
        self.watch.take()
    }
}

#[cfg(test)]
pub(crate) mod tests;
