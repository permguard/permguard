// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The membership records, byte for byte (WP-4.1; owner decisions of 2026-10-09;
//! `contracts/cbor/membership.json`, `contracts/vectors/membership.json`).
//!
//! | Record             | Shape                                                                                         |
//! | ------------------ | --------------------------------------------------------------------------------------------- |
//! | host_ref           | {1 host_id, 2 epoch, 3 fingerprint}                                                           |
//! | limits             | {1 max_body_bytes, 2 max_concurrency, 3 max_rate_per_minute, 4 max_batch_records, 5 retention_seconds} |
//! | task               | {1 task_id, 2 type, 3 provider_role, 4 consumer_role, 5 selector, 6 resource_types, 7 required, 8 limits, 9 assurance_requirements, 10 version} (10: WP-4.4) |
//! | capability         | {1 type, 2 version, 3 role}: a contract a Host registered, `provider` or `consumer` (WP-4.4) |
//! | lease_policy       | {1 max_session_seconds, 2 offline_grace_seconds, 3 clock_skew_seconds, 4 dormant_after_seconds, 5 revoke_after_seconds} |
//! | ring_pin           | {1 owner, 2 ring, 3 epoch, 4 key_set_digest, 5 binding, 6? retiring} (6: WP-4.5)             |
//! | ring_statement     | {1 ring, 2 epoch, 3 suite, 4 keys, 5 binding}                                                 |
//! | manifest payload   | {1 membership_id, 2 coordinator, 3 member, 4 selector, 5 tasks, 6 member_assurance, 7? min_assurance, 8? assurance_binding, 9 ring_pins, 10 epoch, 11 lease_policy, 12? previous_manifest_digest, 13 issued_at, 14 not_after, 15 status} |
//! | claim              | {1 control, 2 class, 3 by, 4? record} (WP-4.2)                                                |
//! | assurance_binding  | {1 member, 2 task_ids, 3 policy_revision, 4 claims, 5 result_digest, 6 appraised_by, 7 issued_at, 8 expires_at, 9 verdict} (WP-4.2) |
//! | assurance_result   | {1 member, 2 task_ids, 3 policy_revision, 4 claims}, digested (WP-4.2)                       |
//! | operator_approval  | {1 membership_id, 2 control, 3 principal, 4 task_ids, 5 reason, 6 expires_at, 7 approved_at}, digested and audited (WP-4.2) |
//! | assurance_evidence | [verifier, evidence], digested and never kept (WP-4.2)                                        |
//! | lease_request      | {1 membership_id, 2 task_id, 3 epoch, 4 resource, 5 member_boot_id, 6? evidence} (WP-4.3)     |
//! | lease payload      | {1 membership_id, 2 task_id, 3 epoch, 4 coordinator, 5 member, 6 coordinator_boot_id, 7 member_boot_id, 8 selector, 9 resource, 10 limits, 11 issued_at, 12 expires_at, 13 channel_binding, 14? binding_digest} (WP-4.3) |
//! | lease_answer       | {1 lease, 2? manifest} (WP-4.3)                                                               |
//! | task_message       | {1 membership_id, 2 task_id, 3 epoch, 4 request_id, 5 body, 6? kind} (WP-4.3; 6: WP-4.4)      |
//! | task_answer        | {1 request_id, 2 body} (WP-4.3)                                                               |
//! | task_progress      | {1 membership_id, 2 task_id, 3 manifest_epoch, 4 member_boot_id, 5 report_seq, 6 reported_at, 7 resources} (WP-4.4) |
//! | progress_resource  | {1 resource, 2 state, 3? frontier, 4? checkpoint_digest, 5? verified_at, 6? reason} (WP-4.4)   |
//! | progress_answer    | {1 report_seq, 2 received_at} (WP-4.4)                                                        |
//! | kept_progress      | {1 report, 2 received_at}: `progress/<membership_id>/<task_id>.cbor` (WP-4.4)                 |
//! | last_session       | {1 at, 2 member_boot_id}: `progress/<membership_id>/<task_id>.session` (WP-4.4)               |
//! | watch_request      | {1 positions [{1 key, 2 counter}]} (WP-4.4)                                                   |
//! | watch_event        | {1 hints [{1 key, 2 head, 3 counter}]}, empty a heartbeat (WP-4.4)                            |
//! | cutover            | {1 ring, 2 epoch, 3 streams [{1 stream, 2 from_seq}]} (WP-4.5)                              |
//! | acknowledgement    | {1 ring, 2 epoch, 3 stream, 4 through_seq} (WP-4.5)                                         |
//! | delivered          | {1 epoch, 2 at}: `progress/<membership_id>/manifest.delivered` (WP-4.5)                     |
//! | replay_entry       | {1 task_id, 2 request_id, 3 message_digest, 4 answer, 5 seq}: `replay/<membership_id>/` (WP-4.4) |
//! | invitation         | {1 invite_id, 2 token_key, 3 selector, 4 tasks, 5 expires, 6? expected_fingerprint, 7? min_assurance, 8 max_uses, 9 created_at, 10 created_by} |
//! | enrollment request | {1 invite_id, 2 token_proof, 3 selector, 4 tasks, 5 member, 6 ring_statements, 7 capabilities} (7: WP-4.4) |
//! | pending membership | {1 membership_id, 2 invite_id, 3 coordinator, 4 member, 5 selector, 6 tasks, 7 member_assurance, 8 ring_statements, 9 requested_at, 10? coordinator_address, 11? identity, 12 capabilities} (12: WP-4.4) |
//! | enroll answer      | {1 membership_id, 2 status}                                                                   |
//! | membership request | {1 action, 2 membership_id, 3? held_epoch}                                                    |
//! | membership answer  | {1 status, 2 manifests, 3 ring_statements}                                                    |
//! | journal entry      | {1 seq, 2 kind, 3 subject, 4? epoch, 5 at, 6? operation_id, 7 previous, 8? detail, 9? statements} |
//!
//! Every map is closed and canonical; an absent optional member is omitted, never null.

use std::fmt;
use std::str::FromStr;

use permguard_core::assurance::{AssuranceProfile, Control, EvidenceClass};
use permguard_core::authz::Selector;
use permguard_core::domains::digest;
use permguard_objects::cbor::Value;
use permguard_objects::crypto::suite::Suite;
use permguard_objects::digest::Digest;

use crate::identity::record::{Labelled, RecordError, encode, is_uuid_v7, uint};

/// The most bytes one record takes: a manifest with its pins, a pending membership with its ring
/// statements.
pub const MAX_RECORD_BYTES: usize = 256 * 1024;
/// The most tasks one membership grants.
pub const MAX_TASKS: usize = 32;
/// The most rings one membership pins, or one request presents.
pub const MAX_RINGS: usize = 16;
/// The most keys one ring statement carries.
pub const MAX_KEYS: usize = 64;
/// The longest task id, resource type, assurance requirement or principal.
pub const MAX_NAME_BYTES: usize = 128;
/// The longest reason an operator gives for an approval.
pub const MAX_REASON_BYTES: usize = 512;
/// The highest version a task contract takes (WP-4.4).
pub const MAX_CONTRACT_VERSION: u64 = 65_535;
/// The most contracts one Host declares (WP-4.4).
pub const MAX_CAPABILITIES: usize = 64;
/// The most resources one progress report carries (WP-4.4, owner decision).
pub const MAX_PROGRESS_RESOURCES: usize = 256;
/// The most bytes one progress report takes (WP-4.4, owner decision).
pub const MAX_PROGRESS_BYTES: usize = 64 * 1024;
/// The most keys a watch tracks (WP-4.4, owner decision).
pub const MAX_WATCH_KEYS: usize = 1024;
/// The longest watch key or head.
pub const MAX_WATCH_TEXT_BYTES: usize = 256;
/// The most bytes a progress answer or a last session takes.
pub const MAX_SMALL_RECORD_BYTES: usize = 128;

/// Which side of a membership a role is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Role {
    Coordinator,
    Member,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Coordinator => "coordinator",
            Self::Member => "member",
        }
    }
}

impl FromStr for Role {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, RecordError> {
        match text {
            "coordinator" => Ok(Self::Coordinator),
            "member" => Ok(Self::Member),
            _ => Err(RecordError(format!("`{text}` is not a membership role"))),
        }
    }
}

/// The task types and the roles that provide and consume them (the membership model's table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TaskType {
    PolicyMirror,
    DecisionsShip,
    EventsShip,
    EventsImport,
    AuditCheckpoints,
    ZoneSecrets,
}

impl TaskType {
    pub const ALL: [Self; 6] = [
        Self::PolicyMirror,
        Self::DecisionsShip,
        Self::EventsShip,
        Self::EventsImport,
        Self::AuditCheckpoints,
        Self::ZoneSecrets,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicyMirror => "policy.mirror",
            Self::DecisionsShip => "decisions.ship",
            Self::EventsShip => "events.ship",
            Self::EventsImport => "events.import",
            Self::AuditCheckpoints => "audit.checkpoints",
            Self::ZoneSecrets => "zone.secrets",
        }
    }

    /// The role that provides the task.
    pub fn provider(self) -> Role {
        match self {
            Self::PolicyMirror | Self::EventsImport | Self::ZoneSecrets => Role::Coordinator,
            Self::DecisionsShip | Self::EventsShip | Self::AuditCheckpoints => Role::Member,
        }
    }

    /// The role that consumes it: the other one.
    pub fn consumer(self) -> Role {
        match self.provider() {
            Role::Coordinator => Role::Member,
            Role::Member => Role::Coordinator,
        }
    }
}

impl FromStr for TaskType {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, RecordError> {
        Self::ALL
            .into_iter()
            .find(|task| task.as_str() == text)
            .ok_or_else(|| RecordError(format!("`{text}` is not a task type")))
    }
}

/// A membership's status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Status {
    Pending,
    Active,
    Suspended,
    Revoked,
    Rejected,
    Expired,
    /// On a Host whose identity was reset while its coordinator had not acknowledged the
    /// revocation: terminal here, tracked until revoked out of band.
    Orphaned,
}

impl Status {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Revoked => "revoked",
            Self::Rejected => "rejected",
            Self::Expired => "expired",
            Self::Orphaned => "orphaned",
        }
    }

    /// No transition leaves it.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Revoked | Self::Rejected | Self::Expired | Self::Orphaned
        )
    }

    /// Whether the membership state machine moves from `self` to `next` (the blueprint's table;
    /// `orphaned` from any status that is not terminal, on an identity reset).
    pub fn allows(self, next: Self) -> bool {
        use Status::{Active, Expired, Orphaned, Pending, Rejected, Revoked, Suspended};
        matches!(
            (self, next),
            (Pending, Active | Rejected | Expired)
                | (Active, Suspended | Expired | Revoked | Active)
                | (Suspended, Active | Expired | Revoked)
        ) || (next == Orphaned && !self.is_terminal())
    }
}

impl FromStr for Status {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, RecordError> {
        [
            Self::Pending,
            Self::Active,
            Self::Suspended,
            Self::Revoked,
            Self::Rejected,
            Self::Expired,
            Self::Orphaned,
        ]
        .into_iter()
        .find(|status| status.as_str() == text)
        .ok_or_else(|| RecordError(format!("`{text}` is not a membership status")))
    }
}

impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A Host as a membership pins it: its id, its identity epoch and that epoch's fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRef {
    pub host_id: [u8; 16],
    pub epoch: u64,
    pub fingerprint: String,
}

impl HostRef {
    fn value(&self) -> Result<Value, RecordError> {
        Ok(Value::Map(vec![
            (Value::Int(1), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(2), uint(self.epoch)?),
            (Value::Int(3), Value::Text(self.fingerprint.clone())),
        ]))
    }

    fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "a host reference")?;
        let host = Self {
            host_id: map.id(1)?,
            epoch: map.uint(2)?,
            fingerprint: map.text(3)?,
        };
        map.finish()?;
        if !is_uuid_v7(&host.host_id) || host.epoch == 0 {
            return Err(RecordError(
                "a host reference names a UUIDv7 Host and an epoch from 1".to_owned(),
            ));
        }
        Digest::parse(&host.fingerprint)
            .map_err(|_| RecordError("a fingerprint is `sha256:` and 64 hex digits".to_owned()))?;
        Ok(host)
    }
}

/// A task's limits, signed with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_body_bytes: u64,
    pub max_concurrency: u64,
    pub max_rate_per_minute: u64,
    pub max_batch_records: u64,
    pub retention_seconds: u64,
}

impl Limits {
    fn value(&self) -> Result<Value, RecordError> {
        Ok(Value::Map(vec![
            (Value::Int(1), uint(self.max_body_bytes)?),
            (Value::Int(2), uint(self.max_concurrency)?),
            (Value::Int(3), uint(self.max_rate_per_minute)?),
            (Value::Int(4), uint(self.max_batch_records)?),
            (Value::Int(5), uint(self.retention_seconds)?),
        ]))
    }

    fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "task limits")?;
        let limits = Self {
            max_body_bytes: map.uint(1)?,
            max_concurrency: map.uint(2)?,
            max_rate_per_minute: map.uint(3)?,
            max_batch_records: map.uint(4)?,
            retention_seconds: map.uint(5)?,
        };
        map.finish()?;
        Ok(limits)
    }

    /// Whether every limit of `self` is at most `other`'s: what narrowing keeps.
    pub fn within(&self, other: &Self) -> bool {
        self.max_body_bytes <= other.max_body_bytes
            && self.max_concurrency <= other.max_concurrency
            && self.max_rate_per_minute <= other.max_rate_per_minute
            && self.max_batch_records <= other.max_batch_records
            && self.retention_seconds <= other.retention_seconds
    }
}

/// One task a membership grants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Task {
    pub task_id: String,
    pub task_type: TaskType,
    pub selector: Selector,
    pub resource_types: Vec<String>,
    pub required: bool,
    pub limits: Limits,
    pub assurance_requirements: Vec<String>,
    /// The contract version both sides speak (WP-4.4, owner decision), from 1.
    pub version: u64,
}

fn names(values: &[String]) -> Value {
    Value::Array(values.iter().cloned().map(Value::Text).collect())
}

fn name(text: &str, what: &str) -> Result<(), RecordError> {
    if text.is_empty() || text.len() > MAX_NAME_BYTES || text.chars().any(char::is_control) {
        return Err(RecordError(format!(
            "{what} is printable text of 1 to {MAX_NAME_BYTES} bytes"
        )));
    }
    Ok(())
}

impl Task {
    fn value(&self) -> Result<Value, RecordError> {
        Ok(Value::Map(vec![
            (Value::Int(1), Value::Text(self.task_id.clone())),
            (
                Value::Int(2),
                Value::Text(self.task_type.as_str().to_owned()),
            ),
            (
                Value::Int(3),
                Value::Text(self.task_type.provider().as_str().to_owned()),
            ),
            (
                Value::Int(4),
                Value::Text(self.task_type.consumer().as_str().to_owned()),
            ),
            (Value::Int(5), Value::Text(self.selector.to_string())),
            (Value::Int(6), names(&self.resource_types)),
            (Value::Int(7), Value::Bool(self.required)),
            (Value::Int(8), self.limits.value()?),
            (Value::Int(9), names(&self.assurance_requirements)),
            (Value::Int(10), uint(self.version)?),
        ]))
    }

    fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "a task")?;
        let task_id = map.text(1)?;
        let task_type: TaskType = map.text(2)?.parse()?;
        let provider: Role = map.text(3)?.parse()?;
        let consumer: Role = map.text(4)?.parse()?;
        let selector = Selector::parse(&map.text(5)?)
            .map_err(|error| RecordError(format!("a task's selector: {error}")))?;
        let task = Self {
            task_id,
            task_type,
            selector,
            resource_types: map.texts(6)?,
            required: map.boolean(7)?,
            limits: Limits::read(map.value(8)?)?,
            assurance_requirements: map.texts(9)?,
            version: map.uint(10)?,
        };
        map.finish()?;
        if provider != task_type.provider() || consumer != task_type.consumer() {
            return Err(RecordError(format!(
                "`{}` is provided by the {} and consumed by the {}",
                task_type.as_str(),
                task_type.provider().as_str(),
                task_type.consumer().as_str()
            )));
        }
        task.check()?;
        Ok(task)
    }

    /// The task's own rules: a well-formed id and names.
    pub fn check(&self) -> Result<(), RecordError> {
        name(&self.task_id, "a task id")?;
        if !self
            .task_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(RecordError(
                "a task id is lowercase letters, digits and `-`".to_owned(),
            ));
        }
        for resource_type in &self.resource_types {
            name(resource_type, "a resource type")?;
        }
        for requirement in &self.assurance_requirements {
            name(requirement, "an assurance requirement")?;
        }
        // Both are enforced (WP-4.4): a 0 would refuse every session or every message.
        if self.limits.max_concurrency == 0 || self.limits.max_rate_per_minute == 0 {
            return Err(RecordError(
                "a task's `max_concurrency` and `max_rate_per_minute` are at least 1".to_owned(),
            ));
        }
        check_version(self.version)
    }
}

fn check_version(version: u64) -> Result<(), RecordError> {
    if version == 0 || version > MAX_CONTRACT_VERSION {
        return Err(RecordError(format!(
            "a task contract's version is 1 to {MAX_CONTRACT_VERSION}"
        )));
    }
    Ok(())
}

/// Which side of a task a contract serves: the provider's handler or the consumer's client
/// (WP-4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContractRole {
    Provider,
    Consumer,
}

impl ContractRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Provider => "provider",
            Self::Consumer => "consumer",
        }
    }

    /// The side `role` takes in `task`.
    pub fn of(task: TaskType, role: Role) -> Self {
        if task.provider() == role {
            Self::Provider
        } else {
            Self::Consumer
        }
    }
}

impl FromStr for ContractRole {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, RecordError> {
        match text {
            "provider" => Ok(Self::Provider),
            "consumer" => Ok(Self::Consumer),
            _ => Err(RecordError(format!("`{text}` is not a contract role"))),
        }
    }
}

/// A task contract a Host registered (WP-4.4, owner decision): what the member declares in its
/// enrollment request and the coordinator holds of itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Capability {
    pub task_type: TaskType,
    pub version: u64,
    pub role: ContractRole,
}

impl Capability {
    fn value(&self) -> Result<Value, RecordError> {
        Ok(Value::Map(vec![
            (
                Value::Int(1),
                Value::Text(self.task_type.as_str().to_owned()),
            ),
            (Value::Int(2), uint(self.version)?),
            (Value::Int(3), Value::Text(self.role.as_str().to_owned())),
        ]))
    }

    fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "a capability")?;
        let capability = Self {
            task_type: map.text(1)?.parse()?,
            version: map.uint(2)?,
            role: map.text(3)?.parse()?,
        };
        map.finish()?;
        check_version(capability.version)?;
        Ok(capability)
    }
}

/// Reads a Host's capabilities: at most [`MAX_CAPABILITIES`], in order, each once.
fn read_capabilities(values: Vec<Value>) -> Result<Vec<Capability>, RecordError> {
    if values.len() > MAX_CAPABILITIES {
        return Err(RecordError(format!(
            "at most {MAX_CAPABILITIES} capabilities"
        )));
    }
    let capabilities: Vec<Capability> = values
        .into_iter()
        .map(Capability::read)
        .collect::<Result<_, _>>()?;
    if !sorted_unique(&capabilities) {
        return Err(RecordError(
            "capabilities are listed in order, each once".to_owned(),
        ));
    }
    Ok(capabilities)
}

fn capabilities_value(capabilities: &[Capability]) -> Result<Value, RecordError> {
    let mut sorted = capabilities.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    Ok(Value::Array(
        sorted
            .iter()
            .map(Capability::value)
            .collect::<Result<_, _>>()?,
    ))
}

/// A manifest's pins: one current set per owner and ring, and at most one retiring set beside
/// it, of a lower epoch (WP-4.5).
fn check_pins(pins: Vec<RingPin>) -> Result<Vec<RingPin>, RecordError> {
    for pin in &pins {
        let same = |retiring: bool| {
            pins.iter()
                .filter(|other| {
                    other.owner == pin.owner && other.ring == pin.ring && other.retiring == retiring
                })
                .collect::<Vec<_>>()
        };
        if same(pin.retiring).len() != 1 {
            return Err(RecordError(format!(
                "the {} `{}` is pinned twice",
                pin.owner.as_str(),
                pin.ring
            )));
        }
        if pin.retiring && !same(false).iter().any(|current| current.epoch > pin.epoch) {
            return Err(RecordError(format!(
                "a retiring `{}` needs a current set of a later epoch",
                pin.ring
            )));
        }
    }
    Ok(pins)
}

/// Reads the tasks of a record: at most [`MAX_TASKS`], ids unique.
fn read_tasks(values: Vec<Value>) -> Result<Vec<Task>, RecordError> {
    if values.len() > MAX_TASKS {
        return Err(RecordError(format!("at most {MAX_TASKS} tasks")));
    }
    let tasks: Vec<Task> = values
        .into_iter()
        .map(Task::read)
        .collect::<Result<_, _>>()?;
    let mut ids: Vec<&str> = tasks.iter().map(|task| task.task_id.as_str()).collect();
    ids.sort_unstable();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(RecordError("a task id appears twice".to_owned()));
    }
    Ok(tasks)
}

fn tasks_value(tasks: &[Task]) -> Result<Value, RecordError> {
    Ok(Value::Array(
        tasks.iter().map(Task::value).collect::<Result<_, _>>()?,
    ))
}

/// The lease policy a membership signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LeasePolicy {
    pub max_session_seconds: u64,
    pub offline_grace_seconds: u64,
    pub clock_skew_seconds: u64,
    pub dormant_after_seconds: u64,
    pub revoke_after_seconds: u64,
}

impl LeasePolicy {
    fn value(&self) -> Result<Value, RecordError> {
        Ok(Value::Map(vec![
            (Value::Int(1), uint(self.max_session_seconds)?),
            (Value::Int(2), uint(self.offline_grace_seconds)?),
            (Value::Int(3), uint(self.clock_skew_seconds)?),
            (Value::Int(4), uint(self.dormant_after_seconds)?),
            (Value::Int(5), uint(self.revoke_after_seconds)?),
        ]))
    }

    fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "a lease policy")?;
        let policy = Self {
            max_session_seconds: map.uint(1)?,
            offline_grace_seconds: map.uint(2)?,
            clock_skew_seconds: map.uint(3)?,
            dormant_after_seconds: map.uint(4)?,
            revoke_after_seconds: map.uint(5)?,
        };
        map.finish()?;
        policy.check()?;
        Ok(policy)
    }

    /// `revoke_after` is greater than `dormant_after`, and no bound is zero.
    pub fn check(&self) -> Result<(), RecordError> {
        if self.revoke_after_seconds <= self.dormant_after_seconds {
            return Err(RecordError(
                "a lease policy's revoke_after is greater than its dormant_after".to_owned(),
            ));
        }
        if self.max_session_seconds == 0 || self.dormant_after_seconds == 0 {
            return Err(RecordError(
                "a lease policy bounds sessions and dormancy above zero".to_owned(),
            ));
        }
        Ok(())
    }
}

/// A ring a membership pins: whose, which, at what epoch and set, and the identity-signed
/// binding that vouches for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingPin {
    pub owner: Role,
    pub ring: String,
    pub epoch: u64,
    pub key_set_digest: [u8; 32],
    pub binding: Vec<u8>,
    /// The set a re-pin replaced, kept to verify the spans below each stream's cutover until
    /// they are acknowledged (WP-4.5, owner decision); label 6 present only when set.
    pub retiring: bool,
}

impl RingPin {
    pub(crate) fn value(&self) -> Result<Value, RecordError> {
        Ok(Value::Map(
            vec![
                (Value::Int(1), Value::Text(self.owner.as_str().to_owned())),
                (Value::Int(2), Value::Text(self.ring.clone())),
                (Value::Int(3), uint(self.epoch)?),
                (Value::Int(4), Value::Bytes(self.key_set_digest.to_vec())),
                (Value::Int(5), Value::Bytes(self.binding.clone())),
            ]
            .into_iter()
            .chain(self.retiring.then_some((Value::Int(6), Value::Bool(true))))
            .collect(),
        ))
    }

    pub(crate) fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "a ring pin")?;
        let pin = Self {
            owner: map.text(1)?.parse()?,
            ring: map.text(2)?,
            epoch: map.uint(3)?,
            key_set_digest: map.fixed(4)?,
            binding: map.bytes(5)?,
            retiring: match map.optional_value(6)? {
                None => false,
                Some(Value::Bool(true)) => true,
                Some(_) => {
                    return Err(RecordError(
                        "a ring pin's label 6 is `true` or absent".to_owned(),
                    ));
                }
            },
        };
        map.finish()?;
        Ok(pin)
    }
}

/// A ring as a Host presents it for pinning: its keys and the binding of their set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingStatement {
    pub ring: String,
    pub epoch: u64,
    pub suite: Suite,
    /// The RFC 7517 JSON of each published key.
    pub keys: Vec<String>,
    pub binding: Vec<u8>,
}

impl RingStatement {
    pub(crate) fn value(&self) -> Result<Value, RecordError> {
        Ok(Value::Map(vec![
            (Value::Int(1), Value::Text(self.ring.clone())),
            (Value::Int(2), uint(self.epoch)?),
            (Value::Int(3), Value::Text(self.suite.name().to_owned())),
            (Value::Int(4), names(&self.keys)),
            (Value::Int(5), Value::Bytes(self.binding.clone())),
        ]))
    }

    pub(crate) fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "a ring statement")?;
        let statement = Self {
            ring: map.text(1)?,
            epoch: map.uint(2)?,
            suite: map.suite(3)?,
            keys: map.texts(4)?,
            binding: map.bytes(5)?,
        };
        map.finish()?;
        if statement.keys.is_empty() || statement.keys.len() > MAX_KEYS {
            return Err(RecordError(format!(
                "a ring statement carries 1 to {MAX_KEYS} keys"
            )));
        }
        Ok(statement)
    }
}

fn read_statements(values: Vec<Value>) -> Result<Vec<RingStatement>, RecordError> {
    if values.len() > MAX_RINGS {
        return Err(RecordError(format!("at most {MAX_RINGS} rings")));
    }
    values.into_iter().map(RingStatement::read).collect()
}

fn statements_value(statements: &[RingStatement]) -> Result<Value, RecordError> {
    Ok(Value::Array(
        statements
            .iter()
            .map(RingStatement::value)
            .collect::<Result<_, _>>()?,
    ))
}

fn profile(text: &str) -> Result<AssuranceProfile, RecordError> {
    text.parse()
        .map_err(|_| RecordError(format!("`{text}` is not an assurance profile")))
}

fn selector(text: &str) -> Result<Selector, RecordError> {
    Selector::parse(text).map_err(|error| RecordError(format!("a selector: {error}")))
}

fn bounded(bytes: &[u8], what: &str) -> Result<(), RecordError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError(format!(
            "{what} takes at most {MAX_RECORD_BYTES} bytes"
        )));
    }
    Ok(())
}

/// What a membership manifest signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    pub membership_id: [u8; 16],
    pub coordinator: HostRef,
    pub member: HostRef,
    pub selector: Selector,
    pub tasks: Vec<Task>,
    pub member_assurance: AssuranceProfile,
    pub min_assurance: Option<AssuranceProfile>,
    /// The coordinator's appraisal of the controls the tasks require; `None` when none does.
    pub assurance_binding: Option<AssuranceBinding>,
    pub ring_pins: Vec<RingPin>,
    pub epoch: u64,
    pub lease_policy: LeasePolicy,
    /// The digest of the manifest this one succeeds; `None` at genesis.
    pub previous: Option<Digest>,
    pub issued_at: u64,
    pub not_after: u64,
    pub status: Status,
}

impl Manifest {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(self.membership_id.to_vec())),
            (Value::Int(2), self.coordinator.value()?),
            (Value::Int(3), self.member.value()?),
            (Value::Int(4), Value::Text(self.selector.to_string())),
            (Value::Int(5), tasks_value(&self.tasks)?),
            (
                Value::Int(6),
                Value::Text(self.member_assurance.as_str().to_owned()),
            ),
        ];
        if let Some(min) = self.min_assurance {
            pairs.push((Value::Int(7), Value::Text(min.as_str().to_owned())));
        }
        if let Some(binding) = &self.assurance_binding {
            pairs.push((Value::Int(8), binding.value()?));
        }
        pairs.push((
            Value::Int(9),
            Value::Array(
                self.ring_pins
                    .iter()
                    .map(RingPin::value)
                    .collect::<Result<_, _>>()?,
            ),
        ));
        pairs.push((Value::Int(10), uint(self.epoch)?));
        pairs.push((Value::Int(11), self.lease_policy.value()?));
        if let Some(previous) = &self.previous {
            pairs.push((Value::Int(12), Value::Text(previous.to_string())));
        }
        pairs.push((Value::Int(13), uint(self.issued_at)?));
        pairs.push((Value::Int(14), uint(self.not_after)?));
        pairs.push((Value::Int(15), Value::Text(self.status.as_str().to_owned())));
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a membership manifest")?;
        let mut map = Labelled::read(bytes, "a membership manifest")?;
        let pins = map.array(9)?;
        if pins.len() > MAX_RINGS {
            return Err(RecordError(format!("at most {MAX_RINGS} ring pins")));
        }
        let manifest = Self {
            membership_id: map.id(1)?,
            coordinator: HostRef::read(map.value(2)?)?,
            member: HostRef::read(map.value(3)?)?,
            selector: selector(&map.text(4)?)?,
            tasks: read_tasks(map.array(5)?)?,
            member_assurance: profile(&map.text(6)?)?,
            min_assurance: map.optional_text(7)?.as_deref().map(profile).transpose()?,
            assurance_binding: map
                .optional_value(8)?
                .map(AssuranceBinding::read)
                .transpose()?,
            ring_pins: check_pins(
                pins.into_iter()
                    .map(RingPin::read)
                    .collect::<Result<_, _>>()?,
            )?,
            epoch: map.uint(10)?,
            lease_policy: LeasePolicy::read(map.value(11)?)?,
            previous: map.optional_digest(12)?,
            issued_at: map.uint(13)?,
            not_after: map.uint(14)?,
            status: match map.text(15)?.parse()? {
                // A manifest states where a relationship stands; pending is before any, and
                // orphaned is the resetting Host's own reading.
                Status::Pending | Status::Orphaned => {
                    return Err(RecordError(
                        "a manifest is active, suspended, revoked, rejected or expired".to_owned(),
                    ));
                }
                status => status,
            },
        };
        map.finish()?;
        if !is_uuid_v7(&manifest.membership_id) || manifest.epoch == 0 {
            return Err(RecordError(
                "a manifest names a UUIDv7 membership and an epoch from 1".to_owned(),
            ));
        }
        if manifest.previous.is_none() != (manifest.epoch == 1) {
            return Err(RecordError(
                "the genesis manifest is epoch 1 and names no predecessor; every other names one"
                    .to_owned(),
            ));
        }
        if let Some(binding) = &manifest.assurance_binding {
            // A binding appraises this manifest's member, for exactly the tasks it grants that
            // require controls.
            let mut requiring: Vec<&str> = manifest
                .tasks
                .iter()
                .filter(|task| !task.assurance_requirements.is_empty())
                .map(|task| task.task_id.as_str())
                .collect();
            requiring.sort_unstable();
            if binding.member != manifest.member || binding.task_ids != requiring {
                return Err(RecordError(
                    "an assurance binding names the manifest's member and the tasks requiring \
                     controls"
                        .to_owned(),
                ));
            }
        }
        Ok(manifest)
    }
}

/// The digest a successor and the history cite a signed manifest by: over its envelope bytes.
pub fn manifest_digest(envelope: &[u8]) -> Digest {
    let mut input = digest::MEMBERSHIP_MANIFEST.as_bytes().to_vec();
    input.extend_from_slice(envelope);
    Digest::compute(&input)
}

/// Whether `names` is sorted and names each once.
fn sorted_unique<T: Ord>(names: &[T]) -> bool {
    names.windows(2).all(|pair| pair[0] < pair[1])
}

/// One control as a coordinator accepted it (WP-4.2): the class of evidence, who vouches for it,
/// and the digest of the record behind it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    pub control: Control,
    pub class: EvidenceClass,
    /// The declared profile for `declared`, the approving principal for `operator-approved`, the
    /// verifier id for `attested`.
    pub by: String,
    /// The operator approval's digest, or the evidence's; `None` for `declared`.
    pub record: Option<Digest>,
}

impl Claim {
    fn value(&self) -> Result<Value, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.control.name().to_owned())),
            (Value::Int(2), Value::Text(self.class.as_str().to_owned())),
            (Value::Int(3), Value::Text(self.by.clone())),
        ];
        if let Some(record) = &self.record {
            pairs.push((Value::Int(4), Value::Text(record.to_string())));
        }
        Ok(Value::Map(pairs))
    }

    fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "a claim")?;
        let control = map.text(1)?;
        let class = map.text(2)?;
        let claim = Self {
            control: control.parse().map_err(RecordError)?,
            class: class.parse().map_err(RecordError)?,
            by: map.text(3)?,
            record: map.optional_digest(4)?,
        };
        // Spelled exactly: a record has one encoding.
        if claim.control.name() != control || claim.class.as_str() != class {
            return Err(RecordError(
                "a claim names its control and class exactly".to_owned(),
            ));
        }
        // A declaration is vouched for by the profile declared.
        if claim.class == EvidenceClass::Declared
            && profile(&claim.by).map(AssuranceProfile::as_str) != Ok(claim.by.as_str())
        {
            return Err(RecordError(
                "a declared claim names the profile declared".to_owned(),
            ));
        }
        map.finish()?;
        name(&claim.by, "a claim's appraiser")?;
        // A declaration has no record behind it; every other class has one.
        if claim.record.is_none() != (claim.class == EvidenceClass::Declared) {
            return Err(RecordError(
                "a claim names its record unless it is declared".to_owned(),
            ));
        }
        Ok(claim)
    }
}

/// Where a binding stands: accepted until it expires, or revoked by an operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accepted,
    Revoked,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Revoked => "revoked",
        }
    }
}

impl FromStr for Verdict {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, RecordError> {
        match text {
            "accepted" => Ok(Self::Accepted),
            "revoked" => Ok(Self::Revoked),
            _ => Err(RecordError(format!("`{text}` is not a binding verdict"))),
        }
    }
}

/// A coordinator's appraisal of a member's controls, signed in the manifest (WP-4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssuranceBinding {
    pub member: HostRef,
    /// The tasks requiring controls, sorted, each once.
    pub task_ids: Vec<String>,
    pub policy_revision: Digest,
    /// One per required control, sorted by the control's name.
    pub claims: Vec<Claim>,
    pub result_digest: Digest,
    pub appraised_by: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub verdict: Verdict,
}

/// The canonical bytes of an appraisal's result: the member, the tasks, the policy and the claims.
pub fn result_bytes(
    member: &HostRef,
    task_ids: &[String],
    policy_revision: &Digest,
    claims: &[Claim],
) -> Result<Vec<u8>, RecordError> {
    encode(vec![
        (Value::Int(1), member.value()?),
        (Value::Int(2), names(task_ids)),
        (Value::Int(3), Value::Text(policy_revision.to_string())),
        (
            Value::Int(4),
            Value::Array(claims.iter().map(Claim::value).collect::<Result<_, _>>()?),
        ),
    ])
}

/// The digest of an appraisal's result, which the binding names.
pub fn result_digest(
    member: &HostRef,
    task_ids: &[String],
    policy_revision: &Digest,
    claims: &[Claim],
) -> Result<Digest, RecordError> {
    let mut input = digest::MEMBERSHIP_ASSURANCE_RESULT.as_bytes().to_vec();
    input.extend_from_slice(&result_bytes(member, task_ids, policy_revision, claims)?);
    Ok(Digest::compute(&input))
}

impl AssuranceBinding {
    fn value(&self) -> Result<Value, RecordError> {
        Ok(Value::Map(vec![
            (Value::Int(1), self.member.value()?),
            (Value::Int(2), names(&self.task_ids)),
            (Value::Int(3), Value::Text(self.policy_revision.to_string())),
            (
                Value::Int(4),
                Value::Array(
                    self.claims
                        .iter()
                        .map(Claim::value)
                        .collect::<Result<_, _>>()?,
                ),
            ),
            (Value::Int(5), Value::Text(self.result_digest.to_string())),
            (Value::Int(6), Value::Text(self.appraised_by.clone())),
            (Value::Int(7), uint(self.issued_at)?),
            (Value::Int(8), uint(self.expires_at)?),
            (Value::Int(9), Value::Text(self.verdict.as_str().to_owned())),
        ]))
    }

    fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "an assurance binding")?;
        let claims = map.array(4)?;
        if claims.len() > Control::ALL.len() {
            return Err(RecordError(format!(
                "a binding carries at most {} claims",
                Control::ALL.len()
            )));
        }
        let binding = Self {
            member: HostRef::read(map.value(1)?)?,
            task_ids: map.texts(2)?,
            policy_revision: map.digest(3)?,
            claims: claims
                .into_iter()
                .map(Claim::read)
                .collect::<Result<_, _>>()?,
            result_digest: map.digest(5)?,
            appraised_by: map.text(6)?,
            issued_at: map.uint(7)?,
            expires_at: map.uint(8)?,
            verdict: map.text(9)?.parse()?,
        };
        map.finish()?;
        // Sorted by the control's stable name, never by this build's order of the controls.
        let controls: Vec<&str> = binding
            .claims
            .iter()
            .map(|claim| claim.control.name())
            .collect();
        if binding.task_ids.is_empty()
            || binding.task_ids.len() > MAX_TASKS
            || !sorted_unique(&binding.task_ids)
            || binding.claims.is_empty()
            || !sorted_unique(&controls)
        {
            return Err(RecordError(
                "a binding names its tasks and its claims each once, sorted".to_owned(),
            ));
        }
        name(&binding.appraised_by, "a binding's appraiser")?;
        if binding.expires_at < binding.issued_at {
            return Err(RecordError(
                "a binding expires no earlier than it was issued".to_owned(),
            ));
        }
        // The result digest is over what the binding says: recomputed, never trusted.
        if binding.result_digest
            != result_digest(
                &binding.member,
                &binding.task_ids,
                &binding.policy_revision,
                &binding.claims,
            )?
        {
            return Err(RecordError(
                "a binding's result digest is not the digest of its result".to_owned(),
            ));
        }
        Ok(binding)
    }

    /// The canonical bytes of the binding alone.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let Value::Map(pairs) = self.value()? else {
            unreachable!("a binding is a map");
        };
        encode(pairs)
    }

    /// The digest a task admission answers the binding by.
    pub fn digest(&self) -> Result<Digest, RecordError> {
        let mut input = digest::MEMBERSHIP_ASSURANCE_BINDING.as_bytes().to_vec();
        input.extend_from_slice(&self.encode()?);
        Ok(Digest::compute(&input))
    }

    /// Whether the binding is for `task_id`.
    pub fn covers(&self, task_id: &str) -> bool {
        self.task_ids.iter().any(|id| id == task_id)
    }

    /// The claim for `control`.
    pub fn claim(&self, control: Control) -> Option<&Claim> {
        self.claims.iter().find(|claim| claim.control == control)
    }
}

/// An operator's approval of one control: an accountable risk decision, not attestation. Kept in
/// the audit whole and cited by its digest in the claim (WP-4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorApproval {
    pub membership_id: [u8; 16],
    pub control: Control,
    pub principal: String,
    /// The scope: the tasks requiring the control.
    pub task_ids: Vec<String>,
    pub reason: String,
    pub expires_at: u64,
    pub approved_at: u64,
}

impl OperatorApproval {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.membership_id.to_vec())),
            (Value::Int(2), Value::Text(self.control.name().to_owned())),
            (Value::Int(3), Value::Text(self.principal.clone())),
            (Value::Int(4), names(&self.task_ids)),
            (Value::Int(5), Value::Text(self.reason.clone())),
            (Value::Int(6), uint(self.expires_at)?),
            (Value::Int(7), uint(self.approved_at)?),
        ])
    }

    /// The digest the claim cites the approval by.
    pub fn digest(&self) -> Result<Digest, RecordError> {
        let mut input = digest::MEMBERSHIP_OPERATOR_APPROVAL.as_bytes().to_vec();
        input.extend_from_slice(&self.encode()?);
        Ok(Digest::compute(&input))
    }
}

/// The canonical bytes a piece of evidence is digested as: `[verifier, evidence]`.
pub fn evidence_bytes(verifier: &str, evidence: &[u8]) -> Result<Vec<u8>, RecordError> {
    permguard_objects::cbor::encode(&Value::Array(vec![
        Value::Text(verifier.to_owned()),
        Value::Bytes(evidence.to_vec()),
    ]))
    .map_err(|error| RecordError(error.to_string()))
}

/// The digest a claim cites a piece of evidence by: the evidence itself is never kept.
pub fn evidence_digest(verifier: &str, evidence: &[u8]) -> Result<Digest, RecordError> {
    let mut input = digest::MEMBERSHIP_ASSURANCE_EVIDENCE.as_bytes().to_vec();
    input.extend_from_slice(&evidence_bytes(verifier, evidence)?);
    Ok(Digest::compute(&input))
}

/// The reason of an operator approval: printable text of 1 to [`MAX_REASON_BYTES`] bytes.
pub fn check_reason(reason: &str) -> Result<(), RecordError> {
    if reason.trim().is_empty()
        || reason.len() > MAX_REASON_BYTES
        || reason.chars().any(char::is_control)
    {
        return Err(RecordError(format!(
            "a reason is printable text of 1 to {MAX_REASON_BYTES} bytes"
        )));
    }
    Ok(())
}

/// An invitation, as the coordinator keeps it: never the token, only its hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invitation {
    pub invite_id: [u8; 16],
    /// The public key the invitation's token derives: nothing the coordinator holds signs.
    pub token_key: [u8; 32],
    pub selector: Selector,
    pub tasks: Vec<Task>,
    pub expires: u64,
    pub expected_fingerprint: Option<String>,
    pub min_assurance: Option<AssuranceProfile>,
    pub max_uses: u64,
    pub created_at: u64,
    pub created_by: String,
}

impl Invitation {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(self.invite_id.to_vec())),
            (Value::Int(2), Value::Bytes(self.token_key.to_vec())),
            (Value::Int(3), Value::Text(self.selector.to_string())),
            (Value::Int(4), tasks_value(&self.tasks)?),
            (Value::Int(5), uint(self.expires)?),
        ];
        if let Some(fingerprint) = &self.expected_fingerprint {
            pairs.push((Value::Int(6), Value::Text(fingerprint.clone())));
        }
        if let Some(min) = self.min_assurance {
            pairs.push((Value::Int(7), Value::Text(min.as_str().to_owned())));
        }
        pairs.extend([
            (Value::Int(8), uint(self.max_uses)?),
            (Value::Int(9), uint(self.created_at)?),
            (Value::Int(10), Value::Text(self.created_by.clone())),
        ]);
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "an invitation")?;
        let mut map = Labelled::read(bytes, "an invitation")?;
        let invitation = Self {
            invite_id: map.id(1)?,
            token_key: map.fixed(2)?,
            selector: selector(&map.text(3)?)?,
            tasks: read_tasks(map.array(4)?)?,
            expires: map.uint(5)?,
            expected_fingerprint: map.optional_text(6)?,
            min_assurance: map.optional_text(7)?.as_deref().map(profile).transpose()?,
            max_uses: map.uint(8)?,
            created_at: map.uint(9)?,
            created_by: map.text(10)?,
        };
        map.finish()?;
        if invitation.max_uses != 1 {
            return Err(RecordError("an invitation is used once".to_owned()));
        }
        Ok(invitation)
    }
}

/// What an enrolling member asks for, its bytes bound into the session transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollRequest {
    pub invite_id: [u8; 16],
    /// The token key's Ed25519 signature over the coordinator, the member and the exporter.
    pub token_proof: [u8; 64],
    pub selector: Selector,
    pub tasks: Vec<Task>,
    pub member: HostRef,
    pub ring_statements: Vec<RingStatement>,
    /// The contracts the member registered (WP-4.4).
    pub capabilities: Vec<Capability>,
}

impl EnrollRequest {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.invite_id.to_vec())),
            (Value::Int(2), Value::Bytes(self.token_proof.to_vec())),
            (Value::Int(3), Value::Text(self.selector.to_string())),
            (Value::Int(4), tasks_value(&self.tasks)?),
            (Value::Int(5), self.member.value()?),
            (Value::Int(6), statements_value(&self.ring_statements)?),
            (Value::Int(7), capabilities_value(&self.capabilities)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "an enrollment request")?;
        let mut map = Labelled::read(bytes, "an enrollment request")?;
        let request = Self {
            invite_id: map.id(1)?,
            token_proof: map.fixed(2)?,
            selector: selector(&map.text(3)?)?,
            tasks: read_tasks(map.array(4)?)?,
            member: HostRef::read(map.value(5)?)?,
            ring_statements: read_statements(map.array(6)?)?,
            capabilities: read_capabilities(map.array(7)?)?,
        };
        map.finish()?;
        Ok(request)
    }
}

/// The digest the session `hello` and transcript cite a request by: over its bytes.
pub fn request_digest(bytes: &[u8]) -> Digest {
    let mut input = digest::MEMBERSHIP_REQUEST.as_bytes().to_vec();
    input.extend_from_slice(bytes);
    Digest::compute(&input)
}

/// A membership waiting for approval, as the enrollment created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    pub membership_id: [u8; 16],
    pub invite_id: [u8; 16],
    pub coordinator: HostRef,
    pub member: HostRef,
    pub selector: Selector,
    pub tasks: Vec<Task>,
    pub member_assurance: AssuranceProfile,
    pub ring_statements: Vec<RingStatement>,
    pub requested_at: u64,
    /// Where the member reaches its coordinator: the member's copy only.
    pub coordinator_address: Option<String>,
    /// The member's identity as its enrollment session proved it, the session's presentation
    /// bytes: the coordinator's copy only, what a verification bundle carries of the member.
    pub identity: Option<Vec<u8>>,
    /// The contracts the member declared in its request (WP-4.4).
    pub capabilities: Vec<Capability>,
}

impl Pending {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(self.membership_id.to_vec())),
            (Value::Int(2), Value::Bytes(self.invite_id.to_vec())),
            (Value::Int(3), self.coordinator.value()?),
            (Value::Int(4), self.member.value()?),
            (Value::Int(5), Value::Text(self.selector.to_string())),
            (Value::Int(6), tasks_value(&self.tasks)?),
            (
                Value::Int(7),
                Value::Text(self.member_assurance.as_str().to_owned()),
            ),
            (Value::Int(8), statements_value(&self.ring_statements)?),
            (Value::Int(9), uint(self.requested_at)?),
        ];
        if let Some(address) = &self.coordinator_address {
            pairs.push((Value::Int(10), Value::Text(address.clone())));
        }
        if let Some(identity) = &self.identity {
            pairs.push((Value::Int(11), Value::Bytes(identity.clone())));
        }
        pairs.push((Value::Int(12), capabilities_value(&self.capabilities)?));
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a pending membership")?;
        let mut map = Labelled::read(bytes, "a pending membership")?;
        let pending = Self {
            membership_id: map.id(1)?,
            invite_id: map.id(2)?,
            coordinator: HostRef::read(map.value(3)?)?,
            member: HostRef::read(map.value(4)?)?,
            selector: selector(&map.text(5)?)?,
            tasks: read_tasks(map.array(6)?)?,
            member_assurance: profile(&map.text(7)?)?,
            ring_statements: read_statements(map.array(8)?)?,
            requested_at: map.uint(9)?,
            coordinator_address: map.optional_text(10)?,
            identity: map.optional_bytes(11)?,
            capabilities: read_capabilities(map.array(12)?)?,
        };
        map.finish()?;
        Ok(pending)
    }
}

/// What the coordinator answers an enrollment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollAnswer {
    pub membership_id: [u8; 16],
    pub status: Status,
}

impl EnrollAnswer {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.membership_id.to_vec())),
            (Value::Int(2), Value::Text(self.status.as_str().to_owned())),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "an enrollment answer")?;
        let mut map = Labelled::read(bytes, "an enrollment answer")?;
        let answer = Self {
            membership_id: map.id(1)?,
            status: map.text(2)?.parse()?,
        };
        map.finish()?;
        Ok(answer)
    }
}

/// What a member asks of its coordinator on a `membership` session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// The current manifest and the ones since `held_epoch`.
    Fetch,
    /// The membership revoked: the member leaves, its identity reset or retired.
    Revoke,
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Revoke => "revoke",
        }
    }
}

impl FromStr for Action {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, RecordError> {
        match text {
            "fetch" => Ok(Self::Fetch),
            "revoke" => Ok(Self::Revoke),
            _ => Err(RecordError(format!("`{text}` is not a membership action"))),
        }
    }
}

/// A member's request on a `membership` session, its bytes bound into the transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipRequest {
    pub action: Action,
    pub membership_id: [u8; 16],
    pub held_epoch: Option<u64>,
}

impl MembershipRequest {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.action.as_str().to_owned())),
            (Value::Int(2), Value::Bytes(self.membership_id.to_vec())),
        ];
        if let Some(epoch) = self.held_epoch {
            pairs.push((Value::Int(3), uint(epoch)?));
        }
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a membership request")?;
        let mut map = Labelled::read(bytes, "a membership request")?;
        let request = Self {
            action: map.text(1)?.parse()?,
            membership_id: map.id(2)?,
            held_epoch: map.optional_uint(3)?,
        };
        map.finish()?;
        Ok(request)
    }
}

/// What the coordinator answers a `membership` session: the status, the manifests the member
/// does not hold yet, oldest first, and the statements of the coordinator's pinned rings, which
/// verify them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipAnswer {
    pub status: Status,
    pub manifests: Vec<Vec<u8>>,
    pub ring_statements: Vec<RingStatement>,
}

impl MembershipAnswer {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Text(self.status.as_str().to_owned())),
            (
                Value::Int(2),
                Value::Array(self.manifests.iter().cloned().map(Value::Bytes).collect()),
            ),
            (Value::Int(3), statements_value(&self.ring_statements)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a membership answer")?;
        let mut map = Labelled::read(bytes, "a membership answer")?;
        let answer = Self {
            status: map.text(1)?.parse()?,
            manifests: map.byte_strings(2)?,
            ring_statements: read_statements(map.array(3)?)?,
        };
        map.finish()?;
        Ok(answer)
    }
}

/// What a journal entry records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// An invitation was issued; the detail is the invitation.
    Invited,
    /// An invitation was revoked before use.
    InviteRevoked,
    /// A member enrolled, consuming its invitation; the detail is the pending membership.
    Enrolled,
    /// A manifest was issued or accepted: approval, rejection, suspension, resumption, fence,
    /// revocation, expiry or a re-pin; the detail is the signed manifest.
    Manifest,
    /// The member side joined a coordinator: the detail is the pending membership as the member
    /// keeps it.
    Joined,
    /// The membership became orphaned on an identity reset.
    Orphaned,
    /// The coordinator saw an epoch it never issued: the membership is held for review until
    /// revoked (WP-4.3); the entry's epoch is the one seen.
    Held,
    /// A member's cutover to a re-pinned set; the detail is the [`Cutover`] (WP-4.5).
    Cutover,
    /// A stream's spans under a retiring set acknowledged; the detail is the
    /// [`Acknowledgement`] (WP-4.5).
    Acknowledged,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Invited => "invited",
            Self::InviteRevoked => "invite_revoked",
            Self::Enrolled => "enrolled",
            Self::Manifest => "manifest",
            Self::Joined => "joined",
            Self::Orphaned => "orphaned",
            Self::Held => "held",
            Self::Cutover => "cutover",
            Self::Acknowledged => "acknowledged",
        }
    }
}

impl FromStr for Kind {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, RecordError> {
        [
            Self::Invited,
            Self::InviteRevoked,
            Self::Enrolled,
            Self::Manifest,
            Self::Joined,
            Self::Orphaned,
            Self::Held,
            Self::Cutover,
            Self::Acknowledged,
        ]
        .into_iter()
        .find(|kind| kind.as_str() == text)
        .ok_or_else(|| RecordError(format!("`{text}` is not a membership journal entry")))
    }
}

/// One entry of `journal.cborseq`, chained to the one before.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    pub kind: Kind,
    /// The invitation or membership the entry is about.
    pub subject: [u8; 16],
    pub epoch: Option<u64>,
    pub at: u64,
    pub operation_id: Option<[u8; 16]>,
    /// The chain: [`chain`] over the entry before, or over nothing for the first.
    pub previous: Digest,
    pub detail: Option<Vec<u8>>,
    /// The coordinator's statements of the rings a manifest it issued pins, as they stood when it
    /// signed: what a member verifies that manifest with, whatever the rings did since. Absent
    /// when empty.
    pub statements: Vec<RingStatement>,
}

impl Entry {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), uint(self.seq)?),
            (Value::Int(2), Value::Text(self.kind.as_str().to_owned())),
            (Value::Int(3), Value::Bytes(self.subject.to_vec())),
        ];
        if let Some(epoch) = self.epoch {
            pairs.push((Value::Int(4), uint(epoch)?));
        }
        pairs.push((Value::Int(5), uint(self.at)?));
        if let Some(operation_id) = &self.operation_id {
            pairs.push((Value::Int(6), Value::Bytes(operation_id.to_vec())));
        }
        pairs.push((Value::Int(7), Value::Text(self.previous.to_string())));
        if let Some(detail) = &self.detail {
            pairs.push((Value::Int(8), Value::Bytes(detail.clone())));
        }
        if !self.statements.is_empty() {
            pairs.push((Value::Int(9), statements_value(&self.statements)?));
        }
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a membership journal entry")?;
        let mut map = Labelled::read(bytes, "a membership journal entry")?;
        let entry = Self {
            seq: map.uint(1)?,
            kind: map.text(2)?.parse()?,
            subject: map.id(3)?,
            epoch: map.optional_uint(4)?,
            at: map.uint(5)?,
            operation_id: map.optional_id(6)?,
            previous: map.digest(7)?,
            detail: map.optional_bytes(8)?,
            statements: match map.optional_array(9)? {
                Some(values) if values.is_empty() => {
                    return Err(RecordError(
                        "a journal entry with no statements omits label 9".to_owned(),
                    ));
                }
                Some(values) => read_statements(values)?,
                None => Vec::new(),
            },
        };
        map.finish()?;
        Ok(entry)
    }
}

/// The chain value an entry names: `sha256:` over the domain and the entry before, the genesis
/// over the domain alone.
pub fn chain(previous_entry: Option<&[u8]>) -> Digest {
    let mut input = digest::MEMBERSHIP_JOURNAL.as_bytes().to_vec();
    if let Some(bytes) = previous_entry {
        input.extend_from_slice(bytes);
    }
    Digest::compute(&input)
}

#[cfg(test)]
mod tests;

/// The most bytes a task message's body takes: inside one peer frame
/// (`session::record::MAX_FRAME_BYTES`, 512 KiB) with room for the envelope.
pub const MAX_BODY_BYTES: usize = 448 * 1024;
/// The longest request id a task message names.
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// A task id as a manifest grants it: lowercase letters, digits and `-`, 1 to
/// [`MAX_NAME_BYTES`] bytes.
fn task_id(text: String) -> Result<String, RecordError> {
    name(&text, "a task id")?;
    if !text
        .bytes()
        .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(RecordError(
            "a task id is lowercase letters, digits and `-`".to_owned(),
        ));
    }
    Ok(text)
}

fn resource(text: String) -> Result<String, RecordError> {
    permguard_core::authz::Resource::parse(&text)
        .map_err(|error| RecordError(format!("a resource: {error}")))?;
    Ok(text)
}

/// What a member asks a task session for (WP-4.3): a lease for one task of one membership, at the
/// epoch it holds, over one resource, from this incarnation of itself.
#[derive(Clone, PartialEq, Eq)]
pub struct LeaseRequest {
    pub membership_id: [u8; 16],
    pub task_id: String,
    pub epoch: u64,
    pub resource: String,
    pub member_boot_id: [u8; 16],
    /// Evidence for the coordinator's appraisal, as `POST …/appraise` takes it (WP-4.2).
    pub evidence: Vec<(String, Vec<u8>)>,
}

impl fmt::Debug for LeaseRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LeaseRequest")
            .field("task_id", &self.task_id)
            .field("epoch", &self.epoch)
            .field("resource", &self.resource)
            .field("evidence", &self.evidence.len())
            .finish_non_exhaustive()
    }
}

impl LeaseRequest {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(self.membership_id.to_vec())),
            (Value::Int(2), Value::Text(self.task_id.clone())),
            (Value::Int(3), uint(self.epoch)?),
            (Value::Int(4), Value::Text(self.resource.clone())),
            (Value::Int(5), Value::Bytes(self.member_boot_id.to_vec())),
        ];
        if !self.evidence.is_empty() {
            pairs.push((
                Value::Int(6),
                Value::Array(
                    self.evidence
                        .iter()
                        .map(|(verifier, evidence)| {
                            Value::Array(vec![
                                Value::Text(verifier.clone()),
                                Value::Bytes(evidence.clone()),
                            ])
                        })
                        .collect(),
                ),
            ));
        }
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a lease request")?;
        let mut map = Labelled::read(bytes, "a lease request")?;
        let request = Self {
            membership_id: map.id(1)?,
            task_id: task_id(map.text(2)?)?,
            epoch: map.uint(3)?,
            resource: resource(map.text(4)?)?,
            member_boot_id: map.id(5)?,
            evidence: match map.optional_array(6)? {
                None => Vec::new(),
                Some(items) => {
                    if items.is_empty() || items.len() > 4 {
                        return Err(RecordError(
                            "a lease request carries 1 to 4 pieces of evidence, or none".to_owned(),
                        ));
                    }
                    items
                        .into_iter()
                        .map(|item| match item {
                            Value::Array(pair) => match <[Value; 2]>::try_from(pair) {
                                Ok([Value::Text(verifier), Value::Bytes(evidence)]) => {
                                    Ok((verifier, evidence))
                                }
                                _ => Err(RecordError(
                                    "a piece of evidence is [verifier, bytes]".to_owned(),
                                )),
                            },
                            _ => Err(RecordError(
                                "a piece of evidence is [verifier, bytes]".to_owned(),
                            )),
                        })
                        .collect::<Result<_, _>>()?
                }
            },
        };
        map.finish()?;
        if request.epoch == 0 {
            return Err(RecordError(
                "a lease request names an epoch from 1".to_owned(),
            ));
        }
        Ok(request)
    }
}

/// The digest a lease binds its connection by: of the connection's RFC 9266 exporter, never the
/// exporter itself.
pub fn channel_binding(exporter: &[u8; 32]) -> [u8; 32] {
    let mut input = digest::MEMBERSHIP_LEASE_CHANNEL.as_bytes().to_vec();
    input.extend_from_slice(exporter);
    *Digest::compute(&input).raw()
}

/// What a lease signs (WP-4.3): one task session of one membership, at one epoch, between two
/// incarnations of two Hosts, on one connection, until it expires.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub membership_id: [u8; 16],
    pub task_id: String,
    pub epoch: u64,
    pub coordinator: [u8; 16],
    pub member: [u8; 16],
    pub coordinator_boot_id: [u8; 16],
    pub member_boot_id: [u8; 16],
    pub selector: Selector,
    pub resource: String,
    pub limits: Limits,
    pub issued_at: u64,
    pub expires_at: u64,
    pub channel_binding: [u8; 32],
    /// The assurance binding the task was admitted under, when it requires controls.
    pub binding_digest: Option<Digest>,
}

impl Lease {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(self.membership_id.to_vec())),
            (Value::Int(2), Value::Text(self.task_id.clone())),
            (Value::Int(3), uint(self.epoch)?),
            (Value::Int(4), Value::Bytes(self.coordinator.to_vec())),
            (Value::Int(5), Value::Bytes(self.member.to_vec())),
            (
                Value::Int(6),
                Value::Bytes(self.coordinator_boot_id.to_vec()),
            ),
            (Value::Int(7), Value::Bytes(self.member_boot_id.to_vec())),
            (Value::Int(8), Value::Text(self.selector.to_string())),
            (Value::Int(9), Value::Text(self.resource.clone())),
            (Value::Int(10), self.limits.value()?),
            (Value::Int(11), uint(self.issued_at)?),
            (Value::Int(12), uint(self.expires_at)?),
            (Value::Int(13), Value::Bytes(self.channel_binding.to_vec())),
        ];
        if let Some(binding) = &self.binding_digest {
            pairs.push((Value::Int(14), Value::Text(binding.to_string())));
        }
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a lease")?;
        let mut map = Labelled::read(bytes, "a lease")?;
        let lease = Self {
            membership_id: map.id(1)?,
            task_id: task_id(map.text(2)?)?,
            epoch: map.uint(3)?,
            coordinator: map.id(4)?,
            member: map.id(5)?,
            coordinator_boot_id: map.id(6)?,
            member_boot_id: map.id(7)?,
            selector: selector(&map.text(8)?)?,
            resource: resource(map.text(9)?)?,
            limits: Limits::read(map.value(10)?)?,
            issued_at: map.uint(11)?,
            expires_at: map.uint(12)?,
            channel_binding: map.fixed(13)?,
            binding_digest: map.optional_digest(14)?,
        };
        map.finish()?;
        if lease.epoch == 0 || lease.expires_at <= lease.issued_at {
            return Err(RecordError(
                "a lease names an epoch from 1 and expires after it is issued".to_owned(),
            ));
        }
        Ok(lease)
    }
}

/// What a coordinator answers a lease request: the lease, and the manifest an appraisal at the
/// session revised, which the member accepts as the exact successor first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseAnswer {
    pub lease: Vec<u8>,
    pub manifest: Option<Vec<u8>>,
}

impl LeaseAnswer {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![(Value::Int(1), Value::Bytes(self.lease.clone()))];
        if let Some(manifest) = &self.manifest {
            pairs.push((Value::Int(2), Value::Bytes(manifest.clone())));
        }
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a lease answer")?;
        let mut map = Labelled::read(bytes, "a lease answer")?;
        let answer = Self {
            lease: map.bytes(1)?,
            manifest: map.optional_bytes(2)?,
        };
        map.finish()?;
        Ok(answer)
    }
}

fn request_id(text: String) -> Result<String, RecordError> {
    if text.is_empty() || text.len() > MAX_REQUEST_ID_BYTES || text.chars().any(char::is_control) {
        return Err(RecordError(format!(
            "a request id is printable text of 1 to {MAX_REQUEST_ID_BYTES} bytes"
        )));
    }
    Ok(text)
}

fn body(bytes: Vec<u8>) -> Result<Vec<u8>, RecordError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(RecordError(format!(
            "a task message's body takes at most {MAX_BODY_BYTES} bytes"
        )));
    }
    Ok(bytes)
}

/// One application message of a task session (WP-4.3): it repeats the membership, the task and
/// the epoch, and names its request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskMessage {
    pub membership_id: [u8; 16],
    pub task_id: String,
    pub epoch: u64,
    pub request_id: String,
    pub body: Vec<u8>,
    /// What the message is (WP-4.4): one for the task's handler unless it says otherwise.
    pub kind: MessageKind,
}

/// What a task message carries (WP-4.4, owner decision): label 6 is absent for the handler's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// A message the task's handler answers.
    Handler,
    /// A [`TaskProgress`] report.
    Progress,
    /// A [`WatchRequest`]: the session then belongs to the watch.
    Watch,
    /// A [`RingStatement`] the member's ring moved to: the re-pin (WP-4.5).
    Repin,
    /// A [`Cutover`] fixing each stream's first sequence under the new set (WP-4.5).
    Cutover,
}

impl MessageKind {
    fn label(self) -> Option<&'static str> {
        match self {
            Self::Handler => None,
            Self::Progress => Some("progress"),
            Self::Watch => Some("watch"),
            Self::Repin => Some("repin"),
            Self::Cutover => Some("cutover"),
        }
    }

    fn parse(text: Option<String>) -> Result<Self, RecordError> {
        match text.as_deref() {
            None => Ok(Self::Handler),
            Some("progress") => Ok(Self::Progress),
            Some("watch") => Ok(Self::Watch),
            Some("repin") => Ok(Self::Repin),
            Some("cutover") => Ok(Self::Cutover),
            Some(other) => Err(RecordError(format!("`{other}` is not a task message kind"))),
        }
    }
}

impl TaskMessage {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(
            [
                (Value::Int(1), Value::Bytes(self.membership_id.to_vec())),
                (Value::Int(2), Value::Text(self.task_id.clone())),
                (Value::Int(3), uint(self.epoch)?),
                (Value::Int(4), Value::Text(self.request_id.clone())),
                (Value::Int(5), Value::Bytes(self.body.clone())),
            ]
            .into_iter()
            .chain(
                self.kind
                    .label()
                    .map(|kind| (Value::Int(6), Value::Text(kind.to_owned()))),
            )
            .collect(),
        )
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_BODY_BYTES + 1024 {
            return Err(RecordError("a task message is out of its bound".to_owned()));
        }
        let mut map = Labelled::read(bytes, "a task message")?;
        let message = Self {
            membership_id: map.id(1)?,
            task_id: task_id(map.text(2)?)?,
            epoch: map.uint(3)?,
            request_id: request_id(map.text(4)?)?,
            body: body(map.bytes(5)?)?,
            kind: MessageKind::parse(map.optional_text(6)?)?,
        };
        map.finish()?;
        Ok(message)
    }
}

/// What a task's handler answers one message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskAnswer {
    pub request_id: String,
    pub body: Vec<u8>,
}

impl TaskAnswer {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Text(self.request_id.clone())),
            (Value::Int(2), Value::Bytes(self.body.clone())),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_BODY_BYTES + 1024 {
            return Err(RecordError("a task answer is out of its bound".to_owned()));
        }
        let mut map = Labelled::read(bytes, "a task answer")?;
        let answer = Self {
            request_id: request_id(map.text(1)?)?,
            body: body(map.bytes(2)?)?,
        };
        map.finish()?;
        Ok(answer)
    }
}

fn small(bytes: &[u8], what: &str) -> Result<(), RecordError> {
    if bytes.len() > MAX_SMALL_RECORD_BYTES {
        return Err(RecordError(format!("{what} is out of its bound")));
    }
    Ok(())
}

fn body_bound(bytes: &[u8], what: &str) -> Result<(), RecordError> {
    if bytes.len() > MAX_BODY_BYTES {
        return Err(RecordError(format!("{what} is out of its bound")));
    }
    Ok(())
}

/// Printable text of 1 to `most` bytes.
fn bounded_text(text: String, most: usize, what: &str) -> Result<String, RecordError> {
    if text.is_empty() || text.len() > most || text.chars().any(char::is_control) {
        return Err(RecordError(format!(
            "{what} is printable text of 1 to {most} bytes"
        )));
    }
    Ok(text)
}

/// One resource of a progress report, as the member states it (WP-4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgressResource {
    pub resource: String,
    pub state: String,
    pub frontier: Option<String>,
    pub checkpoint_digest: Option<Digest>,
    pub verified_at: Option<u64>,
    pub reason: Option<String>,
}

impl ProgressResource {
    fn value(&self) -> Result<Value, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.resource.clone())),
            (Value::Int(2), Value::Text(self.state.clone())),
        ];
        if let Some(frontier) = &self.frontier {
            pairs.push((Value::Int(3), Value::Text(frontier.clone())));
        }
        if let Some(digest) = &self.checkpoint_digest {
            pairs.push((Value::Int(4), Value::Text(digest.to_string())));
        }
        if let Some(verified_at) = self.verified_at {
            pairs.push((Value::Int(5), uint(verified_at)?));
        }
        if let Some(reason) = &self.reason {
            pairs.push((Value::Int(6), Value::Text(reason.clone())));
        }
        Ok(Value::Map(pairs))
    }

    fn read(value: Value) -> Result<Self, RecordError> {
        let mut map = Labelled::from_value(value, "a progress resource")?;
        let resource = Self {
            resource: resource(map.text(1)?)?,
            state: bounded_text(map.text(2)?, MAX_NAME_BYTES, "a progress state")?,
            frontier: map
                .optional_text(3)?
                .map(|text| bounded_text(text, MAX_REASON_BYTES, "a frontier"))
                .transpose()?,
            checkpoint_digest: map.optional_digest(4)?,
            verified_at: map.optional_uint(5)?,
            reason: map
                .optional_text(6)?
                .map(|text| bounded_text(text, MAX_REASON_BYTES, "a reason"))
                .transpose()?,
        };
        map.finish()?;
        Ok(resource)
    }
}

/// What a member last reported doing for one task (the membership's task progress, WP-4.4):
/// never proof that it is reachable, kept exactly as sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskProgress {
    pub membership_id: [u8; 16],
    pub task_id: String,
    pub manifest_epoch: u64,
    pub member_boot_id: [u8; 16],
    pub report_seq: u64,
    pub reported_at: u64,
    pub resources: Vec<ProgressResource>,
}

impl TaskProgress {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        if self.resources.len() > MAX_PROGRESS_RESOURCES {
            return Err(RecordError(format!(
                "a progress report carries at most {MAX_PROGRESS_RESOURCES} resources"
            )));
        }
        let bytes = encode(vec![
            (Value::Int(1), Value::Bytes(self.membership_id.to_vec())),
            (Value::Int(2), Value::Text(self.task_id.clone())),
            (Value::Int(3), uint(self.manifest_epoch)?),
            (Value::Int(4), Value::Bytes(self.member_boot_id.to_vec())),
            (Value::Int(5), uint(self.report_seq)?),
            (Value::Int(6), uint(self.reported_at)?),
            (
                Value::Int(7),
                Value::Array(
                    self.resources
                        .iter()
                        .map(ProgressResource::value)
                        .collect::<Result<_, _>>()?,
                ),
            ),
        ])?;
        if bytes.len() > MAX_PROGRESS_BYTES {
            return Err(RecordError(format!(
                "a progress report takes at most {MAX_PROGRESS_BYTES} bytes"
            )));
        }
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_PROGRESS_BYTES {
            return Err(RecordError(format!(
                "a progress report takes at most {MAX_PROGRESS_BYTES} bytes"
            )));
        }
        let mut map = Labelled::read(bytes, "a progress report")?;
        let membership_id = map.id(1)?;
        let task_id = task_id(map.text(2)?)?;
        let manifest_epoch = map.uint(3)?;
        let member_boot_id = map.fixed(4)?;
        let report_seq = map.uint(5)?;
        let reported_at = map.uint(6)?;
        let resources = map.array(7)?;
        if resources.len() > MAX_PROGRESS_RESOURCES {
            return Err(RecordError(format!(
                "a progress report carries at most {MAX_PROGRESS_RESOURCES} resources"
            )));
        }
        let progress = Self {
            membership_id,
            task_id,
            manifest_epoch,
            member_boot_id,
            report_seq,
            reported_at,
            resources: resources
                .into_iter()
                .map(ProgressResource::read)
                .collect::<Result<_, _>>()?,
        };
        map.finish()?;
        Ok(progress)
    }
}

/// What the coordinator answers a progress report it kept (WP-4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgressAnswer {
    pub report_seq: u64,
    pub received_at: u64,
}

impl ProgressAnswer {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), uint(self.report_seq)?),
            (Value::Int(2), uint(self.received_at)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        small(bytes, "a progress answer")?;
        let mut map = Labelled::read(bytes, "a progress answer")?;
        let answer = Self {
            report_seq: map.uint(1)?,
            received_at: map.uint(2)?,
        };
        map.finish()?;
        Ok(answer)
    }
}

/// A progress report as the coordinator keeps it: the exact bytes and when they arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeptProgress {
    pub report: Vec<u8>,
    pub received_at: u64,
}

impl KeptProgress {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.report.clone())),
            (Value::Int(2), uint(self.received_at)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_PROGRESS_BYTES + 64 {
            return Err(RecordError(
                "a kept progress report is out of its bound".to_owned(),
            ));
        }
        let mut map = Labelled::read(bytes, "a kept progress report")?;
        let kept = Self {
            report: map.bytes(1)?,
            received_at: map.uint(2)?,
        };
        map.finish()?;
        TaskProgress::decode(&kept.report)?;
        Ok(kept)
    }
}

/// The last session a coordinator leased for one task, from its own clock (WP-4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LastSession {
    pub at: u64,
    pub member_boot_id: [u8; 16],
}

impl LastSession {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), uint(self.at)?),
            (Value::Int(2), Value::Bytes(self.member_boot_id.to_vec())),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        small(bytes, "a last session")?;
        let mut map = Labelled::read(bytes, "a last session")?;
        let last = Self {
            at: map.uint(1)?,
            member_boot_id: map.fixed(2)?,
        };
        map.finish()?;
        Ok(last)
    }
}

fn watch_key(text: String) -> Result<String, RecordError> {
    bounded_text(text, MAX_WATCH_TEXT_BYTES, "a watch key")
}

/// What a member opens a watch with (WP-4.4): the counter it holds per key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchRequest {
    pub positions: Vec<(String, u64)>,
}

impl WatchRequest {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut positions = self.positions.clone();
        positions.sort();
        encode(vec![(
            Value::Int(1),
            Value::Array(
                positions
                    .iter()
                    .map(|(key, counter)| {
                        Ok(Value::Map(vec![
                            (Value::Int(1), Value::Text(key.clone())),
                            (Value::Int(2), uint(*counter)?),
                        ]))
                    })
                    .collect::<Result<_, RecordError>>()?,
            ),
        )])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        body_bound(bytes, "a watch request")?;
        let mut map = Labelled::read(bytes, "a watch request")?;
        let values = map.array(1)?;
        map.finish()?;
        if values.len() > MAX_WATCH_KEYS {
            return Err(RecordError(format!(
                "a watch tracks at most {MAX_WATCH_KEYS} keys"
            )));
        }
        let mut positions = Vec::with_capacity(values.len());
        for value in values {
            let mut position = Labelled::from_value(value, "a watch position")?;
            let key = watch_key(position.text(1)?)?;
            let counter = position.uint(2)?;
            position.finish()?;
            positions.push((key, counter));
        }
        if !positions.windows(2).all(|pair| pair[0].0 < pair[1].0) {
            return Err(RecordError(
                "a watch names its keys in order, each once".to_owned(),
            ));
        }
        Ok(Self { positions })
    }
}

/// One hint of a watch: a key advanced to `head` at `counter`; it grants nothing (WP-4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchHint {
    pub key: String,
    pub head: String,
    pub counter: u64,
}

/// What a watch sends: the hints coalesced since the last event, none for a heartbeat (WP-4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchEvent {
    pub hints: Vec<WatchHint>,
}

impl WatchEvent {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut hints = self.hints.clone();
        hints.sort_by(|a, b| a.key.cmp(&b.key));
        encode(vec![(
            Value::Int(1),
            Value::Array(
                hints
                    .iter()
                    .map(|hint| {
                        Ok(Value::Map(vec![
                            (Value::Int(1), Value::Text(hint.key.clone())),
                            (Value::Int(2), Value::Text(hint.head.clone())),
                            (Value::Int(3), uint(hint.counter)?),
                        ]))
                    })
                    .collect::<Result<_, RecordError>>()?,
            ),
        )])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        body_bound(bytes, "a watch event")?;
        let mut map = Labelled::read(bytes, "a watch event")?;
        let values = map.array(1)?;
        map.finish()?;
        if values.len() > MAX_WATCH_KEYS {
            return Err(RecordError(format!(
                "a watch event carries at most {MAX_WATCH_KEYS} hints"
            )));
        }
        let mut hints = Vec::with_capacity(values.len());
        for value in values {
            let mut hint = Labelled::from_value(value, "a watch hint")?;
            let read = WatchHint {
                key: watch_key(hint.text(1)?)?,
                head: bounded_text(hint.text(2)?, MAX_WATCH_TEXT_BYTES, "a watch head")?,
                counter: hint.uint(3)?,
            };
            hint.finish()?;
            hints.push(read);
        }
        if !hints.windows(2).all(|pair| pair[0].key < pair[1].key) {
            return Err(RecordError(
                "a watch event names its keys in order, each once".to_owned(),
            ));
        }
        Ok(Self { hints })
    }
}

/// One answered request in a membership's replay window (WP-4.4, owner decision): an identical
/// repeat is answered `answer` without reaching the handler.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayEntry {
    pub task_id: String,
    pub request_id: String,
    /// SHA-256 of the task message's bytes followed by the session's resource.
    pub message_digest: [u8; 32],
    /// The encoded task answer.
    pub answer: Vec<u8>,
    /// Its place in the task's window: the slot is `seq` modulo the window.
    pub seq: u64,
}

impl ReplayEntry {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Text(self.task_id.clone())),
            (Value::Int(2), Value::Text(self.request_id.clone())),
            (Value::Int(3), Value::Bytes(self.message_digest.to_vec())),
            (Value::Int(4), Value::Bytes(self.answer.clone())),
            (Value::Int(5), uint(self.seq)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_BODY_BYTES + 1024 {
            return Err(RecordError("a replay entry is out of its bound".to_owned()));
        }
        let mut map = Labelled::read(bytes, "a replay entry")?;
        let entry = Self {
            task_id: task_id(map.text(1)?)?,
            request_id: request_id(map.text(2)?)?,
            message_digest: map.fixed(3)?,
            answer: map.bytes(4)?,
            seq: map.uint(5)?,
        };
        map.finish()?;
        Ok(entry)
    }
}

/// The most streams one cutover names (WP-4.5).
pub const MAX_STREAMS: usize = 64;
/// The longest stream name.
pub const MAX_STREAM_BYTES: usize = 256;

impl RingStatement {
    /// The statement's bytes, as a re-pin carries it (WP-4.5).
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let Value::Map(pairs) = self.value()? else {
            return Err(RecordError("a ring statement is a map".to_owned()));
        };
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a ring statement")?;
        let value = permguard_objects::cbor::decode_canonical(bytes)
            .map_err(|error| RecordError(format!("a ring statement: {error}")))?;
        Self::read(value)
    }
}

fn ring_name(text: String) -> Result<String, RecordError> {
    bounded_text(text, MAX_NAME_BYTES, "a ring")
}

/// A member's cutover to the set a re-pin accepted: the first sequence each stream signs under
/// it (WP-4.5, owner decision); the old set verifies only below.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cutover {
    pub ring: String,
    /// The ring epoch the re-pin accepted.
    pub epoch: u64,
    /// `(stream, from_seq)`, in stream order, each once.
    pub streams: Vec<(String, u64)>,
}

impl Cutover {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut streams = self.streams.clone();
        streams.sort();
        encode(vec![
            (Value::Int(1), Value::Text(self.ring.clone())),
            (Value::Int(2), uint(self.epoch)?),
            (
                Value::Int(3),
                Value::Array(
                    streams
                        .iter()
                        .map(|(stream, from)| {
                            Ok(Value::Map(vec![
                                (Value::Int(1), Value::Text(stream.clone())),
                                (Value::Int(2), uint(*from)?),
                            ]))
                        })
                        .collect::<Result<_, RecordError>>()?,
                ),
            ),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        bounded(bytes, "a cutover")?;
        let mut map = Labelled::read(bytes, "a cutover")?;
        let ring = ring_name(map.text(1)?)?;
        let epoch = map.uint(2)?;
        let values = map.array(3)?;
        map.finish()?;
        // None when the member signs no stream under the ring (owner decision, after the review).
        if values.len() > MAX_STREAMS {
            return Err(RecordError(format!(
                "a cutover names at most {MAX_STREAMS} streams"
            )));
        }
        let mut streams = Vec::with_capacity(values.len());
        for value in values {
            let mut stream = Labelled::from_value(value, "a cutover stream")?;
            let name = bounded_text(stream.text(1)?, MAX_STREAM_BYTES, "a stream")?;
            let from = stream.uint(2)?;
            stream.finish()?;
            streams.push((name, from));
        }
        if !streams.windows(2).all(|pair| pair[0].0 < pair[1].0) {
            return Err(RecordError(
                "a cutover names its streams in order, each once".to_owned(),
            ));
        }
        Ok(Self {
            ring,
            epoch,
            streams,
        })
    }
}

/// One stream's spans under a retiring set, acknowledged through `through_seq` (WP-4.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Acknowledgement {
    pub ring: String,
    pub epoch: u64,
    pub stream: String,
    pub through_seq: u64,
}

impl Acknowledgement {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Text(self.ring.clone())),
            (Value::Int(2), uint(self.epoch)?),
            (Value::Int(3), Value::Text(self.stream.clone())),
            (Value::Int(4), uint(self.through_seq)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        small_bounded(bytes, "an acknowledgement")?;
        let mut map = Labelled::read(bytes, "an acknowledgement")?;
        let acknowledgement = Self {
            ring: ring_name(map.text(1)?)?,
            epoch: map.uint(2)?,
            stream: bounded_text(map.text(3)?, MAX_STREAM_BYTES, "a stream")?,
            through_seq: map.uint(4)?,
        };
        map.finish()?;
        Ok(acknowledgement)
    }
}

/// The last manifest epoch a coordinator delivered to its member, by a lease or a sync (WP-4.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delivered {
    pub epoch: u64,
    pub at: u64,
}

impl Delivered {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), uint(self.epoch)?),
            (Value::Int(2), uint(self.at)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        small(bytes, "a delivery")?;
        let mut map = Labelled::read(bytes, "a delivery")?;
        let delivered = Self {
            epoch: map.uint(1)?,
            at: map.uint(2)?,
        };
        map.finish()?;
        Ok(delivered)
    }
}

/// The most bytes an acknowledgement takes: two names and two numbers.
const MAX_ACKNOWLEDGEMENT_BYTES: usize = 1024;

fn small_bounded(bytes: &[u8], what: &str) -> Result<(), RecordError> {
    if bytes.len() > MAX_ACKNOWLEDGEMENT_BYTES {
        return Err(RecordError(format!("{what} is out of its bound")));
    }
    Ok(())
}
