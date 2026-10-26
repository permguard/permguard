// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host's stream engine (WP-5.1; owner decisions of 2026-10-13): one durable engine every
//! Plane registers its streams with, instead of keeping a journal of its own.
//!
//! ```text
//! Plane declaration ─▶ Descriptor::check: names, version, registered domains, ring and task
//!   ─▶ beneath host/streams/<plane>/<type>/<version>/, its protected fields pinned in DESCRIPTOR
//!   ─▶ no second registration of the same stream and role
//!   ─▶ Producer<C> / Consumer<C>: typed handles over the codec the Plane gives
//!
//! append(resource, record) ─▶ the stream key (plane, type, resource, producer_host_id)
//!   ─▶ its physical stream: one framed journal, runs inside it (RUN-OPEN … records … TERMINAL)
//!   ─▶ the write gate gives the record the next sequence of the current run
//!   ─▶ group commit: the records waiting share one frame and one flush
//!   ─▶ the caller is answered once the flush covering its record completes
//! ```
//!
//! ```text
//! host/streams/<plane>/<type>/<version>/
//! ├── DESCRIPTOR                                      the protected fields' digest
//! ├── producer/<sha256(resource)>/<producer-host>/
//! │   ├── STATE  RESERVE
//! │   └── records/seg-<first>.pgj                     the storage library's framed journal
//! └── consumer/<sha256(resource)>/<producer-host>/<run>/
//!     └── records/seg-<first>.pgj
//! ```
//!
//! A resource is in a path as its digest, a Host and a run as their hex ids: validated
//! identifiers or fixed digests, never a caller's text. ANCHOR, batches, signers and
//! subscriptions arrive with WP-5.2 to WP-5.6.
//!
//! The Plane-side engines that predate this one are named in [`LEGACY_ENGINES`]: the decision
//! spool and the event journals the owner's decision named, adopted by WP-6.1 and WP-6.2, and the
//! consumer stores and indexes the structural check found beside them. No other Plane code keeps
//! a journal (`permguard-conformance` `stream_engines`).

pub mod anchor;
pub mod batch;
pub(crate) mod codec;
mod consumer;
pub mod ingest;
mod producer;
pub mod reads;
pub mod retention;
pub mod run;
pub mod state;
pub mod verify;

use std::collections::BTreeSet;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use permguard_core::authz::Resource;
use permguard_host::identity::Identity;
use permguard_host::keys::ring::{CONTROL_ATTEST, DATA_ATTEST, HOST_OPERATIONS, Ring};
use permguard_host::membership::record::TaskType;
use permguard_host::storage::Dir;
use permguard_host::storage::format;
use permguard_host::storage::volume::Volume;
use permguard_host::storage::write::{read_view, replace_view};
use permguard_host::time::TimeGuard;
use permguard_objects::cbor::Value;
use sha2::{Digest as _, Sha256};

pub use consumer::{Consumer, ConsumerState, ForkMark, MAX_VIEW_BYTES};
pub use producer::{
    Cutover, MAX_CUTOVER_BYTES, MAX_SIGNERS_BYTES, MAX_SUBSCRIPTION_BYTES, Position,
    PressureBounds, Producer, Receipt, Restored, Sealing, Span, Spans, Subscription,
    SubscriptionState, canonical_jwk, decode_group, encode_group,
};
pub use run::{Fence, RunEnd, RunStatement};
pub use state::State;

/// The Plane-side stream engines that predate this one, adopted by WP-6.1 and WP-6.2 (owner
/// decision): the only Plane sources that may keep a journal, a STATE or a reserve of their own.
pub const LEGACY_ENGINES: [&str; 11] = [
    // The producers the owner's decision named. The decision spool is only drained since WP-6.1,
    // until its archive: the plane records on this engine.
    "crates/permguard-decisions/src/spool.rs",
    "crates/permguard-events/src/journal.rs",
    // The consumers and indexes found beside them.
    "crates/permguard-events/src/index.rs",
    "crates/permguard-data-plane/src/temporal/imports.rs",
    "crates/permguard-control-plane/src/decisions/store.rs",
    "crates/permguard-control-plane/src/decisions/retention.rs",
    "crates/permguard-control-plane/src/events/store.rs",
    // The Data Plane code driving them, adopted with them.
    "crates/permguard-data-plane/src/decisions/mod.rs",
    "crates/permguard-data-plane/src/decisions/shipper.rs",
    "crates/permguard-data-plane/src/temporal/streams.rs",
    "crates/permguard-data-plane/src/temporal/submit.rs",
];

/// The directory below `host/` every stream lives in.
pub const STREAMS: &str = "streams";
/// The view pinning a descriptor version's protected fields.
const DESCRIPTOR: &str = "DESCRIPTOR";

/// Why the engine refused.
#[derive(Debug)]
pub enum StreamError {
    /// A descriptor the engine cannot register.
    Descriptor(String),
    /// A stream and role registered twice.
    Duplicate(String),
    /// A record, resource or stored structure that does not read or does not fit.
    Invalid(String),
    /// A run could not be signed or verified.
    Sign(String),
    /// The stream was reported forked: no run opens without an approved successor.
    Forked { at_seq: u64 },
    /// The storage library refused.
    Storage(permguard_host::storage::StorageError),
    /// What is on disk contradicts itself; nothing was changed.
    Corruption(String),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Descriptor(detail) => write!(f, "the stream descriptor is refused: {detail}"),
            Self::Duplicate(stream) => write!(f, "{stream} is registered twice"),
            Self::Invalid(detail) => write!(f, "{detail}"),
            Self::Sign(detail) => write!(f, "a run statement: {detail}"),
            Self::Forked { at_seq } => write!(
                f,
                "the stream forked at sequence {at_seq}: a run opens only as a successor an \
                 operator approved"
            ),
            Self::Storage(error) => write!(f, "{error}"),
            Self::Corruption(detail) => write!(f, "the stream is corrupt: {detail}"),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<permguard_host::storage::StorageError> for StreamError {
    fn from(error: permguard_host::storage::StorageError) -> Self {
        Self::Storage(error)
    }
}

/// `(plane, type, resource, producer_host_id)`, at the descriptor version it is written under.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamKey {
    pub plane: String,
    pub stream_type: String,
    pub version: u32,
    /// The canonical text of the resource.
    pub resource: String,
    pub producer_host_id: [u8; 16],
}

impl StreamKey {
    /// A key whose names and resource are checked: lowercase names, a version of at least 1, a
    /// resource in its canonical form under the stream's plane.
    pub fn new(
        plane: &str,
        stream_type: &str,
        version: u32,
        resource: &str,
        producer_host_id: [u8; 16],
    ) -> Result<Self, StreamError> {
        name(plane, "plane")?;
        name(stream_type, "stream type")?;
        if version == 0 {
            return Err(StreamError::Invalid(
                "a descriptor version is at least 1".to_owned(),
            ));
        }
        let parsed = Resource::parse(resource)
            .map_err(|error| StreamError::Invalid(format!("a resource: {error}")))?;
        if parsed.to_string() != resource || parsed.plane_id() != Some(plane) {
            return Err(StreamError::Invalid(format!(
                "`{resource}` is not a canonical resource of the `{plane}` plane"
            )));
        }
        Ok(Self {
            plane: plane.to_owned(),
            stream_type: stream_type.to_owned(),
            version,
            resource: resource.to_owned(),
            producer_host_id,
        })
    }

    /// The resource's path component: the hex of its SHA-256, never its text.
    pub fn resource_component(&self) -> String {
        hex(&Sha256::digest(self.resource.as_bytes()))
    }
}

/// The level of resource a stream's records belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceShape {
    Plane,
    Zone,
    Ledger,
}

impl ResourceShape {
    fn as_str(self) -> &'static str {
        match self {
            Self::Plane => "plane",
            Self::Zone => "zone",
            Self::Ledger => "ledger",
        }
    }

    fn takes(self, resource: &Resource) -> bool {
        matches!(
            (self, resource),
            (Self::Plane, Resource::Plane { .. })
                | (Self::Zone, Resource::Zone { .. })
                | (Self::Ledger, Resource::Ledger { .. })
        )
    }
}

/// How long a stream's records are kept (WP-5.6 applies it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retention {
    Evidence,
    History,
}

impl Retention {
    fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::History => "history",
        }
    }
}

/// An immutable, versioned declaration of one stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub plane: String,
    pub stream_type: String,
    pub version: u32,
    /// The `typ` of its signed batches: a registered `protected` domain.
    pub batch_typ: &'static str,
    /// The domain its records are digested under: a registered `digest` domain.
    pub record_domain: &'static str,
    pub codec_version: u32,
    /// The event types its records may carry.
    pub event_types: Vec<String>,
    pub resource_shape: ResourceShape,
    pub max_record_bytes: u32,
    pub max_batch_records: u32,
    pub retention: Retention,
    /// Whether a required subscription must acknowledge before records are truncated.
    pub subscription_required: bool,
    /// The ring that signs its batches.
    pub ring: &'static str,
    /// The membership task that ships it, when one does.
    pub task: Option<TaskType>,
}

/// The most bytes one record takes, whatever a descriptor says: below a journal frame.
pub const MAX_RECORD_BYTES: u32 = 1 << 20;

impl Descriptor {
    /// Validates the descriptor (registration): lowercase names, versions of at least 1,
    /// registered domains, a known ring, the ring its task's provider signs with, bounds.
    pub fn check(&self) -> Result<(), StreamError> {
        let refused = |detail: String| Err(StreamError::Descriptor(detail));
        name(&self.plane, "plane").map_err(|error| StreamError::Descriptor(error.to_string()))?;
        name(&self.stream_type, "stream type")
            .map_err(|error| StreamError::Descriptor(error.to_string()))?;
        if self.version == 0 || self.codec_version == 0 {
            return refused("a descriptor and its codec are versioned from 1".to_owned());
        }
        let registered = permguard_core::domains::all();
        let is = |kind: &str, value: &str| {
            registered
                .iter()
                .any(|(name, held)| name.starts_with(kind) && *held == value)
        };
        if !is("protected.", self.batch_typ) {
            return refused(format!("`{}` is no registered batch `typ`", self.batch_typ));
        }
        if !is("digest.", self.record_domain) {
            return refused(format!(
                "`{}` is no registered record digest domain",
                self.record_domain.trim_end()
            ));
        }
        let mut seen = BTreeSet::new();
        for event in &self.event_types {
            let shaped = !event.is_empty()
                && event.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b'_' | b'-')
                });
            if !shaped || !seen.insert(event) {
                return refused(format!("`{event}` is no event type, or is named twice"));
            }
        }
        if self.max_record_bytes == 0
            || self.max_record_bytes > MAX_RECORD_BYTES
            || self.max_batch_records == 0
        {
            return refused(format!(
                "a record of 1 to {MAX_RECORD_BYTES} bytes and a batch of at least one record"
            ));
        }
        if ![DATA_ATTEST, CONTROL_ATTEST, HOST_OPERATIONS].contains(&self.ring) {
            return refused(format!(
                "`{}` is no ring a stream is signed with",
                self.ring
            ));
        }
        if let Some(task) = self.task {
            // The ring the task's provider signs with: what `rings_needed` adds to the
            // coordinator's `host.operations`, which every manifest pins.
            let ring = permguard_host::membership::rings_needed(&[task_of(task)])
                .into_iter()
                .find(|needed| {
                    *needed
                        != (
                            permguard_host::membership::record::Role::Coordinator,
                            HOST_OPERATIONS,
                        )
                })
                .map_or(HOST_OPERATIONS, |(_, ring)| ring);
            if ring != self.ring {
                return refused(format!(
                    "the `{}` task is not signed with `{}`",
                    task.as_str(),
                    self.ring
                ));
            }
        }
        Ok(())
    }

    /// The digest of the fields a change of which makes a new descriptor version: everything
    /// but the limits a deployment tunes (`max_*`, `subscription_required`).
    pub fn protected_digest(&self) -> [u8; 32] {
        let mut events = self.event_types.clone();
        events.sort();
        let tuple = Value::Array(vec![
            Value::Text(self.plane.clone()),
            Value::Text(self.stream_type.clone()),
            Value::Int(i64::from(self.version)),
            Value::Text(self.batch_typ.to_owned()),
            Value::Text(self.record_domain.to_owned()),
            Value::Int(i64::from(self.codec_version)),
            Value::Array(events.into_iter().map(Value::Text).collect()),
            Value::Text(self.resource_shape.as_str().to_owned()),
            Value::Text(self.retention.as_str().to_owned()),
            Value::Text(self.ring.to_owned()),
            Value::Text(self.task.map_or("", TaskType::as_str).to_owned()),
        ]);
        let bytes = permguard_objects::cbor::encode(&tuple).unwrap_or_default();
        Sha256::digest(bytes).into()
    }

    /// The stream key of `resource` produced by `producer`: refused unless the resource has the
    /// descriptor's shape on its plane.
    pub fn key(&self, resource: &Resource, producer: [u8; 16]) -> Result<StreamKey, StreamError> {
        if !self.resource_shape.takes(resource) {
            return Err(StreamError::Invalid(format!(
                "`{resource}` is not a {} resource",
                self.resource_shape.as_str()
            )));
        }
        StreamKey::new(
            &self.plane,
            &self.stream_type,
            self.version,
            &resource.to_string(),
            producer,
        )
    }
}

/// A task of `task_type`, for the ring a task needs.
fn task_of(task_type: TaskType) -> permguard_host::membership::record::Task {
    permguard_host::membership::record::Task {
        task_id: "stream".to_owned(),
        task_type,
        selector: permguard_core::authz::Selector::exactly(Resource::host()),
        resource_types: Vec::new(),
        required: false,
        limits: permguard_host::membership::record::Limits {
            max_body_bytes: 1,
            max_concurrency: 1,
            max_rate_per_minute: 1,
            max_batch_records: 1,
            retention_seconds: 1,
        },
        assurance_requirements: Vec::new(),
        version: 1,
    }
}

/// How a Plane's records are encoded and checked: the typed validator a handle carries.
pub trait RecordCodec: Send + Sync + 'static {
    type Record;
    /// The record's canonical bytes.
    fn encode(&self, record: &Self::Record) -> Result<Vec<u8>, String>;
    /// The record `bytes` hold, refusing what is not one.
    fn decode(&self, bytes: &[u8]) -> Result<Self::Record, String>;
}

/// The engine of one Host.
pub struct Streams {
    root: Dir,
    host_id: [u8; 16],
    boot_id: [u8; 16],
    claim: u64,
    operations: Arc<Ring>,
    time: Arc<TimeGuard>,
    registered: Mutex<BTreeSet<(String, String, u32, &'static str)>>,
    /// The size past which a stream's journal segment rolls: where a prefix deletion can end.
    segment_bytes: u64,
}

impl fmt::Debug for Streams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Streams")
            .field("root", &self.root.path())
            .finish_non_exhaustive()
    }
}

impl Streams {
    /// The engine of the Host whose `volume` and `identity` it runs on, signing runs under
    /// `operations`, its `host.operations` ring.
    pub fn open(
        volume: &Volume,
        identity: &Identity,
        operations: Arc<Ring>,
        time: Arc<TimeGuard>,
    ) -> Result<Self, StreamError> {
        if operations.id() != HOST_OPERATIONS {
            return Err(StreamError::Sign(format!(
                "runs are signed under `{HOST_OPERATIONS}`, not `{}`",
                operations.id()
            )));
        }
        Ok(Self {
            root: volume.host().subdir(STREAMS, true)?,
            host_id: identity.host_id(),
            boot_id: identity.boot_id(),
            claim: volume.generation(),
            operations,
            time,
            registered: Mutex::new(BTreeSet::new()),
            segment_bytes: permguard_host::storage::journal::DEFAULT_SEGMENT_BYTES,
        })
    }

    /// The engine rolling its streams' journal segments past `bytes`, the granularity a prefix
    /// deletion frees space at (WP-5.6b): smaller for a constrained volume, and for tests.
    pub fn with_segment_bytes(mut self, bytes: u64) -> Self {
        self.segment_bytes = bytes;
        self
    }

    /// The directory of `descriptor` and `role`, after checking the descriptor and pinning its
    /// protected fields: a version whose fields changed is refused.
    fn register(&self, descriptor: &Descriptor, role: &'static str) -> Result<Dir, StreamError> {
        descriptor.check()?;
        let mut registered = self
            .registered
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let identity = (
            descriptor.plane.clone(),
            descriptor.stream_type.clone(),
            descriptor.version,
            role,
        );
        if registered.contains(&identity) {
            return Err(StreamError::Duplicate(format!(
                "the {role} of `{}/{}` version {}",
                descriptor.plane, descriptor.stream_type, descriptor.version
            )));
        }
        let version = self
            .root
            .subdir(&descriptor.plane, true)?
            .subdir(&descriptor.stream_type, true)?
            .subdir(&descriptor.version.to_string(), true)?;
        let digest = descriptor.protected_digest();
        match read_view(&version, DESCRIPTOR, format::VIEW)? {
            Some(held) if held != digest => {
                return Err(StreamError::Descriptor(format!(
                    "`{}/{}` version {} was registered with other protected fields: a change \
                     is a new version",
                    descriptor.plane, descriptor.stream_type, descriptor.version
                )));
            }
            Some(_) => {}
            None => replace_view(&version, DESCRIPTOR, format::VIEW, &digest)?,
        }
        let dir = version.subdir(role, true)?;
        registered.insert(identity);
        Ok(dir)
    }

    /// The typed producer handle of `descriptor`.
    pub fn register_producer<C: RecordCodec>(
        &self,
        descriptor: Descriptor,
        codec: C,
    ) -> Result<Producer<C>, StreamError> {
        let dir = self.register(&descriptor, "producer")?;
        Ok(Producer::new(
            producer::Context {
                dir,
                host_id: self.host_id,
                boot_id: self.boot_id,
                claim: self.claim,
                operations: Arc::clone(&self.operations),
                time: Arc::clone(&self.time),
                segment_bytes: self.segment_bytes,
            },
            descriptor,
            codec,
        ))
    }

    /// The typed consumer handle of `descriptor`.
    pub fn register_consumer<C: RecordCodec>(
        &self,
        descriptor: Descriptor,
        codec: C,
    ) -> Result<Consumer<C>, StreamError> {
        let dir = self.register(&descriptor, "consumer")?;
        Ok(
            Consumer::new(dir, self.claim, descriptor, codec, Arc::clone(&self.time))
                .with_segment_bytes(self.segment_bytes),
        )
    }
}

/// The producers the engine serves, by the name a Plane declares its stream under: what the
/// server hands the composition as its [`permguard_host::composition::StreamEngine`], and the
/// membership side as its [`permguard_host::composition::StreamCutovers`] (WP-5.2).
#[derive(Default)]
pub struct Served {
    producers:
        std::collections::BTreeMap<String, Arc<dyn permguard_host::composition::StreamAppender>>,
    cutovers: Vec<Arc<dyn permguard_host::composition::StreamCutovers>>,
    shipping: Vec<Arc<dyn permguard_host::composition::StreamShipping>>,
    prunables: Vec<Arc<dyn retention::Prunable>>,
    inspected: Vec<Arc<dyn reads::Inspect>>,
    consumers: std::collections::BTreeMap<
        String,
        Arc<dyn permguard_host::composition::StreamConsumerReads>,
    >,
}

impl fmt::Debug for Served {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.producers.keys()).finish()
    }
}

impl Served {
    /// The Host API's reads of these producers (WP-5.7a), with what else the server serves.
    pub fn reads(&self) -> reads::Reads {
        self.inspected
            .iter()
            .fold(reads::Reads::default(), |reads, handle| {
                reads.with(Arc::clone(handle))
            })
    }

    /// The producers the garbage collection runs (WP-5.6b).
    pub fn prunables(&self) -> Vec<Arc<dyn retention::Prunable>> {
        self.prunables.clone()
    }

    /// These and `producer`, served as `name` (`<plane>/<type>`).
    pub fn with<P>(mut self, name: &str, producer: Arc<P>) -> Self
    where
        P: permguard_host::composition::StreamAppender
            + permguard_host::composition::StreamCutovers
            + permguard_host::composition::StreamShipping
            + retention::Prunable
            + reads::Inspect
            + 'static,
    {
        self.producers.insert(
            name.to_owned(),
            Arc::clone(&producer) as Arc<dyn permguard_host::composition::StreamAppender>,
        );
        self.cutovers
            .push(Arc::clone(&producer) as Arc<dyn permguard_host::composition::StreamCutovers>);
        self.prunables
            .push(Arc::clone(&producer) as Arc<dyn retention::Prunable>);
        self.inspected
            .push(Arc::clone(&producer) as Arc<dyn reads::Inspect>);
        self.shipping.push(producer);
        self
    }

    /// These and `consumer`, read as `name` by the Planes that declare they read it (WP-6.1).
    pub fn with_consumer<P>(mut self, name: &str, consumer: Arc<P>) -> Self
    where
        P: permguard_host::composition::StreamConsumerReads + 'static,
    {
        self.consumers.insert(
            name.to_owned(),
            consumer as Arc<dyn permguard_host::composition::StreamConsumerReads>,
        );
        self
    }

    /// The names served, in order.
    pub fn names(&self) -> Vec<&str> {
        self.producers.keys().map(String::as_str).collect()
    }
}

impl permguard_host::composition::StreamEngine for Served {
    fn producer(
        &self,
        stream: &str,
    ) -> Option<Arc<dyn permguard_host::composition::StreamAppender>> {
        self.producers.get(stream).map(Arc::clone)
    }

    fn consumer(
        &self,
        stream: &str,
    ) -> Option<Arc<dyn permguard_host::composition::StreamConsumerReads>> {
        self.consumers.get(stream).map(Arc::clone)
    }
}

impl permguard_host::composition::StreamCutovers for Served {
    fn due(
        &self,
        membership_id: &[u8; 16],
        ring: &str,
        kid: &str,
    ) -> Result<Vec<(String, u64)>, String> {
        let mut due = Vec::new();
        for producer in &self.cutovers {
            due.extend(producer.due(membership_id, ring, kid)?);
        }
        Ok(due)
    }

    fn journaled(&self, ring: &str, kid: &str, streams: &[(String, u64)]) -> Result<(), String> {
        for producer in &self.cutovers {
            producer.journaled(ring, kid, streams)?;
        }
        Ok(())
    }
}

impl permguard_host::composition::StreamShipping for Served {
    fn due(
        &self,
        subscription: &permguard_host::composition::Subscribed<'_>,
    ) -> Result<Vec<String>, String> {
        let mut due = Vec::new();
        for producer in &self.shipping {
            due.extend(producer.due(subscription)?);
        }
        Ok(due)
    }

    fn next(
        &self,
        subscription: &permguard_host::composition::Subscribed<'_>,
        resource: &str,
        max_bytes: u64,
    ) -> Result<Option<permguard_host::composition::Shipment>, String> {
        for producer in &self.shipping {
            if let Some(shipment) = producer.next(subscription, resource, max_bytes)? {
                return Ok(Some(shipment));
            }
        }
        Ok(None)
    }

    fn answered(
        &self,
        subscription: &permguard_host::composition::Subscribed<'_>,
        resource: &str,
        shipment: &permguard_host::composition::Shipment,
        answer: &[u8],
    ) -> Result<bool, String> {
        let mut go_on = false;
        for producer in &self.shipping {
            go_on |= producer.answered(subscription, resource, shipment, answer)?;
        }
        Ok(go_on)
    }

    fn deferred(
        &self,
        subscription: &permguard_host::composition::Subscribed<'_>,
        resource: &str,
    ) -> Result<(), String> {
        for producer in &self.shipping {
            producer.deferred(subscription, resource)?;
        }
        Ok(())
    }

    fn retain(&self, membership_id: &[u8; 16], task_ids: &[String]) -> Result<(), String> {
        for producer in &self.shipping {
            producer.retain(membership_id, task_ids)?;
        }
        Ok(())
    }

    fn behind(&self) -> Result<Vec<permguard_host::composition::Unshipped>, String> {
        let mut found = Vec::new();
        for producer in &self.shipping {
            found.extend(producer.behind()?);
        }
        Ok(found)
    }

    fn mark_unshipped(&self) -> Result<Vec<permguard_host::composition::Unshipped>, String> {
        let mut marked = Vec::new();
        for producer in &self.shipping {
            marked.extend(producer.mark_unshipped()?);
        }
        Ok(marked)
    }

    fn unshipped_on(
        &self,
        subscription: &permguard_host::composition::Subscribed<'_>,
        resource: &str,
    ) -> Result<Option<permguard_host::composition::Unshipped>, String> {
        for producer in &self.shipping {
            if let Some(mark) = producer.unshipped_on(subscription, resource)? {
                return Ok(Some(mark));
            }
        }
        Ok(None)
    }

    fn settle_unshipped(&self) -> Result<Vec<permguard_host::composition::Unshipped>, String> {
        let mut remaining = Vec::new();
        for producer in &self.shipping {
            remaining.extend(producer.settle_unshipped()?);
        }
        Ok(remaining)
    }
}

/// A lowercase name of letters, digits and inner hyphens.
fn name(text: &str, what: &str) -> Result<(), StreamError> {
    let shaped = !text.is_empty()
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && !text.starts_with('-')
        && !text.ends_with('-');
    if !shaped {
        return Err(StreamError::Invalid(format!(
            "`{text}` cannot name a {what}: lowercase letters, digits and inner hyphens"
        )));
    }
    Ok(())
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The digest of one record under its descriptor's domain.
pub fn record_digest(domain: &str, record: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(record);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests;
