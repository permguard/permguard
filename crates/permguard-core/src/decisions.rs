// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a data plane's decision path is allowed to spend, and what it records
//! about what it decided — the `dataPlane.decisions` block of the file.
//!
//! # Why the two live in one block
//!
//! They are one subject. A decision is answered out of memory, and a decision
//! is written down: the bounds on the first and the destination of the second
//! belong beside each other, so an operator reading the block sees the whole
//! decision path rather than half of it here and half three sections away.
//!
//! # The bounds
//!
//! A compiled partition — every policy parsed, the engine's program built, the
//! schema checked — is what answers a request. Building one costs
//! milliseconds; keeping it costs memory. Two bounds decide how far: how many
//! partitions, and how many bytes. Whichever is reached first, the least
//! recently used is dropped and rebuilt next time somebody asks.
//!
//! # The log
//!
//! The destination is described exactly like a mirror source — an exact URL
//! and its own trust material — because it is the same kind of relationship: a
//! server this plane must authenticate before it speaks to it. Its client
//! certificate is deliberately its own: *may ship decision logs* and *may read
//! policy* are two different authorizations, and a deployment should be able
//! to grant one without the other.
//!
//! Every scalar rides the ordinary layered pipeline, so an environment
//! variable still beats the file. The allow-lists do not, for the same reason
//! the mirror server list does not: an array has no sensible single-variable
//! form, and a half-parsed one is worse than none.
//!
//! # Where it lives
//!
//! Inside `dataPlane`, beside `mirrors`: answering decisions is the data
//! plane's own business, and a control plane has no decision path to bound.

use serde::Deserialize;

use crate::config::{
    SETTING_AUTHZ_CACHE_BYTES, SETTING_AUTHZ_CACHE_PARTITIONS, SETTING_AUTHZ_MAX_EVALUATIONS,
    SETTING_LOG_BATCH_BYTES, SETTING_LOG_BATCH_INTERVAL, SETTING_LOG_COMMITMENT_KEY_REF,
    SETTING_LOG_COMMITMENT_KEY_VERSION, SETTING_LOG_ENABLED, SETTING_LOG_ON_FULL,
    SETTING_LOG_PDP_ID, SETTING_LOG_SAMPLE_PERMITS, SETTING_LOG_SPOOL_AGE, SETTING_LOG_SPOOL_BYTES,
    SETTING_LOG_SPOOL_DIRECTORY, SETTING_MAX_BLOCKING,
};
use crate::config::{
    SETTING_DECISION_STORE_DIRECTORY, SETTING_DECISION_STORE_ENABLED,
    SETTING_DECISION_STORE_RETENTION,
};
use crate::config::{
    SETTING_EVENT_STORE_DIRECTORY, SETTING_EVENT_STORE_ENABLED, SETTING_EVENT_STORE_RETENTION,
};
use crate::config::{
    SETTING_EVENTS_ALLOWED_LATENESS, SETTING_EVENTS_CLOCK_SKEW, SETTING_EVENTS_DIRECTORY,
    SETTING_EVENTS_ENABLED, SETTING_EVENTS_MAX_BYTES, SETTING_EVENTS_MAX_RECORD_BYTES,
    SETTING_EVENTS_PRODUCER_ID, SETTING_EVENTS_RETENTION_MINIMUM, SETTING_EVENTS_SEGMENT_BYTES,
};
use crate::config::{
    SETTING_EVENTS_GROUP_COMMIT_DELAY, SETTING_EVENTS_PULL_INTERVAL,
    SETTING_EVENTS_PULL_MAX_STALENESS, SETTING_EVENTS_PULL_MODE,
};
use crate::mirrors::MirrorTls;

/// The decision path's block, as the file declares it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionsSection {
    /// What is kept in memory between requests.
    #[serde(default)]
    cache: CacheSection,
    /// The most evaluations one boxcarred request may carry.
    #[serde(default)]
    max_evaluations: Option<String>,
    /// How many pieces of blocking work this plane may have in flight at once.
    ///
    /// Beside `max_evaluations` because they bound the same request from two directions: that one
    /// caps how much work a single request may ask for, this one caps how much of it the whole
    /// plane may be doing. Reached, requests are refused rather than queued.
    #[serde(default)]
    max_blocking: Option<String>,
    /// Where the record of each decision goes.
    #[serde(default)]
    log: LogSection,
}

/// The in-memory bound: entries, and bytes.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CacheSection {
    /// How many compiled partitions to keep — one ledger contributes one per
    /// partition it declares.
    #[serde(default)]
    partitions: Option<String>,
    /// How many bytes those partitions may occupy. Accepts `k`/`M`/`G`.
    #[serde(default)]
    bytes: Option<String>,
}

/// The decision log, as the file declares it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogSection {
    /// Whether decisions are recorded at all.
    #[serde(default)]
    enabled: Option<String>,
    /// This plane's name in the log. Required when the log is on: falling back
    /// to a hostname is convenient and wrong the first time two replicas share
    /// a host.
    #[serde(default)]
    pdp_id: Option<String>,
    /// Where records are shipped.
    #[serde(default)]
    server: Option<LogServerSection>,
    /// Durability before the network.
    #[serde(default)]
    spool: SpoolSection,
    /// Latency against efficiency: whichever comes first.
    #[serde(default)]
    batch: BatchSection,
    /// What to do when the spool is full — the one decision only a deployment
    /// can make.
    #[serde(default)]
    on_full: Option<String>,
    /// What is written. Denies and errors are never sampled, whatever this says.
    #[serde(default)]
    sample: SampleSection,
    /// Caller-supplied attributes to record, named one by one.
    #[serde(default)]
    include: IncludeSection,
    /// The key input commitments are taken under.
    #[serde(default)]
    commitment: CommitmentSection,
}

/// The secret input commitments are computed with.
///
/// Its own key, and a *secret* one: a commitment under a value anybody can read
/// — a hostname, an identifier that travels in every record — is a bare digest
/// wearing a hat, and a bare digest of `department=HR` has a few thousand
/// plausible preimages. Named here rather than derived so that rotating it is
/// an operation somebody performs deliberately.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentSection {
    /// Which secret, in the store this deployment composes.
    #[serde(default)]
    key_ref: Option<String>,
    /// Which version of it, recorded in every marker.
    #[serde(default)]
    key_version: Option<String>,
}

/// The server records are shipped to.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogServerSection {
    /// The exact base URL — an identity, never a pattern.
    url: String,
    /// How that server is trusted, and who this plane says it is.
    #[serde(default)]
    tls: MirrorTls,
}

/// The local durable record, bounded both ways: a spool that grows without
/// limit turns a control-plane outage into a full disk.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpoolSection {
    /// Where under the volume it lives.
    #[serde(default)]
    directory: Option<String>,
    /// The bound on decision records. The terminal record is reserved apart.
    #[serde(default)]
    bytes: Option<String>,
    /// How old the oldest unshipped record may be.
    #[serde(default)]
    age: Option<String>,
}

/// When a batch leaves.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchSection {
    /// How large a batch may grow before it is sent.
    #[serde(default)]
    bytes: Option<String>,
    /// How long it may wait before it is sent anyway.
    #[serde(default)]
    interval: Option<String>,
}

/// What the stream claims to be complete about.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SampleSection {
    /// The rate at which permits are recorded.
    #[serde(default)]
    permits: Option<String>,
}

/// The allow-lists. Never a deny-list: a field added to a request tomorrow
/// must not start being recorded by itself.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncludeSection {
    /// Subject properties to record by name.
    #[serde(default)]
    pub subject_properties: Vec<String>,
    /// Resource properties to record by name.
    #[serde(default)]
    pub resource_properties: Vec<String>,
    /// Context members to record by name.
    #[serde(default)]
    pub context: Vec<String>,
}

/// Where decisions are **kept**, as the `controlPlane.decisions` block of the
/// file declares it.
///
/// The same word under the other plane means where decisions are *made and
/// recorded*; here it means where they are received and held. One subject,
/// two ends of it, and an operator reading either block is reading about the
/// decision log.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionStoreSection {
    /// Whether this plane receives decision records at all.
    #[serde(default)]
    enabled: Option<String>,
    /// Where they are kept, under the working directory.
    #[serde(default)]
    directory: Option<String>,
    /// How long they are kept before segments leave.
    #[serde(default)]
    retention: Option<String>,
    /// The published key sets of the producers this plane accepts records from.
    ///
    /// A batch is signed by the **data plane** that decided, not by this one,
    /// so this plane cannot verify one against its own ring. It needs each
    /// producer's published set, and it does not dial back to fetch it: a
    /// control plane that reached out to every PDP would make ingestion depend
    /// on the reachability of the very planes that are shipping to it.
    ///
    /// A list, so it comes from the file only. Empty means this plane accepts
    /// records from producers that share its process — the all-in-one — and
    /// from nobody else.
    #[serde(default)]
    producer_keys: Vec<String>,
}

impl DecisionStoreSection {
    /// The block, as pairs for the configuration-file layer.
    pub fn settings(&self) -> Vec<(String, String)> {
        [
            (SETTING_DECISION_STORE_ENABLED, self.enabled.as_ref()),
            (SETTING_DECISION_STORE_DIRECTORY, self.directory.as_ref()),
            (SETTING_DECISION_STORE_RETENTION, self.retention.as_ref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone())))
        .collect()
    }

    /// The producers' key sets, as declared: paths to JWKS documents.
    pub fn producer_keys(&self) -> &[String] {
        &self.producer_keys
    }
}

/// Where a plane ships its decision records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogDestination {
    /// The exact base URL.
    pub url: String,
    /// The trust material for reaching it.
    pub tls: MirrorTls,
}

/// Where a plane ships and reads event records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventDestination {
    /// The exact base URL.
    pub url: String,
    /// The transport selected by the deployment: `http` or `grpc`.
    pub transport: String,
    /// The trust material for reaching it.
    pub tls: MirrorTls,
}

impl DecisionsSection {
    /// The block's scalars, as pairs for the configuration-file layer.
    pub fn settings(&self) -> Vec<(String, String)> {
        [
            (
                SETTING_AUTHZ_CACHE_PARTITIONS,
                self.cache.partitions.as_ref(),
            ),
            (SETTING_AUTHZ_CACHE_BYTES, self.cache.bytes.as_ref()),
            (SETTING_AUTHZ_MAX_EVALUATIONS, self.max_evaluations.as_ref()),
            (SETTING_MAX_BLOCKING, self.max_blocking.as_ref()),
            (SETTING_LOG_ENABLED, self.log.enabled.as_ref()),
            (SETTING_LOG_PDP_ID, self.log.pdp_id.as_ref()),
            (
                SETTING_LOG_SPOOL_DIRECTORY,
                self.log.spool.directory.as_ref(),
            ),
            (SETTING_LOG_SPOOL_BYTES, self.log.spool.bytes.as_ref()),
            (SETTING_LOG_SPOOL_AGE, self.log.spool.age.as_ref()),
            (SETTING_LOG_BATCH_BYTES, self.log.batch.bytes.as_ref()),
            (SETTING_LOG_BATCH_INTERVAL, self.log.batch.interval.as_ref()),
            (SETTING_LOG_ON_FULL, self.log.on_full.as_ref()),
            (SETTING_LOG_SAMPLE_PERMITS, self.log.sample.permits.as_ref()),
            (
                SETTING_LOG_COMMITMENT_KEY_REF,
                self.log.commitment.key_ref.as_ref(),
            ),
            (
                SETTING_LOG_COMMITMENT_KEY_VERSION,
                self.log.commitment.key_version.as_ref(),
            ),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone())))
        .collect()
    }

    /// Where records are shipped, when the file names a server.
    ///
    /// Absent is not an error here: a plane that mirrors exactly one server
    /// ships there, and the plane resolves that — this crate carries what was
    /// declared, not what was inferred.
    pub fn destination(&self) -> Option<LogDestination> {
        self.log.server.as_ref().map(|server| LogDestination {
            url: server.url.clone(),
            tls: server.tls.clone(),
        })
    }

    /// The caller-supplied attributes this plane may record.
    pub fn include(&self) -> &IncludeSection {
        &self.log.include
    }
}

/// The control plane's event store, as the file declares it.
///
/// The receiving end of what a data plane's `events` block produces, and named the same way for
/// that reason: one subject seen from its two ends. What it does *not* share is the producer's
/// rule about forgetting — a data plane keeps what its policies still read, and this keeps what a
/// deployment still wants to be able to read, export and verify.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventStoreSection {
    /// Whether this plane receives event records at all.
    #[serde(default)]
    enabled: Option<String>,
    /// Where they are kept, under the working directory.
    #[serde(default)]
    directory: Option<String>,
    /// How long they are kept before sealed segments leave.
    #[serde(default)]
    retention: Option<String>,
    /// The published key sets of the producers this plane accepts records from.
    ///
    /// A batch is signed by the **data plane** that recorded, not by this one, so this plane
    /// cannot verify one against its own ring. It needs each producer's published set, and it does
    /// not dial back to fetch it: a control plane that reached out to every plane shipping to it
    /// would make ingestion depend on the reachability of the very planes it is receiving from.
    #[serde(default)]
    producer_keys: Vec<EventProducerSource>,
}

/// One event producer identity and the tenant scope its published keys may attest.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventProducerSource {
    pub path: String,
    pub producer: String,
    pub zone: String,
    pub ledger: String,
}

impl EventStoreSection {
    /// The block, as pairs for the configuration-file layer.
    pub fn settings(&self) -> Vec<(String, String)> {
        [
            (SETTING_EVENT_STORE_ENABLED, self.enabled.as_ref()),
            (SETTING_EVENT_STORE_DIRECTORY, self.directory.as_ref()),
            (SETTING_EVENT_STORE_RETENTION, self.retention.as_ref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone())))
        .collect()
    }

    /// The producers' published key sets, by path.
    pub fn producer_keys(&self) -> &[EventProducerSource] {
        &self.producer_keys
    }
}

/// The temporal event journal, as the file declares it.
///
/// Its own block rather than a corner of `decisions`, because it is a different subsystem with a
/// different rule about forgetting. A decision record may be dropped once it is shipped; an event
/// record is also an *input* — the history a temporal policy reads — so what may be deleted is
/// decided by what the loaded policies still look at. There is deliberately no `on_full` member:
/// dropping an event silently changes what future authorizations mean, so a journal that cannot
/// accept fails the submission closed and there is nothing for a deployment to choose.
///
/// Structured rather than flat, so a Dogwood option added later is a member of the block it
/// belongs to rather than an unrelated top-level flag.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSection {
    /// Whether this plane serves the temporal interface at all.
    #[serde(default)]
    enabled: Option<String>,
    /// This plane's name as an event producer. Required when the interface is on: a producer id
    /// names a hash chain, and two planes sharing one would each append to a stream the other
    /// also claims.
    #[serde(default)]
    producer_id: Option<String>,
    /// Where the journals live, under the working directory.
    #[serde(default)]
    directory: Option<String>,
    /// What bounds one ledger's journal.
    #[serde(default)]
    stream: EventsStreamSection,
    /// How long history is kept, and what this plane will believe about a caller's clock.
    #[serde(default)]
    retention: EventsRetentionSection,
    /// Where records are shipped. Absent, the decision log's destination is used — one deployment
    /// ships both to one control plane, and naming it twice is two settings to keep in step.
    #[serde(default)]
    destination: Option<EventsDestinationSection>,
    /// Whether this plane also *reads* history other planes recorded.
    #[serde(default)]
    pull: EventsPullSection,
}

/// What bounds one ledger's journal.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsStreamSection {
    /// The bound on one ledger's records. The reserve is kept outside it.
    #[serde(default)]
    max_bytes: Option<String>,
    /// When a segment is closed and a new one started.
    #[serde(default)]
    segment_bytes: Option<String>,
    /// The largest single record a journal accepts.
    #[serde(default)]
    max_record_bytes: Option<String>,
    /// How long a group commit may wait to amortise an `fsync` across a batch.
    ///
    /// A latency budget, never a durability one: a receipt is still withheld until the record is
    /// on disk. What this buys is that ten submissions arriving together cost one flush.
    #[serde(default)]
    group_commit_max_delay: Option<String>,
}

/// How long history is kept, and what this plane will believe about a caller's clock.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsRetentionSection {
    /// The shortest history this deployment promises, before the policies' own requirement is
    /// applied on top of it.
    #[serde(default)]
    minimum: Option<String>,
    /// How late an occurrence may arrive and still be recorded.
    #[serde(default)]
    allowed_lateness: Option<String>,
    /// How far a caller's clock may run ahead of this one.
    #[serde(default)]
    clock_skew: Option<String>,
}

/// Where event records are shipped.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsDestinationSection {
    /// The exact base URL — an identity, never a pattern.
    url: String,
    /// `http` or `grpc`. Absent, the URL's own scheme decides.
    #[serde(default)]
    transport: Option<String>,
    /// How that server is trusted, and who this plane says it is.
    #[serde(default)]
    tls: MirrorTls,
}

/// Whether this plane reads history other planes recorded.
///
/// Off by default — `local` — and deliberately: a plane that silently began deciding against
/// another plane's events would change what its policies mean without anybody choosing that.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsPullSection {
    /// `local`, `shared-eventual` or `shared-bounded`.
    #[serde(default)]
    mode: Option<String>,
    /// How often the worker asks for more.
    #[serde(default)]
    interval: Option<String>,
    /// How stale the imported history may be before `shared-bounded` fails decisions closed.
    #[serde(default)]
    max_staleness: Option<String>,
    /// Which ledgers to subscribe to, and to which registered event types.
    #[serde(default)]
    ledgers: Vec<EventsPullLedgerSection>,
    /// Producer keys and the scopes they are allowed to attest. Required for shared modes.
    #[serde(default)]
    producer_keys: Vec<EventProducerSource>,
}

/// One subscription: a ledger, and the registered types this plane will import from it.
#[derive(Debug, Default, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsPullLedgerSection {
    pub zone: String,
    pub ledger: String,
    /// The registered event types. Part of the canonical filter set the cursor is bound to, so
    /// widening it starts a new read rather than quietly widening this one.
    #[serde(default)]
    pub event_types: Vec<String>,
}

impl EventsSection {
    /// The block's scalars, as pairs for the configuration-file layer.
    pub fn settings(&self) -> Vec<(String, String)> {
        [
            (SETTING_EVENTS_ENABLED, self.enabled.as_ref()),
            (SETTING_EVENTS_PRODUCER_ID, self.producer_id.as_ref()),
            (SETTING_EVENTS_DIRECTORY, self.directory.as_ref()),
            (SETTING_EVENTS_MAX_BYTES, self.stream.max_bytes.as_ref()),
            (
                SETTING_EVENTS_SEGMENT_BYTES,
                self.stream.segment_bytes.as_ref(),
            ),
            (
                SETTING_EVENTS_MAX_RECORD_BYTES,
                self.stream.max_record_bytes.as_ref(),
            ),
            (
                SETTING_EVENTS_GROUP_COMMIT_DELAY,
                self.stream.group_commit_max_delay.as_ref(),
            ),
            (
                SETTING_EVENTS_RETENTION_MINIMUM,
                self.retention.minimum.as_ref(),
            ),
            (
                SETTING_EVENTS_ALLOWED_LATENESS,
                self.retention.allowed_lateness.as_ref(),
            ),
            (
                SETTING_EVENTS_CLOCK_SKEW,
                self.retention.clock_skew.as_ref(),
            ),
            (SETTING_EVENTS_PULL_MODE, self.pull.mode.as_ref()),
            (SETTING_EVENTS_PULL_INTERVAL, self.pull.interval.as_ref()),
            (
                SETTING_EVENTS_PULL_MAX_STALENESS,
                self.pull.max_staleness.as_ref(),
            ),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|value| (key.to_owned(), value.clone())))
        .collect()
    }

    /// Where records are shipped, when the file names a server.
    ///
    /// Absent is not an error: a deployment that ships decisions and events to one control plane
    /// names it once, under the decision log, and this follows it.
    pub fn destination(&self) -> Option<EventDestination> {
        self.destination.as_ref().map(|held| EventDestination {
            url: held.url.clone(),
            transport: held.transport.clone().unwrap_or_else(|| {
                match held.url.split_once("://").map(|(scheme, _)| scheme) {
                    Some("grpc" | "grpcs") => "grpc",
                    _ => "http",
                }
                .to_owned()
            }),
            tls: held.tls.clone(),
        })
    }

    /// The ledgers this plane subscribes to.
    pub fn pull_ledgers(&self) -> &[EventsPullLedgerSection] {
        &self.pull.ledgers
    }

    pub fn pull_producer_keys(&self) -> &[EventProducerSource] {
        &self.pull.producer_keys
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn the_block_becomes_the_settings_the_plane_reads() {
        let section: DecisionsSection = serde_norway::from_str(
            "cache:\n  partitions: \"32\"\n  bytes: 128M\nmax_evaluations: \"64\"\n",
        )
        .expect("the section parses");

        assert_eq!(
            section.settings(),
            vec![
                (SETTING_AUTHZ_CACHE_PARTITIONS.to_owned(), "32".to_owned()),
                (SETTING_AUTHZ_CACHE_BYTES.to_owned(), "128M".to_owned()),
                (SETTING_AUTHZ_MAX_EVALUATIONS.to_owned(), "64".to_owned()),
            ]
        );
    }

    #[test]
    fn an_absent_block_leaves_every_default_alone() {
        let section: DecisionsSection =
            serde_norway::from_str("{}").expect("an empty block is a block");

        assert!(section.settings().is_empty());
        assert_eq!(section.destination(), None);
    }

    #[test]
    fn the_log_carries_its_own_client_identity_not_the_mirrors() {
        let section: DecisionsSection = serde_norway::from_str(
            "log:\n  enabled: \"true\"\n  pdp_id: plane-a\n  server:\n    url: \"grpcs://control:6443\"\n    tls:\n      ca_file: tls/ca.pem\n      cert: tls/decision-log-client.pem\n      key: tls/decision-log-client.key\n",
        )
        .expect("the section parses");

        let destination = section.destination().expect("a server is named");
        assert_eq!(destination.url, "grpcs://control:6443");
        assert_eq!(
            destination.tls.cert.as_deref(),
            Some("tls/decision-log-client.pem"),
            "shipping decisions and reading policy are two authorizations"
        );
        assert!(
            section
                .settings()
                .contains(&(SETTING_LOG_PDP_ID.to_owned(), "plane-a".to_owned()))
        );
    }

    #[test]
    fn what_is_recorded_of_a_caller_is_named_one_field_at_a_time() {
        let section: DecisionsSection = serde_norway::from_str(
            "log:\n  include:\n    subject_properties: [department]\n    context: [ip]\n",
        )
        .expect("the section parses");

        assert_eq!(section.include().subject_properties, vec!["department"]);
        assert_eq!(section.include().context, vec!["ip"]);
        assert!(
            section.include().resource_properties.is_empty(),
            "an allow-list, never a deny-list"
        );
    }

    #[test]
    fn a_member_nobody_declared_is_refused_rather_than_ignored() {
        // `deny_unknown_fields` is what turns a typo into a startup failure
        // instead of a setting that silently never applied.
        assert!(
            serde_norway::from_str::<DecisionsSection>("log:\n  sample:\n    permit: \"0.5\"\n")
                .is_err()
        );
    }
}
