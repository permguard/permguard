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
    SETTING_LOG_SPOOL_DIRECTORY,
};
use crate::config::{
    SETTING_DECISION_STORE_DIRECTORY, SETTING_DECISION_STORE_ENABLED,
    SETTING_DECISION_STORE_RETENTION,
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
            "log:\n  enabled: \"true\"\n  pdp_id: plane-a\n  server:\n    url: \"grpcs://control:7557\"\n    tls:\n      ca_file: tls/ca.pem\n      cert: tls/decision-log-client.pem\n      key: tls/decision-log-client.key\n",
        )
        .expect("the section parses");

        let destination = section.destination().expect("a server is named");
        assert_eq!(destination.url, "grpcs://control:7557");
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
