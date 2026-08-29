// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event record: what one occurrence becomes once a data plane has accepted it.
//!
//! # Three classifications, never inferred from one another
//!
//! A record carries three names that are easy to confuse and must not be:
//!
//! | | |
//! | --- | --- |
//! | **record type** | the storage/wire envelope — `permguard.event.record.v1` |
//! | **event type** | the typed occurrence the record carries — `permguard.dogwood.event.v1` today |
//! | **event kind** | runtime data *inside* that occurrence — Dogwood's `request`, `response`, `error` |
//!
//! The kind is a free-form domain word chosen by a schema author; the other two are registry
//! entries with an owner, a version and a validator. Reading a kind as a wire type — or deciding
//! which validator to run by looking at one — would let a caller pick its own parser.
//!
//! # Verbatim, on the receiving side
//!
//! Records are digested as [`serde_json::Value`], not as this struct. A control plane that
//! reparsed a record into a struct it understands and re-serialised it would silently drop any
//! field a newer producer added, and the digest would stop matching. So the wire type is the
//! value, this struct is how a producer *builds* one, and the two meet at [`Record::to_value`].

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use permguard_decisions::jcs::{self, CanonicalError};

/// The domain this crate's record digests live in.
///
/// Distinct from the decision log's on purpose: a verifier must not be able to accept one where
/// the other belongs.
pub const DIGEST_DOMAIN: &str = "permguard.event.record.v1\n";

/// The domain an occurrence digest lives in.
///
/// A *second* domain, and not the record's. The occurrence digest covers what the caller sent,
/// before this plane added its sequence and clocks; digesting both under one domain would make a
/// record and the occurrence inside it confusable.
pub const OCCURRENCE_DOMAIN: &str = "permguard.event.occurrence.v1\n";

/// The registered name of this storage/wire envelope.
pub const RECORD_TYPE: &str = "permguard.event.record.v1";

/// The only producer class accepted in the first release.
///
/// Registered as a class rather than assumed, so a future authenticated ingress — a PIP, another
/// control-plane surface — can be admitted as a *different* class without changing offsets,
/// records, signed batches or storage layout. It is not accepted today.
pub const PRODUCER_CLASS_DATA_PLANE: &str = "permguard.event.producer.data-plane.v1";

/// The `prev` of the first record of any stream: sixty-four zeroes.
pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The schema version every record carries.
pub const VERSION: u32 = 1;

/// Who produced a stream.
///
/// A class plus an identity plus one continuous incarnation. The class is what makes a future
/// producer expressible without a format migration; the instance is what makes a restart that
/// cannot prove continuation safe — it becomes a new stream rather than reusing sequence numbers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Producer {
    /// The registered producer class. Only [`PRODUCER_CLASS_DATA_PLANE`] is accepted now.
    pub class: String,
    /// The deployment's name for this producer, stable across restarts.
    pub id: String,
    /// One continuous incarnation: minted with the journal, and again whenever continuity breaks.
    pub instance: String,
}

impl Producer {
    /// A data-plane producer.
    pub fn data_plane(id: impl Into<String>, instance: impl Into<String>) -> Self {
        Self {
            class: PRODUCER_CLASS_DATA_PLANE.to_owned(),
            id: id.into(),
            instance: instance.into(),
        }
    }

    /// Whether this build accepts records from this class.
    ///
    /// Fail-closed by construction: a class nobody registered is refused before persistence rather
    /// than stored as "unknown producer" for somebody to interpret later.
    pub fn is_accepted(&self) -> bool {
        self.class == PRODUCER_CLASS_DATA_PLANE
    }
}

/// One cryptographic stream: a producer's history for one tenant ledger.
///
/// The tenant is part of the identity, not a field beside it. One producer writing two ledgers
/// writes two streams with independent sequences and independent chains, so a tenant reading its
/// own history never has to be told which records were not theirs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Stream {
    pub producer: Producer,
    pub zone: String,
    pub ledger: String,
}

impl Stream {
    /// Builds a stream identity.
    pub fn new(producer: Producer, zone: impl Into<String>, ledger: impl Into<String>) -> Self {
        Self {
            producer,
            zone: zone.into(),
            ledger: ledger.into(),
        }
    }

    /// Whether two stream identities name the same *chain*, ignoring which incarnation wrote it.
    ///
    /// # Why the instance is not part of this
    ///
    /// Four of the five fields are decided by configuration and outlive any process: the producer's
    /// class and id say which plane this is, and the zone and ledger say whose history it keeps. A
    /// journal whose directory holds one of those and is opened for another has been moved or
    /// restored under the wrong identity, and appending to it would splice two histories together.
    ///
    /// The instance is the opposite kind of thing. It is minted per process start, and it exists to
    /// say *which incarnation* wrote a run of records — so that a restart which cannot prove
    /// continuation starts a new one instead of reusing sequences. A restart which *can* prove it
    /// adopts the instance its own `STATE` recorded, which means the instance a restarted process
    /// proposes is always the wrong one to compare against, and comparing it would refuse every
    /// restart as somebody else's stream.
    pub fn same_chain_as(&self, other: &Self) -> bool {
        self.producer.class == other.producer.class
            && self.producer.id == other.producer.id
            && self.zone == other.zone
            && self.ledger == other.ledger
    }
}

/// One event, as the log keeps it.
///
/// Field order here is the order the canonical form takes, but nothing depends on that: the digest
/// is over JCS-canonicalized bytes, which sort keys themselves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The record schema version.
    pub v: u32,
    /// The storage/wire envelope this is. Always [`RECORD_TYPE`] today.
    pub record_type: String,
    /// Whose history, for which tenant.
    pub stream: Stream,
    /// This record's position in that stream. Monotonic, never reset inside an instance.
    pub seq: u64,
    /// The digest of the record at `seq - 1`, or [`GENESIS`].
    pub prev: String,
    /// The registered event type of the occurrence carried below.
    ///
    /// Independent of `kind` and of `record_type`. One producer stream may carry several
    /// registered types; each record is validated against its own type's contract, and the store
    /// builds a secondary index so reading one type does not scan the others.
    pub event_type: String,
    /// The caller's identifier for this occurrence, unique within the ledger.
    pub event_id: String,
    /// The digest of the occurrence exactly as the caller sent it, before this plane added
    /// anything. What makes the same client retry reaching two data planes recognisable as one
    /// logical occurrence rather than two.
    pub occurrence_digest: String,
    /// The runtime's own word for what happened — Dogwood's `request`, `response`, `error`. Domain
    /// data, never a wire type.
    pub kind: String,
    /// The profile the request selected.
    pub profile: String,
    /// The partitions the profile addressed, in the profile's order.
    pub policy_partitions: Vec<String>,
    /// The immutable ledger commit the partitions were loaded from.
    pub commit: String,
    /// The history key this occurrence belongs to, derived from the loaded event schema's pins.
    /// Absent for a partition with global history.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub history_key: Option<HistoryKey>,
    /// When the occurrence happened, as the request stated it. Untrusted unless the caller is an
    /// authorized clock source; validated against skew and lateness bounds before it gets here.
    pub occurred_at: String,
    /// When this plane accepted it. The server's own clock, always.
    pub observed_at: String,
    /// The typed occurrence itself, verbatim.
    pub event: Value,
}

/// The derived history key, kept explicitly beside its hash.
///
/// The hash alone would make a collision undetectable and an audit impossible: an investigator
/// looking at a record has to be able to see *which* values put it in that partition, not just
/// that two records agree. So the values travel in the signed record and the hash is only an index
/// key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HistoryKey {
    /// The schema-declared pin names, in the schema's order.
    pub pins: Vec<String>,
    /// Their canonical typed encodings, positionally matching `pins`.
    pub values: Vec<String>,
    /// The digest over that canonical typed encoding — the index key, never a substitute for the
    /// values above.
    pub digest: String,
}

impl Record {
    /// The record as the value it is shipped and digested as.
    pub fn to_value(&self) -> Result<Value, DigestError> {
        serde_json::to_value(self).map_err(|error| DigestError::Shape(error.to_string()))
    }
}

/// Why a record could not be digested.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// The value is not canonicalizable.
    Canonical(CanonicalError),
    /// The value is not a record-shaped object.
    Shape(String),
}

impl std::fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(detail) => write!(formatter, "the record is not canonical: {detail}"),
            Self::Shape(detail) => write!(formatter, "a record that is not an object: {detail}"),
        }
    }
}

impl std::error::Error for DigestError {}

/// The domain a history key's digest is taken under.
///
/// Its own domain, like every other digest here: a history key is a short structure of text, and a
/// digest that shared a domain with a record's could be presented as one.
pub const HISTORY_DOMAIN: &str = "permguard.event.history.v1\n";

/// The digest of a derived history key — the index key, never a substitute for its values.
///
/// Taken over the pin **names** as well as their values, because two schemas pinning different
/// fields may derive the same values and those are different histories. The values arrive already
/// canonically encoded by the runtime that derived them, so what this adds is the domain and the
/// canonicalization that makes the pair one string.
pub fn history_digest_of(value: &Value) -> Result<String, DigestError> {
    domain_digest(HISTORY_DOMAIN, value)
}

/// The digest of a record, taken over the bytes it is shipped as.
///
/// Verbatim by design: whatever fields the value carries are hashed, including ones this build
/// does not understand. That is what lets an older control plane keep a newer producer's records
/// and still prove their chain.
pub fn digest_of(value: &Value) -> Result<String, DigestError> {
    domain_digest(DIGEST_DOMAIN, value)
}

/// The digest of the caller's occurrence, before this plane added anything to it.
///
/// Taken over the occurrence alone — not the record — so two data planes that receive the same
/// retry compute the same value despite assigning different sequences, instances and observation
/// times. Same id and same digest is one logical occurrence; same id and a *different* digest is a
/// conflict, and a conflict is a security event rather than a duplicate to collapse.
pub fn occurrence_digest_of(occurrence: &Value) -> Result<String, DigestError> {
    domain_digest(OCCURRENCE_DOMAIN, occurrence)
}

/// A plain hex SHA-256 of some bytes, for addressing a file by a string a client chose.
///
/// Not a record digest and deliberately undomained: this is a file name, not evidence. What it has
/// to be is stable, fixed-length and safe on a filesystem — an occurrence id is any string a caller
/// sent, and using it verbatim would let a caller name a path.
pub fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);

    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn domain_digest(domain: &str, value: &Value) -> Result<String, DigestError> {
    let canonical = jcs::canonicalize(value).map_err(DigestError::Canonical)?;

    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(&canonical);

    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    fn record(seq: u64, prev: &str) -> Record {
        Record {
            v: VERSION,
            record_type: RECORD_TYPE.to_owned(),
            stream: Stream::new(
                Producer::data_plane("data-plane-7f3a", "01931f2c"),
                "acme",
                "agent-governance",
            ),
            seq,
            prev: prev.to_owned(),
            event_type: "permguard.dogwood.event.v1".to_owned(),
            event_id: "01J8Z9".to_owned(),
            occurrence_digest: GENESIS.to_owned(),
            kind: "request".to_owned(),
            profile: "temporal".to_owned(),
            policy_partitions: vec!["session-access".to_owned()],
            commit: "sha256:abc".to_owned(),
            history_key: None,
            occurred_at: "2026-08-28T10:15:30Z".to_owned(),
            observed_at: "2026-08-28T10:15:31Z".to_owned(),
            event: json!({"kind": "request", "action": "Drupe::Action::Read"}),
        }
    }

    #[test]
    fn a_record_round_trips_through_the_value_it_is_shipped_as() {
        let built = record(1, GENESIS);
        let value = built.to_value().expect("it serializes");
        let back: Record = serde_json::from_value(value).expect("it deserializes");

        assert_eq!(back, built);
    }

    /// The one property the whole log rests on: an event digest is not a decision digest.
    #[test]
    fn the_event_domain_is_separate_from_the_decision_domain() {
        let value = json!({"anything": true});
        let event = digest_of(&value).expect("it digests");
        let decision = permguard_decisions::record::digest_of(&value).expect("it digests");

        assert_ne!(
            event, decision,
            "one verifier must never accept a decision record where an event record belongs"
        );
    }

    /// And an occurrence digest is not a record digest, for the same reason.
    #[test]
    fn the_occurrence_domain_is_separate_from_the_record_domain() {
        let value = json!({"anything": true});

        assert_ne!(
            occurrence_digest_of(&value).expect("it digests"),
            digest_of(&value).expect("it digests")
        );
    }

    /// Key order in the JSON cannot change a digest: the canonical form sorts them.
    #[test]
    fn the_digest_is_over_canonical_bytes_and_not_over_the_writers_key_order() {
        let one = json!({"a": 1, "b": 2});
        let other = json!({"b": 2, "a": 1});

        assert_eq!(
            digest_of(&one).expect("it digests"),
            digest_of(&other).expect("it digests")
        );
    }

    /// A field this build does not know still contributes to the digest.
    #[test]
    fn an_unknown_field_is_hashed_rather_than_dropped() {
        let known = record(1, GENESIS).to_value().expect("it serializes");
        let mut newer = known.clone();
        newer
            .as_object_mut()
            .expect("an object")
            .insert("from_a_later_build".to_owned(), json!("something"));

        assert_ne!(
            digest_of(&known).expect("it digests"),
            digest_of(&newer).expect("it digests"),
            "a control plane must not be able to drop a field and still verify the chain"
        );
    }

    #[test]
    fn only_the_registered_data_plane_producer_class_is_accepted() {
        assert!(Producer::data_plane("dp", "i1").is_accepted());

        let future = Producer {
            class: "permguard.event.producer.pip.v1".to_owned(),
            id: "pip".to_owned(),
            instance: "i1".to_owned(),
        };
        assert!(
            !future.is_accepted(),
            "a class this release does not admit is refused before persistence"
        );
    }

    /// Two producers of one ledger are two streams, and two ledgers of one producer are too.
    #[test]
    fn a_stream_is_a_producer_and_a_tenant_together() {
        let producer = Producer::data_plane("dp-a", "i1");
        let one = Stream::new(producer.clone(), "acme", "agent-governance");
        let other_ledger = Stream::new(producer, "acme", "other");
        let other_producer = Stream::new(
            Producer::data_plane("dp-b", "i1"),
            "acme",
            "agent-governance",
        );

        assert_ne!(one, other_ledger);
        assert_ne!(one, other_producer);
    }
}
