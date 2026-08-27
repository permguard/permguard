// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The record: what a data plane writes when it answers, and the exact bytes
//! its digest is taken over.
//!
//! Three kinds share one envelope, and a reader must switch on `kind`:
//!
//! | Kind | What it is |
//! | --- | --- |
//! | `decision` | one answer, and what it was answered from |
//! | `marker` | an epoch — identity, build, sampling — governing the records that follow |
//! | `discontinuity` | the last record of a stream, naming what was lost and who continues |
//!
//! # The digest, and why it is not a field
//!
//! ```text
//! digest(record) = SHA-256( "permguard.decision.v1\n" || JCS(record) )
//! ```
//!
//! The whole record is hashed, `prev` included — that is what binds it to its
//! predecessor — and nothing is excluded, so there is no "which fields count"
//! question for an implementation to answer differently. The digest is
//! **computed, never transmitted**: a digest that travels beside the record is
//! a field somebody can make agree with a lie.
//!
//! The domain-separation prefix keeps these digests from ever being confusable
//! with an object digest or a seal digest elsewhere in the product.
//!
//! # Verbatim, on the receiving side
//!
//! Records are digested as [`serde_json::Value`], not as this crate's structs.
//! A control plane that reparsed a record into a struct it understands and
//! re-serialised it would silently drop any field a newer producer added, and
//! the digest would stop matching. So the wire type is the value, this struct
//! is how a producer *builds* one, and the two meet at [`Record::to_value`].

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::jcs::{self, CanonicalError};

/// The domain this crate's digests live in.
pub const DIGEST_DOMAIN: &str = "permguard.decision.v1\n";

/// The `prev` of the first record of any stream: sixty-four zeroes.
///
/// The same genesis the audit trail uses, so one verifier shape serves both.
pub const GENESIS: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The schema version every record carries.
pub const VERSION: u32 = 1;

/// Which producer, and which continuous incarnation of it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Stream {
    /// The deployment's name for this plane, stable across restarts.
    pub id: String,
    /// One continuous incarnation: minted with the spool, and again whenever
    /// continuity breaks.
    pub instance: String,
}

impl Stream {
    /// Builds a stream identity.
    pub fn new(id: impl Into<String>, instance: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            instance: instance.into(),
        }
    }
}

/// Which policy state produced an answer — the forensic core.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreRef {
    /// The zone that owns the ledger.
    pub zone: String,
    /// The ledger the decision was answered from.
    pub ledger: String,
    /// The exact commit, content-addressed and immutable.
    pub commit: String,
    /// Where that commit stood in the ledger's history.
    pub counter: u64,
    /// Which profile of the manifest was asked for.
    pub profile: String,
}

/// One party of a decision, as it is recorded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Party {
    /// The entity type, as the request named it.
    #[serde(rename = "type")]
    pub kind: String,
    /// The identifier — pseudonymised before it leaves the plane.
    pub id: String,
    /// The attributes the deployment named in `include`, in clear.
    ///
    /// Absent unless somebody asked for them by name. An allow-list, never a
    /// deny-list: a property added to a request tomorrow must not start being
    /// recorded by itself.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub properties: Option<serde_json::Map<String, Value>>,
}

/// What the decision saw, without keeping it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inputs {
    /// A keyed commitment over the caller's context.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context: Option<String>,
    /// A keyed commitment over the inputs the request addressed to the profile's partitions.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub partition_inputs: Option<String>,
    /// Anything fetched at decision time. Empty until a PIP exists.
    #[serde(default)]
    pub external: Vec<Value>,
}

/// Why an answer came out the way it did — the class, not the sentence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    /// The code, which is an interface; prose is not.
    pub code: String,
}

/// W3C Trace Context, when the caller sent one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Trace {
    /// The trace this decision belongs to.
    pub trace_id: String,
    /// The span that asked.
    pub span_id: String,
}

/// The build that decided, and under which evaluation semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Build {
    /// The plane's released version.
    pub version: String,
    /// The digest of the binary, where the deployment attests it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub build: Option<String>,
    /// Engine versions, by language — what `version` alone cannot answer.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub engines: Option<std::collections::BTreeMap<String, String>>,
}

/// What a stream claims to be complete about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sampling {
    /// The rate at which permits are recorded. Denies and errors are never sampled.
    pub permits: String,
}

/// How input commitments were computed, so a verifier knows what it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitments {
    /// The algorithm — `HMAC-SHA256`.
    pub alg: String,
    /// Which version of the commitment key.
    pub key_version: String,
}

/// The stream a discontinuity ended, and where it continues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lost {
    /// The first sequence that will never be shipped: `acked + 1`.
    pub from_seq: u64,
    /// How many written records are being discarded.
    pub count_estimate: u64,
}

/// The stream this one continues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Predecessor {
    /// The incarnation that ended.
    pub instance: String,
    /// Its last sequence, which is its terminal record.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub last_seq: Option<u64>,
    /// Why it ended — `spool_full`, `age_expiry` or `closed_by_server`.
    pub reason: String,
}

/// The kind-specific half of a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Body {
    /// One answer.
    Decision(Box<DecisionBody>),
    /// An epoch governing the records that follow it.
    Marker(Box<MarkerBody>),
    /// The last record of a stream.
    Discontinuity(Box<DiscontinuityBody>),
}

impl Body {
    /// One word, for logs, metrics and the reader's switch.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Decision(_) => "decision",
            Self::Marker(_) => "marker",
            Self::Discontinuity(_) => "discontinuity",
        }
    }

    /// The tenant this record belongs to, when it belongs to one.
    ///
    /// `None` for stream-level records: they are properties of the producer,
    /// not of a tenant, which is why they are copied into every view.
    pub fn tenancy(&self) -> Option<(&str, &str)> {
        match self {
            Self::Decision(body) => Some((body.store.zone.as_str(), body.store.ledger.as_str())),
            Self::Marker(_) | Self::Discontinuity(_) => None,
        }
    }
}

/// One decision, and what it was decided from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionBody {
    /// Joins this record to the response the caller received.
    pub id: String,
    /// The plane's released version. The build is in the governing marker.
    pub pdp: Build,
    /// The policy state that answered.
    pub store: StoreRef,
    /// Who asked.
    pub subject: Party,
    /// About what.
    pub resource: Party,
    /// To do what.
    pub action: ActionRef,
    /// On whose behalf, where the request said so.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub principal: Option<Party>,
    /// What the decision saw, as commitments.
    pub inputs: Inputs,
    /// The answer.
    pub decision: bool,
    /// Which policies decided — identities that survive renames.
    #[serde(default)]
    pub policies: Vec<String>,
    /// The class of the outcome.
    pub reason: Reason,
    /// The request this decision belongs to, when the caller traced it.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub trace: Option<Trace>,
    /// The caller's own correlation handle.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub request_id: Option<String>,
    /// The context members the deployment named in `include`, in clear.
    ///
    /// The whole context is committed to in `inputs`; this is the part somebody
    /// asked to be able to *read*. Recording an address or a device id is a
    /// data-protection decision, so it is made by naming the field.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub context: Option<serde_json::Map<String, Value>>,
    /// How long it took — a slow plane told from a slow policy set.
    pub latency_us: u64,
}

/// What was asked for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionRef {
    /// The action's name.
    pub name: String,
}

/// An epoch: what is true of a range of records rather than of each one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MarkerBody {
    /// The stream this one continues, when it continues one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub predecessor: Option<Predecessor>,
    /// The build and the engines inside it.
    pub pdp: Build,
    /// What this range claims to be complete about.
    pub sampling: Sampling,
    /// How input commitments are computed in this range.
    pub commitments: Commitments,
}

/// The last record of a stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscontinuityBody {
    /// Why the stream ended.
    pub reason: String,
    /// What will never be shipped.
    pub lost: Lost,
    /// The incarnation that continues — minted *before* this record is written.
    pub successor: String,
}

/// A record, as a producer builds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// The schema version.
    pub v: u32,
    /// Which producer and incarnation.
    pub stream: Stream,
    /// Where in that incarnation.
    pub seq: u64,
    /// The digest of `seq - 1`, or the genesis.
    pub prev: String,
    /// When, informational: ordering is by `seq`.
    pub at: String,
    /// The kind-specific half, which carries `kind` itself.
    #[serde(flatten)]
    pub body: Body,
}

impl Record {
    /// Renders the record as the value that is shipped and digested.
    pub fn to_value(&self) -> Result<Value, DigestError> {
        serde_json::to_value(self).map_err(|error| DigestError::Shape(error.to_string()))
    }

    /// The digest this record will be chained by.
    pub fn digest(&self) -> Result<String, DigestError> {
        digest_of(&self.to_value()?)
    }
}

/// Why a digest could not be taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DigestError {
    /// The value could not be canonicalised.
    Canonical(CanonicalError),
    /// The record could not be rendered as JSON at all.
    Shape(String),
}

impl std::fmt::Display for DigestError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Canonical(error) => write!(formatter, "{error}"),
            Self::Shape(detail) => write!(formatter, "a record that is not an object: {detail}"),
        }
    }
}

impl std::error::Error for DigestError {}

/// The digest of a record, taken over the bytes it is shipped as.
///
/// Verbatim by design: whatever fields the value carries are hashed, including
/// ones this build does not understand.
pub fn digest_of(value: &Value) -> Result<String, DigestError> {
    let canonical = jcs::canonicalize(value).map_err(DigestError::Canonical)?;

    let mut hasher = Sha256::new();
    hasher.update(DIGEST_DOMAIN.as_bytes());
    hasher.update(&canonical);

    Ok(format!("sha256:{:x}", hasher.finalize()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    fn marker(seq: u64, prev: &str) -> Record {
        Record {
            v: VERSION,
            stream: Stream::new("data-plane-7f3a", "01931f2c"),
            seq,
            prev: prev.to_owned(),
            at: "2026-08-24T10:00:00Z".to_owned(),
            body: Body::Marker(Box::new(MarkerBody {
                predecessor: None,
                pdp: Build {
                    version: "0.1.0".to_owned(),
                    build: None,
                    engines: None,
                },
                sampling: Sampling {
                    permits: "1.0".to_owned(),
                },
                commitments: Commitments {
                    alg: "HMAC-SHA256".to_owned(),
                    key_version: "v1".to_owned(),
                },
            })),
        }
    }

    #[test]
    fn test_the_kind_is_a_field_of_the_shipped_record() {
        let value = marker(1, GENESIS).to_value().expect("it renders");

        assert_eq!(value["kind"], json!("marker"));
        assert_eq!(value["seq"], json!(1));
    }

    #[test]
    fn test_a_record_round_trips_through_its_own_wire_form() {
        let record = marker(1, GENESIS);
        let value = record.to_value().expect("it renders");
        let parsed: Record = serde_json::from_value(value).expect("it parses back");

        assert_eq!(parsed, record);
    }

    #[test]
    fn test_the_digest_is_domain_separated_from_a_bare_hash() {
        let value = json!({ "a": 1 });
        let ours = digest_of(&value).expect("it digests");

        let bare = {
            use sha2::Digest as _;
            format!("sha256:{:x}", sha2::Sha256::digest(br#"{"a":1}"#))
        };

        assert_ne!(ours, bare, "the prefix is part of the input");
    }

    #[test]
    fn test_changing_prev_changes_the_digest() {
        let one = marker(2, GENESIS).digest().expect("it digests");
        let other = marker(2, "sha256:11").digest().expect("it digests");

        assert_ne!(one, other, "prev is inside the hashed input");
    }

    #[test]
    fn test_a_field_this_build_does_not_know_is_still_hashed() {
        // What a newer producer would ship. Verbatim digesting is what keeps
        // an older verifier able to check it.
        let mut value = marker(1, GENESIS).to_value().expect("it renders");
        let before = digest_of(&value).expect("it digests");
        value["future_field"] = json!("something");

        assert_ne!(
            before,
            digest_of(&value).expect("it digests"),
            "nothing is excluded from the hashed input"
        );
    }

    #[test]
    fn test_stream_level_records_carry_no_tenancy() {
        assert_eq!(marker(1, GENESIS).body.tenancy(), None);
    }
}
