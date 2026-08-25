// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Serving a page of records, and the proof that goes with it.
//!
//! # Falling off retention is answered, not discovered
//!
//! An offset older than what the scope still holds is refused explicitly, with
//! the oldest offset now available. A consumer returning from a long outage
//! therefore learns three things at once — that it lost records, where the
//! remaining ones begin, and that its run was not clean — instead of resuming
//! from the wrong place and reporting success.
//!
//! # What a tenant can verify, and how
//!
//! A tenant-scoped reader sees a subsequence of a producer's stream, so the
//! chain does not verify for it: the records in between belong to other
//! tenants and must not be disclosed. The inclusion path is what closes that
//! gap — it proves *this record was in a batch signed by that producer, and
//! has not been altered* without handing over anything of anybody else's.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use permguard_decisions::{merkle, record};

use super::offset::{Offset, OffsetError};
use super::store::{DecisionStore, Scope, read_segment};

/// One page of records, and where to continue.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    /// The records, verbatim.
    pub records: Vec<Value>,
    /// The offset to present next. Opaque, and bound to this scope.
    pub next: String,
    /// Whether the scope holds more right now.
    pub more: bool,
    /// The signed envelopes covering these records, when the reader asked.
    ///
    /// A reader checking signatures needs them: the records carry the chain,
    /// and the envelope is what a key actually signed.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub proof: Vec<Value>,
    /// One inclusion path per record, when the reader asked for a proof.
    ///
    /// This is what a **tenant-scoped** reader verifies with. Its page is a
    /// subsequence of a producer's stream — the records in between belong to
    /// other tenants and must not be disclosed — so the chain cannot be
    /// checked across it. The path proves *this record was in a batch signed
    /// by that producer, and has not been altered*, without handing over
    /// anything of anybody else's.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub inclusion: Vec<Inclusion>,
}

/// One record's place in the tree its batch was signed with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Inclusion {
    /// Which record this proves.
    pub seq: u64,
    /// The digest of the record, which is the leaf.
    pub leaf: String,
    /// The root the path reaches — the one the signed envelope attests.
    pub root: String,
    /// The siblings, from the leaf upwards.
    pub path: Vec<permguard_decisions::merkle::Step>,
}

/// Why a read was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadError {
    /// The offset is not usable here.
    Offset(OffsetError),
    /// The offset is older than what is held; here is where to resume.
    Expired {
        /// The oldest offset the scope still holds.
        oldest: String,
    },
    /// The store could not answer.
    Unavailable(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Offset(error) => write!(formatter, "{error}"),
            Self::Expired { oldest } => write!(
                formatter,
                "this offset is older than what is still held; the oldest available is `{oldest}`"
            ),
            Self::Unavailable(detail) => write!(formatter, "{detail}"),
        }
    }
}

/// Reads up to `limit` records of `scope`, starting at `token`.
pub fn page(
    store: &DecisionStore,
    scope: &Scope,
    token: Option<&str>,
    limit: usize,
) -> Result<Page, ReadError> {
    page_with(store, scope, token, limit, false)
}

/// Reads a page, optionally with the signed envelopes that attest it.
pub fn page_with(
    store: &DecisionStore,
    scope: &Scope,
    token: Option<&str>,
    limit: usize,
    proof: bool,
) -> Result<Page, ReadError> {
    let segments = store
        .segments(scope)
        .map_err(|error| ReadError::Unavailable(error.to_string()))?;
    let oldest = segments.first().map(|(first, _)| *first).unwrap_or(0);

    let mut offset = match token {
        Some(token) => Offset::decode(token, scope).map_err(ReadError::Offset)?,
        None => Offset::beginning(scope),
    };
    if offset.segment == 0 {
        offset.segment = oldest;
    }
    // A position naming a segment that has left on the retention schedule.
    if offset.segment < oldest {
        return Err(ReadError::Expired {
            oldest: Offset {
                scope: scope.key(),
                segment: oldest,
                position: 0,
            }
            .encode(),
        });
    }

    let mut records = Vec::new();
    let mut cursor = offset.clone();
    for (first, path) in &segments {
        if *first < cursor.segment {
            continue;
        }
        let position = if *first == cursor.segment {
            cursor.position
        } else {
            cursor.segment = *first;
            cursor.position = 0;
            0
        };
        let (found, next_position) = read_segment(path, position, limit - records.len())
            .map_err(|error| ReadError::Unavailable(error.to_string()))?;
        cursor.position = next_position;
        records.extend(found);
        if records.len() >= limit {
            break;
        }
    }

    let more = records.len() >= limit;
    // The envelopes of whichever streams these records came from. Read from
    // the record itself rather than from the request, so a tenant asking for a
    // proof cannot name a stream it has no records of.
    let proof = if proof {
        let mut streams: Vec<(String, String)> = records
            .iter()
            .filter_map(|record| {
                let stream = record.get("stream")?;
                Some((
                    stream.get("id")?.as_str()?.to_owned(),
                    stream.get("instance")?.as_str()?.to_owned(),
                ))
            })
            .collect();
        streams.sort();
        streams.dedup();
        streams
            .into_iter()
            .filter_map(|(pdp_id, instance)| store.envelopes(&pdp_id, &instance).ok())
            .flatten()
            .collect()
    } else {
        Vec::new()
    };

    let inclusion = if proof.is_empty() {
        Vec::new()
    } else {
        inclusion_paths(store, &records, &proof)
    };

    Ok(Page {
        records,
        next: cursor.encode(),
        more,
        proof,
        inclusion,
    })
}

/// Builds the inclusion path of every record, against the batch that carried it.
///
/// The leaves of a batch include records of every tenant it touched, so the
/// tree is rebuilt from the **producer stream**, not from the page. That is the
/// point: the tenant never sees those records, and still gets a path that
/// reaches the root its signed envelope attests.
fn inclusion_paths(store: &DecisionStore, records: &[Value], proof: &[Value]) -> Vec<Inclusion> {
    let mut built = Vec::new();
    for record in records {
        let Some(seq) = record.get("seq").and_then(Value::as_u64) else {
            continue;
        };
        let Some(stream) = record.get("stream") else {
            continue;
        };
        let (Some(pdp_id), Some(instance)) = (
            stream.get("id").and_then(Value::as_str),
            stream.get("instance").and_then(Value::as_str),
        ) else {
            continue;
        };

        // Which batch carried it, and what that batch attested.
        let Some((first_seq, last_seq, root)) = covering(proof, seq, pdp_id, instance) else {
            continue;
        };
        let leaves = leaves_of(store, pdp_id, instance, first_seq, last_seq);
        let Some(index) = leaves.iter().position(|(leaf_seq, _)| *leaf_seq == seq) else {
            continue;
        };
        let digests: Vec<String> = leaves.into_iter().map(|(_, digest)| digest).collect();
        let Some(path) = merkle::path(&digests, index) else {
            continue;
        };

        built.push(Inclusion {
            seq,
            leaf: digests[index].clone(),
            root,
            path,
        });
    }

    built
}

/// The batch that covers `seq`, as its envelope attests it.
fn covering(proof: &[Value], seq: u64, pdp_id: &str, instance: &str) -> Option<(u64, u64, String)> {
    use base64::Engine as _;

    for signed in proof {
        let payload = signed.get("payload").and_then(Value::as_str)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .ok()?;
        let envelope: Value = serde_json::from_slice(&bytes).ok()?;
        let stream = envelope.get("stream")?;
        if stream.get("id").and_then(Value::as_str) != Some(pdp_id)
            || stream.get("instance").and_then(Value::as_str) != Some(instance)
        {
            continue;
        }
        let first = envelope.get("first_seq").and_then(Value::as_u64)?;
        let last = envelope.get("last_seq").and_then(Value::as_u64)?;
        if (first..=last).contains(&seq) {
            let root = envelope
                .get("merkle_root")
                .and_then(Value::as_str)?
                .to_owned();

            return Some((first, last, root));
        }
    }

    None
}

/// The digests of one batch's records, in the order they were hashed.
fn leaves_of(
    store: &DecisionStore,
    pdp_id: &str,
    instance: &str,
    first_seq: u64,
    last_seq: u64,
) -> Vec<(u64, String)> {
    let scope = Scope::Stream {
        pdp_id: pdp_id.to_owned(),
        instance: instance.to_owned(),
    };
    let mut leaves = Vec::new();
    for (_, path) in store.segments(&scope).unwrap_or_default() {
        let Ok((records, _)) = read_segment(&path, 0, usize::MAX) else {
            continue;
        };
        for value in records {
            let Some(seq) = value.get("seq").and_then(Value::as_u64) else {
                continue;
            };
            if (first_seq..=last_seq).contains(&seq)
                && let Ok(digest) = record::digest_of(&value)
            {
                leaves.push((seq, digest));
            }
        }
    }
    leaves.sort_by_key(|(seq, _)| *seq);

    leaves
}
