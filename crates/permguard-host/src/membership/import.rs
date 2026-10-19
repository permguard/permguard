// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The `events.import` task, contract version 1 (WP-6.2c; owner decisions of 2026-10-18 and
//! 2026-10-19).
//!
//! ```text
//! member       task session over a ledger resource, within the task's selector
//!   ─▶ { action: "origins" }
//! coordinator  every required origin of the resource, with its membership manifest, and one
//!              checkpoint over their runs, signed now by `control.attest`, bound to the session
//!   ─▶ { checkpoint, origins: [{ host_id, membership_id, manifest }] }
//! member       verifies the checkpoint under the pinned `control.attest`, each manifest under the
//!              pinned `host.operations`, then asks for each batch past what it holds
//!   ─▶ { action: "batch", host_id, run, seq }
//! coordinator  the batch covering `seq`, as the origin shipped it: the batch file and the ring
//!              statement it was verified under, the `ship_message` the origin sent
//! ```
//!
//! | Record             | Shape                                                                     |
//! | ------------------ | ------------------------------------------------------------------------- |
//! | import_request     | {1 action, 2? host_id, 3? run, 4? seq}                                    |
//! | import_origins     | {1 checkpoint, 2 origins}: each {1 host_id, 2 membership_id, 3 manifest}  |
//! | import_checkpoint  | {1 coordinator, 2 resource, 3 revision, 4 origins, 5 issued_at, 6 channel_binding, 7 ring_epoch, 8 key_set_digest}: each origin {1 host_id, 2 runs}, each run {1 run, 2 acked, 3 oldest_retained, 4? admitted_at} |
//!
//! The required origins are the coordinator's active members whose `events.ship` task covers the
//! resource (owner decision of 2026-10-19); their revision is the digest of each one's `host_id`
//! and membership, so a member joining or leaving moves it, and a manifest re-issued over the same
//! membership does not (after the review). A checkpoint is signed for every `origins` request, even when no origin has a new
//! record: its freshness is the member's age since it verified it, never an event's time.

use sha2::{Digest as _, Sha256};

use permguard_core::domains::protected;
use permguard_objects::cbor::Value;
use permguard_objects::cose::Sign1;

use super::record::{RingPin, RingStatement};
use super::{MembershipError, public_of, statement_matches};
use crate::identity::record::{Labelled, RecordError, encode, uint};
use crate::keys::ring::CONTROL_ATTEST;

/// The contract version this module speaks.
pub const VERSION: u64 = 1;
/// The request for the origins and their checkpoint.
pub const ORIGINS: &str = "origins";
/// The request for one batch of one origin's run.
pub const BATCH: &str = "batch";
/// The most bytes a request takes.
pub const MAX_REQUEST_BYTES: usize = 1024;
/// The most required origins one answer names.
pub const MAX_ORIGINS: usize = 64;
/// The most runs one checkpoint names, over every origin.
pub const MAX_CHECKPOINT_RUNS: usize = 1024;
/// The longest resource a checkpoint names.
const MAX_RESOURCE_BYTES: usize = 512;

/// What a member asks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The required origins, their manifests and a checkpoint signed now.
    Origins,
    /// The batch covering `seq` of `host_id`'s run `run`.
    Batch {
        host_id: [u8; 16],
        run: [u8; 16],
        seq: u64,
    },
}

impl Request {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        match self {
            Self::Origins => encode(vec![(Value::Int(1), Value::Text(ORIGINS.to_owned()))]),
            Self::Batch { host_id, run, seq } => encode(vec![
                (Value::Int(1), Value::Text(BATCH.to_owned())),
                (Value::Int(2), Value::Bytes(host_id.to_vec())),
                (Value::Int(3), Value::Bytes(run.to_vec())),
                (Value::Int(4), uint(*seq)?),
            ]),
        }
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_REQUEST_BYTES {
            return Err(RecordError(
                "an import request is out of its bound".to_owned(),
            ));
        }
        let mut map = Labelled::read(bytes, "an import request")?;
        let action = map.text(1)?;
        let request = match action.as_str() {
            ORIGINS => Self::Origins,
            BATCH => {
                let seq = map.uint(4)?;
                if seq == 0 {
                    return Err(RecordError(
                        "an import request names a sequence from 1".to_owned(),
                    ));
                }
                Self::Batch {
                    host_id: map.id(2)?,
                    run: map.id(3)?,
                    seq,
                }
            }
            other => {
                return Err(RecordError(format!(
                    "`{other}` is not an import request action"
                )));
            }
        };
        map.finish()?;
        Ok(request)
    }
}

/// One required origin: a member of the coordinator's whose `events.ship` covers the resource.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    pub host_id: [u8; 16],
    pub membership_id: [u8; 16],
    /// The manifest in force, its envelope as the coordinator signed it.
    pub manifest: Vec<u8>,
}

/// The required origins of a resource and their revision, as the coordinator's membership store
/// holds them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OriginSet {
    pub revision: [u8; 32],
    /// By `host_id`, each once.
    pub origins: Vec<Origin>,
}

/// The coordinator's answer to [`Request::Origins`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origins {
    /// The [`Checkpoint`], a COSE_Sign1 under the coordinator's `control.attest`.
    pub checkpoint: Vec<u8>,
    /// By `host_id`, each once.
    pub origins: Vec<Origin>,
}

impl Origins {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let bytes = encode(vec![
            (Value::Int(1), Value::Bytes(self.checkpoint.clone())),
            (
                Value::Int(2),
                Value::Array(
                    self.origins
                        .iter()
                        .map(|origin| {
                            Value::Map(vec![
                                (Value::Int(1), Value::Bytes(origin.host_id.to_vec())),
                                (Value::Int(2), Value::Bytes(origin.membership_id.to_vec())),
                                (Value::Int(3), Value::Bytes(origin.manifest.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ])?;
        bounded(bytes, "an import answer")
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > super::record::MAX_BODY_BYTES {
            return Err(RecordError(
                "an import answer is out of its bound".to_owned(),
            ));
        }
        let mut map = Labelled::read(bytes, "an import answer")?;
        let checkpoint = map.bytes(1)?;
        let items = map.array(2)?;
        if items.len() > MAX_ORIGINS {
            return Err(RecordError(format!(
                "an import answer names at most {MAX_ORIGINS} origins"
            )));
        }
        let mut origins = Vec::with_capacity(items.len());
        for item in items {
            let mut origin = Labelled::from_value(item, "an import origin")?;
            origins.push(Origin {
                host_id: origin.id(1)?,
                membership_id: origin.id(2)?,
                manifest: origin.bytes(3)?,
            });
            origin.finish()?;
        }
        if !origins
            .windows(2)
            .all(|pair| pair[0].host_id < pair[1].host_id)
        {
            return Err(RecordError(
                "an import answer names its origins by host, each once".to_owned(),
            ));
        }
        map.finish()?;
        Ok(Self {
            checkpoint,
            origins,
        })
    }
}

/// One run of an origin, as the coordinator's consumer holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointRun {
    pub run: [u8; 16],
    /// The last sequence the coordinator admitted.
    pub acked: u64,
    /// The first sequence it still holds: below it, a gap of retention.
    pub oldest_retained: u64,
    /// The coordinator's own time it admitted the run's last batch, in seconds.
    pub admitted_at: Option<u64>,
}

/// One required origin's runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckpointOrigin {
    pub host_id: [u8; 16],
    pub runs: Vec<CheckpointRun>,
}

/// The coordinator's observation checkpoint of a resource's required origins (owner decision of
/// 2026-10-18): what it held of each, at `issued_at`, for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub coordinator: [u8; 16],
    pub resource: String,
    /// The digest of the required-origin set, [`revision`].
    pub revision: [u8; 32],
    /// By `host_id`, each once; every required origin, a new one with no run.
    pub origins: Vec<CheckpointOrigin>,
    /// The coordinator's time it signed the checkpoint, in seconds.
    pub issued_at: u64,
    /// The channel binding of the session's lease: a checkpoint answers one connection alone.
    pub channel_binding: [u8; 32],
    /// The `control.attest` epoch and key set it was signed under, filled by the signer.
    pub ring_epoch: u64,
    pub key_set_digest: [u8; 32],
}

impl Checkpoint {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut origins = Vec::with_capacity(self.origins.len());
        for origin in &self.origins {
            let mut runs = Vec::with_capacity(origin.runs.len());
            for run in &origin.runs {
                let mut fields = vec![
                    (Value::Int(1), Value::Bytes(run.run.to_vec())),
                    (Value::Int(2), uint(run.acked)?),
                    (Value::Int(3), uint(run.oldest_retained)?),
                ];
                if let Some(at) = run.admitted_at {
                    fields.push((Value::Int(4), uint(at)?));
                }
                runs.push(Value::Map(fields));
            }
            origins.push(Value::Map(vec![
                (Value::Int(1), Value::Bytes(origin.host_id.to_vec())),
                (Value::Int(2), Value::Array(runs)),
            ]));
        }
        encode(vec![
            (Value::Int(1), Value::Bytes(self.coordinator.to_vec())),
            (Value::Int(2), Value::Text(self.resource.clone())),
            (Value::Int(3), Value::Bytes(self.revision.to_vec())),
            (Value::Int(4), Value::Array(origins)),
            (Value::Int(5), uint(self.issued_at)?),
            (Value::Int(6), Value::Bytes(self.channel_binding.to_vec())),
            (Value::Int(7), uint(self.ring_epoch)?),
            (Value::Int(8), Value::Bytes(self.key_set_digest.to_vec())),
        ])
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > super::record::MAX_BODY_BYTES {
            return Err(RecordError(
                "an import checkpoint is out of its bound".to_owned(),
            ));
        }
        let mut map = Labelled::read(bytes, "an import checkpoint")?;
        let coordinator = map.id(1)?;
        let resource = map.text(2)?;
        if resource.is_empty() || resource.len() > MAX_RESOURCE_BYTES {
            return Err(RecordError(format!(
                "an import checkpoint names a resource of 1 to {MAX_RESOURCE_BYTES} bytes"
            )));
        }
        let revision = map.fixed(3)?;
        let items = map.array(4)?;
        if items.len() > MAX_ORIGINS {
            return Err(RecordError(format!(
                "an import checkpoint names at most {MAX_ORIGINS} origins"
            )));
        }
        let mut origins = Vec::with_capacity(items.len());
        let mut runs_named = 0usize;
        for item in items {
            let mut origin = Labelled::from_value(item, "a checkpoint origin")?;
            let host_id = origin.id(1)?;
            let held = origin.array(2)?;
            runs_named += held.len();
            if runs_named > MAX_CHECKPOINT_RUNS {
                return Err(RecordError(format!(
                    "an import checkpoint names at most {MAX_CHECKPOINT_RUNS} runs"
                )));
            }
            let mut runs = Vec::with_capacity(held.len());
            for value in held {
                let mut run = Labelled::from_value(value, "a checkpoint run")?;
                let read = CheckpointRun {
                    run: run.id(1)?,
                    acked: run.uint(2)?,
                    oldest_retained: run.uint(3)?,
                    admitted_at: run.optional_uint(4)?,
                };
                run.finish()?;
                if read.oldest_retained == 0 || read.oldest_retained > read.acked + 1 {
                    return Err(RecordError(
                        "a checkpoint run holds from sequence 1 to past what it acknowledged"
                            .to_owned(),
                    ));
                }
                runs.push(read);
            }
            if !runs.windows(2).all(|pair| pair[0].run < pair[1].run) {
                return Err(RecordError(
                    "a checkpoint origin names its runs in order, each once".to_owned(),
                ));
            }
            origin.finish()?;
            origins.push(CheckpointOrigin { host_id, runs });
        }
        if !origins
            .windows(2)
            .all(|pair| pair[0].host_id < pair[1].host_id)
        {
            return Err(RecordError(
                "an import checkpoint names its origins by host, each once".to_owned(),
            ));
        }
        let checkpoint = Self {
            coordinator,
            resource,
            revision,
            origins,
            issued_at: map.uint(5)?,
            channel_binding: map.fixed(6)?,
            ring_epoch: map.uint(7)?,
            key_set_digest: map.fixed(8)?,
        };
        map.finish()?;
        Ok(checkpoint)
    }
}

/// The revision of a required-origin set: SHA-256 over the canonical CBOR array of each origin's
/// `[host_id, membership_id]`, by `host_id`.
pub fn revision(origins: &[([u8; 16], [u8; 16])]) -> Result<[u8; 32], RecordError> {
    let mut sorted = origins.to_vec();
    sorted.sort();
    let mut items = Vec::with_capacity(sorted.len());
    for (host_id, membership_id) in sorted {
        items.push(Value::Array(vec![
            Value::Bytes(host_id.to_vec()),
            Value::Bytes(membership_id.to_vec()),
        ]));
    }
    let bytes = permguard_objects::cbor::encode(&Value::Array(items))
        .map_err(|error| RecordError(error.to_string()))?;
    Ok(Sha256::digest(bytes).into())
}

/// Verifies a checkpoint under the coordinator's `control.attest` that `pin` names, its keys the
/// statement among `statements` that matches the pin: the pin, then the epoch and key set the
/// checkpoint claims, then the signature under the key its `kid` names. The claims are the
/// caller's to check against its session and resource.
pub fn verify_checkpoint(
    envelope: &[u8],
    statements: &[RingStatement],
    pin: &RingPin,
) -> Result<Checkpoint, MembershipError> {
    let unverified = |detail: &str| MembershipError::Unverified(format!("a checkpoint: {detail}"));
    if pin.ring != CONTROL_ATTEST {
        return Err(unverified("the pin is not of `control.attest`"));
    }
    let statement = statements
        .iter()
        .find(|statement| statement_matches(statement, pin).is_ok())
        .ok_or_else(|| unverified("no statement of the pinned `control.attest` set"))?;
    let sign1 = Sign1::decode(envelope).map_err(|error| unverified(&error.to_string()))?;
    let claimed = Checkpoint::decode(sign1.payload_unverified())
        .map_err(|error| unverified(&error.to_string()))?;
    if claimed.ring_epoch != pin.epoch || claimed.key_set_digest != pin.key_set_digest {
        return Err(unverified("signed under another `control.attest` set"));
    }
    let header = sign1
        .header()
        .map_err(|error| unverified(&error.to_string()))?;
    let (_, suite, public_key) = statement
        .keys
        .iter()
        .filter_map(|text| public_of(text))
        .find(|(kid, ..)| kid.as_bytes() == header.kid.as_slice())
        .ok_or_else(|| unverified("signed by no key of the pinned set"))?;
    let payload = sign1
        .verify(suite, &public_key, protected::EVENT_IMPORT_CHECKPOINT)
        .map_err(|error| unverified(&error.to_string()))?;
    Checkpoint::decode(payload).map_err(|error| unverified(&error.to_string()))
}

fn bounded(bytes: Vec<u8>, what: &str) -> Result<Vec<u8>, RecordError> {
    if bytes.len() > super::record::MAX_BODY_BYTES {
        return Err(RecordError(format!("{what} is out of its bound")));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests;
