// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Accepting a batch of events: verify, append, flush, and answer with a number the producer can
//! safely delete by.
//!
//! # The acknowledgement is the whole contract, and it means more here than for decisions
//!
//! It is the highest **contiguous durable** sequence for that stream. A decision producer deletes
//! its spool by it; an event producer does the same, and its journal is *also* the history its own
//! policies read. So a number with a hole behind it does not merely lose evidence — it changes
//! what future authorizations mean on the plane that trusted it.
//!
//! # What each answer means
//!
//! ```text
//! ≤ acked entirely       ok, acked unchanged     a replay: deduplicated
//! acked + 1              ok, acked moves         the ordinary case
//! > acked + 1            out_of_order            nothing stored; resend from expected_seq
//! same seq, other bytes  fork                    the stream is closed permanently
//! ```
//!
//! The last is not a retry and never becomes one. Two different records claiming one
//! `(stream, seq)` is a bug or an attack, and in both cases the stream's history can no longer be
//! reasoned about as one sequence. Nothing is repaired and nothing is overwritten: what is stored
//! stays as evidence, and the producer opens a new incarnation to keep recording.
//!
//! # What is checked before anything is durable
//!
//! The producer class is registered and permitted; the signature verifies against a key that
//! producer published; the envelope's type and algorithm are the event log's own; every record's
//! digest matches, chains, and belongs to the stream the envelope names; the Merkle root is the
//! root of exactly those digests; every record's event type is one this build registers. In that
//! order, and all of it before a byte is written.

use anyhow::Result;
use permguard_core::Jwk;
use permguard_events::envelope::Envelope;
use permguard_events::record::PRODUCER_CLASS_DATA_PLANE;
use permguard_events::{chain, record};
use serde_json::Value;
use tracing::{info, warn};

use super::store::{EventStore, StreamState};

const COMPONENT: &str = "control-plane";

/// The producer classes this release accepts.
///
/// One entry, and the list is a list on purpose: the record, batch and storage protocols are
/// generic so a later authenticated producer — a PIP, say — can be admitted without changing
/// offsets, envelopes or layout. What is *not* done is enabling one before its payload, its owner
/// and its validation contract exist, because an unenforced registry entry is an open door with a
/// label on it.
pub const ACCEPTED_PRODUCER_CLASSES: [&str; 1] = [PRODUCER_CLASS_DATA_PLANE];

/// What accepting a batch concluded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Accepted {
    /// Stored (or already held), and durable through `acked`.
    Ok {
        /// The highest contiguous durable sequence.
        acked: u64,
        /// How many records this batch added. Zero for a replay.
        stored: u64,
    },
    /// The shipper ran ahead: nothing was stored.
    OutOfOrder {
        /// What the store needs next.
        expected_seq: u64,
    },
}

/// Why a batch was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// The signature does not verify, or names a key nobody published.
    Unattributable(String),
    /// The records are not a chain, or do not match what the envelope attests.
    Unverifiable(String),
    /// A producer class or event type this build does not accept.
    Unregistered(String),
    /// A record conflicts with one already stored. The stream is now closed.
    Fork {
        /// Where the two disagree.
        seq: u64,
    },
    /// The stream was closed permanently and accepts nothing more.
    Closed(String),
    /// The store could not accept right now. A shipper retries this.
    Unavailable(String),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unattributable(detail)
            | Self::Unverifiable(detail)
            | Self::Unregistered(detail)
            | Self::Unavailable(detail) => write!(formatter, "{detail}"),
            Self::Fork { seq } => write!(
                formatter,
                "a different record is already stored at sequence {seq}: this stream has forked, \
                 so it is closed permanently and what it holds is kept as evidence"
            ),
            Self::Closed(reason) => write!(
                formatter,
                "this stream was closed permanently ({reason}) and accepts nothing further: open a \
                 new incarnation"
            ),
        }
    }
}

/// The code a caller switches on.
impl Refused {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Unattributable(_) => "batch_unattributable",
            Self::Unverifiable(_) => "batch_unverifiable",
            Self::Unregistered(_) => "batch_unregistered",
            Self::Fork { .. } => "stream_forked",
            Self::Closed(_) => "stream_closed",
            Self::Unavailable(_) => "store_unavailable",
        }
    }
}

/// One batch, as the wire carries it.
///
/// The producer's own definition, not a copy: both sides must agree about it byte for byte, and
/// two definitions would be two chances to render the same batch two ways.
pub use permguard_events::Batch;

/// One verification key bound to the producer and tenant scope it is allowed to attest.
#[derive(Debug, Clone)]
pub struct ProducerTrust {
    pub key: Jwk,
    pub producer: String,
    pub zone: String,
    pub ledger: String,
}

impl ProducerTrust {
    fn authorizes(&self, stream: &permguard_events::Stream) -> bool {
        self.producer == stream.producer.id
            && (self.zone == "*" || self.zone == stream.zone)
            && (self.ledger == "*" || self.ledger == stream.ledger)
    }
}

/// Accepts one signed batch into `store`.
pub fn accept(
    store: &EventStore,
    batch: &Batch,
    producers: &[ProducerTrust],
    accepted_types: &[&str],
) -> Result<Accepted, Refused> {
    let protected = batch
        .signature
        .protected()
        .map_err(|error| Refused::Unattributable(error.to_string()))?;
    let mut verified = None;
    let mut wrong_scope = false;
    for producer in producers
        .iter()
        .filter(|held| held.key.kid == protected.kid)
    {
        let Ok(envelope) = batch.signature.verify(std::slice::from_ref(&producer.key)) else {
            continue;
        };
        if producer.authorizes(&envelope.stream) {
            verified = Some((envelope, &producer.key));
            break;
        }
        wrong_scope = true;
    }
    let Some((envelope, signing_key)) = verified else {
        return Err(Refused::Unattributable(if wrong_scope {
            "the signature is valid, but its key is not authorized for the producer, zone and \
             ledger declared by this batch"
                .to_owned()
        } else {
            format!(
                "no current key bound to an authorized event producer verifies key id `{}`",
                protected.kid
            )
        }));
    };

    // The producer class, before anything else about the batch: an ingress that verified a
    // signature and then discovered it did not accept that producer would have done the expensive
    // work for a caller it was never going to serve.
    if !ACCEPTED_PRODUCER_CLASSES.contains(&envelope.stream.producer.class.as_str()) {
        return Err(Refused::Unregistered(format!(
            "`{}` is not a producer class this release accepts; it accepts {}",
            envelope.stream.producer.class,
            ACCEPTED_PRODUCER_CLASSES.join(", ")
        )));
    }

    // The key that signed is archived beside what it attests, the first time it is seen: a batch
    // signed today must still verify after that key has been rotated a dozen times.
    if let Err(error) = store.archive_key(signing_key) {
        return Err(Refused::Unavailable(error.to_string()));
    }

    // One writer per stream, from the first read of its state to the acknowledgement.
    let gate = store.gate(&envelope.stream);
    let _writing = match gate.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };
    // Several producer streams contribute to one tenant view. Hold its gate for the whole batch,
    // not once per record: otherwise two producers interleave a physical page and a reader can
    // observe rows that neither batch has acknowledged yet.
    let view_gate = store.view_gate(&envelope.stream.zone, &envelope.stream.ledger);
    let _view = match view_gate.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };

    let state = store
        .stream_state(&envelope.stream)
        .map_err(|error| Refused::Unavailable(error.to_string()))?;
    if let Some(reason) = &state.closed {
        return Err(Refused::Closed(reason.clone()));
    }

    check(batch, &envelope, accepted_types)?;

    // A batch entirely at or below the acknowledged point is a replay: the producer did not hear
    // the answer and sent it again. Deduplicated, and the acknowledgement does not move.
    if envelope.last_seq <= state.acked {
        return replay(store, batch, &envelope, &state);
    }
    if envelope.first_seq > state.acked + 1 {
        return Ok(Accepted::OutOfOrder {
            expected_seq: state.acked + 1,
        });
    }
    if envelope.first_seq == state.acked + 1 {
        continues(&envelope, batch, &state)?;
    }

    let dropped = store
        .rollback_unacked(&envelope.stream, state.acked)
        .map_err(|error| Refused::Unavailable(error.to_string()))?;
    if dropped > 0 {
        warn!(
            event.name = "events.rolled_back",
            component = COMPONENT,
            zone = envelope.stream.zone.as_str(),
            ledger = envelope.stream.ledger.as_str(),
            instance = envelope.stream.producer.instance.as_str(),
            acked = state.acked,
            dropped,
            "records written but never acknowledged were discarded before this batch was appended"
        );
    }

    // The overlap — records at or below `acked` that came again — is checked against what is
    // stored rather than skipped: a producer resending *different* bytes at a sequence already
    // held is the fork case, and it is the one thing that must never be quietly absorbed.
    let held = held_digests(store, &envelope).map_err(Refused::Unavailable)?;
    let mut fresh = Vec::new();
    for value in &batch.records {
        let seq = value.get("seq").and_then(Value::as_u64).unwrap_or_default();
        if seq <= state.acked {
            same_or_fork(store, &held, &envelope, value, seq)?;
            continue;
        }
        fresh.push(value);
    }
    store
        .append_batch(&envelope.stream, &fresh)
        .map_err(|error| Refused::Unavailable(error.to_string()))?;
    let stored = fresh.len() as u64;

    let signature = serde_json::to_value(&batch.signature).map_err(|error| {
        Refused::Unavailable(format!(
            "the verified batch envelope could not be preserved: {error}"
        ))
    })?;
    store
        .keep_envelope(&envelope.stream, envelope.first_seq, &signature)
        .map_err(|error| Refused::Unavailable(error.to_string()))?;

    // Only now, and only after everything is flushed, does the producer get a number it may delete
    // by — and it is about to delete history its own policies read.
    let state = store
        .acknowledge(&envelope.stream, envelope.last_seq, &envelope.head)
        .map_err(|error| Refused::Unavailable(error.to_string()))?;

    info!(
        event.name = "events.accepted",
        component = COMPONENT,
        zone = envelope.stream.zone.as_str(),
        ledger = envelope.stream.ledger.as_str(),
        producer = envelope.stream.producer.id.as_str(),
        instance = envelope.stream.producer.instance.as_str(),
        first_seq = envelope.first_seq,
        last_seq = envelope.last_seq,
        stored,
        "an event batch is durable"
    );

    Ok(Accepted::Ok {
        acked: state.acked,
        stored,
    })
}

/// Everything the batch must be, before anything is written.
fn check(batch: &Batch, envelope: &Envelope, accepted_types: &[&str]) -> Result<(), Refused> {
    envelope
        .check_shape()
        .map_err(|error| Refused::Unverifiable(error.to_string()))?;

    let verified = chain::verify(&batch.records, None)
        .map_err(|error| Refused::Unverifiable(error.to_string()))?;
    if verified.first_seq != envelope.first_seq || verified.last_seq != envelope.last_seq {
        return Err(Refused::Unverifiable(format!(
            "the envelope attests sequences {}..={} and the records run {}..={}",
            envelope.first_seq, envelope.last_seq, verified.first_seq, verified.last_seq
        )));
    }
    if verified.head != envelope.head {
        return Err(Refused::Unverifiable(
            "the envelope's head is not the digest of its last record".to_owned(),
        ));
    }
    if u64::try_from(batch.records.len()).unwrap_or(u64::MAX) != envelope.count {
        return Err(Refused::Unverifiable(format!(
            "the envelope attests {} records and carries {}",
            envelope.count,
            batch.records.len()
        )));
    }
    // `None` only for an empty batch, which the shape check already refused — and comparing
    // `None` against a stated root would be a comparison that could accidentally succeed if the
    // envelope's root were ever optional too.
    let root = permguard_decisions::merkle::root(&verified.digests);
    if root.as_deref() != Some(envelope.merkle_root.as_str()) {
        return Err(Refused::Unverifiable(
            "the envelope's Merkle root is not the root of the records it carries".to_owned(),
        ));
    }
    if verified.stream != envelope.stream {
        return Err(Refused::Unverifiable(
            "the records belong to a different stream than the envelope names".to_owned(),
        ));
    }

    // Every record's own type, checked against the registry — never inferred from its payload and
    // never taken from the envelope's summary, which is a hint for skipping batches rather than an
    // authority about what is in one.
    for value in &batch.records {
        let record =
            record::validate(value).map_err(|error| Refused::Unverifiable(error.to_string()))?;
        if !accepted_types.contains(&record.event_type.as_str()) {
            return Err(Refused::Unregistered(format!(
                "`{}` is not an event type this store accepts; it accepts {}",
                record.event_type,
                accepted_types.join(", ")
            )));
        }
        validate_occurrence(&record)?;
    }

    Ok(())
}

/// Checks the registered event payload and binds the redundant record fields to it.
///
/// Those fields are redundant on purpose: they make filtering cheap and an audit readable. They
/// are safe only while they say the same thing as the typed occurrence the digest covers.
fn validate_occurrence(record: &record::Record) -> Result<(), Refused> {
    if record.event_type != permguard_languages::event::EVENT_TYPE {
        return Err(Refused::Unregistered(format!(
            "this build has no payload validator for `{}`",
            record.event_type
        )));
    }
    let body: permguard_languages::event::OccurrenceBody =
        serde_json::from_value(record.event.clone()).map_err(|error| {
            Refused::Unverifiable(format!(
                "the `{}` payload is malformed: {error}",
                record.event_type
            ))
        })?;
    let occurrence = body
        .read()
        .map_err(|error| Refused::Unverifiable(error.to_string()))?;
    for (name, stated, actual) in [
        (
            "event_id",
            record.event_id.as_str(),
            occurrence.event_id.as_str(),
        ),
        ("kind", record.kind.as_str(), occurrence.kind.as_str()),
        (
            "occurred_at",
            record.occurred_at.as_str(),
            occurrence.occurred_at.as_str(),
        ),
    ] {
        if stated != actual {
            return Err(Refused::Unverifiable(format!(
                "the record states `{name}` as `{stated}` and its typed occurrence states `{actual}`"
            )));
        }
    }

    Ok(())
}

/// Refuses a batch that does not continue the stream this store already holds.
///
/// The chain is `prev(N) = digest(N − 1)` across a **whole stream**, not inside a batch. Verifying
/// each batch on its own leaves the one link that spans the boundary unchecked — and that link is
/// where a producer's history could be silently replaced with a different one that is internally
/// perfect. A store that only checked sequence numbers would accept it.
fn continues(envelope: &Envelope, batch: &Batch, state: &StreamState) -> Result<(), Refused> {
    if envelope.previous_head != state.head {
        return Err(Refused::Unverifiable(format!(
            "this batch continues from `{}` and this stream stands at `{}`",
            envelope.previous_head, state.head
        )));
    }
    let Some(first) = batch.records.first() else {
        return Err(Refused::Unverifiable("an empty batch".to_owned()));
    };
    let stated = first
        .get("prev")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if stated != state.head {
        return Err(Refused::Unverifiable(format!(
            "the first record names `{stated}` as its predecessor and this stream stands at `{}`",
            state.head
        )));
    }

    Ok(())
}

/// A batch entirely at or below the acknowledgement: deduplicated, or a fork.
fn replay(
    store: &EventStore,
    batch: &Batch,
    envelope: &Envelope,
    state: &StreamState,
) -> Result<Accepted, Refused> {
    let held = held_digests(store, envelope).map_err(Refused::Unavailable)?;
    for value in &batch.records {
        let seq = value.get("seq").and_then(Value::as_u64).unwrap_or_default();
        same_or_fork(store, &held, envelope, value, seq)?;
    }

    Ok(Accepted::Ok {
        acked: state.acked,
        stored: 0,
    })
}

/// The digests of what is already stored, by sequence.
fn held_digests(
    store: &EventStore,
    envelope: &Envelope,
) -> Result<std::collections::BTreeMap<u64, String>, String> {
    let scope = super::store::Scope::Stream {
        zone: envelope.stream.zone.clone(),
        ledger: envelope.stream.ledger.clone(),
        class: envelope.stream.producer.class.clone(),
        producer: envelope.stream.producer.id.clone(),
        instance: envelope.stream.producer.instance.clone(),
    };
    let mut held = std::collections::BTreeMap::new();
    for (_, path) in store.segments(&scope).map_err(|error| error.to_string())? {
        let (records, _) =
            super::store::read_segment(&path, 0, usize::MAX).map_err(|error| error.to_string())?;
        for value in records {
            let Some(seq) = value.get("seq").and_then(Value::as_u64) else {
                continue;
            };
            if let Ok(digest) = record::digest_of(&value) {
                held.insert(seq, digest);
            }
        }
    }

    Ok(held)
}

/// The same bytes as what is stored, or a fork that closes the stream.
fn same_or_fork(
    store: &EventStore,
    held: &std::collections::BTreeMap<u64, String>,
    envelope: &Envelope,
    value: &Value,
    seq: u64,
) -> Result<(), Refused> {
    let Some(stored) = held.get(&seq) else {
        // Below the acknowledgement and not stored: this store's own files disagree with its own
        // state. Nothing is written on top of that.
        return Err(Refused::Unavailable(format!(
            "sequence {seq} is acknowledged and absent from this store's segments"
        )));
    };
    let digest =
        record::digest_of(value).map_err(|error| Refused::Unverifiable(error.to_string()))?;
    if &digest == stored {
        return Ok(());
    }

    // A fork. Closed permanently, and what is held stays exactly as it is: repairing history would
    // be indistinguishable, to a later auditor, from an attacker doing the same.
    let _ = store.close(
        &envelope.stream,
        &format!("two different records at sequence {seq}"),
    );
    warn!(
        event.name = "events.forked",
        component = COMPONENT,
        zone = envelope.stream.zone.as_str(),
        ledger = envelope.stream.ledger.as_str(),
        instance = envelope.stream.producer.instance.as_str(),
        seq,
        "two different records claim one sequence: this stream is closed permanently"
    );

    Err(Refused::Fork { seq })
}
