// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Accepting a batch: verify, append, flush, and answer with a number the
//! producer can safely delete by.
//!
//! # The acknowledgement is the whole contract
//!
//! It is the highest **contiguous durable** sequence for that stream — not the
//! highest accepted. The shipper truncates its spool by it, and truncating by
//! a number that had a hole behind it is exactly how a gap becomes permanent.
//!
//! # What each answer means
//!
//! ```text
//! ≤ acked entirely   ok, acked unchanged      a replay: deduplicated
//! acked + 1          ok, acked moves          the ordinary case
//! > acked + 1        out_of_order             nothing stored; resend from expected_seq
//! same seq, other digest   integrity          the stream is closed permanently
//! ```
//!
//! The last one is not a retry and never becomes one. Two different records
//! claiming one `(stream, seq)` means a bug or an attack, and in both cases the
//! stream's history can no longer be reasoned about as a single sequence.
//! Nothing is repaired, nothing is overwritten: what is stored stays as
//! evidence, and the producer opens a new incarnation to keep logging.

use std::collections::BTreeMap;

use anyhow::Result;
use permguard_core::Jwk;
use permguard_decisions::envelope::{Batch, Envelope};
use permguard_decisions::{chain, merkle, record};
use serde_json::Value;
use tracing::{info, warn};

use super::store::{DecisionStore, StreamState};

const COMPONENT: &str = "control-plane";

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
    /// A record conflicts with one already stored. The stream is now closed.
    Conflict {
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
            Self::Unattributable(detail) => write!(formatter, "{detail}"),
            Self::Unverifiable(detail) => write!(formatter, "{detail}"),
            Self::Conflict { seq } => write!(
                formatter,
                "a different record is already stored at sequence {seq}: this stream is closed permanently and what it holds is kept as evidence"
            ),
            Self::Closed(reason) => write!(
                formatter,
                "this stream was closed permanently ({reason}) and accepts nothing further: open a new incarnation"
            ),
            Self::Unavailable(detail) => write!(formatter, "{detail}"),
        }
    }
}

/// Accepts one signed batch into `store`.
pub fn accept(store: &DecisionStore, batch: &Batch, keys: &[Jwk]) -> Result<Accepted, Refused> {
    let envelope = batch
        .signature
        .verify(keys)
        .map_err(|error| Refused::Unattributable(error.to_string()))?;

    // The key that signed is archived beside what it attests, the first time
    // it is seen: a batch signed today must still verify after that key has
    // been rotated a dozen times.
    if let Ok(protected) = batch.signature.protected()
        && let Some(key) = keys.iter().find(|candidate| candidate.kid == protected.kid)
        && let Err(error) = store.archive_key(key)
    {
        return Err(Refused::Unavailable(error.to_string()));
    }

    // One writer per stream, from the first read of its state to the
    // acknowledgement: ingest is read-check-append across several files, and
    // two batches for one stream interleaving that would corrupt exactly what
    // this store exists to keep whole.
    let gate = store.gate(&envelope.stream.id, &envelope.stream.instance);
    let _writing = match gate.lock() {
        Ok(held) => held,
        Err(poisoned) => poisoned.into_inner(),
    };

    let state = store
        .stream_state(&envelope.stream.id, &envelope.stream.instance)
        .map_err(|error| Refused::Unavailable(error.to_string()))?;
    if let Some(reason) = &state.closed {
        return Err(Refused::Closed(reason.clone()));
    }

    check(batch, &envelope)?;

    // A batch entirely at or below the acknowledged point is a replay: the
    // producer did not hear the answer and sent it again. Deduplicated by
    // `(stream, seq)`, and the acknowledgement does not move.
    if envelope.last_seq <= state.acked {
        return replay(store, batch, &envelope, &state);
    }
    if envelope.first_seq > state.acked + 1 {
        return Ok(Accepted::OutOfOrder {
            expected_seq: state.acked + 1,
        });
    }

    // The part that makes a chain a chain, checked on the batch that actually
    // advances the stream. A batch that overlaps what is already held is
    // checked record by record against it instead, below — its own `prev`
    // belongs to a position this store has moved past.
    if envelope.first_seq == state.acked + 1 {
        continues(&envelope, batch, &state)?;
    }

    // Whatever sits above the acknowledged point was written and never
    // confirmed, so it is scratch: this batch is authoritative for that range.
    // See `DecisionStore::rollback_unacked` for why the alternative is either a
    // duplicated sequence or a spurious conflict.
    let dropped = store
        .rollback_unacked(&envelope.stream.id, &envelope.stream.instance, state.acked)
        .map_err(|error| Refused::Unavailable(error.to_string()))?;
    if dropped > 0 {
        warn!(
            event.name = "decisions.rolled_back",
            component = COMPONENT,
            stream.id = envelope.stream.id.as_str(),
            stream.instance = envelope.stream.instance.as_str(),
            acked = state.acked,
            dropped,
            "records written but never acknowledged were discarded before this batch was appended"
        );
    }

    // The overlap — records at or below `acked` that came again — is checked
    // against what is stored rather than skipped: a producer resending
    // *different* bytes at a sequence already held is the conflict case.
    let held = held_digests(store, &envelope, envelope.first_seq).map_err(Refused::Unavailable)?;
    let mut stored = 0;
    for value in &batch.records {
        let seq = value.get("seq").and_then(Value::as_u64).unwrap_or_default();
        if seq <= state.acked {
            verify_same(store, &held, &envelope, value, seq)?;
            continue;
        }
        store
            .append(&envelope.stream.id, &envelope.stream.instance, value)
            .map_err(|error| Refused::Unavailable(error.to_string()))?;
        stored += 1;
    }

    let signature = serde_json::to_value(&batch.signature).unwrap_or(Value::Null);
    store
        .keep_envelope(
            &envelope.stream.id,
            &envelope.stream.instance,
            envelope.first_seq,
            &signature,
        )
        .map_err(|error| Refused::Unavailable(error.to_string()))?;

    // Only now, and only after everything is flushed, does the producer get a
    // number it may delete by.
    let state = store
        .acknowledge(
            &envelope.stream.id,
            &envelope.stream.instance,
            envelope.last_seq,
            &envelope.head,
        )
        .map_err(|error| Refused::Unavailable(error.to_string()))?;

    info!(
        event.name = "decisions.accepted",
        component = COMPONENT,
        stream.id = envelope.stream.id.as_str(),
        stream.instance = envelope.stream.instance.as_str(),
        first_seq = envelope.first_seq,
        last_seq = envelope.last_seq,
        stored,
        "a decision batch is durable"
    );

    Ok(Accepted::Ok {
        acked: state.acked,
        stored,
    })
}

/// Refuses a batch that does not continue the stream this store already holds.
///
/// The chain is `prev(N) = digest(N − 1)` across a **whole stream**, not inside
/// a batch. Verifying each batch on its own leaves the one link that spans the
/// boundary unchecked — and that link is where a producer's history could be
/// silently replaced with a different one that is internally perfect. A store
/// that only checked sequence numbers would accept it: the numbers would run
/// on, and the digests would not.
///
/// Two statements have to agree, and both are covered by the signature:
/// the envelope's `previous_head` must be the head this store recorded, and the
/// first record's `prev` must be that same digest.
///
/// Only the batch that **advances** the stream is checked this way. One that
/// overlaps what is already held — a replay after a lost acknowledgement — is
/// checked record by record against what is stored, because its own `prev`
/// belongs to a position this store has moved past.
fn continues(envelope: &Envelope, batch: &Batch, state: &StreamState) -> Result<(), Refused> {
    if envelope.previous_head != state.head {
        return Err(Refused::Unverifiable(format!(
            "this batch says it continues {}, and this store's head is {}: a stream whose batches \
             do not join is not a chain",
            envelope.previous_head, state.head
        )));
    }
    // The first record of the batch has to name the same predecessor. The
    // envelope alone would let a producer attest one history and ship another.
    let first_prev = batch
        .records
        .first()
        .and_then(|record| record.get("prev"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    if first_prev != state.head {
        return Err(Refused::Unverifiable(format!(
            "the first record of this batch names {first_prev} as its predecessor, and this \
             store's head is {}",
            state.head
        )));
    }

    Ok(())
}

/// Checks that the records are what the signed envelope says they are.
fn check(batch: &Batch, envelope: &Envelope) -> Result<(), Refused> {
    if batch.records.len() as u64 != envelope.count {
        return Err(Refused::Unverifiable(format!(
            "the envelope attests {} records and the batch carries {}",
            envelope.count,
            batch.records.len()
        )));
    }
    let verified = chain::verify(&batch.records, None)
        .map_err(|error| Refused::Unverifiable(error.to_string()))?;
    if verified.stream != envelope.stream {
        return Err(Refused::Unverifiable(
            "the records belong to a different stream than the envelope attests".to_owned(),
        ));
    }
    if verified.first_seq != envelope.first_seq || verified.last_seq != envelope.last_seq {
        return Err(Refused::Unverifiable(format!(
            "the envelope attests sequences {}..{} and the records span {}..{}",
            envelope.first_seq, envelope.last_seq, verified.first_seq, verified.last_seq
        )));
    }
    if verified.head != envelope.head {
        return Err(Refused::Unverifiable(
            "the head the envelope attests is not the digest of the last record".to_owned(),
        ));
    }

    // The tree is checked too, because it is what a tenant-scoped reader will
    // verify against, and a root nobody checked at ingest is a root a tenant
    // discovers is wrong years later.
    let leaves: Vec<String> = batch
        .records
        .iter()
        .map(|value| record::digest_of(value).unwrap_or_default())
        .collect();
    if merkle::root(&leaves).as_deref() != Some(envelope.merkle_root.as_str()) {
        return Err(Refused::Unverifiable(
            "the Merkle root the envelope attests is not the root of the records it carries"
                .to_owned(),
        ));
    }

    Ok(())
}

/// A batch entirely at or below the acknowledged point.
fn replay(
    store: &DecisionStore,
    batch: &Batch,
    envelope: &Envelope,
    state: &StreamState,
) -> Result<Accepted, Refused> {
    let held = held_digests(store, envelope, envelope.first_seq).map_err(Refused::Unavailable)?;
    for value in &batch.records {
        let seq = value.get("seq").and_then(Value::as_u64).unwrap_or_default();
        verify_same(store, &held, envelope, value, seq)?;
    }

    Ok(Accepted::Ok {
        acked: state.acked,
        stored: 0,
    })
}

/// Refuses a record that disagrees with the one already stored at its sequence.
///
/// `held` is the digest of every record this store still holds at or above the
/// batch's first sequence, read once for the whole batch: reading the store per
/// record would make a replayed batch cost the whole store per line, which is a
/// shape a shipper retrying under load can produce at will.
///
/// A sequence that is acknowledged and no longer held is **not** a fault. This
/// store forgets on a schedule — [`retention`](super::retention) removes whole
/// segments once everything in them is past the window — so "acknowledged and
/// absent" is the ordinary end state of every record, and a shipper replaying
/// an old batch after an outage must not be told the store is broken.
fn verify_same(
    store: &DecisionStore,
    held: &BTreeMap<u64, String>,
    envelope: &Envelope,
    value: &Value,
    seq: u64,
) -> Result<(), Refused> {
    let Some(ours) = held.get(&seq) else {
        return Ok(());
    };
    let theirs =
        record::digest_of(value).map_err(|error| Refused::Unverifiable(error.to_string()))?;
    if ours != &theirs {
        // Nothing is repaired and nothing is overwritten.
        let _ = store.close(
            &envelope.stream.id,
            &envelope.stream.instance,
            "two different records claimed one sequence",
        );
        warn!(
            event.name = "decisions.conflict",
            component = COMPONENT,
            stream.id = envelope.stream.id.as_str(),
            stream.instance = envelope.stream.instance.as_str(),
            seq,
            "a decision stream is closed permanently: its history can no longer be reasoned about as one sequence"
        );

        return Err(Refused::Conflict { seq });
    }

    Ok(())
}

/// The digest of every record this store holds at or above `from`, by sequence.
fn held_digests(
    store: &DecisionStore,
    envelope: &Envelope,
    from: u64,
) -> Result<BTreeMap<u64, String>, String> {
    let scope = super::store::Scope::Stream {
        pdp_id: envelope.stream.id.clone(),
        instance: envelope.stream.instance.clone(),
    };
    let segments = store.segments(&scope).map_err(|error| error.to_string())?;
    // A segment is named by its first sequence, so the one that *contains*
    // `from` is the last one starting at or below it: everything before that is
    // entirely below the range and is not read at all.
    let start = segments
        .iter()
        .rposition(|(first, _)| *first <= from)
        .unwrap_or(0);
    let mut held = BTreeMap::new();
    for (_, path) in segments.iter().skip(start) {
        let (records, _) =
            super::store::read_segment(path, 0, usize::MAX).map_err(|error| error.to_string())?;
        for value in records {
            let Some(seq) = value.get("seq").and_then(Value::as_u64) else {
                continue;
            };
            if seq < from {
                continue;
            }
            let digest = record::digest_of(&value).map_err(|error| error.to_string())?;
            held.insert(seq, digest);
        }
    }

    Ok(held)
}
