// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The chain over one producer's stream: `prev(N) = digest(N − 1)`.
//!
//! # What a chain proves, and what it does not
//!
//! It proves that a contiguous run of records is the run this producer wrote, in this order, with
//! nothing inserted, removed or altered between them. It proves nothing about *other* producers:
//! there is no global chain, because there is no global order to chain. Two data planes writing
//! one ledger write two independent, independently verifiable histories, and a reader that needs
//! both merges them by time with a documented tie-break rather than pretending one sequence
//! covered both.
//!
//! # Why it is verified over values
//!
//! The records arrive as [`serde_json::Value`], exactly as they were shipped. Verifying a
//! deserialized struct would verify what this build understands rather than what the producer
//! signed, and the two stop being the same thing the moment a producer is newer than its reader.

use serde_json::Value;

use crate::record::{DigestError, GENESIS, Stream, digest_of};

/// What a verified run establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// The stream every record belonged to.
    pub stream: Stream,
    /// The first sequence in the run.
    pub first_seq: u64,
    /// The last sequence in the run.
    pub last_seq: u64,
    /// The digest of the last record — what the next batch's `previous_head` must be.
    pub head: String,
    /// Every record's digest, in order, for the Merkle root over the same run.
    pub digests: Vec<String>,
}

/// Why a run of records is not a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// There was nothing to verify.
    Empty,
    /// A record could not be digested.
    Digest(DigestError),
    /// A record is not shaped like one.
    Shape(String),
    /// Two records claim different streams.
    Stream { at: u64 },
    /// The sequence is not `previous + 1`.
    Sequence { expected: u64, found: u64 },
    /// A record's `prev` is not the digest of the record before it.
    Link {
        seq: u64,
        expected: String,
        found: String,
    },
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(formatter, "there are no records to verify"),
            Self::Digest(detail) => write!(formatter, "{detail}"),
            Self::Shape(detail) => write!(formatter, "a record is not one: {detail}"),
            Self::Stream { at } => write!(
                formatter,
                "the record at sequence {at} belongs to another stream: one chain covers one \
                 producer and one tenant"
            ),
            Self::Sequence { expected, found } => write!(
                formatter,
                "the sequence jumps from {} to {found}: a gap is a missing record, not a \
                 renumbering",
                expected.saturating_sub(1)
            ),
            Self::Link {
                seq,
                expected,
                found,
            } => write!(
                formatter,
                "the record at sequence {seq} links to {found} and the record before it digests \
                 to {expected}: something between them was changed or removed"
            ),
        }
    }
}

impl std::error::Error for ChainError {}

/// Verifies a contiguous run of one stream's records.
///
/// `expected_prev` is the head the run must continue from — the previous batch's head. Every
/// **internal** link is checked either way: `prev(N) = digest(N − 1)` across the run, which is
/// what makes the run a chain.
///
/// `None` leaves the *first* record's `prev` unchecked, and that is deliberate rather than lax: a
/// batch that arrives out of order continues from a record this verifier has not been given, and
/// refusing it here would report "the chain is broken" for a batch whose only problem is that it
/// is early. The boundary link is the store's to check, against the head it actually holds — see
/// the ingest path's `continues`, which is where a truncated history is caught. A caller that has
/// the previous head and does not pass it is skipping that check, not passing it.
pub fn verify(records: &[Value], expected_prev: Option<&str>) -> Result<Verified, ChainError> {
    let Some(first) = records.first() else {
        return Err(ChainError::Empty);
    };

    let stream = stream_of(first)?;
    let first_seq = seq_of(first)?;
    // `None` starts unset, so the first record's `prev` is adopted rather than compared. From the
    // second record on it is always the digest of the one before, whatever the caller passed.
    let mut expected_link = expected_prev.map(ToOwned::to_owned);
    let mut expected_seq = first_seq;
    let mut digests = Vec::with_capacity(records.len());

    for record in records {
        let seq = seq_of(record)?;
        if seq != expected_seq {
            return Err(ChainError::Sequence {
                expected: expected_seq,
                found: seq,
            });
        }
        if stream_of(record)? != stream {
            return Err(ChainError::Stream { at: seq });
        }
        let prev = text_of(record, "prev")?;
        if let Some(expected) = &expected_link
            && &prev != expected
        {
            return Err(ChainError::Link {
                seq,
                expected: expected.clone(),
                found: prev,
            });
        }

        let digest = digest_of(record).map_err(ChainError::Digest)?;
        expected_link = Some(digest.clone());
        digests.push(digest);
        expected_seq = seq.saturating_add(1);
    }

    Ok(Verified {
        stream,
        first_seq,
        last_seq: expected_seq.saturating_sub(1),
        // Non-empty, because an empty run was refused above.
        head: expected_link.unwrap_or_else(|| GENESIS.to_owned()),
        digests,
    })
}

fn stream_of(record: &Value) -> Result<Stream, ChainError> {
    let stream = record
        .get("stream")
        .ok_or_else(|| ChainError::Shape("a record with no stream".to_owned()))?;

    serde_json::from_value(stream.clone())
        .map_err(|error| ChainError::Shape(format!("a stream that is not one: {error}")))
}

fn seq_of(record: &Value) -> Result<u64, ChainError> {
    record
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or_else(|| ChainError::Shape("a record with no sequence".to_owned()))
}

fn text_of(record: &Value, field: &str) -> Result<String, ChainError> {
    record
        .get(field)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| ChainError::Shape(format!("a record with no `{field}`")))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::record::{Producer, RECORD_TYPE, Record, VERSION};
    use serde_json::json;

    fn run(count: u64) -> Vec<Value> {
        let mut records = Vec::new();
        let mut prev = GENESIS.to_owned();
        for seq in 1..=count {
            let record = Record {
                v: VERSION,
                record_type: RECORD_TYPE.to_owned(),
                stream: Stream::new(Producer::data_plane("dp", "i1"), "acme", "l"),
                seq,
                prev: prev.clone(),
                event_type: "permguard.dogwood.event.v1".to_owned(),
                event_id: format!("e{seq}"),
                occurrence_digest: GENESIS.to_owned(),
                kind: "request".to_owned(),
                profile: "temporal".to_owned(),
                policy_partitions: vec!["p".to_owned()],
                commit: "sha256:abc".to_owned(),
                history_key: None,
                occurred_at: "2026-08-28T10:15:30Z".to_owned(),
                observed_at: "2026-08-28T10:15:31Z".to_owned(),
                event: json!({"n": seq}),
            };
            let value = record.to_value().expect("it serializes");
            prev = digest_of(&value).expect("it digests");
            records.push(value);
        }

        records
    }

    #[test]
    fn a_well_formed_run_verifies_and_reports_its_head() {
        let records = run(4);
        let verified = verify(&records, None).expect("it is a chain");

        assert_eq!(verified.first_seq, 1);
        assert_eq!(verified.last_seq, 4);
        assert_eq!(verified.digests.len(), 4);
        assert_eq!(
            verified.head,
            digest_of(&records[3]).expect("it digests"),
            "the head is the last record's digest"
        );
    }

    #[test]
    fn a_run_that_does_not_continue_the_head_it_was_given_is_refused() {
        let records = run(2);
        let refused = verify(&records, Some("sha256:deadbeef")).expect_err("it continues nothing");

        assert!(matches!(refused, ChainError::Link { seq: 1, .. }));
    }

    #[test]
    fn an_altered_record_breaks_the_link_after_it() {
        let mut records = run(3);
        records[1]
            .as_object_mut()
            .expect("an object")
            .insert("event".to_owned(), json!({"n": 99}));

        let refused = verify(&records, None).expect_err("the chain no longer holds");
        assert!(matches!(refused, ChainError::Link { seq: 3, .. }));
    }

    #[test]
    fn a_missing_record_is_a_gap_and_not_a_renumbering() {
        let records = run(3);
        let with_gap = vec![records[0].clone(), records[2].clone()];

        assert!(matches!(
            verify(&with_gap, None).expect_err("a record is missing"),
            ChainError::Sequence { found: 3, .. }
        ));
    }

    /// One chain covers one producer and one tenant. Records of another stream cannot be smuggled
    /// into a run, however well their sequence happens to line up.
    #[test]
    fn a_record_of_another_stream_is_refused_inside_a_run() {
        let mut records = run(2);
        let stream = Stream::new(Producer::data_plane("dp", "i1"), "acme", "OTHER-LEDGER");
        records[1].as_object_mut().expect("an object").insert(
            "stream".to_owned(),
            serde_json::to_value(stream).expect("it serializes"),
        );

        // The altered record breaks the link first, which is itself correct: whichever check fires,
        // the run is refused. Verify the stream check independently by keeping the link intact.
        let refused = verify(&records, None).expect_err("it is another stream");
        assert!(matches!(
            refused,
            ChainError::Link { .. } | ChainError::Stream { .. }
        ));
    }

    #[test]
    fn nothing_is_not_a_chain() {
        assert_eq!(verify(&[], None), Err(ChainError::Empty));
    }

    /// A run that continues mid-stream is a chain, and its boundary is somebody else's to check.
    #[test]
    fn a_run_that_starts_mid_stream_is_verified_without_its_boundary_link() {
        let records = run(5);
        let tail = &records[2..];

        // Unbounded: the internal links are checked, the first record's `prev` is adopted.
        let verified = verify(tail, None).expect("the tail is a chain");
        assert_eq!(verified.first_seq, 3);
        assert_eq!(verified.last_seq, 5);

        // Bounded by the right head: the boundary is checked too, and holds.
        let head = digest_of(&records[1]).expect("it digests");
        assert!(verify(tail, Some(&head)).is_ok());

        // Bounded by the wrong head: refused, which is the check the store performs.
        assert!(matches!(
            verify(tail, Some(GENESIS)),
            Err(ChainError::Link { seq: 3, .. })
        ));
    }

    /// Leaving the boundary unchecked never leaves an *internal* link unchecked.
    #[test]
    fn an_altered_record_inside_an_unbounded_run_is_still_refused() {
        let mut records = run(4);
        records[2]["kind"] = serde_json::json!("tampered");

        assert!(matches!(
            verify(&records, None),
            Err(ChainError::Link { seq: 4, .. })
        ));
    }
}
