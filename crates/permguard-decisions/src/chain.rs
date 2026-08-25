// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The producer chain: `prev(N) = digest(N − 1)`, spanning a whole stream.
//!
//! Batches and segments are transport and storage boundaries. Integrity must
//! not depend on where they happen to fall, so the chain crosses them: a
//! verifier that holds a contiguous run of records checks it the same way
//! whether those records arrived in one batch or in fifty.
//!
//! # What a verified run means
//!
//! That the records are **contiguous**, in order, from one stream, and that
//! each names the one before it. It does not, on its own, say the run started
//! where the stream started — that is what [`Verified::from_genesis`] answers,
//! and it is a different question a caller must ask deliberately.

use std::fmt;

use serde_json::Value;

use crate::record::{DigestError, GENESIS, Stream, digest_of};

/// What a verified run establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verified {
    /// Whose history this is.
    pub stream: Stream,
    /// The first sequence in the run.
    pub first_seq: u64,
    /// The last sequence in the run.
    pub last_seq: u64,
    /// The digest of the last record — one value standing for all of them.
    pub head: String,
    /// Whether the run begins at the stream's genesis.
    pub from_genesis: bool,
}

/// Why a run of records is not a chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// Nothing to verify. A caller asking about an empty run has a bug.
    Empty,
    /// A record is not an object with the fields every record carries.
    Malformed { at: usize, detail: String },
    /// Two records claim different streams.
    StreamChanged { at: u64 },
    /// A sequence that does not follow the one before it.
    NotContiguous { expected: u64, found: u64 },
    /// `prev` does not name the record before it.
    Broken {
        seq: u64,
        expected: String,
        found: String,
    },
    /// A schema version this build cannot verify.
    Version { seq: u64, version: u64 },
    /// A record whose digest could not be taken.
    Digest(DigestError),
}

impl fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(formatter, "there are no records to verify"),
            Self::Malformed { at, detail } => {
                write!(
                    formatter,
                    "the record at position {at} is malformed: {detail}"
                )
            }
            Self::StreamChanged { at } => write!(
                formatter,
                "the record at sequence {at} belongs to a different stream: a chain is one producer's history"
            ),
            Self::NotContiguous { expected, found } => write!(
                formatter,
                "expected sequence {expected} and found {found}: a verified run has no holes"
            ),
            Self::Broken {
                seq,
                expected,
                found,
            } => write!(
                formatter,
                "the record at sequence {seq} names {found} as its predecessor, but the record before it digests to {expected}"
            ),
            Self::Version { seq, version } => write!(
                formatter,
                "the record at sequence {seq} is version {version}, which this build cannot verify"
            ),
            Self::Digest(error) => write!(formatter, "{error}"),
        }
    }
}

impl std::error::Error for ChainError {}

/// Verifies a contiguous run of records, in order.
///
/// `expected_prev` is what the first record must name: the digest a caller
/// already holds, or `None` to accept whatever the run begins with — which is
/// how a reader that starts mid-stream checks the part it has.
pub fn verify(records: &[Value], expected_prev: Option<&str>) -> Result<Verified, ChainError> {
    let first = records.first().ok_or(ChainError::Empty)?;
    let stream = stream_of(first, 0)?;
    let mut previous: Option<(u64, String)> = None;
    let mut first_seq = 0;
    let mut from_genesis = false;

    for (index, record) in records.iter().enumerate() {
        let seq = field_u64(record, "seq", index)?;
        let version = field_u64(record, "v", index)?;
        if version != u64::from(crate::record::VERSION) {
            return Err(ChainError::Version { seq, version });
        }
        if stream_of(record, index)? != stream {
            return Err(ChainError::StreamChanged { at: seq });
        }
        let prev = field_str(record, "prev", index)?.to_owned();

        match &previous {
            None => {
                first_seq = seq;
                from_genesis = prev == GENESIS && seq == 1;
                if let Some(expected) = expected_prev
                    && expected != prev
                {
                    return Err(ChainError::Broken {
                        seq,
                        expected: expected.to_owned(),
                        found: prev.clone(),
                    });
                }
            }
            Some((last_seq, last_digest)) => {
                if seq != last_seq + 1 {
                    return Err(ChainError::NotContiguous {
                        expected: last_seq + 1,
                        found: seq,
                    });
                }
                if &prev != last_digest {
                    return Err(ChainError::Broken {
                        seq,
                        expected: last_digest.clone(),
                        found: prev,
                    });
                }
            }
        }

        let digest = digest_of(record).map_err(ChainError::Digest)?;
        previous = Some((seq, digest));
    }

    let (last_seq, head) = previous.ok_or(ChainError::Empty)?;

    Ok(Verified {
        stream,
        first_seq,
        last_seq,
        head,
        from_genesis,
    })
}

fn stream_of(record: &Value, index: usize) -> Result<Stream, ChainError> {
    let stream = record.get("stream").ok_or_else(|| ChainError::Malformed {
        at: index,
        detail: "no `stream`".to_owned(),
    })?;

    serde_json::from_value(stream.clone()).map_err(|error| ChainError::Malformed {
        at: index,
        detail: format!("`stream` is not an identity: {error}"),
    })
}

fn field_u64(record: &Value, name: &str, index: usize) -> Result<u64, ChainError> {
    record
        .get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| ChainError::Malformed {
            at: index,
            detail: format!("no `{name}`, or not a whole number"),
        })
}

fn field_str<'a>(record: &'a Value, name: &str, index: usize) -> Result<&'a str, ChainError> {
    record
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| ChainError::Malformed {
            at: index,
            detail: format!("no `{name}`, or not a string"),
        })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::record::{
        Body, Build, Commitments, MarkerBody, Record, Sampling, Stream as StreamId, VERSION,
    };

    fn run(count: u64) -> Vec<Value> {
        let mut records = Vec::new();
        let mut prev = GENESIS.to_owned();
        for seq in 1..=count {
            let record = Record {
                v: VERSION,
                stream: StreamId::new("plane", "inst"),
                seq,
                prev: prev.clone(),
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
            };
            prev = record.digest().expect("it digests");
            records.push(record.to_value().expect("it renders"));
        }

        records
    }

    #[test]
    fn test_a_whole_stream_verifies_and_knows_it_started_at_the_genesis() {
        let verified = verify(&run(5), None).expect("it verifies");

        assert_eq!((verified.first_seq, verified.last_seq), (1, 5));
        assert!(verified.from_genesis);
    }

    #[test]
    fn test_a_missing_record_is_refused_as_a_hole_not_repaired() {
        let mut records = run(5);
        records.remove(2);

        assert_eq!(
            verify(&records, None),
            Err(ChainError::NotContiguous {
                expected: 3,
                found: 4
            })
        );
    }

    #[test]
    fn test_one_altered_field_breaks_the_link_that_follows_it() {
        let mut records = run(4);
        records[1]["at"] = serde_json::json!("2030-01-01T00:00:00Z");

        assert!(matches!(
            verify(&records, None),
            Err(ChainError::Broken { seq: 3, .. })
        ));
    }

    #[test]
    fn test_a_run_that_starts_mid_stream_is_checked_against_what_the_caller_holds() {
        let records = run(6);
        let head_of_three = verify(&records[..3], None).expect("it verifies").head;

        let tail = verify(&records[3..], Some(&head_of_three)).expect("it continues");
        assert_eq!(tail.first_seq, 4);
        assert!(!tail.from_genesis, "it did not begin at the genesis");

        assert!(
            matches!(
                verify(&records[3..], Some("sha256:dead")),
                Err(ChainError::Broken { seq: 4, .. })
            ),
            "a run that does not continue what the caller holds is refused"
        );
    }

    #[test]
    fn test_records_from_two_streams_are_not_one_chain() {
        let mut records = run(3);
        records[2]["stream"]["instance"] = serde_json::json!("other");

        assert_eq!(
            verify(&records, None),
            Err(ChainError::StreamChanged { at: 3 })
        );
    }

    #[test]
    fn test_an_empty_run_is_an_error_not_a_vacuous_success() {
        assert_eq!(verify(&[], None), Err(ChainError::Empty));
    }
}
