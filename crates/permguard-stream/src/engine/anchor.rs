// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! A stream's prefix anchor (WP-5.6; owner decisions of 2026-10-15 and 2026-10-17): what a run
//! keeps of the records it deleted, so a replay below its low watermark is proved equal or
//! answered `gone`, never taken for complete.
//!
//! | Label           | Meaning                                                                  |
//! | --------------- | ------------------------------------------------------------------------ |
//! | 1 resource      | the stream's canonical resource                                          |
//! | 2 run           | the run whose prefix went                                                |
//! | 3 low_watermark | the first sequence still kept: `through + 1`                             |
//! | 4 through       | the last sequence deleted, the end of a whole batch                      |
//! | 5 terminal_head | the record digest at `through`, as a batch envelope spells it            |
//! | 6 covering      | the digest of every deleted batch file's envelope, in sequence order     |
//! | 7 signers       | the run's signer spans covering sequences 1 through `through`            |
//! | 8 checkpoint    | the producer-signed batch file ending at `through`, kept whole           |
//!
//! An anchor is cumulative: each deletion of a run rewrites it from sequence 1 to its new
//! `through`, so one file answers for everything the run no longer holds. It is written and
//! flushed before anything it covers is deleted.

use permguard_objects::cbor::Value;

use super::StreamError;
use super::codec::{Map, encode, uint};
use super::producer::Span;

/// The most bytes an anchor takes: a checkpoint batch and a digest per deleted batch.
pub const MAX_ANCHOR_BYTES: usize = 32 * 1024 * 1024;

/// The file a run's anchor is kept in.
pub const ANCHOR: &str = "ANCHOR";

/// The digest an anchor covers a batch by: the SHA-256 of its signed envelope, which binds the
/// stream, the run and the range.
pub fn envelope_digest(envelope: &super::batch::Envelope) -> Result<String, StreamError> {
    use sha2::Digest as _;
    Ok(format!(
        "sha256:{}",
        super::hex(&sha2::Sha256::digest(envelope.signed_bytes()?))
    ))
}

/// The anchor kept in `dir`, when a prefix went.
pub(crate) fn anchor_in(dir: &permguard_host::storage::Dir) -> Result<Option<Anchor>, StreamError> {
    permguard_host::storage::write::read_view(dir, ANCHOR, permguard_host::storage::format::VIEW)?
        .map(|bytes| Anchor::decode(&bytes))
        .transpose()
}

/// What a read answers (WP-5.6c): the records from the first sequence still held, and the gap
/// below it when the read started there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<R> {
    pub records: Vec<(u64, R)>,
    pub gap: Option<Gap>,
}

/// A deleted prefix a read reached: never answered as complete.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Gap {
    /// The first sequence still held.
    pub low_watermark: u64,
    /// What the run keeps of what went.
    pub anchor: Anchor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub resource: String,
    pub run: [u8; 16],
    pub low_watermark: u64,
    pub through: u64,
    pub terminal_head: String,
    pub covering: Vec<String>,
    pub signers: Vec<Span>,
    pub checkpoint: Vec<u8>,
}

fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    })
}

impl Anchor {
    /// The anchor's bytes; refused, so nothing it would cover is deleted, when it would not read
    /// back: past [`MAX_ANCHOR_BYTES`], or not covering sequences 1 through `through` (after the
    /// review).
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let bytes = self.encode_unchecked()?;
        if bytes.len() > MAX_ANCHOR_BYTES {
            return Err(StreamError::Invalid(format!(
                "the run's anchor would take {} bytes, past its bound of {MAX_ANCHOR_BYTES}: \
                 nothing more of the run is deleted",
                bytes.len()
            )));
        }
        Self::decode(&bytes)?;
        Ok(bytes)
    }

    fn encode_unchecked(&self) -> Result<Vec<u8>, StreamError> {
        let mut signers = Vec::with_capacity(self.signers.len());
        for span in &self.signers {
            signers.push(Value::Map(vec![
                (Value::Int(1), uint(span.from_seq)?),
                (Value::Int(2), Value::Text(span.kid.clone())),
                (Value::Int(3), Value::Text(span.jwk.clone())),
            ]));
        }
        encode(vec![
            (1, Value::Text(self.resource.clone())),
            (2, Value::Bytes(self.run.to_vec())),
            (3, uint(self.low_watermark)?),
            (4, uint(self.through)?),
            (5, Value::Text(self.terminal_head.clone())),
            (
                6,
                Value::Array(self.covering.iter().cloned().map(Value::Text).collect()),
            ),
            (7, Value::Array(signers)),
            (8, Value::Bytes(self.checkpoint.clone())),
        ])
    }

    // conformance: boundary
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_ANCHOR_BYTES {
            return Err(StreamError::Invalid(
                "an anchor is out of its bound".to_owned(),
            ));
        }
        let mut map = Map::read(bytes, "a stream anchor")?;
        let resource = map.text(1)?;
        let run = map.fixed(2)?;
        let low_watermark = map.uint(3)?;
        let through = map.uint(4)?;
        let terminal_head = map.text(5)?;
        let mut covering = Vec::new();
        for value in map.array(6)? {
            let Value::Text(digest) = value else {
                return Err(StreamError::Invalid(
                    "an anchor covers digests, as text".to_owned(),
                ));
            };
            covering.push(digest);
        }
        let mut signers: Vec<Span> = Vec::new();
        for value in map.array(7)? {
            let mut span = Map::of(value, "an anchor's signer span")?;
            let read = Span {
                from_seq: span.uint(1)?,
                kid: span.text(2)?,
                jwk: span.text(3)?,
            };
            span.finish()?;
            if signers
                .last()
                .map_or(read.from_seq != 1, |last| last.from_seq >= read.from_seq)
            {
                return Err(StreamError::Invalid(
                    "an anchor's signer spans start at 1, each after the one before".to_owned(),
                ));
            }
            signers.push(read);
        }
        let checkpoint = map.bytes(8)?;
        map.finish()?;
        if through == 0
            || low_watermark != through + 1
            || covering.is_empty()
            || signers.is_empty()
            || !is_digest(&terminal_head)
            || !covering.iter().all(|held| is_digest(held))
        {
            return Err(StreamError::Invalid(
                "an anchor covers sequences 1 through `through`, keeps from the next, and names \
                 the batches and keys that held them"
                    .to_owned(),
            ));
        }
        Ok(Self {
            resource,
            run,
            low_watermark,
            through,
            terminal_head,
            covering,
            signers,
            checkpoint,
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn anchor() -> Anchor {
        Anchor {
            resource: "plane/data/zone/z/ledger/l".to_owned(),
            run: [3; 16],
            low_watermark: 5,
            through: 4,
            terminal_head: format!("sha256:{}", "a".repeat(64)),
            covering: vec![format!("sha256:{}", "b".repeat(64))],
            signers: vec![Span {
                from_seq: 1,
                kid: "kid".to_owned(),
                jwk: "{}".to_owned(),
            }],
            checkpoint: vec![9; 8],
        }
    }

    /// WP-5.6b: an anchor reads back as it was written, and one that would not read back is
    /// refused when written: past its bound, not covering from 1, or not keeping from `through + 1`.
    #[test]
    fn an_anchor_is_written_only_when_it_reads_back() {
        let held = anchor();
        assert_eq!(
            Anchor::decode(&held.encode().expect("encodes")).expect("decodes"),
            held
        );
        let refused = [
            Anchor {
                checkpoint: vec![0; MAX_ANCHOR_BYTES],
                ..anchor()
            },
            Anchor {
                low_watermark: 4,
                ..anchor()
            },
            Anchor {
                through: 0,
                low_watermark: 1,
                ..anchor()
            },
            Anchor {
                covering: Vec::new(),
                ..anchor()
            },
            Anchor {
                signers: Vec::new(),
                ..anchor()
            },
            Anchor {
                signers: vec![Span {
                    from_seq: 2,
                    kid: "kid".to_owned(),
                    jwk: "{}".to_owned(),
                }],
                ..anchor()
            },
            Anchor {
                terminal_head: "sha256:XYZ".to_owned(),
                ..anchor()
            },
            Anchor {
                covering: vec![format!("sha256:{}", "B".repeat(64))],
                ..anchor()
            },
        ];
        for (at, anchor) in refused.iter().enumerate() {
            assert!(anchor.encode().is_err(), "case {at}");
            if let Ok(bytes) = anchor.encode_unchecked() {
                assert!(Anchor::decode(&bytes).is_err(), "case {at}");
            }
        }
    }
}
