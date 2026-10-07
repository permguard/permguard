// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The audit record and a trail's `META.cbor` as canonical CBOR, registered in
//! `contracts/cbor/audit.json` (owner decision of 2026-10-07).
//!
//! The digest is never stored: it is SHA-256 over `digest::AUDIT_RECORD` and the record's
//! canonical bytes, recomputed by every reader, and the next record carries it as `previous`.

use std::collections::BTreeMap;
use std::fmt;

use permguard_core::domains::digest::AUDIT_RECORD;
use permguard_objects::cbor::{self, Value};
use permguard_objects::digest::Digest;
use sha2::{Digest as _, Sha256};

/// The most bytes one record takes on disk, whatever its schema allows.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// The `previous` of a trail's first record: the digest text `sha256:` and 64 zeros.
pub fn genesis() -> Digest {
    // `Digest` reads its canonical text form; 64 zeros is the digest of nothing a record hashes.
    #[allow(clippy::expect_used)]
    Digest::parse(&format!("sha256:{}", "0".repeat(64))).expect("the genesis digest parses")
}

/// One fact's value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactValue {
    Text(String),
    Uint(u64),
    Bool(bool),
}

/// One audit record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// `<class>:<resource>`.
    pub trail: String,
    pub seq: u64,
    pub operation_id: Option<[u8; 16]>,
    pub phase: Option<String>,
    pub host_id: [u8; 16],
    pub boot_id: [u8; 16],
    pub component: String,
    pub action: String,
    pub principal: String,
    pub resource: String,
    pub target: Option<String>,
    pub outcome: String,
    pub facts: BTreeMap<String, FactValue>,
    pub build: String,
    pub config_revision: Digest,
    /// Seconds since the epoch.
    pub at: u64,
    /// Nanoseconds since the process started.
    pub monotonic_offset: u64,
    pub previous: Digest,
}

/// Why a record or a `META.cbor` did not read or write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    TooLarge(usize),
    Cbor(String),
    Malformed(String),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(bytes) => {
                write!(
                    f,
                    "{bytes} bytes; an audit record takes up to {MAX_RECORD_BYTES}"
                )
            }
            Self::Cbor(detail) => write!(f, "not canonical CBOR: {detail}"),
            Self::Malformed(detail) => write!(f, "not an audit record: {detail}"),
        }
    }
}

impl std::error::Error for RecordError {}

type Result<T> = std::result::Result<T, RecordError>;

fn uint(value: u64) -> Result<Value> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| RecordError::Malformed("an integer beyond the signed 64-bit range".to_owned()))
}

impl AuditRecord {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut pairs = vec![
            (Value::Int(1), Value::Text(self.trail.clone())),
            (Value::Int(2), uint(self.seq)?),
        ];
        if let Some(id) = &self.operation_id {
            pairs.push((Value::Int(3), Value::Bytes(id.to_vec())));
        }
        if let Some(phase) = &self.phase {
            pairs.push((Value::Int(4), Value::Text(phase.clone())));
        }
        pairs.extend([
            (Value::Int(5), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(6), Value::Bytes(self.boot_id.to_vec())),
            (Value::Int(7), Value::Text(self.component.clone())),
            (Value::Int(8), Value::Text(self.action.clone())),
            (Value::Int(9), Value::Text(self.principal.clone())),
            (Value::Int(10), Value::Text(self.resource.clone())),
        ]);
        if let Some(target) = &self.target {
            pairs.push((Value::Int(11), Value::Text(target.clone())));
        }
        let facts = self
            .facts
            .iter()
            .map(|(name, value)| {
                Ok((
                    Value::Text(name.clone()),
                    match value {
                        FactValue::Text(text) => Value::Text(text.clone()),
                        FactValue::Uint(number) => uint(*number)?,
                        FactValue::Bool(flag) => Value::Bool(*flag),
                    },
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        pairs.extend([
            (Value::Int(12), Value::Text(self.outcome.clone())),
            (Value::Int(13), Value::Map(facts)),
            (Value::Int(14), Value::Text(self.build.clone())),
            (
                Value::Int(15),
                Value::Text(self.config_revision.to_string()),
            ),
            (Value::Int(16), uint(self.at)?),
            (Value::Int(17), uint(self.monotonic_offset)?),
            (Value::Int(18), Value::Text(self.previous.to_string())),
        ]);
        let bytes =
            cbor::encode(&Value::Map(pairs)).map_err(|e| RecordError::Cbor(e.to_string()))?;
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        Ok(bytes)
    }

    /// The record's digest: SHA-256 over `digest::AUDIT_RECORD` and its canonical bytes.
    pub fn digest(&self) -> Result<Digest> {
        Ok(digest_of(&self.encode()?))
    }

    /// Reads one record's canonical bytes, refusing an unknown label, a missing required one, a
    /// value of another type or more than [`MAX_RECORD_BYTES`].
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value = cbor::decode_canonical(bytes).map_err(|e| RecordError::Cbor(e.to_string()))?;
        Self::from_value(value)
    }

    /// Reads a decoded record.
    pub fn from_value(value: Value) -> Result<Self> {
        let mut map = Labelled::new(value, 18)?;
        let record = Self {
            trail: map.text(1)?,
            seq: map.uint(2)?,
            operation_id: map.optional_bytes(3)?.map(id16).transpose()?,
            phase: map.optional_text(4)?,
            host_id: id16(map.bytes(5)?)?,
            boot_id: id16(map.bytes(6)?)?,
            component: map.text(7)?,
            action: map.text(8)?,
            principal: map.text(9)?,
            resource: map.text(10)?,
            target: map.optional_text(11)?,
            outcome: map.text(12)?,
            facts: map.facts(13)?,
            build: map.text(14)?,
            config_revision: map.digest(15)?,
            at: map.uint(16)?,
            monotonic_offset: map.uint(17)?,
            previous: map.digest(18)?,
        };
        map.finish()?;
        Ok(record)
    }
}

/// SHA-256 over `digest::AUDIT_RECORD` and `bytes`.
pub fn digest_of(bytes: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(AUDIT_RECORD.as_bytes());
    hasher.update(bytes);
    let raw: [u8; 32] = hasher.finalize().into();
    #[allow(clippy::expect_used)]
    Digest::parse(&format!("sha256:{}", hex(&raw))).expect("a SHA-256 renders as a digest")
}

/// A trail's `META.cbor`: the class and the structured resource its digest path stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrailMeta {
    pub class: String,
    pub resource: String,
}

impl TrailMeta {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>> {
        cbor::encode(&Value::Map(vec![
            (Value::Int(1), Value::Text(self.class.clone())),
            (Value::Int(2), Value::Text(self.resource.clone())),
        ]))
        .map_err(|e| RecordError::Cbor(e.to_string()))
    }

    /// Reads the canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value = cbor::decode_canonical(bytes).map_err(|e| RecordError::Cbor(e.to_string()))?;
        let mut map = Labelled::new(value, 2)?;
        let meta = Self {
            class: map.text(1)?,
            resource: map.text(2)?,
        };
        map.finish()?;
        Ok(meta)
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn id16(bytes: Vec<u8>) -> Result<[u8; 16]> {
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| RecordError::Malformed("an identifier is 16 bytes".to_owned()))
}

struct Labelled {
    pairs: BTreeMap<i64, Value>,
}

impl Labelled {
    fn new(value: Value, highest: i64) -> Result<Self> {
        let Value::Map(pairs) = value else {
            return Err(RecordError::Malformed("the root is a map".to_owned()));
        };
        let mut labelled = BTreeMap::new();
        for (key, value) in pairs {
            let Value::Int(label) = key else {
                return Err(RecordError::Malformed("labels are integers".to_owned()));
            };
            if label < 1 || label > highest {
                return Err(RecordError::Malformed(format!("unknown label {label}")));
            }
            labelled.insert(label, value);
        }
        Ok(Self { pairs: labelled })
    }

    fn take(&mut self, label: i64) -> Result<Value> {
        self.pairs
            .remove(&label)
            .ok_or_else(|| RecordError::Malformed(format!("label {label} is required")))
    }

    fn text(&mut self, label: i64) -> Result<String> {
        match self.take(label)? {
            Value::Text(text) => Ok(text),
            _ => Err(RecordError::Malformed(format!("label {label} is text"))),
        }
    }

    fn optional_text(&mut self, label: i64) -> Result<Option<String>> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Text(text)) => Ok(Some(text)),
            Some(_) => Err(RecordError::Malformed(format!("label {label} is text"))),
        }
    }

    fn bytes(&mut self, label: i64) -> Result<Vec<u8>> {
        match self.take(label)? {
            Value::Bytes(bytes) => Ok(bytes),
            _ => Err(RecordError::Malformed(format!("label {label} is bytes"))),
        }
    }

    fn optional_bytes(&mut self, label: i64) -> Result<Option<Vec<u8>>> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Bytes(bytes)) => Ok(Some(bytes)),
            Some(_) => Err(RecordError::Malformed(format!("label {label} is bytes"))),
        }
    }

    fn uint(&mut self, label: i64) -> Result<u64> {
        match self.take(label)? {
            Value::Int(value) if value >= 0 => Ok(value as u64),
            _ => Err(RecordError::Malformed(format!(
                "label {label} is an unsigned integer"
            ))),
        }
    }

    fn digest(&mut self, label: i64) -> Result<Digest> {
        Digest::parse(&self.text(label)?)
            .map_err(|e| RecordError::Malformed(format!("label {label}: {e}")))
    }

    fn facts(&mut self, label: i64) -> Result<BTreeMap<String, FactValue>> {
        match self.take(label)? {
            Value::Map(pairs) => pairs
                .into_iter()
                .map(|(key, value)| {
                    let Value::Text(name) = key else {
                        return Err(RecordError::Malformed(format!(
                            "label {label} has text keys"
                        )));
                    };
                    let value = match value {
                        Value::Text(text) => FactValue::Text(text),
                        Value::Int(number) if number >= 0 => FactValue::Uint(number as u64),
                        Value::Bool(flag) => FactValue::Bool(flag),
                        _ => {
                            return Err(RecordError::Malformed(format!(
                                "the fact `{name}` is text, an unsigned integer or a boolean"
                            )));
                        }
                    };
                    Ok((name, value))
                })
                .collect(),
            _ => Err(RecordError::Malformed(format!("label {label} is a map"))),
        }
    }

    fn finish(self) -> Result<()> {
        match self.pairs.keys().next() {
            None => Ok(()),
            Some(label) => Err(RecordError::Malformed(format!("unexpected label {label}"))),
        }
    }
}
