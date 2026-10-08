// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The grant record and the journal transitions, byte for byte (owner decision, 2026-10-06).
//!
//! A grant record is a closed CBOR map with integer labels, in the blueprint's member order:
//!
//! | Label | Member           | Type                     |
//! | ----- | ---------------- | ------------------------ |
//! | 1     | `grant_id`       | bytes, 16, a UUID        |
//! | 2     | `principal_id`   | text                     |
//! | 3     | `operations`     | array of text            |
//! | 4     | `selector`       | text                     |
//! | 5     | `resource_types` | array of text            |
//! | 6     | `constraints`    | map of text to text      |
//! | 7     | `revision`       | uint                     |
//! | 8     | `status`         | text: active, revoked, expired |
//! | 9     | `issued_by`      | text                     |
//! | 10    | `issued_at`      | uint, seconds UTC        |
//! | 11    | `expires_at`     | uint, seconds UTC, optional |
//! | 12    | `operation_id`   | bytes, 16, optional: the mutation that issued it (WP-3.6) |
//!
//! The journal carries three frame kinds: `1` issue, whose payload is the record; `2` revoke and
//! `3` expire, whose payload is a [`Transition`]: `{1: grant_id, 2: revision, 3: at, 4: by,
//! 5?: operation_id}`. The operation id is how recovery of the mutation journal learns that a
//! grant mutation was applied (owner decision of 2026-10-07); a frame written before WP-3.6 has
//! none and reads as before.
//! `contracts/cbor/grant.json` registers both maps; a label, once registered, keeps its meaning.

use std::collections::BTreeMap;
use std::fmt;

use permguard_core::authz::{Allow, Principal, Selector};
use permguard_objects::cbor::{self, Value};

use crate::operations::journal::OperationId;

/// A grant record larger than this is refused before it is parsed: the longest record a
/// deployment can write is a few kilobytes of operations and types.
pub const MAX_RECORD_BYTES: usize = 64 * 1024;

/// The journal frame kinds.
pub const FRAME_ISSUE: u16 = 1;
pub const FRAME_REVOKE: u16 = 2;
pub const FRAME_EXPIRE: u16 = 3;

/// A permanent grant identity: 16 random bytes, written as 32 lowercase hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GrantId([u8; 16]);

impl GrantId {
    /// From its bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// Reads the 32-character hex form.
    pub fn parse(text: &str) -> Result<Self, RecordError> {
        let text = text.trim();
        if text.len() != 32 || !text.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(RecordError::Malformed(format!(
                "`{text}` is not a grant id: 32 hex characters"
            )));
        }
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
                .map_err(|_| RecordError::Malformed("a grant id is hex".to_owned()))?;
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for GrantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GrantId({self})")
    }
}

/// Where a grant is in its life. Revocation is terminal; expiry is terminal too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Active,
    Revoked,
    Expired,
}

impl Status {
    /// The status as the record spells it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }

    fn parse(text: &str) -> Result<Self, RecordError> {
        match text {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            "expired" => Ok(Self::Expired),
            other => Err(RecordError::Malformed(format!("`{other}` is not a status"))),
        }
    }
}

/// One grant, as the journal and the snapshot hold it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantRecord {
    pub grant_id: GrantId,
    pub principal_id: Principal,
    pub operations: Vec<String>,
    pub selector: Selector,
    pub resource_types: Vec<String>,
    pub constraints: BTreeMap<String, String>,
    pub revision: u64,
    pub status: Status,
    pub issued_by: String,
    pub issued_at: u64,
    pub expires_at: Option<u64>,
    /// The mutation that issued it; absent on a grant issued before WP-3.6.
    pub operation_id: Option<OperationId>,
}

impl GrantRecord {
    /// Whether the grant allows anything at `now`: active, and not past its expiry.
    pub fn is_active_at(&self, now: u64) -> bool {
        self.status == Status::Active && self.expires_at.is_none_or(|until| now < until)
    }

    /// The allows this record unfolds to: one per operation and resource type.
    pub fn allows(&self) -> Vec<Allow> {
        let mut allows = Vec::with_capacity(self.operations.len() * self.resource_types.len());
        for operation in &self.operations {
            for resource_type in &self.resource_types {
                allows.push(Allow {
                    principal: self.principal_id.clone(),
                    operation: operation.clone(),
                    selector: self.selector.clone(),
                    resource_type: resource_type.clone(),
                });
            }
        }
        allows
    }

    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(self.grant_id.0.to_vec())),
            (
                Value::Int(2),
                Value::Text(self.principal_id.as_str().to_owned()),
            ),
            (Value::Int(3), texts(&self.operations)),
            (Value::Int(4), Value::Text(self.selector.to_string())),
            (Value::Int(5), texts(&self.resource_types)),
            (
                Value::Int(6),
                Value::Map(
                    self.constraints
                        .iter()
                        .map(|(key, value)| (Value::Text(key.clone()), Value::Text(value.clone())))
                        .collect(),
                ),
            ),
            (Value::Int(7), uint(self.revision)?),
            (Value::Int(8), Value::Text(self.status.as_str().to_owned())),
            (Value::Int(9), Value::Text(self.issued_by.clone())),
            (Value::Int(10), uint(self.issued_at)?),
        ];
        if let Some(until) = self.expires_at {
            pairs.push((Value::Int(11), uint(until)?));
        }
        if let Some(operation_id) = self.operation_id {
            pairs.push((
                Value::Int(12),
                Value::Bytes(operation_id.as_bytes().to_vec()),
            ));
        }
        cbor::encode(&Value::Map(pairs)).map_err(|error| RecordError::Cbor(error.to_string()))
    }

    /// Reads the canonical bytes, refusing an unknown label, a missing required one, a value of
    /// another type, or more than [`MAX_RECORD_BYTES`].
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value =
            cbor::decode_canonical(bytes).map_err(|error| RecordError::Cbor(error.to_string()))?;
        let mut map = Labelled::new(value, 12)?;
        let grant_id = map.bytes(1)?;
        let grant_id: [u8; 16] = grant_id
            .as_slice()
            .try_into()
            .map_err(|_| RecordError::Malformed("grant_id is 16 bytes".to_owned()))?;
        let principal_id = Principal::new(map.text(2)?)
            .map_err(|error| RecordError::Malformed(format!("principal_id: {error}")))?;
        let operations = map.texts(3)?;
        let selector = Selector::parse(&map.text(4)?)
            .map_err(|error| RecordError::Malformed(format!("selector: {error}")))?;
        let resource_types = map.texts(5)?;
        let constraints = map.text_map(6)?;
        let revision = map.uint(7)?;
        let status = Status::parse(&map.text(8)?)?;
        let issued_by = map.text(9)?;
        let issued_at = map.uint(10)?;
        let expires_at = map.optional_uint(11)?;
        let operation_id = map.optional_operation_id(12)?;
        map.finish()?;
        if operations.is_empty() || resource_types.is_empty() {
            return Err(RecordError::Malformed(
                "a grant names at least one operation and one resource type".to_owned(),
            ));
        }
        Ok(Self {
            grant_id: GrantId(grant_id),
            principal_id,
            operations,
            selector,
            resource_types,
            constraints,
            revision,
            status,
            issued_by,
            issued_at,
            expires_at,
            operation_id,
        })
    }
}

/// A revoke or expire transition: which grant, at which store revision, when and by whom.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub grant_id: GrantId,
    pub revision: u64,
    pub at: u64,
    pub by: String,
    /// The mutation that made it; absent on a transition written before WP-3.6.
    pub operation_id: Option<OperationId>,
}

impl Transition {
    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(self.grant_id.0.to_vec())),
            (Value::Int(2), uint(self.revision)?),
            (Value::Int(3), uint(self.at)?),
            (Value::Int(4), Value::Text(self.by.clone())),
        ];
        if let Some(operation_id) = self.operation_id {
            pairs.push((
                Value::Int(5),
                Value::Bytes(operation_id.as_bytes().to_vec()),
            ));
        }
        cbor::encode(&Value::Map(pairs)).map_err(|error| RecordError::Cbor(error.to_string()))
    }

    /// Reads the canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        if bytes.len() > MAX_RECORD_BYTES {
            return Err(RecordError::TooLarge(bytes.len()));
        }
        let value =
            cbor::decode_canonical(bytes).map_err(|error| RecordError::Cbor(error.to_string()))?;
        let mut map = Labelled::new(value, 5)?;
        let grant_id: [u8; 16] = map
            .bytes(1)?
            .as_slice()
            .try_into()
            .map_err(|_| RecordError::Malformed("grant_id is 16 bytes".to_owned()))?;
        let transition = Self {
            grant_id: GrantId(grant_id),
            revision: map.uint(2)?,
            at: map.uint(3)?,
            by: map.text(4)?,
            operation_id: map.optional_operation_id(5)?,
        };
        map.finish()?;
        Ok(transition)
    }
}

/// Why a record or transition did not read or write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// More bytes than [`MAX_RECORD_BYTES`].
    TooLarge(usize),
    /// Not canonical CBOR of the profile.
    Cbor(String),
    /// Canonical CBOR, and not a record: a label unknown or missing, a value of another type.
    Malformed(String),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(bytes) => {
                write!(
                    f,
                    "{bytes} bytes; a grant record takes up to {MAX_RECORD_BYTES}"
                )
            }
            Self::Cbor(detail) => write!(f, "not canonical CBOR: {detail}"),
            Self::Malformed(detail) => write!(f, "not a grant record: {detail}"),
        }
    }
}

impl std::error::Error for RecordError {}

fn texts(items: &[String]) -> Value {
    Value::Array(items.iter().map(|item| Value::Text(item.clone())).collect())
}

fn uint(value: u64) -> Result<Value, RecordError> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| RecordError::Malformed("an integer beyond the signed 64-bit range".to_owned()))
}

/// A decoded integer-labelled map, read label by label and then checked for leftovers.
struct Labelled {
    pairs: BTreeMap<i64, Value>,
}

impl Labelled {
    fn new(value: Value, highest: i64) -> Result<Self, RecordError> {
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

    fn take(&mut self, label: i64) -> Result<Value, RecordError> {
        self.pairs
            .remove(&label)
            .ok_or_else(|| RecordError::Malformed(format!("label {label} is required")))
    }

    fn text(&mut self, label: i64) -> Result<String, RecordError> {
        match self.take(label)? {
            Value::Text(text) => Ok(text),
            _ => Err(RecordError::Malformed(format!("label {label} is text"))),
        }
    }

    fn bytes(&mut self, label: i64) -> Result<Vec<u8>, RecordError> {
        match self.take(label)? {
            Value::Bytes(bytes) => Ok(bytes),
            _ => Err(RecordError::Malformed(format!("label {label} is bytes"))),
        }
    }

    fn uint(&mut self, label: i64) -> Result<u64, RecordError> {
        match self.take(label)? {
            Value::Int(value) if value >= 0 => Ok(value as u64),
            _ => Err(RecordError::Malformed(format!(
                "label {label} is an unsigned integer"
            ))),
        }
    }

    fn optional_uint(&mut self, label: i64) -> Result<Option<u64>, RecordError> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Int(value)) if value >= 0 => Ok(Some(value as u64)),
            Some(_) => Err(RecordError::Malformed(format!(
                "label {label} is an unsigned integer"
            ))),
        }
    }

    fn optional_operation_id(&mut self, label: i64) -> Result<Option<OperationId>, RecordError> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Bytes(bytes)) => bytes
                .as_slice()
                .try_into()
                .map(|bytes| Some(OperationId::from_bytes(bytes)))
                .map_err(|_| RecordError::Malformed(format!("label {label} is 16 bytes"))),
            Some(_) => Err(RecordError::Malformed(format!("label {label} is bytes"))),
        }
    }

    fn texts(&mut self, label: i64) -> Result<Vec<String>, RecordError> {
        match self.take(label)? {
            Value::Array(items) => items
                .into_iter()
                .map(|item| match item {
                    Value::Text(text) => Ok(text),
                    _ => Err(RecordError::Malformed(format!(
                        "label {label} is an array of text"
                    ))),
                })
                .collect(),
            _ => Err(RecordError::Malformed(format!("label {label} is an array"))),
        }
    }

    fn text_map(&mut self, label: i64) -> Result<BTreeMap<String, String>, RecordError> {
        match self.take(label)? {
            Value::Map(pairs) => pairs
                .into_iter()
                .map(|(key, value)| match (key, value) {
                    (Value::Text(key), Value::Text(value)) => Ok((key, value)),
                    _ => Err(RecordError::Malformed(format!(
                        "label {label} is a map of text to text"
                    ))),
                })
                .collect(),
            _ => Err(RecordError::Malformed(format!("label {label} is a map"))),
        }
    }

    fn finish(self) -> Result<(), RecordError> {
        match self.pairs.keys().next() {
            None => Ok(()),
            Some(label) => Err(RecordError::Malformed(format!("unexpected label {label}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    pub(crate) fn sample() -> GrantRecord {
        GrantRecord {
            grant_id: GrantId([7; 16]),
            principal_id: Principal::new("spiffe://acme/billing").expect("a principal"),
            operations: vec!["catalog.read".to_owned(), "policy.push".to_owned()],
            selector: Selector::parse("plane/control/zone/z1/*").expect("a selector"),
            resource_types: vec!["*".to_owned()],
            constraints: BTreeMap::from([("note".to_owned(), "billing team".to_owned())]),
            revision: 3,
            status: Status::Active,
            issued_by: "cert:sha256:ab".to_owned(),
            issued_at: 1_759_000_000,
            expires_at: Some(1_790_000_000),
            operation_id: Some(OperationId::from_bytes([5; 16])),
        }
    }

    #[test]
    fn a_record_round_trips_with_and_without_its_optional_member() {
        let record = sample();
        let bytes = record.encode().expect("encodes");
        assert_eq!(GrantRecord::decode(&bytes).expect("decodes"), record);
        let mut open_ended = record;
        open_ended.expires_at = None;
        open_ended.operation_id = None;
        let bytes = open_ended.encode().expect("encodes");
        assert_eq!(GrantRecord::decode(&bytes).expect("decodes"), open_ended);
        assert_eq!(
            bytes,
            cbor::encode(&cbor::decode_canonical(&bytes).expect("canonical")).expect("re-encodes"),
            "one encoding"
        );
    }

    #[test]
    fn an_unknown_label_a_missing_one_and_a_wrong_type_are_refused() {
        let record = sample();
        let value = cbor::decode_canonical(&record.encode().expect("encodes")).expect("canonical");
        let Value::Map(pairs) = value else {
            panic!("a map");
        };
        let mut extra = pairs.clone();
        extra.push((Value::Int(13), Value::Text("x".to_owned())));
        assert!(GrantRecord::decode(&cbor::encode(&Value::Map(extra)).expect("encodes")).is_err());
        let missing: Vec<_> = pairs
            .iter()
            .filter(|(key, _)| *key != Value::Int(2))
            .cloned()
            .collect();
        assert!(
            GrantRecord::decode(&cbor::encode(&Value::Map(missing)).expect("encodes")).is_err()
        );
        let wrong: Vec<_> = pairs
            .iter()
            .map(|(key, value)| {
                if *key == Value::Int(7) {
                    (key.clone(), Value::Text("3".to_owned()))
                } else {
                    (key.clone(), value.clone())
                }
            })
            .collect();
        assert!(GrantRecord::decode(&cbor::encode(&Value::Map(wrong)).expect("encodes")).is_err());
        assert!(matches!(
            GrantRecord::decode(&vec![0u8; MAX_RECORD_BYTES + 1]),
            Err(RecordError::TooLarge(_))
        ));
        assert!(
            GrantRecord::decode(b"\x80").is_err(),
            "an array is not a record"
        );
    }

    #[test]
    fn a_transition_round_trips_and_refuses_a_trailing_label() {
        let transition = Transition {
            grant_id: GrantId([1; 16]),
            revision: 9,
            at: 1_759_000_100,
            by: "cert:sha256:ab".to_owned(),
            operation_id: Some(OperationId::from_bytes([6; 16])),
        };
        let bytes = transition.encode().expect("encodes");
        assert_eq!(Transition::decode(&bytes).expect("decodes"), transition);
        let older = Transition {
            operation_id: None,
            ..transition.clone()
        };
        assert_eq!(
            Transition::decode(&older.encode().expect("encodes")).expect("decodes"),
            older,
            "a transition written before WP-3.6 reads as before"
        );
        let Value::Map(mut pairs) = cbor::decode_canonical(&bytes).expect("canonical") else {
            panic!("a map");
        };
        pairs.push((Value::Int(6), Value::Int(1)));
        assert!(Transition::decode(&cbor::encode(&Value::Map(pairs)).expect("encodes")).is_err());
    }

    #[test]
    fn a_grant_id_reads_its_own_hex_and_nothing_shorter() {
        let id = GrantId([0xab; 16]);
        assert_eq!(id.to_string(), "ab".repeat(16));
        assert_eq!(GrantId::parse(&id.to_string()).expect("parses"), id);
        assert!(GrantId::parse("abcd").is_err());
        assert!(GrantId::parse(&"zz".repeat(16)).is_err());
    }

    #[test]
    fn a_record_is_active_until_it_expires_or_is_revoked() {
        let record = sample();
        assert!(record.is_active_at(1_759_000_001));
        assert!(!record.is_active_at(1_790_000_000), "expiry is exclusive");
        let mut revoked = record.clone();
        revoked.status = Status::Revoked;
        assert!(!revoked.is_active_at(1_759_000_001));
        assert_eq!(record.allows().len(), 2, "one per operation and type");
    }
}
