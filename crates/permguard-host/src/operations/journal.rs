// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The entries of `host/audit/mutations/journal.cborseq` and `snapshot.cbor`, byte for byte
//! (owner decision of 2026-10-07; `contracts/cbor/mutation.json`).
//!
//! Every entry is a closed CBOR map with integer labels; labels 1 to 3 are common:
//!
//! | Kind        | Labels                                                                                                    |
//! | ----------- | --------------------------------------------------------------------------------------------------------- |
//! | `intent`    | 1 kind, 2 operation_id, 3 at, 4 domain, 5 operation, 6 action, 7 initiator kind, 8 initiator, 9 request_id?, 10 request_digest?, 11 target? |
//! | `commit`    | 1 kind, 2 operation_id, 3 at, 4 revision, 5 target?, 6 result?, 7 reconciled                              |
//! | `failed`    | 1 kind, 2 operation_id, 3 at, 4 reason                                                                    |
//! | `projected` | 1 kind, 2 operation_id, 3 at                                                                              |
//! | `snapshot`  | 1 kind, 2 at, 3 entries: the entries that rebuild the live operations, each as its canonical bytes      |
//!
//! `operation_id` is 16 bytes; `at` is seconds since the epoch; `result` is the answer a retry
//! learns, as the bytes its domain wrote. A COMMIT without a result was written by recovery,
//! which observes the domain's revision and target but not the answer.

use std::collections::BTreeMap;
use std::fmt;

use permguard_objects::cbor::{self, Value};

/// The most bytes one entry takes: the largest stored answer a Host mutation returns is a grant
/// of a few kilobytes.
pub const MAX_ENTRY_BYTES: usize = 256 * 1024;

/// One operation's identity: 16 bytes from the OS random source, written as 32 hex characters.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct OperationId([u8; 16]);

impl OperationId {
    /// From its bytes.
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    /// The bytes.
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// A fresh identity, or `None` when the OS random source refuses.
    pub fn mint() -> Option<Self> {
        use ring::rand::SecureRandom as _;
        let mut bytes = [0u8; 16];
        ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
        Some(Self(bytes))
    }
}

impl fmt::Display for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for OperationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OperationId({self})")
    }
}

/// Who began an operation: an authenticated principal, or the Host itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Initiator {
    /// The authorization principal of the request.
    Principal(String),
    /// A Host process: `expiry`, `bootstrap`.
    System(String),
}

impl Initiator {
    fn kind(&self) -> &'static str {
        match self {
            Self::Principal(_) => "principal",
            Self::System(_) => "system",
        }
    }

    /// The name it carries.
    pub fn name(&self) -> &str {
        match self {
            Self::Principal(name) | Self::System(name) => name,
        }
    }
}

/// The idempotency key of an externally retryable operation: the caller's request id and the
/// digest of what it asked, so the same id under another request is told apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestKey {
    pub request_id: String,
    pub digest: String,
}

/// An INTENT: what is about to be applied, flushed before anything is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intent {
    pub operation_id: OperationId,
    pub at: u64,
    /// The domain that applies it: `grants`.
    pub domain: String,
    /// The operation: `grants.create`.
    pub operation: String,
    /// The registered audit action its records carry.
    pub action: String,
    pub initiator: Initiator,
    pub request: Option<RequestKey>,
    /// What it is done to, when known before it is applied.
    pub target: Option<String>,
}

/// A COMMIT: the domain applied the operation, at this revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    pub operation_id: OperationId,
    pub at: u64,
    pub revision: u64,
    pub target: Option<String>,
    /// The answer a retry learns; absent when recovery wrote the commit.
    pub result: Option<Vec<u8>>,
    /// Written by recovery from what the domain shows.
    pub reconciled: bool,
}

/// One entry of the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    Intent(Intent),
    Commit(Commit),
    /// Nothing was applied: refused by the domain, the audit intent unwritten, or no trace of it
    /// found at recovery.
    Failed {
        operation_id: OperationId,
        at: u64,
        reason: String,
    },
    /// The audit record of the operation's outcome is durable.
    Projected {
        operation_id: OperationId,
        at: u64,
    },
}

impl Entry {
    /// The operation the entry belongs to.
    pub fn operation_id(&self) -> OperationId {
        match self {
            Self::Intent(intent) => intent.operation_id,
            Self::Commit(commit) => commit.operation_id,
            Self::Failed { operation_id, .. } | Self::Projected { operation_id, .. } => {
                *operation_id
            }
        }
    }

    /// The canonical bytes.
    pub fn encode(&self) -> Result<Vec<u8>, JournalError> {
        let mut pairs = Vec::new();
        let mut put = |label: i64, value: Value| pairs.push((Value::Int(label), value));
        match self {
            Self::Intent(intent) => {
                put(1, text("intent"));
                put(2, Value::Bytes(intent.operation_id.0.to_vec()));
                put(3, uint(intent.at)?);
                put(4, text(&intent.domain));
                put(5, text(&intent.operation));
                put(6, text(&intent.action));
                put(7, text(intent.initiator.kind()));
                put(8, text(intent.initiator.name()));
                if let Some(request) = &intent.request {
                    put(9, text(&request.request_id));
                    put(10, text(&request.digest));
                }
                if let Some(target) = &intent.target {
                    put(11, text(target));
                }
            }
            Self::Commit(commit) => {
                put(1, text("commit"));
                put(2, Value::Bytes(commit.operation_id.0.to_vec()));
                put(3, uint(commit.at)?);
                put(4, uint(commit.revision)?);
                if let Some(target) = &commit.target {
                    put(5, text(target));
                }
                if let Some(result) = &commit.result {
                    put(6, Value::Bytes(result.clone()));
                }
                put(7, Value::Bool(commit.reconciled));
            }
            Self::Failed {
                operation_id,
                at,
                reason,
            } => {
                put(1, text("failed"));
                put(2, Value::Bytes(operation_id.0.to_vec()));
                put(3, uint(*at)?);
                put(4, text(reason));
            }
            Self::Projected { operation_id, at } => {
                put(1, text("projected"));
                put(2, Value::Bytes(operation_id.0.to_vec()));
                put(3, uint(*at)?);
            }
        }
        let bytes = cbor::encode(&Value::Map(pairs))
            .map_err(|error| JournalError(format!("an entry does not encode: {error}")))?;
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(JournalError(format!(
                "an entry of {} bytes is more than {MAX_ENTRY_BYTES}",
                bytes.len()
            )));
        }
        Ok(bytes)
    }

    /// Reads the canonical bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, JournalError> {
        if bytes.len() > MAX_ENTRY_BYTES {
            return Err(JournalError(format!(
                "an entry of {} bytes is more than {MAX_ENTRY_BYTES}",
                bytes.len()
            )));
        }
        let value = cbor::decode_canonical(bytes)
            .map_err(|error| JournalError(format!("not canonical CBOR: {error}")))?;
        Self::from_value(value)
    }

    /// Reads one decoded item of the sequence.
    pub fn from_value(value: Value) -> Result<Self, JournalError> {
        let mut map = Labelled::new(value)?;
        let kind = map.text(1)?;
        let operation_id = map.operation_id(2)?;
        let at = map.uint(3)?;
        let entry = match kind.as_str() {
            "intent" => {
                let domain = map.text(4)?;
                let operation = map.text(5)?;
                let action = map.text(6)?;
                let initiator = match (map.text(7)?.as_str(), map.text(8)?) {
                    ("principal", name) => Initiator::Principal(name),
                    ("system", name) => Initiator::System(name),
                    (other, _) => {
                        return Err(JournalError(format!("`{other}` is not an initiator kind")));
                    }
                };
                let request = match (map.optional_text(9)?, map.optional_text(10)?) {
                    (Some(request_id), Some(digest)) => Some(RequestKey { request_id, digest }),
                    (None, None) => None,
                    _ => {
                        return Err(JournalError(
                            "a request id and its digest come together".to_owned(),
                        ));
                    }
                };
                Self::Intent(Intent {
                    operation_id,
                    at,
                    domain,
                    operation,
                    action,
                    initiator,
                    request,
                    target: map.optional_text(11)?,
                })
            }
            "commit" => Self::Commit(Commit {
                operation_id,
                at,
                revision: map.uint(4)?,
                target: map.optional_text(5)?,
                result: map.optional_bytes(6)?,
                reconciled: map.boolean(7)?,
            }),
            "failed" => Self::Failed {
                operation_id,
                at,
                reason: map.text(4)?,
            },
            "projected" => Self::Projected { operation_id, at },
            other => return Err(JournalError(format!("`{other}` is not an entry kind"))),
        };
        map.finish()?;
        Ok(entry)
    }
}

/// `snapshot.cbor`: the entries that rebuild the live operations, at `at`.
pub fn encode_snapshot(at: u64, entries: &[Entry]) -> Result<Vec<u8>, JournalError> {
    let mut items = Vec::with_capacity(entries.len());
    for entry in entries {
        items.push(Value::Bytes(entry.encode()?));
    }
    cbor::encode(&Value::Map(vec![
        (Value::Int(1), text("snapshot")),
        (Value::Int(2), uint(at)?),
        (Value::Int(3), Value::Array(items)),
    ]))
    .map_err(|error| JournalError(format!("the snapshot does not encode: {error}")))
}

/// Reads `snapshot.cbor`.
pub fn decode_snapshot(bytes: &[u8]) -> Result<Vec<Entry>, JournalError> {
    let value = cbor::decode_canonical(bytes)
        .map_err(|error| JournalError(format!("the snapshot is not canonical CBOR: {error}")))?;
    let mut map = Labelled::new(value)?;
    if map.text(1)? != "snapshot" {
        return Err(JournalError("not a mutation snapshot".to_owned()));
    }
    let _at = map.uint(2)?;
    let Value::Array(items) = map.take(3)? else {
        return Err(JournalError("label 3 is an array".to_owned()));
    };
    map.finish()?;
    items
        .into_iter()
        .map(|item| match item {
            Value::Bytes(bytes) => Entry::decode(&bytes),
            _ => Err(JournalError("a snapshot entry is bytes".to_owned())),
        })
        .collect()
}

/// Why an entry or the snapshot did not read or write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalError(pub String);

impl fmt::Display for JournalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "a mutation journal entry: {}", self.0)
    }
}

impl std::error::Error for JournalError {}

fn text(value: &str) -> Value {
    Value::Text(value.to_owned())
}

fn uint(value: u64) -> Result<Value, JournalError> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| JournalError("an integer beyond the signed 64-bit range".to_owned()))
}

/// A decoded integer-labelled map, read label by label and then checked for leftovers.
struct Labelled {
    pairs: BTreeMap<i64, Value>,
}

impl Labelled {
    fn new(value: Value) -> Result<Self, JournalError> {
        let Value::Map(pairs) = value else {
            return Err(JournalError("the root is a map".to_owned()));
        };
        let mut labelled = BTreeMap::new();
        for (key, value) in pairs {
            let Value::Int(label) = key else {
                return Err(JournalError("labels are integers".to_owned()));
            };
            labelled.insert(label, value);
        }
        Ok(Self { pairs: labelled })
    }

    fn take(&mut self, label: i64) -> Result<Value, JournalError> {
        self.pairs
            .remove(&label)
            .ok_or_else(|| JournalError(format!("label {label} is required")))
    }

    fn text(&mut self, label: i64) -> Result<String, JournalError> {
        match self.take(label)? {
            Value::Text(text) => Ok(text),
            _ => Err(JournalError(format!("label {label} is text"))),
        }
    }

    fn optional_text(&mut self, label: i64) -> Result<Option<String>, JournalError> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Text(text)) => Ok(Some(text)),
            Some(_) => Err(JournalError(format!("label {label} is text"))),
        }
    }

    fn optional_bytes(&mut self, label: i64) -> Result<Option<Vec<u8>>, JournalError> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Bytes(bytes)) => Ok(Some(bytes)),
            Some(_) => Err(JournalError(format!("label {label} is bytes"))),
        }
    }

    fn uint(&mut self, label: i64) -> Result<u64, JournalError> {
        match self.take(label)? {
            Value::Int(value) if value >= 0 => Ok(value as u64),
            _ => Err(JournalError(format!(
                "label {label} is an unsigned integer"
            ))),
        }
    }

    fn boolean(&mut self, label: i64) -> Result<bool, JournalError> {
        match self.take(label)? {
            Value::Bool(flag) => Ok(flag),
            _ => Err(JournalError(format!("label {label} is a boolean"))),
        }
    }

    fn operation_id(&mut self, label: i64) -> Result<OperationId, JournalError> {
        match self.take(label)? {
            Value::Bytes(bytes) => bytes
                .as_slice()
                .try_into()
                .map(OperationId)
                .map_err(|_| JournalError(format!("label {label} is 16 bytes"))),
            _ => Err(JournalError(format!("label {label} is bytes"))),
        }
    }

    fn finish(self) -> Result<(), JournalError> {
        match self.pairs.keys().next() {
            None => Ok(()),
            Some(label) => Err(JournalError(format!("unexpected label {label}"))),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    fn id(byte: u8) -> OperationId {
        OperationId([byte; 16])
    }

    #[test]
    fn every_entry_kind_round_trips_and_an_unknown_label_is_refused() {
        let entries = [
            Entry::Intent(Intent {
                operation_id: id(1),
                at: 10,
                domain: "grants".to_owned(),
                operation: "grants.create".to_owned(),
                action: "host.grant.issued".to_owned(),
                initiator: Initiator::Principal("alice".to_owned()),
                request: Some(RequestKey {
                    request_id: "r1".to_owned(),
                    digest: "d1".to_owned(),
                }),
                target: None,
            }),
            Entry::Intent(Intent {
                operation_id: id(2),
                at: 11,
                domain: "grants".to_owned(),
                operation: "grants.expire".to_owned(),
                action: "host.grant.expired".to_owned(),
                initiator: Initiator::System("expiry".to_owned()),
                request: None,
                target: Some("g".to_owned()),
            }),
            Entry::Commit(Commit {
                operation_id: id(1),
                at: 12,
                revision: 4,
                target: Some("g".to_owned()),
                result: Some(b"{}".to_vec()),
                reconciled: false,
            }),
            Entry::Failed {
                operation_id: id(2),
                at: 13,
                reason: "refused".to_owned(),
            },
            Entry::Projected {
                operation_id: id(1),
                at: 14,
            },
        ];
        for entry in &entries {
            let bytes = entry.encode().expect("encodes");
            assert_eq!(&Entry::decode(&bytes).expect("decodes"), entry);
        }
        let snapshot = encode_snapshot(20, &entries).expect("encodes");
        assert_eq!(decode_snapshot(&snapshot).expect("decodes"), entries);
        let extra = cbor::encode(&Value::Map(vec![
            (Value::Int(1), text("projected")),
            (Value::Int(2), Value::Bytes(vec![1; 16])),
            (Value::Int(3), Value::Int(1)),
            (Value::Int(4), Value::Int(1)),
        ]))
        .expect("encodes");
        assert!(Entry::decode(&extra).is_err(), "a closed map");
    }
}
