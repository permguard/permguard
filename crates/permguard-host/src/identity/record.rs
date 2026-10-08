// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host identity's records, byte for byte (owner decisions of 2026-10-08;
//! `contracts/cbor/identity.json`).
//!
//! | Record             | Shape                                                                                                  |
//! | ------------------ | ------------------------------------------------------------------------------------------------------ |
//! | identity document  | COSE_Sign1 `permguard.host.identity.v1` by the current epoch's key over {1 host_id, 2 subject, 3 epoch, 4 suite, 5 public key, 6 fingerprint, 7? last succession digest, 8 protocols, 9 revision, 10 issued_at} |
//! | succession record  | COSE_Sign1 `permguard.host.succession.v1` by epoch n's key over {1 host_id, 2 from_epoch, 3 to_epoch, 4 fingerprint, 5 public key, 6 previous, 7 at} |
//! | `INIT`             | {1 host_id, 2 volume_id, 3 first fingerprint, 4 created_at}                                            |
//! | `BOOT`             | {1 boot_id, 2 claim generation}                                                                        |
//!
//! Every map is closed and canonical. A succession record is cited by the digest of its
//! envelope's bytes under `digest::HOST_SUCCESSION`; the first record cites the zero digest.

use std::collections::BTreeMap;
use std::fmt;

use permguard_core::domains::digest::{HOST_IDENTITY_WITNESS, HOST_SUCCESSION};
use permguard_objects::cbor::{self, Value};
use permguard_objects::crypto::suite::Suite;
use permguard_objects::digest::Digest;

/// Why a record did not read or write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordError(pub String);

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RecordError {}

/// The subject of a Host: `urn:permguard:host:v1:<host_id>`.
pub fn subject(host_id: &[u8; 16]) -> String {
    format!(
        "{}{}",
        permguard_core::domains::subject::HOST_V1_PREFIX,
        uuid_text(host_id)
    )
}

/// A UUID's canonical text: 8-4-4-4-12 lowercase hex.
pub fn uuid_text(id: &[u8; 16]) -> String {
    let hex: String = id.iter().map(|byte| format!("{byte:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// A UUIDv7 (RFC 9562): 48 bits of Unix milliseconds, version 7, the variant, and random bits.
pub fn uuid_v7(unix_millis: u64, random: [u8; 10]) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..6].copy_from_slice(&unix_millis.to_be_bytes()[2..]);
    id[6..].copy_from_slice(&random);
    id[6] = (id[6] & 0x0f) | 0x70;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}

/// Whether `id` is a UUIDv7.
pub fn is_uuid_v7(id: &[u8; 16]) -> bool {
    id[6] >> 4 == 7 && id[8] >> 6 == 0b10
}

/// The zero digest: what the first succession record cites as previous.
pub fn zero_digest() -> Digest {
    #[allow(clippy::expect_used)]
    Digest::parse(&format!("sha256:{}", "0".repeat(64))).expect("the zero digest parses")
}

/// The digest a succession record is cited by.
pub fn succession_digest(envelope: &[u8]) -> Digest {
    let mut bytes = HOST_SUCCESSION.as_bytes().to_vec();
    bytes.extend_from_slice(envelope);
    Digest::compute(&bytes)
}

/// The external witness: `sha256:` over the domain ‖ the bytes of `INIT` ‖ `VOLUME_ID` ‖ the
/// first fingerprint (owner decision).
pub fn witness(init: &[u8], volume_id: &[u8; 16], fingerprint: &str) -> String {
    let mut bytes = HOST_IDENTITY_WITNESS.as_bytes().to_vec();
    bytes.extend_from_slice(init);
    bytes.extend_from_slice(volume_id);
    bytes.extend_from_slice(fingerprint.as_bytes());
    Digest::compute(&bytes).to_string()
}

/// The payload of the identity document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    pub host_id: [u8; 16],
    pub subject: String,
    pub epoch: u64,
    pub suite: Suite,
    pub public_key: Vec<u8>,
    pub fingerprint: String,
    /// The digest of the last succession record; absent at epoch 1.
    pub last_succession: Option<Digest>,
    pub protocols: Vec<String>,
    pub revision: u64,
    pub issued_at: u64,
}

impl Document {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        let mut pairs = vec![
            (Value::Int(1), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(2), Value::Text(self.subject.clone())),
            (Value::Int(3), uint(self.epoch)?),
            (Value::Int(4), Value::Text(self.suite.name().to_owned())),
            (Value::Int(5), Value::Bytes(self.public_key.clone())),
            (Value::Int(6), Value::Text(self.fingerprint.clone())),
        ];
        if let Some(digest) = &self.last_succession {
            pairs.push((Value::Int(7), Value::Text(digest.to_string())));
        }
        pairs.push((
            Value::Int(8),
            Value::Array(
                self.protocols
                    .iter()
                    .map(|protocol| Value::Text(protocol.clone()))
                    .collect(),
            ),
        ));
        pairs.push((Value::Int(9), uint(self.revision)?));
        pairs.push((Value::Int(10), uint(self.issued_at)?));
        encode(pairs)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut map = Labelled::read(bytes, "an identity document")?;
        let document = Self {
            host_id: map.id(1)?,
            subject: map.text(2)?,
            epoch: map.uint(3)?,
            suite: map.suite(4)?,
            public_key: map.bytes(5)?,
            fingerprint: map.text(6)?,
            last_succession: map.optional_digest(7)?,
            protocols: map.texts(8)?,
            revision: map.uint(9)?,
            issued_at: map.uint(10)?,
        };
        map.finish()?;
        Ok(document)
    }
}

/// The payload of a succession record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Succession {
    pub host_id: [u8; 16],
    pub from_epoch: u64,
    pub to_epoch: u64,
    /// The new key's fingerprint.
    pub fingerprint: String,
    /// The new key.
    pub public_key: Vec<u8>,
    /// The digest of the record before it; the zero digest for the first.
    pub previous: Digest,
    pub at: u64,
}

impl Succession {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(2), uint(self.from_epoch)?),
            (Value::Int(3), uint(self.to_epoch)?),
            (Value::Int(4), Value::Text(self.fingerprint.clone())),
            (Value::Int(5), Value::Bytes(self.public_key.clone())),
            (Value::Int(6), Value::Text(self.previous.to_string())),
            (Value::Int(7), uint(self.at)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut map = Labelled::read(bytes, "a succession record")?;
        let record = Self {
            host_id: map.id(1)?,
            from_epoch: map.uint(2)?,
            to_epoch: map.uint(3)?,
            fingerprint: map.text(4)?,
            public_key: map.bytes(5)?,
            previous: map.digest(6)?,
            at: map.uint(7)?,
        };
        map.finish()?;
        Ok(record)
    }
}

/// `host/identity/INIT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Init {
    pub host_id: [u8; 16],
    pub volume_id: [u8; 16],
    pub fingerprint: String,
    pub created_at: u64,
}

impl Init {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.host_id.to_vec())),
            (Value::Int(2), Value::Bytes(self.volume_id.to_vec())),
            (Value::Int(3), Value::Text(self.fingerprint.clone())),
            (Value::Int(4), uint(self.created_at)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut map = Labelled::read(bytes, "INIT")?;
        let init = Self {
            host_id: map.id(1)?,
            volume_id: map.id(2)?,
            fingerprint: map.text(3)?,
            created_at: map.uint(4)?,
        };
        map.finish()?;
        Ok(init)
    }
}

/// `host/identity/BOOT`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Boot {
    pub boot_id: [u8; 16],
    pub generation: u64,
}

impl Boot {
    pub fn encode(&self) -> Result<Vec<u8>, RecordError> {
        encode(vec![
            (Value::Int(1), Value::Bytes(self.boot_id.to_vec())),
            (Value::Int(2), uint(self.generation)?),
        ])
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, RecordError> {
        let mut map = Labelled::read(bytes, "BOOT")?;
        let boot = Self {
            boot_id: map.id(1)?,
            generation: map.uint(2)?,
        };
        map.finish()?;
        Ok(boot)
    }
}

pub(crate) fn encode(pairs: Vec<(Value, Value)>) -> Result<Vec<u8>, RecordError> {
    cbor::encode(&Value::Map(pairs)).map_err(|error| RecordError(error.to_string()))
}

pub(crate) fn uint(value: u64) -> Result<Value, RecordError> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| RecordError("an integer beyond the signed 64-bit range".to_owned()))
}

/// A decoded integer-labelled map, read label by label and then checked for leftovers.
pub(crate) struct Labelled {
    what: &'static str,
    pairs: BTreeMap<i64, Value>,
}

impl Labelled {
    pub(crate) fn read(bytes: &[u8], what: &'static str) -> Result<Self, RecordError> {
        let value = cbor::decode_canonical(bytes)
            .map_err(|error| RecordError(format!("{what} is not canonical CBOR: {error}")))?;
        Self::from_value(value, what)
    }

    /// A map already decoded, as an array item is.
    pub(crate) fn from_value(value: Value, what: &'static str) -> Result<Self, RecordError> {
        let Value::Map(pairs) = value else {
            return Err(RecordError(format!("{what} is a map")));
        };
        let mut labelled = BTreeMap::new();
        for (key, value) in pairs {
            let Value::Int(label) = key else {
                return Err(RecordError(format!("{what} has integer labels")));
            };
            labelled.insert(label, value);
        }
        Ok(Self {
            what,
            pairs: labelled,
        })
    }

    fn error(&self, detail: impl fmt::Display) -> RecordError {
        RecordError(format!("{}: {detail}", self.what))
    }

    fn take(&mut self, label: i64) -> Result<Value, RecordError> {
        self.pairs
            .remove(&label)
            .ok_or_else(|| self.error(format!("label {label} is required")))
    }

    pub(crate) fn text(&mut self, label: i64) -> Result<String, RecordError> {
        match self.take(label)? {
            Value::Text(text) => Ok(text),
            _ => Err(self.error(format!("label {label} is text"))),
        }
    }

    pub(crate) fn bytes(&mut self, label: i64) -> Result<Vec<u8>, RecordError> {
        match self.take(label)? {
            Value::Bytes(bytes) => Ok(bytes),
            _ => Err(self.error(format!("label {label} is bytes"))),
        }
    }

    pub(crate) fn id(&mut self, label: i64) -> Result<[u8; 16], RecordError> {
        let bytes = self.bytes(label)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| self.error(format!("label {label} is 16 bytes")))
    }

    pub(crate) fn uint(&mut self, label: i64) -> Result<u64, RecordError> {
        match self.take(label)? {
            Value::Int(value) if value >= 0 => Ok(value as u64),
            _ => Err(self.error(format!("label {label} is an unsigned integer"))),
        }
    }

    /// An optional unsigned integer: absent is `None`, never null.
    pub(crate) fn optional_uint(&mut self, label: i64) -> Result<Option<u64>, RecordError> {
        if self.pairs.contains_key(&label) {
            self.uint(label).map(Some)
        } else {
            Ok(None)
        }
    }

    /// An optional byte string of exactly `N` bytes.
    pub(crate) fn optional_fixed<const N: usize>(
        &mut self,
        label: i64,
    ) -> Result<Option<[u8; N]>, RecordError> {
        if self.pairs.contains_key(&label) {
            self.fixed(label).map(Some)
        } else {
            Ok(None)
        }
    }

    /// An array, its items still to be read.
    pub(crate) fn array(&mut self, label: i64) -> Result<Vec<Value>, RecordError> {
        match self.take(label)? {
            Value::Array(items) => Ok(items),
            _ => Err(self.error(format!("label {label} is an array"))),
        }
    }

    pub(crate) fn suite(&mut self, label: i64) -> Result<Suite, RecordError> {
        let name = self.text(label)?;
        Suite::from_name(&name).ok_or_else(|| self.error(format!("`{name}` is not a suite")))
    }

    pub(crate) fn digest(&mut self, label: i64) -> Result<Digest, RecordError> {
        let text = self.text(label)?;
        Digest::parse(&text).map_err(|error| self.error(format!("label {label}: {error:?}")))
    }

    fn optional_digest(&mut self, label: i64) -> Result<Option<Digest>, RecordError> {
        if self.pairs.contains_key(&label) {
            self.digest(label).map(Some)
        } else {
            Ok(None)
        }
    }

    /// An optional text member: absent is `None`, never null.
    pub(crate) fn optional_text(&mut self, label: i64) -> Result<Option<String>, RecordError> {
        if self.pairs.contains_key(&label) {
            self.text(label).map(Some)
        } else {
            Ok(None)
        }
    }

    /// A byte string of exactly `N` bytes.
    pub(crate) fn fixed<const N: usize>(&mut self, label: i64) -> Result<[u8; N], RecordError> {
        let bytes = self.bytes(label)?;
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| self.error(format!("label {label} is {N} bytes")))
    }

    /// An array of byte strings.
    pub(crate) fn byte_strings(&mut self, label: i64) -> Result<Vec<Vec<u8>>, RecordError> {
        match self.take(label)? {
            Value::Array(items) => items
                .into_iter()
                .map(|item| match item {
                    Value::Bytes(bytes) => Ok(bytes),
                    _ => Err(self.error(format!("label {label} is an array of bytes"))),
                })
                .collect(),
            _ => Err(self.error(format!("label {label} is an array"))),
        }
    }

    fn texts(&mut self, label: i64) -> Result<Vec<String>, RecordError> {
        match self.take(label)? {
            Value::Array(items) => items
                .into_iter()
                .map(|item| match item {
                    Value::Text(text) => Ok(text),
                    _ => Err(self.error(format!("label {label} is an array of text"))),
                })
                .collect(),
            _ => Err(self.error(format!("label {label} is an array"))),
        }
    }

    pub(crate) fn finish(self) -> Result<(), RecordError> {
        match self.pairs.keys().next() {
            None => Ok(()),
            Some(label) => Err(self.error(format!("unexpected label {label}"))),
        }
    }
}
