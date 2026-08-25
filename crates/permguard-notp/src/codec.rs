// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The codec layer every message shares: the error a malformed body raises,
//! and the readers and writers over the canonical CBOR value model.
//!
//! Field keys are integers and they are **normative** — a message is a map
//! from small integers to values, absent optionals are omitted, and nothing
//! here ever guesses: a field of the wrong shape is a refusal, never a
//! default.

use permguard_objects::cbor::{CborError, Value};
use permguard_objects::digest::{Digest, DigestError};

/// Why a message failed to parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    Cbor(CborError),
    Digest(DigestError),
    Schema(&'static str),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Cbor(e) => write!(f, "encoding: {e}"),
            WireError::Digest(e) => write!(f, "digest: {e}"),
            WireError::Schema(what) => write!(f, "schema: {what}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<CborError> for WireError {
    fn from(e: CborError) -> Self {
        WireError::Cbor(e)
    }
}

impl From<DigestError> for WireError {
    fn from(e: DigestError) -> Self {
        WireError::Digest(e)
    }
}

pub(crate) type Result<T> = std::result::Result<T, WireError>;

pub(crate) fn map(pairs: Vec<(i64, Value)>) -> Value {
    Value::Map(pairs.into_iter().map(|(k, v)| (Value::Int(k), v)).collect())
}

pub(crate) fn digests(list: &[Digest]) -> Value {
    Value::Array(list.iter().map(|d| Value::Text(d.to_string())).collect())
}

pub(crate) fn field(pairs: &[(Value, Value)], key: i64) -> Option<&Value> {
    pairs
        .iter()
        .find(|(k, _)| *k == Value::Int(key))
        .map(|(_, v)| v)
}

pub(crate) fn need(pairs: &[(Value, Value)], key: i64) -> Result<&Value> {
    field(pairs, key).ok_or(WireError::Schema("missing field"))
}

pub(crate) fn as_pairs(value: &Value) -> Result<&[(Value, Value)]> {
    match value {
        Value::Map(pairs) => Ok(pairs),
        _ => Err(WireError::Schema("message must be a map")),
    }
}

pub(crate) fn text(value: &Value) -> Result<String> {
    match value {
        Value::Text(t) => Ok(t.clone()),
        _ => Err(WireError::Schema("expected text")),
    }
}

pub(crate) fn uint(value: &Value) -> Result<u64> {
    match value {
        Value::Int(n) if *n >= 0 => Ok(*n as u64),
        _ => Err(WireError::Schema("expected unsigned integer")),
    }
}

pub(crate) fn digest(value: &Value) -> Result<Digest> {
    Ok(Digest::parse(&text(value)?)?)
}

pub(crate) fn digest_list(value: &Value) -> Result<Vec<Digest>> {
    match value {
        Value::Array(items) => items.iter().map(digest).collect(),
        _ => Err(WireError::Schema("expected array of digests")),
    }
}

pub(crate) fn bytes_list(value: &Value) -> Result<Vec<Vec<u8>>> {
    match value {
        Value::Array(items) => items
            .iter()
            .map(|v| match v {
                Value::Bytes(b) => Ok(b.clone()),
                _ => Err(WireError::Schema("expected byte string")),
            })
            .collect(),
        _ => Err(WireError::Schema("expected array of byte strings")),
    }
}

pub(crate) fn opt_digest(pairs: &[(Value, Value)], key: i64) -> Result<Option<Digest>> {
    field(pairs, key).map(digest).transpose()
}

pub(crate) fn opt_text(pairs: &[(Value, Value)], key: i64) -> Result<Option<String>> {
    field(pairs, key).map(text).transpose()
}

pub(crate) fn bytes(value: &Value) -> Result<Vec<u8>> {
    match value {
        Value::Bytes(b) => Ok(b.clone()),
        _ => Err(WireError::Schema("expected byte string")),
    }
}
