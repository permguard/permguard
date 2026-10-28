// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The closed, canonical CBOR maps the engine keeps: a strict reader, refusing an unknown label,
//! a missing one or a value of another type.

use permguard_objects::cbor::{self, Value};

use super::StreamError;

/// Encodes `pairs` as one canonical map.
pub(crate) fn encode(pairs: Vec<(i64, Value)>) -> Result<Vec<u8>, StreamError> {
    cbor::encode(&Value::Map(
        pairs
            .into_iter()
            .map(|(label, value)| (Value::Int(label), value))
            .collect(),
    ))
    .map_err(|error| StreamError::Invalid(error.to_string()))
}

/// An unsigned integer as a CBOR value.
pub(crate) fn uint(value: u64) -> Result<Value, StreamError> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| StreamError::Invalid(format!("{value} is out of range")))
}

/// A map being read: each label taken once, and none left at the end.
pub(crate) struct Map {
    pairs: Vec<(i64, Value)>,
    what: &'static str,
}

impl Map {
    /// Reads `bytes` as one canonical map with integer labels.
    pub(crate) fn read(bytes: &[u8], what: &'static str) -> Result<Self, StreamError> {
        let value = cbor::decode_canonical(bytes)
            .map_err(|error| StreamError::Invalid(format!("{what}: {error}")))?;
        Self::of(value, what)
    }

    /// Reads a decoded value as a map with integer labels.
    pub(crate) fn of(value: Value, what: &'static str) -> Result<Self, StreamError> {
        let Value::Map(pairs) = value else {
            return Err(StreamError::Invalid(format!("{what} is not a map")));
        };
        let pairs = pairs
            .into_iter()
            .map(|(key, value)| match key {
                Value::Int(label) => Ok((label, value)),
                _ => Err(StreamError::Invalid(format!(
                    "{what} has a key that is no label"
                ))),
            })
            .collect::<Result<_, _>>()?;
        Ok(Self { pairs, what })
    }

    fn take(&mut self, label: i64) -> Option<Value> {
        let at = self.pairs.iter().position(|(held, _)| *held == label)?;
        Some(self.pairs.remove(at).1)
    }

    fn missing(&self, label: i64) -> StreamError {
        StreamError::Invalid(format!("{} misses label {label}", self.what))
    }

    fn mistyped(&self, label: i64) -> StreamError {
        StreamError::Invalid(format!("{} has label {label} of another type", self.what))
    }

    pub(crate) fn optional(&mut self, label: i64) -> Option<Value> {
        self.take(label)
    }

    pub(crate) fn value(&mut self, label: i64) -> Result<Value, StreamError> {
        self.take(label).ok_or_else(|| self.missing(label))
    }

    pub(crate) fn uint(&mut self, label: i64) -> Result<u64, StreamError> {
        match self.value(label)? {
            Value::Int(value) => u64::try_from(value).map_err(|_| self.mistyped(label)),
            _ => Err(self.mistyped(label)),
        }
    }

    pub(crate) fn optional_uint(&mut self, label: i64) -> Result<Option<u64>, StreamError> {
        match self.take(label) {
            None => Ok(None),
            Some(Value::Int(value)) => u64::try_from(value)
                .map(Some)
                .map_err(|_| self.mistyped(label)),
            Some(_) => Err(self.mistyped(label)),
        }
    }

    pub(crate) fn text(&mut self, label: i64) -> Result<String, StreamError> {
        match self.value(label)? {
            Value::Text(text) => Ok(text),
            _ => Err(self.mistyped(label)),
        }
    }

    pub(crate) fn bytes(&mut self, label: i64) -> Result<Vec<u8>, StreamError> {
        match self.value(label)? {
            Value::Bytes(bytes) => Ok(bytes),
            _ => Err(self.mistyped(label)),
        }
    }

    pub(crate) fn optional_bytes(&mut self, label: i64) -> Result<Option<Vec<u8>>, StreamError> {
        match self.take(label) {
            None => Ok(None),
            Some(Value::Bytes(bytes)) => Ok(Some(bytes)),
            Some(_) => Err(self.mistyped(label)),
        }
    }

    pub(crate) fn fixed<const N: usize>(&mut self, label: i64) -> Result<[u8; N], StreamError> {
        self.bytes(label)?.try_into().map_err(|_| {
            StreamError::Invalid(format!("{} label {label} is not {N} bytes", self.what))
        })
    }

    pub(crate) fn boolean(&mut self, label: i64) -> Result<bool, StreamError> {
        match self.value(label)? {
            Value::Bool(value) => Ok(value),
            _ => Err(self.mistyped(label)),
        }
    }

    pub(crate) fn array(&mut self, label: i64) -> Result<Vec<Value>, StreamError> {
        match self.value(label)? {
            Value::Array(values) => Ok(values),
            _ => Err(self.mistyped(label)),
        }
    }

    /// Refuses whatever label is left: the maps are closed.
    pub(crate) fn finish(self) -> Result<(), StreamError> {
        match self.pairs.first() {
            None => Ok(()),
            Some((label, _)) => Err(StreamError::Invalid(format!(
                "{} has the unknown label {label}",
                self.what
            ))),
        }
    }
}

/// `bytes` as exactly `N` bytes.
pub(crate) fn fixed<const N: usize>(bytes: Vec<u8>, what: &str) -> Result<[u8; N], StreamError> {
    bytes
        .try_into()
        .map_err(|_| StreamError::Invalid(format!("{what} is not {N} bytes")))
}
