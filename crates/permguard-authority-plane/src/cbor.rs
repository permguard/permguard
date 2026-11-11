// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The closed, integer-labelled CBOR maps the Authority Plane journals: read label by label,
//! every label checked against the registry `contracts/cbor/authority.json` names, and nothing
//! left over.

use std::collections::BTreeMap;
use std::fmt;

use permguard_host::operations::journal::OperationId;
use permguard_objects::cbor::{self, Value};

/// The most bytes one journaled record takes.
pub const MAX_RECORD_BYTES: usize = 256 * 1024;

/// Why a record did not read or write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// More bytes than [`MAX_RECORD_BYTES`].
    TooLarge(usize),
    /// Not canonical CBOR of the profile.
    Cbor(String),
    /// Canonical CBOR, and not the record: a label unknown or missing, a value of another type.
    Malformed(String),
}

impl fmt::Display for RecordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge(bytes) => {
                write!(f, "{bytes} bytes; a record takes up to {MAX_RECORD_BYTES}")
            }
            Self::Cbor(detail) => write!(f, "not canonical CBOR: {detail}"),
            Self::Malformed(detail) => write!(f, "not a record: {detail}"),
        }
    }
}

impl std::error::Error for RecordError {}

/// The canonical bytes of `value`, bounded.
pub fn encode(value: &Value) -> Result<Vec<u8>, RecordError> {
    let bytes = cbor::encode(value).map_err(|error| RecordError::Cbor(error.to_string()))?;
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge(bytes.len()));
    }
    Ok(bytes)
}

/// The map `bytes` holds, read canonically, bounded.
pub fn decode(bytes: &[u8], highest: i64) -> Result<Labelled, RecordError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(RecordError::TooLarge(bytes.len()));
    }
    let value =
        cbor::decode_canonical(bytes).map_err(|error| RecordError::Cbor(error.to_string()))?;
    Labelled::new(value, highest)
}

/// A text array.
pub fn texts<'a>(items: impl IntoIterator<Item = &'a String>) -> Value {
    Value::Array(
        items
            .into_iter()
            .map(|item| Value::Text(item.clone()))
            .collect(),
    )
}

/// An unsigned integer, within the signed 64-bit range the profile keeps.
pub fn uint(value: u64) -> Result<Value, RecordError> {
    i64::try_from(value)
        .map(Value::Int)
        .map_err(|_| RecordError::Malformed("an integer beyond the signed 64-bit range".to_owned()))
}

/// A map of the present `(label, value)` pairs, in label order.
pub fn map(pairs: Vec<(i64, Option<Value>)>) -> Value {
    Value::Map(
        pairs
            .into_iter()
            .filter_map(|(label, value)| value.map(|value| (Value::Int(label), value)))
            .collect(),
    )
}

/// A decoded integer-labelled map, read label by label and then checked for leftovers.
pub struct Labelled {
    pairs: BTreeMap<i64, Value>,
}

impl Labelled {
    /// The map `value` is, its labels between 1 and `highest`.
    pub fn new(value: Value, highest: i64) -> Result<Self, RecordError> {
        let Value::Map(pairs) = value else {
            return Err(RecordError::Malformed("a map is expected".to_owned()));
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

    pub fn text(&mut self, label: i64) -> Result<String, RecordError> {
        match self.take(label)? {
            Value::Text(text) => Ok(text),
            _ => Err(RecordError::Malformed(format!("label {label} is text"))),
        }
    }

    pub fn uint(&mut self, label: i64) -> Result<u64, RecordError> {
        match self.take(label)? {
            Value::Int(value) if value >= 0 => Ok(value as u64),
            _ => Err(RecordError::Malformed(format!(
                "label {label} is an unsigned integer"
            ))),
        }
    }

    pub fn optional_uint(&mut self, label: i64) -> Result<Option<u64>, RecordError> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Int(value)) if value >= 0 => Ok(Some(value as u64)),
            Some(_) => Err(RecordError::Malformed(format!(
                "label {label} is an unsigned integer"
            ))),
        }
    }

    pub fn optional_text(&mut self, label: i64) -> Result<Option<String>, RecordError> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Text(text)) => Ok(Some(text)),
            Some(_) => Err(RecordError::Malformed(format!("label {label} is text"))),
        }
    }

    pub fn optional_id(&mut self, label: i64) -> Result<Option<[u8; 16]>, RecordError> {
        match self.pairs.remove(&label) {
            None => Ok(None),
            Some(Value::Bytes(bytes)) => bytes
                .as_slice()
                .try_into()
                .map(Some)
                .map_err(|_| RecordError::Malformed(format!("label {label} is 16 bytes"))),
            Some(_) => Err(RecordError::Malformed(format!("label {label} is bytes"))),
        }
    }

    pub fn optional_operation_id(
        &mut self,
        label: i64,
    ) -> Result<Option<OperationId>, RecordError> {
        Ok(self.optional_id(label)?.map(OperationId::from_bytes))
    }

    /// An array at `label`, each item read by `item`; empty when the label is absent.
    pub fn array<T>(
        &mut self,
        label: i64,
        item: impl Fn(Value) -> Result<T, RecordError>,
    ) -> Result<Vec<T>, RecordError> {
        match self.pairs.remove(&label) {
            None => Ok(Vec::new()),
            Some(Value::Array(items)) => items.into_iter().map(item).collect(),
            Some(_) => Err(RecordError::Malformed(format!("label {label} is an array"))),
        }
    }

    /// Every label read: anything left is refused.
    pub fn finish(self) -> Result<(), RecordError> {
        match self.pairs.keys().next() {
            None => Ok(()),
            Some(label) => Err(RecordError::Malformed(format!("unexpected label {label}"))),
        }
    }
}

/// The text `value` is.
pub fn text_of(value: Value) -> Result<String, RecordError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(RecordError::Malformed("an item is text".to_owned())),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[test]
    fn a_map_reads_its_labels_and_refuses_what_is_left_or_unknown() {
        let value = map(vec![
            (1, Some(Value::Text("a".to_owned()))),
            (2, Some(uint(7).expect("an integer"))),
            (3, None),
        ]);
        let bytes = encode(&value).expect("encoded");
        let mut read = decode(&bytes, 3).expect("decoded");
        assert_eq!(read.text(1).expect("text"), "a");
        assert_eq!(read.optional_uint(3).expect("absent"), None);
        assert!(read.finish().is_err(), "label 2 was left");
        assert!(decode(&bytes, 1).is_err(), "label 2 is unknown at 1");
        assert!(matches!(
            decode(&vec![0; MAX_RECORD_BYTES + 1], 1),
            Err(RecordError::TooLarge(_))
        ));
        assert!(uint(u64::MAX).is_err());
    }
}
