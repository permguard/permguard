// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Canonical names shared by stream stores, configuration and cursors.

use std::fmt;

/// Whether `name` is one exact, portable filesystem segment.
///
/// Leading or trailing whitespace is refused rather than normalized: normalizing turns two wire
/// identities into one directory. The stricter ASCII alphabet keeps decision producer names
/// portable across every filesystem Permguard supports.
pub fn is_portable_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 128
        && name == name.trim()
        && !name.starts_with('.')
        && name.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

/// One position in the stable `(producer class, producer, instance)` stream order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct StreamPosition {
    producer_class: String,
    producer: String,
    instance: String,
}

impl StreamPosition {
    /// Builds a complete cursor. Empty or non-canonical parts are refused.
    pub fn new(
        producer_class: impl Into<String>,
        producer: impl Into<String>,
        instance: impl Into<String>,
    ) -> Result<Self, PositionError> {
        let position = Self {
            producer_class: producer_class.into(),
            producer: producer.into(),
            instance: instance.into(),
        };
        for (name, value) in [
            ("producer class", position.producer_class.as_str()),
            ("producer", position.producer.as_str()),
            ("instance", position.instance.as_str()),
        ] {
            if !is_portable_name(value) || value == "." || value == ".." {
                return Err(PositionError { part: name });
            }
        }

        Ok(position)
    }

    /// Parses the CLI representation `class/producer/instance` exactly.
    pub fn parse(encoded: &str) -> Result<Self, PositionError> {
        let mut parts = encoded.split('/');
        let (Some(producer_class), Some(producer), Some(instance), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(PositionError { part: "cursor" });
        };

        Self::new(producer_class, producer, instance)
    }

    pub fn as_tuple(&self) -> (&str, &str, &str) {
        (&self.producer_class, &self.producer, &self.instance)
    }

    pub fn into_tuple(self) -> (String, String, String) {
        (self.producer_class, self.producer, self.instance)
    }
}

/// A malformed stream position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PositionError {
    part: &'static str,
}

impl fmt::Display for PositionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the stream cursor's {} is not a canonical name",
            self.part
        )
    }
}

impl std::error::Error for PositionError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_position_is_complete_and_canonical() {
        assert!(StreamPosition::parse("data-plane/plane-a/boot-1").is_ok());
        for malformed in [
            "data-plane/plane-a",
            "data-plane/plane-a/boot-1/more",
            "data-plane//boot-1",
            "data-plane/ plane-a/boot-1",
            "data-plane/.plane-a/boot-1",
            "data-plane/pläne-a/boot-1",
        ] {
            assert!(StreamPosition::parse(malformed).is_err(), "{malformed}");
        }

        let too_long = "a".repeat(129);
        assert!(StreamPosition::new("data-plane", too_long, "boot-1").is_err());
    }
}
