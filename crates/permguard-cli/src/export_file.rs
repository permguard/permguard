// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Reading an export file a verification is asked of (`decisions verify --file`, `events verify
//! --file`): its declared format first, then the archive, in time linear in its size (BUG-0145).
//!
//! The format is read before the archive is: a file of another format is refused for its format,
//! whatever its shape, never as a malformed archive of this one. A file that begins as JSON is
//! JSON, and its own error is the one reported. Nesting deeper than an export ever holds is
//! refused by a single pass before any parser runs: the YAML parser's time grows faster than the
//! nesting it is given.

use serde::de::DeserializeOwned;
use serde_json::Value;

/// The deepest nesting an export holds by far: serde_json's own recursion bound.
const MAX_DEPTH: usize = 128;

/// Why a file is not an archive this command verifies.
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// Not a readable archive: its text, its nesting, or its shape.
    Malformed(String),
    /// An archive of another format, the one it declares.
    Format(String),
}

/// The archive in `text`, declaring `format`.
pub fn read<T: DeserializeOwned>(text: &str, format: &str) -> Result<T, Refused> {
    let depth = depth(text);
    if depth > MAX_DEPTH {
        return Err(Refused::Malformed(format!(
            "it nests {depth} levels deep, where an export holds at most {MAX_DEPTH}"
        )));
    }
    let value: Value = if text.trim_start().starts_with(['{', '[']) {
        serde_json::from_str(text).map_err(|error| Refused::Malformed(error.to_string()))?
    } else {
        let yaml: serde_norway::Value =
            serde_norway::from_str(text).map_err(|error| Refused::Malformed(error.to_string()))?;
        serde_json::to_value(yaml).map_err(|error| Refused::Malformed(error.to_string()))?
    };
    match value.get("format").and_then(Value::as_str) {
        None => {
            return Err(Refused::Malformed("it declares no `format`".to_owned()));
        }
        Some(declared) if declared != format => {
            return Err(Refused::Format(declared.to_owned()));
        }
        Some(_) => {}
    }
    serde_json::from_value(value).map_err(|error| Refused::Malformed(error.to_string()))
}

/// The deepest nesting of `text`, in one pass: brackets and braces outside quoted strings, and
/// the indentation of a block, two columns a level.
fn depth(text: &str) -> usize {
    let (mut deepest, mut open) = (0usize, 0usize);
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for character in text.chars() {
        if let Some(closing) = quote {
            if escaped {
                escaped = false;
            } else if character == '\\' && closing == '"' {
                escaped = true;
            } else if character == closing {
                quote = None;
            }
            continue;
        }
        match character {
            '"' | '\'' => quote = Some(character),
            '[' | '{' => {
                open += 1;
                deepest = deepest.max(open);
            }
            ']' | '}' => open = open.saturating_sub(1),
            _ => {}
        }
    }
    let indented = text
        .lines()
        .map(|line| line.len() - line.trim_start_matches(' ').len())
        .max()
        .unwrap_or(0)
        / 2;
    deepest.max(indented)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[derive(Debug, serde::Deserialize)]
    struct Archive {
        format: String,
        records: Vec<Value>,
    }

    #[test]
    fn the_format_is_read_before_the_archive() {
        let read_as = |text: &str| read::<Archive>(text, "this.v1");
        let archive = read_as(r#"{"format": "this.v1", "records": [1]}"#).expect("an archive");
        assert_eq!(
            (archive.format.as_str(), archive.records.len()),
            ("this.v1", 1)
        );
        assert!(read_as("format: this.v1\nrecords: [1]\n").is_ok(), "YAML");
        assert_eq!(
            read_as(r#"{"format": "other.v1", "anything": true}"#).expect_err("another"),
            Refused::Format("other.v1".to_owned()),
            "another format is refused for its format, whatever its shape"
        );
        assert!(matches!(
            read_as(r#"{"records": []}"#),
            Err(Refused::Malformed(why)) if why.contains("format")
        ));
    }

    #[test]
    fn a_file_that_begins_as_json_reports_the_json_error() {
        let Err(Refused::Malformed(why)) = read::<Archive>("{ \"format\": ", "this.v1") else {
            panic!("refused");
        };
        assert!(why.contains("EOF") || why.contains("line 1"), "{why}");
    }

    #[test]
    fn deep_nesting_is_refused_at_once() {
        for text in [
            format!("{}{}", "[".repeat(100_000), "]".repeat(100_000)),
            format!("format: x\nrecords:\n{}", "- ".repeat(50_000)),
            format!("a: {}", "[".repeat(200)),
        ] {
            let started = std::time::Instant::now();
            assert!(matches!(
                read::<Archive>(&text, "this.v1"),
                Err(Refused::Malformed(_))
            ));
            assert!(
                started.elapsed() < std::time::Duration::from_secs(1),
                "{:?}",
                started.elapsed()
            );
        }
        assert_eq!(
            depth(r#"{"a": "[[[[", "b": '{{'}"#),
            1,
            "quoted brackets are text"
        );
    }
}
