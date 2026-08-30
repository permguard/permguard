// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! JSON Canonicalization Scheme ([RFC 8785]) — the byte-for-byte agreement
//! every digest in this crate rests on.
//!
//! # Why this exists at all
//!
//! A record is hashed, and the hash must be reproducible by somebody who
//! parsed the JSON and re-serialised it years later, in another language.
//! Ordinary serialisation cannot promise that: key order, whitespace, escape
//! choices and number formatting are all free. Canonicalisation removes every
//! degree of freedom, so two implementations that agree on the *value* cannot
//! disagree on the *bytes*.
//!
//! # The three rules that are easy to get wrong
//!
//! - **Object keys sort by UTF-16 code unit**, not by UTF-8 byte. The two
//!   orders differ for anything above the basic plane: `"\u{10000}"` sorts
//!   *before* `"\u{e000}"` in UTF-16 and *after* it in UTF-8. Sorting the
//!   wrong way is invisible until the first non-Latin key.
//! - **Strings escape the minimum**: the two mandatory characters, the six
//!   short forms, and `\u00xx` for the remaining control characters. Nothing
//!   else — an implementation that escapes `/` or non-ASCII produces different
//!   bytes for the same string.
//! - **Numbers are integers here, by construction.** RFC 8785 defines number
//!   output as ECMAScript `Number::toString`, which is the single hardest
//!   part of the specification to implement identically, and the classic
//!   source of interoperability failures. No field of a decision record needs
//!   a fractional value, so this canonicaliser **refuses** them rather than
//!   implementing a shortest-round-trip float printer that two languages might
//!   disagree about. A refusal at write time is a bug caught in a test; a
//!   disagreement is a chain that stops verifying in production.
//!
//! [RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785

use std::fmt;

use serde_json::Value;

/// Why a value could not be canonicalised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// A number that is not an exact integer — see the module documentation.
    NotAnInteger(String),
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnInteger(value) => write!(
                formatter,
                "`{value}` is not an integer: decision records carry no fractional numbers, because their canonical form would depend on a float printer"
            ),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Rewrites `value` so that [`canonicalize`] is total over it.
///
/// The canonicaliser refuses non-integer numbers — deliberately, see the
/// module documentation — but a decision record carries **caller-supplied**
/// values: context members, entity attributes, the properties a deployment
/// named in `include`. A caller who writes `{"risk": 0.7}` has written legal
/// JSON and a legal policy input, and a log that cannot commit to it — or
/// worse, refuses the decision over it — has let the caller steer the audit
/// trail.
///
/// So every non-integer number becomes a **string** carrying serde_json's
/// shortest-round-trip rendering, recursively. Deterministic for a given
/// value, so equality of commitments still means equality of inputs; explicit
/// in the record, so a reader sees `"0.7"` and knows the number was carried as
/// its decimal text rather than as a bit pattern two languages might print
/// differently.
pub fn normalized(value: &Value) -> Value {
    match value {
        Value::Number(number) if number.as_u64().is_none() && number.as_i64().is_none() => {
            Value::String(number.to_string())
        }
        Value::Array(items) => Value::Array(items.iter().map(normalized).collect()),
        Value::Object(members) => Value::Object(
            members
                .iter()
                .map(|(key, member)| (key.clone(), normalized(member)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Serialises `value` to its canonical bytes.
pub fn canonicalize(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;

    Ok(out)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(number) => write_number(number, out)?,
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(members) => {
            // Collected and sorted rather than trusted: the map's own order is
            // an implementation detail of whoever built the value.
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|left, right| utf16_cmp(left, right));

            out.push(b'{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                if let Some(member) = members.get(key) {
                    write_value(member, out)?;
                }
            }
            out.push(b'}');
        }
    }

    Ok(())
}

fn write_number(number: &serde_json::Number, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    if let Some(value) = number.as_u64() {
        out.extend_from_slice(value.to_string().as_bytes());
        return Ok(());
    }
    if let Some(value) = number.as_i64() {
        out.extend_from_slice(value.to_string().as_bytes());
        return Ok(());
    }

    Err(CanonicalError::NotAnInteger(number.to_string()))
}

fn write_string(text: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for character in text.chars() {
        match character {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            control if (control as u32) < 0x20 => {
                out.extend_from_slice(format!("\\u{:04x}", control as u32).as_bytes());
            }
            other => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(other.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Compares two strings by UTF-16 code unit, as RFC 8785 requires.
fn utf16_cmp(left: &str, right: &str) -> std::cmp::Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    fn canonical(value: &Value) -> String {
        String::from_utf8(canonicalize(value).expect("it canonicalises")).expect("it is utf-8")
    }

    #[test]
    fn test_members_are_ordered_and_whitespace_is_gone() {
        let value = json!({ "b": 1, "a": { "d": [1, 2], "c": true } });

        assert_eq!(canonical(&value), r#"{"a":{"c":true,"d":[1,2]},"b":1}"#);
    }

    #[test]
    fn test_keys_sort_by_utf16_code_unit_not_by_utf8_byte() {
        // U+10000 is one code unit pair beginning with 0xD800, so it sorts
        // BEFORE U+E000 in UTF-16 — and after it in UTF-8.
        let value = json!({ "\u{e000}": 1, "\u{10000}": 2 });

        assert_eq!(
            canonical(&value),
            "{\"\u{10000}\":2,\"\u{e000}\":1}",
            "sorting by UTF-8 bytes would put U+E000 first"
        );
    }

    #[test]
    fn test_only_the_mandatory_escapes_are_written() {
        let value = json!({ "s": "a\"b\\c\nd\te\u{1}f/g\u{e9}" });

        assert_eq!(
            canonical(&value),
            "{\"s\":\"a\\\"b\\\\c\\nd\\te\\u0001f/g\u{e9}\"}",
            "a solidus is not escaped, and non-ASCII stays literal"
        );
    }

    #[test]
    fn test_a_fractional_number_is_refused_rather_than_printed() {
        let value = json!({ "latency": 1.5 });

        assert_eq!(
            canonicalize(&value),
            Err(CanonicalError::NotAnInteger("1.5".to_owned()))
        );
    }

    #[test]
    fn test_reparsing_canonical_bytes_reproduces_them() {
        let value =
            json!({ "z": [true, null, -7], "a": "x", "m": { "k": 18446744073709551615u64 } });

        let once = canonical(&value);
        let again = canonical(&serde_json::from_str(&once).expect("it parses"));

        assert_eq!(once, again, "canonicalisation is a fixed point");
    }
}
