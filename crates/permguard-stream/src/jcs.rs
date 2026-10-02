// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! JSON Canonicalization Scheme ([RFC 8785]) over the I-JSON profile ([RFC 7493]) — the
//! byte-for-byte agreement every digest and every signature over JSON rests on.
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
//! # Two directions, one profile
//!
//! [`canonicalize`] writes a value as its canonical bytes. [`parse_strict`] reads bytes that claim
//! to be a value and refuses everything the profile forbids: a duplicated member name, a number
//! that is not an integer within the I-JSON range, text that is not UTF-8, anything but one value.
//! [`decode_canonical`] does both and then requires the input to be byte-identical to the
//! canonical form of what it decoded — the rule at every trust boundary, so that a signature or a
//! digest is only ever checked over bytes that could have been produced by this canonicaliser.
//! A reader that silently repaired its input — kept the last of two duplicate names, re-encoded
//! `1.0` as `1` — would verify a signature over bytes the signer never saw.
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
//! - **Numbers are integers within ±2⁵³, by construction.** RFC 8785 defines number output as
//!   ECMAScript `Number::toString`, the single hardest part of the specification to implement
//!   identically and the classic source of interoperability failures; I-JSON additionally warns
//!   that an integer beyond 2⁵³ is not exactly representable by every reader. No field of a
//!   record needs a fractional value or a larger integer, so this canonicaliser **refuses** them
//!   rather than implementing a float printer two languages might disagree about. A refusal at
//!   write time is a bug caught in a test; a disagreement is a chain that stops verifying in
//!   production. Caller-supplied numbers that may be fractional go through [`normalized`] first.
//!
//! [RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785
//! [RFC 7493]: https://www.rfc-editor.org/rfc/rfc7493

use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// The largest integer magnitude the profile carries: 2⁵³, exactly representable by every reader.
pub const MAX_INTEGER: u64 = 1 << 53;

/// Why a value could not be canonicalised, or bytes could not be read as a canonical value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// A number that is not an exact integer — see the module documentation.
    NotAnInteger(String),
    /// An integer outside ±2⁵³, which not every reader represents exactly.
    OutOfRange(String),
    /// A member name that appears twice in one object; the reader does not choose a winner.
    DuplicateName(String),
    /// Bytes that are not one well-formed JSON text of the profile.
    Syntax(String),
    /// The bytes decoded, but they are not the canonical form of what they decode to.
    NotCanonical,
}

impl fmt::Display for CanonicalError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAnInteger(value) => write!(
                formatter,
                "`{value}` is not an integer: canonical records carry no fractional numbers, because their canonical form would depend on a float printer"
            ),
            Self::OutOfRange(value) => write!(
                formatter,
                "`{value}` is outside ±2^53: not every reader represents it exactly"
            ),
            Self::DuplicateName(name) => {
                write!(formatter, "the member `{name}` appears twice in one object")
            }
            Self::Syntax(detail) => write!(formatter, "not one canonical JSON text: {detail}"),
            Self::NotCanonical => write!(
                formatter,
                "the bytes decode, but they are not the canonical encoding of what they decode to"
            ),
        }
    }
}

impl std::error::Error for CanonicalError {}

/// Rewrites `value` so that [`canonicalize`] is total over it.
///
/// The canonicaliser refuses non-integer and out-of-range numbers — deliberately, see the
/// module documentation — but a decision record carries **caller-supplied**
/// values: context members, entity attributes, the properties a deployment
/// named in `include`. A caller who writes `{"risk": 0.7}` has written legal
/// JSON and a legal policy input, and a log that cannot commit to it — or
/// worse, refuses the decision over it — has let the caller steer the audit
/// trail.
///
/// So every number the profile refuses becomes a **string** carrying serde_json's
/// shortest-round-trip rendering, recursively. Deterministic for a given
/// value, so equality of commitments still means equality of inputs; explicit
/// in the record, so a reader sees `"0.7"` and knows the number was carried as
/// its decimal text rather than as a bit pattern two languages might print
/// differently.
pub fn normalized(value: &Value) -> Value {
    match value {
        Value::Number(number) if integer_in_range(number).is_none() => {
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

/// Reads one JSON text under the profile, refusing what the profile forbids.
///
/// Accepted: one value, UTF-8, integers within ±2⁵³, member names unique at every level. Refused:
/// a second value or trailing bytes, fractional or exponent numbers, integers beyond the range,
/// duplicated names, invalid UTF-8 or lone surrogates, nesting deeper than serde_json's bound.
/// Whitespace and member order are accepted — this reads a value; [`decode_canonical`] is the
/// check that the bytes were already canonical.
pub fn parse_strict(bytes: &[u8]) -> Result<Value, CanonicalError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue
        .deserialize(&mut deserializer)
        .map_err(|error| classify(&error))?;
    deserializer
        .end()
        .map_err(|error| CanonicalError::Syntax(error.to_string()))?;

    Ok(value)
}

/// Reads bytes that must already be canonical: [`parse_strict`], then byte equality with
/// [`canonicalize`] of the result.
pub fn decode_canonical(bytes: &[u8]) -> Result<Value, CanonicalError> {
    let value = parse_strict(bytes)?;
    if canonicalize(&value)? != bytes {
        return Err(CanonicalError::NotCanonical);
    }

    Ok(value)
}

/// The integer a number is, when it is one the profile carries.
fn integer_in_range(number: &serde_json::Number) -> Option<i128> {
    let value = number
        .as_u64()
        .map(i128::from)
        .or_else(|| number.as_i64().map(i128::from))?;
    (value.unsigned_abs() <= u128::from(MAX_INTEGER)).then_some(value)
}

/// A profile refusal travels through serde as a custom error; this reads it back out.
fn classify(error: &serde_json::Error) -> CanonicalError {
    let text = error.to_string();
    for (marker, build) in [
        (
            DUPLICATE,
            CanonicalError::DuplicateName as fn(String) -> CanonicalError,
        ),
        (FRACTION, CanonicalError::NotAnInteger),
        (RANGE, CanonicalError::OutOfRange),
    ] {
        if let Some(rest) = text.strip_prefix(marker) {
            let detail = rest.split(" at line ").next().unwrap_or(rest).to_owned();
            return build(detail);
        }
    }

    CanonicalError::Syntax(text)
}

const DUPLICATE: &str = "duplicate member ";
const FRACTION: &str = "non-integer number ";
const RANGE: &str = "integer out of range ";

/// Builds a [`Value`] while refusing what the profile forbids.
struct StrictValue;

impl<'de> DeserializeSeed<'de> for StrictValue {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(StrictValue)
    }
}

impl<'de> Visitor<'de> for StrictValue {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("one JSON value of the canonical profile")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        if value.unsigned_abs() > MAX_INTEGER {
            return Err(E::custom(format!("{RANGE}{value}")));
        }
        Ok(Value::from(value))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        if value > MAX_INTEGER {
            return Err(E::custom(format!("{RANGE}{value}")));
        }
        Ok(Value::from(value))
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        Err(E::custom(format!("{FRACTION}{value}")))
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: de::Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = sequence.next_element_seed(StrictValue)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let member = map.next_value_seed(StrictValue)?;
            if members.insert(key.clone(), member).is_some() {
                return Err(de::Error::custom(format!("{DUPLICATE}{key}")));
            }
        }
        Ok(Value::Object(members))
    }
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
    match integer_in_range(number) {
        Some(value) => {
            out.extend_from_slice(value.to_string().as_bytes());
            Ok(())
        }
        None if number.as_u64().is_some() || number.as_i64().is_some() => {
            Err(CanonicalError::OutOfRange(number.to_string()))
        }
        None => Err(CanonicalError::NotAnInteger(number.to_string())),
    }
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
    fn test_an_integer_beyond_the_profile_is_refused_and_normalized_to_text() {
        let value = json!({ "big": 18446744073709551615u64, "edge": 9007199254740992u64 });

        assert_eq!(
            canonicalize(&value),
            Err(CanonicalError::OutOfRange(
                "18446744073709551615".to_owned()
            ))
        );
        assert_eq!(
            canonical(&normalized(&value)),
            r#"{"big":"18446744073709551615","edge":9007199254740992}"#,
            "2^53 itself is carried, 2^64-1 becomes its decimal text"
        );
    }

    #[test]
    fn test_reparsing_canonical_bytes_reproduces_them() {
        let value = json!({ "z": [true, null, -7], "a": "x", "m": { "k": 9007199254740991u64 } });

        let once = canonical(&value);
        let again = canonical(&parse_strict(once.as_bytes()).expect("it parses"));

        assert_eq!(once, again, "canonicalisation is a fixed point");
        assert_eq!(
            decode_canonical(once.as_bytes()).expect("it decodes"),
            value
        );
    }

    #[test]
    fn test_a_duplicate_member_is_refused_not_resolved() {
        assert_eq!(
            parse_strict(br#"{"a":1,"a":2}"#),
            Err(CanonicalError::DuplicateName("a".to_owned()))
        );
        assert_eq!(
            parse_strict(br#"{"outer":{"k":1,"k":1}}"#),
            Err(CanonicalError::DuplicateName("k".to_owned())),
            "nested objects are checked too"
        );
    }

    #[test]
    fn test_non_canonical_numbers_and_texts_are_refused_on_read() {
        assert_eq!(
            parse_strict(b"1.0"),
            Err(CanonicalError::NotAnInteger("1".to_owned()))
        );
        assert!(matches!(
            parse_strict(b"1e2"),
            Err(CanonicalError::NotAnInteger(_))
        ));
        assert!(matches!(
            parse_strict(b"-0"),
            Err(CanonicalError::NotAnInteger(_))
        ));
        assert!(matches!(
            parse_strict(b"9007199254740993"),
            Err(CanonicalError::OutOfRange(_))
        ));
        assert!(matches!(
            parse_strict(b"01"),
            Err(CanonicalError::Syntax(_))
        ));
        assert!(matches!(
            parse_strict(b"NaN"),
            Err(CanonicalError::Syntax(_))
        ));
        assert!(matches!(
            parse_strict(b"\"\\udc00\""),
            Err(CanonicalError::Syntax(_))
        ));
        assert!(matches!(
            parse_strict(b"\"\xff\""),
            Err(CanonicalError::Syntax(_))
        ));
        assert!(matches!(
            parse_strict(b"1 2"),
            Err(CanonicalError::Syntax(_))
        ));
        assert!(matches!(
            parse_strict(b"{\"a\":1} x"),
            Err(CanonicalError::Syntax(_))
        ));
    }

    #[test]
    fn test_decode_canonical_refuses_bytes_that_are_not_already_canonical() {
        assert_eq!(
            decode_canonical(br#"{"b":1,"a":2}"#),
            Err(CanonicalError::NotCanonical)
        );
        assert_eq!(
            decode_canonical(br#"{ "a": 1 }"#),
            Err(CanonicalError::NotCanonical)
        );
        assert_eq!(
            decode_canonical(br#"{"a":"\/"}"#),
            Err(CanonicalError::NotCanonical)
        );
        assert_eq!(
            decode_canonical(br#"{"a":1,"b":2}"#),
            Ok(json!({"a": 1, "b": 2}))
        );
    }

    #[test]
    fn test_nesting_past_the_bound_is_refused_not_overflowed() {
        let deep = format!("{}{}", "[".repeat(10_000), "]".repeat(10_000));

        assert!(matches!(
            parse_strict(deep.as_bytes()),
            Err(CanonicalError::Syntax(_))
        ));
    }
}
