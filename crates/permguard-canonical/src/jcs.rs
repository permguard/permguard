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
//! to be a value and refuses everything the profile forbids: a duplicated member name, an integer
//! that does not read back as written, text that is not UTF-8, anything but one value.
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
//! - **Numbers are written as ECMAScript writes them.** RFC 8785 defines number output as
//!   ECMAScript `Number.prototype.toString` over the IEEE-754 double: the shortest digits that
//!   read back to the same double, in plain notation from 10⁻⁶ up to 10²¹ and in exponent
//!   notation outside it — `1e+30`, `4.5`, `0.002`, `-0` as `0`. The digits come from the
//!   standard library's shortest round-trip formatting; the notation rules are applied here. The
//!   RFC's Appendix B and 3 366 values printed by Node are the vectors this is held to.
//! - **An integer must read back as written.** A number with a fraction or an exponent is read
//!   as the nearest double, as RFC 8785 does. An integer written without either, whose double
//!   prints other digits — `9007199254740993` reads as `9007199254740992` — carries precision
//!   beyond IEEE double, which strict I-JSON forbids, and is refused rather than silently
//!   changed. Integers within ±2⁵³ always read back, so their bytes are what they always were.
//!
//! [RFC 8785]: https://www.rfc-editor.org/rfc/rfc8785
//! [RFC 7493]: https://www.rfc-editor.org/rfc/rfc7493

use std::cell::RefCell;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// The largest integer magnitude the profile carries: 2⁵³, exactly representable by every reader.
pub const MAX_INTEGER: u64 = 1 << 53;

/// Why a value could not be canonicalised, or bytes could not be read as a canonical value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalError {
    /// An integer that does not read back as written: precision beyond IEEE double.
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
            Self::OutOfRange(value) => write!(
                formatter,
                "`{value}` does not read back as written: it carries precision beyond IEEE double"
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

/// Rewrites every number outside the integers within ±2⁵³ as its decimal text.
///
/// The canonicaliser writes every finite number, but a decision record carries **caller-supplied**
/// values: context members, entity attributes, the properties a deployment
/// named in `include`. A caller who writes `{"risk": 0.7}` has written legal
/// JSON and a legal policy input, and a log that cannot commit to it — or
/// worse, refuses the decision over it — has let the caller steer the audit
/// trail.
///
/// Records have always committed such a number as a **string** carrying serde_json's
/// shortest-round-trip rendering, recursively. Deterministic for a given
/// value, so equality of commitments still means equality of inputs; explicit
/// in the record, so a reader sees `"0.7"` and knows the number was carried as
/// its decimal text. Kept as it is so a record's committed bytes do not depend on when it was
/// written: carrying such numbers as numbers would be a new record format version.
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
/// Accepted: one value, UTF-8, every finite number, member names unique at every level. Refused:
/// a second value or trailing bytes, an integer that does not read back as written, a number
/// beyond the double range, duplicated names, invalid UTF-8 or lone surrogates, nesting deeper
/// than serde_json's bound.
/// Whitespace and member order are accepted — this reads a value; [`decode_canonical`] is the
/// check that the bytes were already canonical.
pub fn parse_strict(bytes: &[u8]) -> Result<Value, CanonicalError> {
    let numbers = RefCell::new(number_tokens(bytes)?.into_iter());
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = StrictValue { numbers: &numbers }
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
const RANGE: &str = "integer out of range ";

/// Builds a [`Value`] while refusing what the profile forbids.
///
/// `numbers` is every number's text, in document order, which is the order serde_json visits
/// them: a fraction or an exponent is read from its text by the standard library, which rounds
/// to the nearest double as RFC 8785 requires, rather than by serde_json's faster reader, which
/// may land one unit in the last place away.
#[derive(Clone, Copy)]
struct StrictValue<'n> {
    numbers: &'n RefCell<std::vec::IntoIter<String>>,
}

impl StrictValue<'_> {
    fn next_number(&self) -> Option<String> {
        self.numbers.borrow_mut().next()
    }

    /// An integer within ±2⁵³ is kept as the integer it is. A wider one denotes, under RFC 8785,
    /// the double its text reads as — `number_tokens` already refused one that does not read back
    /// as written — so it is kept as that double, which is what the canonical form prints.
    fn integer<E: de::Error>(self, value: i128, approximate: f64) -> Result<Value, E> {
        let text = self.next_number();
        if value.unsigned_abs() <= u128::from(MAX_INTEGER) {
            return Ok(Value::Number(if value < 0 {
                serde_json::Number::from(value as i64)
            } else {
                serde_json::Number::from(value as u64)
            }));
        }
        let double = text
            .and_then(|text| text.parse::<f64>().ok())
            .unwrap_or(approximate);
        serde_json::Number::from_f64(double)
            .map(Value::Number)
            .ok_or_else(|| E::custom(format!("{RANGE}{value}")))
    }
}

impl<'de> DeserializeSeed<'de> for StrictValue<'_> {
    type Value = Value;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for StrictValue<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("one JSON value of the canonical profile")
    }

    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }

    // An integer that does not read back as written was refused before deserialisation began,
    // by `integers_read_back`, which sees the text serde_json does not keep.
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Value, E> {
        self.integer(i128::from(value), value as f64)
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Value, E> {
        self.integer(i128::from(value), value as f64)
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Value, E> {
        let exact = self
            .next_number()
            .and_then(|text| text.parse::<f64>().ok())
            .unwrap_or(value);
        serde_json::Number::from_f64(exact)
            .map(Value::Number)
            .ok_or_else(|| E::custom(format!("{RANGE}{value}")))
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
        while let Some(item) = sequence.next_element_seed(self)? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut members = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            let member = map.next_value_seed(self)?;
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

/// An integer beyond ±2⁵³ that is exactly a double is written with ECMAScript's digits for that
/// double, as RFC 8785 requires — `2⁶³` is `9223372036854776000` — not with its own.
fn write_number(number: &serde_json::Number, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    // Integers within ±2⁵³ are exact doubles, and ECMAScript prints them as plain integers.
    if let Some(value) = integer_in_range(number) {
        out.extend_from_slice(value.to_string().as_bytes());
        return Ok(());
    }
    // A wider integer is written only when its double is exactly it: anything else would be a
    // number silently changed on the way to its signature.
    let integer = number
        .as_u64()
        .map(i128::from)
        .or_else(|| number.as_i64().map(i128::from));
    let double = number
        .as_f64()
        .filter(|double| double.is_finite())
        .ok_or_else(|| CanonicalError::OutOfRange(number.to_string()))?;
    if let Some(integer) = integer
        && double as i128 != integer
    {
        return Err(CanonicalError::OutOfRange(number.to_string()));
    }
    out.extend_from_slice(ecmascript(double).as_bytes());

    Ok(())
}

/// A double as ECMAScript's `Number.prototype.toString` writes it, which RFC 8785 makes canonical.
///
/// The shortest digits that read back to the same double come from the standard library's
/// exponent formatting, which is shortest round-trip; what is applied here is ECMAScript's choice
/// of notation for those digits (ECMA-262, Number::toString, steps 6 to 12).
fn ecmascript(double: f64) -> String {
    if double == 0.0 {
        // Negative zero included: ECMAScript writes both as `0`.
        return "0".to_owned();
    }
    let sign = if double < 0.0 { "-" } else { "" };
    let magnitude = double.abs();
    let shortest = format!("{magnitude:e}");
    // The shortest round trip settles how many digits; which digits, when the double lies exactly
    // halfway between two candidates of that length, ECMAScript settles as the even one. The
    // fixed-precision formatting rounds the exact value half to even, so it is asked for the same
    // number of digits and kept when it still reads back to the same double.
    let length = shortest
        .split_once('e')
        .map_or(shortest.len(), |(mantissa, _)| {
            mantissa.chars().filter(char::is_ascii_digit).count()
        });
    let even = format!(
        "{magnitude:.precision$e}",
        precision = length.saturating_sub(1)
    );
    let scientific = if even.parse::<f64>().ok() == Some(magnitude) {
        even
    } else {
        shortest
    };
    let (mantissa, exponent) = scientific
        .split_once('e')
        .unwrap_or((scientific.as_str(), "0"));
    let digits: String = mantissa.chars().filter(char::is_ascii_digit).collect();
    let exponent: i32 = exponent.parse().unwrap_or(0);
    // ECMAScript's `n`: where the decimal point falls relative to the digits.
    let point = exponent + 1;
    let count = digits.len() as i32;

    let body = if count <= point && point <= 21 {
        format!("{digits}{}", "0".repeat((point - count) as usize))
    } else if 0 < point && point <= 21 {
        let (whole, fraction) = digits.split_at(point as usize);
        format!("{whole}.{fraction}")
    } else if -6 < point && point <= 0 {
        format!("0.{}{digits}", "0".repeat((-point) as usize))
    } else {
        let shown = point - 1;
        let exponent = if shown >= 0 {
            format!("e+{shown}")
        } else {
            format!("e-{}", -shown)
        };
        match digits.split_at(1) {
            (first, "") => format!("{first}{exponent}"),
            (first, rest) => format!("{first}.{rest}{exponent}"),
        }
    };

    format!("{sign}{body}")
}

/// Every number's text, in document order — refusing an integer, a number written without
/// fraction or exponent, that does not read back as written: its double prints other digits, so
/// it carries precision beyond IEEE double.
///
/// Done on the text, before serde_json reads it, because serde_json keeps the value and not the
/// spelling: `18446744073709551616` reaches a visitor as a double, indistinguishable from
/// `1.8446744073709552e19`. `-0` is the one integer spelling allowed to print differently: it is
/// zero, read as zero. Text that is not JSON is left to serde_json to refuse.
fn number_tokens(bytes: &[u8]) -> Result<Vec<String>, CanonicalError> {
    let mut tokens = Vec::new();
    let mut index = 0;
    let mut in_string = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_string {
            match byte {
                b'\\' => index += 1,
                b'"' => in_string = false,
                _ => {}
            }
            index += 1;
            continue;
        }
        if byte == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if byte == b'-' || byte.is_ascii_digit() {
            let start = index;
            while index < bytes.len()
                && (bytes[index].is_ascii_digit() || b"+-.eE".contains(&bytes[index]))
            {
                index += 1;
            }
            let token = &bytes[start..index];
            tokens.push(String::from_utf8_lossy(token).into_owned());
            // Up to fifteen digits every integer is an exact double and prints as written.
            let integer = !token.iter().any(|byte| b".eE".contains(byte));
            let digits = token.iter().filter(|byte| byte.is_ascii_digit()).count();
            if integer && digits > 15 && token != b"-0" {
                let text = std::str::from_utf8(token).unwrap_or_default();
                // Not a number at all is serde_json's to refuse, as syntax.
                if let Ok(double) = text.parse::<f64>()
                    && !(double.is_finite() && ecmascript(double) == text)
                {
                    return Err(CanonicalError::OutOfRange(text.to_owned()));
                }
            }
            continue;
        }
        index += 1;
    }

    Ok(tokens)
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

    /// The strict reader relies on serde_json handing numbers to the visitor as numbers; the
    /// `arbitrary_precision` feature would hand them over as maps, and nothing would notice.
    #[test]
    fn test_serde_json_reads_numbers_as_numbers() {
        assert!(
            serde_json::from_str::<Value>("1.5")
                .expect("it parses")
                .is_number()
        );
        assert_eq!(parse_strict(b"[1.5]"), Ok(json!([1.5])));
    }

    #[test]
    fn test_a_fraction_is_written_as_ecmascript_writes_it() {
        assert_eq!(canonical(&json!({ "latency": 1.5 })), r#"{"latency":1.5}"#);
        assert_eq!(
            canonical(&json!([0.1, -0.0, 1e21, 1e-7, 123e-20])),
            "[0.1,0,1e+21,1e-7,1.23e-18]"
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
        // A number spelled other than canonically reads as its value, and fails byte identity.
        for spelling in [&b"1.0"[..], b"1e2", b"-0", b"4.50"] {
            assert!(parse_strict(spelling).is_ok());
            assert_eq!(
                decode_canonical(spelling),
                Err(CanonicalError::NotCanonical)
            );
        }
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
