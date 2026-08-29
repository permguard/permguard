// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one mapping between JSON on the wire and Dogwood's runtime values.
//!
//! # Why a mapping needs writing down at all
//!
//! JSON has fewer types than Dogwood does, and the places where they disagree are exactly the
//! places a policy can be weakened without anybody noticing:
//!
//! | Dogwood | JSON | What a careless mapping does |
//! | --- | --- | --- |
//! | decimal | number | becomes an IEEE-754 double: `0.1 + 0.2` stops being `0.3` |
//! | entity UID | object or string | becomes a string, and `principal == User::"alice"` stops matching |
//! | record | object | becomes an entity because it happens to have `type` and `id` keys |
//! | absent | `null` | becomes present-and-null, which a policy tests differently |
//!
//! Each of those is a silent change in what a policy decides. So the mapping is explicit, it is
//! the same in both directions, and a value that cannot be represented exactly is **refused**
//! rather than approximated — an authorization system that rounds is an authorization system that
//! answers a question nobody asked.
//!
//! # The shape
//!
//! Ordinary JSON carries the unambiguous types directly, so a caller writes what it means:
//!
//! ```json
//! { "amount": 500, "currency": "EUR", "approved": true, "note": null }
//! ```
//!
//! The two ambiguous ones use Cedar's own escapes, which Permguard already speaks in its Cedar
//! entity stores — one convention across the product rather than a second one invented here:
//!
//! ```json
//! { "owner":  { "__entity": { "type": "Drupe::OAuthUser", "id": "alice" } } }
//! { "amount": { "__extn":   { "fn": "decimal", "arg": "500.25" } } }
//! ```

use std::collections::BTreeMap;

use dogwood_language::Value as DogwoodValue;
use serde_json::{Map, Number, Value as Json};

/// The key Cedar uses to escape an entity reference.
pub const ENTITY_ESCAPE: &str = "__entity";
/// The key Cedar uses to escape an extension value, of which `decimal` is the one Dogwood carries.
pub const EXTENSION_ESCAPE: &str = "__extn";
/// The extension function naming a decimal.
pub const DECIMAL_FUNCTION: &str = "decimal";

/// Why a JSON value is not a Dogwood value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueError {
    /// Where in the document, in dotted path form, so a caller can find it.
    pub at: String,
    pub message: String,
}

impl ValueError {
    fn new(at: &str, message: impl Into<String>) -> Self {
        Self {
            at: if at.is_empty() {
                "<root>".to_owned()
            } else {
                at.to_owned()
            },
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ValueError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "at `{}`: {}", self.at, self.message)
    }
}

impl std::error::Error for ValueError {}

/// One JSON value, as the Dogwood value it exactly represents.
pub fn from_json(json: &Json) -> Result<DogwoodValue, ValueError> {
    convert(json, "")
}

fn convert(json: &Json, at: &str) -> Result<DogwoodValue, ValueError> {
    match json {
        Json::Null => Ok(DogwoodValue::Null),
        Json::Bool(held) => Ok(DogwoodValue::Bool(*held)),
        Json::Number(held) => number(held, at),
        Json::String(held) => Ok(DogwoodValue::String(held.clone())),
        Json::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, item)| convert(item, &push(at, &index.to_string())))
            .collect::<Result<Vec<DogwoodValue>, ValueError>>()
            .map(DogwoodValue::Array),
        Json::Object(fields) => object(fields, at),
    }
}

/// A JSON number, which must be a whole number Dogwood can hold.
///
/// Dogwood's integer is a signed 64-bit one and its decimal is *not* a float — it is canonical
/// text, compared the way Cedar compares decimals. So a JSON fraction has no Dogwood counterpart
/// and is refused with the escape it should have used: silently making it a decimal would invent
/// a precision the caller never stated, and making it an integer would discard the part after the
/// point.
fn number(held: &Number, at: &str) -> Result<DogwoodValue, ValueError> {
    if let Some(whole) = held.as_i64() {
        return Ok(DogwoodValue::Int(whole));
    }
    if held.as_u64().is_some() {
        return Err(ValueError::new(
            at,
            format!(
                "`{held}` is beyond the signed 64-bit integer Dogwood holds: state it as a \
                 decimal with `{{\"{EXTENSION_ESCAPE}\": {{\"fn\": \"{DECIMAL_FUNCTION}\", \
                 \"arg\": \"…\"}}}}` if that is what it is"
            ),
        ));
    }

    Err(ValueError::new(
        at,
        format!(
            "`{held}` is a JSON fraction, and Dogwood has no floating-point type: a decimal is \
             exact text, so state it as `{{\"{EXTENSION_ESCAPE}\": {{\"fn\": \
             \"{DECIMAL_FUNCTION}\", \"arg\": \"{held}\"}}}}` rather than letting a binary float \
             decide what it rounds to"
        ),
    ))
}

/// A JSON object, which is a record unless it is exactly one of the two escapes.
///
/// "Exactly": an object is an escape only when the escape key is its **sole** key. An object that
/// merely contains `__entity` beside other fields is a record with an oddly named field, and
/// guessing otherwise would let a caller turn a record into an entity by naming a field.
fn object(fields: &Map<String, Json>, at: &str) -> Result<DogwoodValue, ValueError> {
    if fields.len() == 1 {
        if let Some(entity) = fields.get(ENTITY_ESCAPE) {
            return self_entity(entity, &push(at, ENTITY_ESCAPE));
        }
        if let Some(extension) = fields.get(EXTENSION_ESCAPE) {
            return decimal(extension, &push(at, EXTENSION_ESCAPE));
        }
    }

    let mut record = BTreeMap::new();
    for (name, value) in fields {
        record.insert(name.clone(), convert(value, &push(at, name))?);
    }

    Ok(DogwoodValue::Object(record))
}

fn self_entity(entity: &Json, at: &str) -> Result<DogwoodValue, ValueError> {
    let Json::Object(fields) = entity else {
        return Err(ValueError::new(
            at,
            "an entity reference is an object with `type` and `id`",
        ));
    };
    let text = |key: &str| {
        fields
            .get(key)
            .and_then(Json::as_str)
            .filter(|held| !held.is_empty())
            .map(ToOwned::to_owned)
            .ok_or_else(|| {
                ValueError::new(
                    at,
                    format!("an entity reference states a non-empty `{key}`"),
                )
            })
    };
    let ty = text("type")?;
    let id = text("id")?;
    if fields.len() != 2 {
        return Err(ValueError::new(
            at,
            "an entity reference carries `type` and `id` and nothing else",
        ));
    }

    Ok(DogwoodValue::Entity { ty, id })
}

fn decimal(extension: &Json, at: &str) -> Result<DogwoodValue, ValueError> {
    let Json::Object(fields) = extension else {
        return Err(ValueError::new(
            at,
            "an extension value is an object with `fn` and `arg`",
        ));
    };
    let function = fields.get("fn").and_then(Json::as_str).unwrap_or_default();
    if function != DECIMAL_FUNCTION {
        return Err(ValueError::new(
            at,
            format!(
                "`{function}` is not an extension Dogwood carries on this boundary: the only one \
                 is `{DECIMAL_FUNCTION}`"
            ),
        ));
    }
    let argument = fields.get("arg").and_then(Json::as_str).ok_or_else(|| {
        ValueError::new(at, "a decimal's `arg` is its exact text, as a JSON string")
    })?;
    if !is_decimal_text(argument) {
        return Err(ValueError::new(
            at,
            format!("`{argument}` is not a decimal: it is text of the form `-?digits.digits`"),
        ));
    }

    Ok(DogwoodValue::Decimal(argument.to_owned()))
}

/// Whether text is a decimal literal, in the shape Cedar accepts.
fn is_decimal_text(text: &str) -> bool {
    let body = text.strip_prefix('-').unwrap_or(text);
    let Some((whole, fraction)) = body.split_once('.') else {
        return false;
    };

    !whole.is_empty()
        && !fraction.is_empty()
        && whole.bytes().all(|byte| byte.is_ascii_digit())
        && fraction.bytes().all(|byte| byte.is_ascii_digit())
}

/// One Dogwood value, as the JSON that represents it exactly.
///
/// The inverse of [`from_json`] for everything [`from_json`] accepts, which is what the round-trip
/// tests hold it to: a value that survives one direction and not the other is a value a caller
/// cannot read back.
pub fn to_json(value: &DogwoodValue) -> Json {
    match value {
        DogwoodValue::Null => Json::Null,
        DogwoodValue::Bool(held) => Json::Bool(*held),
        DogwoodValue::Int(held) => Json::Number(Number::from(*held)),
        DogwoodValue::Decimal(text) => {
            let mut extension = Map::new();
            extension.insert("fn".to_owned(), Json::String(DECIMAL_FUNCTION.to_owned()));
            extension.insert("arg".to_owned(), Json::String(text.clone()));
            let mut wrapper = Map::new();
            wrapper.insert(EXTENSION_ESCAPE.to_owned(), Json::Object(extension));

            Json::Object(wrapper)
        }
        DogwoodValue::String(held) => Json::String(held.clone()),
        DogwoodValue::Entity { ty, id } => {
            let mut entity = Map::new();
            entity.insert("type".to_owned(), Json::String(ty.clone()));
            entity.insert("id".to_owned(), Json::String(id.clone()));
            let mut wrapper = Map::new();
            wrapper.insert(ENTITY_ESCAPE.to_owned(), Json::Object(entity));

            Json::Object(wrapper)
        }
        DogwoodValue::Array(items) => Json::Array(items.iter().map(to_json).collect()),
        DogwoodValue::Object(fields) => Json::Object(
            fields
                .iter()
                .map(|(name, held)| (name.clone(), to_json(held)))
                .collect(),
        ),
    }
}

fn push(at: &str, segment: &str) -> String {
    if at.is_empty() {
        segment.to_owned()
    } else {
        format!("{at}.{segment}")
    }
}

/// How many decimal places Cedar keeps.
///
/// Cedar holds a decimal as `value / 10^4` in an `i64`, so four is not a rounding choice — it is
/// the representation, and a fifth place is a value Cedar refuses rather than rounds.
const DECIMAL_PLACES: u32 = 4;

/// A decimal's exact Cedar value: the text scaled to [`DECIMAL_PLACES`], as Cedar holds it.
///
/// Mirrors upstream's own `cedar_decimal_value`, which is crate-private there. Reimplementing it
/// is a drift risk and is treated as one: `a_canonical_encoding_agrees_with_dogwoods_own_equality`
/// checks this against `Value::dom_eq` over the spellings that make the two disagree — a missing
/// point, a fifth place, a negative zero whose whole part parses to `0`.
fn decimal_scaled(text: &str) -> Option<i64> {
    let (whole_text, fraction_text) = text.split_once('.')?;
    if fraction_text.is_empty() || !fraction_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let digits = whole_text.strip_prefix('-').unwrap_or(whole_text);
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let places: u32 = fraction_text.len().try_into().ok()?;
    if places > DECIMAL_PLACES {
        return None;
    }

    let whole = whole_text.parse::<i64>().ok()?;
    let scaled = whole.checked_mul(10_i64.checked_pow(DECIMAL_PLACES)?)?;
    let fraction = fraction_text
        .parse::<i64>()
        .ok()?
        .checked_mul(10_i64.checked_pow(DECIMAL_PLACES - places)?)?;

    // The sign comes from the spelling, not from the parsed whole part: `-0.5` has a whole part
    // that parses to `0`, and taking the sign from that would make it `+0.5`.
    if whole_text.starts_with('-') {
        scaled.checked_sub(fraction)
    } else {
        scaled.checked_add(fraction)
    }
}

/// The canonical typed encoding of one value — what a history key is hashed over.
///
/// # Why not JSON
///
/// A history key decides which history an event belongs to, so two values that are not the same
/// value must not encode the same way. JSON does not promise that: `1` the integer and `"1"` the
/// string differ only by quoting, and `{"a": "b:c"}` and `{"a:b": "c"}` are one concatenation away
/// from each other. An encoding whose collisions put two tenants' events in one partition is not a
/// key, it is a merge.
///
/// So every value carries its type as a leading tag, and every piece of text carries its length,
/// which is what makes the encoding injective: no sequence of parts can be read two ways. And
/// because the values themselves travel in the signed record beside the hash, an investigator can
/// see *which* values put a record in a partition rather than only that two agree.
///
/// A decimal encodes as the integer Cedar holds it as, so `1.50` and `1.5` — one value to Cedar,
/// and one value to a policy comparing them — are one key.
pub fn canonical(value: &DogwoodValue) -> String {
    let mut encoded = String::new();
    encode(value, &mut encoded);

    encoded
}

fn encode(value: &DogwoodValue, into: &mut String) {
    match value {
        DogwoodValue::Null => into.push_str("n:"),
        DogwoodValue::Bool(held) => {
            into.push_str(if *held { "b:1" } else { "b:0" });
        }
        DogwoodValue::Int(held) => {
            into.push_str("i:");
            into.push_str(&held.to_string());
        }
        DogwoodValue::Decimal(text) => match decimal_scaled(text) {
            // The exact value, so two spellings of one decimal are one key.
            Some(scaled) => {
                into.push_str("d:");
                into.push_str(&scaled.to_string());
            }
            // Not a decimal Cedar accepts. It cannot arrive from the wire — the reader refuses it
            // — but a `Value` built in process could hold it, and encoding it as its verbatim text
            // under its own tag keeps the encoding total and keeps it apart from a real decimal.
            None => {
                into.push_str("d?:");
                text_into(text, into);
            }
        },
        DogwoodValue::String(held) => {
            into.push_str("s:");
            text_into(held, into);
        }
        DogwoodValue::Entity { ty, id } => {
            into.push_str("e:");
            text_into(ty, into);
            text_into(id, into);
        }
        DogwoodValue::Array(items) => {
            into.push_str("a:");
            into.push_str(&items.len().to_string());
            into.push(':');
            for item in items {
                encode(item, into);
            }
        }
        DogwoodValue::Object(fields) => {
            into.push_str("o:");
            into.push_str(&fields.len().to_string());
            into.push(':');
            // `BTreeMap` iterates by key, so the encoding does not depend on insertion order.
            for (name, held) in fields {
                text_into(name, into);
                encode(held, into);
            }
        }
    }
}

/// One piece of text, length-prefixed so nothing that follows it can be read as part of it.
fn text_into(text: &str, into: &mut String) {
    into.push_str(&text.len().to_string());
    into.push(':');
    into.push_str(text);
}

/// One value as a diagnostic writes it: the JSON a caller would have sent.
///
/// The point of showing it in the wire's own shape is that a message about a value the caller sent
/// should be readable against what the caller sent, not against this crate's internal spelling of
/// it.
pub fn render(value: &DogwoodValue) -> String {
    serde_json::to_string(&to_json(value)).unwrap_or_else(|_| "<unrenderable>".to_owned())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

    /// Every variant survives both directions unchanged.
    #[test]
    fn every_value_variant_round_trips_without_coercion() {
        let cases = vec![
            json!(null),
            json!(true),
            json!(false),
            json!(0),
            json!(42),
            json!(-7),
            json!(i64::MAX),
            json!(i64::MIN),
            json!(""),
            json!("alice"),
            json!({"__extn": {"fn": "decimal", "arg": "500.25"}}),
            json!({"__extn": {"fn": "decimal", "arg": "-0.001"}}),
            json!({"__entity": {"type": "Drupe::OAuthUser", "id": "alice"}}),
            json!([]),
            json!([1, "two", true, null]),
            json!({}),
            json!({"amount": 500, "currency": "EUR"}),
            // Nested, and mixing the escapes with ordinary fields.
            json!({
                "owner": {"__entity": {"type": "Drupe::Gateway", "id": "gw1"}},
                "limit": {"__extn": {"fn": "decimal", "arg": "1000.00"}},
                "tags": ["a", "b"],
                "nested": {"deep": {"flag": false}}
            }),
        ];

        for case in cases {
            let value = from_json(&case).unwrap_or_else(|error| panic!("{case}: {error}"));
            let back = to_json(&value);

            assert_eq!(back, case, "a value must read back as what was sent");
        }
    }

    /// A decimal must never become a float — the whole reason the escape exists.
    #[test]
    fn a_json_fraction_is_refused_and_says_what_to_write_instead() {
        let refused = from_json(&json!(1.5)).expect_err("Dogwood has no float");

        assert!(refused.message.contains("decimal"), "{refused}");
        assert!(refused.message.contains("__extn"), "{refused}");

        // And inside a structure, the path names where.
        let nested = from_json(&json!({"input": {"amount": 0.1}})).expect_err("still a float");
        assert_eq!(nested.at, "input.amount");
    }

    /// An integer beyond Dogwood's signed 64-bit range is refused, not wrapped.
    #[test]
    fn an_integer_beyond_what_dogwood_holds_is_refused() {
        let big = Json::Number(Number::from(u64::MAX));

        assert!(from_json(&big).is_err(), "u64::MAX has no i64 counterpart");
        assert_eq!(
            from_json(&json!(i64::MAX)).expect("this one fits"),
            DogwoodValue::Int(i64::MAX)
        );
    }

    /// An object is not an entity merely because it has `type` and `id`.
    #[test]
    fn a_record_with_type_and_id_fields_stays_a_record() {
        let value = from_json(&json!({"type": "invoice", "id": "inv-1"})).expect("a record");

        match value {
            DogwoodValue::Object(fields) => {
                assert_eq!(fields.len(), 2);
                assert_eq!(
                    fields.get("type"),
                    Some(&DogwoodValue::String("invoice".to_owned()))
                );
            }
            other => panic!("guessed an entity from a record: {other:?}"),
        }
    }

    /// The escape counts only when it is the object's sole key.
    #[test]
    fn an_escape_beside_other_fields_is_a_record_not_an_escape() {
        let value = from_json(&json!({"__entity": {"type": "T", "id": "i"}, "extra": 1}))
            .expect("a record with an oddly named field");

        assert!(
            matches!(value, DogwoodValue::Object(ref fields) if fields.len() == 2),
            "a caller must not turn a record into an entity by naming a field"
        );
    }

    #[test]
    fn a_malformed_entity_reference_is_refused_rather_than_guessed() {
        for bad in [
            json!({"__entity": "Drupe::OAuthUser::\"alice\""}), // a string is not a reference
            json!({"__entity": {"type": "T"}}),                 // no id
            json!({"__entity": {"id": "i"}}),                   // no type
            json!({"__entity": {"type": "", "id": "i"}}),       // empty type
            json!({"__entity": {"type": "T", "id": "i", "attrs": {}}}), // and nothing else
        ] {
            assert!(from_json(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_malformed_decimal_is_refused_rather_than_parsed_loosely() {
        for bad in [
            json!({"__extn": {"fn": "decimal", "arg": "500"}}), // no fractional part
            json!({"__extn": {"fn": "decimal", "arg": ".5"}}),  // no whole part
            json!({"__extn": {"fn": "decimal", "arg": "1.2.3"}}), // not a number
            json!({"__extn": {"fn": "decimal", "arg": 1.5}}),   // exact text, as a string
            json!({"__extn": {"fn": "ip", "arg": "10.0.0.1"}}), // not an extension we carry
        ] {
            assert!(from_json(&bad).is_err(), "{bad}");
        }
    }

    /// Explicit null is a value, and stays one.
    #[test]
    fn an_explicit_null_stays_explicit() {
        assert_eq!(from_json(&json!(null)).expect("null"), DogwoodValue::Null);
        let record = from_json(&json!({"note": null})).expect("a record with a null");
        match record {
            DogwoodValue::Object(fields) => {
                assert_eq!(fields.get("note"), Some(&DogwoodValue::Null));
            }
            other => panic!("{other:?}"),
        }
    }

    /// Decimal equality is Dogwood's, not string equality — the mapping keeps the text it was
    /// given so that comparison is the engine's job and not the wire's.
    #[test]
    fn a_decimal_keeps_the_exact_text_it_was_sent() {
        let value =
            from_json(&json!({"__extn": {"fn": "decimal", "arg": "1.50"}})).expect("a decimal");

        assert_eq!(value, DogwoodValue::Decimal("1.50".to_owned()));
        // `1.50` and `1.5` are the same number and different text; Dogwood compares them as
        // decimals, and the wire must not have already collapsed one into the other.
        assert!(value.dom_eq(&DogwoodValue::Decimal("1.5".to_owned())));
    }
}
