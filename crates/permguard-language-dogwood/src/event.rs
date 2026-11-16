// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The occurrence as the event Dogwood's authorizer reads: the one place a value of the contracts
//! (`permguard_language_core::value::Value`) becomes a value of the engine.
//!
//! The contracts hold Dogwood's value domain variant for variant without linking the engine, so
//! every other package — a client sending an occurrence, the journal recording one — reads and
//! writes occurrences with no engine in its build. The conversion is total and exact: each variant
//! becomes the same variant, with the same text.

use std::collections::BTreeMap;

use dogwood_language::{Event, EventBuilder};
use permguard_language_core::occurrence::{
    CALLER_PRINCIPAL, CALLER_RESOURCE, Malformed, Occurrence, split_action,
};
use permguard_language_core::value::Value;

/// The occurrence as the Dogwood event an authorizer reads.
///
/// Built through the *structured* constructors throughout — `builder_for`, `principal_for`,
/// `entity_for`, `parents_for` — so no identifier is joined into a literal and re-parsed on
/// the way in. Whatever form the caller wrote, it was decoded once, here it is escaped once.
pub(crate) fn to_event(occurrence: &Occurrence) -> Result<Event, Malformed> {
    let (namespace, action_id) = split_action(&occurrence.action)?;
    let namespace: Vec<&str> = namespace.iter().map(String::as_str).collect();

    let mut builder: EventBuilder = Event::builder_for(&namespace, &action_id, &occurrence.kind)
        .timestamp(occurrence.occurred_at_epoch)
        .principal_for(&occurrence.principal.kind, &occurrence.principal.id)
        .resource_for(&occurrence.resource.kind, &occurrence.resource.id);

    for (group, value) in &occurrence.logged {
        // The two scope aliases are top-level logged fields, and `principal_for` /
        // `resource_for` above already wrote them from the request's own roots. A caller that
        // restated them was held to the same value at check time, so there is nothing left to
        // write; every other top-level leaf was refused there, because upstream's public
        // builder cannot write one.
        if group == CALLER_PRINCIPAL || group == CALLER_RESOURCE {
            continue;
        }
        for (name, held) in grouped(value, "logged", group)? {
            builder = builder.field(group, name, upstream(held));
        }
    }
    for (group, value) in &occurrence.request_context {
        for (name, held) in grouped(value, "request_context", group)? {
            builder = builder.request_context(group, name, upstream(held));
        }
    }
    for entity in &occurrence.entities {
        let attrs: Vec<(&str, dogwood_language::Value)> = entity
            .attrs
            .iter()
            .map(|(name, held)| (name.as_str(), upstream(held)))
            .collect();
        builder = builder.entity_for(&entity.uid.kind, &entity.uid.id, attrs);
        if !entity.parents.is_empty() {
            let parents: Vec<(&str, &str)> = entity
                .parents
                .iter()
                .map(|parent| (parent.kind.as_str(), parent.id.as_str()))
                .collect();
            builder = builder.parents_for(&entity.uid.kind, &entity.uid.id, parents);
        }
    }

    Ok(builder.build())
}

/// One value of the contracts as the same value of the engine, variant for variant.
pub(crate) fn upstream(value: &Value) -> dogwood_language::Value {
    match value {
        Value::Null => dogwood_language::Value::Null,
        Value::Bool(held) => dogwood_language::Value::Bool(*held),
        Value::Int(held) => dogwood_language::Value::Int(*held),
        Value::Decimal(text) => dogwood_language::Value::Decimal(text.clone()),
        Value::String(text) => dogwood_language::Value::String(text.clone()),
        Value::Entity { ty, id } => dogwood_language::Value::Entity {
            ty: ty.clone(),
            id: id.clone(),
        },
        Value::Array(items) => dogwood_language::Value::Array(items.iter().map(upstream).collect()),
        Value::Object(fields) => dogwood_language::Value::Object(
            fields
                .iter()
                .map(|(name, held)| (name.clone(), upstream(held)))
                .collect(),
        ),
    }
}

/// The fields of one bag group, refusing a group that is not a record of fields.
fn grouped<'a>(
    value: &'a Value,
    bag: &str,
    group: &str,
) -> Result<&'a BTreeMap<String, Value>, Malformed> {
    match value {
        Value::Object(fields) => Ok(fields),
        _ => Err(Malformed::new(
            permguard_core::codes::pdp_temporal::EVENT_BAG_NOT_GROUPED,
            format!(
                "`{bag}.{group}` is not an object. A bag holds named groups of fields, as the \
                 event schema declares them"
            ),
        )),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use permguard_language_core::occurrence::{EntityRef, EntityUidBody, OccurrenceBody};
    use permguard_language_core::value::canonical;
    use serde_json::{Value as Json, json};

    use super::*;

    fn body(overrides: Json) -> OccurrenceBody {
        let mut base = json!({
            "event_id": "01J8Z9",
            "kind": "request",
            "action": "Acme::Action::Transfer",
            "principal": "Acme::User::\"alice\"",
            "resource": "Acme::Account::\"payments\"",
            "logged": {"input": {"currency": "EUR"}},
            "request_context": {"input": {"currency": "EUR"}},
            "occurred_at": "2026-08-28T10:15:30Z"
        });
        if let (Some(base), Some(extra)) = (base.as_object_mut(), overrides.as_object()) {
            for (key, value) in extra {
                base.insert(key.clone(), value.clone());
            }
        }

        serde_json::from_value(base).expect("the body parses")
    }

    #[test]
    fn the_payload_the_contract_documents_reads_and_becomes_a_dogwood_event() {
        let occurrence = body(json!({})).read().expect("it is well formed");

        assert_eq!(occurrence.event_id, "01J8Z9");
        assert_eq!(occurrence.action, "Acme::Action::Transfer");
        assert_eq!(occurrence.principal.kind, "Acme::User");
        assert_eq!(occurrence.principal.id, "alice");
        assert_eq!(occurrence.occurred_at_epoch, 1_787_912_130);

        let event = to_event(&occurrence).expect("it becomes an event");
        assert_eq!(event.kind(), "request");
        assert_eq!(event.action(), "Transfer");
        assert_eq!(event.namespace(), ["Acme", "Action"]);
        assert_eq!(event.timestamp(), 1_787_912_130);
        assert_eq!(event.principal().as_deref(), Some("Acme::User::\"alice\""));
        assert_eq!(
            event.resource().as_deref(),
            Some("Acme::Account::\"payments\"")
        );
        assert_eq!(
            event.field("input", "currency"),
            Some(&dogwood_language::Value::String("EUR".to_owned()))
        );
        assert_eq!(
            event.request_context_path(&["input".to_owned(), "currency".to_owned()]),
            Some(&dogwood_language::Value::String("EUR".to_owned()))
        );
    }

    /// An id Cedar allows but nobody would want to hand-escape survives the structured route, and
    /// the literal Permguard renders is the one Dogwood's own store is keyed by.
    #[test]
    fn an_identifier_that_needs_escaping_round_trips_through_dogwoods_own_escaping() {
        for id in ["ali\"ce", "back\\slash", "line\nbreak", "quote'and\"both"] {
            let occurrence = body(json!({
                "principal": {"type": "Acme::User", "id": id},
                "entities": [{"uid": {"type": "Acme::User", "id": id}, "attrs": {"role": "dev"}}]
            }))
            .read()
            .expect("well formed");
            let event = to_event(&occurrence).expect("it becomes an event");

            // What Permguard renders is what Dogwood renders: one escaping, not two.
            assert_eq!(
                event.principal().as_deref(),
                Some(occurrence.principal_uid().as_str()),
                "{id:?}"
            );
            // And that same literal is the key the attribute store answers to.
            let attributes: Vec<&str> = event
                .entity_attributes(&occurrence.principal_uid())
                .map(|(name, _)| name)
                .collect();
            assert_eq!(attributes, ["role"], "{id:?}");

            // The escaped literal decodes back to the id it came from, so a caller that holds a
            // literal and a caller that holds the pair reach the same entity.
            let round_trip = EntityUidBody::Literal(occurrence.principal_uid())
                .decode("principal")
                .expect("a literal Dogwood produced is a literal Dogwood reads");
            assert_eq!(round_trip.id, id, "{id:?}");
        }
    }

    #[test]
    fn the_attributed_entity_store_reaches_the_event_with_its_parents() {
        let occurrence = body(json!({
            "entities": [{
                "uid": "Acme::User::\"alice\"",
                "attrs": {"role": "Developer"},
                "parents": [{"type": "Acme::Team", "id": "payments"}]
            }]
        }))
        .read()
        .expect("it is well formed");
        let event = to_event(&occurrence).expect("it becomes an event");

        let attributes: Vec<(&str, &dogwood_language::Value)> =
            event.entity_attributes("Acme::User::\"alice\"").collect();
        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].0, "role");
        assert_eq!(
            event.entity_parents("Acme::User::\"alice\""),
            [dogwood_language::Value::Entity {
                ty: "Acme::Team".to_owned(),
                id: "payments".to_owned()
            }]
        );
    }

    /// A bag holds groups of fields; a bare value at group level is not one.
    #[test]
    fn a_bag_group_that_is_not_a_record_is_refused() {
        let occurrence = body(json!({"logged": {"input": 7}, "request_context": {}}))
            .read()
            .expect("shape is the event's business, not the reader's");
        let refused = to_event(&occurrence).expect_err("a group is a record of fields");

        assert_eq!(refused.code, "event_bag_not_grouped");
    }

    /// The contracts decode a uid literal as upstream's event builder decodes the principal it is
    /// given: the same type and the same id, or no reference at all, on every literal below — the
    /// escapes `escape_debug` writes, and the malformed ones a caller can write instead.
    #[test]
    fn a_literal_decodes_as_dogwood_decodes_it() {
        let ids = [
            "alice",
            "ali\"ce",
            "back\\slash",
            "line\nbreak",
            "tab\tand\rreturn",
            "nul\0byte",
            "quote'and\"both",
            "é unicode ✓",
            "\u{1}",
            "\u{7f}",
            "\u{200b}",
            "::\"",
            "",
        ];
        let mut literals: Vec<String> = Vec::new();
        for kind in ["Acme::User", "User", "A::B::C", " ", ""] {
            for id in ids {
                literals.push(format!("{kind}::\"{}\"", id.escape_debug()));
            }
        }
        literals.extend(
            [
                r#"User::"a\u{_41}""#,
                r#"User::"a\u{4_1}""#,
                r#"User::"a\u{1_F600}""#,
                r#"User::"a\u{110000}""#,
                r#"User::"a\u{D800}""#,
                r#"User::"a\u{41""#,
                r#"User::"a\u{}""#,
                r#"User::"a\u41""#,
                r#"User::"a\x41""#,
                r#"User::"a\x4""#,
                r#"User::"a\xZZ""#,
                r#"User::"a\x""#,
                r#"User::"a\q""#,
                r#"User::"a\""#,
                r#"User::"a"#,
                r#"User"a""#,
                r#"::"a""#,
                r#"User::"""#,
                r#"User::"a"""#,
                r#"User::"a::"b""#,
                r#"Acme :: User::"a""#,
                r#"User::"a" "#,
                "",
            ]
            .map(ToOwned::to_owned),
        );

        for literal in literals {
            let ours = EntityUidBody::Literal(literal.clone())
                .decode("principal")
                .ok();
            let probe = Event::builder("Probe", "probe").principal(&literal).build();
            let theirs = match probe.field_path(&[CALLER_PRINCIPAL.to_owned()]) {
                Some(dogwood_language::Value::Entity { ty, id })
                    if !ty.trim().is_empty() && !id.is_empty() =>
                {
                    Some(EntityRef {
                        kind: ty.clone(),
                        id: id.clone(),
                    })
                }
                _ => None,
            };
            assert_eq!(ours, theirs, "{literal:?}");
        }
    }

    /// The contracts' equality and canonical encoding are upstream's: on every pair below, two
    /// values are one value to `Value::dom_eq` exactly when upstream's `Value::dom_eq` says so of
    /// the same values, and exactly when their canonical encodings — what a history key is hashed
    /// over — are one encoding.
    #[test]
    fn the_contracts_values_compare_as_dogwoods_own() {
        let decimal = |text: &str| Value::Decimal(text.to_owned());
        let decimals = [
            // Spellings Cedar accepts, one value written several ways, and different values.
            "1.5",
            "1.50",
            "1.5000",
            "02.5",
            "0002.5000",
            "2.5",
            "-2.5",
            "-02.500",
            "0.0",
            "-0.0",
            "0.0000",
            "0.0001",
            "0.0002",
            "-0.5",
            "0.5",
            "15.0",
            "922337203685477.5807",
            "-922337203685477.5808",
            // Spellings Cedar refuses: no point, a fifth place, no digits, out of range.
            "1",
            "1.0",
            "1.00001",
            ".5",
            "5.",
            "abc",
            "",
            "922337203685477.5808",
            "-922337203685477.5809",
        ];
        let mut values: Vec<Value> = decimals.iter().map(|text| decimal(text)).collect();
        values.extend([
            Value::Null,
            Value::Bool(true),
            Value::Bool(false),
            Value::Int(0),
            Value::Int(15),
            Value::Int(-1),
            Value::String("1.5".to_owned()),
            Value::String(String::new()),
            Value::Entity {
                ty: "Acme::User".to_owned(),
                id: "alice".to_owned(),
            },
            Value::Entity {
                ty: "Acme::User".to_owned(),
                id: "bob".to_owned(),
            },
            Value::Array(vec![decimal("1.5"), Value::Int(1)]),
            Value::Array(vec![decimal("1.50"), Value::Int(1)]),
            Value::Array(vec![Value::Int(1), decimal("1.5")]),
            Value::Array(vec![decimal("1.5")]),
            Value::Array(Vec::new()),
            Value::Object(BTreeMap::from([("amount".to_owned(), decimal("1.5"))])),
            Value::Object(BTreeMap::from([("amount".to_owned(), decimal("01.500"))])),
            Value::Object(BTreeMap::from([("amount".to_owned(), decimal("1.6"))])),
            Value::Object(BTreeMap::from([("total".to_owned(), decimal("1.5"))])),
            Value::Object(BTreeMap::from([
                ("amount".to_owned(), decimal("1.5")),
                ("currency".to_owned(), Value::String("EUR".to_owned())),
            ])),
            Value::Object(BTreeMap::new()),
        ]);

        let mut disagreements = Vec::new();
        for left in &values {
            for right in &values {
                let theirs = upstream(left).dom_eq(&upstream(right));
                if left.dom_eq(right) != theirs {
                    disagreements.push(format!("dom_eq {left:?} {right:?}: upstream {theirs}"));
                }
                if (canonical(left) == canonical(right)) != theirs {
                    disagreements.push(format!("canonical {left:?} {right:?}: upstream {theirs}"));
                }
            }
        }
        assert!(
            disagreements.is_empty(),
            "the contracts' values must compare as Dogwood's own:\n  {}",
            disagreements.join("\n  ")
        );
    }

    /// The conversion keeps every variant and every piece of text.
    #[test]
    fn every_value_becomes_the_same_value_of_the_engine() {
        let value = Value::Object(BTreeMap::from([
            ("null".to_owned(), Value::Null),
            ("bool".to_owned(), Value::Bool(true)),
            ("int".to_owned(), Value::Int(i64::MIN)),
            ("decimal".to_owned(), Value::Decimal("01.50".to_owned())),
            ("string".to_owned(), Value::String("ali\"ce".to_owned())),
            (
                "entity".to_owned(),
                Value::Entity {
                    ty: "Acme::User".to_owned(),
                    id: "alice".to_owned(),
                },
            ),
            (
                "array".to_owned(),
                Value::Array(vec![Value::Int(1), Value::String("two".to_owned())]),
            ),
        ]));

        let expected = dogwood_language::Value::Object(BTreeMap::from([
            ("null".to_owned(), dogwood_language::Value::Null),
            ("bool".to_owned(), dogwood_language::Value::Bool(true)),
            ("int".to_owned(), dogwood_language::Value::Int(i64::MIN)),
            (
                "decimal".to_owned(),
                dogwood_language::Value::Decimal("01.50".to_owned()),
            ),
            (
                "string".to_owned(),
                dogwood_language::Value::String("ali\"ce".to_owned()),
            ),
            (
                "entity".to_owned(),
                dogwood_language::Value::Entity {
                    ty: "Acme::User".to_owned(),
                    id: "alice".to_owned(),
                },
            ),
            (
                "array".to_owned(),
                dogwood_language::Value::Array(vec![
                    dogwood_language::Value::Int(1),
                    dogwood_language::Value::String("two".to_owned()),
                ]),
            ),
        ]));
        assert_eq!(upstream(&value), expected);
    }
}
