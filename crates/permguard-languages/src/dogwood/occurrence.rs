// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! One typed Dogwood occurrence, as `permguard.dogwood.event.v1` carries it.
//!
//! # The two bags, and the invariant between them
//!
//! Dogwood keeps a request's fields in two places on purpose:
//!
//! | Bag | Read by | Written as |
//! | --- | --- | --- |
//! | `logged` | temporal predicates | `Login{ input.user: … }` |
//! | `request_context` | Cedar conditions | `context.input.user` |
//!
//! They are separate because they answer different questions: `logged` is the durable history a
//! `formerly` clause matches against, `request_context` is what this one request says. A field
//! used by both — the common case — has to be in both.
//!
//! Upstream lists that as a production concern and it is the sharpest one, because getting it
//! wrong **weakens a policy silently**. Supply `input.user` only to `logged` and every Cedar
//! `context.input.user` test reads an unresolved field; supply it only to `request_context` and
//! every temporal correlation on it stops matching, so `formerly within 1h Login{…}` quietly finds
//! nothing and a rule meant to restrict starts permitting.
//!
//! So Permguard does not leave it to the caller's discipline: a field present in both bags must be
//! **exactly equal**, and a mismatch is refused before anything is journalled. A caller that means
//! two different values is asking for two different things, and there is no reading of that which
//! is safe to guess.
//!
//! # What the caller does not get to choose
//!
//! Pins come from the loaded event schema, never from a `pins` list on the wire; the producer
//! identity is bound server-side; `occurred_at` is untrusted unless the caller is an authorized
//! clock source. None of that is expressible here, and that is the point: this type is what a
//! caller may say, and everything it may not say is absent from it.

use std::collections::BTreeMap;

use dogwood_language::{Event, EventBuilder, Value as DogwoodValue};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value as Json};

use super::value;

/// The registered name of this event input.
pub const EVENT_TYPE: &str = "permguard.dogwood.event.v1";

/// The logged field Dogwood files the request principal under.
pub const CALLER_PRINCIPAL: &str = "callerPrincipal";
/// The logged field Dogwood files the request resource under.
pub const CALLER_RESOURCE: &str = "callerResource";

/// One occurrence, as the wire carries it.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OccurrenceBody {
    /// The caller's identifier for this occurrence, unique within the ledger scope. Makes a retry
    /// idempotent, and makes the same id with different content a conflict.
    #[serde(default)]
    pub event_id: Option<String>,
    /// The runtime's word for what happened — `request`, `response`, `error`, or whatever the
    /// loaded event schema declares. Domain data, never a wire type.
    #[serde(default)]
    pub kind: Option<String>,
    /// The qualified action, in the form the policies name it: `Acme::Action::Transfer`.
    #[serde(default)]
    pub action: Option<String>,
    /// The principal this request is about.
    #[serde(default)]
    pub principal: Option<EntityUidBody>,
    /// The resource this request is about.
    #[serde(default)]
    pub resource: Option<EntityUidBody>,
    /// The durable temporal record: what a `formerly`/`since` clause matches against.
    #[serde(default)]
    pub logged: Map<String, Json>,
    /// The Cedar request context: what a `when { context… }` clause reads.
    #[serde(default)]
    pub request_context: Map<String, Json>,
    /// The attributed entity store this occurrence carries.
    ///
    /// Distinct from `logged` and from the principal/resource scope: this is what lets a policy
    /// read `principal.role` or test `principal in Team::"payments"`. Validated against the
    /// action schema before authorization.
    #[serde(default)]
    pub entities: Vec<EntityBody>,
    /// When it happened, as a canonical UTC RFC 3339 instant at whole-second precision.
    #[serde(default)]
    pub occurred_at: Option<String>,
}

/// An entity reference, in either of the two forms a caller may write.
///
/// The literal is what §5's payload shows and what most callers already hold. The structured pair
/// exists because a Cedar id may contain `"`, `\` or a control character, and a caller escaping
/// one into a literal by hand escapes it once too many or once too few — upstream calls that out
/// as a footgun. Both arrive at the same decoded pair, and the decoding is **Dogwood's own**: a
/// literal is handed to Dogwood's parser rather than to an escape table maintained here, which
/// could not drift out of step because there is nothing here to drift.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum EntityUidBody {
    /// A canonical Cedar uid literal: `Acme::User::"alice"`.
    Literal(String),
    /// The decoded type and id, which nobody has to escape.
    Structured(EntityRef),
}

/// A decoded entity reference: a type and a raw id, never a pre-joined literal.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntityRef {
    #[serde(rename = "type")]
    pub kind: String,
    pub id: String,
}

/// One entity of the occurrence's attributed store, as the wire carries it.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EntityBody {
    pub uid: EntityUidBody,
    #[serde(default)]
    pub attrs: Map<String, Json>,
    /// Direct `memberOf` edges. Cedar computes the transitive closure, so only direct parents are
    /// stated here.
    #[serde(default)]
    pub parents: Vec<EntityUidBody>,
}

/// One entity of the attributed store, decoded.
#[derive(Debug, Clone)]
pub struct AttributedEntity {
    pub uid: EntityRef,
    pub attrs: BTreeMap<String, DogwoodValue>,
    pub parents: Vec<EntityRef>,
}

/// Why an occurrence is not one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Malformed {
    /// A stable code, so a caller branches without reading prose.
    pub code: &'static str,
    pub message: String,
}

impl Malformed {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for Malformed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Malformed {}

/// A well-formed occurrence, before any schema has seen it.
#[derive(Debug, Clone)]
pub struct Occurrence {
    pub event_id: String,
    pub kind: String,
    /// The action as written, qualified: `Acme::Action::Transfer`.
    pub action: String,
    pub principal: EntityRef,
    pub resource: EntityRef,
    pub logged: BTreeMap<String, DogwoodValue>,
    pub request_context: BTreeMap<String, DogwoodValue>,
    pub entities: Vec<AttributedEntity>,
    /// The instant, as the canonical text the caller sent.
    pub occurred_at: String,
    /// The same instant as the signed epoch seconds Dogwood's windows are measured in.
    pub occurred_at_epoch: i64,
}

impl OccurrenceBody {
    /// Reads the occurrence, checking everything checkable without a schema.
    ///
    /// Schema-dependent questions — is this action declared, does this kind exist, do these field
    /// types match — belong to the partition that will answer, and one partition may answer
    /// differently from its neighbour. What is checked here is what is true of any occurrence.
    pub fn read(&self) -> Result<Occurrence, Malformed> {
        let event_id = required(&self.event_id, "event_id")?;
        let kind = required(&self.kind, "kind")?;
        let action = required(&self.action, "action")?;
        // Qualified, always. A temporal predicate matches the action *as written*, so a bare
        // `Transfer` matches no policy's `Acme::Action::"Transfer"` — the correlation silently
        // finds nothing while Cedar may still authorize the action. Upstream names this as a
        // production concern; refusing the unqualified form is how it stops being one.
        if !action.contains("::") {
            return Err(Malformed::new(
                "event_action_unqualified",
                format!(
                    "`{action}` is not a qualified action. Policies name actions as \
                     `Namespace::Action::Name`, and a bare name matches no temporal predicate \
                     while Cedar may still authorize it"
                ),
            ));
        }
        split_action(&action)?;

        let principal = self
            .principal
            .as_ref()
            .ok_or_else(|| missing("principal"))?
            .decode("principal")?;
        let resource = self
            .resource
            .as_ref()
            .ok_or_else(|| missing("resource"))?
            .decode("resource")?;

        let occurred_at = required(&self.occurred_at, "occurred_at")?;
        let occurred_at_epoch =
            permguard_events::index::epoch_seconds(&occurred_at).ok_or_else(|| {
                Malformed::new(
                    "event_time_not_canonical",
                    format!(
                        "`{occurred_at}` is not a canonical UTC instant at whole-second \
                         precision. Dogwood's windows are closed intervals over signed epoch \
                         seconds, so a fraction, an offset or a leap second has no exact position \
                         in one and would land on whichever side of a boundary the rounding chose"
                    ),
                )
            })?;

        let logged = bag(&self.logged, "logged")?;
        let request_context = bag(&self.request_context, "request_context")?;
        agree(&logged, &request_context)?;

        let mut entities = Vec::with_capacity(self.entities.len());
        for entity in &self.entities {
            entities.push(entity.decode()?);
        }

        Ok(Occurrence {
            event_id,
            kind,
            action,
            principal,
            resource,
            logged,
            request_context,
            entities,
            occurred_at,
            occurred_at_epoch,
        })
    }
}

impl EntityUidBody {
    /// The decoded `(type, id)` this reference names.
    ///
    /// A literal is decoded by Dogwood, through the one path that also builds the event — never by
    /// an unescaping table kept here, which would be a second implementation of a round trip
    /// upstream documents as non-idempotent and easy to get wrong.
    pub fn decode(&self, what: &str) -> Result<EntityRef, Malformed> {
        match self {
            Self::Structured(reference) => {
                if reference.kind.trim().is_empty() || reference.id.is_empty() {
                    return Err(Malformed::new(
                        "field_required",
                        format!("`event.data.{what}` states a non-empty `type` and `id`"),
                    ));
                }

                Ok(reference.clone())
            }
            Self::Literal(literal) => decode_literal(literal).ok_or_else(|| {
                Malformed::new(
                    "event_entity_malformed",
                    format!(
                        "`{literal}` is not a Cedar entity reference. Write it as \
                         `Namespace::Type::\"id\"`, or — for an id holding a quote, a backslash \
                         or a control character — as `{{\"type\": …, \"id\": …}}`, which needs no \
                         escaping at all (`event.data.{what}`)"
                    ),
                )
            }),
        }
    }
}

/// Decodes a canonical Cedar uid literal, using Dogwood's own parser.
///
/// Dogwood keeps the parse `pub(crate)`, so it is reached the way it is reachable: through the
/// builder, which files a parsed principal under `callerPrincipal` in the logged bag. A literal it
/// refuses leaves that field absent, which is exactly the answer wanted. The event built here is
/// discarded; it exists so that the escaping rules live in one place, upstream.
fn decode_literal(literal: &str) -> Option<EntityRef> {
    let probe = Event::builder("Probe", "probe").principal(literal).build();
    match probe.field_path(&[CALLER_PRINCIPAL.to_owned()]) {
        Some(DogwoodValue::Entity { ty, id }) if !ty.trim().is_empty() && !id.is_empty() => {
            Some(EntityRef {
                kind: ty.clone(),
                id: id.clone(),
            })
        }
        _ => None,
    }
}

impl EntityBody {
    fn decode(&self) -> Result<AttributedEntity, Malformed> {
        let uid = self.uid.decode("entities[].uid")?;
        let mut attrs = BTreeMap::new();
        for (name, held) in &self.attrs {
            let value = value::from_json(held).map_err(|error| {
                Malformed::new(
                    "event_value_unrepresentable",
                    format!(
                        "`entities[{}::\"{}\"].attrs.{name}`: {}",
                        uid.kind, uid.id, error.message
                    ),
                )
            })?;
            attrs.insert(name.clone(), value);
        }
        let mut parents = Vec::with_capacity(self.parents.len());
        for parent in &self.parents {
            parents.push(parent.decode("entities[].parents[]")?);
        }

        Ok(AttributedEntity {
            uid,
            attrs,
            parents,
        })
    }
}

impl Occurrence {
    /// The occurrence as the Dogwood event an authorizer reads.
    ///
    /// Built through the *structured* constructors throughout — `builder_for`, `principal_for`,
    /// `entity_for`, `parents_for` — so no identifier is joined into a literal and re-parsed on
    /// the way in. Whatever form the caller wrote, it was decoded once, here it is escaped once.
    pub fn to_event(&self) -> Result<Event, Malformed> {
        let (namespace, action_id) = split_action(&self.action)?;
        let namespace: Vec<&str> = namespace.iter().map(String::as_str).collect();

        let mut builder: EventBuilder = Event::builder_for(&namespace, &action_id, &self.kind)
            .timestamp(self.occurred_at_epoch)
            .principal_for(&self.principal.kind, &self.principal.id)
            .resource_for(&self.resource.kind, &self.resource.id);

        for (group, value) in &self.logged {
            // The two scope aliases are top-level logged fields, and `principal_for` /
            // `resource_for` above already wrote them from the request's own roots. A caller that
            // restated them was held to the same value at check time, so there is nothing left to
            // write; every other top-level leaf was refused there, because upstream's public
            // builder cannot write one.
            if group == CALLER_PRINCIPAL || group == CALLER_RESOURCE {
                continue;
            }
            for (name, held) in grouped(value, "logged", group)? {
                builder = builder.field(group, name, held.clone());
            }
        }
        for (group, value) in &self.request_context {
            for (name, held) in grouped(value, "request_context", group)? {
                builder = builder.request_context(group, name, held.clone());
            }
        }
        for entity in &self.entities {
            let attrs: Vec<(&str, DogwoodValue)> = entity
                .attrs
                .iter()
                .map(|(name, held)| (name.as_str(), held.clone()))
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

    /// The canonical uid literal of the principal, as the entity store keys it.
    pub fn principal_uid(&self) -> String {
        uid_literal(&self.principal)
    }

    /// The canonical uid literal of the resource.
    pub fn resource_uid(&self) -> String {
        uid_literal(&self.resource)
    }
}

/// Renders a decoded reference as the canonical literal Dogwood's store is keyed by.
///
/// `escape_debug` is what Cedar's own `Display` uses and what Dogwood matched it to; the two must
/// agree or an entity's attributes are stored under a key no lookup reconstructs. The round trip
/// is held to that by a test rather than by this comment.
fn uid_literal(reference: &EntityRef) -> String {
    format!("{}::\"{}\"", reference.kind, reference.id.escape_debug())
}

/// The fields of one bag group, refusing a group that is not a record of fields.
fn grouped<'a>(
    value: &'a DogwoodValue,
    bag: &str,
    group: &str,
) -> Result<&'a BTreeMap<String, DogwoodValue>, Malformed> {
    match value {
        DogwoodValue::Object(fields) => Ok(fields),
        _ => Err(Malformed::new(
            "event_bag_not_grouped",
            format!(
                "`{bag}.{group}` is not an object. A bag holds named groups of fields, as the \
                 event schema declares them"
            ),
        )),
    }
}

fn required(value: &Option<String>, field: &'static str) -> Result<String, Malformed> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|held| !held.is_empty())
        .map(ToOwned::to_owned)
        .ok_or_else(|| missing(field))
}

fn missing(field: &str) -> Malformed {
    Malformed::new(
        "field_required",
        format!("`event.data.{field}` is required"),
    )
}

/// One bag of grouped fields, converted value by value.
fn bag(
    fields: &Map<String, Json>,
    what: &str,
) -> Result<BTreeMap<String, DogwoodValue>, Malformed> {
    let mut converted = BTreeMap::new();
    for (group, value) in fields {
        let held = value::from_json(value).map_err(|error| {
            Malformed::new(
                "event_value_unrepresentable",
                format!("`{what}.{group}`: {}", error.message),
            )
        })?;
        converted.insert(group.clone(), held);
    }

    Ok(converted)
}

/// The invariant: a field in both bags carries the same value in both.
///
/// Compared with Dogwood's own equality, not Rust's, so `1.50` and `1.5` are one decimal here
/// exactly as they are to a policy. Two spellings of one number are not a divergence.
fn agree(
    logged: &BTreeMap<String, DogwoodValue>,
    request_context: &BTreeMap<String, DogwoodValue>,
) -> Result<(), Malformed> {
    for (group, left) in logged {
        let Some(right) = request_context.get(group) else {
            continue;
        };
        let (DogwoodValue::Object(left), DogwoodValue::Object(right)) = (left, right) else {
            if !left.dom_eq(right) {
                return Err(divergence(group, ""));
            }

            continue;
        };
        for (name, held) in left {
            let Some(other) = right.get(name) else {
                continue;
            };
            if !held.dom_eq(other) {
                return Err(divergence(group, name));
            }
        }
    }

    Ok(())
}

fn divergence(group: &str, name: &str) -> Malformed {
    let field = if name.is_empty() {
        group.to_owned()
    } else {
        format!("{group}.{name}")
    };

    Malformed::new(
        "event_bags_disagree",
        format!(
            "`logged.{field}` and `request_context.{field}` carry different values. A field a \
             temporal predicate correlates on and a Cedar condition reads must be the same value \
             in both, or one of the two checks is silently weakened — and which one depends on \
             which bag the policy happened to read"
        ),
    )
}

/// Splits `Acme::Action::Transfer` into its namespace path and bare id.
fn split_action(action: &str) -> Result<(Vec<String>, String), Malformed> {
    let mut parts: Vec<String> = action.split("::").map(ToOwned::to_owned).collect();
    let Some(id) = parts.pop().filter(|id| !id.is_empty()) else {
        return Err(Malformed::new(
            "event_action_unqualified",
            format!("`{action}` ends in nothing: an action is `Namespace::Action::Name`"),
        ));
    };
    if parts.iter().any(String::is_empty) {
        return Err(Malformed::new(
            "event_action_unqualified",
            format!("`{action}` has an empty namespace segment"),
        ));
    }

    Ok((parts, id))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use serde_json::json;

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

        let event = occurrence.to_event().expect("it becomes an event");
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
            Some(&DogwoodValue::String("EUR".to_owned()))
        );
        assert_eq!(
            event.request_context_path(&["input".to_owned(), "currency".to_owned()]),
            Some(&DogwoodValue::String("EUR".to_owned()))
        );
    }

    /// The two spellings of one reference are one reference.
    #[test]
    fn a_literal_and_a_structured_reference_decode_to_the_same_entity() {
        let literal = body(json!({"principal": "Acme::User::\"alice\""}))
            .read()
            .expect("well formed");
        let structured = body(json!({"principal": {"type": "Acme::User", "id": "alice"}}))
            .read()
            .expect("well formed");

        assert_eq!(literal.principal, structured.principal);
        assert_eq!(literal.principal_uid(), structured.principal_uid());
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
            let event = occurrence.to_event().expect("it becomes an event");

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

    /// The invariant upstream calls out as a production concern.
    #[test]
    fn a_field_that_disagrees_between_the_two_bags_is_refused() {
        let refused = body(json!({
            "logged": {"input": {"user": "alice"}},
            "request_context": {"input": {"user": "mallory"}}
        }))
        .read()
        .expect_err("one of the two checks would be weakened");

        assert_eq!(refused.code, "event_bags_disagree");
        assert!(refused.message.contains("logged.input.user"), "{refused}");
    }

    /// Two spellings of one decimal are not a divergence: comparison is Dogwood's, not Rust's.
    #[test]
    fn the_same_number_written_two_ways_agrees() {
        assert!(
            body(json!({
                "logged": {"input": {"amount": {"__extn": {"fn": "decimal", "arg": "1.50"}}}},
                "request_context": {"input": {"amount": {"__extn": {"fn": "decimal", "arg": "1.5"}}}}
            }))
            .read()
            .is_ok(),
            "`1.50` and `1.5` are one decimal"
        );
    }

    /// A field in only one bag is legal: not every field is used by both sides.
    #[test]
    fn a_field_in_only_one_bag_is_left_alone() {
        assert!(
            body(json!({
                "logged": {"input": {"currency": "EUR", "only_temporal": "x"}},
                "request_context": {"input": {"currency": "EUR"}, "system": {"ip": "10.0.0.1"}}
            }))
            .read()
            .is_ok()
        );
    }

    #[test]
    fn an_unqualified_action_is_refused() {
        let refused = body(json!({"action": "Transfer"}))
            .read()
            .expect_err("a bare name matches no temporal predicate");

        assert_eq!(refused.code, "event_action_unqualified");
    }

    #[test]
    fn a_time_with_no_exact_position_in_a_window_is_refused() {
        for bad in [
            "2026-08-28T10:15:30.5Z",
            "2026-08-28T10:15:30+02:00",
            "2026-08-28T10:15:60Z",
            "2026-08-28 10:15:30Z",
            "not a time",
        ] {
            let refused = body(json!({ "occurred_at": bad })).read().expect_err(bad);
            assert_eq!(refused.code, "event_time_not_canonical", "{bad}");
        }
    }

    #[test]
    fn a_required_field_left_out_is_named() {
        for field in [
            "event_id",
            "kind",
            "action",
            "principal",
            "resource",
            "occurred_at",
        ] {
            let refused = body(json!({ field: Json::Null }))
                .read()
                .expect_err("a required field left out is refused, not defaulted");

            assert_eq!(refused.code, "field_required", "{field}");
            assert!(refused.message.contains(field), "{refused}");
        }
    }

    #[test]
    fn a_reference_that_is_not_one_says_what_to_write_instead() {
        for bad in ["alice", "Acme::User::alice", "Acme::User::\"alice", ""] {
            let refused = body(json!({ "principal": bad })).read().expect_err(bad);
            assert_eq!(refused.code, "event_entity_malformed", "{bad}");
            assert!(refused.message.contains("\"type\""), "{refused}");
        }
        let refused = body(json!({"principal": {"type": "Acme::User", "id": ""}}))
            .read()
            .expect_err("an empty id names nothing");
        assert_eq!(refused.code, "field_required");
    }

    /// A caller cannot send a field this contract does not define.
    #[test]
    fn an_unknown_field_is_refused_rather_than_ignored() {
        let with_pins = json!({
            "event_id": "e", "kind": "request", "action": "A::Action::B",
            "principal": "A::T::\"i\"", "resource": "A::T::\"i\"",
            "occurred_at": "2026-08-28T10:15:30Z",
            // Pins come from the loaded event schema. A caller that could send them would be
            // choosing its own history partition.
            "pins": {"tenantId": "acme"}
        });

        assert!(serde_json::from_value::<OccurrenceBody>(with_pins).is_err());
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
        let event = occurrence.to_event().expect("it becomes an event");

        let attributes: Vec<(&str, &DogwoodValue)> =
            event.entity_attributes("Acme::User::\"alice\"").collect();
        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].0, "role");
        assert_eq!(
            event.entity_parents("Acme::User::\"alice\""),
            [DogwoodValue::Entity {
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
        let refused = occurrence
            .to_event()
            .expect_err("a group is a record of fields");

        assert_eq!(refused.code, "event_bag_not_grouped");
    }

    /// A value the mapping cannot carry exactly is refused rather than coerced.
    #[test]
    fn a_value_that_cannot_be_represented_exactly_is_refused_by_position() {
        let refused = body(json!({"logged": {"input": {"amount": 1.5}}}))
            .read()
            .expect_err("Dogwood has no float");

        assert_eq!(refused.code, "event_value_unrepresentable");
        assert!(refused.message.contains("logged.input"), "{refused}");
    }
}
