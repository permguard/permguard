// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Deciding with Cedar, through the official `cedar-policy` crate.
//!
//! # What is compiled
//!
//! A `PolicySet` whose policy ids **are** the store's policy identities, so
//! the reason a decision carries names the same thing the audit trail does —
//! and keeps naming it after a rename. When the partition declares a schema,
//! the schema is parsed and the whole set is **validated against it** at
//! compile time, in strict mode: a policy that cannot type-check is a policy
//! that would evaluate differently than it reads, and the load is refused.
//! (The old Go implementation never did this; a PDP that serves policies its
//! own schema rejects is a PDP nobody can reason about.)
//!
//! # What a request becomes
//!
//! | Profile field | Cedar |
//! | --- | --- |
//! | `subject {type,id}` | the principal `type::"id"` |
//! | `resource {type,id}` | the resource `type::"id"` |
//! | `action {name}` | `Action::"name"`, or `T::"name"` when the name is qualified `T::name` |
//! | `context {…}` | the request context record |
//! | `subject.properties`, `resource.properties` | attributes of the two entities, synthesized unless the store already carries that uid |
//! | `permguard.cedar.entities.v1` | the entity store verbatim, in Cedar's own JSON shape |
//!
//! Synthesizing the two named entities is what lets a policy read
//! `resource.status` without the caller restating the resource inside the
//! store — and checking first for the uid is what lets a caller who *does*
//! state it (with parents, say) win.
//!
//! The store is addressed to **this partition by name**. Two Cedar partitions
//! with different schemas are two different worlds: an entity legal in one is
//! refused by the other, so a store was never something to hand to "the Cedar
//! partitions".

use std::str::FromStr as _;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, Policy, PolicyId, PolicySet, Request,
    Schema,
};
use serde_json::{Value, json};

use crate::evaluate::{Evaluating, Evaluator, Query, StoredPolicy, Verdict};

use super::Cedar;

impl Evaluating for Cedar {
    fn compile(
        &self,
        policies: &[StoredPolicy],
        schema: Option<&[u8]>,
    ) -> Result<Box<dyn Evaluator>, String> {
        let schema_bytes = schema.map_or(0, <[u8]>::len);
        let schema = schema.map(super::parse_schema).transpose()?;

        let mut set = PolicySet::new();
        // What the cache accounts for: the bytes this program was compiled
        // from, which is the part that grows with the ledger.
        let mut footprint = schema_bytes;
        for stored in policies {
            let text = std::str::from_utf8(&stored.source)
                .map_err(|_| format!("cedar: policy {} is not valid UTF-8", stored.id))?;
            let policy = Policy::from_str(text)
                .map_err(|error| format!("cedar: policy {} does not parse: {error}", stored.id))?;
            let id = PolicyId::from_str(&stored.id)
                .map_err(|error| format!("cedar: policy id {}: {error}", stored.id))?;
            set.add(policy.new_id(id))
                .map_err(|error| format!("cedar: policy {}: {error}", stored.id))?;
            footprint += stored.source.len();
        }

        // The schema is a contract, so it is enforced where enforcing it is
        // still cheap and still safe: at load, once, for every policy — with
        // the same check authoring and commit acceptance already ran.
        if let Some(schema) = &schema {
            super::check_against_schema(&set, schema)?;
        }

        Ok(Box::new(CedarEvaluator {
            set,
            schema,
            footprint,
            identities: policies.iter().map(|p| p.id.clone()).collect(),
        }))
    }
}

/// A compiled Cedar partition.
struct CedarEvaluator {
    set: PolicySet,
    schema: Option<Schema>,
    footprint: usize,
    identities: Vec<String>,
}

impl Evaluator for CedarEvaluator {
    fn evaluate(&self, query: &Query) -> Verdict {
        let request = match self.request(query) {
            Ok(request) => request,
            Err(error) => return Verdict::refused(error),
        };
        let entities = match self.entities(query) {
            Ok(entities) => entities,
            Err(error) => return Verdict::refused(error),
        };

        let response = Authorizer::new().is_authorized(&request, &self.set, &entities);
        let determining: Vec<String> = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        // An evaluation error is not a permit and not a fault: it is a deny
        // that says what happened.
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();

        match response.decision() {
            Decision::Allow => Verdict::permit(determining),
            Decision::Deny if errors.is_empty() => Verdict::deny(determining),
            Decision::Deny => Verdict {
                permitted: false,
                determining,
                error: Some(format!("cedar: {}", errors.join("; "))),
            },
        }
    }

    /// The entity store, against this partition's own schema, before any policy runs.
    ///
    /// A store the schema refuses is a bad request rather than a denied one, and the difference
    /// matters to whoever has to fix it: `deny` sends them reading policies, and this sends them
    /// to the entity they mistyped.
    fn check_input(&self, input: &crate::input::PartitionData) -> Result<(), String> {
        Entities::from_json_value(
            Value::Array(input.cedar_entities().to_vec()),
            self.schema.as_ref(),
        )
        .map(|_| ())
        .map_err(|error| format!("cedar: the entity store is not legal here: {error}"))
    }

    fn footprint(&self) -> usize {
        self.footprint
    }

    fn policies(&self) -> Vec<String> {
        self.identities.clone()
    }
}

impl CedarEvaluator {
    fn request(&self, query: &Query) -> Result<Request, String> {
        let principal = uid(&query.subject.kind, &query.subject.id, "subject")?;
        let resource = uid(&query.resource.kind, &query.resource.id, "resource")?;
        let action = action_uid(&query.action.name)?;
        let context = Context::from_json_value(
            Value::Object(query.context.clone()),
            self.schema.as_ref().map(|schema| (schema, &action)),
        )
        .map_err(|error| format!("cedar: the context is not a legal record: {error}"))?;

        Request::new(principal, action, resource, context, self.schema.as_ref())
            .map_err(|error| format!("cedar: the request does not satisfy the schema: {error}"))
    }

    fn entities(&self, query: &Query) -> Result<Entities, String> {
        let mut items = query.input.cedar_entities().to_vec();
        for (kind, id, properties) in [
            (
                &query.subject.kind,
                &query.subject.id,
                &query.subject.properties,
            ),
            (
                &query.resource.kind,
                &query.resource.id,
                &query.resource.properties,
            ),
        ] {
            if !states_uid(&items, kind, id) {
                items.push(json!({
                    "uid": {"type": kind, "id": id},
                    "attrs": Value::Object(properties.clone()),
                    "parents": [],
                }));
            }
        }

        Entities::from_json_value(Value::Array(items), self.schema.as_ref())
            .map_err(|error| format!("cedar: the entity graph is not legal: {error}"))
    }
}

/// Whether the caller already stated this uid, in which case theirs wins:
/// a caller who wrote out the resource with its parents means it.
fn states_uid(items: &[Value], kind: &str, id: &str) -> bool {
    items.iter().any(|item| {
        item.get("uid").and_then(|uid| {
            let stated_kind = uid.get("type").and_then(Value::as_str)?;
            let stated_id = uid.get("id").and_then(Value::as_str)?;
            Some(stated_kind == kind && stated_id == id)
        }) == Some(true)
    })
}

fn uid(kind: &str, id: &str, what: &str) -> Result<EntityUid, String> {
    if kind.trim().is_empty() {
        return Err(format!("cedar: the {what} names no type"));
    }
    if id.trim().is_empty() {
        return Err(format!("cedar: the {what} names no id"));
    }
    // Built through Cedar's own parser, from JSON-escaped parts: an id with a
    // quote in it is data, never syntax.
    let escaped = Value::from(id).to_string();
    EntityUid::from_str(&format!("{kind}::{escaped}"))
        .map_err(|error| format!("cedar: the {what} `{kind}::{id}` is not an entity: {error}"))
}

/// The action of a request: `read` is `Action::"read"`, and a qualified
/// `acme::Action::read` keeps the type the caller named.
fn action_uid(name: &str) -> Result<EntityUid, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("cedar: the action names nothing".to_owned());
    }
    match name.rsplit_once("::") {
        Some((kind, id)) => uid(kind, id, "action"),
        None => uid("Action", name, "action"),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::evaluate::{Action, Entity};
    use serde_json::Map;

    fn stored(id: &str, source: &str) -> StoredPolicy {
        StoredPolicy {
            id: id.to_owned(),
            alias: None,
            source: source.as_bytes().to_vec(),
        }
    }

    fn query(subject: &str, action: &str, resource: &str) -> Query {
        Query {
            subject: Entity {
                kind: "User".to_owned(),
                id: subject.to_owned(),
                properties: Map::new(),
            },
            resource: Entity {
                kind: "Document".to_owned(),
                id: resource.to_owned(),
                properties: Map::new(),
            },
            action: Action {
                name: action.to_owned(),
                properties: Map::new(),
            },
            context: Map::new(),
            input: crate::input::PartitionData::default(),
        }
    }

    fn store(items: Vec<Value>) -> crate::input::PartitionData {
        crate::input::PartitionData::CedarEntities(std::sync::Arc::new(items))
    }

    #[test]
    fn a_permit_is_a_permit_and_cites_the_policy_that_decided_it() {
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-read",
                    r#"permit (principal, action == Action::"read", resource);"#,
                )],
                None,
            )
            .expect("the policies compile");

        let verdict = compiled.evaluate(&query("alice", "read", "budget"));
        assert!(verdict.permitted);
        assert_eq!(verdict.determining, vec!["01a0-read".to_owned()]);

        // Nothing permits `delete`, and a Cedar deny is silent about policies.
        let denied = compiled.evaluate(&query("alice", "delete", "budget"));
        assert!(!denied.permitted);
        assert!(denied.error.is_none(), "a deny is an answer, not an error");
    }

    #[test]
    fn a_forbid_overrides_a_permit_and_is_cited() {
        let compiled = Cedar
            .compile(
                &[
                    stored(
                        "01a0-read",
                        r#"permit (principal, action == Action::"read", resource);"#,
                    ),
                    stored(
                        "01a0-not-bob",
                        r#"forbid (principal == User::"bob", action, resource);"#,
                    ),
                ],
                None,
            )
            .expect("the policies compile");

        let verdict = compiled.evaluate(&query("bob", "read", "budget"));
        assert!(!verdict.permitted);
        assert_eq!(verdict.determining, vec!["01a0-not-bob".to_owned()]);
    }

    #[test]
    fn properties_and_context_reach_the_policy() {
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-open",
                    r#"permit (principal, action == Action::"read", resource)
                       when { resource.status == "open" && context.tenant == "acme" };"#,
                )],
                None,
            )
            .expect("the policies compile");

        let mut asked = query("alice", "read", "budget");
        asked
            .resource
            .properties
            .insert("status".to_owned(), Value::from("open"));
        asked
            .context
            .insert("tenant".to_owned(), Value::from("acme"));
        assert!(compiled.evaluate(&asked).permitted);

        // Same policy, a resource that is not open: a deny, not an error.
        let mut closed = query("alice", "read", "budget");
        closed
            .resource
            .properties
            .insert("status".to_owned(), Value::from("closed"));
        closed
            .context
            .insert("tenant".to_owned(), Value::from("acme"));
        assert!(!compiled.evaluate(&closed).permitted);
    }

    #[test]
    fn the_entity_graph_a_caller_states_is_traversed() {
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-group",
                    r#"permit (principal in Group::"finance", action == Action::"read", resource);"#,
                )],
                None,
            )
            .expect("the policies compile");

        let mut asked = query("alice", "read", "budget");
        asked.input = store(vec![
            json!({"uid": {"type": "Group", "id": "finance"}, "attrs": {}, "parents": []}),
            json!({"uid": {"type": "User", "id": "alice"}, "attrs": {},
                   "parents": [{"type": "Group", "id": "finance"}]}),
        ]);

        assert!(
            compiled.evaluate(&asked).permitted,
            "the caller's own entity wins over the synthesized one"
        );
    }

    #[test]
    fn a_policy_that_does_not_satisfy_the_schema_refuses_the_load() {
        let schema = r#"
entity User;
entity Document;
action read appliesTo { principal: [User], resource: [Document] };
"#;
        // Legal Cedar, illegal against this schema: `Folder` is not an entity.
        let refused = Cedar
            .compile(
                &[stored(
                    "01a0-folder",
                    r#"permit (principal, action == Action::"read", resource == Folder::"x");"#,
                )],
                Some(schema.as_bytes()),
            )
            .map(|_| ())
            .expect_err("the schema is a contract");

        assert!(refused.contains("schema"), "{refused}");
    }

    #[test]
    fn with_a_schema_a_well_typed_request_is_answered_and_a_wrong_one_is_refused() {
        let schema = r#"
entity User;
entity Document;
action read appliesTo { principal: [User], resource: [Document] };
"#;
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-read",
                    r#"permit (principal, action == Action::"read", resource);"#,
                )],
                Some(schema.as_bytes()),
            )
            .expect("the policies satisfy the schema");

        assert!(
            compiled
                .evaluate(&query("alice", "read", "budget"))
                .permitted
        );

        // An action the schema never declared cannot be evaluated: a deny
        // that says so, rather than a silent false.
        let refused = compiled.evaluate(&query("alice", "teleport", "budget"));
        assert!(!refused.permitted);
        assert!(refused.error.is_some(), "the reason is carried");
    }

    #[test]
    fn a_request_missing_its_parts_is_a_deny_with_a_reason() {
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-read",
                    r#"permit (principal, action, resource);"#,
                )],
                None,
            )
            .expect("the policies compile");

        let mut asked = query("alice", "read", "budget");
        asked.subject.id = String::new();
        let verdict = compiled.evaluate(&asked);
        assert!(!verdict.permitted);
        assert!(
            verdict.error.expect("a reason").contains("subject"),
            "the reason names what was missing"
        );
    }

    #[test]
    fn a_qualified_action_keeps_its_type() {
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-ns",
                    r#"permit (principal, action == acme::Action::"read", resource);"#,
                )],
                None,
            )
            .expect("the policies compile");

        assert!(
            compiled
                .evaluate(&query("alice", "acme::Action::read", "budget"))
                .permitted
        );
    }
}
