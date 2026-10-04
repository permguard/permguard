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
//! | `subject.properties`, `resource.properties` | attributes of the two entities, synthesized unless the store already carries that uid, which must then hold exactly the same attributes |
//! | `permguard.cedar.entities.v1` | the entity store verbatim, in Cedar's own JSON shape |
//!
//! Synthesizing the two named entities is what lets a policy read
//! `resource.status` without the caller restating the resource inside the
//! store. A caller who states the uid in the store (with parents, say) and
//! also gives it properties must give the same attributes in both places:
//! one value has one authority (CEDAR-04), and a store that silently won
//! would let two callers' views of one entity disagree with nobody told.
//! Parents come only from the store.
//!
//! The store is addressed to **this partition by name**. Two Cedar partitions
//! with different schemas are two different worlds: an entity legal in one is
//! refused by the other, so a store was never something to hand to "the Cedar
//! partitions".

use std::str::FromStr as _;

use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicyId, PolicySet, Request, Schema,
};
use serde_json::{Value, json};

use crate::evaluate::{Evaluating, Evaluator, Query, StoredPolicy, Verdict};

use super::Cedar;

impl Evaluating for Cedar {
    fn compile(
        &self,
        policies: &[StoredPolicy],
        artifacts: &crate::artifact::Artifacts,
    ) -> Result<Box<dyn Evaluator>, String> {
        let schema = artifacts.bytes(crate::cedar::SCHEMA_ARTIFACT);
        let schema_bytes = schema.map_or(0, <[u8]>::len);
        let schema = schema.map(super::parse_schema).transpose()?;

        let mut set = PolicySet::new();
        let mut policy_bytes = 0;
        for stored in policies {
            let text = std::str::from_utf8(&stored.source)
                .map_err(|_| format!("cedar: policy {} is not valid UTF-8", stored.id))?;
            let policy = super::parse_policy(text)
                .map_err(|error| format!("cedar: policy {} does not parse: {error}", stored.id))?;
            let id = PolicyId::from_str(&stored.id)
                .map_err(|error| format!("cedar: policy id {}: {error}", stored.id))?;
            set.add(policy.new_id(id))
                .map_err(|error| format!("cedar: policy {}: {error}", stored.id))?;
            policy_bytes += stored.source.len();
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
            footprint: footprint(policy_bytes, schema_bytes),
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

/// What a compiled Cedar partition keeps, conservatively (LANG-07, CEDAR-06).
///
/// Cedar's parsed policy set and its schema's indexes weigh far more than the text they came
/// from: measured, about 25 times the policy bytes and 13 times the schema bytes, plus a fixed
/// overhead. The estimate is roughly twice that, so the cache's byte bound holds for real;
/// `tests/footprint.rs` proves it is never below what the engine retains. An estimate, not a hard
/// bound: the hard bound on an engine's memory is a supervised worker's `RLIMIT_AS`.
fn footprint(policy_bytes: usize, schema_bytes: usize) -> usize {
    const BASE: usize = 64 * 1024;
    const PER_POLICY_BYTE: usize = 64;
    const PER_SCHEMA_BYTE: usize = 32;

    BASE.saturating_add(policy_bytes.saturating_mul(PER_POLICY_BYTE))
        .saturating_add(schema_bytes.saturating_mul(PER_SCHEMA_BYTE))
}

impl Evaluator for CedarEvaluator {
    fn evaluate(&self, query: &Query) -> Verdict {
        // Cedar terminates by construction — no loops, no recursion, no unbounded traversal — so
        // there is nothing to interrupt mid-evaluation and nothing that needs interrupting. What
        // is worth checking is whether to start at all: a partition reached after the decision ran
        // out of time answers nothing anybody is still waiting for.
        if query.expired() {
            return Verdict::deadline_exceeded(
                "the decision ran out of time before this partition",
            );
        }

        // A request or an entity store this partition cannot represent is not a question its
        // policies can answer: `E`, not a deny they never expressed.
        let request = match self.request(query) {
            Ok(request) => request,
            Err(error) => return Verdict::input_rejected(error),
        };
        let entities = match self.entities(query) {
            Ok(entities) => entities,
            Err(error) => return Verdict::input_rejected(error),
        };

        let response = Authorizer::new().is_authorized(&request, &self.set, &entities);
        let determining: Vec<String> = response
            .diagnostics()
            .reason()
            .map(ToString::to_string)
            .collect();
        // The diagnostics before any permit is read. Cedar answers `Allow` when one policy
        // permits and another failed to evaluate — a permit released after a policy failed is not
        // defensible, so an error beside an `Allow` is `E`. A `forbid` that fired is different:
        // nothing the failed policy could return turns it into a permit, so it is `D`, with the
        // failure kept beside it. A deny no `forbid` decided is the failure: `E`.
        let errors: Vec<String> = response
            .diagnostics()
            .errors()
            .map(ToString::to_string)
            .collect();
        if !errors.is_empty() {
            let message = format!("cedar: {}", errors.join("; "));
            return match response.decision() {
                Decision::Allow => Verdict::engine_failed(message),
                Decision::Deny => Verdict::deny_despite_failure(determining, message),
            };
        }

        match response.decision() {
            Decision::Allow => Verdict::permit(determining),
            // A `forbid` that fired is a deny; a deny nothing fired is Cedar's default, which the
            // algebra calls an abstain. `Verdict::deny` tells the two apart by the list.
            Decision::Deny => Verdict::deny(determining),
        }
    }

    /// The entity store, against this partition's own schema, before any policy runs.
    ///
    /// A store the schema refuses is a bad request rather than a denied one, and the difference
    /// matters to whoever has to fix it: `deny` sends them reading policies, and this sends them
    /// to the entity they mistyped.
    fn check_input(&self, input: &crate::input::PartitionData) -> Result<(), String> {
        build_entities(input.cedar_entities().to_vec(), self.schema.as_ref())
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
            match stated_attrs(&items, kind, id) {
                None => items.push(json!({
                    "uid": {"type": kind, "id": id},
                    "attrs": Value::Object(properties.clone()),
                    "parents": [],
                })),
                // Stated in the store and not restated here: the store is the one authority.
                Some(_) if properties.is_empty() => {}
                Some(stated) if stated == Value::Object(properties.clone()) => {}
                Some(_) => {
                    return Err(format!(
                        "cedar: `{kind}::{id}` appears in the entity store and in the request's \
                         properties with different attributes; one value has one authority"
                    ));
                }
            }
        }

        build_entities(items, self.schema.as_ref())
            .map_err(|error| format!("cedar: the entity graph is not legal: {error}"))
    }
}

/// A uid as Cedar reads it: `{"type", "id"}`, or the same inside the explicit escape
/// `{"__entity": {"type", "id"}}`, which Cedar accepts for a uid and for a parent alike.
fn unescaped(uid: &Value) -> &Value {
    uid.get("__entity").unwrap_or(uid)
}

/// How deep a request's entity hierarchy may be: the longest chain of `parents`.
///
/// Cedar computes the hierarchy's transitive closure when it builds the graph, with stack and
/// time that grow with the depth: two thousand levels overflow an evaluating thread and cost
/// seconds. The bound is checked on the JSON, before Cedar sees it, so a request cannot spend
/// either; a real hierarchy — user, groups, units — is a handful of levels.
pub const MAX_HIERARCHY_DEPTH: usize = 64;

/// The entity graph of a request: the hierarchy bound first, then Cedar's own construction on a
/// stack segment of its own.
fn build_entities(items: Vec<Value>, schema: Option<&Schema>) -> Result<Entities, String> {
    check_hierarchy(&items)?;
    crate::headroom::ample(|| {
        Entities::from_json_value(Value::Array(items), schema).map_err(|error| error.to_string())
    })
}

/// Refuses a hierarchy deeper than [`MAX_HIERARCHY_DEPTH`], or one with a cycle, which has no
/// depth at all.
///
/// Iterative, so the check itself has no depth: each round lengthens every entity's known chain by
/// at most one level, and a chain still growing after the bound has been passed is too deep, or a
/// cycle.
fn check_hierarchy(items: &[Value]) -> Result<(), String> {
    let key = |uid: &Value| -> Option<(String, String)> {
        let uid = unescaped(uid);
        Some((
            uid.get("type")?.as_str()?.to_owned(),
            uid.get("id")?.as_str()?.to_owned(),
        ))
    };
    let mut parents: std::collections::HashMap<(String, String), Vec<(String, String)>> =
        std::collections::HashMap::new();
    for item in items {
        let Some(uid) = item.get("uid").and_then(key) else {
            continue;
        };
        let stated: Vec<(String, String)> = item
            .get("parents")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(key).collect())
            .unwrap_or_default();
        parents.entry(uid).or_default().extend(stated);
    }
    let mut depth: std::collections::HashMap<&(String, String), usize> =
        parents.keys().map(|uid| (uid, 0)).collect();
    for _ in 0..=MAX_HIERARCHY_DEPTH {
        let mut changed = false;
        for (uid, above) in &parents {
            let longest = above
                .iter()
                .map(|parent| depth.get(parent).map_or(1, |held| held + 1))
                .max()
                .unwrap_or(0);
            if longest > depth[uid] {
                depth.insert(uid, longest);
                changed = true;
            }
        }
        if !changed {
            return Ok(());
        }
        if depth.values().any(|held| *held > MAX_HIERARCHY_DEPTH) {
            break;
        }
    }

    Err(format!(
        "the entity hierarchy is deeper than {MAX_HIERARCHY_DEPTH} levels, or a cycle"
    ))
}

/// The attributes the entity store states for this uid, when it states the uid at all; an entity
/// stated without `attrs` states none.
fn stated_attrs(items: &[Value], kind: &str, id: &str) -> Option<Value> {
    items
        .iter()
        .find(|item| {
            item.get("uid").map(unescaped).and_then(|uid| {
                let stated_kind = uid.get("type").and_then(Value::as_str)?;
                let stated_id = uid.get("id").and_then(Value::as_str)?;
                Some(stated_kind == kind && stated_id == id)
            }) == Some(true)
        })
        .map(|item| {
            item.get("attrs")
                .cloned()
                .unwrap_or_else(|| Value::Object(serde_json::Map::new()))
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
    use crate::evaluate::{Action, Entity, Resolution, resolve};
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
            deadline: None,
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
                &crate::artifact::Artifacts::default(),
            )
            .expect("the policies compile");

        let verdict = compiled.evaluate(&query("alice", "read", "budget"));
        assert!(verdict.permitted());
        assert_eq!(verdict.determining(), vec!["01a0-read".to_owned()]);

        // Nothing permits `delete`, and a Cedar deny nothing fired is an abstain: not an error,
        // and not a policy saying no.
        let denied = compiled.evaluate(&query("alice", "delete", "budget"));
        assert_eq!(denied, Verdict::Abstain);
    }

    /// Cedar answers `Allow` when one policy permits and another could not be evaluated. The
    /// languages model calls that `E`: releasing a permit after any policy failed is not
    /// defensible, so the diagnostics are read before the decision and the decision is not.
    #[test]
    fn an_allow_beside_a_diagnostic_error_is_an_evaluation_failure() {
        let compiled = Cedar
            .compile(
                &[
                    stored(
                        "01a0-read",
                        r#"permit (principal, action == Action::"read", resource);"#,
                    ),
                    // `principal` has no `clearance`, so this policy errors rather than matching.
                    stored(
                        "01a0-cleared",
                        r#"permit (principal, action, resource) when { principal.clearance == "top" };"#,
                    ),
                ],
                &crate::artifact::Artifacts::default(),
            )
            .expect("the policies compile");

        let verdict = compiled.evaluate(&query("alice", "read", "budget"));

        let error = verdict.error().expect("an allow beside an error is `E`");
        assert_eq!(
            error.code,
            permguard_core::codes::pdp_native::EVALUATION_FAILED
        );
        assert!(error.message.contains("clearance"), "{error}");
        assert!(verdict.determining().is_empty(), "`E` cites no policy");
        assert_eq!(
            resolve([verdict]).resolution,
            Resolution::Indeterminate,
            "the profile is indeterminate, not a permit and not a deny"
        );
    }

    /// A `forbid` that fired dominates a failure of another policy in the same partition: the
    /// deny stands and cites it, and the failure is kept beside it. Without the `forbid`, the
    /// same failure is `E`.
    #[test]
    fn a_forbid_beside_a_diagnostic_error_is_a_deny_that_keeps_the_error() {
        let compiled = Cedar
            .compile(
                &[
                    stored(
                        "01a0-read",
                        r#"permit (principal, action == Action::"read", resource);"#,
                    ),
                    stored(
                        "01a0-budget",
                        r#"forbid (principal, action, resource == Document::"budget");"#,
                    ),
                    // `principal` has no `clearance`, so this policy errors rather than matching.
                    stored(
                        "01a0-cleared",
                        r#"permit (principal, action, resource) when { principal.clearance == "top" };"#,
                    ),
                ],
                &crate::artifact::Artifacts::default(),
            )
            .expect("the policies compile");

        let verdict = compiled.evaluate(&query("alice", "read", "budget"));
        assert_eq!(
            verdict.determining(),
            ["01a0-budget".to_owned()],
            "{verdict:?}"
        );
        assert!(verdict.error().is_none(), "a `D`, not an `E`: {verdict:?}");
        let failure = verdict
            .failure()
            .expect("the error is kept beside the deny");
        assert_eq!(
            failure.code,
            permguard_core::codes::pdp_native::EVALUATION_FAILED
        );
        assert!(failure.message.contains("clearance"), "{failure}");
        assert_eq!(resolve([verdict]).resolution, Resolution::Deny);

        let elsewhere = compiled.evaluate(&query("alice", "write", "plan"));
        assert_eq!(
            elsewhere.error().map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_FAILED),
            "no forbid fired: the failure is the answer"
        );
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
                &crate::artifact::Artifacts::default(),
            )
            .expect("the policies compile");

        let verdict = compiled.evaluate(&query("bob", "read", "budget"));
        assert!(!verdict.permitted());
        assert_eq!(verdict.determining(), vec!["01a0-not-bob".to_owned()]);
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
                &crate::artifact::Artifacts::default(),
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
        assert!(compiled.evaluate(&asked).permitted());

        // Same policy, a resource that is not open: a deny, not an error.
        let mut closed = query("alice", "read", "budget");
        closed
            .resource
            .properties
            .insert("status".to_owned(), Value::from("closed"));
        closed
            .context
            .insert("tenant".to_owned(), Value::from("acme"));
        assert!(!compiled.evaluate(&closed).permitted());
    }

    #[test]
    fn the_entity_graph_a_caller_states_is_traversed() {
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-group",
                    r#"permit (principal in Group::"finance", action == Action::"read", resource);"#,
                )],
                &crate::artifact::Artifacts::default(),
            )
            .expect("the policies compile");

        let mut asked = query("alice", "read", "budget");
        asked.input = store(vec![
            json!({"uid": {"type": "Group", "id": "finance"}, "attrs": {}, "parents": []}),
            json!({"uid": {"type": "User", "id": "alice"}, "attrs": {},
                   "parents": [{"type": "Group", "id": "finance"}]}),
        ]);

        assert!(
            compiled.evaluate(&asked).permitted(),
            "the caller's own entity wins over the synthesized one"
        );
    }

    /// CEDAR-04: a uid stated both in the entity store and in the request's properties needs the
    /// same attributes in both, or the request is refused as an input the engine rejects; a uid
    /// stated only in the store keeps the store as its one authority, parents included.
    #[test]
    fn one_value_has_one_authority_between_the_store_and_the_properties() {
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-open",
                    r#"permit (principal, action, resource) when { resource.status == "open" };"#,
                )],
                &crate::artifact::Artifacts::default(),
            )
            .expect("the policies compile");
        let stated = |status: &str| {
            store(vec![json!({"uid": {"type": "Document", "id": "budget"},
                              "attrs": {"status": status}, "parents": []})])
        };
        let mut asked = query("alice", "read", "budget");
        asked.resource.kind = "Document".to_owned();

        // Stated in the store only: the store answers.
        asked.input = stated("open");
        assert!(compiled.evaluate(&asked).permitted());

        // Stated in both, equal: one value.
        asked
            .resource
            .properties
            .insert("status".to_owned(), Value::from("open"));
        assert!(compiled.evaluate(&asked).permitted());

        // Stated in both, different: refused, never silently resolved either way.
        asked.input = stated("closed");
        let verdict = compiled.evaluate(&asked);
        assert!(!verdict.permitted());
        let error = verdict.error().expect("`E`, not a deny");
        assert_eq!(
            error.code,
            permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED
        );
        assert!(error.message.contains("one authority"), "{}", error.message);
    }

    /// Required cases: a long conjunction, a deep nesting, a large set and a large entity graph
    /// are answered inside the limits. What is too deep for the engine is refused as an error,
    /// never a crash of the process.
    #[test]
    fn deep_expressions_large_sets_and_large_graphs_stay_inside_limits() {
        let artifacts = crate::artifact::Artifacts::default();
        let compile = |id: &str, source: String| {
            crate::headroom::with(|| Cedar.compile(&[stored(id, &source)], &artifacts))
        };
        let ask = |query: &Query, evaluator: &dyn Evaluator| {
            crate::headroom::with(|| evaluator.evaluate(query))
        };

        let chain = vec!["true"; 2_000].join(" && ");
        let long = compile(
            "01a0-chain",
            format!("permit (principal, action, resource) when {{ {chain} }};"),
        )
        .expect("a long conjunction compiles");
        assert!(ask(&query("alice", "read", "budget"), long.as_ref()).permitted());

        // Nesting is bounded before the parser runs: the bound itself compiles, one level more is
        // refused, and a nesting deep enough to exhaust any stack is refused the same way rather
        // than taking the process down.
        let nested = |levels: usize| {
            let deep = format!("{}true{}", "(".repeat(levels), ")".repeat(levels));
            // One brace of the `when` block is a level too.
            compile(
                "01a0-deep",
                format!("permit (principal, action, resource) when {{ {deep} }};"),
            )
        };
        let at_bound = nested(crate::cedar::MAX_NESTING - 1).expect("the bound compiles");
        assert!(ask(&query("alice", "read", "budget"), at_bound.as_ref()).permitted());
        for refused in [crate::cedar::MAX_NESTING, 5_000] {
            let Err(error) = nested(refused) else {
                panic!("{refused} levels compiled");
            };
            assert!(error.contains("levels deep"), "{error}");
        }
        // Cedar nests without brackets too: every `if` is a level, and a schema's `Set<…>` is.
        let ifs = |levels: usize| {
            let mut expression = "true".to_owned();
            for _ in 0..levels {
                expression = format!("if false then false else {expression}");
            }
            format!("permit (principal, action, resource) when {{ {expression} }};")
        };
        assert!(compile("01a0-ifs", ifs(crate::cedar::MAX_NESTING - 1)).is_ok());
        for levels in [crate::cedar::MAX_NESTING, 5_000] {
            let Err(error) = compile("01a0-ifs", ifs(levels)) else {
                panic!("{levels} nested ifs compiled");
            };
            assert!(error.contains("levels deep"), "{error}");
        }
        // A member chain and a `has` path nest one level per link.
        let member = |links: usize| {
            format!(
                "permit (principal, action, resource) when {{ context{} == 1 }};",
                ".a".repeat(links)
            )
        };
        let path = |links: usize| {
            format!(
                "permit (principal, action, resource) when {{ context has {} }};",
                vec!["a"; links].join(".")
            )
        };
        assert!(compile("01a0-member", member(8)).is_ok());
        assert!(compile("01a0-path", path(8)).is_ok());
        for links in [crate::cedar::MAX_NESTING + 1, 100_000] {
            for (name, source) in [("member", member(links)), ("path", path(links))] {
                let Err(error) = compile("01a0-chain-link", source) else {
                    panic!("a {name} chain of {links} links compiled");
                };
                assert!(error.contains("levels deep"), "{error}");
            }
        }
        let sets = format!(
            "entity User {{ tags: {}Long{} }};",
            "Set<".repeat(5_000),
            ">".repeat(5_000)
        );
        assert!(
            crate::role::Language::validate_schema(&Cedar, sets.as_bytes()).is_err(),
            "a schema nesting `Set<…>` past the bound is refused before the parser"
        );
        assert!(
            crate::role::Language::validate_policy(
                &Cedar,
                format!(
                    "permit (principal, action, resource) when {{ {}true{} }};",
                    "[".repeat(200),
                    "]".repeat(200)
                )
                .as_bytes()
            )
            .is_err(),
            "the push path refuses it too"
        );
        let mut nested_context = Value::from(1);
        for _ in 0..100 {
            nested_context = json!({ "a": nested_context });
        }
        let mut deep_context = query("alice", "read", "budget");
        deep_context
            .context
            .insert("deep".to_owned(), nested_context);
        let _ = ask(&deep_context, long.as_ref());

        let members: Vec<String> = (0..10_000).map(|i| format!("\"v{i}\"")).collect();
        let large = compile(
            "01a0-set",
            format!(
                "permit (principal, action, resource) when {{ [{}].contains(resource.tag) }};",
                members.join(",")
            ),
        )
        .expect("a large set compiles");
        let mut tagged = query("alice", "read", "budget");
        tagged
            .resource
            .properties
            .insert("tag".to_owned(), Value::from("v9999"));
        assert!(ask(&tagged, large.as_ref()).permitted());

        let grouped = compile(
            "01a0-graph",
            r#"permit (principal in Group::"g0", action, resource);"#.to_owned(),
        )
        .expect("compiles");
        // A chain of `levels` groups under `g0`, `alice` in the last: `alice` is `levels` deep.
        let chained = |levels: usize| {
            let mut items: Vec<Value> = (0..levels)
                .map(|i| {
                    let parents = if i == 0 {
                        json!([])
                    } else {
                        json!([{"type": "Group", "id": format!("g{}", i - 1)}])
                    };
                    json!({"uid": {"type": "Group", "id": format!("g{i}")}, "attrs": {},
                           "parents": parents})
                })
                .collect();
            items.push(json!({"uid": {"type": "User", "id": "alice"}, "attrs": {},
                              "parents": [{"type": "Group", "id": format!("g{}", levels - 1)}]}));
            let mut asked = query("alice", "read", "budget");
            asked.input = store(items);
            asked
        };
        assert!(ask(&chained(MAX_HIERARCHY_DEPTH), grouped.as_ref()).permitted());
        // One level more, two thousand (enough to overflow an evaluating thread), and a cycle are
        // each refused as an input the engine rejects, before Cedar builds anything.
        let mut cycle = query("alice", "read", "budget");
        cycle.input = store(vec![
            json!({"uid": {"type": "Group", "id": "a"}, "attrs": {}, "parents": [{"type": "Group", "id": "b"}]}),
            json!({"uid": {"type": "Group", "id": "b"}, "attrs": {}, "parents": [{"type": "Group", "id": "a"}]}),
        ]);
        // The same chain written with Cedar's explicit escape, `{"__entity": {…}}`, is the same
        // hierarchy and is refused the same way.
        let escaped_chain = {
            let items: Vec<Value> = (0..2_000)
                .map(|i| {
                    let parents = if i == 0 {
                        json!([])
                    } else {
                        json!([{"__entity": {"type": "Group", "id": format!("g{}", i - 1)}}])
                    };
                    json!({"uid": {"__entity": {"type": "Group", "id": format!("g{i}")}},
                           "attrs": {}, "parents": parents})
                })
                .collect();
            let mut asked = query("alice", "read", "budget");
            asked.input = store(items);
            asked
        };
        for refused in [
            chained(MAX_HIERARCHY_DEPTH + 1),
            chained(2_000),
            cycle,
            escaped_chain,
        ] {
            let verdict = ask(&refused, grouped.as_ref());
            let error = verdict.error().expect("`E`, not a deny");
            assert_eq!(
                error.code,
                permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED
            );
            assert!(error.message.contains("hierarchy"), "{}", error.message);
        }
    }

    /// Golden results: the same partition compiled twice, as after a restart, answers every case
    /// the same, and as stated; the same table runs on every supported platform.
    #[test]
    fn golden_results_hold_across_a_recompile() {
        let policies = [
            stored(
                "01a0-read",
                r#"permit (principal, action == Action::"read", resource);"#,
            ),
            stored(
                "01a0-not-bob",
                r#"forbid (principal == User::"bob", action, resource);"#,
            ),
            stored(
                "01a0-broken",
                r#"permit (principal, action == Action::"audit", resource) when { resource.clearance > 3 };"#,
            ),
        ];
        let cases = [
            ("alice", "read", "P"),
            ("bob", "read", "D"),
            ("alice", "write", "A"),
            ("alice", "audit", "E"),
        ];
        let compile = || {
            Cedar
                .compile(&policies, &crate::artifact::Artifacts::default())
                .expect("the policies compile")
        };
        let symbol = |verdict: &Verdict| match verdict {
            Verdict::Permit { .. } => "P",
            Verdict::Deny { .. } => "D",
            Verdict::Abstain => "A",
            Verdict::Error { .. } => "E",
        };
        let (first, second) = (compile(), compile());
        for (subject, action, expected) in cases {
            let asked = query(subject, action, "budget");
            let (one, two) = (first.evaluate(&asked), second.evaluate(&asked));
            assert_eq!(symbol(&one), expected, "{subject} {action}");
            assert_eq!(format!("{one:?}"), format!("{two:?}"), "{subject} {action}");
        }
    }

    /// Default deny: no policy matched is an abstain, `A`, not a deny a forbid decided.
    #[test]
    fn nothing_matched_is_an_abstain() {
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-list",
                    r#"permit (principal, action == Action::"list", resource);"#,
                )],
                &crate::artifact::Artifacts::default(),
            )
            .expect("the policies compile");
        let verdict = compiled.evaluate(&query("alice", "read", "budget"));
        assert!(matches!(verdict, Verdict::Abstain), "{verdict:?}");
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
                &crate::artifact::Artifacts::just(crate::cedar::SCHEMA_ARTIFACT, schema.as_bytes())
                    .expect("the schema artifact is registered"),
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
                &crate::artifact::Artifacts::just(crate::cedar::SCHEMA_ARTIFACT, schema.as_bytes())
                    .expect("the schema artifact is registered"),
            )
            .expect("the policies satisfy the schema");

        assert!(
            compiled
                .evaluate(&query("alice", "read", "budget"))
                .permitted()
        );

        // An action the schema never declared cannot be evaluated: a deny
        // that says so, rather than a silent false.
        let refused = compiled.evaluate(&query("alice", "teleport", "budget"));
        assert!(!refused.permitted());
        assert!(refused.error().is_some(), "the reason is carried");
    }

    #[test]
    fn a_request_missing_its_parts_is_an_input_the_engine_rejects() {
        let compiled = Cedar
            .compile(
                &[stored(
                    "01a0-read",
                    r#"permit (principal, action, resource);"#,
                )],
                &crate::artifact::Artifacts::default(),
            )
            .expect("the policies compile");

        let mut asked = query("alice", "read", "budget");
        asked.subject.id = String::new();
        let verdict = compiled.evaluate(&asked);
        assert!(!verdict.permitted());
        let error = verdict.error().expect("`E`, not a deny");
        assert_eq!(
            error.code,
            permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED
        );
        assert!(
            error.message.contains("subject"),
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
                &crate::artifact::Artifacts::default(),
            )
            .expect("the policies compile");

        assert!(
            compiled
                .evaluate(&query("alice", "acme::Action::read", "budget"))
                .permitted()
        );
    }
}
