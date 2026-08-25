// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Deciding with Rego, through Microsoft's `regorus` interpreter.
//!
//! # The contract a Rego partition answers
//!
//! Rego has no built-in notion of a decision, so the profile fixes one — and
//! it is the convention OPA users already write:
//!
//! | Rule | Meaning |
//! | --- | --- |
//! | `allow` | this module permits the request |
//! | `deny` | this module refuses it, **whatever any other module allows** |
//!
//! Every module in the partition is asked, and the resolution is the one an
//! authorization system can defend: **deny overrides**, and absent means no.
//! A module that defines neither rule contributes nothing; a partition where
//! nothing allows denies. `default allow := false` is therefore not a style
//! preference here, it is what makes a module's answer well-defined.
//!
//! # The input a policy reads
//!
//! `input` is the request as the profile received it — the same shape a Cedar
//! partition is given, so a `permguard.pdp.v1` caller cannot tell which
//! language answered:
//!
//! ```text
//! input.subject  {type, id, properties}
//! input.resource {type, id, properties}
//! input.action   {name, properties}
//! input.context  {…}
//! ```
//!
//! The entity graph the request may carry is handed to Rego as `data.entities`
//! — Rego traverses data, not entities, so the graph is data.
//!
//! # Compile once
//!
//! The engine is built and the modules are added at compile time; each
//! request clones that prepared engine, sets its input and evaluates. Nothing
//! on the decision path parses Rego.

use std::num::NonZeroU32;
use std::time::Duration;

use regorus::utils::limits::ExecutionTimerConfig;
use regorus::{Engine, Value as RegoValue};
use serde_json::{Value, json};

use crate::evaluate::{Evaluating, Evaluator, Query, StoredPolicy, Verdict};

use super::Rego;

/// The most wall-clock one rule evaluation may spend.
///
/// Rego is not structurally terminating the way Cedar is: comprehensions and
/// `walk` over adversarial data can be made arbitrarily expensive, and the
/// transport's request timeout is not a preemption boundary for a synchronous
/// evaluation — it ends the response, not the work. This is the boundary. It
/// is enormous next to a real authorization rule, which evaluates in
/// microseconds, and small next to a stalled worker. A rule that exceeds it
/// answers as every other evaluation fault does: a deny that says why.
///
/// The same engine configuration governs the per-rule probe at compile time,
/// so a policy that stalls *loading* is refused rather than served.
const RULE_BUDGET: Duration = Duration::from_secs(1);

/// How many interpreter work units pass between clock checks.
///
/// The check is a monotonic-clock read: cheap, but not free on the decision
/// path. Every 128 units bounds the overshoot to a sliver of the budget
/// without measurably taxing the ordinary microsecond evaluation.
const BUDGET_CHECK_INTERVAL: u32 = 128;

/// A module and the identity of the policy it came from.
struct Module {
    /// The policy identity — what a decision cites.
    id: String,
    /// The rules this module actually defines, fully qualified. Which of the
    /// two a module answers is settled **once, at compile time**: a module
    /// that defines neither is a module with nothing to say, and asking it at
    /// every request would turn "nothing to say" into an error to sift.
    allow: Option<String>,
    deny: Option<String>,
}

impl Evaluating for Rego {
    fn compile(
        &self,
        policies: &[StoredPolicy],
        schema: Option<&[u8]>,
    ) -> Result<Box<dyn Evaluator>, String> {
        // Rego has no schema in this model, and a partition that declares one
        // is a partition somebody misconfigured: refuse it here as well as at
        // ingest, because this is the last place before serving.
        if schema.is_some() {
            return Err(
                "rego: this language has no schema, so a schema partition is refused".into(),
            );
        }

        let mut engine = Engine::new();
        engine.set_execution_timer_config(ExecutionTimerConfig {
            limit: RULE_BUDGET,
            check_interval: NonZeroU32::new(BUDGET_CHECK_INTERVAL).unwrap_or(NonZeroU32::MIN),
        });
        let mut modules = Vec::new();
        let mut footprint = 0;
        for stored in policies {
            let text = std::str::from_utf8(&stored.source)
                .map_err(|_| format!("rego: module {} is not valid UTF-8", stored.id))?;
            let package = engine
                .add_policy(format!("{}.rego", stored.id), text.to_owned())
                .map_err(|error| format!("rego: module {} does not parse: {error}", stored.id))?;
            modules.push(Module {
                id: stored.id.clone(),
                allow: defined(&mut engine, &format!("{package}.allow")),
                deny: defined(&mut engine, &format!("{package}.deny")),
            });
            footprint += stored.source.len();
        }

        Ok(Box::new(RegoEvaluator {
            engine,
            modules,
            footprint,
        }))
    }
}

/// A compiled Rego partition.
struct RegoEvaluator {
    engine: Engine,
    modules: Vec<Module>,
    footprint: usize,
}

impl Evaluator for RegoEvaluator {
    fn evaluate(&self, query: &Query) -> Verdict {
        let input = match value_of(&input_document(query)) {
            Ok(input) => input,
            Err(error) => return Verdict::refused(error),
        };
        // One prepared engine, cloned per request: the modules are already
        // parsed, and an evaluation must never mutate what the next one reads.
        let mut engine = self.engine.clone();
        engine.set_input(input);
        if !query.entities.is_empty() {
            let data = match value_of(&json!({"entities": query.entities})) {
                Ok(data) => data,
                Err(error) => return Verdict::refused(error),
            };
            if let Err(error) = engine.add_data(data) {
                return Verdict::refused(format!(
                    "rego: the entity graph is not legal data: {error}"
                ));
            }
        }

        let mut permitted = Vec::new();
        let mut denied = Vec::new();
        for module in &self.modules {
            for (rule, answers) in [
                (module.deny.as_deref(), &mut denied),
                (module.allow.as_deref(), &mut permitted),
            ] {
                let Some(rule) = rule else { continue };
                match asked(&mut engine, rule) {
                    Ok(true) => answers.push(module.id.clone()),
                    Ok(false) => {}
                    Err(error) => return Verdict::refused(error),
                }
            }
        }

        // Deny overrides, and absent means no: the only resolution an
        // authorization system can defend.
        if !denied.is_empty() {
            return Verdict::deny(denied);
        }
        if permitted.is_empty() {
            return Verdict::deny(Vec::new());
        }

        Verdict::permit(permitted)
    }

    fn footprint(&self) -> usize {
        self.footprint
    }

    fn policies(&self) -> Vec<String> {
        self.modules.iter().map(|m| m.id.clone()).collect()
    }
}

/// Whether a module defines this rule at all. Asked once, at compile time:
/// the engine answers "not a valid rule path" for a rule nobody wrote, and
/// that is a fact about the module, not about a request.
fn defined(engine: &mut Engine, rule: &str) -> Option<String> {
    match engine.eval_rule(rule.to_owned()) {
        Ok(_) => Some(rule.to_owned()),
        Err(error) if error.to_string().contains("not a valid rule path") => None,
        // Anything else means the rule exists and evaluating it without an
        // input went wrong — which is exactly what a request will decide.
        Err(_) => Some(rule.to_owned()),
    }
}

/// Asks one rule the module defines. `undefined` — a rule whose body did not
/// hold — is not an error: it is a no.
fn asked(engine: &mut Engine, rule: &str) -> Result<bool, String> {
    match engine.eval_rule(rule.to_owned()) {
        Ok(RegoValue::Bool(answered)) => Ok(answered),
        Ok(RegoValue::Undefined) => Ok(false),
        // A rule that answers something other than a boolean is a policy bug,
        // and a PDP that guessed what it meant would be worse than one that
        // says so.
        Ok(other) => Err(format!(
            "rego: `{rule}` answered `{other}` instead of a boolean"
        )),
        Err(error) => Err(format!("rego: evaluating `{rule}`: {error}")),
    }
}

/// The request, as the `input` document a policy reads.
fn input_document(query: &Query) -> Value {
    json!({
        "subject": {
            "type": query.subject.kind,
            "id": query.subject.id,
            "properties": Value::Object(query.subject.properties.clone()),
        },
        "resource": {
            "type": query.resource.kind,
            "id": query.resource.id,
            "properties": Value::Object(query.resource.properties.clone()),
        },
        "action": {
            "name": query.action.name,
            "properties": Value::Object(query.action.properties.clone()),
        },
        "context": Value::Object(query.context.clone()),
    })
}

fn value_of(document: &Value) -> Result<RegoValue, String> {
    RegoValue::from_json_str(&document.to_string())
        .map_err(|error| format!("rego: the request is not legal JSON for the engine: {error}"))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::evaluate::{Action, Entity};
    use serde_json::Map;

    const READERS: &str = r#"package documents

import rego.v1

default allow := false

allow if {
    input.subject.type == "user"
    input.action.name == "read"
    input.resource.properties.status == "open"
}
"#;

    const NEVER_BOB: &str = r#"package guards

import rego.v1

default deny := false

deny if input.subject.id == "bob"
"#;

    fn stored(id: &str, source: &str) -> StoredPolicy {
        StoredPolicy {
            id: id.to_owned(),
            alias: None,
            source: source.as_bytes().to_vec(),
        }
    }

    fn query(subject: &str, action: &str, status: &str) -> Query {
        let mut resource = Entity {
            kind: "document".to_owned(),
            id: "budget".to_owned(),
            properties: Map::new(),
        };
        resource
            .properties
            .insert("status".to_owned(), Value::from(status));

        Query {
            subject: Entity {
                kind: "user".to_owned(),
                id: subject.to_owned(),
                properties: Map::new(),
            },
            resource,
            action: Action {
                name: action.to_owned(),
                properties: Map::new(),
            },
            context: Map::new(),
            entities: Vec::new(),
        }
    }

    #[test]
    fn a_hostile_rule_is_stopped_by_the_execution_budget_and_denies() {
        // Gated on the input so the compile-time probe — which runs with no
        // input — fails fast, and only a real request pays: the shape an
        // attacker who can author policy would pick.
        const HOSTILE: &str = r#"package hostile

import rego.v1

default allow := false

allow if {
    input.subject.id != ""
    some x in numbers.range(0, 20000)
    some y in numbers.range(0, 20000)
    x + y == -1
}
"#;
        let compiled = Rego
            .compile(&[stored("01a0-hostile", HOSTILE)], None)
            .expect("the module compiles");

        let started = std::time::Instant::now();
        let verdict = compiled.evaluate(&query("alice", "read", "open"));
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the worker came back: a hostile rule may not stall the decision path"
        );
        assert!(!verdict.permitted, "and the answer fails closed");
        assert!(
            verdict.error.is_some(),
            "as an evaluation fault that says why, not as a silent deny"
        );
    }

    #[test]
    fn a_module_that_allows_permits_and_is_cited() {
        let compiled = Rego
            .compile(&[stored("01a0-readers", READERS)], None)
            .expect("the module compiles");

        let verdict = compiled.evaluate(&query("alice", "read", "open"));
        assert!(verdict.permitted);
        assert_eq!(verdict.determining, vec!["01a0-readers".to_owned()]);
    }

    #[test]
    fn absent_means_no() {
        let compiled = Rego
            .compile(&[stored("01a0-readers", READERS)], None)
            .expect("the module compiles");

        // The action is not the one the module allows.
        assert!(
            !compiled
                .evaluate(&query("alice", "delete", "open"))
                .permitted
        );
        // Nor is the resource in the state it requires.
        assert!(
            !compiled
                .evaluate(&query("alice", "read", "closed"))
                .permitted
        );
    }

    #[test]
    fn deny_overrides_whatever_another_module_allows() {
        let compiled = Rego
            .compile(
                &[
                    stored("01a0-readers", READERS),
                    stored("01a0-guards", NEVER_BOB),
                ],
                None,
            )
            .expect("the modules compile");

        let verdict = compiled.evaluate(&query("bob", "read", "open"));
        assert!(!verdict.permitted);
        assert_eq!(verdict.determining, vec!["01a0-guards".to_owned()]);
        assert!(compiled.evaluate(&query("alice", "read", "open")).permitted);
    }

    #[test]
    fn a_module_that_answers_neither_rule_contributes_nothing() {
        let compiled = Rego
            .compile(
                &[stored(
                    "01a0-quiet",
                    "package quiet\n\nimport rego.v1\n\nsomething := 1\n",
                )],
                None,
            )
            .expect("the module compiles");

        let verdict = compiled.evaluate(&query("alice", "read", "open"));
        assert!(!verdict.permitted, "nothing allowed, so no");
        assert!(verdict.error.is_none(), "and that is not an error");
    }

    #[test]
    fn the_entity_graph_arrives_as_data() {
        let module = r#"package graph

import rego.v1

default allow := false

allow if {
    some entity in data.entities
    entity.id == input.subject.id
    entity.role == "reader"
}
"#;
        let compiled = Rego
            .compile(&[stored("01a0-graph", module)], None)
            .expect("the module compiles");

        let mut asked = query("alice", "read", "open");
        asked.entities = vec![json!({"id": "alice", "role": "reader"})];
        assert!(compiled.evaluate(&asked).permitted);

        let mut other = query("alice", "read", "open");
        other.entities = vec![json!({"id": "alice", "role": "auditor"})];
        assert!(!compiled.evaluate(&other).permitted);
    }

    #[test]
    fn a_schema_partition_is_refused_because_rego_has_no_schema() {
        let refused = Rego
            .compile(&[stored("01a0-readers", READERS)], Some(b"anything"))
            .map(|_| ())
            .expect_err("rego has no schema");

        assert!(refused.contains("no schema"), "{refused}");
    }

    #[test]
    fn a_rule_that_is_not_a_boolean_is_reported_not_guessed() {
        let module = "package odd\n\nimport rego.v1\n\nallow := \"yes\"\n";
        let compiled = Rego
            .compile(&[stored("01a0-odd", module)], None)
            .expect("the module compiles");

        let verdict = compiled.evaluate(&query("alice", "read", "open"));
        assert!(!verdict.permitted);
        assert!(
            verdict.error.expect("a reason").contains("boolean"),
            "the reason says what was wrong"
        );
    }
}
