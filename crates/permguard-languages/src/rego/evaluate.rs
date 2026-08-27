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
//! input.subject   {type, id, properties}
//! input.resource  {type, id, properties}
//! input.action    {name, properties}
//! input.context   {…}
//! input.partition {…}   this partition's own input, or {}
//! ```
//!
//! `input.partition` is the `permguard.rego.data.v1` document the request
//! addressed to **this partition by name** — never to "the Rego partitions",
//! because two of them hold different rules and reading each other's data is
//! exactly the confusion a name prevents.
//!
//! It rides on `input` and not on `data`, and that is the whole difference
//! between a document and a database. `data` is the partition's own compiled
//! world, identical for every request; `input` is what this request said.
//! Grafting request data into `data` meant a global store mutated per
//! evaluation — a shared surface a caller could write into, and one nothing
//! could validate, because a schema describes a request and not a store.
//!
//! # The schema a partition may declare
//!
//! A Rego partition with `schema: true` carries exactly one **JSON Schema**
//! (`application/vnd.permguard.schema.rego+json`), compiled once at load, and
//! `input.partition` is checked against it before any rule runs. Rego is
//! untyped by design and that is a virtue in a rule; it is not a virtue in the
//! data the rule reads, where a renamed field turns a guardrail into a rule
//! that quietly never fires.
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
        // Compiled once, here, and never again: a schema recompiled per request would be the
        // most expensive thing on the decision path and would say the same thing every time.
        let validator = schema.map(compile_schema).transpose()?;

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
            validator,
            footprint: footprint + schema.map_or(0, <[u8]>::len),
        }))
    }
}

/// A compiled Rego partition.
struct RegoEvaluator {
    engine: Engine,
    modules: Vec<Module>,
    /// The partition's compiled JSON Schema, when it declares one.
    validator: Option<jsonschema::Validator>,
    footprint: usize,
}

impl Evaluator for RegoEvaluator {
    fn evaluate(&self, query: &Query) -> Verdict {
        let input = match value_of(&input_document(query)) {
            Ok(input) => input,
            Err(error) => return Verdict::refused(error),
        };
        // One prepared engine, cloned per request: the modules are already parsed, and an
        // evaluation must never mutate what the next one reads. Nothing is added to `data` here —
        // the request rides on `input`, where a schema can describe it and where one request
        // cannot leave anything behind for the next.
        let mut engine = self.engine.clone();
        engine.set_input(input);

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

    /// `input.partition` against this partition's own JSON Schema, before any rule runs.
    ///
    /// Fail-closed: a document the schema refuses never reaches a rule, and never becomes a
    /// silent `undefined` that reads as "the guardrail did not fire".
    fn check_input(&self, input: &crate::input::PartitionData) -> Result<(), String> {
        let Some(validator) = &self.validator else {
            return Ok(());
        };
        let empty = serde_json::Map::new();
        let document = Value::Object(input.rego_data().cloned().unwrap_or(empty));

        validator.validate(&document).map_err(|error| {
            format!(
                "rego: the document does not satisfy this partition's schema: {error} (at {})",
                error.instance_path()
            )
        })
    }

    fn footprint(&self) -> usize {
        self.footprint
    }

    fn policies(&self) -> Vec<String> {
        self.modules.iter().map(|m| m.id.clone()).collect()
    }
}

/// Compiles a partition's JSON Schema, once.
///
/// Draft 2020-12, and **local**: `$ref` may only reach inside the document. There is no retriever
/// configured, so a schema naming a remote reference fails to compile rather than reaching for the
/// network — a policy load that made an outbound request would be a policy load an operator cannot
/// reason about, and one an attacker could aim.
pub(super) fn compile_schema(bytes: &[u8]) -> Result<jsonschema::Validator, String> {
    let text =
        std::str::from_utf8(bytes).map_err(|_| "rego: the schema is not valid UTF-8".to_owned())?;
    let document: Value = serde_json::from_str(text)
        .map_err(|error| format!("rego: the schema is not JSON: {error}"))?;

    jsonschema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .build(&document)
        .map_err(|error| format!("rego: the schema is not a usable JSON Schema: {error}"))
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
        // Always present, even when nothing was addressed to this partition: a rule written
        // against `input.partition.frozen[_]` should read an empty document, not trip over an
        // undefined path and answer nothing at all.
        "partition": Value::Object(query.input.rego_data().cloned().unwrap_or_default()),
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
            input: crate::input::PartitionData::default(),
        }
    }

    fn document(value: serde_json::Value) -> crate::input::PartitionData {
        crate::input::PartitionData::RegoData(std::sync::Arc::new(
            value.as_object().cloned().unwrap_or_default(),
        ))
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
    some entity in input.partition.entities
    entity.id == input.subject.id
    entity.role == "reader"
}
"#;
        let compiled = Rego
            .compile(&[stored("01a0-graph", module)], None)
            .expect("the module compiles");

        let mut asked = query("alice", "read", "open");
        asked.input = document(json!({"entities": [{"id": "alice", "role": "reader"}]}));
        assert!(compiled.evaluate(&asked).permitted);

        let mut other = query("alice", "read", "open");
        other.input = document(json!({"entities": [{"id": "alice", "role": "auditor"}]}));
        assert!(!compiled.evaluate(&other).permitted);
    }

    #[test]
    fn a_schema_that_is_not_json_schema_refuses_the_load() {
        let refused = Rego
            .compile(&[stored("01a0-readers", READERS)], Some(b"anything"))
            .map(|_| ())
            .expect_err("that is not a schema");

        assert!(refused.contains("not JSON"), "{refused}");
    }

    #[test]
    fn a_document_the_schema_refuses_never_reaches_a_rule() {
        const SCHEMA: &[u8] = br#"{
            "type": "object",
            "required": ["frozen_services"],
            "properties": {"frozen_services": {"type": "array", "items": {"type": "string"}}}
        }"#;
        let compiled = Rego
            .compile(&[stored("01a0-readers", READERS)], Some(SCHEMA))
            .expect("the module and the schema compile");

        // What the schema describes, accepted.
        assert!(
            compiled
                .check_input(&document(json!({"frozen_services": ["payments-api"]})))
                .is_ok()
        );
        // A field renamed: the shape a rule would read as `undefined`, which is indistinguishable
        // from a guardrail deciding not to fire. Refused instead.
        let refused = compiled
            .check_input(&document(json!({"frozen": ["payments-api"]})))
            .expect_err("a required property is missing");
        assert!(refused.contains("schema"), "{refused}");
        // And the wrong type inside it.
        assert!(
            compiled
                .check_input(&document(json!({"frozen_services": "payments-api"})))
                .is_err()
        );
    }

    #[test]
    fn a_partition_that_declares_no_schema_checks_nothing_and_reads_the_document() {
        let compiled = Rego
            .compile(&[stored("01a0-readers", READERS)], None)
            .expect("the module compiles");

        assert!(
            compiled
                .check_input(&document(json!({"anything": 1})))
                .is_ok()
        );
    }

    #[test]
    fn the_document_arrives_at_input_partition_and_an_absent_one_is_empty() {
        const MODULE: &str = r#"package frozen

import rego.v1

default deny := false

deny if input.resource.id in input.partition.frozen_services
"#;
        let compiled = Rego
            .compile(&[stored("01a0-frozen", MODULE)], None)
            .expect("the module compiles");

        let mut asked = query("alice", "read", "open");
        asked.resource.id = "payments-api".to_owned();
        asked.input = document(json!({"frozen_services": ["payments-api"]}));
        assert!(!compiled.evaluate(&asked).permitted, "the guardrail fires");

        // Nothing addressed to this partition: an empty document, and a rule that reads a path
        // through it answers no rather than erroring.
        let mut nothing = query("alice", "read", "open");
        nothing.resource.id = "payments-api".to_owned();
        let verdict = compiled.evaluate(&nothing);
        assert!(verdict.error.is_none(), "{:?}", verdict.error);
        assert!(verdict.determining.is_empty(), "nothing denied it");
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
