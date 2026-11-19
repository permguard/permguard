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
//! partition is given, so a `permguard.api.pdp.native.v1` caller cannot tell which
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

use permguard_language_core::evaluate::{Query, StoredPolicy, Verdict};
use permguard_language_core::evaluating::{Evaluating, Evaluator};

use super::Rego;

/// The most wall-clock one partition's evaluation may spend, every module and rule together.
///
/// Rego is not structurally terminating the way Cedar is: comprehensions and
/// `walk` over adversarial data can be made arbitrarily expensive, and the
/// transport's request timeout is not a preemption boundary for a synchronous
/// evaluation — it ends the response, not the work. This is the boundary. It
/// is enormous next to a real authorization rule, which evaluates in
/// microseconds, and small next to a stalled worker.
///
/// One budget, decreasing (REGO-02, LANG-04): each rule is started with what the partition has
/// left, and a partition with no time left starts no rule, so many expensive rules cannot each
/// spend a full budget. Finishing late is `E`, as every evaluation fault is.
const PARTITION_BUDGET: Duration = Duration::from_secs(1);

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
        artifacts: &permguard_language_core::artifact::Artifacts,
    ) -> Result<Box<dyn Evaluator>, String> {
        // Compiled once, here, and never again: a schema recompiled per request would be the
        // most expensive thing on the decision path and would say the same thing every time.
        let schema = artifacts.bytes(crate::SCHEMA_ARTIFACT);
        let input_schema = artifacts.bytes(crate::INPUT_SCHEMA_ARTIFACT);
        // One schema, one truth: v2 types `input.partition` too, so a partition carrying both
        // would answer to two schemas that may disagree.
        if schema.is_some() && input_schema.is_some() {
            return Err(format!(
                "rego: the partition carries both `{}` and `{}`; the whole-input schema covers \
                 the partition document too, so carry one",
                crate::SCHEMA_ARTIFACT,
                crate::INPUT_SCHEMA_ARTIFACT
            ));
        }
        let validator = schema.map(crate::compile_schema).transpose()?;
        let input_validator = input_schema.map(crate::compile_schema).transpose()?;

        let mut engine = prepared_engine();
        let mut modules = Vec::new();
        let mut policy_bytes = 0;
        // Which policy claimed each package. A package is Rego's unit of aggregation, and this is
        // what makes "one package, one citable policy" checkable rather than assumed.
        let mut claimed: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        let mut parsed_modules: Vec<(String, super::parsed::Parsed)> = Vec::new();
        for stored in policies {
            let text = std::str::from_utf8(&stored.source)
                .map_err(|_| format!("rego: module {} is not valid UTF-8", stored.id))?;
            // The parsed tree says which rules the module declares and which built-ins it calls:
            // declarations are inspected, never discovered by running a rule (REGO-05), and a
            // built-in outside the allow-list refuses the load (REGO-01).
            let module = super::parsed::parse(text)
                .map_err(|error| format!("rego: module {} does not parse: {error}", stored.id))?;
            super::parsed::check_builtins(&module)
                .map_err(|error| format!("rego: module {}: {error}", stored.id))?;
            super::parsed::check_decision_rules(&module)
                .map_err(|error| format!("rego: module {}: {error}", stored.id))?;
            // `parse` has bounded the module's nesting and parse work; the parse itself still
            // runs on a stack segment sized for them.
            let package = permguard_language_core::headroom::ample(|| {
                engine.add_policy(format!("{}.rego", stored.id), text.to_owned())
            })
            .map_err(|error| format!("rego: module {} does not parse: {error}", stored.id))?;
            if let Some(first) = claimed.get(&package) {
                return Err(crate::shared_package(&package, first, &stored.id));
            }
            claimed.insert(package.clone(), stored.id.clone());
            parsed_modules.push((stored.id.clone(), module.clone()));
            modules.push(Module {
                id: stored.id.clone(),
                allow: module
                    .rules
                    .contains("allow")
                    .then(|| format!("{package}.allow")),
                deny: module
                    .rules
                    .contains("deny")
                    .then(|| format!("{package}.deny")),
            });
            policy_bytes += stored.source.len();
        }

        // Refused at load as at push: a ledger pushed before the check never reaches the evaluator
        // with a chain it cannot take (BUG-0018, BUG-0236).
        let held: Vec<(&str, &super::parsed::Parsed)> = parsed_modules
            .iter()
            .map(|(id, module)| (id.as_str(), module))
            .collect();
        super::parsed::check_set(&held)?;

        Ok(Box::new(RegoEvaluator {
            engine,
            modules,
            validator,
            input_validator,
            footprint: footprint(policy_bytes, schema.or(input_schema).map_or(0, <[u8]>::len)),
        }))
    }
}

/// A compiled Rego partition.
struct RegoEvaluator {
    engine: Engine,
    modules: Vec<Module>,
    /// The partition's compiled JSON Schema, when it declares one.
    validator: Option<jsonschema::Validator>,
    /// The whole-input schema, v2, when the partition carries one instead.
    input_validator: Option<jsonschema::Validator>,
    footprint: usize,
}

/// An engine as every partition of this adapter starts: the per-rule budget, and `print` gathered
/// rather than written.
///
/// Regorus writes a policy's `print(...)` to the process's standard error unless told to gather it.
/// A policy that printed `input.subject.id` would put tenant data into the container's logs, past
/// the log field classification — so it is gathered into the per-request clone of the engine, and
/// dropped with it.
fn prepared_engine() -> Engine {
    let mut engine = Engine::new();
    engine.set_execution_timer_config(ExecutionTimerConfig {
        limit: PARTITION_BUDGET,
        check_interval: NonZeroU32::new(BUDGET_CHECK_INTERVAL).unwrap_or(NonZeroU32::MIN),
    });
    engine.set_gather_prints(true);
    engine
}

/// What a compiled Rego partition keeps, conservatively (LANG-07).
///
/// Regorus's prepared engine — parsed modules, the analysed rule graph — and a compiled JSON
/// Schema, regular expressions included, weigh far more than their text: measured, about 80 times
/// the module bytes and over 100 times a pattern-heavy schema's, plus a fixed overhead. The
/// estimate is roughly twice that; `tests/footprint.rs` proves it is never below what the engine
/// retains. An estimate, not a hard bound: that is a supervised worker's `RLIMIT_AS` (LANG-04).
fn footprint(policy_bytes: usize, schema_bytes: usize) -> usize {
    const BASE: usize = 64 * 1024;
    const PER_POLICY_BYTE: usize = 160;
    const PER_SCHEMA_BYTE: usize = 256;

    BASE.saturating_add(policy_bytes.saturating_mul(PER_POLICY_BYTE))
        .saturating_add(schema_bytes.saturating_mul(PER_SCHEMA_BYTE))
}

impl Evaluator for RegoEvaluator {
    fn evaluate(&self, query: &Query) -> Verdict {
        // The stack an engine needs is its own to guarantee: see permguard_language_core::headroom.
        permguard_language_core::headroom::with(|| {
            // The partition's budget starts here: building and checking the input spend from it too.
            let started = std::time::Instant::now();
            let document = input_document(query);
            // The whole input against v2 before any rule: a misspelled common field is refused, not
            // read as `undefined` by a rule that then says "no".
            if let Some(validator) = &self.input_validator
                && let Err(error) = validator.validate(&document)
            {
                return Verdict::input_rejected(format!(
                    "rego: the input does not satisfy this partition's whole-input schema: {error} \
                     (at {})",
                    error.instance_path()
                ));
            }
            let input = match value_of(&document) {
                Ok(input) => input,
                Err(error) => return Verdict::input_rejected(error),
            };
            // One prepared engine, cloned per request: the modules are already parsed, and an
            // evaluation must never mutate what the next one reads. Nothing is added to `data` here —
            // the request rides on `input`, where a schema can describe it and where one request
            // cannot leave anything behind for the next.
            let mut engine = self.engine.clone();

            // The partition's one budget: the request's own deadline when it is nearer, the partition
            // budget otherwise. It decreases as rules run and is handed to the interpreter before
            // each one, so no rule can outlive what the partition has left.
            let budget = query
                .remaining()
                .map_or(PARTITION_BUDGET, |left| left.min(PARTITION_BUDGET));
            engine.set_input(input);

            // Every module is evaluated, both rules, in order: what a rule answers is independent of
            // the others, and a failure anywhere is reported whatever else held. An interpreter
            // error, a conflict or a rule that is not a boolean is a failure; undefined and `false`
            // are an answer: no. Only the deadline ends the asking early — past it, nothing a rule
            // could still answer is wanted, and the failure that stopped is the lateness.
            let mut permitted = Vec::new();
            let mut denied = Vec::new();
            let mut failure: Option<Verdict> = None;
            'modules: for module in &self.modules {
                for (rule, answers) in [
                    (module.deny.as_deref(), &mut denied),
                    (module.allow.as_deref(), &mut permitted),
                ] {
                    let Some(rule) = rule else { continue };
                    let left = budget.saturating_sub(started.elapsed());
                    if left.is_zero() {
                        failure.get_or_insert(Verdict::deadline_exceeded(
                            "the partition spent its budget before every rule was asked",
                        ));
                        break 'modules;
                    }
                    engine.set_execution_timer_config(ExecutionTimerConfig {
                        limit: left,
                        check_interval: NonZeroU32::new(BUDGET_CHECK_INTERVAL)
                            .unwrap_or(NonZeroU32::MIN),
                    });
                    match asked(&mut engine, rule) {
                        Ok(true) => answers.push(module.id.clone()),
                        Ok(false) => {}
                        Err(error) if query.expired() || started.elapsed() >= budget => {
                            failure.get_or_insert(Verdict::deadline_exceeded(error));
                            break 'modules;
                        }
                        Err(error) => {
                            failure.get_or_insert(Verdict::engine_failed(error));
                        }
                    }
                }
            }

            // Deny overrides; absent means no rule matched: an abstain, which the profile resolves
            // to a deny by default unless another partition permits.
            let answered = if !denied.is_empty() {
                Verdict::deny(denied)
            } else if !permitted.is_empty() {
                Verdict::permit(permitted)
            } else {
                Verdict::abstain()
            };
            // A deny a rule determined stands beside a failure, the failure kept; a permit or
            // silence beside one is the failure: `E`.
            match failure {
                Some(failure) => answered.despite(failure),
                None => answered,
            }
        })
    }

    /// `input.partition` against this partition's own JSON Schema, before any rule runs.
    ///
    /// Fail-closed: a document the schema refuses never reaches a rule, and never becomes a
    /// silent `undefined` that reads as "the guardrail did not fire".
    fn check_input(
        &self,
        input: &permguard_language_core::input::PartitionData,
    ) -> Result<(), String> {
        // The stack an engine needs is its own to guarantee: see permguard_language_core::headroom.
        permguard_language_core::headroom::with(|| {
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
        })
    }

    fn footprint(&self) -> usize {
        self.footprint
    }

    fn policies(&self) -> Vec<String> {
        self.modules.iter().map(|m| m.id.clone()).collect()
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

    /// The artifacts of a partition that carries exactly one blob, of the type `name` this
    /// language registers.
    fn just(name: &str, data: &[u8]) -> Option<permguard_language_core::artifact::Artifacts> {
        use permguard_language_core::role::Language as _;

        crate::Rego
            .artifacts()
            .iter()
            .copied()
            .find(|held| held.name() == name)
            .map(|artifact| permguard_language_core::artifact::Artifacts::just_of(artifact, data))
    }

    use super::*;
    use permguard_language_core::evaluate::{Action, Entity};
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

    /// A partition carrying just this Rego schema.
    fn artifacts(schema: &[u8]) -> permguard_language_core::artifact::Artifacts {
        just(crate::SCHEMA_ARTIFACT, schema).expect("the Rego schema artifact is registered")
    }

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
            deadline: None,
            input: permguard_language_core::input::PartitionData::default(),
        }
    }

    fn document(value: serde_json::Value) -> permguard_language_core::input::PartitionData {
        permguard_language_core::input::PartitionData::RegoData(std::sync::Arc::new(
            value.as_object().cloned().unwrap_or_default(),
        ))
    }

    /// A module whose `allow` reads a chain of `links` rules, each reading the next.
    fn chain(links: usize) -> String {
        let mut source =
            String::from("package chain\n\nimport rego.v1\n\ndefault allow := false\n\n");
        source.push_str("allow if r0\n\n");
        for at in 0..links {
            if at + 1 == links {
                source.push_str(&format!("r{at} if input.subject.id == \"alice\"\n"));
            } else {
                source.push_str(&format!("r{at} if r{}\n", at + 1));
            }
        }
        source
    }

    /// BUG-0236: a chain of rules longer than the bound is refused at validation, at the set check
    /// and at compile, naming the bound, never evaluated; one within it is evaluated, on a thread
    /// with a small stack too, and the process keeps running.
    #[test]
    fn a_rule_chain_past_the_bound_is_refused_and_one_within_it_is_decided() {
        use permguard_language_core::role::Language as _;

        let deep = chain(1000);
        let refused = Rego
            .validate_policy(deep.as_bytes())
            .expect_err("past the bound");
        assert!(refused.contains("more than the 64"), "{refused}");
        assert!(
            Rego.validate_set(&[("deep", deep.as_bytes())], None)
                .is_err()
        );
        let refused = Rego
            .compile(
                &[stored("01a0-deep", &deep)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .err()
            .expect("refused at load too");
        assert!(refused.contains("chain"), "{refused}");

        let within = chain(super::super::parsed::MAX_RULE_DEPTH - 2);
        Rego.validate_policy(within.as_bytes())
            .expect("within the bound");
        let verdict = std::thread::Builder::new()
            .stack_size(256 * 1024)
            .spawn(move || {
                let compiled = Rego
                    .compile(
                        &[stored("01a0-within", &within)],
                        &permguard_language_core::artifact::Artifacts::default(),
                    )
                    .expect("compiles");
                compiled
                    .evaluate(&query("alice", "read", "open"))
                    .permitted()
            })
            .expect("a thread")
            .join()
            .expect("no overflow");
        assert!(verdict, "decided through the whole chain");
    }

    /// BUG-0016: a set-valued or function `deny` or `allow` is refused at validation and at load,
    /// naming the rule; a boolean one is accepted and decides as before.
    #[test]
    fn a_set_valued_decision_rule_is_refused_at_validation_and_load() {
        use permguard_language_core::role::Language as _;

        for module in [
            "package guard\n\nimport rego.v1\n\ndeny contains msg if {\n    input.resource.properties.status == \"secret\"\n    msg := \"secret\"\n}\n",
            "package guard\n\nimport rego.v1\n\nallow contains \"x\" if true\n",
            "package guard\n\nimport rego.v1\n\ndeny(x) if x\n",
        ] {
            let refused = Rego.validate_policy(module.as_bytes()).expect_err(module);
            assert!(
                refused.contains("data.guard.") && refused.contains("boolean rules"),
                "{module}: {refused}"
            );
            assert!(
                Rego.compile(
                    &[stored("01a0-guard", module)],
                    &permguard_language_core::artifact::Artifacts::default(),
                )
                .is_err(),
                "{module}: refused at load too"
            );
        }
        let boolean = "package guard\n\nimport rego.v1\n\ndefault deny := false\n\ndeny if input.resource.properties.status == \"secret\"\n";
        Rego.validate_policy(boolean.as_bytes())
            .expect("a boolean deny");
        let compiled = Rego
            .compile(
                &[
                    stored("01a0-readers", READERS),
                    stored("01a0-guard", boolean),
                ],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("compiles");
        assert!(
            compiled
                .evaluate(&query("alice", "read", "open"))
                .error()
                .is_none()
        );
    }

    /// BUG-0018: a module that writes rules into another module's package, by a nested ref head or
    /// a package below one of its rules, is refused naming both; modules of sibling packages are
    /// not.
    #[test]
    fn a_module_writing_into_another_package_is_refused() {
        use permguard_language_core::role::Language as _;

        let guard = "package app.guard\n\nimport rego.v1\n\ndefault allow := false\n";
        for writer in [
            "package app\n\nimport rego.v1\n\nguard.allow if true\n",
            "package app\n\nimport rego.v1\n\nguard.deny if true\n",
            "package app\n\nimport rego.v1\n\nguard[\"allow\"] := true\n",
        ] {
            let refused = Rego
                .validate_set(
                    &[
                        ("01a0-guard", guard.as_bytes()),
                        ("01a0-app", writer.as_bytes()),
                    ],
                    None,
                )
                .expect_err(writer);
            assert!(
                refused.contains("01a0-app") && refused.contains("01a0-guard"),
                "{writer}: {refused}"
            );
            assert!(
                Rego.compile(
                    &[stored("01a0-guard", guard), stored("01a0-app", writer)],
                    &permguard_language_core::artifact::Artifacts::default(),
                )
                .is_err(),
                "{writer}: refused at load too"
            );
        }
        let sibling_a = "package app.a\n\nimport rego.v1\n\ndefault allow := false\n";
        let sibling_b = "package app.b\n\nimport rego.v1\n\ndefault allow := false\n";
        Rego.validate_set(
            &[
                ("01a0-a", sibling_a.as_bytes()),
                ("01a0-b", sibling_b.as_bytes()),
            ],
            None,
        )
        .expect("siblings write nothing of each other");
    }

    #[test]
    fn a_hostile_rule_is_stopped_by_the_decisions_deadline_long_before_the_rule_budget() {
        // `PARTITION_BUDGET` bounds a partition at a second; a decision given 150ms must not spend a
        // second on it. This is the propagation working: the interpreter is handed whichever
        // budget is smaller, so a request nearly out of time cannot start a rule that would
        // outlive it — and a partition with many modules cannot spend the per-rule budget once
        // per module and still call itself bounded.
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
            .compile(
                &[stored("01a0-hostile", HOSTILE)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the module compiles");

        let mut asked = query("alice", "read", "open");
        asked.deadline = Some(std::time::Instant::now() + Duration::from_millis(150));

        let started = std::time::Instant::now();
        let verdict = compiled.evaluate(&asked);
        let spent = started.elapsed();

        assert!(!verdict.permitted(), "it fails closed");
        assert!(verdict.error().is_some(), "and says why");
        assert!(
            spent < PARTITION_BUDGET,
            "the decision's deadline bounded it, not the per-rule budget: {spent:?}"
        );
    }

    #[test]
    fn a_hostile_rule_is_stopped_by_the_execution_budget_and_is_an_evaluation_failure() {
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
            .compile(
                &[stored("01a0-hostile", HOSTILE)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the module compiles");

        let started = std::time::Instant::now();
        let verdict = compiled.evaluate(&query("alice", "read", "open"));
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the worker came back: a hostile rule may not stall the decision path"
        );
        assert!(!verdict.permitted(), "and the answer fails closed");
        assert!(
            verdict.error().is_some(),
            "as an evaluation fault that says why, not as a silent deny"
        );
    }

    /// REGO-02: many expensive rules share the partition's one budget. Five modules, each able to
    /// spend far more than the budget, stop together near one budget — never five — as `E`.
    #[test]
    fn many_expensive_rules_share_one_decreasing_budget() {
        let hostile = |package: &str| {
            format!(
                "package {package}\n\nimport rego.v1\n\nallow if {{\n    input.subject.id != \"\"\n    \
                 some x in numbers.range(0, 20000)\n    some y in numbers.range(0, 20000)\n    \
                 x + y == -1\n}}\n"
            )
        };
        let policies: Vec<StoredPolicy> = (0..5)
            .map(|i| {
                stored(
                    &format!("01a0-hostile-{i}"),
                    &hostile(&format!("hostile{i}")),
                )
            })
            .collect();
        let compiled = Rego
            .compile(
                &policies,
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the modules compile");

        let started = std::time::Instant::now();
        let verdict = compiled.evaluate(&query("alice", "read", "open"));
        let spent = started.elapsed();
        assert!(
            spent < PARTITION_BUDGET * 2,
            "five rules spent {spent:?}: the budget is the partition's, not each rule's"
        );
        let error = verdict.error().expect("finishing late is `E`");
        assert_eq!(
            error.code,
            permguard_core::codes::pdp_native::EVALUATION_DEADLINE_EXCEEDED
        );
    }

    /// REGO-06: the whole-input schema refuses an input it does not admit before any rule runs,
    /// and admits one it describes; a partition carrying v1 and v2 is refused at load; a remote
    /// `$ref` never compiles.
    #[test]
    fn the_whole_input_schema_types_every_member_and_excludes_v1() {
        let v2 = br#"{
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "required": ["subject", "context"],
            "properties": {
                "subject": { "type": "object", "required": ["id"] },
                "context": { "type": "object", "required": ["tenant"],
                             "properties": { "tenant": { "type": "string" } } }
            }
        }"#;
        let held = just(crate::INPUT_SCHEMA_ARTIFACT, v2).expect("the v2 artifact is registered");
        let compiled = Rego
            .compile(
                &[stored(
                    "01a0-allow",
                    "package typed\nimport rego.v1\nallow if { input.context.tenant == \"acme\" }\n",
                )],
                &held,
            )
            .expect("compiles with v2");

        let mut typed = query("alice", "read", "open");
        typed
            .context
            .insert("tenant".to_owned(), Value::from("acme"));
        assert!(compiled.evaluate(&typed).permitted());

        let mut misspelled = query("alice", "read", "open");
        misspelled
            .context
            .insert("tennant".to_owned(), Value::from("acme"));
        let error = compiled
            .evaluate(&misspelled)
            .error()
            .expect("a refusal, not an `undefined` read as no");
        assert_eq!(
            error.code,
            permguard_core::codes::pdp_native::EVALUATION_INPUT_REJECTED
        );
        assert!(
            error.message.contains("whole-input schema"),
            "{}",
            error.message
        );

        let mut both = held.clone();
        both.insert(
            &crate::SchemaArtifact,
            permguard_language_core::artifact::ArtifactBlob {
                name: "partition.regoschema".to_owned(),
                media_type: crate::SCHEMA_MEDIA_TYPE.to_owned(),
                data: br#"{"type":"object"}"#.to_vec(),
            },
        );
        let refused = Rego
            .compile(
                &[stored("01a0-allow", "package typed\nimport rego.v1\n")],
                &both,
            )
            .err()
            .expect("v1 and v2 together are refused");
        assert!(refused.contains("carry one"), "{refused}");

        let remote = br#"{"$ref": "https://example.invalid/schema.json"}"#;
        assert!(
            permguard_language_core::artifact::ArtifactType::validate(
                &crate::InputSchemaArtifact,
                remote
            )
            .is_err(),
            "a remote reference is refused at compile, without I/O"
        );
    }

    /// REGO-06 floors: from `production` a Rego partition carries v1 or v2, under `regulated`
    /// the whole-input v2.
    #[test]
    fn the_assurance_profile_raises_the_schema_floor() {
        use permguard_core::assurance::AssuranceProfile::{Development, Production, Regulated};
        let floor = |profile, held: &permguard_language_core::artifact::Artifacts| {
            permguard_language_core::registry::check_schema_floor_of(
                &permguard_language_core::guard::Guarded(crate::Rego),
                profile,
                held,
            )
        };
        let none = permguard_language_core::artifact::Artifacts::default();
        let v1 = artifacts(br#"{"type":"object"}"#);
        let v2 = just(crate::INPUT_SCHEMA_ARTIFACT, br#"{"type":"object"}"#).expect("registered");
        assert!(floor(Development, &none).is_ok());
        assert!(floor(Production, &none).is_err());
        assert!(floor(Production, &v1).is_ok() && floor(Production, &v2).is_ok());
        assert!(
            floor(Regulated, &v1).is_err(),
            "v1 types only the partition document"
        );
        assert!(floor(Regulated, &v2).is_ok());
    }

    #[test]
    fn a_module_that_allows_permits_and_is_cited() {
        let compiled = Rego
            .compile(
                &[stored("01a0-readers", READERS)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the module compiles");

        let verdict = compiled.evaluate(&query("alice", "read", "open"));
        assert!(verdict.permitted());
        assert_eq!(verdict.determining(), vec!["01a0-readers".to_owned()]);
    }

    #[test]
    fn absent_means_no() {
        let compiled = Rego
            .compile(
                &[stored("01a0-readers", READERS)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the module compiles");

        // The action is not the one the module allows.
        assert!(
            !compiled
                .evaluate(&query("alice", "delete", "open"))
                .permitted()
        );
        // Nor is the resource in the state it requires.
        assert!(
            !compiled
                .evaluate(&query("alice", "read", "closed"))
                .permitted()
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
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the modules compile");

        let verdict = compiled.evaluate(&query("bob", "read", "open"));
        assert!(!verdict.permitted());
        assert_eq!(verdict.determining(), vec!["01a0-guards".to_owned()]);
        assert!(
            compiled
                .evaluate(&query("alice", "read", "open"))
                .permitted()
        );
    }

    #[test]
    fn a_module_that_answers_neither_rule_contributes_nothing() {
        let compiled = Rego
            .compile(
                &[stored(
                    "01a0-quiet",
                    "package quiet\n\nimport rego.v1\n\nsomething := 1\n",
                )],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the module compiles");

        let verdict = compiled.evaluate(&query("alice", "read", "open"));
        assert_eq!(
            verdict,
            Verdict::Abstain,
            "nothing allowed and nothing denied: the partition abstains, which is not an error"
        );
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
            .compile(
                &[stored("01a0-graph", module)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the module compiles");

        let mut asked = query("alice", "read", "open");
        asked.input = document(json!({"entities": [{"id": "alice", "role": "reader"}]}));
        assert!(compiled.evaluate(&asked).permitted());

        let mut other = query("alice", "read", "open");
        other.input = document(json!({"entities": [{"id": "alice", "role": "auditor"}]}));
        assert!(!compiled.evaluate(&other).permitted());
    }

    #[test]
    fn a_schema_that_is_not_json_schema_refuses_the_load() {
        let refused = Rego
            .compile(&[stored("01a0-readers", READERS)], &artifacts(b"anything"))
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
            .compile(&[stored("01a0-readers", READERS)], &artifacts(SCHEMA))
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
            .compile(
                &[stored("01a0-readers", READERS)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
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
            .compile(
                &[stored("01a0-frozen", MODULE)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the module compiles");

        let mut asked = query("alice", "read", "open");
        asked.resource.id = "payments-api".to_owned();
        asked.input = document(json!({"frozen_services": ["payments-api"]}));
        assert!(
            !compiled.evaluate(&asked).permitted(),
            "the guardrail fires"
        );

        // Nothing addressed to this partition: an empty document, and a rule that reads a path
        // through it answers no rather than erroring.
        let mut nothing = query("alice", "read", "open");
        nothing.resource.id = "payments-api".to_owned();
        let verdict = compiled.evaluate(&nothing);
        assert_eq!(
            verdict,
            Verdict::Abstain,
            "nothing denied it, and nothing failed"
        );
    }

    #[test]
    fn a_rule_that_is_not_a_boolean_is_reported_not_guessed() {
        let module = "package odd\n\nimport rego.v1\n\nallow := \"yes\"\n";
        let compiled = Rego
            .compile(
                &[stored("01a0-odd", module)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the module compiles");

        let verdict = compiled.evaluate(&query("alice", "read", "open"));
        let error = verdict
            .error()
            .expect("a non-boolean rule is `E`, not a deny");
        assert_eq!(
            error.code,
            permguard_core::codes::pdp_native::EVALUATION_FAILED,
            "the engine reported the failure"
        );
        assert!(
            error.message.contains("boolean"),
            "the reason says what was wrong"
        );
    }

    /// A deny rule that is true decides the partition beside another rule's failure: `D`, citing
    /// it, with the failure kept. The same failure beside a permit, with no deny rule true, is
    /// `E`: a permit released after a rule failed is not defensible.
    #[test]
    fn a_true_deny_rule_beside_a_failing_rule_is_a_deny_that_keeps_the_failure() {
        let odd_deny = "package odd\n\nimport rego.v1\n\ndeny := \"yes\"\n";
        let compiled = Rego
            .compile(
                &[
                    stored("01a0-readers", READERS),
                    stored("01a0-guards", NEVER_BOB),
                    stored("01a0-odd", odd_deny),
                ],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the modules compile");

        let verdict = compiled.evaluate(&query("bob", "read", "open"));
        assert_eq!(
            verdict.determining(),
            vec!["01a0-guards".to_owned()],
            "{verdict:?}"
        );
        assert!(verdict.error().is_none(), "a `D`, not an `E`: {verdict:?}");
        let failure = verdict
            .failure()
            .expect("the failure is kept beside the deny");
        assert_eq!(
            failure.code,
            permguard_core::codes::pdp_native::EVALUATION_FAILED
        );
        assert!(failure.message.contains("boolean"), "{failure}");

        // An `allow` that fails beside a true `deny` is asked and kept too: every module is
        // evaluated, so the failure is reported whatever else held.
        let odd_allow = "package oddallow\n\nimport rego.v1\n\nallow := \"yes\"\n";
        let allow_fails = Rego
            .compile(
                &[
                    stored("01a0-guards", NEVER_BOB),
                    stored("01a0-oddallow", odd_allow),
                ],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .expect("the modules compile");
        let verdict = allow_fails.evaluate(&query("bob", "read", "open"));
        assert_eq!(
            verdict.determining(),
            vec!["01a0-guards".to_owned()],
            "{verdict:?}"
        );
        assert!(
            verdict
                .failure()
                .is_some_and(|failure| failure.message.contains("boolean")),
            "{verdict:?}"
        );

        let beside_a_permit = compiled.evaluate(&query("alice", "read", "open"));
        assert!(!beside_a_permit.permitted(), "{beside_a_permit:?}");
        assert_eq!(
            beside_a_permit.error().map(|error| error.code),
            Some(permguard_core::codes::pdp_native::EVALUATION_FAILED),
            "no deny rule is true: the failure is the answer"
        );
    }

    /// A policy's `print` never reaches the process's standard error: the adapter's engines gather
    /// it, and the per-request clone that gathered it is dropped.
    #[test]
    fn a_policys_print_is_gathered_and_never_written() {
        let mut engine = super::prepared_engine();
        engine
            .add_policy(
                "printing.rego".to_owned(),
                "package printing\n\nimport rego.v1\n\nallow if {\n    print(\"subject\", input.subject.id)\n}\n"
                    .to_owned(),
            )
            .expect("the module parses");
        engine.set_input(
            regorus::Value::from_json_str(r#"{"subject": {"id": "alice"}}"#).expect("input"),
        );

        let answer = engine
            .eval_rule("data.printing.allow".to_owned())
            .expect("it evaluates");
        assert_eq!(answer, regorus::Value::Bool(true));
        let printed = engine.take_prints().expect("the prints are held");
        assert_eq!(printed.len(), 1, "gathered, not written: {printed:?}");
        assert!(printed[0].contains("alice"));
    }

    /// Two files in one package are one rule set, and a decision must not claim otherwise.
    ///
    /// `package.allow` is the union of every `allow` rule in the package — that is Rego, not a
    /// detail of this engine. Evaluating it once per file and attributing the result to each file
    /// names policies that did not decide anything, which is a false audit trail: the verdict is
    /// right and the explanation is wrong, and the explanation is what an incident response reads.
    #[test]
    fn two_modules_in_one_package_cannot_be_cited_separately() {
        const NO: &str = "package shared\n\nimport rego.v1\n\ndefault allow := false\n";
        const YES: &str =
            "package shared\n\nimport rego.v1\n\nallow if { input.action.name == \"read\" }\n";

        let refused = Rego
            .compile(
                &[stored("01a0-no", NO), stored("01a0-yes", YES)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .err()
            .expect("a package this engine cannot attribute is refused, not served");

        assert!(refused.contains("shared"), "{refused}");
        assert!(
            refused.contains("01a0-no") && refused.contains("01a0-yes"),
            "{refused}"
        );
    }

    /// And the same refusal at authoring, where it costs least.
    #[test]
    fn the_set_check_refuses_one_package_across_two_files() {
        const NO: &str = "package shared\n\nimport rego.v1\n\ndefault allow := false\n";
        const YES: &str = "package shared\n\nimport rego.v1\n\nallow if { true }\n";

        let refused = permguard_language_core::role::Language::validate_set(
            &Rego,
            &[("a.rego", NO.as_bytes()), ("b.rego", YES.as_bytes())],
            None,
        )
        .expect_err("the author hears it before the ledger is pushed");

        assert!(refused.contains("shared"), "{refused}");
    }

    /// One file per package is the ordinary case and stays ordinary.
    #[test]
    fn distinct_packages_are_unaffected() {
        const ONE: &str = "package one\n\nimport rego.v1\n\nallow if { true }\n";
        const TWO: &str = "package two\n\nimport rego.v1\n\ndefault allow := false\n";

        assert!(
            Rego.compile(
                &[stored("01a0-one", ONE), stored("01a0-two", TWO)],
                &permguard_language_core::artifact::Artifacts::default(),
            )
            .is_ok()
        );
    }
}
