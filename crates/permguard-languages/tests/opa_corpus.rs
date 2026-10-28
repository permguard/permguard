// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Upstream corpus parity for Rego (TL-6): OPA's conformance cases at `v1.2.0`, the revision
//! `regorus 0.12.0` pins in its own harness (`OPA_BRANCH` in its `tests/opa.rs`), for every folder
//! that harness lists as passing (`tests/opa.passing`) — 106 folders, the four others it lists not
//! existing at that revision — run on the engine as this build configures it, its feature set and
//! no defaults, and judged the way that harness judges them.
//!
//! What this proves is the engine: regorus answers OPA's cases as OPA does. It does not go through
//! Permguard's Rego adapter, whose allow-list refuses at load the clock, randomness and UUID
//! built-ins some of these folders exercise, and whose verdicts are the golden vectors'
//! (`tests/language_vectors.rs`).
//!
//! `tests/corpus/opa/SOURCE.json` names the revision, the engine and every vendored file's digest;
//! each upstream YAML file is converted to JSON, its original digest kept beside its cases. A case
//! passes when the query's results equal `want_result`, when it answers nothing and none is wanted,
//! or when it fails and a failure is what the case wants. The cases regorus's harness re-reads or
//! sets apart are re-read and set apart by name, with the reason, and the counts are pinned so the
//! corpus cannot quietly shrink.

#![allow(clippy::expect_used, clippy::panic)]

use regorus::{Engine, Value};
use serde_json::Value as Json;
use sha2::{Digest as _, Sha256};

fn root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/opa")
}

fn source() -> Json {
    serde_json::from_str(&std::fs::read_to_string(root().join("SOURCE.json")).expect("SOURCE"))
        .expect("JSON")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn test_the_vendored_opa_cases_are_the_ones_their_source_names() {
    let source = source();
    assert_eq!(source["revision"], "v1.2.0");
    for (file, digest) in source["files"].as_object().expect("files") {
        let bytes = std::fs::read(root().join(file)).expect("a vendored file");
        assert_eq!(
            digest,
            &Json::from(format!("sha256:{}", hex(&Sha256::digest(bytes)))),
            "{file} changed since it was vendored"
        );
    }
    let engine = permguard_languages::language("rego")
        .expect("rego")
        .engine()
        .locked;
    assert_eq!(
        source["engine"],
        serde_json::json!({ "name": engine.name, "version": engine.version }),
        "the cases were vendored for another Regorus: vendor the OPA revision the locked engine pins"
    );
}

/// An engine error, as text: the harness judges only that a case failed.
fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

/// What one case answers, as regorus's own harness renders it.
fn evaluate(case: &Json) -> Result<Value, String> {
    let mut engine = Engine::new();
    engine.set_rego_v0(false);
    if let Some(data) = case.get("data").filter(|data| !data.is_null()) {
        engine
            .add_data(Value::from_json_str(&data.to_string()).map_err(text)?)
            .map_err(text)?;
    }
    if let Some(input) = case.get("input").filter(|input| !input.is_null()) {
        engine.set_input(Value::from_json_str(&input.to_string()).map_err(text)?);
    }
    if let Some(term) = case["input_term"].as_str() {
        let results = engine.eval_query(term.to_owned(), true).map_err(text)?;
        let input = results
            .result
            .last()
            .and_then(|result| result.expressions.last())
            .map(|expression| expression.value.clone())
            .ok_or_else(|| "no results in evaluated input term".to_owned())?;
        engine.set_input(input);
    }
    for (index, module) in case["modules"].as_array().into_iter().flatten().enumerate() {
        engine
            .add_policy(
                format!("rego{index}.rego"),
                module.as_str().expect("a module").to_owned(),
            )
            .map_err(text)?;
    }
    engine.set_strict_builtin_errors(case["strict_error"].as_bool().unwrap_or_default());
    let query = case["query"].as_str().expect("a query").to_owned();
    // As regorus's harness does for this one case: the deep query is answered by evaluating every
    // rule first.
    let results = if case["note"] == "refheads/general, set leaf, deep query" {
        engine.eval_query_and_all_rules(query, true).map_err(text)?
    } else {
        engine.eval_query(query, true).map_err(text)?
    };
    let mut values = Vec::new();
    for result in results.result {
        values.push(if !result.bindings.as_object().map_err(text)?.is_empty() {
            if case["sort_bindings"].as_bool() == Some(true) {
                let mut bindings = result.bindings.clone();
                for (_, value) in bindings.as_object_mut().map_err(text)?.iter_mut() {
                    if let Value::Array(_) = value {
                        value.as_array_mut().map_err(text)?.sort();
                    }
                }
                bindings
            } else {
                result.bindings.clone()
            }
        } else if let Some(expression) = result.expressions.last() {
            expression.value.clone()
        } else {
            Value::Undefined
        });
    }
    Value::from_json_str(&Value::from(values).to_string()).map_err(text)
}

/// Whether `case` passes, as regorus's harness judges it.
fn passes(case: &Json) -> Result<(), String> {
    let wants_failure = case.get("want_error").is_some_and(|w| !w.is_null())
        || case["strict_error"].as_bool() == Some(true)
        || case.get("want_error_code").is_some_and(|w| !w.is_null());
    let wanted = case
        .get("want_result")
        .filter(|want| !want.is_null())
        .map(|want| Value::from_json_str(&want.to_string()).expect("a wanted result"));
    // A JSON Schema case compares the verdict and not the message, which no two engines share.
    let schema_case = case["note"].as_str().is_some_and(|note| {
        note.starts_with("json_verify_schema") || note.starts_with("json_match_schema")
    });
    match (evaluate(case), wanted) {
        (Ok(actual), Some(expected)) if schema_case => {
            let (actual, expected) = (&actual[0]["x"], &expected[0]["x"]);
            match (actual, expected) {
                (Value::Array(a), Value::Array(e))
                    if a.len() == 2 && e.len() == 2 && a[0] == e[0] =>
                {
                    Ok(())
                }
                _ => Err(format!("answered {actual}, wanted {expected}")),
            }
        }
        (Ok(actual), Some(expected)) if actual == expected => Ok(()),
        (Ok(actual), None) if actual == Value::new_array() && !wants_failure => Ok(()),
        (Err(_), _) if wants_failure => Ok(()),
        (Ok(actual), expected) => Err(format!("answered {actual}, wanted {expected:?}")),
        (Err(error), _) => Err(format!("failed: {error}")),
    }
}

/// Cases this build does not run, each with why: what regorus's own harness also sets apart, and
/// one that needs a built-in only OPA's test runner has.
const SET_APART: &[(&str, &str)] = &[
    (
        "strings/sprintf: float too big",
        "regorus's harness passes it whatever it answers (OPA prints the float in scientific \
         notation, regorus in full); this build's number parser refuses the literal `2e308`, so \
         the module is refused at load: fail-closed, and nothing to compare",
    ),
    (
        "withkeyword/builtin: nested, multiple mocks",
        "regorus's harness skips it: it mocks `io.jwt.decode_verify`, which does not exist",
    ),
    (
        "withkeyword/builtin-builtin: arity 0",
        "regorus's harness skips it: it expects `opa.runtime` to answer an empty object",
    ),
    (
        "withkeyword/builtin-builtin: arity 1, replacement is simple",
        "regorus's harness skips it: it calls a deprecated built-in",
    ),
    (
        "withkeyword/builtin-builtin: arity 1, replacement is compound",
        "regorus's harness skips it: it calls a deprecated built-in",
    ),
    (
        "withkeyword/function: direct call, built-in replacement, arity 1",
        "regorus's harness skips it: it calls a deprecated built-in",
    ),
    (
        "withkeyword/function: direct call, built-in replacement, arity 1, result captured",
        "regorus's harness skips it: it calls a deprecated built-in",
    ),
    (
        "time/time caching",
        "it calls `test.sleep`, a built-in of OPA's own test runner that no engine build carries",
    ),
];

/// The answers regorus's harness fixes or re-reads, as it does (its `tests/opa.rs`): the cases
/// whose upstream answer is ill-defined or whose order is not one.
fn adjusted(case: &Json) -> Json {
    let mut case = case.clone();
    match case["note"].as_str() {
        // OPA's answer here is not well-defined (open-policy-agent/opa#5871, #6128): regorus locks
        // every path to a leaf instead.
        Some("reachable_paths/cycle_1022_3") => {
            case["want_result"] = serde_json::json!([{ "x": [
                ["one", "five", "seven", "eight", "three"],
                ["one", "five", "six", "nine"],
                ["one", "five", "six", "seven", "eight", "three"],
                ["one", "two", "four", "three"]
            ]}]);
        }
        // Stated in the reverse of the order object keys sort in.
        Some("refheads/general, multiple result-set entries") => {
            if let Some(wanted) = case["want_result"].as_array_mut() {
                wanted.reverse();
            }
        }
        _ => {}
    }
    case
}

#[test]
fn test_rego_reproduces_the_upstream_opa_conformance_cases() {
    let source = source();
    let mut passed = 0;
    let mut set_apart = 0;
    let mut failures = Vec::new();
    for file in source["files"].as_object().expect("files").keys() {
        let folder: Json =
            serde_json::from_slice(&std::fs::read(root().join(file)).expect("a folder"))
                .expect("JSON");
        for (name, yaml) in folder["files"].as_object().expect("files") {
            for case in yaml["cases"].as_array().expect("cases") {
                if SET_APART.iter().any(|(note, _)| case["note"] == *note) {
                    set_apart += 1;
                    continue;
                }
                match passes(&adjusted(case)) {
                    Ok(()) => passed += 1,
                    Err(why) => failures.push(format!("{file}/{name} `{}`: {why}", case["note"])),
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} cases:\n{}",
        failures.len(),
        passed + failures.len(),
        failures.join("\n")
    );
    assert_eq!(
        (passed, set_apart),
        (1452, SET_APART.len()),
        "OPA cases decided, set apart"
    );
}
