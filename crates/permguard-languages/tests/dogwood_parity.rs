// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! TL-5b: what this build reads of a Dogwood source where upstream keeps the reading private —
//! the `max_window` directive (DOGWOOD-06, LANG-11) and the `@id` annotation (DOGWOOD-07) — held
//! to upstream itself by pinned vectors.
//!
//! Each vector is checked twice: against this build's reading, through the contract and the alias
//! it derives, and against upstream, which enforces the window it parsed when it validates a policy
//! and parses the annotations it lowers. The vectors name the upstream version they were taken at,
//! and a lock naming another fails here until they are rerun: an upgrade cannot drift silently.

#![allow(clippy::expect_used)]

use permguard_languages::artifact::{ArtifactBlob, Artifacts, artifact_type};
use permguard_languages::evaluate::{Evaluator, StoredPolicy};
use serde_json::Value;

const POLICY: &str = include_str!("fixtures/dogwood/read-login-not-logout.dw");
const ACTION_SCHEMA: &str = include_str!("fixtures/dogwood/read-login-not-logout.cedarschema");
const EVENT_SCHEMA: &str = include_str!("fixtures/dogwood/pinned.dwschema");

fn vectors(name: &str) -> Value {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).expect("readable")).expect("JSON")
}

/// The version the lock resolves upstream to: a published crate, which cannot change under it.
fn locked_version() -> String {
    let lock = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"))
        .expect("the lock is readable");
    let entry = lock
        .split("[[package]]")
        .find(|entry| entry.contains("name = \"dogwood-language\""))
        .expect("the lock carries upstream");
    entry
        .lines()
        .find_map(|line| line.strip_prefix("version = \""))
        .and_then(|tail| tail.strip_suffix('"'))
        .expect("a locked version")
        .to_owned()
}

fn compile(policy: &str, event_schema: &str) -> Result<Box<dyn Evaluator>, String> {
    let mut artifacts = Artifacts::default();
    for (name, data) in [
        (
            permguard_languages::dogwood_artifacts::ACTION_SCHEMA,
            ACTION_SCHEMA,
        ),
        (
            permguard_languages::dogwood_artifacts::EVENT_SCHEMA,
            event_schema,
        ),
    ] {
        let held = artifact_type(name).expect("registered");
        artifacts.insert(
            held,
            ArtifactBlob {
                name: held.canonical_filename().unwrap_or(name).to_owned(),
                media_type: held.media_type().to_owned(),
                data: data.as_bytes().to_vec(),
            },
        );
    }
    let engine = permguard_languages::registry::evaluating("dogwood").expect("dogwood");
    permguard_languages::headroom::with(|| {
        engine.compile(
            &[StoredPolicy {
                id: "01a0-read".to_owned(),
                alias: None,
                source: policy.as_bytes().to_vec(),
            }],
            &artifacts,
        )
    })
}

/// The fixture's event declarations, without any directive.
fn declarations() -> String {
    EVENT_SCHEMA
        .lines()
        .filter(|line| !line.trim_start().starts_with("max_window"))
        .collect::<Vec<_>>()
        .join("\n")
}

/// The fixture policy, its window set to `seconds`.
fn within(seconds: i64) -> String {
    POLICY.replace("within 1h", &format!("within {seconds}s"))
}

#[test]
fn test_the_vectors_name_the_locked_upstream_version() {
    let locked = locked_version();
    for name in ["dogwood_max_window.json", "dogwood_alias.json"] {
        assert_eq!(
            vectors(name)["version"].as_str(),
            Some(locked.as_str()),
            "`{name}` was taken at another upstream version: rerun it against this one"
        );
    }
}

#[test]
fn test_the_max_window_this_build_reads_is_the_one_upstream_enforces() {
    for case in vectors("dogwood_max_window.json")["cases"]
        .as_array()
        .expect("cases")
    {
        let prefix = case["prefix"].as_str().expect("a prefix");
        let schema = format!("{prefix}\n{}", declarations());
        match case["seconds"].as_i64() {
            Some(seconds) => {
                let compiled = compile(&within(seconds), &schema).unwrap_or_else(|error| {
                    panic!(
                        "`{}`: a window of {seconds}s compiles: {error}",
                        prefix.escape_debug()
                    )
                });
                assert_eq!(
                    compiled
                        .temporal()
                        .expect("it remembers")
                        .contract()
                        .max_window_seconds,
                    seconds,
                    "`{}`: this build's reading",
                    prefix.escape_debug()
                );
                assert!(
                    compile(&within(seconds + 1), &schema).is_err(),
                    "`{}`: upstream enforces {seconds}s, so one second more is refused",
                    prefix.escape_debug()
                );
            }
            None => {
                assert!(
                    dogwood_language::ServiceSchema::builder()
                        .event_schema_str(&schema)
                        .build()
                        .is_err(),
                    "`{}`: upstream itself refuses the schema",
                    prefix.escape_debug()
                );
                assert!(
                    compile(&within(60), &schema).is_err(),
                    "`{}`: and so does this build",
                    prefix.escape_debug()
                );
            }
        }
    }
}

#[test]
fn test_the_id_this_build_reads_is_the_one_upstream_parses() {
    let dogwood = permguard_languages::language("dogwood").expect("dogwood");
    let body: String = POLICY
        .lines()
        .filter(|line| !line.trim_start().starts_with("@id("))
        .collect::<Vec<_>>()
        .join("\n");
    for case in vectors("dogwood_alias.json")["cases"]
        .as_array()
        .expect("cases")
    {
        let prefix = case["prefix"].as_str().expect("a prefix");
        let source = format!("{prefix}\n{body}\n");
        let read = dogwood.declared_alias(source.as_bytes());
        let compiled = compile(&source, EVENT_SCHEMA);
        // What upstream's own parser answers, so a drift there fails here even where this build
        // refuses the source for a reason of its own.
        let upstream = dogwood_language::ParsedPolicySet::parse(
            &source,
            &dogwood_language::ServiceSchema::defaults(),
        );
        assert_eq!(
            if upstream.is_ok() {
                "parses"
            } else {
                "refuses"
            },
            case["upstream"].as_str().expect("an upstream verdict"),
            "`{}`: upstream's parser",
            prefix.escape_debug()
        );
        if case["refused"].as_bool() == Some(true) {
            assert!(read.is_err(), "`{}`: refused", prefix.escape_debug());
            assert!(
                compiled.is_err(),
                "`{}`: refused at load too",
                prefix.escape_debug()
            );
            continue;
        }
        assert_eq!(
            read.expect("read").as_deref(),
            case["alias"].as_str(),
            "`{}`",
            prefix.escape_debug()
        );
        // Compiling checks this build's reading against upstream's parse, policy by policy.
        compiled.unwrap_or_else(|error| {
            panic!("`{}`: upstream agrees: {error}", prefix.escape_debug())
        });
    }
}
