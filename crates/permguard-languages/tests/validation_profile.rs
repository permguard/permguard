// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The validating half, alone: what the Control Plane's ingest asks of the catalogue, answered by a
//! build that carries no evaluating half (the crate boundaries refactoring, phase 2).
//!
//! This suite asks for no feature, so it runs in every profile, and in the one that matters: the
//! catalogue's default build, every language and no `evaluate`, which is the Control Plane's. There
//! it proves that validation still refuses what must not be stored:
//!
//! | What is pushed            | Held to                                                             |
//! | ------------------------- | ------------------------------------------------------------------- |
//! | a manifest                | the golden vectors' `manifests`: accepted, or refused with the text |
//! | a partition's policies    | the golden vectors' `partitions`: validated exactly when they load  |
//! | a blob of a media type    | refused when nothing registers the type, or its language refuses it |
//! | a Dogwood bundle          | upstream's example accepted; a broken policy, a wrong artifact and  |
//! |                           | a history scope the schema contradicts refused                      |
//!
//! `dependency_direction.rs` proves the Control Plane's build links no `permguard-pdp-core`; this
//! proves that build still validates.

#![allow(clippy::expect_used, clippy::panic)]
// A build that carries neither stateless runtime has no vectors to answer here.
#![cfg_attr(not(any(feature = "cedar", feature = "rego")), allow(dead_code))]

use std::collections::BTreeMap;

use permguard_languages::language;
use permguard_languages::registry::{check_manifest, validate_blob};
use permguard_objects::manifest::Partition;
use serde_json::{Value, json};

/// A runtime's golden vectors, the same file the evaluating suite answers.
fn vectors(runtime: &str) -> Value {
    let file = format!(
        "{}/tests/vectors/{runtime}.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str(
        &std::fs::read_to_string(&file).unwrap_or_else(|error| panic!("{file}: {error}")),
    )
    .expect("the vectors are JSON")
}

/// What the load gate answers for a manifest's YAML, as the vectors write it.
fn manifest_outcome(yaml: &str) -> Value {
    let manifest = match permguard_languages::manifest_file::from_yaml(yaml.as_bytes()) {
        Ok(manifest) => manifest,
        Err(error) => return json!({ "refused": error }),
    };
    match check_manifest(&manifest) {
        Ok(()) => json!("accepted"),
        Err(error) => json!({ "refused": error.detail }),
    }
}

/// A partition of `runtime` that declares nothing beyond its runtime.
fn declared(runtime: &str) -> Partition {
    Partition {
        runtime: runtime.to_owned(),
        media_types: Vec::new(),
        schema: false,
        artifacts: Vec::new(),
        history: None,
        input: None,
        interfaces: Vec::new(),
    }
}

/// Every manifest of the runtime's vectors is answered as recorded, and every partition passes
/// ingest's two checks, each blob then the whole, exactly when the vectors say it loads: what
/// ingest accepts is what a plane serves.
fn check(runtime: &str) {
    let vectors = vectors(runtime);
    let plugin = language(runtime).expect("the runtime is carried");

    let manifests = vectors["manifests"].as_array().expect("manifests");
    assert!(!manifests.is_empty(), "{runtime}: no manifests");
    for manifest in manifests {
        assert_eq!(
            manifest_outcome(manifest["yaml"].as_str().expect("yaml")),
            manifest["expect"],
            "{runtime} manifest `{}`",
            manifest["name"]
        );
    }

    let partitions = vectors["partitions"].as_array().expect("partitions");
    let mut refused = 0;
    for partition in partitions {
        let policies: Vec<(String, Vec<u8>)> = partition["policies"]
            .as_array()
            .expect("policies")
            .iter()
            .map(|policy| {
                (
                    policy["id"].as_str().expect("an id").to_owned(),
                    policy["source"]
                        .as_str()
                        .expect("a source")
                        .as_bytes()
                        .to_vec(),
                )
            })
            .collect();
        let named: Vec<(&str, &[u8])> = policies
            .iter()
            .map(|(id, source)| (id.as_str(), source.as_slice()))
            .collect();
        let artifacts: BTreeMap<String, Vec<u8>> = partition["artifacts"]
            .as_object()
            .into_iter()
            .flatten()
            .map(|(name, data)| {
                let data = match data {
                    Value::String(text) => text.as_bytes().to_vec(),
                    other => serde_json::to_vec(other).expect("JSON"),
                };
                (name.clone(), data)
            })
            .collect();

        // As ingest does: each blob by itself, then the partition as a whole.
        let validated = named
            .iter()
            .try_for_each(|(_, source)| plugin.validate_policy(source))
            .and_then(|()| plugin.validate_bundle("p", &named, &artifacts, &declared(runtime)));
        let loads = partition["expect"] == "compiles";
        assert_eq!(
            validated.is_ok(),
            loads,
            "{runtime} partition `{}`: validation answered {validated:?} and the vectors say {}",
            partition["name"],
            partition["expect"]
        );
        if !loads {
            refused += 1;
        }
    }
    assert!(refused > 0, "{runtime}: the vectors refuse no partition");
}

#[cfg(feature = "cedar")]
#[test]
fn test_cedar_is_validated_as_its_golden_vectors_say() {
    check("cedar");
}

#[cfg(feature = "rego")]
#[test]
fn test_rego_is_validated_as_its_golden_vectors_say() {
    check("rego");
}

/// A blob is refused when nothing registers its media type, and when its language refuses its
/// bytes; a policy its language reads is accepted. Asked of every language this build carries.
#[test]
fn test_a_blob_is_refused_by_its_media_type_or_by_its_language() {
    let refused = validate_blob("application/vnd.acme.thing", b"anything")
        .expect_err("nothing registers the type");
    assert_eq!(
        refused.code,
        permguard_core::codes::notp::MEDIA_TYPE_UNREGISTERED
    );

    let carried = permguard_languages::languages();
    assert!(!carried.is_empty(), "a build carries a language");
    for plugin in carried {
        let refused = validate_blob(plugin.policy_media_type(), &[0xff, 0xfe, 0x00])
            .expect_err("bytes no language reads as a policy");
        assert_eq!(
            refused.code,
            permguard_core::codes::notp::BLOB_REJECTED,
            "`{}`",
            plugin.name()
        );
        for artifact in plugin.artifacts() {
            // A registered artifact is validated by its own type, never as a policy.
            let answered = validate_blob(artifact.media_type(), &[0xff, 0xfe, 0x00]);
            assert_eq!(
                answered.err().map(|refused| refused.code),
                Some(permguard_core::codes::notp::BLOB_REJECTED),
                "`{}`",
                artifact.name()
            );
        }
    }
}

#[cfg(feature = "cedar")]
#[test]
fn test_a_well_formed_cedar_policy_is_accepted_and_a_broken_one_refused() {
    let media_type = permguard_core::domains::media::POLICY_CEDAR;
    validate_blob(media_type, b"permit (principal, action, resource);")
        .expect("a policy Cedar reads");
    let refused = validate_blob(media_type, b"permit (principal").expect_err("not a policy");
    assert_eq!(refused.code, permguard_core::codes::notp::BLOB_REJECTED);
}

#[cfg(feature = "rego")]
#[test]
fn test_a_well_formed_rego_module_is_accepted_and_a_broken_one_refused() {
    let media_type = permguard_core::domains::media::POLICY_REGO;
    validate_blob(
        media_type,
        b"package acme.release\n\nimport rego.v1\n\ndefault allow := false\n",
    )
    .expect("a module Rego reads");
    let refused = validate_blob(media_type, b"package ???").expect_err("not a module");
    assert_eq!(refused.code, permguard_core::codes::notp::BLOB_REJECTED);
}

/// Dogwood validates a bundle with the analysis its evaluating half is built on, and needs no
/// evaluating half to do it.
#[cfg(feature = "dogwood")]
mod dogwood {
    use permguard_languages::dogwood_artifacts;
    use permguard_objects::manifest::{ArtifactContract, HistoryScope};

    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        let file = format!(
            "{}/tests/fixtures/dogwood/{name}",
            env!("CARGO_MANIFEST_DIR")
        );
        std::fs::read(&file).unwrap_or_else(|error| panic!("{file}: {error}"))
    }

    /// Upstream's example, as a partition declares it: its action schema, required.
    fn partition() -> Partition {
        Partition {
            artifacts: vec![ArtifactContract {
                r#type: dogwood_artifacts::ACTION_SCHEMA.to_owned(),
                required: true,
            }],
            ..declared("dogwood")
        }
    }

    fn validate(
        policy: &[u8],
        artifacts: &[(&str, Vec<u8>)],
        declared: &Partition,
    ) -> Result<(), String> {
        let artifacts: BTreeMap<String, Vec<u8>> = artifacts
            .iter()
            .map(|(name, data)| ((*name).to_owned(), data.clone()))
            .collect();
        language("dogwood").expect("carried").validate_bundle(
            "governance",
            &[("read-login-not-logout", policy)],
            &artifacts,
            declared,
        )
    }

    #[test]
    fn test_upstreams_example_is_accepted_and_what_breaks_it_is_refused() {
        let policy = fixture("read-login-not-logout.dw");
        let schema = fixture("read-login-not-logout.cedarschema");
        let held = [(dogwood_artifacts::ACTION_SCHEMA, schema.clone())];

        validate(&policy, &held, &partition()).expect("upstream's example validates");

        // A policy that does not parse.
        let refused =
            validate(b"permit (principal", &held, &partition()).expect_err("not a Dogwood policy");
        assert!(refused.contains("dogwood"), "{refused}");
        // An action schema that is not one.
        let broken = [(dogwood_artifacts::ACTION_SCHEMA, b"entity ;;;".to_vec())];
        validate(&policy, &broken, &partition()).expect_err("not an action schema");
        // No action schema at all: the partition cannot be lowered.
        validate(&policy, &[], &partition()).expect_err("no action schema");
    }

    /// The manifest's claim about the partition's history is checked against what its schemas say,
    /// at ingest as at load: the default event schema pins the principal on every kind, so
    /// declaring the history global contradicts it.
    #[test]
    fn test_a_history_scope_the_schema_contradicts_is_refused_at_ingest() {
        let policy = fixture("read-login-not-logout.dw");
        let held = [(
            dogwood_artifacts::ACTION_SCHEMA,
            fixture("read-login-not-logout.cedarschema"),
        )];
        let global = Partition {
            history: Some(HistoryScope::Global),
            ..partition()
        };

        let refused = validate(&policy, &held, &global).expect_err("the schema is partitioned");
        assert!(refused.contains("callerPrincipal"), "{refused}");
    }
}
