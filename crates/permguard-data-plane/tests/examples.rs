// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Every example under `examples/`, decided by the real decision path.
//!
//! The manifest, the policies and the requests are read from the example directory —
//! the same files its README tells a reader to apply — and so are the expectations:
//! **the `tests/*.yml` `permguard test` reads**. There is no table of expected answers
//! here, deliberately. One would be a second copy of what each example claims, free to
//! drift from the first, and a case added to an example would be covered by the CLI and
//! silently not by this.
//!
//! So the two paths share their expectations and differ only in how the answer is
//! reached: `permguard test` compiles the workspace and evaluates it; this drives the
//! real `Decider` against a mirror built out of the same objects an `apply` pushes.
//! Between them, an example cannot claim something neither path can produce.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use permguard_core::Metrics;
use permguard_data_plane::authz::cache::Cache;
use permguard_data_plane::authz::decide::Decider;
use permguard_languages::registry;
use std::path::PathBuf;
use std::sync::Arc;

mod support;

use support::examples::*;

fn scratch(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-release-pipeline-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the scratch directory is created");

    dir
}

/// Every case of every example, decided by the real decision path.
#[tokio::test]
async fn every_example_decides_the_way_its_cases_say_it_does() {
    let mut checked = 0;

    for name in EXAMPLES {
        let root = scratch(name).join("mirrors");
        provision(&root, name);
        let decider = Arc::new(Decider::new(
            root.clone(),
            Arc::new(Cache::new(64, 8 * 1024 * 1024)),
            Metrics::none(),
            None,
            256,
        ));

        for (_, case) in cases(name) {
            // A request may be refused two ways, and a case expecting an error means either: the
            // plane declines to read it at all — a reserved field, an override naming a partition
            // nobody has — or it reads it and an engine cannot evaluate it. The CLI reports both
            // as an error, so this must too, or the two would judge the same case differently.
            let answer = match decider.decide(&request(name, &case), None).await {
                Ok(answer) => answer,
                Err(error) => {
                    let refusal = format!(
                        "{}: {}",
                        error.code(),
                        error.disclosed_message(permguard_core::Disclosure::Full)
                    );
                    let wanted =
                        case.expect.error.as_deref().unwrap_or_else(|| {
                            panic!("{name}/{}: not served: {refusal}", case.name)
                        });
                    assert!(
                        refusal.contains(wanted),
                        "{name}/{}: expected a refusal saying `{wanted}`, got `{refusal}`",
                        case.name
                    );
                    checked += 1;

                    continue;
                }
            };
            let context = answer.context.as_ref();
            let refused = context
                .and_then(|context| context.reason_admin.as_ref())
                .filter(|reason| reason.code == "500")
                .map(|reason| reason.message.clone());

            if let Some(wanted) = &case.expect.error {
                let found = refused.as_deref().unwrap_or_else(|| {
                    panic!(
                        "{name}/{}: expected a refusal saying `{wanted}`, and it was evaluated",
                        case.name
                    )
                });
                assert!(
                    found.contains(wanted.as_str()),
                    "{name}/{}: expected a refusal saying `{wanted}`, got `{found}`",
                    case.name
                );
            } else if let Some(found) = &refused {
                panic!("{name}/{}: could not be evaluated: {found}", case.name);
            }

            if let Some(wanted) = &case.expect.decision {
                let wanted_permit = wanted == "permit";
                assert_eq!(
                    answer.decision, wanted_permit,
                    "{name}/{}: expected {wanted}",
                    case.name
                );
            }

            // A boxcarred request has no single policy to cite, so a case names the
            // policies only for a plain one — which is what the CLI does too.
            if let Some(wanted) = &case.expect.policies {
                let cited: Vec<String> = context
                    .map(|context| context.policies.clone())
                    .unwrap_or_default();
                // The mirror stores each policy under its alias, which is what the CLI's
                // reports name too — so a citation is comparable to a case as it stands.
                assert_eq!(
                    &cited, wanted,
                    "{name}/{}: cited something other than the policies its case names",
                    case.name
                );
            }

            if let Some(wanted) = &case.expect.evaluations {
                let held = answer
                    .evaluations
                    .as_ref()
                    .unwrap_or_else(|| panic!("{name}/{}: not answered as a batch", case.name));
                for (request_id, decision) in wanted {
                    let found = held
                        .iter()
                        .find(|evaluation| {
                            evaluation.request_id.as_deref() == Some(request_id.as_str())
                        })
                        .unwrap_or_else(|| {
                            panic!("{name}/{}: no evaluation named `{request_id}`", case.name)
                        });
                    let got = if found.decision { "permit" } else { "deny" };
                    assert_eq!(
                        got, decision,
                        "{name}/{}: `{request_id}` expected {decision}",
                        case.name
                    );
                }
            }

            checked += 1;
        }
    }

    assert!(checked > 12, "only {checked} cases were decided");
}

/// Corrupted-cache fault injection (TL-6): every policy object of a mirror altered on disk after
/// its partitions compiled — the commit, the manifest and the checkpoint left as they were. A cold
/// load, a restart's empty cache, refuses the ledger rather than compiling altered bytes; the warm
/// partitions, compiled from the verified objects and cached under the same commit, decide as they
/// did. For each runtime of the example: Cedar and Rego.
#[tokio::test]
async fn a_corrupted_mirror_fails_a_cold_load_and_never_changes_a_warm_answer() {
    let name = "basics";
    let root = scratch("corrupted").join("mirrors");
    provision(&root, name);
    let warm = Arc::new(Decider::new(
        root.clone(),
        Arc::new(Cache::new(64, 8 * 1024 * 1024)),
        Metrics::none(),
        None,
        256,
    ));
    // One permitted case of each partition's runtime, decided while the mirror is intact.
    let permitted: Vec<Case> = cases(name)
        .into_iter()
        .map(|(_, case)| case)
        .filter(|case| {
            case.expect.decision.as_deref() == Some("permit") && case.expect.error.is_none()
        })
        .collect();
    assert!(!permitted.is_empty(), "the example permits something");
    for case in &permitted {
        let answer = warm
            .decide(&request(name, case), None)
            .await
            .expect("decided");
        assert!(answer.decision, "{}: permitted while intact", case.name);
    }

    // Every policy object of the mirror, stored compressed: one byte of its content flipped and
    // stored again under the same name.
    let mut altered = std::collections::BTreeSet::new();
    let mut pending = vec![root.clone()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("readable") {
            let path = entry.expect("an entry").path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if !path.components().any(|part| part.as_os_str() == "objects") {
                continue;
            }
            let stored = std::fs::read(&path).expect("an object");
            let Ok(mut bytes) = permguard_objects::compress::inflate(
                &stored,
                permguard_objects::limits::MAX_OBJECT_BYTES,
            ) else {
                continue;
            };
            let media_type = match permguard_objects::object::decode(&bytes) {
                Ok(permguard_objects::object::Object::Blob(blob)) => blob.media_type,
                _ => continue,
            };
            if media_type != registry::MEDIA_TYPE_POLICY_CEDAR
                && media_type != registry::MEDIA_TYPE_POLICY_REGO
            {
                continue;
            }
            let last = bytes.len() - 1;
            bytes[last] ^= 0x01;
            std::fs::write(&path, permguard_objects::compress::deflate(&bytes)).expect("rewritten");
            altered.insert(media_type);
        }
    }
    assert_eq!(
        altered.len(),
        2,
        "a policy object of each runtime altered: {altered:?}"
    );

    let cold = Arc::new(Decider::new(
        root.clone(),
        Arc::new(Cache::new(64, 8 * 1024 * 1024)),
        Metrics::none(),
        None,
        256,
    ));
    for case in &permitted {
        match cold.decide(&request(name, case), None).await {
            Err(_) => {}
            Ok(answer) => panic!(
                "{}: a cold load answered from altered objects: decision {}",
                case.name, answer.decision
            ),
        }
        let answer = warm
            .decide(&request(name, case), None)
            .await
            .unwrap_or_else(|error| {
                panic!("{}: the warm partitions refused: {error:?}", case.name)
            });
        assert!(
            answer.decision,
            "{}: the warm partition answered differently after the corruption",
            case.name
        );
    }
}

/// The point of the release pipeline's three partitions: a profile compiles what it
/// names and nothing else.
#[test]
fn each_profile_loads_only_the_partitions_it_needs() {
    let manifest = manifest("release-pipeline");

    assert_eq!(
        manifest.profiles.get("admin").map(|p| p.partitions.clone()),
        Some(vec!["admin-cedar".to_owned(), "admin-rego".to_owned()]),
        "what a person asks is answered by the org chart and the guardrails together"
    );
    assert_eq!(
        manifest
            .profiles
            .get("pipeline")
            .map(|p| p.partitions.clone()),
        Some(vec!["pipeline-rego".to_owned()]),
        "what the pipeline asks is answered by the rules for machines, alone"
    );
    assert_eq!(
        manifest
            .partitions
            .get("admin-rego")
            .map(|p| p.runtime.clone()),
        manifest
            .partitions
            .get("pipeline-rego")
            .map(|p| p.runtime.clone()),
        "both Rego partitions run the same runtime — they are split by what is asked"
    );
    assert!(
        manifest
            .partitions
            .get("admin-cedar")
            .is_some_and(|p| p.schema),
        "the Cedar partition carries a schema, and the example depends on it being checked"
    );
    // Each partition declares what a request may hand it, and the three differ on purpose: the
    // org chart the Cedar rules traverse is required, the guardrails' list is optional, and the
    // pipeline rules read the request alone and accept nothing.
    let input = |name: &str| {
        manifest
            .partitions
            .get(name)
            .and_then(|held| held.input.clone())
    };
    let cedar = input("admin-cedar").expect("admin-cedar accepts an entity store");
    assert_eq!(cedar.r#type, permguard_languages::input::CEDAR_ENTITIES_V1);
    assert!(cedar.required, "its policies traverse that store");
    let rego = input("admin-rego").expect("admin-rego accepts a document");
    assert_eq!(rego.r#type, permguard_languages::input::REGO_DATA_V1);
    assert!(!rego.required, "the guardrails hold without one");
    assert!(
        input("pipeline-rego").is_none(),
        "the pipeline rules read the request alone: anything addressed to them is refused"
    );
    assert!(
        manifest
            .partitions
            .get("admin-rego")
            .is_some_and(|p| p.schema),
        "and the document a request hands the guardrails is described by a JSON Schema"
    );
}
