// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The embedded Data Plane under the profile this build selected, outside the repository's
//! workspace (`11-refactoring/1-dependencies.md`, Verification requirements).
//!
//! | Profile                 | What is proven                                                       |
//! | ----------------------- | -------------------------------------------------------------------- |
//! | no language             | the start is refused, by name: a Data Plane decides with a language  |
//! | `cedar` or `rego` alone | the basics example narrowed to that language is decided as it says;  |
//! |                         | as published, with both, its manifest is refused by the language     |
//! | a build without Dogwood | an event history is refused at the start, by the feature it lacks    |
//! | `dogwood` alone         | the Plane starts and is ready                                        |
//!
//! Each test is compiled only in the profile it speaks of; `scripts/check-embedded-fixture.sh`
//! runs every profile and refuses one that ran no test.

// Each profile compiles part of this file: what one test imports, another profile does not use.
#![allow(unused_imports, clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use permguard_data_plane::embedded::StartError;
use permguard_embedded_fixture::embed;

// The Host an application composes and the repository's examples as verified mirrors: the Data
// Plane's own test support, read here so both suites start the Plane over the same composition.
#[allow(dead_code)]
#[path = "../../../crates/permguard-data-plane/tests/support/embedded.rs"]
mod composed;
#[allow(dead_code)]
#[path = "../../../crates/permguard-data-plane/tests/support/examples.rs"]
mod examples;

use composed::{Recording, capabilities, config, scratch};

/// A build with no language carries nothing to decide with, and says so instead of starting.
#[cfg(not(any(feature = "cedar", feature = "rego", feature = "dogwood")))]
#[tokio::test]
async fn test_a_build_with_no_language_refuses_to_start() {
    let working = scratch("no-language");

    let refused = match embed(capabilities(
        config(&working, &[]),
        Arc::new(Recording::default()),
    ))
    .await
    {
        Ok(_) => panic!("a Data Plane with no language started"),
        Err(refused) => refused,
    };

    assert!(
        matches!(refused, StartError::Configuration(_)),
        "refused for another reason: {refused}"
    );
    assert!(
        refused.to_string().contains("carries no policy language"),
        "{refused}"
    );
}

/// An event history is decided the way Dogwood decides: a build without it refuses the start.
#[cfg(all(any(feature = "cedar", feature = "rego"), not(feature = "dogwood")))]
#[tokio::test]
async fn test_an_event_history_is_refused_in_a_build_without_dogwood() {
    use permguard_core::config::{SETTING_EVENTS_ENABLED, SETTING_EXPERIMENTAL_DOGWOOD};

    let working = scratch("events-without-dogwood");

    let refused = match embed(capabilities(
        config(
            &working,
            &[
                (SETTING_EVENTS_ENABLED, "true"),
                (SETTING_EXPERIMENTAL_DOGWOOD, "true"),
            ],
        ),
        Arc::new(Recording::default()),
    ))
    .await
    {
        Ok(_) => panic!("an event history was served without Dogwood"),
        Err(refused) => refused,
    };

    assert!(
        matches!(refused, StartError::Configuration(_)),
        "refused for another reason: {refused}"
    );
    assert!(refused.to_string().contains("dogwood"), "{refused}");
}

/// One language alone: the example as an author publishes it for this build is decided as its
/// cases say, and the example published with both languages is refused, never permitted.
#[cfg(any(
    all(feature = "cedar", not(feature = "rego"), not(feature = "dogwood")),
    all(feature = "rego", not(feature = "cedar"), not(feature = "dogwood"))
))]
mod one_language {
    use permguard_core::authz::Actor;

    use super::*;

    #[cfg(feature = "cedar")]
    const LANGUAGE: &str = "cedar";
    #[cfg(feature = "rego")]
    const LANGUAGE: &str = "rego";

    /// The requests of the example this language answers by itself, a permit and a deny: Cedar's
    /// carry its entities and ask the default profile, Rego's ask the gateway profile it holds
    /// alone.
    #[cfg(feature = "cedar")]
    const REQUESTS: [&str; 2] = ["permit.json", "deny.json"];
    #[cfg(feature = "rego")]
    const REQUESTS: [&str; 2] = ["gateway-permit.json", "boxcarred.json"];

    const ZONE_ID: &str = "01a1a166-5743-7014-b7bf-197ed0437363";
    const LEDGER_ID: &str = "01a1a166-5747-7d8c-a96a-6e17f5281a37";

    /// The cases of the example this language answers by itself, as the example states them.
    fn cases() -> Vec<(String, examples::Case)> {
        examples::cases("basics")
            .into_iter()
            .filter(|(_, case)| {
                case.profile.is_none()
                    && case.expect.decision.is_some()
                    && std::path::Path::new(&case.request)
                        .file_name()
                        .and_then(std::ffi::OsStr::to_str)
                        .is_some_and(|request| REQUESTS.contains(&request))
            })
            .collect()
    }

    #[tokio::test]
    async fn test_the_example_narrowed_to_the_one_language_is_decided_as_its_cases_say() {
        let working = scratch("one-language");
        let config = config(&working, &[]);
        examples::provision_manifest(
            &config.mirrors_directory(),
            "basics",
            examples::manifest_narrowed_to("basics", LANGUAGE),
            ZONE_ID,
            LEDGER_ID,
        );
        let streams = Arc::new(Recording::default());

        let runtime = embed(capabilities(config, Arc::clone(&streams)))
            .await
            .expect("the embedded Data Plane starts with one language");
        assert!(runtime.health().is_ready(), "ready once its services run");

        let cases = cases();
        let wanted: Vec<&str> = cases
            .iter()
            .filter_map(|(_, case)| case.expect.decision.as_deref())
            .collect();
        assert!(
            wanted.contains(&"permit") && wanted.contains(&"deny"),
            "a permit and a deny: {wanted:?}"
        );
        for (name, case) in &cases {
            let wanted = case.expect.decision.as_deref().expect("a decision");
            let answer = runtime
                .evaluate(&Actor::Anonymous, examples::request(name, case), None)
                .await
                .unwrap_or_else(|refused| panic!("{name}/{}: refused: {refused:?}", case.name));
            assert_eq!(
                answer.decision,
                wanted == "permit",
                "{LANGUAGE} alone, {name}/{}: expected {wanted}",
                case.name
            );
        }

        let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
        assert!(
            shutdown.unfinished.is_empty(),
            "everything drained: {:?}",
            shutdown.unfinished
        );
    }

    /// The example as its directory publishes it names both languages: this build reads no such
    /// manifest, and says which language it lacks, so no ledger of it is ever loaded here.
    #[test]
    fn test_the_example_as_published_names_a_language_this_build_refuses_by_name() {
        let other = if LANGUAGE == "cedar" { "rego" } else { "cedar" };
        let published = std::fs::read(examples::example("basics").join("manifest.yml"))
            .expect("the example carries a manifest");

        let refused = permguard_languages::manifest_file::from_yaml(&published)
            .expect_err("a manifest naming a language this build does not carry");

        assert!(refused.contains(other), "{refused}");
    }
}

/// Dogwood alone: the Plane starts over the application's Host and is ready.
#[cfg(all(feature = "dogwood", not(feature = "cedar"), not(feature = "rego")))]
#[tokio::test]
async fn test_a_build_with_dogwood_alone_starts_and_is_ready() {
    let working = scratch("dogwood-alone");

    let runtime = embed(capabilities(
        config(&working, &[]),
        Arc::new(Recording::default()),
    ))
    .await
    .expect("the embedded Data Plane starts with Dogwood alone");

    assert!(runtime.health().is_ready(), "ready once its services run");
    let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
    assert!(
        shutdown.unfinished.is_empty(),
        "everything drained: {:?}",
        shutdown.unfinished
    );
}

/// Every language: the application's own selection of them all decides the example as published.
#[cfg(all(feature = "cedar", feature = "rego", feature = "dogwood"))]
#[tokio::test]
async fn test_a_build_with_every_language_decides_the_example_as_published() {
    use permguard_core::authz::Actor;

    let working = scratch("every-language");
    let config = config(&working, &[]);
    examples::provision_as(
        &config.mirrors_directory(),
        "basics",
        "01a1a166-5743-7014-b7bf-197ed0437363",
        "01a1a166-5747-7d8c-a96a-6e17f5281a37",
    );

    let runtime = embed(capabilities(config, Arc::new(Recording::default())))
        .await
        .expect("the embedded Data Plane starts with every language");

    let mut decided = 0;
    for (name, case) in examples::cases("basics") {
        let Some(wanted) = case.expect.decision.as_deref() else {
            continue;
        };
        let answer = runtime
            .evaluate(&Actor::Anonymous, examples::request(&name, &case), None)
            .await
            .unwrap_or_else(|refused| panic!("{name}/{}: refused: {refused:?}", case.name));
        assert_eq!(answer.decision, wanted == "permit", "{name}/{}", case.name);
        decided += 1;
    }
    assert!(decided > 0, "the example claims decisions");

    let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
    assert!(shutdown.unfinished.is_empty(), "{:?}", shutdown.unfinished);
}
