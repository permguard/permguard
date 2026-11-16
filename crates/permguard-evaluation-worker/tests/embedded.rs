// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An application embedding the Data Plane under `production`, with the dedicated worker named:
//! its Rego partition, which that profile requires isolated, is compiled and decided in the
//! worker, and the application's own executable, this test, is never started as one.
//!
//! Without the name the supervisor would start this test binary with the worker argument, which
//! speaks no protocol: the partition would be unavailable, and nothing permitted.
//!
//! A binary of its own: the decision path and its worker are composed once per process.

#![allow(clippy::expect_used, clippy::unwrap_used)]
#![cfg(unix)]

use std::sync::Arc;
use std::time::Duration;

use permguard_core::authz::Actor;
use permguard_core::config::SETTING_ASSURANCE_PROFILE;
use permguard_data_plane::embedded::DataPlane;

#[allow(dead_code)]
#[path = "../../permguard-data-plane/tests/support/embedded.rs"]
mod composed;
#[allow(dead_code)]
#[path = "../../permguard-data-plane/tests/support/examples.rs"]
mod examples;

use composed::{Recording, capabilities, config, scratch};

#[tokio::test(flavor = "multi_thread")]
async fn test_an_embedded_data_plane_under_production_decides_rego_in_the_dedicated_worker() {
    let working = scratch("dedicated-worker");
    let config = config(&working, &[(SETTING_ASSURANCE_PROFILE, "production")]);
    assert_eq!(
        config.assurance().profile(),
        permguard_core::assurance::AssuranceProfile::Production
    );
    // The example narrowed to Rego, its partition naming the interface it promises, as
    // `production` requires of every partition.
    let mut manifest = examples::manifest_narrowed_to("basics", "rego");
    let interface = manifest
        .profiles
        .values()
        .next()
        .expect("a profile")
        .r#type
        .clone();
    // And the schema of its whole input, which `production` requires a Rego partition to carry:
    // the example reads the request alone, and this one admits any object.
    const INPUT_SCHEMA: &str = permguard_core::domains::artifact::REGO_SCHEMA_V2;
    for partition in manifest.partitions.values_mut() {
        partition.interfaces = vec![interface.clone()];
        partition.schema = false;
        partition.artifacts = vec![permguard_objects::manifest::ArtifactContract {
            r#type: INPUT_SCHEMA.to_owned(),
            required: true,
        }];
    }
    examples::provision_with_artifacts(
        &config.mirrors_directory(),
        "basics",
        manifest,
        ("01a1a166-5743-7014-b7bf-197ed0437363", examples::ZONE),
        ("01a1a166-5747-7d8c-a96a-6e17f5281a37", examples::LEDGER),
        &[(INPUT_SCHEMA, br#"{"type":"object"}"#)],
    );

    let runtime = DataPlane::builder(capabilities(config, Arc::new(Recording::default())))
        .worker_executable(env!("CARGO_BIN_EXE_permguard-evaluation-worker"))
        .start()
        .await
        .expect("the embedded Data Plane starts under production");

    let mut decided = 0;
    for (name, case) in examples::cases("basics") {
        let Some(wanted) = case.expect.decision.as_deref() else {
            continue;
        };
        let rego = ["gateway-permit.json", "boxcarred.json"]
            .iter()
            .any(|request| case.request.ends_with(request));
        if !rego || case.profile.is_some() {
            continue;
        }
        let answer = runtime
            .evaluate(&Actor::Anonymous, examples::request(&name, &case), None)
            .await
            .unwrap_or_else(|refused| panic!("{name}/{}: refused: {refused:?}", case.name));
        assert_eq!(answer.decision, wanted == "permit", "{name}/{}", case.name);
        decided += 1;
    }
    assert_eq!(
        decided, 2,
        "a permit and a deny, each decided in the worker"
    );

    let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
    assert!(shutdown.unfinished.is_empty(), "{:?}", shutdown.unfinished);
}
