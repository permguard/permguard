// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each profile of the application does, built by itself.
//!
//! | Profile                     | What is proven                                                  |
//! | --------------------------- | --------------------------------------------------------------- |
//! | no language                 | the start is refused: a Data Plane decides with a language      |
//! | `cedar`                     | a Host with no listener, a ledger decided, an ordered shutdown  |
//! | without `decision-evidence` | a configuration that turns the log on is refused, by the name   |
//! | without `event-evidence`    | a configuration that turns the events on is refused, by the name |
//!
//! A test a binary: the evaluation path is composed once per process.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use permguard_core::{BuildSettings, ProductIdentity};
use permguard_native_fixture::Embedded;

#[allow(dead_code)]
#[path = "../../../crates/permguard-data-plane/tests/support/examples.rs"]
mod examples;

const ZONE_ID: &str = "01a1a166-5743-7014-b7bf-197ed0437363";
const LEDGER_ID: &str = "01a1a166-5747-7d8c-a96a-6e17f5281a37";

/// A configuration file and the volume it names: the server's contract, with no listener asked
/// for, one public grant, and whatever `more` adds.
fn fixture(tag: &str, more: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "permguard-native-fixture-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the fixture directory");
    let volume = dir.join("volume");
    let file = dir.join("config.yml");
    std::fs::write(
        &file,
        format!(
            "assurance:\n  profile: development\nworking_dir: {}\nhost:\n  addr: \"off\"\n  \
             authz:\n    public:\n      - operations: [decision.evaluate]\n        selector: \
             \"plane/data/zone/{ZONE_ID}/ledger/{LEDGER_ID}\"\n{more}",
            volume.to_str().expect("a UTF-8 path")
        ),
    )
    .expect("the configuration file");
    (file, volume)
}

fn application() -> (Embedded, permguard_embedded::Started) {
    Embedded::builder(
        ProductIdentity::new("an-application", "An Application", "", "", ""),
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
    )
    .build()
    .expect("the build's languages are registered once")
}

/// What a start that must be refused says.
#[allow(dead_code)]
async fn refusal(tag: &str, more: &str) -> String {
    let (file, _) = fixture(tag, more);
    let (embedded, _started) = application();
    let config = match embedded.config(&file) {
        Ok(config) => config,
        Err(refused) => return format!("{refused:#}"),
    };
    let refused = embedded
        .serve(&config, &file, std::future::pending::<()>())
        .await
        .expect_err("the start is refused");
    format!("{refused:#}")
}

#[cfg(not(any(feature = "cedar", feature = "rego")))]
#[tokio::test(flavor = "multi_thread")]
async fn with_no_language_the_start_is_refused() {
    let said = refusal("no-language", "").await;
    assert!(said.contains("no policy language"), "{said}");
}

#[cfg(feature = "cedar")]
#[tokio::test(flavor = "multi_thread")]
async fn the_data_plane_decides_over_a_host_with_no_listener_and_stops_in_order() {
    use permguard_native_fixture::Actor;

    let (file, _) = fixture("decides", "");
    let (embedded, started) = application();
    let config = embedded.config(&file).expect("the server's configuration");
    // The example narrowed to the one language this build carries.
    examples::provision_manifest(
        &config.mirrors_directory(),
        "basics",
        examples::manifest_narrowed_to("basics", "cedar"),
        ZONE_ID,
        LEDGER_ID,
    );

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let asks = async {
        let handle = started.handle().await?;
        assert!(handle.health().is_ready(), "ready once its services run");
        let mut decided = 0;
        // The cases Cedar answers by itself: they ask the default profile and carry its entities.
        let alone = |case: &examples::Case| {
            case.profile.is_none()
                && std::path::Path::new(&case.request)
                    .file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|request| ["permit.json", "deny.json"].contains(&request))
        };
        for (name, case) in examples::cases("basics") {
            let Some(wanted) = case.expect.decision.as_deref().filter(|_| alone(&case)) else {
                continue;
            };
            let answer = handle
                .evaluate(&Actor::Anonymous, examples::request(&name, &case), None)
                .await
                .unwrap_or_else(|refused| panic!("{name}/{}: refused: {refused:?}", case.name));
            assert_eq!(answer.decision, wanted == "permit", "{name}/{}", case.name);
            decided += 1;
        }
        assert!(decided > 0, "the example claims decisions");
        stop.send(()).expect("the Host is still running");
        Some(handle)
    };
    let (served, handle) = tokio::join!(
        embedded.serve(&config, &file, async {
            let _ = stopped.await;
        }),
        asks
    );
    served.expect("the Host started, drained and stopped");
    let handle = handle.expect("the Plane started on the Host composed for it");
    assert!(!handle.health().is_ready(), "a stopped Host takes no work");
}

#[cfg(all(feature = "cedar", not(feature = "decision-evidence")))]
#[tokio::test(flavor = "multi_thread")]
async fn a_decision_log_this_build_does_not_keep_is_refused_by_name() {
    let said = refusal(
        "no-log",
        "operations:\n  secrets:\n    coordinator_root_ref: coordinator-root\n  audit:\n    pseudonym:\n      enabled: \"true\"\n      key_ref: audit-pseudonym\ndataPlane:\n  decisions:\n    log:\n      enabled: \"true\"\n",
    )
    .await;
    assert!(said.contains("decision-evidence"), "{said}");
}

#[cfg(all(feature = "cedar", not(feature = "event-evidence")))]
#[tokio::test(flavor = "multi_thread")]
async fn a_temporal_interface_this_build_does_not_serve_is_refused_by_name() {
    let said = refusal(
        "no-events",
        "dataPlane:\n  events:\n    enabled: \"true\"\n",
    )
    .await;
    assert!(said.contains("event-evidence"), "{said}");
}
