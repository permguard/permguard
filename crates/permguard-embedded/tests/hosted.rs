// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! An application that embeds the Data Plane and composes no Host by hand: from the configuration
//! file a server reads, the Host is opened on its volume by the headless runtime, the Data Plane
//! runs as its one Plane with no listener, the repository's example is decided as its cases say,
//! and the application's own signal ends it in order.
//!
//! | What the application does         | What it proves                                           |
//! | --------------------------------- | -------------------------------------------------------- |
//! | builds, reads the file, serves    | the Host composed for it: identity, rings, authorization |
//! | awaits the handle, decides        | the pipeline both transports use, with no transport      |
//! | asks without the public grant     | the Host's authorization decides, default deny           |
//! | resolves its shutdown future      | drained and stopped in order, the volume released        |
//!
//! A binary of its own: the evaluation path is composed once per process.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;

use permguard_core::{BuildSettings, ProductIdentity};
use permguard_embedded::{Actor, Embedded};

#[allow(dead_code)]
#[path = "../../permguard-data-plane/tests/support/examples.rs"]
mod examples;

const ZONE_ID: &str = "01a1a166-5743-7014-b7bf-197ed0437363";
const LEDGER_ID: &str = "01a1a166-5747-7d8c-a96a-6e17f5281a37";
/// A second ledger of the same example, which the configuration grants nobody.
const CLOSED_LEDGER_ID: &str = "01a1a166-5747-7d8c-a96a-6e17f5281a38";

/// A configuration file and the volume it names, each the test's own: the server's contract,
/// with no listener asked for and one public grant, the evaluations of one ledger.
fn fixture() -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("permguard-embedded-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("the fixture directory");
    let volume = dir.join("volume");
    let file = dir.join("config.yml");
    std::fs::write(
        &file,
        format!(
            "assurance:\n  profile: development\nworking_dir: {}\nhost:\n  addr: \"off\"\n  \
             authz:\n    public:\n      - operations: [decision.evaluate]\n        selector: \
             \"plane/data/zone/{ZONE_ID}/ledger/{LEDGER_ID}\"\n",
            volume.to_str().expect("a UTF-8 path")
        ),
    )
    .expect("the configuration file");
    (file, volume)
}

#[tokio::test(flavor = "multi_thread")]
async fn test_an_application_embeds_the_data_plane_over_a_host_composed_for_it() {
    let (file, volume) = fixture();
    let (embedded, started) = Embedded::builder(
        ProductIdentity::new("an-application", "An Application", "", "", ""),
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
    )
    .build()
    .expect("the build's languages are registered once");
    let config = embedded.config(&file).expect("the server's configuration");
    examples::provision_as(&config.mirrors_directory(), "basics", ZONE_ID, LEDGER_ID);
    // The same example again, as a ledger the configuration grants nobody.
    examples::provision_named(
        &config.mirrors_directory(),
        "basics",
        examples::manifest("basics"),
        (ZONE_ID, examples::ZONE),
        (CLOSED_LEDGER_ID, "closed"),
    );

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let application = async {
        // Nothing started when the Host ended first: its own result, below, says why.
        let handle = started.handle().await?;
        assert!(handle.health().is_ready(), "ready once its services run");

        let mut decided = 0;
        for (name, case) in examples::cases("basics") {
            let Some(wanted) = case.expect.decision.as_deref() else {
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

        // The Host's authorization decides before any policy is read: the same question of the
        // ledger nobody was granted is refused, whatever its policies would say.
        let (name, case) = examples::cases("basics")
            .into_iter()
            .find(|(_, case)| case.expect.decision.as_deref() == Some("permit"))
            .expect("a case the example permits");
        let mut asked = serde_json::to_value(examples::request(&name, &case)).expect("JSON");
        asked["ledger"] = serde_json::Value::String("closed".to_owned());
        let refused = handle
            .evaluate(
                &Actor::Anonymous,
                serde_json::from_value(asked).expect("a request"),
                None,
            )
            .await;
        assert!(
            refused.is_err(),
            "a ledger nobody was granted answered: {refused:?}"
        );
        stop.send(()).expect("the Host is still running");
        Some(handle)
    };

    let (served, handle) = tokio::join!(
        embedded.serve(&config, &file, async {
            let _ = stopped.await;
        }),
        application
    );
    served.expect("the Host started, drained and stopped");
    let handle = handle.expect("the Plane started on the Host composed for it");
    assert!(!handle.health().is_ready(), "a stopped Host takes no work");

    // The volume is released, and holds the identity the start provisioned under `development`.
    let claimed = permguard_host::storage::volume::Volume::claim(
        &volume,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("the volume is released once the Host returns");
    assert!(
        permguard_host::identity::witness_of(&claimed)
            .expect("the identity is read")
            .is_some(),
        "the start provisioned no identity"
    );
}
