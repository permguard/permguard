// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane embedded in an application (`11-refactoring/1-dependencies.md`, Embedded public
//! API and lifecycle): on the test's own Tokio runtime and with no Plane listener, it decides the
//! repository's examples against their verified mirror as their cases say, records each decision
//! on the stream of the Host the application composed, and shuts down in order. Started outside
//! a runtime, it refuses.
//!
//! A binary of its own: the evaluation path and the decision log are composed once per process.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::future::Future as _;
use std::sync::Arc;
use std::time::Duration;

use permguard_core::authz::Actor;
use permguard_core::lifecycle::{HOST, Phase};
use permguard_data_plane::embedded::{DataPlane, StartError};

mod support;

use support::embedded::{Recording, capabilities, config, scratch};
use support::examples;

/// Owner's plan, RD-5: an application embeds the Data Plane on its own runtime and with no
/// listener; every case of the repository's examples is decided as the case says, each decision
/// is recorded on the Host's stream, and the shutdown drains and stops every service.
#[tokio::test(flavor = "multi_thread")]
async fn an_embedded_data_plane_decides_records_and_shuts_down_in_order() {
    let working = scratch("decides");
    let config = config(&working, &[]);
    // The ids the decision log keys its tags and pseudonyms by are UUIDs, as a catalog gives them.
    examples::provision_as(
        &config.mirrors_directory(),
        "basics",
        "01a1a166-5743-7014-b7bf-197ed0437363",
        "01a1a166-5747-7d8c-a96a-6e17f5281a37",
    );
    let streams = Arc::new(Recording::default());

    let runtime = DataPlane::builder(capabilities(config, Arc::clone(&streams)))
        .start()
        .await
        .expect("the embedded Data Plane starts");
    assert!(runtime.health().is_ready(), "ready once its services run");

    let mut decided = 0;
    for (name, case) in examples::cases("basics") {
        let Some(wanted) = case.expect.decision.as_deref() else {
            continue;
        };
        let answer = runtime
            .evaluate(&Actor::Anonymous, examples::request(&name, &case), None)
            .await
            .unwrap_or_else(|refused| panic!("{name}/{}: refused: {refused:?}", case.name));
        assert_eq!(
            answer.decision,
            wanted == "permit",
            "{name}/{}: expected {wanted}",
            case.name
        );
        decided += 1;
    }
    assert!(decided > 0, "the example claims decisions");

    // The decision log appends on the Host's stream, off the decision's own path.
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while streams.count() < decided && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        streams.count() >= decided,
        "every decision recorded on the Host's stream: {} of {decided}",
        streams.count()
    );

    let health = runtime.health();
    let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
    assert!(
        shutdown.unfinished.is_empty(),
        "everything drained: {:?}",
        shutdown.unfinished
    );
    assert_eq!(health.lifecycle().phase(HOST), Some(Phase::Stopped));
    assert_eq!(health.lifecycle().phase("data"), Some(Phase::Stopped));
    assert!(!health.is_ready(), "a stopped plane takes no work");
}

/// The application owns the runtime: started outside one, the Data Plane refuses at once and
/// leaves nothing running.
#[test]
fn an_embedded_data_plane_refuses_to_start_outside_a_runtime() {
    let working = scratch("no-runtime");
    let start = DataPlane::builder(capabilities(
        config(&working, &[]),
        Arc::new(Recording::default()),
    ))
    .start();
    let mut start = std::pin::pin!(start);
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match start.as_mut().poll(&mut context) {
        std::task::Poll::Ready(Err(StartError::NoRuntime)) => {}
        std::task::Poll::Ready(Err(other)) => panic!("refused for another reason: {other}"),
        std::task::Poll::Ready(Ok(_)) => panic!("started outside a runtime"),
        std::task::Poll::Pending => panic!("waited instead of refusing"),
    }
}
