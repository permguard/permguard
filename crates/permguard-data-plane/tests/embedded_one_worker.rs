// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The one-worker embedded profile (`11-refactoring/1-dependencies.md`, Resource budgets; the
//! crate boundaries refactoring, RD-17): an application that configures one evaluation at a time,
//! none waiting and one piece of blocking work, on a single-threaded runtime of its own.
//!
//! | What is bounded                   | By                                 | What this proves                 |
//! | --------------------------------- | ---------------------------------- | -------------------------------- |
//! | the evaluations run at once       | `PERMGUARD_EVALUATION_CONCURRENCY` | one, and decisions still answer  |
//! | the workers partitions fan out on | the same setting                   | none: no evaluating thread more  |
//! | the storage and evidence work     | `PERMGUARD_MAX_BLOCKING`           | one, and every decision recorded |
//!
//! The profile changes no answer: every case of the repository's examples is decided as its case
//! says. A binary of its own: the evaluation path and its pools are composed once per process.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use permguard_core::authz::Actor;
use permguard_core::config::{
    SETTING_EVALUATION_CONCURRENCY, SETTING_EVALUATION_QUEUE, SETTING_MAX_BLOCKING,
};
use permguard_data_plane::embedded::DataPlane;
use permguard_languages::fanout::Fanout;

mod support;

use support::embedded::{Recording, capabilities, config, scratch};
use support::examples;

#[tokio::test]
async fn an_embedded_data_plane_decides_with_one_worker_and_no_fan_out() {
    let working = scratch("one-worker");
    let config = config(
        &working,
        &[
            (SETTING_EVALUATION_CONCURRENCY, "1"),
            (SETTING_EVALUATION_QUEUE, "1"),
            (SETTING_MAX_BLOCKING, "1"),
        ],
    );
    assert_eq!(config.evaluation_concurrency(), 1);
    assert_eq!(config.max_blocking(), 1);
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
        .expect("the embedded Data Plane starts under the one-worker profile");
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

    // The start bound the pool before anything decided: it holds no worker, so the one
    // evaluation slot is the one thread that evaluates.
    assert_eq!(
        Fanout::shared().workers(),
        0,
        "a one-worker profile started evaluation workers"
    );

    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while streams.count() < decided && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        streams.count() >= decided,
        "every decision recorded on the Host's stream: {} of {decided}",
        streams.count()
    );

    let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
    assert!(
        shutdown.unfinished.is_empty(),
        "everything drained: {:?}",
        shutdown.unfinished
    );
}
