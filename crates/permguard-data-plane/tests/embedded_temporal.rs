// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The temporal interface of the Data Plane embedded in an application
//! (`11-refactoring/1-dependencies.md`, Embedded public API and lifecycle): with no listener, on
//! the application's runtime, it records each occurrence of the repository's Dogwood example on
//! the Host's event producer and decides it against the history before it, as the example's cases say.
//!
//! The example's cases are one history here, in the order they happened: a read before any login
//! is denied, a login alone permits nothing, a login's response is history and decides nothing, a
//! read inside the window is permitted, one outside it denied, and another principal's read
//! denied, since it ranges over another history.
//!
//! A binary of its own: the evaluation path and the event history are composed once per process.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use permguard_core::authz::Actor;
use permguard_core::config::{
    SETTING_EVENTS_ALLOWED_LATENESS, SETTING_EVENTS_ENABLED, SETTING_EXPERIMENTAL_DOGWOOD,
};
use permguard_data_plane::embedded::{DataPlane, SubmitRequest};

mod support;

use support::embedded::{Recording, capabilities, config, scratch};
use support::examples;

const EXAMPLE: &str = "dogwood-session-access";

#[tokio::test(flavor = "multi_thread")]
async fn an_embedded_data_plane_decides_each_occurrence_against_the_history_before_it() {
    let working = scratch("temporal");
    let config = config(
        &working,
        &[
            (SETTING_EVENTS_ENABLED, "true"),
            (SETTING_EXPERIMENTAL_DOGWOOD, "true"),
            // The example's history spans an hour and ten minutes, and ends a minute ago.
            (SETTING_EVENTS_ALLOWED_LATENESS, "2h"),
        ],
    );
    examples::provision_named(
        &config.mirrors_directory(),
        EXAMPLE,
        examples::manifest(EXAMPLE),
        ("01a3185c-5000-7000-8000-000000000a01", "acme"),
        ("01a3185c-5000-7000-8000-000000000b01", "agent-governance"),
    );
    let runtime = DataPlane::builder(capabilities(config, Arc::new(Recording::default())))
        .start()
        .await
        .expect("the embedded Data Plane starts with an event history");
    assert!(runtime.health().is_ready(), "ready once its services run");

    let timeline = examples::timeline(EXAMPLE, 60);
    let (mut permitted, mut denied, mut history) = (0, 0, 0);
    for occurrence in &timeline {
        let request: SubmitRequest = serde_json::from_value(occurrence.submission.clone())
            .unwrap_or_else(|error| panic!("{}: not a submission: {error}", occurrence.file));
        let answer = runtime
            .submit(&Actor::Anonymous, request)
            .await
            .unwrap_or_else(|refused| panic!("{}: refused: {refused:?}", occurrence.file));
        assert_eq!(
            answer.decision, occurrence.decision,
            "{}: decided {:?}, and the example says {:?}",
            occurrence.file, answer.decision, occurrence.decision
        );
        match occurrence.decision {
            Some(true) => permitted += 1,
            Some(false) => denied += 1,
            None => history += 1,
        }
    }
    assert!(
        permitted >= 1 && denied >= 3 && history >= 1,
        "the example permits, denies and records: {permitted}, {denied}, {history}"
    );
    let shutdown = runtime.shutdown(Duration::from_secs(10)).await;
    assert!(
        shutdown.unfinished.is_empty(),
        "everything drained: {:?}",
        shutdown.unfinished
    );
}
