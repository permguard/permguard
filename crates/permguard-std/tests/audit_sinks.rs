#![cfg(feature = "audit")]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each sink writes, and what it refuses to write in the clear.

use permguard_core::{AuditEvent, AuditSink, Pseudonymizer};
use permguard_std::audit::{RecordingAuditSink, TracingAuditSink};

#[tokio::test]
async fn test_the_tracing_sink_accepts_events_and_names_itself() {
    let sink = TracingAuditSink::new("demo-x", "9.9.9");

    sink.record(&AuditEvent::system("server.start", "permguard"), None)
        .await
        .expect("the event is recorded");

    assert_eq!(sink.name(), "tracing");
}

#[tokio::test]
async fn test_the_recording_sink_keeps_events_in_order() {
    let sink = RecordingAuditSink::new();

    sink.record(&AuditEvent::system("first", "a"), None)
        .await
        .expect("the first event is recorded");
    sink.record(&AuditEvent::system("second", "b"), None)
        .await
        .expect("the second event is recorded");

    assert_eq!(
        sink.events().expect("the events are readable"),
        vec![
            ("first".to_owned(), "a".to_owned()),
            ("second".to_owned(), "b".to_owned()),
        ]
    );
}

#[tokio::test]
async fn test_a_new_recording_sink_has_recorded_nothing() {
    assert!(
        RecordingAuditSink::new()
            .events()
            .expect("the events are readable")
            .is_empty()
    );
}

#[tokio::test]
async fn test_a_principal_reaches_neither_sink_in_the_clear() {
    let sink = RecordingAuditSink::new();

    sink.record(
        &AuditEvent::principal("session.open", "nicola@nitroagility.com"),
        None,
    )
    .await
    .expect("the event is recorded");

    let recorded = sink.events().expect("the events are readable");
    assert_eq!(recorded.len(), 1);
    assert!(!recorded[0].1.contains("nicola"));
    assert_eq!(recorded[0].1, permguard_core::redact::MASK);
}

/// A policy of the kind a deployment composes.
struct StubPolicy;

impl Pseudonymizer for StubPolicy {
    fn key_version(&self) -> &str {
        "v1"
    }

    fn pseudonymize(&self, value: &str) -> String {
        format!("v1:{}", value.len())
    }
}

#[tokio::test]
async fn test_with_a_policy_a_principal_is_recorded_as_a_stable_token() {
    let sink = RecordingAuditSink::new();

    sink.record(
        &AuditEvent::principal("session.open", "nicola@nitroagility.com"),
        Some(&StubPolicy),
    )
    .await
    .expect("the event is recorded");
    sink.record(
        &AuditEvent::principal("session.close", "nicola@nitroagility.com"),
        Some(&StubPolicy),
    )
    .await
    .expect("the event is recorded");

    let recorded = sink.events().expect("the events are readable");
    assert!(!recorded[0].1.contains("nicola"));
    // The same person keeps the same token, which is what makes the trail followable.
    assert_eq!(recorded[0].1, recorded[1].1);
    assert!(recorded[0].1.starts_with("v1:"));
}

#[tokio::test]
async fn test_both_implementations_are_usable_through_the_trait_object() {
    let sinks: Vec<Box<dyn AuditSink>> = vec![
        Box::new(TracingAuditSink::new("demo-x", "9.9.9")),
        Box::new(RecordingAuditSink::new()),
    ];

    for sink in &sinks {
        sink.record(&AuditEvent::system("server.start", "permguard"), None)
            .await
            .expect("the event is recorded");
    }
}
