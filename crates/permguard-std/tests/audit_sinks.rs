#![cfg(feature = "audit")]
// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What each sink writes, and what it refuses to write in the clear.

use std::io::Write;
use std::sync::{Arc, Mutex};

use permguard_core::{AuditEvent, AuditOutcome, AuditPhase, AuditSink, Pseudonymizer};
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

/// The log lines a subscriber wrote, shared with the test.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("the capture lock")
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The `audit` lines `events` produce through the tracing sink, as JSON.
fn logged(events: &[AuditEvent<'_>]) -> Vec<serde_json::Value> {
    let logs = Captured::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .flatten_event(true)
        .with_writer(move || writer.clone())
        .finish();
    let sink = TracingAuditSink::new("demo-x", "9.9.9");
    tracing::subscriber::with_default(subscriber, || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("a runtime");
        for event in events {
            runtime
                .block_on(sink.record(event, None))
                .expect("the event is recorded");
        }
    });
    let bytes = logs.0.lock().expect("the capture lock").clone();
    String::from_utf8(bytes)
        .expect("utf-8 lines")
        .lines()
        .map(|line| serde_json::from_str(line).expect("a JSON line"))
        .collect()
}

#[test]
fn test_a_log_line_tells_an_intent_from_its_result_and_a_refusal_from_a_grant() {
    // BUG-0197: a refused approval read, in the log, exactly like a granted one.
    let operation = [7u8; 16];
    let lines = logged(&[
        AuditEvent::principal("host.membership.approved", "v1:abc")
            .in_operation(&operation, AuditPhase::Intent),
        AuditEvent::principal("host.membership.approved", "v1:abc")
            .in_operation(&operation, AuditPhase::Failed)
            .with_outcome(AuditOutcome::Failed),
        AuditEvent::principal("host.membership.approved", "v1:abc")
            .in_operation(&operation, AuditPhase::Applied),
        AuditEvent::system("host.join.refused", "permguard"),
    ]);
    let said: Vec<(Option<&str>, Option<&str>)> = lines
        .iter()
        .map(|line| (line["audit.phase"].as_str(), line["audit.outcome"].as_str()))
        .collect();
    assert_eq!(
        said,
        vec![
            (Some("intent"), Some("ok")),
            (Some("failed"), Some("failed")),
            (Some("applied"), Some("ok")),
            // A simple observation has no phase, and an action named `.refused` reads `refused`,
            // as the trail records it.
            (None, Some("refused")),
        ]
    );
}
