// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What an audit subject is, and what may be done with it.
//!
//! Here rather than beside the code because the taxonomy is the part worth reading as a whole: five
//! kinds, three sensitivities, and one rule per pair about how each may appear in a record.

use anyhow::anyhow;
use permguard_core::AuditError;
use std::sync::Mutex;

use permguard_core::{AuditEvent, AuditSink, BoxFuture, Pseudonymizer, Sensitivity, Subject};

/// A sink written against the contract from outside any implementation crate.
#[derive(Default)]
struct StubSink {
    actions: Mutex<Vec<String>>,
}

impl AuditSink for StubSink {
    fn name(&self) -> &'static str {
        "stub"
    }

    fn record<'a>(
        &'a self,
        event: &'a AuditEvent<'a>,
        _policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, std::result::Result<(), AuditError>> {
        Box::pin(async move {
            self.actions
                .lock()
                .map_err(|_| AuditError::backend(anyhow!("poisoned")))?
                .push(event.action().to_owned());

            Ok(())
        })
    }
}

#[test]
fn test_an_event_carries_what_happened_and_to_what() {
    let event = AuditEvent::system("server.start", "permguard");

    assert_eq!(event.action(), "server.start");
    assert_eq!(event.subject(), Subject::System("permguard"));
    assert_eq!(event.subject().value(), Some("permguard"));
}

#[test]
fn test_a_continuity_and_a_capability_are_neither_people_nor_components() {
    let continuity = Subject::Continuity("c-8f3a");
    let capability = Subject::Capability("key:9d21");

    for subject in [continuity, capability] {
        assert!(!subject.is_personal());
        assert_eq!(subject.sensitivity(), Sensitivity::Pseudonymous);
        // Already opaque, so they render as themselves: recognising the same continuity across
        // records is the entire reason they are in the trail.
        assert_eq!(subject.render(None), subject.value().unwrap_or_default());
    }

    assert_eq!(continuity.kind(), "continuity");
    assert_eq!(capability.kind(), "capability");
}

#[test]
fn test_an_anonymous_subject_names_nothing_and_says_so() {
    let subject = Subject::Anonymous;

    assert_eq!(subject.value(), None);
    assert_eq!(subject.kind(), "anonymous");
    assert_eq!(subject.sensitivity(), Sensitivity::Public);
    assert_eq!(subject.to_string(), "-");
}

#[test]
fn test_a_pseudonymiser_transforms_a_principal_and_leaves_the_opaque_ones_alone() {
    let policy = StubPolicy;

    assert_ne!(
        Subject::Principal("nicola@nitroagility.com").render(Some(&policy)),
        "nicola@nitroagility.com"
    );
    assert_eq!(
        Subject::Continuity("c-8f3a").render(Some(&policy)),
        "c-8f3a"
    );
    assert_eq!(
        Subject::Capability("key:9d21").render(Some(&policy)),
        "key:9d21"
    );
}

#[test]
fn test_a_system_subject_is_not_personal_data_and_renders_as_itself() {
    let subject = Subject::System("default");

    assert!(!subject.is_personal());
    assert_eq!(subject.kind(), "system");
    assert_eq!(subject.sensitivity(), Sensitivity::Public);
    assert_eq!(subject.to_string(), "default");
}

#[test]
fn test_a_principal_is_personal_data_and_never_renders_readable() {
    let subject = Subject::Principal("nicola@nitroagility.com");

    assert!(subject.is_personal());
    assert_eq!(subject.kind(), "principal");
    assert_eq!(subject.to_string(), permguard_core::redact::MASK);
    assert!(!format!("{subject}").contains("nicola"));
}

#[test]
fn test_two_principals_render_identically_whatever_they_were() {
    let short = Subject::Principal("a@b.c");
    let long = Subject::Principal("a-very-long-account-identifier@example.com");

    assert_eq!(short.to_string(), long.to_string());
}

#[test]
fn test_reading_a_principal_in_the_clear_takes_an_explicit_call() {
    let subject = Subject::Principal("nicola@nitroagility.com");

    // `value()` is the deliberate path; `Display` is the accidental one.
    assert_eq!(subject.value(), Some("nicola@nitroagility.com"));
    assert_ne!(Some(subject.to_string().as_str()), subject.value());
}

/// A policy of the kind a deployment would compose.
struct StubPolicy;

impl Pseudonymizer for StubPolicy {
    fn key_version(&self) -> &str {
        "v1"
    }

    fn pseudonymize(&self, value: &str) -> String {
        format!("v1:{}", value.len())
    }
}

#[test]
fn test_without_a_policy_a_principal_renders_masked() {
    let subject = Subject::Principal("nicola@nitroagility.com");

    assert_eq!(subject.render(None), permguard_core::redact::MASK);
}

#[test]
fn test_with_a_policy_a_principal_renders_as_a_stable_token() {
    let subject = Subject::Principal("nicola@nitroagility.com");
    let policy = StubPolicy;

    let first = subject.render(Some(&policy));
    let second = subject.render(Some(&policy));

    assert_eq!(first, second);
    assert!(!first.contains("nicola"));
}

#[test]
fn test_a_system_subject_renders_as_itself_with_or_without_a_policy() {
    let subject = Subject::System("default");

    assert_eq!(subject.render(None), "default");
    assert_eq!(subject.render(Some(&StubPolicy)), "default");
}

#[tokio::test]
async fn test_the_contract_is_implementable_from_outside_and_usable_as_a_trait_object() {
    let sink: Box<dyn AuditSink> = Box::new(StubSink::default());

    sink.record(&AuditEvent::system("server.start", "permguard"), None)
        .await
        .expect("the event is recorded");

    assert_eq!(sink.name(), "stub");
    sink.shutdown().await.expect("the default releases nothing");
}
