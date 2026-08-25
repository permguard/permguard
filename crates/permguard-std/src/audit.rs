// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Implementations of [`permguard_core::AuditSink`].
//!
//! Three of them, for three different answers to "where does this deployment keep its audit trail".
//!
//! * [`TracingAuditSink`] puts records into the process's log stream, which is right when something
//!   else — a collector, a SIEM — is already responsible for keeping them.
//! * [`FileAuditSink`] keeps them itself, on the local filesystem, chained so that a later edit is
//!   detectable and expired on a retention the deployment sets.
//! * [`RecordingAuditSink`] keeps them in memory, so a build can test what it records.
//!
//! A build that has to ship records to a SIEM or a customer's own collector implements the contract
//! and never touches any of these.

mod file;

use std::sync::Mutex;

use permguard_core::AuditError;

pub use file::{Body, FileAuditSink, Record, Verification, verify};

/// What these sinks answer with.
type Result<T> = std::result::Result<T, AuditError>;

use permguard_core::{AuditEvent, AuditSink, BoxFuture, Pseudonymizer, ready};

/// A sink that emits events as `tracing` records.
///
/// It writes nothing on its own: what reaches an operator depends entirely on the subscriber the
/// binary installs, which keeps the command's own output stream clean.
///
/// It is told which product it belongs to, so its records carry the same `service.name` and
/// `service.version` as the lifecycle ones. Without them a monitoring tool filtering by service sees
/// the lifecycle of a deployment and none of its audit trail — the two halves of the same stream,
/// separated by a missing field.
#[derive(Debug)]
pub struct TracingAuditSink {
    service_name: &'static str,
    service_version: &'static str,
}

impl TracingAuditSink {
    /// Builds the tracing-backed sink for a product.
    pub fn new(service_name: &'static str, service_version: &'static str) -> Self {
        Self {
            service_name,
            service_version,
        }
    }
}

impl AuditSink for TracingAuditSink {
    fn name(&self) -> &'static str {
        "tracing"
    }

    /// Records the event, rendering the subject rather than exposing it.
    ///
    /// A principal reaches the stream masked: this build has no way to pseudonymise, and a default
    /// that writes a person's identifier into a log pipeline is not a default worth having. The
    /// `audit.subject.kind` field still says a person was involved, so nothing is hidden except who.
    fn record<'a>(
        &'a self,
        event: &'a AuditEvent<'a>,
        policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, Result<()>> {
        tracing::info!(
            event.name = "audit",
            service.name = self.service_name,
            service.version = self.service_version,
            audit.action = event.action(),
            audit.subject = event.subject().render(policy),
            audit.subject.kind = event.subject().kind(),
            audit.subject.sensitivity = event.subject().sensitivity().as_str(),
            // Absent rather than empty when there is none: a field that is always present and
            // sometimes blank is a field every query has to special-case.
            audit.target = event.target(),
            audit.continuity.id = event.continuity_id(),
            audit.continuity.position = event.continuity_position(),
            "audit"
        );

        ready(Ok(()))
    }
}

/// A sink that keeps events in memory so a test can assert on what was recorded.
///
/// It ships outside `cfg(test)` on purpose: a binary built on these crates needs it to test its own
/// composition without reimplementing it.
#[derive(Debug, Default)]
pub struct RecordingAuditSink {
    events: Mutex<Vec<(String, String)>>,
}

impl RecordingAuditSink {
    /// Builds an empty recording sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the recorded events as `(action, rendered subject)` pairs, oldest first.
    ///
    /// The subject is what the sink would have written, not what it was handed: a test asserting on
    /// this sink is asserting on what actually reaches a log.
    pub fn events(&self) -> Result<Vec<(String, String)>> {
        Ok(self
            .events
            .lock()
            .map_err(|error| {
                AuditError::backend(format!("the recording sink lock is poisoned: {error}"))
            })?
            .clone())
    }
}

impl AuditSink for RecordingAuditSink {
    fn name(&self) -> &'static str {
        "recording"
    }

    fn record<'a>(
        &'a self,
        event: &'a AuditEvent<'a>,
        policy: Option<&'a dyn Pseudonymizer>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            self.events
                .lock()
                .map_err(|error| {
                    AuditError::backend(format!("the recording sink lock is poisoned: {error}"))
                })?
                .push((event.action().to_owned(), event.subject().render(policy)));

            Ok(())
        })
    }
}
