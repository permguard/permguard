// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Decision-path audit without putting the audit sink on the decision path.
//!
//! A decision log configured `closed` is part of the answer contract: a request
//! may not leave before its decision record is durable. The operational audit
//! trail is different in this plane: an audit write failure has always been
//! reported and the decision still answered. This worker keeps that contract
//! honest under load: bounded, observable, and drained after listeners stop.

use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Result;
use permguard_core::{
    AuditError, AuditRecorder, BoxFuture, Metrics, ServerContext, Service, Subject, ready,
};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};

use super::measure;

const COMPONENT: &str = "data-plane";
const MIN_CAPACITY: usize = 256;
const MAX_CAPACITY: usize = 16_384;

static DECISION_AUDIT: OnceLock<Option<Arc<DecisionAudit>>> = OnceLock::new();

#[derive(Debug)]
struct Entry {
    subject: String,
    target: String,
}

struct Running {
    task: JoinHandle<()>,
    stop: watch::Sender<bool>,
}

/// A bounded audit queue for authorization decisions.
pub struct DecisionAudit {
    sender: mpsc::Sender<Entry>,
    running: Mutex<Option<Running>>,
    metrics: Metrics,
}

impl DecisionAudit {
    /// Starts a worker that records queued decision audit entries.
    pub fn start(recorder: AuditRecorder, metrics: Metrics, capacity: usize) -> Arc<Self> {
        let capacity = capacity.clamp(MIN_CAPACITY, MAX_CAPACITY);
        let (sender, receiver) = mpsc::channel(capacity);
        let (stop, stopped) = watch::channel(false);
        let worker_metrics = metrics.clone();
        let task = tokio::spawn(async move {
            run(recorder, receiver, stopped, worker_metrics).await;
        });

        Arc::new(Self {
            sender,
            running: Mutex::new(Some(Running { task, stop })),
            metrics,
        })
    }

    /// Queue one decision audit record, or drop it visibly when backpressure says to.
    pub fn record(&self, subject: String, target: String) {
        match self.sender.try_send(Entry { subject, target }) {
            Ok(()) => {
                self.metrics
                    .count(&measure::AUDIT_RECORDS, &[("outcome", "queued")]);
                self.publish_depth();
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.metrics
                    .count(&measure::AUDIT_RECORDS, &[("outcome", "dropped")]);
                self.publish_depth();
                warn!(
                    event.name = "authz.audit_dropped",
                    component = COMPONENT,
                    reason = "queue_full",
                    "a decision was answered and its audit queue was full"
                );
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.metrics
                    .count(&measure::AUDIT_RECORDS, &[("outcome", "dropped")]);
                self.publish_depth();
                warn!(
                    event.name = "authz.audit_dropped",
                    component = COMPONENT,
                    reason = "worker_stopped",
                    "a decision was answered after the audit worker stopped"
                );
            }
        }
    }

    /// Stops the worker after draining whatever was already queued.
    pub async fn stop(&self) {
        let running = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => {
                warn!(
                    event.name = "authz.audit_stop_failed",
                    component = COMPONENT,
                    "the decision audit worker lock is poisoned"
                );
                return;
            }
        };

        let Some(running) = running else {
            return;
        };
        let _ = running.stop.send(true);
        match running.task.await {
            Ok(()) => debug!(
                event.name = "authz.audit_stopped",
                component = COMPONENT,
                "no longer recording decision audit entries"
            ),
            Err(error) => warn!(
                event.name = "authz.audit_stop_failed",
                component = COMPONENT,
                error = %error,
                "the decision audit worker did not finish"
            ),
        }
        self.publish_depth();
    }

    fn publish_depth(&self) {
        self.metrics.set(
            &measure::AUDIT_QUEUE_DEPTH,
            &[],
            self.sender
                .max_capacity()
                .saturating_sub(self.sender.capacity()) as f64,
        );
    }
}

/// Starts and drains the decision-audit worker with the rest of the data plane.
pub struct DecisionAuditService;

impl Default for DecisionAuditService {
    fn default() -> Self {
        Self::new()
    }
}

impl DecisionAuditService {
    /// Builds the service.
    pub fn new() -> Self {
        Self
    }
}

impl Service for DecisionAuditService {
    fn name(&self) -> &'static str {
        "authz-audit"
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let _ = decision_audit(context);

            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let audit = DECISION_AUDIT.get().and_then(Clone::clone);
        let Some(audit) = audit else {
            return ready(Ok(()));
        };

        Box::pin(async move {
            audit.stop().await;

            Ok(())
        })
    }
}

/// Returns the decision-audit worker for this process, when audit is composed.
pub fn decision_audit(context: &ServerContext<'_>) -> Option<Arc<DecisionAudit>> {
    DECISION_AUDIT
        .get_or_init(|| {
            let recorder = context.recorder().cloned()?;
            let capacity = capacity(context);
            info!(
                event.name = "authz.audit_worker",
                component = COMPONENT,
                capacity,
                "decision audit records are queued off the request path"
            );

            Some(DecisionAudit::start(
                recorder,
                context.metrics().clone(),
                capacity,
            ))
        })
        .clone()
}

fn capacity(context: &ServerContext<'_>) -> usize {
    let requests = context.config().limits().concurrent_requests() as usize;
    let evaluations = context.config().authz_max_evaluations();

    requests
        .saturating_mul(evaluations)
        .clamp(MIN_CAPACITY, MAX_CAPACITY)
}

async fn run(
    recorder: AuditRecorder,
    mut receiver: mpsc::Receiver<Entry>,
    mut stopped: watch::Receiver<bool>,
    metrics: Metrics,
) {
    loop {
        tokio::select! {
            entry = receiver.recv() => {
                let Some(entry) = entry else {
                    break;
                };
                record_one(recorder.clone(), entry, &metrics).await;
            }
            changed = stopped.changed() => {
                if changed.is_err() || *stopped.borrow() {
                    while let Ok(entry) = receiver.try_recv() {
                        record_one(recorder.clone(), entry, &metrics).await;
                    }
                    break;
                }
            }
        }
    }
}

async fn record_one(recorder: AuditRecorder, entry: Entry, metrics: &Metrics) {
    let handle = tokio::runtime::Handle::current();
    let outcome = tokio::task::spawn_blocking(move || {
        handle.block_on(async move {
            recorder
                .record_on(
                    "authz.decision",
                    Subject::Principal(entry.subject.as_str()),
                    &entry.target,
                )
                .await
        })
    })
    .await;

    match outcome {
        Ok(Ok(())) => {
            metrics.count(&measure::AUDIT_RECORDS, &[("outcome", "written")]);
        }
        Ok(Err(error)) => report_failure(error, metrics),
        Err(error) => report_failure(
            AuditError::backend(format!("the decision audit worker panicked: {error}")),
            metrics,
        ),
    }
}

fn report_failure(error: AuditError, metrics: &Metrics) {
    metrics.count(&measure::AUDIT_RECORDS, &[("outcome", "failed")]);
    warn!(
        event.name = "authz.audit_failed",
        component = COMPONENT,
        error = %error,
        "a decision was answered and its audit record was not written"
    );
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::Duration;

    use permguard_core::{AuditEvent, AuditSink, BoxFuture, Pseudonymizer};

    use super::*;

    struct BlockingSink {
        release: Arc<AtomicBool>,
    }

    impl AuditSink for BlockingSink {
        fn name(&self) -> &'static str {
            "blocking"
        }

        fn record<'a>(
            &'a self,
            _event: &'a AuditEvent<'a>,
            _policy: Option<&'a dyn Pseudonymizer>,
        ) -> BoxFuture<'a, std::result::Result<(), AuditError>> {
            Box::pin(async move {
                while !self.release.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }

                Ok(())
            })
        }
    }

    #[tokio::test]
    async fn queuing_a_decision_does_not_wait_for_the_sink() {
        let release = Arc::new(AtomicBool::new(false));
        let sink = Arc::new(BlockingSink {
            release: Arc::clone(&release),
        });
        let audit = DecisionAudit::start(AuditRecorder::new(sink), Metrics::none(), 1);

        tokio::time::timeout(Duration::from_secs(1), async {
            audit.record("alice".to_owned(), "ledger read decision=true".to_owned());
        })
        .await
        .expect("queueing does not wait for the blocked sink");

        release.store(true, Ordering::SeqCst);
        audit.stop().await;
    }
}
