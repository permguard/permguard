// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the default host does between starting and stopping, and in what order.
//!
//! Here rather than beside the code because the interesting cases are services that misbehave — one
//! that will not start, one that will not stop, one that takes longer than any budget — and each is a
//! type of its own.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Result, bail};

use permguard_core::{
    BoxFuture, Config, ProductIdentity, ServerContext, ServerHost, Service, ready,
};
use permguard_server::DefaultServerHost;
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;

fn identity() -> ProductIdentity {
    ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>")
}

/// A shutdown that has already happened, for the runs that only care about the sequence.
fn at_once() -> BoxFuture<'static, ()> {
    Box::pin(std::future::ready(()))
}

/// A service that starts and stops without doing anything else.
struct StubService(&'static str);

impl Service for StubService {
    fn name(&self) -> &'static str {
        self.0
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        ready(Ok(()))
    }
}

/// A service that refuses to start, to show the failure reaches the caller named.
struct FailingStart;

impl Service for FailingStart {
    fn name(&self) -> &'static str {
        "failing-start"
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { bail!("the port is already bound") })
    }
}

/// A service that refuses to stop, to show shutdown continues past it.
struct FailingStop;

impl Service for FailingStop {
    fn name(&self) -> &'static str {
        "failing-stop"
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        ready(Ok(()))
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async { bail!("the connection pool would not drain") })
    }
}

/// A service that takes longer to stop than any budget a test will give it.
struct SlowStop;

impl Service for SlowStop {
    fn name(&self) -> &'static str {
        "slow-stop"
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        ready(Ok(()))
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;

            Ok(())
        })
    }
}

/// A service that writes down when it was started and stopped, to check the ordering.
struct Ordered {
    name: &'static str,
    journal: Arc<Mutex<Vec<String>>>,
}

impl Ordered {
    fn record(&self, what: &str) -> Result<()> {
        self.journal
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned"))?
            .push(format!("{} {what}", self.name));

        Ok(())
    }
}

impl Service for Ordered {
    fn name(&self) -> &'static str {
        self.name
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.record("start") })
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move { self.record("stop") })
    }
}

/// Runs the default host to completion with the given services.
async fn run_with(services: &[Box<dyn Service>]) -> (Result<()>, RecordingAuditSink) {
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();

    let outcome = {
        let context =
            ServerContext::new(identity(), &config, &storage, &audit).with_services(services);

        DefaultServerHost::new().run(&context, at_once()).await
    };

    (outcome, audit)
}

/// The action of every event a run recorded, in order.
fn actions(audit: &RecordingAuditSink) -> Vec<String> {
    audit
        .events()
        .expect("the events are readable")
        .into_iter()
        .map(|(action, _)| action)
        .collect()
}

#[tokio::test]
async fn test_a_run_without_services_starts_and_stops_the_server() {
    let (outcome, audit) = run_with(&[]).await;

    outcome.expect("the default host runs");
    assert_eq!(actions(&audit), vec!["server.start", "server.stop"]);
}

#[tokio::test]
async fn test_services_start_in_order_and_stop_in_reverse() {
    let journal = Arc::new(Mutex::new(Vec::new()));
    let services: Vec<Box<dyn Service>> = vec![
        Box::new(Ordered {
            name: "admin",
            journal: journal.clone(),
        }),
        Box::new(Ordered {
            name: "discovery",
            journal: journal.clone(),
        }),
    ];

    let (outcome, audit) = run_with(&services).await;
    outcome.expect("the default host runs");

    assert_eq!(
        journal.lock().expect("the journal is readable").clone(),
        vec![
            "admin start",
            "discovery start",
            "discovery stop",
            "admin stop"
        ]
    );
    assert_eq!(
        actions(&audit),
        vec![
            "server.start",
            "service.start",
            "service.start",
            "service.stop",
            "service.stop",
            "server.stop",
        ]
    );
}

#[tokio::test]
async fn test_a_service_that_refuses_to_start_names_itself_and_stops_the_run() {
    let services: Vec<Box<dyn Service>> = vec![Box::new(FailingStart)];

    let (outcome, _) = run_with(&services).await;

    let message = format!(
        "{:#}",
        outcome.expect_err("the failing service stops the run")
    );
    assert!(message.contains("failing-start"));
    assert!(message.contains("the port is already bound"));
}

#[tokio::test]
async fn test_a_service_that_refuses_to_stop_does_not_prevent_the_others_from_stopping() {
    let services: Vec<Box<dyn Service>> = vec![
        Box::new(StubService("admin")),
        Box::new(FailingStop),
        Box::new(StubService("discovery")),
    ];

    let (outcome, audit) = run_with(&services).await;

    let message = format!("{:#}", outcome.expect_err("the failure is reported"));
    assert!(message.contains("failing-stop"));
    // `admin` was registered before the failing service, so its stop still ran.
    assert_eq!(
        actions(&audit)
            .iter()
            .filter(|action| *action == "service.stop")
            .count(),
        2
    );
}

#[tokio::test(start_paused = true)]
async fn test_the_budget_running_out_says_what_had_not_finished() {
    let services: Vec<Box<dyn Service>> = vec![Box::new(SlowStop)];

    let (outcome, _) = run_with(&services).await;

    let message = format!("{:#}", outcome.expect_err("the budget runs out"));
    assert!(message.contains("slow-stop"), "{message}");
    assert!(message.contains("ran out"), "{message}");
}

#[tokio::test]
async fn test_readiness_is_off_before_the_start_and_after_the_run() {
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), &config, &storage, &audit);
    let health = context.health().clone();

    assert!(!health.is_ready(), "nothing is ready before it starts");

    DefaultServerHost::new()
        .run(&context, at_once())
        .await
        .expect("the default host runs");

    assert!(
        !health.is_ready(),
        "readiness must be off once the run is over"
    );
    assert!(health.is_live(), "the process is still alive");
}

#[tokio::test]
async fn test_the_host_waits_for_the_shutdown_it_was_given() {
    let (trigger, wait) = tokio::sync::oneshot::channel::<()>();
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), &config, &storage, &audit);
    let health = context.health().clone();

    let shutdown: BoxFuture<'static, ()> = Box::pin(async move {
        let _ = wait.await;
    });
    let host = DefaultServerHost::new();
    let run = host.run(&context, shutdown);
    tokio::pin!(run);

    // The run does not finish on its own: it is waiting for the signal it was handed.
    tokio::select! {
        _ = &mut run => panic!("the host returned before it was asked to stop"),
        () = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    assert!(health.is_ready(), "the server is up while it waits");

    let _ = trigger.send(());
    run.await.expect("the host stops when asked");
    assert!(!health.is_ready());
}

#[tokio::test]
async fn test_the_default_host_is_usable_through_the_trait_object() {
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let host: Box<dyn ServerHost> = Box::new(DefaultServerHost::new());
    let context = ServerContext::new(identity(), &config, &storage, &audit);

    host.run(&context, at_once()).await.expect("the host runs");

    assert_eq!(host.name(), "default");
    assert_eq!(
        actions(&audit).first().map(String::as_str),
        Some("server.start")
    );
}
