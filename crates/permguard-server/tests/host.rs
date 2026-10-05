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

/// A Plane's service: writes down which phase the Host and its own Plane were in when it started,
/// records what its Plane waits for, and may refuse to start.
struct PlaneStub {
    plane: &'static str,
    name: &'static str,
    seen: Arc<Mutex<Vec<String>>>,
    waits_for: Option<&'static str>,
    fails: bool,
}

impl PlaneStub {
    fn new(plane: &'static str, name: &'static str, seen: &Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            plane,
            name,
            seen: Arc::clone(seen),
            waits_for: None,
            fails: false,
        }
    }
}

impl Service for PlaneStub {
    fn name(&self) -> &'static str {
        self.name
    }

    fn plane(&self) -> Option<&'static str> {
        Some(self.plane)
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            use permguard_core::lifecycle::{HOST, Phase};

            let lifecycle = context.health().lifecycle();
            let phase = |name: &str| lifecycle.phase(name).map_or("unlisted", Phase::as_str);
            self.seen
                .lock()
                .map_err(|_| anyhow::anyhow!("poisoned"))?
                .push(format!(
                    "{} saw host {} and {} {}",
                    self.name,
                    phase(HOST),
                    self.plane,
                    phase(self.plane)
                ));
            if let Some(requirement) = self.waits_for {
                lifecycle.wait(
                    self.plane,
                    requirement,
                    "the server did not answer",
                    std::time::SystemTime::now(),
                );
            }
            if self.fails {
                bail!("the store did not open");
            }
            // What the Plane's own `PlaneService`, registered last, does once its listeners are
            // bound; a Plane whose earlier service failed never gets this far.
            lifecycle.initialize(self.plane);
            lifecycle.settle(self.plane);

            Ok(())
        })
    }
}

/// A context whose lifecycle lists `planes` in Bootstrap, as the composition does before any
/// service starts.
fn with_planes<'a>(
    context: ServerContext<'a>,
    planes: &[(&'static str, bool)],
) -> ServerContext<'a> {
    use permguard_core::lifecycle::{Kind, Phase};

    for (plane, required) in planes {
        context
            .health()
            .lifecycle()
            .enter(plane, Kind::Plane, *required, Phase::Bootstrap);
    }

    context
}

#[tokio::test]
async fn test_the_host_is_ready_before_any_plane_leaves_bootstrap() {
    use permguard_core::lifecycle::{HOST, Phase};

    let seen = Arc::new(Mutex::new(Vec::new()));
    let services: Vec<Box<dyn Service>> = vec![
        // Registered after the Plane's, and still started first: the Host's own come first.
        Box::new(PlaneStub::new("data", "data-sync", &seen)),
        Box::new(Ordered {
            name: "host-keys",
            journal: Arc::clone(&seen),
        }),
    ];
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = with_planes(
        ServerContext::new(identity(), &config, &storage, &audit).with_services(&services),
        &[("data", true)],
    );
    let health = context.health().clone();

    DefaultServerHost::new()
        .run(&context, at_once())
        .await
        .expect("the host runs");

    assert_eq!(
        *seen.lock().expect("readable"),
        vec![
            "host-keys start".to_owned(),
            "data-sync saw host ready and data load".to_owned(),
            "host-keys stop".to_owned(),
        ],
        "the Host reaches Ready before the Plane leaves Bootstrap, and the Plane is in Load while \
         its services start"
    );
    assert_eq!(health.lifecycle().phase(HOST), Some(Phase::Stopped));
    assert_eq!(health.lifecycle().phase("data"), Some(Phase::Stopped));
    assert!(!health.is_ready());
}

#[tokio::test]
async fn test_an_optional_plane_that_fails_to_start_is_listed_failed_and_does_not_gate() {
    use permguard_core::lifecycle::{Phase, State};

    let (trigger, wait) = tokio::sync::oneshot::channel::<()>();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut failing = PlaneStub::new("control", "control-inventory", &seen);
    failing.fails = true;
    let services: Vec<Box<dyn Service>> = vec![
        Box::new(failing),
        Box::new(PlaneStub::new("data", "data-sync", &seen)),
    ];
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = with_planes(
        ServerContext::new(identity(), &config, &storage, &audit).with_services(&services),
        &[("control", false), ("data", true)],
    );
    let health = context.health().clone();
    let shutdown: BoxFuture<'static, ()> = Box::pin(async move {
        let _ = wait.await;
    });
    let host = DefaultServerHost::new();
    let run = host.run(&context, shutdown);
    tokio::pin!(run);
    tokio::select! {
        _ = &mut run => panic!("the host returned before it was asked to stop"),
        () = tokio::time::sleep(Duration::from_millis(50)) => {}
    }

    let control = health.lifecycle().component("control").expect("listed");
    assert_eq!(control.state, State::Phase(Phase::Failed));
    assert_eq!(
        control.reason.as_deref(),
        Some("in load: starting the control-inventory service: the store did not open")
    );
    assert_eq!(health.lifecycle().phase("data"), Some(Phase::Serving));
    assert!(
        health.is_ready(),
        "an optional plane that failed does not gate readiness"
    );
    assert!(
        seen.lock()
            .expect("readable")
            .iter()
            .any(|line| line.starts_with("data-sync saw")),
        "the rest of the start went on"
    );

    let _ = trigger.send(());
    run.await.expect("the host stops when asked");
    assert_eq!(
        health.lifecycle().phase("control"),
        Some(Phase::Failed),
        "failed is terminal: a drain does not rewrite it"
    );
}

#[tokio::test]
async fn test_a_required_plane_that_fails_to_start_fails_the_run() {
    use permguard_core::lifecycle::Phase;

    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut failing = PlaneStub::new("data", "data-sync", &seen);
    failing.fails = true;
    let services: Vec<Box<dyn Service>> = vec![Box::new(failing)];
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = with_planes(
        ServerContext::new(identity(), &config, &storage, &audit).with_services(&services),
        &[("data", true)],
    );
    let health = context.health().clone();

    let error = DefaultServerHost::new()
        .run(&context, at_once())
        .await
        .expect_err("a required plane that fails fails the process");
    let message = format!("{error:#}");
    assert!(message.contains("data-sync"), "{message}");
    assert_eq!(health.lifecycle().phase("data"), Some(Phase::Failed));
    assert!(!health.is_ready());
}

#[tokio::test]
async fn test_a_required_plane_waiting_for_a_remote_keeps_readiness_off_and_liveness_on() {
    use permguard_core::lifecycle::Phase;

    let (trigger, wait) = tokio::sync::oneshot::channel::<()>();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut waiting = PlaneStub::new("data", "data-sync", &seen);
    waiting.waits_for = Some("mirrors:http://cp");
    let services: Vec<Box<dyn Service>> = vec![Box::new(waiting)];
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = with_planes(
        ServerContext::new(identity(), &config, &storage, &audit).with_services(&services),
        &[("data", true)],
    );
    let health = context.health().clone();
    let shutdown: BoxFuture<'static, ()> = Box::pin(async move {
        let _ = wait.await;
    });
    let host = DefaultServerHost::new();
    let run = host.run(&context, shutdown);
    tokio::pin!(run);
    tokio::select! {
        _ = &mut run => panic!("the host returned before it was asked to stop"),
        () = tokio::time::sleep(Duration::from_millis(50)) => {}
    }

    let data = health.lifecycle().component("data").expect("listed");
    assert_eq!(data.state.as_str(), "load", "listed in load, never omitted");
    assert!(data.stalled_since.is_some());
    assert!(
        !health.is_ready(),
        "a required plane in load gates readiness"
    );
    assert!(
        health.is_live(),
        "a remote dependency never affects liveness"
    );
    assert_eq!(
        health.lifecycle().phase(permguard_core::lifecycle::HOST),
        Some(Phase::Serving),
        "the Host serves on its own"
    );

    // The requirement is satisfied: the Plane moves on, and readiness follows.
    health.lifecycle().satisfy("data", "mirrors:http://cp");
    assert_eq!(health.lifecycle().phase("data"), Some(Phase::Serving));
    assert!(health.is_ready());

    let _ = trigger.send(());
    run.await.expect("the host stops when asked");
}

/// A Host service whose stop writes down the phase the Host and a Plane were in at that moment.
struct PhaseWitness {
    plane: &'static str,
    seen: Arc<Mutex<Vec<String>>>,
}

impl Service for PhaseWitness {
    fn name(&self) -> &'static str {
        "phase-witness"
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        ready(Ok(()))
    }

    fn stop<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            use permguard_core::lifecycle::{HOST, Phase};

            let lifecycle = context.health().lifecycle();
            let phase = |name: &str| lifecycle.phase(name).map_or("unlisted", Phase::as_str);
            self.seen
                .lock()
                .map_err(|_| anyhow::anyhow!("poisoned"))?
                .push(format!(
                    "stop saw host {} and {} {} with ready {}",
                    phase(HOST),
                    self.plane,
                    phase(self.plane),
                    context.health().is_ready()
                ));

            Ok(())
        })
    }
}

#[tokio::test]
async fn test_a_drain_reports_draining_with_readiness_off_while_the_services_stop() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let services: Vec<Box<dyn Service>> = vec![
        Box::new(PhaseWitness {
            plane: "data",
            seen: Arc::clone(&seen),
        }),
        Box::new(PlaneStub::new("data", "data-sync", &seen)),
    ];
    let config = Config::default();
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = with_planes(
        ServerContext::new(identity(), &config, &storage, &audit).with_services(&services),
        &[("data", true)],
    );

    DefaultServerHost::new()
        .run(&context, at_once())
        .await
        .expect("the host runs");

    assert!(
        seen.lock()
            .expect("readable")
            .contains(&"stop saw host draining and data draining with ready false".to_owned()),
        "{seen:?}"
    );
}
