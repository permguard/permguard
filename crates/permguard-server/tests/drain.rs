// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The drain (WP-2.7): readiness goes false first, every intake stops before any drain waits,
//! in-flight requests finish within `drain_timeout`, service hooks run in reverse order, one
//! total budget bounds it all, and a drain that does not complete is never reported clean.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use axum::Router;
use axum::routing::get;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use permguard_core::config::{SETTING_SHUTDOWN_DRAIN_TIMEOUT, SETTING_SHUTDOWN_TIMEOUT};
use permguard_core::{
    BoxFuture, BuildSettings, Config, Drained, IncompleteDrain, Layers, ProductIdentity,
    ServerContext, ServerHost, Service, ready,
};
use permguard_server::DefaultServerHost;
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;
use permguard_transport::Surface;

fn identity() -> ProductIdentity {
    ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>")
}

fn config(drain: &str, total: &str) -> Config {
    Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(vec![
            (SETTING_SHUTDOWN_DRAIN_TIMEOUT.to_owned(), drain.to_owned()),
            (SETTING_SHUTDOWN_TIMEOUT.to_owned(), total.to_owned()),
        ]),
    )
    .expect("the config builds")
}

/// Writes down every hook the host called, in order.
struct Hooks {
    name: &'static str,
    journal: Arc<Mutex<Vec<String>>>,
    drained: Drained,
}

impl Hooks {
    fn note(&self, what: &str) {
        self.journal
            .lock()
            .unwrap()
            .push(format!("{} {what}", self.name));
    }
}

impl Service for Hooks {
    fn name(&self) -> &'static str {
        self.name
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        ready(Ok(()))
    }

    fn stop_intake(&self, context: &ServerContext<'_>) {
        assert!(!context.health().is_ready(), "readiness goes false first");
        self.note("intake");
    }

    fn drain<'a>(
        &'a self,
        _context: &'a ServerContext<'a>,
        _deadline: std::time::Instant,
    ) -> BoxFuture<'a, Result<Drained>> {
        self.note("drain");
        ready(Ok(self.drained.clone()))
    }

    fn stop<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        self.note("stop");
        ready(Ok(()))
    }
}

/// A drain hook that never finishes on its own.
struct Stuck;

impl Service for Stuck {
    fn name(&self) -> &'static str {
        "stuck"
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        ready(Ok(()))
    }

    fn drain<'a>(
        &'a self,
        _context: &'a ServerContext<'a>,
        _deadline: std::time::Instant,
    ) -> BoxFuture<'a, Result<Drained>> {
        Box::pin(async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(Drained::Complete)
        })
    }
}

async fn run(services: &[Box<dyn Service>], config: &Config) -> Result<()> {
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), config, &storage, &audit).with_services(services);
    DefaultServerHost::new()
        .run(&context, Box::pin(std::future::ready(())))
        .await
}

fn incomplete(outcome: Result<()>) -> IncompleteDrain {
    let error = outcome.expect_err("the drain is incomplete");
    error
        .downcast_ref::<IncompleteDrain>()
        .cloned()
        .unwrap_or_else(|| panic!("not an incomplete drain: {error:#}"))
}

#[tokio::test]
async fn every_intake_stops_before_any_drain_and_hooks_run_in_reverse_order() {
    let journal = Arc::new(Mutex::new(Vec::new()));
    let services: Vec<Box<dyn Service>> = ["first", "second", "third"]
        .into_iter()
        .map(|name| {
            Box::new(Hooks {
                name,
                journal: Arc::clone(&journal),
                drained: Drained::Complete,
            }) as Box<dyn Service>
        })
        .collect();

    run(&services, &config("2s", "3s"))
        .await
        .expect("a clean drain is a clean run");

    assert_eq!(
        *journal.lock().unwrap(),
        vec![
            "third intake",
            "second intake",
            "first intake",
            "third drain",
            "second drain",
            "first drain",
            "third stop",
            "second stop",
            "first stop",
        ]
    );
}

#[tokio::test]
async fn a_hook_that_reports_unfinished_work_makes_the_drain_incomplete_and_the_rest_still_runs() {
    let journal = Arc::new(Mutex::new(Vec::new()));
    let services: Vec<Box<dyn Service>> = vec![
        Box::new(Hooks {
            name: "producer",
            journal: Arc::clone(&journal),
            drained: Drained::Incomplete("12 records unshipped".to_owned()),
        }),
        Box::new(Hooks {
            name: "listener",
            journal: Arc::clone(&journal),
            drained: Drained::Complete,
        }),
    ];

    let drained = incomplete(run(&services, &config("2s", "3s")).await);
    assert_eq!(
        drained.unfinished,
        vec!["producer: 12 records unshipped".to_owned()]
    );
    // Incomplete is not a reason to stop releasing: every service was still stopped.
    let journal = journal.lock().unwrap();
    assert!(journal.contains(&"producer stop".to_owned()), "{journal:?}");
    assert!(journal.contains(&"listener stop".to_owned()), "{journal:?}");
}

#[tokio::test(start_paused = true)]
async fn a_forced_timeout_is_incomplete_and_never_reported_clean() {
    let services: Vec<Box<dyn Service>> = vec![Box::new(Stuck)];

    let drained = incomplete(run(&services, &config("2s", "3s")).await);
    assert_eq!(drained.unfinished.len(), 1, "{drained:?}");
    assert!(
        drained.unfinished[0].starts_with("stuck: the drain deadline passed"),
        "{drained:?}"
    );
}

#[test]
fn an_incomplete_drain_exits_75_and_any_other_failure_exits_1() {
    let drained = anyhow::Error::new(IncompleteDrain {
        unfinished: vec!["x".to_owned()],
    })
    .context("running the server");
    assert_eq!(
        format!("{:?}", permguard_server::app::exit_code_of(&drained)),
        format!("{:?}", std::process::ExitCode::from(75))
    );
    assert_eq!(permguard_core::EXIT_DRAIN_INCOMPLETE, 75);
    let other = anyhow::anyhow!("the port is already bound");
    assert_eq!(
        format!("{:?}", permguard_server::app::exit_code_of(&other)),
        format!("{:?}", std::process::ExitCode::FAILURE)
    );
}

/// A service owning one real listener, whose handler takes `work` to answer.
struct Listener {
    surface: Mutex<Option<Surface>>,
}

impl Listener {
    async fn bound(work: Duration) -> (Self, SocketAddr) {
        let router = Router::new().route(
            "/slow",
            get(move || async move {
                tokio::time::sleep(work).await;
                "done"
            }),
        );
        let surface = Surface::listener("test", "127.0.0.1:0", router)
            .start()
            .await
            .expect("the listener binds");
        let address = surface.address();
        (
            Self {
                surface: Mutex::new(Some(surface)),
            },
            address,
        )
    }
}

impl Service for Listener {
    fn name(&self) -> &'static str {
        "listener"
    }

    fn start<'a>(&'a self, _context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        ready(Ok(()))
    }

    fn stop_intake(&self, _context: &ServerContext<'_>) {
        if let Some(surface) = self.surface.lock().unwrap().as_ref() {
            surface.stop_intake();
        }
    }

    fn drain<'a>(
        &'a self,
        _context: &'a ServerContext<'a>,
        deadline: std::time::Instant,
    ) -> BoxFuture<'a, Result<Drained>> {
        let surface = self.surface.lock().unwrap().take();
        Box::pin(permguard_server::host::drain_surfaces(
            "test",
            surface.into_iter().collect(),
            deadline,
        ))
    }
}

/// Sends `GET /slow` and returns what came back, or the I/O error.
async fn ask(address: SocketAddr) -> std::io::Result<String> {
    let mut stream = tokio::net::TcpStream::connect(address).await?;
    stream
        .write_all(b"GET /slow HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut said = Vec::new();
    stream.read_to_end(&mut said).await?;
    Ok(String::from_utf8_lossy(&said).into_owned())
}

/// The shutdown signal arrives while a request is in flight: it finishes within the drain, and
/// the drain is clean.
#[tokio::test(flavor = "multi_thread")]
async fn a_shutdown_during_an_in_flight_request_lets_it_finish_within_the_drain() {
    let (listener, address) = Listener::bound(Duration::from_millis(300)).await;
    let services: Vec<Box<dyn Service>> = vec![Box::new(listener)];
    let config = config("5s", "6s");
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();

    let in_flight = tokio::spawn(ask(address));
    // The request reaches its handler, then the process is asked to stop.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let context =
        ServerContext::new(identity(), &config, &storage, &audit).with_services(&services);
    DefaultServerHost::new()
        .run(&context, Box::pin(std::future::ready(())))
        .await
        .expect("the in-flight request finished within the drain: clean");

    let answered = in_flight
        .await
        .unwrap()
        .expect("the in-flight request is answered");
    assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
    assert!(answered.ends_with("done"), "{answered}");
}

/// A request still running at the drain deadline is cut, and the drain is incomplete.
#[tokio::test(flavor = "multi_thread")]
async fn a_request_outlasting_the_drain_is_cut_and_the_drain_is_incomplete() {
    let (listener, address) = Listener::bound(Duration::from_secs(30)).await;
    let services: Vec<Box<dyn Service>> = vec![Box::new(listener)];
    let config = config("300ms", "1s");
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();

    let in_flight = tokio::spawn(ask(address));
    tokio::time::sleep(Duration::from_millis(100)).await;

    let context =
        ServerContext::new(identity(), &config, &storage, &audit).with_services(&services);
    let started = std::time::Instant::now();
    let outcome = DefaultServerHost::new()
        .run(&context, Box::pin(std::future::ready(())))
        .await;
    let took = started.elapsed();

    let drained = incomplete(outcome);
    assert!(
        drained.unfinished[0].starts_with("listener: requests in flight on"),
        "{drained:?}"
    );
    assert!(
        took < Duration::from_secs(1),
        "one budget bounds it all: {took:?}"
    );
    let cut = in_flight.await.unwrap();
    assert!(
        cut.as_ref().map_or(true, |said| !said.contains("done")),
        "the cut request was not answered: {cut:?}"
    );
}
