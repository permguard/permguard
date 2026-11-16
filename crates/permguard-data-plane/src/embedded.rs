// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Data Plane embedded in another Rust application (`11-refactoring/1-dependencies.md`,
//! Embedded public API and lifecycle): a Host and a Data Plane in one process, without a Plane
//! listener, on the application's own Tokio runtime.
//!
//! ```text
//! application ── Capabilities { identity, config, host, storage, audit, metrics }
//!                     │
//!                     ▼
//!              DataPlane::builder(..).start()        registers the Plane's declaration with
//!                     │                               the Host, starts its services
//!                     ▼
//!              Runtime ── evaluate(actor, request)    the evaluation pipeline both transports use
//!                     ├── submit(actor, request)      the temporal interface, when served
//!                     ├── health()                    the lifecycle readiness is derived from
//!                     └── shutdown(budget)            drained, then stopped, in reverse order
//! ```
//!
//! | Rule              | Here                                                                                   |
//! | ----------------- | -------------------------------------------------------------------------------------- |
//! | the Host          | composed by the application: identity, rings, streams, zone keys, the tasks it serves |
//! | the volume        | claimed by the application's Host composition, which owns and releases it             |
//! | the runtime       | the caller's: `start` refuses outside one, and nothing here creates one               |
//! | signals           | none installed: the application decides when to call `shutdown`                       |
//! | authentication    | the application's: the actor it hands `evaluate` is part of its trusted base         |
//! | authorization     | the Host's, on the exact ledger, before any policy is read, as on every surface       |
//! | synchronization   | the `policy.mirror` tasks the application's Host serves, over its own sessions       |
//! | evidence          | the decision log and history on the Host's streams, when the configuration keeps them |
//! | `Drop`            | a fail-safe cancellation, never a graceful end: only `shutdown` drains                |
//! | languages         | the build's features, `cedar`, `rego`, `dogwood`, none by default: `start` refuses none |
//! | isolated runtimes | the application calls [`crate::serve_if_worker`] first in `main`, before its arguments |
//!
//! The evaluation path and the decision log are composed once per process, as in a server, so one
//! process embeds one Data Plane.
//!
//! A runtime the assurance profile requires isolated, Rego from `production`, is compiled and
//! evaluated in a supervised worker: this executable started again with the worker argument. The
//! application opts in by calling [`crate::serve_if_worker`] before it parses its own arguments
//! or starts its runtime; an application that does not is refused such a partition at load, which
//! is never evaluated in process instead.
//!
//! This module is the composition root of an embedded process, as a server's entry point is of a
//! standalone one: the only place in this package that builds the context a Plane runs in.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use permguard_core::lifecycle::{HOST, Kind, Phase, ServiceState};
use permguard_core::{
    AuditSink, Config, Drained, Metrics, PlaneContext, PlaneTask, ProductIdentity, ServerContext,
    Storage,
};
use permguard_host::composition::{Authorization, Host, Registration};

use crate::authz::decide::Decider;
use crate::evaluation::{Answer, EvaluationRequest, Services};
use crate::temporal::submit::Submitter;
use crate::{COMPONENT, PLANE};

// The types the facade's signatures name, from the one place an application imports them: the
// request and its answer, the refusal, the temporal submission, the caller and the health.
pub use permguard_core::Health;
pub use permguard_core::authz::Actor;
/// An engine, both halves of one language, as a language package hands it out.
pub use permguard_languages::Engine;
pub use permguard_languages::temporal::{SubmitRequest, SubmitResponse};

pub use crate::authz::wire::{CheckRequest, CheckResponse, TraceContext};
pub use crate::evaluation::Refused;

/// What the embedding application supplies: who it is, the effective configuration, the Host it
/// composed, and the storage and audit sink the Host writes through.
pub struct Capabilities {
    /// The product the records and documents name.
    pub identity: ProductIdentity,
    /// The effective configuration: the volume and the Data Plane's settings.
    pub config: Config,
    /// The Host, composed by the application with every capability the Plane's declaration asks
    /// for under `config`; the Plane registers with it at `start`.
    pub host: Host,
    /// The storage the Host composed.
    pub storage: Arc<dyn Storage>,
    /// The audit sink the Host composed.
    pub audit: Arc<dyn AuditSink>,
    /// Where the numbers the Plane records go; [`Metrics::none`] records nothing.
    pub metrics: Metrics,
}

/// The embedded Data Plane.
pub struct DataPlane;

impl DataPlane {
    /// A builder over the application's `capabilities`.
    pub fn builder(capabilities: Capabilities) -> Builder {
        Builder {
            capabilities,
            worker: None,
            engines: Vec::new(),
        }
    }
}

/// What starts an embedded Data Plane.
pub struct Builder {
    capabilities: Capabilities,
    /// The dedicated evaluation worker, when the application named one.
    worker: Option<std::path::PathBuf>,
    /// The engines the application registers, beside those this build's features select.
    engines: Vec<Engine>,
}

/// Why an embedded Data Plane did not start. Nothing is left running when it is returned.
#[derive(Debug)]
#[non_exhaustive]
pub enum StartError {
    /// `start` was called outside a Tokio runtime: the application owns the runtime, and the
    /// Plane creates none.
    NoRuntime,
    /// The configuration is refused before anything starts, as a server refuses it.
    Configuration(anyhow::Error),
    /// The Host refused the Plane's declaration: a capability it asks for is absent, or claimed.
    Declaration(String),
    /// A service did not start; the services started before it were stopped.
    Service {
        service: &'static str,
        error: anyhow::Error,
    },
}

impl std::fmt::Display for StartError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoRuntime => formatter.write_str(
                "the embedded Data Plane starts on the application's Tokio runtime, and none is \
                 running",
            ),
            Self::Configuration(error) => {
                write!(formatter, "the configuration is refused: {error:#}")
            }
            Self::Declaration(error) => {
                write!(formatter, "the Host refused the Data Plane: {error}")
            }
            Self::Service { service, error } => {
                write!(
                    formatter,
                    "the service `{service}` did not start: {error:#}"
                )
            }
        }
    }
}

impl std::error::Error for StartError {}

/// What a shutdown left unfinished: each service whose work in flight did not end, or that did not
/// stop, within the budget, with why. Empty when everything drained and stopped.
#[derive(Debug, Default)]
#[non_exhaustive]
pub struct Shutdown {
    pub unfinished: Vec<String>,
}

/// What the runtime holds between `start` and `shutdown`.
struct Parts {
    identity: ProductIdentity,
    config: Config,
    storage: Arc<dyn Storage>,
    audit: Arc<dyn AuditSink>,
    metrics: Metrics,
    health: Health,
    registration: Arc<Registration>,
    services: Vec<Box<dyn PlaneTask>>,
}

impl Parts {
    /// The Host's context, as the Plane's services and surfaces are given it: built anew for each
    /// call over what the runtime holds, so the lifecycle and the numbers carry over.
    fn server(&self) -> ServerContext<'_> {
        ServerContext::new(
            self.identity,
            &self.config,
            self.storage.as_ref(),
            self.audit.as_ref(),
        )
        .with_plane_handles(PLANE, Arc::clone(&self.registration) as _)
        .with_health(self.health.clone())
        .with_metrics(self.metrics.clone())
    }
}

/// A running embedded Data Plane.
pub struct Runtime {
    parts: Option<Parts>,
    handle: Handle,
}

/// What an application asks a running Data Plane: a decision, a temporal submission, its health.
/// Cheap to clone, and the same whoever composed the Host the Plane runs over.
#[derive(Clone)]
pub struct Handle {
    authorization: Arc<Authorization>,
    decider: Arc<Decider>,
    submitter: Option<Arc<Submitter>>,
    health: Health,
}

impl Handle {
    /// The surfaces the Plane was granted, read once from the context it runs in.
    fn over(context: &PlaneContext<'_>, health: Health) -> Self {
        Self {
            authorization: crate::handles::authorization(context),
            decider: crate::authz::decider(context),
            submitter: crate::temporal::served(context.config())
                .then(|| crate::temporal::submitter(context))
                .flatten(),
            health,
        }
    }

    /// Decides `request` for `actor`, the context the application authenticated: authorized on
    /// the exact ledger before any policy is read, then decided against the verified mirror,
    /// recorded in the decision log when the configuration keeps one. The same pipeline both
    /// network transports call.
    pub async fn evaluate(
        &self,
        actor: &Actor,
        request: CheckRequest,
        trace: Option<TraceContext>,
    ) -> Result<CheckResponse, Refused> {
        let services = Services {
            authorization: &self.authorization,
            decider: &self.decider,
            submitter: None,
        };
        let request_id = request.request_id.clone();
        match crate::evaluation::evaluate(
            &services,
            actor,
            EvaluationRequest::native(request, request_id, trace),
        )
        .await?
        {
            Answer::Native(answered) => Ok(*answered),
            Answer::Temporal(_) => Err(Refused::Failed(crate::evaluation::mismatched(
                "the embedded native evaluation",
            ))),
        }
    }

    /// Submits a temporal occurrence for `actor`, when the configuration serves the temporal
    /// interface: authorized, then recorded durably and idempotently.
    pub async fn submit(
        &self,
        actor: &Actor,
        request: SubmitRequest,
    ) -> Result<SubmitResponse, Refused> {
        let services = Services {
            authorization: &self.authorization,
            decider: &self.decider,
            submitter: self.submitter.as_ref(),
        };
        match crate::evaluation::evaluate(&services, actor, EvaluationRequest::temporal(request))
            .await?
        {
            Answer::Temporal(answered) => Ok(*answered),
            Answer::Native(_) => Err(Refused::Failed(crate::evaluation::mismatched(
                "the embedded temporal submission",
            ))),
        }
    }

    /// The lifecycle the Plane's readiness is derived from: live, ready, and what each component
    /// and service reports.
    pub fn health(&self) -> Health {
        self.health.clone()
    }
}

impl Builder {
    /// Registers an engine the application links itself: `permguard_language_cedar::engine()`,
    /// say, from a language package built with its `evaluate` feature.
    ///
    /// A feature of this package, `cedar`, `rego` or `dogwood`, and a registration are the same
    /// implementation reached two ways, and never both for one language: `start` refuses an
    /// engine whose language the process already carries, since nothing is ever replaced, and one
    /// registered after the process's catalogue was read, since what it held then is what the
    /// process decides with. The order engines are registered in changes nothing.
    ///
    /// What a ledger may then use is still the load gate's to say: a manifest naming a language,
    /// a version or an interface the registered engine does not provide is refused when loaded.
    pub fn engine(mut self, engine: Engine) -> Self {
        self.engines.push(engine);
        self
    }

    /// Names the dedicated evaluation worker: the executable a runtime the assurance profile
    /// requires isolated is evaluated in, `permguard-evaluation-worker` built with the languages
    /// and at the version of this library.
    ///
    /// Without it the supervisor starts the application's own executable as the worker, which
    /// works only for an application that calls [`serve_if_worker`](crate::serve_if_worker) first
    /// in `main`. With it the application's entry point is its own. The path is absolute and names
    /// a regular file, not a link, its owner may execute and nobody else may write; `start`
    /// refuses any other.
    /// The first name holds for the process.
    pub fn worker_executable(mut self, executable: impl Into<std::path::PathBuf>) -> Self {
        self.worker = Some(executable.into());
        self
    }

    /// Registers the Plane with the Host and starts its services on the caller's runtime:
    /// mirroring, the decision log, the decision audit and the temporal history, each as its
    /// configuration enables it. Refused, with nothing left running, when the configuration or
    /// the Host refuses the Plane or a service does not start.
    pub async fn start(self) -> Result<Runtime, StartError> {
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(StartError::NoRuntime);
        }
        let Capabilities {
            identity,
            config,
            host,
            storage,
            audit,
            metrics,
        } = self.capabilities;
        // First: the start check reads the catalogue, and reading it seals it.
        for engine in self.engines {
            permguard_languages::register(engine)
                .map_err(|refused| StartError::Configuration(anyhow::Error::new(refused)))?;
        }
        crate::plane::startup_check(&config).map_err(StartError::Configuration)?;
        // Before anything decides: the decision path is built on the worker named here.
        if let Some(worker) = &self.worker {
            crate::authz::name_worker(worker).map_err(StartError::Configuration)?;
        }
        let registration = host
            .register(crate::plane::declaration(&config))
            .map_err(|error| StartError::Declaration(error.to_string()))?;
        let health = Health::new();
        let lifecycle = health.lifecycle();
        lifecycle.enter(PLANE, Kind::Plane, true, Phase::Load);
        let mut parts = Parts {
            identity,
            config,
            storage,
            audit,
            metrics,
            health: health.clone(),
            registration: Arc::new(registration),
            services: Vec::new(),
        };

        let mut started: Vec<Box<dyn PlaneTask>> = Vec::new();
        let mut failed = None;
        {
            let server = parts.server();
            let context = PlaneContext::new(&server, PLANE);
            for service in crate::plane::services() {
                match service.start(&context).await {
                    Ok(()) => {
                        // A service that reported its own state keeps it, as in a server.
                        if lifecycle.component(service.name()).is_none() {
                            lifecycle.service(
                                service.name(),
                                ServiceState::Running,
                                None,
                                None,
                                None,
                            );
                        }
                        started.push(service);
                    }
                    Err(error) => {
                        failed = Some((service.name(), error));
                        break;
                    }
                }
            }
            if let Some((service, error)) = failed {
                for running in started.iter().rev() {
                    if let Err(stop) = running.stop(&context).await {
                        tracing::warn!(
                            event.name = "embedded.stop_failed",
                            component = COMPONENT,
                            service = running.name(),
                            error = %stop,
                            "a service started before a failed one did not stop cleanly"
                        );
                    }
                }
                lifecycle.advance(PLANE, Phase::Failed);
                return Err(StartError::Service { service, error });
            }
        }

        parts.services = started;

        Ok(Runtime::over(parts))
    }
}

impl Runtime {
    /// The running Data Plane over its started services: the surfaces the Plane was granted, read
    /// once, and the Host and the Plane marked ready.
    fn over(parts: Parts) -> Self {
        let handle = {
            let server = parts.server();
            let context = PlaneContext::new(&server, PLANE);
            Handle::over(&context, parts.health.clone())
        };
        // The Host the application composed is up, and the Plane's services are: both take work.
        let lifecycle = parts.health.lifecycle();
        lifecycle.advance(HOST, Phase::Ready);
        lifecycle.advance(PLANE, Phase::Ready);
        tracing::info!(
            event.name = "embedded.started",
            component = COMPONENT,
            services = parts.services.len(),
            "the embedded Data Plane is ready"
        );

        Self {
            parts: Some(parts),
            handle,
        }
    }
}

impl Runtime {
    /// Decides `request` for `actor`: [`Handle::evaluate`].
    pub async fn evaluate(
        &self,
        actor: &Actor,
        request: CheckRequest,
        trace: Option<TraceContext>,
    ) -> Result<CheckResponse, Refused> {
        self.handle.evaluate(actor, request, trace).await
    }

    /// Submits a temporal occurrence for `actor`: [`Handle::submit`].
    pub async fn submit(
        &self,
        actor: &Actor,
        request: SubmitRequest,
    ) -> Result<SubmitResponse, Refused> {
        self.handle.submit(actor, request).await
    }

    /// The lifecycle the Plane's readiness is derived from: live, ready, and what each component
    /// and service reports.
    pub fn health(&self) -> Health {
        self.handle.health()
    }

    /// What the application asks the running Plane, as a value it may clone and hand to its
    /// request handlers.
    pub fn handle(&self) -> Handle {
        self.handle.clone()
    }

    /// Ends the embedded Data Plane in order, within `budget`: every service finishes its work in
    /// flight before the deadline, in reverse order of start, then each stops, in the same order.
    /// The only end that drains: what it could not finish is returned, never hidden.
    ///
    /// The budget bounds the whole end, the stops included: a service that has not stopped by the
    /// deadline is named in what is returned, and its stop goes on without the caller, on the
    /// runtime, as a dropped runtime's does.
    pub async fn shutdown(mut self, budget: Duration) -> Shutdown {
        let Some(parts) = self.parts.take() else {
            return Shutdown::default();
        };

        end(parts, budget).await
    }
}

/// The ordered end of [`Runtime::shutdown`], over what the runtime held.
async fn end(parts: Parts, budget: Duration) -> Shutdown {
    let lifecycle = parts.health.lifecycle();
    lifecycle.advance(HOST, Phase::Draining);
    lifecycle.advance(PLANE, Phase::Draining);
    let deadline = Instant::now() + budget;
    let mut unfinished = Vec::new();
    {
        let server = parts.server();
        let context = PlaneContext::new(&server, PLANE);
        for service in parts.services.iter().rev() {
            match tokio::time::timeout_at(
                tokio::time::Instant::from_std(deadline),
                service.drain(&context, deadline),
            )
            .await
            {
                Ok(Ok(Drained::Complete)) => {}
                Ok(Ok(Drained::Incomplete(reason))) => {
                    unfinished.push(format!("{}: {reason}", service.name()));
                }
                Ok(Err(error)) => unfinished.push(format!("{}: {error:#}", service.name())),
                Err(_) => unfinished.push(format!(
                    "{}: the drain deadline passed before it finished",
                    service.name()
                )),
            }
        }
    }

    // The stops run on a task of their own, so a service that never stops cannot hold the caller
    // past the deadline: the caller is told which did not stop, and the task goes on stopping.
    let names: Vec<&'static str> = parts.services.iter().rev().map(|s| s.name()).collect();
    let stopped: Stopped = Arc::default();
    let stopping = tokio::spawn(stop_all(parts, Arc::clone(&stopped)));
    let in_time = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), stopping).await;
    let stopped = stopped
        .lock()
        .map(|stopped| stopped.clone())
        .unwrap_or_default();
    for (name, failure) in &stopped {
        if let Some(failure) = failure {
            unfinished.push(format!("{name}: did not stop: {failure}"));
        }
    }
    if !matches!(in_time, Ok(Ok(()))) {
        for name in names {
            if !stopped.iter().any(|(held, _)| *held == name) {
                unfinished.push(format!(
                    "{name}: did not stop before the deadline; its stop goes on without the caller"
                ));
            }
        }
    }
    tracing::info!(
        event.name = "embedded.stopped",
        component = COMPONENT,
        unfinished = unfinished.len(),
        "the embedded Data Plane ended"
    );

    Shutdown { unfinished }
}

/// The services that stopped, in the order they did, each with why its stop failed, if it did.
type Stopped = Arc<Mutex<Vec<(&'static str, Option<String>)>>>;

/// Stops every service in reverse order of start, recording each as it stops with why it failed
/// to, then marks the Plane and the Host stopped: reached only when every stop returned.
async fn stop_all(parts: Parts, stopped: Stopped) {
    {
        let server = parts.server();
        let context = PlaneContext::new(&server, PLANE);
        for service in parts.services.iter().rev() {
            let failure = service
                .stop(&context)
                .await
                .err()
                .map(|error| format!("{error:#}"));
            if let Ok(mut stopped) = stopped.lock() {
                stopped.push((service.name(), failure));
            }
        }
    }
    let lifecycle = parts.health.lifecycle();
    lifecycle.advance(PLANE, Phase::Stopped);
    lifecycle.advance(HOST, Phase::Stopped);
}

/// The fail-safe end of a dropped runtime: the services stop without draining, and only the Plane
/// is marked stopped. The Host is not: nothing was drained, so nothing ended in order.
async fn abandon(parts: Parts) {
    {
        let server = parts.server();
        let context = PlaneContext::new(&server, PLANE);
        for service in parts.services.iter().rev() {
            let _ = service.stop(&context).await;
        }
    }
    parts.health.lifecycle().advance(PLANE, Phase::Stopped);
}

impl Drop for Runtime {
    /// A fail-safe, never a graceful end: the services are stopped on the runtime they run on,
    /// without draining, and nothing in flight is flushed. `shutdown` is the end that drains.
    fn drop(&mut self) {
        let Some(parts) = self.parts.take() else {
            return;
        };
        tracing::warn!(
            event.name = "embedded.dropped",
            component = COMPONENT,
            "the embedded Data Plane was dropped without shutdown: its services are stopped \
             without draining, and nothing in flight is flushed"
        );
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        runtime.spawn(abandon(parts));
    }
}

/// The Data Plane as a service of a Host composed for the application, with no listener: what
/// `permguard-runtime`'s composition, or any server host, starts, drains and stops with the Host's
/// own services. The application composes no Host by hand; it is handed a [`Handle`] once the
/// Plane is up.
///
/// The Host that runs it declares the Plane ([`declaration`]) and checks its configuration
/// ([`startup_check`]) before it starts anything, as for a served Plane.
pub struct Hosted {
    /// The dedicated evaluation worker, when the application named one.
    worker: Option<std::path::PathBuf>,
    started: Mutex<Option<tokio::sync::oneshot::Sender<Handle>>>,
    running: Mutex<Vec<Box<dyn PlaneTask>>>,
}

/// The promise of a hosted Plane's [`Handle`].
pub struct Started(tokio::sync::oneshot::Receiver<Handle>);

impl Started {
    /// The handle, once the Plane's services are up; `None` when the Host ended before they were,
    /// which the Host's own result says why.
    pub async fn handle(self) -> Option<Handle> {
        self.0.await.ok()
    }
}

impl Hosted {
    /// A hosted Data Plane, and the promise of its handle.
    pub fn new() -> (Self, Started) {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        (
            Self {
                worker: None,
                started: Mutex::new(Some(sender)),
                running: Mutex::new(Vec::new()),
            },
            Started(receiver),
        )
    }

    /// Names the dedicated evaluation worker, as [`Builder::worker_executable`] does.
    pub fn worker_executable(mut self, executable: impl Into<std::path::PathBuf>) -> Self {
        self.worker = Some(executable.into());
        self
    }
}

/// What the Plane declares to the Host under `config`: the capabilities it asks for.
pub fn declaration(config: &Config) -> permguard_host::composition::Declaration {
    crate::plane::declaration(config)
}

/// The evidence streams the Plane declares under `config`, enabled or not: what a Host registers
/// before any of them serves.
pub fn streams(config: &Config) -> Vec<permguard_stream::StreamDescriptor> {
    crate::plane::streams(config)
}

/// What the Plane requires of `config` before anything starts: a language, a consistent
/// catalogue, no retired setting.
pub fn startup_check(config: &Config) -> anyhow::Result<()> {
    crate::plane::startup_check(config)
}

impl permguard_core::Service for Hosted {
    fn name(&self) -> &'static str {
        "data-plane-embedded"
    }

    fn plane(&self) -> Option<&'static str> {
        Some(PLANE)
    }

    fn start<'a>(
        &'a self,
        server: &'a ServerContext<'a>,
    ) -> permguard_core::BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            // Before anything decides: the decision path is built on the worker named here.
            if let Some(worker) = &self.worker {
                crate::authz::name_worker(worker)?;
            }
            let context = PlaneContext::new(server, PLANE);
            let lifecycle = server.health().lifecycle().clone();
            lifecycle.initialize(PLANE);
            let mut started: Vec<Box<dyn PlaneTask>> = Vec::new();
            for service in crate::plane::services() {
                if let Err(error) = service.start(&context).await {
                    // Those started before it are stopped: a Plane that did not start runs nothing.
                    for running in started.iter().rev() {
                        if let Err(stop) = running.stop(&context).await {
                            tracing::warn!(
                                event.name = "embedded.stop_failed",
                                component = COMPONENT,
                                service = running.name(),
                                error = %stop,
                                "a service started before a failed one did not stop cleanly"
                            );
                        }
                    }
                    return Err(error.context(format!(
                        "starting the `{}` service of the embedded Data Plane",
                        service.name()
                    )));
                }
                if lifecycle.component(service.name()).is_none() {
                    lifecycle.service(service.name(), ServiceState::Running, None, None, None);
                }
                started.push(service);
            }
            let handle = Handle::over(&context, server.health().clone());
            *self.running.lock().map_err(|_| {
                anyhow::anyhow!("the embedded Data Plane's services are poisoned")
            })? = started;
            // Ready now, or as soon as its services report the last requirement satisfied.
            lifecycle.settle(PLANE);
            if let Some(sender) = self.started.lock().ok().and_then(|mut held| held.take()) {
                // An application that dropped the promise asks nothing: the Plane still runs.
                let _ = sender.send(handle);
            }
            tracing::info!(
                event.name = "embedded.started",
                component = COMPONENT,
                "the embedded Data Plane is ready on the Host composed for it"
            );
            Ok(())
        })
    }

    fn drain<'a>(
        &'a self,
        server: &'a ServerContext<'a>,
        deadline: Instant,
    ) -> permguard_core::BoxFuture<'a, anyhow::Result<Drained>> {
        Box::pin(async move {
            let running =
                std::mem::take(&mut *self.running.lock().map_err(|_| {
                    anyhow::anyhow!("the embedded Data Plane's services are poisoned")
                })?);
            let context = PlaneContext::new(server, PLANE);
            let mut unfinished = Vec::new();
            for service in running.iter().rev() {
                match service.drain(&context, deadline).await {
                    Ok(Drained::Complete) => {}
                    Ok(Drained::Incomplete(reason)) => {
                        unfinished.push(format!("{}: {reason}", service.name()));
                    }
                    Err(error) => unfinished.push(format!("{}: {error:#}", service.name())),
                }
            }
            // Handed back for the stop, which the host calls after every drain.
            if let Ok(mut held) = self.running.lock() {
                *held = running;
            }
            Ok(if unfinished.is_empty() {
                Drained::Complete
            } else {
                Drained::Incomplete(unfinished.join("; "))
            })
        })
    }

    fn stop<'a>(
        &'a self,
        server: &'a ServerContext<'a>,
    ) -> permguard_core::BoxFuture<'a, anyhow::Result<()>> {
        Box::pin(async move {
            let running =
                std::mem::take(&mut *self.running.lock().map_err(|_| {
                    anyhow::anyhow!("the embedded Data Plane's services are poisoned")
                })?);
            let context = PlaneContext::new(server, PLANE);
            let mut failures = Vec::new();
            // Every service is stopped, whatever an earlier one answered.
            for service in running.iter().rev() {
                if let Err(error) = service.stop(&context).await {
                    failures.push(format!("{}: {error:#}", service.name()));
                }
            }
            anyhow::ensure!(
                failures.is_empty(),
                "services of the embedded Data Plane did not stop: {}",
                failures.join("; ")
            );
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::unwrap_used)]

    use permguard_core::config::SETTING_WORKING_DIR;
    use permguard_core::{BoxFuture, BuildSettings, Layers};

    use super::*;

    /// A service that records what was asked of it, and may never stop.
    struct Probe {
        name: &'static str,
        asked: Arc<Mutex<Vec<String>>>,
        stuck: bool,
    }

    impl PlaneTask for Probe {
        fn name(&self) -> &'static str {
            self.name
        }

        fn start<'a>(&'a self, _: &'a PlaneContext<'a>) -> BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async { Ok(()) })
        }

        fn stop<'a>(&'a self, _: &'a PlaneContext<'a>) -> BoxFuture<'a, anyhow::Result<()>> {
            Box::pin(async move {
                if self.stuck {
                    std::future::pending::<()>().await;
                }
                self.asked
                    .lock()
                    .unwrap()
                    .push(format!("stop {}", self.name));
                Ok(())
            })
        }

        fn drain<'a>(
            &'a self,
            _: &'a PlaneContext<'a>,
            _: Instant,
        ) -> BoxFuture<'a, anyhow::Result<Drained>> {
            Box::pin(async move {
                self.asked
                    .lock()
                    .unwrap()
                    .push(format!("drain {}", self.name));
                Ok(Drained::Complete)
            })
        }
    }

    /// What a runtime holds, over a Host that grants the Plane's declaration and the `services`
    /// a test chooses in place of the Plane's own.
    fn parts(tag: &str, services: Vec<Box<dyn PlaneTask>>) -> Parts {
        let working = std::env::temp_dir().join(format!(
            "pg-embedded-end-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&working);
        std::fs::create_dir_all(&working).expect("the working directory");
        let config = Config::from_layers(
            BuildSettings::new("9.9.9", "2026", "Test Holder"),
            Vec::<String>::new(),
            Layers::new().with_file(vec![(
                SETTING_WORKING_DIR.to_owned(),
                working.to_str().expect("a path").to_owned(),
            )]),
        )
        .expect("the configuration builds");
        let host = Host::builder()
            .host_id([3; 16])
            .authorization(Arc::new(Authorization::permissive()))
            .build();
        let registration = host
            .register(crate::plane::declaration(&config))
            .expect("the Host grants the declaration");
        let health = Health::new();
        health
            .lifecycle()
            .enter(PLANE, Kind::Plane, true, Phase::Load);

        Parts {
            identity: ProductIdentity::new("an-embedding-application", "Permguard", "", "", ""),
            config,
            storage: Arc::new(permguard_std::storage::MemoryStorage::new()),
            audit: Arc::new(permguard_std::audit::RecordingAuditSink::new()),
            metrics: Metrics::none(),
            health,
            registration: Arc::new(registration),
            services,
        }
    }

    fn probe(
        name: &'static str,
        asked: &Arc<Mutex<Vec<String>>>,
        stuck: bool,
    ) -> Box<dyn PlaneTask> {
        Box::new(Probe {
            name,
            asked: Arc::clone(asked),
            stuck,
        })
    }

    /// A shutdown within its budget drains every service, in reverse order of start, before any
    /// stops, then stops each in the same order, and only then is anything marked stopped.
    #[tokio::test]
    async fn a_shutdown_drains_every_service_then_stops_each_in_reverse_order() {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let parts = parts(
            "ordered",
            vec![
                probe("first", &asked, false),
                probe("second", &asked, false),
            ],
        );
        let health = parts.health.clone();

        let shutdown = Runtime::over(parts).shutdown(Duration::from_secs(10)).await;

        assert!(shutdown.unfinished.is_empty(), "{:?}", shutdown.unfinished);
        assert_eq!(
            *asked.lock().unwrap(),
            ["drain second", "drain first", "stop second", "stop first"]
        );
        assert_eq!(health.lifecycle().phase(PLANE), Some(Phase::Stopped));
        assert_eq!(health.lifecycle().phase(HOST), Some(Phase::Stopped));
    }

    /// The budget bounds the stops too: a service that never stops is named, with every service
    /// waiting behind it, the caller is back at the deadline, and nothing is marked stopped.
    #[tokio::test]
    async fn a_service_that_never_stops_cannot_hold_a_shutdown_past_its_budget() {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let parts = parts(
            "stuck",
            vec![probe("behind", &asked, false), probe("stuck", &asked, true)],
        );
        let health = parts.health.clone();
        let began = Instant::now();

        let shutdown = Runtime::over(parts)
            .shutdown(Duration::from_millis(200))
            .await;

        assert!(
            began.elapsed() < Duration::from_secs(5),
            "the caller is back at the deadline, not when the service stops: {:?}",
            began.elapsed()
        );
        for name in ["stuck", "behind"] {
            assert!(
                shutdown
                    .unfinished
                    .iter()
                    .any(|left| left
                        .starts_with(&format!("{name}: did not stop before the deadline"))),
                "`{name}` is named: {:?}",
                shutdown.unfinished
            );
        }
        assert_ne!(health.lifecycle().phase(PLANE), Some(Phase::Stopped));
        assert_ne!(health.lifecycle().phase(HOST), Some(Phase::Stopped));
    }

    /// A dropped runtime is a fail-safe cancellation, never a durable flush: its services stop,
    /// none is drained, and the Host is never marked stopped as an ordered end marks it.
    #[tokio::test]
    async fn a_dropped_runtime_stops_without_draining_and_claims_no_ordered_end() {
        let asked = Arc::new(Mutex::new(Vec::new()));
        let parts = parts(
            "dropped",
            vec![
                probe("first", &asked, false),
                probe("second", &asked, false),
            ],
        );
        let health = parts.health.clone();

        drop(Runtime::over(parts));

        let deadline = Instant::now() + Duration::from_secs(10);
        while health.lifecycle().phase(PLANE) != Some(Phase::Stopped) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(
            *asked.lock().unwrap(),
            ["stop second", "stop first"],
            "stopped in reverse order, and nothing drained"
        );
        assert_eq!(health.lifecycle().phase(PLANE), Some(Phase::Stopped));
        assert_eq!(
            health.lifecycle().phase(HOST),
            Some(Phase::Ready),
            "the Host did not end in order, and is not said to have"
        );
    }
}
