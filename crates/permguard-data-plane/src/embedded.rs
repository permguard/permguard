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
//!
//! The evaluation path and the decision log are composed once per process, as in a server, so one
//! process embeds one Data Plane.
//!
//! This module is the composition root of an embedded process, as a server's entry point is of a
//! standalone one: the only place in this package that builds the context a Plane runs in.

use std::sync::Arc;
use std::time::{Duration, Instant};

use permguard_core::authz::Actor;
use permguard_core::lifecycle::{HOST, Kind, Phase, ServiceState};
use permguard_core::{
    AuditSink, Config, Drained, Health, Metrics, PlaneContext, PlaneTask, ProductIdentity,
    ServerContext, Storage,
};
use permguard_host::composition::{Authorization, Host, Registration};
use permguard_languages::temporal::{SubmitRequest, SubmitResponse};

use crate::authz::decide::Decider;
use crate::authz::wire::{CheckRequest, CheckResponse, TraceContext};
use crate::evaluation::{Answer, EvaluationRequest, Refused, Services};
use crate::temporal::submit::Submitter;
use crate::{COMPONENT, PLANE};

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
        Builder { capabilities }
    }
}

/// What starts an embedded Data Plane.
pub struct Builder {
    capabilities: Capabilities,
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

/// What a shutdown left unfinished: each service whose work in flight did not end within the
/// budget, with why. Empty when everything drained.
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
    authorization: Arc<Authorization>,
    decider: Arc<Decider>,
    submitter: Option<Arc<Submitter>>,
}

impl Builder {
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
        crate::plane::startup_check(&config).map_err(StartError::Configuration)?;
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

        let (authorization, decider, submitter) = {
            let server = parts.server();
            let context = PlaneContext::new(&server, PLANE);
            (
                crate::handles::authorization(&context),
                crate::authz::decider(&context),
                crate::temporal::served(context.config())
                    .then(|| crate::temporal::submitter(&context))
                    .flatten(),
            )
        };
        parts.services = started;
        // The Host the application composed is up, and the Plane's services are: both take work.
        lifecycle.advance(HOST, Phase::Ready);
        lifecycle.advance(PLANE, Phase::Ready);
        tracing::info!(
            event.name = "embedded.started",
            component = COMPONENT,
            services = parts.services.len(),
            "the embedded Data Plane is ready"
        );

        Ok(Runtime {
            parts: Some(parts),
            authorization,
            decider,
            submitter,
        })
    }
}

impl Runtime {
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
        self.parts
            .as_ref()
            .map_or_else(Health::new, |parts| parts.health.clone())
    }

    /// Ends the embedded Data Plane in order: every service finishes its work in flight before the
    /// deadline `budget` sets, in reverse order of start, then each stops, in the same order. The
    /// only end that drains: what it could not finish is returned, never hidden.
    pub async fn shutdown(mut self, budget: Duration) -> Shutdown {
        let Some(parts) = self.parts.take() else {
            return Shutdown::default();
        };
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
            for service in parts.services.iter().rev() {
                if let Err(error) = service.stop(&context).await {
                    unfinished.push(format!("{}: did not stop: {error:#}", service.name()));
                }
            }
        }
        lifecycle.advance(PLANE, Phase::Stopped);
        lifecycle.advance(HOST, Phase::Stopped);
        tracing::info!(
            event.name = "embedded.stopped",
            component = COMPONENT,
            unfinished = unfinished.len(),
            "the embedded Data Plane stopped"
        );
        Shutdown { unfinished }
    }
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
        runtime.spawn(async move {
            let server = parts.server();
            let context = PlaneContext::new(&server, PLANE);
            for service in parts.services.iter().rev() {
                let _ = service.stop(&context).await;
            }
            parts.health.lifecycle().advance(PLANE, Phase::Stopped);
        });
    }
}
