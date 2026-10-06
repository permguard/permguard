// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The server host Permguard starts when a binary does not supply one of its own.
//!
//! The host says what it is doing through the log, not through the command's output stream: a server
//! that printed its lifecycle to stdout would be unreadable to the thing collecting it. Every record
//! carries the `component` it belongs to, so one server and five services stay tellable apart.
//!
//! The lifecycle is split across two levels on purpose. `started` and `stopped` are what happened and
//! are recorded at `info`; `starting` and `stopping` are the transitions between them and are
//! recorded at `debug`. A default deployment therefore reports that the server came up and went down,
//! and asking for `debug` is what shows it going through the motions.
//!
//! # Shutting down
//!
//! The order matters more than it looks:
//!
//! 1. readiness goes false **first**, before anything is closed, so a load balancer stops routing
//!    while the process is still able to finish what it already has;
//! 2. every service stops its intake, in reverse order and without waiting, so no listener still
//!    accepts while another drains (WP-2.7);
//! 3. every service drains what it has in flight, in reverse order, within `shutdown.drain_timeout`;
//!    what is cut at that deadline makes the drain incomplete;
//! 4. services stop in the reverse of the order they started;
//! 5. storage is released — it may have buffered writes or a pool to drain;
//! 6. the audit sink is released **last**, after the final record, because a sink flushed before the
//!    last write is a trail with a hole in it;
//! 7. all of it shares one budget, `shutdown.timeout`, and when anything did not finish the host
//!    returns an `IncompleteDrain` naming it, which the process exits with status `75`: never clean.

use std::future::Future;

use anyhow::{Context, Result};
use tokio::time::{Instant, timeout_at};
use tracing::{debug, info, warn};

use permguard_core::{BoxFuture, ServerContext, ServerHost, Service, Subject};

/// The storage key under which a run records the host that produced it.
pub const LAST_START_KEY: &str = "server/last-start";

/// How long past the drain deadline the host waits for a hook that is cutting its own work, so
/// the hook's reason is the one reported; always inside the total budget.
const HOOK_CUT_MARGIN: std::time::Duration = std::time::Duration::from_millis(500);

/// The `component` every record of the host itself carries.
const COMPONENT: &str = "server";

/// Records a state something reached, at `info`.
///
/// Every record carries the same keys, because those are what a monitoring tool builds on:
/// `event.name` is the stable machine name an alert fires on, `message` is the human wording that may
/// change without breaking that alert, `component` says which part of the process spoke, and
/// `service.name`/`service.version` say which build it was.
fn state(context: &ServerContext<'_>, event_name: &str, component: &str, message: &str) {
    info!(
        event.name = event_name,
        component = component,
        service.name = context.identity().binary_name(),
        service.version = context.config().version(),
        "{message}"
    );
}

/// Records a transition between two states, at `debug`.
///
/// Same keys as [`state`]: a deployment that turns `debug` on gets more records, not differently
/// shaped ones.
fn transition(context: &ServerContext<'_>, event_name: &str, component: &str, message: &str) {
    debug!(
        event.name = event_name,
        component = component,
        service.name = context.identity().binary_name(),
        service.version = context.config().version(),
        "{message}"
    );
}

/// Awaits `work` until `deadline`, returning nothing when the budget ran out first.
async fn within<T>(deadline: Instant, work: impl Future<Output = T>) -> Option<T> {
    timeout_at(deadline, work).await.ok()
}

/// The host that starts every registered service, waits, and puts everything away again.
#[derive(Debug, Default)]
pub struct DefaultServerHost;

impl DefaultServerHost {
    /// Builds the default server host.
    pub fn new() -> Self {
        Self
    }

    /// Starts the Host's services, then the Planes': the Host reaches Ready before any Plane
    /// leaves Bootstrap (P2). Within each group, registration order.
    ///
    /// A Plane's service that fails fails its Plane. A required Plane failing fails the process; an
    /// optional one stays listed as `failed` and the rest starts.
    async fn start_services(&self, context: &ServerContext<'_>) -> Result<()> {
        use permguard_core::lifecycle::{HOST, Phase, ServiceState};

        let lifecycle = context.health().lifecycle();
        lifecycle.advance(HOST, Phase::Initialize);
        for service in context
            .services()
            .iter()
            .filter(|service| service.plane().is_none())
        {
            self.start_one(context, service.as_ref()).await?;
        }
        lifecycle.advance(HOST, Phase::Ready);

        for service in context
            .services()
            .iter()
            .filter(|service| service.plane().is_some())
        {
            let Some(plane) = service.plane() else {
                continue;
            };
            // A Plane the configuration does not select is not listed: its services are still
            // taken through their lifecycle, and each says it has nothing to do. A failed Plane's
            // remaining services are not started: what they would serve is gone.
            match lifecycle.phase(plane) {
                Some(Phase::Failed) => continue,
                Some(Phase::Bootstrap) => lifecycle.advance(plane, Phase::Load),
                None | Some(_) => {}
            }
            if let Err(error) = self.start_one(context, service.as_ref()).await {
                lifecycle.fail(plane, format!("{error:#}"));
                let required = lifecycle
                    .component(plane)
                    .is_some_and(|component| component.required);
                if required {
                    // The process fails with it: the Host says so before it exits non-zero.
                    lifecycle.fail(HOST, format!("the required {plane} plane failed to start"));
                    return Err(error);
                }
                warn!(
                    event.name = "plane.failed",
                    component = service.name(),
                    plane,
                    error = %format!("{error:#}"),
                    "an optional plane failed to start; it stays listed as failed and does not \
                     gate readiness"
                );
                lifecycle.service(
                    service.name(),
                    ServiceState::Failed,
                    None,
                    None,
                    Some(format!("{error:#}")),
                );
            }
        }

        Ok(())
    }

    async fn start_one(&self, context: &ServerContext<'_>, service: &dyn Service) -> Result<()> {
        transition(context, "service.starting", service.name(), "starting");

        service
            .start(context)
            .await
            .with_context(|| format!("starting the {} service", service.name()))?;

        context
            .record_audit("service.start", Subject::System(service.name()))
            .await
            .with_context(|| format!("recording the start of the {} service", service.name()))?;

        // A Host service that reports its own state keeps it; the rest are running once started.
        // A Plane's services are listed by the Plane's wrapper, which knows whether they ran.
        if service.plane().is_none()
            && context
                .health()
                .lifecycle()
                .component(service.name())
                .is_none()
        {
            context.health().lifecycle().service(
                service.name(),
                permguard_core::lifecycle::ServiceState::Running,
                None,
                None,
                None,
            );
        }
        state(context, "service.started", service.name(), "started");

        Ok(())
    }

    /// Moves every Plane to `phase`; a failed Plane stays failed.
    fn planes_enter(&self, context: &ServerContext<'_>, phase: permguard_core::lifecycle::Phase) {
        let lifecycle = context.health().lifecycle();
        for component in lifecycle.components() {
            if component.kind == permguard_core::lifecycle::Kind::Plane {
                lifecycle.advance(&component.name, phase);
            }
        }
    }

    /// The drain (WP-2.7): every service stops its intake first, in reverse order and without
    /// waiting, so no listener still accepts while another drains; then each finishes what it has
    /// in flight, in reverse order, against the one `deadline`. Returns what did not finish.
    async fn drain_services(
        &self,
        context: &ServerContext<'_>,
        deadline: Instant,
        budget: Instant,
    ) -> Vec<String> {
        for service in context.services().iter().rev() {
            service.stop_intake(context);
        }
        transition(
            context,
            "server.intake_stopped",
            COMPONENT,
            "intake stopped",
        );

        let mut unfinished = Vec::new();
        for service in context.services().iter().rev() {
            let hook_deadline =
                std::time::Instant::now() + deadline.saturating_duration_since(Instant::now());
            // The hook cuts what is still open at `deadline` itself and says so; the host's own
            // cut comes a little later, inside the budget, for a hook that does not.
            let cut = (deadline + HOOK_CUT_MARGIN).min(budget);
            match within(cut, service.drain(context, hook_deadline)).await {
                Some(Ok(permguard_core::Drained::Complete)) => {}
                Some(Ok(permguard_core::Drained::Incomplete(reason))) => {
                    warn!(
                        event.name = "service.drain_incomplete",
                        component = service.name(),
                        reason = %reason,
                        "the service did not finish draining"
                    );
                    unfinished.push(format!("{}: {reason}", service.name()));
                }
                Some(Err(error)) => {
                    warn!(
                        event.name = "service.drain_failed",
                        component = service.name(),
                        error = %error,
                        "the service's drain failed"
                    );
                    unfinished.push(format!("{}: {error:#}", service.name()));
                }
                None => unfinished.push(format!(
                    "{}: the drain deadline passed before it finished",
                    service.name()
                )),
            }
        }

        unfinished
    }

    /// Stops every registered service in the reverse of the order it started them.
    ///
    /// Returns the names of whatever did not finish: a service that failed, and every service the
    /// budget never reached. A failure does not stop the ones before it from being stopped — the
    /// point of a shutdown is to release as much as it can, not to give up at the first problem.
    async fn stop_services(&self, context: &ServerContext<'_>, deadline: Instant) -> Vec<String> {
        let mut unfinished = Vec::new();

        for service in context.services().iter().rev() {
            transition(context, "service.stopping", service.name(), "stopping");

            match within(deadline, service.stop(context)).await {
                Some(Ok(())) => {
                    if let Err(error) = context
                        .record_audit("service.stop", Subject::System(service.name()))
                        .await
                    {
                        warn!(
                            event.name = "service.stop.unrecorded",
                            component = service.name(),
                            error = %error,
                            "the service stopped but the record did not"
                        );
                    }

                    state(context, "service.stopped", service.name(), "stopped");
                }
                Some(Err(error)) => {
                    warn!(
                        event.name = "service.stop.failed",
                        component = service.name(),
                        error = %error,
                        "the service did not stop cleanly"
                    );
                    unfinished.push(service.name().to_owned());
                }
                None => unfinished.push(format!(
                    "{}: the shutdown budget ran out before it stopped",
                    service.name()
                )),
            }
        }

        unfinished
    }
}

impl ServerHost for DefaultServerHost {
    fn name(&self) -> &'static str {
        "default"
    }

    fn run<'a>(
        &'a self,
        context: &'a ServerContext<'a>,
        shutdown: BoxFuture<'a, ()>,
    ) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            transition(context, "server.starting", COMPONENT, "starting");

            context
                .record_audit("server.start", Subject::System(self.name()))
                .await
                .context("recording the server start event")?;

            context
                .storage()
                .put(LAST_START_KEY, self.name().as_bytes())
                .await
                .context("recording the host that started the server")?;

            self.start_services(context).await?;

            // The Host serves; each Plane reaches Ready on its own, and readiness waits for the
            // required ones.
            context.health().set_ready(true);
            state(context, "server.started", COMPONENT, "started");

            shutdown.await;

            // Readiness goes first and on its own: from here the process still finishes what it has,
            // but nothing new should be routed to it.
            context.health().set_ready(false);
            transition(context, "server.stopping", COMPONENT, "stopping");

            // Every Plane drains with the Host; a failed one stays failed, which is terminal.
            // One total budget, aligned with the orchestrator's grace; the drain gets the first
            // `drain_timeout` of it, the release the rest (WP-2.7).
            let started = Instant::now();
            let deadline = started + context.config().shutdown_timeout();
            let drain_deadline =
                (started + context.config().shutdown_drain_timeout()).min(deadline);
            self.planes_enter(context, permguard_core::lifecycle::Phase::Draining);
            let mut unfinished = self.drain_services(context, drain_deadline, deadline).await;
            unfinished.extend(self.stop_services(context, deadline).await);

            match within(deadline, context.storage().shutdown()).await {
                Some(Ok(())) => {}
                Some(Err(error)) => {
                    warn!(
                        event.name = "storage.shutdown.failed",
                        component = context.storage().name(),
                        error = %error,
                        "the store did not release cleanly"
                    );
                    unfinished.push(context.storage().name().to_owned());
                }
                None => unfinished.push(context.storage().name().to_owned()),
            }

            let stop_recorded = context
                .record_audit("server.stop", Subject::System(self.name()))
                .await
                .context("recording the server stop event");
            // An unrecorded stop is something that did not finish, not a different failure: the
            // run still ends as an incomplete drain, so the exit status says so.
            if let Err(error) = stop_recorded {
                unfinished.push(format!("audit: server.stop unrecorded: {error:#}"));
            }

            // Stopped: the services are down and the store released, whatever did not finish in
            // the budget is named below. The Host goes last, after its Planes.
            self.planes_enter(context, permguard_core::lifecycle::Phase::Stopped);
            context.health().lifecycle().advance(
                permguard_core::lifecycle::HOST,
                permguard_core::lifecycle::Phase::Stopped,
            );
            state(context, "server.stopped", COMPONENT, "stopped");

            // Each realm's trail is sealed too, in sequence — one process, one drain, no task apiece.
            // A realm that fails to release is named and the next is still tried: a shutdown releases
            // as much as it can.
            for realm in context.realms().all() {
                match within(deadline, realm.audit().shutdown()).await {
                    Some(Ok(())) => {}
                    Some(Err(error)) => {
                        warn!(
                            event.name = "audit.shutdown.failed",
                            component = realm.audit().name(),
                            realm = realm.name(),
                            error = %error,
                            "a realm's audit sink did not release cleanly"
                        );
                        unfinished.push(format!("realm {}", realm.name()));
                    }
                    None => unfinished.push(format!("realm {}", realm.name())),
                }
            }

            // Last, and after the final record: a sink flushed before the last write loses it.
            match within(deadline, context.audit().shutdown()).await {
                Some(Ok(())) => {}
                Some(Err(error)) => {
                    warn!(
                        event.name = "audit.shutdown.failed",
                        component = context.audit().name(),
                        error = %error,
                        "the audit sink did not release cleanly"
                    );
                    unfinished.push(context.audit().name().to_owned());
                }
                None => unfinished.push(context.audit().name().to_owned()),
            }

            if unfinished.is_empty() {
                state(context, "server.drained", COMPONENT, "drained");
                return Ok(());
            }

            // Never reported clean: the process exits with the incomplete-drain status, and what
            // did not finish is named (WP-2.7).
            warn!(
                event.name = "server.drain_incomplete",
                component = COMPONENT,
                unfinished = %unfinished.join("; "),
                "the drain did not complete within the shutdown budget"
            );
            Err(anyhow::Error::new(permguard_core::IncompleteDrain {
                unfinished,
            }))
        })
    }
}

/// Drains `surfaces` whose intake already stopped (WP-2.7): each finishes its open requests
/// until `deadline`, and a surface that had to cut requests makes the drain incomplete. For the
/// services that own listeners.
pub async fn drain_surfaces(
    component: &str,
    surfaces: Vec<permguard_transport::Surface>,
    deadline: std::time::Instant,
) -> Result<permguard_core::Drained> {
    let deadline = Instant::now() + deadline.saturating_duration_since(std::time::Instant::now());
    let mut cut = Vec::new();
    for surface in surfaces {
        let (address, complete) = surface
            .finish(deadline)
            .await
            .with_context(|| format!("draining a {component} listener"))?;
        if complete {
            info!(
                event.name = "surface.drained",
                component = component,
                address = %address,
                "drained"
            );
        } else {
            warn!(
                event.name = "surface.drain_cut",
                component = component,
                address = %address,
                "the drain deadline cut requests still in flight"
            );
            cut.push(address.to_string());
        }
    }

    Ok(if cut.is_empty() {
        permguard_core::Drained::Complete
    } else {
        permguard_core::Drained::Incomplete(format!(
            "requests in flight on {} were cut at the drain deadline",
            cut.join(", ")
        ))
    })
}
