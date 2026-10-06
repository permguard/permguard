// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The surface itself: one [`Service`] that binds, serves the probes, and stops with everything else.

use std::sync::Mutex;

use anyhow::{Context, Result, anyhow};
use axum::Router;
use tracing::{info, warn};

use permguard_core::{BoxFuture, Config, ServerContext, Service, ready};
use permguard_transport::Surface;

use crate::host;
use crate::probes;

/// The `component` every record of this surface carries.
const COMPONENT: &str = "telemetry";

/// The telemetry surface.
///
/// It is a [`Service`] like any other, so it starts and stops with everything else and needs no
/// special case in the host. What makes it unusual is only that it reads the health the host writes.
#[derive(Default)]
pub struct TelemetryService {
    running: Mutex<Option<Surface>>,
    /// Builds the process-level `/.well-known/server-configuration` document
    /// — the registry of the planes this process hosts. Injected by the
    /// composition (it knows the planes); this surface only serves it.
    /// Operator material on the operator's port: a plane's public port
    /// describes itself, never its neighbours.
    configuration: Option<ConfigurationDocument>,
    /// Where the operations ring's public set is served once the Host listener serves it
    /// (WP-2.5): `/server-host/keys` then redirects there instead of publishing the ring.
    keys_location: Option<KeysLocation>,
}

/// Renders the registry document from the materialized configuration.
type ConfigurationDocument = Box<dyn Fn(&Config) -> String + Send + Sync>;

/// Names where the keys moved to, from the materialized configuration; `None` keeps the route.
type KeysLocation = Box<dyn Fn(&Config) -> Option<String> + Send + Sync>;

impl TelemetryService {
    /// Builds a telemetry surface that has not started yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// Names how the process-level server-configuration document is built.
    pub fn with_configuration<F>(mut self, build: F) -> Self
    where
        F: Fn(&Config) -> String + Send + Sync + 'static,
    {
        self.configuration = Some(Box::new(build));

        self
    }

    /// Names where the operations ring's public set is served once a Host listener serves it:
    /// `/server-host/keys` answers `308 Permanent Redirect` there, as the legacy route it is.
    pub fn with_keys_location<F>(mut self, location: F) -> Self
    where
        F: Fn(&Config) -> Option<String> + Send + Sync + 'static,
    {
        self.keys_location = Some(Box::new(location));

        self
    }

    /// The address the surface is bound to, while it runs: what a test connects to when the
    /// configuration asked for an ephemeral port.
    pub fn bound(&self) -> Option<std::net::SocketAddr> {
        self.running
            .lock()
            .ok()
            .and_then(|running| running.as_ref().map(Surface::address))
    }

    /// Builds the routes this surface answers on.
    ///
    /// Public so a build that assembles its own HTTP surface can mount the same handlers somewhere
    /// else rather than reimplement them.
    pub fn routes(reported: probes::Reported) -> Router {
        probes::routes(reported)
    }
}

impl Service for TelemetryService {
    fn name(&self) -> &'static str {
        COMPONENT
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // No address means the deployment did not ask for this surface. That is a choice, not a
            // misconfiguration, so it is reported and the run continues.
            let Some(configured) = context.config().telemetry_addr() else {
                info!(
                    event.name = "telemetry.disabled",
                    component = COMPONENT,
                    "no telemetry address is configured"
                );

                return Ok(());
            };

            let secured = context.config().telemetry_tls();
            // P10: the telemetry listener is authenticated or network-scoped. The process cannot see
            // a NetworkPolicy, so it says plainly when nothing it can see does either.
            if secured.is_none() && !scoped_to_loopback(configured) {
                warn!(
                    event.name = "telemetry.unscoped",
                    component = COMPONENT,
                    address = configured,
                    "the telemetry listener is reachable beyond this host without TLS: scope it to \
                     the scrapers' network (the chart's `networkPolicy.telemetry.from`), or configure \
                     PERMGUARD_TELEMETRY_TLS_CERT and PERMGUARD_TELEMETRY_TLS_KEY"
                );
            }
            let surface = Surface::listener(COMPONENT, configured, {
                let mut routes = Self::routes(probes::Reported::new(
                    context.health().clone(),
                    context.metrics().clone(),
                ));
                if let Some(build) = &self.configuration {
                    routes = routes.merge(probes::configuration_route(build(context.config())));
                }
                // The process version, under the same disclosure policy the planes answer with.
                routes = routes.merge(host::version_route(host::version_body(
                    "server-host",
                    context.identity(),
                    context.config(),
                )));
                // The operations ring as a JWKS, when this process composes one. Absent ring,
                // absent route: a deployment that keeps no keys has nothing to publish, and a
                // `404` says so better than an empty set would. With a Host listener a verifier
                // can reach — one that demands no client certificate — the ring is served
                // there, and this route is the legacy one: a redirect, so a verifier configured
                // against it follows, and the telemetry listener publishes nothing
                // administrative (WP-2.5). Behind mutual TLS the ring stays here, by owner
                // decision: a verifier holds no operator certificate.
                if let Some(keys) = context.keys() {
                    let moved = self
                        .keys_location
                        .as_ref()
                        .and_then(|location| location(context.config()));
                    routes = routes.merge(match moved {
                        Some(location) => host::keys_moved_route(location),
                        None => host::keys_route(std::sync::Arc::clone(keys)),
                    });
                }
                routes
            })
            .tls(secured.as_ref())
            .limits(context.config().limits())
            .metrics(context.metrics().clone())
            .start()
            .await
            .context("starting the telemetry surface")?;

            let bound = surface.address();
            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the telemetry surface lock is poisoned"))? = Some(surface);

            info!(
                event.name = "telemetry.listening",
                component = COMPONENT,
                address = %bound,
                tls = secured.is_some(),
                "listening"
            );

            Ok(())
        })
    }

    fn stop<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let surface = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the telemetry surface lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(surface) = surface else {
                return Ok(());
            };

            let address = surface
                .stop(context.config().shutdown_timeout())
                .await
                .context("waiting for the telemetry surface to finish")?;

            info!(
                event.name = "telemetry.stopped_listening",
                component = COMPONENT,
                address = %address,
                "stopped listening"
            );

            Ok(())
        })
    }
}
/// Whether a listen address only accepts connections from this host.
fn scoped_to_loopback(address: &str) -> bool {
    if let Ok(socket) = address.parse::<std::net::SocketAddr>() {
        return socket.ip().is_loopback();
    }
    if let Ok(ip) = address.trim_matches(['[', ']']).parse::<std::net::IpAddr>() {
        return ip.is_loopback();
    }

    address.rsplit_once(':').map_or(address, |(host, _)| host) == "localhost"
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_only_a_loopback_address_counts_as_scoped() {
        for address in [
            "127.0.0.1:5443",
            "[::1]:5443",
            "localhost:5443",
            "::1",
            "127.0.0.1",
            "localhost",
        ] {
            assert!(super::scoped_to_loopback(address), "{address}");
        }
        for address in [
            "0.0.0.0:5443",
            "[::]:5443",
            "10.0.0.7:5443",
            "permguard:5443",
        ] {
            assert!(!super::scoped_to_loopback(address), "{address}");
        }
    }
}
