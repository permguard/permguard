// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host listener as a [`Service`]: binds `admin.addr` over `admin.tls`, gated by
//! `admin.allow`, and serves both transports of the Host API on it. It starts and stops with
//! the Host's other services and is listed by the lifecycle like them.

use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use tracing::info;

use permguard_core::{BoxFuture, ServerContext, Service, ready};
use permguard_host::api::HostApi;
use permguard_transport::Surface;

use super::COMPONENT;

/// The Host listener.
#[derive(Default)]
pub struct HostApiService {
    running: Mutex<Option<Surface>>,
}

impl HostApiService {
    /// Builds a listener that has not started yet.
    pub fn new() -> Self {
        Self::default()
    }

    /// The address the listener is bound to, while it runs: what a test connects to when the
    /// configuration asked for an ephemeral port.
    pub fn bound(&self) -> Option<std::net::SocketAddr> {
        self.running
            .lock()
            .ok()
            .and_then(|running| running.as_ref().map(Surface::address))
    }
}

impl Service for HostApiService {
    fn name(&self) -> &'static str {
        COMPONENT
    }

    fn start<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            // No address means the deployment did not ask for this listener: grants are then
            // administered offline, with `permguard host grants`.
            let Some(configured) = context.config().admin_addr() else {
                info!(
                    event.name = "host_api.disabled",
                    component = COMPONENT,
                    "no Host listener address is configured; grants are administered offline"
                );
                return Ok(());
            };
            let Some(api) = context.host_handles::<HostApi>() else {
                bail!(
                    "`admin.addr` is {configured} and the composition built no Host API: the \
                     listener has nothing to serve"
                );
            };
            // Validation refused a listener without TLS; this is the same decision, kept where
            // the socket is bound, so a composition that skipped validation cannot serve in the
            // clear.
            let Some(tls) = context.config().admin_tls() else {
                bail!(
                    "the Host listener at {configured} has no TLS material: nothing \
                     administrative travels in the clear"
                );
            };
            if !tls.is_mutual() && !context.config().admin_plain_tls_allowed() {
                bail!(
                    "the Host listener at {configured} demands no client certificate and is not \
                     a loopback bind in development: set `admin.tls.client_ca`"
                );
            }
            let tls = tls.with_allow(context.config().admin_allow().to_vec());
            let surface = Surface::listener(
                COMPONENT,
                configured,
                super::routes(api, context.config().error_detail()),
            )
            .tls(Some(&tls))
            .limits(context.config().limits())
            .metrics(context.metrics().clone())
            .authenticator(context.authenticator())
            // The peer channel is one long-lived stream: bounded per frame, not in total.
            .streaming([super::peer::channel_path()])
            .start()
            .await
            .context("starting the Host listener")?;

            let bound = surface.address();
            *self
                .running
                .lock()
                .map_err(|_| anyhow!("the Host listener lock is poisoned"))? = Some(surface);

            info!(
                event.name = "host_api.listening",
                component = COMPONENT,
                address = %bound,
                mutual_tls = tls.is_mutual(),
                allow = tls.allow().len(),
                "listening"
            );

            Ok(())
        })
    }

    fn stop_intake(&self, _context: &ServerContext<'_>) {
        if let Ok(running) = self.running.lock()
            && let Some(surface) = running.as_ref()
        {
            surface.stop_intake();
        }
    }

    fn drain<'a>(
        &'a self,
        _context: &'a ServerContext<'a>,
        deadline: std::time::Instant,
    ) -> BoxFuture<'a, Result<permguard_core::Drained>> {
        let surface = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the Host listener lock is poisoned"))),
        };
        Box::pin(crate::host::drain_surfaces(
            COMPONENT,
            surface.into_iter().collect(),
            deadline,
        ))
    }

    fn stop<'a>(&'a self, context: &'a ServerContext<'a>) -> BoxFuture<'a, Result<()>> {
        let surface = match self.running.lock() {
            Ok(mut running) => running.take(),
            Err(_) => return ready(Err(anyhow!("the Host listener lock is poisoned"))),
        };

        Box::pin(async move {
            let Some(surface) = surface else {
                return Ok(());
            };

            let address = surface
                .stop(context.config().shutdown_timeout())
                .await
                .context("waiting for the Host listener to finish")?;

            info!(
                event.name = "host_api.stopped_listening",
                component = COMPONENT,
                address = %address,
                "stopped listening"
            );

            Ok(())
        })
    }
}
