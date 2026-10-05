// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What a Plane is given: its own context, never the Host's (P1, P2).
//!
//! A Plane runs inside the Host, and the Host's [`ServerContext`] carries what only the Host may
//! touch: the operations ring, the realms' rings and trails, the raw audit sink, the rings it
//! maintains, every other Plane's handles, and the lifecycle of every component. [`PlaneContext`]
//! is the Plane's view of it, built by the composition root for one Plane: what the Plane serves
//! from, the handles the Host registered for that Plane and no other, and a [`PlaneHealth`] that
//! reads the process's health and reports only the Plane's own requirements and services.
//!
//! The split is by type: none of the Host's accessors exists here, so a Plane cannot reach them
//! however it is written. `scripts/check-composition-root.sh` keeps [`PlaneContext::new`] and
//! [`ServerContext`] itself out of the Plane crates' non-test code.
//!
//! A Plane's background work implements [`PlaneTask`] instead of [`Service`](crate::Service); the
//! composition wraps each one into the Host's service list with the Plane's context.

use std::sync::Arc;
use std::time::SystemTime;

use anyhow::Result;

use crate::lifecycle::{Component, Phase, Report, ServiceState};
use crate::{
    BoxFuture, Catalog, Config, Health, Metrics, ProductIdentity, ServerContext, future::ready,
};

/// One Plane's view of the Host: what it serves from, and nothing the Host keeps for itself.
pub struct PlaneContext<'a> {
    server: &'a ServerContext<'a>,
    plane: &'static str,
}

impl<'a> PlaneContext<'a> {
    /// The context of Plane `plane`, inside `server`. For composition roots and tests only.
    pub fn new(server: &'a ServerContext<'a>, plane: &'static str) -> Self {
        Self { server, plane }
    }

    /// The Plane's id, as configuration spells it.
    pub fn plane(&self) -> &'static str {
        self.plane
    }

    /// The identity of the product the Plane belongs to.
    pub fn identity(&self) -> &ProductIdentity {
        self.server.identity()
    }

    /// The effective configuration.
    pub fn config(&self) -> &Config {
        self.server.config()
    }

    /// Where the numbers the Plane records about itself go.
    pub fn metrics(&self) -> &Metrics {
        self.server.metrics()
    }

    /// The catalog of zones and ledgers, when this build composed one.
    pub fn catalog(&self) -> Option<&Arc<dyn Catalog>> {
        self.server.catalog()
    }

    /// The handles the Host registered for this Plane, as the type the composition stored them as.
    /// Another Plane's handles are not reachable from here.
    pub fn handles<T: std::any::Any + Send + Sync>(&self) -> Option<Arc<T>> {
        self.server.plane_handles::<T>(self.plane)
    }

    /// The process's health as this Plane reads and reports it.
    pub fn health(&self) -> PlaneHealth {
        PlaneHealth {
            health: self.server.health().clone(),
            plane: self.plane,
        }
    }
}

/// The process's health, read by a Plane, and its own part of the lifecycle reported by it.
///
/// It reads everything a health surface shows; it writes only what belongs to its Plane: the
/// Plane's requirements, its degraded capabilities and its services' states. The Host's phase,
/// another Plane's, liveness and the process's readiness are not the Plane's to set.
#[derive(Debug, Clone)]
pub struct PlaneHealth {
    health: Health,
    plane: &'static str,
}

impl PlaneHealth {
    /// A Plane's view of `health`. For composition roots and tests only.
    pub fn new(health: Health, plane: &'static str) -> Self {
        Self { health, plane }
    }

    /// The Plane's id.
    pub fn plane(&self) -> &'static str {
        self.plane
    }

    /// Whether the process is live.
    pub fn is_live(&self) -> bool {
        self.health.is_live()
    }

    /// Whether the process accepts work: the Host and every required Plane are Ready or Serving.
    pub fn is_ready(&self) -> bool {
        self.health.is_ready()
    }

    /// The Plane's own phase; Bootstrap until the Host lists it.
    pub fn phase(&self) -> Phase {
        self.health
            .lifecycle()
            .phase(self.plane)
            .unwrap_or(Phase::Bootstrap)
    }

    /// The Plane as health reports it.
    pub fn component(&self) -> Option<Component> {
        self.health.lifecycle().component(self.plane)
    }

    /// Every component: the Host, every configured Plane, every service.
    pub fn components(&self) -> Vec<Component> {
        self.health.lifecycle().components()
    }

    /// The health body's lifecycle part, as this Plane reports it: its phase, what it serves
    /// without, and every component.
    pub fn report(&self) -> Report {
        self.health.lifecycle().report(self.plane)
    }

    /// The Plane cannot leave Load until `requirement` is satisfied; it is stalled since `now`
    /// for `reason`. Once the Plane accepts work, a lost requirement is reported as degraded.
    pub fn wait(&self, requirement: &str, reason: impl Into<String>, now: SystemTime) {
        self.health
            .lifecycle()
            .wait(self.plane, requirement, reason, now);
    }

    /// `requirement` is satisfied.
    pub fn satisfy(&self, requirement: &str) {
        self.health.lifecycle().satisfy(self.plane, requirement);
    }

    /// Reports the state of one of the Plane's services.
    pub fn service(
        &self,
        name: &str,
        state: ServiceState,
        last_success: Option<SystemTime>,
        next_attempt: Option<SystemTime>,
        reason: Option<String>,
    ) {
        self.health
            .lifecycle()
            .service(name, state, last_success, next_attempt, reason);
    }
}

/// A Plane's background work: started with the Plane's context, after the Host is Ready.
///
/// What [`Service`](crate::Service) promises holds here too: `start` returns once the work is up,
/// and what must keep running belongs on a task it spawns and cancels in `stop`.
pub trait PlaneTask: Send + Sync {
    /// The name of this work, for banners, diagnostics, audit records and health.
    fn name(&self) -> &'static str;

    /// Brings the work up, or reports why it could not come up.
    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>>;

    /// Takes the work down; the default has nothing to release.
    fn stop<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        let _ = context;

        ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use crate::lifecycle::{HOST, Kind};

    #[test]
    fn a_plane_reports_only_its_own_requirements() {
        let health = Health::new();
        let lifecycle = health.lifecycle();
        lifecycle.enter("data", Kind::Plane, true, Phase::Load);
        lifecycle.enter("control", Kind::Plane, true, Phase::Load);
        let data = PlaneHealth::new(health.clone(), "data");
        data.wait("ledgers", "none mirrored", SystemTime::now());
        assert_eq!(lifecycle.awaiting("data"), vec!["ledgers"]);
        assert!(lifecycle.awaiting("control").is_empty());
        assert_eq!(data.phase(), Phase::Load);
        assert_eq!(
            lifecycle.phase(HOST),
            Some(Phase::Bootstrap),
            "the Host is not the Plane's"
        );
    }
}
