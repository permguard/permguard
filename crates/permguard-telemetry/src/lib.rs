// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The telemetry surface: liveness, readiness and metrics.
//!
//! It is HTTP and it is on a port of its own, and both of those are deliberate.
//!
//! **HTTP**, because this is the one surface whose clients are not ours: Prometheus scrapes over
//! HTTP and a kubelet probes over HTTP. Serving it over gRPC would mean every operator needs a custom
//! client to read a number.
//!
//! **A port of its own**, because it must never leave the cluster. Metrics describe the inside of the
//! process and health tells an attacker when the process is struggling; neither belongs on the port
//! that faces the world.
//!
//! # Liveness is not readiness
//!
//! `/healthz` answers "is this process wedged", and a `false` means *restart me*. `/readyz` answers
//! "should I be sent work", and it goes false at the very start of shutdown — before anything is
//! closed — so a load balancer stops routing while the process is still able to finish what it
//! already has. Reporting one number for both loses requests at every deploy.

#![forbid(unsafe_code)]
#![deny(clippy::all, clippy::unwrap_used, clippy::expect_used)]

pub mod exposition;
pub mod probes;
pub mod service;

pub use exposition::render;
pub use probes::Reported;
pub use service::TelemetryService;
