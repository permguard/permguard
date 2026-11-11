// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The gRPC Health Checking Protocol's `Check` on every Plane's gRPC surface: what HTTP's
//! `/healthz` and `/readyz` answer, for a load balancer or an orchestrator that probes over gRPC.
//! `SERVING` while the Plane accepts work, `NOT_SERVING` before and after; a service name other
//! than the surface's own, empty, or its Plane's, is `NOT_FOUND`, as the protocol says.

use tonic::{Request, Response, Status};

/// The generated half of `grpc.health.v1`.
#[allow(clippy::all, missing_docs)]
pub mod v1 {
    tonic::include_proto!("grpc.health.v1");
}

use v1::health_check_response::ServingStatus;
use v1::health_server::{Health, HealthServer};
use v1::{HealthCheckRequest, HealthCheckResponse};

/// One Plane's health, as its lifecycle says it.
#[derive(Clone)]
pub struct PlaneHealthCheck {
    health: permguard_core::PlaneHealth,
}

#[tonic::async_trait]
impl Health for PlaneHealthCheck {
    async fn check(
        &self,
        request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        let service = request.into_inner().service;
        if !service.is_empty() && service != self.health.plane() {
            return Err(Status::not_found(format!(
                "this surface serves the `{}` Plane, not `{service}`",
                self.health.plane()
            )));
        }
        let serving = self.health.phase().accepts_work();
        Ok(Response::new(HealthCheckResponse {
            status: if serving {
                ServingStatus::Serving
            } else {
                ServingStatus::NotServing
            } as i32,
        }))
    }
}

/// The `grpc.health.v1.Health` service of the Plane `context` serves, for its `RoutesBuilder`.
pub fn service(context: &permguard_core::PlaneContext<'_>) -> HealthServer<PlaneHealthCheck> {
    HealthServer::new(PlaneHealthCheck {
        health: context.health(),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    #[tokio::test]
    async fn a_plane_is_serving_once_it_accepts_work_and_another_name_is_not_found() {
        let health = permguard_core::server::Health::default();
        let lifecycle = health.lifecycle().clone();
        let check = PlaneHealthCheck {
            health: permguard_core::PlaneHealth::new(health.clone(), "data"),
        };
        let ask = |service: &str| {
            let check = check.clone();
            let service = service.to_owned();
            async move {
                check
                    .check(Request::new(HealthCheckRequest { service }))
                    .await
            }
        };
        let before = ask("").await.expect("answered").into_inner().status;
        assert_eq!(before, ServingStatus::NotServing as i32);
        lifecycle.enter(
            "data",
            permguard_core::lifecycle::Kind::Plane,
            true,
            permguard_core::lifecycle::Phase::Ready,
        );
        assert_eq!(
            ask("data").await.expect("answered").into_inner().status,
            ServingStatus::Serving as i32
        );
        assert_eq!(
            ask("control").await.expect_err("another plane").code(),
            tonic::Code::NotFound
        );
    }
}
