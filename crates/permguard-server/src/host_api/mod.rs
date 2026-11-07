// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host listener (WP-2.5): REST under `/host/v1` and gRPC in `permguard.host.v1`, on one
//! port, over the one facade `permguard_host::api::HostApi`; on the IAM Host also the directory,
//! REST under `/iam/v1` and gRPC in `permguard.iam.v1` (WP-11.1). The handlers here decode, hand the
//! actor the boundary decided to the facade, and map its answer onto the wire; nothing is
//! decided in this module.
//!
//! The listener is the `admin` section of the configuration: `admin.addr`, `admin.tls` and
//! `admin.allow` (owner decision, 2026-10-06). TLS is required and mutual TLS with it, except on
//! a loopback bind under `development_mode`; `admin.allow` is a peer gate before the credential
//! mapper; every route authorizes with the Host's grants.

pub mod grpc;
pub mod http;
pub mod peer;
pub mod service;
pub(crate) mod wire;

/// The generated server half of `permguard.iam.v1` (iteration 02, WP-11.1).
#[allow(clippy::all, missing_docs)]
pub mod iam_v1 {
    include!(concat!(env!("OUT_DIR"), "/iam/permguard.iam.v1.rs"));
}

/// The generated server half of `permguard.host.v1`.
#[allow(clippy::all, missing_docs)]
pub mod v1 {
    tonic::include_proto!("permguard.host.v1");
}

use std::sync::Arc;

use axum::Router;
use tonic::service::RoutesBuilder;

use permguard_core::Disclosure;
use permguard_host::api::HostApi;

pub use service::HostApiService;

/// The `component` every record of the listener carries.
pub const COMPONENT: &str = "host-api";

/// Both transports of the Host API on one router: the REST routes and the gRPC services, the
/// path nothing serves answered as the protocol's own "no such thing".
pub fn routes(api: Arc<HostApi>, disclosure: Disclosure) -> Router {
    let rest = http::routes(Arc::clone(&api), disclosure);
    crate::plane::shared_port(rest, grpc_routes(api, disclosure).into_axum_router())
}

/// The gRPC services of the Host API, for a composition that serves them on their own.
pub fn grpc_routes(api: Arc<HostApi>, disclosure: Disclosure) -> tonic::service::Routes {
    let mut routes = RoutesBuilder::default();
    let iam_host = api.is_iam_host();
    let served = grpc::Served::new(api, disclosure);
    routes.add_service(
        v1::identity_service_server::IdentityServiceServer::new(served.clone())
            .max_decoding_message_size(peer::MAX_MESSAGE_BYTES),
    );
    routes.add_service(v1::key_service_server::KeyServiceServer::new(
        served.clone(),
    ));
    routes.add_service(v1::membership_service_server::MembershipServiceServer::new(
        served.clone(),
    ));
    routes.add_service(v1::evidence_service_server::EvidenceServiceServer::new(
        served.clone(),
    ));
    routes.add_service(v1::operations_service_server::OperationsServiceServer::new(
        served.clone(),
    ));
    // The directory of the IAM Host (WP-11.1): a member serves none.
    if iam_host {
        routes.add_service(iam_v1::grant_service_server::GrantServiceServer::new(
            served.clone(),
        ));
        routes.add_service(iam_v1::role_service_server::RoleServiceServer::new(
            served.clone(),
        ));
        routes.add_service(iam_v1::user_service_server::UserServiceServer::new(
            served.clone(),
        ));
        routes.add_service(iam_v1::provider_service_server::ProviderServiceServer::new(
            served.clone(),
        ));
        routes.add_service(iam_v1::recovery_service_server::RecoveryServiceServer::new(
            served.clone(),
        ));
        routes.add_service(
            iam_v1::service_account_service_server::ServiceAccountServiceServer::new(
                served.clone(),
            ),
        );
        routes.add_service(iam_v1::token_service_server::TokenServiceServer::new(
            served,
        ));
    }
    routes.routes()
}
