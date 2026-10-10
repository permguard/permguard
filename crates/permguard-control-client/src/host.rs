// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host listener, as a client sees it (TC-1): one facade over REST and gRPC, the scheme of
//! one URL deciding which (`https` or `grpcs`).
//!
//! The answers are the Host API's own views (`permguard_host::api`), read from JSON over REST and
//! mapped field for field from the generated messages over gRPC, so a command built on this
//! facade prints the same report whichever transport carried it. A refusal is the same
//! `{class, code, message}` on both: the REST body, or the gRPC status and its metadata.
//!
//! Today it reads the status and the identity; TC-2's `host` commands add the rest.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use permguard_host::api::identity::IdentityView;
use permguard_host::api::sessions::PeerSessionsView;
use permguard_host::api::status::{
    Assurance, ComponentView, DegradedView, ListenerView, StatusView,
};

use crate::catalog::Failure;
use crate::endpoint::Endpoint;
use crate::grpc::GrpcChannel;
use crate::host_v1 as proto;
use crate::http::Client;
use crate::tls::TlsOptions;

/// What the Host listener answers, whichever transport asked.
pub trait Host {
    /// `GET /host/v1/status`, `OperationsService.GetStatus`.
    fn status(&self) -> Result<StatusView, Failure>;
    /// `GET /host/v1/identity`, `IdentityService.GetIdentity`.
    fn identity(&self) -> Result<IdentityView, Failure>;
}

/// Connects to a Host listener: `https`/`http` ride REST, `grpcs`/`grpc` gRPC.
pub fn client(
    url: &str,
    tls: &TlsOptions,
    narrator: Box<dyn crate::narrate::Narrator>,
) -> Result<Box<dyn Host>, String> {
    let endpoint = Endpoint::parse(url).map_err(|error| error.to_string())?;
    if endpoint.is_grpc() {
        return Ok(Box::new(GrpcHost(GrpcChannel::connect(
            url, tls, narrator,
        )?)));
    }
    let client = Client::new(
        std::time::Duration::from_secs(30),
        tls.clone(),
        endpoint.is_tls(),
    )
    .map_err(|error| error.to_string())?
    .with_narrator(narrator);
    Ok(Box::new(RestHost { client, endpoint }))
}

struct RestHost {
    client: Client,
    endpoint: Endpoint,
}

impl Host for RestHost {
    fn status(&self) -> Result<StatusView, Failure> {
        crate::catalog::call(&self.client, &self.endpoint, "GET", "/host/v1/status", None)
    }

    fn identity(&self) -> Result<IdentityView, Failure> {
        crate::catalog::call(
            &self.client,
            &self.endpoint,
            "GET",
            "/host/v1/identity",
            None,
        )
    }
}

struct GrpcHost(GrpcChannel);

impl Host for GrpcHost {
    fn status(&self) -> Result<StatusView, Failure> {
        let mut client =
            proto::operations_service_client::OperationsServiceClient::new(self.0.channel());
        let answer = self
            .0
            .run("GetStatus", client.get_status(proto::GetStatusRequest {}))
            .map_err(crate::grpc::failure_of)?;
        Ok(status_of(answer))
    }

    fn identity(&self) -> Result<IdentityView, Failure> {
        let mut client =
            proto::identity_service_client::IdentityServiceClient::new(self.0.channel());
        let answer = self
            .0
            .run(
                "GetIdentity",
                client.get_identity(proto::GetIdentityRequest {}),
            )
            .map_err(crate::grpc::failure_of)?;
        // REST carries bytes as base64url without padding; the view is that spelling on both.
        Ok(IdentityView {
            document: URL_SAFE_NO_PAD.encode(answer.document),
            successions: answer
                .successions
                .iter()
                .map(|record| URL_SAFE_NO_PAD.encode(record))
                .collect(),
            first_public_key: URL_SAFE_NO_PAD.encode(answer.first_public_key),
            protocol_versions: answer.protocol_versions,
        })
    }
}

/// The status view a `GetStatusResponse` means, field for field.
fn status_of(answer: proto::GetStatusResponse) -> StatusView {
    let assurance = answer.assurance.unwrap_or_default();
    let peer_sessions = answer.peer_sessions.unwrap_or_default();
    StatusView {
        live: answer.live,
        ready: answer.ready,
        state: answer.state,
        degraded: answer
            .degraded
            .into_iter()
            .map(|degraded| DegradedView {
                capability: degraded.capability,
                reason: degraded.reason,
            })
            .collect(),
        components: answer
            .components
            .into_iter()
            .map(|component| ComponentView {
                component: component.component,
                kind: component.kind,
                state: component.state,
                required: component.required,
                stalled_since: component.stalled_since,
                last_success: component.last_success,
                next_attempt: component.next_attempt,
                reason: component.reason,
            })
            .collect(),
        assurance: Assurance {
            profile: assurance.profile,
            enforcement: assurance.enforcement,
            added_controls: assurance.added_controls,
            relaxations: assurance.relaxations,
        },
        peer_sessions: PeerSessionsView {
            served: peer_sessions.served,
            reason: peer_sessions.reason,
        },
        listeners: answer
            .listeners
            .into_iter()
            .map(|listener| ListenerView {
                name: listener.name,
                class: listener.class,
                authentication: listener.authentication,
                client_allow: listener.client_allow,
                tls_min_version: listener.tls_min_version,
            })
            .collect(),
    }
}
