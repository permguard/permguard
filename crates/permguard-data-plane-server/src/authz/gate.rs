// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Authorization before evaluation, as each transport answers a refusal: the decision itself is
//! the domain's (`permguard_data_plane::authz::gate`), taken by the evaluation pipeline.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tonic::Status;
use tonic::metadata::MetadataValue;

use permguard_core::AccessDenial;

/// A denial over HTTP: the closed `{code, message}` body, `401` with the challenge or `403`.
pub fn http_denial(denial: &AccessDenial) -> Response {
    tracing::debug!(
        event.name = "authz.denied",
        component = "data-plane",
        error.code = denial.code(),
        "an evaluation was denied"
    );
    let status = StatusCode::from_u16(denial.http_status()).unwrap_or(StatusCode::FORBIDDEN);
    let mut response = (status, Json(denial.on_the_wire())).into_response();
    if let Some(challenge) = denial.challenge()
        && let Ok(value) = axum::http::HeaderValue::from_str(challenge)
    {
        response
            .headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, value);
    }
    response
}

/// A denial over gRPC: `UNAUTHENTICATED` or `PERMISSION_DENIED`, the code as metadata.
pub fn grpc_denial(denial: &AccessDenial) -> Status {
    tracing::debug!(
        event.name = "authz.denied",
        component = "data-plane",
        error.code = denial.code(),
        "an evaluation was denied"
    );
    let mut status = Status::new(
        tonic::Code::from(denial.grpc_code().number()),
        denial.message().to_owned(),
    );
    if let Ok(code) = MetadataValue::try_from(denial.code()) {
        status
            .metadata_mut()
            .insert(permguard_core::GRPC_ERROR_CODE, code);
    }
    status
}
