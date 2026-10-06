// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How the facade's refusals reach each wire: the taxonomy's status and the shared body over
//! HTTP, the taxonomy's code and the same fields as metadata over gRPC. A conflict carries the
//! current revision: as a `revision` member of the body, and as `permguard-revision` metadata.

use axum::Json;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use tonic::Status;
use tonic::metadata::MetadataValue;

use permguard_core::{
    AccessDenial, ApiError, Disclosure, ErrorClass, GRPC_ERROR_CLASS, GRPC_ERROR_CODE,
};
use permguard_host::api::Refusal;

use super::COMPONENT;

/// The gRPC metadata key carrying the current revision beside a conflict.
pub const GRPC_REVISION: &str = "permguard-revision";

/// Writes the operator's copy of a refusal. `warn` for what is this process's own failure;
/// `debug` for what the caller caused or asked for, including a route a later package serves and
/// a principal over its bound, which would otherwise warn once per refused request.
fn record(error: &ApiError) {
    let routine = matches!(
        error.code(),
        permguard_core::codes::host::NOT_SERVED_YET
            | permguard_core::codes::host::PRINCIPAL_BOUND_EXCEEDED
    );
    match error.class() {
        ErrorClass::Internal | ErrorClass::Unavailable if !routine => tracing::warn!(
            event.name = "api.failed",
            component = COMPONENT,
            error.class = error.class().as_str(),
            error.code = error.code(),
            error.message = %error.disclosed_message(Disclosure::Full),
            "a Host API call could not be served"
        ),
        _ => tracing::debug!(
            event.name = "api.refused",
            component = COMPONENT,
            error.class = error.class().as_str(),
            error.code = error.code(),
            error.message = %error.disclosed_message(Disclosure::Full),
            "a Host API call was refused"
        ),
    }
}

fn record_denial(denial: &AccessDenial) {
    tracing::debug!(
        event.name = "api.denied",
        component = COMPONENT,
        error.code = denial.code(),
        "a Host API call was denied"
    );
}

/// A refusal over HTTP.
pub fn http_refusal(refusal: &Refusal, disclosure: Disclosure) -> Response {
    match refusal {
        Refusal::Api(error) => http_error(error, None, disclosure),
        Refusal::Conflict { error, revision } => http_error(error, Some(*revision), disclosure),
        Refusal::Denied(denial) => http_denial(denial),
    }
}

/// A refusal over gRPC.
pub fn grpc_refusal(refusal: &Refusal, disclosure: Disclosure) -> Status {
    match refusal {
        Refusal::Api(error) => grpc_error(error, None, disclosure),
        Refusal::Conflict { error, revision } => grpc_error(error, Some(*revision), disclosure),
        Refusal::Denied(denial) => grpc_denial(denial),
    }
}

fn http_error(error: &ApiError, revision: Option<u64>, disclosure: Disclosure) -> Response {
    record(error);
    let status =
        StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut body = serde_json::to_value(error.on_the_wire(disclosure)).unwrap_or_default();
    if let (Some(revision), Some(members)) = (revision, body.as_object_mut()) {
        members.insert("revision".to_owned(), serde_json::Value::from(revision));
    }
    (status, Json(body)).into_response()
}

fn http_denial(denial: &AccessDenial) -> Response {
    record_denial(denial);
    let status = StatusCode::from_u16(denial.http_status()).unwrap_or(StatusCode::FORBIDDEN);
    let mut response = (status, Json(denial.on_the_wire())).into_response();
    if let Some(challenge) = denial.challenge()
        && let Ok(value) = HeaderValue::from_str(challenge)
    {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    response
}

fn grpc_error(error: &ApiError, revision: Option<u64>, disclosure: Disclosure) -> Status {
    record(error);
    let mut status = Status::new(
        tonic::Code::from(error.grpc_code().number()),
        error.disclosed_message(disclosure),
    );
    let metadata = status.metadata_mut();
    if let Ok(class) = MetadataValue::try_from(error.class().as_str()) {
        metadata.insert(GRPC_ERROR_CLASS, class);
    }
    if let Ok(code) = MetadataValue::try_from(error.code()) {
        metadata.insert(GRPC_ERROR_CODE, code);
    }
    if let Some(revision) = revision
        && let Ok(value) = MetadataValue::try_from(revision.to_string())
    {
        metadata.insert(GRPC_REVISION, value);
    }
    status
}

fn grpc_denial(denial: &AccessDenial) -> Status {
    record_denial(denial);
    let mut status = Status::new(
        tonic::Code::from(denial.grpc_code().number()),
        denial.message().to_owned(),
    );
    if let Ok(code) = MetadataValue::try_from(denial.code()) {
        status.metadata_mut().insert(GRPC_ERROR_CODE, code);
    }
    status
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;
    use permguard_core::codes;

    #[test]
    fn a_conflict_carries_the_revision_on_both_wires() {
        let refusal = Refusal::revision_mismatch(3, 5);
        let response = http_refusal(&refusal, Disclosure::Minimal);
        assert_eq!(response.status(), StatusCode::CONFLICT);
        let status = grpc_refusal(&refusal, Disclosure::Minimal);
        assert_eq!(status.code(), tonic::Code::FailedPrecondition);
        assert_eq!(
            status
                .metadata()
                .get(GRPC_REVISION)
                .and_then(|value| value.to_str().ok()),
            Some("5")
        );
        assert_eq!(
            status
                .metadata()
                .get(GRPC_ERROR_CODE)
                .and_then(|value| value.to_str().ok()),
            Some(codes::host::REVISION_MISMATCH)
        );
    }

    #[test]
    fn a_denial_is_401_with_the_challenge_or_403() {
        let nobody = Refusal::Denied(AccessDenial::unauthenticated("who?"));
        let response = http_refusal(&nobody, Disclosure::Minimal);
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        assert_eq!(
            grpc_refusal(&nobody, Disclosure::Minimal).code(),
            tonic::Code::Unauthenticated
        );
        let somebody = Refusal::Denied(AccessDenial::forbidden("no"));
        assert_eq!(
            http_refusal(&somebody, Disclosure::Minimal).status(),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            grpc_refusal(&somebody, Disclosure::Minimal).code(),
            tonic::Code::PermissionDenied
        );
    }
}
