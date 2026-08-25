// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where an [`ApiError`] becomes an answer — once, for every domain this plane will ever serve.
//!
//! A domain module produces `Result<T, ApiError>` and never sees a status code; this module owns the
//! two translations. Adding a domain adds no error-mapping code, and adding an error class is a
//! change here rather than in every handler that might meet it.
//!
//! # The two audiences, separated here
//!
//! Before anything reaches a wire, an error's internal detail — the path, the io error — is written
//! to this process's own log at full fidelity, always. What crosses the wire is then decided by the
//! deployment's [`Disclosure`]: `full` on a workstation, `minimal` anywhere real. The operator loses
//! nothing; the caller learns the class, the code and a safe sentence.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tonic::Status;
use tonic::metadata::MetadataValue;

use permguard_core::{ApiError, Disclosure, ErrorClass};

/// The gRPC metadata keys carrying the structured half of a refusal.
///
/// gRPC's status line has one message string; the class and the code — the fields a client switches
/// on — ride as metadata so no client ever parses them out of a sentence.
pub const GRPC_ERROR_CLASS: &str = "x-permguard-error-class";
pub const GRPC_ERROR_CODE: &str = "x-permguard-error-code";

/// Writes the operator's copy of a refusal: everything, whatever the wire is about to say.
///
/// `warn` for the classes a caller caused and can fix; `error` for the ones that are this process's
/// own failure — those are the records an alert should wake somebody for.
fn record(error: &ApiError) {
    match error.class() {
        ErrorClass::Internal | ErrorClass::Unavailable => tracing::error!(
            event.name = "api.failed",
            component = "control-plane",
            error.class = error.class().as_str(),
            error.code = error.code(),
            error.message = %error.disclosed_message(Disclosure::Full),
            "an api call failed inside the server"
        ),
        _ => tracing::debug!(
            event.name = "api.refused",
            component = "control-plane",
            error.class = error.class().as_str(),
            error.code = error.code(),
            error.message = %error.disclosed_message(Disclosure::Full),
            "an api call was refused"
        ),
    }
}

/// Turns a refusal into the HTTP answer: the class's status, the shared JSON body.
pub fn http_error(error: &ApiError, disclosure: Disclosure) -> Response {
    record(error);

    let status = match error.class() {
        ErrorClass::Validation => StatusCode::UNPROCESSABLE_ENTITY,
        ErrorClass::Conflict => StatusCode::CONFLICT,
        ErrorClass::NotFound => StatusCode::NOT_FOUND,
        ErrorClass::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorClass::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (status, Json(error.on_the_wire(disclosure))).into_response()
}

/// Turns a refusal into the gRPC answer: the class's status, the same fields as metadata.
pub fn grpc_error(error: &ApiError, disclosure: Disclosure) -> Status {
    record(error);

    let message = error.disclosed_message(disclosure);
    let mut status = match error.class() {
        ErrorClass::Validation => Status::invalid_argument(message),
        // gRPC tells apart the two conflicts HTTP folds into 409: a name that exists already, and a
        // precondition — an occupied zone — that the caller has to clear first.
        ErrorClass::Conflict if error.code() == "name_taken" => Status::already_exists(message),
        ErrorClass::Conflict => Status::failed_precondition(message),
        ErrorClass::NotFound => Status::not_found(message),
        ErrorClass::Unavailable => Status::unavailable(message),
        ErrorClass::Internal => Status::internal(message),
    };

    let metadata = status.metadata_mut();

    if let Ok(class) = MetadataValue::try_from(error.class().as_str()) {
        metadata.insert(GRPC_ERROR_CLASS, class);
    }
    if let Ok(code) = MetadataValue::try_from(error.code()) {
        metadata.insert(GRPC_ERROR_CODE, code);
    }

    status
}
