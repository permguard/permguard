// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! Where an [`ApiError`] becomes an answer — once, for every domain this plane will ever serve.
//!
//! A domain module produces `Result<T, ApiError>` and never sees a status code; this module owns the
//! two translations. The mapping itself is not decided here: the class and the code decide the HTTP
//! and gRPC statuses in `permguard-core`, so every surface of every plane answers the same way, and
//! this module only renders that decision on the two wires. Adding a domain adds no error-mapping
//! code, and adding an error class is a change in the core taxonomy rather than in every handler.
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

use permguard_core::{ApiError, Disclosure, ErrorClass, GrpcCode};

/// The gRPC metadata keys carrying the structured half of a refusal: the one pair every surface and
/// every client uses, defined with the taxonomy.
pub use permguard_core::{GRPC_ERROR_CLASS, GRPC_ERROR_CODE};

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

/// The HTTP status the taxonomy assigns to a refusal.
pub fn http_status(error: &ApiError) -> StatusCode {
    StatusCode::from_u16(error.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
}

/// Turns a refusal into the HTTP answer: the class's status, the shared JSON body.
pub fn http_error(error: &ApiError, disclosure: Disclosure) -> Response {
    record(error);

    (http_status(error), Json(error.on_the_wire(disclosure))).into_response()
}

/// A gRPC status of the given code carrying `message`.
pub fn grpc_status(code: GrpcCode, message: String) -> Status {
    match code {
        GrpcCode::InvalidArgument => Status::invalid_argument(message),
        GrpcCode::NotFound => Status::not_found(message),
        GrpcCode::AlreadyExists => Status::already_exists(message),
        GrpcCode::PermissionDenied => Status::permission_denied(message),
        GrpcCode::FailedPrecondition => Status::failed_precondition(message),
        GrpcCode::Internal => Status::internal(message),
        GrpcCode::Unavailable => Status::unavailable(message),
        GrpcCode::Unauthenticated => Status::unauthenticated(message),
    }
}

/// Attaches the class and the code as metadata, so both transports say one thing.
pub fn with_refusal_metadata(mut status: Status, class: &str, code: &str) -> Status {
    let metadata = status.metadata_mut();

    if let Ok(class) = MetadataValue::try_from(class) {
        metadata.insert(GRPC_ERROR_CLASS, class);
    }
    if let Ok(code) = MetadataValue::try_from(code) {
        metadata.insert(GRPC_ERROR_CODE, code);
    }

    status
}

/// Turns a refusal into the gRPC answer: the taxonomy's status, the same fields as metadata.
pub fn grpc_error(error: &ApiError, disclosure: Disclosure) -> Status {
    record(error);

    with_refusal_metadata(
        grpc_status(error.grpc_code(), error.disclosed_message(disclosure)),
        error.class().as_str(),
        error.code(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use permguard_core::codes;

    #[test]
    fn test_validation_answers_the_contract_status_on_both_wires() {
        let refused = ApiError::new(
            ErrorClass::Validation,
            codes::catalog::INVALID_NAME,
            "not a name",
        );

        assert_eq!(http_status(&refused), StatusCode::BAD_REQUEST);
        let status = grpc_error(&refused, Disclosure::Minimal);
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert_eq!(
            status
                .metadata()
                .get(GRPC_ERROR_CODE)
                .and_then(|v| v.to_str().ok()),
            Some("invalid_name")
        );
        assert_eq!(
            status
                .metadata()
                .get(GRPC_ERROR_CLASS)
                .and_then(|v| v.to_str().ok()),
            Some("validation")
        );
    }

    #[test]
    fn test_a_taken_name_is_already_exists_and_an_occupied_zone_is_a_precondition() {
        let taken = ApiError::new(ErrorClass::Conflict, codes::catalog::NAME_TAKEN, "taken");
        let occupied = ApiError::new(ErrorClass::Conflict, codes::catalog::NOT_EMPTY, "occupied");

        assert_eq!(
            grpc_error(&taken, Disclosure::Minimal).code(),
            tonic::Code::AlreadyExists
        );
        assert_eq!(
            grpc_error(&occupied, Disclosure::Minimal).code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(http_status(&taken), StatusCode::CONFLICT);
        assert_eq!(http_status(&occupied), StatusCode::CONFLICT);
    }
}
