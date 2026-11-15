// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! How a refusal of the facade reaches either wire: the same class and code over REST and gRPC.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use tonic::Status;
use tonic::metadata::MetadataValue;

use permguard_core::{
    AccessDenial, ApiError, Disclosure, ErrorClass, GRPC_ERROR_CLASS, GRPC_ERROR_CODE,
};

use crate::authority::Refusal;

fn record(error: &ApiError) {
    match error.class() {
        ErrorClass::Internal | ErrorClass::Unavailable => tracing::error!(
            event.name = "api.failed",
            component = crate::COMPONENT,
            error.class = error.class().as_str(),
            error.code = error.code(),
            error.message = %error.disclosed_message(Disclosure::Full),
            "an api call failed inside the server"
        ),
        _ => tracing::debug!(
            event.name = "api.refused",
            component = crate::COMPONENT,
            error.class = error.class().as_str(),
            error.code = error.code(),
            "an api call was refused"
        ),
    }
}

fn http_denial(denial: &AccessDenial) -> Response {
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

/// The REST answer of `refusal`.
pub fn http_refusal(refusal: &Refusal, disclosure: Disclosure) -> Response {
    match refusal {
        Refusal::Api(error) => {
            record(error);
            let status = StatusCode::from_u16(error.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
            (status, Json(error.on_the_wire(disclosure))).into_response()
        }
        Refusal::Denied(denial) => http_denial(denial),
    }
}

fn status_of(code: permguard_core::GrpcCode, message: String) -> Status {
    Status::new(tonic::Code::from(code.number()), message)
}

/// The gRPC answer of `refusal`.
pub fn grpc_refusal(refusal: &Refusal, disclosure: Disclosure) -> Status {
    match refusal {
        Refusal::Api(error) => {
            record(error);
            let mut status = status_of(error.grpc_code(), error.disclosed_message(disclosure));
            let metadata = status.metadata_mut();
            if let Ok(class) = MetadataValue::try_from(error.class().as_str()) {
                metadata.insert(GRPC_ERROR_CLASS, class);
            }
            if let Ok(code) = MetadataValue::try_from(error.code()) {
                metadata.insert(GRPC_ERROR_CODE, code);
            }
            status
        }
        Refusal::Denied(denial) => {
            let mut status = status_of(denial.grpc_code(), denial.message().to_owned());
            if let Ok(code) = MetadataValue::try_from(denial.code()) {
                status.metadata_mut().insert(GRPC_ERROR_CODE, code);
            }
            status
        }
    }
}
