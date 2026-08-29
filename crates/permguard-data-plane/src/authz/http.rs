// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The decision endpoint's HTTP shape: routes, headers, status codes.
//!
//! Three lines per handler, because everything that can be wrong lives in
//! [`super::decide`] and everything about *saying* it lives in
//! [`crate::authz::wire`]. What is here is the interface's HTTP binding: `POST`,
//! `application/json`, `X-Request-ID` echoed, and the status codes a PEP
//! switches on.
//!
//! # Status codes
//!
//! | Situation | Answer |
//! | --- | --- |
//! | a decision, permit or deny | `200` with `{"decision": …}` |
//! | the payload is not a request | `400` |
//! | the ledger is not served here | `404` |
//! | the ledger cannot be evaluated (empty, incompatible, damaged) | `503` |
//! | this process failed | `500` |
//!
//! A deny is **never** a 4xx: it is an answer. And `400` here rather than the
//! `422` the rest of this server uses for validation, deliberately — this
//! surface implements a published contract, and the contract says
//! `400 Bad Request`.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use permguard_core::{ApiError, Disclosure, ErrorClass};

use super::configuration;
use super::decide::Decider;
use super::wire::{CheckRequest, TraceContext};

/// The correlation header, echoed verbatim when the caller sends it.
const REQUEST_ID: &str = "x-request-id";
/// The W3C Trace Context header, so a decision joins the request that caused it.
const TRACEPARENT: &str = "traceparent";

/// What the handlers share.
#[derive(Clone)]
pub struct Surface {
    pub decider: std::sync::Arc<Decider>,
    pub disclosure: Disclosure,
    /// The base URL this plane is reached at, for the configuration document.
    pub base_url: String,
}

/// The routes the decision endpoint answers.
pub fn routes(surface: Surface) -> Router {
    // Mounted from the interface's own constants, which is also what the configuration document
    // advertises — so the document cannot name a path this plane does not answer.
    Router::new()
        .route(
            permguard_languages::request::EVALUATION_PATH,
            post(evaluation),
        )
        .route(
            permguard_languages::request::EVALUATIONS_PATH,
            post(evaluations),
        )
        .route(
            permguard_languages::request::CONFIGURATION_PATH,
            get(pdp_configuration),
        )
        .with_state(surface)
}

async fn evaluation(
    State(surface): State<Surface>,
    headers: HeaderMap,
    body: Result<Json<CheckRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    answer(&surface, &headers, body).await
}

/// The boxcarred endpoint. The same handler: a request with no `evaluations[]`
/// is a single check.
async fn evaluations(
    State(surface): State<Surface>,
    headers: HeaderMap,
    body: Result<Json<CheckRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    answer(&surface, &headers, body).await
}

async fn answer(
    surface: &Surface,
    headers: &HeaderMap,
    body: Result<Json<CheckRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let request_id = headers
        .get(REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);
    // The trace this request belongs to, when the caller propagated one. A
    // header, so it is read here and not in the decision path.
    let trace = headers
        .get(TRACEPARENT)
        .and_then(|value| value.to_str().ok())
        .and_then(TraceContext::parse);

    let Json(mut request) = match body {
        Ok(body) => body,
        Err(rejection) => {
            // A payload that is not JSON never reaches a policy: it is a bad
            // request, and saying which is more useful than a bare 400.
            return with_request_id(
                error(
                    &ApiError::new(
                        ErrorClass::Validation,
                        "payload_malformed",
                        format!("the request body is not a valid payload: {rejection}"),
                    ),
                    surface.disclosure,
                ),
                request_id.as_deref(),
            );
        }
    };
    // The header is the transport's way of saying it; the body is the
    // profile's. Either does, and the body wins because it is the one a
    // boxcarred evaluation can carry per entry.
    if request.request_id.is_none() {
        request.request_id = request_id.clone();
    }

    let response = match surface.decider.decide(&request, trace).await {
        Ok(answered) => (StatusCode::OK, Json(answered)).into_response(),
        Err(failed) => error(&failed, surface.disclosure),
    };

    with_request_id(response, request_id.as_deref())
}

/// The `permguard.api.pdp.native.v1` configuration: what this interface offers here.
///
/// Answered as a value: the response type serializes it, so there is no path where a failure to
/// render becomes a `200` carrying an empty object.
async fn pdp_configuration(State(surface): State<Surface>) -> Json<configuration::Configuration> {
    Json(configuration::configuration(&surface.base_url))
}

/// Turns a refusal into the answer the contract names.
fn error(failed: &ApiError, disclosure: Disclosure) -> Response {
    let status = match failed.class() {
        // The contract's own status for a payload that is not a request.
        ErrorClass::Validation => StatusCode::BAD_REQUEST,
        ErrorClass::NotFound => StatusCode::NOT_FOUND,
        ErrorClass::Conflict => StatusCode::CONFLICT,
        ErrorClass::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
        ErrorClass::Internal => StatusCode::INTERNAL_SERVER_ERROR,
    };

    (status, Json(failed.on_the_wire(disclosure))).into_response()
}

fn with_request_id(mut response: Response, request_id: Option<&str>) -> Response {
    if let Some(request_id) = request_id
        && let Ok(value) = HeaderValue::from_str(request_id)
    {
        response
            .headers_mut()
            .insert(HeaderName::from_static(REQUEST_ID), value);
    }

    response
}
