// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The temporal interface's HTTP binding: one route, and the status codes a caller switches on.
//!
//! # Status codes
//!
//! | Situation | Answer |
//! | --- | --- |
//! | a decision, permit or deny | `200` with `{"outcome": "decided", "decision": …}` |
//! | a history-only kind, recorded | `200` with `{"outcome": "accepted"}` |
//! | the payload is not a submission, or a schema refuses it | `400` |
//! | the ledger is not served here | `404` |
//! | the event id is already recorded | `409` |
//! | the ledger cannot be served, or the journal cannot accept | `503` |
//! | this process failed | `500` |
//!
//! A deny is `200`: it is an answer. And a `409` is not a failure either — it is this interface
//! telling a caller that its retry was already dealt with, or that an id it reused means something
//! else here.
//!
//! # Why there is no `GET`
//!
//! A plane's journal is a shipping buffer, not an archive: it holds what the loaded policies still
//! read and what the control plane has not yet acknowledged, and nothing more. Reading events is
//! the control plane's surface, where the history is whole. A read here would answer differently
//! depending on which plane it reached.

use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};

use permguard_core::{ApiError, Disclosure, ErrorClass};
use permguard_languages::temporal::{SUBMISSION_PATH, SubmitRequest};

use super::configuration;
use super::submit::Submitter;

/// The correlation header, echoed verbatim when the caller sends it.
const REQUEST_ID: &str = "x-request-id";

/// What the handlers share.
#[derive(Clone)]
pub struct Surface {
    pub submitter: std::sync::Arc<Submitter>,
    pub disclosure: Disclosure,
    /// The base URL this plane is reached at, for the configuration document.
    pub base_url: String,
    /// This PDP's identifier, as the document publishes it.
    pub pdp: String,
}

/// The routes the temporal interface answers.
pub fn routes(surface: Surface) -> Router {
    // Mounted from the interface's own constants, which is also what the configuration document
    // advertises — so the document cannot name a path this plane does not answer.
    Router::new()
        .route(SUBMISSION_PATH, post(submit))
        .route(configuration::CONFIGURATION_PATH, get(document))
        .with_state(surface)
}

async fn submit(
    State(surface): State<Surface>,
    headers: HeaderMap,
    body: Result<Json<SubmitRequest>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let request_id = headers
        .get(REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .map(ToOwned::to_owned);

    let Json(request) = match body {
        Ok(body) => body,
        Err(rejection) => {
            return with_request_id(
                error(
                    &ApiError::new(
                        ErrorClass::Validation,
                        "payload_malformed",
                        format!("the request body is not a valid submission: {rejection}"),
                    ),
                    surface.disclosure,
                ),
                request_id.as_deref(),
            );
        }
    };

    let response = match surface.submitter.submit(&request).await {
        Ok(answered) => (StatusCode::OK, Json(answered)).into_response(),
        Err(failed) => error(&failed, surface.disclosure),
    };

    with_request_id(response, request_id.as_deref())
}

/// What this interface offers here.
async fn document(State(surface): State<Surface>) -> Json<configuration::Document> {
    Json(configuration::document(&surface.base_url, &surface.pdp))
}

/// Turns a refusal into the answer the contract names.
fn error(failed: &ApiError, disclosure: Disclosure) -> Response {
    let status = match failed.class() {
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
