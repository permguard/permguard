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
//! # Why there is no `GET` for records
//!
//! A plane's journal is a shipping buffer, not an archive: it holds what the loaded policies still
//! read and what the control plane has not yet acknowledged, and nothing more. Reading events is
//! the control plane's surface, where the history is whole. A read here would answer differently
//! depending on which plane it reached.
//!
//! What this plane *does* answer about its own journal is `GET /events/v1alpha1/signers`: its
//! watermarks and which key signed which stretch, public keys included. Those are statements
//! about this plane — a verifier checking what this plane shipped needs them from here, and they
//! are the same wherever the records themselves are read.

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
    /// Who serves the interface, its build and its phase: the discovery document's common header
    /// (WP-7.4a).
    pub describer: permguard_core::stages::Describer,
    /// This PDP's identifier, as the document publishes it.
    pub pdp: String,
    /// The Host's authorization: `event.submit` on the exact ledger, before anything is read or
    /// written (WP-6.2a).
    pub authorization: std::sync::Arc<permguard_host::composition::Authorization>,
}

/// The routes the temporal interface answers.
pub fn routes(surface: Surface) -> Router {
    // Mounted from the interface's own constants, which is also what the configuration document
    // advertises — so the document cannot name a path this plane does not answer.
    Router::new()
        .route(SUBMISSION_PATH, post(submit))
        .route("/events/v1alpha1/signers", get(signers))
        .route(configuration::CONFIGURATION_PATH, get(document))
        .with_state(surface)
}

async fn submit(
    State(surface): State<Surface>,
    permguard_transport::ActorOf(actor): permguard_transport::ActorOf,
    headers: HeaderMap,
    body: Result<axum::body::Bytes, axum::extract::rejection::BytesRejection>,
) -> Response {
    // Bounded by the rule every surface applies: it is echoed and kept in the decision record.
    let request_id = headers
        .get(REQUEST_ID)
        .and_then(|value| value.to_str().ok())
        .and_then(permguard_core::correlation::admitted)
        .map(ToOwned::to_owned);

    // Read strictly (WP-7.5b, IFACE-06): one JSON value, no member named twice at any level, and
    // the numbers in the domain the gRPC binding reads — past ±2^53 refused
    // `value_unrepresentable`, a whole number the integer it is. What the runtime cannot
    // represent stays its own contract's (`event_value_unrepresentable`).
    const WHAT: &str = "the request body is not a valid submission";
    let read = body
        .map_err(|rejection| crate::body::malformed(format!("{WHAT}: {rejection}")))
        .and_then(|bytes| crate::body::json(&headers, &bytes, WHAT))
        .and_then(crate::body::lossless)
        .and_then(|value| {
            serde_json::from_value::<SubmitRequest>(value)
                .map_err(|error| crate::body::malformed(format!("{WHAT}: {error}")))
        });
    let request = match read {
        Ok(request) => request,
        Err(failed) => {
            return with_request_id(error(&failed, surface.disclosure), request_id.as_deref());
        }
    };

    // The shared pipeline (WP-7.5d): authorization before anything is read or written, the
    // source the occurrence is recorded under being the principal the gate authorized (WP-6.2a),
    // then the temporal handler.
    let services = crate::evaluation::Services {
        authorization: &surface.authorization,
        decider: surface.submitter.decider(),
        submitter: Some(&surface.submitter),
    };
    let asked = crate::evaluation::EvaluationRequest::temporal(request);
    let response = match crate::evaluation::evaluate(&services, &actor, asked).await {
        Ok(crate::evaluation::Answer::Temporal(answered)) => (
            StatusCode::OK,
            Json(super::submit::disclosed(*answered, surface.disclosure)),
        )
            .into_response(),
        Ok(crate::evaluation::Answer::Native(_)) => error(
            &crate::evaluation::mismatched("temporal HTTP"),
            surface.disclosure,
        ),
        Err(crate::evaluation::Refused::Denied(denial)) => crate::authz::gate::http_denial(&denial),
        Err(crate::evaluation::Refused::Failed(failed)) => error(&failed, surface.disclosure),
    };

    with_request_id(response, request_id.as_deref())
}

/// What this interface offers here.
async fn document(State(surface): State<Surface>) -> Response {
    match surface
        .describer
        .header(permguard_core::domains::interface::PDP_TEMPORAL_V1ALPHA1)
    {
        Ok(header) => Json(configuration::document(
            &surface.base_url,
            &surface.pdp,
            header,
        ))
        .into_response(),
        Err(refused) => error(&refused, surface.disclosure),
    }
}

/// The signers refusal for a ledger this plane keeps no journal for, the same on both bindings.
pub(crate) fn not_held(zone: &str, ledger: &str) -> ApiError {
    ApiError::new(
        ErrorClass::NotFound,
        permguard_core::codes::stream::STORE_UNKNOWN,
        format!("this plane keeps no journal for `{zone}/{ledger}`"),
    )
}

/// The signers refusal for a held ledger whose journal cannot be read now, the same on both
/// bindings: the store exists, so this is `unavailable`, never `not_found`.
pub(crate) fn unreadable(refused: &dyn std::fmt::Display) -> ApiError {
    ApiError::new(
        ErrorClass::Unavailable,
        permguard_core::codes::stream::STORE_UNAVAILABLE,
        refused.to_string(),
    )
}

/// This plane's own journal watermarks and signer history for one ledger.
///
/// `?zone=&ledger=` name the journal; `from_seq`/`until_seq` bound the spans, both optional.
/// Local statements only: what this plane has made durable, signed and had acknowledged, and
/// which key signed which stretch — public keys included, so a verifier holding shipped records
/// needs nothing else from here.
async fn signers(
    State(surface): State<Surface>,
    axum::extract::RawQuery(query): axum::extract::RawQuery,
) -> Response {
    let mut asked: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for pair in query.as_deref().unwrap_or_default().split('&') {
        if let Some((name, value)) = pair.split_once('=') {
            asked.insert(name.to_owned(), percent_decode(value));
        }
    }
    let (Some(zone), Some(ledger)) = (asked.get("zone"), asked.get("ledger")) else {
        return error(
            &ApiError::new(
                ErrorClass::Validation,
                permguard_core::codes::pdp_temporal::STORE_REQUIRED,
                "a journal is named by its ledger: `?zone=&ledger=`",
            ),
            surface.disclosure,
        );
    };
    let bound = |name: &str| -> Result<u64, String> {
        match asked.get(name) {
            None => Ok(0),
            Some(held) => held.parse().map_err(|_| name.to_owned()),
        }
    };
    let (from_seq, until_seq) = match (bound("from_seq"), bound("until_seq")) {
        (Ok(from_seq), Ok(until_seq)) => (from_seq, until_seq),
        (Err(name), _) | (_, Err(name)) => {
            return error(
                &ApiError::new(
                    ErrorClass::Validation,
                    permguard_core::codes::stream::BOUND_MALFORMED,
                    format!("`{name}` is a sequence number"),
                ),
                surface.disclosure,
            );
        }
    };
    let until = if until_seq == 0 { u64::MAX } else { until_seq };

    let streams = surface.submitter.streams();
    // Only a journal that already exists answers: opening one on a read would let a `GET` with an
    // invented name create directories, and a plane must never grow state because it was asked a
    // question. Checked against what is on disk, which is what "exists" means for a journal.
    if !streams
        .ledgers()
        .iter()
        .any(|(held_zone, held_ledger)| held_zone == zone && held_ledger == ledger)
    {
        return error(&not_held(zone, ledger), surface.disclosure);
    }
    let state = match streams.state(zone, ledger) {
        Ok(state) => state,
        Err(refused) => return error(&unreadable(&refused), surface.disclosure),
    };
    let held = match streams.signers(zone, ledger) {
        Ok(held) => held,
        Err(refused) => return error(&unreadable(&refused), surface.disclosure),
    };

    // The producer identity carries the *journal's* incarnation: the stream-level identity knows
    // who this plane is, and only the journal knows which continuous run of it this is.
    let mut producer = streams.producer().clone();
    if let Ok(instance) = streams.instance(zone, ledger) {
        producer.instance = instance;
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "producer": producer,
            "durable_through": state.durable_through,
            "signed_through": state.signed_through,
            "acked_through": state.acked_through,
            "spans": held.covering(from_seq, until),
        })),
    )
        .into_response()
}

/// Undoes the percent-encoding a caller's client applied to a query value.
fn percent_decode(value: &str) -> String {
    let bytes = value.replace('+', " ").into_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or_default();
            if let Ok(byte) = u8::from_str_radix(pair, 16) {
                out.push(byte);
                index += 3;
                continue;
            }
        }
        out.push(bytes[index]);
        index += 1;
    }

    String::from_utf8_lossy(&out).into_owned()
}

/// Turns a refusal into the answer the contract names.
fn error(failed: &ApiError, disclosure: Disclosure) -> Response {
    let status =
        StatusCode::from_u16(failed.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

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

#[cfg(test)]
mod tests {
    use super::*;

    /// A ledger nobody holds is `not_found`; a held ledger whose journal fails is `unavailable`, on
    /// REST and gRPC alike, because both bindings answer through these two functions.
    #[test]
    fn test_the_signers_refusals_tell_an_unheld_ledger_from_an_unreadable_journal() {
        let unheld = not_held("z", "l");
        assert_eq!(
            (unheld.class(), unheld.code()),
            (
                ErrorClass::NotFound,
                permguard_core::codes::stream::STORE_UNKNOWN
            )
        );
        let broken = unreadable(&"the journal is poisoned");
        assert_eq!(
            (broken.class(), broken.code()),
            (
                ErrorClass::Unavailable,
                permguard_core::codes::stream::STORE_UNAVAILABLE
            )
        );
    }
}
