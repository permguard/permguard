// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The REST binding of the Host API: `/host/v1/…`, each route one call into the facade.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{FromRequest, Path, RawQuery, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;

use permguard_core::{ApiError, Disclosure, ErrorClass, codes};
use permguard_host::api::{
    CreateGrant, HostApi, KeyBundleQuery, PlanKeyRevoke, PlanRevoke, Refusal, RotateIdentity,
    RotateRing, RunKeyRevoke, RunRevoke,
};
use permguard_transport::ActorOf;

use super::wire;

/// What every handler reaches: the facade and how much a refusal says.
#[derive(Clone)]
pub(crate) struct Served {
    api: Arc<HostApi>,
    disclosure: Disclosure,
}

impl Served {
    fn refuse(&self, refusal: &Refusal) -> Response {
        wire::http_refusal(refusal, self.disclosure)
    }
}

/// The routes of the Host API.
pub fn routes(api: Arc<HostApi>, disclosure: Disclosure) -> Router {
    Router::new()
        .route("/host/v1/identity", get(identity))
        .route("/host/v1/identity/rotate", post(rotate_identity))
        .route("/host/v1/ring-bindings", get(ring_bindings))
        .route("/host/v1/sessions/hello", post(session_over_rest))
        .route("/host/v1/sessions/prove", post(session_over_rest))
        .route("/host/v1/grants", get(list_grants).post(create_grant))
        .route("/host/v1/grants/{id}/revoke/plan", post(plan_revoke))
        .route("/host/v1/grants/{id}/revoke/run", post(run_revoke))
        .route("/host/v1/keys", get(list_rings))
        .route("/host/v1/keys/bundle", get(key_bundle))
        .route("/host/v1/keys/{ring}", get(get_ring))
        .route("/host/v1/keys/{ring}/rotate", post(rotate_ring))
        .route("/host/v1/keys/{ring}/revoke/plan", post(plan_key_revoke))
        .route("/host/v1/keys/{ring}/revoke/run", post(run_key_revoke))
        .route("/host/v1/status", get(status))
        .route("/host/v1/config/effective", get(effective_config))
        .route("/host/v1/config/revisions", get(config_revisions))
        .with_state(Served { api, disclosure })
}

/// A closed JSON body: declared `application/json`, well formed, no member the shape does not
/// name. Anything else is `invalid_argument` in the shared shape; the one answer that stays the
/// framework's is the transport's body limit, a plain-text `413` from the `Surface`, which every
/// listener answers alike before any handler.
///
/// The media type is checked first and on purpose: a browser sends a `text/plain` POST cross-site
/// without a preflight, carrying the client certificate the listener authenticates with.
struct Closed<T>(T);

impl<T: DeserializeOwned> FromRequest<Served> for Closed<T> {
    type Rejection = Response;

    async fn from_request(request: Request, served: &Served) -> Result<Self, Response> {
        let refuse = |message: String| {
            served.refuse(&Refusal::Api(ApiError::new(
                ErrorClass::Validation,
                codes::common::INVALID_ARGUMENT,
                message,
            )))
        };
        let json = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"));
        if !json {
            return Err(refuse(
                "the body must be declared `Content-Type: application/json`".to_owned(),
            ));
        }
        let bytes = Bytes::from_request(request, served)
            .await
            .map_err(IntoResponse::into_response)?;
        serde_json::from_slice(&bytes)
            .map(Closed)
            .map_err(|error| refuse(format!("the body is not the request's shape: {error}")))
    }
}

fn answer<T: serde::Serialize>(
    served: &Served,
    status: StatusCode,
    result: Result<T, Refusal>,
) -> Response {
    match result {
        Ok(value) => (status, Json(value)).into_response(),
        Err(refusal) => served.refuse(&refusal),
    }
}

/// Peer sessions are never separate requests: refused whoever asks, before any body is read
/// (WP-2.3).
async fn session_over_rest(State(served): State<Served>) -> Response {
    served.refuse(&served.api.session_over_rest())
}

async fn identity(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.identity(&actor))
}

async fn rotate_identity(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(rotate): Closed<RotateIdentity>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.rotate_identity(&actor, rotate).await,
    )
}

async fn ring_bindings(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.ring_bindings(&actor))
}

async fn list_grants(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    RawQuery(query): RawQuery,
) -> Response {
    let filters = query_members(query.as_deref(), &["principal", "selector"]);
    answer(
        &served,
        StatusCode::OK,
        served
            .api
            .grants(&actor, filters[0].as_deref(), filters[1].as_deref()),
    )
}

async fn create_grant(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Closed(create): Closed<CreateGrant>,
) -> Response {
    answer(
        &served,
        StatusCode::CREATED,
        served.api.create_grant(&actor, create).await,
    )
}

async fn plan_revoke(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(plan): Closed<PlanRevoke>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.plan_revoke(&actor, &id, plan).await,
    )
}

async fn run_revoke(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(id): Path<String>,
    Closed(run): Closed<RunRevoke>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.run_revoke(&actor, &id, run).await,
    )
}

async fn list_rings(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.rings(&actor))
}

async fn key_bundle(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    RawQuery(query): RawQuery,
) -> Response {
    let [resource, frontier, cursor, limit] = <[Option<String>; 4]>::try_from(query_members(
        query.as_deref(),
        &["resource", "frontier", "cursor", "limit"],
    ))
    .unwrap_or_default();
    let query = KeyBundleQuery {
        resource: resource.unwrap_or_default(),
        frontier,
        cursor,
        // A limit that is not a number is out of range, and refused as one.
        limit: limit.map(|text| text.parse().unwrap_or(0)),
    };
    answer(
        &served,
        StatusCode::OK,
        served.api.key_bundle(&actor, &query),
    )
}

async fn get_ring(State(served): State<Served>, Path(ring): Path<String>) -> Response {
    match served.api.ring(&ring) {
        Ok(view) => {
            let mut response = (StatusCode::OK, Json(&view)).into_response();
            if let Ok(value) = HeaderValue::from_str(&format!("max-age={}", view.cache_max_age)) {
                response.headers_mut().insert(header::CACHE_CONTROL, value);
            }
            response
        }
        Err(refusal) => served.refuse(&refusal),
    }
}

async fn rotate_ring(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(ring): Path<String>,
    Closed(rotate): Closed<RotateRing>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.rotate_ring(&actor, &ring, rotate).await,
    )
}

async fn plan_key_revoke(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(ring): Path<String>,
    Closed(plan): Closed<PlanKeyRevoke>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.plan_key_revoke(&actor, &ring, plan).await,
    )
}

async fn run_key_revoke(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(ring): Path<String>,
    Closed(run): Closed<RunKeyRevoke>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.api.run_key_revoke(&actor, &ring, run).await,
    )
}

async fn status(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.status(&actor))
}

async fn effective_config(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.effective_config(&actor))
}

async fn config_revisions(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(&served, StatusCode::OK, served.api.config_revisions(&actor))
}

/// The values of `names` in `query`, percent-decoded; a name given twice keeps its first value,
/// and a name nobody declared is ignored. Two filters do not justify a query framework.
fn query_members(query: Option<&str>, names: &[&str]) -> Vec<Option<String>> {
    let mut values: Vec<Option<String>> = vec![None; names.len()];
    for pair in query.unwrap_or_default().split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            continue;
        };
        // An empty value is no filter, as an absent one and as gRPC's empty string are.
        if let Some(index) = names.iter().position(|wanted| *wanted == name)
            && values[index].is_none()
            && !value.is_empty()
        {
            values[index] = Some(percent_decode(value));
        }
    }
    values
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escaped = bytes[index] == b'%'
            && index + 2 < bytes.len()
            && bytes[index + 1].is_ascii_hexdigit()
            && bytes[index + 2].is_ascii_hexdigit();
        if escaped {
            let pair = std::str::from_utf8(&bytes[index + 1..index + 3]).unwrap_or("00");
            decoded.push(u8::from_str_radix(pair, 16).unwrap_or(b'%'));
            index += 3;
            continue;
        }
        decoded.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

#[cfg(test)]
mod tests {
    #[test]
    fn query_members_decode_and_keep_the_first_value() {
        let values = super::query_members(
            Some(
                "selector=plane%2Fcontrol%2F*&principal=spiffe%3A%2F%2Facme%2Fa&principal=x&other=1",
            ),
            &["principal", "selector"],
        );
        assert_eq!(values[0].as_deref(), Some("spiffe://acme/a"));
        assert_eq!(values[1].as_deref(), Some("plane/control/*"));
        assert_eq!(
            super::percent_decode("a+b%2"),
            "a b%2",
            "a dangling escape is kept as written"
        );
        assert_eq!(super::percent_decode("%zz"), "%zz");
        assert_eq!(super::percent_decode("%41%4a"), "AJ");
        assert_eq!(
            super::query_members(Some("principal=&selector=x"), &["principal", "selector"]),
            vec![None, Some("x".to_owned())],
            "an empty value is no filter"
        );
    }
}
