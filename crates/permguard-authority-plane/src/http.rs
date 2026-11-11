// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The REST binding of the Authority Plane: `/authority/v1/…` and its metadata, each route one
//! call into the facade.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, RawQuery, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use permguard_core::{ApiError, Disclosure, ErrorClass, codes};
use permguard_transport::ActorOf;

use crate::authority::{
    Authority, Change, CreateAccount, CreateKey, Refusal, RevokeToken, SetScopes, TokenRefusal,
    TokenRequest, UpdateAccount,
};
use crate::wire;

/// The token endpoint's path: where `Authorization: Basic` is the client's own credential.
pub const TOKEN_PATH: &str = "/authority/v1/token";
/// The most bytes a token request's form takes.
const MAX_TOKEN_FORM_BYTES: usize = 16 * 1024;

#[derive(Clone)]
pub(crate) struct Served {
    pub(crate) authority: Arc<Authority>,
    pub(crate) disclosure: Disclosure,
}

/// The routes of the Authority Plane's API.
pub(crate) fn routes(served: Served) -> Router {
    Router::new()
        .route("/.well-known/oauth-authorization-server", get(metadata))
        .route(TOKEN_PATH, post(token))
        .route("/authority/v1/keys", get(keys))
        .route("/authority/v1/status-lists", get(status_lists))
        .route("/authority/v1/status-lists/{id}", get(status_list))
        .route("/authority/v1/tokens", get(list_tokens))
        .route("/authority/v1/tokens/{jti}/revoke", post(revoke_token))
        .route(
            "/authority/v1/service-accounts",
            get(list_accounts).post(create_account),
        )
        .route(
            "/authority/v1/service-accounts/{name}",
            get(get_account)
                .patch(update_account)
                .delete(delete_account),
        )
        .route(
            "/authority/v1/service-accounts/{name}/suspend",
            post(suspend_account),
        )
        .route(
            "/authority/v1/service-accounts/{name}/resume",
            post(resume_account),
        )
        .route(
            "/authority/v1/service-accounts/{name}/scopes",
            get(get_scopes).put(set_scopes),
        )
        .route(
            "/authority/v1/service-accounts/{name}/keys",
            get(list_keys).post(create_key),
        )
        .route(
            "/authority/v1/service-accounts/{name}/keys/{access_key}",
            axum::routing::delete(delete_key),
        )
        .with_state(served)
}

fn answer<T: Serialize>(
    served: &Served,
    status: StatusCode,
    result: Result<T, Refusal>,
) -> Response {
    match result {
        Ok(value) => (status, Json(value)).into_response(),
        Err(refusal) => wire::http_refusal(&refusal, served.disclosure),
    }
}

/// Reads a JSON body of the request's shape, refusing anything else as the contract's shape.
fn body<T: DeserializeOwned>(bytes: &Bytes) -> Result<T, Refusal> {
    serde_json::from_slice(bytes).map_err(|error| {
        Refusal::Api(ApiError::new(
            ErrorClass::Validation,
            codes::common::INVALID_ARGUMENT,
            format!("the body is not this request's shape: {error}"),
        ))
    })
}

/// Runs a change off the async workers: a journal write, a secret's hash.
async fn blocking<T: Send + 'static>(
    served: &Served,
    call: impl FnOnce(&Authority) -> Result<T, Refusal> + Send + 'static,
) -> Result<T, Refusal> {
    let authority = Arc::clone(&served.authority);
    tokio::task::spawn_blocking(move || call(&authority))
        .await
        .unwrap_or_else(|error| {
            Err(Refusal::Api(ApiError::new(
                ErrorClass::Internal,
                codes::common::INTERNAL,
                format!("the call did not finish: {error}"),
            )))
        })
}

/// Decodes `%XX` and `+` of a form or query member.
pub(crate) fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut at = 0;
    while at < bytes.len() {
        match bytes[at] {
            b'+' => out.push(b' '),
            b'%' if at + 2 < bytes.len() => {
                match u8::from_str_radix(text.get(at + 1..at + 3).unwrap_or(""), 16) {
                    Ok(byte) => {
                        out.push(byte);
                        at += 2;
                    }
                    Err(_) => out.push(b'%'),
                }
            }
            byte => out.push(byte),
        }
        at += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// The first value of each of `names` in `query`.
fn query_members(query: Option<&str>, names: &[&str]) -> Vec<Option<String>> {
    let mut found = vec![None; names.len()];
    for pair in query.unwrap_or_default().split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        if let Some(position) = names.iter().position(|wanted| *wanted == name)
            && found[position].is_none()
        {
            found[position] = Some(percent_decode(value));
        }
    }
    found
}

fn no_store(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

/// RFC 6749's error answer: `no-store`, and `WWW-Authenticate: Basic` on a failed client proof.
fn token_refused(refusal: &TokenRefusal) -> Response {
    let status = StatusCode::from_u16(refusal.status()).unwrap_or(StatusCode::BAD_REQUEST);
    if let TokenRefusal::Unavailable(detail) = refusal {
        tracing::warn!(
            event.name = "authority.token_unavailable",
            component = crate::COMPONENT,
            detail = %detail,
            "the token endpoint could not answer"
        );
    }
    let mut response = no_store(
        (
            status,
            Json(serde_json::json!({
                "error": refusal.error(),
                "error_description": refusal.description(),
            })),
        )
            .into_response(),
    );
    let headers = response.headers_mut();
    if status == StatusCode::UNAUTHORIZED {
        headers.insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"permguard\""),
        );
    }
    if let TokenRefusal::SlowDown(seconds) = refusal
        && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
    {
        headers.insert(header::RETRY_AFTER, value);
    }
    response
}

/// `client_secret_basic` (RFC 6749 §2.3.1): the id and secret form-encoded, then Basic.
fn basic_client(headers: &axum::http::HeaderMap) -> Result<Option<(String, String)>, ()> {
    use base64::Engine as _;
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let (scheme, encoded) = value
        .to_str()
        .ok()
        .and_then(|value| value.split_once(' '))
        .ok_or(())?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(());
    }
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .map_err(|_| ())?;
    let text = Zeroizing::new(String::from_utf8(decoded).map_err(|_| ())?);
    let (id, secret) = text.split_once(':').ok_or(())?;
    Ok(Some((percent_decode(id), percent_decode(secret))))
}

/// Reads the form of a token request: each member once, an unknown one ignored as RFC 6749 asks.
pub(crate) fn token_request(
    pairs: Vec<(String, String)>,
    basic: Option<(String, String)>,
) -> Result<TokenRequest, TokenRefusal> {
    let mut request = TokenRequest::default();
    let mut seen = std::collections::BTreeSet::new();
    for (name, value) in pairs {
        if matches!(
            name.as_str(),
            "grant_type" | "client_id" | "client_secret" | "scope" | "requested_lifetime"
        ) && !seen.insert(name.clone())
        {
            return Err(TokenRefusal::InvalidRequest(format!(
                "`{name}` is given more than once"
            )));
        }
        match name.as_str() {
            "grant_type" => request.grant_type = value,
            "client_id" => request.client_id = value,
            "client_secret" => request.client_secret = Zeroizing::new(value),
            "scope" => request.scope = Some(value),
            "requested_lifetime" => {
                request.requested_lifetime = Some(value.trim().parse().map_err(|_| {
                    TokenRefusal::InvalidRequest(
                        "`requested_lifetime` is a number of seconds".to_owned(),
                    )
                })?);
            }
            _ => {}
        }
    }
    if let Some((id, secret)) = basic {
        // One proof: the header, or the form, never both.
        if seen.contains("client_secret") {
            return Err(TokenRefusal::InvalidRequest(
                "the client authenticates once: the Authorization header or the form".to_owned(),
            ));
        }
        if seen.contains("client_id") && request.client_id != id {
            return Err(TokenRefusal::InvalidRequest(
                "`client_id` is not the header's".to_owned(),
            ));
        }
        request.client_id = id;
        request.client_secret = Zeroizing::new(secret);
    }
    if request.client_id.is_empty() || request.client_secret.is_empty() {
        return Err(TokenRefusal::InvalidClient);
    }
    Ok(request)
}

/// `POST /authority/v1/token`: a form, as RFC 6749 requires.
async fn token(State(served): State<Served>, request: Request) -> Response {
    let form = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|media| {
            media
                .trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !form {
        return token_refused(&TokenRefusal::InvalidRequest(
            "the request is `application/x-www-form-urlencoded`".to_owned(),
        ));
    }
    let Ok(basic) = basic_client(request.headers()) else {
        return token_refused(&TokenRefusal::InvalidClient);
    };
    let source = request
        .extensions()
        .get::<Arc<permguard_transport::PeerAddress>>()
        .map_or_else(|| "unknown".to_owned(), |address| address.0.to_string());
    let Ok(bytes) = axum::body::to_bytes(request.into_body(), MAX_TOKEN_FORM_BYTES).await else {
        return token_refused(&TokenRefusal::InvalidRequest(format!(
            "the form is at most {MAX_TOKEN_FORM_BYTES} bytes"
        )));
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return token_refused(&TokenRefusal::InvalidRequest(
            "the form is not UTF-8".to_owned(),
        ));
    };
    let pairs = text
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (percent_decode(name), percent_decode(value))
        })
        .collect();
    let parsed = match token_request(pairs, basic) {
        Ok(parsed) => parsed,
        Err(refusal) => {
            served.authority.record_refused("", &refusal).await;
            return token_refused(&refusal);
        }
    };
    match issue(&served.authority, parsed, source).await {
        Ok(answer) => no_store((StatusCode::OK, Json(answer)).into_response()),
        Err(refusal) => token_refused(&refusal),
    }
}

/// Issues a token off the async workers, within the bound every Argon2id verification shares:
/// past it the request is answered `slow_down` rather than queued. Shared by both transports.
pub(crate) async fn issue(
    authority: &Arc<Authority>,
    request: TokenRequest,
    source: String,
) -> Result<crate::authority::TokenAnswer, TokenRefusal> {
    let client_id = request.client_id.clone();
    let Ok(_slot) = Arc::clone(&authority.hashing).try_acquire_owned() else {
        let refusal = TokenRefusal::SlowDown(1);
        authority.record_refused(&client_id, &refusal).await;
        return Err(refusal);
    };
    let issuing = Arc::clone(authority);
    let answered = tokio::task::spawn_blocking(move || issuing.issue_token(&request, &source))
        .await
        .unwrap_or_else(|_| {
            Err(TokenRefusal::Unavailable(
                "the token request was cut short".to_owned(),
            ))
        });
    match answered {
        Ok(issued) => {
            authority.record_issued(&issued).await;
            Ok(issued.answer)
        }
        Err(refusal) => {
            authority.record_refused(&client_id, &refusal).await;
            Err(refusal)
        }
    }
}

async fn metadata(State(served): State<Served>) -> Response {
    (StatusCode::OK, Json(served.authority.metadata())).into_response()
}

async fn keys(State(served): State<Served>) -> Response {
    match served.authority.keys_document() {
        Ok(document) => {
            let mut response = (StatusCode::OK, Json(document)).into_response();
            response.headers_mut().insert(
                header::CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=60"),
            );
            response
        }
        Err(refusal) => wire::http_refusal(&refusal, served.disclosure),
    }
}

async fn status_lists(State(served): State<Served>) -> Response {
    (
        StatusCode::OK,
        Json(serde_json::json!({ "lists": served.authority.list_ids() })),
    )
        .into_response()
}

async fn status_list(State(served): State<Served>, Path(id): Path<String>) -> Response {
    match served.authority.list_token(&id) {
        Ok(token) => {
            let mut response = (StatusCode::OK, token).into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/statuslist+jwt"),
            );
            response
        }
        Err(refusal) => wire::http_refusal(&refusal, served.disclosure),
    }
}

async fn list_tokens(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    RawQuery(query): RawQuery,
) -> Response {
    let found = query_members(query.as_deref(), &["account", "status"]);
    answer(
        &served,
        StatusCode::OK,
        served
            .authority
            .list_tokens(&actor, found[0].as_deref(), found[1].as_deref())
            .map(|tokens| serde_json::json!({ "tokens": tokens })),
    )
}

async fn revoke_token(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(jti): Path<String>,
    bytes: Bytes,
) -> Response {
    let result = match body::<RevokeToken>(&bytes) {
        Ok(revoke) => {
            blocking(&served, move |authority| {
                authority.revoke_token(&actor, &jti, revoke)
            })
            .await
        }
        Err(refusal) => Err(refusal),
    };
    answer(&served, StatusCode::OK, result)
}

async fn list_accounts(State(served): State<Served>, ActorOf(actor): ActorOf) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served
            .authority
            .list_accounts(&actor)
            .map(|accounts| serde_json::json!({ "accounts": accounts })),
    )
}

async fn create_account(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    bytes: Bytes,
) -> Response {
    let result = match body::<CreateAccount>(&bytes) {
        Ok(create) => {
            blocking(&served, move |authority| {
                authority.create_account(&actor, create)
            })
            .await
        }
        Err(refusal) => Err(refusal),
    };
    answer(&served, StatusCode::CREATED, result)
}

async fn get_account(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(name): Path<String>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.authority.get_account(&actor, &name),
    )
}

async fn update_account(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(name): Path<String>,
    bytes: Bytes,
) -> Response {
    let result = match body::<UpdateAccount>(&bytes) {
        Ok(update) => {
            blocking(&served, move |authority| {
                authority.update_account(&actor, &name, update)
            })
            .await
        }
        Err(refusal) => Err(refusal),
    };
    answer(&served, StatusCode::OK, result)
}

async fn delete_account(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(name): Path<String>,
    bytes: Bytes,
) -> Response {
    let result = match body::<Change>(&bytes) {
        Ok(change) => {
            blocking(&served, move |authority| {
                authority.delete_account(&actor, &name, change)
            })
            .await
        }
        Err(refusal) => Err(refusal),
    };
    answer(&served, StatusCode::OK, result)
}

async fn suspend_account(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(name): Path<String>,
    bytes: Bytes,
) -> Response {
    status_change(served, actor, name, true, bytes).await
}

async fn resume_account(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(name): Path<String>,
    bytes: Bytes,
) -> Response {
    status_change(served, actor, name, false, bytes).await
}

async fn status_change(
    served: Served,
    actor: Arc<permguard_core::authz::Actor>,
    name: String,
    suspended: bool,
    bytes: Bytes,
) -> Response {
    let result = match body::<Change>(&bytes) {
        Ok(change) => {
            blocking(&served, move |authority| {
                authority.set_account_status(&actor, &name, suspended, change)
            })
            .await
        }
        Err(refusal) => Err(refusal),
    };
    answer(&served, StatusCode::OK, result)
}

async fn get_scopes(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(name): Path<String>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served.authority.get_scopes(&actor, &name),
    )
}

async fn set_scopes(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(name): Path<String>,
    bytes: Bytes,
) -> Response {
    let result = match body::<SetScopes>(&bytes) {
        Ok(set) => {
            blocking(&served, move |authority| {
                authority.set_scopes(&actor, &name, set)
            })
            .await
        }
        Err(refusal) => Err(refusal),
    };
    answer(&served, StatusCode::OK, result)
}

async fn list_keys(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(name): Path<String>,
) -> Response {
    answer(
        &served,
        StatusCode::OK,
        served
            .authority
            .list_keys(&actor, &name)
            .map(|keys| serde_json::json!({ "keys": keys })),
    )
}

async fn create_key(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path(name): Path<String>,
    bytes: Bytes,
) -> Response {
    let result = match body::<CreateKey>(&bytes) {
        Ok(create) => {
            blocking(&served, move |authority| {
                authority.create_key(&actor, &name, create)
            })
            .await
        }
        Err(refusal) => Err(refusal),
    };
    match result {
        Ok(created) => no_store((StatusCode::CREATED, Json(created)).into_response()),
        Err(refusal) => wire::http_refusal(&refusal, served.disclosure),
    }
}

async fn delete_key(
    State(served): State<Served>,
    ActorOf(actor): ActorOf,
    Path((name, access_key)): Path<(String, String)>,
    bytes: Bytes,
) -> Response {
    let result = match body::<Change>(&bytes) {
        Ok(change) => {
            blocking(&served, move |authority| {
                authority.delete_key(&actor, &name, &access_key, change)
            })
            .await
        }
        Err(refusal) => Err(refusal),
    };
    answer(&served, StatusCode::OK, result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_form_reads_once_and_takes_one_proof() {
        let pairs = |items: &[(&str, &str)]| {
            items
                .iter()
                .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
                .collect::<Vec<_>>()
        };
        let read = token_request(
            pairs(&[
                ("grant_type", "client_credentials"),
                ("client_id", "pgak_A"),
                ("client_secret", "pgsk_B"),
                ("scope", "decision.evaluate"),
            ]),
            None,
        )
        .unwrap_or_else(|_| unreachable!("read"));
        assert_eq!(read.client_id, "pgak_A");
        assert_eq!(read.scope.as_deref(), Some("decision.evaluate"));
        assert!(token_request(pairs(&[("scope", "a"), ("scope", "b")]), None).is_err());
        assert!(
            token_request(
                pairs(&[("grant_type", "client_credentials"), ("client_secret", "x")]),
                Some(("pgak_A".to_owned(), "pgsk_B".to_owned()))
            )
            .is_err(),
            "two proofs"
        );
        let basic = token_request(
            pairs(&[("grant_type", "client_credentials")]),
            Some(("pgak_A".to_owned(), "pgsk_B".to_owned())),
        )
        .unwrap_or_else(|_| unreachable!("read"));
        assert_eq!(basic.client_secret.as_str(), "pgsk_B");
        assert!(matches!(
            token_request(pairs(&[("grant_type", "client_credentials")]), None),
            Err(TokenRefusal::InvalidClient)
        ));
        assert_eq!(percent_decode("a%2Fb+c%zz"), "a/b c%zz");
    }
}
