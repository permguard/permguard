// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `/auth/v1` on the Server Host surface (WP-8.1, `6-contracts/8` Sign-in): password sign-in,
//! sign-out, the session, a password change and a second factor's enrollment.
//!
//! | Route                               | Answers                                                     |
//! | ----------------------------------- | ----------------------------------------------------------- |
//! | `POST /auth/v1/sessions`            | `{token, user, expires_at, opened}`, or `401 auth.refused`  |
//! | `DELETE /auth/v1/sessions/current`  | `204`                                                       |
//! | `GET /auth/v1/session`              | `{user, expires_at, opened}`                                |
//! | `POST /auth/v1/password`            | `204`, or `400 auth.invalid` with why                       |
//! | `POST /auth/v1/factor`              | `{secret, uri}` once                                        |
//! | `POST /auth/v1/factor/confirm`      | `204`                                                       |
//!
//! A password crosses only TLS: on a cleartext listener that is not on a loopback address every
//! route answers `403 auth.insecure` before reading the body. The hashing runs off the runtime's
//! threads. Every sign-in, refusal and sign-out is an audit record naming the user, never a
//! secret.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post};
use permguard_core::server::AuditRecorder;
use permguard_host::authz::signin::SignIn;
use serde::Deserialize;
use serde_json::json;

/// What the routes share.
#[derive(Clone)]
pub struct SignInRoutes {
    pub signin: Arc<SignIn>,
    /// Whether the surface is TLS or on a loopback address: a password crosses nothing else.
    pub secure: bool,
    pub recorder: Option<AuditRecorder>,
}

/// The `/auth/v1` routes over `state`.
pub fn router(state: SignInRoutes) -> axum::Router {
    axum::Router::new()
        .route("/auth/v1/sessions", post(sign_in))
        .route("/auth/v1/sessions/current", delete(sign_out))
        .route("/auth/v1/session", get(session))
        .route("/auth/v1/password", post(password))
        .route("/auth/v1/factor", post(begin_factor))
        .route("/auth/v1/factor/confirm", post(confirm_factor))
        .with_state(state)
}

fn answer(status: StatusCode, code: &str, message: &str) -> Response {
    (status, Json(json!({"code": code, "message": message}))).into_response()
}

fn insecure() -> Response {
    answer(
        StatusCode::FORBIDDEN,
        "auth.insecure",
        "a password signs in over TLS only: this listener is neither TLS nor on a loopback address",
    )
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|token| token.trim().to_owned())
}

fn record(state: &SignInRoutes, action: &'static str, target: String) {
    let Some(recorder) = state.recorder.clone() else {
        return;
    };
    tokio::spawn(async move {
        if let Err(error) = recorder
            .record_on(
                action,
                permguard_core::Subject::System(permguard_core::lifecycle::HOST),
                &target,
            )
            .await
        {
            tracing::error!(
                event.name = "host.signin_unrecorded",
                component = "host",
                action,
                error = %error,
                "a sign-in could not be recorded in the audit trail"
            );
        }
    });
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SignInBody {
    name: String,
    password: String,
    #[serde(default)]
    code: Option<String>,
}

async fn sign_in(
    State(state): State<SignInRoutes>,
    address: Option<axum::Extension<Arc<permguard_transport::PeerAddress>>>,
    Json(body): Json<SignInBody>,
) -> Response {
    if !state.secure {
        return insecure();
    }
    let signin = Arc::clone(&state.signin);
    let name = body.name.clone();
    // The connection's address, over TLS: what the per-source lockout keys on.
    let source = address.map(|axum::Extension(address)| address.0);
    let from = source.map_or_else(|| "unknown".to_owned(), |source| source.to_string());
    let opened = tokio::task::spawn_blocking(move || {
        signin.sign_in(&body.name, &body.password, body.code.as_deref(), source)
    })
    .await;
    match opened {
        Ok(Ok((token, session))) => {
            record(
                &state,
                "host.signin.accepted",
                format!(
                    "user={} opened={} source={from}",
                    session.user,
                    session.opened.as_str()
                ),
            );
            Json(json!({
                "token": token,
                "user": session.user,
                "expires_at": session.expires_at,
                "opened": session.opened.as_str(),
            }))
            .into_response()
        }
        Ok(Err(refused)) => {
            record(
                &state,
                if refused.reason == "locked" {
                    "host.signin.locked"
                } else {
                    "host.signin.refused"
                },
                format!(
                    "user={} reason={} source={from}",
                    name.chars().take(128).collect::<String>(),
                    refused.reason
                ),
            );
            answer(
                StatusCode::UNAUTHORIZED,
                "auth.refused",
                "the sign-in was refused",
            )
        }
        Err(_) => answer(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.unavailable",
            "the sign-in could not be completed",
        ),
    }
}

async fn sign_out(State(state): State<SignInRoutes>, headers: HeaderMap) -> Response {
    let Some(token) = bearer(&headers) else {
        return answer(
            StatusCode::UNAUTHORIZED,
            "auth.refused",
            "no session was given",
        );
    };
    if let Some(session) = state.signin.sessions().resolve(&token) {
        record(
            &state,
            "host.signin.ended",
            format!("user={}", session.user),
        );
    }
    state.signin.sign_out(&token);
    StatusCode::NO_CONTENT.into_response()
}

async fn session(State(state): State<SignInRoutes>, headers: HeaderMap) -> Response {
    match bearer(&headers).and_then(|token| state.signin.session(&token)) {
        Some(session) => Json(json!({
            "user": session.user,
            "expires_at": session.expires_at,
            "opened": session.opened.as_str(),
        }))
        .into_response(),
        None => answer(
            StatusCode::UNAUTHORIZED,
            "auth.refused",
            "the session is not valid",
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordBody {
    current: String,
    new: String,
}

async fn password(
    State(state): State<SignInRoutes>,
    headers: HeaderMap,
    Json(body): Json<PasswordBody>,
) -> Response {
    if !state.secure {
        return insecure();
    }
    let Some(token) = bearer(&headers) else {
        return answer(
            StatusCode::UNAUTHORIZED,
            "auth.refused",
            "no session was given",
        );
    };
    let signin = Arc::clone(&state.signin);
    let changed = tokio::task::spawn_blocking(move || {
        signin.change_password(&token, &body.current, &body.new)
    })
    .await;
    match changed {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(refused)) => answer(StatusCode::BAD_REQUEST, "auth.invalid", &refused.0),
        Err(_) => answer(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.unavailable",
            "the change could not be completed",
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FactorBody {
    password: String,
}

async fn begin_factor(
    State(state): State<SignInRoutes>,
    headers: HeaderMap,
    Json(body): Json<FactorBody>,
) -> Response {
    if !state.secure {
        return insecure();
    }
    let Some(token) = bearer(&headers) else {
        return answer(
            StatusCode::UNAUTHORIZED,
            "auth.refused",
            "no session was given",
        );
    };
    let signin = Arc::clone(&state.signin);
    let begun =
        tokio::task::spawn_blocking(move || signin.begin_factor(&token, &body.password)).await;
    match begun {
        Ok(Ok((secret, uri))) => Json(json!({"secret": secret, "uri": uri})).into_response(),
        Ok(Err(refused)) => answer(StatusCode::BAD_REQUEST, "auth.invalid", &refused.0),
        Err(_) => answer(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.unavailable",
            "the enrollment could not be started",
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmBody {
    code: String,
}

async fn confirm_factor(
    State(state): State<SignInRoutes>,
    headers: HeaderMap,
    Json(body): Json<ConfirmBody>,
) -> Response {
    if !state.secure {
        return insecure();
    }
    let Some(token) = bearer(&headers) else {
        return answer(
            StatusCode::UNAUTHORIZED,
            "auth.refused",
            "no session was given",
        );
    };
    let signin = Arc::clone(&state.signin);
    let confirmed =
        tokio::task::spawn_blocking(move || signin.confirm_factor(&token, &body.code)).await;
    match confirmed {
        Ok(Ok(())) => StatusCode::NO_CONTENT.into_response(),
        Ok(Err(refused)) => answer(StatusCode::BAD_REQUEST, "auth.invalid", &refused.0),
        Err(_) => answer(
            StatusCode::SERVICE_UNAVAILABLE,
            "auth.unavailable",
            "the enrollment could not be confirmed",
        ),
    }
}
