// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `/auth/v1/setup` on the Server Host surface (WP-8.2, `2-security/5` Sign-in): the first
//! administrator, made with the setup code a Host without one waits for.
//!
//! | Route                    | Answers                                                                |
//! | ------------------------ | ---------------------------------------------------------------------- |
//! | `GET /auth/v1/setup`     | `{waiting, origin, expires_at}` while a code waits; `404` otherwise     |
//! | `POST /auth/v1/setup`    | `201` `{user, principal, grant, origin}`; `401` `setup.refused`; `404`  |
//!
//! Over TLS only, loopback aside; ten refusals within fifteen minutes close the route for fifteen
//! minutes; a password is hashed off the runtime's threads, one of the sign-in's few slots. Every
//! success and refusal is an audit record, never the code.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use permguard_core::server::{AuditRecorder, Health};
use permguard_host::setup::{self, Request, Setup};
use serde::Deserialize;
use serde_json::json;

use crate::signin_http::{answer, busy, hashing_slot, insecure};

/// Refusals within [`WINDOW`] that close the route.
const REFUSALS: usize = 10;
/// The window refusals are counted in, and how long the route stays closed after them.
const WINDOW: Duration = Duration::from_secs(900);

/// What the routes share.
#[derive(Clone)]
pub struct SetupRoutes {
    pub setup: Arc<Setup>,
    pub mutations: Arc<permguard_host::operations::mutation::Mutations>,
    pub directory: Arc<permguard_host::authz::directory::Directory>,
    pub store: Arc<permguard_host::authz::GrantStore>,
    /// Whether the surface is TLS or on a loopback address.
    pub secure: bool,
    /// The password policy's length, when the first administrator gets a password.
    pub min_length: usize,
    pub health: Health,
    pub recorder: Option<AuditRecorder>,
    /// When each recent refusal happened.
    pub refusals: Arc<Mutex<VecDeque<Instant>>>,
}

/// The `/auth/v1/setup` routes over `state`.
pub fn router(state: SetupRoutes) -> axum::Router {
    axum::Router::new()
        .route("/auth/v1/setup", get(status).post(complete))
        .with_state(state)
}

fn not_waiting() -> Response {
    answer(
        StatusCode::NOT_FOUND,
        "setup.closed",
        "this Host waits for no setup code",
    )
}

fn record(state: &SetupRoutes, action: &'static str, target: String) {
    let Some(recorder) = state.recorder.clone() else {
        return;
    };
    tokio::spawn(async move {
        if let Err(error) = recorder
            .record_on(action, permguard_core::Subject::System("setup"), &target)
            .await
        {
            tracing::error!(
                event.name = "host.setup_unrecorded",
                component = "server",
                action,
                error = %error,
                "a setup could not be recorded"
            );
        }
    });
}

async fn status(State(state): State<SetupRoutes>) -> Response {
    match state.setup.waiting() {
        Ok(Some(waiting)) if waiting.expires_at > permguard_host::authz::store::now() => {
            Json(json!({
                "waiting": true,
                "origin": waiting.origin.as_str(),
                "expires_at": permguard_core::time::to_rfc3339(
                    i64::try_from(waiting.expires_at).unwrap_or(i64::MAX)
                ),
            }))
            .into_response()
        }
        Ok(_) => not_waiting(),
        Err(_) => answer(
            StatusCode::SERVICE_UNAVAILABLE,
            "setup.unavailable",
            "the setup state cannot be read",
        ),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetupBody {
    code: String,
    name: String,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    password: Option<String>,
}

/// Whether the route is closed by recent refusals; forgets the ones past the window.
fn closed(state: &SetupRoutes) -> bool {
    let mut refusals = state
        .refusals
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    let now = Instant::now();
    while refusals
        .front()
        .is_some_and(|at| now.duration_since(*at) >= WINDOW)
    {
        refusals.pop_front();
    }
    refusals.len() >= REFUSALS
}

/// A refusal, recorded; only a wrong code counts toward closing the route, so an operator who
/// had the code and mistyped a name is not locked out.
fn refused(
    state: &SetupRoutes,
    reason: &'static str,
    status: StatusCode,
    message: &str,
) -> Response {
    if reason == "code" {
        state
            .refusals
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(Instant::now());
    }
    tracing::warn!(
        event.name = "host.setup_refused",
        component = "server",
        reason,
        "a setup was refused"
    );
    record(state, setup::AUDIT_REFUSED, format!("reason={reason}"));
    answer(status, "setup.refused", message)
}

async fn complete(State(state): State<SetupRoutes>, Json(body): Json<SetupBody>) -> Response {
    if !state.secure {
        return insecure();
    }
    if !matches!(state.setup.waiting(), Ok(Some(_))) {
        return not_waiting();
    }
    if closed(&state) {
        return answer(
            StatusCode::TOO_MANY_REQUESTS,
            "setup.closed_for_now",
            "too many refused setups: the route is closed for fifteen minutes",
        );
    }
    // The code first: without it nothing else is read, and no password is hashed.
    match state
        .setup
        .accepts(&body.code, permguard_host::authz::store::now())
    {
        Ok(Some(_)) => {}
        Ok(None) => {
            return refused(
                &state,
                "code",
                StatusCode::UNAUTHORIZED,
                "the setup was refused",
            );
        }
        Err(_) => {
            return answer(
                StatusCode::SERVICE_UNAVAILABLE,
                "setup.unavailable",
                "the setup state cannot be read",
            );
        }
    }
    let Some(_slot) = hashing_slot() else {
        return busy();
    };
    let routes = state.clone();
    let made = tokio::task::spawn_blocking(move || {
        let password = match body.password.as_deref() {
            Some(password) => {
                permguard_host::authz::password::check_policy(
                    &body.name,
                    password,
                    routes.min_length,
                )
                .map_err(setup::Refused::Invalid)?;
                Some(
                    permguard_host::authz::password::hash(password)
                        .map_err(setup::Refused::Unavailable)?,
                )
            }
            None => None,
        };
        setup::complete(
            &routes.setup,
            &routes.mutations,
            &routes.directory,
            &routes.store,
            Request {
                code: &body.code,
                name: &body.name,
                email: body.email.clone(),
                password,
            },
            permguard_host::authz::store::now(),
        )
    })
    .await;
    match made {
        Ok(Ok(made)) => {
            state
                .health
                .lifecycle()
                .restore(permguard_core::lifecycle::HOST, setup::CAPABILITY);
            tracing::info!(
                event.name = "host.setup_completed",
                component = "server",
                user = %made.user,
                origin = made.origin.as_str(),
                "the first administrator is made: the setup code is gone"
            );
            record(
                &state,
                setup::AUDIT_COMPLETED,
                format!("user={} origin={}", made.user, made.origin.as_str()),
            );
            (StatusCode::CREATED, Json(made)).into_response()
        }
        Ok(Err(setup::Refused::Code)) => refused(
            &state,
            "code",
            StatusCode::UNAUTHORIZED,
            "the setup was refused",
        ),
        Ok(Err(setup::Refused::Invalid(message))) => {
            refused(&state, "invalid", StatusCode::BAD_REQUEST, &message)
        }
        Ok(Err(setup::Refused::Unavailable(message))) => {
            tracing::error!(
                event.name = "host.setup_failed",
                component = "server",
                error = %message,
                "a setup could not be completed"
            );
            answer(
                StatusCode::SERVICE_UNAVAILABLE,
                "setup.unavailable",
                "the setup could not be completed",
            )
        }
        Err(_) => answer(
            StatusCode::SERVICE_UNAVAILABLE,
            "setup.unavailable",
            "the setup could not be completed",
        ),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use http_body_util::BodyExt as _;
    use permguard_core::assurance::AssuranceProfile;
    use permguard_host::storage::volume::Volume;
    use tower::ServiceExt as _;

    use super::*;

    /// The routes over a fresh volume with no administrator, and the code it waits for.
    fn served(tag: &str, secure: bool) -> (axum::Router, String, SetupRoutes) {
        let root = std::env::temp_dir().join(format!("pg-setup-http-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("scratch");
        let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
        let (store, _) = permguard_host::authz::GrantStore::open(&volume).expect("grants");
        let (directory, _) =
            permguard_host::authz::directory::Directory::open(&volume).expect("directory");
        let mutations = Arc::new(
            permguard_host::operations::mutation::Mutations::open_offline(&volume, "test")
                .expect("engine"),
        );
        let setup = Arc::new(Setup::open(&volume).expect("setup"));
        setup
            .prepare(
                false,
                None,
                Duration::from_secs(3_600),
                permguard_host::authz::store::now(),
            )
            .expect("a code waits");
        let code = std::fs::read_to_string(setup.code_path())
            .expect("the code")
            .trim()
            .to_owned();
        std::mem::forget(volume);
        let state = SetupRoutes {
            setup,
            mutations,
            directory,
            store,
            secure,
            min_length: 12,
            health: Health::new(),
            recorder: None,
            refusals: Arc::default(),
        };
        (router(state.clone()), code, state)
    }

    async fn call(
        router: &axum::Router,
        method: &str,
        body: Option<serde_json::Value>,
    ) -> (StatusCode, serde_json::Value) {
        let mut request = HttpRequest::builder().method(method).uri("/auth/v1/setup");
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let response = router
            .clone()
            .oneshot(
                request
                    .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                    .expect("a request"),
            )
            .await
            .expect("answered");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("reads")
            .to_bytes();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// The first administrator is made with the code, once; before, a wrong code is refused
    /// without the password ever being read; after, the route is `404`.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_code_makes_the_first_administrator_once_then_the_route_is_gone() {
        let (router, code, state) = served("once", true);
        let (status, waiting) = call(&router, "GET", None).await;
        assert_eq!(status, StatusCode::OK, "{waiting}");
        assert_eq!(waiting["waiting"], true);
        assert!(!waiting.to_string().contains(&code), "never the code");

        let (status, refused) = call(
            &router,
            "POST",
            Some(json!({"code": "pgsetup_wrong", "name": "alice", "password": "short"})),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{refused}");
        assert!(
            !refused.to_string().contains("characters"),
            "no policy without the code"
        );

        let (status, made) = call(
            &router,
            "POST",
            Some(json!({"code": code, "name": "alice", "password": "alice's first password"})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "{made}");
        assert_eq!(made["principal"], "user:alice");
        assert!(permguard_host::setup::administered(
            &state.store,
            permguard_host::authz::store::now()
        ));

        assert_eq!(call(&router, "GET", None).await.0, StatusCode::NOT_FOUND);
        let (status, _) = call(
            &router,
            "POST",
            Some(json!({"code": code, "name": "mallory", "email": "m@evil.example"})),
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND, "once");
    }

    /// Ten refusals close the route; a surface in the clear never takes a code.
    #[tokio::test(flavor = "multi_thread")]
    async fn refusals_close_the_route_and_the_clear_takes_no_code() {
        let (router, code, _) = served("closed", true);
        for _ in 0..REFUSALS {
            let (status, _) = call(
                &router,
                "POST",
                Some(json!({"code": "pgsetup_guess", "name": "x", "email": "x@x.example"})),
            )
            .await;
            assert_eq!(status, StatusCode::UNAUTHORIZED);
        }
        let (status, _) = call(
            &router,
            "POST",
            Some(json!({"code": code, "name": "alice", "email": "alice@acme.example"})),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::TOO_MANY_REQUESTS,
            "closed even to the right code"
        );

        let (clear, code, _) = served("clear", false);
        let (status, _) = call(
            &clear,
            "POST",
            Some(json!({"code": code, "name": "alice", "email": "alice@acme.example"})),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
