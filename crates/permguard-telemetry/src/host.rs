// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! What the Server Host answers about itself: its version, and its operational keys.
//!
//! Both are process-level answers, not plane answers. The version names the build the whole
//! process is running, whichever planes it hosts; the keys are the operations ring — the keys
//! that seal the audit trail — published as a JWKS so an operator can spot-check a seal against
//! the process that made it.
//!
//! Publishing the ring here does **not** replace `keys export`. A forensic verification takes its
//! keys from a snapshot made *before* the incident, never from the machine under suspicion; this
//! endpoint serves the routine case — a dashboard, a readiness gate, a rotation check — where the
//! process is trusted and reaching for a volume would be ceremony.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use serde::Serialize;
use std::sync::Arc;
use tracing::warn;

use permguard_core::keys::{JwkSet, KEY_SET_MAX_AGE, KeyManager};
use permguard_core::{Config, ProductIdentity};

/// What `/version` answers: who this process is, and — when the deployment discloses builds —
/// which build it is.
///
/// The same contract the planes answer, with `component` where a plane says `plane`: the Host is
/// not a plane, and a reader joining the two must not be led to think it is.
#[derive(Clone, Serialize)]
pub struct VersionBody {
    component: &'static str,
    product: String,
    version: String,
    commit: String,
}

/// Renders the process version under `public.disclose_build`, exactly as the planes do.
///
/// One renderer for the disclosure decision, so the Host and a plane can never answer the same
/// question under two different policies.
pub fn version_body(
    component: &'static str,
    identity: &ProductIdentity,
    config: &Config,
) -> VersionBody {
    let disclose = config.disclose_build();

    VersionBody {
        component,
        product: identity.product_name().to_owned(),
        version: if disclose {
            config.version().to_owned()
        } else {
            String::new()
        },
        commit: if disclose {
            config.commit().to_owned()
        } else {
            String::new()
        },
    }
}

/// The `/version` route, from a body rendered once at composition.
pub fn version_route(body: VersionBody) -> Router {
    Router::new().route(
        "/version",
        get(move || {
            let body = body.clone();
            async move { Json(body).into_response() }
        }),
    )
}

/// The `/server-host/keys` route: the operations ring, published as a JWKS.
///
/// An unreadable ring is a `503`, never an empty set: `{"keys":[]}` reads as "nothing is published
/// yet", which is a legitimate state of a young ring, and an error dressed as that state sends a
/// verifier away satisfied when it should have sent an operator to the volume.
pub fn keys_route(keys: Arc<dyn KeyManager>) -> Router {
    async fn answer(State(keys): State<Arc<dyn KeyManager>>) -> axum::response::Response {
        match keys.public_keys() {
            Ok(published) => (
                [(
                    header::CACHE_CONTROL,
                    format!("max-age={}", KEY_SET_MAX_AGE.as_secs()),
                )],
                Json(JwkSet::new(published)),
            )
                .into_response(),
            Err(error) => {
                warn!(
                    event.name = "host.keys.unreadable",
                    component = "telemetry",
                    error = %error,
                    "the operations key ring could not be read"
                );

                (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "the operations key ring could not be read\n",
                )
                    .into_response()
            }
        }
    }

    Router::new()
        .route("/server-host/keys", get(answer))
        .with_state(keys)
}

/// The `/server-host/keys` route once the Host listener serves the ring: `308 Permanent
/// Redirect` to `location`, the one the registry's `jwks_uri` names, with `Deprecation: true`
/// (the HTTP Deprecation header field in the boolean form of its draft; RFC 9745 later made the
/// value a date) so a client reading the headers learns the route is legacy. `308` keeps the method;
/// a verifier fetching a key set follows it as the same `GET`.
pub fn keys_moved_route(location: String) -> Router {
    async fn answer(State(location): State<Arc<String>>) -> axum::response::Response {
        match header::HeaderValue::from_str(&location) {
            Ok(value) => (
                StatusCode::PERMANENT_REDIRECT,
                [
                    (header::LOCATION, value),
                    (
                        header::HeaderName::from_static("deprecation"),
                        header::HeaderValue::from_static("true"),
                    ),
                ],
                "the operations key ring moved to the Host listener\n",
            )
                .into_response(),
            Err(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "the Host listener's address is not a valid Location\n",
            )
                .into_response(),
        }
    }

    Router::new()
        .route("/server-host/keys", get(answer))
        .with_state(Arc::new(location))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use permguard_core::{BuildSettings, Layers};

    use super::*;

    #[tokio::test]
    async fn the_moved_keys_route_redirects_permanently_and_says_it_is_deprecated() {
        use tower::ServiceExt as _;

        let router =
            keys_moved_route("https://127.0.0.1:5444/host/v1/keys/host.operations".to_owned());
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/server-host/keys")
                    .body(axum::body::Body::empty())
                    .expect("a request"),
            )
            .await
            .expect("answered");
        assert_eq!(response.status(), StatusCode::PERMANENT_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("https://127.0.0.1:5444/host/v1/keys/host.operations")
        );
        assert_eq!(
            response
                .headers()
                .get("deprecation")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
    }

    fn config_disclosing(disclose: bool) -> Config {
        let file: Vec<(String, String)> = if disclose {
            Vec::new()
        } else {
            vec![(
                "PERMGUARD_PUBLIC_DISCLOSE_BUILD".to_owned(),
                "false".to_owned(),
            )]
        };
        Config::from_layers(
            BuildSettings::new("1.2.3", "2026", "Build Holder"),
            Vec::<&'static str>::new(),
            Layers::new().with_file(file),
        )
        .expect("the test config assembles")
    }

    /// `/version` answers what `health.json` describes, disclosed or not.
    #[test]
    fn the_version_body_matches_openapi_health() {
        let doc = permguard_conformance::schema::Document::load("health.json");
        let identity = ProductIdentity::new("permguard", "Permguard", "", "", "");
        for disclosing in [true, false] {
            doc.check(
                "VersionBody",
                &version_body("server-host", &identity, &config_disclosing(disclosing)),
            );
        }
    }

    #[test]
    fn the_version_body_discloses_only_when_told_to() {
        let identity = ProductIdentity::new("permguard", "Permguard", "", "", "");

        let open = version_body("server-host", &identity, &config_disclosing(true));
        assert_eq!(open.component, "server-host");
        assert_eq!(open.version, "1.2.3");

        let closed = version_body("server-host", &identity, &config_disclosing(false));
        assert_eq!(closed.component, "server-host");
        assert!(closed.version.is_empty());
        assert!(closed.commit.is_empty());
    }
}
