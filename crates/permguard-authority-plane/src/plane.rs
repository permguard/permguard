// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Authority Plane as a Plane of the Host: what it declares, the handles it composes its
//! facade from, its routes on both transports, and the pass that keeps its lists signed.
//!
//! | Declared                           | Handle                           | Used by                     |
//! | ---------------------------------- | -------------------------------- | --------------------------- |
//! | signs `AccessTokenV1`              | `Signer<AccessTokenV1>`          | the token endpoint, the keys |
//! | signs `StatusListTokenV1`          | `Signer<StatusListTokenV1>`      | the status lists            |
//! | audit schema [`AuthorityAudit`]    | `AuditHandle<AuthorityAudit>`    | tokens issued and refused   |
//! | mutates `authority.accounts`, `authority.tokens` | `MutationHandle`   | every change                |
//! | feeds the token trust              | `AuthorityTrust`                 | this Host's verification    |

use std::sync::{Arc, Mutex, OnceLock};

use axum::extract::State;
use axum::response::{IntoResponse as _, Response};
use axum::routing::get;
use axum::{Json, Router};
use tonic::service::RoutesBuilder;

use anyhow::Result;
use permguard_core::{BoxFuture, PlaneContext, PlaneTask};
use permguard_host::composition::{AccessTokenV1, Declaration, StatusListTokenV1};
use permguard_server::PlaneModule;
use permguard_server::plane::{PlaneId, SETTING_AUTHORITY_AUDIENCE, SETTING_AUTHORITY_URL};

use crate::authority::{Authority, AuthorityAudit, Parts};
use crate::{accounts, admin, tokens};

/// How often the lists are signed again and handed to this Host: well within their `ttl`.
const FEED_EVERY: std::time::Duration = std::time::Duration::from_secs(5);
/// How often the lists whose tokens all expired are retired.
const RETIRE_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

/// What every answer about this plane is built from.
pub(crate) struct PlaneInfo {
    pub(crate) product: String,
    pub(crate) version: String,
    pub(crate) commit: String,
    pub(crate) health: permguard_core::PlaneHealth,
    /// The discovery document, without its first two members.
    rest: String,
}

impl PlaneInfo {
    fn of(context: &PlaneContext<'_>, issuer: &str) -> Self {
        let disclose = context.config().disclose_build();
        let rest = serde_json::json!({
            "edition": crate::authority::EDITION,
            "issuer": issuer,
            "jwks_uri": format!("{issuer}/authority/v1/keys"),
            "token_endpoint": format!("{issuer}/authority/v1/token"),
            "status_lists_endpoint": format!("{issuer}/authority/v1/status-lists"),
            "service_accounts_endpoint": format!("{issuer}/authority/v1/service-accounts"),
            "authorization_server_metadata": format!("{issuer}/.well-known/oauth-authorization-server"),
            "capabilities": ["service_accounts", "access_keys", "tokens", "status_lists"],
            "transports": {"http": true, "grpc": true},
        })
        .to_string();
        Self {
            product: context.identity().product_name().to_owned(),
            version: if disclose {
                context.config().version().to_owned()
            } else {
                String::new()
            },
            commit: if disclose {
                context.config().commit().to_owned()
            } else {
                String::new()
            },
            health: context.health(),
            rest: rest.trim_start_matches('{').to_owned(),
        }
    }

    /// The discovery document: who the plane is and its phase, then what it serves.
    pub(crate) fn document(&self) -> String {
        format!(
            "{{\"plane\":\"authority-plane\",\"state\":\"{}\",{}",
            self.health.phase().as_str(),
            self.rest
        )
    }
}

/// The facade, composed once and shared by both surfaces and the plane's pass.
#[derive(Default)]
struct Composed {
    authority: OnceLock<Option<(Arc<Authority>, Arc<PlaneInfo>)>>,
}

/// The Authority Plane module.
#[derive(Default)]
pub struct AuthorityPlaneModule {
    composed: Arc<Composed>,
}

/// The module every binary that runs the Authority Plane registers.
pub fn module() -> Box<dyn PlaneModule> {
    Box::new(AuthorityPlaneModule::default())
}

/// The issuer the Authority Plane signs as: `authority.url`, or where its HTTP listener is
/// advertised.
pub fn issuer_of(config: &permguard_core::Config) -> Option<String> {
    config
        .setting(SETTING_AUTHORITY_URL)
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .map(str::to_owned)
        .or_else(|| permguard_server::plane::plane_http_base(config, PlaneId::Authority))
        .map(|url| permguard_host::authz::authority::normalized(&url))
}

/// Whether the Authority Plane has a listener of its own: without one it is dormant, as every
/// Plane is that is given no address, and serves and signs nothing.
fn listening(config: &permguard_core::Config) -> bool {
    permguard_server::plane::plane_http_base(config, PlaneId::Authority).is_some()
        || config
            .setting(permguard_server::plane::SETTING_AUTHORITY_GRPC_ADDR)
            .is_some_and(|address| !address.trim().is_empty())
}

fn compose(context: &PlaneContext<'_>) -> Option<(Arc<Authority>, Arc<PlaneInfo>)> {
    let config = context.config();
    if !listening(config) {
        tracing::info!(
            event.name = "authority.dormant",
            component = crate::COMPONENT,
            "the Authority Plane has no listener: it issues nothing in this process"
        );
        return None;
    }
    let fail = |what: &str, error: &dyn std::fmt::Display| {
        tracing::error!(
            event.name = "authority.unserved",
            component = crate::COMPONENT,
            error = %error,
            "the Authority Plane serves nothing: {what}"
        );
    };
    let Some(registration) = crate::handles::registration(context) else {
        fail("no Host registered it", &"no registration");
        return None;
    };
    let Some(issuer) = issuer_of(config) else {
        fail(
            "it has no issuer",
            &"set authority.url, or give the Authority Plane an HTTP listener",
        );
        return None;
    };
    let (dir, options) = match registration.state_dir() {
        Ok(Some(found)) => found,
        Ok(None) => {
            fail("the Host composes no volume", &"no volume");
            return None;
        }
        Err(error) => {
            fail("its directory does not open", &error);
            return None;
        }
    };
    let accounts_mutations = registration.mutations(accounts::DOMAIN).ok().flatten();
    let token_mutations = registration.mutations(tokens::DOMAIN).ok().flatten();
    let (accounts, _) = match accounts::Accounts::open(&dir, options) {
        Ok(opened) => opened,
        Err(error) => {
            fail("its accounts do not open", &error);
            return None;
        }
    };
    let (registry, _) = match tokens::TokenRegistry::open(&dir, options) {
        Ok(opened) => opened,
        Err(error) => {
            fail("its tokens do not open", &error);
            return None;
        }
    };
    // A change a crash left open is committed or failed before anything reads the state.
    if let Some(handle) = &accounts_mutations
        && let Err(error) = handle.recover(&accounts::Recovering(&accounts))
    {
        fail(
            "the account changes a crash left open do not resolve",
            &error,
        );
        return None;
    }
    if let Some(handle) = &token_mutations
        && let Err(error) = handle.recover(&tokens::Recovering(&registry))
    {
        fail(
            "the token revocations a crash left open do not resolve",
            &error,
        );
        return None;
    }
    let time = Arc::new(permguard_host::time::TimeGuard::system(
        config.time_max_clock_skew(),
    ));
    match admin::ensure(&accounts, dir.path(), time.now_secs()) {
        Ok(Some(access_key)) => tracing::warn!(
            event.name = "authority.admin_created",
            component = crate::COMPONENT,
            access_key = %access_key,
            file = %dir.path().join(admin::KEY_FILE).display(),
            "the administrator `admin` is made: its first secret key is in the file named, \
             readable by its owner alone; move it somewhere safe and delete the file"
        ),
        Ok(None) => {}
        Err(error) => {
            fail("the administrator could not be made", &error);
            return None;
        }
    }
    let offline = admin::take_offline_mark(dir.path());
    let signer = |what: &str| {
        tracing::warn!(
            event.name = "authority.unsigned",
            component = crate::COMPONENT,
            "no authority.tokens ring is composed: the Authority Plane issues no {what}"
        );
    };
    let token_signer = registration.signer::<AccessTokenV1>().ok().flatten();
    if token_signer.is_none() {
        signer("token");
    }
    let list_signer = registration.signer::<StatusListTokenV1>().ok().flatten();
    let audit = registration.audit::<AuthorityAudit>().ok().flatten();
    let authority = Arc::new(Authority::new(Parts {
        accounts,
        registry,
        tokens: token_signer,
        lists: list_signer,
        issuer: issuer.clone(),
        audience: config
            .setting(SETTING_AUTHORITY_AUDIENCE)
            .map(str::trim)
            .filter(|audience| !audience.is_empty())
            .unwrap_or(permguard_host::authz::authority::DEFAULT_AUDIENCE)
            .to_owned(),
        profile: config.assurance().profile(),
        authorization: registration.authorization(),
        mutations: accounts_mutations,
        audit: audit.clone(),
        trust: registration.authority_trust(),
        time,
    }));
    authority.feed_trust();
    if let (Some(access_key), Some(audit)) = (offline, audit) {
        tokio::spawn(async move {
            let facts = [("access_key", permguard_core::Fact::Text(&access_key))];
            let event = permguard_core::AuditEvent::new(
                permguard_host::audit::AUDIT_ADMIN_KEY_OFFLINE,
                permguard_core::Subject::System("offline"),
            )
            .on("sa:admin")
            .with_facts(&facts);
            let _ = audit.record_event(&event).await;
        });
    }
    tracing::info!(
        event.name = "authority.serving",
        component = crate::COMPONENT,
        issuer = %issuer,
        accounts = authority.accounts().len(),
        "the Authority Plane issues tokens"
    );
    Some((authority, Arc::new(PlaneInfo::of(context, &issuer))))
}

impl AuthorityPlaneModule {
    fn authority(&self, context: &PlaneContext<'_>) -> Option<(Arc<Authority>, Arc<PlaneInfo>)> {
        self.composed
            .authority
            .get_or_init(|| compose(context))
            .clone()
    }
}

async fn info(State(plane): State<Arc<PlaneInfo>>) -> Response {
    Json(serde_json::json!({
        "plane": crate::PLANE,
        "product": plane.product,
        "version": plane.version,
        "commit": plane.commit,
        "edition": crate::authority::EDITION,
    }))
    .into_response()
}

async fn health(State(plane): State<Arc<PlaneInfo>>) -> Response {
    let mut body = serde_json::to_value(plane.health.report()).unwrap_or_default();
    if let Some(object) = body.as_object_mut() {
        object.insert("live".to_owned(), plane.health.is_live().into());
        object.insert("ready".to_owned(), plane.health.is_ready().into());
    }
    Json(body).into_response()
}

async fn configuration(State(plane): State<Arc<PlaneInfo>>) -> Response {
    (
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        plane.document(),
    )
        .into_response()
}

impl PlaneModule for AuthorityPlaneModule {
    fn id(&self) -> &'static str {
        crate::PLANE
    }

    fn component(&self) -> &'static str {
        crate::COMPONENT
    }

    fn description(&self) -> &'static str {
        "authority plane"
    }

    fn declaration(&self, _config: &permguard_core::Config) -> Declaration {
        Declaration::new(crate::PLANE)
            .signs::<AccessTokenV1>()
            .signs::<StatusListTokenV1>()
            .audits::<AuthorityAudit>()
            .mutates(accounts::DOMAIN)
            .mutates(tokens::DOMAIN)
            .feeds_token_trust()
    }

    fn dormant(&self, config: &permguard_core::Config) -> bool {
        !listening(config)
    }

    fn client_authentication_paths(&self) -> Vec<String> {
        vec![crate::http::TOKEN_PATH.to_owned()]
    }

    fn startup_check(&self, config: &permguard_core::Config) -> anyhow::Result<()> {
        use permguard_core::assurance::AssuranceProfile;
        use permguard_server::plane::{
            SETTING_AUTHORITY_HTTP_TLS_CERT, SETTING_AUTHORITY_HTTP_TLS_TERMINATED_UPSTREAM,
        };

        if issuer_of(config).is_none() {
            anyhow::bail!(
                "the Authority Plane has no issuer: set authority.url, or give it an HTTP listener \
                 (authorityPlane.public.http)"
            );
        }
        // A secret key crosses only TLS outside `development` (`2-security/8` Profiles).
        let profile = config.assurance().profile();
        let tls = config.setting(SETTING_AUTHORITY_HTTP_TLS_CERT).is_some()
            || config.public_tls().is_some()
            || config
                .setting(SETTING_AUTHORITY_HTTP_TLS_TERMINATED_UPSTREAM)
                .is_some_and(|value| value.trim() == "true")
            || config.public_tls_terminated_upstream();
        if profile != AssuranceProfile::Development && !tls {
            anyhow::bail!(
                "the `{}` profile sends a secret key over TLS only: give the Authority Plane TLS \
                 material (authorityPlane.public.http.tls or public.tls)",
                profile.as_str()
            );
        }
        Ok(())
    }

    fn services(&self) -> Vec<Box<dyn PlaneTask>> {
        vec![Box::new(ListsService {
            composed: Arc::clone(&self.composed),
            task: Mutex::new(None),
        })]
    }

    fn http_routes(&self, context: &PlaneContext<'_>) -> Router {
        let Some((authority, plane)) = self.authority(context) else {
            return Router::new();
        };
        Router::new()
            .route("/", get(info))
            .route("/version", get(info))
            .route("/health", get(health))
            .route("/.well-known/server-configuration", get(configuration))
            .with_state(plane)
            .merge(crate::http::routes(crate::http::Served {
                authority,
                disclosure: context.config().error_detail(),
            }))
    }

    fn grpc_routes(&self, context: &PlaneContext<'_>) -> Router {
        let Some((authority, plane)) = self.authority(context) else {
            return Router::new();
        };
        let served = crate::grpc::Served {
            authority,
            disclosure: context.config().error_detail(),
            plane,
        };
        let mut grpc = RoutesBuilder::default();
        // The gRPC Health Checking Protocol, beside the plane's own services.
        grpc.add_service(permguard_server::plane::health::service(context));
        grpc.add_service(
            crate::v1::authority_plane_server::AuthorityPlaneServer::new(served.clone()),
        );
        grpc.add_service(crate::v1::token_service_server::TokenServiceServer::new(
            served.clone(),
        ));
        grpc.add_service(
            crate::v1::service_account_service_server::ServiceAccountServiceServer::new(served),
        );
        grpc.routes().into_axum_router()
    }
}

/// The pass that keeps the lists signed within their `ttl`, hands them to this Host, and retires
/// the lists whose tokens all expired.
struct ListsService {
    composed: Arc<Composed>,
    task: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl PlaneTask for ListsService {
    fn name(&self) -> &'static str {
        "authority-lists"
    }

    fn start<'a>(&'a self, context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            let Some((authority, _)) = self
                .composed
                .authority
                .get_or_init(|| compose(context))
                .clone()
            else {
                return Ok(());
            };
            let task = tokio::spawn(async move {
                let mut retired_at = std::time::Instant::now();
                loop {
                    tokio::time::sleep(FEED_EVERY).await;
                    let feeding = Arc::clone(&authority);
                    let retire = retired_at.elapsed() >= RETIRE_EVERY;
                    if retire {
                        retired_at = std::time::Instant::now();
                    }
                    let _ = tokio::task::spawn_blocking(move || {
                        if retire && let Err(refusal) = feeding.retire_expired() {
                            tracing::warn!(
                                event.name = "authority.retire_failed",
                                component = crate::COMPONENT,
                                refusal = ?refusal,
                                "the expired status lists could not be retired"
                            );
                        }
                        feeding.feed_trust();
                    })
                    .await;
                }
            });
            *self
                .task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
            Ok(())
        })
    }

    fn stop<'a>(&'a self, _context: &'a PlaneContext<'a>) -> BoxFuture<'a, Result<()>> {
        Box::pin(async move {
            if let Some(task) = self
                .task
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
            {
                task.abort();
            }
            Ok(())
        })
    }
}
