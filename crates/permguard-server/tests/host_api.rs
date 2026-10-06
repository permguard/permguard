// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The Host listener (WP-2.5): both transports answer the same vectors through one facade, a
//! retried mutation returns its stored result on each, and the listener binds `admin.addr` over
//! TLS, gated and authenticated like every other surface.

#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use permguard_conformance::contracts::host_v1;
use permguard_conformance::parity::{Outcome, assert_parity, serve};
use permguard_core::assurance::AssuranceProfile;
use permguard_core::authz::{
    Actor, ActorContext, Authenticator, Credential, Principal, Resource, Selector, operations,
};
use permguard_core::config::{
    SETTING_ADMIN_ADDR, SETTING_ADMIN_TLS_CERT, SETTING_ADMIN_TLS_KEY, SETTING_AUTOGENERATE,
    SETTING_DEVELOPMENT_MODE, SETTING_WORKING_DIR,
};
use permguard_core::keys::{Jwk, KeyId, KeyManager, Maintenance, PublicSet, Sign};
use permguard_core::{
    AccessDenial, BuildSettings, Config, Disclosure, Health, Layers, PeerIdentity, ProductIdentity,
    ServerContext, Service as _,
};
use permguard_host::api::{Assurance, Composition, Effective, HostApi, Replay};
use permguard_host::authz::{Authorization, GrantStore, Issue, PublicGrant};
use permguard_host::composition::HOST_OPERATIONS;
use permguard_host::storage::volume::Volume;
use permguard_server::host_api::{self, HostApiService};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;
use permguard_transport::ActorLayer;
use serde_json::{Value, json};
use tower::ServiceExt as _;

const ADMIN: &str = "spiffe://acme/operators/root";
const STRANGER: &str = "spiffe://acme/stranger";

/// Identifiers and instants a mutation mints: two facades cannot share them.
const MINTED: &[&str] = &[
    "grant_id",
    "operation_id",
    "issued_at",
    "plan_id",
    "plan_digest",
    "expires",
];

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-host-api-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

/// A ring with one fixed public key: the Host API never signs or maintains.
struct Fixed;

impl Sign for Fixed {
    fn active_key_id(&self) -> permguard_core::keys::Result<KeyId> {
        unreachable!("the Host API never signs")
    }

    fn sign(&self, _: &[u8]) -> permguard_core::keys::Result<permguard_core::keys::Signature> {
        unreachable!("the Host API never signs")
    }
}

impl PublicSet for Fixed {
    fn public_keys(&self) -> permguard_core::keys::Result<Vec<Jwk>> {
        Ok(vec![Jwk::okp("k1", "Ed25519", "EdDSA", "AAAA")])
    }
}

impl KeyManager for Fixed {
    fn name(&self) -> &'static str {
        "fixed"
    }

    fn maintain(&self) -> permguard_core::keys::Result<Maintenance> {
        unreachable!("the Host API never maintains")
    }
}

/// The credential mapper of these tests: `Bearer <name>` is the principal `<name>`, so a vector
/// names who it acts as the same way on both transports.
struct Bearers;

impl Authenticator for Bearers {
    fn authenticate(
        &self,
        _peer: Option<&PeerIdentity>,
        bearer: Option<&str>,
    ) -> Result<Actor, AccessDenial> {
        match bearer {
            Some(name) => Ok(Actor::Authenticated(ActorContext::new(
                Principal::new(name).expect("a principal"),
                Credential::Oidc,
                None,
            ))),
            None => Ok(Actor::Anonymous),
        }
    }
}

/// The same mapping, as the gRPC boundary would apply it before the handlers.
fn bearer_interceptor(
    mut request: tonic::Request<()>,
) -> Result<tonic::Request<()>, tonic::Status> {
    let bearer = request
        .metadata()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned);
    let actor = Bearers
        .authenticate(None, bearer.as_deref())
        .expect("the test mapper never refuses");
    request.extensions_mut().insert(Arc::new(actor));
    Ok(request)
}

/// A facade over its own volume, with one administrator holding every Host operation and
/// `keys.read` public, as a deployment would declare it.
fn facade(tag: &str) -> Arc<HostApi> {
    let root = scratch(tag);
    let volume = Volume::claim(&root, AssuranceProfile::Development).expect("claimed");
    let (store, _) = GrantStore::open(&volume).expect("the grant store opens");
    store
        .issue(
            Issue {
                principal: Principal::new(ADMIN).expect("a principal"),
                operations: operations::ALL
                    .iter()
                    .map(|operation| (*operation).to_owned())
                    .collect(),
                selector: Selector::under(Resource::host()),
                resource_types: vec!["*".to_owned()],
                constraints: Default::default(),
                issued_by: "test".to_owned(),
                expires_at: None,
            },
            permguard_host::authz::store::now(),
        )
        .expect("the administrator is issued");
    let (replay, _) =
        Replay::open(&volume, permguard_host::authz::store::now()).expect("the replay opens");
    // The volume stays claimed for the life of the test process: the store holds its directory.
    std::mem::forget(volume);
    Arc::new(HostApi::new(Composition {
        authorization: Arc::new(Authorization::new(
            Arc::clone(&store),
            &[PublicGrant::new(
                &[operations::KEYS_READ],
                Selector::exactly(Resource::host()),
            )],
        )),
        store: Some(store),
        replay,
        rings: vec![(HOST_OPERATIONS.as_str().to_owned(), Arc::new(Fixed))],
        health: Health::new(),
        assurance: Assurance {
            profile: "development".to_owned(),
        },
        effective: Effective {
            revision: 0,
            settings: Vec::new(),
        },
        trail: "recording".to_owned(),
        recorder: None,
    }))
}

/// One transport of the Host API, driven as a client would drive it.
enum Transport {
    Rest(axum::Router),
    Grpc(String),
}

/// What one call answered, reduced to what must not differ between transports.
fn reduced_http(status: StatusCode, body: &[u8]) -> Outcome {
    let value: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    if status.is_success() {
        Outcome::Answered(value)
    } else {
        Outcome::Refused {
            class: value["class"].as_str().unwrap_or_default().to_owned(),
            code: value["code"].as_str().unwrap_or_default().to_owned(),
        }
    }
}

fn reduced_grpc<T: serde::Serialize>(result: Result<tonic::Response<T>, tonic::Status>) -> Outcome {
    match result {
        Ok(response) => Outcome::Answered(
            serde_json::to_value(response.into_inner()).expect("a gRPC answer serializes"),
        ),
        Err(status) => {
            let metadata = |key: &str| {
                status
                    .metadata()
                    .get(key)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned()
            };
            Outcome::Refused {
                class: metadata(permguard_core::GRPC_ERROR_CLASS),
                code: metadata(permguard_core::GRPC_ERROR_CODE),
            }
        }
    }
}

impl Transport {
    async fn rest(
        &self,
        method: &str,
        path: &str,
        who: Option<&str>,
        body: Option<Value>,
    ) -> Outcome {
        let Self::Rest(router) = self else {
            unreachable!("asked of the gRPC transport")
        };
        let mut request = Request::builder().method(method).uri(path);
        if let Some(who) = who {
            request = request.header("authorization", format!("Bearer {who}"));
        }
        if body.is_some() {
            request = request.header("content-type", "application/json");
        }
        let request = request
            .body(axum::body::Body::from(
                body.map(|body| body.to_string()).unwrap_or_default(),
            ))
            .expect("a request");
        let response = router.clone().oneshot(request).await.expect("answered");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("reads")
            .to_bytes();
        reduced_http(status, &bytes)
    }

    fn grpc_request<T>(who: Option<&str>, inner: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(inner);
        if let Some(who) = who {
            request.metadata_mut().insert(
                "authorization",
                format!("Bearer {who}").parse().expect("a metadata value"),
            );
        }
        request
    }

    fn grpc_url(&self) -> &str {
        let Self::Grpc(url) = self else {
            unreachable!("asked of the REST transport")
        };
        url.trim_start_matches("grpc://")
    }

    async fn grants(
        &self,
    ) -> host_v1::grant_service_client::GrantServiceClient<tonic::transport::Channel> {
        host_v1::grant_service_client::GrantServiceClient::connect(format!(
            "http://{}",
            self.grpc_url()
        ))
        .await
        .expect("the gRPC endpoint answers")
    }

    async fn keys(
        &self,
    ) -> host_v1::key_service_client::KeyServiceClient<tonic::transport::Channel> {
        host_v1::key_service_client::KeyServiceClient::connect(format!(
            "http://{}",
            self.grpc_url()
        ))
        .await
        .expect("the gRPC endpoint answers")
    }

    async fn operations(
        &self,
    ) -> host_v1::operations_service_client::OperationsServiceClient<tonic::transport::Channel>
    {
        host_v1::operations_service_client::OperationsServiceClient::connect(format!(
            "http://{}",
            self.grpc_url()
        ))
        .await
        .expect("the gRPC endpoint answers")
    }

    async fn identity(
        &self,
    ) -> host_v1::identity_service_client::IdentityServiceClient<tonic::transport::Channel> {
        host_v1::identity_service_client::IdentityServiceClient::connect(format!(
            "http://{}",
            self.grpc_url()
        ))
        .await
        .expect("the gRPC endpoint answers")
    }

    async fn list_grants(&self, who: Option<&str>) -> Outcome {
        match self {
            Self::Rest(_) => self.rest("GET", "/host/v1/grants", who, None).await,
            Self::Grpc(_) => reduced_grpc(
                self.grants()
                    .await
                    .list_grants(Self::grpc_request(
                        who,
                        host_v1::ListGrantsRequest::default(),
                    ))
                    .await,
            ),
        }
    }

    async fn create_grant(
        &self,
        who: Option<&str>,
        request_id: &str,
        principal: &str,
        operation: &str,
        expected_revision: Option<u64>,
    ) -> Outcome {
        match self {
            Self::Rest(_) => {
                let mut body = json!({
                    "request_id": request_id,
                    "principal": principal,
                    "operations": [operation],
                    "selector": "plane/control/*",
                });
                if let Some(expected) = expected_revision {
                    body["expected_revision"] = json!(expected);
                }
                self.rest("POST", "/host/v1/grants", who, Some(body)).await
            }
            Self::Grpc(_) => reduced_grpc(
                self.grants()
                    .await
                    .create_grant(Self::grpc_request(
                        who,
                        host_v1::CreateGrantRequest {
                            request_id: request_id.to_owned(),
                            expected_revision,
                            principal: principal.to_owned(),
                            operations: vec![operation.to_owned()],
                            selector: "plane/control/*".to_owned(),
                            resource_types: Vec::new(),
                            constraints: Default::default(),
                            expires_at: None,
                        },
                    ))
                    .await,
            ),
        }
    }

    /// A create with every optional member: an expiry, a constraint, explicit types. The
    /// principal decides the expiry: `carol` far ahead, anyone else in the past.
    async fn create_grant_full(
        &self,
        who: Option<&str>,
        request_id: &str,
        principal: &str,
    ) -> Outcome {
        let expires_at = if principal.ends_with("carol") {
            "2099-01-01T00:00:00Z"
        } else {
            "2000-01-01T00:00:00Z"
        };
        let constraints = std::collections::BTreeMap::from([("env".to_owned(), "lab".to_owned())]);
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    "/host/v1/grants",
                    who,
                    Some(json!({
                        "request_id": request_id,
                        "principal": principal,
                        "operations": [operations::CATALOG_READ],
                        "selector": "plane/control/*",
                        "resource_types": ["zone"],
                        "constraints": constraints,
                        "expires_at": expires_at,
                    })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.grants()
                    .await
                    .create_grant(Self::grpc_request(
                        who,
                        host_v1::CreateGrantRequest {
                            request_id: request_id.to_owned(),
                            expected_revision: None,
                            principal: principal.to_owned(),
                            operations: vec![operations::CATALOG_READ.to_owned()],
                            selector: "plane/control/*".to_owned(),
                            resource_types: vec!["zone".to_owned()],
                            constraints: constraints.into_iter().collect(),
                            expires_at: Some(expires_at.to_owned()),
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn ring_bindings(&self, who: Option<&str>) -> Outcome {
        match self {
            Self::Rest(_) => self.rest("GET", "/host/v1/ring-bindings", who, None).await,
            Self::Grpc(_) => reduced_grpc(
                self.identity()
                    .await
                    .list_ring_bindings(Self::grpc_request(
                        who,
                        host_v1::ListRingBindingsRequest::default(),
                    ))
                    .await,
            ),
        }
    }

    async fn plan_revoke(&self, who: Option<&str>, grant_id: &str, request_id: &str) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    &format!("/host/v1/grants/{grant_id}/revoke/plan"),
                    who,
                    Some(json!({ "request_id": request_id })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.grants()
                    .await
                    .plan_grant_revoke(Self::grpc_request(
                        who,
                        host_v1::PlanGrantRevokeRequest {
                            grant_id: grant_id.to_owned(),
                            request_id: request_id.to_owned(),
                            expected_revision: None,
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn run_revoke(
        &self,
        who: Option<&str>,
        grant_id: &str,
        request_id: &str,
        plan_id: &str,
        plan_digest: &str,
    ) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    &format!("/host/v1/grants/{grant_id}/revoke/run"),
                    who,
                    Some(json!({
                        "request_id": request_id,
                        "plan_id": plan_id,
                        "plan_digest": plan_digest,
                    })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.grants()
                    .await
                    .run_grant_revoke(Self::grpc_request(
                        who,
                        host_v1::RunGrantRevokeRequest {
                            grant_id: grant_id.to_owned(),
                            request_id: request_id.to_owned(),
                            plan_id: plan_id.to_owned(),
                            plan_digest: plan_digest.to_owned(),
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn list_rings(&self, who: Option<&str>) -> Outcome {
        match self {
            Self::Rest(_) => self.rest("GET", "/host/v1/keys", who, None).await,
            Self::Grpc(_) => reduced_grpc(
                self.keys()
                    .await
                    .list_key_rings(Self::grpc_request(
                        who,
                        host_v1::ListKeyRingsRequest::default(),
                    ))
                    .await,
            ),
        }
    }

    async fn ring(&self, ring: &str) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest("GET", &format!("/host/v1/keys/{ring}"), None, None)
                    .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.keys()
                    .await
                    .get_key_ring(Self::grpc_request(
                        None,
                        host_v1::GetKeyRingRequest {
                            ring: ring.to_owned(),
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn status(&self, who: Option<&str>) -> Outcome {
        match self {
            Self::Rest(_) => self.rest("GET", "/host/v1/status", who, None).await,
            Self::Grpc(_) => reduced_grpc(
                self.operations()
                    .await
                    .get_status(Self::grpc_request(
                        who,
                        host_v1::GetStatusRequest::default(),
                    ))
                    .await,
            ),
        }
    }

    async fn effective_config(&self, who: Option<&str>) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest("GET", "/host/v1/config/effective", who, None)
                    .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.operations()
                    .await
                    .get_effective_config(Self::grpc_request(
                        who,
                        host_v1::GetEffectiveConfigRequest::default(),
                    ))
                    .await,
            ),
        }
    }

    async fn config_revisions(&self, who: Option<&str>) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest("GET", "/host/v1/config/revisions", who, None)
                    .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.operations()
                    .await
                    .list_config_revisions(Self::grpc_request(
                        who,
                        host_v1::ListConfigRevisionsRequest::default(),
                    ))
                    .await,
            ),
        }
    }

    async fn identity_document(&self, who: Option<&str>) -> Outcome {
        match self {
            Self::Rest(_) => self.rest("GET", "/host/v1/identity", who, None).await,
            Self::Grpc(_) => reduced_grpc(
                self.identity()
                    .await
                    .get_identity(Self::grpc_request(
                        who,
                        host_v1::GetIdentityRequest::default(),
                    ))
                    .await,
            ),
        }
    }
}

fn member<'a>(outcome: &'a Outcome, path: &[&str]) -> &'a str {
    let Outcome::Answered(value) = outcome else {
        panic!("expected an answer, got {outcome:?}")
    };
    let mut at = value;
    for step in path {
        at = &at[*step];
    }
    at.as_str()
        .unwrap_or_else(|| panic!("{path:?} is not a string in {value}"))
}

/// Every step of the script, named, with what this transport answered. The retried mutations
/// are compared with their first answers here, unmasked: the replay window returns what was
/// stored, operation id included.
async fn script(transport: &Transport) -> Vec<(&'static str, Outcome)> {
    let admin = Some(ADMIN);
    let mut steps = Vec::new();
    steps.push((
        "list the grants as nobody",
        transport.list_grants(None).await,
    ));
    steps.push((
        "list the grants as a stranger",
        transport.list_grants(Some(STRANGER)).await,
    ));
    steps.push(("list the grants", transport.list_grants(admin).await));
    let created = transport
        .create_grant(
            admin,
            "r1",
            "spiffe://acme/alice",
            operations::CATALOG_READ,
            None,
        )
        .await;
    let retried = transport
        .create_grant(
            admin,
            "r1",
            "spiffe://acme/alice",
            operations::CATALOG_READ,
            None,
        )
        .await;
    assert_eq!(
        retried, created,
        "a retried create returns the stored answer, operation id included"
    );
    steps.push(("create a grant", created.clone()));
    steps.push((
        "create without a request id",
        transport
            .create_grant(
                admin,
                "",
                "spiffe://acme/bob",
                operations::CATALOG_READ,
                None,
            )
            .await,
    ));
    steps.push((
        "reuse the request id for another grant",
        transport
            .create_grant(
                admin,
                "r1",
                "spiffe://acme/bob",
                operations::CATALOG_READ,
                None,
            )
            .await,
    ));
    steps.push((
        "create with an unregistered operation",
        transport
            .create_grant(admin, "r2", "spiffe://acme/bob", "nope.read", None)
            .await,
    ));
    steps.push((
        "create against a stale revision",
        transport
            .create_grant(
                admin,
                "r3",
                "spiffe://acme/bob",
                operations::CATALOG_READ,
                Some(999),
            )
            .await,
    ));
    steps.push((
        "create as a stranger",
        transport
            .create_grant(
                Some(STRANGER),
                "r4",
                "spiffe://acme/bob",
                operations::CATALOG_READ,
                None,
            )
            .await,
    ));
    steps.push(("list the grants after", transport.list_grants(admin).await));
    steps.push((
        "create a grant with an expiry and a constraint",
        transport
            .create_grant_full(admin, "r5", "spiffe://acme/carol")
            .await,
    ));
    steps.push((
        "create a grant with an expiry in the past",
        transport
            .create_grant_full(admin, "r6", "spiffe://acme/dave")
            .await,
    ));
    let grant_id = member(&created, &["grant", "grant_id"]).to_owned();
    let planned = transport.plan_revoke(admin, &grant_id, "p1").await;
    let plan_id = member(&planned, &["plan_id"]).to_owned();
    let plan_digest = member(&planned, &["plan_digest"]).to_owned();
    steps.push(("plan a revocation", planned.clone()));
    steps.push((
        "run with a wrong digest",
        transport
            .run_revoke(admin, &grant_id, "x1", &plan_id, &"00".repeat(32))
            .await,
    ));
    steps.push((
        "run with an unknown plan",
        transport
            .run_revoke(admin, &grant_id, "x2", &"11".repeat(16), &plan_digest)
            .await,
    ));
    let revoked = transport
        .run_revoke(admin, &grant_id, "run1", &plan_id, &plan_digest)
        .await;
    let retried = transport
        .run_revoke(admin, &grant_id, "run1", &plan_id, &plan_digest)
        .await;
    assert_eq!(retried, revoked, "a retried run returns the stored receipt");
    steps.push(("run the revocation", revoked));
    steps.push((
        "run the consumed plan again",
        transport
            .run_revoke(admin, &grant_id, "run2", &plan_id, &plan_digest)
            .await,
    ));
    steps.push((
        "plan against the revoked grant",
        transport.plan_revoke(admin, &grant_id, "p2").await,
    ));
    steps.push((
        "plan against an unknown grant",
        transport.plan_revoke(admin, &"0".repeat(32), "p3").await,
    ));
    steps.push((
        "plan against a malformed id",
        transport.plan_revoke(admin, "not-an-id", "p4").await,
    ));
    steps.push(("list the key rings", transport.list_rings(admin).await));
    steps.push((
        "list the key rings as nobody",
        transport.list_rings(None).await,
    ));
    steps.push((
        "read the operations ring",
        transport.ring(HOST_OPERATIONS.as_str()).await,
    ));
    steps.push(("read an unknown ring", transport.ring("nope").await));
    steps.push(("read the status", transport.status(admin).await));
    steps.push((
        "read the status as a stranger",
        transport.status(Some(STRANGER)).await,
    ));
    steps.push((
        "read the effective configuration",
        transport.effective_config(admin).await,
    ));
    steps.push((
        "read the configuration revisions",
        transport.config_revisions(admin).await,
    ));
    steps.push((
        "read the identity",
        transport.identity_document(admin).await,
    ));
    steps.push((
        "read the identity as nobody",
        transport.identity_document(None).await,
    ));
    steps.push((
        "read the ring bindings",
        transport.ring_bindings(admin).await,
    ));
    steps
}

/// The vectors of the common envelope: the same script, once per transport, every step the same
/// outcome. Each transport has its own facade, since a mutation mints what cannot be shared.
#[tokio::test(flavor = "multi_thread")]
async fn both_transports_answer_the_same_vectors_and_replay_the_same_mutations() {
    let rest = Transport::Rest(
        host_api::http::routes(facade("vectors-rest"), Disclosure::Minimal)
            .layer(ActorLayer::new(Arc::new(Bearers))),
    );
    let mut grpc = tonic::service::RoutesBuilder::default();
    let served = host_api::grpc::Served::new(facade("vectors-grpc"), Disclosure::Minimal);
    // The server halves are the server crate's own; the client halves below are the
    // conformance crate's, generated from the same proto, as any caller's would be.
    use permguard_server::host_api::v1 as served_v1;
    grpc.add_service(
        served_v1::identity_service_server::IdentityServiceServer::with_interceptor(
            served.clone(),
            bearer_interceptor,
        ),
    );
    grpc.add_service(
        served_v1::grant_service_server::GrantServiceServer::with_interceptor(
            served.clone(),
            bearer_interceptor,
        ),
    );
    grpc.add_service(
        served_v1::key_service_server::KeyServiceServer::with_interceptor(
            served.clone(),
            bearer_interceptor,
        ),
    );
    grpc.add_service(
        served_v1::operations_service_server::OperationsServiceServer::with_interceptor(
            served,
            bearer_interceptor,
        ),
    );
    let served = serve(axum::Router::new(), grpc.routes());
    let grpc = Transport::Grpc(served.grpc);

    let over_rest = script(&rest).await;
    let over_grpc = script(&grpc).await;
    assert_eq!(over_rest.len(), over_grpc.len());
    for ((case, rest), (_, grpc)) in over_rest.into_iter().zip(over_grpc) {
        assert_parity(case, rest.masked(MINTED), grpc.masked(MINTED));
    }
}

/// The schema of `host.json` each answered step of the script conforms to.
fn schema_of(case: &str) -> &'static str {
    match case {
        "list the grants" | "list the grants after" => "GrantList",
        "create a grant" | "create a grant with an expiry and a constraint" => "GrantCreated",
        "plan a revocation" => "GrantRevokePlan",
        "run the revocation" => "GrantRevoked",
        "list the key rings" | "list the key rings as nobody" => "KeyRings",
        "read the operations ring" => "KeyRing",
        "read the status" => "HostStatus",
        "read the effective configuration" => "EffectiveConfig",
        other => panic!("`{other}` answered and names no schema"),
    }
}

/// Every REST answer of the script is an instance of its schema in `host.json`, and every REST
/// refusal is a `HostWireError` or a `WireDenial`: the document describes the wire, not a wish.
#[tokio::test]
async fn every_rest_answer_conforms_to_the_host_api_document() {
    use permguard_conformance::schema::Document;

    let rest = Transport::Rest(
        host_api::http::routes(facade("schemas"), Disclosure::Minimal)
            .layer(ActorLayer::new(Arc::new(Bearers))),
    );
    let document = Document::load("host.json");
    let common = Document::load("common.json");
    let mut answered = 0;
    for (case, outcome) in script(&rest).await {
        if let Outcome::Answered(value) = &outcome {
            document.check_json(schema_of(case), value);
            answered += 1;
        }
    }
    assert!(answered >= 9, "{answered} answers were checked");

    // The refusal bodies, read raw: a conflict with its revision, a denial.
    let Transport::Rest(router) = &rest else {
        unreachable!()
    };
    let raw = |method: &'static str,
               path: &'static str,
               who: Option<&'static str>,
               body: Option<Value>| {
        let router = router.clone();
        async move {
            let mut request = Request::builder().method(method).uri(path);
            if let Some(who) = who {
                request = request.header("authorization", format!("Bearer {who}"));
            }
            if body.is_some() {
                request = request.header("content-type", "application/json");
            }
            let response = router
                .oneshot(
                    request
                        .body(axum::body::Body::from(
                            body.map(|body| body.to_string()).unwrap_or_default(),
                        ))
                        .expect("a request"),
                )
                .await
                .expect("answered");
            let bytes = response
                .into_body()
                .collect()
                .await
                .expect("reads")
                .to_bytes();
            serde_json::from_slice::<Value>(&bytes).expect("a JSON body")
        }
    };
    let conflict = raw(
        "POST",
        "/host/v1/grants",
        Some(ADMIN),
        Some(json!({
            "request_id": "schema-conflict",
            "expected_revision": 77,
            "principal": "spiffe://acme/alice",
            "operations": [operations::CATALOG_READ],
            "selector": "plane/control/*",
        })),
    )
    .await;
    assert!(conflict.get("revision").is_some(), "{conflict}");
    document.check_json("HostWireError", &conflict);
    let refused = raw("GET", "/host/v1/config/revisions", Some(ADMIN), None).await;
    document.check_json("HostWireError", &refused);
    let denied = raw("GET", "/host/v1/status", None, None).await;
    common.check_json("WireDenial", &denied);
    // And the bodies the routes accept are instances of their request schemas.
    document.check_json(
        "CreateGrantBody",
        &json!({
            "request_id": "r",
            "expected_revision": null,
            "principal": "spiffe://acme/alice",
            "operations": [operations::CATALOG_READ],
            "selector": "plane/control/*",
            "expires_at": null,
        }),
    );
    document.check_json(
        "PlanRevokeBody",
        &json!({ "request_id": "r", "expected_revision": null }),
    );
    document.check_json(
        "RunRevokeBody",
        &json!({ "request_id": "r", "plan_id": "p", "plan_digest": "d" }),
    );
}

/// The refusals the script expects, by step: a vector whose class or code drifts fails here,
/// before parity could pass with two identical mistakes.
#[tokio::test]
async fn the_rest_vectors_refuse_with_the_contract_codes() {
    let rest = Transport::Rest(
        host_api::http::routes(facade("codes"), Disclosure::Minimal)
            .layer(ActorLayer::new(Arc::new(Bearers))),
    );
    let steps = script(&rest).await;
    let refused = |case: &str| -> (String, String) {
        match steps.iter().find(|(name, _)| *name == case) {
            Some((_, Outcome::Refused { class, code })) => (class.clone(), code.clone()),
            other => panic!("`{case}` was not refused: {other:?}"),
        }
    };
    use permguard_core::codes::{common, host};
    assert_eq!(
        refused("list the grants as nobody"),
        (String::new(), common::UNAUTHENTICATED.to_owned())
    );
    assert_eq!(
        refused("list the grants as a stranger"),
        (String::new(), common::FORBIDDEN.to_owned())
    );
    assert_eq!(
        refused("reuse the request id for another grant"),
        ("conflict".to_owned(), host::REQUEST_ID_REUSED.to_owned())
    );
    assert_eq!(
        refused("create with an unregistered operation"),
        ("validation".to_owned(), common::INVALID_ARGUMENT.to_owned())
    );
    assert_eq!(
        refused("create without a request id"),
        (
            "validation".to_owned(),
            host::REQUEST_ID_REQUIRED.to_owned()
        )
    );
    assert_eq!(
        refused("create against a stale revision"),
        ("conflict".to_owned(), host::REVISION_MISMATCH.to_owned())
    );
    assert_eq!(
        refused("run with a wrong digest"),
        (
            "validation".to_owned(),
            host::PLAN_DIGEST_MISMATCH.to_owned()
        )
    );
    assert_eq!(
        refused("run with an unknown plan"),
        ("not_found".to_owned(), host::PLAN_UNKNOWN.to_owned())
    );
    assert_eq!(
        refused("run the consumed plan again"),
        ("conflict".to_owned(), host::PLAN_EXPIRED.to_owned())
    );
    assert_eq!(
        refused("plan against the revoked grant"),
        ("conflict".to_owned(), host::GRANT_TERMINAL.to_owned())
    );
    assert_eq!(
        refused("plan against an unknown grant"),
        ("not_found".to_owned(), host::GRANT_UNKNOWN.to_owned())
    );
    assert_eq!(
        refused("plan against a malformed id"),
        ("validation".to_owned(), common::INVALID_ARGUMENT.to_owned())
    );
    assert_eq!(
        refused("read an unknown ring"),
        ("not_found".to_owned(), host::RING_UNKNOWN.to_owned())
    );
    assert_eq!(
        refused("read the configuration revisions"),
        ("unavailable".to_owned(), host::NOT_SERVED_YET.to_owned())
    );
    assert_eq!(
        refused("read the identity"),
        ("unavailable".to_owned(), host::NOT_SERVED_YET.to_owned())
    );
    assert_eq!(
        refused("read the identity as nobody"),
        (String::new(), common::UNAUTHENTICATED.to_owned())
    );
    assert_eq!(
        refused("read the ring bindings"),
        ("unavailable".to_owned(), host::NOT_SERVED_YET.to_owned())
    );
    assert_eq!(
        refused("create a grant with an expiry in the past"),
        ("validation".to_owned(), common::INVALID_ARGUMENT.to_owned())
    );
    // `keys.read` is public on this facade, as a deployment may declare it: nobody lists.
    assert!(matches!(
        steps
            .iter()
            .find(|(name, _)| *name == "list the key rings as nobody"),
        Some((_, Outcome::Answered(_)))
    ));
}

/// The REST binding's own shapes: a stale revision carries the current one, a closed body
/// refuses a stranger member, and the ring carries its cache policy as a header.
#[tokio::test]
async fn the_rest_binding_carries_the_revision_the_cache_policy_and_refuses_an_open_body() {
    let router = host_api::http::routes(facade("rest-shapes"), Disclosure::Minimal)
        .layer(ActorLayer::new(Arc::new(Bearers)));
    let send =
        |method: &'static str, path: String, body: Option<Value>, who: Option<&'static str>| {
            let router = router.clone();
            async move {
                let mut request = Request::builder().method(method).uri(path);
                if let Some(who) = who {
                    request = request.header("authorization", format!("Bearer {who}"));
                }
                if body.is_some() {
                    request = request.header("content-type", "application/json");
                }
                let response = router
                    .oneshot(
                        request
                            .body(axum::body::Body::from(
                                body.map(|body| body.to_string()).unwrap_or_default(),
                            ))
                            .expect("a request"),
                    )
                    .await
                    .expect("answered");
                let status = response.status();
                let headers = response.headers().clone();
                let bytes = response
                    .into_body()
                    .collect()
                    .await
                    .expect("reads")
                    .to_bytes();
                let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
                (status, headers, value)
            }
        };
    let (status, _, body) = send(
        "POST",
        "/host/v1/grants".to_owned(),
        Some(json!({
            "request_id": "s1",
            "expected_revision": 77,
            "principal": "spiffe://acme/alice",
            "operations": [operations::CATALOG_READ],
            "selector": "plane/control/*",
        })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["code"], permguard_core::codes::host::REVISION_MISMATCH);
    assert_eq!(
        body["revision"],
        json!(1),
        "the current revision travels beside the conflict"
    );

    let (status, _, body) = send(
        "POST",
        "/host/v1/grants".to_owned(),
        Some(json!({
            "request_id": "s2",
            "principal": "spiffe://acme/alice",
            "operations": [operations::CATALOG_READ],
            "selector": "plane/control/*",
            "surprise": true,
        })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(
        body["code"],
        permguard_core::codes::common::INVALID_ARGUMENT
    );

    let (status, _, body) = send(
        "POST",
        "/host/v1/grants".to_owned(),
        Some(json!({
            "principal": "spiffe://acme/alice",
            "operations": [operations::CATALOG_READ],
            "selector": "plane/control/*",
        })),
        Some(ADMIN),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a body without a request id: {body}"
    );
    assert_eq!(
        body["code"],
        permguard_core::codes::host::REQUEST_ID_REQUIRED,
        "the facade decides, as on gRPC"
    );

    let (status, headers, body) = send(
        "GET",
        format!("/host/v1/keys/{}", HOST_OPERATIONS.as_str()),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers
            .get("cache-control")
            .and_then(|value| value.to_str().ok()),
        Some("max-age=300")
    );
    assert_eq!(body["keys"][0]["kid"], "k1");
    assert!(body["epoch"].is_null() && body["binding"].is_null());

    let (status, headers, body) = send("GET", "/host/v1/status".to_owned(), None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert!(headers.contains_key("www-authenticate"));

    let (status, _, body) = send("GET", "/host/v1/nothing".to_owned(), None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

/// A configuration for the listener over the material the provisioner generates.
fn listener_config(root: &std::path::Path, address: &str, tls: bool) -> Config {
    let mut settings = vec![
        (SETTING_WORKING_DIR, root.to_string_lossy().into_owned()),
        (SETTING_ADMIN_ADDR, address.to_owned()),
        (SETTING_AUTOGENERATE, "true".to_owned()),
        (SETTING_DEVELOPMENT_MODE, "true".to_owned()),
    ];
    if tls {
        settings.push((SETTING_ADMIN_TLS_CERT, "tls/server.pem".to_owned()));
        settings.push((SETTING_ADMIN_TLS_KEY, "tls/server.key".to_owned()));
    }
    Config::from_layers(
        BuildSettings::new("9.9.9", "2026", "Test Holder"),
        Vec::<String>::new(),
        Layers::new().with_file(
            settings
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect::<Vec<_>>(),
        ),
    )
    .expect("the config builds")
}

/// Speaks one HTTP/1.1 request over TLS to `address`, trusting `authority`.
async fn speak_tls(
    address: std::net::SocketAddr,
    authority: &std::path::Path,
    request: &str,
) -> String {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let mut roots = rustls::RootCertStore::empty();
    for certificate in
        permguard_transport::load_certificates(authority).expect("the authority reads")
    {
        roots.add(certificate).expect("the root is added");
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("the listener answers");
    let name = rustls::pki_types::ServerName::try_from("localhost").expect("a server name");
    let mut stream = connector
        .connect(name, stream)
        .await
        .expect("the handshake completes");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("the request is written");
    let mut said = Vec::new();
    stream
        .read_to_end(&mut said)
        .await
        .expect("the answer reads");
    String::from_utf8_lossy(&said).into_owned()
}

#[tokio::test(flavor = "multi_thread")]
async fn the_listener_binds_admin_addr_over_tls_and_serves_the_public_ring() {
    let root = scratch("listener");
    let config = listener_config(&root, "127.0.0.1:0", true);
    permguard_std::provision::prepare(&config).expect("the material is generated");
    config
        .validate()
        .expect("a loopback development listener over plain TLS validates");
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let api = facade("listener-facade");
    let context = ServerContext::new(
        ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>"),
        &config,
        &storage,
        &audit,
    )
    .with_host_handles(api);

    let service = HostApiService::new();
    service.start(&context).await.expect("the listener starts");
    let address = {
        // The bound address is only known through the surface the service holds; the log says it
        // too, but a test reads the socket. Ephemeral ports are read back by connecting to the
        // address the OS chose, which the service does not expose: the test asks the volume for
        // nothing and the service for its surface instead.
        service.bound().expect("the listener is bound")
    };
    let authority = root.join("tls").join("ca.pem");
    let answered = speak_tls(
        address,
        &authority,
        &format!(
            "GET /host/v1/keys/{} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
            HOST_OPERATIONS.as_str()
        ),
    )
    .await;
    assert!(answered.starts_with("HTTP/1.1 200"), "{answered}");
    assert!(
        answered.contains("\"ring\":\"host.operations\""),
        "{answered}"
    );

    let refused = speak_tls(
        address,
        &authority,
        "GET /host/v1/status HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    )
    .await;
    assert!(refused.starts_with("HTTP/1.1 401"), "{refused}");

    service.stop(&context).await.expect("the listener stops");
    service
        .stop(&context)
        .await
        .expect("stopping again is harmless");
}

#[tokio::test]
async fn the_listener_is_a_no_op_without_an_address_and_refuses_to_start_without_tls_or_facade() {
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let identity = ProductIdentity::new("demo-x", "Demo X", "A tagline", "Demo X CLI", "<art>");

    let idle = Config::default();
    let context = ServerContext::new(identity, &idle, &storage, &audit);
    HostApiService::new()
        .start(&context)
        .await
        .expect("no address, nothing to bind");

    let root = scratch("listener-no-facade");
    let configured = listener_config(&root, "127.0.0.1:0", true);
    permguard_std::provision::prepare(&configured).expect("the material is generated");
    let context = ServerContext::new(identity, &configured, &storage, &audit);
    let refused = HostApiService::new()
        .start(&context)
        .await
        .expect_err("an address and no facade is a composition error");
    assert!(
        format!("{refused:#}").contains("no Host API"),
        "{refused:#}"
    );

    let root = scratch("listener-no-tls");
    let clear = listener_config(&root, "127.0.0.1:0", false);
    let context = ServerContext::new(identity, &clear, &storage, &audit)
        .with_host_handles(facade("listener-no-tls-facade"));
    let refused = HostApiService::new()
        .start(&context)
        .await
        .expect_err("never in the clear");
    assert!(format!("{refused:#}").contains("TLS"), "{refused:#}");

    // Plain TLS off loopback: validation refuses it, and so does the listener where it binds,
    // for a composition that skipped validation.
    let root = scratch("listener-plain-off-loopback");
    let exposed = listener_config(&root, "0.0.0.0:0", true);
    permguard_std::provision::prepare(&exposed).expect("the material is generated");
    let context = ServerContext::new(identity, &exposed, &storage, &audit)
        .with_host_handles(facade("listener-plain-off-loopback-facade"));
    let refused = HostApiService::new()
        .start(&context)
        .await
        .expect_err("plain TLS is for loopback development only");
    assert!(format!("{refused:#}").contains("client_ca"), "{refused:#}");
}
