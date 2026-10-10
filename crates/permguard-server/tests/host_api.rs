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
    // A revision names the grant it is about and the second it happened.
    "target",
    "at",
    // The identity each facade provisioned for itself, and its bytes per transport.
    "document",
    "successions",
    "succession",
    "first_public_key",
    // The ring keys each facade generated, and what names and binds them (WP-3.1).
    "kid",
    "x",
    "digest",
    "binding",
    // The verification bundle each facade built of its own keys (WP-3.4).
    "frontier",
    "manifest",
    "bundle_digest",
    "items",
    // The invitations each facade issued (WP-4.1).
    "invite_id",
    "token",
    "created_at",
    // The identity each facade's reset retired and provisioned (WP-4.1).
    "old_host_id",
    "host_id",
    "fingerprint",
    "witness",
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
    let mutations = Arc::new(
        permguard_host::operations::mutation::Mutations::open_offline(&volume, "test")
            .expect("the mutation journal opens"),
    );
    let keys_path = permguard_host::identity::directories(&volume)
        .expect("the identity directory")
        .1
        .path()
        .to_path_buf();
    let provisioner: permguard_host::identity::reset::Provisioner = Arc::new(move |_| {
        Ok(Arc::new(permguard_host::keys::FileKeyProvider::new(
            permguard_host::storage::Dir::open(&keys_path)?,
        )) as Arc<dyn permguard_host::keys::KeyProvider>)
    });
    let identity = Arc::new(
        permguard_host::identity::Identity::provision(
            &volume,
            Arc::new(permguard_host::keys::FileKeyProvider::new(
                permguard_host::identity::directories(&volume)
                    .expect("the identity directory")
                    .1,
            )),
            permguard_host::identity::Suite::Ed25519Sha256V1,
            permguard_host::authz::store::now(),
            permguard_host::authz::store::now() * 1000,
        )
        .expect("the identity is provisioned")
        .with_provisioner(provisioner),
    );
    permguard_host::operations::grants::issue(
        &mutations,
        &store,
        permguard_host::operations::journal::Initiator::System("test".to_owned()),
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
    // The operations ring, on the volume and bound by the identity (WP-3.1).
    let ring = Arc::new(
        permguard_host::keys::ring::Ring::open(
            &volume,
            HOST_OPERATIONS.as_str(),
            permguard_host::identity::Suite::Ed25519Sha256V1,
            permguard_host::keys::ring::Policy {
                publish_ahead: std::time::Duration::from_secs(600),
                rotate_every: std::time::Duration::from_secs(3600),
                retain: std::time::Duration::from_secs(7200),
            },
            Arc::new(permguard_host::time::TimeGuard::system(
                std::time::Duration::from_secs(30),
            )),
        )
        .expect("the ring opens")
        .with_binder(identity.clone()),
    );
    permguard_core::KeyManager::maintain(ring.as_ref()).expect("the ring is maintained");
    let keys = Arc::new(permguard_host::keys::registry::Registry::new(
        Some(Arc::clone(&identity)),
        vec![ring],
    ));
    let members = permguard_host::membership::Store::open(&volume).expect("the memberships open");
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
        keys,
        health: Health::new(),
        assurance: Assurance::of(
            &permguard_core::assurance::Assurance::new(
                AssuranceProfile::Development,
                [permguard_core::assurance::Control::Tls13Only],
            )
            .report(&[permguard_core::assurance::Relaxation::CustodyPlaintext]),
        ),
        effective: Effective {
            revision: 0,
            settings: Vec::new(),
        },
        trail: "recording".to_owned(),
        mutations: Some(mutations),
        identity: Some(identity),
        time: Arc::new(permguard_host::time::TimeGuard::system(
            std::time::Duration::from_secs(30),
        )),
        peer_sessions: permguard_host::api::sessions::PeerSessions::none(),
        memberships: Some(Arc::new(permguard_host::api::members::MembershipService {
            store: members,
            capabilities: permguard_host::membership::Capabilities::default(),
            connector: None,
            appraisal: permguard_host::membership::appraisal::Appraisal::default(),
            live: Arc::default(),
        })),
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

    async fn memberships(
        &self,
    ) -> host_v1::membership_service_client::MembershipServiceClient<tonic::transport::Channel>
    {
        host_v1::membership_service_client::MembershipServiceClient::connect(format!(
            "http://{}",
            self.grpc_url()
        ))
        .await
        .expect("the gRPC endpoint answers")
    }

    fn task() -> (Value, host_v1::MembershipTask) {
        let limits = host_v1::TaskLimits {
            max_body_bytes: 1 << 20,
            max_concurrency: 4,
            max_rate_per_minute: 600,
            max_batch_records: 1000,
            retention_seconds: 86_400,
        };
        (
            json!({
                "task_id": "decisions",
                "type": "decisions.ship",
                "selector": "plane/data/*",
                "resource_types": ["decision"],
                "required": true,
                "limits": {
                    "max_body_bytes": limits.max_body_bytes,
                    "max_concurrency": limits.max_concurrency,
                    "max_rate_per_minute": limits.max_rate_per_minute,
                    "max_batch_records": limits.max_batch_records,
                    "retention_seconds": limits.retention_seconds,
                },
            }),
            host_v1::MembershipTask {
                task_id: "decisions".to_owned(),
                r#type: "decisions.ship".to_owned(),
                selector: "plane/data/*".to_owned(),
                resource_types: vec!["decision".to_owned()],
                required: true,
                limits: Some(limits),
                ..Default::default()
            },
        )
    }

    async fn create_invite(&self, who: Option<&str>, request_id: &str) -> Outcome {
        let (rest, grpc) = Self::task();
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    "/host/v1/members/invites",
                    who,
                    Some(json!({
                        "request_id": request_id,
                        "selector": "plane/data/*",
                        "tasks": [rest],
                        "min_assurance": "production",
                    })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .create_invite(Self::grpc_request(
                        who,
                        host_v1::CreateInviteRequest {
                            request_id: request_id.to_owned(),
                            selector: "plane/data/*".to_owned(),
                            tasks: vec![grpc],
                            min_assurance: Some("production".to_owned()),
                            ..Default::default()
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn list_invites(&self, who: Option<&str>) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest("GET", "/host/v1/members/invites", who, None)
                    .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .list_invites(Self::grpc_request(
                        who,
                        host_v1::ListInvitesRequest::default(),
                    ))
                    .await,
            ),
        }
    }

    async fn delete_invite(&self, who: Option<&str>, id: &str, request_id: &str) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "DELETE",
                    &format!("/host/v1/members/invites/{id}?request_id={request_id}"),
                    who,
                    None,
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .delete_invite(Self::grpc_request(
                        who,
                        host_v1::DeleteInviteRequest {
                            invite_id: id.to_owned(),
                            request_id: request_id.to_owned(),
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn list_members(&self, who: Option<&str>, status: Option<&str>) -> Outcome {
        match self {
            Self::Rest(_) => {
                let path = status.map_or_else(
                    || "/host/v1/members".to_owned(),
                    |status| format!("/host/v1/members?status={status}"),
                );
                self.rest("GET", &path, who, None).await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .list_members(Self::grpc_request(
                        who,
                        host_v1::ListMembersRequest {
                            status: status.unwrap_or_default().to_owned(),
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn get_member(&self, who: Option<&str>, id: &str) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest("GET", &format!("/host/v1/members/{id}"), who, None)
                    .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .get_member(Self::grpc_request(
                        who,
                        host_v1::GetMemberRequest {
                            membership_id: id.to_owned(),
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn suspend_member(&self, who: Option<&str>, id: &str, request_id: &str) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    &format!("/host/v1/members/{id}/suspend"),
                    who,
                    Some(json!({ "request_id": request_id, "expected_revision": 1 })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .suspend_member(Self::grpc_request(
                        who,
                        host_v1::SuspendMemberRequest {
                            membership_id: id.to_owned(),
                            request_id: request_id.to_owned(),
                            expected_revision: 1,
                            reason: None,
                        },
                    ))
                    .await,
            ),
        }
    }

    /// The open task sessions of a membership (WP-4.3).
    async fn member_sessions(&self, who: Option<&str>, id: &str) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest("GET", &format!("/host/v1/members/{id}/sessions"), who, None)
                    .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .list_member_sessions(Self::grpc_request(
                        who,
                        host_v1::ListMemberSessionsRequest {
                            membership_id: id.to_owned(),
                        },
                    ))
                    .await,
            ),
        }
    }

    /// An approval bringing one operator approval and one piece of evidence (WP-4.2): the two
    /// transports decode the offer alike, base64url on REST and raw bytes on gRPC.
    async fn approve_member_assured(
        &self,
        who: Option<&str>,
        id: &str,
        request_id: &str,
    ) -> Outcome {
        use base64::Engine as _;
        let control = permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL;
        let evidence = vec![0xEE_u8; 40];
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    &format!("/host/v1/members/{id}/approve"),
                    who,
                    Some(json!({
                        "request_id": request_id,
                        "expected_revision": 1,
                        "assurance": {
                            "approvals": [{
                                "control": control,
                                "reason": "dual control witnessed",
                                "expires_at": "2099-01-01T00:00:00Z",
                            }],
                            "evidence": [{
                                "verifier": "tpm-quote",
                                "evidence": base64::engine::general_purpose::URL_SAFE_NO_PAD
                                    .encode(&evidence),
                            }],
                        },
                    })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .approve_member(Self::grpc_request(
                        who,
                        host_v1::ApproveMemberRequest {
                            membership_id: id.to_owned(),
                            request_id: request_id.to_owned(),
                            expected_revision: 1,
                            narrow: None,
                            lease_policy: None,
                            assurance: Some(host_v1::AssuranceOffer {
                                approvals: vec![host_v1::OperatorApproval {
                                    control: control.to_owned(),
                                    reason: "dual control witnessed".to_owned(),
                                    expires_at: "2099-01-01T00:00:00Z".to_owned(),
                                }],
                                evidence: vec![host_v1::AttestationEvidence {
                                    verifier: "tpm-quote".to_owned(),
                                    evidence,
                                }],
                            }),
                        },
                    ))
                    .await,
            ),
        }
    }

    /// An appraisal renewing a binding with one operator approval of `control` (WP-4.2).
    async fn appraise_member(
        &self,
        who: Option<&str>,
        id: &str,
        request_id: &str,
        control: &str,
    ) -> Outcome {
        let expires_at = "2099-01-01T00:00:00Z";
        let reason = "dual control witnessed";
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    &format!("/host/v1/members/{id}/appraise"),
                    who,
                    Some(json!({
                        "request_id": request_id,
                        "expected_revision": 1,
                        "approvals": [{
                            "control": control,
                            "reason": reason,
                            "expires_at": expires_at,
                        }],
                    })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .appraise_member(Self::grpc_request(
                        who,
                        host_v1::AppraiseMemberRequest {
                            membership_id: id.to_owned(),
                            request_id: request_id.to_owned(),
                            expected_revision: 1,
                            approvals: vec![host_v1::OperatorApproval {
                                control: control.to_owned(),
                                reason: reason.to_owned(),
                                expires_at: expires_at.to_owned(),
                            }],
                            evidence: Vec::new(),
                            revoke: None,
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn join_membership(&self, who: Option<&str>, request_id: &str) -> Outcome {
        let (rest, grpc) = Self::task();
        let host_id = "0190a5c3-0000-7000-8000-000000000033";
        let invite_id = "0190a5c3-0000-7000-8000-000000000044";
        let fingerprint = format!("sha256:{}", "ab".repeat(32));
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    "/host/v1/memberships/join",
                    who,
                    Some(json!({
                        "request_id": request_id,
                        "coordinator": {
                            "address": "https://coordinator:7443",
                            "host_id": host_id,
                            "fingerprint": fingerprint,
                        },
                        "invite_id": invite_id,
                        "token": "B".repeat(43),
                        "requested": { "selector": "plane/data/*", "tasks": [rest] },
                    })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.memberships()
                    .await
                    .join_membership(Self::grpc_request(
                        who,
                        host_v1::JoinMembershipRequest {
                            request_id: request_id.to_owned(),
                            coordinator: Some(host_v1::MembershipCoordinator {
                                address: "https://coordinator:7443".to_owned(),
                                host_id: host_id.to_owned(),
                                fingerprint,
                            }),
                            invite_id: invite_id.to_owned(),
                            token: vec![0x04; 32],
                            requested: Some(host_v1::MembershipScope {
                                selector: "plane/data/*".to_owned(),
                                tasks: vec![grpc],
                            }),
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn plan_identity_reset(&self, who: Option<&str>, request_id: &str) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    "/host/v1/identity/reset/plan",
                    who,
                    Some(json!({
                        "request_id": request_id,
                        "mode": "emergency",
                        "reason": "a drill",
                    })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.identity()
                    .await
                    .plan_identity_reset(Self::grpc_request(
                        who,
                        host_v1::PlanIdentityResetRequest {
                            request_id: request_id.to_owned(),
                            mode: "emergency".to_owned(),
                            reason: "a drill".to_owned(),
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn run_identity_reset(
        &self,
        who: Option<&str>,
        request_id: &str,
        plan_id: &str,
        plan_digest: &str,
    ) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    "/host/v1/identity/reset/run",
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
                self.identity()
                    .await
                    .run_identity_reset(Self::grpc_request(
                        who,
                        host_v1::RunIdentityResetRequest {
                            request_id: request_id.to_owned(),
                            plan_id: plan_id.to_owned(),
                            plan_digest: plan_digest.to_owned(),
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

    async fn key_bundle(
        &self,
        who: Option<&str>,
        resource: &str,
        frontier: Option<&str>,
        cursor: Option<&str>,
    ) -> Outcome {
        match self {
            Self::Rest(_) => {
                let mut path = format!("/host/v1/keys/bundle?resource={resource}&limit=2");
                if let Some(frontier) = frontier {
                    path.push_str(&format!("&frontier={frontier}"));
                }
                if let Some(cursor) = cursor {
                    path.push_str(&format!("&cursor={cursor}"));
                }
                self.rest("GET", &path, who, None).await
            }
            Self::Grpc(_) => reduced_grpc(
                self.keys()
                    .await
                    .get_key_bundle(Self::grpc_request(
                        who,
                        host_v1::GetKeyBundleRequest {
                            resource: resource.to_owned(),
                            frontier: frontier.unwrap_or_default().to_owned(),
                            cursor: cursor.unwrap_or_default().to_owned(),
                            limit: Some(2),
                        },
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

    async fn rotate_ring(
        &self,
        who: Option<&str>,
        ring: &str,
        request_id: &str,
        expected_epoch: u64,
    ) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    &format!("/host/v1/keys/{ring}/rotate"),
                    who,
                    Some(json!({ "request_id": request_id, "expected_epoch": expected_epoch })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.keys()
                    .await
                    .rotate_key_ring(Self::grpc_request(
                        who,
                        host_v1::RotateKeyRingRequest {
                            ring: ring.to_owned(),
                            request_id: request_id.to_owned(),
                            expected_epoch,
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn plan_key_revoke(
        &self,
        who: Option<&str>,
        ring: &str,
        request_id: &str,
        kid: &str,
    ) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    &format!("/host/v1/keys/{ring}/revoke/plan"),
                    who,
                    Some(json!({
                        "request_id": request_id,
                        "kid": kid,
                        "reason": "key-compromise",
                    })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.keys()
                    .await
                    .plan_key_revoke(Self::grpc_request(
                        who,
                        host_v1::PlanKeyRevokeRequest {
                            ring: ring.to_owned(),
                            request_id: request_id.to_owned(),
                            kid: kid.to_owned(),
                            reason: "key-compromise".to_owned(),
                            compromised_at: None,
                            expected_epoch: None,
                        },
                    ))
                    .await,
            ),
        }
    }

    async fn run_key_revoke(
        &self,
        who: Option<&str>,
        ring: &str,
        request_id: &str,
        plan_id: &str,
        plan_digest: &str,
    ) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    &format!("/host/v1/keys/{ring}/revoke/run"),
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
                self.keys()
                    .await
                    .run_key_revoke(Self::grpc_request(
                        who,
                        host_v1::RunKeyRevokeRequest {
                            ring: ring.to_owned(),
                            request_id: request_id.to_owned(),
                            plan_id: plan_id.to_owned(),
                            plan_digest: plan_digest.to_owned(),
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

    async fn rotate_identity(
        &self,
        who: Option<&str>,
        request_id: &str,
        expected_epoch: u64,
    ) -> Outcome {
        match self {
            Self::Rest(_) => {
                self.rest(
                    "POST",
                    "/host/v1/identity/rotate",
                    who,
                    Some(json!({ "request_id": request_id, "expected_epoch": expected_epoch })),
                )
                .await
            }
            Self::Grpc(_) => reduced_grpc(
                self.identity()
                    .await
                    .rotate_identity(Self::grpc_request(
                        who,
                        host_v1::RotateIdentityRequest {
                            request_id: request_id.to_owned(),
                            expected_epoch,
                        },
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
    let page = transport.key_bundle(admin, "host", None, None).await;
    let Outcome::Answered(first) = &page else {
        panic!("the bundle reads: {page:?}")
    };
    // The manifest is the frontier a later page names, base64url: REST answers it so, gRPC as
    // bytes.
    let frontier = match &first["manifest"] {
        Value::String(text) => text.clone(),
        Value::Array(bytes) => {
            use base64::Engine as _;
            let bytes: Vec<u8> = bytes
                .iter()
                .map(|byte| {
                    byte.as_u64()
                        .and_then(|byte| u8::try_from(byte).ok())
                        .expect("a byte")
                })
                .collect();
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        }
        other => panic!("a manifest: {other}"),
    };
    steps.push(("read the verification bundle", page.clone()));
    steps.push((
        "read the next page of the bundle",
        transport
            .key_bundle(admin, "host", Some(&frontier), Some("2"))
            .await,
    ));
    steps.push((
        "read the bundle of a resource out of the grammar",
        transport.key_bundle(admin, "zone:x", None, None).await,
    ));
    steps.push((
        "read the bundle from a cursor without its frontier",
        transport.key_bundle(admin, "host", None, Some("2")).await,
    ));
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

    // The key ring mutations (WP-3.1), on the operations ring of each facade.
    let ring = HOST_OPERATIONS.as_str();
    let read = transport.ring(ring).await;
    let Outcome::Answered(view) = &read else {
        panic!("the ring reads: {read:?}")
    };
    let first = view["keys"][0]["kid"].as_str().expect("a kid").to_owned();
    steps.push((
        "rotate a ring as a stranger",
        transport.rotate_ring(Some(STRANGER), ring, "k0", 1).await,
    ));
    steps.push((
        "rotate the identity ring",
        transport.rotate_ring(admin, "host.identity", "k0", 1).await,
    ));
    steps.push((
        "rotate the operations ring",
        transport.rotate_ring(admin, ring, "k1", 1).await,
    ));
    steps.push((
        "rotate the operations ring again",
        transport.rotate_ring(admin, ring, "k1", 1).await,
    ));
    steps.push((
        "rotate while a successor waits",
        transport.rotate_ring(admin, ring, "k2", 2).await,
    ));
    let planned = transport.plan_key_revoke(admin, ring, "kp1", &first).await;
    let plan_id = member(&planned, &["plan_id"]).to_owned();
    let plan_digest = member(&planned, &["plan_digest"]).to_owned();
    steps.push(("plan a key revocation", planned));
    steps.push((
        "run the key revocation",
        transport
            .run_key_revoke(admin, ring, "kr1", &plan_id, &plan_digest)
            .await,
    ));
    steps.push((
        "plan the revocation of a revoked key",
        transport.plan_key_revoke(admin, ring, "kp2", &first).await,
    ));

    // The memberships (WP-4.1): what a Host answers before any peer enrolled.
    steps.push((
        "list the memberships",
        transport.list_members(admin, None).await,
    ));
    steps.push((
        "list the memberships of an unknown status",
        transport.list_members(admin, Some("gone")).await,
    ));
    steps.push((
        "list the invitations as a stranger",
        transport.list_invites(Some(STRANGER)).await,
    ));
    let invited = transport.create_invite(admin, "i1").await;
    steps.push(("invite a Host", invited.clone()));
    steps.push((
        "invite again under the same request id",
        transport.create_invite(admin, "i1").await,
    ));
    steps.push(("list the invitations", transport.list_invites(admin).await));
    let invite_id = member(&invited, &["invite_id"]).to_owned();
    let deleted = transport.delete_invite(admin, &invite_id, "d1").await;
    let retried = transport.delete_invite(admin, &invite_id, "d1").await;
    assert_eq!(
        retried, deleted,
        "a retried delete returns the stored receipt"
    );
    steps.push(("delete the invitation", deleted));
    steps.push((
        "delete an unknown invitation",
        transport
            .delete_invite(admin, "0190a5c3-0000-7000-8000-000000000011", "d2")
            .await,
    ));
    steps.push((
        "read an unknown membership",
        transport
            .get_member(admin, "0190a5c3-0000-7000-8000-000000000022")
            .await,
    ));
    steps.push((
        "read a malformed membership id",
        transport.get_member(admin, "not-an-id").await,
    ));
    steps.push((
        "suspend an unknown membership",
        transport
            .suspend_member(admin, "0190a5c3-0000-7000-8000-000000000022", "s1")
            .await,
    ));
    steps.push((
        "list the sessions of an unknown membership",
        transport
            .member_sessions(admin, "0190a5c3-0000-7000-8000-000000000022")
            .await,
    ));
    steps.push((
        "list sessions as a stranger",
        transport
            .member_sessions(Some(STRANGER), "0190a5c3-0000-7000-8000-000000000022")
            .await,
    ));
    steps.push((
        "approve an unknown membership bringing an approval and evidence",
        transport
            .approve_member_assured(admin, "0190a5c3-0000-7000-8000-000000000022", "ap1")
            .await,
    ));
    steps.push((
        "appraise an unknown membership",
        transport
            .appraise_member(
                admin,
                "0190a5c3-0000-7000-8000-000000000022",
                "a1",
                permguard_core::domains::assurance::OPERATIONS_DUAL_CONTROL,
            )
            .await,
    ));
    steps.push((
        "appraise with an approval of no control",
        transport
            .appraise_member(
                admin,
                "0190a5c3-0000-7000-8000-000000000022",
                "a2",
                "custody.magic",
            )
            .await,
    ));
    steps.push((
        "join without an outbound peer client",
        transport.join_membership(admin, "j1").await,
    ));

    // The identity rotation (WP-2.2, WP-2.10): refused to a stranger and on a stale epoch, then
    // the next epoch, a retry answering what the rotation answered.
    steps.push((
        "rotate the identity as a stranger",
        transport.rotate_identity(Some(STRANGER), "ri0", 1).await,
    ));
    steps.push((
        "rotate the identity from a stale epoch",
        transport.rotate_identity(admin, "ri1", 9).await,
    ));
    let rotated = transport.rotate_identity(admin, "ri2", 1).await;
    let retried = transport.rotate_identity(admin, "ri2", 1).await;
    assert_eq!(
        retried, rotated,
        "a retried rotation answers what it answered"
    );
    let Outcome::Answered(answer) = &rotated else {
        panic!("the rotation answers: {rotated:?}")
    };
    assert_eq!(answer["receipt"]["revision"], 2, "the next epoch: {answer}");
    steps.push(("rotate the identity", rotated));
    steps.push((
        "rotate the identity again from the epoch it left",
        transport.rotate_identity(admin, "ri3", 1).await,
    ));
    let after = transport.identity_document(admin).await;
    let Outcome::Answered(view) = &after else {
        panic!("the identity reads: {after:?}")
    };
    assert_eq!(
        view["successions"].as_array().map(Vec::len),
        Some(1),
        "the identity names its one succession: {view}"
    );
    steps.push(("read the identity after its rotation", after));

    // The identity reset (WP-4.1), last: it leaves the facade's identity retired.
    steps.push((
        "plan an identity reset as a stranger",
        transport.plan_identity_reset(Some(STRANGER), "ir0").await,
    ));
    let planned = transport.plan_identity_reset(admin, "ir1").await;
    let plan_id = member(&planned, &["plan_id"]).to_owned();
    let plan_digest = member(&planned, &["plan_digest"]).to_owned();
    steps.push(("plan an identity reset", planned));
    steps.push((
        "run an identity reset with a wrong digest",
        transport
            .run_identity_reset(admin, "rr0", &plan_id, &"00".repeat(32))
            .await,
    ));
    let reset = transport
        .run_identity_reset(admin, "rr1", &plan_id, &plan_digest)
        .await;
    let retried = transport
        .run_identity_reset(admin, "rr1", &plan_id, &plan_digest)
        .await;
    assert_eq!(retried, reset, "a retried reset answers what it answered");
    steps.push(("run the identity reset", reset));
    steps.push((
        "read the identity after its reset",
        transport.identity_document(admin).await,
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
        served_v1::membership_service_server::MembershipServiceServer::with_interceptor(
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
        "read the verification bundle" | "read the next page of the bundle" => "KeyBundlePage",
        "read the status" => "HostStatus",
        "read the effective configuration" => "EffectiveConfig",
        "read the configuration revisions" => "ConfigRevisions",
        "read the identity" | "read the identity after its rotation" => "HostIdentity",
        "rotate the identity" => "IdentityRotated",
        "read the ring bindings" => "RingBindings",
        "rotate the operations ring" | "rotate the operations ring again" => "RingRotated",
        "plan a key revocation" => "KeyRevokePlan",
        "run the key revocation" => "KeyRevoked",
        "list the memberships" => "Members",
        "invite a Host" => "InviteCreated",
        "list the invitations" => "Invites",
        "delete the invitation" => "InviteDeleted",
        "plan an identity reset" => "IdentityResetPlan",
        "run the identity reset" => "IdentityReset",
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

    // The refusal bodies, read raw: a conflict with its revision, a denial. On a facade of their
    // own, since the script ends by resetting the identity of its own.
    let router = host_api::http::routes(facade("schemas-raw"), Disclosure::Minimal)
        .layer(ActorLayer::new(Arc::new(Bearers)));
    let router = &router;
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
    // The identity's own ring: a view, never bound (WP-3.1).
    let identity_ring = raw("GET", "/host/v1/keys/host.identity", None, None).await;
    document.check_json("KeyRing", &identity_ring);
    assert!(identity_ring["binding"].is_null(), "{identity_ring}");
    // A rotation's body and answer (WP-2.2): the stale epoch is a conflict with the current one.
    let stale = raw(
        "POST",
        "/host/v1/identity/rotate",
        Some(ADMIN),
        Some(json!({ "request_id": "rot-0", "expected_epoch": 9 })),
    )
    .await;
    assert_eq!(stale["revision"], 1, "{stale}");
    document.check_json("HostWireError", &stale);
    let rotated = raw(
        "POST",
        "/host/v1/identity/rotate",
        Some(ADMIN),
        Some(json!({ "request_id": "rot-1", "expected_epoch": 1 })),
    )
    .await;
    document.check_json("IdentityRotated", &rotated);
    document.check_json(
        "RotateIdentityBody",
        &json!({ "request_id": "r", "expected_epoch": 1 }),
    );
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
    assert!(
        matches!(
            steps
                .iter()
                .find(|(name, _)| *name == "read the configuration revisions"),
            Some((_, Outcome::Answered(_)))
        ),
        "the revisions are served (WP-2.9)"
    );
    assert!(
        matches!(
            steps.iter().find(|(name, _)| *name == "read the identity"),
            Some((_, Outcome::Answered(_)))
        ),
        "the identity is served (WP-2.2)"
    );
    assert_eq!(
        refused("read the identity as nobody"),
        (String::new(), common::UNAUTHENTICATED.to_owned())
    );
    assert!(
        matches!(
            steps
                .iter()
                .find(|(name, _)| *name == "read the ring bindings"),
            Some((_, Outcome::Answered(_)))
        ),
        "the ring bindings are served (WP-3.1)"
    );
    assert_eq!(
        refused("rotate a ring as a stranger"),
        (String::new(), common::FORBIDDEN.to_owned())
    );
    assert_eq!(
        refused("rotate the identity as a stranger"),
        (String::new(), common::FORBIDDEN.to_owned())
    );
    assert_eq!(
        refused("rotate the identity from a stale epoch"),
        ("conflict".to_owned(), host::REVISION_MISMATCH.to_owned())
    );
    assert_eq!(
        refused("rotate the identity again from the epoch it left"),
        ("conflict".to_owned(), host::REVISION_MISMATCH.to_owned())
    );
    assert_eq!(
        refused("rotate the identity ring"),
        ("validation".to_owned(), host::RING_NOT_MUTABLE.to_owned())
    );
    assert_eq!(
        refused("rotate while a successor waits"),
        ("conflict".to_owned(), host::KEY_ROTATION_PENDING.to_owned())
    );
    assert_eq!(
        refused("plan the revocation of a revoked key"),
        ("conflict".to_owned(), host::KEY_REVOKED.to_owned())
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
    // The memberships (WP-4.1).
    for (case, class, code) in [
        (
            "list the memberships of an unknown status",
            "validation",
            common::INVALID_ARGUMENT,
        ),
        (
            "invite again under the same request id",
            "conflict",
            host::INVITE_TOKEN_SHOWN,
        ),
        (
            "delete an unknown invitation",
            "not_found",
            host::INVITE_UNKNOWN,
        ),
        (
            "read an unknown membership",
            "not_found",
            host::MEMBERSHIP_UNKNOWN,
        ),
        (
            "read a malformed membership id",
            "validation",
            common::INVALID_ARGUMENT,
        ),
        (
            "suspend an unknown membership",
            "not_found",
            host::MEMBERSHIP_UNKNOWN,
        ),
        (
            "join without an outbound peer client",
            "unavailable",
            host::PEER_CLIENT_UNCONFIGURED,
        ),
    ] {
        assert_eq!(refused(case), (class.to_owned(), code.to_owned()), "{case}");
    }
    assert_eq!(
        refused("list the invitations as a stranger"),
        (String::new(), common::FORBIDDEN.to_owned())
    );
    for (case, class, code) in [
        (
            "plan an identity reset as a stranger",
            "",
            common::FORBIDDEN,
        ),
        (
            "run an identity reset with a wrong digest",
            "validation",
            host::PLAN_DIGEST_MISMATCH,
        ),
        (
            "read the identity after its reset",
            "unavailable",
            host::IDENTITY_UNAVAILABLE,
        ),
    ] {
        assert_eq!(refused(case), (class.to_owned(), code.to_owned()), "{case}");
    }
    // An enrollment is never a request of its own.
    let Transport::Rest(router) = &rest else {
        unreachable!("the REST transport")
    };
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/host/v1/members/enroll")
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .expect("a request"),
        )
        .await
        .expect("answered");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("reads")
        .to_bytes();
    assert_eq!(
        reduced_http(StatusCode::SERVICE_UNAVAILABLE, &body),
        Outcome::Refused {
            class: "unavailable".to_owned(),
            code: host::PEER_SESSIONS_UNSERVEABLE.to_owned(),
        }
    );
    // Nor is a task session (WP-4.3): it runs on the PeerChannel, opened by its lease request.
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/host/v1/tasks/decisions/session")
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .expect("a request"),
        )
        .await
        .expect("answered");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = response
        .into_body()
        .collect()
        .await
        .expect("reads")
        .to_bytes();
    assert_eq!(
        reduced_http(StatusCode::SERVICE_UNAVAILABLE, &body),
        Outcome::Refused {
            class: "unavailable".to_owned(),
            code: host::PEER_SESSIONS_UNSERVEABLE.to_owned(),
        }
    );
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
    // The ring's own key under `<ring>:<thumbprint>`, its epoch and its identity binding
    // (WP-3.1).
    assert!(
        body["keys"][0]["kid"]
            .as_str()
            .is_some_and(|kid| kid.starts_with("host.operations:")),
        "{body}"
    );
    assert_eq!(body["epoch"], 1, "{body}");
    assert!(body["binding"].is_string(), "{body}");

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
