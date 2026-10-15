// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! NOTP's HTTP shape: routes, CBOR bodies, and nothing else.
//!
//! Every body is `application/vnd.permguard.notp.v1+cbor` — the one codec of
//! the whole stack — decoded by the shared message module, so this file
//! cannot disagree with gRPC or with any client about a single byte.

use axum::Router;
use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use permguard_core::{ApiError, ErrorClass};
use permguard_notp::{
    self, CommitPushRequest, FetchObjectsRequest, NegotiatePullRequest, NegotiatePushRequest,
    UploadObjectsRequest,
};

use super::NotpFacade;
use crate::wire;

/// The routes the control plane answers about ledger contents.
pub(crate) fn routes(facade: NotpFacade) -> Router {
    Router::new()
        .route(
            "/v1/zones/{zone}/ledgers/{ledger}/refs/{*name}",
            get(get_ref),
        )
        .route(
            "/v1/zones/{zone}/ledgers/{ledger}/notp/push/negotiate",
            post(negotiate_push),
        )
        .route(
            "/v1/zones/{zone}/ledgers/{ledger}/notp/objects",
            post(upload),
        )
        .route(
            "/v1/zones/{zone}/ledgers/{ledger}/notp/push/commit",
            post(commit_push),
        )
        .route(
            "/v1/zones/{zone}/ledgers/{ledger}/notp/pull/negotiate",
            post(negotiate_pull),
        )
        .route(
            "/v1/zones/{zone}/ledgers/{ledger}/notp/objects/fetch",
            post(fetch),
        )
        .route_layer(axum::middleware::from_fn_with_state(
            facade.clone(),
            declared_notp,
        ))
        .with_state(facade)
}

/// Refuses a request body not declared `application/vnd.permguard.notp.v1+cbor`, before the
/// handler reads it.
///
/// A browser sends a `text/plain` POST cross-site without a preflight, carrying the client
/// certificate the listener authenticates with; a body read whatever its declared type would let
/// any page push to a ledger. A request without a body, the ref read, is not affected.
async fn declared_notp(
    State(facade): State<NotpFacade>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if request.method() == axum::http::Method::POST {
        let declared = request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|media| {
                media
                    .trim()
                    .eq_ignore_ascii_case(permguard_notp::MEDIA_TYPE)
            });
        if !declared {
            return wire::http_error(
                &bad_body(format!(
                    "the body must be declared `Content-Type: {}`",
                    permguard_notp::MEDIA_TYPE
                )),
                facade.disclosure,
            );
        }
    }
    next.run(request).await
}

/// Shapes a CBOR answer, or the taxonomy's refusal.
fn answer(facade: &NotpFacade, outcome: Result<Vec<u8>, wire::Refusal>) -> Response {
    match outcome {
        Ok(body) => cbor_response(StatusCode::OK, body),
        Err(refusal) => wire::http_refusal(&refusal, facade.disclosure),
    }
}

fn cbor_response(status: StatusCode, body: Vec<u8>) -> Response {
    (
        status,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static(permguard_notp::MEDIA_TYPE),
        )],
        body,
    )
        .into_response()
}

fn bad_body(detail: impl std::fmt::Display) -> ApiError {
    ApiError::new(
        ErrorClass::Validation,
        permguard_core::codes::notp::BODY_REJECTED,
        format!("the request body is not a valid NOTP message: {detail}"),
    )
}

async fn get_ref(
    State(facade): State<NotpFacade>,
    permguard_transport::ActorOf(actor): permguard_transport::ActorOf,
    Path((zone, ledger, name)): Path<(String, String, String)>,
) -> Response {
    let outcome = facade
        .get_ref(&actor, &zone, &ledger, &name)
        .await
        .and_then(|answered| {
            // The advertised ref rides the same framing as everything else.
            answered.encode().map_err(|error| unencodable(error).into())
        });
    answer(&facade, outcome)
}

/// An answer that could not be encoded: a fault of this plane, never of the request.
fn unencodable(error: impl std::fmt::Display) -> permguard_core::ApiError {
    permguard_core::ApiError::new(
        permguard_core::ErrorClass::Internal,
        permguard_core::codes::common::INTERNAL,
        "the answer could not be encoded",
    )
    .with_internal(error.to_string())
}

async fn negotiate_push(
    State(facade): State<NotpFacade>,
    permguard_transport::ActorOf(actor): permguard_transport::ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let outcome = match NegotiatePushRequest::decode(&body) {
        Ok(request) => facade
            .negotiate_push(&actor, &zone, &ledger, &request)
            .await
            .and_then(|response| response.encode().map_err(|error| unencodable(error).into())),
        Err(error) => Err(bad_body(error).into()),
    };
    answer(&facade, outcome)
}

async fn upload(
    State(facade): State<NotpFacade>,
    permguard_transport::ActorOf(actor): permguard_transport::ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let outcome = match UploadObjectsRequest::decode(&body) {
        Ok(request) => facade
            .upload(&actor, &zone, &ledger, &request)
            .await
            .and_then(|response| response.encode().map_err(|error| unencodable(error).into())),
        Err(error) => Err(bad_body(error).into()),
    };
    answer(&facade, outcome)
}

async fn commit_push(
    State(facade): State<NotpFacade>,
    permguard_transport::ActorOf(actor): permguard_transport::ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let outcome = match CommitPushRequest::decode(&body) {
        Ok(request) => facade
            .commit_push(&actor, &zone, &ledger, &request)
            .await
            .and_then(|response| response.encode().map_err(|error| unencodable(error).into())),
        Err(error) => Err(bad_body(error).into()),
    };
    answer(&facade, outcome)
}

async fn negotiate_pull(
    State(facade): State<NotpFacade>,
    permguard_transport::ActorOf(actor): permguard_transport::ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let outcome = match NegotiatePullRequest::decode(&body) {
        Ok(request) => facade
            .negotiate_pull(&actor, &zone, &ledger, &request)
            .await
            .and_then(|response| response.encode().map_err(|error| unencodable(error).into())),
        Err(error) => Err(bad_body(error).into()),
    };
    answer(&facade, outcome)
}

async fn fetch(
    State(facade): State<NotpFacade>,
    permguard_transport::ActorOf(actor): permguard_transport::ActorOf,
    Path((zone, ledger)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let outcome = match FetchObjectsRequest::decode(&body) {
        Ok(request) => facade
            .fetch(&actor, &zone, &ledger, &request)
            .await
            .and_then(|response| response.encode().map_err(|error| unencodable(error).into())),
        Err(error) => Err(bad_body(error).into()),
    };
    answer(&facade, outcome)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use super::*;

    /// The routes behind the boundary every served surface has (WP-2.4): every request here is
    /// anonymous, and the permissive authorization admits it.
    fn routes(facade: NotpFacade) -> Router {
        super::routes(facade).layer(permguard_transport::ActorLayer::new(std::sync::Arc::new(
            permguard_core::NoRules,
        )))
    }
    use crate::engine::{
        ANNOTATION_POLICY_ID, ANNOTATION_POLICY_KIND, EngineLimits, MEDIA_TYPE_MANIFEST,
        MEDIA_TYPE_POLICY_CEDAR,
    };
    use axum::body::Body;
    use http::Request as HttpRequest;
    use permguard_core::Disclosure;
    use permguard_core::catalog::Catalog;
    use permguard_core::keys::KeyManager as _;
    use permguard_notp::{
        CommitPushResponse, NegotiatePullResponse, NegotiatePushResponse, ObjectClaim,
        UploadObjectsResponse,
    };
    use permguard_objects::digest::Digest;
    use permguard_objects::manifest::{
        KIND_POLICY, Manifest, PROFILE_PDP_V1, Partition, Profile, Requirement, Runtime,
    };
    use permguard_objects::object::{Blob, Commit, Kind, Tree, TreeEntry};
    use permguard_objects::policy_id::derive_policy_id;
    use permguard_objects::semver::Constraint;
    use permguard_std::catalog::FileCatalog;
    use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;
    use tower::util::ServiceExt;

    fn testing_routes() -> (Router, String, String) {
        testing_routes_with(None)
    }

    fn testing_routes_with(recorder: Option<crate::handles::Audit>) -> (Router, String, String) {
        let (facade, zone, ledger) = testing_facade_with(recorder, None);
        (routes(facade), zone, ledger)
    }

    /// The facade every surface of a test shares, with the zone and ledger names it serves.
    fn testing_facade_with(
        recorder: Option<crate::handles::Audit>,
        hints: Option<permguard_host::composition::Hints>,
    ) -> (NotpFacade, String, String) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);

        let root = std::env::temp_dir().join(format!(
            "permguard-notp-http-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = std::fs::remove_dir_all(&root);

        let catalog = Arc::new(FileCatalog::new(root.join("zones")));
        let zone = catalog.create_zone("delivery").expect("a zone");
        let ledger = catalog
            .create_ledger(
                &permguard_core::catalog::Selector::Id(zone.id.clone()),
                "main-ledger",
            )
            .expect("a ledger");

        // A signing ring whose key activates on the first maintenance pass.
        let keys = Arc::new(DirectoryKeyManager::new(
            root.join("keys"),
            KeyPolicy {
                publish_ahead: Duration::ZERO,
                rotate_every: Duration::from_secs(3600),
                retain: Duration::from_secs(3600),
                verify_retain: Duration::from_secs(3600),
            },
        ));
        keys.maintain().expect("the ring publishes");
        keys.maintain().expect("the ring activates");
        let keys = crate::handles::head_signer_for_tests(keys);

        let facade = NotpFacade::new(
            catalog,
            root.join("zones"),
            keys,
            [0x11; 16],
            EngineLimits {
                max_batch_bytes: 8 * 1024 * 1024,
                max_batch_objects: 1000,
                max_push_objects: 1000,
                max_push_bytes: 64 * 1024 * 1024,
                ledger_quota_bytes: 256 * 1024 * 1024,
            },
            crate::engine::TransferPolicy {
                ttl: Duration::from_secs(900),
                grace: Duration::from_secs(3600),
            },
            crate::handles::ref_mutations_for_tests(&root.join("volume")),
            hints,
            permguard_languages::registry::Enabled::everything(),
            true,
            recorder,
            Disclosure::Minimal,
            false,
            permguard_core::metrics::Metrics::none(),
            std::sync::Arc::new(permguard_host::composition::Authorization::permissive()),
        );

        (facade, zone.name, ledger.name)
    }

    /// Negotiates, uploads and commits `objects` through `routes`, as a REST client does.
    async fn rest_push(routes: &Router, base: &str, objects: &[Vec<u8>], head: &Digest) {
        let negotiate = NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: objects
                .iter()
                .map(|bytes| ObjectClaim {
                    digest: Digest::compute(bytes),
                    size: bytes.len() as u64,
                })
                .collect(),
            request_id: "push-1".into(),
        };
        let (status, body) = post(
            routes,
            &format!("{base}/notp/push/negotiate"),
            negotiate.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let transfer_id = NegotiatePushResponse::decode(&body)
            .expect("decodes")
            .transfer_id;
        let upload = UploadObjectsRequest {
            objects: objects.to_vec(),
            compression: None,
            transfer_id,
        };
        let (status, body) = post(
            routes,
            &format!("{base}/notp/objects"),
            upload.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let commit = CommitPushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            transfer_id,
            request_id: "push-1".into(),
        };
        let (status, body) = post(
            routes,
            &format!("{base}/notp/push/commit"),
            commit.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    }

    /// WP-7.12: a member pulls over the `policy.mirror` task what a REST client pushed, through
    /// the same facade, within the resource its session reads; its transfer is its membership's,
    /// which a REST caller cannot name.
    #[tokio::test]
    async fn test_a_member_pulls_over_the_task_what_rest_pushed() {
        use permguard_host::membership::task::TaskHandler as _;
        use permguard_notp::{GetRefRequest, MirrorOperation, MirrorRequest};

        let (facade, zone, ledger) = testing_facade_with(None, None);
        let routes = routes(facade.clone());
        let base = format!("/v1/zones/{zone}/ledgers/{ledger}");
        let (objects, head) = build_commit();
        rest_push(&routes, &base, &objects, &head).await;

        let (zone_id, ledger_id) = facade.ledger_ids(&zone, &ledger).expect("the ledger");
        let mirror = crate::notp::mirror::Mirror {
            facade: Arc::new(facade.clone()),
        };
        let context = |resource: String| permguard_host::membership::task::TaskContext {
            membership_id: [0x42; 16],
            task_id: "mirror".to_owned(),
            task_type: permguard_host::membership::record::TaskType::PolicyMirror,
            version: 1,
            epoch: 1,
            resource,
            member: [0x43; 16],
            request_id: "r".to_owned(),
            limits: permguard_host::membership::record::Limits {
                max_body_bytes: 1 << 24,
                max_concurrency: 1,
                max_rate_per_minute: 60,
                max_batch_records: 1000,
                retention_seconds: 60,
            },
            channel_binding: [0; 32],
        };
        let message = |operation, body: Vec<u8>| {
            MirrorRequest {
                operation,
                zone: zone_id.clone(),
                ledger: ledger_id.clone(),
                body,
            }
            .encode()
            .expect("it encodes")
        };
        let session = context(format!("plane/control/zone/{zone_id}"));

        let advertised = permguard_notp::GetRefResponse::decode(
            &mirror
                .handle(
                    &session,
                    &message(
                        MirrorOperation::GetRef,
                        GetRefRequest {
                            r#ref: "main".into(),
                        }
                        .encode()
                        .expect("it encodes"),
                    ),
                )
                .expect("the ref reads"),
        )
        .expect("a ref answer");
        assert_eq!(advertised.head, head);

        let negotiated = NegotiatePullResponse::decode(
            &mirror
                .handle(
                    &session,
                    &message(
                        MirrorOperation::NegotiatePull,
                        NegotiatePullRequest {
                            r#ref: "main".into(),
                            at: None,
                            have: vec![],
                            checkpoint: None,
                        }
                        .encode()
                        .expect("it encodes"),
                    ),
                )
                .expect("the pull negotiates"),
        )
        .expect("a pull answer");
        assert_eq!(negotiated.missing.len(), objects.len());
        let fetch = FetchObjectsRequest {
            digests: negotiated.missing.clone(),
            accept_compression: None,
            transfer_id: negotiated.transfer_id,
        };
        let fetched = permguard_notp::FetchObjectsResponse::decode(
            &mirror
                .handle(
                    &session,
                    &message(
                        MirrorOperation::FetchObjects,
                        fetch.encode().expect("it encodes"),
                    ),
                )
                .expect("the objects come"),
        )
        .expect("a fetch answer");
        assert_eq!(fetched.objects.len(), objects.len());
        let keys = mirror
            .handle(&session, &message(MirrorOperation::KeyRing, Vec::new()))
            .expect("the key ring");
        assert!(String::from_utf8_lossy(&keys).contains("\"keys\""));

        // The member's transfer is its membership's: a REST caller naming it learns nothing.
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/objects/fetch"),
            fetch.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 404, "{}", String::from_utf8_lossy(&body));
        assert!(String::from_utf8_lossy(&body).contains("transfer_unknown"));
        // Nor does another membership.
        let mut stranger = context(format!("plane/control/zone/{zone_id}"));
        stranger.membership_id = [0x44; 16];
        assert_eq!(
            mirror
                .handle(
                    &stranger,
                    &message(
                        MirrorOperation::FetchObjects,
                        fetch.encode().expect("it encodes"),
                    ),
                )
                .expect_err("another membership's transfer")
                .code,
            "transfer_unknown"
        );

        // A ledger outside the session's resource is refused before it is read.
        let elsewhere = context("plane/control/zone/another-zone".to_owned());
        assert_eq!(
            mirror
                .handle(&elsewhere, &message(MirrorOperation::KeyRing, Vec::new()))
                .expect_err("outside the session's resource")
                .code,
            permguard_core::codes::common::FORBIDDEN
        );
        // A ledger named by its name, not its id, is not one the session's resource names.
        let by_name = MirrorRequest {
            operation: MirrorOperation::KeyRing,
            zone: zone.clone(),
            ledger: ledger.clone(),
            body: Vec::new(),
        }
        .encode()
        .expect("it encodes");
        assert_eq!(
            mirror
                .handle(&context("plane/control".to_owned()), &by_name)
                .expect_err("names are not ids")
                .code,
            permguard_core::codes::common::FORBIDDEN
        );
        // A message that is not one is refused as such.
        assert_eq!(
            mirror
                .handle(&session, b"not cbor")
                .expect_err("not a message")
                .code,
            permguard_core::codes::notp::BODY_REJECTED
        );
    }

    /// WP-7.12: the other direction: negotiated and uploaded over gRPC, committed over REST.
    #[tokio::test]
    async fn test_a_transfer_negotiated_over_grpc_commits_over_rest() {
        use crate::v1::git_like_store_server::GitLikeStore;

        /// The request as the anonymous caller the REST routes of this test see.
        fn anonymous<T>(message: T) -> tonic::Request<T> {
            let mut request = tonic::Request::new(message);
            request
                .extensions_mut()
                .insert(Arc::new(permguard_core::authz::Actor::Anonymous));
            request
        }

        let (facade, zone, ledger) = testing_facade_with(None, None);
        let routes = routes(facade.clone());
        let base = format!("/v1/zones/{zone}/ledgers/{ledger}");
        let (objects, head) = build_commit();
        let negotiated = GitLikeStore::negotiate_push(
            &facade,
            anonymous(crate::v1::NegotiatePushRequest {
                zone: zone.clone(),
                ledger: ledger.clone(),
                r#ref: "main".into(),
                new_head: head.to_string(),
                expected_ref: None,
                closure: objects
                    .iter()
                    .map(|bytes| crate::v1::ObjectClaim {
                        digest: Digest::compute(bytes).to_string(),
                        size: bytes.len() as u64,
                    })
                    .collect(),
                request_id: "push-1".into(),
            }),
        )
        .await
        .expect("the gRPC negotiation answers")
        .into_inner();
        let transfer_id: [u8; 16] = negotiated.transfer_id.clone().try_into().expect("16 bytes");
        GitLikeStore::upload_objects(
            &facade,
            anonymous(crate::v1::UploadObjectsRequest {
                zone: zone.clone(),
                ledger: ledger.clone(),
                objects: objects.clone(),
                compression: String::new(),
                transfer_id: negotiated.transfer_id,
            }),
        )
        .await
        .expect("the gRPC upload lands");
        let commit = CommitPushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            transfer_id,
            request_id: "push-1".into(),
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/push/commit"),
            commit.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            CommitPushResponse::decode(&body).expect("decodes").counter,
            1
        );
    }

    /// WP-7.12: a commit tells the watches of its ledger (`WatchRefs`): the hint names the ref
    /// and its new head and counter.
    #[tokio::test]
    async fn test_a_commit_hints_the_watches_of_its_ledger() {
        use permguard_host::membership::record::{
            Lease, Limits, TaskType, WatchHint, WatchRequest,
        };

        let hub = Arc::new(permguard_host::membership::watch::Hub::default());
        let hints = permguard_host::composition::Host::builder()
            .watch_hub(Arc::clone(&hub))
            .build()
            .register(
                permguard_host::composition::Declaration::new("control")
                    .handles_task(TaskType::PolicyMirror, 1),
            )
            .expect("registers")
            .hints();
        let (facade, zone, ledger) = testing_facade_with(None, hints);
        let (zone_id, ledger_id) = facade.ledger_ids(&zone, &ledger).expect("the ledger");
        let lease = Lease {
            membership_id: [1; 16],
            task_id: "mirror".to_owned(),
            epoch: 1,
            coordinator: [2; 16],
            member: [3; 16],
            coordinator_boot_id: [4; 16],
            member_boot_id: [5; 16],
            selector: permguard_core::authz::Selector::parse("plane/control/*")
                .expect("a selector"),
            resource: format!("plane/control/zone/{zone_id}"),
            limits: Limits {
                max_body_bytes: 1024,
                max_concurrency: 1,
                max_rate_per_minute: 60,
                max_batch_records: 10,
                retention_seconds: 60,
            },
            issued_at: 0,
            expires_at: 60,
            channel_binding: [6; 32],
            binding_digest: None,
        };
        let queue = hub
            .subscribe(
                TaskType::PolicyMirror,
                &lease,
                &WatchRequest {
                    positions: Vec::new(),
                },
            )
            .expect("subscribes");
        let routes = routes(facade);
        let base = format!("/v1/zones/{zone}/ledgers/{ledger}");
        let (objects, head) = build_commit();
        rest_push(&routes, &base, &objects, &head).await;
        assert_eq!(
            queue.take(),
            Some(vec![WatchHint {
                key: format!("{zone_id}/{ledger_id}/main"),
                head: head.to_string(),
                counter: 1,
            }])
        );
    }

    /// WP-7.12: one transfer, two surfaces: negotiated and uploaded over REST, committed over
    /// gRPC, through one facade and one compare-and-swap.
    #[tokio::test]
    async fn test_a_transfer_negotiated_over_rest_commits_over_grpc() {
        let (facade, zone, ledger) = testing_facade_with(None, None);
        let routes = routes(facade.clone());
        let base = format!("/v1/zones/{zone}/ledgers/{ledger}");
        let (objects, head) = build_commit();
        let negotiate = NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: objects
                .iter()
                .map(|bytes| ObjectClaim {
                    digest: Digest::compute(bytes),
                    size: bytes.len() as u64,
                })
                .collect(),
            request_id: "push-1".into(),
        };
        let (_, body) = post(
            &routes,
            &format!("{base}/notp/push/negotiate"),
            negotiate.encode().expect("it encodes"),
        )
        .await;
        let transfer_id = NegotiatePushResponse::decode(&body)
            .expect("decodes")
            .transfer_id;
        let upload = UploadObjectsRequest {
            objects: objects.clone(),
            compression: None,
            transfer_id,
        };
        let (status, _) = post(
            &routes,
            &format!("{base}/notp/objects"),
            upload.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200);

        // The same caller on both surfaces: the transfer is bound to it.
        let mut request = tonic::Request::new(crate::v1::CommitPushRequest {
            zone: zone.clone(),
            ledger: ledger.clone(),
            r#ref: "main".into(),
            new_head: head.to_string(),
            expected_ref: None,
            transfer_id: transfer_id.to_vec(),
            request_id: "push-1".into(),
        });
        request
            .extensions_mut()
            .insert(Arc::new(permguard_core::authz::Actor::Anonymous));
        let committed =
            crate::v1::git_like_store_server::GitLikeStore::commit_push(&facade, request)
                .await
                .expect("the gRPC commit lands")
                .into_inner();
        assert_eq!((committed.head, committed.counter), (head.to_string(), 1));

        // The same commit asked again over REST is the transfer's answer, not a second update.
        let commit = CommitPushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            transfer_id,
            request_id: "push-1".into(),
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/push/commit"),
            commit.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            CommitPushResponse::decode(&body).expect("decodes").counter,
            1
        );
    }

    /// A NOTP body not declared as one is refused before it is read: a cross-site `text/plain`
    /// POST needs no preflight.
    #[tokio::test]
    async fn test_a_body_not_declared_notp_is_refused_before_it_is_read() {
        let (routes, zone, ledger) = testing_routes();
        let body = NegotiatePullRequest {
            r#ref: "main".to_owned(),
            at: None,
            have: Vec::new(),
            checkpoint: None,
        }
        .encode()
        .expect("encodes");
        for media in [Some("text/plain"), Some("application/json"), None] {
            let mut request = HttpRequest::builder().method("POST").uri(format!(
                "/v1/zones/{zone}/ledgers/{ledger}/notp/pull/negotiate"
            ));
            if let Some(media) = media {
                request = request.header("content-type", media);
            }
            let answer = routes
                .clone()
                .oneshot(request.body(Body::from(body.clone())).expect("builds"))
                .await
                .expect("the router answers");
            assert_eq!(answer.status().as_u16(), 400, "{media:?}");
            let bytes = axum::body::to_bytes(answer.into_body(), 1 << 20)
                .await
                .expect("reads");
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                text.contains(r#""code":"body_rejected""#),
                "{media:?}: {text}"
            );
        }
    }

    async fn post(routes: &Router, path: &str, body: Vec<u8>) -> (u16, Vec<u8>) {
        let request = HttpRequest::builder()
            .method("POST")
            .uri(path)
            .header("content-type", permguard_notp::MEDIA_TYPE)
            .body(Body::from(body))
            .expect("a request builds");
        let answer = routes
            .clone()
            .oneshot(request)
            .await
            .expect("the router answers");
        let status = answer.status().as_u16();
        let bytes = axum::body::to_bytes(answer.into_body(), 1 << 24)
            .await
            .expect("the body reads");
        (status, bytes.to_vec())
    }

    fn build_commit() -> (Vec<Vec<u8>>, Digest) {
        let source = "permit(principal, action, resource);";
        let policy = Blob {
            media_type: MEDIA_TYPE_POLICY_CEDAR.into(),
            data: source.as_bytes().to_vec(),
        };
        let policy_bytes = policy.encode().expect("a blob encodes");
        let manifest = Manifest {
            kind: KIND_POLICY.into(),
            name: "test".into(),
            description: String::new(),
            author: String::new(),
            license: String::new(),
            runtimes: BTreeMap::from([(
                "cedar".to_string(),
                Runtime {
                    language: Requirement {
                        name: "cedar".into(),
                        constraint: Constraint::parse(">=4.0.0").unwrap(),
                    },
                    engine: Requirement {
                        name: "permguard".into(),
                        constraint: Constraint::parse(">=0.1.0 <0.2.0").unwrap(),
                    },
                },
            )]),
            partitions: BTreeMap::from([(
                "cedar".to_string(),
                Partition {
                    interfaces: Vec::new(),
                    runtime: "cedar".into(),
                    media_types: vec![MEDIA_TYPE_POLICY_CEDAR.to_string()],
                    schema: false,
                    artifacts: Vec::new(),
                    history: None,
                    input: None,
                },
            )]),
            profiles: BTreeMap::from([(
                "default".to_string(),
                Profile {
                    r#type: PROFILE_PDP_V1.into(),
                    partitions: vec!["cedar".into()],
                },
            )]),
        };
        let manifest_blob = Blob {
            media_type: MEDIA_TYPE_MANIFEST.into(),
            data: manifest.encode().expect("it encodes"),
        };
        let manifest_bytes = manifest_blob.encode().expect("a manifest encodes");
        let mut annotations = BTreeMap::new();
        annotations.insert(
            ANNOTATION_POLICY_ID.to_string(),
            derive_policy_id(source.as_bytes()),
        );
        annotations.insert(ANNOTATION_POLICY_KIND.to_string(), "policy".to_string());
        let partition = Tree {
            entries: vec![TreeEntry {
                kind: Kind::Blob,
                digest: Digest::compute(&policy_bytes),
                name: "billing-view.cedar".into(),
                annotations,
            }],
        };
        let partition_bytes = partition.encode().expect("a tree encodes");
        let root = Tree {
            entries: vec![
                TreeEntry {
                    kind: Kind::Tree,
                    digest: Digest::compute(&partition_bytes),
                    name: "cedar".into(),
                    annotations: BTreeMap::new(),
                },
                TreeEntry {
                    kind: Kind::Blob,
                    digest: Digest::compute(&manifest_bytes),
                    name: "manifest".into(),
                    annotations: BTreeMap::new(),
                },
            ],
        };
        let root_bytes = root.encode().expect("a root encodes");
        let commit = Commit {
            tree: Digest::compute(&root_bytes),
            manifest: Digest::compute(&manifest_bytes),
            predecessors: vec![],
            author: "test".into(),
            author_at: 0,
            message: "first".into(),
        };
        let commit_bytes = commit.encode().expect("a commit encodes");
        let head = Digest::compute(&commit_bytes);
        (
            vec![
                policy_bytes,
                manifest_bytes,
                partition_bytes,
                root_bytes,
                commit_bytes,
            ],
            head,
        )
    }

    /// A CBOR body that nests deeper than the decoder will walk, on every NOTP entry point.
    ///
    /// One array per byte: `0x81` repeated is a legal-looking payload that opens a level for every
    /// byte of it, comfortably inside any body limit, and a recursive decoder walks it until the
    /// stack is gone. That is a remote abort of the control plane, from an unauthenticated socket.
    ///
    /// The decoder's own limit is asserted where it lives. What is asserted here is the thing that
    /// actually matters: the **network path** answers, with a refusal, and the process is still
    /// there to answer the next request.
    #[tokio::test]
    async fn test_a_deeply_nested_body_is_refused_rather_than_taking_the_process_down() {
        let (routes, zone, ledger) = testing_routes();
        let base = format!("/v1/zones/{zone}/ledgers/{ledger}");

        // 50 001 bytes, 50 000 levels: the payload that aborted the process before the limit.
        let mut deep = vec![0x81u8; 50_000];
        deep.push(0x00);

        for path in [
            format!("{base}/notp/push/negotiate"),
            format!("{base}/notp/objects"),
            format!("{base}/notp/push/commit"),
            format!("{base}/notp/pull/negotiate"),
            format!("{base}/notp/objects/fetch"),
        ] {
            let (status, body) = post(&routes, &path, deep.clone()).await;

            // 400: the body is well-formed CBOR framing that this decoder will not walk, which
            // is the taxonomy's status for a request that is not the contract's shape.
            assert_eq!(
                status,
                400,
                "{path} did not refuse a body it cannot read: {}",
                String::from_utf8_lossy(&body)
            );
            assert!(
                String::from_utf8_lossy(&body).contains("nests deeper"),
                "{path} refused it for some other reason: {}",
                String::from_utf8_lossy(&body)
            );
            assert!(
                String::from_utf8_lossy(&body).contains("body_rejected"),
                "{path} refused it as something other than a bad body: {}",
                String::from_utf8_lossy(&body)
            );
        }

        // Still serving: the point of the limit is that the next caller is answered.
        let request = NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: build_commit().1,
            expected_ref: None,
            closure: Vec::new(),
            request_id: "push-1".into(),
        };
        let (status, _) = post(
            &routes,
            &format!("{base}/notp/push/negotiate"),
            request.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "the plane stopped answering after the refusal");
    }

    /// The whole protocol over HTTP: negotiate, upload, commit, ref, pull.
    #[tokio::test]
    async fn test_push_then_pull_over_http() {
        let (routes, zone, ledger) = testing_routes();
        let base = format!("/v1/zones/{zone}/ledgers/{ledger}");
        let (objects, head) = build_commit();

        // Negotiate: everything is missing.
        let request = NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: objects
                .iter()
                .map(|bytes| ObjectClaim {
                    digest: Digest::compute(bytes),
                    size: bytes.len() as u64,
                })
                .collect(),
            request_id: "push-1".into(),
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/push/negotiate"),
            request.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let negotiated = NegotiatePushResponse::decode(&body).expect("a response decodes");
        assert_eq!(negotiated.missing.len(), objects.len());

        // Upload the batch.
        let upload = UploadObjectsRequest {
            objects: objects.clone(),
            compression: None,
            transfer_id: negotiated.transfer_id,
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/objects"),
            upload.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        assert_eq!(
            UploadObjectsResponse::decode(&body)
                .expect("decodes")
                .received
                .len(),
            objects.len()
        );

        // Commit: counter 1, a statement comes back.
        let commit = CommitPushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            transfer_id: negotiated.transfer_id,
            request_id: "push-1".into(),
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/push/commit"),
            commit.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let committed = CommitPushResponse::decode(&body).expect("decodes");
        assert_eq!(committed.head, head);
        assert_eq!(committed.counter, 1);
        assert!(!committed.statement.is_empty());
        let first = permguard_objects::refstate::RefState::first(head.clone());
        assert_eq!(
            committed.ref_digest,
            first.ref_digest().expect("a ref digest"),
            "the answer names the first state's digest"
        );

        // The advertised ref answers.
        let request = HttpRequest::builder()
            .method("GET")
            .uri(format!("{base}/refs/main"))
            .body(Body::empty())
            .expect("a request builds");
        let answer = routes.clone().oneshot(request).await.expect("answers");
        assert_eq!(answer.status().as_u16(), 200);
        let bytes = axum::body::to_bytes(answer.into_body(), usize::MAX)
            .await
            .expect("a body");
        let advertised = permguard_notp::GetRefResponse::decode(&bytes).expect("a ref answer");
        assert_eq!(advertised.ref_digest, committed.ref_digest);
        let statement = permguard_objects::statement::SignedHead::decode(&advertised.statement)
            .expect("a statement")
            .statement_unverified()
            .expect("a payload");
        assert_eq!(statement.ref_digest, committed.ref_digest);
        assert_eq!(statement.authority_host_id, [0x11; 16]);
        assert_eq!(
            statement.ring_epoch, 1,
            "the ring's epoch, bound by the signer"
        );

        // Pull: full clone gets every object back, hash-verified.
        let pull = NegotiatePullRequest {
            r#ref: "main".into(),
            at: None,
            have: vec![],
            checkpoint: None,
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/pull/negotiate"),
            pull.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let negotiated = NegotiatePullResponse::decode(&body).expect("decodes");
        assert_eq!(negotiated.head, head);
        let fetch = FetchObjectsRequest {
            digests: negotiated.missing.clone(),
            accept_compression: None,
            transfer_id: negotiated.transfer_id,
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/objects/fetch"),
            fetch.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200);
        let fetched = permguard_notp::FetchObjectsResponse::decode(&body).expect("decodes");
        assert_eq!(fetched.objects.len(), negotiated.missing.len());

        // The key ring publishes the key the statement names (the HTTP
        // route lives on the plane's discovery surface, /control/keys).
    }

    /// A push is recorded by the mutation transaction its ref update runs in (WP-7.12), not by
    /// the plane's own audit handle: a handle whose sink refuses every record does not touch it.
    #[tokio::test]
    async fn test_a_push_is_recorded_by_its_mutation_transaction_not_the_planes_handle() {
        use permguard_core::{AuditEvent, AuditRecorder, AuditSink, BoxFuture};

        /// A sink that refuses every record.
        struct Refusing;

        impl AuditSink for Refusing {
            fn name(&self) -> &'static str {
                "refusing"
            }

            fn record<'a>(
                &'a self,
                _event: &'a AuditEvent<'_>,
                _policy: Option<&'a dyn permguard_core::Pseudonymizer>,
            ) -> BoxFuture<'a, Result<(), permguard_core::error::AuditError>> {
                Box::pin(async move {
                    Err(permguard_core::error::AuditError::unavailable(
                        "the trail is full",
                    ))
                })
            }
        }

        let (routes, zone, ledger) = testing_routes_with(Some(crate::handles::audit_for_tests(
            AuditRecorder::new(Arc::new(Refusing)),
        )));
        let base = format!("/v1/zones/{zone}/ledgers/{ledger}");
        let (objects, head) = build_commit();
        let negotiate = NegotiatePushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            closure: objects
                .iter()
                .map(|bytes| ObjectClaim {
                    digest: Digest::compute(bytes),
                    size: bytes.len() as u64,
                })
                .collect(),
            request_id: "push-1".into(),
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/push/negotiate"),
            negotiate.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
        let transfer_id = NegotiatePushResponse::decode(&body)
            .expect("a response decodes")
            .transfer_id;
        let upload = UploadObjectsRequest {
            objects,
            compression: None,
            transfer_id,
        };
        let (status, _) = post(
            &routes,
            &format!("{base}/notp/objects"),
            upload.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 200);
        let commit = CommitPushRequest {
            r#ref: "main".into(),
            new_head: head.clone(),
            expected_ref: None,
            transfer_id,
            request_id: "push-1".into(),
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/push/commit"),
            commit.encode().expect("it encodes"),
        )
        .await;
        let body = String::from_utf8_lossy(&body);
        assert_eq!(status, 200, "{body}");
        let request = HttpRequest::builder()
            .method("GET")
            .uri(format!("{base}/refs/main"))
            .body(Body::empty())
            .expect("a request builds");
        let answer = routes.clone().oneshot(request).await.expect("answers");
        assert_eq!(answer.status().as_u16(), 200, "the push stands");
        let bytes = axum::body::to_bytes(answer.into_body(), usize::MAX)
            .await
            .expect("a body");
        let permguard_objects::cbor::Value::Map(pairs) =
            permguard_objects::cbor::decode_canonical(&bytes).expect("canonical")
        else {
            panic!("a map");
        };
        assert_eq!(
            pairs[0],
            (
                permguard_objects::cbor::Value::Int(1),
                permguard_objects::cbor::Value::Text(head.to_string())
            ),
            "the ref names the pushed head"
        );
    }

    /// Refusals speak the shared taxonomy: unknown ledger, malformed body.
    #[tokio::test]
    async fn test_a_compressed_batch_cannot_inflate_past_the_ceiling() {
        // Decompression amplifies bytes; the batch ceiling must apply to
        // what comes OUT, while it comes out — a small wire body cannot
        // become an allocation the sender chose.
        let (routes, zone, ledger) = testing_routes();
        let base = format!("/v1/zones/{zone}/ledgers/{ledger}");

        // One legal blob (well under the object limit) whose zlib form is
        // tiny; enough copies that the inflated batch passes 8 MiB.
        let blob = Blob {
            media_type: MEDIA_TYPE_POLICY_CEDAR.into(),
            data: format!(
                "permit(principal, action, resource); // {}",
                "x".repeat(512 * 1024)
            )
            .into_bytes(),
        }
        .encode()
        .expect("a blob encodes");
        let packed = permguard_objects::compress::deflate(&blob);
        let bomb = UploadObjectsRequest {
            objects: vec![packed; 32],
            compression: Some("deflate".into()),
            transfer_id: [0x7a; 16],
        };

        let (status, body) = post(
            &routes,
            &format!("{base}/notp/objects"),
            bomb.encode().expect("it encodes"),
        )
        .await;
        // Validation on the wire: 400, the taxonomy's own status.
        assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
        let text = String::from_utf8_lossy(&body);
        assert!(text.contains("inflates past"), "{text}");
    }

    #[tokio::test]
    async fn test_refusals_speak_the_taxonomy() {
        let (routes, zone, _) = testing_routes();

        let pull = NegotiatePullRequest {
            r#ref: "main".into(),
            at: None,
            have: vec![],
            checkpoint: None,
        };
        let (status, body) = post(
            &routes,
            &format!("/v1/zones/{zone}/ledgers/ghost/notp/pull/negotiate"),
            pull.encode().expect("it encodes"),
        )
        .await;
        assert_eq!(status, 404, "{}", String::from_utf8_lossy(&body));
        let error: serde_json::Value = serde_json::from_slice(&body).expect("json error");
        assert_eq!(error["class"], "not_found");

        let (status, body) = post(
            &routes,
            &format!("/v1/zones/{zone}/ledgers/ghost/notp/push/negotiate"),
            b"not cbor".to_vec(),
        )
        .await;
        assert_eq!(status, 400, "{}", String::from_utf8_lossy(&body));
    }
}
