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
            permguard_objects::cbor::encode(&permguard_objects::cbor::Value::Map(vec![
                (
                    permguard_objects::cbor::Value::Int(1),
                    permguard_objects::cbor::Value::Text(answered.head),
                ),
                (
                    permguard_objects::cbor::Value::Int(2),
                    permguard_objects::cbor::Value::Int(answered.counter as i64),
                ),
                (
                    permguard_objects::cbor::Value::Int(3),
                    permguard_objects::cbor::Value::Bytes(answered.statement),
                ),
            ]))
            .map_err(|error| unencodable(error).into())
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

        let facade = NotpFacade::new(
            catalog,
            root.join("zones"),
            keys,
            EngineLimits {
                max_batch_bytes: 8 * 1024 * 1024,
                max_batch_objects: 1000,
                max_push_objects: 1000,
                max_push_bytes: 64 * 1024 * 1024,
                ledger_quota_bytes: 256 * 1024 * 1024,
            },
            permguard_languages::registry::Enabled::everything(),
            true,
            recorder,
            Disclosure::Minimal,
            false,
            permguard_core::metrics::Metrics::none(),
            std::sync::Arc::new(permguard_host::composition::Authorization::permissive()),
        );

        (routes(facade), zone.name, ledger.name)
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
            expected_old: None,
            closure: Vec::new(),
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
            expected_old: None,
            closure: objects
                .iter()
                .map(|bytes| ObjectClaim {
                    digest: Digest::compute(bytes),
                    size: bytes.len() as u64,
                })
                .collect(),
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
            expected_old: None,
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

        // The advertised ref answers.
        let request = HttpRequest::builder()
            .method("GET")
            .uri(format!("{base}/refs/main"))
            .body(Body::empty())
            .expect("a request builds");
        let answer = routes.clone().oneshot(request).await.expect("answers");
        assert_eq!(answer.status().as_u16(), 200);

        // Pull: full clone gets every object back, hash-verified.
        let pull = NegotiatePullRequest {
            r#ref: "main".into(),
            at: None,
            have: vec![],
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

    /// A push whose `security` record fails is committed and answered `mutation_unrecorded`,
    /// never success (WP-3.6, owner decision): the ref moved, and the caller reads it.
    #[tokio::test]
    async fn test_a_push_whose_record_fails_is_unrecorded_and_stands() {
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
        let upload = UploadObjectsRequest {
            objects,
            compression: None,
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
            expected_old: None,
        };
        let (status, body) = post(
            &routes,
            &format!("{base}/notp/push/commit"),
            commit.encode().expect("it encodes"),
        )
        .await;
        let body = String::from_utf8_lossy(&body);
        assert_eq!(status, 500, "{body}");
        assert!(body.contains("mutation_unrecorded"), "{body}");
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
