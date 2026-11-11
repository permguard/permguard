// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! F-21 and F-22 on the control plane (WP-2.4): the catalog and the NOTP push answer `401` to
//! nobody, `403` to a token without the scope, and a `billing` service account cannot read
//! `people`, nor learn whether `people` exists.

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use permguard_core::authz::{Selector, operations};
use permguard_core::config::SETTING_WORKING_DIR;
use permguard_core::keys::KeyManager as _;
use permguard_core::{
    Catalog as _, Config, PeerIdentity, PlaneContext, ProductIdentity, ServerContext,
};
use permguard_host::authz::testing::TestAuthority;
use permguard_host::authz::{PrincipalMapper, PublicGrant};
use permguard_host::composition::{Authorization, CONTROL_ATTEST, Host};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::catalog::FileCatalog;
use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
use permguard_std::storage::MemoryStorage;
use permguard_transport::ActorLayer;
use tower::ServiceExt as _;

fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-authz-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).expect("the scratch directory is created");
    path
}

fn identity() -> ProductIdentity {
    ProductIdentity::new(
        "permguard-control-plane",
        "Permguard",
        "tagline",
        "about",
        "",
    )
}

/// A deployment with a catalog holding `billing` and `people`, each with a `main` ledger, behind
/// a test Authority Plane whose `billing` token may read and push within its own zone. The caller
/// is the bearer of the token the test attaches, or the holder of a certificate.
struct Deployment {
    router: axum::Router,
    billing_zone: String,
    people_zone: String,
    /// The authority the router verifies tokens against: a test may revoke billing's token while
    /// a push is under way.
    authority: TestAuthority,
    /// Billing's token, and its index in the authority's status list.
    billing: Caller,
    billing_index: u64,
}

/// Who sends a request: a token's bearer, or a certificate's holder.
#[derive(Clone)]
enum Caller {
    Bearer(String),
    Certificate(Arc<PeerIdentity>),
}

fn deployment(tag: &str, public: &[PublicGrant]) -> Deployment {
    let volume = scratch(tag);
    let config: &'static Config = Box::leak(Box::new(
        Config::from_layers(
            permguard_core::config::BuildSettings::new(
                "0.0.0-test",
                "2022",
                "Nitro Agility S.r.l.",
            ),
            vec![permguard_server::plane::SETTING_CONTROL_HTTP_ADDR],
            permguard_core::config::Layers::new().with_environment(vec![
                (
                    SETTING_WORKING_DIR.to_owned(),
                    volume.to_string_lossy().into_owned(),
                ),
                (
                    permguard_server::plane::SETTING_CONTROL_HTTP_ADDR.to_owned(),
                    "127.0.0.1:6443".to_owned(),
                ),
            ]),
        )
        .expect("the configuration builds"),
    ));
    let storage: &'static MemoryStorage = Box::leak(Box::new(MemoryStorage::new()));
    let audit: &'static RecordingAuditSink = Box::leak(Box::new(RecordingAuditSink::new()));
    let catalog = Arc::new(FileCatalog::new(config.zones_directory()));
    let billing_zone = catalog.create_zone("billing").expect("billing");
    let people_zone = catalog.create_zone("people").expect("people");
    for zone in [&billing_zone, &people_zone] {
        catalog
            .create_ledger(
                &permguard_core::catalog::Selector::Id(zone.id.clone()),
                "main",
            )
            .expect("a ledger");
    }
    let keys = Arc::new(DirectoryKeyManager::new(
        volume.join("keys/control"),
        KeyPolicy {
            publish_ahead: std::time::Duration::ZERO,
            rotate_every: std::time::Duration::from_secs(3600),
            retain: std::time::Duration::from_secs(3600),
            verify_retain: std::time::Duration::from_secs(3600),
        },
    ));
    keys.maintain().expect("published");
    keys.maintain().expect("activated");

    // Billing's token: billing within billing, nothing else.
    let authority = TestAuthority::new();
    let (billing, billing_index) = authority.token_with_index(
        "billing",
        &[(
            &[operations::CATALOG_READ, operations::POLICY_PUSH],
            &format!("plane/control/zone/{}/*", billing_zone.id),
        )],
    );
    let held = permguard_host::storage::volume::Volume::claim(
        &volume,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("the volume is claimed");
    let ref_mutations = std::sync::Arc::new(
        permguard_host::operations::mutation::Mutations::open_offline(&held, "test")
            .expect("the mutation journal opens"),
    );
    std::mem::forget(held);

    let module = permguard_control_plane::module();
    let registration = Host::builder()
        .ring(CONTROL_ATTEST, keys)
        // Every head statement names its Host (WP-7.1): NOTP is served only with one.
        .host_id([0x11; 16])
        // Every ref update runs in a mutation transaction (WP-7.12).
        .mutations(ref_mutations)
        .authorization(Arc::new(Authorization::public_only(public)))
        .build()
        .register(module.declaration(config))
        .expect("the control plane registers");
    let server: &'static ServerContext<'static> = Box::leak(Box::new(
        ServerContext::new(identity(), config, storage, audit)
            .with_catalog(catalog)
            .with_plane_handles("control", Arc::new(registration)),
    ));
    let router = module
        .http_routes(&PlaneContext::new(server, "control"))
        .layer(ActorLayer::new(Arc::new(
            authority.authenticator(Arc::new(PrincipalMapper::empty())),
        )));
    Deployment {
        router,
        billing_zone: billing_zone.id,
        people_zone: people_zone.id,
        authority,
        billing: Caller::Bearer(billing),
        billing_index,
    }
}

/// The certificate of `uri`'s holder, as the acceptor would attach it.
fn certificate(uri: &str) -> Caller {
    Caller::Certificate(Arc::new(
        PeerIdentity::new(
            "CN=anyone",
            Some("anyone".to_owned()),
            "ab".repeat(32),
            "01",
        )
        .with_san_uris(vec![uri.to_owned()]),
    ))
}

/// `request` as `caller` sends it.
fn attach(request: &mut Request<axum::body::Body>, caller: Option<Caller>) {
    match caller {
        Some(Caller::Bearer(token)) => {
            request.headers_mut().insert(
                http::header::AUTHORIZATION,
                format!("Bearer {token}").parse().expect("a header"),
            );
        }
        Some(Caller::Certificate(peer)) => {
            request.extensions_mut().insert(peer);
        }
        None => {}
    }
}

async fn send(
    router: &axum::Router,
    method: &str,
    path: &str,
    caller: Option<Caller>,
    body: Option<&str>,
) -> (StatusCode, http::HeaderMap, String) {
    let mut request = Request::builder().method(method).uri(path);
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let mut request = request
        .body(axum::body::Body::from(body.unwrap_or("").to_owned()))
        .expect("a request");
    attach(&mut request, caller);
    let response = router.clone().oneshot(request).await.expect("answered");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body reads")
        .to_bytes();
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

#[tokio::test]
async fn f21_the_catalog_answers_401_to_nobody_and_a_stranger_and_nothing_is_readable_without_a_grant()
 {
    let deployed = deployment("f21", &[]);
    let (status, headers, body) =
        send(&deployed.router, "GET", "/catalog/v1/zones", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(
        headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some("Mutual-TLS realm=\"permguard\"")
    );
    let body: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert_eq!(body["code"], "unauthenticated");
    assert!(
        body.get("class").is_none(),
        "the closed denial body has no class"
    );

    // A certificate no rule maps is a stranger: unauthenticated, not anonymous.
    let (status, _, _) = send(
        &deployed.router,
        "GET",
        "/catalog/v1/zones",
        Some(certificate("spiffe://acme/nobody")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // A token without the scope here is somebody without a grant: forbidden, never unauthenticated.
    let scopeless = Caller::Bearer(deployed.authority.token(
        "nobody",
        &[(&[operations::DECISION_EVALUATE], "plane/data/*")],
    ));
    let (status, headers, _) = send(
        &deployed.router,
        "GET",
        &format!("/catalog/v1/zones/{}", deployed.billing_zone),
        Some(scopeless),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        headers
            .get("www-authenticate")
            .and_then(|v| v.to_str().ok()),
        Some(permguard_core::api::SCOPE_CHALLENGE)
    );

    // Discovery and health stay open to everybody.
    let (status, _, _) = send(&deployed.router, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn f22_billing_reads_billing_and_cannot_read_people_nor_tell_it_from_a_zone_that_is_not_there()
 {
    let deployed = deployment("f22", &[]);
    let billing = deployed.billing.clone();

    let (status, _, body) = send(
        &deployed.router,
        "GET",
        &format!("/catalog/v1/zones/{}", deployed.billing_zone),
        Some(billing.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (people_status, _, people_body) = send(
        &deployed.router,
        "GET",
        &format!("/catalog/v1/zones/{}", deployed.people_zone),
        Some(billing.clone()),
        None,
    )
    .await;
    assert_eq!(people_status, StatusCode::FORBIDDEN, "F-22: {people_body}");
    let (unknown_status, _, unknown_body) = send(
        &deployed.router,
        "GET",
        "/catalog/v1/zones/nowhere",
        Some(billing.clone()),
        None,
    )
    .await;
    assert_eq!(unknown_status, StatusCode::FORBIDDEN);
    assert_eq!(
        unknown_body, people_body,
        "existence outside the scope is not disclosed"
    );
    let denial: serde_json::Value = serde_json::from_str(&people_body).expect("JSON");
    assert_eq!(denial["code"], "forbidden");

    // By name as well as by id, and the listing shows only what is granted.
    let (status, _, body) = send(
        &deployed.router,
        "GET",
        "/catalog/v1/zones/people",
        Some(billing.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _, body) = send(
        &deployed.router,
        "GET",
        "/catalog/v1/zones",
        Some(billing.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let listed: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    let names: Vec<&str> = listed
        .as_array()
        .expect("an array")
        .iter()
        .filter_map(|zone| zone["name"].as_str())
        .collect();
    assert_eq!(names, vec!["billing"]);

    // Reading is not writing: the token holds catalog.read and policy.push only.
    let (status, _, body) = send(
        &deployed.router,
        "PATCH",
        &format!("/catalog/v1/zones/{}", deployed.billing_zone),
        Some(billing.clone()),
        Some(r#"{"name":"billing-2","request_id":"r-rename","expected_revision":1}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _, body) = send(
        &deployed.router,
        "POST",
        "/catalog/v1/zones",
        Some(billing.clone()),
        Some(r#"{"name":"finance","request_id":"r-create"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // NOTP push: a well-formed negotiation against people is refused before anything is
    // resolved; the same against billing goes through to the engine.
    let negotiation = permguard_notp::NegotiatePushRequest {
        r#ref: "main".to_owned(),
        new_head: permguard_objects::Digest::compute(b"a commit"),
        expected_ref: None,
        closure: Vec::new(),
        request_id: "push-1".to_owned(),
    }
    .encode()
    .expect("the negotiation encodes");
    let people_push = format!(
        "/notp/v1/zones/{}/ledgers/main/push/negotiate",
        deployed.people_zone
    );
    let billing_push = format!(
        "/notp/v1/zones/{}/ledgers/main/push/negotiate",
        deployed.billing_zone
    );
    let (status, _, body) = send_notp(
        &deployed.router,
        &people_push,
        Some(billing.clone()),
        &negotiation,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "F-22 on push: {body}");
    let (status, _, body) = send_notp(
        &deployed.router,
        &billing_push,
        Some(billing.clone()),
        &negotiation,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "billing may push to billing: {body}"
    );
    let (status, _, _) = send_notp(&deployed.router, &billing_push, None, &negotiation).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "F-21 on push");

    // Ledger level: an unknown ledger of billing and people's ledger answer alike.
    let (foreign_status, _, foreign_body) = send(
        &deployed.router,
        "GET",
        &format!("/catalog/v1/zones/{}/ledgers/main", deployed.people_zone),
        Some(billing.clone()),
        None,
    )
    .await;
    let (unknown_status, _, unknown_body) = send(
        &deployed.router,
        "GET",
        &format!(
            "/catalog/v1/zones/{}/ledgers/nowhere",
            deployed.billing_zone
        ),
        Some(billing.clone()),
        None,
    )
    .await;
    assert_eq!(foreign_status, StatusCode::FORBIDDEN, "{foreign_body}");
    // Billing's scope covers its whole zone, so an unknown ledger there is honestly not found:
    // nothing outside the scope is disclosed by saying so.
    assert_eq!(unknown_status, StatusCode::NOT_FOUND, "{unknown_body}");
    // Outside its zone, an unknown ledger is as foreign as a real one.
    let (status, _, body) = send(
        &deployed.router,
        "GET",
        &format!("/catalog/v1/zones/{}/ledgers/nowhere", deployed.people_zone),
        Some(billing.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, foreign_body);

    // Pulls and refs read a ledger: `catalog.read` on the exact ledger, the same way.
    let (status, _, _) = send(
        &deployed.router,
        "GET",
        &format!(
            "/notp/v1/zones/{}/ledgers/main/refs/main",
            deployed.people_zone
        ),
        Some(billing.clone()),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "F-22 on a ref read");
    let (status, _, _) = send(
        &deployed.router,
        "GET",
        &format!(
            "/notp/v1/zones/{}/ledgers/main/refs/main",
            deployed.billing_zone
        ),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "F-21 on a ref read");
    let (status, _, body) = send(
        &deployed.router,
        "GET",
        &format!(
            "/notp/v1/zones/{}/ledgers/main/refs/main",
            deployed.billing_zone
        ),
        Some(billing.clone()),
        None,
    )
    .await;
    assert_ne!(
        status,
        StatusCode::FORBIDDEN,
        "billing reads its own refs: {body}"
    );
    assert_ne!(status, StatusCode::UNAUTHORIZED, "{body}");

    // Pull negotiation and object fetch: the same `catalog.read` on the exact ledger.
    let pull = permguard_notp::NegotiatePullRequest {
        r#ref: "main".to_owned(),
        at: None,
        have: Vec::new(),
        checkpoint: None,
    }
    .encode()
    .expect("the pull encodes");
    let fetch = permguard_notp::FetchObjectsRequest {
        digests: Vec::new(),
        accept_compression: None,
        transfer_id: [0; 16],
    }
    .encode()
    .expect("the fetch encodes");
    for (suffix, body) in [("pull/negotiate", &pull), ("objects/fetch", &fetch)] {
        let people_path = format!(
            "/notp/v1/zones/{}/ledgers/main/{suffix}",
            deployed.people_zone
        );
        let billing_path = format!(
            "/notp/v1/zones/{}/ledgers/main/{suffix}",
            deployed.billing_zone
        );
        let (status, _, answered) =
            send_notp(&deployed.router, &people_path, Some(billing.clone()), body).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "F-22 on {suffix}: {answered}"
        );
        assert_eq!(
            answered, foreign_body,
            "the same denial as any foreign resource"
        );
        let (status, _, _) = send_notp(&deployed.router, &billing_path, None, body).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "F-21 on {suffix}");
        let (status, _, answered) =
            send_notp(&deployed.router, &billing_path, Some(billing.clone()), body).await;
        assert!(
            !matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
            "billing {suffix} on billing: {status} {answered}"
        );
    }
}

async fn send_notp(
    router: &axum::Router,
    path: &str,
    caller: Option<Caller>,
    body: &[u8],
) -> (StatusCode, http::HeaderMap, String) {
    let (status, headers, bytes) = send_notp_bytes(router, path, caller, body).await;
    (
        status,
        headers,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

async fn send_notp_bytes(
    router: &axum::Router,
    path: &str,
    caller: Option<Caller>,
    body: &[u8],
) -> (StatusCode, http::HeaderMap, Vec<u8>) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", permguard_notp::MEDIA_TYPE)
        .body(axum::body::Body::from(body.to_vec()))
        .expect("a request");
    attach(&mut request, caller);
    let response = router.clone().oneshot(request).await.expect("answered");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("the body reads")
        .to_bytes();
    (status, headers, bytes.to_vec())
}

#[tokio::test]
async fn an_explicit_public_grant_opens_exactly_what_it_names_to_anonymous() {
    let deployed = deployment(
        "public",
        &[PublicGrant::new(
            &[operations::CATALOG_READ],
            Selector::parse("plane/control/*").expect("a selector"),
        )],
    );
    let (status, _, body) = send(&deployed.router, "GET", "/catalog/v1/zones", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = send(
        &deployed.router,
        "POST",
        "/catalog/v1/zones",
        None,
        Some(r#"{"name":"finance","request_id":"r-create"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    // With everything under the plane readable, an unknown zone is honestly not found.
    let (status, _, _) = send(
        &deployed.router,
        "GET",
        "/catalog/v1/zones/nowhere",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A stranger's certificate never widens to the public grants.
    let (status, _, body) = send(
        &deployed.router,
        "GET",
        "/catalog/v1/zones",
        Some(certificate("spiffe://acme/nobody")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

#[tokio::test]
async fn a_token_revoked_between_negotiation_and_commit_refuses_the_commit() {
    let deployed = deployment("withdrawn", &[]);
    let billing = deployed.billing.clone();
    let base = format!("/notp/v1/zones/{}/ledgers/main/push", deployed.billing_zone);
    let new_head = permguard_objects::Digest::compute(b"a commit");
    let negotiation = permguard_notp::NegotiatePushRequest {
        r#ref: "main".to_owned(),
        new_head: new_head.clone(),
        expected_ref: None,
        closure: Vec::new(),
        request_id: "push-withdrawn".to_owned(),
    }
    .encode()
    .expect("the negotiation encodes");
    let (status, _, body) = send_notp_bytes(
        &deployed.router,
        &format!("{base}/negotiate"),
        Some(billing.clone()),
        &negotiation,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
    let negotiated =
        permguard_notp::NegotiatePushResponse::decode(&body).expect("the negotiation decodes");
    let commit = permguard_notp::CommitPushRequest {
        r#ref: "main".to_owned(),
        new_head: new_head.clone(),
        expected_ref: None,
        transfer_id: negotiated.transfer_id,
        request_id: "push-withdrawn".to_owned(),
    }
    .encode()
    .expect("the commit encodes");

    // Its token still live, the commit reaches the engine: it is refused for what it carries (the head
    // was never uploaded), not for who sends it.
    let (status, _, body) = send_notp(
        &deployed.router,
        &format!("{base}/commit"),
        Some(billing.clone()),
        &commit,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "allowed, the commit is judged on its content: {body}"
    );
    let refused: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert!(
        refused["message"]
            .as_str()
            .is_some_and(|message| message.contains(&new_head.to_string())),
        "the head it carries was never uploaded: {body}"
    );

    deployed.authority.revoke(deployed.billing_index);

    // The negotiated session does not carry the token: the commit is authenticated afresh, and
    // the revoked token is refused.
    let (status, _, body) = send_notp(
        &deployed.router,
        &format!("{base}/commit"),
        Some(billing.clone()),
        &commit,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}

/// WP-13.1: the catalog, NOTP, key and stream routes of the Control Plane are at their place in the
/// API layout of iteration 02 (`/<interface>/<version>/<resource>`, `endpoints.csv`), and the paths
/// before it answer `404`: moved, never aliased (D18). A route that exists answers `405` to a
/// method none of them takes. The evidence routes are `event_discovery`'s.
#[tokio::test]
async fn the_routes_are_at_their_layout_paths_and_the_old_ones_are_gone() {
    let deployment = deployment("layout", &[]);
    let status = |method: &'static str, path: &'static str| {
        let router = deployment.router.clone();
        async move { send(&router, method, path, None, None).await.0.as_u16() }
    };
    for path in [
        "/catalog/v1/zones",
        "/catalog/v1/zones/z",
        "/catalog/v1/zones/z/export",
        "/catalog/v1/zones/z/import",
        "/catalog/v1/zones/z/ledgers",
        "/catalog/v1/zones/z/ledgers/l",
        "/catalog/v1/zones/z/ledgers/l/archive",
        "/catalog/v1/zones/z/ledgers/l/restore",
        "/catalog/v1/zones/z/ledgers/l/export",
        "/notp/v1/zones/z/ledgers/l/refs/main",
        "/notp/v1/zones/z/ledgers/l/push/negotiate",
        "/notp/v1/zones/z/ledgers/l/push/commit",
        "/notp/v1/zones/z/ledgers/l/pull/negotiate",
        "/notp/v1/zones/z/ledgers/l/objects",
        "/notp/v1/zones/z/ledgers/l/objects/fetch",
        "/control-plane/v1/keys",
        "/streams/v1",
    ] {
        assert_eq!(status("PUT", path).await, 405, "{path} is served");
    }
    for path in [
        "/v1/zones",
        "/v1/zones/z",
        "/v1/zones/z/ledgers/l",
        "/v1/zones/z/ledgers/l/refs/main",
        "/v1/zones/z/ledgers/l/notp/push/negotiate",
        "/v1/zones/z/ledgers/l/notp/objects/fetch",
        "/control-plane/keys",
        "/v1/streams",
    ] {
        assert_eq!(status("GET", path).await, 404, "{path} is gone");
    }
}
