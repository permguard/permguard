// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! F-21 and F-22 on the control plane (WP-2.4): the catalog and the NOTP push answer `401` to
//! nobody, `403` to somebody without a grant, and a `billing` member cannot read `people`, nor
//! learn whether `people` exists.

#![allow(clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;

use http::{Request, StatusCode};
use http_body_util::BodyExt as _;
use permguard_core::authz::{Principal, Selector, operations};
use permguard_core::config::SETTING_WORKING_DIR;
use permguard_core::keys::KeyManager as _;
use permguard_core::{
    Catalog as _, Config, PeerIdentity, PlaneContext, ProductIdentity, ServerContext,
};
use permguard_host::authz::{GrantStore, Issue, PrincipalMapper, PublicGrant, Rule};
use permguard_host::composition::{Authorization, CONTROL_ATTEST, Host};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::catalog::FileCatalog;
use permguard_std::keys::{DirectoryKeyManager, KeyPolicy};
use permguard_std::storage::MemoryStorage;
use permguard_transport::ActorLayer;
use tower::ServiceExt as _;

const BILLING: &str = "spiffe://acme/billing";

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

/// A deployment with a catalog holding `billing` and `people`, each with a `main` ledger, and a
/// grant store where `billing` may read and push within its own zone and nobody else holds
/// anything. The caller is identified by the SAN URI of the certificate the test attaches.
struct Deployment {
    router: axum::Router,
    billing_zone: String,
    people_zone: String,
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

    // The grant store on the volume: billing within billing, nothing else.
    let held = permguard_host::storage::volume::Volume::claim(
        &volume,
        permguard_core::assurance::AssuranceProfile::Development,
    )
    .expect("the volume is claimed");
    let (store, _) = GrantStore::open(&held).expect("the grant store opens");
    permguard_host::operations::grants::issue(
        &permguard_host::operations::mutation::Mutations::open_offline(&held, "test")
            .expect("the mutation journal opens"),
        &store,
        permguard_host::operations::journal::Initiator::System("test".to_owned()),
        Issue {
            principal: Principal::new(BILLING).expect("a principal"),
            operations: vec![
                operations::CATALOG_READ.to_owned(),
                operations::POLICY_PUSH.to_owned(),
            ],
            selector: Selector::parse(&format!("plane/control/zone/{}/*", billing_zone.id))
                .expect("a selector"),
            resource_types: vec!["*".to_owned()],
            constraints: Default::default(),
            issued_by: "test".to_owned(),
            expires_at: None,
        },
        1,
    )
    .expect("issued");
    std::mem::forget(held);

    let module = permguard_control_plane::module();
    let registration = Host::builder()
        .ring(CONTROL_ATTEST, keys)
        .authorization(Arc::new(Authorization::new(store, public)))
        .build()
        .register(module.declaration(config), None)
        .expect("the control plane registers");
    let server: &'static ServerContext<'static> = Box::leak(Box::new(
        ServerContext::new(identity(), config, storage, audit)
            .with_catalog(catalog)
            .with_plane_handles("control", Arc::new(registration)),
    ));
    let mapper = PrincipalMapper::new(&[Rule::SanUri(BILLING.to_owned())], None).expect("a mapper");
    let router = module
        .http_routes(&PlaneContext::new(server, "control"))
        .layer(ActorLayer::new(Arc::new(mapper)));
    Deployment {
        router,
        billing_zone: billing_zone.id,
        people_zone: people_zone.id,
    }
}

/// The certificate of `uri`'s holder, as the acceptor would attach it.
fn certificate(uri: &str) -> Arc<PeerIdentity> {
    Arc::new(
        PeerIdentity::new(
            "CN=anyone",
            Some("anyone".to_owned()),
            "ab".repeat(32),
            "01",
        )
        .with_san_uris(vec![uri.to_owned()]),
    )
}

async fn send(
    router: &axum::Router,
    method: &str,
    path: &str,
    peer: Option<Arc<PeerIdentity>>,
    body: Option<&str>,
) -> (StatusCode, http::HeaderMap, String) {
    let mut request = Request::builder().method(method).uri(path);
    if body.is_some() {
        request = request.header("content-type", "application/json");
    }
    let mut request = request
        .body(axum::body::Body::from(body.unwrap_or("").to_owned()))
        .expect("a request");
    if let Some(peer) = peer {
        request.extensions_mut().insert(peer);
    }
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
    let (status, headers, body) = send(&deployed.router, "GET", "/v1/zones", None, None).await;
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
        "/v1/zones",
        Some(certificate("spiffe://acme/nobody")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // Discovery and health stay open to everybody.
    let (status, _, _) = send(&deployed.router, "GET", "/health", None, None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn f22_billing_reads_billing_and_cannot_read_people_nor_tell_it_from_a_zone_that_is_not_there()
 {
    let deployed = deployment("f22", &[]);
    let billing = certificate(BILLING);

    let (status, _, body) = send(
        &deployed.router,
        "GET",
        &format!("/v1/zones/{}", deployed.billing_zone),
        Some(Arc::clone(&billing)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (people_status, _, people_body) = send(
        &deployed.router,
        "GET",
        &format!("/v1/zones/{}", deployed.people_zone),
        Some(Arc::clone(&billing)),
        None,
    )
    .await;
    assert_eq!(people_status, StatusCode::FORBIDDEN, "F-22: {people_body}");
    let (unknown_status, _, unknown_body) = send(
        &deployed.router,
        "GET",
        "/v1/zones/nowhere",
        Some(Arc::clone(&billing)),
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
        "/v1/zones/people",
        Some(Arc::clone(&billing)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _, body) = send(
        &deployed.router,
        "GET",
        "/v1/zones",
        Some(Arc::clone(&billing)),
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

    // Reading is not writing: the grant names catalog.read and policy.push only.
    let (status, _, body) = send(
        &deployed.router,
        "PATCH",
        &format!("/v1/zones/{}", deployed.billing_zone),
        Some(Arc::clone(&billing)),
        Some(r#"{"name":"billing-2"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    let (status, _, body) = send(
        &deployed.router,
        "POST",
        "/v1/zones",
        Some(Arc::clone(&billing)),
        Some(r#"{"name":"finance"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // NOTP push: a well-formed negotiation against people is refused before anything is
    // resolved; the same against billing goes through to the engine.
    let negotiation = permguard_notp::NegotiatePushRequest {
        r#ref: "main".to_owned(),
        new_head: permguard_objects::Digest::compute(b"a commit"),
        expected_old: None,
        closure: Vec::new(),
    }
    .encode()
    .expect("the negotiation encodes");
    let people_push = format!(
        "/v1/zones/{}/ledgers/main/notp/push/negotiate",
        deployed.people_zone
    );
    let billing_push = format!(
        "/v1/zones/{}/ledgers/main/notp/push/negotiate",
        deployed.billing_zone
    );
    let (status, _, body) = send_notp(
        &deployed.router,
        &people_push,
        Some(Arc::clone(&billing)),
        &negotiation,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "F-22 on push: {body}");
    let (status, _, body) = send_notp(
        &deployed.router,
        &billing_push,
        Some(Arc::clone(&billing)),
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
        &format!("/v1/zones/{}/ledgers/main", deployed.people_zone),
        Some(Arc::clone(&billing)),
        None,
    )
    .await;
    let (unknown_status, _, unknown_body) = send(
        &deployed.router,
        "GET",
        &format!("/v1/zones/{}/ledgers/nowhere", deployed.billing_zone),
        Some(Arc::clone(&billing)),
        None,
    )
    .await;
    assert_eq!(foreign_status, StatusCode::FORBIDDEN, "{foreign_body}");
    // Billing's grant covers its whole zone, so an unknown ledger there is honestly not found:
    // nothing outside the grant is disclosed by saying so.
    assert_eq!(unknown_status, StatusCode::NOT_FOUND, "{unknown_body}");
    // Outside its zone, an unknown ledger is as foreign as a real one.
    let (status, _, body) = send(
        &deployed.router,
        "GET",
        &format!("/v1/zones/{}/ledgers/nowhere", deployed.people_zone),
        Some(Arc::clone(&billing)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, foreign_body);

    // Pulls and refs read a ledger: `catalog.read` on the exact ledger, the same way.
    let (status, _, _) = send(
        &deployed.router,
        "GET",
        &format!("/v1/zones/{}/ledgers/main/refs/main", deployed.people_zone),
        Some(Arc::clone(&billing)),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "F-22 on a ref read");
    let (status, _, _) = send(
        &deployed.router,
        "GET",
        &format!("/v1/zones/{}/ledgers/main/refs/main", deployed.billing_zone),
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "F-21 on a ref read");
    let (status, _, body) = send(
        &deployed.router,
        "GET",
        &format!("/v1/zones/{}/ledgers/main/refs/main", deployed.billing_zone),
        Some(Arc::clone(&billing)),
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
    }
    .encode()
    .expect("the pull encodes");
    let fetch = permguard_notp::FetchObjectsRequest {
        digests: Vec::new(),
        accept_compression: None,
    }
    .encode()
    .expect("the fetch encodes");
    for (suffix, body) in [("pull/negotiate", &pull), ("objects/fetch", &fetch)] {
        let people_path = format!(
            "/v1/zones/{}/ledgers/main/notp/{suffix}",
            deployed.people_zone
        );
        let billing_path = format!(
            "/v1/zones/{}/ledgers/main/notp/{suffix}",
            deployed.billing_zone
        );
        let (status, _, answered) = send_notp(
            &deployed.router,
            &people_path,
            Some(Arc::clone(&billing)),
            body,
        )
        .await;
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
        let (status, _, answered) = send_notp(
            &deployed.router,
            &billing_path,
            Some(Arc::clone(&billing)),
            body,
        )
        .await;
        assert!(
            !matches!(status, StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED),
            "billing {suffix} on billing: {status} {answered}"
        );
    }
}

async fn send_notp(
    router: &axum::Router,
    path: &str,
    peer: Option<Arc<PeerIdentity>>,
    body: &[u8],
) -> (StatusCode, http::HeaderMap, String) {
    let mut request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", permguard_notp::MEDIA_TYPE)
        .body(axum::body::Body::from(body.to_vec()))
        .expect("a request");
    if let Some(peer) = peer {
        request.extensions_mut().insert(peer);
    }
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
async fn an_explicit_public_grant_opens_exactly_what_it_names_to_anonymous() {
    let deployed = deployment(
        "public",
        &[PublicGrant::new(
            &[operations::CATALOG_READ],
            Selector::parse("plane/control/*").expect("a selector"),
        )],
    );
    let (status, _, body) = send(&deployed.router, "GET", "/v1/zones", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, _, body) = send(
        &deployed.router,
        "POST",
        "/v1/zones",
        None,
        Some(r#"{"name":"finance"}"#),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    // With everything under the plane readable, an unknown zone is honestly not found.
    let (status, _, _) = send(&deployed.router, "GET", "/v1/zones/nowhere", None, None).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    // A stranger's certificate never widens to the public grants.
    let (status, _, body) = send(
        &deployed.router,
        "GET",
        "/v1/zones",
        Some(certificate("spiffe://acme/nobody")),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
}
