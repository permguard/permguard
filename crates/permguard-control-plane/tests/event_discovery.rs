// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! The event log's discovery chain, walked the way a producer walks it.
//!
//! A data plane that ships its history is configured with one URL. Everything else it needs — where
//! batches go, which event types will be accepted, how offsets are spelled — it learns by following
//! links: the plane's document names the interface, the interface's document names the endpoints.
//!
//! So these tests never assert on a substring of a body. They follow the links, and would catch the
//! failure a `contains` check cannot: a document that is present and points somewhere wrong.

#![allow(clippy::expect_used)]

use std::path::PathBuf;

use http::Request;
use http_body_util::BodyExt as _;
use permguard_core::config::{
    SETTING_EVENT_STORE_DIRECTORY, SETTING_EVENT_STORE_ENABLED, SETTING_EXPERIMENTAL_DOGWOOD,
    SETTING_WORKING_DIR,
};
use permguard_core::{Config, ProductIdentity, ServerContext};
use permguard_std::audit::RecordingAuditSink;
use permguard_std::storage::MemoryStorage;
use tower::ServiceExt as _;

/// A directory nothing else is using.
fn scratch(tag: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "permguard-event-discovery-{tag}-{}",
        std::process::id()
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

/// A deployment on the conventional port, plus whatever a test wants to say.
fn deployed(extra: &[(&str, &str)]) -> Config {
    let mut file: Vec<(String, String)> = vec![(
        permguard_server::plane::SETTING_CONTROL_HTTP_ADDR.to_owned(),
        "127.0.0.1:7556".to_owned(),
    )];
    for (name, value) in extra {
        file.push(((*name).to_owned(), (*value).to_owned()));
    }

    Config::from_layers(
        permguard_server::plane::build_settings("0.0.0-test"),
        vec![
            permguard_server::plane::SETTING_RUNTIME_PLANES,
            permguard_server::plane::SETTING_CONTROL_HTTP_ADDR,
        ],
        permguard_core::config::Layers {
            file,
            ..Default::default()
        },
    )
    .expect("the test configuration builds")
}

/// A deployment that receives events, with a store it can actually open.
fn receiving(tag: &str) -> Config {
    let root = scratch(tag);

    deployed(&[
        (SETTING_WORKING_DIR, &root.to_string_lossy()),
        (SETTING_EVENT_STORE_ENABLED, "true"),
        (SETTING_EXPERIMENTAL_DOGWOOD, "true"),
        (SETTING_EVENT_STORE_DIRECTORY, "events"),
    ])
}

async fn get(router: axum::Router, path: &str) -> (u16, String) {
    let answer = router
        .oneshot(
            Request::builder()
                .method("GET")
                .uri(path)
                .body(axum::body::Body::empty())
                .expect("a request builds"),
        )
        .await
        .expect("the router answers");
    let status = answer.status().as_u16();
    let body = answer
        .into_body()
        .collect()
        .await
        .expect("the body reads")
        .to_bytes();

    (status, String::from_utf8_lossy(&body).into_owned())
}

/// The path part of an absolute URL the document published.
fn path_of(url: &str) -> String {
    let after_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);

    match after_scheme.find('/') {
        Some(at) => after_scheme[at..].to_owned(),
        None => "/".to_owned(),
    }
}

/// A producer arriving with one URL finds everything it needs by following links.
#[tokio::test]
async fn the_chain_leads_from_the_plane_to_the_endpoints_a_producer_ships_to() {
    let config = receiving("chain");
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), &config, &storage, &audit);
    let module = permguard_control_plane::module();

    // Layer two: the plane says which interfaces it serves.
    let (status, plane) = get(
        module.http_routes(&context),
        "/.well-known/server-configuration",
    )
    .await;
    assert_eq!(status, 200);
    let plane: serde_json::Value = serde_json::from_str(&plane).expect("the plane's document");
    let api = permguard_control_plane::events::read::API;
    let link = plane["interfaces"][api]["configuration"]
        .as_str()
        .unwrap_or_else(|| panic!("the plane links to `{api}`: {plane}"))
        .to_owned();

    // Layer three: followed, not guessed.
    let (status, document) = get(module.http_routes(&context), &path_of(&link)).await;
    assert_eq!(status, 200, "the link the plane published is answered");
    let document: serde_json::Value =
        serde_json::from_str(&document).expect("the interface's document");
    assert_eq!(document["interface"], api);
    assert_eq!(
        document["offsets"]["api"], api,
        "and the offsets it issues belong to the family it names"
    );
    assert_eq!(
        document["event_types"],
        serde_json::json!([permguard_languages::event::EVENT_TYPE]),
        "it advertises what this build can actually validate"
    );

    // And every endpoint it named is answered by this plane rather than being a `404` a producer
    // would only discover when it tried to ship.
    let ingest = path_of(
        document["endpoints"]["ingest"]
            .as_str()
            .expect("an ingest endpoint"),
    );
    let answered = module
        .http_routes(&context)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(&ingest)
                .header("content-type", "application/json")
                .body(axum::body::Body::from("{}"))
                .expect("a request builds"),
        )
        .await
        .expect("the router answers");
    assert_ne!(
        answered.status().as_u16(),
        404,
        "the advertised ingest path `{ingest}` is mounted"
    );

    let records = path_of(
        document["endpoints"]["records"]
            .as_str()
            .expect("a records endpoint"),
    );
    let (status, _) = get(module.http_routes(&context), &records).await;
    assert_ne!(status, 404, "and so is `{records}`");
}

/// A plane that does not serve the interface neither advertises it nor answers its document.
///
/// The two have to move together. An advertised interface that answers `404` sends a producer's
/// whole history nowhere; a served interface nobody advertised is one an operator configures from a
/// runbook instead of from the deployment.
#[tokio::test]
async fn an_unserved_interface_is_neither_advertised_nor_answered() {
    let config = deployed(&[]);
    let storage = MemoryStorage::new();
    let audit = RecordingAuditSink::new();
    let context = ServerContext::new(identity(), &config, &storage, &audit);
    let module = permguard_control_plane::module();

    let (status, plane) = get(
        module.http_routes(&context),
        "/.well-known/server-configuration",
    )
    .await;
    assert_eq!(status, 200);
    let plane: serde_json::Value = serde_json::from_str(&plane).expect("the plane's document");
    assert!(
        plane["interfaces"][permguard_control_plane::events::read::API].is_null(),
        "not advertised: {plane}"
    );

    let (status, _) = get(
        module.http_routes(&context),
        permguard_control_plane::events::configuration::CONFIGURATION_PATH,
    )
    .await;
    assert_eq!(status, 404, "and not answered either");
}
