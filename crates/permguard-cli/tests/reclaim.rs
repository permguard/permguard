// Copyright (c) 2022 Nitro Agility S.r.l.
// SPDX-License-Identifier: Apache-2.0

//! `permguard reclaim run` over HTTP (TD-2): a fake Kubernetes API and a fake coordinator Host
//! listener, the command line in between. It reads the workload, the claims, the Job, its Pod and
//! both containers' logs; asks the coordinator for its memberships and its frontier; and deletes
//! the claim under its UID, then the Job — or, for a Job that did not complete, deletes nothing.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::extract::{Path as UrlPath, RawQuery, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use serde_json::{Value, json};

const WORKLOAD: &str = "pg-permguard-data-plane-billing";
const FIXTURES: &str = include_str!("fixtures/drain-receipts.json");

#[derive(Default)]
struct Cluster {
    job_condition: String,
    /// `METHOD path body` of every change.
    changes: Vec<String>,
}

type Shared = Arc<Mutex<Cluster>>;

fn fixture(name: &str) -> Value {
    serde_json::from_str::<Value>(FIXTURES).unwrap()[name].clone()
}

fn kube(state: Shared) -> Router {
    Router::new()
        .route(
            "/apis/apps/v1/namespaces/pg/statefulsets",
            get(|| async {
                axum::Json(json!({ "items": [{ "metadata": { "name": WORKLOAD }, "spec": { "replicas": 1 } }] }))
            }),
        )
        .route(
            "/apis/apps/v1/namespaces/pg/statefulsets/{name}",
            get(|| async {
                axum::Json(json!({ "metadata": { "name": WORKLOAD }, "spec": { "replicas": 1 } }))
            }),
        )
        .route(
            "/api/v1/namespaces/pg/persistentvolumeclaims",
            get(|| async {
                axum::Json(json!({ "items": [
                    { "metadata": { "name": format!("state-{WORKLOAD}-0"), "uid": "uid-0" } },
                    { "metadata": { "name": format!("state-{WORKLOAD}-1"), "uid": "uid-1" } },
                ] }))
            }),
        )
        .route(
            "/api/v1/namespaces/pg/persistentvolumeclaims/{name}",
            axum::routing::delete(
                |State(state): State<Shared>, UrlPath(name): UrlPath<String>, body: String| async move {
                    state.lock().unwrap().changes.push(format!("DELETE claim {name} {body}"));
                    axum::Json(json!({}))
                },
            ),
        )
        .route(
            "/api/v1/namespaces/pg/pods/{name}",
            get(|UrlPath(name): UrlPath<String>| async move {
                // Only ordinal 0 runs.
                if name == format!("{WORKLOAD}-0") {
                    axum::Json(json!({ "metadata": { "name": name } })).into_response()
                } else {
                    StatusCode::NOT_FOUND.into_response()
                }
            }),
        )
        .route(
            "/api/v1/namespaces/pg/pods",
            get(|RawQuery(query): RawQuery| async move {
                assert_eq!(
                    query.as_deref(),
                    Some(format!("labelSelector=job-name%3D{WORKLOAD}-drain-1").as_str())
                );
                axum::Json(json!({ "items": [{ "metadata": { "name": "drain-pod", "creationTimestamp": "2026-10-26T00:00:00Z" } }] }))
            }),
        )
        .route(
            "/api/v1/namespaces/pg/pods/drain-pod/log",
            get(|RawQuery(query): RawQuery| async move {
                let query = query.unwrap_or_default();
                assert!(query.ends_with("&tailLines=2000"), "{query}");
                match query.trim_end_matches("&tailLines=2000").trim_start_matches("container=") {
                    "claim" => "the volume at /var/lib/permguard/volume (id 07070707070707070707070707070707) is claimed at generation 3 (was 2)\n".to_owned(),
                    "data-plane" => format!(
                        "{{\"timestamp\":\"x\"}}\n{}\n{{\"timestamp\":\"y\"}}\n",
                        json!({ "drain_receipt": fixture("shipped")["export"] })
                    ),
                    other => panic!("no container {other}"),
                }
            }),
        )
        .route(
            "/apis/batch/v1/namespaces/pg/jobs/{name}",
            get(|State(state): State<Shared>| async move {
                let condition = state.lock().unwrap().job_condition.clone();
                axum::Json(json!({ "status": { "conditions": [
                    { "type": condition, "status": "True", "reason": "DeadlineExceeded" }
                ] } }))
            })
            .delete(
                |State(state): State<Shared>, UrlPath(name): UrlPath<String>, body: String| async move {
                    state.lock().unwrap().changes.push(format!("DELETE job {name} {body}"));
                    axum::Json(json!({}))
                },
            ),
        )
        .with_state(state)
}

fn coordinator(status: &str) -> Router {
    let shipped = fixture("shipped");
    let host_id = shipped["host_id"].as_str().unwrap().to_owned();
    let pin = shipped["pin"].as_str().unwrap().to_owned();
    let producer = shipped["host_id_hex"].as_str().unwrap().to_owned();
    let host = |id: &str, fingerprint: &str| json!({ "host_id": id, "epoch": 1, "fingerprint": fingerprint });
    let members = json!({ "members": [{
        "membership_id": "0198f2aa-0000-7000-8000-000000000009",
        "role": "coordinator",
        "status": status,
        "epoch": 1,
        "revision": 1,
        "coordinator": host("0198f2aa-0000-7000-8000-000000000001", "sha256:11"),
        "member": host(&host_id, &pin),
        "selector": "plane/data/*",
        "tasks": [],
        "member_assurance": "production",
        "lease_policy": null,
        "manifest": null,
        "updated_at": "2026-10-26T00:00:00Z",
        "last_session_at": null,
    }] });
    let frontier = json!({
        "resource": "plane/data/zone/acme/ledger/main",
        "producer": [],
        "consumer": [
            { "producer": producer, "run": "0a0b0a0b0a0b0a0b0a0b0a0b0a0b0a0b", "acked": 12, "oldest_retained": 1 },
            { "producer": producer, "run": "0c0d0c0d0c0d0c0d0c0d0c0d0c0d0c0d", "acked": 7, "oldest_retained": 1 },
        ],
    });
    Router::new()
        .route(
            "/host/v1/members",
            get(move || async move { axum::Json(members) }),
        )
        .route(
            "/host/v1/streams/data/decisions/frontier",
            get(move || async move { axum::Json(frontier) }),
        )
}

fn serve(router: Router) -> SocketAddr {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                sender.send(listener.local_addr().unwrap()).unwrap();
                axum::serve(listener, router).await.unwrap();
            });
    });
    receiver.recv().unwrap()
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "pg-cli-reclaim-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn reclaim(dir: &Path, kube: SocketAddr, host: SocketAddr) -> std::process::Output {
    let template = dir.join("job.json");
    std::fs::write(&template, r#"{"metadata":{"name":"__JOB__"}}"#).unwrap();
    std::process::Command::new(env!("CARGO_BIN_EXE_permguard"))
        .arg("-w")
        .arg(dir)
        .args(["--host-endpoint", &format!("http://{host}")])
        .args([
            "reclaim",
            "run",
            "--namespace",
            "pg",
            "--selector",
            "app.kubernetes.io/instance=pg",
            "--kube-api",
            &format!("http://{kube}"),
            "--job-template",
        ])
        .arg(&template)
        .env("PERMGUARD_CONFIG", dir.join("cli-config.yml"))
        .env("NO_COLOR", "1")
        .output()
        .expect("the binary runs")
}

fn lines(output: &std::process::Output) -> Vec<Value> {
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).expect("one JSON line per claim"))
        .collect()
}

#[test]
fn the_drain_controller_reclaims_a_proven_claim_over_http() {
    let state: Shared = Arc::new(Mutex::new(Cluster {
        job_condition: "Complete".to_owned(),
        ..Cluster::default()
    }));
    let kube = serve(kube(Arc::clone(&state)));
    let host = serve(coordinator("active"));
    let dir = scratch("reclaimed");

    let output = reclaim(&dir, kube, host);
    assert!(output.status.success(), "{output:?}");
    let lines = lines(&output);
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert_eq!(lines[0]["claim"], format!("state-{WORKLOAD}-1"));
    assert_eq!(lines[0]["outcome"], "reclaimed", "{lines:?}");

    let changes = state.lock().unwrap().changes.clone();
    assert_eq!(changes.len(), 2, "{changes:?}");
    assert!(changes[0].starts_with(&format!("DELETE claim state-{WORKLOAD}-1 ")));
    let options: Value = serde_json::from_str(changes[0].splitn(4, ' ').nth(3).unwrap()).unwrap();
    assert_eq!(options["preconditions"]["uid"], "uid-1");
    assert!(changes[1].starts_with(&format!("DELETE job {WORKLOAD}-drain-1 ")));
}

#[test]
fn the_drain_controller_keeps_the_claim_of_a_failed_job_over_http() {
    let state: Shared = Arc::new(Mutex::new(Cluster {
        job_condition: "Failed".to_owned(),
        ..Cluster::default()
    }));
    let kube = serve(kube(Arc::clone(&state)));
    let host = serve(coordinator("active"));
    let dir = scratch("failed");

    let output = reclaim(&dir, kube, host);
    assert!(output.status.success(), "{output:?}");
    let lines = lines(&output);
    assert_eq!(lines[0]["outcome"], "kept", "{lines:?}");
    assert!(
        lines[0]["detail"]
            .as_str()
            .unwrap()
            .contains("DeadlineExceeded")
    );
    assert!(state.lock().unwrap().changes.is_empty());
}

#[test]
fn a_membership_the_coordinator_has_not_approved_pins_nothing_over_http() {
    for status in ["pending", "suspended", "revoked"] {
        let state: Shared = Arc::new(Mutex::new(Cluster {
            job_condition: "Complete".to_owned(),
            ..Cluster::default()
        }));
        let kube = serve(kube(Arc::clone(&state)));
        let host = serve(coordinator(status));
        let dir = scratch(status);

        let output = reclaim(&dir, kube, host);
        assert!(output.status.success(), "{output:?}");
        let lines = lines(&output);
        assert_eq!(lines[0]["outcome"], "kept", "{status}: {lines:?}");
        assert!(
            lines[0]["detail"]
                .as_str()
                .unwrap()
                .contains("holds no membership"),
            "{status}: {lines:?}"
        );
        assert!(state.lock().unwrap().changes.is_empty(), "{status}");
    }
}
